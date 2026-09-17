//! Performing the opening handshake over a real socket.
//!
//! [`proto::handshake`](crate::proto::handshake) knows the HTTP and none of
//! the I/O; this reads and writes it. The split is the same one the rest of
//! the crate uses, and it is what lets every rule above be tested without a
//! socket.

use alloc::vec::Vec;
use bytes::BytesMut;

use crate::conn::{Connection, Error, Role};
use crate::proto::handshake::{
    build_rejection, build_request, build_response, check_response, head_end, new_key,
    parse_request, Request, UpgradeError, DEFAULT_MAX_HEAD,
};
use crate::proto::message::Limits;
use crate::reactor::bytes::{ByteStream, StreamExt};

impl From<UpgradeError> for Error {
    fn from(value: UpgradeError) -> Self {
        Self::Upgrade(value)
    }
}

/// Read an HTTP head from `stream`, returning it and anything read past it.
///
/// A client may send its first frames in the same segment as the request, so
/// the bytes beyond the head are kept rather than discarded: throwing them
/// away loses the first message of every fast client.
async fn read_head<S: ByteStream + StreamExt>(
    stream: &mut S,
    max_head: usize,
) -> Result<(Vec<u8>, BytesMut), Error> {
    let mut buffer = BytesMut::with_capacity(2 * 1024);
    loop {
        if let Some(end) = head_end(&buffer) {
            let rest = buffer.split_off(end);
            return Ok((buffer.to_vec(), rest));
        }
        if buffer.len() > max_head {
            return Err(Error::Upgrade(UpgradeError::HeadTooLarge));
        }

        if buffer.capacity() - buffer.len() < 1024 {
            buffer.reserve(2 * 1024);
        }
        let read = stream.read_buf(&mut buffer).await?;
        if read == 0 {
            // The peer hung up mid handshake. Malformed rather than a
            // transport error: there is nothing wrong with the socket.
            return Err(Error::Upgrade(UpgradeError::Malformed));
        }
    }
}

/// Accept a WebSocket connection on an already connected socket.
///
/// `select` is given the subprotocols the client offered and returns the one
/// to use, or `None` for none. It is a callback rather than a list because the
/// choice is usually the server's policy rather than a simple intersection.
///
/// On a request that cannot be upgraded, the HTTP refusal is written before
/// returning, so the client learns why instead of waiting for frames that will
/// never arrive.
pub async fn accept<S, F>(
    mut stream: S,
    limits: Limits,
    select: F,
) -> Result<(Connection<S>, Request), Error>
where
    S: ByteStream + StreamExt,
    F: FnOnce(&[alloc::string::String]) -> Option<alloc::string::String>,
{
    let (head, rest) = read_head(&mut stream, DEFAULT_MAX_HEAD).await?;

    let request = match parse_request(&head, DEFAULT_MAX_HEAD) {
        Ok(request) => request,
        Err(error) => {
            // Best effort: the connection is being refused either way, so a
            // failure to deliver the reason does not change the outcome.
            let _ = stream.write_all(&build_rejection(error)).await;
            return Err(Error::Upgrade(error));
        }
    };

    let protocol = select(&request.protocols);
    let response = build_response(&request.key, protocol.as_deref());
    stream.write_all(&response).await?;

    Ok((
        Connection::with_buffered(stream, Role::Server, limits, rest),
        request,
    ))
}

/// Open a WebSocket connection to a server over an already connected socket.
///
/// `entropy` is sixteen random bytes for the handshake key. It is a parameter
/// because this crate does no I/O of its own and will not reach for a
/// generator behind the caller's back; §4.1 wants the key unpredictable so a
/// cache cannot replay a handshake, not secret.
pub async fn connect<S: ByteStream + StreamExt>(
    mut stream: S,
    path: &str,
    host: &str,
    protocols: &[&str],
    headers: &[(&str, &str)],
    entropy: [u8; 16],
    limits: Limits,
) -> Result<(Connection<S>, Option<alloc::string::String>), Error> {
    let key = new_key(entropy);
    let request = build_request(path, host, &key, protocols, headers);
    stream.write_all(&request).await?;

    let (head, rest) = read_head(&mut stream, DEFAULT_MAX_HEAD).await?;
    let protocol = check_response(&head, &key)?;

    Ok((
        Connection::with_buffered(stream, Role::Client, limits, rest),
        protocol,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::message::Message;
    use crate::reactor::socket::Addr;
    use crate::reactor::{Reactor, TcpListener, TcpStream};
    use bytes::Bytes;

    #[test]
    fn a_full_handshake_then_messages() {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(Addr::localhost(0), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let client_handle = handle.clone();
        let client = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let stream = TcpStream::connect(addr, &client_handle)
                    .await
                    .expect("connect");
                let (mut conn, protocol) = connect(
                    stream,
                    "/chat",
                    "localhost",
                    &["mcp"],
                    &[],
                    [9u8; 16],
                    Limits::default(),
                )
                .await
                .expect("handshake");

                assert_eq!(protocol.as_deref(), Some("mcp"), "subprotocol not agreed");
                conn.write(Message::Text(Bytes::from_static(b"hello")))
                    .await
                    .expect("write");
                let echoed = conn.read().await.expect("read").expect("message");
                assert_eq!(echoed, Message::Text(Bytes::from_static(b"hello")));
            });
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            let (mut conn, request) = accept(stream, Limits::default(), |offered| {
                // Take the client's first offer, which is the ordinary policy.
                offered.first().cloned()
            })
            .await
            .expect("handshake");

            assert_eq!(request.path, "/chat");
            let message = conn.read().await.expect("read").expect("message");
            conn.write(message).await.expect("write");
        });

        client.join().expect("client thread");
    }

    #[test]
    fn a_non_upgrade_request_is_refused_in_http() {
        // A plain GET, which is what a browser address bar produces. The
        // server must answer in HTTP rather than leaving it hanging.
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(Addr::localhost(0), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let peer = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut stream = std::net::TcpStream::connect(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                addr.port(),
            )))
            .expect("connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .expect("write");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read");
            response
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            let result = accept(stream, Limits::default(), |_| None).await;
            assert!(
                matches!(result, Err(Error::Upgrade(UpgradeError::NotAnUpgrade))),
                "a plain GET should not upgrade"
            );
        });

        let response = peer.join().expect("peer");
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "client got no usable refusal: {response:?}"
        );
    }

    #[test]
    fn frames_arriving_with_the_handshake_are_not_lost() {
        // A fast client puts its first frame in the same segment as the
        // request. Those bytes are already out of the socket by the time the
        // handshake completes, so they have to be carried across.
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(Addr::localhost(0), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let peer = std::thread::spawn(move || {
            use std::io::Write;
            let mut stream = std::net::TcpStream::connect(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                addr.port(),
            )))
            .expect("connect");

            let key = crate::proto::handshake::new_key([4u8; 16]);
            let mut wire = crate::proto::handshake::build_request("/", "localhost", &key, &[], &[]);
            // A masked text frame carrying "hi", appended to the request so
            // both land in one write.
            wire.extend_from_slice(&[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']);
            stream.write_all(&wire).expect("write");
            std::thread::sleep(std::time::Duration::from_millis(200));
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            let (mut conn, _) = accept(stream, Limits::default(), |_| None)
                .await
                .expect("handshake");
            let message = conn.read().await.expect("read").expect("message");
            assert_eq!(message, Message::Text(Bytes::from_static(b"hi")));
        });

        peer.join().expect("peer");
    }
}
