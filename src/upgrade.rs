//! Performing the opening handshake over a real socket.
//!
//! [`proto::handshake`](crate::proto::handshake) knows the HTTP and none of
//! the I/O; this reads and writes it. The split is the same one the rest of
//! the crate uses, and it is what lets every rule above be tested without a
//! socket.

use alloc::string::String;
use alloc::vec::Vec;
use bytes::BytesMut;

use crate::conn::{Connection, Error, Role};
use crate::proto::handshake::{
    build_rejection, build_request, build_response, check_response, head_end, new_key,
    parse_request, Parsed, Request, UpgradeError, DEFAULT_MAX_HEAD,
};
use crate::proto::message::Limits;
use crate::stream::{ByteStream, StreamExt};

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

/// What [`accept`] found on the socket.
///
/// **New in 0.3**, and the reason [`accept`] no longer returns a connection
/// directly. A listening socket receives more than upgrades: preflights,
/// health checks and browser address bars all arrive on it, and every one of
/// them used to come back as an `Err` that had thrown the request away. The
/// answer to those depends on the server's routes and its CORS policy, which
/// this crate does not know and will not guess, so it hands back the pieces
/// instead.
pub enum UpgradeOutcome<S> {
    /// The handshake completed. The 101 has been written and the connection
    /// is live.
    Upgraded(Connection<S>, Request),
    /// A well formed HTTP request that did not ask for an upgrade. Nothing
    /// has been written: the caller owns the response, and a caller that
    /// drops this without writing one leaves the peer waiting.
    Plain {
        /// The socket, still in HTTP, positioned after the head.
        stream: S,
        /// The request, with its method and all of its headers.
        request: Request,
        /// Whatever arrived past the head, which on a plain request is a body
        /// or a pipelined second request. Kept for the same reason the
        /// upgrade path keeps it: those bytes are already out of the socket
        /// and nothing else will hand them back.
        buffered: BytesMut,
    },
}

/// Accept a WebSocket connection on an already connected socket.
///
/// `select` is given the parsed request and returns the subprotocol to use, or
/// `None` for none, along with any headers to put on the 101. It is a callback
/// rather than a list because the choice is usually the server's policy rather
/// than a simple intersection, and it now receives the whole request because a
/// CORS header on the response is a function of the `Origin` on the request.
///
/// `error_headers` go on any refusal this function writes. They are a separate
/// parameter and not `select`'s doing because a head that failed to parse
/// never reaches `select`; they are therefore the headers that hold for every
/// error regardless of who sent it, which is what `Server` and
/// `Cache-Control: no-store` are.
///
/// On a request that asked for a WebSocket and got it wrong, the HTTP refusal
/// is written before returning, so the client learns why instead of waiting
/// for frames that will never arrive.
///
/// **Breaking change in 0.3:** three things at once, all of them the same
/// change. The return type is [`UpgradeOutcome`] rather than a connection,
/// `select` takes a [`Request`] and returns headers as well as a subprotocol,
/// and `error_headers` is new. A caller that only ever wanted upgrades reads
/// `Ok(UpgradeOutcome::Upgraded(conn, request))` and treats `Plain` as the
/// refusal it used to get, except that it must now write the refusal itself.
pub async fn accept<S, F>(
    mut stream: S,
    limits: Limits,
    error_headers: &[(&str, &str)],
    select: F,
) -> Result<UpgradeOutcome<S>, Error>
where
    S: ByteStream + StreamExt,
    F: FnOnce(&Request) -> (Option<String>, Vec<(String, String)>),
{
    let (head, rest) = read_head(&mut stream, DEFAULT_MAX_HEAD).await?;

    let request = match parse_request(&head, DEFAULT_MAX_HEAD) {
        Ok(Parsed::Upgrade(request)) => request,
        Ok(Parsed::Plain(request)) => {
            return Ok(UpgradeOutcome::Plain {
                stream,
                request,
                buffered: rest,
            })
        }
        Err(error) => {
            // Best effort: the connection is being refused either way, so a
            // failure to deliver the reason does not change the outcome.
            let _ = stream
                .write_all(&build_rejection(error, error_headers))
                .await;
            return Err(Error::Upgrade(error));
        }
    };

    let (protocol, headers) = select(&request);
    // Borrowed down to `&str` pairs for `build_response`, which takes them
    // that way so a caller with literals does not have to allocate. The owned
    // form comes back from `select` because a header it computed from the
    // request cannot borrow from a request the callback does not own.
    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let response = build_response(&request.key, protocol.as_deref(), &borrowed);
    stream.write_all(&response).await?;

    Ok(UpgradeOutcome::Upgraded(
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
    use bytes::Bytes;
    use nagoya::net::{TcpListener, TcpStream};
    use nagoya::reactor::Addr;
    use nagoya::reactor::Reactor;

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
            let outcome = accept(stream, Limits::default(), &[], |request| {
                // Take the client's first offer, which is the ordinary policy,
                // and no extra headers.
                (request.protocols.first().cloned(), Vec::new())
            })
            .await
            .expect("handshake");

            let UpgradeOutcome::Upgraded(mut conn, request) = outcome else {
                panic!("an upgrade request did not upgrade");
            };
            assert_eq!(request.path, "/chat");
            let message = conn.read().await.expect("read").expect("message");
            conn.write(message).await.expect("write");
        });

        client.join().expect("client thread");
    }

    #[test]
    fn a_non_upgrade_request_is_handed_back_for_the_caller_to_answer() {
        // A plain GET, which is what a browser address bar produces. It used
        // to come back as `Err(NotAnUpgrade)` with a 400 already on the wire;
        // it now comes back whole, because a 400 was never the right answer to
        // a request the server has a route for. The `Origin` rides along so
        // the caller can decide what it is allowed to say.
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
                .write_all(
                    b"GET /health HTTP/1.1\r\nHost: localhost\r\n\
                      Origin: https://app.example.com\r\n\r\n",
                )
                .expect("write");
            let mut response = std::string::String::new();
            stream.read_to_string(&mut response).expect("read");
            response
        });

        nagoya::block_on(async {
            let (listened, _) = listener.accept().await.expect("accept");
            let outcome = accept(listened, Limits::default(), &[], |_| (None, Vec::new()))
                .await
                .expect("a plain GET is not an error");

            let UpgradeOutcome::Plain {
                mut stream,
                request,
                ..
            } = outcome
            else {
                panic!("a plain GET should not upgrade");
            };

            assert_eq!(
                request.method,
                crate::proto::handshake::Method::Get,
                "the method a caller routes on"
            );
            assert_eq!(request.path, "/health");
            let origin = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("origin"))
                .map(|(_, value)| value.clone())
                .expect("the Origin did not survive the parse");
            assert_eq!(origin, "https://app.example.com");

            // The caller writes its own bytes, which is the whole point of
            // getting the request back rather than an error.
            let answer = alloc::format!(
                "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: {origin}\r\n\
                 Cache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(answer.as_bytes()).await.expect("write");
        });

        let response = peer.join().expect("peer");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "client got no usable answer: {response:?}"
        );
        assert!(
            response.contains("Access-Control-Allow-Origin: https://app.example.com"),
            "the caller could not echo the Origin: {response:?}"
        );
    }

    #[test]
    fn a_preflight_is_handed_back_with_its_cors_headers() {
        // An OPTIONS preflight used to be indistinguishable from a POST and
        // from a malformed head: all three were one error. The caller has to
        // tell them apart to answer the first with 204 and the others with a
        // status that says no.
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
                .write_all(
                    b"OPTIONS /chat HTTP/1.1\r\nHost: localhost\r\n\
                      Origin: https://app.example.com\r\n\
                      Access-Control-Request-Method: GET\r\n\r\n",
                )
                .expect("write");
            let mut response = std::string::String::new();
            stream.read_to_string(&mut response).expect("read");
            response
        });

        nagoya::block_on(async {
            let (listened, _) = listener.accept().await.expect("accept");
            let outcome = accept(listened, Limits::default(), &[], |_| (None, Vec::new()))
                .await
                .expect("a preflight is not an error");

            let UpgradeOutcome::Plain {
                mut stream,
                request,
                ..
            } = outcome
            else {
                panic!("a preflight should not upgrade");
            };
            assert_eq!(request.method, crate::proto::handshake::Method::Options);
            assert!(request.headers.iter().any(|(name, value)| name
                .eq_ignore_ascii_case("access-control-request-method")
                && value == "GET"));

            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\n\
                      Access-Control-Allow-Origin: https://app.example.com\r\n\
                      Access-Control-Allow-Methods: GET, OPTIONS\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write");
        });

        let response = peer.join().expect("peer");
        assert!(
            response.starts_with("HTTP/1.1 204"),
            "the preflight went unanswered: {response:?}"
        );
    }

    #[test]
    fn a_malformed_head_still_gets_the_refusal_with_the_caller_s_headers() {
        // The case that stayed an error, and the one `error_headers` exists
        // for: nothing here reached `select`, so the headers cannot have come
        // from it.
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
            // An upgrade attempt with a version this crate does not speak,
            // which is a client bug rather than a request to route.
            stream
                .write_all(
                    b"GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\n\
                      Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                      Sec-WebSocket-Version: 8\r\n\r\n",
                )
                .expect("write");
            let mut response = std::string::String::new();
            stream.read_to_string(&mut response).expect("read");
            response
        });

        nagoya::block_on(async {
            let (listened, _) = listener.accept().await.expect("accept");
            let result = accept(
                listened,
                Limits::default(),
                &[("Cache-Control", "no-store"), ("Server", "nago-wss")],
                |_| (None, Vec::new()),
            )
            .await;
            assert!(
                matches!(result, Err(Error::Upgrade(UpgradeError::WrongVersion))),
                "version 8 is not a handshake this crate completes"
            );
        });

        let response = peer.join().expect("peer");
        assert!(response.starts_with("HTTP/1.1 426"), "{response:?}");
        assert!(response.contains("Cache-Control: no-store"), "{response:?}");
        assert!(response.contains("Server: nago-wss"), "{response:?}");
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
            let outcome = accept(stream, Limits::default(), &[], |_| (None, Vec::new()))
                .await
                .expect("handshake");
            let UpgradeOutcome::Upgraded(mut conn, _) = outcome else {
                panic!("an upgrade request did not upgrade");
            };
            let message = conn.read().await.expect("read").expect("message");
            assert_eq!(message, Message::Text(Bytes::from_static(b"hi")));
        });

        peer.join().expect("peer");
    }
}
