//! TLS over the reactor.
//!
//! # Why there is no fork of rustls here
//!
//! rustls is already sans-io. [`read_tls`] takes bytes that arrived,
//! [`process_new_packets`] decrypts them, and [`write_tls`] hands back bytes
//! to send: the same shape as this crate's own protocol core, and it knows
//! nothing about any runtime. So driving it from this reactor needs glue
//! rather than a rewrite, and that glue is this module.
//!
//! [`read_tls`]: rustls::ConnectionCommon::read_tls
//! [`write_tls`]: rustls::ConnectionCommon::write_tls
//! [`process_new_packets`]: rustls::ConnectionCommon::process_new_packets
//!
//! # Why this is generic over the stream
//!
//! Nothing here is specific to a TCP socket. The loop needs somewhere to put
//! ciphertext and somewhere to get it from, which is two methods, so that is
//! what it asks for. [`TcpStream`](crate::reactor::net::TcpStream) satisfies
//! it, and so would a Unix socket, an in-memory pipe for a test, or another
//! crate's stream entirely.
//!
//! That keeps this module an island: it depends on rustls and on a two method
//! trait rather than on this crate's reactor, so it could be lifted out whole
//! if it ever earns its own crate. It has not yet: it is a few hundred lines
//! that have only run against one reactor on one platform, and publishing it
//! would turn that into a promise.
//!
//! # The shape of the loop
//!
//! Every operation is the same three steps in a ring: give rustls whatever the
//! socket produced, let it work, and send whatever it produced. The subtlety
//! is that either direction can block, and a handshake stalls if the side that
//! wants to write is not drained, so both are serviced on every pass rather
//! than only the one the caller asked about.

use alloc::vec::Vec;
// rustls' plaintext ends are `std::io` types, so the traits have to be in
// scope to call them. This module already requires `std` through `reactor`.
use std::io::{Read as _, Write as _};

use rustls::{ClientConnection, ServerConnection};

use crate::reactor::bytes::ByteStream;
use crate::reactor::error::{Errno, Result};

/// A TLS session over a reactor socket.
///
/// Either end of the connection: the difference is only which rustls type is
/// inside, and every operation below is identical for both.
#[derive(Debug)]
pub struct TlsStream<S> {
    stream: S,
    session: Session,
    /// Plaintext rustls has decrypted but the caller has not taken yet.
    incoming: Vec<u8>,
    /// Where in `incoming` the caller has read up to.
    taken: usize,
}

/// Which side of the handshake this is.
#[derive(Debug)]
enum Session {
    Client(alloc::boxed::Box<ClientConnection>),
    Server(alloc::boxed::Box<ServerConnection>),
}

/// Dispatch a method to whichever session is inside.
///
/// rustls has no object-safe trait covering both directions, and the
/// alternative to this macro is writing every method twice.
macro_rules! session {
    // A single call: `session!(self, wants_write())`.
    ($self:expr, $method:ident($($argument:expr),*)) => {
        match &mut $self.session {
            Session::Client(session) => session.$method($($argument),*),
            Session::Server(session) => session.$method($($argument),*),
        }
    };
    // A call on what another call returned, which is how `reader()` and
    // `writer()` are reached: `session!(self, reader().read(buffer))`.
    ($self:expr, $outer:ident().$inner:ident($($argument:expr),*)) => {
        match &mut $self.session {
            Session::Client(session) => session.$outer().$inner($($argument),*),
            Session::Server(session) => session.$outer().$inner($($argument),*),
        }
    };
}

impl<S: ByteStream> TlsStream<S> {
    /// Start a client session over an already connected stream.
    pub fn client(stream: S, session: ClientConnection) -> Self {
        Self {
            stream,
            session: Session::Client(alloc::boxed::Box::new(session)),
            incoming: Vec::new(),
            taken: 0,
        }
    }

    /// Start a server session over an already accepted stream.
    pub fn server(stream: S, session: ServerConnection) -> Self {
        Self {
            stream,
            session: Session::Server(alloc::boxed::Box::new(session)),
            incoming: Vec::new(),
            taken: 0,
        }
    }

    /// Run the handshake to completion.
    ///
    /// Worth doing explicitly rather than letting the first read drive it: a
    /// certificate failure should surface at connect time, not as a strange
    /// error in the middle of the application's first message.
    pub async fn handshake(&mut self) -> Result<()> {
        while session!(self, is_handshaking()) {
            let wrote = self.flush_outgoing().await?;
            if !session!(self, is_handshaking()) {
                break;
            }
            // Only wait for the peer when there was nothing left to send:
            // reading first would deadlock a handshake whose next move is ours.
            if !wrote && self.fill_incoming().await? == 0 {
                return Err(Errno(libc::ECONNRESET));
            }
        }
        // The last flight of the handshake is still in the buffer.
        self.flush_outgoing().await?;
        Ok(())
    }

    /// Send everything rustls currently wants to send.
    ///
    /// Returns whether anything went out, which the handshake loop uses to
    /// decide whether waiting on the peer is safe.
    async fn flush_outgoing(&mut self) -> Result<bool> {
        let mut sent = false;
        while session!(self, wants_write()) {
            let mut buffer = Vec::new();
            // Writing into a Vec cannot fail, so the error is a rustls state
            // problem rather than an I/O one.
            session!(self, write_tls(&mut buffer)).map_err(|_| Errno(libc::EIO))?;
            if buffer.is_empty() {
                break;
            }
            self.stream.write_all(&buffer).await?;
            sent = true;
        }
        Ok(sent)
    }

    /// Read from the socket and let rustls decrypt.
    ///
    /// Returns how many ciphertext bytes arrived; zero means the peer closed.
    async fn fill_incoming(&mut self) -> Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let read = self.stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(0);
        }

        let mut cursor = &chunk[..read];
        while !cursor.is_empty() {
            // `read_tls` takes as much as its internal buffer allows, which
            // may be less than offered, so this loops rather than assuming.
            let taken = session!(self, read_tls(&mut cursor)).map_err(|_| Errno(libc::EIO))?;
            if taken == 0 {
                break;
            }
            let state = session!(self, process_new_packets())
                // A protocol error here is an attack or a broken peer; either
                // way the connection is finished.
                .map_err(|_| Errno(libc::EPROTO))?;

            let available = state.plaintext_bytes_to_read();
            if available > 0 {
                let start = self.incoming.len();
                self.incoming.resize(start + available, 0);
                // Reading plaintext out of rustls cannot fail once it has
                // reported the bytes are there.
                let _ = session!(self, reader().read(&mut self.incoming[start..]));
            }
        }
        Ok(read)
    }

    /// Read decrypted bytes into `buffer`.
    ///
    /// Returns zero when the peer has closed the session cleanly.
    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            // Serve what has already been decrypted before going to the socket.
            if self.taken < self.incoming.len() {
                let available = self.incoming.len() - self.taken;
                let take = available.min(buffer.len());
                buffer[..take].copy_from_slice(&self.incoming[self.taken..self.taken + take]);
                self.taken += take;

                // Reset rather than grow forever once drained.
                if self.taken == self.incoming.len() {
                    self.incoming.clear();
                    self.taken = 0;
                }
                return Ok(take);
            }

            // rustls may owe the peer a message even on a read: a key update
            // or an alert. Not sending it stalls the session.
            self.flush_outgoing().await?;

            if self.fill_incoming().await? == 0 {
                return Ok(0);
            }
        }
    }

    /// Write plaintext, encrypting and sending all of it.
    pub async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < buffer.len() {
            // rustls buffers the plaintext and encrypts on `write_tls`, so a
            // short accept here just means its buffer is full and needs
            // draining to the socket.
            let took = session!(self, writer().write(&buffer[written..]))
                .map_err(|_| Errno(libc::EIO))?;
            written += took;
            self.flush_outgoing().await?;
            if took == 0 {
                return Err(Errno(libc::EIO));
            }
        }
        Ok(())
    }

    /// Send a close_notify and stop.
    ///
    /// Skipping this is what produces "connection reset" in a peer's logs
    /// instead of a clean end, and it is how a truncation attack is detected.
    pub async fn close(&mut self) -> Result<()> {
        session!(self, send_close_notify());
        self.flush_outgoing().await?;
        Ok(())
    }

    /// The negotiated ALPN protocol, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match &self.session {
            Session::Client(session) => session.alpn_protocol(),
            Session::Server(session) => session.alpn_protocol(),
        }
    }

    /// The stream underneath, for a caller that needs its address.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

/// A TLS session is itself a byte stream, which is the whole point: a
/// WebSocket connection cannot tell whether it is speaking through one.
impl<S: ByteStream> ByteStream for TlsStream<S> {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        Self::read(self, buffer).await
    }

    async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        Self::write_all(self, buffer).await
    }
}

/// A client configuration trusting the platform's usual roots.
///
/// Uses the webpki bundle rather than the OS store: it is the same set every
/// other Rust TLS client in this house already trusts, and reading a system
/// store is a per-platform dependency this crate does not otherwise need.
#[must_use]
pub fn default_client_config() -> alloc::sync::Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    alloc::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reactor::socket::Addr;
    use crate::reactor::{Reactor, TcpListener, TcpStream};
    use alloc::sync::Arc;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

    /// A self signed certificate for `localhost`, and a client config that
    /// trusts exactly it.
    ///
    /// Generated rather than checked in: a committed test certificate expires
    /// and then the suite fails for a reason that has nothing to do with the
    /// code.
    fn certificate() -> (
        Arc<rustls::ServerConfig>,
        Arc<rustls::ClientConfig>,
    ) {
        let issued = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate certificate");
        let certificate = CertificateDer::from(issued.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(issued.signing_key.serialize_der())
            .expect("private key");

        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(alloc::vec![certificate.clone()], key)
            .expect("server config");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust the test certificate");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        (Arc::new(server), Arc::new(client))
    }

    #[test]
    fn a_tls_session_carries_bytes_both_ways() {
        let (server_config, client_config) = certificate();

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
                let name = ServerName::try_from("localhost").expect("name");
                let session = ClientConnection::new(client_config, name).expect("session");
                let mut tls = TlsStream::client(stream, session);

                tls.handshake().await.expect("handshake");
                tls.write_all(b"ping").await.expect("write");

                let mut buffer = [0u8; 4];
                let read = tls.read(&mut buffer).await.expect("read");
                assert_eq!(read, 4, "short read");
                assert_eq!(&buffer, b"pong");
                tls.close().await.expect("close");
            });
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsStream::server(stream, session);

            tls.handshake().await.expect("handshake");
            let mut buffer = [0u8; 4];
            let read = tls.read(&mut buffer).await.expect("read");
            assert_eq!(read, 4, "short read");
            assert_eq!(&buffer, b"ping");
            tls.write_all(b"pong").await.expect("write");
        });

        client.join().expect("client thread");
    }

    #[test]
    fn a_message_larger_than_one_tls_record_round_trips() {
        // TLS records cap at 16 KiB, so this necessarily spans several and
        // exercises the loop that reassembles them.
        const SIZE: usize = 200 * 1024;
        let (server_config, client_config) = certificate();

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
                let name = ServerName::try_from("localhost").expect("name");
                let session = ClientConnection::new(client_config, name).expect("session");
                let mut tls = TlsStream::client(stream, session);
                tls.handshake().await.expect("handshake");
                tls.write_all(&alloc::vec![0x5Au8; SIZE])
                    .await
                    .expect("write");
                tls.close().await.expect("close");
            });
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsStream::server(stream, session);
            tls.handshake().await.expect("handshake");

            let mut total = 0usize;
            let mut buffer = alloc::vec![0u8; 32 * 1024];
            while total < SIZE {
                let read = tls.read(&mut buffer).await.expect("read");
                if read == 0 {
                    break;
                }
                assert!(
                    buffer[..read].iter().all(|byte| *byte == 0x5A),
                    "payload corrupted through TLS"
                );
                total += read;
            }
            assert_eq!(total, SIZE, "did not receive the whole payload");
        });

        client.join().expect("client thread");
    }

    #[test]
    fn the_loop_works_over_something_that_is_not_a_socket() {
        // The point of the trait: this drives a full TLS handshake and a round
        // trip over an in-memory pipe, with no reactor and no file descriptor
        // anywhere. If this compiles and passes, the module is extractable.
        use std::sync::mpsc::{Receiver, SyncSender};

        struct Pipe {
            outgoing: SyncSender<alloc::vec::Vec<u8>>,
            incoming: Receiver<alloc::vec::Vec<u8>>,
            pending: alloc::vec::Vec<u8>,
        }

        impl ByteStream for Pipe {
            async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
                while self.pending.is_empty() {
                    match self.incoming.recv() {
                        Ok(chunk) => self.pending = chunk,
                        // The far end went away, which is end of stream.
                        Err(_) => return Ok(0),
                    }
                }
                let take = self.pending.len().min(buffer.len());
                buffer[..take].copy_from_slice(&self.pending[..take]);
                self.pending.drain(..take);
                Ok(take)
            }

            async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
                self.outgoing
                    .send(buffer.to_vec())
                    .map_err(|_| Errno(libc::EPIPE))
            }
        }

        let (server_config, client_config) = certificate();

        // Two channels crossed over, so each end reads what the other wrote.
        let (to_server, server_receives) = std::sync::mpsc::sync_channel(64);
        let (to_client, client_receives) = std::sync::mpsc::sync_channel(64);

        let server = std::thread::spawn(move || {
            let pipe = Pipe {
                outgoing: to_client,
                incoming: server_receives,
                pending: alloc::vec::Vec::new(),
            };
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsStream::server(pipe, session);
            nagoya::block_on(async move {
                tls.handshake().await.expect("handshake");
                let mut buffer = [0u8; 5];
                let read = tls.read(&mut buffer).await.expect("read");
                assert_eq!(&buffer[..read], b"hello");
                tls.write_all(b"world").await.expect("write");
            });
        });

        let pipe = Pipe {
            outgoing: to_server,
            incoming: client_receives,
            pending: alloc::vec::Vec::new(),
        };
        let name = ServerName::try_from("localhost").expect("name");
        let session = ClientConnection::new(client_config, name).expect("session");
        let mut tls = TlsStream::client(pipe, session);

        nagoya::block_on(async move {
            tls.handshake().await.expect("handshake");
            tls.write_all(b"hello").await.expect("write");
            let mut buffer = [0u8; 5];
            let read = tls.read(&mut buffer).await.expect("read");
            assert_eq!(&buffer[..read], b"world");
        });

        server.join().expect("server thread");
    }

    #[test]
    fn an_untrusted_certificate_is_refused() {
        // The client trusts a certificate generated separately from the one
        // the server presents, so the handshake must fail rather than warn.
        let (server_config, _) = certificate();
        let (_, other_client_config) = certificate();

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
                let name = ServerName::try_from("localhost").expect("name");
                let session =
                    ClientConnection::new(other_client_config, name).expect("session");
                let mut tls = TlsStream::client(stream, session);
                assert!(
                    tls.handshake().await.is_err(),
                    "an unknown certificate was accepted"
                );
            });
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            let session = ServerConnection::new(server_config).expect("session");
            let mut tls = TlsStream::server(stream, session);
            // The server's handshake fails too, when the client rejects it.
            let _ = tls.handshake().await;
        });

        client.join().expect("client thread");
    }
}
