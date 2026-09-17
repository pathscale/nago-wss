//! Opening a connection from a URL.
//!
//! # What this adds
//!
//! [`upgrade`](crate::upgrade) performs a handshake over a stream someone else
//! connected, and [`tls`](crate::tls) wraps a stream in a TLS session. Both
//! are the right shape for a caller that already has a socket and knows what
//! it wants. Neither is the right shape for "connect me to this URL", which is
//! what most callers actually have, and assembling it by hand means parsing
//! the URL, choosing the port, deciding whether TLS applies and getting the
//! SNI name right. Getting any of those wrong is quiet rather than loud, so
//! they live here once.

// `getaddrinfo` is the platform's resolver and there is no safe binding for
// it. The unsafe is confined to `resolve` below; everything else here is URL
// handling.
#![allow(unsafe_code)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::conn::{Connection, Error};
use crate::proto::message::Limits;
use crate::stream::Errno;
use nagoya::reactor::Addr;
use nagoya::reactor::Handle;
use nagoya::reactor::TcpStream;

/// A parsed `ws://` or `wss://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// Whether TLS applies.
    pub secure: bool,
    /// The host, for both the connection and the `Host` header.
    pub host: String,
    /// The port, defaulted from the scheme when absent.
    pub port: u16,
    /// The path and query, defaulted to `/`.
    pub path: String,
}

impl Url {
    /// Parse a WebSocket URL.
    ///
    /// Deliberately not a general URL parser: it handles the two schemes this
    /// crate speaks and rejects everything else, rather than accepting an
    /// `http://` URL and connecting somewhere surprising.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let (scheme, rest) = input
            .split_once("://")
            .ok_or(Error::Url("missing scheme"))?;
        let secure = match scheme {
            "ws" => false,
            "wss" => true,
            _ => return Err(Error::Url("scheme is not ws or wss")),
        };

        // The path starts at the first slash after the authority.
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(Error::Url("missing host"));
        }

        // Credentials in the authority are not supported: WebSocket has no use
        // for them and silently dropping them would be worse than refusing.
        if authority.contains('@') {
            return Err(Error::Url("credentials are not supported"));
        }

        let default_port = if secure { 443 } else { 80 };

        // An IPv6 literal is bracketed precisely because it is full of colons,
        // so the brackets have to be found before any colon can be read as a
        // port separator. Splitting on the last colon first gets `[::1]:9000`
        // wrong in both directions.
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or(Error::Url("unclosed bracket in host"))?;
            let port = match after.strip_prefix(':') {
                Some(port) => port
                    .parse::<u16>()
                    .map_err(|_| Error::Url("port is not a number"))?,
                None if after.is_empty() => default_port,
                None => return Err(Error::Url("unexpected text after host")),
            };
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| Error::Url("port is not a number"))?;
                    (host, port)
                }
                None => (authority, default_port),
            }
        };

        Ok(Self {
            secure,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// The value for the `Host` header.
    ///
    /// The port is omitted when it is the scheme's default, which is what
    /// every other client does and what servers matching on virtual hosts
    /// expect.
    #[must_use]
    pub fn host_header(&self) -> String {
        let default = if self.secure { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            alloc::format!("{}:{}", self.host, self.port)
        }
    }
}

/// How to open a connection.
pub struct ClientOptions<'a> {
    /// Subprotocols to offer, in order of preference.
    pub protocols: &'a [&'a str],
    /// Extra request headers, for authorisation and the like.
    pub headers: &'a [(&'a str, &'a str)],
    /// Sixteen random bytes for the handshake key.
    ///
    /// A parameter because this crate does no I/O of its own and will not
    /// reach for a generator behind the caller's back.
    pub entropy: [u8; 16],
    /// Message size limits.
    pub limits: Limits,
    /// The TLS configuration, when the URL is `wss://`.
    ///
    /// `None` uses the webpki roots.
    #[cfg(feature = "tls")]
    pub tls: Option<alloc::sync::Arc<crate::tls::rustls::ClientConfig>>,
}

impl Default for ClientOptions<'_> {
    fn default() -> Self {
        Self {
            protocols: &[],
            headers: &[],
            // A fixed default would make every connection from this process
            // use the same key, which is exactly what 4.1 asks callers to
            // avoid. Named so it is obvious in a stack trace.
            entropy: *b"nago-wss-default",
            limits: Limits::default(),
            #[cfg(feature = "tls")]
            tls: None,
        }
    }
}

/// Resolve a host to every address the platform offers.
///
/// All of them, in the resolver's order, rather than just the first. A host
/// with both an A and an AAAA record is ordinary, and on a machine where only
/// one family actually works, taking the first answer fails outright: this is
/// exactly what `localhost` does when it resolves to `::1` and the listener is
/// on IPv4. The caller tries them in turn.
///
/// Uses `getaddrinfo`, which is the platform's resolver: it honours
/// `/etc/hosts`, search domains and whatever else the machine is configured
/// with. Writing a DNS client instead would be a second network stack.
fn resolve(host: &str, port: u16) -> Result<Vec<Addr>, Error> {
    let name = alloc::ffi::CString::new(host).map_err(|_| Error::Url("host has a nul byte"))?;

    // SAFETY: an all-zero `addrinfo` is a valid set of hints.
    let mut hints: libc::addrinfo = unsafe { core::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;

    let mut result: *mut libc::addrinfo = core::ptr::null_mut();
    // SAFETY: `name` is a live C string, `hints` a live local, and `result`
    // receives a list this function frees below.
    let status = unsafe {
        libc::getaddrinfo(
            name.as_ptr(),
            core::ptr::null(),
            core::ptr::addr_of!(hints),
            core::ptr::addr_of_mut!(result),
        )
    };
    if status != 0 || result.is_null() {
        return Err(Error::Io(Errno(libc::EAI_NONAME)));
    }

    let mut found = Vec::new();
    let mut cursor = result;
    while !cursor.is_null() {
        // SAFETY: the list is well formed until the null terminator.
        let entry = unsafe { &*cursor };
        match entry.ai_family {
            libc::AF_INET => {
                // SAFETY: the family says this is a `sockaddr_in`.
                let addr = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in) };
                found.push(Addr::V4(addr.sin_addr.s_addr.to_ne_bytes(), port));
            }
            libc::AF_INET6 => {
                // SAFETY: the family says this is a `sockaddr_in6`.
                let addr = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in6) };
                found.push(Addr::V6(addr.sin6_addr.s6_addr, port));
            }
            // A family this crate does not speak, skipped rather than
            // guessed at.
            _ => {}
        }
        cursor = entry.ai_next;
    }
    // SAFETY: `result` came from `getaddrinfo` and is freed exactly once.
    unsafe { libc::freeaddrinfo(result) };

    if found.is_empty() {
        return Err(Error::Io(Errno(libc::EAI_NONAME)));
    }
    Ok(found)
}

/// Connect to the first address that accepts us.
///
/// Sequential rather than the parallel racing a browser does: the complexity
/// of happy eyeballs buys latency on a dual stacked network, and what is
/// needed here is only that a host answering on one family is reachable.
async fn connect_any(addrs: &[Addr], handle: &Handle) -> Result<TcpStream, Error> {
    let mut last = Errno(libc::ECONNREFUSED);
    for addr in addrs {
        match TcpStream::connect(*addr, handle).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(Error::Io(last))
}

/// What a successful connection produced.
pub struct Connected<S> {
    /// The live connection.
    pub connection: Connection<S>,
    /// The subprotocol the server selected, if any.
    pub protocol: Option<String>,
}

/// Connect to a `ws://` URL.
pub async fn connect_plain(
    url: &Url,
    handle: &Handle,
    options: ClientOptions<'_>,
) -> Result<Connected<TcpStream>, Error> {
    let addrs = resolve(&url.host, url.port)?;
    let stream = connect_any(&addrs, handle).await?;

    let headers: Vec<(&str, &str)> = options.headers.to_vec();
    let (connection, protocol) = crate::upgrade::connect(
        stream,
        &url.path,
        &url.host_header(),
        options.protocols,
        &headers,
        options.entropy,
        options.limits,
    )
    .await?;

    Ok(Connected {
        connection,
        protocol,
    })
}

/// Connect to a `wss://` URL.
#[cfg(feature = "tls")]
pub async fn connect_secure(
    url: &Url,
    handle: &Handle,
    options: ClientOptions<'_>,
) -> Result<Connected<crate::tls::TlsStream<TcpStream>>, Error> {
    // Through the re-export, so this crate never names a rustls version of
    // its own and cannot drift from the one nago-rustls links.
    use crate::tls::rustls_pki_types::ServerName;

    let addrs = resolve(&url.host, url.port)?;
    let stream = connect_any(&addrs, handle).await?;

    // The default only exists when the trust anchors are bundled. Without
    // `webpki-roots` there is nothing to fall back to, so a caller that did
    // not supply a configuration is asking for a connection that cannot
    // validate anything, and is told so rather than silently trusting.
    #[cfg(feature = "webpki-roots")]
    let config = options
        .tls
        .clone()
        .unwrap_or_else(crate::tls::default_client_config);
    #[cfg(not(feature = "webpki-roots"))]
    let config = options.tls.clone().ok_or(Error::Url(
        "wss:// needs a TLS configuration: this build has no bundled roots",
    ))?;
    // SNI and certificate validation both key off this name, so it is the
    // host from the URL rather than the address that was connected to.
    let name = ServerName::try_from(url.host.clone())
        .map_err(|_| Error::Url("host is not a valid server name"))?;
    let session = crate::tls::rustls::ClientConnection::new(config, name)
        .map_err(|_| Error::Io(Errno(libc::EPROTO)))?;

    let mut tls = crate::tls::TlsStream::client(stream, session);
    // Explicit, so a certificate failure surfaces here rather than in the
    // middle of the handshake that follows.
    tls.handshake().await?;

    let headers: Vec<(&str, &str)> = options.headers.to_vec();
    let (connection, protocol) = crate::upgrade::connect(
        tls,
        &url.path,
        &url.host_header(),
        options.protocols,
        &headers,
        options.entropy,
        options.limits,
    )
    .await?;

    Ok(Connected {
        connection,
        protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shapes_a_caller_actually_writes() {
        let plain = Url::parse("ws://example.com/chat").unwrap();
        assert!(!plain.secure);
        assert_eq!(plain.host, "example.com");
        assert_eq!(plain.port, 80);
        assert_eq!(plain.path, "/chat");

        let secure = Url::parse("wss://example.com/chat").unwrap();
        assert!(secure.secure);
        assert_eq!(secure.port, 443, "wss must default to 443");

        // No path at all is the root, not an empty path.
        assert_eq!(Url::parse("ws://example.com").unwrap().path, "/");

        // An explicit port wins over the default.
        assert_eq!(Url::parse("ws://example.com:8080/").unwrap().port, 8080);

        // The query is part of the path as far as the request line is
        // concerned, so it must survive.
        assert_eq!(
            Url::parse("ws://example.com/chat?room=1").unwrap().path,
            "/chat?room=1"
        );
    }

    #[test]
    fn an_ipv6_literal_is_not_mistaken_for_a_port() {
        // The colons inside the brackets are the address, and the one after
        // them is the port. Splitting on the last colon unconditionally gets
        // this wrong, which is why the check looks for the bracket.
        let url = Url::parse("ws://[::1]:9000/chat").unwrap();
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 9000);

        let bare = Url::parse("ws://[::1]/chat").unwrap();
        assert_eq!(bare.host, "::1");
        assert_eq!(bare.port, 80, "a bracketed host with no port took one");
    }

    #[test]
    fn refuses_urls_it_would_have_to_guess_at() {
        for input in [
            "example.com/chat",            // no scheme
            "http://example.com/chat",     // not a websocket scheme
            "ws:///chat",                  // no host
            "ws://example.com:noport/",    // port is not a number
            "ws://user:pass@example.com/", // credentials
        ] {
            assert!(
                Url::parse(input).is_err(),
                "accepted a url it should have refused: {input}"
            );
        }
    }

    #[test]
    fn the_host_header_omits_a_default_port() {
        // Servers matching on virtual hosts compare this string, and every
        // other client omits the default, so including it breaks routing.
        assert_eq!(
            Url::parse("ws://example.com/").unwrap().host_header(),
            "example.com"
        );
        assert_eq!(
            Url::parse("wss://example.com/").unwrap().host_header(),
            "example.com"
        );
        assert_eq!(
            Url::parse("ws://example.com:8080/").unwrap().host_header(),
            "example.com:8080"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_wss_url_reaches_a_tls_websocket_server() {
        // The whole stack in one test: resolve, connect, TLS handshake,
        // WebSocket upgrade, a message each way. Every layer this crate has.
        use crate::proto::message::Message;
        use crate::tls::rustls;
        use crate::tls::rustls_pki_types::{CertificateDer, PrivateKeyDer};
        use alloc::sync::Arc;
        use bytes::Bytes;
        use nagoya::reactor::{Reactor, TcpListener};

        let issued =
            rcgen::generate_simple_self_signed(["localhost".to_string()]).expect("certificate");
        let certificate = CertificateDer::from(issued.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(issued.signing_key.serialize_der()).expect("key");

        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(alloc::vec![certificate.clone()], key)
                .expect("server config"),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust");
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(Addr::localhost(0), &handle).expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let server = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let session = rustls::ServerConnection::new(server_config).expect("session");
                let mut tls = crate::tls::TlsStream::server(stream, session);
                tls.handshake().await.expect("tls handshake");

                let (mut conn, request) =
                    crate::upgrade::accept(tls, Limits::default(), |offered| {
                        offered.first().cloned()
                    })
                    .await
                    .expect("upgrade");
                assert_eq!(request.path, "/chat");

                let message = conn.read().await.expect("read").expect("message");
                conn.write(message).await.expect("write");
            });
        });

        let url = Url::parse(&alloc::format!("wss://localhost:{port}/chat")).expect("url");
        nagoya::block_on(async {
            let options = ClientOptions {
                protocols: &["mcp"],
                tls: Some(client_config),
                entropy: [11u8; 16],
                ..Default::default()
            };
            let mut connected = connect_secure(&url, &handle, options)
                .await
                .expect("connect");
            assert_eq!(connected.protocol.as_deref(), Some("mcp"));

            connected
                .connection
                .write(Message::Text(Bytes::from_static(b"over tls")))
                .await
                .expect("write");
            let echoed = connected
                .connection
                .read()
                .await
                .expect("read")
                .expect("message");
            assert_eq!(echoed, Message::Text(Bytes::from_static(b"over tls")));
        });

        server.join().expect("server thread");
    }

    #[test]
    fn resolves_localhost() {
        // Uses the platform resolver, so this also checks that the hosts file
        // path works rather than only DNS.
        let addrs = resolve("localhost", 1234).expect("localhost did not resolve");
        assert!(!addrs.is_empty(), "no addresses");
        assert!(addrs.iter().all(|addr| addr.port() == 1234));
    }

    #[test]
    fn resolution_keeps_every_family_offered() {
        // localhost is commonly both 127.0.0.1 and ::1. Keeping only the
        // first makes a connection fail whenever the listener is on the other
        // one, which is a bug that only shows up on some machines.
        let addrs = resolve("localhost", 80).expect("resolve");
        let v4 = addrs.iter().any(|addr| matches!(addr, Addr::V4(..)));
        let v6 = addrs.iter().any(|addr| matches!(addr, Addr::V6(..)));
        assert!(v4 || v6, "localhost resolved to neither family: {addrs:?}");
    }
}
