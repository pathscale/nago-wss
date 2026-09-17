//! TLS, for `wss://`.
//!
//! # Why this is only a re-export
//!
//! The loop that drives rustls has nothing to do with WebSockets. It needs
//! somewhere to put ciphertext and somewhere to get it from, which is what
//! [`ByteStream`](crate::reactor::bytes::ByteStream) already describes, so
//! keeping it here meant a WebSocket crate owning a general piece of TLS
//! plumbing that anything else would have had to depend on a WebSocket crate
//! to reuse.
//!
//! It lives in [`nago_rustls`] now. This module re-exports it so a caller
//! writes `nago_wss::tls::TlsStream` either way, and so the dependency is
//! visible rather than implied.

pub use nago_rustls::{Errno as TlsErrno, TlsSession};

// Two crates each define what a byte stream is, and they have to agree.
//
// Collapsing to one definition is the obvious tidy-up and it is the wrong
// trade. The trait is needed with `tls` off: a deployment that terminates TLS
// at the edge, which is what the fleet's does, speaks ws:// and still needs
// `Connection`, the upgrade and the socket. Taking the definition from
// nago-rustls would put rustls and its crypto in that build, twelve crates
// including ring, to name two methods. That is the coupling that makes
// tokio-rustls depend on the whole of tokio.
//
// So each crate keeps its own and this bridges them, which costs about thirty
// lines that only exist when `tls` is on. Neither crate can implement the
// other's trait for the other's type, so it has to be written here.
impl nago_rustls::ByteStream for crate::reactor::net::TcpStream {
    async fn read(&mut self, buffer: &mut [u8]) -> nago_rustls::Result<usize> {
        crate::reactor::bytes::ByteStream::read(self, buffer)
            .await
            .map_err(|error| nago_rustls::Errno(error.0))
    }

    async fn write_all(&mut self, buffer: &[u8]) -> nago_rustls::Result<()> {
        crate::reactor::bytes::ByteStream::write_all(self, buffer)
            .await
            .map_err(|error| nago_rustls::Errno(error.0))
    }
}

/// A TLS session carries WebSocket frames, which is the point of the feature.
impl<S> crate::reactor::bytes::ByteStream for TlsSession<S>
where
    S: nago_rustls::ByteStream,
{
    async fn read(&mut self, buffer: &mut [u8]) -> crate::reactor::error::Result<usize> {
        TlsSession::read(self, buffer)
            .await
            .map_err(|error| crate::reactor::error::Errno(error.0))
    }

    async fn write_all(&mut self, buffer: &[u8]) -> crate::reactor::error::Result<()> {
        TlsSession::write_all(self, buffer)
            .await
            .map_err(|error| crate::reactor::error::Errno(error.0))
    }
}

/// The previous name for [`TlsSession`], kept so existing callers compile.
pub type TlsStream<S> = TlsSession<S>;

#[cfg(feature = "webpki-roots")]
pub use nago_rustls::default_client_config;

// The rustls types a caller needs to build a configuration, so it does not
// have to name a matching rustls version of its own. Getting that wrong is
// the usual way a TLS dependency goes bad.
pub use nago_rustls::{rustls, rustls_pki_types};
