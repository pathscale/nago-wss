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

/// The previous name for [`TlsSession`], kept so existing callers compile.
pub type TlsStream<S> = TlsSession<S>;

#[cfg(feature = "webpki-roots")]
pub use nago_rustls::default_client_config;

// The rustls types a caller needs to build a configuration, so it does not
// have to name a matching rustls version of its own. Getting that wrong is
// the usual way a TLS dependency goes bad.
pub use nago_rustls::{rustls, rustls_pki_types};
