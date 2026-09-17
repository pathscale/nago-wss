//! TLS, for `wss://`.
//!
//! # Why this is only a re-export
//!
//! The loop that drives rustls has nothing to do with WebSockets: it needs
//! somewhere to put ciphertext and somewhere to get it from, which is what a
//! byte stream already is. Keeping it here meant a WebSocket crate owning a
//! general piece of TLS plumbing that anything else would have had to depend
//! on a WebSocket crate to reuse.
//!
//! It lives in [`nago_rustls`] now, and both crates take the byte stream
//! trait from nagoya, which sits below either of them. So there is nothing to
//! bridge: a [`TlsSession`] already implements the trait this crate's
//! [`Connection`](crate::conn::Connection) consumes, which is what lets a
//! WebSocket run over TLS without knowing it has.
//!
//! This module re-exports the pieces so a caller writes
//! `nago_wss::tls::TlsStream` and does not have to name a matching rustls
//! version of its own.

pub use nago_rustls::TlsSession;

/// The previous name for [`TlsSession`], kept so existing callers compile.
pub type TlsStream<S> = TlsSession<S>;

#[cfg(feature = "webpki-roots")]
pub use nago_rustls::default_client_config;

// The rustls types a caller needs to build a configuration. Re-exported so it
// cannot end up linking a second, incompatible rustls, which is the usual way
// a TLS dependency goes wrong.
pub use nago_rustls::{rustls, rustls_pki_types};

/// A TLS session takes the default fast paths rather than overriding them.
///
/// Neither optimisation applies here. Reading into uninitialised memory is a
/// syscall-level trick and a TLS session's reads come out of rustls' own
/// buffer; a vectored write cannot help either, because the header and the
/// payload are both encrypted into one record regardless.
impl<S: nagoya::io::Stream> crate::stream::StreamExt for TlsSession<S> {}
