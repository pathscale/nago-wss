//! RFC 6455 WebSockets without tokio.
//!
//! # Why this crate exists
//!
//! The fleet speaks WebSocket through `endpoint-libs`, and underneath that sat
//! `tokio-tungstenite`, which drags in the whole tokio runtime for what is, in
//! the end, a framing layer and a reactor. This crate is the replacement: the
//! protocol written against no runtime at all, and the I/O written against
//! [nagoya](https://github.com/pathscale/nagoya).
//!
//! # Shape
//!
//! Two layers, and the boundary between them is the point:
//!
//! * [`proto`] — the sans-io core. Bytes in, frames out, frames in, bytes out.
//!   No I/O, no runtime, no allocator beyond `alloc`. It is `no_std`, it is
//!   exhaustively testable without a socket, and it is the part that has to be
//!   correct.
//! * The connection, where that core meets a socket. It is generic over
//!   [`stream::ByteStream`], so the same code runs over TCP, over TLS, or over
//!   an in-memory pipe in a test.
//!
//! The readiness reactor was written here and now lives in
//! [`nagoya::reactor`], because generational tokens, edge triggered
//! registration and integrating a timer wheel without polling it are the same
//! problem for anything that wants a socket, and none of it was about
//! WebSockets. Nagoya supplies the scheduler, `sync`, `time` and now the
//! sockets; this crate supplies the protocol.
//!
//! # Unsafe
//!
//! One block, in [`client`]: the `getaddrinfo` binding that turns a hostname
//! into addresses. The syscall bindings that used to sit beside it left with
//! the reactor. Resolution has not followed yet only because nagoya has no
//! resolver to follow into, and it is the same kind of thing: anything that
//! connects to a name needs it, and everyone who writes it writes the same
//! dual stack bug.
//!
//! # Only what is used
//!
//! This is not a general-purpose WebSocket library and does not try to be.
//! `permessage-deflate` is not implemented, and the RSV bits are therefore a
//! hard error rather than a negotiation. What the fleet does not use is not
//! here.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
// Denied rather than forbidden, so that exactly one module can opt out and say
// why. Everything but the resolver in `client` is unsafe-free, and `proto`
// forbids it outright.
#![deny(unsafe_code)]

extern crate alloc;

pub mod proto;

pub use proto::{CloseCode, FrameError, Header, OpCode};

/// The transport a connection runs over, and the fast paths a socket has.
#[cfg(feature = "reactor")]
pub mod stream;

/// A live WebSocket connection, where the protocol meets a socket.
#[cfg(feature = "reactor")]
pub mod conn;

/// Performing the opening handshake over a socket.
#[cfg(feature = "reactor")]
pub mod upgrade;

/// TLS, for `wss://`.
#[cfg(feature = "tls")]
pub mod tls;

/// Opening a connection from a URL.
#[cfg(feature = "reactor")]
pub mod client;
