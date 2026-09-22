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
//! None. The `getaddrinfo` binding that used to live in [`client`] moved to
//! `nagoya::reactor::resolve` with the rest of name resolution. A second copy
//! here is how the dual-stack bug comes back: take the first address, and
//! `localhost` fails whenever that first address is the family the listener
//! is not on.
//!
//! # Only what is used
//!
//! This is not a general-purpose WebSocket library and does not try to be.
//! `permessage-deflate` is not implemented, and the RSV bits are therefore a
//! hard error rather than a negotiation. What the fleet does not use is not
//! here.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
// The resolver used to be the one module allowed to opt out. It moved to
// nagoya, and `proto` forbids unsafe on its own as well.
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
