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
//! * The reactor (in progress) — readiness over kqueue/epoll, driving the core.
//!
//! Nagoya deliberately ships no I/O driver ("a caller that wants sockets brings
//! its own reactor"), so the reactor lives here rather than there. Nagoya
//! supplies the scheduler, `sync` and `time`; this crate supplies the sockets.
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
// why. `proto` is unsafe-free and stays that way; the syscall bindings in
// `reactor::poller` cannot be, since calling the kernel is the whole job.
#![deny(unsafe_code)]

extern crate alloc;

pub mod proto;

pub use proto::{CloseCode, FrameError, Header, OpCode};

/// The I/O side. See the module for why the reactor lives here.
#[cfg(feature = "reactor")]
pub mod reactor;

/// A live WebSocket connection, where the protocol meets the reactor.
#[cfg(feature = "reactor")]
pub mod conn;

/// Performing the opening handshake over a socket.
#[cfg(feature = "reactor")]
pub mod upgrade;

/// TLS, for `wss://`.
#[cfg(feature = "tls")]
pub mod tls;
