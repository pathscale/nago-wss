//! The sans-io protocol core: RFC 6455 with no I/O in it at all.
//!
//! Nothing in this module reads, writes, sleeps or spawns. It turns bytes into
//! frames and frames into bytes, and the caller decides where those bytes come
//! from. That is what lets the same code serve a kqueue reactor, a TLS session,
//! an in-memory duplex pipe and a fuzz harness without a feature flag between
//! them.
//!
//! # Cost
//!
//! The split is a compile-time seam, not a dynamic one: there are no trait
//! objects and no allocation per frame on either path, so a reactor calling
//! into this pays nothing for the layering.

// The protocol core keeps the stronger guarantee the crate root relaxes: there
// is no reason to touch raw memory to parse a frame, so nothing here may.
#![forbid(unsafe_code)]

pub mod frame;
pub mod mask;
pub mod opcode;

pub use frame::{FrameError, Header, Incomplete};
pub use mask::Mask;
pub use message::{Assembler, CloseFrame, Limits, Message, ProtocolError};
pub use opcode::{CloseCode, OpCode};

pub mod message;
pub mod handshake;
