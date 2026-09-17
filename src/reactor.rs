//! The I/O side: a readiness reactor and the sockets it drives.
//!
//! Nagoya deliberately ships no I/O driver ("a caller that wants sockets brings
//! its own reactor"), so this is that reactor. Nagoya keeps the scheduler,
//! `sync` and `time`; what follows is the part it declines to own.

pub mod bytes;
pub mod driver;
pub mod error;
pub mod local;
pub mod net;
pub mod poller;
pub mod socket;
#[cfg(test)]
mod testing;

pub use bytes::ByteStream;
pub use driver::{Handle, Reactor, Registration};
pub use error::{Errno, Result};
pub use local::{block_on, block_on_with};
pub use net::{TcpListener, TcpStream};
pub use poller::{Event, Interest, Poller};
pub use socket::Addr;
