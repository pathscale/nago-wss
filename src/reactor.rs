//! The I/O side: a readiness reactor and the sockets it drives.
//!
//! Nagoya deliberately ships no I/O driver ("a caller that wants sockets brings
//! its own reactor"), so this is that reactor. Nagoya keeps the scheduler,
//! `sync` and `time`; what follows is the part it declines to own.

pub mod poller;

pub use poller::{Event, Interest, Poller};
