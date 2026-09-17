//! Errors from the kernel, without `std::io`.
//!
//! An `Errno` is what every syscall in this crate actually returns. Wrapping
//! it in `std::io::Error` means an allocation-capable type carrying a code,
//! and more importantly means `WouldBlock` arrives as an error variant when it
//! is the ordinary state of a reactive socket rather than a failure.
//!
//! So the code is kept as a code, and the question a reactor actually asks -
//! is this "not ready" or a real failure - is a method rather than a match on
//! an error kind.

// Reading this thread's errno is a dereference of a pointer libc hands out.
#![allow(unsafe_code)]

/// A raw platform error number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

/// The result of a syscall.
pub type Result<T> = core::result::Result<T, Errno>;

impl Errno {
    /// The error the last failing syscall left behind.
    pub fn last() -> Self {
        // SAFETY: `__errno_location`/`__error` return a pointer to this
        // thread's errno, valid for the life of the thread.
        #[cfg(target_os = "linux")]
        let value = unsafe { *libc::__errno_location() };
        #[cfg(not(target_os = "linux"))]
        let value = unsafe { *libc::__error() };
        Self(value)
    }

    /// Whether this means "nothing to do yet" rather than a failure.
    ///
    /// POSIX allows `EAGAIN` and `EWOULDBLOCK` to differ and does not say
    /// which a given call returns, so both are checked.
    #[inline]
    pub fn would_block(self) -> bool {
        self.0 == libc::EAGAIN || self.0 == libc::EWOULDBLOCK
    }

    /// Whether the call was interrupted by a signal and should be retried.
    #[inline]
    pub fn interrupted(self) -> bool {
        self.0 == libc::EINTR
    }

    /// Whether the peer is gone.
    #[inline]
    pub fn disconnected(self) -> bool {
        matches!(
            self.0,
            libc::EPIPE | libc::ECONNRESET | libc::ENOTCONN | libc::ESHUTDOWN
        )
    }

    /// Whether an `accept` failure concerns only the connection being accepted.
    ///
    /// A peer that resets between the readiness notification and the accept
    /// produces one of these. Failing the listener on one would let any client
    /// take a server down by connecting and immediately resetting.
    #[inline]
    pub fn transient_accept(self) -> bool {
        matches!(
            self.0,
            libc::ECONNABORTED | libc::ECONNRESET | libc::ECONNREFUSED
        )
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "errno {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Errno {}

#[cfg(feature = "std")]
impl From<Errno> for std::io::Error {
    fn from(value: Errno) -> Self {
        Self::from_raw_os_error(value.0)
    }
}
