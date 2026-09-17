//! The transport a protocol sits on.
//!
//! # Why this trait is two methods
//!
//! Both things built on top of the reactor - the WebSocket connection and the
//! TLS session - need the same thing from below: somewhere to put bytes and
//! somewhere to get them from. Naming that separately is what lets a
//! WebSocket run over TLS, since a TLS session is itself a byte stream, and
//! what lets either be tested over an in-memory pipe with no socket involved.
//!
//! It is deliberately small. Anything wider would start describing a socket,
//! and then a TLS session would have to pretend to be one.

use super::error::Result;

/// Somewhere to read bytes from and write them to.
///
/// nagoya's, rather than this crate's own. Two crates need it - a TLS session
/// implements it so a protocol can run over one, and this crate consumes it
/// so it need not know whether TLS is underneath - and restating it in each
/// costs every consumer a mechanical impl to make identical definitions
/// agree. nagoya is below both, so it holds the definition.
pub use nagoya::io::{Stream as ByteStream, StreamError};

/// What a failed read or write reports.
pub use nagoya::io::StreamError as Errno;

/// The two things a socket can do better than the general case.
///
/// `ByteStream` is deliberately two methods, which is right for a trait two
/// crates have to agree on. It leaves performance on the floor for a socket
/// though: a read through it fills a stack buffer and copies, and a frame
/// header written through it is concatenated onto its payload.
///
/// So these sit in a second trait with defaults that do the correct slow
/// thing, and `TcpStream` overrides both. A caller writes against
/// `ByteStream` and gets the fast path when the stream underneath has one.
#[allow(async_fn_in_trait)]
pub trait StreamExt: ByteStream {
    /// Read into a `BytesMut`'s spare capacity.
    ///
    /// A socket can read straight into uninitialised memory, which avoids
    /// zeroing bytes the kernel is about to overwrite. The default reads into
    /// a stack buffer and copies: correct, and the copy is the price of not
    /// being a socket.
    async fn read_buf(&mut self, buffer: &mut bytes::BytesMut) -> Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let take = chunk.len().min(buffer.capacity() - buffer.len()).max(1);
        let read = self.read(&mut chunk[..take]).await?;
        buffer.extend_from_slice(&chunk[..read]);
        Ok(read)
    }

    /// Write a header and a payload as one unit, without joining them.
    ///
    /// A frame is a short header in front of a payload the caller already
    /// owns, and concatenating them copies the payload for the sake of at most
    /// fourteen bytes. A socket hands the kernel both addresses instead.
    async fn write_all_vectored(&mut self, header: &[u8], payload: &[u8]) -> Result<()> {
        let mut joined = alloc::vec::Vec::with_capacity(header.len() + payload.len());
        joined.extend_from_slice(header);
        joined.extend_from_slice(payload);
        self.write_all(&joined).await
    }
}

// No blanket impl. Rust has no specialisation, so `impl<S: ByteStream>
// StreamExt for S` would collide with the socket's own, and the socket is the
// entire reason the trait has defaults worth overriding. Each type opts in,
// which is one line for anything happy with the slow path.

impl ByteStream for super::net::TcpStream {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        Self::read(self, buffer).await
    }

    async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        Self::write_all(self, buffer).await
    }
}

/// The socket takes both fast paths.
impl StreamExt for super::net::TcpStream {
    async fn read_buf(&mut self, buffer: &mut bytes::BytesMut) -> Result<usize> {
        // Straight into the uninitialised tail, so nothing is zeroed first.
        Self::read_buf(self, buffer).await
    }

    async fn write_all_vectored(&mut self, header: &[u8], payload: &[u8]) -> Result<()> {
        // Both addresses to the kernel, so the payload is never copied.
        Self::write_all_vectored(self, header, payload).await
    }
}
