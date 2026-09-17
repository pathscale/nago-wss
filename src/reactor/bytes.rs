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
#[allow(async_fn_in_trait)]
pub trait ByteStream {
    /// Read into `buffer`, returning zero at end of stream.
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize>;

    /// Write all of `buffer`.
    async fn write_all(&mut self, buffer: &[u8]) -> Result<()>;

    /// Read into a `BytesMut`'s spare capacity.
    ///
    /// A socket can read straight into uninitialised memory, which avoids
    /// zeroing bytes the kernel is about to overwrite. Anything that cannot
    /// gets the default, which reads into a stack buffer and copies: correct,
    /// and the copy is the price of not being a socket.
    async fn read_buf(&mut self, buffer: &mut bytes::BytesMut) -> Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let take = chunk.len().min(buffer.capacity() - buffer.len()).max(1);
        let read = self.read(&mut chunk[..take]).await?;
        buffer.extend_from_slice(&chunk[..read]);
        Ok(read)
    }

    /// Write a header and a payload as one unit, without joining them.
    ///
    /// A WebSocket frame is a short header in front of a payload the caller
    /// already owns, and concatenating them copies the payload for the sake of
    /// at most fourteen bytes. A socket can do better with `writev`, so this
    /// has a default that concatenates and an override that does not.
    async fn write_all_vectored(&mut self, header: &[u8], payload: &[u8]) -> Result<()> {
        let mut joined = alloc::vec::Vec::with_capacity(header.len() + payload.len());
        joined.extend_from_slice(header);
        joined.extend_from_slice(payload);
        self.write_all(&joined).await
    }
}

impl ByteStream for super::net::TcpStream {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        Self::read(self, buffer).await
    }

    async fn write_all(&mut self, buffer: &[u8]) -> Result<()> {
        Self::write_all(self, buffer).await
    }

    async fn write_all_vectored(&mut self, header: &[u8], payload: &[u8]) -> Result<()> {
        // The socket can hand the kernel both addresses, so the payload is
        // never copied.
        Self::write_all_vectored(self, header, payload).await
    }

    async fn read_buf(&mut self, buffer: &mut bytes::BytesMut) -> Result<usize> {
        // Straight into the uninitialised tail; see the method on TcpStream.
        Self::read_buf(self, buffer).await
    }
}
