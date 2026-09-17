//! Non-blocking TCP over the reactor.
//!
//! # Why `std::net` and not raw syscalls
//!
//! The descriptors come from `std::net::TcpStream` and `TcpListener` rather
//! than from `socket(2)` directly. `std` already carries the address parsing,
//! the dual-stack handling and the platform differences in `connect`, all of
//! which are tedious and none of which are interesting here. What `std` does
//! not have is a way to *wait* without blocking a thread, and that is exactly
//! what the reactor adds. Set the descriptor non-blocking, register it, and the
//! standard type becomes an async one.
//!
//! # Where `std::net`'s interface stops being enough
//!
//! The descriptors come from `std`, but two of its interfaces do not survive
//! contact with a reactor and are bypassed here.
//!
//! `std::io::Read::read` takes `&mut [u8]`, which is initialised memory. The
//! kernel is about to overwrite that memory, so zeroing it first is pure
//! waste, and it is not free: 0.15us per read on a 16 KiB buffer, on every
//! message. [`TcpStream::poll_read_buf`] calls `recv` directly into the
//! uninitialised tail instead.
//!
//! `WouldBlock` as an `io::Error` is the other one. "Not ready" is the normal
//! state of a reactive socket rather than a failure, and routing it through
//! error construction and a `kind()` comparison is the wrong shape for the
//! signal the whole design turns on. That one is absorbed here rather than
//! fixed, since the syscall reports it through `errno` regardless.
//!
//! # The edge triggered contract
//!
//! Every read and write loops until the kernel says `EWOULDBLOCK`, and only
//! then parks a waker. Registering interest without first draining would wait
//! for an edge that has already passed, and the task would hang with data
//! sitting in the socket buffer.

// This module owns the descriptor level calls that `std::io`'s traits cannot
// express, so the crate wide deny is lifted here. Every block names what it
// relies on.
#![allow(unsafe_code)]

use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener as StdListener, TcpStream as StdStream};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::driver::{Handle, Registration};
use super::poller::Interest;

/// A TCP connection that yields to the executor instead of blocking.
#[derive(Debug)]
pub struct TcpStream {
    inner: StdStream,
    registration: Registration,
}

impl TcpStream {
    /// Adopt an already connected socket.
    ///
    /// The socket is put into non-blocking mode and registered for both
    /// directions.
    pub fn from_std(stream: StdStream, handle: &Handle) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        // Nagle interacts badly with a framed protocol: a small frame written
        // on its own waits for an ack that is waiting for more data. Every
        // WebSocket implementation worth using turns it off.
        stream.set_nodelay(true)?;
        let registration = handle.register(stream.as_raw_fd(), Interest::BOTH)?;
        Ok(Self {
            inner: stream,
            registration,
        })
    }

    /// Connect to `addr`.
    ///
    /// The connect itself is performed blocking, because a DNS-resolved connect
    /// is a one-off at session start and making it async would mean owning
    /// resolution too. The socket is non-blocking from the moment it is
    /// connected, which is what the rest of the session needs.
    pub fn connect(addr: SocketAddr, handle: &Handle) -> io::Result<Self> {
        let stream = StdStream::connect(addr)?;
        Self::from_std(stream, handle)
    }

    /// The peer's address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Read straight into a `BytesMut`'s spare capacity.
    ///
    /// The obvious way to fill a growable buffer is to read into a stack array
    /// and copy, and that copies every byte received for no reason. This reads
    /// into the uninitialised tail and then declares how much arrived, so the
    /// bytes land where they are going to be parsed.
    ///
    /// `buffer` must have spare capacity; a full buffer reads nothing and
    /// returns `Ok(0)`, which the caller would misread as end of stream.
    pub fn poll_read_buf(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut bytes::BytesMut,
    ) -> Poll<io::Result<usize>> {
        let spare = buffer.spare_capacity_mut();
        if spare.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let spare_len = spare.len();
        let spare_ptr = spare.as_mut_ptr();
        let filled = buffer.len();

        loop {
            // `recv` into the uninitialised tail. This is the call
            // `std::io::Read` cannot express: its signature demands an
            // initialised slice, so going through it means zeroing memory the
            // kernel is about to overwrite.
            //
            // SAFETY: `spare_ptr` points at `spare_len` bytes of allocated
            // capacity owned by `buffer`, which outlives this call, and `recv`
            // only ever writes within the length it is given. `buffer` is not
            // aliased here: the spare region is beyond its length, so no live
            // reference into the initialised part overlaps it.
            let read = unsafe {
                libc::recv(
                    self.inner.as_raw_fd(),
                    spare_ptr.cast::<libc::c_void>(),
                    spare_len,
                    0,
                )
            };

            if read >= 0 {
                let read = read as usize;
                // SAFETY: `recv` reported writing `read` bytes into the spare
                // capacity, so that many bytes past `filled` are initialised.
                unsafe { buffer.set_len(filled + read) };
                return Poll::Ready(Ok(read));
            }

            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => {
                    self.registration.poll_readable(cx.waker());
                    return Poll::Pending;
                }
                io::ErrorKind::Interrupted => continue,
                _ => return Poll::Ready(Err(error)),
            }
        }
    }

    /// Read into `buffer`, parking `cx`'s waker if the socket would block.
    pub fn poll_read(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.inner.read(buffer) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // Drained: now it is safe to wait for the next edge.
                    self.registration.poll_readable(cx.waker());
                    return Poll::Pending;
                }
                // A signal interrupted the read; the data is still there.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    /// Write from `buffer`, parking `cx`'s waker if the socket would block.
    pub fn poll_write(&mut self, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.inner.write(buffer) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.registration.poll_writable(cx.waker());
                    return Poll::Pending;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    /// Write two slices as one datagram to the kernel, without joining them.
    ///
    /// A WebSocket frame is a short header followed by a payload the caller
    /// already owns. Concatenating them to get one `write` copies the whole
    /// payload for the sake of at most fourteen leading bytes. `writev` hands
    /// the kernel both addresses instead: one syscall, one segment, no copy.
    pub fn poll_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        first: &[u8],
        second: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let slices = [io::IoSlice::new(first), io::IoSlice::new(second)];
            match self.inner.write_vectored(&slices) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.registration.poll_writable(cx.waker());
                    return Poll::Pending;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    /// Write a header and a payload, looping until both are gone.
    ///
    /// The partial-write bookkeeping is the reason this is a method rather
    /// than something the caller assembles: a vectored write can stop anywhere,
    /// including part way through the header, and resuming it correctly means
    /// tracking which slice the remainder falls in.
    pub fn write_all_vectored<'a>(
        &'a mut self,
        header: &'a [u8],
        payload: &'a [u8],
    ) -> WriteAllVectored<'a> {
        WriteAllVectored {
            stream: self,
            header,
            payload,
            written: 0,
        }
    }

    /// Flush, which is a no-op for an unbuffered socket but completes the trait.
    pub fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Read some bytes, as a future.
    pub fn read<'a>(&'a mut self, buffer: &'a mut [u8]) -> Read<'a> {
        Read {
            stream: self,
            buffer,
        }
    }

    /// Read into a `BytesMut`'s spare capacity, as a future.
    ///
    /// See [`Self::poll_read_buf`] for why this exists rather than reading into
    /// an array and copying.
    pub fn read_buf<'a>(&'a mut self, buffer: &'a mut bytes::BytesMut) -> ReadBuf<'a> {
        ReadBuf {
            stream: self,
            buffer,
        }
    }

    /// Write the whole of `buffer`, as a future.
    ///
    /// A partial write is normal on a socket whose send buffer filled, so this
    /// loops rather than returning a count the caller has to handle.
    pub fn write_all<'a>(&'a mut self, buffer: &'a [u8]) -> WriteAll<'a> {
        WriteAll {
            stream: self,
            buffer,
            written: 0,
        }
    }
}

/// The future returned by [`TcpStream::read`].
#[derive(Debug)]
pub struct Read<'a> {
    stream: &'a mut TcpStream,
    buffer: &'a mut [u8],
}

impl core::future::Future for Read<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.stream.poll_read(cx, this.buffer)
    }
}

/// The future returned by [`TcpStream::write_all_vectored`].
#[derive(Debug)]
pub struct WriteAllVectored<'a> {
    stream: &'a mut TcpStream,
    header: &'a [u8],
    payload: &'a [u8],
    /// Bytes of `header + payload` already accepted by the socket.
    written: usize,
}

impl core::future::Future for WriteAllVectored<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let total = this.header.len() + this.payload.len();

        while this.written < total {
            // Where the remainder starts. Once the header is fully out the
            // first slice is empty and this degenerates to a plain write of
            // what is left of the payload.
            let (first, second) = if this.written < this.header.len() {
                (&this.header[this.written..], this.payload)
            } else {
                (&[][..], &this.payload[this.written - this.header.len()..])
            };

            match this.stream.poll_write_vectored(cx, first, second) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "socket accepted no bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.written += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// The future returned by [`TcpStream::read_buf`].
#[derive(Debug)]
pub struct ReadBuf<'a> {
    stream: &'a mut TcpStream,
    buffer: &'a mut bytes::BytesMut,
}

impl core::future::Future for ReadBuf<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.stream.poll_read_buf(cx, this.buffer)
    }
}

/// The future returned by [`TcpStream::write_all`].
#[derive(Debug)]
pub struct WriteAll<'a> {
    stream: &'a mut TcpStream,
    buffer: &'a [u8],
    written: usize,
}

impl core::future::Future for WriteAll<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        while this.written < this.buffer.len() {
            match this.stream.poll_write(cx, &this.buffer[this.written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "socket accepted no bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.written += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// A TCP listener that yields instead of blocking on `accept`.
#[derive(Debug)]
pub struct TcpListener {
    inner: StdListener,
    registration: Registration,
    handle: Handle,
}

impl TcpListener {
    /// Bind to `addr` and register for incoming connections.
    pub fn bind(addr: SocketAddr, handle: &Handle) -> io::Result<Self> {
        let listener = StdListener::bind(addr)?;
        Self::from_std(listener, handle)
    }

    /// Adopt an already bound listener.
    pub fn from_std(listener: StdListener, handle: &Handle) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        let registration = handle.register(listener.as_raw_fd(), Interest::READABLE)?;
        Ok(Self {
            inner: listener,
            registration,
            handle: handle.clone(),
        })
    }

    /// The address this listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Accept one connection, parking `cx`'s waker if none is waiting.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        loop {
            match self.inner.accept() {
                Ok((stream, addr)) => {
                    return Poll::Ready(
                        TcpStream::from_std(stream, &self.handle).map(|stream| (stream, addr)),
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.registration.poll_readable(cx.waker());
                    return Poll::Pending;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // A connection that died between the readiness event and the
                // accept is not this listener's problem: drop it and look for
                // the next one rather than failing the accept loop.
                Err(error) if is_transient_accept_error(&error) => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    /// Accept one connection, as a future.
    pub fn accept(&self) -> Accept<'_> {
        Accept { listener: self }
    }
}

/// Whether an `accept` error concerns only the connection being accepted.
///
/// These arrive when the peer resets between the readiness notification and the
/// accept call. Failing the whole listener on one of them would let any client
/// take the server down by connecting and immediately resetting.
fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    )
}

/// The future returned by [`TcpListener::accept`].
#[derive(Debug)]
pub struct Accept<'a> {
    listener: &'a TcpListener,
}

impl core::future::Future for Accept<'_> {
    type Output = io::Result<(TcpStream, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.listener.poll_accept(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reactor::Reactor;
    use std::net::{IpAddr, Ipv4Addr};

    fn local() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn a_connection_round_trips_through_the_reactor() {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();

        let listener = TcpListener::bind(local(), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        // The client runs on another thread so the accept below has something
        // to accept. Both sides go through the reactor.
        let client_handle = handle.clone();
        let client = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let mut stream = TcpStream::connect(addr, &client_handle).expect("connect");
                stream.write_all(b"ping").await.expect("write");
                let mut buffer = [0u8; 4];
                stream.read(&mut buffer).await.expect("read");
                buffer
            })
        });

        let echoed = nagoya::block_on(async {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 4];
            let read = stream.read(&mut buffer).await.expect("read");
            assert_eq!(read, 4, "short read");
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").await.expect("write");
            buffer
        });
        assert_eq!(&echoed, b"ping");

        let received = client.join().expect("client thread");
        assert_eq!(&received, b"pong", "client did not receive the reply");
    }

    #[test]
    fn a_large_write_completes_across_multiple_wakeups() {
        // Bigger than any socket send buffer, so the write necessarily blocks
        // partway and has to be resumed by a writability wakeup. This is the
        // path a naive write_all gets wrong.
        const SIZE: usize = 4 * 1024 * 1024;

        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(local(), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let client_handle = handle.clone();
        let client = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let mut stream = TcpStream::connect(addr, &client_handle).expect("connect");
                let payload = alloc::vec![0xABu8; SIZE];
                stream.write_all(&payload).await.expect("write");
            })
        });

        let total = nagoya::block_on(async {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = alloc::vec![0u8; 64 * 1024];
            let mut total = 0usize;
            while total < SIZE {
                let read = stream.read(&mut buffer).await.expect("read");
                if read == 0 {
                    break;
                }
                assert!(
                    buffer[..read].iter().all(|byte| *byte == 0xAB),
                    "payload corrupted in transit"
                );
                total += read;
            }
            total
        });

        client.join().expect("client thread");
        assert_eq!(total, SIZE, "did not receive the whole payload");
    }

    #[test]
    fn a_closed_peer_reads_zero() {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(local(), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let client = std::thread::spawn(move || {
            // Connect and drop immediately.
            let _ = StdStream::connect(addr).expect("connect");
        });

        let read = nagoya::block_on(async {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 16];
            stream.read(&mut buffer).await.expect("read")
        });

        client.join().expect("client thread");
        assert_eq!(read, 0, "a hung up peer should read zero");
    }
}
