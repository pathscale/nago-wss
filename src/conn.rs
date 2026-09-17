//! A WebSocket connection: the protocol core driven over a real socket.
//!
//! # What joins here
//!
//! [`proto`](crate::proto) knows the protocol and no I/O. `nagoya::reactor`
//! knows I/O and no protocol. This is the only place the two meet, which is why
//! the seam stayed cheap: everything above deals in
//! [`Message`](crate::proto::message::Message), everything below in bytes, and
//! neither has to know about the other.
//!
//! # Buffering
//!
//! One read buffer per connection, reused across frames. A frame is parsed in
//! place out of it and its payload copied once, into the `Bytes` the message
//! carries. That single copy is what makes the payload reference counted and
//! cheap to hand around afterwards, which is what the endpoint-libs seam wants.
//!
//! The buffer compacts rather than growing without bound: once a frame is
//! consumed the remainder shifts down, so a long-lived connection sending small
//! frames keeps a small buffer.
//!
//! # Why writes are not buffered
//!
//! A frame goes to the socket as soon as it is written. The obvious speedup is
//! to hold frames and flush them together, turning a syscall per message into
//! one per batch, and it does measure faster on a throughput benchmark.
//!
//! It is the wrong trade. A held frame is one the peer cannot see, so the
//! latency of any message comes to depend on what the sender happens to do
//! next. On a request/response connection, which is what the fleet runs, that
//! is a reply sitting in memory waiting for traffic that may never arrive. The
//! failure is not theoretical: the first version of this crate buffered, and
//! the streaming benchmark deadlocked on the spot, a sender holding frames a
//! receiver was already blocked waiting for.
//!
//! So the write itself is immediate. What is avoided instead is the copying:
//! the header goes out as its own iovec alongside the caller's payload, so a
//! frame costs one syscall and no copy of the body at all. A server, which
//! never masks, touches the payload zero times between the caller handing it
//! over and the kernel taking it.

use bytes::{Bytes, BytesMut};

use crate::proto::frame::{FrameError, Header};
use crate::proto::message::{Assembler, Limits, Message, ProtocolError};
use crate::proto::opcode::{CloseCode, OpCode};
use crate::proto::{mask, message::CloseFrame};
use crate::stream::Errno;
use crate::stream::{ByteStream, StreamExt};
#[cfg(test)]
use nagoya::reactor::Addr;

/// Which side of the connection this is.
///
/// It decides masking: RFC 6455 §5.1 requires a client to mask every frame it
/// sends and a server to mask none, and requires each to reject the other's
/// mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The connecting side. Masks what it sends.
    Client,
    /// The accepting side. Never masks.
    Server,
}

/// Anything that can go wrong on a live connection.
#[derive(Debug)]
pub enum Error {
    /// The transport failed.
    Io(Errno),
    /// A frame could not be decoded.
    Frame(FrameError),
    /// A rule spanning frames was broken.
    Protocol(ProtocolError),
    /// The peer masked when it should not have, or did not when it should.
    ///
    /// §5.1: a server must close on an unmasked client frame, and a client must
    /// close on a masked server frame. Tolerating either hides a broken peer.
    MaskingViolation,
    /// The peer closed the connection without a closing handshake.
    UnexpectedEof,
    /// The opening handshake failed.
    Upgrade(crate::proto::handshake::UpgradeError),
    /// The URL could not be used.
    Url(&'static str),
}

impl Error {
    /// The close code this failure should be reported to the peer with.
    ///
    /// §7.4.1 gives each class of failure a code, and a peer that gets the
    /// right one learns what it did wrong rather than just finding the socket
    /// gone. This is the mapping, in one place, so a server does not have to
    /// invent it: anything that broke the protocol is 1002, a payload that was
    /// the wrong shape for its opcode is 1007, and something simply too big is
    /// 1009.
    ///
    /// `None` means there is no one left to tell: the transport failed, the
    /// peer vanished, or the connection was never established.
    pub fn close_code(&self) -> Option<CloseCode> {
        match self {
            Self::Frame(FrameError::TooLarge) => Some(CloseCode::TOO_LARGE),
            Self::Frame(_) | Self::MaskingViolation => Some(CloseCode::PROTOCOL),
            Self::Protocol(ProtocolError::InvalidUtf8) => Some(CloseCode::INVALID_PAYLOAD),
            Self::Protocol(ProtocolError::MessageTooLarge) => Some(CloseCode::TOO_LARGE),
            Self::Protocol(_) => Some(CloseCode::PROTOCOL),
            Self::Io(_) | Self::UnexpectedEof | Self::Upgrade(_) | Self::Url(_) => None,
        }
    }
}

impl From<Errno> for Error {
    fn from(value: Errno) -> Self {
        Self::Io(value)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io: {error}"),
            Self::Frame(error) => write!(formatter, "frame: {error:?}"),
            Self::Protocol(error) => write!(formatter, "protocol: {error:?}"),
            Self::MaskingViolation => formatter.write_str("masking rule violated"),
            Self::UnexpectedEof => formatter.write_str("closed without a handshake"),
            Self::Upgrade(error) => write!(formatter, "upgrade: {error:?}"),
            Self::Url(reason) => write!(formatter, "url: {reason}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// How much spare capacity to keep available for each read.
///
/// The buffer is allocated at this size once, rather than starting smaller and
/// growing: a connection that started at 8 KiB and then reserved 16 KiB on its
/// first read paid an allocation and a copy on the first message of every
/// connection, which is exactly the message a latency measurement sees.
const READ_CHUNK: usize = 16 * 1024;

/// A live WebSocket connection.
#[derive(Debug)]
pub struct Connection<S = nagoya::reactor::TcpStream> {
    stream: S,
    role: Role,
    assembler: Assembler,
    /// Unparsed bytes from the socket.
    read_buffer: BytesMut,
    /// Scratch for encoding one frame, reused across frames.
    ///
    /// Not a write buffer: it holds exactly one frame and the write that
    /// follows empties it. It exists so framing does not allocate per message,
    /// and it delays nothing.
    scratch: Vec<u8>,
    /// Frames waiting to go out as one write, for [`Self::write_all`] only.
    ///
    /// Empty except inside that call. Nothing is ever held here across an
    /// await for anything the peer might send, which is what separates this
    /// from a write buffer: see that method for why that distinction is the
    /// whole design.
    outgoing: Vec<u8>,
    /// The next masking key to use, for a client. See [`Self::next_mask`].
    mask_state: u64,
    /// Set once a close frame has been sent, so it is not sent twice.
    close_sent: bool,
}

/// The most coalescing buffer a connection keeps between calls.
///
/// A batch larger than this still goes out in one write; only the capacity is
/// handed back afterwards. Eight kilobytes is a hundred and sixteen small
/// frames, far beyond the four where the syscall stops dominating, and it is a
/// fifth of what one connection already costs.
const MAX_RETAINED_OUTGOING: usize = 8 * 1024;

impl<S: ByteStream + StreamExt> Connection<S> {
    /// Wrap an already upgraded stream.
    ///
    /// The handshake is the caller's business; by the time a `Connection`
    /// exists, both sides have agreed to speak WebSocket.
    pub fn new(stream: S, role: Role, limits: Limits) -> Self {
        Self::with_buffered(stream, role, limits, BytesMut::new())
    }

    /// Wrap a stream, carrying bytes already read past the handshake.
    ///
    /// A client often sends its first frames in the same segment as its
    /// upgrade request, so those bytes have already left the socket by the
    /// time the handshake finishes. Dropping them would lose the first message
    /// of every fast client.
    pub fn with_buffered(stream: S, role: Role, limits: Limits, buffered: BytesMut) -> Self {
        let mut read_buffer = BytesMut::with_capacity(READ_CHUNK);
        read_buffer.extend_from_slice(&buffered);
        Self {
            stream,
            role,
            assembler: Assembler::new(limits),
            read_buffer,
            // Sized for a typical RPC payload. A larger message grows this
            // once and then keeps it, and only a client ever uses it at all,
            // since a server writes its payload without copying.
            scratch: Vec::with_capacity(4 * 1024),
            // Four small frames, which is where the syscall stops dominating:
            // measured 514k messages a second unbuffered, 2.5M coalescing
            // four. Past that the curve flattens, so this is the smallest
            // buffer that solves the problem rather than the largest that
            // helps. It grows if a caller writes larger frames in a batch.
            outgoing: Vec::with_capacity(512),
            mask_state: seed_from(&stream_seed()),
            close_sent: false,
        }
    }

    /// The role this side is playing.
    #[inline]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Read the next message, waiting for it to arrive.
    ///
    /// Returns `Ok(None)` when the peer closed cleanly after a close handshake.
    pub async fn read(&mut self) -> Result<Option<Message>, Error> {
        loop {
            // Try to satisfy the request from what is already buffered before
            // going back to the socket: a single read often carries several
            // frames, and returning to the reactor between them would be a
            // syscall per message rather than per batch.
            if let Some(message) = self.parse_buffered()? {
                return Ok(Some(message));
            }

            // Read straight into the parse buffer's spare capacity rather
            // than into an array and then copying: the copy would touch every
            // byte received, which at 4 KiB messages is most of what the read
            // path does.
            if self.read_buffer.capacity() - self.read_buffer.len() < READ_CHUNK {
                self.read_buffer.reserve(READ_CHUNK);
            }
            let read = self.stream.read_buf(&mut self.read_buffer).await?;
            if read == 0 {
                // A clean close already told us this was coming.
                if self.assembler.is_closed() {
                    return Ok(None);
                }
                return Err(Error::UnexpectedEof);
            }
        }
    }

    /// Try to take one message out of the buffer without touching the socket.
    fn parse_buffered(&mut self) -> Result<Option<Message>, Error> {
        loop {
            let limits = self.assembler.limits();
            let decoded =
                Header::decode(&self.read_buffer, limits.max_frame).map_err(Error::Frame)?;
            let Ok((header, header_len)) = decoded else {
                return Ok(None);
            };

            let total = header_len + header.payload_len as usize;
            if self.read_buffer.len() < total {
                // Reserve the rest up front so the frame lands in one
                // allocation rather than growing the buffer repeatedly.
                self.read_buffer.reserve(total - self.read_buffer.len());
                return Ok(None);
            }

            // §5.1, both directions. Checked before the payload is touched.
            match (self.role, header.mask) {
                (Role::Server, None) | (Role::Client, Some(_)) => {
                    return Err(Error::MaskingViolation);
                }
                _ => {}
            }

            let mut payload = self.read_buffer.split_to(total).split_off(header_len);
            if let Some(key) = header.mask {
                mask::apply(&mut payload, key, 0);
            }

            match self
                .assembler
                .accept(header.opcode, header.fin, payload.freeze())
            {
                Ok(Some(message)) => return Ok(Some(message)),
                // A fragment that did not complete a message: keep going, there
                // may be more already buffered.
                Ok(None) => continue,
                Err(error) => return Err(Error::Protocol(error)),
            }
        }
    }

    /// Send a message.
    pub async fn write(&mut self, message: Message) -> Result<(), Error> {
        let (opcode, payload) = match message {
            Message::Text(payload) => (OpCode::Text, payload),
            Message::Binary(payload) => (OpCode::Binary, payload),
            Message::Ping(payload) => (OpCode::Ping, payload),
            Message::Pong(payload) => (OpCode::Pong, payload),
            Message::Close(frame) => {
                self.close_sent = true;
                (OpCode::Close, encode_close_body(frame))
            }
        };
        self.write_frame(opcode, true, &payload).await
    }

    /// Send several messages, coalescing them into as few writes as possible.
    ///
    /// # Why this is not a write buffer
    ///
    /// A write buffer holds a frame in the hope that another one follows, and
    /// that hope is latency: a lone message waits for company that may never
    /// come. Worse, an earlier attempt here held frames across an await for
    /// the peer and deadlocked outright, because the receiver was blocked
    /// waiting for exactly the bytes the sender was sitting on.
    ///
    /// This holds nothing speculatively. The caller hands over everything it
    /// has, the frames are encoded back to back, and the write happens before
    /// this returns. Nothing is ever retained past the call, so there is no
    /// state a later `read` can deadlock against, and no message is ever
    /// delayed waiting for one that has not been written yet.
    ///
    /// # Why it is worth having
    ///
    /// A `writev` on loopback costs about 3.6us, which is larger than
    /// everything else this crate does per message put together. Sending two
    /// thousand small messages one syscall at a time is two thousand syscalls;
    /// coalescing four of them measured 514k messages a second against 2.5M.
    ///
    /// [`Self::write`] is unchanged and still writes immediately, so a caller
    /// with one message to send pays exactly what it paid before.
    pub async fn write_all<I>(&mut self, messages: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = Message>,
    {
        let mut outgoing = core::mem::take(&mut self.outgoing);
        outgoing.clear();

        let result = self.encode_all(&mut outgoing, messages);

        // Flush whatever was encoded even if a later message failed to encode:
        // the earlier ones are valid frames and the peer is entitled to them.
        let flushed = if outgoing.is_empty() {
            Ok(())
        } else {
            self.stream.write_all(&outgoing).await.map_err(Error::Io)
        };

        // Give back the capacity a large burst grew, rather than keeping the
        // high water mark for the life of the connection. Ten thousand
        // connections that each saw one big batch would otherwise retain the
        // peak forever, which is exactly the memory advantage this crate has
        // over tokio-tungstenite and not worth trading for a reallocation.
        outgoing.clear();
        if outgoing.capacity() > MAX_RETAINED_OUTGOING {
            outgoing.shrink_to(MAX_RETAINED_OUTGOING);
        }
        self.outgoing = outgoing;
        result?;
        flushed
    }

    /// Encode every message into `outgoing`, back to back.
    ///
    /// Separate from the write so a failure partway still flushes what came
    /// before it, and so this stays a plain synchronous loop.
    fn encode_all<I>(&mut self, outgoing: &mut Vec<u8>, messages: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = Message>,
    {
        for message in messages {
            let (opcode, payload) = match message {
                Message::Text(payload) => (OpCode::Text, payload),
                Message::Binary(payload) => (OpCode::Binary, payload),
                Message::Ping(payload) => (OpCode::Ping, payload),
                Message::Pong(payload) => (OpCode::Pong, payload),
                Message::Close(frame) => {
                    self.close_sent = true;
                    (OpCode::Close, encode_close_body(frame))
                }
            };
            self.encode_frame(outgoing, opcode, true, &payload);
        }
        Ok(())
    }

    /// Append one whole frame, header and masked payload, to `outgoing`.
    fn encode_frame(&mut self, outgoing: &mut Vec<u8>, opcode: OpCode, fin: bool, payload: &[u8]) {
        let mask = match self.role {
            Role::Client => Some(self.next_mask()),
            Role::Server => None,
        };
        let header = Header {
            fin,
            opcode,
            mask,
            payload_len: payload.len() as u64,
        };
        let mut header_bytes = [0u8; Header::MAX_ENCODED_LEN];
        let header_len = header
            .encode(&mut header_bytes)
            .expect("MAX_ENCODED_LEN is by definition large enough");

        outgoing.extend_from_slice(&header_bytes[..header_len]);
        let from = outgoing.len();
        outgoing.extend_from_slice(payload);
        if let Some(key) = mask {
            // Masked in place in the buffer, so the payload is copied once
            // rather than once into scratch and again into the buffer.
            mask::apply(&mut outgoing[from..], key, 0);
        }
    }

    /// Answer a ping. The payload must be echoed exactly, per §5.5.2.
    pub async fn pong(&mut self, payload: Bytes) -> Result<(), Error> {
        self.write_frame(OpCode::Pong, true, &payload).await
    }

    /// Start the closing handshake.
    ///
    /// Sending twice is a no-op rather than an error: a connection closing for
    /// two reasons at once is ordinary, and the second close is redundant
    /// rather than wrong.
    pub async fn close(&mut self, frame: Option<CloseFrame>) -> Result<(), Error> {
        if self.close_sent {
            return Ok(());
        }
        self.write(Message::Close(frame)).await
    }

    /// Encode and send one frame.
    async fn write_frame(
        &mut self,
        opcode: OpCode,
        fin: bool,
        payload: &[u8],
    ) -> Result<(), Error> {
        let mask = match self.role {
            Role::Client => Some(self.next_mask()),
            Role::Server => None,
        };

        let header = Header {
            fin,
            opcode,
            mask,
            payload_len: payload.len() as u64,
        };

        // Header and payload go out in one write. Two writes would put a frame
        // header on the wire in its own segment, which with a filled send
        // buffer can leave a peer holding a header and waiting for a body.
        let mut header_bytes = [0u8; Header::MAX_ENCODED_LEN];
        let header_len = header
            .encode(&mut header_bytes)
            .expect("MAX_ENCODED_LEN is by definition large enough");

        match mask {
            // A server never masks, so the payload is already exactly what
            // goes on the wire. Header and body are handed to the kernel as
            // two addresses: one syscall, one segment, and the body is not
            // copied at all.
            None => {
                self.stream
                    .write_all_vectored(&header_bytes[..header_len], payload)
                    .await?;
            }
            // A client must mask, which rewrites every byte, so the payload
            // cannot go out from the caller's buffer. It is masked into the
            // connection's scratch, which is reused across frames rather than
            // allocated per message. The header still rides alongside as its
            // own iovec rather than being prepended.
            Some(key) => {
                let mut scratch = core::mem::take(&mut self.scratch);
                scratch.clear();
                scratch.extend_from_slice(payload);
                mask::apply(&mut scratch, key, 0);

                let result = self
                    .stream
                    .write_all_vectored(&header_bytes[..header_len], &scratch)
                    .await;
                self.scratch = scratch;
                result?;
            }
        }
        Ok(())
    }

    /// The next masking key.
    ///
    /// §5.3 wants a value the peer cannot predict, to stop a client being used
    /// to inject chosen bytes into a proxy that misparses the stream. This is a
    /// SplitMix64 over a seed taken from the address space and the clock, which
    /// is unpredictable to a remote peer without pulling in a CSPRNG for a
    /// value that is not a secret and is sent in cleartext in every frame.
    fn next_mask(&mut self) -> [u8; 4] {
        self.mask_state = self.mask_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.mask_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z as u32).to_ne_bytes()
    }
}

/// A seed for the masking sequence.
fn stream_seed() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos() as u64);
    // The address of a stack local varies with ASLR between processes, which
    // the clock alone does not give on a machine where two processes start in
    // the same nanosecond.
    let local = 0u8;
    let address = core::ptr::addr_of!(local) as u64;
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&nanos.to_ne_bytes());
    out[8..].copy_from_slice(&address.to_ne_bytes());
    out
}

fn seed_from(bytes: &[u8; 16]) -> u64 {
    let mut first = [0u8; 8];
    let mut second = [0u8; 8];
    first.copy_from_slice(&bytes[..8]);
    second.copy_from_slice(&bytes[8..]);
    u64::from_ne_bytes(first) ^ u64::from_ne_bytes(second)
}

/// Encode a close frame body: a code then a reason, or nothing at all.
fn encode_close_body(frame: Option<CloseFrame>) -> Bytes {
    let Some(frame) = frame else {
        return Bytes::new();
    };
    // A code that must never be sent is replaced rather than transmitted: the
    // caller asking for it is a bug, but putting it on the wire would make the
    // peer close on us for a protocol violation we introduced.
    let code = if frame.code.is_sendable() {
        frame.code
    } else {
        CloseCode::INTERNAL_ERROR
    };
    let mut out = Vec::with_capacity(2 + frame.reason.len());
    out.extend_from_slice(&code.0.to_be_bytes());
    out.extend_from_slice(&frame.reason);
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nagoya::reactor::{Reactor, TcpListener};

    /// `write_all` must deliver every message, and retain nothing.
    ///
    /// The retaining half is the point. An earlier attempt at coalescing held
    /// frames past the call and deadlocked: the receiver blocked waiting for
    /// bytes the sender was still sitting on. Asserting the buffer is empty
    /// afterwards is what stops that being reintroduced.
    #[test]
    fn write_all_delivers_everything_and_keeps_nothing() {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(local(), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let mut conn = Connection::new(stream, Role::Server, Limits::default());
                let mut seen = Vec::new();
                for _ in 0..4 {
                    seen.push(conn.read().await.expect("read").expect("message"));
                }
                tx.send(seen).expect("signal");
            });
        });

        let client_handle = handle.clone();
        nagoya::block_on(async move {
            let stream = nagoya::reactor::TcpStream::connect(addr, &client_handle)
                .await
                .expect("connect");
            let mut conn = Connection::new(stream, Role::Client, Limits::default());
            conn.write_all([
                Message::Text(Bytes::from_static(b"one")),
                Message::Binary(Bytes::from_static(&[0xFF, 0x00])),
                Message::Text(Bytes::from_static(b"three")),
                Message::Ping(Bytes::from_static(b"p")),
            ])
            .await
            .expect("write_all");

            assert!(
                conn.outgoing.is_empty(),
                "write_all retained {} bytes past the call",
                conn.outgoing.len()
            );
        });

        let seen = rx.recv().expect("messages");
        server.join().expect("server");
        assert_eq!(
            seen,
            vec![
                Message::Text(Bytes::from_static(b"one")),
                Message::Binary(Bytes::from_static(&[0xFF, 0x00])),
                Message::Text(Bytes::from_static(b"three")),
                Message::Ping(Bytes::from_static(b"p")),
            ]
        );
    }

    /// Coalesced frames must be masked exactly as individual ones are.
    ///
    /// Masking happens in place in the shared buffer here rather than in the
    /// per frame scratch, and each frame takes a fresh key, so an off by one
    /// in the offset would corrupt every frame after the first.
    #[test]
    fn coalesced_frames_are_masked_per_frame() {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(local(), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let mut conn = Connection::new(stream, Role::Server, Limits::default());
                let mut seen = Vec::new();
                for _ in 0..8 {
                    seen.push(conn.read().await.expect("read").expect("message"));
                }
                tx.send(seen).expect("signal");
            });
        });

        let client_handle = handle.clone();
        let sent: Vec<Message> = (0..8u8)
            .map(|i| Message::Binary(Bytes::from(alloc::vec![i; 40 + i as usize])))
            .collect();
        let expected = sent.clone();

        nagoya::block_on(async move {
            let stream = nagoya::reactor::TcpStream::connect(addr, &client_handle)
                .await
                .expect("connect");
            let mut conn = Connection::new(stream, Role::Client, Limits::default());
            conn.write_all(sent).await.expect("write_all");
        });

        let seen = rx.recv().expect("messages");
        server.join().expect("server");
        assert_eq!(seen, expected, "a coalesced frame was masked wrongly");
    }

    #[test]
    fn every_failure_reports_the_code_the_rfc_gives_it() {
        // §7.4.1. Getting one of these wrong tells a peer the wrong thing
        // about what it did, which is worse than saying nothing.
        let cases: &[(Error, Option<CloseCode>)] = &[
            (
                Error::Frame(FrameError::ReservedBitSet),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Frame(FrameError::ReservedOpCode(0x3)),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Frame(FrameError::InvalidControlFrame),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Frame(FrameError::InvalidLength),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Frame(FrameError::TooLarge),
                Some(CloseCode::TOO_LARGE),
            ),
            (Error::MaskingViolation, Some(CloseCode::PROTOCOL)),
            (
                Error::Protocol(ProtocolError::UnexpectedContinuation),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Protocol(ProtocolError::InterleavedDataFrame),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Protocol(ProtocolError::MalformedCloseFrame),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Protocol(ProtocolError::InvalidCloseCode),
                Some(CloseCode::PROTOCOL),
            ),
            (
                Error::Protocol(ProtocolError::InvalidUtf8),
                Some(CloseCode::INVALID_PAYLOAD),
            ),
            (
                Error::Protocol(ProtocolError::MessageTooLarge),
                Some(CloseCode::TOO_LARGE),
            ),
            // Nobody left to tell.
            (Error::UnexpectedEof, None),
            (Error::Url("bad scheme"), None),
        ];

        for (error, expected) in cases {
            assert_eq!(
                error.close_code(),
                *expected,
                "{error} reported the wrong close code"
            );
        }
    }

    /// Whatever code is reported must itself be legal to put on the wire,
    /// or reporting it is a second protocol violation.
    #[test]
    fn a_reported_close_code_may_actually_be_sent() {
        for code in [
            CloseCode::PROTOCOL,
            CloseCode::INVALID_PAYLOAD,
            CloseCode::TOO_LARGE,
        ] {
            assert!(code.is_sendable(), "{code:?} cannot be sent");
        }
    }
    /// Port zero: the kernel picks a free one, which `local_addr` reports.
    fn local() -> Addr {
        Addr::localhost(0)
    }

    /// The same address as `std` spells it.
    ///
    /// Several tests below deliberately put a plain `std::net` socket on the
    /// other end: checking that this crate interoperates with an ordinary TCP
    /// stack is worth more than checking it agrees with itself.
    fn std_addr(addr: Addr) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], addr.port()))
    }

    /// A `std` listener, and the address to reach it on.
    fn std_listener() -> (std::net::TcpListener, Addr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        (listener, Addr::localhost(port))
    }

    /// Run a client and a server against each other over real TCP.
    ///
    /// The bodies are given the already wrapped `Connection`, so a test says
    /// what it wants to exchange rather than how to set a socket up.
    fn exchange<S, C>(server: S, client: C)
    where
        S: FnOnce(Connection) + Send + 'static,
        C: FnOnce(Connection) + Send + 'static,
    {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(local(), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let client_handle = handle.clone();
        let client_thread = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let stream = nagoya::reactor::TcpStream::connect(addr, &client_handle)
                    .await
                    .expect("connect");
                client(Connection::new(stream, Role::Client, Limits::default()));
            });
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            server(Connection::new(stream, Role::Server, Limits::default()));
        });

        client_thread.join().expect("client thread");
    }

    #[test]
    fn a_text_message_survives_the_round_trip() {
        exchange(
            |mut server| {
                nagoya::block_on(async move {
                    let message = server.read().await.expect("read").expect("a message");
                    assert_eq!(message, Message::Text(Bytes::from_static(b"hello")));
                    // Echo it back so the client can check the server path too.
                    server.write(message).await.expect("write");
                });
            },
            |mut client| {
                nagoya::block_on(async move {
                    client
                        .write(Message::Text(Bytes::from_static(b"hello")))
                        .await
                        .expect("write");
                    let echoed = client.read().await.expect("read").expect("a message");
                    assert_eq!(echoed, Message::Text(Bytes::from_static(b"hello")));
                });
            },
        );
    }

    #[test]
    fn a_large_binary_message_survives_the_round_trip() {
        // Past the 16 bit length boundary, so the extended header is exercised
        // on the wire rather than only in the codec's own tests, and past a
        // socket buffer so it necessarily spans several reads.
        const SIZE: usize = 300 * 1024;

        exchange(
            |mut server| {
                nagoya::block_on(async move {
                    let message = server.read().await.expect("read").expect("a message");
                    let Message::Binary(payload) = message else {
                        panic!("wrong kind");
                    };
                    assert_eq!(payload.len(), SIZE, "truncated in transit");
                    assert!(
                        payload.iter().all(|byte| *byte == 0x5A),
                        "corrupted in transit"
                    );
                });
            },
            |mut client| {
                nagoya::block_on(async move {
                    let payload = Bytes::from(alloc::vec![0x5Au8; SIZE]);
                    client.write(Message::Binary(payload)).await.expect("write");
                });
            },
        );
    }

    #[test]
    fn several_messages_pipelined_into_one_read_all_arrive() {
        // Three small messages written back to back usually land in a single
        // read. The buffered parse path has to yield all three rather than
        // dropping the tail of the buffer.
        exchange(
            |mut server| {
                nagoya::block_on(async move {
                    for expected in ["one", "two", "three"] {
                        let message = server.read().await.expect("read").expect("a message");
                        assert_eq!(
                            message,
                            Message::Text(Bytes::copy_from_slice(expected.as_bytes()))
                        );
                    }
                });
            },
            |mut client| {
                nagoya::block_on(async move {
                    for text in ["one", "two", "three"] {
                        client
                            .write(Message::Text(Bytes::copy_from_slice(text.as_bytes())))
                            .await
                            .expect("write");
                    }
                });
            },
        );
    }

    #[test]
    fn a_ping_is_answered_with_the_same_payload() {
        exchange(
            |mut server| {
                nagoya::block_on(async move {
                    let message = server.read().await.expect("read").expect("a message");
                    let Message::Ping(payload) = message else {
                        panic!("expected a ping");
                    };
                    server.pong(payload).await.expect("pong");
                });
            },
            |mut client| {
                nagoya::block_on(async move {
                    client
                        .write(Message::Ping(Bytes::from_static(b"probe")))
                        .await
                        .expect("write");
                    let reply = client.read().await.expect("read").expect("a message");
                    assert_eq!(reply, Message::Pong(Bytes::from_static(b"probe")));
                });
            },
        );
    }

    #[test]
    fn a_close_handshake_ends_the_stream_cleanly() {
        exchange(
            |mut server| {
                nagoya::block_on(async move {
                    let message = server.read().await.expect("read").expect("a message");
                    assert_eq!(
                        message,
                        Message::Close(Some(CloseFrame {
                            code: CloseCode::NORMAL,
                            reason: Bytes::from_static(b"done"),
                        }))
                    );
                    server.close(None).await.expect("close");
                    // After a close in both directions the stream ends, and
                    // that is a clean end rather than an error.
                    assert_eq!(server.read().await.expect("read"), None);
                });
            },
            |mut client| {
                nagoya::block_on(async move {
                    client
                        .close(Some(CloseFrame {
                            code: CloseCode::NORMAL,
                            reason: Bytes::from_static(b"done"),
                        }))
                        .await
                        .expect("close");
                    let _ = client.read().await;
                });
            },
        );
    }

    #[test]
    fn a_server_rejects_an_unmasked_client_frame() {
        // The client half deliberately writes an unmasked frame, which is what
        // a broken or hostile client does. RFC 6455 says the server must fail
        // the connection rather than accept it.
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let listener = TcpListener::bind(local(), &handle).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let client = std::thread::spawn(move || {
            use std::io::Write as _;
            let mut raw = std::net::TcpStream::connect(std_addr(addr)).expect("connect");
            // FIN + text, length 2, no mask bit.
            raw.write_all(&[0x81, 0x02, b'h', b'i']).expect("write");
            // Hold the connection open so the server sees the frame, not an EOF.
            std::thread::sleep(std::time::Duration::from_millis(200));
        });

        nagoya::block_on(async {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut server = Connection::new(stream, Role::Server, Limits::default());
            match server.read().await {
                Err(Error::MaskingViolation) => {}
                other => panic!("expected a masking violation, got {other:?}"),
            }
        });

        client.join().expect("client thread");
    }

    #[test]
    fn a_client_masks_every_frame_it_sends() {
        // Read the raw bytes a client produces and confirm the mask bit is set
        // and the payload is not on the wire in cleartext.
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let (listener, addr) = std_listener();

        let client_handle = handle.clone();
        let client = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let stream = nagoya::reactor::TcpStream::connect(addr, &client_handle)
                    .await
                    .expect("connect");
                let mut client = Connection::new(stream, Role::Client, Limits::default());
                client
                    .write(Message::Text(Bytes::from_static(b"secret")))
                    .await
                    .expect("write");
            });
        });

        use std::io::Read as _;
        let (mut raw, _) = listener.accept().expect("accept");
        let mut buffer = [0u8; 64];
        let read = raw.read(&mut buffer).expect("read");
        let frame = &buffer[..read];

        assert_eq!(frame[0], 0x81, "not a final text frame");
        assert_eq!(frame[1] & 0x80, 0x80, "client did not set the mask bit");
        assert_eq!(frame[1] & 0x7F, 6, "wrong payload length");
        assert!(
            !frame[6..].windows(6).any(|window| window == b"secret"),
            "payload went out unmasked"
        );

        client.join().expect("client thread");
    }

    #[test]
    fn successive_frames_use_different_masking_keys() {
        // A fixed key would let a peer predict the keystream, which is the
        // thing masking exists to prevent.
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let (listener, addr) = std_listener();

        let client_handle = handle.clone();
        let client = std::thread::spawn(move || {
            nagoya::block_on(async move {
                let stream = nagoya::reactor::TcpStream::connect(addr, &client_handle)
                    .await
                    .expect("connect");
                let mut client = Connection::new(stream, Role::Client, Limits::default());
                for _ in 0..4 {
                    client
                        .write(Message::Text(Bytes::from_static(b"x")))
                        .await
                        .expect("write");
                }
            });
        });

        use std::io::Read as _;
        let (mut raw, _) = listener.accept().expect("accept");
        let mut buffer = alloc::vec![0u8; 256];
        let mut total = 0usize;
        // Four frames of 2 header + 4 mask + 1 payload.
        while total < 4 * 7 {
            let read = raw.read(&mut buffer[total..]).expect("read");
            if read == 0 {
                break;
            }
            total += read;
        }

        let keys: alloc::vec::Vec<[u8; 4]> = (0..4)
            .map(|i| {
                let start = i * 7 + 2;
                [
                    buffer[start],
                    buffer[start + 1],
                    buffer[start + 2],
                    buffer[start + 3],
                ]
            })
            .collect();

        assert!(
            keys.windows(2).any(|pair| pair[0] != pair[1]),
            "every frame used the same masking key: {keys:?}"
        );

        client.join().expect("client thread");
    }
}
