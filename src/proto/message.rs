//! Messages: reassembly, validation and the closing handshake.
//!
//! This is the layer above [`frame`](super::frame). It owns the rules that span
//! more than one frame, which is where a WebSocket implementation usually goes
//! wrong: fragmentation sequencing, control frames interleaved into a fragmented
//! message, UTF-8 that straddles a fragment boundary, and the close handshake.
//!
//! Still no I/O. The caller feeds decoded frames in and takes messages out.

use alloc::vec::Vec;
use bytes::Bytes;

use super::opcode::{CloseCode, OpCode};

/// A complete application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A validated UTF-8 payload. Validity is checked during reassembly, so a
    /// consumer may treat the bytes as text without re-scanning them.
    Text(Bytes),
    /// Opaque bytes.
    Binary(Bytes),
    /// A liveness probe. The caller is expected to answer with `Pong`.
    Ping(Bytes),
    /// A reply to a probe.
    Pong(Bytes),
    /// The peer started the closing handshake.
    Close(Option<CloseFrame>),
}

/// The body of a close frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    /// Why the peer closed.
    pub code: CloseCode,
    /// A human-readable reason. Required to be UTF-8, and checked.
    pub reason: Bytes,
}

/// A rule this layer enforces that the frame codec cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// A continuation frame arrived with no fragmented message in progress.
    UnexpectedContinuation,
    /// A new data frame arrived while a fragmented message was still open.
    ///
    /// §5.4: the fragments of one message may only be interleaved with control
    /// frames, never with another data message.
    InterleavedDataFrame,
    /// A text payload was not valid UTF-8.
    InvalidUtf8,
    /// A close frame carried a one-byte body, which cannot hold a status code.
    MalformedCloseFrame,
    /// A close frame carried a status code that must never be sent.
    InvalidCloseCode,
    /// The reassembled message exceeded the configured limit.
    MessageTooLarge,
}

/// How large a message this endpoint will reassemble.
///
/// The frame codec already caps a single frame; this caps their sum, which is
/// the limit that actually matters, because fragmentation otherwise lets a peer
/// send an unbounded message as many small legal frames.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest single frame payload, in bytes.
    pub max_frame: u64,
    /// Largest reassembled message, in bytes.
    pub max_message: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // 16 MiB. Large enough for the RPC payloads the fleet actually sends,
        // small enough that a hostile peer cannot exhaust memory with one
        // message.
        Self {
            max_frame: 16 * 1024 * 1024,
            max_message: 16 * 1024 * 1024,
        }
    }
}

/// Reassembles frames into messages and enforces the cross-frame rules.
///
/// Holds at most one partial message at a time, which is all the protocol
/// permits.
#[derive(Debug)]
pub struct Assembler {
    limits: Limits,
    /// The message being reassembled: its kind, and the bytes so far.
    partial: Option<(OpCode, Vec<u8>)>,
    /// Set once a close frame has been seen in either direction. After this,
    /// data frames are no longer meaningful.
    closed: bool,
}

impl Assembler {
    /// A new assembler with the given limits.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            partial: None,
            closed: false,
        }
    }

    /// The limits this assembler enforces.
    #[inline]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Whether a close frame has been seen.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Feed one decoded frame and its (already unmasked) payload.
    ///
    /// Returns `Some` when the frame completed a message. A non-final fragment
    /// returns `None` with the bytes retained.
    pub fn accept(
        &mut self,
        opcode: OpCode,
        fin: bool,
        payload: Bytes,
    ) -> Result<Option<Message>, ProtocolError> {
        // Control frames never fragment and never join the partial message, so
        // they are handled before any reassembly state is touched. The frame
        // codec has already rejected a fragmented or oversized control frame.
        if opcode.is_control() {
            return self.accept_control(opcode, payload).map(Some);
        }

        match opcode {
            OpCode::Continuation => {
                let Some((kind, buffer)) = self.partial.as_mut() else {
                    return Err(ProtocolError::UnexpectedContinuation);
                };
                if buffer.len().saturating_add(payload.len()) > self.limits.max_message {
                    return Err(ProtocolError::MessageTooLarge);
                }
                buffer.extend_from_slice(&payload);
                if !fin {
                    return Ok(None);
                }
                let kind = *kind;
                // `expect` cannot fire: the `let else` above proved it is Some.
                let (_, buffer) = self.partial.take().expect("partial was just borrowed");
                self.finish(kind, buffer).map(Some)
            }
            OpCode::Text | OpCode::Binary => {
                if self.partial.is_some() {
                    return Err(ProtocolError::InterleavedDataFrame);
                }
                if payload.len() > self.limits.max_message {
                    return Err(ProtocolError::MessageTooLarge);
                }
                if fin {
                    // The whole message arrived in one frame, which is the
                    // common case: hand the payload straight over rather than
                    // copying it through the reassembly buffer.
                    return self.finish_unfragmented(opcode, payload).map(Some);
                }
                self.partial = Some((opcode, payload.to_vec()));
                Ok(None)
            }
            // Control opcodes were routed above.
            OpCode::Close | OpCode::Ping | OpCode::Pong => {
                unreachable!("control opcodes are handled before this match")
            }
        }
    }

    fn accept_control(
        &mut self,
        opcode: OpCode,
        payload: Bytes,
    ) -> Result<Message, ProtocolError> {
        match opcode {
            OpCode::Ping => Ok(Message::Ping(payload)),
            OpCode::Pong => Ok(Message::Pong(payload)),
            OpCode::Close => {
                self.closed = true;
                Ok(Message::Close(parse_close_body(&payload)?))
            }
            _ => unreachable!("not a control opcode"),
        }
    }

    /// Complete a single-frame message without going through the buffer.
    fn finish_unfragmented(
        &mut self,
        kind: OpCode,
        payload: Bytes,
    ) -> Result<Message, ProtocolError> {
        match kind {
            OpCode::Text => {
                if core::str::from_utf8(&payload).is_err() {
                    return Err(ProtocolError::InvalidUtf8);
                }
                Ok(Message::Text(payload))
            }
            OpCode::Binary => Ok(Message::Binary(payload)),
            _ => unreachable!("only data opcodes reach here"),
        }
    }

    /// Complete a reassembled message.
    ///
    /// UTF-8 is validated over the joined bytes rather than per fragment,
    /// because a multi-byte character may legally straddle a fragment boundary:
    /// validating each fragment alone would reject valid messages.
    fn finish(&mut self, kind: OpCode, buffer: Vec<u8>) -> Result<Message, ProtocolError> {
        let payload = Bytes::from(buffer);
        self.finish_unfragmented(kind, payload)
    }
}

/// Parse the body of a close frame.
///
/// An empty body is legal and means "no status given". One byte cannot hold a
/// 16-bit code and is malformed. Anything longer is a code plus a UTF-8 reason.
fn parse_close_body(payload: &Bytes) -> Result<Option<CloseFrame>, ProtocolError> {
    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() == 1 {
        return Err(ProtocolError::MalformedCloseFrame);
    }

    let code = CloseCode(u16::from_be_bytes([payload[0], payload[1]]));
    if !code.is_sendable() {
        return Err(ProtocolError::InvalidCloseCode);
    }

    let reason = payload.slice(2..);
    if core::str::from_utf8(&reason).is_err() {
        return Err(ProtocolError::InvalidUtf8);
    }

    Ok(Some(CloseFrame { code, reason }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assembler() -> Assembler {
        Assembler::new(Limits::default())
    }

    fn bytes(value: &[u8]) -> Bytes {
        Bytes::copy_from_slice(value)
    }

    #[test]
    fn passes_an_unfragmented_text_message_through_without_copying() {
        let mut a = assembler();
        let payload = Bytes::from_static(b"hello");
        let pointer = payload.as_ptr();
        let message = a.accept(OpCode::Text, true, payload).unwrap().unwrap();
        let Message::Text(text) = message else {
            panic!("wrong message kind");
        };
        assert_eq!(&text[..], b"hello");
        // The single-frame path must not route through the reassembly buffer.
        assert_eq!(text.as_ptr(), pointer, "payload was copied");
    }

    #[test]
    fn reassembles_a_fragmented_message() {
        let mut a = assembler();
        assert_eq!(a.accept(OpCode::Text, false, bytes(b"he")).unwrap(), None);
        assert_eq!(
            a.accept(OpCode::Continuation, false, bytes(b"ll")).unwrap(),
            None
        );
        let done = a
            .accept(OpCode::Continuation, true, bytes(b"o"))
            .unwrap()
            .unwrap();
        assert_eq!(done, Message::Text(Bytes::from_static(b"hello")));
    }

    #[test]
    fn accepts_utf8_split_across_a_fragment_boundary() {
        // The euro sign is three bytes; split it so no fragment is valid alone.
        let euro = "€".as_bytes();
        let mut a = assembler();
        assert_eq!(
            a.accept(OpCode::Text, false, bytes(&euro[..1])).unwrap(),
            None
        );
        let done = a
            .accept(OpCode::Continuation, true, bytes(&euro[1..]))
            .unwrap()
            .unwrap();
        assert_eq!(done, Message::Text(Bytes::from_static("€".as_bytes())));
    }

    #[test]
    fn rejects_invalid_utf8_in_text() {
        let mut a = assembler();
        assert_eq!(
            a.accept(OpCode::Text, true, bytes(&[0xFF, 0xFE])),
            Err(ProtocolError::InvalidUtf8)
        );
    }

    #[test]
    fn allows_arbitrary_bytes_in_binary() {
        let mut a = assembler();
        let message = a
            .accept(OpCode::Binary, true, bytes(&[0xFF, 0xFE]))
            .unwrap()
            .unwrap();
        assert_eq!(message, Message::Binary(bytes(&[0xFF, 0xFE])));
    }

    #[test]
    fn control_frames_may_interleave_with_fragments() {
        let mut a = assembler();
        assert_eq!(a.accept(OpCode::Text, false, bytes(b"he")).unwrap(), None);

        // A ping between fragments is legal and must not disturb reassembly.
        let ping = a.accept(OpCode::Ping, true, bytes(b"x")).unwrap().unwrap();
        assert_eq!(ping, Message::Ping(bytes(b"x")));

        let done = a
            .accept(OpCode::Continuation, true, bytes(b"llo"))
            .unwrap()
            .unwrap();
        assert_eq!(done, Message::Text(Bytes::from_static(b"hello")));
    }

    #[test]
    fn rejects_a_continuation_with_nothing_in_progress() {
        let mut a = assembler();
        assert_eq!(
            a.accept(OpCode::Continuation, true, bytes(b"x")),
            Err(ProtocolError::UnexpectedContinuation)
        );
    }

    #[test]
    fn rejects_a_data_frame_interleaved_into_a_fragmented_message() {
        let mut a = assembler();
        a.accept(OpCode::Text, false, bytes(b"he")).unwrap();
        assert_eq!(
            a.accept(OpCode::Text, true, bytes(b"other")),
            Err(ProtocolError::InterleavedDataFrame)
        );
    }

    #[test]
    fn caps_a_message_reassembled_from_many_legal_frames() {
        let limits = Limits {
            max_frame: 1024,
            max_message: 8,
        };
        let mut a = Assembler::new(limits);
        a.accept(OpCode::Binary, false, bytes(b"12345")).unwrap();
        // Each frame is legal on its own; their sum is not.
        assert_eq!(
            a.accept(OpCode::Continuation, true, bytes(b"6789")),
            Err(ProtocolError::MessageTooLarge)
        );
    }

    #[test]
    fn parses_close_bodies() {
        let mut a = assembler();
        // Empty: no status given.
        assert_eq!(
            a.accept(OpCode::Close, true, Bytes::new()).unwrap().unwrap(),
            Message::Close(None)
        );

        let mut a = assembler();
        let mut body = alloc::vec![0x03, 0xE8];
        body.extend_from_slice(b"bye");
        let message = a.accept(OpCode::Close, true, bytes(&body)).unwrap().unwrap();
        assert_eq!(
            message,
            Message::Close(Some(CloseFrame {
                code: CloseCode::NORMAL,
                reason: Bytes::from_static(b"bye"),
            }))
        );
        assert!(a.is_closed(), "close was not recorded");
    }

    #[test]
    fn rejects_malformed_and_illegal_close_bodies() {
        let mut a = assembler();
        assert_eq!(
            a.accept(OpCode::Close, true, bytes(&[0x03])),
            Err(ProtocolError::MalformedCloseFrame)
        );

        // 1005 is observable by an application but must never appear on the wire.
        let mut a = assembler();
        assert_eq!(
            a.accept(OpCode::Close, true, bytes(&[0x03, 0xED])),
            Err(ProtocolError::InvalidCloseCode)
        );

        // A reason that is not UTF-8.
        let mut a = assembler();
        assert_eq!(
            a.accept(OpCode::Close, true, bytes(&[0x03, 0xE8, 0xFF])),
            Err(ProtocolError::InvalidUtf8)
        );
    }

    #[test]
    fn accepts_application_close_codes() {
        let mut a = assembler();
        // 4000-4999 belong to the application and must round trip.
        let message = a
            .accept(OpCode::Close, true, bytes(&[0x0F, 0xA0]))
            .unwrap()
            .unwrap();
        assert_eq!(
            message,
            Message::Close(Some(CloseFrame {
                code: CloseCode(4000),
                reason: Bytes::new(),
            }))
        );
    }
}
