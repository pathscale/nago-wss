//! RFC 6455 conformance, as tests rather than an external suite.
//!
//! # Why not Autobahn
//!
//! Autobahn is the standard conformance suite and it ships as a Docker image
//! driving a live server. That is a container runtime as a dependency for
//! something that is, underneath, a list of byte sequences and the behaviour
//! each one should produce.
//!
//! The behaviour is what matters, so the cases are written directly against
//! the protocol core: no server, no sockets, no runtime. They run with
//! `cargo test`, they name what they check, and a failure points at a line
//! rather than at an HTML report.
//!
//! Numbered after Autobahn's own cases where one matches, so a case here can
//! be read against its published description.

use bytes::Bytes;
use nago_wss::proto::frame::{FrameError, Header};
use nago_wss::proto::mask;
use nago_wss::proto::message::{Assembler, CloseFrame, Limits, Message, ProtocolError};
use nago_wss::proto::opcode::{CloseCode, OpCode};

/// Either layer's rejection, so a case can say which one caught it.
#[derive(Debug, PartialEq, Eq)]
enum Fault {
    Frame(FrameError),
    Protocol(ProtocolError),
}

/// Decode one complete frame and hand it on, as a connection would.
fn feed(assembler: &mut Assembler, wire: &[u8]) -> Result<Option<Message>, Fault> {
    let (header, used) = Header::decode(wire, u64::MAX)
        .map_err(Fault::Frame)?
        .expect("test frames are complete");

    let mut payload = wire[used..used + header.payload_len as usize].to_vec();
    if let Some(key) = header.mask {
        mask::apply(&mut payload, key, 0);
    }

    assembler
        .accept(header.opcode, header.fin, Bytes::from(payload))
        .map_err(Fault::Protocol)
}

/// Build a client frame: masked, as 5.1 requires of a client.
fn frame(opcode: OpCode, fin: bool, payload: &[u8]) -> Vec<u8> {
    let key = [0x37, 0xfa, 0x21, 0x3d];
    let header = Header {
        fin,
        opcode,
        mask: Some(key),
        payload_len: payload.len() as u64,
    };
    let mut head = [0u8; Header::MAX_ENCODED_LEN];
    let used = header.encode(&mut head).expect("encode");

    let mut out = head[..used].to_vec();
    let mut body = payload.to_vec();
    mask::apply(&mut body, key, 0);
    out.extend_from_slice(&body);
    out
}

fn assembler() -> Assembler {
    Assembler::new(Limits::default())
}

// --- 1.x  framing ---------------------------------------------------------

#[test]
fn case_1_1_text_message_echoes() {
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Text, true, b"Hello, world!"))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::from_static(b"Hello, world!")));
}

#[test]
fn case_1_2_binary_message_echoes() {
    let mut a = assembler();
    let payload = [0x00, 0xFF, 0x7F, 0x80];
    let message = feed(&mut a, &frame(OpCode::Binary, true, &payload))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Binary(Bytes::copy_from_slice(&payload)));
}

#[test]
fn an_empty_payload_is_still_a_message() {
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Text, true, b""))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::new()));
}

// --- 2.x  pings and pongs -------------------------------------------------

#[test]
fn case_2_1_ping_payload_is_returned_verbatim() {
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Ping, true, b"payload"))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Ping(Bytes::from_static(b"payload")));
}

#[test]
fn case_2_5_a_fragmented_ping_is_a_protocol_error() {
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Ping, false, b"x")),
        Err(Fault::Frame(FrameError::InvalidControlFrame))
    );
}

#[test]
fn case_2_6_a_control_frame_over_125_bytes_is_a_protocol_error() {
    let mut a = assembler();
    let payload = vec![b'x'; 126];
    assert_eq!(
        feed(&mut a, &frame(OpCode::Ping, true, &payload)),
        Err(Fault::Frame(FrameError::InvalidControlFrame))
    );
}

// --- 3.x and 4.x  reserved bits and opcodes -------------------------------

#[test]
fn case_3_1_a_reserved_bit_is_a_protocol_error() {
    for bit in [0x40u8, 0x20, 0x10] {
        let mut wire = frame(OpCode::Text, true, b"x");
        wire[0] |= bit;
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &wire),
            Err(Fault::Frame(FrameError::ReservedBitSet)),
            "accepted reserved bit {bit:#04x}"
        );
    }
}

#[test]
fn case_4_1_a_reserved_opcode_is_a_protocol_error() {
    for opcode in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
        let mut wire = frame(OpCode::Text, true, b"x");
        wire[0] = 0x80 | opcode;
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &wire),
            Err(Fault::Frame(FrameError::ReservedOpCode(opcode))),
            "accepted reserved opcode {opcode:#x}"
        );
    }
}

// --- 5.x  fragmentation ---------------------------------------------------

#[test]
fn case_5_1_a_fragmented_message_reassembles() {
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, b"frag")).unwrap(),
        None
    );
    let message = feed(&mut a, &frame(OpCode::Continuation, true, b"ment"))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::from_static(b"fragment")));
}

#[test]
fn case_5_6_a_ping_may_interleave_with_fragments() {
    let mut a = assembler();
    a.accept(OpCode::Text, false, Bytes::from_static(b"frag"))
        .unwrap();

    let ping = feed(&mut a, &frame(OpCode::Ping, true, b"mid"))
        .unwrap()
        .unwrap();
    assert_eq!(ping, Message::Ping(Bytes::from_static(b"mid")));

    let message = feed(&mut a, &frame(OpCode::Continuation, true, b"ment"))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::from_static(b"fragment")));
}

#[test]
fn case_5_9_a_continuation_with_nothing_open_is_a_protocol_error() {
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Continuation, true, b"orphan")),
        Err(Fault::Protocol(ProtocolError::UnexpectedContinuation))
    );
}

#[test]
fn case_5_11_a_new_data_frame_during_a_fragment_is_a_protocol_error() {
    let mut a = assembler();
    a.accept(OpCode::Text, false, Bytes::from_static(b"open"))
        .unwrap();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, true, b"other")),
        Err(Fault::Protocol(ProtocolError::InterleavedDataFrame))
    );
}

// --- 6.x  UTF-8 -----------------------------------------------------------

#[test]
fn case_6_1_valid_utf8_passes() {
    let text = "κόσμε";
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Text, true, text.as_bytes()))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::from_static("κόσμε".as_bytes())));
}

#[test]
fn case_6_3_invalid_utf8_fails_the_connection() {
    let cases: [&[u8]; 6] = [
        &[0xC0, 0xAF],
        &[0xE0, 0x80, 0xAF],
        &[0xF0, 0x80, 0x80, 0xAF],
        &[0xED, 0xA0, 0x80],
        &[0xF4, 0x90, 0x80, 0x80],
        &[0xFE],
    ];
    for payload in cases {
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Text, true, payload)),
            Err(Fault::Protocol(ProtocolError::InvalidUtf8)),
            "accepted invalid utf8: {payload:02x?}"
        );
    }
}

#[test]
fn case_6_4_utf8_split_across_fragments_is_judged_whole() {
    let euro = "€".as_bytes();
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, &euro[..1])).unwrap(),
        None
    );
    let message = feed(&mut a, &frame(OpCode::Continuation, true, &euro[1..]))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::from_static("€".as_bytes())));
}

#[test]
fn binary_carries_bytes_text_would_refuse() {
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Binary, true, &[0xC0, 0xAF, 0xFE]))
        .unwrap()
        .unwrap();
    assert_eq!(
        message,
        Message::Binary(Bytes::from_static(&[0xC0, 0xAF, 0xFE]))
    );
}

// --- 7.x  closing ---------------------------------------------------------

#[test]
fn case_7_1_a_close_with_code_and_reason_parses() {
    let mut a = assembler();
    let mut body = 1000u16.to_be_bytes().to_vec();
    body.extend_from_slice(b"going away");
    let message = feed(&mut a, &frame(OpCode::Close, true, &body))
        .unwrap()
        .unwrap();
    assert_eq!(
        message,
        Message::Close(Some(CloseFrame {
            code: CloseCode::NORMAL,
            reason: Bytes::from_static(b"going away"),
        }))
    );
    assert!(a.is_closed());
}

#[test]
fn case_7_3_1_an_empty_close_is_legal() {
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Close, true, b""))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Close(None));
}

#[test]
fn case_7_3_2_a_one_byte_close_is_a_protocol_error() {
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Close, true, &[0x03])),
        Err(Fault::Protocol(ProtocolError::MalformedCloseFrame))
    );
}

#[test]
fn case_7_5_1_a_close_reason_must_be_utf8() {
    let mut a = assembler();
    let mut body = 1000u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0xC0, 0xAF]);
    assert_eq!(
        feed(&mut a, &frame(OpCode::Close, true, &body)),
        Err(Fault::Protocol(ProtocolError::InvalidUtf8))
    );
}

#[test]
fn case_7_9_reserved_close_codes_are_refused() {
    for code in [999u16, 1004, 1005, 1006, 1015, 1016, 2000] {
        let mut a = assembler();
        let body = code.to_be_bytes().to_vec();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Close, true, &body)),
            Err(Fault::Protocol(ProtocolError::InvalidCloseCode)),
            "accepted reserved close code {code}"
        );
    }
}

#[test]
fn case_7_9_application_close_codes_are_accepted() {
    for code in [3000u16, 3999, 4000, 4999] {
        let mut a = assembler();
        let body = code.to_be_bytes().to_vec();
        let message = feed(&mut a, &frame(OpCode::Close, true, &body))
            .unwrap()
            .unwrap();
        assert_eq!(
            message,
            Message::Close(Some(CloseFrame {
                code: CloseCode(code),
                reason: Bytes::new(),
            })),
            "refused application close code {code}"
        );
    }
}

// --- length encoding ------------------------------------------------------

#[test]
fn non_minimal_lengths_are_refused() {
    let cases: [&[u8]; 3] = [
        &[0x81, 0x7E, 0x00, 0x05],
        &[0x81, 0x7F, 0, 0, 0, 0, 0, 0, 0x01, 0x00],
        &[0x81, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0],
    ];
    for wire in cases {
        assert_eq!(
            Header::decode(wire, u64::MAX),
            Err(FrameError::InvalidLength),
            "accepted a non-minimal length: {wire:02x?}"
        );
    }
}

#[test]
fn a_frame_over_the_limit_is_refused_from_its_header() {
    assert_eq!(
        Header::decode(&[0x82, 0x7E, 0x03, 0xE8], 100),
        Err(FrameError::TooLarge)
    );
}

#[test]
fn a_message_reassembled_past_the_limit_is_refused() {
    let mut a = Assembler::new(Limits {
        max_frame: 1024,
        max_message: 8,
    });
    a.accept(OpCode::Binary, false, Bytes::from_static(b"12345"))
        .unwrap();
    assert_eq!(
        a.accept(OpCode::Continuation, true, Bytes::from_static(b"6789")),
        Err(ProtocolError::MessageTooLarge)
    );
}
