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

// --- 6.x  UTF-8 -----------------------------------------------------------

#[test]
fn case_6_1_valid_utf8_passes() {
    let text = "κόσμε";
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Text, true, text.as_bytes()))
        .unwrap()
        .unwrap();
    assert_eq!(
        message,
        Message::Text(Bytes::from_static("κόσμε".as_bytes()))
    );
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

// --- length encoding, which Autobahn folds into 1.x ----------------------

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

// --- 5.x  fragmentation, the awkward shapes -------------------------------

#[test]
fn case_5_2_a_message_in_many_small_fragments_reassembles() {
    // One byte per frame, which is legal and which a naive reassembler that
    // assumes a frame is a message gets wrong.
    let mut a = assembler();
    let text = b"fragmented";
    for (index, byte) in text.iter().enumerate() {
        let first = index == 0;
        let last = index == text.len() - 1;
        let opcode = if first {
            OpCode::Text
        } else {
            OpCode::Continuation
        };
        let result = feed(&mut a, &frame(opcode, last, &[*byte])).unwrap();
        if last {
            assert_eq!(
                result,
                Some(Message::Text(Bytes::from_static(b"fragmented")))
            );
        } else {
            assert_eq!(result, None, "fragment {index} completed early");
        }
    }
}

#[test]
fn case_5_4_an_empty_fragment_is_legal() {
    // A zero length continuation carries nothing and ends nothing, and must
    // not be mistaken for the end of the message.
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, b"a")).unwrap(),
        None
    );
    assert_eq!(
        feed(&mut a, &frame(OpCode::Continuation, false, b"")).unwrap(),
        None
    );
    let message = feed(&mut a, &frame(OpCode::Continuation, true, b"b"))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::from_static(b"ab")));
}

#[test]
fn case_5_8_a_close_may_interrupt_a_fragmented_message() {
    // The close is delivered rather than held until the message completes,
    // because the message never will.
    let mut a = assembler();
    a.accept(OpCode::Text, false, Bytes::from_static(b"never"))
        .unwrap();
    let message = feed(&mut a, &frame(OpCode::Close, true, b""))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Close(None));
    assert!(a.is_closed());
}

#[test]
fn a_fragmented_message_may_follow_a_complete_one() {
    // Reassembly state has to be cleared on completion, or the second message
    // is reported as an interleaved data frame.
    let mut a = assembler();
    feed(&mut a, &frame(OpCode::Text, true, b"first"))
        .unwrap()
        .unwrap();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, b"sec")).unwrap(),
        None
    );
    let message = feed(&mut a, &frame(OpCode::Continuation, true, b"ond"))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Text(Bytes::from_static(b"second")));
}

// --- 6.x  the UTF-8 boundaries -------------------------------------------

#[test]
fn case_6_2_the_first_and_last_codepoint_of_each_length_pass() {
    // The edges of each encoding width, where an off-by-one in a validator
    // shows up.
    for text in [
        "\u{0}",      // one byte, first
        "\u{7F}",     // one byte, last
        "\u{80}",     // two bytes, first
        "\u{7FF}",    // two bytes, last
        "\u{800}",    // three bytes, first
        "\u{FFFF}",   // three bytes, last
        "\u{10000}",  // four bytes, first
        "\u{10FFFF}", // four bytes, last, and the highest codepoint there is
    ] {
        let mut a = assembler();
        let message = feed(&mut a, &frame(OpCode::Text, true, text.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(
            message,
            Message::Text(Bytes::copy_from_slice(text.as_bytes())),
            "refused a valid codepoint: {text:?}"
        );
    }
}

#[test]
fn case_6_6_a_truncated_sequence_at_the_end_is_refused() {
    // Autobahn's 6.6.x walk a valid string cut short mid character. Each
    // prefix that ends inside a sequence must fail.
    let full = "κόσμε".as_bytes();
    for cut in 1..full.len() {
        if core::str::from_utf8(&full[..cut]).is_ok() {
            continue;
        }
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Text, true, &full[..cut])),
            Err(Fault::Protocol(ProtocolError::InvalidUtf8)),
            "accepted a sequence truncated at {cut}"
        );
    }
}

#[test]
fn case_6_12_a_lone_continuation_byte_is_refused() {
    // A byte in the 0x80-0xBF range cannot start a character.
    for byte in [0x80u8, 0xA0, 0xBF] {
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Text, true, &[byte])),
            Err(Fault::Protocol(ProtocolError::InvalidUtf8)),
            "accepted a lone continuation byte {byte:#04x}"
        );
    }
}

#[test]
fn case_6_14_an_invalid_sequence_split_across_fragments_is_still_refused() {
    // Each half is inconclusive alone; together they are invalid. Validating
    // per fragment would let this through.
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, &[0xF0])).unwrap(),
        None
    );
    assert_eq!(
        feed(
            &mut a,
            &frame(OpCode::Continuation, true, &[0x80, 0x80, 0xAF])
        ),
        Err(Fault::Protocol(ProtocolError::InvalidUtf8))
    );
}

// --- 7.x  closing, the body shapes ----------------------------------------

#[test]
fn case_7_3_x_a_close_reason_may_be_any_valid_utf8() {
    let mut a = assembler();
    let mut body = 1000u16.to_be_bytes().to_vec();
    body.extend_from_slice("κόσμε".as_bytes());
    let message = feed(&mut a, &frame(OpCode::Close, true, &body))
        .unwrap()
        .unwrap();
    assert_eq!(
        message,
        Message::Close(Some(CloseFrame {
            code: CloseCode::NORMAL,
            reason: Bytes::from_static("κόσμε".as_bytes()),
        }))
    );
}

#[test]
fn case_7_7_every_code_the_registry_allows_is_accepted() {
    // 1000-1003 and 1007-1011 are the codes an endpoint may send.
    for code in [1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011] {
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
            "refused close code {code}, which the registry allows"
        );
    }
}

#[test]
fn a_close_frame_is_at_most_125_bytes() {
    // It is a control frame, so the reason has 123 bytes after the code.
    let mut a = assembler();
    let mut body = 1000u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[b'x'; 124]);
    assert_eq!(
        feed(&mut a, &frame(OpCode::Close, true, &body)),
        Err(Fault::Frame(FrameError::InvalidControlFrame))
    );
}

// --- 9.x  the sizes Autobahn uses for throughput -------------------------

#[test]
fn case_9_x_large_messages_survive_fragmentation() {
    // Autobahn's 9.x send megabytes in fragments of varying size. This is the
    // same shape smaller: what matters is that the pieces are reassembled in
    // order and none is lost.
    const TOTAL: usize = 256 * 1024;
    const PIECE: usize = 4096;

    let mut a = Assembler::new(Limits {
        max_frame: 1024 * 1024,
        max_message: 1024 * 1024,
    });

    let payload: Vec<u8> = (0..TOTAL).map(|index| (index % 251) as u8).collect();
    let mut sent = 0usize;
    let mut result = None;

    while sent < TOTAL {
        let end = (sent + PIECE).min(TOTAL);
        let last = end == TOTAL;
        let opcode = if sent == 0 {
            OpCode::Binary
        } else {
            OpCode::Continuation
        };
        result = feed(&mut a, &frame(opcode, last, &payload[sent..end])).unwrap();
        sent = end;
    }

    assert_eq!(
        result,
        Some(Message::Binary(Bytes::from(payload))),
        "a large fragmented message did not reassemble intact"
    );
}

// ==========================================================================
// Everything above is one case written out. Everything below is a section
// generated from the rule that defines it, which is how the large sections
// are covered: transcribing a hundred and forty five UTF-8 cases would say
// less than the table they all come from.
// ==========================================================================

// --- 6.x in bulk ---------------------------------------------------------
//
// Section 6 is the largest part of Autobahn, around a hundred and forty five
// cases, and almost all of it is one question asked of many byte sequences:
// is this valid UTF-8, and does the connection do the right thing either way.
//
// Hand writing a hundred and forty five of those would be transcription. What
// follows generates the same space from the rules that define it, which
// covers more than the published list and states why each sequence is in it.

/// Every way a UTF-8 sequence can be malformed, and one example of each.
///
/// Taken from the same table Autobahn's 6.3 through 6.21 are built from:
/// Markus Kuhn's stress test, which is where that section comes from.
const MALFORMED: &[(&str, &[u8])] = &[
    ("lone continuation byte", &[0x80]),
    ("lone continuation byte, high", &[0xBF]),
    ("two continuation bytes", &[0x80, 0xBF]),
    ("lone start, two byte", &[0xC2]),
    ("lone start, three byte", &[0xE0]),
    ("lone start, four byte", &[0xF0]),
    ("truncated two byte", &[0xC2, 0x41]),
    ("truncated three byte", &[0xE0, 0xA0, 0x41]),
    ("truncated four byte", &[0xF0, 0x90, 0x80, 0x41]),
    ("overlong solidus, two byte", &[0xC0, 0xAF]),
    ("overlong solidus, three byte", &[0xE0, 0x80, 0xAF]),
    ("overlong solidus, four byte", &[0xF0, 0x80, 0x80, 0xAF]),
    ("overlong nul, two byte", &[0xC0, 0x80]),
    ("overlong nul, three byte", &[0xE0, 0x80, 0x80]),
    ("overlong nul, four byte", &[0xF0, 0x80, 0x80, 0x80]),
    ("maximum overlong, two byte", &[0xC1, 0xBF]),
    ("maximum overlong, three byte", &[0xE0, 0x9F, 0xBF]),
    ("maximum overlong, four byte", &[0xF0, 0x8F, 0xBF, 0xBF]),
    ("surrogate D800", &[0xED, 0xA0, 0x80]),
    ("surrogate DBFF", &[0xED, 0xAF, 0xBF]),
    ("surrogate DC00", &[0xED, 0xB0, 0x80]),
    ("surrogate DFFF", &[0xED, 0xBF, 0xBF]),
    ("paired surrogates", &[0xED, 0xA0, 0x80, 0xED, 0xB0, 0x80]),
    ("beyond U+10FFFF", &[0xF4, 0x90, 0x80, 0x80]),
    ("five byte sequence", &[0xF8, 0x88, 0x80, 0x80, 0x80]),
    ("six byte sequence", &[0xFC, 0x84, 0x80, 0x80, 0x80, 0x80]),
    ("0xFE is never valid", &[0xFE]),
    ("0xFF is never valid", &[0xFF]),
    ("0xFE 0xFF", &[0xFE, 0xFF]),
];

#[test]
fn case_6_3_to_6_21_every_malformed_sequence_is_refused() {
    for (name, payload) in MALFORMED {
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Text, true, payload)),
            Err(Fault::Protocol(ProtocolError::InvalidUtf8)),
            "accepted {name}: {payload:02x?}"
        );
    }
}

#[test]
fn a_malformed_sequence_is_refused_wherever_it_sits() {
    // Autobahn places its bad sequences at the start, the middle and the end
    // of a valid string, because a validator that scans in blocks can miss
    // one that straddles a boundary.
    let filler = "The quick brown fox jumps over the lazy dog. ".repeat(8);
    for (name, bad) in MALFORMED {
        for position in [0, filler.len() / 2, filler.len()] {
            let mut payload = filler.as_bytes()[..position].to_vec();
            payload.extend_from_slice(bad);
            payload.extend_from_slice(&filler.as_bytes()[position..]);

            let mut a = assembler();
            assert_eq!(
                feed(&mut a, &frame(OpCode::Text, true, &payload)),
                Err(Fault::Protocol(ProtocolError::InvalidUtf8)),
                "accepted {name} at offset {position}"
            );
        }
    }
}

#[test]
fn a_malformed_sequence_is_refused_in_a_close_reason() {
    // 7.5.1 is this question for close frames, which take the same path.
    for (name, bad) in MALFORMED {
        // A close frame is a control frame: code plus 123 bytes at most.
        if bad.len() > 123 {
            continue;
        }
        let mut body = 1000u16.to_be_bytes().to_vec();
        body.extend_from_slice(bad);

        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Close, true, &body)),
            Err(Fault::Protocol(ProtocolError::InvalidUtf8)),
            "accepted {name} as a close reason"
        );
    }
}

#[test]
fn a_malformed_sequence_is_refused_across_a_fragment_boundary() {
    // The case per fragment validation would let through: each half alone is
    // merely incomplete, and only the join is invalid.
    for (name, bad) in MALFORMED {
        if bad.len() < 2 {
            continue;
        }
        let split = bad.len() / 2;

        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Text, false, &bad[..split])).unwrap(),
            None,
            "{name}: a partial sequence completed a message early"
        );
        assert_eq!(
            feed(&mut a, &frame(OpCode::Continuation, true, &bad[split..])),
            Err(Fault::Protocol(ProtocolError::InvalidUtf8)),
            "accepted {name} split across fragments"
        );
    }
}

#[test]
fn every_valid_codepoint_class_passes_where_the_bad_ones_fail() {
    // The other half of section 6: the sequences that must be accepted, so
    // that a validator which refuses everything cannot pass the tests above.
    let valid: &[(&str, &str)] = &[
        ("ascii", "hello world"),
        ("two byte", "\u{80}\u{7FF}"),
        ("three byte", "\u{800}\u{FFFF}"),
        ("four byte", "\u{10000}\u{10FFFF}"),
        ("greek", "κόσμε"),
        ("nul", "\u{0}"),
        ("replacement character", "\u{FFFD}"),
        ("just below a surrogate", "\u{D7FF}"),
        ("just above a surrogate", "\u{E000}"),
        ("non-characters are valid utf8", "\u{FFFE}\u{FFFF}"),
    ];
    for (name, text) in valid {
        let mut a = assembler();
        let message = feed(&mut a, &frame(OpCode::Text, true, text.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(
            message,
            Message::Text(Bytes::copy_from_slice(text.as_bytes())),
            "refused {name}, which is valid"
        );
    }
}

// --- 1.x in bulk ----------------------------------------------------------
//
// Autobahn's 1.1.1 through 1.2.8 are one question asked sixteen times: does a
// payload of size N survive, as text and as binary, whole and in fragments.
// The sizes are the ones that cross a boundary in the length field, plus the
// fragment size Autobahn itself uses.

/// The payload sizes Autobahn's section 1 walks.
///
/// 125 is the last length the 7-bit field can hold, 126 is the first that
/// forces the 16-bit form, 65535 is the last that fits it and 65536 the first
/// that forces the 64-bit form. 0 and 1 are there because an empty frame is
/// legal and a one-byte one exercises no encoding at all.
const SECTION_1_SIZES: &[usize] = &[0, 1, 125, 126, 127, 128, 65535, 65536];

/// Autobahn fragments its large section 1 payloads at this size.
const AUTOBAHN_FRAGMENT: usize = 4096;

/// A payload of `size` bytes that is valid UTF-8, so the same body can be sent
/// as text or as binary and the text path is actually exercised rather than
/// skipped over ASCII.
fn payload_of(size: usize) -> Vec<u8> {
    // Repeating "Hello" keeps it readable in a failure and keeps every byte
    // ASCII, which text requires and binary does not care about.
    b"Hello, world! "
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
}

fn expect_message(kind: OpCode, payload: Vec<u8>) -> Message {
    match kind {
        OpCode::Text => Message::Text(Bytes::from(payload)),
        OpCode::Binary => Message::Binary(Bytes::from(payload)),
        _ => unreachable!("section 1 is data frames only"),
    }
}

#[test]
fn case_1_1_1_to_1_2_8_every_size_survives_whole() {
    for kind in [OpCode::Text, OpCode::Binary] {
        for &size in SECTION_1_SIZES {
            let payload = payload_of(size);
            let mut a = assembler();
            let message = feed(&mut a, &frame(kind, true, &payload))
                .unwrap()
                .unwrap_or_else(|| panic!("{kind:?} of {size} bytes completed nothing"));
            assert_eq!(
                message,
                expect_message(kind, payload),
                "{kind:?} of {size} bytes did not round trip whole"
            );
        }
    }
}

#[test]
fn case_1_1_1_to_1_2_8_every_size_survives_fragmentation() {
    for kind in [OpCode::Text, OpCode::Binary] {
        for &size in SECTION_1_SIZES {
            let payload = payload_of(size);
            let mut a = assembler();

            // An empty payload has no chunks at all, so it is sent as a single
            // non-final frame closed by an empty continuation: still two
            // frames, still one message, which is what the case asks.
            let chunks: Vec<&[u8]> = if payload.is_empty() {
                vec![&[]]
            } else {
                payload.chunks(AUTOBAHN_FRAGMENT).collect()
            };

            let mut delivered = None;
            for (index, chunk) in chunks.iter().enumerate() {
                let first = index == 0;
                let last = index == chunks.len() - 1;
                let opcode = if first { kind } else { OpCode::Continuation };
                let result = feed(&mut a, &frame(opcode, last, chunk)).unwrap();
                if last {
                    delivered = result;
                } else {
                    assert!(
                        result.is_none(),
                        "{kind:?} of {size} bytes completed at fragment {index}"
                    );
                }
            }

            assert_eq!(
                delivered.unwrap_or_else(|| panic!("{kind:?} of {size} bytes never completed")),
                expect_message(kind, payload),
                "{kind:?} of {size} bytes did not round trip in fragments"
            );
        }
    }
}

// --- 2.x in bulk ----------------------------------------------------------
//
// Section 2 is about control frames: what a ping may carry, and what an
// endpoint does with pongs it never asked for.

#[test]
fn case_2_3_and_2_4_a_ping_may_carry_the_full_125_bytes() {
    // 125 is the whole control frame budget, so this is the largest legal
    // ping, and the one either side of the boundary decides the case.
    for size in [0usize, 1, 124, 125] {
        let payload = vec![0xA5u8; size];
        let mut a = assembler();
        let message = feed(&mut a, &frame(OpCode::Ping, true, &payload))
            .unwrap()
            .unwrap();
        assert_eq!(
            message,
            Message::Ping(Bytes::from(payload)),
            "a {size} byte ping did not survive"
        );
    }
}

#[test]
fn case_2_5_a_ping_over_125_bytes_is_refused() {
    for size in [126usize, 127, 1024] {
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Ping, true, &vec![0u8; size])),
            Err(Fault::Frame(FrameError::InvalidControlFrame)),
            "accepted a {size} byte ping"
        );
    }
}

#[test]
fn case_2_6_a_ping_payload_may_be_arbitrary_bytes() {
    // A ping is not text, so it carries the bytes a text frame would refuse
    // and they must come back exactly as sent.
    let payload: Vec<u8> = (0u8..=255).collect();
    let payload = payload[..125].to_vec();
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Ping, true, &payload))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Ping(Bytes::from(payload)));
}

#[test]
fn case_2_7_an_unsolicited_pong_is_accepted_and_answers_nothing() {
    // §5.5.3: an unsolicited pong is a unidirectional heartbeat and is legal.
    // It is delivered so the application may see it; it is not an error and
    // nothing is owed in reply.
    let mut a = assembler();
    let message = feed(&mut a, &frame(OpCode::Pong, true, b"unsolicited"))
        .unwrap()
        .unwrap();
    assert_eq!(message, Message::Pong(Bytes::from_static(b"unsolicited")));
}

#[test]
fn case_2_8_an_unsolicited_pong_does_not_disturb_a_later_ping() {
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Pong, true, b"first")).unwrap(),
        Some(Message::Pong(Bytes::from_static(b"first")))
    );
    assert_eq!(
        feed(&mut a, &frame(OpCode::Ping, true, b"second")).unwrap(),
        Some(Message::Ping(Bytes::from_static(b"second")))
    );
}

#[test]
fn case_2_10_and_2_11_pings_arrive_in_order() {
    // Ten pings back to back. Each must surface separately and in the order
    // sent, because the pongs owed for them are only correct in that order.
    let mut a = assembler();
    for index in 0..10u8 {
        let payload = [index];
        assert_eq!(
            feed(&mut a, &frame(OpCode::Ping, true, &payload)).unwrap(),
            Some(Message::Ping(Bytes::copy_from_slice(&payload))),
            "ping {index} came back out of order or not at all"
        );
    }
}

// --- 5.x in bulk ----------------------------------------------------------
//
// Section 5 is fragmentation sequencing. The rule is short: fragments of one
// message may be interleaved with control frames and with nothing else, and a
// continuation only means something while a message is open. Most of the
// section is that rule tested at every position a frame can occupy.

#[test]
fn case_5_6_to_5_20_a_control_frame_may_sit_at_any_fragment_boundary() {
    // Autobahn places a ping between the first and second fragment, then
    // between the second and third, and so on. Rather than fixing a position,
    // walk every one of them: a four fragment message has three boundaries,
    // and the message must reassemble identically whichever one is used.
    let fragments: &[&[u8]] = &[b"frag", b"ment", b"ed m", b"essage"];
    let joined: Vec<u8> = fragments.concat();

    for boundary in 0..fragments.len() - 1 {
        let mut a = assembler();
        let mut delivered = None;

        for (index, fragment) in fragments.iter().enumerate() {
            let opcode = if index == 0 {
                OpCode::Text
            } else {
                OpCode::Continuation
            };
            let last = index == fragments.len() - 1;
            let result = feed(&mut a, &frame(opcode, last, fragment)).unwrap();
            if last {
                delivered = result;
            } else {
                assert!(result.is_none(), "fragment {index} completed a message");
            }

            if index == boundary {
                // A ping here must surface on its own and leave the partial
                // message exactly as it was.
                let probe = feed(&mut a, &frame(OpCode::Ping, true, b"probe"))
                    .unwrap()
                    .unwrap();
                assert_eq!(probe, Message::Ping(Bytes::from_static(b"probe")));
            }
        }

        assert_eq!(
            delivered.unwrap(),
            Message::Text(Bytes::from(joined.clone())),
            "a ping after fragment {boundary} disturbed reassembly"
        );
    }
}

#[test]
fn case_5_6_to_5_20_several_control_frames_may_sit_at_one_boundary() {
    // Nothing limits a peer to one control frame between fragments.
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, b"a")).unwrap(),
        None
    );

    for opcode in [OpCode::Ping, OpCode::Pong, OpCode::Ping] {
        let message = feed(&mut a, &frame(opcode, true, b"x")).unwrap().unwrap();
        let expected = match opcode {
            OpCode::Ping => Message::Ping(Bytes::from_static(b"x")),
            OpCode::Pong => Message::Pong(Bytes::from_static(b"x")),
            _ => unreachable!("only ping and pong are sent here"),
        };
        assert_eq!(message, expected);
    }

    let done = feed(&mut a, &frame(OpCode::Continuation, true, b"b"))
        .unwrap()
        .unwrap();
    assert_eq!(done, Message::Text(Bytes::from_static(b"ab")));
}

#[test]
fn case_5_15_a_continuation_after_a_completed_message_is_a_protocol_error() {
    // The message ended with the FIN fragment, so the next continuation has
    // nothing to continue. This is the failure a naive implementation misses,
    // because it never cleared the state the last FIN should have cleared.
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, b"a")).unwrap(),
        None
    );
    assert_eq!(
        feed(&mut a, &frame(OpCode::Continuation, true, b"b")).unwrap(),
        Some(Message::Text(Bytes::from_static(b"ab")))
    );
    assert_eq!(
        feed(&mut a, &frame(OpCode::Continuation, true, b"c")),
        Err(Fault::Protocol(ProtocolError::UnexpectedContinuation))
    );
}

#[test]
fn case_5_16_to_5_17_a_continuation_before_anything_is_a_protocol_error() {
    // Both the final and the non-final form, since an implementation that
    // checks only one of them passes half the section.
    for fin in [true, false] {
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Continuation, fin, b"x")),
            Err(Fault::Protocol(ProtocolError::UnexpectedContinuation)),
            "accepted a continuation with fin={fin} and nothing open"
        );
    }
}

#[test]
fn case_5_18_to_5_20_a_data_frame_during_a_fragment_is_a_protocol_error() {
    // Every combination: the open message is text or binary, the interloper is
    // text or binary, final or not. All four by four are the same violation.
    for open in [OpCode::Text, OpCode::Binary] {
        for interloper in [OpCode::Text, OpCode::Binary] {
            for fin in [true, false] {
                let mut a = assembler();
                assert_eq!(feed(&mut a, &frame(open, false, b"a")).unwrap(), None);
                assert_eq!(
                    feed(&mut a, &frame(interloper, fin, b"b")),
                    Err(Fault::Protocol(ProtocolError::InterleavedDataFrame)),
                    "accepted {interloper:?} (fin={fin}) inside an open {open:?}"
                );
            }
        }
    }
}

// --- 7.x in bulk ----------------------------------------------------------
//
// Section 7 is the closing handshake: which close bodies parse, which codes
// may appear on the wire, and what happens to anything sent afterwards.

#[test]
fn case_7_3_x_a_close_body_may_be_empty_a_code_or_a_code_and_reason() {
    // The four legal shapes, by length: nothing, the code alone, the code with
    // a reason, and the code with the largest reason a control frame holds.
    let cases: &[(&str, usize)] = &[
        ("code alone", 0),
        ("short reason", 5),
        ("largest reason", 123),
    ];

    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Close, true, b"")).unwrap(),
        Some(Message::Close(None)),
        "an empty close body means no status given and is legal"
    );

    for (name, reason_len) in cases {
        let reason = vec![b'y'; *reason_len];
        let mut body = 1000u16.to_be_bytes().to_vec();
        body.extend_from_slice(&reason);

        let mut a = assembler();
        let message = feed(&mut a, &frame(OpCode::Close, true, &body))
            .unwrap()
            .unwrap();
        assert_eq!(
            message,
            Message::Close(Some(CloseFrame {
                code: CloseCode::NORMAL,
                reason: Bytes::from(reason),
            })),
            "the {name} form did not parse"
        );
    }
}

#[test]
fn case_7_7_and_7_9_the_registry_decides_every_code() {
    // The whole u16 space, judged by the rule rather than by a list: 1000-1003
    // and 1007-1011 are the protocol's own, 3000-3999 are registered by
    // libraries and 4000-4999 are private. Everything else, including the
    // codes an application may observe but must never send (1005, 1006, 1015),
    // is a violation when it appears on the wire.
    let sendable =
        |code: u16| matches!(code, 1000..=1003 | 1007..=1011 | 3000..=3999 | 4000..=4999);

    // Every code near a boundary, plus the ones Autobahn names explicitly.
    let interesting: Vec<u16> = (0u16..=1020)
        .chain([
            1100, 2000, 2999, 3000, 3001, 3999, 4000, 4001, 4999, 5000, 65535,
        ])
        .collect();

    for code in interesting {
        let mut a = assembler();
        let body = code.to_be_bytes().to_vec();
        let result = feed(&mut a, &frame(OpCode::Close, true, &body));

        if sendable(code) {
            assert_eq!(
                result,
                Ok(Some(Message::Close(Some(CloseFrame {
                    code: CloseCode(code),
                    reason: Bytes::new(),
                })))),
                "refused close code {code}, which may be sent"
            );
        } else {
            assert_eq!(
                result,
                Err(Fault::Protocol(ProtocolError::InvalidCloseCode)),
                "accepted close code {code}, which must never be sent"
            );
        }
    }
}

#[test]
fn case_7_9_x_a_code_is_judged_before_its_reason() {
    // An illegal code with a perfectly good reason is still illegal: the code
    // must be checked before the reason is looked at, or a peer can smuggle
    // one past by attaching something valid to it.
    for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2000, 5000] {
        let mut a = assembler();
        let mut body = code.to_be_bytes().to_vec();
        body.extend_from_slice(b"a perfectly good reason");
        assert_eq!(
            feed(&mut a, &frame(OpCode::Close, true, &body)),
            Err(Fault::Protocol(ProtocolError::InvalidCloseCode)),
            "accepted close code {code} because its reason was valid"
        );
    }
}

#[test]
fn case_7_1_2_a_second_close_is_discarded() {
    // §5.5.1: the connection is closing from the first one. Acting on the
    // second would mean answering a peer that has already said goodbye.
    let mut a = assembler();
    let first = feed(&mut a, &frame(OpCode::Close, true, &1000u16.to_be_bytes()))
        .unwrap()
        .unwrap();
    assert_eq!(
        first,
        Message::Close(Some(CloseFrame {
            code: CloseCode::NORMAL,
            reason: Bytes::new(),
        }))
    );
    assert!(a.is_closed());

    assert_eq!(
        feed(&mut a, &frame(OpCode::Close, true, &1001u16.to_be_bytes())).unwrap(),
        None,
        "a second close was delivered"
    );
}

#[test]
fn case_7_1_3_to_7_1_5_anything_after_a_close_is_discarded() {
    // A ping after a close must not draw a pong, and a message after a close
    // must not be echoed. Both follow from the same rule, so both are checked
    // the same way: the frame parses, and nothing comes out.
    let after: &[(&str, OpCode)] = &[
        ("a ping", OpCode::Ping),
        ("a pong", OpCode::Pong),
        ("a text message", OpCode::Text),
        ("a binary message", OpCode::Binary),
    ];

    for (name, opcode) in after {
        let mut a = assembler();
        feed(&mut a, &frame(OpCode::Close, true, &1000u16.to_be_bytes())).unwrap();
        assert_eq!(
            feed(&mut a, &frame(*opcode, true, b"ignored")).unwrap(),
            None,
            "{name} was delivered after a close"
        );
    }
}

#[test]
fn case_7_1_5_a_close_abandons_a_fragmented_message() {
    // The message was half sent when the close arrived. It never completes,
    // and the continuation that would have completed it is discarded rather
    // than reassembled into a message delivered after the goodbye.
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, b"half")).unwrap(),
        None
    );
    feed(&mut a, &frame(OpCode::Close, true, &1000u16.to_be_bytes())).unwrap();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Continuation, true, b" sent")).unwrap(),
        None,
        "a fragmented message completed after a close"
    );
}

// --- 3.x and 4.x in bulk --------------------------------------------------
//
// Reserved bits and reserved opcodes are rejected for the same reason: this
// endpoint negotiates no extension, so a peer that sets either is speaking a
// protocol that was never agreed to. Autobahn checks that at every position
// one can appear, which is a small cross product rather than a list.

/// Every frame kind a reserved bit or opcode can ride on.
const EVERY_OPCODE: &[OpCode] = &[
    OpCode::Continuation,
    OpCode::Text,
    OpCode::Binary,
    OpCode::Close,
    OpCode::Ping,
    OpCode::Pong,
];

#[test]
fn case_3_1_to_3_7_every_combination_of_reserved_bits_is_refused() {
    // Seven combinations: each bit alone, each pair, and all three. A codec
    // that masks one bit at a time and forgets to check the rest passes the
    // three singles and fails here.
    for bits in 1u8..=7 {
        let encoded = bits << 4;
        for &opcode in EVERY_OPCODE {
            let mut wire = frame(opcode, true, b"x");
            wire[0] |= encoded;
            let mut a = assembler();
            assert_eq!(
                feed(&mut a, &wire),
                Err(Fault::Frame(FrameError::ReservedBitSet)),
                "accepted reserved bits {encoded:#04x} on {opcode:?}"
            );
        }
    }
}

#[test]
fn case_3_x_a_reserved_bit_is_refused_before_anything_else_is_judged() {
    // The bit is set on a frame that is also wrong in a second way. The
    // reserved bit must still be what catches it, because it is judged from
    // the first byte and nothing later should be reached.
    let mut a = assembler();

    // A continuation with nothing open, which would otherwise be a protocol
    // error one layer up.
    let mut wire = frame(OpCode::Continuation, true, b"x");
    wire[0] |= 0x40;
    assert_eq!(
        feed(&mut a, &wire),
        Err(Fault::Frame(FrameError::ReservedBitSet))
    );

    // Text that is not UTF-8, which would otherwise be caught during assembly.
    let mut wire = frame(OpCode::Text, true, &[0xFF]);
    wire[0] |= 0x20;
    assert_eq!(
        feed(&mut a, &wire),
        Err(Fault::Frame(FrameError::ReservedBitSet))
    );
}

#[test]
fn case_3_x_a_reserved_bit_is_refused_inside_a_fragmented_message() {
    // The message opened legally; the continuation carries the bit. An
    // implementation that checks the first frame of a message and then trusts
    // the rest passes everything above and fails this.
    let mut a = assembler();
    assert_eq!(
        feed(&mut a, &frame(OpCode::Text, false, b"a")).unwrap(),
        None
    );

    let mut wire = frame(OpCode::Continuation, true, b"b");
    wire[0] |= 0x40;
    assert_eq!(
        feed(&mut a, &wire),
        Err(Fault::Frame(FrameError::ReservedBitSet))
    );
}

#[test]
fn case_4_1_x_and_4_2_x_every_reserved_opcode_is_refused_either_way() {
    // 0x3 to 0x7 are reserved data opcodes and 0xB to 0xF reserved control
    // opcodes. Both ranges are refused, and the FIN bit does not change that:
    // a reserved opcode is unknown, so there is no way to know what a fragment
    // of one would even mean.
    for opcode in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
        for fin in [true, false] {
            let mut wire = frame(OpCode::Text, fin, b"x");
            wire[0] = (if fin { 0x80 } else { 0x00 }) | opcode;
            let mut a = assembler();
            assert_eq!(
                feed(&mut a, &wire),
                Err(Fault::Frame(FrameError::ReservedOpCode(opcode))),
                "accepted reserved opcode {opcode:#x} with fin={fin}"
            );
        }
    }
}

#[test]
fn case_4_x_a_reserved_opcode_is_refused_inside_a_fragmented_message() {
    for opcode in [0x3u8, 0xB] {
        let mut a = assembler();
        assert_eq!(
            feed(&mut a, &frame(OpCode::Text, false, b"a")).unwrap(),
            None
        );

        let mut wire = frame(OpCode::Text, true, b"b");
        wire[0] = 0x80 | opcode;
        assert_eq!(
            feed(&mut a, &wire),
            Err(Fault::Frame(FrameError::ReservedOpCode(opcode))),
            "accepted reserved opcode {opcode:#x} inside a fragmented message"
        );
    }
}
