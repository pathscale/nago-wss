//! The protocol core alone, with no socket anywhere.
//!
//! sockudo-ws benchmarks masking, UTF-8 validation, frame parsing and frame
//! encoding as pure CPU work. That is the axis where its SIMD and its unsafe
//! should show, and it is the one axis this crate had never measured: every
//! other benchmark here puts a socket in the path, where the kernel dominates
//! and a protocol difference of a few nanoseconds disappears.
//!
//! So this measures the same four things, the same way, on both.

use std::hint::black_box;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use nago_wss::proto::frame::Header;
use nago_wss::proto::handshake::accept_for;
use nago_wss::proto::mask;
use nago_wss::proto::message::{Assembler, Limits};
use nago_wss::proto::opcode::OpCode;

/// Payload sizes, matching the ones sockudo-ws uses.
const SIZES: [usize; 4] = [64, 1024, 16 * 1024, 256 * 1024];

/// Run `body` until it has taken a stable amount of time, and report the cost
/// of one iteration.
///
/// Not criterion: this has to finish in seconds, and what is wanted is a
/// number per operation rather than a statistical report.
fn measure<F: FnMut()>(mut body: F) -> f64 {
    // Warm the branch predictor and any lazily initialised state.
    for _ in 0..1_000 {
        body();
    }

    // Grow the iteration count until the run is long enough that timer
    // resolution stops mattering.
    let mut iterations = 1_000u64;
    loop {
        let start = Instant::now();
        for _ in 0..iterations {
            body();
        }
        let elapsed = start.elapsed();
        if elapsed >= Duration::from_millis(50) {
            return elapsed.as_secs_f64() / iterations as f64;
        }
        iterations *= 4;
    }
}

/// Nanoseconds, messages per second, and throughput where size applies.
///
/// Messages per second is the number that means something at the fleet level:
/// a per-operation nanosecond figure is hard to compare against a message
/// rate, and the fleet's traffic is counted in messages.
fn report(name: &str, size: usize, seconds: f64) {
    let nanos = seconds * 1e9;
    let per_second = 1.0 / seconds;
    if size > 0 {
        let gb_per_second = size as f64 / seconds / 1e9;
        println!(
            "  {name:<26} {size:>7} B  {nanos:>9.1} ns  {:>12}/s  {gb_per_second:>7.2} GB/s",
            thousands(per_second)
        );
    } else {
        println!(
            "  {name:<26} {:>7}  {nanos:>9.1} ns  {:>12}/s",
            "-",
            thousands(per_second)
        );
    }
}

/// A rate with thousands separators, because nine unbroken digits are
/// unreadable and these numbers run to hundreds of millions.
fn thousands(value: f64) -> String {
    let whole = format!("{:.0}", value);
    let mut out = String::with_capacity(whole.len() + whole.len() / 3);
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn main() {
    println!("\nprotocol core, no I/O. rate is operations per second\n");

    // Masking: every byte a client sends and every byte a server receives.
    for size in SIZES {
        let mut payload = vec![0x5Au8; size];
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let seconds = measure(|| {
            mask::apply(black_box(&mut payload), key, 0);
        });
        report("mask", size, seconds);
    }
    println!();

    // UTF-8 validation, which every text frame pays.
    for size in SIZES {
        let ascii = vec![b'a'; size];
        let seconds = measure(|| {
            black_box(core::str::from_utf8(black_box(&ascii)).is_ok());
        });
        report("utf8 ascii", size, seconds);
    }
    // Multi-byte characters take the slower path in any validator.
    for size in SIZES {
        let mixed: Vec<u8> = "héllo wörld "
            .repeat(size / 13 + 1)
            .into_bytes()
            .into_iter()
            .take(size)
            .collect();
        // Truncating can split a character, which would measure the error
        // path instead; back off to the last boundary.
        let valid = match core::str::from_utf8(&mixed) {
            Ok(_) => mixed,
            Err(error) => mixed[..error.valid_up_to()].to_vec(),
        };
        let seconds = measure(|| {
            black_box(core::str::from_utf8(black_box(&valid)).is_ok());
        });
        report("utf8 mixed", valid.len(), seconds);
    }
    println!();

    // Frame decode: header parse plus unmask, which is what a read does.
    for size in SIZES {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let header = Header {
            fin: true,
            opcode: OpCode::Binary,
            mask: Some(key),
            payload_len: size as u64,
        };
        let mut frame = [0u8; Header::MAX_ENCODED_LEN];
        let header_len = header.encode(&mut frame).expect("encode");

        let mut wire = Vec::with_capacity(header_len + size);
        wire.extend_from_slice(&frame[..header_len]);
        wire.extend_from_slice(&vec![0x5Au8; size]);

        let mut scratch = vec![0u8; size];
        let seconds = measure(|| {
            let (decoded, at) = Header::decode(black_box(&wire), u64::MAX)
                .expect("decode")
                .expect("complete");
            scratch.copy_from_slice(&wire[at..]);
            if let Some(key) = decoded.mask {
                mask::apply(&mut scratch, key, 0);
            }
            black_box(&scratch);
        });
        report("decode frame (masked)", size, seconds);
    }
    println!();

    // Frame encode, both roles: a server writes unmasked, a client masks.
    for size in SIZES {
        let header = Header {
            fin: true,
            opcode: OpCode::Binary,
            mask: None,
            payload_len: size as u64,
        };
        let mut out = [0u8; Header::MAX_ENCODED_LEN];
        let seconds = measure(|| {
            black_box(header.encode(black_box(&mut out)));
        });
        // No size column: this writes at most fourteen bytes and never looks
        // at the payload, so dividing by the payload size would report a
        // throughput it never achieved.
        report(&format!("encode header ({size} B frame)"), 0, seconds);
    }
    for size in SIZES {
        let payload = vec![0x5Au8; size];
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let header = Header {
            fin: true,
            opcode: OpCode::Binary,
            mask: Some(key),
            payload_len: size as u64,
        };
        let mut scratch = vec![0u8; size];
        let mut out = [0u8; Header::MAX_ENCODED_LEN];
        let seconds = measure(|| {
            black_box(header.encode(&mut out));
            scratch.copy_from_slice(black_box(&payload));
            mask::apply(&mut scratch, key, 0);
            black_box(&scratch);
        });
        report("encode frame (client)", size, seconds);
    }
    println!();

    // Reassembly, which is what the read path actually calls.
    for size in SIZES {
        let payload = Bytes::from(vec![0x5Au8; size]);
        let mut assembler = Assembler::new(Limits::default());
        let seconds = measure(|| {
            black_box(
                assembler
                    .accept(OpCode::Binary, true, black_box(payload.clone()))
                    .expect("accept"),
            );
        });
        // Reported without a size for the same reason as the header: a
        // single-frame message hands its payload straight through, so the
        // work is constant and a per-byte figure would flatter it.
        report(&format!("assemble ({size} B, unfragmented)"), 0, seconds);
    }
    println!();

    // A whole message end to end, which is the number that compares against
    // fleet traffic. Everything above is a stage; this is a client encoding a
    // frame and a server decoding and assembling it, which is what one
    // message actually costs in CPU with no socket in the way.
    println!("  a full message, encode then decode then assemble:");
    for size in SIZES {
        let payload = Bytes::from(vec![0x5Au8; size]);
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let header = Header {
            fin: true,
            opcode: OpCode::Binary,
            mask: Some(key),
            payload_len: size as u64,
        };
        let mut wire = vec![0u8; Header::MAX_ENCODED_LEN + size];
        let mut assembler = Assembler::new(Limits::default());

        let seconds = measure(|| {
            // Client side: encode the header, copy the payload, mask it.
            let mut head = [0u8; Header::MAX_ENCODED_LEN];
            let header_len = header.encode(&mut head).expect("encode");
            wire[..header_len].copy_from_slice(&head[..header_len]);
            wire[header_len..header_len + size].copy_from_slice(&payload);
            mask::apply(&mut wire[header_len..header_len + size], key, 0);

            // Server side: decode the header, unmask, reassemble.
            let (decoded, at) = Header::decode(&wire, u64::MAX)
                .expect("decode")
                .expect("complete");
            let mut body = wire[at..at + size].to_vec();
            if let Some(key) = decoded.mask {
                mask::apply(&mut body, key, 0);
            }
            black_box(
                assembler
                    .accept(decoded.opcode, decoded.fin, Bytes::from(body))
                    .expect("accept"),
            );
        });
        report("full message", size, seconds);
    }
    println!();

    // The handshake, once per connection rather than per message.
    let seconds = measure(|| {
        black_box(accept_for(black_box(b"dGhlIHNhbXBsZSBub25jZQ==")));
    });
    report("handshake accept key", 0, seconds);

    // Buffer growth, which a read does on every connection's first message.
    let seconds = measure(|| {
        let mut buffer = BytesMut::with_capacity(16 * 1024);
        buffer.extend_from_slice(black_box(b"a short frame"));
        black_box(&buffer);
    });
    report("buffer alloc + fill", 0, seconds);
    println!();
}
