//! The protocol core alone, with no socket anywhere.
//!
//! sockudo-ws benchmarks masking, UTF-8 validation, frame parsing and frame
//! encoding as pure CPU work. That is the axis where its SIMD and its unsafe
//! should show, and it is the one axis this crate had never measured: every
//! other benchmark here puts a socket in the path, where the kernel dominates
//! and a protocol difference of a few nanoseconds disappears.
//!
//! So this measures the same things on all three: this crate, tungstenite
//! (what the fleet runs today), and sockudo-ws. Same input, same sizes, same
//! loop, each through the other crate's own public entry point rather than a
//! reimplementation of it.

// One `align_to_mut`, in the copy of tungstenite's masking below.
#![allow(unsafe_code)]

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

/// What this crate actually uses to validate text, feature dependent.
#[inline]
fn validate(payload: &[u8]) -> bool {
    #[cfg(feature = "simd-utf8")]
    {
        simdutf8::basic::from_utf8(payload).is_ok()
    }
    #[cfg(not(feature = "simd-utf8"))]
    {
        core::str::from_utf8(payload).is_ok()
    }
}

/// tungstenite's masking, copied because theirs is private.
///
/// This is `apply_mask_fast32` from tungstenite 0.29 verbatim: 32-bit words
/// over an aligned slice, where this crate uses 64-bit. It is reproduced
/// rather than reached through their public API because the only public path
/// to it also builds a frame, which would measure framing rather than
/// masking. If they change it, this number goes stale.
fn tungstenite_mask(buf: &mut [u8], mask: [u8; 4]) {
    fn fallback(buf: &mut [u8], mask: [u8; 4]) {
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte ^= mask[index & 3];
        }
    }

    let mask_u32 = u32::from_ne_bytes(mask);
    // SAFETY: the same call tungstenite makes. `align_to_mut` is safe for
    // plain integers, which `u8` and `u32` both are.
    let (prefix, words, suffix) = unsafe { buf.align_to_mut::<u32>() };
    fallback(prefix, mask);
    let head = prefix.len() & 3;
    let mask_u32 = if head > 0 {
        if cfg!(target_endian = "big") {
            mask_u32.rotate_left(8 * head as u32)
        } else {
            mask_u32.rotate_right(8 * head as u32)
        }
    } else {
        mask_u32
    };
    for word in words.iter_mut() {
        *word ^= mask_u32;
    }
    fallback(suffix, mask_u32.to_ne_bytes());
}

/// One row, three arms, with the fastest named.
///
/// Rates rather than nanoseconds, because a rate is what compares against
/// traffic, and the ratio against this crate because that is the question.
fn compare(size: usize, ours: f64, tungstenite: f64, sockudo: f64) {
    let rate = |seconds: f64| 1.0 / seconds;
    let gb = |seconds: f64| size as f64 / seconds / 1e9;

    println!(
        "  {size:>7} B   nago {:>12}/s {:>6.2} GB/s   tung {:>12}/s {:>6.2}   sock {:>12}/s {:>6.2}",
        thousands(rate(ours)),
        gb(ours),
        thousands(rate(tungstenite)),
        gb(tungstenite),
        thousands(rate(sockudo)),
        gb(sockudo),
    );

    // Only the losses are called out. A win needs no annotation and the
    // interesting number is where this crate is behind and by how much.
    let mut notes = alloc_notes(ours, tungstenite, sockudo);
    if !notes.is_empty() {
        notes.insert_str(0, "             ");
        println!("{notes}");
    }
}

/// The "slower than" notes for a row, empty when this crate leads.
fn alloc_notes(ours: f64, tungstenite: f64, sockudo: f64) -> String {
    let mut out = String::new();
    if tungstenite < ours {
        out.push_str(&format!("tungstenite {:.2}x faster  ", ours / tungstenite));
    }
    if sockudo < ours {
        out.push_str(&format!("sockudo {:.2}x faster", ours / sockudo));
    }
    out
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
    // sockudo-ws does this with SIMD, which is the headline claim.
    println!("  masking\n");
    for size in SIZES {
        let key = [0x37, 0xfa, 0x21, 0x3d];

        let mut ours = vec![0x5Au8; size];
        let a = measure(|| {
            black_box(mask::apply(black_box(&mut ours), key, 0));
        });

        let mut theirs = vec![0x5Au8; size];
        let b = measure(|| {
            tungstenite_mask(black_box(&mut theirs), key);
        });

        let mut sock = vec![0x5Au8; size];
        let c = measure(|| {
            sockudo_ws::simd::apply_mask(black_box(&mut sock), key);
        });

        compare(size, a, b, c);
    }
    println!();

    // UTF-8 validation, which every text frame pays. Ours is the standard
    // library's; sockudo-ws has a hand written SIMD one. tungstenite also
    // uses the standard library, so that column is the same code as ours and
    // is the control.
    println!("  utf8 validation, ascii\n");
    for size in SIZES {
        let ascii = vec![b'a'; size];
        let a = measure(|| {
            black_box(validate(black_box(&ascii)));
        });
        // tungstenite uses the standard library here, so this column is that
        // rather than a second call into the same code.
        let b = measure(|| {
            black_box(core::str::from_utf8(black_box(&ascii)).is_ok());
        });
        let c = measure(|| {
            black_box(sockudo_ws::utf8::validate_utf8(black_box(&ascii)));
        });
        compare(size, a, b, c);
    }
    println!();
    println!("  utf8 validation, mixed\n");
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
        let a = measure(|| {
            black_box(validate(black_box(&valid)));
        });
        let b = measure(|| {
            black_box(core::str::from_utf8(black_box(&valid)).is_ok());
        });
        let c = measure(|| {
            black_box(sockudo_ws::utf8::validate_utf8(black_box(&valid)));
        });
        compare(valid.len(), a, b, c);
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
