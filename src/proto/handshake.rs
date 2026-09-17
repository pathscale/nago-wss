//! The opening handshake, RFC 6455 §4.
//!
//! # Why SHA-1 and base64 are in here
//!
//! The handshake needs exactly one SHA-1 of one short string and one base64 of
//! its twenty-byte digest. Both are implemented below rather than pulled in as
//! dependencies: they are small, they are fully specified, they are exercised
//! against published test vectors, and taking crates for them would mean two
//! more supply chain edges on a crate whose whole purpose is to have fewer.
//!
//! The SHA-1 here is used only for `Sec-WebSocket-Accept`, which RFC 6455 §1.3
//! defines with a constant, publicly known GUID. It carries no secret and
//! proves no identity. It exists so a caching proxy cannot accidentally
//! complete a WebSocket handshake, and SHA-1's collision weaknesses do not
//! bear on that. This is not a general purpose hash and must not be used as one.

use alloc::string::String;
use alloc::vec::Vec;

/// The GUID from RFC 6455 §1.3, concatenated with the client key before hashing.
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`.
///
/// `key` is the base64 text exactly as it arrived on the header line.
pub fn accept_for(key: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key);
    hasher.update(WS_GUID);
    base64_encode(&hasher.finish())
}

/// Whether a `Sec-WebSocket-Key` is well formed.
///
/// §4.1 requires 16 random bytes, base64 encoded, which is always 24 characters
/// ending in `==`. A server that skips this will happily hand an `Accept` back
/// for a malformed key, which hides client bugs.
pub fn is_valid_key(key: &[u8]) -> bool {
    key.len() == 24
        && key.ends_with(b"==")
        && key[..22].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/'
        })
}

// --- base64 ---------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding. Only ever fed a 20 byte digest.
fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64[(triple >> 18) as usize & 0x3F] as char);
        out.push(B64[(triple >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            B64[(triple >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[triple as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

// --- SHA-1 ----------------------------------------------------------------

/// SHA-1, FIPS 180-4. For `Sec-WebSocket-Accept` only; see the module note.
struct Sha1 {
    state: [u32; 5],
    buffer: Vec<u8>,
    length: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [
                0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
            ],
            buffer: Vec::new(),
            length: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&self.buffer[..64]);
            self.compress(&block);
            self.buffer.drain(..64);
        }
    }

    fn finish(mut self) -> [u8; 20] {
        // Padding: a 1 bit, then zeros, then the length in bits as big endian.
        let bit_length = self.length * 8;
        self.buffer.push(0x80);
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }
        self.buffer.extend_from_slice(&bit_length.to_be_bytes());

        let buffered = core::mem::take(&mut self.buffer);
        for block in buffered.chunks_exact(64) {
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
        }

        let mut out = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: &[u8; 20]) -> String {
        use core::fmt::Write;
        let mut out = String::new();
        for byte in digest {
            write!(out, "{byte:02x}").expect("writing to a String cannot fail");
        }
        out
    }

    #[test]
    fn sha1_matches_the_published_vectors() {
        // FIPS 180-2 examples, plus the empty string.
        let mut h = Sha1::new();
        h.update(b"");
        assert_eq!(hex(&h.finish()), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let mut h = Sha1::new();
        h.update(b"abc");
        assert_eq!(hex(&h.finish()), "a9993e364706816aba3e25717850c26c9cd0d89d");

        let mut h = Sha1::new();
        h.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hex(&h.finish()), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    #[test]
    fn sha1_handles_multi_block_and_split_input() {
        // A million 'a's is the standard long vector. Fed in uneven pieces to
        // exercise the buffering across block boundaries.
        let mut h = Sha1::new();
        let chunk = alloc::vec![b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(hex(&h.finish()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");

        // The same input split at a size that is not a block multiple.
        let mut h = Sha1::new();
        for _ in 0..1000 {
            h.update(&alloc::vec![b'a'; 500]);
            h.update(&alloc::vec![b'a'; 500]);
        }
        assert_eq!(hex(&h.finish()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn computes_the_accept_value_from_the_rfc() {
        // RFC 6455 §1.3 works this exact example end to end.
        assert_eq!(accept_for(b"dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn validates_key_shape() {
        assert!(is_valid_key(b"dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(!is_valid_key(b"tooshort=="));
        assert!(!is_valid_key(b"dGhlIHNhbXBsZSBub25jZQ="));
        // Right length, but not base64.
        assert!(!is_valid_key(b"!!!!!!!!!!!!!!!!!!!!!!=="));
    }
}
