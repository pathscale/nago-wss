//! Payload masking, RFC 6455 §5.3.
//!
//! # Why this is not a byte loop
//!
//! Masking is XOR against a repeating four-byte key, and it runs over every
//! byte a client sends and every byte a server receives. A naive
//! `for (i, b) in payload.iter_mut().enumerate() { *b ^= key[i % 4] }` costs a
//! modulo and a bounds check per byte and defeats vectorisation.
//!
//! Instead the key is broadcast into a `u64` and applied a word at a time. The
//! compiler turns that into SIMD on every target worth caring about, and the
//! tail is handled separately. No `unsafe`, no intrinsics, no target-specific
//! code: the win comes from giving the optimiser a shape it can already widen.

/// A four-byte masking key.
pub type Mask = [u8; 4];

/// XOR `payload` against `key`, starting `offset` bytes into the keystream.
///
/// `offset` exists because a payload can arrive split across reads: the second
/// chunk must continue the key rotation where the first left off rather than
/// restarting it. Pass `0` for a whole payload held in one buffer.
#[inline]
pub fn apply(payload: &mut [u8], key: Mask, offset: usize) -> usize {
    if payload.is_empty() {
        return offset;
    }

    // Rotate the key so index 0 of `payload` lines up with the right key byte.
    let shift = offset & 3;
    let mut rotated = [0u8; 4];
    let mut i = 0;
    while i < 4 {
        rotated[i] = key[(i + shift) & 3];
        i += 1;
    }

    // One key period widened to a word. Little- and big-endian both work
    // because the bytes are laid out through `from_ne_bytes`, matching however
    // the chunk below is read back.
    let word = u64::from_ne_bytes([
        rotated[0], rotated[1], rotated[2], rotated[3], rotated[0], rotated[1], rotated[2],
        rotated[3],
    ]);

    let (chunks, tail) = payload.split_at_mut(payload.len() & !7);
    for chunk in chunks.chunks_exact_mut(8) {
        // `try_into` on a fixed-size slice compiles to a plain load.
        let value = u64::from_ne_bytes(chunk.try_into().expect("chunk is 8 bytes"));
        chunk.copy_from_slice(&(value ^ word).to_ne_bytes());
    }

    for (i, byte) in tail.iter_mut().enumerate() {
        *byte ^= rotated[i & 3];
    }

    offset.wrapping_add(payload.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definition from the RFC, used to check the fast path.
    fn reference(payload: &mut [u8], key: Mask, offset: usize) {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[(offset + i) & 3];
        }
    }

    #[test]
    fn matches_the_reference_at_every_length_and_offset() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        // Past 8 so the word path, the tail and their boundary are all covered.
        for len in 0..40usize {
            for offset in 0..8usize {
                let original: alloc::vec::Vec<u8> =
                    (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();

                let mut fast = original.clone();
                let returned = apply(&mut fast, key, offset);

                let mut slow = original.clone();
                reference(&mut slow, key, offset);

                assert_eq!(fast, slow, "len={len} offset={offset}");
                if len > 0 {
                    assert_eq!(returned, offset + len, "offset not advanced");
                }
            }
        }
    }

    #[test]
    fn split_application_equals_one_pass() {
        let key = [0x01, 0x02, 0x03, 0x04];
        let original: alloc::vec::Vec<u8> = (0..37u8).collect();

        let mut whole = original.clone();
        apply(&mut whole, key, 0);

        // The same bytes masked in two pieces, the second continuing the
        // keystream. This is the case a chunked read produces.
        let mut split = original.clone();
        let (head, rest) = split.split_at_mut(5);
        let next = apply(head, key, 0);
        apply(rest, key, next);

        assert_eq!(whole, split, "chunked masking diverged from one pass");
    }

    #[test]
    fn masking_is_its_own_inverse() {
        let key = [0xde, 0xad, 0xbe, 0xef];
        let original: alloc::vec::Vec<u8> = (0..64u8).collect();
        let mut buffer = original.clone();
        apply(&mut buffer, key, 0);
        assert_ne!(buffer, original, "masking did nothing");
        apply(&mut buffer, key, 0);
        assert_eq!(buffer, original, "unmasking did not restore");
    }
}
