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

use alloc::string::{String, ToString};
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
        && key[..22]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
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
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
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
        assert_eq!(
            accept_for(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// A well formed request, which the negative cases below mutate.
    fn good_request() -> String {
        "GET /chat HTTP/1.1\r\n\
         Host: example.com\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
            .to_string()
    }

    /// The upgrade a test expects, or a panic naming what came back instead.
    fn upgrade_of(input: &[u8]) -> Request {
        match parse_request(input, DEFAULT_MAX_HEAD) {
            Ok(Parsed::Upgrade(request)) => request,
            other => panic!("expected an upgrade, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_well_formed_upgrade() {
        let request = upgrade_of(good_request().as_bytes());
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.path, "/chat");
        assert_eq!(request.key, b"dGhlIHNhbXBsZSBub25jZQ==");
        assert!(request.protocols.is_empty());
    }

    #[test]
    fn finds_the_end_of_a_head_and_waits_for_the_rest() {
        let full = good_request();
        assert_eq!(head_end(full.as_bytes()), Some(full.len()));
        // A head that has not finished arriving must report absent rather than
        // parsing what is there.
        assert_eq!(head_end(&full.as_bytes()[..40]), None);
        // Bare LF, which plenty of clients and test scripts send.
        assert_eq!(head_end(b"GET / HTTP/1.1\n\n"), Some(16));
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let request = "GET / HTTP/1.1\r\n\
             HOST: example.com\r\n\
             upgrade: WebSocket\r\n\
             CoNnEcTiOn: Upgrade\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             SEC-WEBSOCKET-VERSION: 13\r\n\r\n";
        // Asserting on the upgrade rather than on `is_ok`: a head that is not
        // an upgrade is now also `Ok`, so the weaker check would pass even if
        // none of these names matched.
        assert_eq!(upgrade_of(request.as_bytes()).path, "/");
    }

    #[test]
    fn accepts_connection_with_other_tokens_alongside_upgrade() {
        // Proxies add tokens to this header; requiring it to equal "Upgrade"
        // exactly breaks real clients.
        let request =
            good_request().replace("Connection: Upgrade", "Connection: keep-alive, Upgrade");
        assert_eq!(upgrade_of(request.as_bytes()).path, "/chat");
    }

    #[test]
    fn collects_offered_subprotocols_in_order() {
        let request = good_request().replace(
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Protocol: mcp, chat\r\nSec-WebSocket-Version: 13",
        );
        assert_eq!(upgrade_of(request.as_bytes()).protocols, ["mcp", "chat"]);
    }

    #[test]
    fn a_request_that_is_not_an_upgrade_comes_back_whole() {
        // These three used to be errors, which told a server only that no
        // WebSocket was coming and threw away the request it still had to
        // answer. Each is now a `Plain` carrying enough to answer it.
        let cases = [
            (
                good_request().replace("GET", "POST"),
                Method::Other("POST".to_string()),
            ),
            (good_request().replace("GET", "OPTIONS"), Method::Options),
            (good_request().replace("GET", "HEAD"), Method::Head),
            (
                good_request().replace("Upgrade: websocket\r\n", ""),
                Method::Get,
            ),
            (
                good_request().replace("Connection: Upgrade\r\n", ""),
                Method::Get,
            ),
        ];
        for (request, method) in cases {
            match parse_request(request.as_bytes(), DEFAULT_MAX_HEAD) {
                Ok(Parsed::Plain(plain)) => {
                    assert_eq!(plain.method, method);
                    assert_eq!(plain.path, "/chat");
                    // No key on a request that did not ask for one, whatever
                    // the head happened to carry.
                    assert!(plain.key.is_empty());
                }
                other => panic!("expected a plain request for {method:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_preflight_is_distinguishable_from_a_plain_get() {
        // The distinction a CORS policy turns on: both are answered with 200
        // and neither is an upgrade, but only one of them is asking for
        // permission on behalf of a request that has not been sent yet.
        let preflight = "OPTIONS /chat HTTP/1.1\r\n\
             Host: example.com\r\n\
             Origin: https://app.example.com\r\n\
             Access-Control-Request-Method: GET\r\n\
             Access-Control-Request-Headers: authorization\r\n\r\n";
        let parsed = parse_request(preflight.as_bytes(), DEFAULT_MAX_HEAD).unwrap();
        let Parsed::Plain(request) = parsed else {
            panic!("a preflight is not an upgrade");
        };
        assert_eq!(request.method, Method::Options);
        assert_eq!(
            header(&request, "access-control-request-method"),
            Some("GET")
        );
        assert_eq!(
            header(&request, "access-control-request-headers"),
            Some("authorization")
        );

        let plain = parse_request(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            DEFAULT_MAX_HEAD,
        )
        .unwrap();
        assert_eq!(plain.request().method, Method::Get);
        assert!(matches!(plain, Parsed::Plain(_)));
    }

    /// Look a header up the way a caller has to: case insensitively, first
    /// match wins.
    fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(had, _)| had.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn the_origin_survives_a_parse() {
        // The header the old parse dropped, and the one a server cannot
        // implement CORS without.
        let request = good_request().replace(
            "Host: example.com",
            "Host: example.com\r\nOrigin: https://app.example.com\r\nCookie: session=abc",
        );
        let parsed = upgrade_of(request.as_bytes());
        assert_eq!(header(&parsed, "origin"), Some("https://app.example.com"));
        assert_eq!(header(&parsed, "ORIGIN"), Some("https://app.example.com"));
        // Everything else is there too, including the names the parse
        // interprets for itself.
        assert_eq!(header(&parsed, "cookie"), Some("session=abc"));
        assert_eq!(header(&parsed, "sec-websocket-version"), Some("13"));
        assert_eq!(header(&parsed, "x-absent"), None);
    }

    #[test]
    fn refuses_a_head_with_too_many_headers() {
        // Retaining the headers means a peer can spend four bytes to make the
        // server allocate a `String` pair, so the count is capped as well as
        // the byte length.
        let mut request = good_request();
        request.pop();
        request.pop();
        request.push_str(&"a: b\r\n".repeat(MAX_HEADERS));
        request.push_str("\r\n");
        assert!(
            request.len() < DEFAULT_MAX_HEAD,
            "the byte guard would fire first"
        );
        assert_eq!(
            parse_request(request.as_bytes(), DEFAULT_MAX_HEAD),
            Err(UpgradeError::HeadTooLarge)
        );
    }

    #[test]
    fn rejects_upgrades_that_got_the_handshake_wrong() {
        let cases = [
            (
                good_request().replace("Version: 13", "Version: 8"),
                UpgradeError::WrongVersion,
            ),
            (
                good_request().replace("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", ""),
                UpgradeError::BadKey,
            ),
            (
                // Right shape, wrong length: 16 bytes of base64 is 24 chars.
                good_request().replace("dGhlIHNhbXBsZSBub25jZQ==", "c2hvcnQ="),
                UpgradeError::BadKey,
            ),
        ];
        for (request, expected) in cases {
            assert_eq!(
                parse_request(request.as_bytes(), DEFAULT_MAX_HEAD),
                Err(expected),
                "accepted a request it should have refused"
            );
        }
    }

    #[test]
    fn refuses_an_oversized_head() {
        // The guard that stops a peer growing the buffer forever by never
        // sending the blank line.
        let mut request = good_request();
        request.push_str(&"X-Padding: x\r\n".repeat(4096));
        assert_eq!(
            parse_request(request.as_bytes(), DEFAULT_MAX_HEAD),
            Err(UpgradeError::HeadTooLarge)
        );
    }

    #[test]
    fn a_response_completes_the_handshake_the_client_started() {
        let key = new_key([7u8; 16]);
        let request = build_request("/chat", "example.com", &key, &["mcp"], &[]);

        let parsed = upgrade_of(&request);
        assert_eq!(parsed.path, "/chat");
        assert_eq!(parsed.protocols, ["mcp"]);

        let response = build_response(&parsed.key, Some("mcp"), &[]);
        let protocol = check_response(&response, &key).expect("own response rejected");
        assert_eq!(protocol.as_deref(), Some("mcp"));
    }

    #[test]
    fn an_empty_extra_slice_changes_nothing() {
        // The compatibility claim in both doc comments, checked rather than
        // asserted: a caller that wants no extra headers gets the bytes this
        // crate sent before the parameter existed.
        let key = new_key([5u8; 16]);
        let expected = alloc::format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             Sec-WebSocket-Protocol: mcp\r\n\r\n",
            accept_for(key.as_bytes())
        );
        assert_eq!(
            build_response(key.as_bytes(), Some("mcp"), &[]),
            expected.into_bytes()
        );
        assert_eq!(
            build_rejection(UpgradeError::Malformed, &[]),
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn extra_headers_reach_a_101() {
        // What a deployment that terminates its own CORS needs on the success
        // path: its name, and permission for the browser to have asked.
        let key = new_key([6u8; 16]);
        let response = build_response(
            key.as_bytes(),
            None,
            &[
                ("Server", "endpoint-libs"),
                ("Access-Control-Allow-Origin", "https://app.example.com"),
            ],
        );
        let text = core::str::from_utf8(&response).unwrap();
        assert!(text.contains("\r\nServer: endpoint-libs\r\n"), "{text}");
        assert!(
            text.contains("\r\nAccess-Control-Allow-Origin: https://app.example.com\r\n"),
            "{text}"
        );
        // Before the blank line, not after it: a header past the terminator is
        // body, and a 101's body is the first frame.
        assert!(text.ends_with("https://app.example.com\r\n\r\n"), "{text}");
        // And the handshake still completes, which is the part the extra
        // headers must not disturb.
        assert_eq!(check_response(&response, &key), Ok(None));
    }

    #[test]
    fn extra_headers_reach_a_rejection() {
        let refusal = build_rejection(
            UpgradeError::WrongVersion,
            &[("Cache-Control", "no-store"), ("Server", "endpoint-libs")],
        );
        let text = core::str::from_utf8(&refusal).unwrap();
        assert!(text.starts_with("HTTP/1.1 426"), "{text}");
        // The headers the refusal already carried are still there, ahead of
        // the caller's.
        assert!(text.contains("Sec-WebSocket-Version: 13\r\n"), "{text}");
        assert!(text.contains("Content-Length: 0\r\n"), "{text}");
        assert!(text.contains("\r\nCache-Control: no-store\r\n"), "{text}");
        assert!(text.ends_with("Server: endpoint-libs\r\n\r\n"), "{text}");
    }

    #[test]
    fn a_client_rejects_a_response_with_the_wrong_accept() {
        // The check that stops a cache or a confused proxy from completing a
        // handshake it did not understand.
        let key = new_key([1u8; 16]);
        let other = new_key([2u8; 16]);
        let response = build_response(other.as_bytes(), None, &[]);
        assert_eq!(check_response(&response, &key), Err(UpgradeError::BadKey));
    }

    #[test]
    fn a_client_rejects_a_non_101_response() {
        let key = new_key([3u8; 16]);
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            check_response(response, &key),
            Err(UpgradeError::NotAnUpgrade)
        );
    }

    #[test]
    fn rejections_name_a_status_a_client_can_act_on() {
        let version = build_rejection(UpgradeError::WrongVersion, &[]);
        let text = core::str::from_utf8(&version).unwrap();
        assert!(text.starts_with("HTTP/1.1 426"), "{text}");
        // 426 must say which version would work, per RFC 6455 4.4.
        assert!(text.contains("Sec-WebSocket-Version: 13"), "{text}");

        // Still spelled here even though the parse no longer produces it: a
        // server that refuses a method wants this response.
        let bad = build_rejection(UpgradeError::NotGet, &[]);
        assert!(core::str::from_utf8(&bad)
            .unwrap()
            .starts_with("HTTP/1.1 400"));
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

// --- the HTTP upgrade -----------------------------------------------------

/// Why an upgrade request was not acceptable.
///
/// A server answers every one of these with a plain HTTP error rather than a
/// WebSocket frame, since by definition no WebSocket exists yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeError {
    /// The request head was not valid HTTP, or a header line had no colon.
    Malformed,
    /// The method was not GET. §4.2.1 requires it.
    ///
    /// **Breaking change in 0.3:** [`parse_request`] no longer produces this.
    /// A non-GET request is well formed HTTP and comes back as
    /// [`Parsed::Plain`] with its [`Method`] intact, because a server that
    /// answers `OPTIONS` and `HEAD` needs to see them rather than be told the
    /// handshake failed. The variant stays because a server that decides a
    /// method is unacceptable still wants [`build_rejection`] to spell the
    /// 400, and deleting it would take that spelling with it.
    NotGet,
    /// `Upgrade: websocket` or `Connection: Upgrade` was missing.
    NotAnUpgrade,
    /// `Sec-WebSocket-Version` was absent or not 13.
    WrongVersion,
    /// `Sec-WebSocket-Key` was absent or not 16 bytes of base64.
    BadKey,
    /// The head was longer than the caller's limit, which is a denial of
    /// service guard rather than a protocol rule: a peer that never sends the
    /// terminating blank line would otherwise grow the buffer forever.
    HeadTooLarge,
}

/// The largest request head this will parse, unless the caller says otherwise.
///
/// Generous for real traffic (cookies and auth headers are the large ones) and
/// small enough that ten thousand half-open connections cannot exhaust memory.
pub const DEFAULT_MAX_HEAD: usize = 16 * 1024;

/// The largest number of header lines a head may contain.
///
/// [`Request`] keeps every header it parsed, and a retained header costs far
/// more in small allocations than the four bytes (`a:\r\n`) a peer spends to
/// send one. `max_head` alone therefore stops bounding the memory once the
/// headers are kept: a head at the default limit made entirely of minimal
/// header lines would be four thousand `String` pairs. This caps the count as
/// well, on the same reasoning [`DEFAULT_MAX_HEAD`] caps the bytes. Real
/// requests carry a few dozen headers at the most; anything near this is not a
/// browser.
pub const MAX_HEADERS: usize = 128;

/// The method on the request line.
///
/// The three named here are the ones a WebSocket endpoint has to tell apart:
/// `GET` may be an upgrade, `OPTIONS` may be a CORS preflight, and `HEAD` is a
/// `GET` whose response carries no body. Everything else is a method this
/// crate has no opinion about, kept verbatim so the caller can form its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// `GET`, the only method §4.2.1 allows to carry an upgrade.
    Get,
    /// `OPTIONS`, which is what a browser sends ahead of a cross-origin
    /// request it is not sure it is allowed to make.
    Options,
    /// `HEAD`, answered with the headers of the `GET` and no body.
    Head,
    /// Any other method, as it appeared on the request line.
    Other(String),
}

/// What a server needs out of a client's upgrade request.
///
/// **Breaking change in 0.3:** `method` and `headers` are new fields, so
/// constructing this by literal no longer compiles. Both exist because a
/// server that answers preflights and echoes an `Origin` cannot do it from
/// the four things this used to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, which decides whether an upgrade was even possible.
    pub method: Method,
    /// The path requested, which routing may care about.
    pub path: String,
    /// The value to echo back through [`accept_for`], empty on a request that
    /// was not an upgrade.
    pub key: Vec<u8>,
    /// The subprotocols the client offered, in its order of preference.
    pub protocols: Vec<String>,
    /// Every header line, name and value, in the order it arrived.
    ///
    /// The parse used to match five names and drop the rest, which lost
    /// `Origin` and with it any chance of the caller implementing CORS. A
    /// narrower set was the alternative, and it was rejected: `Origin`,
    /// `Access-Control-Request-Method` and `Access-Control-Request-Headers`
    /// are what is wanted today, `Authorization`, `Cookie` and
    /// `X-Forwarded-For` are what gets wanted next, and each addition to an
    /// allowlist is another breaking release of this crate for a header it
    /// already had in its hand. Keeping all of them costs a bounded amount of
    /// memory ([`MAX_HEADERS`] entries out of at most `max_head` bytes) and no
    /// further releases.
    ///
    /// Names are stored exactly as they arrived, so a lookup must compare case
    /// insensitively, the same way the parse does. Duplicates are kept: which
    /// of two `Origin` headers to believe is a policy question and answering
    /// it here would hide the attack that asks it.
    pub headers: Vec<(String, String)>,
}

/// A parsed request head, and whether it asked for a WebSocket.
///
/// **Breaking change in 0.3:** [`parse_request`] returns this rather than a
/// bare [`Request`]. A plain `GET`, a `HEAD` and an `OPTIONS` preflight used
/// to collapse into [`UpgradeError::NotGet`] or
/// [`UpgradeError::NotAnUpgrade`], which told the caller only that no
/// WebSocket was coming. They are all perfectly good HTTP requests that a
/// server answers with 200 and its own headers, and it cannot do that from an
/// error that dropped the request on the floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// A well formed upgrade: the method is `GET`, the `Upgrade` and
    /// `Connection` headers are right, the version is 13, and `key` has
    /// passed [`is_valid_key`].
    Upgrade(Request),
    /// A well formed HTTP request that did not ask to be upgraded. The caller
    /// owns the answer; this crate does not know its routes or its CORS
    /// policy and will not invent either.
    Plain(Request),
}

impl Parsed {
    /// The request either way, for the fields that do not depend on which it
    /// was.
    pub fn request(&self) -> &Request {
        match self {
            Self::Upgrade(request) | Self::Plain(request) => request,
        }
    }

    /// Take the request out, for the same reason.
    pub fn into_request(self) -> Request {
        match self {
            Self::Upgrade(request) | Self::Plain(request) => request,
        }
    }
}

/// Find the end of an HTTP head.
///
/// Returns the offset just past the terminating blank line, or `None` if the
/// head has not fully arrived. Scanning for this before parsing is what makes
/// the parse work on a stream rather than needing the whole request at once.
pub fn head_end(input: &[u8]) -> Option<usize> {
    // A bare LF pair is tolerated as well as CRLF: some clients and many test
    // scripts send it, and rejecting them buys nothing.
    input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
        .or_else(|| {
            input
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|at| at + 2)
        })
}

/// Parse a client's request head.
///
/// `input` must contain a complete head, as found by [`head_end`].
///
/// **Breaking change in 0.3:** the success type is [`Parsed`], and the two
/// failures that were not really failures no longer occur.
/// [`UpgradeError::NotGet`] is gone from here entirely and
/// [`UpgradeError::NotAnUpgrade`] is now raised only by [`check_response`]:
/// a non-GET method and a `GET` without the upgrade headers both come back as
/// [`Parsed::Plain`], with the method and every header retained. What remains
/// an error is a head that is not HTTP, or one that asked for a WebSocket and
/// got the version or the key wrong, which is a client bug the caller should
/// not have to diagnose.
pub fn parse_request(input: &[u8], max_head: usize) -> Result<Parsed, UpgradeError> {
    if input.len() > max_head {
        return Err(UpgradeError::HeadTooLarge);
    }

    let text = core::str::from_utf8(input).map_err(|_| UpgradeError::Malformed)?;
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));

    // Request line: <method> <path> HTTP/1.1
    let start = lines.next().ok_or(UpgradeError::Malformed)?;
    let mut parts = start.split(' ');
    let method = parts.next().ok_or(UpgradeError::Malformed)?;
    let path = parts.next().ok_or(UpgradeError::Malformed)?;
    // The three named methods are matched case insensitively because the GET
    // check always was, and tightening that here would refuse clients this
    // crate has been serving.
    let method = if method.eq_ignore_ascii_case("GET") {
        Method::Get
    } else if method.eq_ignore_ascii_case("OPTIONS") {
        Method::Options
    } else if method.eq_ignore_ascii_case("HEAD") {
        Method::Head
    } else {
        Method::Other(method.to_string())
    };

    let mut upgrade_seen = false;
    let mut connection_seen = false;
    let mut version_ok = false;
    let mut key: Option<Vec<u8>> = None;
    let mut protocols = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(UpgradeError::Malformed)?;
        let value = value.trim();

        // Header names are case insensitive, and real clients vary.
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade_seen = value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            // The value is a comma separated list and `Upgrade` may sit
            // anywhere in it; some proxies add `keep-alive` alongside.
            connection_seen = value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            version_ok = value == "13";
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            key = Some(value.as_bytes().to_vec());
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            protocols.extend(
                value
                    .split(',')
                    .map(|token| token.trim().to_string())
                    .filter(|token| !token.is_empty()),
            );
        }

        // Retained after the matching, not instead of it: the five names above
        // are still interpreted here, and the copy is what lets a caller reach
        // the ones this crate has no use for.
        if headers.len() == MAX_HEADERS {
            return Err(UpgradeError::HeadTooLarge);
        }
        headers.push((name.to_string(), value.to_string()));
    }

    let mut request = Request {
        method,
        path: path.to_string(),
        key: Vec::new(),
        protocols,
        headers,
    };

    // Not an upgrade attempt at all. This is the answerable case: a browser
    // address bar, a health check, a preflight. Hand it back whole.
    if request.method != Method::Get || !upgrade_seen || !connection_seen {
        return Ok(Parsed::Plain(request));
    }

    // Past here it meant to open a WebSocket and got it wrong, which is worth
    // a status code naming the reason rather than a 200.
    if !version_ok {
        return Err(UpgradeError::WrongVersion);
    }
    let key = key.ok_or(UpgradeError::BadKey)?;
    if !is_valid_key(&key) {
        return Err(UpgradeError::BadKey);
    }

    request.key = key;
    Ok(Parsed::Upgrade(request))
}

/// Build the 101 response that completes the handshake.
///
/// `protocol` names the subprotocol the server selected, which must be one the
/// client offered; `None` selects none, which is always legal.
///
/// `extra` is appended after the headers RFC 6455 requires and before the
/// blank line, for the ones it says nothing about: `Server`, a CORS set, or
/// whatever else the deployment puts on every response. Nothing in it is
/// validated or deduplicated, so a caller that writes `Upgrade` a second time
/// gets a response with two of them.
///
/// **Breaking change in 0.3:** `extra` is a new parameter. It was added to
/// this function rather than paired with a `build_response_with` twin because
/// [`build_request`] already carries exactly this parameter under exactly this
/// name, and two functions that must be kept byte for byte in step is how the
/// one nobody calls drifts. `&[]` produces the same bytes as before.
pub fn build_response(key: &[u8], protocol: Option<&str>, extra: &[(&str, &str)]) -> Vec<u8> {
    let accept = accept_for(key);
    let mut out = String::with_capacity(160);
    out.push_str("HTTP/1.1 101 Switching Protocols\r\n");
    out.push_str("Upgrade: websocket\r\n");
    out.push_str("Connection: Upgrade\r\n");
    out.push_str("Sec-WebSocket-Accept: ");
    out.push_str(&accept);
    out.push_str("\r\n");
    if let Some(protocol) = protocol {
        out.push_str("Sec-WebSocket-Protocol: ");
        out.push_str(protocol);
        out.push_str("\r\n");
    }
    for (name, value) in extra {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Build the plain HTTP refusal for a request that cannot be upgraded.
///
/// A WebSocket client sees the status and gives up, which is the point: the
/// alternative is leaving the connection open while it waits for frames that
/// are never coming.
///
/// `extra` is appended before the blank line, on the same terms as
/// [`build_response`]. An error response is where a deployment most wants its
/// own headers: `Cache-Control: no-store` so an intermediary does not serve
/// the refusal to somebody else, and the CORS set so a browser is allowed to
/// read the status instead of reporting a network error it cannot explain.
///
/// **Breaking change in 0.3:** `extra` is a new parameter. `&[]` produces the
/// same bytes as before.
pub fn build_rejection(error: UpgradeError, extra: &[(&str, &str)]) -> Vec<u8> {
    let (status, reason) = match error {
        UpgradeError::WrongVersion => ("426 Upgrade Required", "Sec-WebSocket-Version: 13\r\n"),
        UpgradeError::HeadTooLarge => ("431 Request Header Fields Too Large", ""),
        _ => ("400 Bad Request", ""),
    };
    let mut out = String::with_capacity(96);
    out.push_str("HTTP/1.1 ");
    out.push_str(status);
    out.push_str("\r\n");
    out.push_str(reason);
    out.push_str("Connection: close\r\n");
    out.push_str("Content-Length: 0\r\n");
    for (name, value) in extra {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Build a client's upgrade request.
///
/// `key` should come from [`new_key`]; `host` is what the server will match
/// against its own name, and is required by §4.1.
pub fn build_request(
    path: &str,
    host: &str,
    key: &str,
    protocols: &[&str],
    extra: &[(&str, &str)],
) -> Vec<u8> {
    let mut out = String::with_capacity(160);
    out.push_str("GET ");
    out.push_str(path);
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(host);
    out.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    out.push_str(key);
    out.push_str("\r\nSec-WebSocket-Version: 13\r\n");
    if !protocols.is_empty() {
        out.push_str("Sec-WebSocket-Protocol: ");
        out.push_str(&protocols.join(", "));
        out.push_str("\r\n");
    }
    for (name, value) in extra {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Check a server's response against the key that was sent.
///
/// The accept value is the only thing that proves the peer understood the
/// handshake rather than being a cache or a proxy replaying a 101 it liked the
/// look of, so it is checked rather than assumed.
pub fn check_response(input: &[u8], key: &str) -> Result<Option<String>, UpgradeError> {
    let text = core::str::from_utf8(input).map_err(|_| UpgradeError::Malformed)?;
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));

    let status = lines.next().ok_or(UpgradeError::Malformed)?;
    if !status.contains("101") {
        return Err(UpgradeError::NotAnUpgrade);
    }

    let expected = accept_for(key.as_bytes());
    let mut accept_ok = false;
    let mut protocol = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("sec-websocket-accept") {
            accept_ok = value == expected;
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            protocol = Some(value.to_string());
        }
    }

    if !accept_ok {
        return Err(UpgradeError::BadKey);
    }
    Ok(protocol)
}

/// Generate a `Sec-WebSocket-Key` from 16 bytes of caller-supplied randomness.
///
/// The randomness is a parameter rather than taken from a generator here for
/// the same reason the masking key is: this module does no I/O, and a key that
/// silently came from a weak source would be worse than one the caller had to
/// think about. §4.1 wants it unpredictable so a cache cannot replay a
/// handshake, not secret.
pub fn new_key(entropy: [u8; 16]) -> String {
    base64_encode(&entropy)
}
