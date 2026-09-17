# nago-wss

RFC 6455 WebSockets without tokio.

The fleet speaks WebSocket through `endpoint-libs`, and underneath that sat
`tokio-tungstenite`, which brings the whole tokio runtime along for what is, in
the end, a framing layer and a reactor. This is the replacement.

## Shape

Two layers, and the boundary between them is the point.

**`proto`** is the protocol with no I/O in it at all. Bytes in, frames out;
frames in, bytes out. It is `no_std` plus `alloc`, it forbids `unsafe`, and it
is testable exhaustively without a socket. This is the part that has to be
correct.

**The connection** joins that core to a socket. It is generic over
`stream::ByteStream`, so the same code runs over TCP, over TLS, or over an
in-memory pipe in a test, and it enforces the masking rules in both directions.

The readiness reactor was written here and now lives in
[nagoya](https://github.com/pathscale/nagoya) as `nagoya::reactor`. It was moved
because none of it was about WebSockets: generational tokens, edge triggered
registration and integrating a timer wheel without polling it are the same
problem for anything that wants a socket, and the ways of getting them wrong are
quiet ones. It is still fully event driven, with no tick, no retry interval and
no spin, and the timer integration still caches the next deadline so a socket
delivering ten thousand events a second never takes the timer lock to be told
nothing is due.

What that left behind is a crate with almost no platform in it. The syscall
bindings went with the reactor, and one `unsafe` block remains: the
`getaddrinfo` binding in `client`, which turns a hostname into addresses.
Nagoya has no resolver yet, and that is the only reason it is still here.

The split costs nothing at runtime. There are no trait objects across it and no
per-frame allocation on either path, so the calls into the core monomorphise
exactly as if the layering were not there.

## Only what is used

This is not a general-purpose WebSocket library and does not try to be.
`permessage-deflate` is not implemented, and the RSV bits are therefore a hard
error rather than a negotiation. What the fleet does not use is not here.

## On the SHA-1

`Sec-WebSocket-Accept` is defined by RFC 6455 §1.3 as SHA-1 over the client key
concatenated with a constant, publicly known GUID. It carries no secret and
proves no identity. It exists so a caching proxy cannot accidentally complete a
WebSocket handshake, and SHA-1's collision weaknesses do not bear on that.

The implementation in `proto::handshake` is private and exists for that one
value. It is not a general-purpose hash and should not be used as one.

## Numbers

Re-measured 2026-09-17 on an idle 16 core M-series laptop, after the reactor
moved to nagoya. Rates are operations per second; the three arms are this
crate, tungstenite (what the fleet runs today) and sockudo-ws, each through its
own public entry point.

Run them with `cargo bench --features simd-utf8`. The earlier table here was
taken on a machine under heavy load and every figure in it was low by roughly
four times, which is why these are larger rather than better.

### Masking

Every byte a client sends and every byte a server receives.

| payload | nago-wss | tungstenite | sockudo-ws |
|---|---|---|---|
| 64 B | 18.46 GB/s | 18.96 | **22.59** |
| 1 KB | **85.52** | 70.33 | 53.99 |
| 16 KB | 118.36 | 118.42 | 58.89 |
| 256 KB | 68.10 | **68.56** | 62.82 |

A 64-bit word loop. It beats sockudo-ws's hand written NEON at 1 KB and above,
by a wide margin, and loses to it at 64 bytes where there are too few
iterations to amortise the call. Against tungstenite's 32-bit loop it wins at
1 KB and ties within a percent everywhere else, which is inside this
benchmark's run to run spread: do not read those rows as a win in either
direction. No unsafe.

### UTF-8 validation

Text frames only; binary skips it. Requires `--features simd-utf8`, and the
benchmark refuses to build without it: the fallback is the standard library's
byte loop, which is the same code as the tungstenite column, and measuring it
makes this crate look three times slower than it is.

| payload | nago-wss | tungstenite | sockudo-ws |
|---|---|---|---|
| ascii 64 B | **40.21 GB/s** | 20.65 | 36.89 |
| ascii 1 KB | **168.04** | 54.19 | 162.07 |
| ascii 16 KB | 169.60 | 56.81 | **170.16** |
| ascii 256 KB | **109.26** | 55.18 | 108.79 |
| mixed 64 B | **12.68** | 2.42 | 12.68 |
| mixed 1 KB | **13.49** | 2.96 | 13.29 |
| mixed 16 KB | 13.57 | 2.69 | **13.71** |
| mixed 256 KB | **13.75** | 2.51 | 13.66 |

Level with sockudo-ws's hand written SIMD, within one percent either way, and
three to five times ahead of tungstenite. Ours is `simdutf8`, a crate that
contains unsafe but is not this crate's unsafe, which is why it is a feature.

### A whole message

Encode, mask, decode, unmask, reassemble.

| payload | rate |
|---|---|
| 64 B | 36.1M msg/s |
| 1 KB | 12.8M msg/s |
| 16 KB | 1.38M msg/s |

### Ten thousand connections

Both ends in one process, so every arm is handicapped the same way.

| | establish | broadcast | memory |
|---|---|---|---|
| nago-wss | **0.44 s** | **88.2 ms** | 43.6 KB/conn |
| tokio-tungstenite | 0.78 s | 324.8 ms | 151.5 KB/conn |
| sockudo-ws | 1.18 s | 296.4 ms | **35.4 KB/conn** |

Broadcast is 3.7x tokio-tungstenite's and establish 1.8x, on 3.5x less memory.
This is the most repeatable result here: broadcast has measured between 85 and
89ms across every run since reactor wakes were routed to the worker holding
each descriptor, against 95 to 99ms before it.

### Concurrency

Aggregate throughput, 256 byte echo, messages per second.

| connections | nago-wss | tokio-tungstenite | sockudo-ws |
|---|---|---|---|
| 1 | 12,685 | 14,401 | **15,237** |
| 8 | 125,049 | **169,566** | 154,974 |
| 32 | 174,436 | **175,511** | 139,126 |

**Read this table with suspicion.** The same binary on an idle machine has
produced 90k and 182k at eight connections on consecutive runs, so a single
reading of any row is worth little and the earlier numbers here, which showed
this crate winning at one and eight connections, were that noise rather than a
result. What repeats is the shape: tokio-tungstenite leads in the middle, and
the three converge by thirty two.

Ten thousand connections, below, is the count that does repeat, and it is also
the one a fleet actually runs.

### Where this loses

A single connection doing one round trip at a time on loopback: 20.2us against
tokio-tungstenite's 17.0 and sockudo-ws's 15.3. Streaming small payloads is
worse, 1.54us against tokio's 0.59 at 64 bytes.

Most of that is neither crate's, and most of the rest is one thing: a reactor
that polls on a different thread from the one the kernel returned to pays a
park and an unpark per message, measured at 3.6us. `Reactor::local` does not,
and is 2.4 to 2.9us faster than the threaded reactor as a result. Use it for a
connection driven by one thread, which is the shape a WebSocket server usually
wants anyway.

What is left after that is not a fixed cost. Against a tokio arm given the same
two thread shape, eight consecutive paired runs on an idle machine put this
crate 3.4us behind seven times and exactly level once, from the same binary.
That is a scheduling interaction rather than slow code, and chasing it means
pinning threads and reading the scheduler. `benches/floor.rs` has the numbers
and the list of what has already been measured and ruled out.

Worth noting where this crate is not behind: waking a task and repolling it,
with no I/O at all, is 0.0018us here against tokio's 0.0714.

Run them with `cargo bench --features simd-utf8`, or one at a time with
`--bench micro`, `--bench echo`, `--bench concurrent`, `--bench scale`,
`--bench floor`.

## Status

Working end to end over real TCP, with no tokio in the path.

The protocol core:

- frame header codec, strict about the things the RFC says to fail on
  (reserved bits and opcodes, oversized or fragmented control frames,
  non-minimal length encodings)
- masking, applied a word at a time, checked against the RFC's own definition
  at every length and key offset
- message reassembly, with UTF-8 validated across fragment boundaries and a
  message-level size cap
- the opening handshake, checked against the worked example in the RFC

The connection, over whatever `nagoya::reactor` or a TLS session provides:

- the masking rules, enforced in both directions
- a read path that parses every frame already buffered before returning to the
  socket, so a batch of messages costs one syscall rather than one each
- the fast paths a socket has and a general stream does not, behind `StreamExt`:
  reading into a `BytesMut`'s uninitialised tail, and writing a frame header and
  its payload without joining them

Conformance: **the Autobahn suite passes, 301 of 301 cases.** It runs in CI on
every push, against the echo server in `examples/autobahn_server.rs`, and the
report is kept as a build artifact. `autobahn/README.md` has the command to run
it yourself.

Sections 12 and 13 are excluded and nothing else is. They are
`permessage-deflate`, which this crate does not implement: no extension is
negotiated, so a peer that sets a reserved bit is speaking a protocol that was
never agreed to and the frame is refused. That is the right answer to those
cases, but the suite scores them against a compressor.

Alongside it, 58 tests run under `cargo test` with no suite, no server and no
sockets, written straight against the protocol core. They exist because a
failure there names a rule and points at a line, where Autobahn points at a
case number in an HTML report. Most are generated from the rule rather than
transcribed from the case list, so they cover more sequences than Autobahn
publishes: section 6 alone is twenty nine malformed UTF-8 sequences in four
contexts, about three hundred and eighty assertions, against the hundred and
forty five cases the suite ships.

Still to come: the `endpoint-libs` adapter.
