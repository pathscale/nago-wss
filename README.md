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

What that left behind is a crate with no platform bindings of its own. The
syscall bindings went with the reactor, and name resolution followed:
`client` calls `nagoya::reactor::resolve` and `nagoya::reactor::connect_any`.
There is no `unsafe` left in this crate.

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

Measured 2026-09-18 on an idle laptop: 12 performance cores and 4 efficiency
cores, 16 logical. Three arms throughout: this crate, tokio-tungstenite (what
the fleet runs today) and sockudo-ws, each through its own public entry point.

Everything below is one run of each benchmark, reported whether it flatters
this crate or not. Where a benchmark is unstable, the spread is stated rather
than hidden behind a single figure.

### Reproducing

```sh
cargo bench
```

Or one at a time, with `--bench micro`, `--bench echo`, `--bench concurrent`,
`--bench scale`, `--bench floor`.

`micro` requires `simd-utf8`, which is on by default, so it cannot silently
measure the scalar fallback instead of the vector path. That feature is worth
having on: measured against `core::str::from_utf8` over the same 16 KiB
buffers, 57.37 GB/s becomes 115.84 on ASCII and 2.56 GB/s becomes 13.49 on
mixed text. Turning it off with `default-features = false` is for a consumer
that will not carry `unsafe`, and costs only speed.

Every arm connects to a `SocketAddr` directly. The tokio arms used to connect
by URL, which put the system resolver in front of the socket: with a VPN
holding DNS that turned a one second benchmark into a multi minute one.
Numbers taken before that was fixed penalised the tokio arms and are not
comparable to these.

### The one that matters: concurrent throughput

Aggregate messages per second through the process, 256 byte echo, server and
clients in one process over loopback. This is the shape a fleet actually runs
and the benchmark to read first.

| conns | nago-wss | tokio-tungstenite | sockudo-ws | standing |
|---|---|---|---|---|
| 1 | 16.0k-16.7k | 42.0k-46.2k | 41.9k-49.2k | **behind, roughly 2.6x** |
| 8 | 133k-143k | 181k-201k | 142k-166k | **behind, roughly 1.4x** |
| 32 | 174k | 177k-183k | 137k-138k | level with tokio, ahead of sockudo |

With the clients moved onto the server's reactor rather than one reactor per
client thread, which is the shape tokio's arm already had: 19.7k-28.3k at one
connection, 146k-148k at eight, 168k-174k at 32. Better at one connection, not
enough to close either gap.

The deficit is at low connection counts and closes as load rises. It is not
explained; the list of explanations already measured and withdrawn is under
[Where this loses](#where-this-loses).

### Everything else, in one table

Concurrent throughput is above and not repeated here. Bold is the winner of a
row. `msg/s` is messages per second, higher better; `us/op` is microseconds per
operation, lower better.

| bench | case | nago-wss | tokio-tungstenite | sockudo-ws | result |
|---|---|---|---|---|---|
| echo | round trip 43 B | 19.37 us/op, 51,635 msg/s | 18.59 us/op, 53,795 msg/s | **15.94 us/op, 62,717 msg/s** | sockudo 1.21x faster; tokio within sample overlap |
| echo | streaming 64 B | 0.05 us/op, 19,933,422 msg/s, 1231 MiB/s | 1.45 us/op, 689,002 msg/s, 51 MiB/s | 1.66 us/op, 603,531 msg/s, 53 MiB/s | see the caveat below, this is not like for like |
| echo | streaming 4096 B | 0.65 us/op, 1,528,517 msg/s, 6065 MiB/s | 1.79 us/op, 558,490 msg/s, 2192 MiB/s | 1.82 us/op, 548,647 msg/s, 2269 MiB/s | same caveat |
| scale | 10k establish | **0.43 s** | 0.81 s | 1.18 s | nago 1.9x faster |
| scale | 10k broadcast | **101 ms** | 329 ms | 285 ms | nago 3.3x faster |
| scale | 10k bytes per conn | 43,624 B | 151,620 B | **35,433 B** | sockudo lowest, nago 3.5x under tokio |
| floor | 1 B round trip, threaded | 24.51 us/op | **15.14 us/op** (one thread) | - | tokio 1.6x faster |
| floor | 1 B round trip, local | 21.21 us/op | 18.48 us/op (two threads) | - | tokio faster |
| micro | masking 64 B | 241,113,736/s, 15.43 GB/s | 306,267,555/s, 19.60 GB/s | **323,364,033/s, 20.70 GB/s** | sockudo 1.34x, tungstenite 1.27x |
| micro | masking 1024 B | **85,478,041/s, 87.53 GB/s** | 70,236,307/s, 71.92 GB/s | 52,773,304/s, 54.04 GB/s | nago wins |
| micro | masking 16384 B | 7,303,615/s, 119.66 GB/s | **7,415,821/s, 121.50 GB/s** | 3,740,077/s, 61.28 GB/s | tungstenite 1.02x |
| micro | masking 262144 B | 265,218/s, 69.53 GB/s | **269,843/s, 70.74 GB/s** | 242,804/s, 63.65 GB/s | tungstenite 1.02x |
| micro | utf8 ascii 64 B | 581,397,943/s, 37.21 GB/s | 325,128,825/s, 20.81 GB/s | **631,382,711/s, 40.41 GB/s** | sockudo 1.09x |
| micro | utf8 ascii 1024 B | 156,285,610/s, 160.04 GB/s | 52,376,618/s, 53.63 GB/s | **161,759,969/s, 165.64 GB/s** | sockudo 1.04x |
| micro | utf8 ascii 16384 B | 10,405,548/s, 170.48 GB/s | 3,345,538/s, 54.81 GB/s | **10,433,817/s, 170.95 GB/s** | sockudo 1.00x |
| micro | utf8 ascii 262144 B | 414,980/s, 108.78 GB/s | 202,315/s, 53.04 GB/s | **418,426/s, 109.69 GB/s** | sockudo 1.01x |
| micro | utf8 mixed 64 B | **199,912,453/s, 12.79 GB/s** | 41,074,204/s, 2.63 GB/s | 198,607,180/s, 12.71 GB/s | nago level with sockudo, 5x tungstenite |
| micro | utf8 mixed 1023 B | **13,416,891/s, 13.73 GB/s** | 2,679,180/s, 2.74 GB/s | 13,348,389/s, 13.66 GB/s | nago level with sockudo |
| micro | utf8 mixed 16384 B | **844,940/s, 13.84 GB/s** | 176,128/s, 2.89 GB/s | 843,252/s, 13.82 GB/s | nago level with sockudo |
| micro | utf8 mixed 262144 B | 52,578/s, 13.78 GB/s | 10,729/s, 2.81 GB/s | **52,682/s, 13.81 GB/s** | sockudo 1.00x |

Protocol core operations with no comparison arm, because the other two crates
do not expose an equivalent entry point. Sizes are 64 B, 1024 B, 16384 B and
262144 B:

| operation | 64 B | 1024 B | 16384 B | 262144 B |
|---|---|---|---|---|
| decode frame (masked) | 4.2 ns | 20.1 ns | 292.3 ns | 7374.9 ns |
| encode header | 2.0 ns | 1.8 ns | 1.5 ns | 2.0 ns |
| encode frame (client) | 3.7 ns | 24.4 ns | 274.9 ns | 7362.5 ns |
| assemble (unfragmented) | 6.4 ns | 6.4 ns | 6.4 ns | 6.3 ns |
| full message (encode, decode, assemble) | 26.7 ns | 72.0 ns | 712.0 ns | 16072.4 ns |

Handshake accept key: 425.2 ns, 2,351,610/s. Buffer alloc and fill: 23.0 ns,
43,386,441/s.

### The streaming figure is not a like for like win

`echo`'s streaming rows show this crate at 24x tokio-tungstenite at 64 bytes.
That is a batching difference, not a speed difference: `Connection::write_all`
coalesces a caller supplied batch into a single write, and the other two arms
send one message per call. A caller that hands this crate one message at a
time will not see that number. It is in the table because it is what the
benchmark measures, and it is annotated because quoting it unqualified would
be dishonest.

### What is unstable, and by how much

Two of these benchmarks do not repeat well, and a single reading from either
should not be quoted:

- `concurrent` at 8 connections has been observed between 90k and 182k msg/s
  on identical code. The two runs above are 133k and 143k.
- `floor`'s threaded arm swings between 17.77 and 24.66 us on unchanged code,
  and has beaten the local arm in one run of three.

`scale` and `micro` repeat reliably.

### Where this loses

At one connection and at eight, against both other crates. At 32 connections
it is level with tokio and ahead of sockudo, so the deficit is at low
connection counts and closes as load rises.

That gap is not yet explained. Several explanations have been offered and
each was withdrawn after measurement:

- Syscall count. Measured at `Connection::read` with nagoya's counters: one
  `recv` per message and zero `EWOULDBLOCK` at 1, 8 and 32 connections. The
  read path is already at the floor.
- Reactor sharding. `Reactor::sharded` measured worse: 120k against 135k at
  eight connections.
- Masking. A NEON implementation was slower than the scalar word loop at every
  size.
- The thread handoff. A single thread reactor loop measures 20.13us against
  tokio's 18.38, so the ceiling is already below target and removing the
  handoff cannot close it.
- Worker pool parking. A profile suggested it; an exact counter refuted it,
  reporting zero spurious wakes at every pool size.

`benches/floor.rs` carries the full list of what has been ruled out, with the
numbers.

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

Conformance: **the Autobahn cases are ported, 58 tests under `cargo test`.**
No container, no server, no sockets, no runtime. The published suite ships only
as a Docker image, so rather than carry one, the rules it encodes are written
directly against the protocol core, numbered after Autobahn's own cases so each
one can be read against its published description.

Where a section is large and mechanical the rule is written out and the cases
generated from it, which covers more sequences than the published list does:
section 6 alone is twenty nine malformed UTF-8 sequences in four contexts,
about three hundred and eighty assertions, against the hundred and forty five
cases the suite ships.

They run in hundredths of a second, they name what they check, and a failure
points at a line rather than a case number in an HTML report. That is the
difference that matters while writing the crate.

Sections 12 and 13 are not covered, and would be excluded from the suite in any
case. They are `permessage-deflate`, which this crate does not implement: no
extension is negotiated, so a peer that sets a reserved bit is speaking a
protocol that was never agreed to and the frame is refused. That is the right
answer to those cases, but the suite scores them against a compressor.

`examples/autobahn_server.rs` remains, so anyone who does want to point the
published suite at this crate can. Nothing in the build, the tests or CI
depends on it.

Still to come: the `endpoint-libs` adapter.
