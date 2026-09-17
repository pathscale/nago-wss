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

**The reactor** is readiness over kqueue/epoll, driving the core. It is fully
event driven: the thread blocks in `kevent`/`epoll_wait`, which is an
interrupt-driven kernel wait, and is woken by a descriptor changing state, by an
expiring deadline, or by an explicit wake. There is no tick, no retry interval
and no spin anywhere in the crate.

Timers are event driven in the same sense, which takes a little care. The next
deadline is cached in an atomic, and nagoya's timer wheel is consulted only when
that deadline actually arrives or when a caller arms a sooner one. The naive
version asks the wheel on every wakeup, which means a connection delivering ten
thousand readiness events a second takes the timer lock ten thousand times to
learn that nothing is due. Socket traffic and timer work stay independent.

[Nagoya](https://github.com/pathscale/nagoya) deliberately ships no I/O driver:
*"a caller that wants sockets brings its own reactor."* So the reactor lives
here. Nagoya supplies the scheduler, `sync` and `time`, which is most of what a
WebSocket stack actually takes from a runtime; this crate supplies the sockets.

The split costs nothing at runtime. There are no trait objects across it and no
per-frame allocation on either path, so the reactor's calls into the core
monomorphise exactly as if the layering were not there.

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

Protocol core, no sockets, on an M-series laptop. Rates are operations per
second; the three arms are this crate, tungstenite (what the fleet runs today)
and sockudo-ws, each through its own public entry point.

### Masking

Every byte a client sends and every byte a server receives.

| payload | nago-wss | tungstenite | sockudo-ws |
|---|---|---|---|
| 64 B | **73.8M/s** (4.72 GB/s) | 32.8M/s (2.10) | 19.0M/s (1.22) |
| 1 KB | **8.8M/s** (8.99) | 8.4M/s (8.64) | 4.4M/s (4.56) |
| 16 KB | **905K/s** (14.82) | 496K/s (8.12) | 188K/s (3.08) |
| 256 KB | **53.7K/s** (14.07) | 35.9K/s (9.40) | 10.7K/s (2.81) |

A 64-bit word loop, which beats tungstenite's 32-bit one and beats
sockudo-ws's SIMD. No unsafe.

### UTF-8 validation

Text frames only; binary skips it. With `simd-utf8` on.

| payload | nago-wss | tungstenite | sockudo-ws |
|---|---|---|---|
| ascii 1 KB | **17.46 GB/s** | 9.07 | 4.01 |
| ascii 16 KB | 23.37 | 2.06 | **28.85** |
| mixed 1 KB | 0.88 | 0.22 | **1.58** |
| mixed 16 KB | 1.33 | 0.26 | **2.23** |

Without the feature this is the standard library's byte loop and sockudo-ws is
eight times faster. With it, that gap closes to between 1.1 and 1.8, and
tungstenite is two to five times behind.

### A whole message

Encode, mask, decode, unmask, reassemble.

| payload | rate |
|---|---|
| 64 B | 7.7M msg/s |
| 1 KB | 1.6M msg/s |
| 16 KB | 242K msg/s |

### Ten thousand connections

Both ends in one process, so every arm is handicapped the same way.

| | establish | broadcast | memory |
|---|---|---|---|
| nago-wss | **0.89 s** | **194 ms** | 42 KB/conn |
| tokio-tungstenite | 2.11 s | 475 ms | 151 KB/conn |
| sockudo-ws | 4.18 s | 263 ms | **35 KB/conn** |

### Where this loses

A single connection doing one round trip at a time on loopback: about 17.8us
against tokio's 14.7. Most of that is neither crate's, a unix socketpair does
the same handoff in 4.9us against loopback TCP's 12.1, but the remaining
difference is real and not yet explained.

Run them with `cargo bench --bench micro`, `--bench scale`, `--bench floor`.

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

The reactor:

- kqueue and epoll behind one type, edge triggered
- generational tokens, so a readiness event in flight when a registration is
  dropped cannot wake whatever later takes the same slot
- async `TcpStream` and `TcpListener`, draining to `EWOULDBLOCK` before parking
  a waker

The connection joins the two, enforcing the masking rules in both directions.

Conformance: 55 tests run under `cargo test`, covering Autobahn's sections 1
through 7 and the shape of 9. Fragmentation and its interleaving rules,
reserved bits and opcodes, control frame limits, the close code registry over
the whole u16 space, every length encoding boundary as text and as binary and
whole and fragmented, the first and last codepoint of each UTF-8 width,
truncated and overlong and surrogate sequences, and what happens to anything
sent after a close.

Most of it is generated from the rule rather than transcribed from the case
list, so it covers more sequences than Autobahn publishes: section 6 alone is
twenty nine malformed sequences in four contexts, around three hundred and
eighty assertions, against the hundred and forty five cases the suite ships.
Sections 12 and 13 are skipped deliberately: they are `permessage-deflate`,
which is not implemented here, and a reserved bit is a hard error.

**Autobahn itself has not been run.** It ships as a Docker image and `wstest`
needs Python 2, so these cases are written from its specifications rather than
driven by it. The rules are covered, but a suite catches what its author did
not think to test, and this one cannot make that claim.

Still to come: the `endpoint-libs` adapter.
