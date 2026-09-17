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

Still to come: TLS, the HTTP upgrade, and the `endpoint-libs` adapter.
