//! What the transport costs before any WebSocket exists.
//!
//! The echo benchmark compares three WebSocket stacks and finds them within
//! about 20% of each other, which is a suspicious result: the framing code in
//! each differs far more than that. This measures the floor underneath them,
//! a bare ping-pong over TCP with no protocol at all, on this crate's reactor
//! and on tokio.
//!
//! If the two floors match the two WebSocket numbers, the framing is not what
//! is being measured and optimising it is wasted effort.
//!
//! # Why there is no sockudo-ws arm here
//!
//! It runs on tokio, so its transport floor is the tokio arm. A third column
//! would measure the same reactor twice and imply a difference that does not
//! exist. Where sockudo-ws differs is above this line, in framing and in how
//! it drives many connections, which is what `micro` and `scale` measure.
//!
//! # What the remaining gap is not
//!
//! This crate sits about 3us behind tokio on a single connection doing one
//! round trip at a time. Each of these was measured and none of them accounts
//! for it:
//!
//! * **Syscall count.** A trivial syscall costs a nanosecond here, and both
//!   designs make the same three calls per trip: an optimistic read, a wait,
//!   then the real read. Counted directly, the read blocks on 0.98 of trips,
//!   so neither side is winning by guessing better.
//! * **std::net.** Measured equal to raw `send`/`recv`, and it is gone from
//!   this crate's path anyway.
//! * **The reactor's own work.** One `kevent` with an event already pending
//!   is 0.34us, a mutex pair 0.009us, a clock read 0.024us. The whole of it
//!   is under a microsecond per trip.
//! * **Copies.** The read path is copy-free from the socket to the message.
//!
//! # The thread handoff, which was wrongly eliminated
//!
//! This list used to say `Reactor::local` "measured the same as the threaded
//! reactor". It does not, and the measurement that said so was taken on a
//! machine under a load average of 150, which flattened every arm together.
//! Re-measured idle, `local` is consistently 2.4 to 2.9us faster than the
//! threaded reactor, and `examples/floor_probe.rs` puts a park/unpark round
//! trip between two threads at 3.6us: paid once per message by a reactor that
//! polls somewhere other than where the kernel returned.
//!
//! So the handoff is most of the threaded arm's gap, and using `local` is the
//! answer to it rather than a tuning exercise.
//!
//! # What remains, and why it is not a fixed cost
//!
//! Against a tokio arm given the same two thread shape, `local` is bimodal.
//! Eight consecutive paired runs on an idle machine:
//!
//! ```text
//!   local  22.07 21.62 21.44 21.99 21.54 21.61 21.62 18.33
//!   tokio  18.39 18.18 18.02 18.25 18.38 18.20 18.35 18.23
//! ```
//!
//! Seven runs sit 3.4us behind. The eighth is level, from the same binary on
//! the same machine. A fixed cost in the code path cannot do that, so what is
//! left is a scheduling interaction that this arrangement usually loses and
//! occasionally does not, most likely which core the two threads land on.
//!
//! Chasing it further means pinning threads and reading the scheduler, which
//! is a different kind of work from anything above. It is also the shape this
//! crate is worst at and a fleet is least likely to run: ten thousand
//! connections is the case that matters and this crate leads it comfortably.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use nagoya::reactor::Addr;
use nagoya::reactor::{Reactor, TcpListener, TcpStream};

const ROUND_TRIPS: usize = 500;
const SAMPLES: usize = 3;

/// Loopback, port chosen by the kernel. For the tokio and sockudo arms.
fn local() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// The same, in this crate's own address type.
fn local_addr() -> Addr {
    Addr::localhost(0)
}

fn best(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[0]
}

/// The same, with the reactor and the task sharing a thread.
///
/// This is the arrangement tokio's current-thread runtime uses, and the one
/// the threaded reactor below pays a park and unpark per message to avoid.
fn nago_local_floor() -> Duration {
    use nagoya::reactor::block_on_with;
    use nagoya::reactor::Reactor;

    let reactor = Reactor::local().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(local_addr(), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    // The echo half is a plain blocking socket on its own thread. What is
    // being measured is this side's path; giving the peer its own reactor
    // would measure two of them and hide which one cost what.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let reactor = Reactor::local().expect("reactor");
        block_on_with(&reactor, async move {
            // Tell the client the accept is armed before it connects, so the
            // two do not race.
            ready_tx.send(()).expect("signal");
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut byte = [0u8; 1];
            for _ in 0..ROUND_TRIPS {
                let read = stream.read(&mut byte).await.expect("read");
                if read == 0 {
                    break;
                }
                stream.write_all(&byte).await.expect("write");
            }
        });
    });

    ready_rx.recv().expect("server ready");
    let elapsed = block_on_with(&reactor, async {
        let mut stream = TcpStream::connect(addr, &handle).await.expect("connect");
        let mut byte = [0u8; 1];
        let start = Instant::now();
        for _ in 0..ROUND_TRIPS {
            stream.write_all(b"x").await.expect("write");
            let read = stream.read(&mut byte).await.expect("read");
            assert_eq!(read, 1, "peer closed mid benchmark");
        }
        start.elapsed()
    });

    server.join().expect("server");
    elapsed
}

/// One byte there, one byte back, on this crate's reactor.
fn nago_floor() -> Duration {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(local_addr(), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut byte = [0u8; 1];
            for _ in 0..ROUND_TRIPS {
                let read = stream.read(&mut byte).await.expect("read");
                if read == 0 {
                    break;
                }
                stream.write_all(&byte).await.expect("write");
            }
        });
    });

    let elapsed = nagoya::block_on(async {
        let mut stream = TcpStream::connect(addr, &handle).await.expect("connect");
        let mut byte = [0u8; 1];
        let start = Instant::now();
        for _ in 0..ROUND_TRIPS {
            stream.write_all(b"x").await.expect("write");
            stream.read(&mut byte).await.expect("read");
        }
        start.elapsed()
    });

    server.join().expect("server");
    elapsed
}

/// The same, on tokio.
/// tokio with the two ends on separate threads, which is the shape the nago
/// arms are measured in.
///
/// `tokio_floor` puts both ends on one current thread runtime, so a round trip
/// never crosses a thread. Both nago arms give the peer its own thread, so
/// every trip crosses one twice. Comparing those two directly charges this
/// crate for a thread boundary tokio was never asked to pay, which is most of
/// what the gap looked like.
fn tokio_floor_two_threads() -> Duration {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let listener = runtime
        .block_on(async { tokio::net::TcpListener::bind(local()).await })
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            ready_tx.send(()).expect("signal");
            let (mut stream, _) = listener.accept().await.expect("accept");
            stream.set_nodelay(true).ok();
            let mut byte = [0u8; 1];
            for _ in 0..ROUND_TRIPS {
                let read = stream.read(&mut byte).await.expect("read");
                if read == 0 {
                    break;
                }
                stream.write_all(&byte).await.expect("write");
            }
        });
    });

    ready_rx.recv().expect("server ready");
    let elapsed = runtime.block_on(async {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.set_nodelay(true).ok();
        let mut byte = [0u8; 1];
        let start = Instant::now();
        for _ in 0..ROUND_TRIPS {
            stream.write_all(b"x").await.expect("write");
            let read = stream.read(&mut byte).await.expect("read");
            assert_eq!(read, 1, "peer closed mid benchmark");
        }
        start.elapsed()
    });

    server.join().expect("server thread");
    elapsed
}

fn tokio_floor() -> Duration {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(local()).await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            stream.set_nodelay(true).ok();
            let mut byte = [0u8; 1];
            for _ in 0..ROUND_TRIPS {
                let read = stream.read(&mut byte).await.expect("read");
                if read == 0 {
                    break;
                }
                stream.write_all(&byte).await.expect("write");
            }
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.set_nodelay(true).ok();
        let mut byte = [0u8; 1];

        let start = Instant::now();
        for _ in 0..ROUND_TRIPS {
            stream.write_all(b"x").await.expect("write");
            let read = stream.read(&mut byte).await.expect("read");
            assert_eq!(read, 1, "peer closed mid benchmark");
        }
        let elapsed = start.elapsed();

        server.await.expect("server");
        elapsed
    })
}

fn main() {
    // Warm both arms; the first connection pays for lazily initialised state.
    let _ = nago_floor();
    let _ = nago_local_floor();
    let _ = tokio_floor();

    let nago = best((0..SAMPLES).map(|_| nago_floor()).collect());
    let nago_local = best((0..SAMPLES).map(|_| nago_local_floor()).collect());
    let tokio = best((0..SAMPLES).map(|_| tokio_floor()).collect());
    let _ = tokio_floor_two_threads();
    let tokio_two = best((0..SAMPLES).map(|_| tokio_floor_two_threads()).collect());

    let each = |d: Duration| d.as_secs_f64() / ROUND_TRIPS as f64 * 1e6;
    println!("\ntransport floor, 1 byte round trip (best of {SAMPLES})\n");
    println!("  nago-wss threaded  {:>8.2} us/op", each(nago));
    println!("  nago-wss local     {:>8.2} us/op", each(nago_local));
    println!("  tokio one thread   {:>8.2} us/op", each(tokio));
    println!("  tokio two threads  {:>8.2} us/op", each(tokio_two));
    // What the framing costs is deliberately not computed here.
    //
    // It used to be, by subtracting these numbers from two constants copied
    // out of an echo run. Both benchmarks then drifted, and subtracting a
    // stale constant from a live measurement produced a framing cost of minus
    // 2.8us: the protocol measured faster than the transport underneath it,
    // which cannot happen. A number that can go negative was never measuring
    // what it claimed.
    //
    // Run `cargo bench --bench echo` and subtract by hand if the difference is
    // wanted. Both arms have to come from the same machine on the same day for
    // the subtraction to mean anything, which is the part the constants hid.
    println!(
        "\n  Most of a loopback round trip is the transport, not the protocol:\n  \
         compare these against the round trip figures from `--bench echo`.\n"
    );
}
