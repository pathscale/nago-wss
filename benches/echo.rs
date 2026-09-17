//! Throughput and latency against tokio-tungstenite, over real loopback TCP.
//!
//! # What is measured
//!
//! Two shapes, because they stress different things:
//!
//! * **round trip** sends one small message and waits for the reply before
//!   sending the next. Nothing is pipelined, so the number is per-message
//!   latency: two syscalls, two wakeups and the framing, with no batching to
//!   hide behind. This is what an RPC call over the socket actually costs.
//! * **streaming** sends a large batch without waiting, which measures
//!   throughput: framing cost per byte, masking, and how well the read path
//!   coalesces frames that arrive together.
//!
//! # The arms
//!
//! * **nago-wss**, on its own reactor.
//! * **tokio-tungstenite**, the version endpoint-libs pins, which is what the
//!   fleet runs today.
//! * **sockudo-ws**, which advertises ultra low latency for HFT and gets there
//!   with SIMD masking and a lot of unsafe. It is the interesting comparison:
//!   it sits at the opposite end of the safety trade from this crate, whose
//!   protocol core forbids unsafe outright, so the gap between them is roughly
//!   the price of that decision.
//!
//! # Fairness
//!
//! Both sides run the same shape: a real client and a real server, connected
//! over loopback, both doing the masking their role requires. The tokio arm
//! uses a current-thread runtime, because the nago arm has one reactor thread
//! and one task thread and pitting that against a multi-thread work-stealing
//! pool would measure the scheduler rather than the WebSocket path.
//!
//! This is a benchmark, not a proof. Loopback has no real network in it, and
//! numbers from one machine under one load are indicative rather than final.
//!
//! # Reporting the spread, not just the median
//!
//! An early version reported a bare median from three samples, and it was
//! actively misleading: the same unchanged tokio arm measured 18.5us, then
//! 73us, then 20.3us on consecutive runs, which turned one piece of code into
//! "1.32x slower", "3.28x faster" and "1.04x faster" depending on when it was
//! run. A median hides that completely.
//!
//! So every arm now reports its best and worst alongside the median, and the
//! comparison refuses to name a winner when the two arms' ranges overlap. The
//! best sample is the most informative single number here, being the one least
//! disturbed by whatever else the machine was doing, but the spread is what
//! says whether to believe any of it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nago_wss::conn::{Connection, Role};
use nago_wss::proto::message::{Limits, Message};
use nago_wss::reactor::socket::Addr;
use nago_wss::reactor::{Reactor, TcpListener, TcpStream};

/// Messages per sample in the round trip arm.
///
/// Kept small deliberately: this has to finish in seconds in the foreground,
/// not run as a background job. A few thousand round trips is already well past
/// the point where the per-message cost stops moving.
const ROUND_TRIPS: usize = 500;
/// Messages per sample in the streaming arm.
const STREAM_MESSAGES: usize = 2_000;
/// Payload for the small-message arms.
const SMALL: &[u8] = b"the quick brown fox jumps over the lazy dog";
/// How many samples to take.
///
/// More than three, because three cannot distinguish a real difference from an
/// unlucky sample, and few enough to stay inside a few seconds.
const SAMPLES: usize = 3;

/// Loopback, port chosen by the kernel. For the tokio and sockudo arms.
fn local() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// The same, in this crate's own address type.
fn local_addr() -> Addr {
    Addr::localhost(0)
}

/// What a set of samples for one arm looks like.
#[derive(Debug, Clone, Copy)]
struct Stats {
    best: Duration,
    median: Duration,
    worst: Duration,
}

fn stats(mut values: Vec<Duration>) -> Stats {
    values.sort_unstable();
    Stats {
        best: values[0],
        median: values[values.len() / 2],
        worst: values[values.len() - 1],
    }
}

// --- nago-wss -------------------------------------------------------------

/// One round trip sample: `ROUND_TRIPS` echoes, one at a time.
fn nago_round_trip() -> Duration {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(local_addr(), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = handle.clone();
    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            drop(server_handle);
            let mut conn = Connection::new(stream, Role::Server, Limits::default());
            for _ in 0..ROUND_TRIPS {
                let message = conn.read().await.expect("read").expect("message");
                conn.write(message).await.expect("write");
            }
        });
    });

    let elapsed = nagoya::block_on(async {
        let stream = TcpStream::connect(addr, &handle).await.expect("connect");
        let mut conn = Connection::new(stream, Role::Client, Limits::default());
        let payload = Bytes::from_static(SMALL);

        let start = Instant::now();
        for _ in 0..ROUND_TRIPS {
            conn.write(Message::Binary(payload.clone()))
                .await
                .expect("write");
            let _ = conn.read().await.expect("read").expect("message");
        }
        start.elapsed()
    });

    server.join().expect("server");
    elapsed
}

/// One streaming sample: `STREAM_MESSAGES` sent without waiting for replies.
fn nago_stream(payload_len: usize) -> Duration {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(local_addr(), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut conn = Connection::new(stream, Role::Server, Limits::default());
            for _ in 0..STREAM_MESSAGES {
                let _ = conn.read().await.expect("read").expect("message");
            }
            // The clock stops when the last message has been parsed by the
            // receiver, not when the sender's last write returned: a write that
            // lands in a socket buffer has not been delivered.
            done_tx.send(Instant::now()).expect("signal");
        });
    });

    let start = nagoya::block_on(async {
        let stream = TcpStream::connect(addr, &handle).await.expect("connect");
        let mut conn = Connection::new(stream, Role::Client, Limits::default());
        let payload = Bytes::from(vec![0x5Au8; payload_len]);

        let start = Instant::now();
        for _ in 0..STREAM_MESSAGES {
            conn.write(Message::Binary(payload.clone()))
                .await
                .expect("write");
        }
        start
    });

    let finished = done_rx.recv().expect("completion");
    server.join().expect("server");
    finished.duration_since(start)
}

// --- tokio-tungstenite ----------------------------------------------------

mod tokio_arm {
    use super::{local, ROUND_TRIPS, SMALL, STREAM_MESSAGES};
    use futures_util::{SinkExt, StreamExt};
    use std::time::{Duration, Instant};
    use tokio_tungstenite::tungstenite::Message as TMessage;

    /// The same round trip shape, on tokio.
    pub fn round_trip() -> Duration {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind(local()).await.expect("bind");
            let addr = listener.local_addr().expect("addr");

            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let mut ws = tokio_tungstenite::accept_async(stream)
                    .await
                    .expect("handshake");
                for _ in 0..ROUND_TRIPS {
                    let message = ws.next().await.expect("some").expect("read");
                    ws.send(message).await.expect("write");
                }
            });

            let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
                .await
                .expect("connect");
            let payload = SMALL.to_vec();

            let start = Instant::now();
            for _ in 0..ROUND_TRIPS {
                ws.send(TMessage::Binary(payload.clone().into()))
                    .await
                    .expect("write");
                let _ = ws.next().await.expect("some").expect("read");
            }
            let elapsed = start.elapsed();

            server.await.expect("server");
            elapsed
        })
    }

    /// The same streaming shape, on tokio.
    pub fn stream(payload_len: usize) -> Duration {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind(local()).await.expect("bind");
            let addr = listener.local_addr().expect("addr");

            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let mut ws = tokio_tungstenite::accept_async(stream)
                    .await
                    .expect("handshake");
                for _ in 0..STREAM_MESSAGES {
                    let _ = ws.next().await.expect("some").expect("read");
                }
                done_tx.send(Instant::now()).expect("signal");
            });

            let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
                .await
                .expect("connect");
            let payload = vec![0x5Au8; payload_len];

            let start = Instant::now();
            for _ in 0..STREAM_MESSAGES {
                ws.send(TMessage::Binary(payload.clone().into()))
                    .await
                    .expect("write");
            }

            let finished = done_rx.await.expect("completion");
            server.await.expect("server");
            finished.duration_since(start)
        })
    }
}

// --- sockudo-ws -----------------------------------------------------------

mod sockudo_arm {
    use super::{local, ROUND_TRIPS, SMALL, STREAM_MESSAGES};
    use bytes::BytesMut;
    use futures_util::{SinkExt, StreamExt};
    use sockudo_ws::handshake::{build_response, generate_accept_key, parse_request};
    use sockudo_ws::protocol::Message as SMessage;
    use sockudo_ws::{Config, WebSocketStream};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// This crate leaves the opening handshake to the caller, so the server
    /// side does it by hand exactly as its own example does.
    async fn server_handshake(stream: &mut TcpStream) {
        let mut buffer = BytesMut::with_capacity(4096);
        loop {
            let read = stream.read_buf(&mut buffer).await.expect("read");
            assert!(read > 0, "closed during the handshake");
            if let Some((request, _)) = parse_request(&buffer).expect("parse") {
                let accept = generate_accept_key(request.key);
                let response = build_response(&accept, None, None);
                stream.write_all(&response).await.expect("write");
                stream.flush().await.expect("flush");
                return;
            }
        }
    }

    /// The client half of the handshake, written out for the same reason.
    async fn client_handshake(stream: &mut TcpStream, addr: std::net::SocketAddr) {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");

        // Read until the end of the response headers.
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        while !buffer.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("read");
            assert!(read > 0, "closed during the handshake");
            buffer.push(byte[0]);
        }
    }

    pub fn round_trip() -> Duration {
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
                server_handshake(&mut stream).await;
                let mut ws = WebSocketStream::server(stream, Config::default());
                for _ in 0..ROUND_TRIPS {
                    let message = ws.next().await.expect("some").expect("read");
                    ws.send(message).await.expect("write");
                }
            });

            let mut stream = TcpStream::connect(addr).await.expect("connect");
            stream.set_nodelay(true).ok();
            client_handshake(&mut stream, addr).await;
            let mut ws = WebSocketStream::client(stream, Config::default());
            let payload = bytes::Bytes::from_static(SMALL);

            let start = Instant::now();
            for _ in 0..ROUND_TRIPS {
                ws.send(SMessage::Binary(payload.clone()))
                    .await
                    .expect("write");
                let _ = ws.next().await.expect("some").expect("read");
            }
            let elapsed = start.elapsed();

            server.await.expect("server");
            elapsed
        })
    }

    pub fn stream(payload_len: usize) -> Duration {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind(local()).await.expect("bind");
            let addr = listener.local_addr().expect("addr");

            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                stream.set_nodelay(true).ok();
                server_handshake(&mut stream).await;
                let mut ws = WebSocketStream::server(stream, Config::default());
                for _ in 0..STREAM_MESSAGES {
                    let _ = ws.next().await.expect("some").expect("read");
                }
                done_tx.send(Instant::now()).expect("signal");
            });

            let mut stream = TcpStream::connect(addr).await.expect("connect");
            stream.set_nodelay(true).ok();
            client_handshake(&mut stream, addr).await;
            let mut ws = WebSocketStream::client(stream, Config::default());
            let payload = bytes::Bytes::from(vec![0x5Au8; payload_len]);

            let start = Instant::now();
            for _ in 0..STREAM_MESSAGES {
                ws.send(SMessage::Binary(payload.clone()))
                    .await
                    .expect("write");
            }

            let finished = done_rx.await.expect("completion");
            server.await.expect("server");
            finished.duration_since(start)
        })
    }
}

// --- reporting ------------------------------------------------------------

/// Microseconds per operation.
fn per_op(duration: Duration, operations: usize) -> f64 {
    duration.as_secs_f64() / operations as f64 * 1e6
}

/// Whether two arms' sample ranges overlap, in which case their ordering is an
/// artefact of scheduling rather than a property of the code.
fn overlaps(a: Stats, b: Stats) -> bool {
    a.best <= b.worst && b.best <= a.worst
}

fn report(name: &str, arms: &[(&str, Stats)], operations: usize) {
    println!("{name}");
    for (label, arm) in arms {
        println!(
            "  {label:<20} {:>8.2} us/op  (best {:.2}, worst {:.2})",
            per_op(arm.median, operations),
            per_op(arm.best, operations),
            per_op(arm.worst, operations),
        );
    }

    // Compare everything against this crate, on the best sample: the run least
    // disturbed by whatever else the machine was doing.
    let (_, ours) = arms[0];
    for (label, arm) in &arms[1..] {
        if overlaps(ours, *arm) {
            println!("  vs {label}: too close to call, the samples overlap");
            continue;
        }
        let ratio = per_op(arm.best, operations) / per_op(ours.best, operations);
        if ratio >= 1.0 {
            println!("  vs {label}: nago-wss {ratio:.2}x faster");
        } else {
            println!("  vs {label}: nago-wss {:.2}x slower", 1.0 / ratio);
        }
    }
    println!();
}

fn main() {
    // A warm sample first: the first connection pays for lazily initialised
    // state on every side and would otherwise land in the measurement.
    let _ = nago_round_trip();
    let _ = tokio_arm::round_trip();
    let _ = sockudo_arm::round_trip();

    println!("\nsamples: {SAMPLES} per arm; median shown, best used for comparison\n");

    // The arms alternate rather than running all of one then all of the other,
    // so a transient load on the machine hits both instead of penalising
    // whichever happened to run during it.
    let mut nago_samples = Vec::with_capacity(SAMPLES);
    let mut tokio_samples = Vec::with_capacity(SAMPLES);
    let mut sockudo_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        nago_samples.push(nago_round_trip());
        tokio_samples.push(tokio_arm::round_trip());
        sockudo_samples.push(sockudo_arm::round_trip());
    }
    report(
        &format!("round trip, {} byte payload", SMALL.len()),
        &[
            ("nago-wss", stats(nago_samples)),
            ("tokio-tungstenite", stats(tokio_samples)),
            ("sockudo-ws", stats(sockudo_samples)),
        ],
        ROUND_TRIPS,
    );

    for size in [64usize, 4096] {
        let mut nago_samples = Vec::with_capacity(SAMPLES);
        let mut tokio_samples = Vec::with_capacity(SAMPLES);
        let mut sockudo_samples = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            nago_samples.push(nago_stream(size));
            tokio_samples.push(tokio_arm::stream(size));
            sockudo_samples.push(sockudo_arm::stream(size));
        }
        let nago = stats(nago_samples);
        let tokio = stats(tokio_samples);
        let sockudo = stats(sockudo_samples);
        report(
            &format!("streaming, {size} byte payload"),
            &[
                ("nago-wss", nago),
                ("tokio-tungstenite", tokio),
                ("sockudo-ws", sockudo),
            ],
            STREAM_MESSAGES,
        );
        // Throughput from the best sample, for the same reason.
        let throughput = |d: Duration| {
            (STREAM_MESSAGES as f64 * size as f64) / d.as_secs_f64() / (1024.0 * 1024.0)
        };
        println!(
            "  peak throughput: nago-wss {:.0}, tokio-tungstenite {:.0}, sockudo-ws {:.0} MiB/s\n",
            throughput(nago.best),
            throughput(tokio.best),
            throughput(sockudo.best),
        );
    }
}
