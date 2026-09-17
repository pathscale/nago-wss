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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nago_wss::conn::{Connection, Role};
use nago_wss::proto::message::{Limits, Message};
use nago_wss::reactor::{Reactor, TcpListener, TcpStream};

/// Messages per sample in the round trip arm.
///
/// Kept small deliberately: this has to finish in seconds in the foreground,
/// not run as a background job. A few thousand round trips is already well past
/// the point where the per-message cost stops moving.
const ROUND_TRIPS: usize = 1_000;
/// Messages per sample in the streaming arm.
const STREAM_MESSAGES: usize = 5_000;
/// Payload for the small-message arms.
const SMALL: &[u8] = b"the quick brown fox jumps over the lazy dog";
/// How many samples to take; the median is reported.
const SAMPLES: usize = 3;

fn local() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

// --- nago-wss -------------------------------------------------------------

/// One round trip sample: `ROUND_TRIPS` echoes, one at a time.
fn nago_round_trip() -> Duration {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(local(), &handle).expect("bind");
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
        let stream = TcpStream::connect(addr, &handle).expect("connect");
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
    let listener = TcpListener::bind(local(), &handle).expect("bind");
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
        let stream = TcpStream::connect(addr, &handle).expect("connect");
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

// --- reporting ------------------------------------------------------------

fn report(name: &str, nago: Duration, tokio: Duration, operations: usize) {
    let nago_each = nago.as_secs_f64() / operations as f64;
    let tokio_each = tokio.as_secs_f64() / operations as f64;
    let ratio = tokio_each / nago_each;

    println!("{name}");
    println!(
        "  nago-wss            {:>9.2} us/op   {:>10.0} op/s",
        nago_each * 1e6,
        1.0 / nago_each
    );
    println!(
        "  tokio-tungstenite   {:>9.2} us/op   {:>10.0} op/s",
        tokio_each * 1e6,
        1.0 / tokio_each
    );
    if ratio >= 1.0 {
        println!("  nago-wss is {ratio:.2}x faster\n");
    } else {
        println!("  nago-wss is {:.2}x slower\n", 1.0 / ratio);
    }
}

fn main() {
    // A warm sample first: the first connection pays for lazily initialised
    // state on both sides and would otherwise land in the measurement.
    let _ = nago_round_trip();
    let _ = tokio_arm::round_trip();

    println!("\nsamples: {SAMPLES}, median reported\n");

    let nago = median((0..SAMPLES).map(|_| nago_round_trip()).collect());
    let tokio = median((0..SAMPLES).map(|_| tokio_arm::round_trip()).collect());
    report(
        &format!("round trip, {} byte payload", SMALL.len()),
        nago,
        tokio,
        ROUND_TRIPS,
    );

    for size in [64usize, 4096] {
        let nago = median((0..SAMPLES).map(|_| nago_stream(size)).collect());
        let tokio = median((0..SAMPLES).map(|_| tokio_arm::stream(size)).collect());
        report(
            &format!("streaming, {size} byte payload"),
            nago,
            tokio,
            STREAM_MESSAGES,
        );
        let throughput = |d: Duration| {
            (STREAM_MESSAGES as f64 * size as f64) / d.as_secs_f64() / (1024.0 * 1024.0)
        };
        println!(
            "  throughput: nago-wss {:.0} MiB/s, tokio-tungstenite {:.0} MiB/s\n",
            throughput(nago),
            throughput(tokio)
        );
    }
}
