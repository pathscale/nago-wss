//! The other axis: many connections at once.
//!
//! # Why this exists
//!
//! Every other benchmark here drives one connection and reports per-message
//! latency. That is the axis a reactor design can lose on without the number
//! moving at all, because one connection never exercises the thing a reactor
//! is for: one wait serving many descriptors, one scheduler feeding many
//! tasks.
//!
//! So this measures aggregate throughput across a connection count that grows,
//! which is where the shapes actually differ. A design that batches a wait
//! across descriptors pulls ahead as the count rises; a design that pays a
//! fixed cost per wakeup does not.
//!
//! # What it does
//!
//! `CONNECTIONS` clients each send `PER_CONNECTION` WebSocket messages and
//! read the echo back, all in flight together. The clock covers the whole set,
//! so the number is messages per second through the process rather than the
//! latency of any one of them.
//!
//! Both arms run their server and their clients in one process over loopback,
//! which is a real limitation: the two halves compete for the same cores, so
//! this measures a pair rather than a server. It is still the right
//! comparison, because both arms are handicapped identically.

use std::time::{Duration, Instant};

use bytes::Bytes;
use nago_wss::conn::{Connection, Role};
use nago_wss::proto::message::{Limits, Message};
use nago_wss::reactor::socket::Addr;
use nago_wss::reactor::{Reactor, TcpListener, TcpStream};

/// How many connections to run at once, in successive rounds.
const COUNTS: [usize; 5] = [1, 8, 16, 32, 64];
/// Messages each connection sends.
const PER_CONNECTION: usize = 30;
/// Payload size, in the range the fleet's RPC traffic actually uses.
const PAYLOAD: usize = 256;
/// Samples per count; the best is reported.
const SAMPLES: usize = 2;

fn best(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[0]
}

// --- nago-wss -------------------------------------------------------------

/// One round: `count` connections, each echoing `PER_CONNECTION` messages.
///
/// The server runs one reactor thread and one task per connection, which is
/// the arrangement this crate is actually for.
fn nago_round(count: usize) -> Duration {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(Addr::localhost(0), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = handle.clone();
    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            // Accept every connection first, then serve them all. Accepting
            // lazily would let the clients' connect latency leak into the
            // measurement of the echo loop.
            let mut streams = Vec::with_capacity(count);
            for _ in 0..count {
                let (stream, _) = listener.accept().await.expect("accept");
                streams.push(stream);
            }
            drop(server_handle);

            // One task per connection, all on the pool, which is what a real
            // server does and what the single connection benchmarks never
            // reach.
            let mut handles = Vec::with_capacity(count);
            for stream in streams {
                handles.push(nagoya::runtime::background().spawn(async move {
                    let mut conn = Connection::new(stream, Role::Server, Limits::default());
                    for _ in 0..PER_CONNECTION {
                        let Some(message) = conn.read().await.expect("read") else {
                            break;
                        };
                        conn.write(message).await.expect("write");
                    }
                }));
            }
            for handle in handles {
                handle.await;
            }
        });
    });

    // Clients get a thread each up to a point; past that they share, because
    // 256 threads on a laptop measures the scheduler rather than the crate.
    let threads = count.min(8);
    let per_thread = count / threads;
    let payload = Bytes::from(vec![0x5Au8; PAYLOAD]);

    let start = Instant::now();
    let mut clients = Vec::with_capacity(threads);
    for _ in 0..threads {
        let handle = handle.clone();
        let payload = payload.clone();
        clients.push(std::thread::spawn(move || {
            nagoya::block_on(async move {
                let mut conns = Vec::with_capacity(per_thread);
                for _ in 0..per_thread {
                    let stream = TcpStream::connect(addr, &handle).await.expect("connect");
                    conns.push(Connection::new(stream, Role::Client, Limits::default()));
                }
                // Interleave across this thread's connections rather than
                // finishing one at a time, so they are genuinely concurrent.
                for _ in 0..PER_CONNECTION {
                    for conn in conns.iter_mut() {
                        conn.write(Message::Binary(payload.clone()))
                            .await
                            .expect("write");
                    }
                    for conn in conns.iter_mut() {
                        let _ = conn.read().await.expect("read").expect("message");
                    }
                }
            });
        }));
    }
    for client in clients {
        client.join().expect("client");
    }
    let elapsed = start.elapsed();

    server.join().expect("server");
    elapsed
}

// --- tokio-tungstenite ----------------------------------------------------

mod tokio_arm {
    use super::{PAYLOAD, PER_CONNECTION};
    use futures_util::{SinkExt, StreamExt};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio_tungstenite::tungstenite::Message as TMessage;

    /// The same round, on tokio.
    ///
    /// A multi-thread runtime, because that is what a tokio server would
    /// actually deploy and the point here is the concurrent shape rather than
    /// a matched thread count.
    pub fn round(count: usize) -> Duration {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind(SocketAddr::from((
                [127, 0, 0, 1],
                0,
            )))
            .await
            .expect("bind");
            let addr = listener.local_addr().expect("addr");

            let server = tokio::spawn(async move {
                let mut tasks = Vec::with_capacity(count);
                for _ in 0..count {
                    let (stream, _) = listener.accept().await.expect("accept");
                    tasks.push(tokio::spawn(async move {
                        let mut ws = tokio_tungstenite::accept_async(stream)
                            .await
                            .expect("handshake");
                        for _ in 0..PER_CONNECTION {
                            let Some(message) = ws.next().await else {
                                break;
                            };
                            let message = message.expect("read");
                            ws.send(message).await.expect("write");
                        }
                    }));
                }
                for task in tasks {
                    task.await.expect("task");
                }
            });

            let payload = vec![0x5Au8; PAYLOAD];
            let start = Instant::now();

            let mut clients = Vec::with_capacity(count);
            for _ in 0..count {
                let payload = payload.clone();
                clients.push(tokio::spawn(async move {
                    let (mut ws, _) =
                        tokio_tungstenite::connect_async(format!("ws://{addr}/"))
                            .await
                            .expect("connect");
                    for _ in 0..PER_CONNECTION {
                        ws.send(TMessage::Binary(payload.clone().into()))
                            .await
                            .expect("write");
                        let _ = ws.next().await.expect("some").expect("read");
                    }
                }));
            }
            for client in clients {
                client.await.expect("client");
            }
            let elapsed = start.elapsed();

            server.await.expect("server");
            elapsed
        })
    }
}

// --- reporting ------------------------------------------------------------

fn main() {
    // Warm both arms on the smallest count.
    let _ = nago_round(1);
    let _ = tokio_arm::round(1);

    println!("\naggregate throughput, {PAYLOAD} byte echo, best of {SAMPLES}\n");
    println!(
        "  {:>6}  {:>14}  {:>14}  {:>8}",
        "conns", "nago-wss", "tokio-tung", "ratio"
    );

    for count in COUNTS {
        let total = count * PER_CONNECTION;
        let rate = |d: Duration| total as f64 / d.as_secs_f64();

        let nago = best((0..SAMPLES).map(|_| nago_round(count)).collect());
        let tokio = best((0..SAMPLES).map(|_| tokio_arm::round(count)).collect());

        let nago_rate = rate(nago);
        let tokio_rate = rate(tokio);
        println!(
            "  {count:>6}  {:>10.0} m/s  {:>10.0} m/s  {:>7.2}x",
            nago_rate,
            tokio_rate,
            nago_rate / tokio_rate
        );
    }
    println!("\n  ratio above 1 means nago-wss moved more messages per second.\n");
}
