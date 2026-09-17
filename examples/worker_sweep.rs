//! Does the eight connection deficit move with the worker count?
//!
//! # Why
//!
//! `concurrent` says this crate runs at roughly two thirds of tokio at eight
//! connections and level with it at thirty two. A gap that closes as load
//! rises is not a per message cost; it is a distribution problem at low
//! occupancy. The pool has one thread per core, sixteen here, and the reactor
//! routes each descriptor to `index % workers`. At thirty two connections
//! every worker has something to do. At eight, half the pool is idle and the
//! eight that are busy are whichever ones the descriptor numbers happened to
//! pick, which on this machine can be efficiency cores.
//!
//! So this sweeps the worker count against a fixed eight connection load. If
//! the deficit is occupancy, a smaller pool should beat the default.
//!
//! # What it found
//!
//! Not occupancy. More workers is worse at every connection count tried, and
//! the default is the slowest setting of the six at all of them:
//!
//! ```text
//!  workers       8 conns      32 conns     512 conns
//!        1        171-199k          201k          207k
//!        2        292-308k          316k          170k
//!        4        268-345k          255k          127k
//!        8        156-157k          177k          130k
//!       12        147-149k          169k          113k
//!       16        129-139k          160k           92k
//! ```
//!
//! Sixteen is `available_parallelism` on this machine, so the default pool is
//! two to three times slower than a pool of two or four, and at eight
//! connections the measured deficit against tokio-tungstenite is entirely
//! inside that factor. A pool that slows down as threads are added is not
//! mistuned, it is contending, and the sweep does not say where. That is the
//! next question rather than an answer, which is why this is a probe and no
//! default has been changed on the strength of it.
//!
//! ```text
//! cargo run --release --example worker_sweep
//! ```

use std::time::{Duration, Instant};

use bytes::Bytes;
use nago_wss::conn::{Connection, Role};
use nago_wss::proto::message::{Limits, Message};
use nagoya::reactor::{Addr, Reactor, TcpListener, TcpStream};
use nagoya::runtime::Runtime;

const CONNECTIONS: usize = 8;
const PER_CONNECTION: usize = 200;
const PAYLOAD: usize = 256;
const SAMPLES: usize = 3;

/// Worker counts to try. One is the degenerate case and sixteen is the default
/// on this machine; the interesting region is in between.
const WORKERS: [usize; 6] = [1, 2, 4, 8, 12, 16];

fn round(workers: usize) -> Duration {
    // A runtime of our own rather than the shared one, which is a process
    // singleton and therefore fixed at the default for the whole run.
    let runtime = std::sync::Arc::new(Runtime::new(workers));
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(Addr::localhost(0), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = handle.clone();
    let server_runtime = runtime.clone();
    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let mut streams = Vec::with_capacity(CONNECTIONS);
            for _ in 0..CONNECTIONS {
                let (stream, _) = listener.accept().await.expect("accept");
                streams.push(stream);
            }
            drop(server_handle);

            let mut handles = Vec::with_capacity(CONNECTIONS);
            for stream in streams {
                handles.push(server_runtime.spawn(async move {
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

    let payload = Bytes::from(vec![0x5Au8; PAYLOAD]);
    let start = Instant::now();
    let clients = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let mut handles = Vec::with_capacity(CONNECTIONS);
            for _ in 0..CONNECTIONS {
                let handle = handle.clone();
                let payload = payload.clone();
                handles.push(runtime.spawn(async move {
                    let stream = TcpStream::connect(addr, &handle).await.expect("connect");
                    let mut conn = Connection::new(stream, Role::Client, Limits::default());
                    for _ in 0..PER_CONNECTION {
                        conn.write(Message::Binary(payload.clone()))
                            .await
                            .expect("write");
                        let _ = conn.read().await.expect("read").expect("message");
                    }
                }));
            }
            for handle in handles {
                handle.await;
            }
        });
    });
    clients.join().expect("clients");
    let elapsed = start.elapsed();
    server.join().expect("server");
    elapsed
}

fn main() {
    let _ = round(4);

    println!("\n{CONNECTIONS} connections, {PAYLOAD} byte echo, best of {SAMPLES}\n");
    println!("  {:>8}  {:>14}", "workers", "throughput");

    let total = CONNECTIONS * PER_CONNECTION;
    for workers in WORKERS {
        let mut samples: Vec<Duration> = (0..SAMPLES).map(|_| round(workers)).collect();
        samples.sort_unstable();
        let rate = total as f64 / samples[0].as_secs_f64();
        println!("  {workers:>8}  {rate:>10.0} m/s");
    }
    println!();
}
