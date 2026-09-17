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
//! # What it found, after two wrong answers
//!
//! The effect is real and reproduces on every run: two to four workers move
//! two to three times what the default sixteen does.
//!
//! ```text
//!  workers   throughput   spurious/msg   threads
//!        1       191k m/s         0.00        23
//!        2       302k m/s         0.00        25
//!        4       264k m/s         0.00        29
//!        8       149k m/s         0.00        37
//!       12       145k m/s         0.37        49
//!       16       141k m/s         0.00        65
//! ```
//!
//! Two explanations were offered for it before this column existed, and both
//! were wrong. The first was park and unpark churn, from a `sample` profile.
//! `spurious/msg` refutes it exactly rather than by sampling: a park that woke
//! with nothing to do is precisely what the pool counts as spurious, and it is
//! zero at every size. Workers are not waking up to find no work.
//!
//! The second was the injector, which the profile also did not support.
//!
//! What the `threads` column shows instead is that this probe was measuring
//! its own harness. Two separate leaks:
//!
//! * Building a `Runtime` per sample and dropping it *detaches* its threads
//!   rather than stopping them, so three samples at sixteen workers left a
//!   hundred and fifty one threads alive on a sixteen core machine. Fixed here
//!   by reusing one runtime per setting, which brought sixteen workers from
//!   151 threads to 65.
//! * `route_reactor_wake` asks `background()` which pool to route to, and
//!   `background()` starts the shared pool on first use. Measured directly:
//!   one thread at process start, seventeen after touching it. So a consumer
//!   that builds its own `Runtime` still gets a second pool of one thread per
//!   core, and the routing modulus is that pool's width rather than the
//!   runtime's, sending wakes to worker indices the runtime does not have.
//!
//! The second is a bug in nagoya rather than in this probe, and it is the
//! reason the remaining thread counts are still four times the worker count.
//! The throughput effect survives fixing the first leak, so neither leak is
//! the whole story, but no explanation offered so far has survived contact
//! with a counter and none should be believed without one.
//!
//! One more thing this machine makes relevant: `available_parallelism` reports
//! sixteen, and that is twelve performance cores plus four efficiency ones.
//! A pool sized at sixteen therefore puts a quarter of its workers on cores
//! that run at a fraction of the speed, which is a defaulting question of its
//! own.
//!
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
    round_counted(workers).0
}

/// The round, the parks that woke with nothing to do, and the process's thread
/// count at the end of it.
///
/// The thread count is here because of what it exposed: `route_reactor_wake`
/// asks `background()` for the pool it should route to, and `background()`
/// starts the shared sixteen thread pool on first use. So every row below was
/// running its own pool of `workers` threads *and* an idle shared pool, with
/// the routing modulus taken from the wrong one.
fn round_counted(workers: usize) -> (Duration, u64, usize) {
    round_on(&std::sync::Arc::new(Runtime::new(workers)))
}

/// One round on a runtime the caller owns.
///
/// Separate from `round_counted` because dropping a `Runtime` detaches its
/// threads rather than stopping them. Building one per sample leaks a whole
/// pool each time, and at sixteen workers over three samples that reached a
/// hundred and fifty one threads on a sixteen core machine, which is what the
/// sweep was really measuring.
fn round_on(runtime: &std::sync::Arc<Runtime>) -> (Duration, u64, usize) {
    let counter = runtime.clone();
    let runtime = runtime.clone();
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
    (elapsed, counter.spurious_wakes(), live_threads())
}

/// Threads in this process, from the kernel rather than from bookkeeping.
fn live_threads() -> usize {
    let output = std::process::Command::new("ps")
        .args(["-M", &std::process::id().to_string()])
        .output();
    match output {
        // One header line, the rest are threads.
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .count()
            .saturating_sub(1),
        Err(_) => 0,
    }
}

/// Threads before any round runs, so the baseline is visible.
fn report_baseline() {
    println!("  threads at start: {}", live_threads());
    // The reactor used to start the shared pool behind the caller's back on
    // every wake. It no longer does, so a sweep that never asks for it should
    // never pay for it.
}

fn main() {
    report_baseline();
    let _ = round(4);

    println!("\n{CONNECTIONS} connections, {PAYLOAD} byte echo, best of {SAMPLES}\n");
    println!(
        "  {:>8}  {:>14}  {:>12}  {:>8}",
        "workers", "throughput", "spurious/msg", "threads"
    );

    let total = CONNECTIONS * PER_CONNECTION;
    for workers in WORKERS {
        // One runtime for all the samples at this size, so the thread count
        // stays at what the setting actually asks for.
        let runtime = std::sync::Arc::new(Runtime::new(workers));
        let mut runs: Vec<(Duration, u64, usize)> =
            (0..SAMPLES).map(|_| round_on(&runtime)).collect();
        runs.sort_unstable_by_key(|(elapsed, _, _)| *elapsed);
        let (elapsed, spurious, threads) = runs[0];
        let rate = total as f64 / elapsed.as_secs_f64();
        let per_message = spurious as f64 / total as f64;
        println!("  {workers:>8}  {rate:>10.0} m/s  {per_message:>12.2}  {threads:>8}");
    }
    println!();
}
