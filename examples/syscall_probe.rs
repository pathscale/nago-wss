//! How many syscalls a WebSocket message costs, through this crate's read loop.
//!
//! # Why this exists
//!
//! `benches/concurrent.rs` says this crate moves fewer messages per second at
//! eight connections than tokio-tungstenite does, and no latency number
//! explains it: the single connection floor is already at or below tokio's.
//! A throughput gap that latency does not account for is usually syscall
//! count, and counting is the only way to know.
//!
//! An earlier attempt counted through `nagoya::reactor::TcpStream::read`
//! directly. That was the wrong layer and the number it produced described
//! nothing here, because `Connection::read` does not call `read` once per
//! message: it parses out of a buffer first and only goes to the socket when
//! the buffer cannot satisfy the request. Whether that buffering is working is
//! exactly the question, so the probe has to run through it.
//!
//! # What it reports
//!
//! Per WebSocket message read, across both halves of the process:
//!
//! - `recv`, every one the reactor issued.
//! - `EWOULDBLOCK`, the ones that found nothing and cost a park.
//! - `wait`, the `kevent`/`epoll_wait` calls the poller blocked in.
//!
//! One recv per message is the floor for a connection that is never ahead of
//! its peer. Anything above it is the read loop going back to a socket that
//! had nothing new, which is the shape that would explain the gap.
//!
//! # Two client shapes, because the counters are process wide
//!
//! The statics count every socket in the process, and `concurrent` runs its
//! clients here too, so a single row cannot say whether a wait belongs to the
//! server or to a client. So each count is probed twice:
//!
//! - `nago clients`: the benchmark's own shape, a thread per connection each
//!   running `block_on` with its own poller over one descriptor. Both halves
//!   are counted.
//! - `tokio clients`: the same server, driven by tokio-tungstenite over a real
//!   handshake. Nothing on the client side touches nagoya, so the counters
//!   describe the server alone.
//!
//! The difference between the two rows is what the benchmark's client harness
//! costs, which is worth knowing before reading anything into the gap: tokio's
//! arm puts its server and all its clients on one shared reactor, and this
//! crate's arm does not.
//!
//! Run it with the feature, which is off by default:
//!
//! ```text
//! cargo run --release --features syscall-counters --example syscall_probe
//! ```

use bytes::Bytes;
use nago_wss::conn::{Connection, Role};
use nago_wss::proto::message::{Limits, Message};
use nagoya::reactor::counters;
use nagoya::reactor::{Addr, Reactor, TcpListener, TcpStream};

/// Connection counts to probe. The same three `concurrent` reports, so the
/// counts line up with the throughput they are meant to explain.
const COUNTS: [usize; 3] = [1, 8, 32];
/// Connection counts the tokio client arm is probed at. It deadlocks above
/// one, and the attribution it is there for is already answered at one.
const TOKIO_COUNTS: [usize; 1] = [1];
/// Messages each connection sends. Larger than the benchmark's, because this
/// is a ratio rather than a clock and a longer run makes the setup syscalls
/// a smaller share of it.
const PER_CONNECTION: usize = 200;
/// Payload size, matching `concurrent`.
const PAYLOAD: usize = 256;

/// Which side drives the clients.
#[derive(Clone, Copy, PartialEq)]
enum Clients {
    /// The benchmark's shape: a thread per connection, each with its own
    /// poller. Counted, because these are nagoya sockets.
    Nago,
    /// One tokio runtime for all of them, over a real handshake. Not counted,
    /// which is the point: what remains is the server.
    Tokio,
}

/// One round, shaped like `concurrent`'s nago arm on the server side.
fn round(count: usize, clients: Clients) -> (u64, u64, u64) {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(Addr::localhost(0), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle = handle.clone();
    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let mut streams = Vec::with_capacity(count);
            for _ in 0..count {
                let (stream, _) = listener.accept().await.expect("accept");
                streams.push(stream);
            }
            drop(server_handle);

            let mut handles = Vec::with_capacity(count);
            for stream in streams {
                handles.push(nagoya::runtime::background().spawn(async move {
                    // The tokio clients speak the real protocol, so the server
                    // has to answer the handshake. The nago clients skip it,
                    // exactly as `concurrent` does.
                    let mut conn = match clients {
                        Clients::Nago => Connection::new(stream, Role::Server, Limits::default()),
                        Clients::Tokio => {
                            nago_wss::upgrade::accept(stream, Limits::default(), |_| None)
                                .await
                                .expect("handshake")
                                .0
                        }
                    };
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

    // Connect first, then clear: the counters should describe the echo loop
    // rather than the connects and accepts that set it up.
    let ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    let driver = match clients {
        Clients::Nago => nago_clients(count, addr, handle.clone(), ready.clone()),
        Clients::Tokio => tokio_clients(count, addr, ready.clone()),
    };

    ready.wait();
    let _ = counters::take();

    driver.join().expect("clients");
    let counted = counters::take();
    server.join().expect("server");
    counted
}

/// The benchmark's client harness: `count.min(8)` threads, each its own poller.
fn nago_clients(
    count: usize,
    addr: Addr,
    handle: nagoya::reactor::Handle,
    ready: std::sync::Arc<std::sync::Barrier>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let threads = count.min(8);
        let per_thread = count / threads;
        let payload = Bytes::from(vec![0x5Au8; PAYLOAD]);
        let connected = std::sync::Arc::new(std::sync::Barrier::new(threads + 1));

        let mut clients = Vec::with_capacity(threads);
        for _ in 0..threads {
            let handle = handle.clone();
            let payload = payload.clone();
            let connected = connected.clone();
            clients.push(std::thread::spawn(move || {
                nagoya::block_on(async move {
                    let mut conns = Vec::with_capacity(per_thread);
                    for _ in 0..per_thread {
                        let stream = TcpStream::connect(addr, &handle).await.expect("connect");
                        conns.push(Connection::new(stream, Role::Client, Limits::default()));
                    }
                    connected.wait();
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
        connected.wait();
        ready.wait();
        for client in clients {
            client.join().expect("client");
        }
    })
}

/// The same load from tokio, so nothing on this side is counted.
fn tokio_clients(
    count: usize,
    addr: Addr,
    ready: std::sync::Arc<std::sync::Barrier>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use futures_util::{SinkExt, StreamExt};
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], addr.port()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let payload = vec![0x5Au8; PAYLOAD];
            let mut sockets = Vec::with_capacity(count);
            for _ in 0..count {
                let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
                stream.set_nodelay(true).ok();
                // Address rather than URL: the system resolver stalls for
                // minutes under a VPN and has no business on this path.
                let (ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/"), stream)
                    .await
                    .expect("handshake");
                sockets.push(ws);
            }
            ready.wait();

            let mut tasks = Vec::with_capacity(count);
            for mut ws in sockets {
                let payload = payload.clone();
                tasks.push(tokio::spawn(async move {
                    for _ in 0..PER_CONNECTION {
                        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
                            payload.clone().into(),
                        ))
                        .await
                        .expect("write");
                        let _ = ws.next().await.expect("some").expect("read");
                    }
                }));
            }
            for task in tasks {
                task.await.expect("client");
            }
        });
    })
}

fn main() {
    println!("syscalls per WebSocket message read, {PAYLOAD} byte payloads");
    println!(
        "{:>6}  {:>14}  {:>10}  {:>12}  {:>10}",
        "conns", "clients", "recv/msg", "eblock/msg", "wait/msg"
    );

    for count in COUNTS {
        for (clients, label) in [(Clients::Nago, "nago"), (Clients::Tokio, "tokio")] {
            if clients == Clients::Tokio && !TOKIO_COUNTS.contains(&count) {
                continue;
            }
            let (recv, blocked, wait) = round(count, clients);
            // With nago clients both halves read every message, and both are
            // counted. With tokio clients only the server's reads are.
            let reads = match clients {
                Clients::Nago => count * PER_CONNECTION * 2,
                Clients::Tokio => count * PER_CONNECTION,
            };
            let reads = reads as f64;
            println!(
                "{:>6}  {:>14}  {:>10.2}  {:>12.2}  {:>10.2}",
                count,
                label,
                recv as f64 / reads,
                blocked as f64 / reads,
                wait as f64 / reads,
            );
        }
    }
}
