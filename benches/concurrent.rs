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
use nagoya::reactor::Addr;
use nagoya::reactor::{Reactor, TcpListener, TcpStream};

/// How many connections to run at once, in successive rounds.
const COUNTS: [usize; 3] = [1, 8, 32];
/// Messages each connection sends.
const PER_CONNECTION: usize = 50;
/// Payload size, in the range the fleet's RPC traffic actually uses.
const PAYLOAD: usize = 256;
/// Samples per count; the best is reported.
// One sample of twenty messages was noise: the same arm came out ahead and
// behind on consecutive runs, which is a benchmark reporting scheduler jitter
// rather than throughput. The whole thing ran in under a tenth of a second, so
// there was no reason for either number to be this small.
const SAMPLES: usize = 3;

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
            let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
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
                    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
                    stream.set_nodelay(true).ok();
                    // Address rather than URL, so the system resolver is not
                    // on the path. See the note in benches/echo.rs.
                    let (mut ws, _) =
                        tokio_tungstenite::client_async(format!("ws://{addr}/"), stream)
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

// --- sockudo-ws -----------------------------------------------------------

mod sockudo_arm {
    use super::{PAYLOAD, PER_CONNECTION};
    use bytes::BytesMut;
    use futures_util::{SinkExt, StreamExt};
    use sockudo_ws::handshake::{build_response, generate_accept_key, parse_request};
    use sockudo_ws::protocol::Message as SMessage;
    use sockudo_ws::{Config, WebSocketStream};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// This crate leaves the handshake to its caller, in both directions.
    async fn server_handshake(stream: &mut TcpStream) -> bool {
        let mut buffer = BytesMut::with_capacity(1024);
        loop {
            let Ok(read) = stream.read_buf(&mut buffer).await else {
                return false;
            };
            if read == 0 {
                return false;
            }
            match parse_request(&buffer) {
                Ok(Some((request, _))) => {
                    let accept = generate_accept_key(request.key);
                    let response = build_response(&accept, None, None);
                    if stream.write_all(&response).await.is_err() {
                        return false;
                    }
                    return stream.flush().await.is_ok();
                }
                Ok(None) => continue,
                Err(_) => return false,
            }
        }
    }

    async fn client_handshake(stream: &mut TcpStream, addr: SocketAddr) -> bool {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        if stream.write_all(request.as_bytes()).await.is_err() {
            return false;
        }
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte).await {
                Ok(0) | Err(_) => return false,
                Ok(_) => seen.push(byte[0]),
            }
        }
        true
    }

    /// The same round, on sockudo-ws.
    pub fn round(count: usize) -> Duration {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");

            let server = tokio::spawn(async move {
                let mut tasks = Vec::with_capacity(count);
                for _ in 0..count {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    stream.set_nodelay(true).ok();
                    tasks.push(tokio::spawn(async move {
                        if !server_handshake(&mut stream).await {
                            return;
                        }
                        let mut ws = WebSocketStream::server(stream, Config::default());
                        for _ in 0..PER_CONNECTION {
                            let Some(Ok(message)) = ws.next().await else {
                                break;
                            };
                            if ws.send(message).await.is_err() {
                                break;
                            }
                        }
                    }));
                }
                for task in tasks {
                    let _ = task.await;
                }
            });

            let payload = bytes::Bytes::from(vec![0x5Au8; PAYLOAD]);
            let start = Instant::now();

            let mut clients = Vec::with_capacity(count);
            for _ in 0..count {
                let payload = payload.clone();
                clients.push(tokio::spawn(async move {
                    let mut stream = TcpStream::connect(addr).await.expect("connect");
                    stream.set_nodelay(true).ok();
                    client_handshake(&mut stream, addr).await;
                    let mut ws = WebSocketStream::client(stream, Config::default());
                    for _ in 0..PER_CONNECTION {
                        if ws.send(SMessage::Binary(payload.clone())).await.is_err() {
                            break;
                        }
                        if ws.next().await.is_none() {
                            break;
                        }
                    }
                }));
            }
            for client in clients {
                let _ = client.await;
            }
            let elapsed = start.elapsed();

            let _ = server.await;
            elapsed
        })
    }
}

// --- reporting ------------------------------------------------------------

fn main() {
    // Warm both arms on the smallest count.
    let _ = nago_round(1);
    let _ = tokio_arm::round(1);
    let _ = sockudo_arm::round(1);

    println!("\naggregate throughput, {PAYLOAD} byte echo, best of {SAMPLES}\n");
    println!(
        "  {:>6}  {:>14}  {:>14}  {:>8}",
        "conns", "nago-wss", "tokio-tung", "sockudo-ws"
    );

    for count in COUNTS {
        let total = count * PER_CONNECTION;
        let rate = |d: Duration| total as f64 / d.as_secs_f64();

        let nago = best((0..SAMPLES).map(|_| nago_round(count)).collect());
        let tokio = best((0..SAMPLES).map(|_| tokio_arm::round(count)).collect());

        let sockudo = best((0..SAMPLES).map(|_| sockudo_arm::round(count)).collect());
        println!(
            "  {count:>6}  {:>11.0} m/s  {:>11.0} m/s  {:>11.0} m/s",
            rate(nago),
            rate(tokio),
            rate(sockudo),
        );
    }
    println!("\n  messages per second through the process, higher is better.\n");
}
