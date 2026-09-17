//! Does it hold ten thousand connections, and what does idle cost.
//!
//! # The question this answers
//!
//! Throughput benchmarks run a handful of busy connections. A chat or
//! notification server has the opposite shape: a great many connections that
//! are mostly idle, where what matters is whether the design holds them at all
//! and what each one costs while doing nothing.
//!
//! Three things are measured per arm, at each connection count:
//!
//! * **establish** - wall clock to open and complete every connection.
//! * **idle cost** - resident memory divided by connection count, which is
//!   the number that decides whether ten thousand fit in a process.
//! * **broadcast** - one message to every connection and the replies back,
//!   which is the operation that actually scales with the count.
//!
//! # Honesty about the setup
//!
//! Both ends live in one process, so every connection costs two descriptors
//! and both halves compete for the same cores. That inflates every arm
//! equally. It also means the reported memory covers client and server state
//! together, so the per-connection figure is roughly twice what a server alone
//! would carry.

use std::time::{Duration, Instant};

use bytes::Bytes;
use nago_wss::conn::{Connection, Role};
use nago_wss::proto::message::{Limits, Message};
use nago_wss::reactor::socket::Addr;
use nago_wss::reactor::{Reactor, TcpListener, TcpStream};

/// Connection counts to try, in order. The run stops at the first count an
/// arm cannot reach, which is itself the answer.
const COUNTS: [usize; 1] = [10_000];
/// Payload for the broadcast round.
const PAYLOAD: usize = 64;

/// Resident set size of this process, in bytes.
///
/// Read from the kernel rather than estimated, because the question is what
/// the process actually costs rather than what the data structures ought to.
fn resident_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        // `mach_task_basic_info` is the supported way to ask on macOS; the
        // alternative is parsing `ps`, which is slower and rounds.
        #[repr(C)]
        struct TaskBasicInfo {
            virtual_size: u64,
            resident_size: u64,
            resident_size_max: u64,
            user_time: [i32; 2],
            system_time: [i32; 2],
            policy: i32,
            suspend_count: i32,
        }
        const TASK_BASIC_INFO_64: i32 = 20;
        let mut info = TaskBasicInfo {
            virtual_size: 0,
            resident_size: 0,
            resident_size_max: 0,
            user_time: [0; 2],
            system_time: [0; 2],
            policy: 0,
            suspend_count: 0,
        };
        let mut count = (core::mem::size_of::<TaskBasicInfo>() / core::mem::size_of::<i32>()) as u32;
        // SAFETY: the struct and count match what TASK_BASIC_INFO_64 writes.
        // `mach_task_self` is deprecated in favour of the `mach2` crate, which
        // is a dependency this benchmark does not need for one call that works.
        #[allow(deprecated)]
        let result = unsafe {
            libc::task_info(
                libc::mach_task_self(),
                TASK_BASIC_INFO_64 as libc::task_flavor_t,
                core::ptr::addr_of_mut!(info).cast(),
                core::ptr::addr_of_mut!(count),
            )
        };
        if result == 0 {
            info.resident_size
        } else {
            0
        }
    }
    #[cfg(target_os = "linux")]
    {
        // statm reports pages; the second field is resident.
        let Ok(text) = std::fs::read_to_string("/proc/self/statm") else {
            return 0;
        };
        let Some(field) = text.split_whitespace().nth(1) else {
            return 0;
        };
        field.parse::<u64>().unwrap_or(0) * 4096
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

/// What one arm managed at one connection count.
struct Outcome {
    establish: Duration,
    broadcast: Duration,
    bytes_per_connection: u64,
}

/// Raise the descriptor limit as far as the kernel allows.
///
/// Ten thousand connections in one process is twenty thousand descriptors, and
/// the default soft limit is far below that on most systems. Failing here with
/// "too many open files" would look like a design limit rather than a setting.
fn raise_fd_limit() {
    // SAFETY: `rlimit` is a plain struct of two integers.
    let mut limit: libc::rlimit = unsafe { core::mem::zeroed() };
    // SAFETY: `limit` is a live local of the right type.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return;
    }
    limit.rlim_cur = limit.rlim_max;
    // SAFETY: as above; raising to the hard limit is always permitted.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
}

// --- nago-wss -------------------------------------------------------------

fn nago_round(count: usize) -> Option<Outcome> {
    let reactor = Reactor::start().ok()?;
    let handle = reactor.handle();
    let listener = TcpListener::bind(Addr::localhost(0), &handle).ok()?;
    let addr = listener.local_addr().ok()?;

    let baseline = resident_bytes();

    // The server accepts everything and then holds each connection in a task
    // that echoes one message. Tasks rather than threads is the whole point:
    // ten thousand threads would not fit.
    let server_handle = handle.clone();
    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let mut tasks = Vec::with_capacity(count);
            for _ in 0..count {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tasks.push(nagoya::runtime::background().spawn(async move {
                    let mut conn = Connection::new(stream, Role::Server, Limits::default());
                    if let Ok(Some(message)) = conn.read().await {
                        let _ = conn.write(message).await;
                    }
                }));
            }
            drop(server_handle);
            for task in tasks {
                task.await;
            }
        });
    });

    // Establishing: every connection opened and handshaked.
    let establish_start = Instant::now();
    let mut conns = Vec::with_capacity(count);
    nagoya::block_on(async {
        for _ in 0..count {
            let Ok(stream) = TcpStream::connect(addr, &handle).await else {
                break;
            };
            conns.push(Connection::new(stream, Role::Client, Limits::default()));
        }
    });
    let establish = establish_start.elapsed();
    if conns.len() < count {
        return None;
    }

    let bytes_per_connection = resident_bytes().saturating_sub(baseline) / count as u64;

    // Broadcast: one message out to all, all replies back.
    let payload = Bytes::from(vec![0x5Au8; PAYLOAD]);
    let broadcast_start = Instant::now();
    nagoya::block_on(async {
        for conn in conns.iter_mut() {
            let _ = conn.write(Message::Binary(payload.clone())).await;
        }
        for conn in conns.iter_mut() {
            let _ = conn.read().await;
        }
    });
    let broadcast = broadcast_start.elapsed();

    drop(conns);
    let _ = server.join();
    reactor.shutdown();

    Some(Outcome {
        establish,
        broadcast,
        bytes_per_connection,
    })
}

// --- tokio-tungstenite ----------------------------------------------------

mod tokio_arm {
    use super::{resident_bytes, Outcome, PAYLOAD};
    use futures_util::{SinkExt, StreamExt};
    use std::net::SocketAddr;
    use std::time::Instant;
    use tokio_tungstenite::tungstenite::Message as TMessage;

    pub fn round(count: usize) -> Option<Outcome> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .ok()?;

        runtime.block_on(async move {
            let listener =
                tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .ok()?;
            let addr = listener.local_addr().ok()?;
            let baseline = resident_bytes();

            let server = tokio::spawn(async move {
                let mut tasks = Vec::with_capacity(count);
                for _ in 0..count {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    tasks.push(tokio::spawn(async move {
                        let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                            return;
                        };
                        if let Some(Ok(message)) = ws.next().await {
                            let _ = ws.send(message).await;
                        }
                    }));
                }
                for task in tasks {
                    let _ = task.await;
                }
            });

            let establish_start = Instant::now();
            let mut conns = Vec::with_capacity(count);
            for _ in 0..count {
                let Ok((ws, _)) =
                    tokio_tungstenite::connect_async(format!("ws://{addr}/")).await
                else {
                    break;
                };
                conns.push(ws);
            }
            let establish = establish_start.elapsed();
            if conns.len() < count {
                return None;
            }

            let bytes_per_connection =
                resident_bytes().saturating_sub(baseline) / count as u64;

            let payload = vec![0x5Au8; PAYLOAD];
            let broadcast_start = Instant::now();
            for ws in conns.iter_mut() {
                let _ = ws.send(TMessage::Binary(payload.clone().into())).await;
            }
            for ws in conns.iter_mut() {
                let _ = ws.next().await;
            }
            let broadcast = broadcast_start.elapsed();

            drop(conns);
            let _ = server.await;

            Some(Outcome {
                establish,
                broadcast,
                bytes_per_connection,
            })
        })
    }
}

// --- sockudo-ws -----------------------------------------------------------

mod sockudo_arm {
    use super::{resident_bytes, Outcome, PAYLOAD};
    use bytes::BytesMut;
    use futures_util::{SinkExt, StreamExt};
    use sockudo_ws::handshake::{build_response, generate_accept_key, parse_request};
    use sockudo_ws::protocol::Message as SMessage;
    use sockudo_ws::{Config, WebSocketStream};
    use std::net::SocketAddr;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// This crate leaves the handshake to the caller, both directions.
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

    pub fn round(count: usize) -> Option<Outcome> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .ok()?;

        runtime.block_on(async move {
            let listener =
                tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .ok()?;
            let addr = listener.local_addr().ok()?;
            let baseline = resident_bytes();

            let server = tokio::spawn(async move {
                let mut tasks = Vec::with_capacity(count);
                for _ in 0..count {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    tasks.push(tokio::spawn(async move {
                        if !server_handshake(&mut stream).await {
                            return;
                        }
                        let mut ws = WebSocketStream::server(stream, Config::default());
                        if let Some(Ok(message)) = ws.next().await {
                            let _ = ws.send(message).await;
                        }
                    }));
                }
                for task in tasks {
                    let _ = task.await;
                }
            });

            let establish_start = Instant::now();
            let mut conns = Vec::with_capacity(count);
            for _ in 0..count {
                let Ok(mut stream) = TcpStream::connect(addr).await else {
                    break;
                };
                stream.set_nodelay(true).ok();
                if !client_handshake(&mut stream, addr).await {
                    break;
                }
                conns.push(WebSocketStream::client(stream, Config::default()));
            }
            let establish = establish_start.elapsed();
            if conns.len() < count {
                return None;
            }

            let bytes_per_connection =
                resident_bytes().saturating_sub(baseline) / count as u64;

            let payload = bytes::Bytes::from(vec![0x5Au8; PAYLOAD]);
            let broadcast_start = Instant::now();
            for ws in conns.iter_mut() {
                let _ = ws.send(SMessage::Binary(payload.clone())).await;
            }
            for ws in conns.iter_mut() {
                let _ = ws.next().await;
            }
            let broadcast = broadcast_start.elapsed();

            drop(conns);
            let _ = server.await;

            Some(Outcome {
                establish,
                broadcast,
                bytes_per_connection,
            })
        })
    }
}

// --- reporting ------------------------------------------------------------

fn report(name: &str, count: usize, outcome: Option<Outcome>) {
    match outcome {
        Some(outcome) => println!(
            "  {name:<18} {:>8.2} s establish  {:>8.2} ms broadcast  {:>7} B/conn",
            outcome.establish.as_secs_f64(),
            outcome.broadcast.as_secs_f64() * 1000.0,
            outcome.bytes_per_connection,
        ),
        None => println!("  {name:<18} could not reach {count} connections"),
    }
}

fn main() {
    raise_fd_limit();

    println!("\nholding connections, both ends in one process\n");

    for count in COUNTS {
        println!("{count} connections:");
        report("nago-wss", count, nago_round(count));
        report("tokio-tungstenite", count, tokio_arm::round(count));
        report("sockudo-ws", count, sockudo_arm::round(count));
        println!();
    }
}
