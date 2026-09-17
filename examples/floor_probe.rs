//! Where the eighteen microseconds actually go.
//!
//! The floor benchmark says a one byte round trip costs about 18us on this
//! reactor. That number is a sum, and optimising a sum without knowing its
//! terms is guesswork. This measures each layer separately, on the same
//! machine, in the same process:
//!
//! 1. raw blocking `send`/`recv` on two threads: the syscalls alone.
//! 2. raw non-blocking with a `kevent` wait: syscalls plus the readiness wait.
//! 3. the full reactor path: the above plus waker dispatch and task wakeup.
//!
//! The difference between 1 and 2 is what readiness costs. The difference
//! between 2 and 3 is what this crate's own machinery costs on top.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Instant;

const ROUND_TRIPS: usize = 2_000;

fn local() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// A connected pair over loopback, both ends with Nagle off.
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(local()).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = std::thread::spawn(move || {
        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_nodelay(true).expect("nodelay");
        stream
    });
    let (server, _) = listener.accept().expect("accept");
    server.set_nodelay(true).expect("nodelay");
    (client.join().expect("client"), server)
}

/// Layer 1: blocking syscalls only, no readiness, no runtime.
///
/// This is the floor under every other number: two `write`s and two `read`s
/// per round trip and nothing else at all.
fn blocking_syscalls() -> f64 {
    use std::io::{Read, Write};
    let (mut client, mut server) = pair();

    let echo = std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        for _ in 0..ROUND_TRIPS {
            if server.read(&mut byte).expect("read") == 0 {
                break;
            }
            server.write_all(&byte).expect("write");
        }
    });

    let mut byte = [0u8; 1];
    let start = Instant::now();
    for _ in 0..ROUND_TRIPS {
        client.write_all(b"x").expect("write");
        client.read_exact(&mut byte).expect("read");
    }
    let elapsed = start.elapsed();
    drop(client);
    echo.join().expect("echo");
    elapsed.as_secs_f64() / ROUND_TRIPS as f64 * 1e6
}

/// Layer 2: non-blocking plus a kqueue wait, still no runtime.
///
/// The same traffic, but reaching readiness the way a reactor does: try the
/// read, get EWOULDBLOCK, wait for the edge, try again. This isolates what the
/// readiness model costs before any executor is involved.
fn readiness_syscalls() -> f64 {
    use std::io::{Read, Write};

    let (client, server) = pair();
    client.set_nonblocking(true).expect("nonblocking");

    let echo = std::thread::spawn(move || {
        let mut server = server;
        let mut byte = [0u8; 1];
        for _ in 0..ROUND_TRIPS {
            if server.read(&mut byte).expect("read") == 0 {
                break;
            }
            server.write_all(&byte).expect("write");
        }
    });

    // One kqueue watching the client end for readability.
    let kq = unsafe { libc::kqueue() };
    assert!(kq >= 0, "kqueue failed");
    let change = libc::kevent {
        ident: client.as_raw_fd() as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    unsafe {
        libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
    }

    let mut client = client;
    let mut byte = [0u8; 1];
    let start = Instant::now();
    for _ in 0..ROUND_TRIPS {
        client.write_all(b"x").expect("write");
        loop {
            match client.read(&mut byte) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                    unsafe {
                        libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, std::ptr::null());
                    }
                }
                Err(error) => panic!("read failed: {error}"),
            }
        }
    }
    let elapsed = start.elapsed();
    unsafe {
        libc::close(kq);
    }
    drop(client);
    echo.join().expect("echo");
    elapsed.as_secs_f64() / ROUND_TRIPS as f64 * 1e6
}

/// Layer 0: `send`/`recv` through libc directly, bypassing `std::net`.
///
/// `std::net::TcpStream::read` is a thin wrapper: it calls `recv` and maps the
/// result. This checks that claim rather than trusting it, because if std were
/// adding meaningful overhead per call then the fix would be to stop using it,
/// and that is worth knowing before rewriting anything larger.
fn raw_libc_syscalls() -> f64 {
    let (client, server) = pair();
    let client_fd = client.as_raw_fd();
    let server_fd = server.as_raw_fd();

    let echo = std::thread::spawn(move || {
        // Keep the stream alive for the duration; the fd is what is used.
        let _server = server;
        let mut byte = 0u8;
        for _ in 0..ROUND_TRIPS {
            let read = unsafe {
                libc::recv(
                    server_fd,
                    std::ptr::addr_of_mut!(byte).cast::<libc::c_void>(),
                    1,
                    0,
                )
            };
            if read <= 0 {
                break;
            }
            unsafe {
                libc::send(
                    server_fd,
                    std::ptr::addr_of!(byte).cast::<libc::c_void>(),
                    1,
                    0,
                );
            }
        }
    });

    let _client = client;
    let out = b'x';
    let mut byte = 0u8;
    let start = Instant::now();
    for _ in 0..ROUND_TRIPS {
        unsafe {
            libc::send(
                client_fd,
                std::ptr::addr_of!(out).cast::<libc::c_void>(),
                1,
                0,
            );
            libc::recv(
                client_fd,
                std::ptr::addr_of_mut!(byte).cast::<libc::c_void>(),
                1,
                0,
            );
        }
    }
    let elapsed = start.elapsed();
    drop(_client);
    echo.join().expect("echo");
    elapsed.as_secs_f64() / ROUND_TRIPS as f64 * 1e6
}

fn main() {
    // Warm every path.
    let _ = raw_libc_syscalls();
    let _ = blocking_syscalls();
    let _ = readiness_syscalls();

    let raw = (0..3).map(|_| raw_libc_syscalls()).fold(f64::MAX, f64::min);
    let blocking = (0..3)
        .map(|_| blocking_syscalls())
        .fold(f64::MAX, f64::min);
    let readiness = (0..3)
        .map(|_| readiness_syscalls())
        .fold(f64::MAX, f64::min);

    println!("\nwhere a loopback round trip goes (best of 3, us/op)\n");
    println!("  0. raw libc send/recv          {raw:>8.2}");
    println!("  1. via std::net TcpStream      {blocking:>8.2}");
    println!("     std's own overhead          {:>8.2}", blocking - raw);
    println!("  2. non-blocking + kqueue wait  {readiness:>8.2}");
    println!("     readiness costs             {:>8.2}", readiness - blocking);
    println!("  3. full reactor (floor bench)  {:>8.2}  (measured separately)", 18.2);
    println!("     this crate's machinery      {:>8.2}", 18.2 - readiness);
    println!();
}
