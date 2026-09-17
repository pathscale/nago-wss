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

/// What one mode switch costs, measured on its own.
///
/// If the round trip is syscall bound then the cost of a single trivial
/// syscall, times the number of them, should account for most of it. This
/// measures the cheapest syscall there is so that arithmetic can be checked
/// rather than assumed.
fn one_syscall() -> f64 {
    const CALLS: usize = 200_000;
    let start = Instant::now();
    for _ in 0..CALLS {
        // `getpid` does essentially nothing in the kernel, so what is left is
        // the mode switch. It is not vDSO accelerated on macOS the way a clock
        // read is, which is what makes it usable as a probe.
        unsafe {
            libc::getpid();
        }
    }
    start.elapsed().as_secs_f64() / CALLS as f64 * 1e6
}

/// A round trip where the read half is a blocking recv on its own thread.
///
/// The readiness model spends a syscall discovering there is nothing to read,
/// then another waiting, then another reading. A blocking recv is one syscall
/// that returns when the data arrives. This is the shape a completion based
/// interface would have, approximated with threads, and it bounds what
/// removing the speculative calls could buy before any io_uring exists.
fn blocking_recv_shape() -> f64 {
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
        // One syscall that parks until the byte is there: no EWOULDBLOCK
        // probe, no separate wait call.
        client.read_exact(&mut byte).expect("read");
    }
    let elapsed = start.elapsed();
    drop(client);
    echo.join().expect("echo");
    elapsed.as_secs_f64() / ROUND_TRIPS as f64 * 1e6
}

/// The same ping pong over a Unix socket pair instead of loopback TCP.
///
/// Same syscalls, same threads, same handoff, but none of the TCP stack. What
/// separates this from the TCP number is what loopback TCP costs: checksums,
/// the protocol path, and the socket buffer machinery around it.
fn unix_socket_shape() -> f64 {
    let mut fds = [0i32; 2];
    let result = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(result, 0, "socketpair failed");
    let (client_fd, server_fd) = (fds[0], fds[1]);

    let echo = std::thread::spawn(move || {
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
        unsafe { libc::close(server_fd) };
    });

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
    unsafe { libc::close(client_fd) };
    echo.join().expect("echo");
    elapsed.as_secs_f64() / ROUND_TRIPS as f64 * 1e6
}

/// What zeroing a read buffer costs, per read.
///
/// `std::io::Read::read` takes `&mut [u8]`, which means initialised memory,
/// so filling a growable buffer from a socket means writing zeros over the
/// spare capacity first. The kernel is about to overwrite it. This measures
/// the write that exists only to satisfy the signature.
fn buffer_zeroing(size: usize) -> f64 {
    const REPEATS: usize = 20_000;
    let mut buffer = vec![0u8; size];
    let start = Instant::now();
    for _ in 0..REPEATS {
        // Same shape as the read path: zero the region, then pretend to read.
        for byte in buffer.iter_mut() {
            *byte = 0;
        }
        std::hint::black_box(&buffer);
    }
    start.elapsed().as_secs_f64() / REPEATS as f64 * 1e6
}

/// How long a wake-to-poll round trip costs with no I/O in it at all.
///
/// The reactor's job on each event is: wake a waker, have the executor poll
/// the task, and get back into the wait. This measures that cycle alone, by
/// bouncing a task between two wakes, so the scheduler's contribution can be
/// separated from anything the socket is doing.
fn wake_latency() -> f64 {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    const HOPS: usize = 20_000;

    /// A future that yields `HOPS` times, waking itself each time. Each yield
    /// is one full wake, reschedule and poll.
    struct Yielder(usize);
    impl Future for Yielder {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 == 0 {
                return Poll::Ready(());
            }
            self.0 -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    let start = Instant::now();
    nagoya::block_on(Yielder(HOPS));
    start.elapsed().as_secs_f64() / HOPS as f64 * 1e6
}

/// The same, on tokio, for comparison.
fn tokio_wake_latency() -> f64 {
    const HOPS: usize = 20_000;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let start = Instant::now();
        for _ in 0..HOPS {
            tokio::task::yield_now().await;
        }
        start.elapsed().as_secs_f64() / HOPS as f64 * 1e6
    })
}

/// What one thread handing off to another costs.
///
/// This crate's reactor runs on its own thread: it returns from `kevent`,
/// wakes a waker, and the task polls on a different thread. tokio's
/// current-thread runtime returns from `kevent` and polls on the same one.
/// That difference is a park and an unpark per message, and this measures it.
fn thread_handoff() -> f64 {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const HOPS: usize = 20_000;

    let flag = Arc::new(AtomicBool::new(false));
    let back = Arc::new(AtomicBool::new(false));

    let their_flag = Arc::clone(&flag);
    let their_back = Arc::clone(&back);
    let main_thread = std::thread::current();

    let worker = std::thread::spawn(move || {
        let mut parked = std::thread::current();
        let _ = &mut parked;
        for _ in 0..HOPS {
            while !their_flag.swap(false, Ordering::AcqRel) {
                std::thread::park();
            }
            their_back.store(true, Ordering::Release);
            main_thread.unpark();
        }
    });

    // The worker needs this thread's handle to unpark it, which it captured
    // above; here the ping half just drives the cycle.
    let worker_thread = worker.thread().clone();
    let start = Instant::now();
    for _ in 0..HOPS {
        flag.store(true, Ordering::Release);
        worker_thread.unpark();
        while !back.swap(false, Ordering::AcqRel) {
            std::thread::park();
        }
    }
    let elapsed = start.elapsed();
    worker.join().expect("worker");
    elapsed.as_secs_f64() / HOPS as f64 * 1e6
}

/// What one `kevent` wait costs when an event is already pending.
///
/// The reactor does one of these per round trip. If it is expensive, that is
/// the gap; if it is not, the gap is in what surrounds it.
fn kevent_with_event_ready() -> f64 {
    const CALLS: usize = 20_000;

    let (client, server) = pair();
    client.set_nonblocking(true).expect("nonblocking");

    let kq = unsafe { libc::kqueue() };
    let change = libc::kevent {
        ident: client.as_raw_fd() as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    unsafe {
        libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
    }

    // One byte sitting unread, so every wait returns immediately. This
    // measures the syscall and the event copy, not any waiting.
    use std::io::Write;
    let mut writer = server;
    writer.write_all(b"x").expect("write");

    let mut events: [libc::kevent; 64] = unsafe { std::mem::zeroed() };
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let start = Instant::now();
    for _ in 0..CALLS {
        unsafe {
            libc::kevent(kq, std::ptr::null(), 0, events.as_mut_ptr(), 64, &timeout);
        }
    }
    let elapsed = start.elapsed();

    unsafe { libc::close(kq) };
    drop(client);
    drop(writer);
    elapsed.as_secs_f64() / CALLS as f64 * 1e6
}

/// A mutex lock and unlock, which the reactor does twice per wakeup: once to
/// park the waker, once to take it back out.
fn mutex_pair() -> f64 {
    use std::sync::Mutex;
    const CALLS: usize = 200_000;
    let lock = Mutex::new(0u64);
    let start = Instant::now();
    for _ in 0..CALLS {
        *lock.lock().expect("lock") += 1;
    }
    start.elapsed().as_secs_f64() / CALLS as f64 * 1e6
}

/// Reading nagoya's clock, which `service_timers` does on every pass.
fn clock_read() -> f64 {
    const CALLS: usize = 200_000;
    let start = Instant::now();
    for _ in 0..CALLS {
        std::hint::black_box(nagoya::now_ns());
    }
    start.elapsed().as_secs_f64() / CALLS as f64 * 1e6
}

/// How many syscalls a round trip actually makes, counted rather than
/// reasoned about.
///
/// Both arms are timed against a known count of `getpid`, so the figure is in
/// syscall-equivalents rather than microseconds: it says how many trips into
/// the kernel each design is paying for, which is the thing that would
/// explain a gap the individual pieces do not.
fn syscalls_per_round_trip() -> (f64, f64) {
    // A read that returns EWOULDBLOCK, then a kevent, then the real read:
    // three calls, which is what the reactor does when data has not arrived
    // yet. tokio does the same, so any difference is in how often each one
    // guesses wrong.
    const TRIPS: usize = 20_000;

    let (client, server) = pair();
    client.set_nonblocking(true).expect("nonblocking");

    let kq = unsafe { libc::kqueue() };
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

    let echo = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut server = server;
        let mut byte = [0u8; 1];
        for _ in 0..TRIPS {
            if server.read(&mut byte).expect("read") == 0 {
                break;
            }
            server.write_all(&byte).expect("write");
        }
    });

    // Optimistic: try the read first and only wait when it blocks. This is
    // what this crate does.
    use std::io::{Read, Write};
    let mut client = client;
    let mut byte = [0u8; 1];
    let mut waits = 0u64;

    let start = Instant::now();
    for _ in 0..TRIPS {
        client.write_all(b"x").expect("write");
        loop {
            match client.read(&mut byte) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    waits += 1;
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

    unsafe { libc::close(kq) };
    drop(client);
    echo.join().expect("echo");

    (
        elapsed.as_secs_f64() / TRIPS as f64 * 1e6,
        waits as f64 / TRIPS as f64,
    )
}

fn main() {
    // Warm every path.
    let _ = raw_libc_syscalls();
    let _ = blocking_syscalls();
    let _ = readiness_syscalls();

    let raw = (0..3).map(|_| raw_libc_syscalls()).fold(f64::MAX, f64::min);
    let blocking = (0..3).map(|_| blocking_syscalls()).fold(f64::MAX, f64::min);
    let readiness = (0..3)
        .map(|_| readiness_syscalls())
        .fold(f64::MAX, f64::min);

    println!("\nwhere a loopback round trip goes (best of 3, us/op)\n");
    println!("  0. raw libc send/recv          {raw:>8.2}");
    println!("  1. via std::net TcpStream      {blocking:>8.2}");
    println!("     std's own overhead          {:>8.2}", blocking - raw);
    println!("  2. non-blocking + kqueue wait  {readiness:>8.2}");
    println!(
        "     readiness costs             {:>8.2}",
        readiness - blocking
    );
    println!(
        "  3. full reactor (floor bench)  {:>8.2}  (measured separately)",
        18.2
    );
    println!("     this crate's machinery      {:>8.2}", 18.2 - readiness);
    let syscall = one_syscall();
    let blocking_shape = (0..3)
        .map(|_| blocking_recv_shape())
        .fold(f64::MAX, f64::min);

    println!("  one trivial syscall            {syscall:>8.4}");
    println!(
        "  readiness does ~4 calls/trip   {:>8.2}  of pure mode switching",
        syscall * 4.0
    );
    println!("\n  completion shaped (blocking recv, no readiness probe)");
    println!("    {blocking_shape:>8.2} us/op vs {readiness:.2} for readiness");
    println!(
        "    so removing the speculative calls is worth about {:.2}us here",
        readiness - blocking_shape
    );

    let unix = (0..3).map(|_| unix_socket_shape()).fold(f64::MAX, f64::min);
    println!("\n  same ping pong over a unix socketpair");
    println!("    {unix:>8.2} us/op vs {raw:.2} for loopback TCP");
    println!(
        "    so the TCP stack itself is about {:.2}us of the {raw:.2}\n",
        raw - unix
    );
    println!(
        "  a syscall is {:.4}us, so the {raw:.2}us is not syscall count:\n           it is the kernel scheduling two threads through a socket.\n",
        syscall
    );

    let nago_wake = (0..3).map(|_| wake_latency()).fold(f64::MAX, f64::min);
    let tokio_wake = (0..3)
        .map(|_| tokio_wake_latency())
        .fold(f64::MAX, f64::min);
    println!("  wake and repoll, no I/O at all:");
    println!("    nagoya block_on  {nago_wake:>8.4} us/hop");
    println!("    tokio            {tokio_wake:>8.4} us/hop\n");

    let handoff = (0..3).map(|_| thread_handoff()).fold(f64::MAX, f64::min);
    println!("  park/unpark round trip between two threads:");
    println!("    {handoff:>8.3} us  <- paid once per message by a reactor");
    println!("                 that polls on a different thread\n");

    let (trip, waits) = syscalls_per_round_trip();
    println!("  optimistic read then wait:");
    println!("    {trip:>8.2} us/trip, {waits:.2} waits per trip");
    println!("    (1.00 means the read always blocked and the wait was needed)");
    println!();

    println!("  what the reactor does per round trip:");
    println!(
        "    kevent, event ready  {:>8.3} us",
        kevent_with_event_ready()
    );
    println!(
        "    mutex lock/unlock    {:>8.4} us  (x2 per wakeup)",
        mutex_pair()
    );
    println!("    nagoya clock read    {:>8.4} us", clock_read());
    println!();

    println!("  cost of zeroing a read buffer, which std::io::Read's");
    println!("  signature requires before every read:");
    for size in [4096usize, 16 * 1024, 64 * 1024] {
        println!("    {size:>6} bytes  {:>8.3} us", buffer_zeroing(size));
    }
    println!();
}
