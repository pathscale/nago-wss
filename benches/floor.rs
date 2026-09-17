//! What the transport costs before any WebSocket exists.
//!
//! The echo benchmark compares three WebSocket stacks and finds them within
//! about 20% of each other, which is a suspicious result: the framing code in
//! each differs far more than that. This measures the floor underneath them,
//! a bare ping-pong over TCP with no protocol at all, on this crate's reactor
//! and on tokio.
//!
//! If the two floors match the two WebSocket numbers, the framing is not what
//! is being measured and optimising it is wasted effort.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use nago_wss::reactor::socket::Addr;
use nago_wss::reactor::{Reactor, TcpListener, TcpStream};

const ROUND_TRIPS: usize = 500;
const SAMPLES: usize = 3;

/// Loopback, port chosen by the kernel. For the tokio and sockudo arms.
fn local() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// The same, in this crate's own address type.
fn local_addr() -> Addr {
    Addr::localhost(0)
}


fn best(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[0]
}

/// One byte there, one byte back, on this crate's reactor.
fn nago_floor() -> Duration {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(local_addr(), &handle).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = std::thread::spawn(move || {
        nagoya::block_on(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut byte = [0u8; 1];
            for _ in 0..ROUND_TRIPS {
                let read = stream.read(&mut byte).await.expect("read");
                if read == 0 {
                    break;
                }
                stream.write_all(&byte).await.expect("write");
            }
        });
    });

    let elapsed = nagoya::block_on(async {
        let mut stream = TcpStream::connect(addr, &handle).await.expect("connect");
        let mut byte = [0u8; 1];
        let start = Instant::now();
        for _ in 0..ROUND_TRIPS {
            stream.write_all(b"x").await.expect("write");
            stream.read(&mut byte).await.expect("read");
        }
        start.elapsed()
    });

    server.join().expect("server");
    elapsed
}

/// The same, on tokio.
fn tokio_floor() -> Duration {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            let mut byte = [0u8; 1];
            for _ in 0..ROUND_TRIPS {
                let read = stream.read(&mut byte).await.expect("read");
                if read == 0 {
                    break;
                }
                stream.write_all(&byte).await.expect("write");
            }
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.set_nodelay(true).ok();
        let mut byte = [0u8; 1];

        let start = Instant::now();
        for _ in 0..ROUND_TRIPS {
            stream.write_all(b"x").await.expect("write");
            let read = stream.read(&mut byte).await.expect("read");
            assert_eq!(read, 1, "peer closed mid benchmark");
        }
        let elapsed = start.elapsed();

        server.await.expect("server");
        elapsed
    })
}

fn main() {
    // Warm both arms; the first connection pays for lazily initialised state.
    let _ = nago_floor();
    let _ = tokio_floor();

    let nago = best((0..SAMPLES).map(|_| nago_floor()).collect());
    let tokio = best((0..SAMPLES).map(|_| tokio_floor()).collect());

    let each = |d: Duration| d.as_secs_f64() / ROUND_TRIPS as f64 * 1e6;
    println!("\ntransport floor, 1 byte round trip (best of {SAMPLES})\n");
    println!("  nago-wss reactor   {:>8.2} us/op", each(nago));
    println!("  tokio              {:>8.2} us/op", each(tokio));
    // The echo benchmark's round trip numbers, for subtraction. Hardcoded
    // rather than measured here because running the WebSocket arms again just
    // to subtract them would double the runtime of a benchmark whose whole
    // point is to be quick.
    const WS_NAGO_US: f64 = 21.0;
    const WS_TOKIO_US: f64 = 18.5;
    println!(
        "\n  against ~{WS_NAGO_US:.1}us and ~{WS_TOKIO_US:.1}us for the same round trip\n  \
         with WebSocket framing, so framing is about {:.1}us and {:.1}us of it.\n\
         \n  Most of a loopback round trip is the transport, not the protocol.\n",
        WS_NAGO_US - each(nago),
        WS_TOKIO_US - each(tokio)
    );
}
