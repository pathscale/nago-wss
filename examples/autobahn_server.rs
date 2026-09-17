//! The echo server the Autobahn suite drives.
//!
//! # What this is for
//!
//! Autobahn is the conformance suite for RFC 6455: about five hundred cases
//! covering fragmentation, close codes, reserved bits, oversized frames and a
//! great deal of malformed UTF-8. It drives a plain echo server and checks
//! that every case ends the way the RFC says it should, which is mostly by
//! failing the connection with a particular close code rather than by echoing
//! anything.
//!
//! So this echoes text and binary, answers pings, and otherwise does nothing:
//! everything being tested is in the protocol core underneath.
//!
//! # Running it
//!
//!     cargo run --release --example autobahn_server
//!
//! then point the suite at `ws://127.0.0.1:9001`. `autobahn/README.md` has the
//! Docker line.

use bytes::Bytes;
use nago_wss::conn::Error;
use nago_wss::proto::message::{CloseFrame, Limits, Message};
use nago_wss::reactor::socket::Addr;
use nago_wss::reactor::{Reactor, TcpListener};

fn main() {
    let reactor = Reactor::start().expect("reactor");
    let handle = reactor.handle();
    let listener = TcpListener::bind(Addr::localhost(9001), &handle).expect("bind 127.0.0.1:9001");

    println!("autobahn echo server on ws://127.0.0.1:9001");

    nagoya::block_on(async {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            // One task per connection. The suite opens them one at a time,
            // but a case that leaves a connection open must not block the
            // next one.
            nagoya::runtime::background().spawn(async move {
                if let Err(error) = serve(stream).await {
                    // Expected for most of the suite: a malformed frame is
                    // supposed to fail the connection. Printed rather than
                    // ignored so a surprising one is visible.
                    eprintln!("connection ended: {error}");
                }
            });
        }
    });
}

/// Echo until the peer closes or breaks the protocol.
async fn serve(stream: nago_wss::reactor::TcpStream) -> Result<(), Error> {
    // The suite sends messages far larger than the default, and a case that
    // is meant to be refused for its content should not be refused for its
    // size instead.
    let limits = Limits {
        max_frame: 32 * 1024 * 1024,
        max_message: 32 * 1024 * 1024,
    };

    let (mut conn, _) = nago_wss::upgrade::accept(stream, limits, |_| None).await?;

    loop {
        let message = match conn.read().await {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(()),
            // Most of the suite ends here. A case that sends a bad frame is
            // checking two things: that the connection fails, and that it
            // fails with the code §7.4.1 gives that failure. Dropping the
            // socket would get the first right and the second wrong, so the
            // code goes out before the connection does.
            Err(error) => {
                if let Some(code) = error.close_code() {
                    let _ = conn
                        .close(Some(CloseFrame {
                            code,
                            reason: Bytes::new(),
                        }))
                        .await;
                }
                return Err(error);
            }
        };

        match message {
            // Echoed back unchanged, which is what every data case checks.
            Message::Text(_) | Message::Binary(_) => conn.write(message).await?,
            // The payload must come back exactly, per 5.5.2.
            Message::Ping(payload) => conn.pong(payload).await?,
            Message::Pong(_) => {}
            // Echo the peer's close frame back and stop, which completes the
            // handshake rather than dropping the connection under it.
            Message::Close(frame) => {
                conn.close(frame).await?;
                return Ok(());
            }
        }
    }
}
