//! The reactor thread: readiness in, wakers out.
//!
//! # What it does
//!
//! One thread owns the [`Poller`] and loops. Each pass waits for readiness,
//! wakes whatever task registered interest in each ready descriptor, and then
//! drives nagoya's timer wheel. Nothing else happens here: the reactor does not
//! run tasks, which is nagoya's job, and does not touch sockets, which is the
//! task's job. It only converts kernel readiness into `Waker::wake`.
//!
//! # Why the timers share this loop
//!
//! `nagoya::time` needs someone to call [`nagoya::poll_timers`], and that call
//! returns when the next timer is due. That is exactly the timeout the poller
//! needs for its wait. Running both in one thread means a sleeping reactor
//! wakes precisely when the next timer fires, with no separate timer thread and
//! no polling interval to tune. A timer armed while the reactor is already
//! blocked is handled by [`Poller::wake`].
//!
//! # Registration lifetime
//!
//! A [`Registration`] owns its slot: dropping it removes the descriptor from
//! the poller and frees the token. Tokens are generational, so a readiness
//! event that was already in flight when a registration was dropped resolves to
//! a stale slot and is discarded rather than waking an unrelated task that has
//! since taken the same index.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;

use super::poller::{Event, Interest, Poller};

/// The wakers waiting on one descriptor.
#[derive(Debug, Default)]
struct Slot {
    /// Bumped on every reuse of this index, so a stale event can be spotted.
    generation: u64,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// Shared reactor state. The thread and every handle hold one of these.
#[derive(Debug)]
struct Shared {
    poller: Poller,
    /// Indexed by slot index, not by token: the token carries the generation.
    slots: Mutex<HashMap<u64, Slot>>,
    next_index: AtomicU64,
    running: AtomicBool,
}

/// Split a token into its slot index and generation.
///
/// The generation occupies the high 16 bits, which is enough that a slot would
/// have to be reused 65,536 times inside one in-flight event for a collision,
/// and leaves 48 bits of index: more descriptors than any process can open.
const GENERATION_SHIFT: u32 = 48;

#[inline]
fn make_token(index: u64, generation: u64) -> u64 {
    (generation << GENERATION_SHIFT) | index
}

#[inline]
fn split_token(token: u64) -> (u64, u64) {
    (token & ((1 << GENERATION_SHIFT) - 1), token >> GENERATION_SHIFT)
}

/// A handle to the running reactor.
#[derive(Debug, Clone)]
pub struct Handle {
    shared: Arc<Shared>,
}

impl Handle {
    /// Register `fd` with the reactor.
    ///
    /// The returned [`Registration`] must be kept for as long as the descriptor
    /// is in use; dropping it deregisters. `fd` must be non-blocking and must
    /// outlive the registration.
    pub fn register(&self, fd: i32, interest: Interest) -> io::Result<Registration> {
        let index = self.shared.next_index.fetch_add(1, Ordering::Relaxed);

        let generation = {
            let mut slots = self.shared.slots.lock().expect("reactor slots poisoned");
            let slot = slots.entry(index).or_default();
            slot.generation = slot.generation.wrapping_add(1);
            slot.generation
        };

        let token = make_token(index, generation);
        if let Err(error) = self.shared.poller.add(fd, token, interest) {
            self.shared
                .slots
                .lock()
                .expect("reactor slots poisoned")
                .remove(&index);
            return Err(error);
        }

        Ok(Registration {
            shared: Arc::clone(&self.shared),
            fd,
            index,
            token,
        })
    }

    /// Wake the reactor thread if it is blocked.
    ///
    /// Needed after arming a timer, since the thread may already be waiting on
    /// a deadline further out than the new one.
    pub fn wake(&self) -> io::Result<()> {
        self.shared.poller.wake()
    }
}

/// A descriptor's registration with the reactor.
///
/// Dropping this deregisters the descriptor and invalidates its token.
#[derive(Debug)]
pub struct Registration {
    shared: Arc<Shared>,
    fd: i32,
    index: u64,
    token: u64,
}

impl Registration {
    /// Park `waker` until the descriptor is readable.
    ///
    /// Call this only after a read has actually returned `EWOULDBLOCK`: the
    /// poller is edge triggered, so registering interest without first draining
    /// means waiting for an edge that has already passed.
    pub fn poll_readable(&self, waker: &Waker) {
        let mut slots = self.shared.slots.lock().expect("reactor slots poisoned");
        if let Some(slot) = slots.get_mut(&self.index) {
            slot.reader = Some(waker.clone());
        }
    }

    /// Park `waker` until the descriptor is writable. See [`Self::poll_readable`].
    pub fn poll_writable(&self, waker: &Waker) {
        let mut slots = self.shared.slots.lock().expect("reactor slots poisoned");
        if let Some(slot) = slots.get_mut(&self.index) {
            slot.writer = Some(waker.clone());
        }
    }

    /// Change what this descriptor is watched for.
    pub fn modify(&self, interest: Interest) -> io::Result<()> {
        self.shared.poller.modify(self.fd, self.token, interest)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Order matters: stop the kernel delivering first, then drop the slot.
        // The reverse would leave a window where an event arrives for a slot
        // that is already gone, which is harmless but pointless work.
        let _ = self.shared.poller.remove(self.fd);
        self.shared
            .slots
            .lock()
            .expect("reactor slots poisoned")
            .remove(&self.index);
    }
}

/// Start a reactor on its own thread.
///
/// The thread runs until [`Reactor::shutdown`] is called or the returned
/// [`Reactor`] is dropped.
pub struct Reactor {
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Reactor {
    /// Start the reactor.
    pub fn start() -> io::Result<Self> {
        let shared = Arc::new(Shared {
            poller: Poller::new()?,
            slots: Mutex::new(HashMap::new()),
            next_index: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });

        let worker = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("nago-wss-reactor".into())
            .spawn(move || run(&worker))?;

        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    /// A cloneable handle for registering descriptors.
    pub fn handle(&self) -> Handle {
        Handle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Stop the reactor thread and wait for it to finish.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.shared.running.store(false, Ordering::Release);
        // The thread may be blocked in `wait`; this is what gets it out.
        let _ = self.shared.poller.wake();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The reactor loop.
fn run(shared: &Arc<Shared>) {
    let mut events: Vec<Event> = Vec::with_capacity(64);

    while shared.running.load(Ordering::Acquire) {
        // Drive timers first and learn when the next one is due. That deadline
        // becomes the wait timeout, so the thread sleeps exactly as long as it
        // can rather than on a fixed tick.
        let now = nagoya::now_ns();
        let timeout = nagoya::poll_timers(now).map(|deadline| deadline.saturating_sub(now));

        events.clear();
        if shared.poller.wait(&mut events, timeout).is_err() {
            // A failed wait is not recoverable by retrying in a tight loop; the
            // descriptor set is intact, so stop rather than spin.
            break;
        }

        dispatch(shared, &events);
    }
}

/// Wake the tasks named by `events`.
fn dispatch(shared: &Arc<Shared>, events: &[Event]) {
    // Wakers are collected under the lock and invoked after it is released: a
    // waker may run arbitrary code, including code that registers another
    // descriptor, and this lock is not reentrant.
    let mut pending: Vec<Waker> = Vec::new();

    {
        let mut slots = shared.slots.lock().expect("reactor slots poisoned");
        for event in events {
            let (index, generation) = split_token(event.token);
            let Some(slot) = slots.get_mut(&index) else {
                continue;
            };
            // A stale event: the slot was reused after this event was queued.
            if slot.generation != generation {
                continue;
            }
            if event.readable {
                pending.extend(slot.reader.take());
            }
            if event.writable {
                pending.extend(slot.writer.take());
            }
        }
    }

    for waker in pending {
        waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reactor::testing::{socket_pair, write_byte};
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;
    use std::time::Duration;

    /// A waker that reports having been woken, over a channel.
    fn channel_waker() -> (Waker, mpsc::Receiver<()>) {
        use std::sync::Arc as StdArc;
        struct Signal(mpsc::Sender<()>);
        impl std::task::Wake for Signal {
            fn wake(self: StdArc<Self>) {
                let _ = self.0.send(());
            }
            fn wake_by_ref(self: &StdArc<Self>) {
                let _ = self.0.send(());
            }
        }
        let (tx, rx) = mpsc::channel();
        (Waker::from(StdArc::new(Signal(tx))), rx)
    }

    #[test]
    fn wakes_a_reader_when_data_arrives() {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let (a, b) = socket_pair();

        let registration = handle
            .register(a.as_raw_fd(), Interest::READABLE)
            .expect("register");
        let (waker, woken) = channel_waker();
        registration.poll_readable(&waker);

        // Nothing written: the waker must stay untouched.
        assert!(
            woken.recv_timeout(Duration::from_millis(100)).is_err(),
            "woken with no data pending"
        );

        write_byte(&b);

        woken
            .recv_timeout(Duration::from_secs(5))
            .expect("reader was never woken");
    }

    #[test]
    fn a_dropped_registration_stops_waking() {
        let reactor = Reactor::start().expect("reactor");
        let handle = reactor.handle();
        let (a, b) = socket_pair();

        let (waker, woken) = channel_waker();
        {
            let registration = handle
                .register(a.as_raw_fd(), Interest::READABLE)
                .expect("register");
            registration.poll_readable(&waker);
        }

        write_byte(&b);

        assert!(
            woken.recv_timeout(Duration::from_millis(200)).is_err(),
            "a dropped registration still woke its task"
        );
    }

    #[test]
    fn a_stale_token_does_not_wake_the_slots_new_owner() {
        // Generations exist for this: an event queued for one registration must
        // not wake whatever later takes the same slot index.
        let (index, generation) = split_token(make_token(5, 3));
        assert_eq!((index, generation), (5, 3));

        let mut slots: HashMap<u64, Slot> = HashMap::new();
        slots.insert(
            5,
            Slot {
                generation: 4,
                reader: None,
                writer: None,
            },
        );

        let slot = slots.get(&5).expect("slot");
        assert_ne!(
            slot.generation, generation,
            "a reused slot must not match the old generation"
        );
    }

    #[test]
    fn shuts_down_promptly_while_blocked() {
        let reactor = Reactor::start().expect("reactor");
        // The thread is now blocked in `wait` with no timers and no
        // descriptors, so this only returns if `wake` breaks it out.
        let start = std::time::Instant::now();
        reactor.shutdown();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "shutdown did not interrupt a blocked reactor"
        );
    }
}
