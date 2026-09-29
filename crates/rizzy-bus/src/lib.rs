//! `rizzy-bus` — typed domain events for the rizzy-vault server (roadmap M1, [ADR 0016] §3).
//!
//! Roles inside one process talk through Rust APIs and this in-process event bus ([ADR 0010]
//! §3). Domains that must not depend on each other ([ADR 0016] R4) can exchange events here.
//! The `PostgreSQL` `LISTEN/NOTIFY` backend that carries the same kind of message between
//! processes in profile C is M3 and does not exist yet.
//!
//! # What an event is
//!
//! An [`Event`] says that something changed, and names *what* by id only, in the spirit of
//! ADR 0010 §3's "account X changed". It carries no secret, no ciphertext, no header, no
//! version vector, no count and no size: nothing a subscriber could leak beyond the ids the
//! server already stores (threat model AST-13 keeps even those to a minimum). The id types
//! redact their bytes in `Debug`, so an event that ends up in a log line names its kind only.
//!
//! # Events are hints, never the record of truth
//!
//! The conservative reading of ADR 0010 and ADR 0011, applied throughout this crate:
//!
//! - **Publish after commit.** A domain publishes an event only after the transaction that
//!   made the change has committed. A cross-domain change (revocation, account deletion) is one
//!   transaction under the account lock ([ADR 0011] "Transactions and concurrency"), never a
//!   chain of events.
//! - **Losing an event loses no data.** The durable state, including `worker`'s compaction
//!   queue ([ADR 0021] "Where it runs"), lives in the database. A subscriber that misses events
//!   ([`RecvError::Lagged`]) re-reads the durable state it cares about; it never assumes that
//!   the events it did receive are complete.
//! - **The publisher never waits.** Each bus is a bounded ring buffer of [`Capacity`] events.
//!   A slow subscriber falls behind and is told how many events it missed; it never blocks a
//!   request handler, and memory stays bounded.
//!
//! # Which events exist
//!
//! The ADRs name no event list. [`Event`] holds only the kinds that have a consumer an
//! Accepted ADR names for M1. M1 runs the `api`, `web` and `worker` roles ([ADR 0010] §1, §4),
//! and the one in-process reaction the ADRs describe is `worker` picking up the compaction
//! queue that `api` fills ([ADR 0021] "Where it runs"): [`Event::CompactionQueued`].
//!
//! The enum is `#[non_exhaustive]`; a kind is added in the same change as the domain code
//! that consumes it, with the ADR that names that consumer. Kinds considered and left out
//! for want of a named M1 consumer, pending the owner's confirmation:
//!
//! - *Account changed*: ADR 0010 §3's "account X changed" is the M3 inter-process
//!   `LISTEN/NOTIFY` wake-up for the `notify` role, which is M3. Its signals carry no content
//!   (threat model INV-54), so [`Event::account`] already serves it.
//! - *Device enrolled*: clients learn of new enrollments from the signed account state and
//!   device certificates they fetch, not from a server event.
//! - *Device revoked*: ADR 0012 §6 makes the revocation, the new account state and the
//!   rotation one request under the account lock and names no subscriber.
//! - *Ops stored*: no M1 role reacts to it; live push to clients is `notify`, M3.
//! - *Restore completed*: `rizzy-vault restore` runs only while the server is stopped
//!   ([ADR 0010] §2), so no in-process subscriber could receive it.
//!
//! # Not a wire format
//!
//! Events never leave the process in M1, so this crate defines no encoding for them. The
//! payload of M3's `LISTEN/NOTIFY` messages is left to the ADR that introduces that backend.
//!
//! # Contract
//!
//! - No `unsafe` code (workspace lint and `#![forbid(unsafe_code)]` below).
//! - No panics: [`Bus::new`] checks the capacity before tokio's `broadcast::channel` could
//!   reject it, and every other call returns a value or a typed error.
//! - The only external dependency is tokio with its `sync` feature: no runtime and no I/O
//!   driver. `cargo xtask check-deps` checks the crate's boundaries ([ADR 0016] R2–R6): no
//!   internal dependencies, no getrandom, no sqlx.
//! - No fuzz target: the crate parses no input. Events are built from typed ids by trusted
//!   server code.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use core::fmt;

use tokio::sync::broadcast;

/// The length of every object id (CRYPTO.md §2: 16 random bytes, created by the client).
pub const ID_LEN: usize = 16;

/// Defines one opaque 16-byte id type with a redacting `Debug`.
macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Opaque: the bytes are compared, never interpreted. `Debug` prints the type name
        /// only, so an id never reaches a log line through formatting (threat model AST-13).
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// Wraps the 16 id bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// The 16 id bytes.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; ID_LEN] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

id_type!(
    /// An account id (CRYPTO.md §2, §5: the 16-byte `account_id`).
    AccountId
);
id_type!(
    /// A vault id (CRYPTO.md §2).
    VaultId
);
id_type!(
    /// An item id (CRYPTO.md §2).
    ItemId
);

/// One domain event: which thing changed, by id only.
///
/// Every event names its account, so a subscriber that only needs "account X changed" (the
/// M3 `notify` wake-up, ADR 0010 §3; its signals carry no content, threat model INV-54) can
/// use [`Event::account`] and ignore the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A snapshot was stored and its item queued for compaction (`rizzy-domain-vault`, ADR
    /// 0021 "Where it runs"). The queue entry itself is durable in the database; this event
    /// only lets an in-process `worker` look sooner.
    CompactionQueued {
        /// The account that owns the vault.
        account: AccountId,
        /// The vault.
        vault: VaultId,
        /// The item whose snapshot was stored.
        item: ItemId,
    },
}

impl Event {
    /// The account this event is about.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        match *self {
            Self::CompactionQueued { account, .. } => account,
        }
    }
}

/// The number of events a bus buffers for its slowest subscriber.
///
/// A power of two between 1 and [`Capacity::MAX`] inclusive. [`Capacity::new`] rounds the
/// requested size up to the next power of two, because tokio's broadcast channel does the
/// same to its ring buffer; [`Capacity::get`] returns the rounded value, so it is the exact
/// bound. A subscriber that is [`Capacity::get`] events behind still receives all of them;
/// once one more event is published, the oldest is dropped for it and its next receive
/// reports [`RecvError::Lagged`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity(usize);

impl Capacity {
    /// The default: 1,024 events.
    pub const DEFAULT: Self = Self(1024);

    /// The largest capacity accepted: 65,536 events. Each buffered event is a few dozen bytes;
    /// the cap keeps a misconfigured bus from reserving an unbounded ring buffer.
    pub const MAX: Self = Self(65_536);

    /// Checks a capacity and rounds it up to the next power of two (3 becomes 4, 1,000 becomes
    /// 1,024), the size tokio's ring buffer really has.
    ///
    /// # Errors
    ///
    /// [`CapacityError`] if `events` is 0 or above [`Capacity::MAX`].
    pub const fn new(events: usize) -> Result<Self, CapacityError> {
        if events == 0 || events > Self::MAX.0 {
            Err(CapacityError)
        } else {
            // `events` is at most MAX, itself a power of two, so the rounded value is at most
            // MAX and the rounding cannot overflow.
            Ok(Self(events.next_power_of_two()))
        }
    }

    /// The number of events the bus buffers: the rounded, exact bound.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for Capacity {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A bus capacity outside 1 to [`Capacity::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bus capacity must be between 1 and {}", Capacity::MAX.0)
    }
}

impl core::error::Error for CapacityError {}

/// An in-process event bus: every subscriber receives every event published after it
/// subscribed, in publication order.
///
/// Cloning a bus gives another handle to the same bus. The bus closes when its last handle is
/// dropped; subscribers then drain what is buffered and get [`RecvError::Closed`].
#[derive(Clone, Debug)]
pub struct Bus {
    /// The sending side of the ring buffer.
    sender: broadcast::Sender<Event>,
}

impl Bus {
    /// Creates a bus that buffers up to [`Capacity::get`] events for its slowest subscriber.
    #[must_use]
    pub fn new(capacity: Capacity) -> Self {
        // `Capacity` is a power of two in 1..=65,536, inside tokio's accepted range
        // (1..=usize::MAX / 2), so the channel constructor's capacity panic cannot fire, and
        // tokio's own rounding to a power of two leaves the size unchanged.
        let (sender, _) = broadcast::channel(capacity.get());
        Self { sender }
    }

    /// Publishes an event to every current subscriber and returns how many there were.
    ///
    /// Never blocks and never fails. With no subscriber the event is dropped and 0 is returned:
    /// events are hints, so nobody listening is not an error. A subscriber whose buffer is full
    /// loses its oldest event instead of slowing the publisher.
    #[expect(
        clippy::must_use_candidate,
        reason = "the receiver count is informational; publishing is the effect"
    )]
    pub fn publish(&self, event: Event) -> usize {
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribes to every event published from now on.
    #[must_use]
    pub fn subscribe(&self) -> Subscriber {
        Subscriber {
            receiver: self.sender.subscribe(),
        }
    }

    /// The number of live subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new(Capacity::DEFAULT)
    }
}

/// One subscription to a [`Bus`].
#[derive(Debug)]
pub struct Subscriber {
    /// The receiving side of the ring buffer.
    receiver: broadcast::Receiver<Event>,
}

/// Why a subscriber received no event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvError {
    /// The subscriber fell behind and `missed` events were dropped for it. The next receive
    /// returns the oldest event still buffered. The subscriber must re-read the durable state
    /// it cares about, because it no longer knows everything that changed.
    Lagged {
        /// How many events were dropped for this subscriber.
        missed: u64,
    },
    /// Every [`Bus`] handle was dropped and nothing is left to receive.
    Closed,
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lagged { missed } => write!(f, "subscriber lagged; {missed} events missed"),
            Self::Closed => f.write_str("bus closed"),
        }
    }
}

impl core::error::Error for RecvError {}

impl Subscriber {
    /// Waits for the next event.
    ///
    /// Cancel-safe: dropping the future loses no event.
    ///
    /// # Errors
    ///
    /// [`RecvError::Lagged`] once after events were dropped for this subscriber;
    /// [`RecvError::Closed`] when the bus is closed and drained.
    pub async fn recv(&mut self) -> Result<Event, RecvError> {
        self.receiver.recv().await.map_err(|e| match e {
            broadcast::error::RecvError::Lagged(missed) => RecvError::Lagged { missed },
            broadcast::error::RecvError::Closed => RecvError::Closed,
        })
    }

    /// Takes the next event if one is buffered, without waiting. `Ok(None)` means none is.
    ///
    /// # Errors
    ///
    /// As [`Subscriber::recv`].
    pub fn try_recv(&mut self) -> Result<Option<Event>, RecvError> {
        match self.receiver.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(broadcast::error::TryRecvError::Lagged(missed)) => {
                Err(RecvError::Lagged { missed })
            }
            Err(broadcast::error::TryRecvError::Closed) => Err(RecvError::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test account id.
    const A: AccountId = AccountId::from_bytes([1; ID_LEN]);

    /// The `n`th test event.
    fn ops(n: u8) -> Event {
        Event::CompactionQueued {
            account: A,
            vault: VaultId::from_bytes([n; ID_LEN]),
            item: ItemId::from_bytes([n; ID_LEN]),
        }
    }

    #[test]
    fn every_subscriber_gets_every_event_in_order() {
        let bus = Bus::default();
        let mut s1 = bus.subscribe();
        let mut s2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        for n in 0..5 {
            assert_eq!(bus.publish(ops(n)), 2);
        }
        for s in [&mut s1, &mut s2] {
            for n in 0..5 {
                assert_eq!(s.try_recv(), Ok(Some(ops(n))));
            }
            assert_eq!(s.try_recv(), Ok(None));
        }
    }

    #[test]
    fn publishing_with_no_subscriber_is_not_an_error() {
        let bus = Bus::default();
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.publish(ops(0)), 0);
        // A late subscriber sees only what is published after it subscribed.
        let mut s = bus.subscribe();
        assert_eq!(s.try_recv(), Ok(None));
        assert_eq!(bus.publish(ops(1)), 1);
        assert_eq!(s.try_recv(), Ok(Some(ops(1))));
        drop(s);
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.publish(ops(2)), 0);
    }

    #[test]
    fn a_slow_subscriber_lags_and_the_publisher_never_waits() {
        let bus = Bus::new(Capacity::new(2).unwrap());
        let mut slow = bus.subscribe();
        let mut fast = bus.subscribe();
        for n in 0..5 {
            assert_eq!(bus.publish(ops(n)), 2);
            assert_eq!(fast.try_recv(), Ok(Some(ops(n))));
        }
        assert_eq!(slow.try_recv(), Err(RecvError::Lagged { missed: 3 }));
        assert_eq!(slow.try_recv(), Ok(Some(ops(3))));
        assert_eq!(slow.try_recv(), Ok(Some(ops(4))));
        assert_eq!(slow.try_recv(), Ok(None));
    }

    #[test]
    fn closed_after_the_last_handle_is_dropped_and_drained() {
        let bus = Bus::default();
        let other = bus.clone();
        let mut s = bus.subscribe();
        bus.publish(ops(0));
        drop(bus);
        assert_eq!(other.publish(ops(1)), 1);
        drop(other);
        assert_eq!(s.try_recv(), Ok(Some(ops(0))));
        assert_eq!(s.try_recv(), Ok(Some(ops(1))));
        assert_eq!(s.try_recv(), Err(RecvError::Closed));
    }

    #[test]
    fn async_recv_delivers_lags_and_closes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let bus = Bus::new(Capacity::new(1).unwrap());
            let mut s = bus.subscribe();
            bus.publish(ops(0));
            assert_eq!(s.recv().await, Ok(ops(0)));
            bus.publish(ops(1));
            bus.publish(ops(2));
            assert_eq!(s.recv().await, Err(RecvError::Lagged { missed: 1 }));
            assert_eq!(s.recv().await, Ok(ops(2)));
            drop(bus);
            assert_eq!(s.recv().await, Err(RecvError::Closed));
        });
    }

    #[test]
    fn capacity_bounds() {
        assert_eq!(Capacity::new(0), Err(CapacityError));
        assert_eq!(Capacity::new(1).map(Capacity::get), Ok(1));
        assert_eq!(Capacity::new(65_536), Ok(Capacity::MAX));
        assert_eq!(Capacity::new(65_537), Err(CapacityError));
        assert_eq!(Capacity::new(usize::MAX), Err(CapacityError));
        assert_eq!(Capacity::default(), Capacity::DEFAULT);
        // The largest capacity builds a bus without panicking.
        let bus = Bus::new(Capacity::MAX);
        assert_eq!(bus.publish(ops(0)), 0);
    }

    #[test]
    fn capacity_rounds_up_to_the_power_of_two_tokio_uses() {
        assert_eq!(Capacity::new(3).map(Capacity::get), Ok(4));
        assert_eq!(Capacity::new(1000).map(Capacity::get), Ok(1024));
        assert_eq!(Capacity::new(65_535), Ok(Capacity::MAX));
        assert_eq!(Capacity::new(1024), Ok(Capacity::DEFAULT));
    }

    #[test]
    fn a_non_power_of_two_capacity_lags_exactly_at_the_rounded_bound() {
        let cap = Capacity::new(3).unwrap();
        assert_eq!(cap.get(), 4);
        let bus = Bus::new(cap);
        let mut s = bus.subscribe();
        // `get()` events behind: nothing lost.
        for n in 0..4 {
            bus.publish(ops(n));
        }
        for n in 0..4 {
            assert_eq!(s.try_recv(), Ok(Some(ops(n))));
        }
        // One more than `get()`: exactly the oldest is lost.
        for n in 4..9 {
            bus.publish(ops(n));
        }
        assert_eq!(s.try_recv(), Err(RecvError::Lagged { missed: 1 }));
        for n in 5..9 {
            assert_eq!(s.try_recv(), Ok(Some(ops(n))));
        }
        assert_eq!(s.try_recv(), Ok(None));
    }

    #[test]
    fn events_name_their_account_and_debug_redacts_ids() {
        let v = VaultId::from_bytes([0xCD; ID_LEN]);
        let i = ItemId::from_bytes([0xEF; ID_LEN]);
        let e = Event::CompactionQueued {
            account: A,
            vault: v,
            item: i,
        };
        assert_eq!(e.account(), A);
        let shown = format!("{e:?}").to_lowercase();
        for byte in ["01", "cd", "ef", "205", "239"] {
            assert!(!shown.contains(byte), "{shown}");
        }
        assert_eq!(format!("{v:?}"), "VaultId(..)");
        assert_eq!(format!("{i:?}"), "ItemId(..)");
        assert_eq!(A.to_bytes(), [1; ID_LEN]);
    }
}
