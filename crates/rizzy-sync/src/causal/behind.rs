//! Whether the server is behind this device: a restore from an old backup, or a rollback
//! ([ADR 0021] §9 "Server behind", which replaces [ADR 0012] §7 "Healing a server rollback"'s
//! read-only condition and "Leaving read-only"; threat model §5.8, INV-59).
//!
//! The rule, in full: "A device finds the server behind when the server's `state_seq` is lower;
//! or a head h(V, d) is below the device's cursor or item-VV entry for d, or, for the device
//! itself, below its highest acknowledged `device_seq`; or the server lacks an item-key wrap the
//! device got from it or had acknowledged. Each entry is capped at d's known revocation
//! cut-off. The device leaves read-only once none holds."
//!
//! [`VaultLog::server_behind`] evaluates it for one vault and returns every condition that
//! holds, so the client goes read-only while the list is non-empty and leaves read-only once it
//! is empty. While read-only it re-publishes as ADR 0012 §7 and ADR 0021 §9 "Healing request"
//! say; that is the client's.
//!
//! # Inputs
//!
//! - The server's `state_seq` and the `state_seq` of the last `account-state` this device
//!   accepted (INV-25).
//! - The server's heads h(V, d) for the vault, as one [`VersionVector`] (a missing entry is 0,
//!   ADR 0021 §2).
//! - Whether the server lacks an item-key wrap the device got from it or had acknowledged: wraps
//!   are key objects outside this layer, so the client compares its wrap sets and passes the
//!   answer.
//! - From the log: the cursor (every chain head), the settled VVs of every item, the own chain's
//!   highest acknowledged `device_seq`, and the known revocation cut-offs.
//!
//! # Readings
//!
//! - **The own device** is compared only by its highest acknowledged `device_seq`. Its cursor
//!   entry and its item-VV entries include own ops not yet uploaded, which no honest server
//!   holds; the merge spike excludes them the same way (`world.rs` `server_behind`,
//!   `x != dev.id`).
//! - **"Item-VV entry for d"** is read as the highest entry for d among the vault's items'
//!   settled VVs: a head below any of them is below "the device's item-VV entry for d".
//!
//! Other read-only triggers (a fork or a lower `settings_seq` of the signed state, CRYPTO.md
//! §11.3 step 2.5) live with the account state, not here.
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

use std::collections::BTreeSet;

use rizzy_core::ids::DeviceId;

use crate::dot::Dot;
use crate::vv::VersionVector;

use super::VaultLog;

/// What the server serves, for [`VaultLog::server_behind`].
#[derive(Clone, Copy, Debug)]
pub struct ServerView<'a> {
    /// The `state_seq` of the `account-state` the server serves.
    pub state_seq: u64,
    /// The server's heads h(V, d) for this vault: entry d is the `device_seq` of the last op
    /// of d it holds in the vault, 0 if none.
    pub heads: &'a VersionVector,
    /// The server lacks an item-key wrap of this vault that the device got from it or had
    /// acknowledged (the client compares its wrap sets).
    pub lacks_wrap: bool,
}

/// One condition under which the server is behind this device (ADR 0021 §9 "Server behind").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Behind {
    /// The server's `state_seq` is below the one this device accepted.
    StateSeq {
        /// The server's.
        server: u64,
        /// This device's.
        accepted: u64,
    },
    /// The server's head for another device is below this device's cursor or settled item-VV
    /// entry for it, capped at its cut-off.
    Head {
        /// The device whose chain the server lacks.
        device: DeviceId,
        /// The server's head for it.
        server: u64,
        /// The higher of this device's cursor and item-VV entries for it, capped at its
        /// cut-off.
        local: u64,
    },
    /// The server's head for this device is below its highest acknowledged `device_seq`,
    /// capped at its own cut-off if it has one.
    OwnHead {
        /// The server's head for this device.
        server: u64,
        /// The highest acknowledged `device_seq`, capped.
        acknowledged: u64,
    },
    /// The server lacks an item-key wrap this device got from it or had acknowledged.
    Wrap,
}

impl VaultLog {
    /// Every condition under which the server is behind this device in this vault
    /// (ADR 0021 §9 "Server behind"), given the `state_seq` of the last `account-state` this
    /// device accepted and what the server serves. Empty when none holds: the device is not,
    /// or no longer, read-only on this vault's account.
    #[must_use]
    pub fn server_behind(&self, accepted_state_seq: u64, view: ServerView<'_>) -> Vec<Behind> {
        let mut out = Vec::new();
        if view.state_seq < accepted_state_seq {
            out.push(Behind::StateSeq {
                server: view.state_seq,
                accepted: accepted_state_seq,
            });
        }
        let cap = |device: DeviceId, seq: u64| self.cutoff(device).map_or(seq, |c| seq.min(c));
        let devices: BTreeSet<DeviceId> = self
            .chains
            .keys()
            .copied()
            .chain(
                self.items
                    .values()
                    .flat_map(|vv| vv.entries().map(Dot::device_id)),
            )
            .filter(|&d| d != self.own)
            .collect();
        for device in devices {
            let item_max = self
                .items
                .values()
                .map(|vv| vv.get(device))
                .max()
                .unwrap_or(0);
            let local = cap(device, self.head(device).max(item_max));
            let server = view.heads.get(device);
            if server < local {
                out.push(Behind::Head {
                    device,
                    server,
                    local,
                });
            }
        }
        let acknowledged = cap(self.own, self.acknowledged());
        let server = view.heads.get(self.own);
        if server < acknowledged {
            out.push(Behind::OwnHead {
                server,
                acknowledged,
            });
        }
        if view.lacks_wrap {
            out.push(Behind::Wrap);
        }
        out
    }
}
