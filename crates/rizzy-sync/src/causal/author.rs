//! The author checks of "Verify first" that read only a header and the author's signed
//! statements ([ADR 0012] §4 step 1; CRYPTO.md §10.2 "Web-vault certificates" rule (c), §11.8
//! step 4; [ADR 0021] §9 "Revoked and kind-4 authors").
//!
//! The signature itself, the certificate chain to the identity key, rules (a) and (b) of
//! CRYPTO.md §10.2 and the device set are checked in `rizzy-core`
//! ([`DeviceCertificate::verify`](rizzy_core::sign::DeviceCertificate::verify) and the account
//! state). What is left needs the parsed header, and is pure:
//!
//! - **Ops** ([`check_op_author`]): "The signature must chain to a device certificate that is
//!   not revoked. The exception is a revoked device's op with `device_seq ≤
//!   last_accepted_device_seq`" (ADR 0012 §4 step 1; CRYPTO.md §11.8 step 4: peers "reject that
//!   device's ops with `device_seq > last_accepted_device_seq`"). And rule (c): "the op's HLC,
//!   read as milliseconds (its top 48 bits), is ≤ `expires_at_ms`", for a kind-4 certificate
//!   and for a durable one that carries an expiry (CRYPTO.md §10.2, owner decision of
//!   2026-09-27). The rule reads the HLC the header carries, never a local clock, so every
//!   replica gives the same answer (ADR 0012 §4 step 1). It is the rule of
//!   [`DeviceCertificate::permits_hlc`](rizzy_core::sign::DeviceCertificate::permits_hlc) and
//!   [`DeviceRevocation::permits_device_seq`](rizzy_core::sign::DeviceRevocation::permits_device_seq),
//!   applied to a parsed header; the tests check that they agree.
//! - **Snapshots** ([`check_snapshot_author`]): peers reject a revoked device's "snapshots whose
//!   covered-VV entry for it is above `last_accepted_device_seq`" (CRYPTO.md §11.8 step 4), and
//!   accept a kind-4 device's only if "a snapshot's covered-VV entry for its author is at most
//!   that device's last accepted `device_seq`" (§10.2 rule (c); ADR 0021 §9).
//!
//! # Reading
//!
//! For a revoked author the snapshot bound is its revocation's `last_accepted_device_seq`
//! ([`VaultLog::cutoff`](super::VaultLog::cutoff)). For a kind-4 author that is not revoked, no
//! spec says what "that device's last accepted `device_seq`" is, and the merge spike did not
//! model kind 4 (ADR 0021 owner decision 5). The caller supplies the bound; the reading this
//! layer suggests is the highest `device_seq` of the author's ops the client has verified, the
//! headers of the response being processed included, which is also where the merge's "Snapshots
//! are claims" cut stops the covered VV (ADR 0018 §3).
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

use core::fmt;

use rizzy_core::ids::DeviceId;
use rizzy_core::sign::{DeviceCertificate, DeviceRevocation};

use crate::header::{OpHeader, SnapshotHeader};

/// What an op's verification needs to know about its author, from its verified
/// `device-certificate` and, if it is revoked, its verified `device-revocation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthorStatus {
    /// The device the statements are about.
    pub device: DeviceId,
    /// The revocation's `last_accepted_device_seq`; `None` while the device is not revoked.
    pub last_accepted: Option<u64>,
    /// The certificate's `expires_at_ms`; 0 means none (CRYPTO.md §10.2).
    pub expires_at_ms: u64,
}

impl AuthorStatus {
    /// The status of `certificate`'s device, revoked by `revocation` if one is given.
    ///
    /// # Errors
    /// [`AuthorRefusal::OtherDevice`] if the revocation names another device.
    pub fn from_statements(
        certificate: &DeviceCertificate,
        revocation: Option<&DeviceRevocation>,
    ) -> Result<Self, AuthorRefusal> {
        if revocation.is_some_and(|r| r.device_id != certificate.device_id) {
            return Err(AuthorRefusal::OtherDevice);
        }
        Ok(Self {
            device: certificate.device_id,
            last_accepted: revocation.map(|r| r.last_accepted_device_seq),
            expires_at_ms: certificate.expires_at_ms,
        })
    }
}

/// Why an op or snapshot is rejected for its author. Server-visible metadata only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthorRefusal {
    /// The statements, or the header, are about another device.
    OtherDevice,
    /// The author is revoked and the op's `device_seq` is above `last_accepted_device_seq`.
    PastCutoff {
        /// The revocation's `last_accepted_device_seq`.
        last_accepted: u64,
    },
    /// The op's HLC, read as milliseconds, is after the certificate's `expires_at_ms` (rule
    /// (c)).
    PastExpiry {
        /// The certificate's `expires_at_ms`.
        expires_at_ms: u64,
    },
    /// The snapshot's covered-VV entry for its author is above the author's bound.
    ClaimsPastBound {
        /// The bound: the author's last accepted `device_seq`.
        bound: u64,
    },
}

impl fmt::Display for AuthorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherDevice => f.write_str("the statements name another device"),
            Self::PastCutoff { last_accepted } => {
                write!(f, "op past the revocation cut-off {last_accepted}")
            }
            Self::PastExpiry { expires_at_ms } => {
                write!(f, "op after the certificate expiry {expires_at_ms}")
            }
            Self::ClaimsPastBound { bound } => {
                write!(f, "snapshot claims its author's ops past {bound}")
            }
        }
    }
}

impl core::error::Error for AuthorRefusal {}

/// Whether an op passes the author checks of ADR 0012 §4 step 1 that read its header: the
/// revocation cut-off and rule (c) (see the module docs).
///
/// # Errors
/// [`AuthorRefusal::OtherDevice`] if `author` is about another device than the header's;
/// [`AuthorRefusal::PastCutoff`] if the author is revoked and `device_seq` is above
/// `last_accepted_device_seq`; [`AuthorRefusal::PastExpiry`] if the certificate expires and
/// `hlc >> 16` is above `expires_at_ms`.
pub fn check_op_author(header: &OpHeader, author: AuthorStatus) -> Result<(), AuthorRefusal> {
    if header.dot.device_id() != author.device {
        return Err(AuthorRefusal::OtherDevice);
    }
    if let Some(last_accepted) = author.last_accepted
        && header.dot.seq() > last_accepted
    {
        return Err(AuthorRefusal::PastCutoff { last_accepted });
    }
    if author.expires_at_ms != 0 && header.hlc.millis() > author.expires_at_ms {
        return Err(AuthorRefusal::PastExpiry {
            expires_at_ms: author.expires_at_ms,
        });
    }
    Ok(())
}

/// Whether a snapshot passes the author bound of CRYPTO.md §10.2 rule (c) and §11.8 step 4:
/// its covered-VV entry for its own author is at most `bound`. `bound` is `None` for an author
/// that is neither revoked nor kind 4, which has no such bound; for a revoked author it is the
/// revocation's `last_accepted_device_seq`; for a kind-4 author, see the module docs.
///
/// # Errors
/// [`AuthorRefusal::ClaimsPastBound`] if the entry is above `bound`.
pub fn check_snapshot_author(
    header: &SnapshotHeader,
    bound: Option<u64>,
) -> Result<(), AuthorRefusal> {
    match bound {
        Some(bound) if header.covered.get(header.author) > bound => {
            Err(AuthorRefusal::ClaimsPastBound { bound })
        }
        _ => Ok(()),
    }
}
