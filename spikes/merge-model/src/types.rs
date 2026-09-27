//! Dots, version vectors, HLC values, key ids, register entries and the op record.
//!
//! Model simplifications (each keeps the ordering the ADRs specify):
//! - `device_id` is a `u8`; bytewise order of a 16-byte id is modelled by numeric order.
//! - Field keys are short ASCII `&'static str`; `str` ordering is bytewise (ADR 0018 §4 "Order").
//! - Values are small integers. `@lifecycle` values are 1 = Active, 2 = Trashed (ADR 0018 §3
//!   "Lifecycle": one byte, 0x01 Active or 0x02 Trashed).
//! - A key id encodes the item key's `created_vault_key_epoch` (CRYPTO.md §11.6).

use std::collections::BTreeMap;
use std::fmt;

pub type Dev = u8;
pub type Seq = u64;
pub type Hlc = u64;
pub type Key = &'static str;
pub type Val = u32;

/// ADR 0018 §3 "Lifecycle": the reserved register key. `@` (0x40) sorts before every grammar key,
/// so it is the first register, as §3 requires.
pub const LIFECYCLE: Key = "@lifecycle";
pub const ACTIVE: Val = 1;
pub const TRASHED: Val = 2;

/// ADR 0012 §2 "Dot": `(device_id, device_seq)`. Derived `Ord` is `device_id` then `seq`, the
/// canonical dot order of ADR 0018 §4.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Dot {
    pub dev: Dev,
    pub seq: Seq,
}

impl Dot {
    pub fn new(dev: Dev, seq: Seq) -> Self {
        Dot { dev, seq }
    }
}

impl fmt::Display for Dot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.dev, self.seq)
    }
}

/// ADR 0012 §2 "Per-item version vector". A missing entry counts as 0 (ADR 0021 §2).
/// `BTreeMap` iteration gives the canonical VV encoding order of ADR 0012 §3.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VV(pub BTreeMap<Dev, Seq>);

impl VV {
    pub fn get(&self, d: Dev) -> Seq {
        self.0.get(&d).copied().unwrap_or(0)
    }

    /// ADR 0012 §2: a dot `(d, s)` is covered by `V` when `V[d] >= s`.
    pub fn covers(&self, dot: Dot) -> bool {
        self.get(dot.dev) >= dot.seq
    }

    pub fn add(&mut self, dot: Dot) {
        if dot.seq == 0 {
            return;
        }
        let e = self.0.entry(dot.dev).or_insert(0);
        if *e < dot.seq {
            *e = dot.seq;
        }
    }

    /// Canonical join: per device, the highest seq (ADR 0018 §3 "Context").
    pub fn join(&mut self, o: &VV) {
        for (&d, &s) in &o.0 {
            self.add(Dot::new(d, s));
        }
    }

    pub fn joined(&self, o: &VV) -> VV {
        let mut v = self.clone();
        v.join(o);
        v
    }

    /// `self <= o` entry-wise.
    pub fn leq(&self, o: &VV) -> bool {
        self.0.iter().all(|(&d, &s)| o.get(d) >= s)
    }

    pub fn is_empty(&self) -> bool {
        self.0.values().all(|&s| s == 0)
    }

    /// Entry-wise minimum (the ADR 0021 §2 clamp), zero entries left out.
    pub fn meet(&self, o: &VV) -> VV {
        let mut v = VV::default();
        for (&d, &s) in &self.0 {
            let m = s.min(o.get(d));
            if m > 0 {
                v.0.insert(d, m);
            }
        }
        v
    }
}

impl fmt::Display for VV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        let mut first = true;
        for (d, s) in &self.0 {
            if *s == 0 {
                continue;
            }
            if !first {
                write!(f, ",")?;
            }
            first = false;
            write!(f, "{d}:{s}")?;
        }
        write!(f, "}}")
    }
}

/// The signed op headers a replica holds, by dot (ADR 0012 §3 op header). The chain check
/// (ADR 0012 §7) verifies every header a replica receives, bodied or bodiless, so a replica knows
/// the header of every dot below its cursor, and of every op it wrote.
pub type Headers = BTreeMap<Dot, Header>;

/// Per device, the highest seq whose header is in `h` (the verified chain heads).
pub fn header_heads(h: &Headers) -> VV {
    let mut v = VV::default();
    for d in h.keys() {
        v.add(*d);
    }
    v
}

/// ADR 0012 §2 "HLC": top 48 bits Unix ms, low 16 bits a logical counter.
pub fn fmt_hlc(h: Hlc) -> String {
    format!("{}.{}", h >> 16, h & 0xffff)
}

/// An item key id (CRYPTO.md §4.4 key id, §9.1 envelope `key_id`). The model packs the item
/// key's `created_vault_key_epoch`, its generating device and a per-device counter, so that key
/// ids are deterministic per schedule and `Ord` follows `(created_epoch, dev, n)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyId(pub u32);

impl KeyId {
    pub fn new(epoch: u32, dev: Dev, n: u32) -> Self {
        KeyId((epoch << 16) | ((dev as u32) << 8) | (n & 0xff))
    }

    /// CRYPTO.md §11.6: `created_vault_key_epoch` of the item key.
    pub fn created_epoch(self) -> u32 {
        self.0 >> 16
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "K{}.{}.{}",
            self.0 >> 16,
            (self.0 >> 8) & 0xff,
            self.0 & 0xff
        )
    }
}

/// One register or history value: ADR 0018 §3 `register` production `dot ‖ u64 hlc ‖ bytes(value)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Entry {
    pub dot: Dot,
    pub hlc: Hlc,
    pub val: Val,
}

impl Entry {
    /// ADR 0012 §5 "Pruning is deterministic": ordered by `(hlc, device_id, device_seq)`; also
    /// ADR 0018 §6 display order and §3 recorded-purge order.
    pub fn rank(&self) -> (Hlc, Dev, Seq) {
        (self.hlc, self.dot.dev, self.dot.seq)
    }

    pub fn fmt_with(&self, key: Key) -> String {
        let v = if key == LIFECYCLE {
            match self.val {
                ACTIVE => "A".to_string(),
                TRASHED => "T".to_string(),
                x => format!("?{x}"),
            }
        } else {
            self.val.to_string()
        };
        format!("{}@{}={}", self.dot, fmt_hlc(self.hlc), v)
    }
}

/// ADR 0018 §3 op data `lifecycle` byte: 0x01 Active | 0x02 Trashed | 0x03 Purge.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Marker {
    Active,
    Trashed,
    Purge,
}

/// ADR 0012 §3 op header fields the model needs (vault, item and op ids are constant: one item).
/// The server sees and keeps this for the life of the vault (ADR 0012 §7).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Header {
    pub dot: Dot,
    /// ADR 0012 §2 `vault_prev_seq`. One vault, so it is the device's previous `device_seq`.
    pub prev: Seq,
    pub hlc: Hlc,
    /// ADR 0012 §2 "Causal context": the item VV the author had at write time.
    pub ctx: VV,
    /// ADR 0012 §3 `vault_key_epoch`, the epoch the author believed current.
    pub epoch: u32,
}

/// The `ITEM_OP` body (ADR 0018 §3 op data) plus the envelope header's `key_id` and the optional
/// `ITEM_KEY_WRAP` (ADR 0012 §3 "Key wrap"). The server can delete it (ADR 0012 §7, ADR 0021 R1).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Body {
    pub key_id: KeyId,
    pub wrap: Option<KeyId>,
    pub marker: Marker,
    /// ADR 0018 §3: sorted by key, no duplicates, never `@lifecycle`; empty unless Active.
    pub writes: Vec<(Key, Val)>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Op {
    pub h: Header,
    pub b: Body,
}

impl Op {
    pub fn dot(&self) -> Dot {
        self.h.dot
    }

    /// ADR 0018 §3 "Lifecycle": "An op's marker is applied as a write to it." Every field edit also
    /// writes Active (ADR 0012 §5 "Trash").
    pub fn writes_with_lifecycle(&self) -> Vec<(Key, Val)> {
        let mut w = self.b.writes.clone();
        match self.b.marker {
            Marker::Active => w.push((LIFECYCLE, ACTIVE)),
            Marker::Trashed => w.push((LIFECYCLE, TRASHED)),
            Marker::Purge => {}
        }
        w.sort_by(|a, b| a.0.cmp(b.0));
        w
    }

    pub fn describe(&self) -> String {
        let what = match self.b.marker {
            Marker::Purge => "Purge".to_string(),
            Marker::Trashed => "Trash".to_string(),
            Marker::Active if self.b.writes.is_empty() => "Restore".to_string(),
            Marker::Active => {
                let ws: Vec<String> = self
                    .b
                    .writes
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                format!("Write{{{}}}", ws.join(","))
            }
        };
        let wrap = match self.b.wrap {
            Some(w) => format!(" +wrap {w}"),
            None => String::new(),
        };
        format!(
            "op {} {} hlc={} ctx={} epoch={} key={}{}",
            self.h.dot,
            what,
            fmt_hlc(self.h.hlc),
            self.h.ctx,
            self.h.epoch,
            self.b.key_id,
            wrap
        )
    }
}
