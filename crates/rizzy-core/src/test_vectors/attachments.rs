// SPDX-License-Identifier: AGPL-3.0-only

//! `attachments.json`: the attachment vectors of [ADR 0054] §8 (CRYPTO.md §15 item 1, tier A).
//!
//! [ADR 0054]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0054-attachments-envelope-and-api.md
//!
//! - `ATTACHMENT_KEY_WRAP`: an attachment key wrapped under an item key.
//! - `single-chunk`: a 1000-byte attachment, one chunk, every envelope in full.
//! - `three-chunk`: a `2 × 512 KiB + 1000`-byte attachment, two full chunks and a short final
//!   one. Its plaintext is not stored: byte `i` is `i mod 251` (the input `plaintext_rule`). The
//!   full chunks' envelopes are given by their SHA-256; the short final one in full.
//! - `reject`: a chunk opened at another `chunk_index`, for another `attachment_id`, and against
//!   a `chunk_count` derived from another `size`. Each keeps the envelope length the reader
//!   expects, so the failure is the commitment (the output `reader_commitment` differs from the
//!   envelope's), before the AEAD runs (§8.3, §15 item 4).
//!
//! Every nonce is drawn by the generator, stored as an input and fed back through
//! [`ExactRng`]: no seal function takes a nonce (INV-12). Every computed envelope is also
//! checked against the §8.3 formula with the raw AEAD, and opened again through the API.

use chacha20::ChaCha20Rng;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use super::{
    ExactRng, Obj, Vector, arr, bytes, bytes_list, field, object, random, random_vec, text, u64_of,
};
use crate::attachment::{AttachmentKey, AttachmentLayout, AttachmentRef, CHUNK_SIZE};
use crate::envelope::purpose::AttachmentKeyWrapCtx;
use crate::envelope::{Context, Purpose};
use crate::ids::{AttachmentId, ItemId, VaultId};
use crate::keys::ItemKey;
use crate::{kdf, labels};

/// The `kind` of every vector in this file.
const KIND: &str = "attachment";

/// The `plaintext_rule` input of vectors whose plaintext is too large to store.
const PLAINTEXT_RULE: &str = "byte at offset i is i mod 251";

/// One full chunk, as a `u64`.
const CHUNK: u64 = CHUNK_SIZE as u64;

fn vector(name: &str, index: usize, inputs: Obj) -> Vector {
    Vector::build(compute, KIND, name, index, inputs)
}

/// The three ids of an attachment context, drawn from `rng`.
fn ids(rng: &mut ChaCha20Rng) -> Obj {
    Obj::new()
        .bytes("vault_id", &random::<16>(rng))
        .bytes("item_id", &random::<16>(rng))
        .bytes("attachment_id", &random::<16>(rng))
}

fn nonces(rng: &mut ChaCha20Rng, n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|_| random::<24>(rng).to_vec()).collect()
}

pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    let mut out = Vec::new();

    let inputs = Obj::new()
        .bytes("key", &random::<32>(rng))
        .obj("ctx", ids(rng))
        .bytes("plaintext", &random::<32>(rng))
        .bytes("nonce", &random::<24>(rng));
    out.push(vector("ATTACHMENT_KEY_WRAP", 0, inputs));

    let inputs = Obj::new()
        .bytes("key", &random::<32>(rng))
        .obj("ctx", ids(rng))
        .u64("size", 1000)
        .bytes("plaintext", &random_vec(rng, 1000))
        .bytes_list("nonces", &nonces(rng, 1));
    out.push(vector("single-chunk", 0, inputs));

    let inputs = Obj::new()
        .bytes("key", &random::<32>(rng))
        .obj("ctx", ids(rng))
        .u64("size", 2 * CHUNK + 1000)
        .text("plaintext_rule", PLAINTEXT_RULE)
        .bytes_list("nonces", &nonces(rng, 3));
    out.push(vector("three-chunk", 0, inputs));

    // reject/0: chunk 0 (full) opened at index 1 (also full) of the same three-chunk layout.
    // reject/1: the only chunk of a 1000-byte attachment opened for another attachment id.
    // reject/2: chunk 0 of a three-chunk attachment opened against the four-chunk layout of
    // another size, whose chunk 0 has the same length.
    let cases: [(&str, u64, u32, u64, u32); 3] = [
        ("chunk_index", 2 * CHUNK + 1000, 0, 2 * CHUNK + 1000, 1),
        ("attachment_id", 1000, 0, 1000, 0),
        ("chunk_count", 2 * CHUNK + 1000, 0, 3 * CHUNK + 1, 0),
    ];
    for (index, (case, size, chunk_index, open_size, open_index)) in cases.into_iter().enumerate() {
        let ctx = ids(rng);
        let key = random::<32>(rng);
        let nonce = random::<24>(rng);
        let open_attachment = random::<16>(rng);
        let mut open = Obj::new()
            .u64("size", open_size)
            .num("chunk_index", open_index);
        open = if case == "attachment_id" {
            open.bytes("attachment_id", &open_attachment)
        } else {
            open.null("attachment_id")
        };
        let inputs = Obj::new()
            .text("case", case)
            .bytes("key", &key)
            .obj("ctx", ctx)
            .u64("size", size)
            .num("chunk_index", chunk_index)
            .text("plaintext_rule", PLAINTEXT_RULE)
            .bytes("nonce", &nonce)
            .obj("open", open);
        out.push(vector("reject", index, inputs));
    }
    out
}

/// The attachment of a vector's `ctx` object.
fn attachment_ref(c: &Map<String, Value>) -> AttachmentRef {
    AttachmentRef {
        vault_id: VaultId::from_bytes(arr(c, "vault_id")),
        item_id: ItemId::from_bytes(arr(c, "item_id")),
        attachment_id: AttachmentId::from_bytes(arr(c, "attachment_id")),
    }
}

/// The plaintext the rule describes: byte `i` is `i mod 251`.
fn pattern(len: u64) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("below 251"))
        .collect()
}

/// An attachment key from raw bytes: `generate` draws exactly 32 of them.
fn attachment_key(raw: &[u8]) -> AttachmentKey {
    let mut rng = ExactRng::new(raw);
    let key = AttachmentKey::generate(&mut rng);
    rng.finish();
    key
}

/// `okm = HKDF(K, salt = nonce, LABEL("envelope/xchacha20poly1305") ‖ 0x00 ‖ aad, 64)` (§8.3).
fn okm(key: &[u8], nonce: &[u8; 24], aad: &[u8]) -> [u8; 64] {
    let mut okm = [0u8; 64];
    kdf::hkdf_sha256(
        key,
        Some(nonce),
        labels::ENVELOPE_XCHACHA20POLY1305,
        aad,
        &mut okm,
    )
    .expect("HKDF");
    okm
}

/// `aad = header ‖ u16(purpose) ‖ ctx` (§8.4).
fn aad<C: Context>(header: &[u8], ctx: &C) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(&C::PURPOSE.id().to_be_bytes());
    aad.extend_from_slice(&ctx.ctx_bytes());
    aad
}

/// Checks `envelope` against the §8.3 formula under `key` and `ctx`: the header names a
/// `0x01` envelope under `key`, the nonce and commitment sit where §9.1 puts them, and the raw
/// AEAD opens the body to `plaintext` under `k_enc`. Returns `(ctx, aad, k_enc, commitment)`.
fn formula<C: Context>(
    key: &[u8],
    ctx: &C,
    nonce: &[u8; 24],
    envelope: &[u8],
    plaintext: &[u8],
) -> [Vec<u8>; 4] {
    let header = envelope.get(..18).expect("a header");
    assert_eq!(
        header.get(..2),
        Some(&[0x01, 0x01][..]),
        "version, alg 0x01"
    );
    let aad = aad(header, ctx);
    let okm = okm(key, nonce, &aad);
    let (k_enc, commitment) = okm.split_at(32);
    assert_eq!(envelope.get(18..42), Some(&nonce[..]), "nonce");
    assert_eq!(envelope.get(42..74), Some(commitment), "commitment");
    let body = XChaCha20Poly1305::new_from_slice(k_enc)
        .expect("a key")
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: envelope.get(74..).expect("a body"),
                aad: &aad,
            },
        )
        .expect("the raw AEAD opens the body under k_enc");
    assert_eq!(body, plaintext, "chunks are unpadded");
    [ctx.ctx_bytes(), aad, k_enc.to_vec(), commitment.to_vec()]
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

pub(super) fn compute(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    match name {
        "ATTACHMENT_KEY_WRAP" => key_wrap(m),
        "single-chunk" | "three-chunk" => chunks(name, m),
        "reject" => reject(m),
        other => panic!("unknown attachment vector {other}"),
    }
}

fn key_wrap(m: &Map<String, Value>) -> Map<String, Value> {
    let at = attachment_ref(object(m, "ctx"));
    let ctx: AttachmentKeyWrapCtx = at.key_wrap_ctx();
    let raw = bytes(m, "key");
    let mut rng = ExactRng::new(&raw);
    let item_key = ItemKey::generate(&mut rng, 0);
    rng.finish();
    let plaintext = bytes(m, "plaintext");
    let attachment = attachment_key(&plaintext);
    let nonce = arr::<24>(m, "nonce");
    let mut rng = ExactRng::new(&nonce);
    let envelope = item_key
        .wrap_attachment_key(&mut rng, &ctx, &attachment)
        .expect("wrap");
    rng.finish();
    assert_eq!(
        envelope.get(2..18),
        Some(&item_key.key_id().expect("key id").as_bytes()[..])
    );
    let opened = item_key
        .unwrap_attachment_key(&ctx, &envelope)
        .expect("the wrap opens");
    assert_eq!(opened.expose_for_tests().as_slice(), plaintext.as_slice());
    let [ctx_bytes, aad, k_enc, commitment] = formula(&raw, &ctx, &nonce, &envelope, &plaintext);
    Obj::new()
        .bytes("ctx", &ctx_bytes)
        .bytes("aad", &aad)
        .bytes("k_enc", &k_enc)
        .bytes("commitment", &commitment)
        .bytes("envelope", &envelope)
        .done()
}

fn chunks(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    let at = attachment_ref(object(m, "ctx"));
    let size = u64_of(m, "size");
    let layout = AttachmentLayout::new(size).expect("within the cap");
    let plaintext = if name == "single-chunk" {
        bytes(m, "plaintext")
    } else {
        assert_eq!(text(m, "plaintext_rule"), PLAINTEXT_RULE);
        pattern(size)
    };
    assert_eq!(plaintext.len() as u64, size);
    let raw = bytes(m, "key");
    let key = attachment_key(&raw);
    let nonce_list = bytes_list(m, "nonces");
    assert_eq!(nonce_list.len(), layout.chunk_count() as usize);
    let mut rng = ExactRng::new(&nonce_list.concat());
    let mut columns: [Vec<Vec<u8>>; 4] = Default::default();
    let mut envelopes = Vec::new();
    for (index, nonce) in (0u32..).zip(&nonce_list) {
        let off = usize::try_from(layout.chunk_offset(index).expect("in range")).expect("usize");
        let len = layout.chunk_len(index).expect("in range");
        let chunk = &plaintext[off..off + len];
        let envelope = key
            .seal_chunk(&mut rng, &at, layout, index, chunk)
            .expect("seal");
        assert_eq!(Some(envelope.len()), layout.chunk_envelope_len(index));
        let opened = key
            .open_chunk(&at, layout, index, &envelope)
            .expect("the chunk opens in place");
        assert_eq!(opened.expose_secret(), chunk);
        let ctx = at.chunk_ctx(layout, index).expect("in range");
        let nonce: [u8; 24] = nonce.as_slice().try_into().expect("24 bytes");
        for (column, value) in columns
            .iter_mut()
            .zip(formula(&raw, &ctx, &nonce, &envelope, chunk))
        {
            column.push(value);
        }
        envelopes.push(envelope);
    }
    rng.finish();
    let [ctx, aad, k_enc, commitment] = columns;
    let out = Obj::new()
        .num("chunk_count", layout.chunk_count())
        .bytes_list("ctx", &ctx)
        .bytes_list("aad", &aad)
        .bytes_list("k_enc", &k_enc)
        .bytes_list("commitment", &commitment);
    let out = if name == "single-chunk" {
        out.bytes_list("envelopes", &envelopes)
    } else {
        let hashes: Vec<Vec<u8>> = envelopes.iter().map(|e| sha256(e)).collect();
        out.bytes("plaintext_sha256", &sha256(&plaintext))
            .bytes_list("envelope_sha256", &hashes)
            .bytes("final_envelope", envelopes.last().expect("three chunks"))
    };
    out.done()
}

fn reject(m: &Map<String, Value>) -> Map<String, Value> {
    let at = attachment_ref(object(m, "ctx"));
    let size = u64_of(m, "size");
    let index: u32 = super::num(m, "chunk_index");
    let layout = AttachmentLayout::new(size).expect("within the cap");
    assert_eq!(text(m, "plaintext_rule"), PLAINTEXT_RULE);
    let plaintext = pattern(size);
    let off = usize::try_from(layout.chunk_offset(index).expect("in range")).expect("usize");
    let chunk = &plaintext[off..off + layout.chunk_len(index).expect("in range")];
    let raw = bytes(m, "key");
    let key = attachment_key(&raw);
    let nonce = arr::<24>(m, "nonce");
    let mut rng = ExactRng::new(&nonce);
    let envelope = key
        .seal_chunk(&mut rng, &at, layout, index, chunk)
        .expect("seal");
    rng.finish();
    let sealed_ctx = at.chunk_ctx(layout, index).expect("in range");
    let [ctx_bytes, ..] = formula(&raw, &sealed_ctx, &nonce, &envelope, chunk);

    // What the reader expects: another index, attachment or size.
    let open = object(m, "open");
    let mut reader = at;
    if !field(open, "attachment_id").is_null() {
        reader.attachment_id = AttachmentId::from_bytes(arr(open, "attachment_id"));
    }
    let reader_layout = AttachmentLayout::new(u64_of(open, "size")).expect("within the cap");
    let reader_index: u32 = super::num(open, "chunk_index");
    let reader_ctx = reader
        .chunk_ctx(reader_layout, reader_index)
        .expect("in range");
    assert_ne!(
        reader_ctx.ctx_bytes(),
        ctx_bytes,
        "the case changes the context"
    );
    // The reader's length check passes, so the commitment is what refuses it.
    assert_eq!(
        reader_layout.chunk_envelope_len(reader_index),
        Some(envelope.len())
    );
    assert!(
        key.open_chunk(&reader, reader_layout, reader_index, &envelope)
            .is_err()
    );
    let reader_aad = aad(envelope.get(..18).expect("a header"), &reader_ctx);
    let reader_okm = okm(&raw, &nonce, &reader_aad);
    let reader_commitment = reader_okm.get(32..).expect("64 bytes");
    let envelope_commitment = envelope.get(42..74).expect("a commitment");
    assert_ne!(reader_commitment, envelope_commitment);
    assert_eq!(Purpose::AttachmentChunk.id(), 0x0033);
    Obj::new()
        .bytes("ctx", &ctx_bytes)
        .bytes("envelope_sha256", &sha256(&envelope))
        .bytes("envelope_commitment", envelope_commitment)
        .bytes("reader_ctx", &reader_ctx.ctx_bytes())
        .bytes("reader_aad", &reader_aad)
        .bytes("reader_commitment", reader_commitment)
        .bool("opens", false)
        .done()
}
