//! Conversions between `rizzy-core` values and the bounded `rizzy-proto` wire types.
//!
//! The wire types bound every length; building one from a value this crate made can only fail
//! if an internal invariant broke, which is [`ClientError::Internal`]. Reading a wire value is
//! never trusted by itself: the flows verify what they read through `rizzy-core`.

use rizzy_proto::wire::{Bytes, Id};

use crate::error::ClientError;

/// A wire id from 16 id bytes.
pub(crate) const fn id(bytes: [u8; 16]) -> Id {
    Id::from_bytes(bytes)
}

/// A bounded wire byte string from bytes this client produced.
///
/// # Errors
/// [`ClientError::Internal`] if the bytes exceed the wire bound, which no value this crate
/// produces does.
pub(crate) fn bytes<const N: usize>(v: Vec<u8>) -> Result<Bytes<N>, ClientError> {
    Bytes::new(v).map_err(|_| ClientError::Internal)
}
