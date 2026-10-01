//! Device authentication and request signing (CRYPTO.md §5.10; ROADMAP §4.3 "Request
//! signing"; threat model Q-7).
//!
//! After an unlock, an enrolled device authenticates with its device key: the server sends a
//! 32-byte challenge, the client answers with one `device-auth` signature container over the
//! canonical origin, the account and device ids and the challenge. Every later request over
//! that session is signed with the `device-request` statement: origin, account, device, the
//! session id, a per-session counter, the method, the path and query, and `SHA-256(body)`.
//!
//! # Sans-I/O
//!
//! The host sends the request values this module builds and passes back the server's answers.
//! How the bearer token and the signature travel in HTTP headers is not fixed by any Accepted
//! ADR (`rizzy-proto` "Left open"), so this module hands the host the values only
//! ([`DeviceSession::bearer_token`], [`rizzy_proto::auth::RequestSignature`]), never a header
//! string.
//!
//! # Counter
//!
//! The server accepts each counter at most once per session within a sliding window of 64
//! (§5.10). This client never reuses one: counters start at 1 and only increase, and
//! [`DeviceSession::sign_request`] refuses to wrap.

use core::fmt;

use rizzy_core::ids::{AccountId, DeviceId, SessionId};
use rizzy_core::normalize::ServerOrigin;
use rizzy_core::sign::{DeviceAuth, DeviceRequest};
use rizzy_proto::auth::{
    DeviceAuthFinishRequest, DeviceAuthFinishResponse, DeviceAuthStartRequest,
    DeviceAuthStartResponse, Reconciliation, RequestSignature,
};
use rizzy_proto::wire::{Fixed, SessionToken};

use crate::device::{DeviceState, UnlockedDevice};
use crate::error::ClientError;
use crate::wire::id;

/// Step 1 of device authentication: the request for a challenge.
#[must_use]
pub fn device_auth_start(state: &DeviceState) -> DeviceAuthStartRequest {
    DeviceAuthStartRequest {
        account_id: id(state.account_id.to_bytes()),
        device_id: id(state.device_id.to_bytes()),
        reconciliation: None,
    }
}

/// Step 1 for a device the server's database does not know after a restore (ADR 0012 §7 "A
/// device enrolled after the backup"): the request carries `reconciliation`, built by
/// [`crate::healing::reconciliation`]. The host sends it only after the plain
/// [`device_auth_start`] was refused; the server accepts it only during the account's
/// reconciliation epoch. The same objects go with step 2
/// ([`device_auth_finish_reconciling`]).
#[must_use]
pub fn device_auth_start_reconciling(
    state: &DeviceState,
    reconciliation: Reconciliation,
) -> DeviceAuthStartRequest {
    DeviceAuthStartRequest {
        reconciliation: Some(reconciliation),
        ..device_auth_start(state)
    }
}

/// Step 2 of a certificate-carrying device authentication: [`device_auth_finish`] with the
/// objects of [`device_auth_start_reconciling`] sent again, which the server verifies again
/// before it stores anything.
///
/// # Errors
/// As [`device_auth_finish`].
pub fn device_auth_finish_reconciling(
    state: &DeviceState,
    unlocked: &UnlockedDevice,
    challenge: &DeviceAuthStartResponse,
    reconciliation: Reconciliation,
) -> Result<DeviceAuthFinishRequest, ClientError> {
    let mut request = device_auth_finish(state, unlocked, challenge)?;
    request.reconciliation = Some(reconciliation);
    Ok(request)
}

/// Step 2: signs the served challenge with the device key (CRYPTO.md §5.10 step 2). The
/// origin is the one the device is enrolled with, never one from the answer.
///
/// # Errors
/// [`ClientError::InvalidInput`] if `unlocked` is another device's; [`ClientError::Internal`]
/// if signing fails.
pub fn device_auth_finish(
    state: &DeviceState,
    unlocked: &UnlockedDevice,
    challenge: &DeviceAuthStartResponse,
) -> Result<DeviceAuthFinishRequest, ClientError> {
    if unlocked.account_id != state.account_id || unlocked.device_id != state.device_id {
        return Err(ClientError::InvalidInput);
    }
    let container = DeviceAuth {
        server_origin: &state.server_origin,
        account_id: state.account_id,
        device_id: state.device_id,
        challenge: challenge.challenge.to_bytes(),
    }
    .sign(unlocked.device_keys.signing_key())
    .map_err(|_| ClientError::Internal)?;
    Ok(DeviceAuthFinishRequest {
        account_id: id(state.account_id.to_bytes()),
        device_id: id(state.device_id.to_bytes()),
        challenge: challenge.challenge,
        signature: Fixed::from_bytes(container.to_bytes()),
        reconciliation: None,
    })
}

/// A device-authenticated session (CRYPTO.md §5.10). Holds the bearer token (a secret, wiped
/// on drop) and the request counter. `Debug` shows neither the token nor the session id.
pub struct DeviceSession {
    /// The bearer token.
    token: SessionToken,
    /// The session id request signatures cover.
    session_id: SessionId,
    /// The next request counter.
    next_counter: u64,
    /// The canonical origin.
    server_origin: ServerOrigin,
    /// The account.
    account_id: AccountId,
    /// The device.
    device_id: DeviceId,
}

impl fmt::Debug for DeviceSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceSession")
            .field("device_id", &self.device_id)
            .field("next_counter", &self.next_counter)
            .finish_non_exhaustive()
    }
}

impl DeviceSession {
    /// The session from the server's answer to [`device_auth_finish`]'s request.
    #[must_use]
    pub fn new(state: &DeviceState, answer: DeviceAuthFinishResponse) -> Self {
        Self {
            token: answer.session_token,
            session_id: SessionId::from_bytes(answer.session_id.to_bytes()),
            next_counter: 1,
            server_origin: state.server_origin.clone(),
            account_id: state.account_id,
            device_id: state.device_id,
        }
    }

    /// The bearer token, for the host's transport. Never log it.
    #[must_use]
    pub const fn bearer_token(&self) -> &SessionToken {
        &self.token
    }

    /// Signs one request with the next counter (`device-request`, CRYPTO.md §5.10 "Request
    /// signing"). `body` is the exact bytes the host sends.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if `unlocked` is another device's, or the method or path
    /// is empty; [`ClientError::SessionExhausted`] when the counter would wrap;
    /// [`ClientError::Internal`] if signing fails.
    pub fn sign_request(
        &mut self,
        unlocked: &UnlockedDevice,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<RequestSignature, ClientError> {
        if unlocked.account_id != self.account_id
            || unlocked.device_id != self.device_id
            || method.is_empty()
            || path_and_query.is_empty()
        {
            return Err(ClientError::InvalidInput);
        }
        let counter = self.next_counter;
        let next = counter
            .checked_add(1)
            .ok_or(ClientError::SessionExhausted)?;
        let container = DeviceRequest {
            server_origin: &self.server_origin,
            account_id: self.account_id,
            device_id: self.device_id,
            session_id: self.session_id,
            request_counter: counter,
            method,
            path_and_query,
            body_hash: DeviceRequest::body_hash(body),
        }
        .sign(unlocked.device_keys.signing_key())
        .map_err(|_| ClientError::Internal)?;
        self.next_counter = next;
        Ok(RequestSignature {
            request_counter: counter,
            signature: Fixed::from_bytes(container.to_bytes()),
        })
    }
}
