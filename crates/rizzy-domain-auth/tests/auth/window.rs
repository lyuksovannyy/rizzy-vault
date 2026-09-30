//! The replay window of a device-authenticated session, at its edges, through the database
//! (ADR 0028 item 5 "Replay window"; CRYPTO.md §5.10).

use rizzy_core::sign::DeviceRequest;
use rizzy_domain_auth::config::MAX_REQUEST_COUNTER;
use rizzy_domain_auth::{AuthError, Session};
use rizzy_proto::auth::RequestSignature;
use rizzy_proto::wire::Fixed;

use crate::common::{Client, Device, DeviceSession, Env, block_on, origin, request};

/// A valid `device-request` signature for `counter` over the test request with `body`.
fn sign(
    client: &Client,
    device: &Device,
    session: &DeviceSession,
    counter: u64,
    body: &[u8],
) -> RequestSignature {
    let origin = origin();
    let parts = request(body);
    let container = DeviceRequest {
        server_origin: &origin,
        account_id: client.account_id,
        device_id: device.id,
        session_id: session.session_id,
        request_counter: counter,
        method: parts.method,
        path_and_query: parts.path_and_query,
        body_hash: DeviceRequest::body_hash(body),
    }
    .sign(device.keys.signing_key())
    .unwrap();
    RequestSignature {
        request_counter: counter,
        signature: Fixed::from_bytes(container.to_bytes()),
    }
}

/// Sends the test request with `body` under `signature`.
async fn send(
    env: &Env,
    session: &DeviceSession,
    signature: &RequestSignature,
    body: &[u8],
) -> Result<Session, AuthError> {
    env.svc
        .authenticate_request(
            session.token.expose_secret(),
            Some(signature),
            request(body),
            env.now,
        )
        .await
}

/// The first signed request may carry any counter, `0` included; `max − 63 ..= max` is accepted
/// once each; a duplicate, or a counter 64 or more behind, is refused; a jump of 64 or more
/// forgets the map.
#[test]
fn the_window_edges_hold_through_the_database() {
    block_on(async {
        let mut env = Env::new(61).await;
        let client = env.signup("wendy", "correct horse battery staple").await;
        let device = &client.devices[0];

        // A first request with counter 0.
        let zero = env.device_auth(&client, device).await.unwrap();
        env.signed_with(&client, device, &zero, 0, b"a")
            .await
            .unwrap();
        assert!(matches!(
            env.signed_with(&client, device, &zero, 0, b"a").await,
            Err(AuthError::Unauthorized)
        ));

        // A first request far up the range, on a session of its own.
        let session = env.device_auth(&client, device).await.unwrap();
        let max = 1_000_000;
        env.signed_with(&client, device, &session, max, b"a")
            .await
            .unwrap();
        // The lowest counter of the window, once. Its bit is the top bit of the stored map.
        env.signed_with(&client, device, &session, max - 63, b"b")
            .await
            .unwrap();
        assert!(matches!(
            env.signed_with(&client, device, &session, max - 63, b"b")
                .await,
            Err(AuthError::Unauthorized)
        ));
        // One below the window: refused, although it was never used.
        assert!(matches!(
            env.signed_with(&client, device, &session, max - 64, b"c")
                .await,
            Err(AuthError::Unauthorized)
        ));
        // A counter inside the window that was never used is still open.
        env.signed_with(&client, device, &session, max - 1, b"d")
            .await
            .unwrap();

        // A jump of 63 keeps `max` as the lowest counter of the window, still marked.
        env.signed_with(&client, device, &session, max + 63, b"e")
            .await
            .unwrap();
        assert!(matches!(
            env.signed_with(&client, device, &session, max, b"a").await,
            Err(AuthError::Unauthorized)
        ));
        env.signed_with(&client, device, &session, max + 1, b"f")
            .await
            .unwrap();
        // A jump of exactly 64 forgets the map: everything at or below the old `max` is now
        // too old, and the 63 counters in between are open.
        let top = max + 63 + 64;
        env.signed_with(&client, device, &session, top, b"g")
            .await
            .unwrap();
        assert!(matches!(
            env.signed_with(&client, device, &session, max + 63, b"e")
                .await,
            Err(AuthError::Unauthorized)
        ));
        env.signed_with(&client, device, &session, top - 63, b"h")
            .await
            .unwrap();
    });
}

/// The window moves only for a request whose signature verified, it is spent then, and it lives
/// in the session's row: a service opened over the same database still refuses the replay.
#[test]
fn a_forged_request_cannot_move_the_window_and_a_restart_keeps_it() {
    block_on(async {
        let mut env = Env::new(62).await;
        let client = env.signup("xena", "correct horse battery staple").await;
        let device = &client.devices[0];
        let session = env.device_auth(&client, device).await.unwrap();
        env.signed_with(&client, device, &session, 1, b"one")
            .await
            .unwrap();

        // A signature that does not cover the body sent, with a counter far ahead. Were the
        // window moved before the signature is checked, counter 2 would now be too old.
        let far = sign(&client, device, &session, 50_000, b"signed body");
        assert!(matches!(
            send(&env, &session, &far, b"another body").await,
            Err(AuthError::Unauthorized)
        ));
        // The counter in the header is not the signed one.
        let mut lifted = sign(&client, device, &session, 3, b"x");
        lifted.request_counter = 60_000;
        assert!(matches!(
            send(&env, &session, &lifted, b"x").await,
            Err(AuthError::Unauthorized)
        ));
        env.signed_with(&client, device, &session, 2, b"two")
            .await
            .unwrap();
        // The forged counters were not spent either: the real requests with them pass.
        assert!(send(&env, &session, &far, b"signed body").await.is_ok());

        // "Restart": a new service over the same database.
        let db = env.db.clone();
        env.reopen(db, |_| {});
        for spent in [1, 2, 50_000] {
            assert!(
                matches!(
                    env.signed_with(&client, device, &session, spent, b"again")
                        .await,
                    Err(AuthError::Unauthorized)
                ),
                "{spent} after the restart"
            );
        }
        env.signed_with(&client, device, &session, 50_001, b"next")
            .await
            .unwrap();
    });
}

/// The top of the counter range the session row can record, and the refusal above it.
#[test]
fn the_highest_recordable_counter_is_accepted_and_the_next_is_refused() {
    block_on(async {
        let mut env = Env::new(63).await;
        let client = env.signup("yara", "correct horse battery staple").await;
        let device = &client.devices[0];
        let session = env.device_auth(&client, device).await.unwrap();
        env.signed_with(&client, device, &session, 1, b"a")
            .await
            .unwrap();
        // Above the limit: refused like any unusable counter, with a valid signature, and the
        // window stays where it was.
        for over in [MAX_REQUEST_COUNTER + 1, u64::MAX] {
            assert!(
                matches!(
                    env.signed_with(&client, device, &session, over, b"a").await,
                    Err(AuthError::Unauthorized)
                ),
                "{over}"
            );
        }
        env.signed_with(&client, device, &session, 2, b"b")
            .await
            .unwrap();
        // The limit itself: any jump forward is accepted.
        env.signed_with(&client, device, &session, MAX_REQUEST_COUNTER, b"c")
            .await
            .unwrap();
        env.signed_with(&client, device, &session, MAX_REQUEST_COUNTER - 63, b"d")
            .await
            .unwrap();
        for refused in [MAX_REQUEST_COUNTER, MAX_REQUEST_COUNTER - 64, 3] {
            assert!(
                matches!(
                    env.signed_with(&client, device, &session, refused, b"e")
                        .await,
                    Err(AuthError::Unauthorized)
                ),
                "{refused}"
            );
        }
    });
}
