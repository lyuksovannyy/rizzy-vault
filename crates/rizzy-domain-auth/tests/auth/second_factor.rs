//! Server-side 2FA with TOTP (CRYPTO.md §11.15): enrolment, login, replay, removal.

use rizzy_core::totp::{TotpParams, TotpSecret};
use rizzy_domain_auth::AuthError;

use crate::common::{Env, block_on};

/// The server's code for `secret` at `now_ms`.
fn code_at(secret: &TotpSecret, now_ms: u64) -> String {
    TotpParams::DEFAULT
        .code_at(secret, now_ms / 1000)
        .unwrap()
        .to_digits()
        .to_string()
}

#[test]
fn totp_enrolment_login_replay_and_removal() {
    block_on(async {
        let mut env = Env::new(50).await;
        let client = env.signup("kim", "pw").await;
        let (name, password) = (client.name.clone(), client.password.clone());
        let login = env.login(&client).await;
        let fresh = env.bearer(&login.response.session_token).await;

        let enrolment = env
            .svc
            .totp_enrol_start(&mut env.rng, &fresh, env.now)
            .await
            .unwrap();
        assert_eq!(enrolment.totp_credential_seq, 1);
        assert!(!format!("{enrolment:?}").contains(&code_at(&enrolment.secret, env.now)));
        // An unconfirmed enrolment gates nothing.
        env.login(&client).await;
        // A wrong code does not confirm it.
        assert!(matches!(
            env.svc
                .totp_enrol_confirm(&fresh, 1, "000000", env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        let first = code_at(&enrolment.secret, env.now);
        env.svc
            .totp_enrol_confirm(&fresh, 1, &first, env.now)
            .await
            .unwrap();

        // From now on a login needs a code; the step used to confirm cannot be replayed.
        let none = env
            .login_as(&name, &password, &client.secret_key, None, None)
            .await;
        assert!(matches!(none, Err(AuthError::SecondFactorRequired)));
        let replay = env
            .login_as(&name, &password, &client.secret_key, Some(&first), None)
            .await;
        assert!(matches!(replay, Err(AuthError::SecondFactorRequired)));
        env.tick(30_000);
        let next = code_at(&enrolment.secret, env.now);
        env.login_as(&name, &password, &client.secret_key, Some(&next), None)
            .await
            .unwrap();
        let again = env
            .login_as(&name, &password, &client.secret_key, Some(&next), None)
            .await;
        assert!(matches!(again, Err(AuthError::SecondFactorRequired)));

        // Removal needs a fresh session and a current code.
        env.tick(30_000);
        let login = env
            .login_as(
                &name,
                &password,
                &client.secret_key,
                Some(&code_at(&enrolment.secret, env.now)),
                None,
            )
            .await
            .unwrap();
        let fresh = env.bearer(&login.response.session_token).await;
        env.tick(30_000);
        env.svc
            .totp_disable(&fresh, &code_at(&enrolment.secret, env.now), env.now)
            .await
            .unwrap();
        env.login(&client).await;
    });
}
