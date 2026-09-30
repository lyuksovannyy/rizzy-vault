//! Account enumeration (CRYPTO.md §5.9) and rate limits (ADR 0010 §5, INV-7).

use rizzy_core::ids::AccountId;
use rizzy_core::opaque::{
    KE2_LEN, KE3_LEN, PasswordInput, client_login_start, client_registration_start,
};
use rizzy_core::secret_key::SecretKey;
use rizzy_domain_auth::AuthError;
use rizzy_proto::auth::{LoginStartRequest, LoginStartResponse, RegisterStartRequest};
use rizzy_proto::wire::Text;

use crate::common::{Env, block_on, bytes, wid};

impl Env {
    /// One `login_start` for `name` from `source` with a fresh KE1.
    async fn probe(
        &mut self,
        name: &str,
        source: &[u8],
        reauth: Option<&rizzy_domain_auth::Session>,
    ) -> Result<LoginStartResponse, AuthError> {
        let sk = SecretKey::generate(&mut self.rng);
        let pw_in = PasswordInput::derive("guess", &sk).unwrap();
        let (_, ke1) = client_login_start(&mut self.rng, &pw_in).unwrap();
        let req = LoginStartRequest {
            login_name: Text::new(name.to_owned()).unwrap(),
            ke1: bytes(ke1),
        };
        self.svc
            .login_start(&mut self.rng, &req, source, reauth, self.now)
            .await
    }
}

/// A real and an unknown login name get the same shape of answer, and the same refusal for a
/// wrong KE3; a wrong password fails exactly like an unknown account.
#[test]
fn unknown_and_real_names_answer_alike() {
    block_on(async {
        let mut env = Env::new(10).await;
        let alice = env.signup("alice", "right password").await;
        let source = env.source.clone();
        let real = env.probe("alice", &source, None).await.unwrap();
        let fake = env.probe("mallory", &source, None).await.unwrap();
        assert_eq!(real.kdf_id, fake.kdf_id);
        assert_eq!(real.kdf_id, 1);
        assert_eq!(real.server_origin, fake.server_origin);
        assert_eq!(real.ke2.len(), KE2_LEN);
        assert_eq!(fake.ke2.len(), KE2_LEN);
        for started in [real, fake] {
            let answer = env
                .finish_login(started.login_id, vec![7; KE3_LEN], None, None)
                .await;
            assert!(matches!(answer, Err(AuthError::Unauthorized)));
            // The login state was used up by the failed attempt.
            let again = env
                .finish_login(started.login_id, vec![7; KE3_LEN], None, None)
                .await;
            assert!(matches!(again, Err(AuthError::Unauthorized)));
        }
        // A wrong password, and a right password with a wrong Secret Key: both Unauthorized.
        let wrong = env
            .login_as("alice", "wrong password", &alice.secret_key, None, None)
            .await;
        assert!(matches!(wrong, Err(AuthError::Unauthorized)));
        let other_sk = SecretKey::generate(&mut env.rng);
        let wrong_sk = env
            .login_as("alice", "right password", &other_sk, None, None)
            .await;
        assert!(matches!(wrong_sk, Err(AuthError::Unauthorized)));
        let unknown = env
            .login_as("nobody", "right password", &alice.secret_key, None, None)
            .await;
        assert!(matches!(unknown, Err(AuthError::Unauthorized)));
        // Names are normalised before the lookup (§2): the typed case does not matter.
        env.login_as("ALICE", "right password", &alice.secret_key, None, None)
            .await
            .unwrap();
        // A login state expires after 60 s (§5.10).
        let started = env.probe("alice", &source, None).await.unwrap();
        env.tick(60_000);
        let late = env
            .finish_login(started.login_id, vec![7; KE3_LEN], None, None)
            .await;
        assert!(matches!(late, Err(AuthError::Unauthorized)));
        // Recovery answers an unknown name and a wrong code alike (§5.9).
        let token = alice.recovery_token();
        let a = env
            .svc
            .recovery_start("nobody", &token, &source, env.now)
            .await;
        let b = env
            .svc
            .recovery_start("alice", &[0u8; 32], &source, env.now)
            .await;
        assert!(matches!(a, Err(AuthError::Unauthorized)));
        assert!(matches!(b, Err(AuthError::Unauthorized)));
    });
}

/// Backoff per (name, source) and a cap per name, never a lockout; a device-authenticated
/// re-authentication has its own bucket (INV-7).
#[test]
fn rate_limits_and_the_reauth_bucket() {
    block_on(async {
        let mut env = Env::new(11).await;
        let client = env.signup("dora", "pw").await;
        let source = env.source.clone();
        // Five attempts pass; the sixth passes and sets a backoff; the seventh waits.
        for _ in 0..6 {
            env.probe("dora", &source, None).await.unwrap();
        }
        assert!(matches!(
            env.probe("dora", &source, None).await,
            Err(AuthError::RateLimited { .. })
        ));
        // Another source is not blocked by this source's backoff.
        env.probe("dora", b"198.51.100.7", None).await.unwrap();
        // The enrolled device re-authenticates through its own bucket.
        let device = &client.devices[0];
        let mut ds = env.device_auth(&client, device).await.unwrap();
        let session = env.signed(&client, device, &mut ds, b"").await.unwrap();
        env.probe("dora", &source, Some(&session)).await.unwrap();
        // The backoff ends: after it the source may try again.
        env.tick(1_000);
        env.probe("dora", &source, None).await.unwrap();
        // An unknown name is counted the same way.
        for _ in 0..6 {
            env.probe("ghost", &source, None).await.unwrap();
        }
        assert!(matches!(
            env.probe("ghost", &source, None).await,
            Err(AuthError::RateLimited { .. })
        ));
    });
}

/// INV-7 covers registration too: probing whether one name is taken backs off per name even
/// when every attempt comes from another source (the per-name cap).
#[test]
fn signup_is_rate_limited_per_name() {
    block_on(async {
        let mut env = Env::new(12).await;
        env.signup("erin", "pw").await;
        let sk = SecretKey::generate(&mut env.rng);
        let pw_in = PasswordInput::derive_for_new_password("guess", &sk).unwrap();
        let (_, m1) = client_registration_start(&mut env.rng, &pw_in).unwrap();
        let attempt = |env: &mut Env, name: &str| RegisterStartRequest {
            invite: None,
            login_name: Text::new(name.to_owned()).unwrap(),
            account_id: wid(AccountId::generate(&mut env.rng).to_bytes()),
            registration_request: bytes(m1.clone()),
        };
        // The signup itself was the first attempt on the name. Nineteen more pass (the name is
        // taken), the 21st passes and sets a backoff, the 22nd waits, each from a new source.
        for i in 0..20u8 {
            let req = attempt(&mut env, "erin");
            let source = [198, 51, 100, i];
            assert!(matches!(
                env.svc.register_start(&req, &source, env.now).await,
                Err(AuthError::Conflict)
            ));
        }
        let req = attempt(&mut env, "erin");
        assert!(matches!(
            env.svc.register_start(&req, b"203.0.113.9", env.now).await,
            Err(AuthError::RateLimited { .. })
        ));
        // Another name from a fresh source is not blocked by it.
        let req = attempt(&mut env, "fred");
        env.svc
            .register_start(&req, b"203.0.113.10", env.now)
            .await
            .unwrap();
    });
}
