// SPDX-License-Identifier: AGPL-3.0-only

//! Account settings flows against the fake server (ADR 0042 §5–§6): a web session writes the
//! match default and a user group, another session reads them, a concurrent edit loses the
//! compare-and-swap and restarts on the winner's record, unknown tags survive an edit, and a
//! record this build cannot read blocks every write. The server-side checks of a settings
//! commit are `rizzy-domain-auth`'s own tests (`requests::settings_change_over_a_device_session`).

use rizzy_core::sign::CasRetry;
use rizzy_match::{GroupId, MatchMode};
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::error::ErrorCode;

use super::*;
use crate::login::{WebSession, verify_web_refresh, web_account_query};
use crate::matching::{FrameContext, ItemUri, decide_with_settings};
use crate::settings::{
    AccountSettingsRecord, PendingSettingsChange, SettingsEdit, account_settings, change_settings,
    seal_commit,
};

impl Server {
    /// `account/commit` of a settings-only change: compare-and-swap on `state_seq`, then
    /// `settings_seq + 1` with an envelope that hashes to the new `settings_hash`. A
    /// byte-identical repeat succeeds.
    fn commit_settings(&mut self, req: &CommitChangeRequest) -> Result<(), ErrorCode> {
        let s = self.stored();
        if req.account_state.as_slice() == s.state.as_slice() {
            return Ok(());
        }
        let bundle = PublicKeyBundle::verify_self_signed(s.bundles.last().unwrap()).unwrap();
        let verify = |wire: &[u8]| {
            AccountState::verify(wire, &bundle.identity_ed25519, bundle.identity_epoch)
                .map(rizzy_core::sign::Verified::into_statement)
        };
        let current = verify(&s.state).unwrap();
        let new = verify(req.account_state.as_slice()).map_err(|_| ErrorCode::InvalidRequest)?;
        if new.state_seq != current.state_seq + 1 {
            return Err(ErrorCode::StateConflict);
        }
        let settings = req
            .account_settings
            .clone()
            .ok_or(ErrorCode::InvalidRequest)?;
        if new.settings_seq != current.settings_seq + 1
            || settings.settings_seq != new.settings_seq
            || !new.matches_settings(Some(settings.envelope.as_slice()))
            || req.registration_upload.is_some()
            || req.vault_rotation.is_some()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let s = self.account.as_mut().unwrap();
        s.state = req.account_state.as_slice().to_vec();
        s.settings = Some(settings);
        Ok(())
    }
}

/// A web-vault signup and one web session of it, plus the Secret Key for more sessions.
fn web_account(server: &mut Server, rng: &mut ChaCha20Rng) -> (WebSession, String) {
    let input = SignupInput {
        server_origin: ORIGIN,
        login_name: "Alice",
        password: PASSWORD,
        invite: None,
        issue_recovery_code: false,
        device_kind: DeviceKind::WebEphemeral,
        now_ms: T0,
    };
    let (started, request) = start_signup(rng, &input).unwrap();
    let account_id = AccountId::from_bytes(request.account_id.to_bytes());
    let response = server.register_start(&request);
    let mut pending = started.finish(rng, &response).unwrap();
    let sk = pending.emergency_kit().secret_key().to_owned();
    let last = sk.rsplit('-').next().unwrap().to_owned();
    pending.confirm_kit(&last).unwrap();
    server.register_finish(account_id, pending.commit_request().unwrap());
    pending.finalize().unwrap();
    (web_login(server, rng, &sk), sk)
}

/// Sends `pending` and, on success, adopts it.
fn commit(server: &mut Server, web: &mut WebSession, pending: PendingSettingsChange) {
    server.commit_settings(pending.commit_request()).unwrap();
    pending.finalize(&mut web.account).unwrap();
}

/// Builds \`edit\` on the session's account, sends it and adopts it.
fn apply(server: &mut Server, rng: &mut ChaCha20Rng, web: &mut WebSession, change: SettingsEdit) {
    let pending = edit(rng, web, change);
    commit(server, web, pending);
}

/// The session's account re-fetched and verified (what a sync's `account/state` step does).
fn refresh(server: &Server, web: &mut WebSession) {
    let view = server.view_since(&web_account_query(&web.account));
    web.account = verify_web_refresh(&web.account, &web.unlocked, &view).unwrap();
}

fn read(web: &WebSession) -> AccountSettingsRecord {
    account_settings(&web.account, &web.unlocked).unwrap()
}

fn edit(rng: &mut ChaCha20Rng, web: &WebSession, edit: SettingsEdit) -> PendingSettingsChange {
    change_settings(rng, &web.account, &web.unlocked, edit).unwrap()
}

fn group_edit(domains: &[&str]) -> SettingsEdit {
    SettingsEdit::AddUserGroup(domains.iter().map(|d| (*d).to_owned()).collect())
}

/// The candidates for `page` among one saved URI `saved` whose mode is the account default.
fn candidates(web: &WebSession, page: &str, saved: &str) -> usize {
    let uri = ItemUri {
        item_id: [1; 16],
        uri_id: [2; 16],
        value: saved,
        mode: MatchMode::AccountDefault,
    };
    let frame = FrameContext {
        is_top_frame: true,
        frame_origin: page,
    };
    let (global, _) = crate::matching::global_equivalence_groups(0);
    decide_with_settings(page, &frame, &[uri], &read(web), &global)
        .unwrap()
        .candidates
        .len()
}

#[test]
fn a_web_session_writes_the_settings_and_another_session_reads_them() {
    let mut rng = ChaCha20Rng::seed_from_u64(91);
    let mut server = Server::new(92);
    let (mut web, sk) = web_account(&mut server, &mut rng);

    // settings_seq = 0: the absent record, read as the ADR 0037 §6 defaults.
    assert_eq!(web.account.pin.state.settings_seq, 0);
    assert_eq!(read(&web), AccountSettingsRecord::default());
    assert_eq!(
        candidates(&web, "https://www.example.com/", "https://example.com/"),
        1
    );
    assert_eq!(
        candidates(&web, "https://example.net/", "https://example.com/"),
        0
    );

    // A user group widens Base domain to the group's other member.
    let pending = edit(&mut rng, &web, group_edit(&["example.com", "Example.NET"]));
    let commit_bytes = pending.commit_request().clone();
    assert!(commit_bytes.account_settings.is_some());
    assert!(commit_bytes.registration_upload.is_none() && commit_bytes.recovery.is_none());
    commit(&mut server, &mut web, pending);
    assert_eq!(web.account.pin.state.settings_seq, 1);
    assert_eq!(web.account.pin.state.state_seq, 2);
    assert_eq!(
        candidates(&web, "https://example.net/", "https://example.com/"),
        1
    );

    // The account default narrows every 0x0000 URI: Host refuses the subdomain.
    apply(
        &mut server,
        &mut rng,
        &mut web,
        SettingsEdit::SetMatchDefault(MatchMode::Host),
    );
    assert_eq!(
        candidates(&web, "https://www.example.com/", "https://example.com/"),
        0
    );
    assert_eq!(
        candidates(&web, "https://example.com/", "https://example.com/"),
        1
    );

    // A new session of the same account reads the same record from the server.
    let other = web_login(&mut server, &mut rng, &sk);
    assert_eq!(read(&other), read(&web));
    assert_eq!(read(&other).matching().match_default(), MatchMode::Host);

    // Removing the group narrows again.
    let id = read(&web).matching().user_groups()[0].id();
    apply(
        &mut server,
        &mut rng,
        &mut web,
        SettingsEdit::RemoveUserGroup(id),
    );
    assert!(read(&web).matching().user_groups().is_empty());
    assert_eq!(
        candidates(&web, "https://example.net/", "https://example.net/"),
        1
    );
    assert_eq!(
        candidates(&web, "https://example.net/", "https://example.com/"),
        0
    );
    // A group that is gone cannot be removed again.
    assert_eq!(
        change_settings(
            &mut rng,
            &web.account,
            &web.unlocked,
            SettingsEdit::RemoveUserGroup(id)
        )
        .unwrap_err(),
        ClientError::InvalidInput
    );
    // A public suffix is refused before anything is built.
    assert_eq!(
        change_settings(
            &mut rng,
            &web.account,
            &web.unlocked,
            group_edit(&["co.uk", "example.com"])
        )
        .unwrap_err(),
        ClientError::EquivalenceDomainRejected
    );
}

#[test]
fn a_concurrent_edit_loses_the_cas_and_restarts_on_the_winners_record() {
    let mut rng = ChaCha20Rng::seed_from_u64(93);
    let mut server = Server::new(94);
    let (mut first, sk) = web_account(&mut server, &mut rng);
    let mut second = web_login(&mut server, &mut rng, &sk);
    let stale = second.account.pin.state.clone();

    // Both build on settings_seq 0; the first wins.
    apply(
        &mut server,
        &mut rng,
        &mut first,
        group_edit(&["a.example", "b.example"]),
    );
    let disabled = GroupId::from_bytes([0x5a; 16]);
    let losing = edit(
        &mut rng,
        &second,
        SettingsEdit::DisableGlobalGroup(disabled),
    );
    assert_eq!(
        server.commit_settings(losing.commit_request()).unwrap_err(),
        ErrorCode::StateConflict
    );

    // The loser re-fetches; settings_seq moved, so CasRetry says Restart: the same edit is
    // redone on the winner's full record, the winner's group carried forward.
    refresh(&server, &mut second);
    assert_eq!(
        stale.cas_retry(&second.account.pin.state),
        CasRetry::Restart
    );
    let retried = losing
        .on_state_conflict(&mut rng, &second.account, &second.unlocked)
        .unwrap();
    commit(&mut server, &mut second, retried);
    let record = read(&second);
    assert_eq!(record.matching().user_groups().len(), 1);
    assert!(record.matching().disabled_global().contains(&disabled));
    assert_eq!(second.account.pin.state.settings_seq, 2);
    refresh(&server, &mut first);
    assert_eq!(read(&first), record);

    // A re-fetch that answers an older state than the change was built on is a rollback.
    let pending = edit(&mut rng, &second, SettingsEdit::EnableGlobalGroup(disabled));
    let old = web_login(&mut server, &mut rng, &sk);
    let mut behind = old;
    behind.account.pin.state.state_seq = 1;
    assert_eq!(
        pending
            .on_state_conflict(&mut rng, &behind.account, &behind.unlocked)
            .unwrap_err(),
        ClientError::Rollback
    );
}

#[test]
fn unknown_tags_survive_an_edit_and_an_unreadable_record_blocks_writes() {
    let mut rng = ChaCha20Rng::seed_from_u64(95);
    let mut server = Server::new(96);
    let (mut web, sk) = web_account(&mut server, &mut rng);

    // A newer client wrote tag 0x0003 (ADR 0081 Part B's contact pins), which this build does
    // not know.
    let newer: &[u8] = &[0, 1, 0, 1, 0, 3, 0, 0, 0, 3, b'n', b'e', b'w'];
    let (request, _) = seal_commit(&mut rng, &web.account, &web.unlocked, newer).unwrap();
    server.commit_settings(&request).unwrap();
    refresh(&server, &mut web);
    assert_eq!(read(&web).unknown_tags().collect::<Vec<_>>(), [0x0003]);
    apply(
        &mut server,
        &mut rng,
        &mut web,
        SettingsEdit::SetMatchDefault(MatchMode::Exact),
    );
    let other = web_login(&mut server, &mut rng, &sk);
    let record = read(&other);
    assert_eq!(record.unknown_tags().collect::<Vec<_>>(), [0x0003]);
    assert_eq!(record.matching().match_default(), MatchMode::Exact);
    // ADR 0081 §A10: the first settings write of this build adds the vault directory.
    assert!(record.vault_directory().is_some());
    let bytes = record.encode().unwrap();
    assert!(bytes.ends_with(&[0, 3, 0, 0, 0, 3, b'n', b'e', b'w']));

    // A record of a later format_version is parked: no read, no write, no matching.
    let (request, _) = seal_commit(&mut rng, &web.account, &web.unlocked, &[0, 2, 0, 0]).unwrap();
    server.commit_settings(&request).unwrap();
    refresh(&server, &mut web);
    assert_eq!(
        account_settings(&web.account, &web.unlocked).unwrap_err(),
        ClientError::SettingsUpdateRequired
    );
    assert_eq!(
        change_settings(
            &mut rng,
            &web.account,
            &web.unlocked,
            SettingsEdit::SetMatchDefault(MatchMode::Host)
        )
        .unwrap_err(),
        ClientError::SettingsUpdateRequired
    );

    // A malformed record is rejected with the severity of a failed decryption.
    let (request, _) = seal_commit(&mut rng, &web.account, &web.unlocked, &[0, 1, 0, 1]).unwrap();
    server.commit_settings(&request).unwrap();
    refresh(&server, &mut web);
    assert_eq!(
        account_settings(&web.account, &web.unlocked).unwrap_err(),
        ClientError::InvalidServerResponse
    );
    assert_eq!(
        change_settings(
            &mut rng,
            &web.account,
            &web.unlocked,
            group_edit(&["a.example", "b.example"])
        )
        .unwrap_err(),
        ClientError::InvalidServerResponse
    );
}

#[test]
fn the_settings_cache_reads_each_object_once() {
    let mut rng = ChaCha20Rng::seed_from_u64(97);
    let mut server = Server::new(98);
    let (mut web, _) = web_account(&mut server, &mut rng);
    let mut cache = crate::settings::SettingsCache::default();
    assert_eq!(
        cache.get(&web.account, &web.unlocked).unwrap(),
        &AccountSettingsRecord::default()
    );
    apply(
        &mut server,
        &mut rng,
        &mut web,
        SettingsEdit::SetMatchDefault(MatchMode::StartsWith),
    );
    // A new settings_seq is read again.
    assert_eq!(
        cache
            .get(&web.account, &web.unlocked)
            .unwrap()
            .matching()
            .match_default(),
        MatchMode::StartsWith
    );
}
