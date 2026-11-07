-- Records one security event (ADR 0090 §4): $1 event_id, $2 account_id, $3 at_ms, $4 kind, $5 class,
-- $6 actor_kind, $7 actor_device_id, $8 actor_admin_id, $9 subject_device_id, $10 label, $11 value_old,
-- $12 value_new, $13 state_seq.
INSERT INTO auth_security_events (event_id, account_id, at_ms, kind, class, actor_kind, actor_device_id,
    actor_admin_id, subject_device_id, label, value_old, value_new, state_seq)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
