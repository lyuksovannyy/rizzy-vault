-- Restore: one row of `auth_security_events` (ADR 0011 "Backups", ADR 0090 §11). Shared by both engines ($N placeholders).
INSERT INTO auth_security_events (event_id, account_id, at_ms, kind, class, actor_kind, actor_device_id, actor_admin_id, subject_device_id, label, value_old, value_new, state_seq)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
