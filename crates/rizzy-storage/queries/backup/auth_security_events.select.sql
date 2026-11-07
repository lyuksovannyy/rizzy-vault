-- Backup: every row of `auth_security_events`, in primary-key order (ADR 0011 "Backups", ADR 0090 §11). Shared by both engines.
SELECT event_id, account_id, at_ms, kind, class, actor_kind, actor_device_id, actor_admin_id, subject_device_id, label, value_old, value_new, state_seq
FROM auth_security_events
ORDER BY event_id
