-- Demotes a verified login to a second-factor-pending row, 60 s TTL (ADR 0058 point 3). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_webauthn_pending (pending_id, account_id, expires_at_ms) VALUES ($1, $2, $3)
