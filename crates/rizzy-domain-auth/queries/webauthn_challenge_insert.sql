-- Stores a ceremony state, unsealed, 60 s TTL (ADR 0077 §2). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_webauthn_challenges (challenge_id, account_id, purpose, state_format, state, expires_at_ms) VALUES ($1, $2, $3, $4, $5, $6)
