-- Deletes the TOTP credential of every account (ADR 0047 `secrets invalidate` step 4, a whole loss: no data key carries forward). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_totp_credentials
