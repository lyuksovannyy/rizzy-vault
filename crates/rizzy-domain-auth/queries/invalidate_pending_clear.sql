-- Clears the crash marker of `secrets invalidate` once the new secrets file is written (ADR 0047 step 6). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_invalidate_pending
