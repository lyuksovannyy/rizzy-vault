-- The crash marker of an interrupted `secrets invalidate`, if any (ADR 0047 step 2). Shared by both engines; every value is a bound parameter (INV-53).
SELECT loss_case, setup_id, diagnosed_at_ms FROM auth_invalidate_pending WHERE id = 1
