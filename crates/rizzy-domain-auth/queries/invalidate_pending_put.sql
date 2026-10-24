-- Writes the crash marker of `secrets invalidate` (ADR 0047 step 4): the case $1, the minted setup_id $2 and the diagnosis time $3, replacing an earlier run's. Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_invalidate_pending (id, loss_case, setup_id, diagnosed_at_ms)
VALUES (1, $1, $2, $3)
ON CONFLICT (id) DO UPDATE SET
    loss_case = excluded.loss_case,
    setup_id = excluded.setup_id,
    diagnosed_at_ms = excluded.diagnosed_at_ms
