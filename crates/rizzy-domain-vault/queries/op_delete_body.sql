-- R1: deletes one op's body; its signed header, hashes and signature stay (ADR 0021 §3). Shared.
UPDATE vault_ops SET body = NULL
WHERE vault_id = $1 AND device_id = $2 AND device_seq = $3 AND item_id = $4
