-- Every head h(V, d): the highest `device_seq` of each device's ops in the vault (ADR 0021 §2).
-- Ascending by device id. Shared.
SELECT device_id, MAX(device_seq) FROM vault_ops WHERE vault_id = $1 GROUP BY device_id ORDER BY device_id
