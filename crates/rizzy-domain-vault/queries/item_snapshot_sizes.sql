-- The stored size of each of one item's retained snapshots (header, envelope, signature and
-- carried wrap), for a Fetch page's byte budget (`fetch.rs`). Contents are not read. Shared.
SELECT store_seq,
       CAST(length(header) + length(envelope) + length(signature)
            + COALESCE(length(key_wrap), 0) AS BIGINT)
FROM vault_snapshots WHERE vault_id = $1 AND item_id = $2
