-- Up to $3 attachments of one item, complete or not, for `attachments/delete-item` (ADR 0093
-- §1.1), in id order. Read through the `vault_attachments_by_item` index. Shared.
SELECT attachment_id FROM vault_attachments
WHERE vault_id = $1 AND item_id = $2
ORDER BY attachment_id
LIMIT $3
