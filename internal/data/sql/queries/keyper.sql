-- write sql queries here

-- name: GetDecryptionKey :one
SELECT * FROM decryption_key
WHERE eon = $1 AND epoch_id = $2;

-- name: InsertDecryptionKey :exec
INSERT INTO decryption_key (eon, epoch_id, decryption_key)
VALUES ($1, $2, $3);