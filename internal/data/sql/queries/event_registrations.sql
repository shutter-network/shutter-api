-- write sql queries here

-- name: InsertEventIdentityRegistration :exec
INSERT INTO event_identity_registration (
    eon,
    identity,
    identity_prefix,
    sender,
    event_trigger_definition,
    tx_hash
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (eon, identity) DO NOTHING;

-- name: GetEventIdentityRegistration :one
SELECT
    eon,
    identity,
    identity_prefix,
    sender,
    event_trigger_definition,
    COALESCE(expiration_block_number, 0) AS expiration_block_number,
    tx_hash,
    created_at
FROM event_identity_registration
WHERE eon = $1 AND identity = $2;

-- name: GetEventTriggerExpirationBlockNumber :one
SELECT COALESCE(expiration_block_number, 0) FROM event_identity_registration
WHERE eon = $1 AND identity = $2;

-- name: UpdateEventIdentityRegistrationExpirationBlockNumber :exec
UPDATE event_identity_registration
SET expiration_block_number = $1
WHERE eon = $2 AND identity = $3;
