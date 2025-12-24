-- write sql queries here

-- name: InsertEventIdentityRegistration :exec
INSERT INTO event_identity_registration (
    eon,
    identity,
    identity_prefix,
    eon_key,
    event_trigger_definition,
    ttl,
    tx_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (eon, identity) DO NOTHING;

-- name: GetEventIdentityRegistration :one
SELECT * FROM event_identity_registration
WHERE eon = $1 AND identity = $2;

-- name: GetEventIdentityRegistrationTTL :one
SELECT ttl FROM event_identity_registration
WHERE eon = $1 AND identity = $2;