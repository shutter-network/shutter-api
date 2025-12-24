-- write schema definitions here

CREATE TABLE event_identity_registration (
    eon bigint,
    identity bytea,
    identity_prefix bytea,
    eon_key bytea,
    event_trigger_definition bytea,
    ttl bigint,
    tx_hash bytea,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (eon, identity)
);