-- write schema definitions here

CREATE TABLE event_identity_registration (
    eon bigint NOT NULL,
    identity bytea NOT NULL,
    identity_prefix bytea NOT NULL,
    sender text NOT NULL,
    event_trigger_definition bytea NOT NULL,
    expiration_block_number bigint,
    tx_hash bytea NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (eon, identity)
);
