-- +goose Up
-- +goose StatementBegin
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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE event_identity_registration;
-- +goose StatementEnd
