-- +goose Up
-- +goose StatementBegin
ALTER TABLE event_identity_registration 
DROP CONSTRAINT event_identity_registration_pkey;

ALTER TABLE event_identity_registration 
ADD PRIMARY KEY (eon, identity);
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
ALTER TABLE event_identity_registration 
DROP CONSTRAINT event_identity_registration_pkey;

ALTER TABLE event_identity_registration 
ADD PRIMARY KEY (eon, identity_prefix, sender);
-- +goose StatementEnd
