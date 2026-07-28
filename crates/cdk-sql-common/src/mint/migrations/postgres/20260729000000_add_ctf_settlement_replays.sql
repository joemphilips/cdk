CREATE TABLE ctf_settlement_replays (
    request_digest BYTEA PRIMARY KEY NOT NULL
        CHECK (octet_length(request_digest) = 32),
    operation_id TEXT NOT NULL UNIQUE
        CHECK (char_length(operation_id) = 36)
        REFERENCES completed_operations(operation_id) ON DELETE RESTRICT,
    response_json TEXT NOT NULL
        CHECK (jsonb_typeof(response_json::jsonb) = 'object'),
    created_at BIGINT NOT NULL
        CHECK (created_at >= 0)
);

CREATE INDEX idx_ctf_settlement_replays_created_at
    ON ctf_settlement_replays(created_at);
