CREATE TABLE ctf_settlement_replays (
    request_digest BLOB PRIMARY KEY NOT NULL
        CHECK (typeof(request_digest) = 'blob' AND length(request_digest) = 32),
    operation_id TEXT NOT NULL UNIQUE
        CHECK (typeof(operation_id) = 'text' AND length(operation_id) = 36)
        REFERENCES completed_operations(operation_id) ON DELETE RESTRICT,
    response_json TEXT NOT NULL
        CHECK (
            typeof(response_json) = 'text'
            AND json_valid(response_json)
            AND json_type(response_json) = 'object'
        ),
    created_at INTEGER NOT NULL
        CHECK (typeof(created_at) = 'integer' AND created_at >= 0)
) STRICT;

CREATE INDEX idx_ctf_settlement_replays_created_at
    ON ctf_settlement_replays(created_at);
