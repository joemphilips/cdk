CREATE TABLE ctf_settlement_replays_new (
    request_digest BYTEA PRIMARY KEY NOT NULL
        CHECK (octet_length(request_digest) = 32),
    outcome_kind TEXT NOT NULL
        CHECK (outcome_kind IN ('committed', 'rejected_after_cutoff')),
    operation_id TEXT UNIQUE
        CHECK (operation_id IS NULL OR char_length(operation_id) = 36)
        REFERENCES completed_operations(operation_id) ON DELETE RESTRICT,
    response_json TEXT,
    cutoff BIGINT,
    created_at BIGINT NOT NULL
        CHECK (created_at >= 0),
    CHECK (
        (
            outcome_kind = 'committed'
            AND operation_id IS NOT NULL
            AND response_json IS NOT NULL
            AND jsonb_typeof(response_json::jsonb) = 'object'
            AND cutoff IS NULL
        )
        OR (
            outcome_kind = 'rejected_after_cutoff'
            AND operation_id IS NULL
            AND response_json IS NULL
            AND cutoff IS NOT NULL
            AND cutoff >= 0
        )
    )
);

INSERT INTO ctf_settlement_replays_new
    (request_digest, outcome_kind, operation_id, response_json, cutoff, created_at)
SELECT request_digest, 'committed', operation_id, response_json, NULL, created_at
FROM ctf_settlement_replays;

DROP TABLE ctf_settlement_replays;

ALTER TABLE ctf_settlement_replays_new RENAME TO ctf_settlement_replays;

CREATE INDEX idx_ctf_settlement_replays_created_at
    ON ctf_settlement_replays(created_at);
