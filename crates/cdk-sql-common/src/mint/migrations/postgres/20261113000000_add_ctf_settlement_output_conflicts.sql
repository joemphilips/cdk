-- A settlement request that the mint refused because outputs are signed or
-- pending in another operation. The request can never commit. Additive only:
-- no existing table changes.
CREATE TABLE ctf_settlement_output_conflicts (
    request_digest BYTEA PRIMARY KEY NOT NULL
        CHECK (octet_length(request_digest) = 32),
    conflicts_json TEXT NOT NULL
        CHECK (
            jsonb_typeof(conflicts_json::jsonb) = 'array'
            AND jsonb_array_length(conflicts_json::jsonb) > 0
        ),
    cutoff BIGINT
        CHECK (cutoff IS NULL OR cutoff >= 0),
    created_at BIGINT NOT NULL
        CHECK (created_at >= 0)
);

CREATE INDEX idx_ctf_settlement_output_conflicts_cutoff
    ON ctf_settlement_output_conflicts(cutoff);
