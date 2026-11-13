-- A settlement request that the mint refused because outputs are signed or
-- pending in another operation. The request can never commit. Additive only:
-- no existing table changes.
CREATE TABLE ctf_settlement_output_conflicts (
    request_digest BLOB PRIMARY KEY NOT NULL
        CHECK (typeof(request_digest) = 'blob' AND length(request_digest) = 32),
    conflicts_json TEXT NOT NULL
        CHECK (
            typeof(conflicts_json) = 'text'
            AND json_valid(conflicts_json)
            AND json_type(conflicts_json) = 'array'
            AND json_array_length(conflicts_json) > 0
        ),
    cutoff INTEGER
        CHECK (cutoff IS NULL OR (typeof(cutoff) = 'integer' AND cutoff >= 0)),
    created_at INTEGER NOT NULL
        CHECK (typeof(created_at) = 'integer' AND created_at >= 0)
) STRICT;

CREATE INDEX idx_ctf_settlement_output_conflicts_cutoff
    ON ctf_settlement_output_conflicts(cutoff);
