-- A settlement request that the mint refused because outputs are signed or
-- pending in another operation. The request can never commit. The row holds
-- two bits of state for each request output, in request order, and no B_:
-- the request digest binds the outputs. Only a request with a PAY_TO_UNLOCK
-- input gets a row, so every row has a cutoff. Additive only: no existing
-- table changes.
CREATE TABLE ctf_settlement_output_conflicts (
    request_digest BLOB PRIMARY KEY NOT NULL
        CHECK (typeof(request_digest) = 'blob' AND length(request_digest) = 32),
    output_count INTEGER NOT NULL
        CHECK (typeof(output_count) = 'integer' AND output_count > 0),
    conflict_states BLOB NOT NULL
        CHECK (typeof(conflict_states) = 'blob'),
    cutoff INTEGER NOT NULL
        CHECK (typeof(cutoff) = 'integer' AND cutoff >= 0),
    created_at INTEGER NOT NULL
        CHECK (typeof(created_at) = 'integer' AND created_at >= 0),
    CHECK (length(conflict_states) = (output_count + 3) / 4)
) STRICT;

CREATE INDEX idx_ctf_settlement_output_conflicts_cutoff
    ON ctf_settlement_output_conflicts(cutoff);
