-- A settlement request that the mint refused because outputs are signed or
-- pending in another operation. The request can never commit. The row holds
-- two bits of state for each request output, in request order, and no B_:
-- the request digest binds the outputs. Only a request with a PAY_TO_UNLOCK
-- input gets a row, so every row has a cutoff. Additive only: no existing
-- table changes.
CREATE TABLE ctf_settlement_output_conflicts (
    request_digest BYTEA PRIMARY KEY NOT NULL
        CHECK (octet_length(request_digest) = 32),
    output_count BIGINT NOT NULL
        CHECK (output_count > 0),
    conflict_states BYTEA NOT NULL,
    cutoff BIGINT NOT NULL
        CHECK (cutoff >= 0),
    created_at BIGINT NOT NULL
        CHECK (created_at >= 0),
    CHECK (octet_length(conflict_states) = (output_count + 3) / 4)
);

CREATE INDEX idx_ctf_settlement_output_conflicts_cutoff
    ON ctf_settlement_output_conflicts(cutoff);
