-- NUT-CTF: Conditional tokens - conditions table
CREATE TABLE IF NOT EXISTS conditions (
    condition_id TEXT PRIMARY KEY,
    threshold INTEGER NOT NULL DEFAULT 1 CHECK (threshold BETWEEN 1 AND 32),
    tags_json TEXT NOT NULL DEFAULT '[]',
    announcements_json TEXT NOT NULL,
    attestation_status TEXT NOT NULL DEFAULT 'pending' CHECK (attestation_status IN ('pending', 'attested', 'expired', 'violation')),
    winning_outcome TEXT,
    attested_at BIGINT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    collateral TEXT,
    condition_type TEXT NOT NULL DEFAULT 'enum' CHECK (condition_type IN ('enum', 'numeric')),
    lo_bound BIGINT,
    hi_bound BIGINT,
    precision INTEGER,
    oracle_sigs_json TEXT,
    CHECK ((condition_type = 'enum' AND lo_bound IS NULL AND hi_bound IS NULL AND precision IS NULL)
        OR (condition_type = 'numeric' AND lo_bound IS NOT NULL AND hi_bound IS NOT NULL AND lo_bound < hi_bound AND precision IS NOT NULL)),
    CHECK ((winning_outcome IS NULL AND attested_at IS NULL AND oracle_sigs_json IS NULL AND attestation_status <> 'attested')
        OR (winning_outcome IS NOT NULL AND length(winning_outcome) > 0 AND attested_at IS NOT NULL AND attested_at >= 0 AND oracle_sigs_json IS NOT NULL AND attestation_status <> 'pending')),
    CHECK (oracle_sigs_json IS NULL OR (jsonb_typeof(oracle_sigs_json::jsonb) = 'array' AND jsonb_array_length(oracle_sigs_json::jsonb) BETWEEN threshold AND 64))
);

-- NUT-CTF: Conditional tokens - conditional keysets table
--
-- Standalone table mirroring `keyset` schema plus CTF-specific columns.
-- Conditional keysets live here and are NOT written to `keyset`, which keeps
-- the HashMap<CurrencyUnit, Id> collapse inside `reload_keys_from_db` from
-- clobbering the primary non-conditional keyset for each unit.
CREATE TABLE IF NOT EXISTS conditional_keyset (
    id                     TEXT    PRIMARY KEY,
    unit                   TEXT    NOT NULL,
    active                 BOOLEAN NOT NULL,
    valid_from             BIGINT  NOT NULL,
    valid_to               BIGINT,
    derivation_path        TEXT    NOT NULL,
    derivation_path_index  BIGINT,
    input_fee_ppk          BIGINT  NOT NULL DEFAULT 0,
    amounts                TEXT    NOT NULL,
    issuer_version         TEXT,

    condition_id           TEXT    NOT NULL,
    outcome_collection     TEXT    NOT NULL,
    outcome_collection_id  TEXT    NOT NULL,
    created_at             BIGINT  NOT NULL DEFAULT 0,

    FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
);

-- NEW invariant: at most one active keyset per outcome collection.
CREATE UNIQUE INDEX IF NOT EXISTS conditional_keyset_active_per_collection
    ON conditional_keyset(outcome_collection_id)
    WHERE active = TRUE;

CREATE INDEX IF NOT EXISTS conditional_keyset_condition_id_idx
    ON conditional_keyset(condition_id);

CREATE INDEX IF NOT EXISTS conditional_keyset_outcome_collection_id_idx
    ON conditional_keyset(outcome_collection_id);

-- Use registration timestamp and ID for stable listing seeks.
CREATE INDEX IF NOT EXISTS conditional_keyset_created_at_idx
    ON conditional_keyset(created_at, id);
