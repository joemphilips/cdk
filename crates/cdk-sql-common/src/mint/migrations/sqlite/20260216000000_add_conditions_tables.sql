-- NUT-CTF: Conditional tokens - conditions table
CREATE TABLE IF NOT EXISTS conditions (
    condition_id TEXT PRIMARY KEY,
    threshold INTEGER NOT NULL DEFAULT 1 CHECK (threshold BETWEEN 1 AND 32),
    tags_json TEXT NOT NULL DEFAULT '[]',
    announcements_json TEXT NOT NULL,
    attestation_status TEXT NOT NULL DEFAULT 'pending' CHECK (attestation_status IN ('pending', 'attested', 'expired', 'violation')),
    winning_outcome TEXT,
    attested_at INTEGER,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    collateral TEXT,
    condition_type TEXT NOT NULL DEFAULT 'enum' CHECK (condition_type IN ('enum', 'numeric')),
    lo_bound INTEGER,
    hi_bound INTEGER,
    precision INTEGER,
    oracle_sigs_json TEXT,
    CHECK ((condition_type = 'enum' AND lo_bound IS NULL AND hi_bound IS NULL AND precision IS NULL)
        OR (condition_type = 'numeric' AND lo_bound IS NOT NULL AND hi_bound IS NOT NULL AND lo_bound < hi_bound AND precision IS NOT NULL)),
    CHECK ((winning_outcome IS NULL AND attested_at IS NULL AND oracle_sigs_json IS NULL AND attestation_status <> 'attested')
        OR (winning_outcome IS NOT NULL AND length(winning_outcome) > 0 AND attested_at IS NOT NULL AND attested_at >= 0 AND oracle_sigs_json IS NOT NULL AND attestation_status <> 'pending')),
    CHECK (oracle_sigs_json IS NULL OR (json_valid(oracle_sigs_json) AND json_type(oracle_sigs_json) = 'array' AND json_array_length(oracle_sigs_json) BETWEEN threshold AND 64))
) STRICT;

-- NUT-CTF: Conditional tokens - conditional keysets table
--
-- Standalone table mirroring `keyset` schema plus CTF-specific columns.
-- Conditional keysets live here and are NOT written to `keyset`, which keeps
-- the HashMap<CurrencyUnit, Id> collapse inside `reload_keys_from_db` from
-- clobbering the primary non-conditional keyset for each unit.
--
-- Active semantics: at most one active keyset per outcome_collection_id, enforced
-- by the partial unique index below. Regular `keyset` table keeps its original
-- "one active per unit" invariant untouched.
CREATE TABLE IF NOT EXISTS conditional_keyset (
    id                     TEXT    PRIMARY KEY,
    unit                   TEXT    NOT NULL,
    active                 BOOL    NOT NULL,
    valid_from             INTEGER NOT NULL,
    valid_to               INTEGER,
    derivation_path        TEXT    NOT NULL,
    derivation_path_index  INTEGER,
    input_fee_ppk          INTEGER NOT NULL DEFAULT 0,
    amounts                TEXT    NOT NULL,
    issuer_version         TEXT,

    condition_id           TEXT    NOT NULL,
    outcome_collection     TEXT    NOT NULL,
    outcome_collection_id  TEXT    NOT NULL,
    created_at             INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
);

-- NEW invariant: at most one active keyset per outcome collection.
-- Nothing prevents multiple collections from each having their own active keyset.
CREATE UNIQUE INDEX IF NOT EXISTS conditional_keyset_active_per_collection
    ON conditional_keyset(outcome_collection_id)
    WHERE active = 1;

CREATE INDEX IF NOT EXISTS conditional_keyset_condition_id_idx
    ON conditional_keyset(condition_id);

CREATE INDEX IF NOT EXISTS conditional_keyset_outcome_collection_id_idx
    ON conditional_keyset(outcome_collection_id);

-- Use registration timestamp and ID for stable listing seeks.
CREATE INDEX IF NOT EXISTS conditional_keyset_created_at_idx
    ON conditional_keyset(created_at, id);
