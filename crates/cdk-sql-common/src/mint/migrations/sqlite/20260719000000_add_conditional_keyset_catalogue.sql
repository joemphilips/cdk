-- Stable, bounded NUT-CTF keyset catalogue pagination. Rebuild the table so
-- catalogue_sequence has no unsafe zero/default state.
--
-- Startup/maintenance migration: the rebuild and backfill require an exclusive
-- DDL maintenance window. This is intentionally not an online migration.
CREATE TABLE conditional_keyset_catalogue_new (
    id                     TEXT    PRIMARY KEY,
    unit                   TEXT    NOT NULL CHECK (
        length(CAST(unit AS BLOB)) BETWEEN 1 AND 64
    ),
    active                 INTEGER NOT NULL CHECK (active IN (0, 1)),
    valid_from             INTEGER NOT NULL CHECK (valid_from >= 0),
    valid_to               INTEGER CHECK (valid_to IS NULL OR valid_to >= 0),
    derivation_path        TEXT    NOT NULL,
    derivation_path_index  INTEGER CHECK (
        derivation_path_index IS NULL OR derivation_path_index >= 0
    ),
    input_fee_ppk          INTEGER NOT NULL CHECK (input_fee_ppk >= 0),
    amounts                TEXT    NOT NULL,
    issuer_version         TEXT,
    condition_id           TEXT    NOT NULL CHECK (
        length(condition_id) = 64
        AND condition_id NOT GLOB '*[^0-9a-f]*'
    ),
    outcome_collection     TEXT    NOT NULL CHECK (
        length(CAST(outcome_collection AS BLOB)) BETWEEN 1 AND 16384
    ),
    outcome_collection_id  TEXT    NOT NULL CHECK (
        length(outcome_collection_id) = 64
        AND outcome_collection_id NOT GLOB '*[^0-9a-f]*'
    ),
    created_at             INTEGER NOT NULL CHECK (created_at >= 0),
    catalogue_sequence     INTEGER NOT NULL CHECK (catalogue_sequence > 0),
    CHECK (valid_to IS NULL OR valid_to >= valid_from),
    FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
) STRICT;

INSERT INTO conditional_keyset_catalogue_new (
    id, unit, active, valid_from, valid_to, derivation_path,
    derivation_path_index, input_fee_ppk, amounts, issuer_version,
    condition_id, outcome_collection, outcome_collection_id, created_at,
    catalogue_sequence
)
SELECT id, unit, active, valid_from, valid_to, derivation_path,
       derivation_path_index, input_fee_ppk, amounts, issuer_version,
       condition_id, outcome_collection, outcome_collection_id, created_at,
       ROW_NUMBER() OVER (ORDER BY created_at, id)
FROM conditional_keyset;

DROP TABLE conditional_keyset;
ALTER TABLE conditional_keyset_catalogue_new RENAME TO conditional_keyset;

CREATE UNIQUE INDEX conditional_keyset_active_per_collection
    ON conditional_keyset(outcome_collection_id)
    WHERE active = 1;
CREATE INDEX conditional_keyset_condition_id_idx
    ON conditional_keyset(condition_id);
CREATE INDEX conditional_keyset_outcome_collection_id_idx
    ON conditional_keyset(outcome_collection_id);
CREATE INDEX conditional_keyset_created_at_idx
    ON conditional_keyset(created_at);
CREATE INDEX idx_conditional_keyset_active_created
    ON conditional_keyset(active, created_at);

CREATE UNIQUE INDEX conditional_keyset_catalogue_sequence_idx
    ON conditional_keyset(catalogue_sequence);

CREATE TABLE conditional_keyset_catalogue_state (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    high_water         INTEGER NOT NULL CHECK (high_water >= 0),
    cursor_signing_key BLOB CHECK (
        cursor_signing_key IS NULL OR length(cursor_signing_key) = 32
    )
) STRICT;

INSERT INTO conditional_keyset_catalogue_state (
    singleton, high_water, cursor_signing_key
)
SELECT 1, COALESCE(MAX(catalogue_sequence), 0), NULL
FROM conditional_keyset;

-- Catalogue rows are recovery authority. Operational lifecycle state must be
-- represented separately rather than mutating or deleting published metadata.
CREATE TRIGGER conditional_keyset_catalogue_no_delete
BEFORE DELETE ON conditional_keyset
BEGIN
    SELECT RAISE(ABORT, 'conditional keyset catalogue rows are append-only');
END;

CREATE TRIGGER conditional_keyset_catalogue_no_update
BEFORE UPDATE ON conditional_keyset
BEGIN
    SELECT RAISE(ABORT, 'conditional keyset catalogue rows are immutable');
END;

-- The singleton and its cursor authority are recovery state. The high-water may
-- only advance, and the signing key may only transition from NULL to one value.
CREATE TRIGGER conditional_keyset_catalogue_state_no_delete
BEFORE DELETE ON conditional_keyset_catalogue_state
BEGIN
    SELECT RAISE(ABORT, 'conditional keyset catalogue state is immutable');
END;

CREATE TRIGGER conditional_keyset_catalogue_state_no_rollback
BEFORE UPDATE OF high_water ON conditional_keyset_catalogue_state
WHEN NEW.high_water < OLD.high_water
BEGIN
    SELECT RAISE(ABORT, 'conditional keyset catalogue high-water cannot decrease');
END;

CREATE TRIGGER conditional_keyset_catalogue_cursor_key_immutable
BEFORE UPDATE OF cursor_signing_key ON conditional_keyset_catalogue_state
WHEN OLD.cursor_signing_key IS NOT NULL
 AND NEW.cursor_signing_key IS NOT OLD.cursor_signing_key
BEGIN
    SELECT RAISE(ABORT, 'conditional keyset catalogue cursor key is immutable');
END;
