-- Stable, bounded NUT-CTF keyset catalogue pagination.
--
-- Startup/maintenance migration: the backfill and table-wide validation require
-- an exclusive DDL maintenance window. This is intentionally not an online
-- migration.
ALTER TABLE conditional_keyset
    ADD COLUMN catalogue_sequence BIGINT;

WITH ranked AS (
    SELECT id, ROW_NUMBER() OVER (ORDER BY created_at, id) AS sequence
    FROM conditional_keyset
)
UPDATE conditional_keyset
SET catalogue_sequence = ranked.sequence
FROM ranked
WHERE ranked.id = conditional_keyset.id;

ALTER TABLE conditional_keyset
    ALTER COLUMN catalogue_sequence SET NOT NULL;
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_catalogue_sequence_positive
    CHECK (catalogue_sequence > 0);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_valid_from_unsigned
    CHECK (valid_from >= 0);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_valid_to_unsigned
    CHECK (valid_to IS NULL OR valid_to >= 0);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_valid_range_ordered
    CHECK (valid_to IS NULL OR valid_to >= valid_from);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_derivation_path_index_unsigned
    CHECK (derivation_path_index IS NULL OR derivation_path_index >= 0);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_input_fee_ppk_unsigned
    CHECK (input_fee_ppk >= 0);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_created_at_unsigned
    CHECK (created_at >= 0);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_unit_bounded
    CHECK (octet_length(unit) BETWEEN 1 AND 64);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_condition_id_canonical
    CHECK (condition_id ~ '^[0-9a-f]{64}$');
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_outcome_collection_bounded
    CHECK (octet_length(outcome_collection) BETWEEN 1 AND 16384);
ALTER TABLE conditional_keyset
    ADD CONSTRAINT conditional_keyset_outcome_collection_id_canonical
    CHECK (outcome_collection_id ~ '^[0-9a-f]{64}$');

CREATE UNIQUE INDEX conditional_keyset_catalogue_sequence_idx
    ON conditional_keyset(catalogue_sequence);

CREATE TABLE conditional_keyset_catalogue_state (
    singleton          SMALLINT PRIMARY KEY CHECK (singleton = 1),
    high_water         BIGINT NOT NULL CHECK (high_water >= 0),
    cursor_signing_key BYTEA CHECK (
        cursor_signing_key IS NULL OR octet_length(cursor_signing_key) = 32
    )
);

INSERT INTO conditional_keyset_catalogue_state (
    singleton, high_water, cursor_signing_key
)
SELECT 1, COALESCE(MAX(catalogue_sequence), 0), NULL
FROM conditional_keyset;

-- Catalogue rows are recovery authority. Operational lifecycle state must be
-- represented separately rather than mutating or deleting published metadata.
CREATE FUNCTION reject_conditional_keyset_catalogue_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'conditional keyset catalogue rows are append-only and immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER conditional_keyset_catalogue_no_delete
BEFORE DELETE ON conditional_keyset
FOR EACH ROW EXECUTE FUNCTION reject_conditional_keyset_catalogue_mutation();

CREATE TRIGGER conditional_keyset_catalogue_no_update
BEFORE UPDATE ON conditional_keyset
FOR EACH ROW EXECUTE FUNCTION reject_conditional_keyset_catalogue_mutation();

CREATE FUNCTION protect_conditional_keyset_catalogue_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'conditional keyset catalogue state is immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.high_water < OLD.high_water THEN
        RAISE EXCEPTION 'conditional keyset catalogue high-water cannot decrease'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.cursor_signing_key IS NOT NULL
       AND NEW.cursor_signing_key IS DISTINCT FROM OLD.cursor_signing_key THEN
        RAISE EXCEPTION 'conditional keyset catalogue cursor key is immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER conditional_keyset_catalogue_state_no_delete
BEFORE DELETE ON conditional_keyset_catalogue_state
FOR EACH ROW EXECUTE FUNCTION protect_conditional_keyset_catalogue_state();

CREATE TRIGGER conditional_keyset_catalogue_state_no_rollback_or_key_mutation
BEFORE UPDATE ON conditional_keyset_catalogue_state
FOR EACH ROW EXECUTE FUNCTION protect_conditional_keyset_catalogue_state();
