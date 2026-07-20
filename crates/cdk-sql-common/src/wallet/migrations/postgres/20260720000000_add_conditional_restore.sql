CREATE TABLE conditional_restore_high_water (
    mint_url TEXT NOT NULL,
    unit TEXT NOT NULL,
    high_water BYTEA NOT NULL CHECK (octet_length(high_water) = 8),
    PRIMARY KEY (mint_url, unit)
);

ALTER TABLE keyset_counter ALTER COLUMN counter TYPE BIGINT;

ALTER TABLE keyset ADD COLUMN restore_kind TEXT NOT NULL DEFAULT 'ordinary'
    CHECK (restore_kind IN ('ordinary', 'conditional'));
ALTER TABLE key ADD COLUMN restore_kind TEXT NOT NULL DEFAULT 'ordinary'
    CHECK (restore_kind IN ('ordinary', 'conditional'));

CREATE TABLE conditional_restore_keyset (
    id TEXT PRIMARY KEY,
    mint_url TEXT NOT NULL,
    unit TEXT NOT NULL CHECK (octet_length(unit) BETWEEN 1 AND 64),
    active BOOLEAN NOT NULL,
    input_fee_ppk BIGINT CHECK (input_fee_ppk IS NULL OR input_fee_ppk >= 0),
    final_expiry BIGINT CHECK (final_expiry IS NULL OR final_expiry > 0),
    condition_id TEXT NOT NULL CHECK (condition_id ~ '^[0-9a-f]{64}$'),
    outcome_collection TEXT NOT NULL CHECK (octet_length(outcome_collection) BETWEEN 1 AND 16384),
    outcome_collection_id TEXT NOT NULL CHECK (outcome_collection_id ~ '^[0-9a-f]{64}$'),
    registered_at BIGINT NOT NULL CHECK (registered_at >= 0),
    FOREIGN KEY(id) REFERENCES keyset(id) ON UPDATE CASCADE
);

CREATE INDEX conditional_restore_keyset_owner_idx
    ON conditional_restore_keyset(mint_url, unit, id);
CREATE INDEX proof_mint_unit_state_keyset_idx
    ON proof(mint_url, unit, state, keyset_id);

CREATE OR REPLACE FUNCTION reject_conditional_restore_high_water_mutation()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('cdk.conditional_restore_url_migration', true) IS DISTINCT FROM 'on' THEN
            RAISE EXCEPTION 'conditional restore high-water is append-only outside URL migration';
        END IF;
        RETURN OLD;
    ELSIF NEW.high_water < OLD.high_water THEN
        RAISE EXCEPTION 'conditional restore high-water cannot decrease';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER conditional_restore_high_water_immutable
BEFORE UPDATE OR DELETE ON conditional_restore_high_water
FOR EACH ROW EXECUTE FUNCTION reject_conditional_restore_high_water_mutation();

CREATE OR REPLACE FUNCTION reject_conditional_restore_keyset_kind_mutation()
RETURNS trigger AS $$
BEGIN
    IF NEW.restore_kind IS DISTINCT FROM OLD.restore_kind THEN
        RAISE EXCEPTION 'conditional restore keyset namespace is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER conditional_restore_keyset_kind_immutable
BEFORE UPDATE OF restore_kind ON keyset
FOR EACH ROW EXECUTE FUNCTION reject_conditional_restore_keyset_kind_mutation();

CREATE TRIGGER conditional_restore_key_kind_immutable
BEFORE UPDATE OF restore_kind ON key
FOR EACH ROW EXECUTE FUNCTION reject_conditional_restore_keyset_kind_mutation();

CREATE OR REPLACE FUNCTION enforce_conditional_restore_keyset_binding()
RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM keyset k JOIN key p ON p.id = k.id
        WHERE k.id = NEW.id
          AND k.restore_kind = 'conditional'
          AND p.restore_kind = 'conditional'
          AND k.mint_url = NEW.mint_url
          AND k.unit = NEW.unit
          AND k.input_fee_ppk = COALESCE(NEW.input_fee_ppk, 0)
          AND k.final_expiry IS NOT DISTINCT FROM NEW.final_expiry
    ) THEN
        RAISE EXCEPTION 'conditional restore classification is not bound to owned key material';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER conditional_restore_keyset_binding
BEFORE INSERT OR UPDATE OF mint_url ON conditional_restore_keyset
FOR EACH ROW EXECUTE FUNCTION enforce_conditional_restore_keyset_binding();

CREATE OR REPLACE FUNCTION reject_conditional_restore_keyset_mutation()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.unit IS DISTINCT FROM OLD.unit
       OR NEW.active IS DISTINCT FROM OLD.active
       OR NEW.input_fee_ppk IS DISTINCT FROM OLD.input_fee_ppk
       OR NEW.final_expiry IS DISTINCT FROM OLD.final_expiry
       OR NEW.condition_id IS DISTINCT FROM OLD.condition_id
       OR NEW.outcome_collection IS DISTINCT FROM OLD.outcome_collection
       OR NEW.outcome_collection_id IS DISTINCT FROM OLD.outcome_collection_id
       OR NEW.registered_at IS DISTINCT FROM OLD.registered_at THEN
        RAISE EXCEPTION 'conditional restore keyset metadata is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER conditional_restore_keyset_immutable
BEFORE UPDATE OR DELETE ON conditional_restore_keyset
FOR EACH ROW EXECUTE FUNCTION reject_conditional_restore_keyset_mutation();
