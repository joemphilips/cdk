CREATE TABLE conditional_restore_high_water (
    mint_url TEXT NOT NULL,
    unit TEXT NOT NULL,
    high_water BLOB NOT NULL CHECK (typeof(high_water) = 'blob' AND length(high_water) = 8),
    PRIMARY KEY (mint_url, unit)
) STRICT;

CREATE TABLE conditional_restore_high_water_move_authority (
    old_mint_url TEXT PRIMARY KEY,
    new_mint_url TEXT NOT NULL
) STRICT;

ALTER TABLE keyset ADD COLUMN restore_kind TEXT NOT NULL DEFAULT 'ordinary'
    CHECK (restore_kind IN ('ordinary', 'conditional'));
ALTER TABLE key ADD COLUMN restore_kind TEXT NOT NULL DEFAULT 'ordinary'
    CHECK (restore_kind IN ('ordinary', 'conditional'));

CREATE TABLE conditional_restore_keyset (
    id TEXT PRIMARY KEY,
    mint_url TEXT NOT NULL,
    unit TEXT NOT NULL CHECK (length(CAST(unit AS BLOB)) BETWEEN 1 AND 64),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    input_fee_ppk INTEGER CHECK (input_fee_ppk IS NULL OR input_fee_ppk >= 0),
    final_expiry INTEGER CHECK (final_expiry IS NULL OR final_expiry > 0),
    condition_id TEXT NOT NULL CHECK (
        length(condition_id) = 64
        AND condition_id NOT GLOB '*[^0-9a-f]*'
    ),
    outcome_collection TEXT NOT NULL CHECK (
        length(CAST(outcome_collection AS BLOB)) BETWEEN 1 AND 16384
    ),
    outcome_collection_id TEXT NOT NULL CHECK (
        length(outcome_collection_id) = 64
        AND outcome_collection_id NOT GLOB '*[^0-9a-f]*'
    ),
    registered_at INTEGER NOT NULL CHECK (registered_at >= 0),
    FOREIGN KEY(id) REFERENCES keyset(id) ON UPDATE CASCADE
) STRICT;

CREATE INDEX conditional_restore_keyset_owner_idx
    ON conditional_restore_keyset(mint_url, unit, id);
CREATE INDEX proof_mint_unit_state_keyset_idx
    ON proof(mint_url, unit, state, keyset_id);

CREATE TRIGGER conditional_restore_high_water_no_decrease
BEFORE UPDATE OF high_water ON conditional_restore_high_water
WHEN NEW.high_water < OLD.high_water
BEGIN
    SELECT RAISE(ABORT, 'conditional restore high-water cannot decrease');
END;

CREATE TRIGGER conditional_restore_high_water_no_delete
BEFORE DELETE ON conditional_restore_high_water
WHEN NOT EXISTS (
    SELECT 1 FROM conditional_restore_high_water_move_authority
    WHERE old_mint_url = OLD.mint_url
)
BEGIN
    SELECT RAISE(ABORT, 'conditional restore high-water is append-only outside URL migration');
END;

CREATE TRIGGER conditional_restore_keyset_kind_immutable
BEFORE UPDATE OF restore_kind ON keyset
WHEN NEW.restore_kind <> OLD.restore_kind
BEGIN
    SELECT RAISE(ABORT, 'conditional restore keyset namespace is immutable');
END;

CREATE TRIGGER conditional_restore_key_kind_immutable
BEFORE UPDATE OF restore_kind ON key
WHEN NEW.restore_kind <> OLD.restore_kind
BEGIN
    SELECT RAISE(ABORT, 'conditional restore key namespace is immutable');
END;

CREATE TRIGGER conditional_restore_keyset_binding_insert
BEFORE INSERT ON conditional_restore_keyset
WHEN NOT EXISTS (
    SELECT 1
    FROM keyset k JOIN key p ON p.id = k.id
    WHERE k.id = NEW.id
      AND k.restore_kind = 'conditional'
      AND p.restore_kind = 'conditional'
      AND k.mint_url = NEW.mint_url
      AND k.unit = NEW.unit
      AND k.input_fee_ppk = COALESCE(NEW.input_fee_ppk, 0)
      AND k.final_expiry IS NEW.final_expiry
)
BEGIN
    SELECT RAISE(ABORT, 'conditional restore classification is not bound to owned key material');
END;

CREATE TRIGGER conditional_restore_keyset_binding_update
BEFORE UPDATE OF mint_url ON conditional_restore_keyset
WHEN NOT EXISTS (
    SELECT 1 FROM keyset k
    WHERE k.id = NEW.id
      AND k.restore_kind = 'conditional'
      AND k.mint_url = NEW.mint_url
      AND k.unit = NEW.unit
      AND k.input_fee_ppk = COALESCE(NEW.input_fee_ppk, 0)
      AND k.final_expiry IS NEW.final_expiry
)
BEGIN
    SELECT RAISE(ABORT, 'conditional restore classification owner is inconsistent');
END;

CREATE TRIGGER conditional_restore_keyset_immutable_metadata
BEFORE UPDATE OF id, unit, active, input_fee_ppk, final_expiry,
                 condition_id, outcome_collection, outcome_collection_id, registered_at
ON conditional_restore_keyset
BEGIN
    SELECT RAISE(ABORT, 'conditional restore keyset metadata is immutable');
END;

CREATE TRIGGER conditional_restore_keyset_no_delete
BEFORE DELETE ON conditional_restore_keyset
BEGIN
    SELECT RAISE(ABORT, 'conditional restore keyset metadata is append-only');
END;
