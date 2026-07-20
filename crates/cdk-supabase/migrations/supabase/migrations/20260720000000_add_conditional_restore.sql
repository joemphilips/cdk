-- Atomic wallet storage for conditional-token recovery.

ALTER TABLE keyset ADD COLUMN IF NOT EXISTS restore_kind TEXT NOT NULL DEFAULT 'ordinary'
    CHECK (restore_kind IN ('ordinary', 'conditional'));
ALTER TABLE key ADD COLUMN IF NOT EXISTS restore_kind TEXT NOT NULL DEFAULT 'ordinary'
    CHECK (restore_kind IN ('ordinary', 'conditional'));
ALTER TABLE proof ADD COLUMN IF NOT EXISTS restore_fingerprint TEXT;
ALTER TABLE proof ADD COLUMN IF NOT EXISTS p2pk_e TEXT;
ALTER TABLE keyset_counter ALTER COLUMN counter TYPE BIGINT;

CREATE TABLE IF NOT EXISTS conditional_restore_high_water (
    mint_url TEXT NOT NULL,
    unit TEXT NOT NULL CHECK (octet_length(unit) BETWEEN 1 AND 64),
    high_water TEXT NOT NULL CHECK (high_water ~ '^[0-9a-f]{16}$'),
    wallet_id TEXT NOT NULL DEFAULT public.get_current_wallet_id(),
    PRIMARY KEY (mint_url, unit, wallet_id)
);

CREATE TABLE IF NOT EXISTS conditional_restore_keyset (
    id TEXT NOT NULL,
    mint_url TEXT NOT NULL,
    unit TEXT NOT NULL CHECK (octet_length(unit) BETWEEN 1 AND 64),
    active BOOLEAN NOT NULL,
    input_fee_ppk BIGINT,
    final_expiry BIGINT CHECK (final_expiry IS NULL OR final_expiry > 0),
    condition_id TEXT NOT NULL CHECK (condition_id ~ '^[0-9a-f]{64}$'),
    outcome_collection TEXT NOT NULL CHECK (octet_length(outcome_collection) BETWEEN 1 AND 16384),
    outcome_collection_id TEXT NOT NULL CHECK (outcome_collection_id ~ '^[0-9a-f]{64}$'),
    registered_at BIGINT NOT NULL CHECK (registered_at >= 0),
    wallet_id TEXT NOT NULL DEFAULT public.get_current_wallet_id(),
    PRIMARY KEY (id, wallet_id)
);

CREATE INDEX IF NOT EXISTS conditional_restore_keyset_owner_idx
    ON conditional_restore_keyset(wallet_id, mint_url, unit, id);
CREATE INDEX IF NOT EXISTS proof_wallet_mint_unit_state_keyset_idx
    ON proof(wallet_id, mint_url, unit, state, keyset_id);

ALTER TABLE conditional_restore_high_water ENABLE ROW LEVEL SECURITY;
ALTER TABLE conditional_restore_keyset ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users access own conditional restore fences" ON conditional_restore_high_water;
CREATE POLICY "Users access own conditional restore fences" ON conditional_restore_high_water
    FOR ALL USING (wallet_id = public.get_current_wallet_id())
    WITH CHECK (wallet_id = public.get_current_wallet_id());
DROP POLICY IF EXISTS "Users access own conditional restore keysets" ON conditional_restore_keyset;
CREATE POLICY "Users access own conditional restore keysets" ON conditional_restore_keyset
    FOR ALL USING (wallet_id = public.get_current_wallet_id())
    WITH CHECK (wallet_id = public.get_current_wallet_id());
GRANT SELECT ON conditional_restore_high_water, conditional_restore_keyset TO authenticated;

CREATE OR REPLACE FUNCTION public.reject_conditional_restore_direct_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $body$
BEGIN
    IF current_setting('cdk.conditional_restore_mutation', true) IS DISTINCT FROM 'on'
       AND ((TG_OP = 'DELETE' AND OLD.restore_kind = 'conditional')
            OR (TG_OP <> 'DELETE' AND NEW.restore_kind = 'conditional')
            OR (TG_OP = 'UPDATE' AND OLD.restore_kind = 'conditional')) THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.restore_kind IS DISTINCT FROM OLD.restore_kind THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$body$;

DROP TRIGGER IF EXISTS conditional_restore_keyset_guard ON keyset;
CREATE TRIGGER conditional_restore_keyset_guard
BEFORE INSERT OR UPDATE OR DELETE ON keyset
FOR EACH ROW EXECUTE FUNCTION public.reject_conditional_restore_direct_mutation();
DROP TRIGGER IF EXISTS conditional_restore_key_guard ON key;
CREATE TRIGGER conditional_restore_key_guard
BEFORE INSERT OR UPDATE OR DELETE ON key
FOR EACH ROW EXECUTE FUNCTION public.reject_conditional_restore_direct_mutation();

CREATE OR REPLACE FUNCTION public.reject_conditional_restore_classification_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $body$
BEGIN
    IF current_setting('cdk.conditional_restore_mutation', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;
    IF TG_OP = 'DELETE'
       OR (TG_OP = 'UPDATE' AND (
          NEW.id IS DISTINCT FROM OLD.id
       OR NEW.unit IS DISTINCT FROM OLD.unit
       OR NEW.active IS DISTINCT FROM OLD.active
       OR NEW.input_fee_ppk IS DISTINCT FROM OLD.input_fee_ppk
       OR NEW.final_expiry IS DISTINCT FROM OLD.final_expiry
       OR NEW.condition_id IS DISTINCT FROM OLD.condition_id
       OR NEW.outcome_collection IS DISTINCT FROM OLD.outcome_collection
       OR NEW.outcome_collection_id IS DISTINCT FROM OLD.outcome_collection_id
       OR NEW.registered_at IS DISTINCT FROM OLD.registered_at)) THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;
    IF TG_OP <> 'DELETE' AND NOT EXISTS (
        SELECT 1 FROM keyset s JOIN key k USING (id, wallet_id)
        WHERE s.id = NEW.id AND s.wallet_id = NEW.wallet_id
          AND s.restore_kind = 'conditional' AND k.restore_kind = 'conditional'
          AND s.mint_url = NEW.mint_url AND s.unit = NEW.unit
          AND s.input_fee_ppk = COALESCE(NEW.input_fee_ppk, 0)
          AND s.final_expiry IS NOT DISTINCT FROM NEW.final_expiry
    ) THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;
    RETURN NEW;
END
$body$;

DROP TRIGGER IF EXISTS conditional_restore_keyset_immutable ON conditional_restore_keyset;
CREATE TRIGGER conditional_restore_keyset_immutable
BEFORE INSERT OR UPDATE OR DELETE ON conditional_restore_keyset
FOR EACH ROW EXECUTE FUNCTION public.reject_conditional_restore_classification_mutation();

CREATE OR REPLACE FUNCTION public.advance_conditional_restore_high_water(
    p_mint_url TEXT,
    p_unit TEXT,
    p_observed_high_water TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $body$
DECLARE
    v_wallet TEXT := public.get_current_wallet_id();
    v_effective TEXT;
BEGIN
    IF p_observed_high_water !~ '^[0-9a-f]{16}$' THEN
        RAISE EXCEPTION 'invalid_conditional_restore_high_water';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext(v_wallet || E'\n' || p_mint_url));
    INSERT INTO conditional_restore_high_water (mint_url, unit, high_water, wallet_id)
    VALUES (p_mint_url, p_unit, p_observed_high_water, v_wallet)
    ON CONFLICT (mint_url, unit, wallet_id) DO UPDATE
    SET high_water = GREATEST(conditional_restore_high_water.high_water, EXCLUDED.high_water)
    RETURNING high_water INTO v_effective;
    RETURN v_effective;
END
$body$;

CREATE OR REPLACE FUNCTION public.commit_conditional_restore(
    p_mint_url TEXT,
    p_unit TEXT,
    p_observed_high_water TEXT,
    p_mode TEXT,
    p_conditional_keyset JSONB,
    p_keyset JSONB,
    p_keys JSONB,
    p_proofs JSONB,
    p_spent_proofs JSONB,
    p_counter_floor BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $body$
DECLARE
    v_wallet TEXT := public.get_current_wallet_id();
    v_id TEXT := p_keyset->>'id';
    v_effective TEXT;
    v_existing conditional_restore_keyset%ROWTYPE;
    v_proof JSONB;
    v_stored proof%ROWTYPE;
    v_classified BOOLEAN := FALSE;
BEGIN
    IF p_mode NOT IN ('held_proofs', 'progress_only')
       OR p_counter_floor < 0 OR p_counter_floor > 4294967295
       OR p_observed_high_water !~ '^[0-9a-f]{16}$'
       OR p_conditional_keyset->>'id' IS DISTINCT FROM v_id
       OR p_conditional_keyset->>'unit' IS DISTINCT FROM p_unit
       OR p_keyset->>'mint_url' IS DISTINCT FROM p_mint_url
       OR p_keyset->>'unit' IS DISTINCT FROM p_unit
       OR (p_keyset->>'active')::BOOLEAN IS DISTINCT FROM FALSE
       OR p_keys->>'id' IS DISTINCT FROM v_id
       OR (p_mode = 'held_proofs' AND jsonb_array_length(p_proofs) = 0)
       OR (p_mode = 'progress_only' AND jsonb_array_length(p_proofs) <> 0)
       OR jsonb_array_length(p_proofs) + jsonb_array_length(p_spent_proofs) <>
          (SELECT count(DISTINCT item->>'y')
           FROM jsonb_array_elements(p_proofs || p_spent_proofs) AS item) THEN
        RAISE EXCEPTION 'invalid_conditional_restore_admission';
    END IF;
    PERFORM set_config('cdk.conditional_restore_mutation', 'on', true);
    v_effective := public.advance_conditional_restore_high_water(
        p_mint_url, p_unit, p_observed_high_water
    );

    IF (p_conditional_keyset->>'final_expiry') IS NOT NULL
       AND (v_effective >= '8000000000000000'
            OR (p_conditional_keyset->>'final_expiry')::BIGINT
               <= (('x' || v_effective)::bit(64)::BIGINT)) THEN
        RETURN jsonb_build_object('result', 'expired', 'effective_time', v_effective);
    END IF;

    SELECT * INTO v_existing
    FROM conditional_restore_keyset
    WHERE id = v_id AND wallet_id = v_wallet;
    v_classified := FOUND;
    IF v_classified AND (
        v_existing.mint_url IS DISTINCT FROM p_mint_url
        OR v_existing.unit IS DISTINCT FROM p_unit
        OR v_existing.active IS DISTINCT FROM (p_conditional_keyset->>'active')::BOOLEAN
        OR v_existing.input_fee_ppk IS DISTINCT FROM (p_conditional_keyset->>'input_fee_ppk')::BIGINT
        OR v_existing.final_expiry IS DISTINCT FROM (p_conditional_keyset->>'final_expiry')::BIGINT
        OR v_existing.condition_id IS DISTINCT FROM p_conditional_keyset->>'condition_id'
        OR v_existing.outcome_collection IS DISTINCT FROM p_conditional_keyset->>'outcome_collection'
        OR v_existing.outcome_collection_id IS DISTINCT FROM p_conditional_keyset->>'outcome_collection_id'
        OR v_existing.registered_at IS DISTINCT FROM (p_conditional_keyset->>'registered_at')::BIGINT
    ) THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;

    IF NOT v_classified AND EXISTS (
        SELECT 1 FROM keyset WHERE id = v_id AND wallet_id = v_wallet
        UNION ALL SELECT 1 FROM key WHERE id = v_id AND wallet_id = v_wallet
    ) THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;

    IF p_mode = 'held_proofs' AND NOT v_classified THEN
        INSERT INTO keyset (
            id, wallet_id, mint_url, unit, active, input_fee_ppk,
            final_expiry, keyset_u32, restore_kind
        ) VALUES (
            v_id, v_wallet, p_mint_url, p_unit, FALSE,
            (p_keyset->>'input_fee_ppk')::BIGINT,
            (p_keyset->>'final_expiry')::BIGINT,
            (p_keyset->>'keyset_u32')::BIGINT, 'conditional'
        );
        INSERT INTO key (id, wallet_id, keys, keyset_u32, restore_kind)
        VALUES (
            v_id, v_wallet, p_keys->>'keys',
            (p_keys->>'keyset_u32')::BIGINT, 'conditional'
        );
        INSERT INTO conditional_restore_keyset (
            id, wallet_id, mint_url, unit, active, input_fee_ppk, final_expiry,
            condition_id, outcome_collection, outcome_collection_id, registered_at
        ) VALUES (
            v_id, v_wallet, p_mint_url, p_unit,
            (p_conditional_keyset->>'active')::BOOLEAN,
            (p_conditional_keyset->>'input_fee_ppk')::BIGINT,
            (p_conditional_keyset->>'final_expiry')::BIGINT,
            p_conditional_keyset->>'condition_id',
            p_conditional_keyset->>'outcome_collection',
            p_conditional_keyset->>'outcome_collection_id',
            (p_conditional_keyset->>'registered_at')::BIGINT
        );
        v_classified := TRUE;
    ELSIF v_classified AND NOT EXISTS (
        SELECT 1 FROM keyset s JOIN key k USING (id, wallet_id)
        WHERE s.id = v_id AND s.wallet_id = v_wallet
          AND s.restore_kind = 'conditional' AND k.restore_kind = 'conditional'
          AND s.mint_url = p_mint_url AND s.unit = p_unit
          AND s.active = FALSE
          AND s.input_fee_ppk = (p_keyset->>'input_fee_ppk')::BIGINT
          AND s.final_expiry IS NOT DISTINCT FROM (p_keyset->>'final_expiry')::BIGINT
          AND k.keys = p_keys->>'keys'
    ) THEN
        RAISE EXCEPTION 'conditional_restore_metadata_conflict';
    END IF;

    IF p_mode = 'progress_only' AND NOT v_classified THEN
        FOR v_proof IN SELECT value FROM jsonb_array_elements(p_spent_proofs) LOOP
            IF v_proof->>'state' IS DISTINCT FROM 'SPENT'
               OR v_proof->>'mint_url' IS DISTINCT FROM p_mint_url
               OR v_proof->>'unit' IS DISTINCT FROM p_unit
               OR v_proof->>'keyset_id' IS DISTINCT FROM v_id
               OR v_proof->>'restore_fingerprint' !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'invalid_conditional_restore_admission';
            END IF;
            IF EXISTS (SELECT 1 FROM proof WHERE y = v_proof->>'y' AND wallet_id = v_wallet) THEN
                RAISE EXCEPTION 'conditional_restore_metadata_conflict';
            END IF;
        END LOOP;
    ELSE
        FOR v_proof IN SELECT value FROM jsonb_array_elements(p_proofs) LOOP
            IF v_proof->>'state' NOT IN ('UNSPENT', 'PENDING')
               OR v_proof->>'mint_url' IS DISTINCT FROM p_mint_url
               OR v_proof->>'unit' IS DISTINCT FROM p_unit
               OR v_proof->>'keyset_id' IS DISTINCT FROM v_id
               OR v_proof->>'restore_fingerprint' !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'invalid_conditional_restore_admission';
            END IF;
            SELECT * INTO v_stored FROM proof
            WHERE y = v_proof->>'y' AND wallet_id = v_wallet;
            IF FOUND THEN
                IF v_stored.mint_url IS DISTINCT FROM p_mint_url
                   OR v_stored.unit IS DISTINCT FROM p_unit
                   OR v_stored.keyset_id IS DISTINCT FROM v_id
                   OR v_stored.amount IS DISTINCT FROM (v_proof->>'amount')::BIGINT
                   OR v_stored.spending_condition IS DISTINCT FROM v_proof->>'spending_condition'
                   OR v_stored.restore_fingerprint IS DISTINCT FROM v_proof->>'restore_fingerprint' THEN
                    RAISE EXCEPTION 'conditional_restore_metadata_conflict';
                END IF;
                IF v_stored.state = 'UNSPENT' AND v_proof->>'state' = 'PENDING' THEN
                    UPDATE proof SET state = 'PENDING'
                    WHERE y = v_proof->>'y' AND wallet_id = v_wallet
                      AND state = 'UNSPENT';
                END IF;
            ELSE
                INSERT INTO proof (
                    y, wallet_id, mint_url, state, spending_condition, unit, amount,
                    keyset_id, secret, c, witness, dleq_e, dleq_s, dleq_r,
                    used_by_operation, created_by_operation, p2pk_e, restore_fingerprint
                ) VALUES (
                    v_proof->>'y', v_wallet, p_mint_url, v_proof->>'state',
                    v_proof->>'spending_condition', p_unit, (v_proof->>'amount')::BIGINT,
                    v_id, v_proof->>'secret', v_proof->>'c', v_proof->>'witness',
                    v_proof->>'dleq_e', v_proof->>'dleq_s', v_proof->>'dleq_r',
                    v_proof->>'used_by_operation', v_proof->>'created_by_operation',
                    v_proof->>'p2pk_e', v_proof->>'restore_fingerprint'
                );
            END IF;
        END LOOP;

        FOR v_proof IN SELECT value FROM jsonb_array_elements(p_spent_proofs) LOOP
            IF v_proof->>'state' IS DISTINCT FROM 'SPENT'
               OR v_proof->>'mint_url' IS DISTINCT FROM p_mint_url
               OR v_proof->>'unit' IS DISTINCT FROM p_unit
               OR v_proof->>'keyset_id' IS DISTINCT FROM v_id
               OR v_proof->>'restore_fingerprint' !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'invalid_conditional_restore_admission';
            END IF;
            SELECT * INTO v_stored FROM proof
            WHERE y = v_proof->>'y' AND wallet_id = v_wallet;
            IF FOUND THEN
                IF v_stored.mint_url IS DISTINCT FROM p_mint_url
                   OR v_stored.unit IS DISTINCT FROM p_unit
                   OR v_stored.keyset_id IS DISTINCT FROM v_id
                   OR v_stored.amount IS DISTINCT FROM (v_proof->>'amount')::BIGINT
                   OR v_stored.spending_condition IS DISTINCT FROM v_proof->>'spending_condition'
                   OR v_stored.restore_fingerprint IS DISTINCT FROM v_proof->>'restore_fingerprint' THEN
                    RAISE EXCEPTION 'conditional_restore_metadata_conflict';
                END IF;
                UPDATE proof SET state = 'SPENT'
                WHERE y = v_proof->>'y' AND wallet_id = v_wallet;
            END IF;
        END LOOP;
    END IF;

    INSERT INTO keyset_counter (keyset_id, wallet_id, counter)
    VALUES (v_id, v_wallet, p_counter_floor)
    ON CONFLICT (keyset_id, wallet_id) DO UPDATE
    SET counter = GREATEST(keyset_counter.counter, EXCLUDED.counter);

    RETURN jsonb_build_object('result', p_mode, 'effective_time', v_effective);
END
$body$;

CREATE OR REPLACE FUNCTION public.get_ordinary_proofs(
    p_mint_url TEXT,
    p_unit TEXT
)
RETURNS SETOF proof
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $body$
    SELECT p.* FROM proof p
    WHERE p.wallet_id = public.get_current_wallet_id()
      AND p.mint_url = p_mint_url AND p.unit = p_unit
      AND NOT EXISTS (
          SELECT 1 FROM conditional_restore_keyset c
          WHERE c.wallet_id = p.wallet_id AND c.id = p.keyset_id
      )
$body$;

CREATE OR REPLACE FUNCTION public.update_mint_url_atomic(
    p_old_mint_url TEXT,
    p_new_mint_url TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $body$
DECLARE
    v_wallet TEXT := public.get_current_wallet_id();
BEGIN
    IF p_old_mint_url = p_new_mint_url THEN RETURN; END IF;
    PERFORM pg_advisory_xact_lock(hashtext(v_wallet || E'\n' || LEAST(p_old_mint_url, p_new_mint_url)));
    PERFORM pg_advisory_xact_lock(hashtext(v_wallet || E'\n' || GREATEST(p_old_mint_url, p_new_mint_url)));
    PERFORM set_config('cdk.conditional_restore_mutation', 'on', true);

    INSERT INTO conditional_restore_high_water (mint_url, unit, high_water, wallet_id)
    SELECT p_new_mint_url, unit, high_water, wallet_id
    FROM conditional_restore_high_water
    WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet
    ON CONFLICT (mint_url, unit, wallet_id) DO UPDATE
    SET high_water = GREATEST(conditional_restore_high_water.high_water, EXCLUDED.high_water);
    DELETE FROM conditional_restore_high_water
    WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;

    IF EXISTS (
        SELECT 1 FROM mint WHERE mint_url = p_new_mint_url AND wallet_id = v_wallet
    ) THEN
        DELETE FROM mint WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;
    ELSE
        UPDATE mint SET mint_url = p_new_mint_url
        WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;
    END IF;
    UPDATE keyset SET mint_url = p_new_mint_url
    WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;
    UPDATE conditional_restore_keyset SET mint_url = p_new_mint_url
    WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;
    UPDATE mint_quote SET mint_url = p_new_mint_url
    WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;
    UPDATE proof SET mint_url = p_new_mint_url
    WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;
    UPDATE transactions SET mint_url = p_new_mint_url
    WHERE mint_url = p_old_mint_url AND wallet_id = v_wallet;
END
$body$;

-- PostgreSQL overloads functions by argument type. The v1 migration installed
-- an INTEGER overload, so CREATE OR REPLACE with BIGINT would otherwise leave
-- both RPC candidates visible to PostgREST.
DROP FUNCTION IF EXISTS public.increment_keyset_counter(TEXT, INTEGER);

CREATE OR REPLACE FUNCTION public.increment_keyset_counter(
    p_keyset_id TEXT,
    p_increment BIGINT DEFAULT 1
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $body$
DECLARE v_counter BIGINT;
BEGIN
    IF p_increment < 0 OR p_increment > 4294967295 THEN
        RAISE EXCEPTION 'keyset_counter_overflow';
    END IF;
    INSERT INTO keyset_counter (keyset_id, wallet_id, counter)
    VALUES (p_keyset_id, public.get_current_wallet_id(), p_increment)
    ON CONFLICT (keyset_id, wallet_id) DO UPDATE
    SET counter = keyset_counter.counter + EXCLUDED.counter
    WHERE keyset_counter.counter <= 4294967295 - EXCLUDED.counter
    RETURNING counter INTO v_counter;
    IF v_counter IS NULL THEN RAISE EXCEPTION 'keyset_counter_overflow'; END IF;
    RETURN v_counter;
END
$body$;

GRANT EXECUTE ON FUNCTION public.advance_conditional_restore_high_water(TEXT, TEXT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.commit_conditional_restore(TEXT, TEXT, TEXT, TEXT, JSONB, JSONB, JSONB, JSONB, JSONB, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_ordinary_proofs(TEXT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.update_mint_url_atomic(TEXT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.increment_keyset_counter(TEXT, BIGINT) TO authenticated;

INSERT INTO schema_info (key, value)
VALUES ('schema_version', '6')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
