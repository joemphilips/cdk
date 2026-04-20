-- Reconcile conditions table schema: add any columns/tables that may be missing
-- from earlier versions of the migration.

-- Add missing columns to conditions table
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS condition_type TEXT NOT NULL DEFAULT 'enum';
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS lo_bound BIGINT;
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS hi_bound BIGINT;
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS "precision" INTEGER;

-- Create missing related tables
CREATE TABLE IF NOT EXISTS condition_partitions (
    condition_id TEXT NOT NULL,
    partition_json TEXT NOT NULL,
    collateral TEXT NOT NULL,
    parent_collection_id TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    created_at BIGINT NOT NULL,
    PRIMARY KEY (condition_id, partition_json),
    FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
);

CREATE TABLE IF NOT EXISTS conditional_keysets (
    condition_id TEXT NOT NULL,
    outcome_collection TEXT NOT NULL,
    outcome_collection_id TEXT NOT NULL,
    keyset_id TEXT NOT NULL,
    created_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (condition_id, outcome_collection),
    FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
);

CREATE INDEX IF NOT EXISTS idx_conditional_keysets_keyset_id ON conditional_keysets(keyset_id);
