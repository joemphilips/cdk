-- Reconcile conditions table schema: add any columns that may be missing
-- from earlier versions of the migration.
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS condition_type TEXT NOT NULL DEFAULT 'enum';
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS lo_bound BIGINT;
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS hi_bound BIGINT;
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS "precision" INTEGER;
