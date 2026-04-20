-- NUT-CTF-numeric: Add numeric condition columns to conditions table
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS condition_type TEXT NOT NULL DEFAULT 'enum';
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS lo_bound BIGINT;
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS hi_bound BIGINT;
ALTER TABLE conditions ADD COLUMN IF NOT EXISTS "precision" INTEGER;
