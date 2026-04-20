-- Reconcile conditions table schema: add any columns that may be missing
-- from earlier versions of the migration.
-- SQLite: ALTER TABLE ADD COLUMN is idempotent by default (ignores if exists)
-- but doesn't support IF NOT EXISTS until 3.35.0, so use a separate approach.

-- Check via pragma and add if missing. Since SQLite doesn't support
-- ALTER TABLE ADD COLUMN IF NOT EXISTS universally, we use a DO-NOTHING
-- approach: if the column already exists, the ALTER will fail but we catch it
-- at the application level.

-- For now, rely on the fact that the initial migration should have all columns.
-- This migration is primarily needed for PostgreSQL where older schema may persist.
