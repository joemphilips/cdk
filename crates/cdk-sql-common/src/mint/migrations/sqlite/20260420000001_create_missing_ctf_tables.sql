-- SQLite counterpart: create condition-related tables if missing.

CREATE TABLE IF NOT EXISTS condition_partitions (
    condition_id TEXT NOT NULL,
    partition_json TEXT NOT NULL,
    collateral TEXT NOT NULL,
    parent_collection_id TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (condition_id, partition_json),
    FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
);

CREATE TABLE IF NOT EXISTS conditional_keysets (
    condition_id TEXT NOT NULL,
    outcome_collection TEXT NOT NULL,
    outcome_collection_id TEXT NOT NULL,
    keyset_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (condition_id, outcome_collection),
    FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
);

CREATE INDEX IF NOT EXISTS idx_conditional_keysets_keyset_id ON conditional_keysets(keyset_id);
