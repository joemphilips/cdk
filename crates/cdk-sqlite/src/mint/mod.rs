//! SQLite Mint

use cdk_sql_common::mint::SQLMintAuthDatabase;
use cdk_sql_common::SQLMintDatabase;

use crate::common::SqliteConnectionManager;

pub mod memory;

/// Mint SQLite implementation with rusqlite
pub type MintSqliteDatabase = SQLMintDatabase<SqliteConnectionManager>;

/// Mint Auth database with rusqlite
pub type MintSqliteAuthDatabase = SQLMintAuthDatabase<SqliteConnectionManager>;

#[cfg(test)]
mod test {
    #[cfg(feature = "conditional-tokens")]
    use std::collections::HashSet;
    use std::fs::remove_file;

    #[cfg(feature = "conditional-tokens")]
    use cdk_common::database::mint::ConditionsDatabase;
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::mint_db_conditional_test;
    use cdk_common::mint_db_test;
    use cdk_sql_common::pool::Pool;
    use cdk_sql_common::stmt::query;

    use super::*;
    use crate::common::Config;

    async fn provide_db(_test_name: String) -> MintSqliteDatabase {
        memory::empty().await.unwrap()
    }

    mint_db_test!(provide_db);

    #[cfg(feature = "conditional-tokens")]
    cdk_common::mint_db_conditional_test!(provide_db);

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conditional_keyset_catalogue_first_page_does_not_block_writer() {
        let file =
            std::env::temp_dir().join(format!("cdk_catalogue_fence_{}.sqlite", std::process::id()));
        let _ = remove_file(&file);
        let db = MintSqliteDatabase::new(file.to_string_lossy().as_ref())
            .await
            .expect("file-backed test database should open");

        cdk_common::database::mint::test::conditional_keyset_catalogue_first_page_does_not_block_writer(db)
            .await;

        let _ = remove_file(file);
    }

    #[cfg(all(feature = "conditional-tokens", not(feature = "sqlcipher")))]
    #[tokio::test]
    async fn conditional_keyset_catalogue_rejects_zero_sequence() {
        let file = std::env::temp_dir().join(format!(
            "cdk_catalogue_positive_sequence_{}.sqlite",
            std::process::id()
        ));
        let _ = remove_file(&file);
        let db = MintSqliteDatabase::new(file.to_string_lossy().as_ref())
            .await
            .expect("file-backed test database should migrate");
        drop(db);

        let conn = rusqlite::Connection::open(&file).expect("migrated database should reopen");
        let error = conn
            .execute(
                r#"
                INSERT INTO conditional_keyset (
                    id, unit, active, valid_from, valid_to, derivation_path,
                    derivation_path_index, amounts, input_fee_ppk, issuer_version,
                    condition_id, outcome_collection, outcome_collection_id, created_at,
                    catalogue_sequence
                ) VALUES (
                    'test-keyset', 'sat', 0, 0, NULL, 'm/0',
                    NULL, '[]', 0, NULL,
                    'abababababababababababababababababababababababababababababababab',
                    'test-outcome',
                    'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd', 0,
                    0
                )
                "#,
                [],
            )
            .expect_err("catalogue sequence zero must violate the database invariant");
        assert!(
            error.to_string().contains("catalogue_sequence > 0"),
            "unexpected SQLite error: {error}"
        );

        drop(conn);
        let _ = remove_file(file);
    }

    #[cfg(all(feature = "conditional-tokens", not(feature = "sqlcipher")))]
    #[tokio::test]
    async fn conditional_keyset_catalogue_migration_is_strict_and_append_only() {
        let file = std::env::temp_dir().join(format!(
            "cdk_catalogue_schema_{}.sqlite",
            std::process::id()
        ));
        let _ = remove_file(&file);
        let db = MintSqliteDatabase::new(file.to_string_lossy().as_ref())
            .await
            .expect("file-backed test database should migrate");
        drop(db);

        let conn = rusqlite::Connection::open(&file).expect("migrated database should reopen");
        let strict: i64 = conn
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name = 'conditional_keyset'",
                [],
                |row| row.get(0),
            )
            .expect("conditional_keyset table metadata should exist");
        assert_eq!(strict, 1, "catalogue table must use SQLite STRICT mode");
        let state_strict: i64 = conn
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name = 'conditional_keyset_catalogue_state'",
                [],
                |row| row.get(0),
            )
            .expect("catalogue state table metadata should exist");
        assert_eq!(
            state_strict, 1,
            "catalogue state must use SQLite STRICT mode"
        );

        let indexes = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'conditional_keyset'")
            .expect("index query should prepare")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("index query should run")
            .collect::<Result<HashSet<_>, _>>()
            .expect("index names should decode");
        for required in [
            "conditional_keyset_active_per_collection",
            "conditional_keyset_condition_id_idx",
            "conditional_keyset_outcome_collection_id_idx",
            "conditional_keyset_created_at_idx",
            "idx_conditional_keyset_active_created",
            "conditional_keyset_catalogue_sequence_idx",
        ] {
            assert!(
                indexes.contains(required),
                "missing migrated index {required}"
            );
        }
        for unused in [
            "conditional_keyset_catalogue_active_sequence_idx",
            "conditional_keyset_catalogue_since_sequence_idx",
            "conditional_keyset_catalogue_active_since_sequence_idx",
        ] {
            assert!(
                !indexes.contains(unused),
                "unused strict index {unused} must not ship"
            );
        }

        let triggers = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'conditional_keyset'")
            .expect("trigger query should prepare")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("trigger query should run")
            .collect::<Result<HashSet<_>, _>>()
            .expect("trigger names should decode");
        assert!(triggers.contains("conditional_keyset_catalogue_no_delete"));
        assert!(triggers.contains("conditional_keyset_catalogue_no_update"));

        let state_triggers = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'conditional_keyset_catalogue_state'")
            .expect("state trigger query should prepare")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("state trigger query should run")
            .collect::<Result<HashSet<_>, _>>()
            .expect("state trigger names should decode");
        assert!(state_triggers.contains("conditional_keyset_catalogue_state_no_delete"));
        assert!(state_triggers.contains("conditional_keyset_catalogue_state_no_rollback"));
        assert!(state_triggers.contains("conditional_keyset_catalogue_cursor_key_immutable"));

        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            INSERT INTO conditions (
                condition_id, threshold, tags_json, announcements_json,
                collateral, attestation_status, created_at, condition_type
            ) VALUES (
                'abababababababababababababababababababababababababababababababab',
                1, '[]', '[]', 'sat', 'pending', 0, 'enum'
            );
            INSERT INTO conditional_keyset (
                id, unit, active, valid_from, valid_to, derivation_path,
                derivation_path_index, amounts, input_fee_ppk, issuer_version,
                condition_id, outcome_collection, outcome_collection_id, created_at,
                catalogue_sequence
            ) VALUES (
                'schema-keyset', 'sat', 1, 0, NULL, 'm/0',
                NULL, '[]', 0, NULL,
                'abababababababababababababababababababababababababababababababab',
                'schema-outcome',
                'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                0, 1
            );
            "#,
        )
        .expect("valid catalogue fixture should insert");
        conn.execute(
            "DELETE FROM conditional_keyset WHERE id = 'schema-keyset'",
            [],
        )
        .expect_err("catalogue deletion must fail closed");
        conn.execute(
            "UPDATE conditional_keyset SET outcome_collection = 'changed' WHERE id = 'schema-keyset'",
            [],
        )
        .expect_err("catalogue metadata update must fail closed");
        conn.execute(
            "UPDATE conditional_keyset SET catalogue_sequence = 2 WHERE id = 'schema-keyset'",
            [],
        )
        .expect_err("catalogue sequence update must fail closed");

        let insert_invalid = |id: &str,
                              valid_from: i64,
                              valid_to: Option<i64>,
                              derivation_path_index: Option<i64>,
                              input_fee_ppk: i64,
                              created_at: i64,
                              catalogue_sequence: i64| {
            conn.execute(
                r#"
                INSERT INTO conditional_keyset (
                    id, unit, active, valid_from, valid_to, derivation_path,
                    derivation_path_index, amounts, input_fee_ppk, issuer_version,
                    condition_id, outcome_collection, outcome_collection_id, created_at,
                    catalogue_sequence
                ) VALUES (
                    ?1, 'sat', 0, ?2, ?3, 'm/0', ?4, '[]', ?5, NULL,
                    'abababababababababababababababababababababababababababababababab',
                    ?1 || '-outcome',
                    'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                    ?6, ?7
                )
                "#,
                rusqlite::params![
                    id,
                    valid_from,
                    valid_to,
                    derivation_path_index,
                    input_fee_ppk,
                    created_at,
                    catalogue_sequence,
                ],
            )
        };

        insert_invalid("negative-valid-from", -1, None, None, 0, 0, 2)
            .expect_err("negative valid_from must violate the database invariant");
        insert_invalid("negative-valid-to", 0, Some(-1), None, 0, 0, 3)
            .expect_err("negative valid_to must violate the database invariant");
        insert_invalid("reversed-valid-range", 2, Some(1), None, 0, 0, 4)
            .expect_err("valid_to before valid_from must violate the database invariant");
        insert_invalid("negative-path-index", 0, None, Some(-1), 0, 0, 5)
            .expect_err("negative derivation path index must violate the database invariant");
        insert_invalid("negative-input-fee", 0, None, None, -1, 0, 6)
            .expect_err("negative input fee must violate the database invariant");
        insert_invalid("negative-created-at", 0, None, None, 0, -1, 7)
            .expect_err("negative created_at must violate the database invariant");
        insert_invalid("zero-sequence", 0, None, None, 0, 0, 0)
            .expect_err("zero catalogue sequence must violate the database invariant");
        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET high_water = -1 WHERE singleton = 1",
            [],
        )
        .expect_err("negative high-water must violate the database invariant");
        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET cursor_signing_key = zeroblob(31) WHERE singleton = 1",
            [],
        )
        .expect_err("cursor signing keys must be exactly 32 bytes");
        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET cursor_signing_key = zeroblob(32) WHERE singleton = 1",
            [],
        )
        .expect("cursor signing key should initialize once");
        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET high_water = 1 WHERE singleton = 1",
            [],
        )
        .expect("catalogue high-water should advance");
        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET cursor_signing_key = randomblob(32) WHERE singleton = 1",
            [],
        )
        .expect_err("cursor signing key mutation must fail closed");
        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET high_water = 0 WHERE singleton = 1",
            [],
        )
        .expect_err("catalogue high-water rollback must fail closed");
        conn.execute(
            "DELETE FROM conditional_keyset_catalogue_state WHERE singleton = 1",
            [],
        )
        .expect_err("catalogue singleton deletion must fail closed");
        drop(conn);

        let pool = Pool::<SqliteConnectionManager>::new(file.to_string_lossy().as_ref().into());
        let managed = pool.get().expect("managed connection should open");
        let foreign_keys = query("PRAGMA foreign_keys")
            .expect("foreign-key query should parse")
            .pluck(&*managed)
            .await
            .expect("foreign-key query should run");
        assert_eq!(foreign_keys, Some(cdk_sql_common::stmt::Column::Integer(1)));

        drop(managed);
        drop(pool);
        let _ = remove_file(file);
    }

    #[cfg(all(feature = "conditional-tokens", not(feature = "sqlcipher")))]
    #[tokio::test]
    async fn conditional_keyset_catalogue_rejects_raw_state_and_sequence_corruption() {
        let file = std::env::temp_dir().join(format!(
            "cdk_catalogue_corruption_{}.sqlite",
            std::process::id()
        ));
        let _ = remove_file(&file);
        let db = MintSqliteDatabase::new(file.to_string_lossy().as_ref())
            .await
            .expect("file-backed test database should migrate");
        let conn = rusqlite::Connection::open(&file).expect("raw database should reopen");
        conn.execute_batch(
            r#"
            INSERT INTO conditions (
                condition_id, threshold, tags_json, announcements_json,
                collateral, attestation_status, created_at, condition_type
            ) VALUES ('abababababababababababababababababababababababababababababababab',
                      1, '[]', '[]', 'sat', 'pending', 0, 'enum');
            INSERT INTO conditional_keyset (
                id, unit, active, valid_from, valid_to, derivation_path,
                derivation_path_index, amounts, input_fee_ppk, issuer_version,
                condition_id, outcome_collection, outcome_collection_id, created_at,
                catalogue_sequence
            ) VALUES
                ('0000000000000001', 'sat', 0, 0, NULL, 'm/0''/0''/0''', 0, '[]', 0, NULL,
                 'abababababababababababababababababababababababababababababababab',
                 'A', '0101010101010101010101010101010101010101010101010101010101010101', 0, 1),
                ('0000000000000002', 'sat', 0, 0, NULL, 'm/0''/0''/0''', 0, '[]', 0, NULL,
                 'abababababababababababababababababababababababababababababababab',
                 'B', '0202020202020202020202020202020202020202020202020202020202020202', 0, 2),
                ('0000000000000003', 'sat', 0, 0, NULL, 'm/0''/0''/0''', 0, '[]', 0, NULL,
                 'abababababababababababababababababababababababababababababababab',
                 'C', '0303030303030303030303030303030303030303030303030303030303030303', 0, 3);
            UPDATE conditional_keyset_catalogue_state SET high_water = 3 WHERE singleton = 1;

            -- Simulate offline/raw corruption after proving the migration's
            -- protections in the schema test above.
            DROP TRIGGER conditional_keyset_catalogue_no_delete;
            DROP TRIGGER conditional_keyset_catalogue_state_no_rollback;
            "#,
        )
        .expect("raw corruption fixture should initialize");

        assert_eq!(
            db.get_conditional_keyset_catalogue_page(None, 0, 3)
                .await
                .expect("valid catalogue should read")
                .keysets
                .len(),
            3
        );

        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET high_water = 2 WHERE singleton = 1",
            [],
        )
        .expect("test should force downward divergence");
        assert!(db
            .get_conditional_keyset_catalogue_page(None, 0, 3)
            .await
            .is_err());

        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET high_water = 4 WHERE singleton = 1",
            [],
        )
        .expect("test should force upward divergence");
        assert!(db
            .get_conditional_keyset_catalogue_page(None, 0, 3)
            .await
            .is_err());

        conn.execute(
            "UPDATE conditional_keyset_catalogue_state SET high_water = 3 WHERE singleton = 1",
            [],
        )
        .expect("test should restore the writer fence");
        conn.execute(
            "DELETE FROM conditional_keyset WHERE catalogue_sequence = 2",
            [],
        )
        .expect("test should remove a middle row");
        assert!(db
            .get_conditional_keyset_catalogue_page(None, 0, 3)
            .await
            .is_err());

        conn.execute(
            r#"
            INSERT INTO conditional_keyset (
                id, unit, active, valid_from, valid_to, derivation_path,
                derivation_path_index, amounts, input_fee_ppk, issuer_version,
                condition_id, outcome_collection, outcome_collection_id, created_at,
                catalogue_sequence
            ) VALUES ('0000000000000002', 'sat', 0, 0, NULL, 'm/0''/0''/0''', 0, '[]', 0, NULL,
                      'abababababababababababababababababababababababababababababababab',
                      'B', '0202020202020202020202020202020202020202020202020202020202020202', 0, 2)
            "#,
            [],
        )
        .expect("test should restore the middle row");
        conn.execute(
            "DELETE FROM conditional_keyset WHERE catalogue_sequence = 3",
            [],
        )
        .expect("test should remove the final row");
        assert!(db
            .get_conditional_keyset_catalogue_page(None, 0, 3)
            .await
            .is_err());

        drop(conn);
        drop(db);
        let _ = remove_file(file);
    }

    #[cfg(all(feature = "conditional-tokens", not(feature = "sqlcipher")))]
    #[test]
    fn conditional_keyset_catalogue_migrates_large_legacy_fixture_with_indexed_filters() {
        const LEGACY_ROWS: usize = 10_001;
        let file = std::env::temp_dir().join(format!(
            "cdk_catalogue_large_legacy_{}.sqlite",
            std::process::id()
        ));
        let _ = remove_file(&file);
        let mut conn = rusqlite::Connection::open(&file).expect("legacy database should open");
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            CREATE TABLE conditions (
                condition_id TEXT PRIMARY KEY,
                threshold INTEGER NOT NULL,
                tags_json TEXT NOT NULL,
                announcements_json TEXT NOT NULL,
                collateral TEXT,
                attestation_status TEXT NOT NULL,
                winning_outcome TEXT,
                attested_at INTEGER,
                created_at INTEGER NOT NULL,
                condition_type TEXT NOT NULL,
                lo_bound INTEGER,
                hi_bound INTEGER,
                precision INTEGER
            );
            CREATE TABLE conditional_keyset (
                id TEXT PRIMARY KEY,
                unit TEXT NOT NULL,
                active BOOL NOT NULL,
                valid_from INTEGER NOT NULL,
                valid_to INTEGER,
                derivation_path TEXT NOT NULL,
                derivation_path_index INTEGER,
                input_fee_ppk INTEGER NOT NULL,
                amounts TEXT NOT NULL,
                issuer_version TEXT,
                condition_id TEXT NOT NULL,
                outcome_collection TEXT NOT NULL,
                outcome_collection_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (condition_id) REFERENCES conditions(condition_id)
            );
            INSERT INTO conditions (
                condition_id, threshold, tags_json, announcements_json,
                collateral, attestation_status, created_at, condition_type
            ) VALUES ('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                      1, '[]', '[]', 'sat', 'pending', 0, 'enum');
            "#,
        )
        .expect("legacy schema should initialize");
        let tx = conn.transaction().expect("legacy population should begin");
        {
            let mut insert = tx
                .prepare(
                    r#"
                    INSERT INTO conditional_keyset (
                        id, unit, active, valid_from, valid_to, derivation_path,
                        derivation_path_index, input_fee_ppk, amounts, issuer_version,
                        condition_id, outcome_collection, outcome_collection_id, created_at
                    ) VALUES (?1, 'sat', ?2, 0, NULL, 'm/0', NULL, 0, '[]', NULL,
                              'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                              ?3, ?4, ?5)
                    "#,
                )
                .expect("legacy insert should prepare");
            for index in 1..=LEGACY_ROWS {
                insert
                    .execute(rusqlite::params![
                        format!("legacy-{index:05}"),
                        i64::from(index % 97 == 0),
                        format!("outcome-{index}"),
                        format!("{index:064x}"),
                        index as i64,
                    ])
                    .expect("legacy row should insert");
            }
        }
        tx.commit().expect("legacy population should commit");

        let started = std::time::Instant::now();
        conn.execute_batch(include_str!(
            "../../../cdk-sql-common/src/mint/migrations/sqlite/20260719000000_add_conditional_keyset_catalogue.sql"
        ))
        .expect("large legacy catalogue should migrate");
        let elapsed = started.elapsed();
        eprintln!(
            "migrated {LEGACY_ROWS} legacy conditional keysets in {} ms",
            elapsed.as_millis()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "representative migration exceeded the 30-second predeployment budget: {elapsed:?}"
        );

        let (rows, high_water): (i64, i64) = conn
            .query_row(
                r#"
                SELECT COUNT(*),
                       (SELECT high_water FROM conditional_keyset_catalogue_state WHERE singleton = 1)
                FROM conditional_keyset
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("migrated counts should read");
        assert_eq!(rows, LEGACY_ROWS as i64);
        assert_eq!(high_water, LEGACY_ROWS as i64);

        let bounded_plan = conn
            .prepare(
                r#"
                EXPLAIN QUERY PLAN
                SELECT id FROM conditional_keyset
                WHERE catalogue_sequence > 9900
                  AND catalogue_sequence <= 10001
                ORDER BY catalogue_sequence
                LIMIT 101
                "#,
            )
            .expect("bounded sequence query plan should prepare")
            .query_map([], |row| row.get::<_, String>(3))
            .expect("bounded sequence query plan should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("bounded sequence query plan should decode")
            .join(" | ");
        assert!(
            bounded_plan.contains("conditional_keyset_catalogue_sequence_idx"),
            "raw catalogue window did not use its bounded sequence index: {bounded_plan}"
        );
        assert!(
            !bounded_plan.contains("TEMP") && !bounded_plan.contains("MATERIALIZE"),
            "raw catalogue window unexpectedly materialized or sorted: {bounded_plan}"
        );

        drop(conn);
        let _ = remove_file(file);
    }

    #[tokio::test]
    async fn bug_opening_relative_path() {
        let config: Config = "test.db".into();

        let pool = Pool::<SqliteConnectionManager>::new(config);
        let db = pool.get();
        assert!(db.is_ok());
        let _ = remove_file("test.db");
    }

    #[tokio::test]
    async fn open_legacy_and_migrate() {
        let file = format!(
            "{}/db.sqlite",
            std::env::temp_dir().to_str().unwrap_or_default()
        );

        {
            let _ = remove_file(&file);
            #[cfg(not(feature = "sqlcipher"))]
            let config: Config = file.as_str().into();
            #[cfg(feature = "sqlcipher")]
            let config: Config = (file.as_str(), "test").into();

            let pool = Pool::<SqliteConnectionManager>::new(config);

            let conn = pool.get().expect("valid connection");

            query(include_str!("../../tests/legacy-sqlx.sql"))
                .expect("query")
                .execute(&*conn)
                .await
                .expect("create former db failed");
        }

        #[cfg(not(feature = "sqlcipher"))]
        let conn = MintSqliteDatabase::new(file.as_str()).await;

        #[cfg(feature = "sqlcipher")]
        let conn = MintSqliteDatabase::new((file.as_str(), "test")).await;

        let conn = conn.expect("legacy database should migrate");

        #[cfg(not(feature = "conditional-tokens"))]
        let _ = conn;

        #[cfg(feature = "conditional-tokens")]
        {
            let page = conn
                .get_conditional_keyset_catalogue_page(None, 0, 1)
                .await
                .expect("catalogue state should be readable after legacy migration");
            assert_eq!(page.snapshot, 0);
            assert!(page.keysets.is_empty());
            assert!(!page.has_more);
        }

        let _ = remove_file(&file);
    }
}
