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
    use std::fs::remove_file;
    use std::time::Duration;

    #[cfg(feature = "conditional-tokens")]
    use cdk_common::database::mint::{ConditionsDatabase, Database};
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::mint::StoredCondition;
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
    async fn condition_lock_serializes_attestation_across_connections() {
        let path =
            std::env::temp_dir().join(format!("cdk-condition-lock-{}.db", uuid::Uuid::new_v4()));
        let db = std::sync::Arc::new(MintSqliteDatabase::new(path.clone()).await.unwrap());
        let condition = StoredCondition {
            condition_id: "ac".repeat(32),
            threshold: 1,
            tags_json: "[]".to_string(),
            announcements_json: r#"["deadbeef"]"#.to_string(),
            collateral: Some(cdk_common::CurrencyUnit::Sat),
            attestation_status: "pending".to_string(),
            winning_outcome: None,
            attested_at: None,
            oracle_sigs: None,
            created_at: 1_000_000,
            condition_type: "enum".to_string(),
            lo_bound: None,
            hi_bound: None,
            precision: None,
        };
        db.add_condition(condition.clone()).await.unwrap();

        let mut condition_tx = db.begin_transaction().await.unwrap();
        condition_tx
            .get_condition_for_update(&condition.condition_id)
            .await
            .unwrap()
            .unwrap();

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let attestation_db = db.clone();
        let condition_id = condition.condition_id.clone();
        let mut attestation = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            attestation_db
                .update_condition_attestation(
                    &condition_id,
                    "attested",
                    Some("YES"),
                    Some(2_000_000),
                    &cdk_common::nuts::nut_ctf::test_helpers::create_oracle_witness(
                        &cdk_common::nuts::nut_ctf::test_helpers::create_test_oracle(),
                        "YES",
                    )
                    .oracle_sigs,
                )
                .await
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut attestation)
                .await
                .is_err(),
            "attestation must remain blocked while the condition transaction is open"
        );

        condition_tx.commit().await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), attestation)
            .await
            .expect("attestation should resume after commit")
            .expect("attestation task")
            .unwrap());

        drop(db);
        remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn bug_opening_relative_path() {
        let config: Config = "test.db".into();

        let pool = Pool::<SqliteConnectionManager>::new(config);
        let db = pool.get().await;
        assert!(db.is_ok());
        let _ = remove_file("test.db");
    }

    #[tokio::test]
    async fn exhausted_in_memory_pool_times_out() {
        let config: Config = ":memory:".into();
        let pool = Pool::<SqliteConnectionManager>::new(config);

        let _conn = pool.get().await.expect("valid connection");
        let result = pool.get_timeout(Duration::from_millis(10)).await;

        assert!(matches!(result, Err(cdk_sql_common::pool::Error::Timeout)));
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

            let conn = pool.get().await.expect("valid connection");

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

        assert!(conn.is_ok(), "Failed with {:?}", conn.unwrap_err());

        let _ = remove_file(&file);
    }
}

#[cfg(all(test, feature = "conditional-tokens"))]
mod d2_evidence_storage_tests {
    use super::*;
    use cdk_common::database::mint::{ConditionsDatabase, Database};
    use cdk_common::mint::StoredCondition;
    use cdk_common::nuts::nut_ctf::test_helpers::{
        create_oracle_witness, create_test_announcement, create_test_oracle,
    };
    use cdk_sql_common::pool::Pool;
    use cdk_sql_common::stmt::query;

    #[tokio::test]
    async fn d2_evidence_constraints_and_strict_provider_reads() {
        let path = std::env::temp_dir().join(format!("cdk-d2-storage-{}.db", uuid::Uuid::new_v4()));
        let db = MintSqliteDatabase::new(path.clone()).await.unwrap();
        let pool = Pool::<crate::common::SqliteConnectionManager>::new(
            crate::common::Config::from(path.clone()),
        );
        let conn = pool.get().await.unwrap();
        let oracle = create_test_oracle();
        let (_, announcement) =
            create_test_announcement(&oracle, &["YES", "NO"], "storage-evidence");
        let condition = StoredCondition {
            condition_id: "dd".repeat(32),
            threshold: 1,
            tags_json: "[]".to_string(),
            announcements_json: serde_json::to_string(&vec![announcement]).unwrap(),
            collateral: Some(cdk_common::CurrencyUnit::Sat),
            attestation_status: "pending".to_string(),
            winning_outcome: None,
            attested_at: None,
            oracle_sigs: None,
            created_at: 1,
            condition_type: "enum".to_string(),
            lo_bound: None,
            hi_bound: None,
            precision: None,
        };
        db.add_condition(condition.clone()).await.unwrap();
        for mutation in ["attestation_status = 'unknown'", "winning_outcome = 'YES'",
            "attestation_status = 'attested'",
            "attestation_status = 'attested', winning_outcome = 'YES', attested_at = 2, oracle_sigs_json = 'invalid'",
            "attestation_status = 'attested', winning_outcome = 'YES', attested_at = 2, oracle_sigs_json = '{}'",
            "attestation_status = 'attested', winning_outcome = 'YES', attested_at = 2, oracle_sigs_json = '[]'",
            "condition_type = 'unknown'", "condition_type = 'numeric'",
            "created_at = 1.5", "created_at = 'unknown'",
            "threshold = 1.5", "threshold = 'unknown'"] {
            let sql = format!("UPDATE conditions SET {mutation} WHERE condition_id = :id");
            assert!(query(&sql).unwrap().bind("id", condition.condition_id.clone()).execute(&*conn).await.is_err(), "storage must reject: {mutation}");
            let unchanged = db.get_condition(&condition.condition_id).await.unwrap().unwrap();
            assert_eq!(unchanged.attestation_status, "pending"); assert!(unchanged.oracle_sigs.is_none());
        }
        let witness = create_oracle_witness(&oracle, "YES");
        assert!(db
            .update_condition_attestation(
                &condition.condition_id,
                "attested",
                Some("YES"),
                Some(2),
                &witness.oracle_sigs
            )
            .await
            .unwrap());
        let stored = db
            .get_condition(&condition.condition_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.oracle_sigs.as_ref(), Some(&witness.oracle_sigs));
        assert_eq!(stored.attested_at, Some(2));
        for mutation in [
            "attested_at = 2.5",
            "attested_at = 'unknown'",
            "created_at = 1.5",
            "threshold = 1.5",
        ] {
            let sql = format!("UPDATE conditions SET {mutation} WHERE condition_id = :id");
            assert!(
                query(&sql)
                    .unwrap()
                    .bind("id", condition.condition_id.clone())
                    .execute(&*conn)
                    .await
                    .is_err(),
                "integer state must reject: {mutation}"
            );
            let unchanged = db
                .get_condition(&condition.condition_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(unchanged.created_at, condition.created_at);
            assert_eq!(unchanged.threshold, condition.threshold);
            assert_eq!(unchanged.oracle_sigs, stored.oracle_sigs);
            assert_eq!(unchanged.winning_outcome, stored.winning_outcome);
            assert_eq!(unchanged.attested_at, stored.attested_at);
        }
        let listed = db.get_conditions(None, None, &[]).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].oracle_sigs, stored.oracle_sigs);
        assert_eq!(listed[0].winning_outcome, stored.winning_outcome);
        assert_eq!(listed[0].attested_at, stored.attested_at);
        // A syntactically valid JSON array can still contain malformed signatures.
        // Every public and locked row read must reject such a corrupt value.
        query("UPDATE conditions SET oracle_sigs_json = '[{}]' WHERE condition_id = :id")
            .unwrap()
            .bind("id", condition.condition_id.clone())
            .execute(&*conn)
            .await
            .unwrap();
        assert!(db.get_condition(&condition.condition_id).await.is_err());
        assert!(db.get_conditions(None, None, &[]).await.is_err());
        let mut tx = db.begin_transaction().await.unwrap();
        assert!(tx
            .get_condition_for_update(&condition.condition_id)
            .await
            .is_err());
        tx.rollback().await.unwrap();
        drop(conn);
        drop(pool);
        drop(db);
        std::fs::remove_file(path).unwrap();
    }
}
