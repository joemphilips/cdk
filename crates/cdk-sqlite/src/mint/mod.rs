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
