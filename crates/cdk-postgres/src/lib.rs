//! CDK Postgres

use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use cdk_common::database::Error;
use cdk_sql_common::database::{DatabaseConnector, DatabaseExecutor, GenericTransactionHandler};
use cdk_sql_common::mint::SQLMintAuthDatabase;
use cdk_sql_common::pool::{DatabaseConfig, DatabasePool};
use cdk_sql_common::stmt::{Column, Statement};
use cdk_sql_common::{SQLMintDatabase, SQLWalletDatabase};
use db::{pg_batch, pg_execute, pg_fetch_all, pg_fetch_one, pg_pluck};
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use tokio_postgres::{Client, Error as PgError, NoTls};

mod db;
mod tls;
mod value;

#[derive(Debug)]
/// Postgres connection pool
pub struct PgConnectionPool;

#[derive(Clone)]
/// SSL Mode
pub enum SslMode {
    /// No TLS
    NoTls(NoTls),
    /// Native TLS
    NativeTls(postgres_native_tls::MakeTlsConnector),
}
impl Default for SslMode {
    fn default() -> Self {
        SslMode::NoTls(NoTls {})
    }
}

impl fmt::Debug for SslMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_text = match self {
            Self::NoTls(_) => "NoTls",
            Self::NativeTls(_) => "NativeTls",
        };

        write!(f, "SslMode::{debug_text}")
    }
}

/// Postgres configuration
#[derive(Clone)]
pub struct PgConfig {
    url: String,
    schema: Option<String>,
    tls_mode: Option<String>,
    max_connections: usize,
    connection_timeout: Duration,
}

impl fmt::Debug for PgConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConfig")
            .field("url", &"[redacted]")
            .field("schema", &self.schema)
            .field("tls_mode", &self.tls_mode.as_ref().map(|_| "[configured]"))
            .field("max_connections", &self.max_connections)
            .field("connection_timeout", &self.connection_timeout)
            .finish()
    }
}

impl DatabaseConfig for PgConfig {
    fn default_timeout(&self) -> Duration {
        self.connection_timeout
    }

    fn max_size(&self) -> usize {
        self.max_connections
    }
}

/// Default maximum number of connections in the pool
const DEFAULT_MAX_CONNECTIONS: usize = 20;

/// Default connection timeout in seconds
const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 10;

impl PgConfig {
    /// Create a new `PgConfig` with explicit TLS mode, pool size, and timeout.
    ///
    /// `tls_mode` accepts the same strings as the configuration file:
    /// `"disable"`, `"prefer"`, `"allow"`, `"require"`, `"verify-ca"`,
    /// `"verify-full"`.  When `None`, the TLS mode is inferred from
    /// `sslmode=` in the connection URL. With neither setting, TLS is disabled.
    /// Invalid modes and TLS connector errors are returned when validating or connecting.
    /// `allow` uses the same opportunistic TLS policy as `prefer`.
    pub fn new(
        conn_str: &str,
        tls_mode: Option<&str>,
        max_connections: Option<usize>,
        connection_timeout_secs: Option<u64>,
    ) -> Self {
        let (schema, conn_str) = Self::strip_schema(conn_str);
        Self {
            url: conn_str,
            schema,
            tls_mode: tls_mode.map(str::to_owned),
            max_connections: max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            connection_timeout: Duration::from_secs(
                connection_timeout_secs.unwrap_or(DEFAULT_CONNECTION_TIMEOUT_SECS),
            ),
        }
    }

    /// Validate connection parameters and construct the configured TLS connector.
    ///
    /// Does not open a connection or verify the server's certificate. Uses the
    /// same TLS policy and connector construction as connection establishment.
    pub fn validate(&self) -> Result<(), Error> {
        tls::configure(&self.url, self.tls_mode.as_deref()).map(|_| ())
    }

    /// Compare effective TLS policies, including certificate verification requirements.
    ///
    /// Resolves explicit modes, URL modes, and defaults using the connection policy.
    /// Invalid settings return an error. Does not connect or construct TLS connectors.
    pub fn has_same_tls_policy(&self, other: &Self) -> Result<bool, Error> {
        let (_, policy) = tls::resolve(&self.url, self.tls_mode.as_deref())?;
        let (_, other_policy) = tls::resolve(&other.url, other.tls_mode.as_deref())?;
        Ok(policy == other_policy)
    }

    /// strip schema from the connection string
    fn strip_schema(input: &str) -> (Option<String>, String) {
        let mut schema: Option<String> = None;

        // Split by whitespace
        let mut parts = Vec::new();
        for token in input.split_whitespace() {
            if let Some(rest) = token.strip_prefix("schema=") {
                schema = Some(rest.to_string());
            } else {
                parts.push(token);
            }
        }

        let cleaned = parts.join(" ");
        (schema, cleaned)
    }
}

impl From<&str> for PgConfig {
    fn from(conn_str: &str) -> Self {
        Self::new(conn_str, None, None, None)
    }
}

impl DatabasePool for PgConnectionPool {
    type Config = PgConfig;

    type Connection = PostgresConnection;

    type Error = PgError;

    fn new_resource(
        config: &Self::Config,
        stale: Arc<AtomicBool>,
        timeout: Duration,
    ) -> Result<Self::Connection, cdk_sql_common::pool::Error<Self::Error>> {
        Ok(PostgresConnection::new(config.to_owned(), timeout, stale))
    }
}

/// A postgres connection
#[derive(Debug)]
pub struct PostgresConnection {
    timeout: Duration,
    error: Arc<Mutex<Option<cdk_common::database::Error>>>,
    result: Arc<OnceLock<Client>>,
    notify: Arc<Notify>,
}

impl PostgresConnection {
    /// Creates a new instance
    pub fn new(config: PgConfig, timeout: Duration, stale: Arc<AtomicBool>) -> Self {
        let failed = Arc::new(Mutex::new(None));
        let result = Arc::new(OnceLock::new());
        let notify = Arc::new(Notify::new());
        let error_clone = failed.clone();
        let result_clone = result.clone();
        let notify_clone = notify.clone();

        async fn select_schema(conn: &Client, schema: &str) -> Result<(), Error> {
            conn.batch_execute(&format!(
                r#"
                    CREATE SCHEMA IF NOT EXISTS "{schema}";
                    SET search_path TO "{schema}"
                    "#
            ))
            .await
            .map_err(|e| Error::Database(Box::new(e)))
        }

        tokio::spawn(async move {
            let (connection_config, tls) =
                match tls::configure(&config.url, config.tls_mode.as_deref()) {
                    Ok(config) => config,
                    Err(err) => {
                        *error_clone.lock().await = Some(err);
                        stale.store(true, std::sync::atomic::Ordering::Release);
                        notify_clone.notify_waiters();
                        return;
                    }
                };
            match tls {
                SslMode::NoTls(tls) => {
                    let (client, connection) = match connection_config.connect(tls).await {
                        Ok((client, connection)) => (client, connection),
                        Err(err) => {
                            *error_clone.lock().await =
                                Some(cdk_common::database::Error::Database(Box::new(err)));
                            stale.store(true, std::sync::atomic::Ordering::Release);
                            notify_clone.notify_waiters();
                            return;
                        }
                    };

                    let stale_for_spawn = stale.clone();
                    tokio::spawn(async move {
                        let _ = connection.await;
                        stale_for_spawn.store(true, std::sync::atomic::Ordering::Release);
                    });

                    if let Some(schema) = config.schema.as_ref() {
                        if let Err(err) = select_schema(&client, schema).await {
                            *error_clone.lock().await = Some(err);
                            stale.store(true, std::sync::atomic::Ordering::Release);
                            notify_clone.notify_waiters();
                            return;
                        }
                    }

                    let _ = result_clone.set(client);
                    notify_clone.notify_waiters();
                }
                SslMode::NativeTls(tls) => {
                    let (client, connection) = match connection_config.connect(tls).await {
                        Ok((client, connection)) => (client, connection),
                        Err(err) => {
                            *error_clone.lock().await =
                                Some(cdk_common::database::Error::Database(Box::new(err)));
                            stale.store(true, std::sync::atomic::Ordering::Release);
                            notify_clone.notify_waiters();
                            return;
                        }
                    };

                    let stale_for_spawn = stale.clone();
                    tokio::spawn(async move {
                        let _ = connection.await;
                        stale_for_spawn.store(true, std::sync::atomic::Ordering::Release);
                    });

                    if let Some(schema) = config.schema.as_ref() {
                        if let Err(err) = select_schema(&client, schema).await {
                            *error_clone.lock().await = Some(err);
                            stale.store(true, std::sync::atomic::Ordering::Release);
                            notify_clone.notify_waiters();
                            return;
                        }
                    }

                    let _ = result_clone.set(client);
                    notify_clone.notify_waiters();
                }
            }
        });

        Self {
            error: failed,
            timeout,
            result,
            notify,
        }
    }

    /// Gets the wrapped instance or the connection error. The connection is returned as reference,
    /// and the actual error is returned once, next times a generic error would be returned
    async fn inner(&self) -> Result<&Client, cdk_common::database::Error> {
        if let Some(client) = self.result.get() {
            return Ok(client);
        }

        if let Some(error) = self.error.lock().await.take() {
            return Err(error);
        }

        if timeout(self.timeout, self.notify.notified()).await.is_err() {
            return Err(cdk_common::database::Error::Internal("Timeout".to_owned()));
        }

        // Check result again
        if let Some(client) = self.result.get() {
            Ok(client)
        } else if let Some(error) = self.error.lock().await.take() {
            Err(error)
        } else {
            Err(cdk_common::database::Error::Internal(
                "Failed connection".to_owned(),
            ))
        }
    }
}

#[async_trait::async_trait]
impl DatabaseConnector for PostgresConnection {
    type Transaction = GenericTransactionHandler<Self>;
}

#[async_trait::async_trait]
impl DatabaseExecutor for PostgresConnection {
    fn name() -> &'static str {
        "postgres"
    }

    async fn execute(&self, statement: Statement) -> Result<usize, Error> {
        pg_execute(self.inner().await?, statement).await
    }

    async fn fetch_one(&self, statement: Statement) -> Result<Option<Vec<Column>>, Error> {
        pg_fetch_one(self.inner().await?, statement).await
    }

    async fn fetch_all(&self, statement: Statement) -> Result<Vec<Vec<Column>>, Error> {
        pg_fetch_all(self.inner().await?, statement).await
    }

    async fn pluck(&self, statement: Statement) -> Result<Option<Column>, Error> {
        pg_pluck(self.inner().await?, statement).await
    }

    async fn batch(&self, statement: Statement) -> Result<(), Error> {
        pg_batch(self.inner().await?, statement).await
    }
}

/// Mint DB implementation with PostgreSQL
pub type MintPgDatabase = SQLMintDatabase<PgConnectionPool>;

/// Mint Auth database with Postgres
pub type MintPgAuthDatabase = SQLMintAuthDatabase<PgConnectionPool>;

/// Wallet DB implementation with PostgreSQL
pub type WalletPgDatabase = SQLWalletDatabase<PgConnectionPool>;

/// Convenience free functions (cannot add inherent impls for a foreign type).
/// These mirror the Mint patterns and call through to the generic constructors.
pub async fn new_wallet_pg_database(conn_str: &str) -> Result<WalletPgDatabase, Error> {
    <SQLWalletDatabase<PgConnectionPool>>::new(conn_str).await
}

#[cfg(test)]
mod test {
    use cdk_common::{mint_db_test, wallet_db_test, QuoteId};
    #[cfg(feature = "conditional-tokens")]
    use std::time::Duration;

    #[cfg(feature = "conditional-tokens")]
    use cdk_common::database::mint::{ConditionsDatabase, CtfSettlementReplay, Database};
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::mint::Operation;
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::mint::StoredCondition;
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::mint_db_conditional_test;
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::nuts::nut_ctf::settlement::{CanonicalHash, CtfSettlementResponse};
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::Amount;

    use super::*;

    fn database_url() -> String {
        std::env::var("CDK_MINTD_DATABASE_URL")
            .or_else(|_| std::env::var("PG_DB_URL")) // Fallback for compatibility
            .unwrap_or(
                "host=localhost user=cdk_user password=cdk_password dbname=cdk_mint port=5432"
                    .to_owned(),
            )
    }

    async fn provide_mint_db(test_id: String) -> MintPgDatabase {
        let db_url = format!("{} schema={test_id}", database_url());

        MintPgDatabase::new(db_url.as_str())
            .await
            .expect("database")
    }

    mint_db_test!(provide_mint_db);

    #[tokio::test]
    async fn mint_pool_accepts_single_connection_configuration() {
        use cdk_common::database::MintDatabase;

        let test_id = format!("test_single_connection_pool_{}", uuid::Uuid::new_v4());
        let db_url = std::env::var("CDK_MINTD_DATABASE_URL")
            .or_else(|_| std::env::var("PG_DB_URL"))
            .unwrap_or(
                "host=localhost user=cdk_user password=cdk_password dbname=cdk_mint port=5432"
                    .to_owned(),
            );
        let config = PgConfig::new(
            &format!("{db_url} schema={test_id}"),
            None,
            Some(1),
            Some(10),
        );

        let db = MintPgDatabase::new(config)
            .await
            .expect("single-connection mint pool should remain supported");
        let regular = MintDatabase::begin_transaction(&db)
            .await
            .expect("regular transaction");
        regular.rollback().await.expect("regular rollback");
    }

    #[tokio::test]
    async fn quote_lock_batch_excludes_concurrent_transaction() {
        use std::sync::Arc;
        use std::time::Duration;

        use cdk_common::database::MintDatabase;

        let test_id = format!("test_quote_lock_batch_{}", uuid::Uuid::new_v4());
        let db = Arc::new(provide_mint_db(test_id).await);
        let first = QuoteId::new();
        let second = QuoteId::new();

        let mut holder = MintDatabase::begin_transaction(&*db).await.expect("tx");
        holder
            .lock_quotes(&[first.clone(), second.clone()])
            .await
            .expect("lock");

        let waiter = tokio::spawn({
            let db = db.clone();
            async move {
                let mut tx = MintDatabase::begin_transaction(&*db).await.expect("tx");
                tx.lock_quotes(&[second, first]).await.expect("lock");
                tx.commit().await.expect("commit");
            }
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !waiter.is_finished(),
            "reversed quote batch did not wait for the holder"
        );

        holder.commit().await.expect("commit");
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("reversed quote batch remained blocked")
            .expect("waiter task");
    }

    #[tokio::test]
    async fn kvstore_compare_and_swap() {
        let test_id = format!("test_kvstore_compare_and_swap_{}", uuid::Uuid::new_v4());
        cdk_common::database::mint::test::kvstore_compare_and_swap(provide_mint_db(test_id).await)
            .await;
    }

    #[tokio::test]
    async fn concurrent_mint_quote_batches_use_consistent_lock_order() {
        let test_id = format!(
            "test_concurrent_mint_quote_batches_{}",
            uuid::Uuid::new_v4()
        );
        cdk_common::database::mint::test::concurrent_mint_quote_batches_use_consistent_lock_order(
            Arc::new(provide_mint_db(test_id).await),
        )
        .await;
    }

    #[tokio::test]
    async fn concurrent_multi_keyset_spends_use_consistent_lock_order() {
        let test_id = format!(
            "test_concurrent_multi_keyset_spends_{}",
            uuid::Uuid::new_v4()
        );
        cdk_common::database::mint::test::concurrent_multi_keyset_spends_use_consistent_lock_order(
            Arc::new(provide_mint_db(test_id).await),
        )
        .await;
    }

    #[cfg(feature = "conditional-tokens")]
    cdk_common::mint_db_conditional_test!(provide_mint_db);

    async fn provide_wallet_db(test_id: String) -> WalletPgDatabase {
        let db_url = format!("{} schema={test_id}", database_url());

        WalletPgDatabase::new(db_url.as_str())
            .await
            .expect("database")
    }

    wallet_db_test!(provide_wallet_db);

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn condition_lock_serializes_attestation_across_connections() {
        let schema = format!("condition_lock_{}", uuid::Uuid::new_v4().simple());
        let locking_db = provide_mint_db(schema.clone()).await;
        let attestation_db = provide_mint_db(schema).await;
        let condition = test_condition();
        locking_db.add_condition(condition.clone()).await.unwrap();

        let mut condition_tx = locking_db.begin_transaction().await.unwrap();
        condition_tx
            .get_condition_for_update(&condition.condition_id)
            .await
            .unwrap()
            .unwrap();

        let condition_id = condition.condition_id.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
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
            tokio::time::timeout(Duration::from_millis(100), &mut attestation)
                .await
                .is_err(),
            "attestation must remain blocked while the condition row is locked"
        );

        condition_tx.commit().await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), attestation)
            .await
            .expect("attestation should resume after commit")
            .expect("attestation task")
            .unwrap());
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn condition_lock_serializes_terminal_settlement_outcomes_across_pools() {
        let schema = format!("settlement_outcome_{}", uuid::Uuid::new_v4().simple());
        let winning_db = provide_mint_db(schema.clone()).await;
        let waiting_db = provide_mint_db(schema).await;
        let condition = test_condition();
        winning_db.add_condition(condition.clone()).await.unwrap();
        let digest = CanonicalHash::from_bytes([0x42; 32]);
        let response = CtfSettlementResponse {
            signatures: vec![Vec::new(), Vec::new()],
        };
        let operation = Operation::new_swap(Amount::ZERO, Amount::ZERO, Amount::ZERO);

        let mut winning_tx = winning_db.begin_transaction().await.unwrap();
        winning_tx
            .get_condition_for_update(&condition.condition_id)
            .await
            .unwrap()
            .unwrap();
        winning_tx
            .add_completed_operation(&operation, &std::collections::HashMap::new())
            .await
            .unwrap();
        winning_tx
            .add_ctf_settlement_replay(digest, operation.id(), &response)
            .await
            .unwrap();

        let condition_id = condition.condition_id.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut waiting = tokio::spawn(async move {
            let mut transaction = waiting_db.begin_transaction().await?;
            assert!(transaction
                .get_ctf_settlement_replay(digest)
                .await?
                .is_none());
            started_tx
                .send(())
                .expect("waiting transaction start signal");
            transaction.get_condition_for_update(&condition_id).await?;
            let outcome = transaction
                .get_ctf_settlement_replay(digest)
                .await?
                .expect("condition lock winner must publish one terminal outcome");
            transaction.rollback().await?;
            Ok::<_, Error>(outcome)
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err(),
            "second pool must wait on the condition lock before selecting an outcome"
        );

        winning_tx.commit().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .expect("waiting transaction should resume")
                .expect("waiting task")
                .expect("waiting transaction"),
            CtfSettlementReplay::Committed(response)
        );

        let schema = format!("settlement_rejection_{}", uuid::Uuid::new_v4().simple());
        let winning_db = provide_mint_db(schema.clone()).await;
        let waiting_db = provide_mint_db(schema).await;
        let condition = test_condition();
        winning_db.add_condition(condition.clone()).await.unwrap();
        let digest = CanonicalHash::from_bytes([0x24; 32]);
        let cutoff = 1_723_456_789;

        let mut winning_tx = winning_db.begin_transaction().await.unwrap();
        winning_tx
            .get_condition_for_update(&condition.condition_id)
            .await
            .unwrap()
            .unwrap();
        winning_tx
            .add_ctf_settlement_rejection(digest, cutoff)
            .await
            .unwrap();

        let condition_id = condition.condition_id.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut waiting = tokio::spawn(async move {
            let mut transaction = waiting_db.begin_transaction().await?;
            assert!(transaction
                .get_ctf_settlement_replay(digest)
                .await?
                .is_none());
            started_tx
                .send(())
                .expect("waiting transaction start signal");
            transaction.get_condition_for_update(&condition_id).await?;
            let outcome = transaction
                .get_ctf_settlement_replay(digest)
                .await?
                .expect("condition lock winner must publish one terminal outcome");
            transaction.rollback().await?;
            Ok::<_, Error>(outcome)
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err(),
            "second pool must wait on the condition lock before selecting an outcome"
        );

        winning_tx.commit().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .expect("waiting transaction should resume")
                .expect("waiting task")
                .expect("waiting transaction"),
            CtfSettlementReplay::RejectedAfterCutoff { cutoff }
        );
    }

    #[cfg(feature = "conditional-tokens")]
    fn test_condition() -> StoredCondition {
        StoredCondition {
            condition_id: "ad".repeat(32),
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
        }
    }

    #[tokio::test]
    async fn failed_initial_connect_marks_connection_stale() {
        let stale = Arc::new(AtomicBool::new(false));
        let config = PgConfig::from("host=127.0.0.1 port=1 user=cdk dbname=cdk connect_timeout=1");
        let conn = PostgresConnection::new(config, Duration::from_secs(5), stale.clone());

        assert!(
            conn.inner().await.is_err(),
            "connect to refused port should fail"
        );
        tokio::task::yield_now().await;

        assert!(
            stale.load(std::sync::atomic::Ordering::SeqCst),
            "failed initial connect should mark the pooled connection stale"
        );
    }

    #[test]
    fn pgconfig_debug_does_not_leak_password() {
        let config = PgConfig::from("host=localhost user=u password=hunter2secret dbname=d");
        let rendered = format!("{config:?}");

        assert!(
            !rendered.contains("hunter2secret"),
            "PgConfig Debug leaked the DB password: {rendered}"
        );
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
        let url = std::env::var("PG_DB_URL")
            .or_else(|_| std::env::var("CDK_MINTD_DATABASE_URL"))
            .unwrap();
        let url = format!("{url} schema=d2_storage_{}", uuid::Uuid::new_v4().simple());
        let db = MintPgDatabase::new(url.as_str()).await.unwrap();
        let pool = Pool::<PgConnectionPool>::new(PgConfig::from(url.as_str()));
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
            "condition_type = 'unknown'", "condition_type = 'numeric'"] {
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
    }
}
