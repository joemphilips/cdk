//! CDK Postgres

use std::fmt::Debug;
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
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use tokio_postgres::{connect, Client, Error as PgError, NoTls};
#[cfg(feature = "conditional-tokens")]
use zeroize::Zeroizing;

mod db;
mod rate_quote;
mod value;

#[derive(Clone, Copy, Debug)]
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
const SSLMODE_VERIFY_FULL: &str = "sslmode=verify-full";
const SSLMODE_VERIFY_CA: &str = "sslmode=verify-ca";
const SSLMODE_PREFER: &str = "sslmode=prefer";
const SSLMODE_ALLOW: &str = "sslmode=allow";
const SSLMODE_REQUIRE: &str = "sslmode=require";

impl Default for SslMode {
    fn default() -> Self {
        SslMode::NoTls(NoTls {})
    }
}

impl Debug for SslMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let debug_text = match self {
            Self::NoTls(_) => "NoTls",
            Self::NativeTls(_) => "NativeTls",
        };

        write!(f, "SslMode::{debug_text}")
    }
}

/// Postgres configuration
#[derive(Clone, Debug)]
pub struct PgConfig {
    url: String,
    schema: Option<String>,
    tls: SslMode,
    max_connections: usize,
    connection_timeout: Duration,
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

/// Build a TLS connector with the given certificate/hostname validation settings.
fn build_tls(accept_invalid_certs: bool, accept_invalid_hostnames: bool) -> SslMode {
    let mut builder = TlsConnector::builder();
    if accept_invalid_certs {
        builder.danger_accept_invalid_certs(true);
    }
    if accept_invalid_hostnames {
        builder.danger_accept_invalid_hostnames(true);
    }

    match builder.build() {
        Ok(connector) => {
            let make_tls_connector = MakeTlsConnector::new(connector);
            SslMode::NativeTls(make_tls_connector)
        }
        Err(_) => SslMode::NoTls(NoTls {}),
    }
}

/// Determine TLS mode from the `sslmode=` parameter in a connection URL.
fn ssl_mode_from_url(url: &str) -> SslMode {
    if url.contains(SSLMODE_VERIFY_FULL) {
        // Strict TLS: valid certs and hostnames required
        build_tls(false, false)
    } else if url.contains(SSLMODE_VERIFY_CA) {
        // Verify CA, but allow invalid hostnames
        build_tls(false, true)
    } else if url.contains(SSLMODE_PREFER)
        || url.contains(SSLMODE_ALLOW)
        || url.contains(SSLMODE_REQUIRE)
    {
        // Lenient TLS for preferred/allow/require: accept invalid certs and hostnames
        build_tls(true, true)
    } else {
        SslMode::NoTls(NoTls {})
    }
}

/// Resolve TLS mode from an explicit `tls_mode` string (from config/env), such
/// as `"disable"`, `"prefer"`, `"require"`, `"verify-ca"`, or `"verify-full"`.
///
/// If the value is `None`, falls back to parsing `sslmode=` from the URL.
fn ssl_mode_from_config(tls_mode: Option<&str>, url: &str) -> SslMode {
    match tls_mode {
        Some(mode) => match mode.to_lowercase().as_str() {
            "verify-full" => build_tls(false, false),
            "verify-ca" => build_tls(false, true),
            "require" | "prefer" | "allow" => build_tls(true, true),
            // "disable" or any unrecognised value → no TLS
            _ => SslMode::NoTls(NoTls {}),
        },
        // No explicit tls_mode: fall back to URL-based detection
        None => ssl_mode_from_url(url),
    }
}

impl PgConfig {
    /// Create a new `PgConfig` with explicit TLS mode, pool size, and timeout.
    ///
    /// `tls_mode` accepts the same strings as the configuration file:
    /// `"disable"`, `"prefer"`, `"allow"`, `"require"`, `"verify-ca"`,
    /// `"verify-full"`.  When `None`, the TLS mode is inferred from
    /// `sslmode=` in the connection URL (matching the old behaviour).
    pub fn new(
        conn_str: &str,
        tls_mode: Option<&str>,
        max_connections: Option<usize>,
        connection_timeout_secs: Option<u64>,
    ) -> Self {
        let (schema, conn_str) = Self::strip_schema(conn_str);
        let tls = ssl_mode_from_config(tls_mode, &conn_str);
        PgConfig {
            url: conn_str,
            schema,
            tls,
            max_connections: max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            connection_timeout: Duration::from_secs(
                connection_timeout_secs.unwrap_or(DEFAULT_CONNECTION_TIMEOUT_SECS),
            ),
        }
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
        let (schema, conn_str) = Self::strip_schema(conn_str);
        let tls = ssl_mode_from_url(&conn_str);

        PgConfig {
            url: conn_str,
            schema,
            tls,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connection_timeout: Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS),
        }
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
            match config.tls {
                SslMode::NoTls(tls) => {
                    let (client, connection) = match connect(&config.url, tls).await {
                        Ok((client, connection)) => (client, connection),
                        Err(err) => {
                            *error_clone.lock().await =
                                Some(cdk_common::database::Error::Database(Box::new(err)));
                            stale.store(false, std::sync::atomic::Ordering::Release);
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
                            stale.store(false, std::sync::atomic::Ordering::Release);
                            notify_clone.notify_waiters();
                            return;
                        }
                    }

                    let _ = result_clone.set(client);
                    notify_clone.notify_waiters();
                }
                SslMode::NativeTls(tls) => {
                    let (client, connection) = match connect(&config.url, tls).await {
                        Ok((client, connection)) => (client, connection),
                        Err(err) => {
                            *error_clone.lock().await =
                                Some(cdk_common::database::Error::Database(Box::new(err)));
                            stale.store(false, std::sync::atomic::Ordering::Release);
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

    #[cfg(feature = "conditional-tokens")]
    async fn get_or_create_conditional_keyset_cursor_key(
        &self,
        candidate: Zeroizing<[u8; 32]>,
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        let row = self
            .inner()
            .await?
            .query_opt(
                r#"
                UPDATE conditional_keyset_catalogue_state
                SET cursor_signing_key = COALESCE(cursor_signing_key, $1)
                WHERE singleton = 1
                RETURNING cursor_signing_key
                "#,
                &[&candidate.as_slice()],
            )
            .await
            .map_err(|err| Error::Database(Box::new(err)))?
            .ok_or_else(|| {
                Error::Internal("conditional keyset catalogue state is missing".to_string())
            })?;
        let stored = Zeroizing::new(row.get::<_, Vec<u8>>(0));
        let key = <[u8; 32]>::try_from(stored.as_slice()).map_err(|_| {
            Error::Internal(format!(
                "conditional keyset cursor key has invalid length {}",
                stored.len()
            ))
        })?;
        Ok(Zeroizing::new(key))
    }
}

/// Mint DB implementation with PostgreSQL
pub type MintPgDatabase = SQLMintDatabase<PgConnectionPool>;

/// Mint Auth database with Postgres
pub type MintPgAuthDatabase = SQLMintAuthDatabase<PgConnectionPool>;

/// Wallet DB implementation with PostgreSQL
pub type WalletPgDatabase = SQLWalletDatabase<PgConnectionPool>;

pub use rate_quote::PostgresRateQuoteStore;

/// Convenience free functions (cannot add inherent impls for a foreign type).
/// These mirror the Mint patterns and call through to the generic constructors.
pub async fn new_wallet_pg_database(conn_str: &str) -> Result<WalletPgDatabase, Error> {
    <SQLWalletDatabase<PgConnectionPool>>::new(conn_str).await
}

#[cfg(test)]
mod test {
    #[cfg(feature = "conditional-tokens")]
    use std::collections::HashSet;
    #[cfg(feature = "conditional-tokens")]
    use std::time::Duration;

    #[cfg(feature = "conditional-tokens")]
    use cdk_common::database::mint::ConditionsDatabase;
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::mint_db_conditional_test;
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::wallet_conditional_restore_db_test;
    use cdk_common::{mint_db_test, wallet_db_test};

    use super::*;

    fn test_database_url() -> String {
        std::env::var("CDK_MINTD_DATABASE_URL")
            .or_else(|_| std::env::var("PG_DB_URL")) // Fallback for compatibility
            .unwrap_or(
                "host=localhost user=cdk_user password=cdk_password dbname=cdk_mint port=5432"
                    .to_owned(),
            )
    }

    async fn provide_mint_db(test_id: String) -> MintPgDatabase {
        let db_url = test_database_url();

        let db_url = format!("{db_url} schema={test_id}");

        MintPgDatabase::new(db_url.as_str())
            .await
            .expect("database")
    }

    mint_db_test!(provide_mint_db);

    #[cfg(feature = "conditional-tokens")]
    cdk_common::mint_db_conditional_test!(provide_mint_db);

    #[cfg(feature = "conditional-tokens")]
    async fn base_client() -> Client {
        let (_, db_url) = PgConfig::strip_schema(&test_database_url());
        let (client, connection) = connect(&db_url, NoTls)
            .await
            .expect("raw PostgreSQL test connection should open");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }

    #[cfg(feature = "conditional-tokens")]
    async fn raw_client(schema: &str) -> Client {
        let client = base_client().await;
        client
            .batch_execute(&format!(r#"SET search_path TO "{schema}""#))
            .await
            .expect("raw PostgreSQL test connection should select its isolated schema");
        client
    }

    #[cfg(feature = "conditional-tokens")]
    #[allow(clippy::too_many_arguments)]
    async fn insert_raw_conditional_keyset(
        client: &Client,
        id: &str,
        valid_from: i64,
        valid_to: Option<i64>,
        derivation_path_index: Option<i64>,
        input_fee_ppk: i64,
        created_at: i64,
        catalogue_sequence: i64,
    ) -> Result<u64, PgError> {
        client
            .execute(
                r#"
                INSERT INTO conditional_keyset (
                    id, unit, active, valid_from, valid_to, derivation_path,
                    derivation_path_index, amounts, input_fee_ppk, issuer_version,
                    condition_id, outcome_collection, outcome_collection_id, created_at,
                    catalogue_sequence
                ) VALUES (
                    $1, 'sat', FALSE, $2, $3, 'm/0', $4, '[]', $5, NULL,
                    'abababababababababababababababababababababababababababababababab',
                    $1 || '-outcome',
                    'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                    $6, $7
                )
                "#,
                &[
                    &id,
                    &valid_from,
                    &valid_to,
                    &derivation_path_index,
                    &input_fee_ppk,
                    &created_at,
                    &catalogue_sequence,
                ],
            )
            .await
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn conditional_keyset_catalogue_postgres_schema_fails_closed() {
        let test_id = format!(
            "test_catalogue_schema_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        );
        let db = provide_mint_db(test_id.clone()).await;
        let client = raw_client(&test_id).await;
        client
            .batch_execute(
                r#"
                INSERT INTO conditions (
                    condition_id, threshold, tags_json, announcements_json,
                    collateral, attestation_status, created_at, condition_type
                ) VALUES (
                    'abababababababababababababababababababababababababababababababab',
                    1, '[]', '[]',
                    'sat', 'pending', 0, 'enum'
                );
                "#,
            )
            .await
            .expect("valid PostgreSQL condition fixture should insert");
        insert_raw_conditional_keyset(&client, "schema-keyset", 0, None, None, 0, 0, 1)
            .await
            .expect("valid PostgreSQL catalogue fixture should insert");

        let indexes = client
            .query(
                r#"
                SELECT indexname
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND tablename = 'conditional_keyset'
                "#,
                &[],
            )
            .await
            .expect("PostgreSQL catalogue indexes should be queryable")
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<HashSet<_>>();
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
                "missing PostgreSQL index {required}"
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
        client
            .batch_execute("SET enable_seqscan = off")
            .await
            .expect("PostgreSQL test should prefer the bounded sequence index");
        let bounded_plan = client
            .query(
                r#"
                EXPLAIN (COSTS OFF)
                SELECT id FROM conditional_keyset
                WHERE catalogue_sequence > 0 AND catalogue_sequence <= 100
                ORDER BY catalogue_sequence
                LIMIT 101
                "#,
                &[],
            )
            .await
            .expect("PostgreSQL bounded catalogue plan should explain")
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            bounded_plan.contains("conditional_keyset_catalogue_sequence_idx"),
            "bounded PostgreSQL scan did not use the sequence index: {bounded_plan}"
        );
        client
            .batch_execute("RESET enable_seqscan")
            .await
            .expect("PostgreSQL planner setting should reset");

        let constraints = client
            .query(
                r#"
                SELECT constraint_name
                FROM information_schema.table_constraints
                WHERE table_schema = current_schema()
                  AND table_name = 'conditional_keyset'
                  AND constraint_type = 'CHECK'
                "#,
                &[],
            )
            .await
            .expect("PostgreSQL catalogue constraints should be queryable")
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<HashSet<_>>();
        for required in [
            "conditional_keyset_catalogue_sequence_positive",
            "conditional_keyset_valid_from_unsigned",
            "conditional_keyset_valid_to_unsigned",
            "conditional_keyset_valid_range_ordered",
            "conditional_keyset_derivation_path_index_unsigned",
            "conditional_keyset_input_fee_ppk_unsigned",
            "conditional_keyset_created_at_unsigned",
        ] {
            assert!(
                constraints.contains(required),
                "missing PostgreSQL constraint {required}"
            );
        }

        client
            .execute(
                "UPDATE conditional_keyset SET outcome_collection = 'changed' WHERE id = 'schema-keyset'",
                &[],
            )
            .await
            .expect_err("PostgreSQL catalogue metadata updates must fail closed");
        client
            .execute(
                "DELETE FROM conditional_keyset WHERE id = 'schema-keyset'",
                &[],
            )
            .await
            .expect_err("PostgreSQL catalogue deletion must fail closed");
        insert_raw_conditional_keyset(&client, "negative-valid-from", -1, None, None, 0, 0, 2)
            .await
            .expect_err("negative valid_from must violate the PostgreSQL invariant");
        insert_raw_conditional_keyset(&client, "negative-valid-to", 0, Some(-1), None, 0, 0, 3)
            .await
            .expect_err("negative valid_to must violate the PostgreSQL invariant");
        insert_raw_conditional_keyset(&client, "reversed-valid-range", 2, Some(1), None, 0, 0, 4)
            .await
            .expect_err("valid_to before valid_from must violate the PostgreSQL invariant");
        insert_raw_conditional_keyset(&client, "negative-path-index", 0, None, Some(-1), 0, 0, 5)
            .await
            .expect_err("negative path index must violate the PostgreSQL invariant");
        insert_raw_conditional_keyset(&client, "negative-input-fee", 0, None, None, -1, 0, 6)
            .await
            .expect_err("negative input fee must violate the PostgreSQL invariant");
        insert_raw_conditional_keyset(&client, "negative-created-at", 0, None, None, 0, -1, 7)
            .await
            .expect_err("negative created_at must violate the PostgreSQL invariant");
        insert_raw_conditional_keyset(&client, "zero-sequence", 0, None, None, 0, 0, 0)
            .await
            .expect_err("zero catalogue sequence must violate the PostgreSQL invariant");
        client
            .execute(
                "UPDATE conditional_keyset_catalogue_state SET high_water = -1 WHERE singleton = 1",
                &[],
            )
            .await
            .expect_err("negative high-water must violate the PostgreSQL invariant");
        client
            .execute(
                "UPDATE conditional_keyset_catalogue_state SET cursor_signing_key = $1 WHERE singleton = 1",
                &[&vec![0_u8; 31]],
            )
            .await
            .expect_err("PostgreSQL cursor signing keys must be exactly 32 bytes");
        client
            .execute(
                "UPDATE conditional_keyset_catalogue_state SET cursor_signing_key = $1 WHERE singleton = 1",
                &[&vec![0_u8; 32]],
            )
            .await
            .expect("PostgreSQL cursor key should initialize once");
        client
            .execute(
                "UPDATE conditional_keyset_catalogue_state SET high_water = 1 WHERE singleton = 1",
                &[],
            )
            .await
            .expect("PostgreSQL high-water should advance");
        client
            .execute(
                "UPDATE conditional_keyset_catalogue_state SET cursor_signing_key = $1 WHERE singleton = 1",
                &[&vec![1_u8; 32]],
            )
            .await
            .expect_err("PostgreSQL cursor key mutation must fail closed");
        client
            .execute(
                "UPDATE conditional_keyset_catalogue_state SET high_water = 0 WHERE singleton = 1",
                &[],
            )
            .await
            .expect_err("PostgreSQL high-water rollback must fail closed");
        client
            .execute(
                "DELETE FROM conditional_keyset_catalogue_state WHERE singleton = 1",
                &[],
            )
            .await
            .expect_err("PostgreSQL catalogue singleton deletion must fail closed");

        drop(db);
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn conditional_keyset_catalogue_rejects_raw_state_and_sequence_corruption() {
        let test_id = format!(
            "test_catalogue_corruption_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        );
        let db = provide_mint_db(test_id.clone()).await;
        let client = raw_client(&test_id).await;
        client
            .batch_execute(
                r#"
                INSERT INTO conditions (
                    condition_id, threshold, tags_json, announcements_json,
                    collateral, attestation_status, created_at, condition_type
                ) VALUES (
                    'abababababababababababababababababababababababababababababababab',
                    1, '[]', '[]', 'sat', 'pending', 0, 'enum'
                );
                "#,
            )
            .await
            .expect("raw condition fixture should insert");
        for sequence in 1..=3 {
            insert_raw_conditional_keyset(
                &client,
                &format!("00{sequence:014x}"),
                0,
                None,
                Some(0),
                0,
                0,
                sequence,
            )
            .await
            .expect("raw catalogue row should insert");
        }
        client
            .batch_execute(
                r#"
                UPDATE conditional_keyset_catalogue_state SET high_water = 3 WHERE singleton = 1;
                DROP TRIGGER conditional_keyset_catalogue_no_delete ON conditional_keyset;
                DROP TRIGGER conditional_keyset_catalogue_state_no_rollback_or_key_mutation
                    ON conditional_keyset_catalogue_state;
                "#,
            )
            .await
            .expect("raw corruption fixture should initialize");

        assert_eq!(
            db.get_conditional_keyset_catalogue_page(None, 0, 3)
                .await
                .expect("valid catalogue should read")
                .keysets
                .len(),
            3
        );

        for high_water in [2_i64, 4_i64] {
            client
                .execute(
                    "UPDATE conditional_keyset_catalogue_state SET high_water = $1 WHERE singleton = 1",
                    &[&high_water],
                )
                .await
                .expect("test should force state divergence");
            assert!(db
                .get_conditional_keyset_catalogue_page(None, 0, 3)
                .await
                .is_err());
        }

        client
            .batch_execute(
                r#"
                UPDATE conditional_keyset_catalogue_state SET high_water = 3 WHERE singleton = 1;
                DELETE FROM conditional_keyset WHERE catalogue_sequence = 2;
                "#,
            )
            .await
            .expect("test should remove a middle row");
        assert!(db
            .get_conditional_keyset_catalogue_page(None, 0, 3)
            .await
            .is_err());

        insert_raw_conditional_keyset(&client, "0000000000000002", 0, None, Some(0), 0, 0, 2)
            .await
            .expect("test should restore the middle row");
        client
            .execute(
                "DELETE FROM conditional_keyset WHERE catalogue_sequence = 3",
                &[],
            )
            .await
            .expect("test should remove the final row");
        assert!(db
            .get_conditional_keyset_catalogue_page(None, 0, 3)
            .await
            .is_err());

        drop(db);
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conditional_keyset_catalogue_first_page_reads_committed_writer_fence() {
        let test_id = format!(
            "test_catalogue_writer_fence_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        );
        let db = provide_mint_db(test_id.clone()).await;
        let mut writer = raw_client(&test_id).await;
        writer
            .batch_execute(
                r#"
                INSERT INTO conditions (
                    condition_id, threshold, tags_json, announcements_json,
                    collateral, attestation_status, created_at, condition_type
                ) VALUES (
                    'abababababababababababababababababababababababababababababababab',
                    1, '[]', '[]',
                    'sat', 'pending', 0, 'enum'
                );
                INSERT INTO conditional_keyset (
                    id, unit, active, valid_from, valid_to, derivation_path,
                    derivation_path_index, amounts, input_fee_ppk, issuer_version,
                    condition_id, outcome_collection, outcome_collection_id, created_at,
                    catalogue_sequence
                ) VALUES (
                    '00916bbf7ef91a36', 'sat', FALSE, 0, NULL, 'm/0', NULL, '[]', 0, NULL,
                    'abababababababababababababababababababababababababababababababab',
                    'committed',
                    '3131313131313131313131313131313131313131313131313131313131313131', 0, 1
                );
                UPDATE conditional_keyset_catalogue_state SET high_water = 1 WHERE singleton = 1;
                "#,
            )
            .await
            .expect("committed catalogue writer fixture should initialize");

        let transaction = writer.transaction().await;
        let transaction = transaction.expect("catalogue writer transaction should begin");
        transaction
            .batch_execute(
                r#"
                UPDATE conditional_keyset_catalogue_state SET high_water = 2 WHERE singleton = 1;
                INSERT INTO conditional_keyset (
                    id, unit, active, valid_from, valid_to, derivation_path,
                    derivation_path_index, amounts, input_fee_ppk, issuer_version,
                    condition_id, outcome_collection, outcome_collection_id, created_at,
                    catalogue_sequence
                ) VALUES (
                    '009a1f293253e41e', 'sat', FALSE, 0, NULL, 'm/0', NULL, '[]', 0, NULL,
                    'abababababababababababababababababababababababababababababababab',
                    'uncommitted',
                    '3232323232323232323232323232323232323232323232323232323232323232', 0, 2
                );
                "#,
            )
            .await
            .expect("uncommitted catalogue writer fixture should stage");

        let page = tokio::time::timeout(
            Duration::from_millis(250),
            db.get_conditional_keyset_catalogue_page(None, 0, 10),
        )
        .await
        .expect("first-page acquisition must not wait for an uncommitted writer fence")
        .expect("first-page acquisition should succeed");
        assert_eq!(page.snapshot, 1);
        assert_eq!(page.keysets.len(), 1);
        assert_eq!(page.keysets[0].sequence, 1);
        assert_eq!(page.keysets[0].keyset.outcome_collection, "committed");
        transaction
            .rollback()
            .await
            .expect("catalogue writer fixture should roll back");
    }

    async fn provide_wallet_db(test_id: String) -> WalletPgDatabase {
        let db_url = std::env::var("CDK_MINTD_DATABASE_URL")
            .or_else(|_| std::env::var("PG_DB_URL")) // Fallback for compatibility
            .unwrap_or(
                "host=localhost user=cdk_user password=cdk_password dbname=cdk_mint port=5432"
                    .to_owned(),
            );

        let db_url = format!("{db_url} schema={test_id}");

        WalletPgDatabase::new(db_url.as_str())
            .await
            .expect("database")
    }

    wallet_db_test!(provide_wallet_db);
    #[cfg(feature = "conditional-tokens")]
    wallet_conditional_restore_db_test!(provide_wallet_db);

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn wallet_conditional_restore_kind_rejects_direct_sql_mutation() {
        let test_id = format!("wallet_kind_{}", uuid::Uuid::new_v4().simple());
        let _database = provide_wallet_db(test_id.clone()).await;
        let client = raw_client(&test_id).await;
        client
            .execute(
                "INSERT INTO mint (mint_url) VALUES ($1)",
                &[&"https://example.com"],
            )
            .await
            .expect("mint fixture");
        let keyset_id = format!("01{}", "11".repeat(32));
        client
            .execute(
                r#"
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, restore_kind)
                VALUES ($1, $2, 'sat', FALSE, 0, NULL, 'conditional')
                "#,
                &[&keyset_id, &"https://example.com"],
            )
            .await
            .expect("conditional namespace fixture");
        client
            .execute(
                "INSERT INTO key (id, keys, restore_kind) VALUES ($1, '{}', 'conditional')",
                &[&keyset_id],
            )
            .await
            .expect("conditional key fixture");
        client
            .execute(
                r#"
                INSERT INTO conditional_restore_keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry,
                     condition_id, outcome_collection, outcome_collection_id, registered_at)
                VALUES ($1, $2, 'usd', TRUE, NULL, NULL, $3, 'YES', $4, 1)
                "#,
                &[
                    &keyset_id,
                    &"https://example.com",
                    &"11".repeat(32),
                    &"22".repeat(32),
                ],
            )
            .await
            .expect_err("classification must match the conditional keyset owner and unit");
        let error = client
            .execute(
                "UPDATE keyset SET restore_kind = 'ordinary' WHERE id = $1",
                &[&keyset_id],
            )
            .await
            .expect_err("namespace discriminator mutation must fail");
        assert_eq!(
            error.as_db_error().map(|error| error.code()),
            Some(&tokio_postgres::error::SqlState::RAISE_EXCEPTION),
            "the database trigger must reject discriminator mutation"
        );
        client
            .execute(
                "UPDATE key SET restore_kind = 'ordinary' WHERE id = $1",
                &[&keyset_id],
            )
            .await
            .expect_err("conditional key discriminator mutation must fail");
        client
            .execute(
                "INSERT INTO conditional_restore_high_water (mint_url, unit, high_water) VALUES ($1, 'sat', $2)",
                &[&"https://example.com", &100_u64.to_be_bytes().to_vec()],
            )
            .await
            .expect("high-water fixture");
        client
            .execute(
                "DELETE FROM conditional_restore_high_water WHERE mint_url = $1",
                &[&"https://example.com"],
            )
            .await
            .expect_err("high-water deletion outside URL migration must fail");
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn wallet_conditional_restore_schema_uses_utf8_byte_boundaries() {
        let test_id = format!("wallet_utf8_{}", uuid::Uuid::new_v4().simple());
        let _database = provide_wallet_db(test_id.clone()).await;
        let client = raw_client(&test_id).await;
        client
            .execute(
                "INSERT INTO mint (mint_url) VALUES ($1)",
                &[&"https://example.com"],
            )
            .await
            .expect("mint fixture");

        async fn insert(
            client: &Client,
            id: &str,
            unit: &str,
            outcome: &str,
        ) -> Result<(), PgError> {
            client
                .execute(
                    r#"
                    INSERT INTO keyset
                        (id, mint_url, unit, active, input_fee_ppk, final_expiry, restore_kind)
                    VALUES ($1, 'https://example.com', $2, FALSE, 0, NULL, 'conditional')
                    "#,
                    &[&id, &unit],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO key (id, keys, restore_kind) VALUES ($1, '{}', 'conditional')",
                    &[&id],
                )
                .await?;
            client
                .execute(
                    r#"
                    INSERT INTO conditional_restore_keyset
                        (id, mint_url, unit, active, input_fee_ppk, final_expiry,
                         condition_id, outcome_collection, outcome_collection_id, registered_at)
                    VALUES ($1, 'https://example.com', $2, TRUE, NULL, NULL,
                            $3, $4, $5, 1)
                    "#,
                    &[&id, &unit, &"11".repeat(32), &outcome, &"22".repeat(32)],
                )
                .await?;
            Ok(())
        }

        let unit_64 = "é".repeat(32);
        let outcome_16384 = format!("{}a", "界".repeat(5461));
        assert_eq!(unit_64.len(), 64);
        assert_eq!(outcome_16384.len(), 16_384);
        insert(&client, "utf8-boundary", &unit_64, &outcome_16384)
            .await
            .expect("exact UTF-8 byte limits should be accepted");
        insert(&client, "unit-too-wide", &format!("{unit_64}a"), "YES")
            .await
            .expect_err("65-byte unit must be rejected");
        insert(
            &client,
            "outcome-too-wide",
            "sat",
            &format!("{outcome_16384}a"),
        )
        .await
        .expect_err("16385-byte outcome collection must be rejected");
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn wallet_conditional_restore_migrates_existing_postgres_schema() {
        let test_id = format!("wallet_upgrade_{}", uuid::Uuid::new_v4().simple());
        let client = base_client().await;
        client
            .batch_execute(&format!(
                r#"
                CREATE SCHEMA "{test_id}";
                SET search_path TO "{test_id}";
                CREATE TABLE migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMP);
                CREATE TABLE keyset (
                    id TEXT PRIMARY KEY, mint_url TEXT NOT NULL, unit TEXT NOT NULL,
                    active BOOLEAN NOT NULL, input_fee_ppk BIGINT NOT NULL,
                    final_expiry BIGINT, keyset_u32 BIGINT
                );
                CREATE TABLE key (
                    id TEXT PRIMARY KEY, keys TEXT NOT NULL, keyset_u32 BIGINT
                );
                CREATE TABLE keyset_counter (
                    keyset_id TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE proof (
                    mint_url TEXT, unit TEXT, state TEXT, keyset_id TEXT
                );
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, keyset_u32)
                VALUES ('legacy', 'https://example.com', 'sat', TRUE, 0, NULL, NULL);
                INSERT INTO key (id, keys, keyset_u32) VALUES ('legacy', '{{}}', NULL);
                "#,
            ))
            .await
            .expect("legacy PostgreSQL wallet schema fixture");

        fn migration_names(path: &std::path::Path, names: &mut Vec<String>) {
            for entry in std::fs::read_dir(path).expect("wallet migrations directory") {
                let entry = entry.expect("migration entry");
                if entry.path().is_dir() {
                    migration_names(&entry.path(), names);
                } else {
                    names.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cdk-sql-common/src/wallet/migrations");
        let mut names = Vec::new();
        migration_names(&migrations_dir, &mut names);
        for name in names {
            if name != "20260720000000_add_conditional_restore.sql" {
                client
                    .execute(
                        "INSERT INTO migrations (name) VALUES ($1) ON CONFLICT DO NOTHING",
                        &[&name],
                    )
                    .await
                    .expect("legacy migration marker");
            }
        }
        drop(client);

        let db_url = format!("{} schema={test_id}", test_database_url());
        let _database = WalletPgDatabase::new(db_url.as_str())
            .await
            .expect("conditional restore migration should upgrade existing PostgreSQL wallet");
        let client = raw_client(&test_id).await;
        let row = client
            .query_one(
                r#"
                SELECT s.restore_kind, k.restore_kind
                FROM keyset s JOIN key k ON k.id = s.id
                WHERE s.id = 'legacy'
                "#,
                &[],
            )
            .await
            .expect("upgraded legacy discriminators");
        assert_eq!(row.get::<_, String>(0), "ordinary");
        assert_eq!(row.get::<_, String>(1), "ordinary");
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn wallet_ordinary_refresh_cannot_race_conditional_namespace_claim() {
        use std::str::FromStr;

        use cdk_common::database::WalletDatabase;
        use cdk_common::mint_url::MintUrl;
        use cdk_common::{CurrencyUnit, Id, KeySetInfo};

        let test_id = format!("wallet_kind_race_{}", uuid::Uuid::new_v4().simple());
        let database = provide_wallet_db(test_id.clone()).await;
        let mint_url = MintUrl::from_str("https://example.com").expect("test mint URL");
        database
            .add_mint(mint_url.clone(), None)
            .await
            .expect("mint fixture");

        let mut writer = raw_client(&test_id).await;
        let transaction = writer
            .transaction()
            .await
            .expect("conditional namespace transaction");
        let keyset_id = format!("01{}", "22".repeat(32));
        transaction
            .execute(
                r#"
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, restore_kind)
                VALUES ($1, $2, 'sat', FALSE, 0, NULL, 'conditional')
                "#,
                &[&keyset_id, &mint_url.to_string()],
            )
            .await
            .expect("uncommitted conditional namespace claim");

        let id = Id::from_str(&keyset_id).expect("test keyset id");
        let ordinary = KeySetInfo {
            id,
            unit: CurrencyUnit::Sat,
            active: true,
            input_fee_ppk: 0,
            final_expiry: None,
        };
        let refresh_database = database.clone();
        let refresh_mint_url = mint_url.clone();
        let mut refresh = tokio::spawn(async move {
            refresh_database
                .add_mint_keysets(refresh_mint_url, vec![ordinary])
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut refresh)
                .await
                .is_err()
        );
        transaction
            .commit()
            .await
            .expect("conditional namespace claim should commit");
        assert!(matches!(
            refresh.await.expect("ordinary refresh task should join"),
            Err(cdk_common::database::Error::ConditionalRestoreMetadataConflict)
        ));
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wallet_conditional_commit_cannot_race_ordinary_namespace_claim() {
        use cdk_common::database::wallet::test::conditional_restore_test_admission;
        use cdk_common::database::WalletDatabase;

        let test_id = format!("wallet_reverse_kind_race_{}", uuid::Uuid::new_v4().simple());
        let database = provide_wallet_db(test_id.clone()).await;
        let admission = conditional_restore_test_admission(100, 300);
        database
            .add_mint(admission.mint_url.clone(), None)
            .await
            .expect("mint fixture");

        let mut writer = raw_client(&test_id).await;
        let transaction = writer.transaction().await.expect("ordinary transaction");
        transaction
            .execute(
                r#"
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, restore_kind)
                VALUES ($1, $2, $3, FALSE, $4, $5, 'ordinary')
                "#,
                &[
                    &admission.keyset.id.to_string(),
                    &admission.mint_url.to_string(),
                    &admission.unit.to_string(),
                    &i32::try_from(admission.keyset.input_fee_ppk)
                        .expect("fixture input fee should fit the keyset INTEGER column"),
                    &admission.keyset.final_expiry.map(|value| {
                        i32::try_from(value)
                            .expect("fixture expiry should fit the keyset INTEGER column")
                    }),
                ],
            )
            .await
            .expect("uncommitted ordinary namespace claim");

        let commit_database = database.clone();
        let mut commit =
            tokio::spawn(
                async move { commit_database.commit_conditional_restore(admission).await },
            );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut commit)
                .await
                .is_err()
        );
        transaction
            .commit()
            .await
            .expect("ordinary claim should commit");
        assert!(matches!(
            commit.await.expect("conditional commit task should join"),
            Err(cdk_common::database::Error::ConditionalRestoreMetadataConflict)
        ));
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wallet_conditional_retry_cannot_overwrite_concurrent_proof_advance() {
        use cdk_common::database::wallet::test::conditional_restore_test_admission;
        use cdk_common::database::WalletDatabase;
        use cdk_common::State;

        let test_id = format!("wallet_proof_race_{}", uuid::Uuid::new_v4().simple());
        let database = provide_wallet_db(test_id.clone()).await;
        let initial = conditional_restore_test_admission(100, 300);
        database
            .add_mint(initial.mint_url.clone(), None)
            .await
            .expect("mint fixture");
        database
            .commit_conditional_restore(initial.clone())
            .await
            .expect("initial conditional proof should commit");

        let mut writer = raw_client(&test_id).await;
        let transaction = writer
            .transaction()
            .await
            .expect("local proof advance transaction");
        transaction
            .execute(
                "UPDATE proof SET state = 'RESERVED' WHERE y = $1",
                &[&initial.proofs[0].y.to_bytes().to_vec()],
            )
            .await
            .expect("uncommitted local proof advance");

        let mut retry = initial.clone();
        retry.observed_wall_time = 110;
        retry.proofs[0].state = State::Pending;
        let retry_database = database.clone();
        let mut retry_task =
            tokio::spawn(async move { retry_database.commit_conditional_restore(retry).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut retry_task)
                .await
                .is_err(),
            "restore retry should wait for the concurrent proof writer"
        );
        transaction
            .commit()
            .await
            .expect("local proof advance should commit");
        retry_task
            .await
            .expect("restore retry task should join")
            .expect("restore retry should preserve the concurrent lifecycle advance");

        let stored = database
            .get_proofs_by_ys(vec![initial.proofs[0].y])
            .await
            .expect("proof should load");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].state, State::Reserved);
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wallet_mint_url_migration_waits_for_high_water_writer() {
        use std::str::FromStr;

        use cdk_common::database::WalletDatabase;
        use cdk_common::mint_url::MintUrl;
        use cdk_common::CurrencyUnit;

        let test_id = format!("wallet_url_fence_{}", uuid::Uuid::new_v4().simple());
        let database = provide_wallet_db(test_id.clone()).await;
        let old_mint = MintUrl::from_str("https://old.example.com").unwrap();
        let new_mint = MintUrl::from_str("https://new.example.com").unwrap();
        database.add_mint(old_mint.clone(), None).await.unwrap();
        database.add_mint(new_mint.clone(), None).await.unwrap();
        database
            .advance_conditional_restore_high_water(old_mint.clone(), CurrencyUnit::Sat, 100)
            .await
            .unwrap();

        let mut writer = raw_client(&test_id).await;
        let transaction = writer
            .transaction()
            .await
            .expect("high-water writer transaction");
        transaction
            .execute(
                r#"
                UPDATE conditional_restore_high_water
                SET high_water = $1
                WHERE mint_url = $2 AND unit = 'sat'
                "#,
                &[&200_u64.to_be_bytes().to_vec(), &old_mint.to_string()],
            )
            .await
            .expect("uncommitted high-water advance");

        let migration_database = database.clone();
        let migration_old = old_mint.clone();
        let migration_new = new_mint.clone();
        let mut migration = tokio::spawn(async move {
            migration_database
                .update_mint_url(migration_old, migration_new)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut migration)
                .await
                .is_err()
        );
        transaction
            .commit()
            .await
            .expect("high-water writer should commit");
        migration
            .await
            .expect("URL migration task should join")
            .expect("URL migration should commit");
        assert_eq!(
            database
                .advance_conditional_restore_high_water(new_mint, CurrencyUnit::Sat, 0)
                .await
                .unwrap(),
            200
        );
    }
}
