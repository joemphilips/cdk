//! Postgres storage for rate-quoted payment terms.

use std::sync::Arc;

use async_trait::async_trait;
use cdk_common::database::Error;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::PaymentIdentifier;
use cdk_exchange_rate::{
    ActiveMintReservation, ParkedPaymentRecord, RateQuoteRecord, RateQuoteSettlement,
    RateQuoteSide, RateQuoteStore, RateQuoteStoreError, UnitControlRecord,
};
use cdk_sql_common::pool::Pool;
use cdk_sql_common::stmt::query;

use crate::{PgConfig, PgConnectionPool};

const MIGRATION_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS rate_quote_terms (
    payment_lookup_id TEXT PRIMARY KEY,
    side TEXT NOT NULL CHECK (side IN ('mint', 'melt')),
    fiat_unit TEXT NOT NULL,
    fiat_subunits BIGINT NOT NULL CHECK (fiat_subunits >= 0),
    fiat_fee_subunits BIGINT NOT NULL DEFAULT 0 CHECK (fiat_fee_subunits >= 0),
    snapshot_json TEXT NOT NULL,
    sats_invoiced BIGINT NOT NULL CHECK (sats_invoiced >= 0),
    sats_unbuffered BIGINT NOT NULL DEFAULT 0 CHECK (
        sats_unbuffered >= 0 AND sats_unbuffered <= sats_invoiced
    ),
    expiry_unix BIGINT NOT NULL CHECK (expiry_unix >= 0),
    settled BIGINT NOT NULL DEFAULT 0 CHECK (settled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS parked_payments (
    payment_lookup_id TEXT NOT NULL,
    bolt11_payment_hash TEXT NOT NULL,
    received_sats BIGINT NOT NULL CHECK (received_sats >= 0),
    observed_at BIGINT NOT NULL CHECK (observed_at >= 0),
    resolution_status TEXT NOT NULL,
    PRIMARY KEY (payment_lookup_id, bolt11_payment_hash)
);

CREATE TABLE IF NOT EXISTS rate_unit_control (
    unit TEXT PRIMARY KEY,
    mint_paused BIGINT NOT NULL DEFAULT 0 CHECK (mint_paused IN (0, 1)),
    melt_paused BIGINT NOT NULL DEFAULT 0 CHECK (melt_paused IN (0, 1)),
    cap BIGINT NOT NULL DEFAULT 0 CHECK (cap >= 0),
    outstanding BIGINT NOT NULL DEFAULT 0 CHECK (outstanding >= 0),
    buffer_surplus_sats BIGINT NOT NULL DEFAULT 0 CHECK (buffer_surplus_sats >= 0)
);
"#;

const SELECT_QUOTE_SQL: &str = r#"
SELECT payment_lookup_id, fiat_unit, fiat_subunits, fiat_fee_subunits, snapshot_json, sats_invoiced, sats_unbuffered, expiry_unix, side
FROM rate_quote_terms
WHERE payment_lookup_id = :payment_lookup_id
"#;

const SELECT_QUOTE_FOR_UPDATE_SQL: &str = r#"
SELECT payment_lookup_id, fiat_unit, fiat_subunits, fiat_fee_subunits, snapshot_json, sats_invoiced, sats_unbuffered, expiry_unix, side, settled
FROM rate_quote_terms
WHERE payment_lookup_id = :payment_lookup_id
FOR UPDATE
"#;

const SELECT_ACTIVE_MINT_RESERVATIONS_SQL: &str = r#"
SELECT payment_lookup_id, fiat_unit, fiat_subunits, expiry_unix
FROM rate_quote_terms
WHERE side = 'mint'
  AND settled = 0
  AND expiry_unix > :now_unix
ORDER BY payment_lookup_id
"#;

const INSERT_PARKED_SQL: &str = r#"
INSERT INTO parked_payments
    (payment_lookup_id, bolt11_payment_hash, received_sats, observed_at, resolution_status)
VALUES
    (:payment_lookup_id, :bolt11_payment_hash, :received_sats, :observed_at, :resolution_status)
ON CONFLICT (payment_lookup_id, bolt11_payment_hash)
DO UPDATE SET
    received_sats = EXCLUDED.received_sats,
    observed_at = EXCLUDED.observed_at,
    resolution_status = EXCLUDED.resolution_status
"#;

/// Postgres-backed [`RateQuoteStore`] colocated with the mint database schema.
#[derive(Debug, Clone)]
pub struct PostgresRateQuoteStore {
    pool: Arc<Pool<PgConnectionPool>>,
}

impl PostgresRateQuoteStore {
    /// Create the store and apply its companion-table migration.
    pub async fn new(conn_str: &str) -> Result<Self, Error> {
        Self::with_config(PgConfig::from(conn_str)).await
    }

    /// Create the store using the same resolved PostgreSQL policy as the mint database.
    pub async fn with_config(config: PgConfig) -> Result<Self, Error> {
        let pool = Pool::<PgConnectionPool>::new(config);
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), Error> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|error| Error::Database(Box::new(error)))?;
        query(MIGRATION_SQL)?.batch(&*conn).await
    }

    async fn conn(
        &self,
    ) -> Result<cdk_sql_common::pool::PooledResource<PgConnectionPool>, RateQuoteStoreError> {
        self.pool
            .get()
            .await
            .map_err(|error| RateQuoteStoreError::Storage(error.to_string()))
    }
}

fn storage_error(error: impl std::fmt::Display) -> RateQuoteStoreError {
    RateQuoteStoreError::Storage(error.to_string())
}

fn insert_parked_statement(
    record: ParkedPaymentRecord,
) -> Result<cdk_sql_common::stmt::Statement, RateQuoteStoreError> {
    Ok(query(INSERT_PARKED_SQL)
        .map_err(storage_error)?
        .bind("payment_lookup_id", record.payment_lookup_id.to_string())
        .bind("bolt11_payment_hash", record.bolt11_payment_hash)
        .bind(
            "received_sats",
            checked_i64(record.received_sats, "received_sats")?,
        )
        .bind(
            "observed_at",
            checked_i64(record.observed_at, "observed_at")?,
        )
        .bind("resolution_status", record.resolution_status))
}

#[async_trait]
impl RateQuoteStore for PostgresRateQuoteStore {
    async fn insert(&self, record: RateQuoteRecord) -> Result<(), RateQuoteStoreError> {
        let conn = self.conn().await?;

        query(
            r#"
            INSERT INTO rate_quote_terms
                (payment_lookup_id, fiat_unit, fiat_subunits, fiat_fee_subunits, snapshot_json, sats_invoiced, sats_unbuffered, expiry_unix, side)
            VALUES
                (:payment_lookup_id, :fiat_unit, :fiat_subunits, :fiat_fee_subunits, :snapshot_json, :sats_invoiced, :sats_unbuffered, :expiry_unix, :side)
            "#,
        )
        .map_err(storage_error)?
        .bind("payment_lookup_id", record.payment_lookup_id.to_string())
        .bind("side", record.side.to_string())
        .bind("fiat_unit", record.fiat_unit.to_string())
        .bind(
            "fiat_subunits",
            checked_i64(record.fiat_subunits, "fiat_subunits")?,
        )
        .bind(
            "fiat_fee_subunits",
            checked_i64(record.fiat_fee_subunits, "fiat_fee_subunits")?,
        )
        .bind("snapshot_json", record.snapshot_json.to_string())
        .bind(
            "sats_invoiced",
            checked_i64(record.sats_invoiced, "sats_invoiced")?,
        )
        .bind(
            "sats_unbuffered",
            checked_i64(record.sats_unbuffered, "sats_unbuffered")?,
        )
        .bind("expiry_unix", checked_i64(record.expiry_unix, "expiry_unix")?)
        .execute(&*conn)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn get_by_lookup_id(
        &self,
        payment_lookup_id: &PaymentIdentifier,
    ) -> Result<Option<RateQuoteRecord>, RateQuoteStoreError> {
        let conn = self.conn().await?;

        let Some(row) = query(SELECT_QUOTE_SQL)
            .map_err(storage_error)?
            .bind("payment_lookup_id", payment_lookup_id.to_string())
            .fetch_one(&*conn)
            .await
            .map_err(storage_error)?
        else {
            return Ok(None);
        };

        Ok(Some(row_to_record(row)?))
    }

    async fn insert_parked(&self, record: ParkedPaymentRecord) -> Result<(), RateQuoteStoreError> {
        let conn = self.conn().await?;

        insert_parked_statement(record)?
            .execute(&*conn)
            .await
            .map_err(storage_error)?;

        Ok(())
    }

    async fn park_or_credit(
        &self,
        parked: ParkedPaymentRecord,
    ) -> Result<Option<RateQuoteRecord>, RateQuoteStoreError> {
        let conn = self.conn().await?;

        // One transaction: the missing-record detection and the parked-row
        // write commit together, so no orphaned payment is silently lost.
        query("START TRANSACTION")
            .map_err(storage_error)?
            .execute(&*conn)
            .await
            .map_err(storage_error)?;

        let result = async {
            let row = query(SELECT_QUOTE_SQL)
                .map_err(storage_error)?
                .bind("payment_lookup_id", parked.payment_lookup_id.to_string())
                .fetch_one(&*conn)
                .await
                .map_err(storage_error)?;

            match row {
                Some(row) => Ok(Some(row_to_record(row)?)),
                None => {
                    insert_parked_statement(parked)?
                        .execute(&*conn)
                        .await
                        .map_err(storage_error)?;
                    Ok(None)
                }
            }
        }
        .await;

        match result {
            Ok(record) => {
                query("COMMIT")
                    .map_err(storage_error)?
                    .execute(&*conn)
                    .await
                    .map_err(storage_error)?;
                Ok(record)
            }
            Err(error) => {
                if let Ok(rollback) = query("ROLLBACK") {
                    let _ = rollback.execute(&*conn).await;
                }
                Err(error)
            }
        }
    }

    async fn mark_settled(
        &self,
        payment_lookup_id: &PaymentIdentifier,
    ) -> Result<bool, RateQuoteStoreError> {
        let conn = self.conn().await?;

        let affected = query(
            r#"
            UPDATE rate_quote_terms
            SET settled = 1
            WHERE payment_lookup_id = :payment_lookup_id AND settled = 0
            "#,
        )
        .map_err(storage_error)?
        .bind("payment_lookup_id", payment_lookup_id.to_string())
        .execute(&*conn)
        .await
        .map_err(storage_error)?;

        Ok(affected > 0)
    }

    async fn settle_quote_and_commit_unit_control(
        &self,
        payment_lookup_id: &PaymentIdentifier,
        unit: &CurrencyUnit,
        settlement: RateQuoteSettlement,
    ) -> Result<bool, RateQuoteStoreError> {
        let conn = self.conn().await?;

        query("START TRANSACTION")
            .map_err(storage_error)?
            .execute(&*conn)
            .await
            .map_err(storage_error)?;

        let result = async {
            let Some(row) = query(SELECT_QUOTE_FOR_UPDATE_SQL)
                .map_err(storage_error)?
                .bind("payment_lookup_id", payment_lookup_id.to_string())
                .fetch_one(&*conn)
                .await
                .map_err(storage_error)?
            else {
                return Ok(false);
            };
            let already_settled = int_col(&row[9])? != 0;
            let record = row_to_record(row)?;
            record.validate_settlement(unit, settlement)?;
            if already_settled {
                return Ok(false);
            }

            let affected = query(
                r#"
                UPDATE rate_quote_terms
                SET settled = 1
                WHERE payment_lookup_id = :payment_lookup_id AND settled = 0
                "#,
            )
            .map_err(storage_error)?
            .bind("payment_lookup_id", payment_lookup_id.to_string())
            .execute(&*conn)
            .await
            .map_err(storage_error)?;

            if affected == 0 {
                return Ok(false);
            }

            match settlement {
                RateQuoteSettlement::MintCredit {
                    fiat_subunits,
                    buffer_surplus_sats,
                } => {
                    query(
                        r#"
                        INSERT INTO rate_unit_control (unit, outstanding, buffer_surplus_sats)
                        VALUES (:unit, :outstanding, :buffer_surplus_sats)
                        ON CONFLICT (unit) DO UPDATE SET
                            outstanding = rate_unit_control.outstanding + EXCLUDED.outstanding,
                            buffer_surplus_sats = rate_unit_control.buffer_surplus_sats + EXCLUDED.buffer_surplus_sats
                        "#,
                    )
                    .map_err(storage_error)?
                    .bind("unit", unit.to_string())
                    .bind("outstanding", checked_i64(fiat_subunits, "outstanding")?)
                    .bind(
                        "buffer_surplus_sats",
                        checked_i64(buffer_surplus_sats, "buffer_surplus_sats")?,
                    )
                    .execute(&*conn)
                    .await
                    .map_err(storage_error)?;
                }
                RateQuoteSettlement::Melt { fiat_subunits } => {
                    query(
                        r#"
                        INSERT INTO rate_unit_control (unit, outstanding)
                        VALUES (:unit, 0)
                        ON CONFLICT (unit) DO UPDATE SET
                            outstanding = GREATEST(rate_unit_control.outstanding - :melted, 0)
                        "#,
                    )
                    .map_err(storage_error)?
                    .bind("unit", unit.to_string())
                    .bind("melted", checked_i64(fiat_subunits, "melted")?)
                    .execute(&*conn)
                    .await
                    .map_err(storage_error)?;
                }
            }

            Ok(true)
        }
        .await;

        match result {
            Ok(settled) => {
                query("COMMIT")
                    .map_err(storage_error)?
                    .execute(&*conn)
                    .await
                    .map_err(storage_error)?;
                Ok(settled)
            }
            Err(error) => {
                if let Ok(rollback) = query("ROLLBACK") {
                    let _ = rollback.execute(&*conn).await;
                }
                Err(error)
            }
        }
    }

    async fn load_unit_controls(&self) -> Result<Vec<UnitControlRecord>, RateQuoteStoreError> {
        let conn = self.conn().await?;

        let rows = query(
            r#"
            SELECT unit, mint_paused, melt_paused, cap, outstanding, buffer_surplus_sats
            FROM rate_unit_control
            "#,
        )
        .map_err(storage_error)?
        .fetch_all(&*conn)
        .await
        .map_err(storage_error)?;

        rows.into_iter().map(row_to_unit_control).collect()
    }

    async fn load_active_mint_reservations(
        &self,
        now_unix: u64,
    ) -> Result<Vec<ActiveMintReservation>, RateQuoteStoreError> {
        let conn = self.conn().await?;
        let rows = query(SELECT_ACTIVE_MINT_RESERVATIONS_SQL)
            .map_err(storage_error)?
            .bind("now_unix", checked_i64(now_unix, "now_unix")?)
            .fetch_all(&*conn)
            .await
            .map_err(storage_error)?;
        rows.into_iter()
            .map(|row| row_to_active_mint_reservation(row, now_unix))
            .collect()
    }

    async fn set_unit_quote_state(
        &self,
        unit: &CurrencyUnit,
        mint_paused: bool,
        melt_paused: bool,
    ) -> Result<(), RateQuoteStoreError> {
        let conn = self.conn().await?;

        query(
            r#"
            INSERT INTO rate_unit_control (unit, mint_paused, melt_paused)
            VALUES (:unit, :mint_paused, :melt_paused)
            ON CONFLICT (unit) DO UPDATE SET
                mint_paused = EXCLUDED.mint_paused,
                melt_paused = EXCLUDED.melt_paused
            "#,
        )
        .map_err(storage_error)?
        .bind("unit", unit.to_string())
        .bind("mint_paused", i64::from(mint_paused))
        .bind("melt_paused", i64::from(melt_paused))
        .execute(&*conn)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn set_unit_issuance_cap(
        &self,
        unit: &CurrencyUnit,
        cap: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let conn = self.conn().await?;

        query(
            r#"
            INSERT INTO rate_unit_control (unit, cap)
            VALUES (:unit, :cap)
            ON CONFLICT (unit) DO UPDATE SET cap = EXCLUDED.cap
            "#,
        )
        .map_err(storage_error)?
        .bind("unit", unit.to_string())
        .bind("cap", checked_i64(cap, "cap")?)
        .execute(&*conn)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn add_unit_outstanding(
        &self,
        unit: &CurrencyUnit,
        fiat_subunits: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let conn = self.conn().await?;

        query(
            r#"
            INSERT INTO rate_unit_control (unit, outstanding)
            VALUES (:unit, :outstanding)
            ON CONFLICT (unit) DO UPDATE SET
                outstanding = rate_unit_control.outstanding + EXCLUDED.outstanding
            "#,
        )
        .map_err(storage_error)?
        .bind("unit", unit.to_string())
        .bind("outstanding", checked_i64(fiat_subunits, "outstanding")?)
        .execute(&*conn)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn subtract_unit_outstanding(
        &self,
        unit: &CurrencyUnit,
        fiat_subunits: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let conn = self.conn().await?;

        query(
            r#"
            UPDATE rate_unit_control
            SET outstanding = GREATEST(outstanding - :melted, 0)
            WHERE unit = :unit
            "#,
        )
        .map_err(storage_error)?
        .bind("unit", unit.to_string())
        .bind("melted", checked_i64(fiat_subunits, "melted")?)
        .execute(&*conn)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn add_unit_buffer_surplus(
        &self,
        unit: &CurrencyUnit,
        sats: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let conn = self.conn().await?;

        query(
            r#"
            INSERT INTO rate_unit_control (unit, buffer_surplus_sats)
            VALUES (:unit, :buffer_surplus_sats)
            ON CONFLICT (unit) DO UPDATE SET
                buffer_surplus_sats = rate_unit_control.buffer_surplus_sats + EXCLUDED.buffer_surplus_sats
            "#,
        )
        .map_err(storage_error)?
        .bind("unit", unit.to_string())
        .bind(
            "buffer_surplus_sats",
            checked_i64(sats, "buffer_surplus_sats")?,
        )
        .execute(&*conn)
        .await
        .map_err(storage_error)?;

        Ok(())
    }
}

fn row_to_record(
    row: Vec<cdk_sql_common::stmt::Column>,
) -> Result<RateQuoteRecord, RateQuoteStoreError> {
    if row.len() < 9 {
        return Err(RateQuoteStoreError::Storage(
            "rate quote row had too few columns".to_string(),
        ));
    }

    let payment_lookup_id = text_col(&row[0])?;
    let fiat_unit = text_col(&row[1])?
        .parse::<CurrencyUnit>()
        .map_err(storage_error)?;
    let snapshot_json = serde_json::from_str(&text_col(&row[4])?).map_err(storage_error)?;
    let side = text_col(&row[8])?
        .parse::<RateQuoteSide>()
        .map_err(storage_error)?;

    Ok(RateQuoteRecord {
        payment_lookup_id: PaymentIdentifier::CustomId(payment_lookup_id),
        side,
        fiat_unit,
        fiat_subunits: int_col(&row[2])?,
        fiat_fee_subunits: int_col(&row[3])?,
        snapshot_json,
        sats_invoiced: int_col(&row[5])?,
        sats_unbuffered: int_col(&row[6])?,
        expiry_unix: int_col(&row[7])?,
    })
}

fn row_to_unit_control(
    row: Vec<cdk_sql_common::stmt::Column>,
) -> Result<UnitControlRecord, RateQuoteStoreError> {
    if row.len() < 6 {
        return Err(RateQuoteStoreError::Storage(
            "rate unit control row had too few columns".to_string(),
        ));
    }

    let unit = text_col(&row[0])?
        .parse::<CurrencyUnit>()
        .map_err(storage_error)?;

    Ok(UnitControlRecord {
        unit,
        mint_paused: int_col(&row[1])? != 0,
        melt_paused: int_col(&row[2])? != 0,
        cap: int_col(&row[3])?,
        outstanding: int_col(&row[4])?,
        buffer_surplus_sats: int_col(&row[5])?,
    })
}

fn row_to_active_mint_reservation(
    row: Vec<cdk_sql_common::stmt::Column>,
    now_unix: u64,
) -> Result<ActiveMintReservation, RateQuoteStoreError> {
    if row.len() != 4 {
        return Err(RateQuoteStoreError::Storage(format!(
            "active mint reservation row had {} columns, expected 4",
            row.len()
        )));
    }
    let payment_lookup_id = PaymentIdentifier::CustomId(text_col(&row[0])?);
    let fiat_unit = text_col(&row[1])?
        .parse::<CurrencyUnit>()
        .map_err(storage_error)?;
    ActiveMintReservation::new(
        payment_lookup_id,
        fiat_unit,
        int_col(&row[2])?,
        int_col(&row[3])?,
        now_unix,
    )
}

fn checked_i64(value: u64, column: &str) -> Result<i64, RateQuoteStoreError> {
    i64::try_from(value).map_err(|_| {
        RateQuoteStoreError::Storage(format!("{column} value {value} exceeds postgres BIGINT"))
    })
}

fn text_col(value: &cdk_sql_common::stmt::Column) -> Result<String, RateQuoteStoreError> {
    match value {
        cdk_sql_common::value::Value::Text(text) => Ok(text.clone()),
        other => Err(RateQuoteStoreError::Storage(format!(
            "expected text column, got {other:?}"
        ))),
    }
}

fn int_col(value: &cdk_sql_common::stmt::Column) -> Result<u64, RateQuoteStoreError> {
    match value {
        cdk_sql_common::value::Value::Integer(value) => {
            u64::try_from(*value).map_err(|error| RateQuoteStoreError::Storage(error.to_string()))
        }
        other => Err(RateQuoteStoreError::Storage(format!(
            "expected integer column, got {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use cdk_sql_common::value::Value;

    use super::*;

    /// Live-Postgres store with an isolated schema per test.
    async fn store(test_id: &str) -> PostgresRateQuoteStore {
        static SCHEMA_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

        let db_url = std::env::var("CDK_MINTD_DATABASE_URL")
            .or_else(|_| std::env::var("PG_DB_URL"))
            .unwrap_or(
                "host=localhost user=cdk_user password=cdk_password dbname=cdk_mint port=5432"
                    .to_owned(),
            );
        let schema_sequence = SCHEMA_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let db_url = format!(
            "{db_url} schema=rate_quote_{test_id}_{}_{}",
            std::process::id(),
            schema_sequence
        );
        PostgresRateQuoteStore::new(&db_url).await.expect("store")
    }

    fn record(lookup_id: &str, side: RateQuoteSide) -> RateQuoteRecord {
        RateQuoteRecord {
            payment_lookup_id: PaymentIdentifier::CustomId(lookup_id.to_string()),
            side,
            fiat_unit: CurrencyUnit::Usd,
            fiat_subunits: 100,
            fiat_fee_subunits: 3,
            snapshot_json: serde_json::json!({ "buffer_bps": 100 }),
            sats_invoiced: 1010,
            sats_unbuffered: 1000,
            expiry_unix: 42,
        }
    }

    fn parked(lookup_id: &str) -> ParkedPaymentRecord {
        ParkedPaymentRecord {
            payment_lookup_id: PaymentIdentifier::CustomId(lookup_id.to_string()),
            bolt11_payment_hash: format!("hash-{lookup_id}"),
            received_sats: 1010,
            observed_at: 7,
            resolution_status: "parked".to_string(),
        }
    }

    #[test]
    fn active_mint_reservation_query_uses_authoritative_filters() {
        let sql = SELECT_ACTIVE_MINT_RESERVATIONS_SQL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        assert!(sql.contains("WHERE side = 'mint' AND settled = 0 AND expiry_unix > :now_unix"));
        assert!(sql.ends_with("ORDER BY payment_lookup_id"));
        assert!(!sql.contains("expiry_unix >= :now_unix"));
    }

    #[test]
    fn active_mint_reservation_decoder_enforces_shape_types_and_expiry() {
        let row = vec![
            Value::Text("lookup".to_string()),
            Value::Text("usd".to_string()),
            Value::Integer(100),
            Value::Integer(101),
        ];
        let reservation =
            row_to_active_mint_reservation(row.clone(), 100).expect("valid projection row");
        assert_eq!(
            reservation.payment_lookup_id,
            PaymentIdentifier::CustomId("lookup".to_string())
        );
        assert_eq!(reservation.fiat_unit, CurrencyUnit::Usd);
        assert_eq!(reservation.fiat_subunits, 100);
        assert_eq!(reservation.expiry_unix, 101);

        assert!(row_to_active_mint_reservation(row[..3].to_vec(), 100).is_err());
        assert!(row_to_active_mint_reservation(
            vec![
                Value::Text("lookup".to_string()),
                Value::Text("usd".to_string()),
                Value::Integer(-1),
                Value::Integer(101),
            ],
            100,
        )
        .is_err());
        assert!(row_to_active_mint_reservation(row, 101).is_err());
    }

    #[tokio::test]
    async fn quote_terms_round_trip() {
        let store = store("round_trip").await;
        let mint_record = record("rt-mint", RateQuoteSide::Mint);
        let melt_record = record("rt-melt", RateQuoteSide::Melt);

        store
            .insert(mint_record.clone())
            .await
            .expect("insert mint");
        store
            .insert(melt_record.clone())
            .await
            .expect("insert melt");
        let loaded_mint = store
            .get_by_lookup_id(&mint_record.payment_lookup_id)
            .await
            .expect("lookup")
            .expect("record");
        let loaded_melt = store
            .get_by_lookup_id(&melt_record.payment_lookup_id)
            .await
            .expect("lookup")
            .expect("record");

        assert_eq!(loaded_mint, mint_record);
        assert_eq!(loaded_melt, melt_record);
    }

    #[tokio::test]
    async fn active_mint_reservations_filter_side_settlement_and_expiry() {
        let store = store("active_reservations").await;
        let now_unix = 100;
        let mut active = record("active", RateQuoteSide::Mint);
        active.expiry_unix = now_unix + 1;
        let mut expired = record("expired", RateQuoteSide::Mint);
        expired.expiry_unix = now_unix;
        let mut melt = record("melt", RateQuoteSide::Melt);
        melt.expiry_unix = now_unix + 1;
        let mut settled = record("settled", RateQuoteSide::Mint);
        settled.expiry_unix = now_unix + 1;

        for record in [active.clone(), expired, melt, settled.clone()] {
            store.insert(record).await.expect("insert quote terms");
        }
        store
            .mark_settled(&settled.payment_lookup_id)
            .await
            .expect("mark settled");

        let reservations = store
            .load_active_mint_reservations(now_unix)
            .await
            .expect("load active reservations");
        assert_eq!(
            reservations,
            vec![ActiveMintReservation::new(
                active.payment_lookup_id,
                active.fiat_unit,
                active.fiat_subunits,
                active.expiry_unix,
                now_unix,
            )
            .expect("active projection")]
        );
    }

    #[tokio::test]
    async fn rate_quote_schema_rejects_invalid_persisted_values() {
        let store = store("side_constraints").await;
        let conn = store.conn().await.expect("connection");

        let missing = query(
            r#"
            INSERT INTO rate_quote_terms
                (payment_lookup_id, fiat_unit, fiat_subunits, snapshot_json, sats_invoiced, expiry_unix)
            VALUES
                ('missing-side', 'usd', 100, '{}', 1000, 42)
            "#,
        )
        .expect("missing-side query")
        .execute(&*conn)
        .await;
        assert!(missing.is_err(), "side must be NOT NULL with no default");

        let unknown = query(
            r#"
            INSERT INTO rate_quote_terms
                (payment_lookup_id, side, fiat_unit, fiat_subunits, snapshot_json, sats_invoiced, expiry_unix)
            VALUES
                ('unknown-side', 'unknown', 'usd', 100, '{}', 1000, 42)
            "#,
        )
        .expect("unknown-side query")
        .execute(&*conn)
        .await;
        assert!(unknown.is_err(), "side CHECK must reject unknown values");

        let negative = query(
            r#"
            INSERT INTO rate_quote_terms
                (payment_lookup_id, side, fiat_unit, fiat_subunits, snapshot_json, sats_invoiced, expiry_unix)
            VALUES
                ('negative-amount', 'mint', 'usd', -1, '{}', 1000, 42)
            "#,
        )
        .expect("negative query")
        .execute(&*conn)
        .await;
        assert!(
            negative.is_err(),
            "u64-backed columns must reject negatives"
        );

        let invalid_unbuffered = query(
            r#"
            INSERT INTO rate_quote_terms
                (payment_lookup_id, side, fiat_unit, fiat_subunits, snapshot_json, sats_invoiced, sats_unbuffered, expiry_unix)
            VALUES
                ('invalid-unbuffered', 'mint', 'usd', 100, '{}', 1000, 1001, 42)
            "#,
        )
        .expect("unbuffered query")
        .execute(&*conn)
        .await;
        assert!(
            invalid_unbuffered.is_err(),
            "unbuffered sats must not exceed invoiced sats"
        );

        let invalid_settled = query(
            r#"
            INSERT INTO rate_quote_terms
                (payment_lookup_id, side, fiat_unit, fiat_subunits, snapshot_json, sats_invoiced, expiry_unix, settled)
            VALUES
                ('invalid-settled', 'mint', 'usd', 100, '{}', 1000, 42, 2)
            "#,
        )
        .expect("settled query")
        .execute(&*conn)
        .await;
        assert!(
            invalid_settled.is_err(),
            "settled flag must be boolean-valued"
        );

        let invalid_control = query(
            r#"
            INSERT INTO rate_unit_control
                (unit, mint_paused, melt_paused, cap)
            VALUES
                ('usd', 2, 0, -1)
            "#,
        )
        .expect("control query")
        .execute(&*conn)
        .await;
        assert!(
            invalid_control.is_err(),
            "unit control booleans and counters must be constrained"
        );

        let invalid_parked = query(
            r#"
            INSERT INTO parked_payments
                (payment_lookup_id, bolt11_payment_hash, received_sats, observed_at, resolution_status)
            VALUES
                ('negative-parked', 'hash', -1, -1, 'parked')
            "#,
        )
        .expect("parked query")
        .execute(&*conn)
        .await;
        assert!(
            invalid_parked.is_err(),
            "parked u64-backed columns must reject negatives"
        );
    }

    #[tokio::test]
    async fn park_or_credit_returns_terms_or_parks() {
        let store = store("park_or_credit").await;
        let record = record("poc-1", RateQuoteSide::Mint);
        store.insert(record.clone()).await.expect("insert");

        let credited = store
            .park_or_credit(parked("poc-1"))
            .await
            .expect("park_or_credit");
        assert_eq!(credited, Some(record));

        let parked_result = store
            .park_or_credit(parked("poc-orphan"))
            .await
            .expect("park_or_credit");
        assert_eq!(parked_result, None);
    }

    #[tokio::test]
    async fn mark_settled_returns_true_exactly_once() {
        let store = store("mark_settled").await;
        let record = record("ms-1", RateQuoteSide::Mint);
        store.insert(record.clone()).await.expect("insert");

        assert!(store
            .mark_settled(&record.payment_lookup_id)
            .await
            .expect("first settle"));
        assert!(!store
            .mark_settled(&record.payment_lookup_id)
            .await
            .expect("second settle"));
        // Unknown lookup ids settle nothing.
        assert!(!store
            .mark_settled(&PaymentIdentifier::CustomId("ms-missing".to_string()))
            .await
            .expect("missing settle"));
    }

    #[tokio::test]
    async fn settle_quote_and_commit_unit_control_is_one_shot() {
        let store = store("settle_commit").await;
        let mint_record = record("sc-mint", RateQuoteSide::Mint);
        let mut melt_record = record("sc-melt", RateQuoteSide::Melt);
        melt_record.fiat_subunits = 37;
        let usd = CurrencyUnit::Usd;
        store
            .insert(mint_record.clone())
            .await
            .expect("insert mint");
        store
            .insert(melt_record.clone())
            .await
            .expect("insert melt");

        for (unit, settlement) in [
            (
                CurrencyUnit::Usd,
                RateQuoteSettlement::Melt { fiat_subunits: 100 },
            ),
            (
                CurrencyUnit::Eur,
                RateQuoteSettlement::MintCredit {
                    fiat_subunits: 100,
                    buffer_surplus_sats: 10,
                },
            ),
            (
                CurrencyUnit::Usd,
                RateQuoteSettlement::MintCredit {
                    fiat_subunits: 101,
                    buffer_surplus_sats: 10,
                },
            ),
        ] {
            let error = store
                .settle_quote_and_commit_unit_control(
                    &mint_record.payment_lookup_id,
                    &unit,
                    settlement,
                )
                .await
                .expect_err("conflicting settlement must fail");
            assert!(matches!(error, RateQuoteStoreError::InvalidSettlement(_)));
            assert!(
                store
                    .load_unit_controls()
                    .await
                    .expect("controls")
                    .is_empty(),
                "invalid settlement must not mutate unit control"
            );
        }

        assert!(store
            .settle_quote_and_commit_unit_control(
                &mint_record.payment_lookup_id,
                &usd,
                RateQuoteSettlement::MintCredit {
                    fiat_subunits: 100,
                    buffer_surplus_sats: 10,
                },
            )
            .await
            .expect("settle mint"));
        assert!(!store
            .settle_quote_and_commit_unit_control(
                &mint_record.payment_lookup_id,
                &usd,
                RateQuoteSettlement::MintCredit {
                    fiat_subunits: 100,
                    buffer_surplus_sats: 10,
                },
            )
            .await
            .expect("settle mint again"));

        let controls = store.load_unit_controls().await.expect("load controls");
        let usd_control = controls
            .iter()
            .find(|control| control.unit == usd)
            .expect("usd control after mint");
        assert_eq!(usd_control.outstanding, 100);
        assert_eq!(usd_control.buffer_surplus_sats, 10);

        assert!(store
            .settle_quote_and_commit_unit_control(
                &melt_record.payment_lookup_id,
                &usd,
                RateQuoteSettlement::Melt { fiat_subunits: 40 },
            )
            .await
            .expect("settle melt"));
        assert!(!store
            .settle_quote_and_commit_unit_control(
                &melt_record.payment_lookup_id,
                &usd,
                RateQuoteSettlement::Melt { fiat_subunits: 40 },
            )
            .await
            .expect("settle melt again"));

        let controls = store.load_unit_controls().await.expect("load controls");
        let usd_control = controls
            .iter()
            .find(|control| control.unit == usd)
            .expect("usd control after melt");
        assert_eq!(usd_control.outstanding, 60);
        assert_eq!(usd_control.buffer_surplus_sats, 10);
    }

    #[tokio::test]
    async fn unit_control_state_round_trips() {
        let store = store("unit_control").await;
        let usd = CurrencyUnit::Usd;

        store
            .set_unit_quote_state(&usd, true, false)
            .await
            .expect("pause");
        store.set_unit_issuance_cap(&usd, 500).await.expect("cap");
        store.add_unit_outstanding(&usd, 200).await.expect("add");
        store
            .subtract_unit_outstanding(&usd, 50)
            .await
            .expect("subtract");
        // Subtraction floors at zero rather than going negative.
        store
            .subtract_unit_outstanding(&CurrencyUnit::Eur, 10)
            .await
            .expect("subtract missing unit");
        store
            .add_unit_buffer_surplus(&usd, 12)
            .await
            .expect("surplus");

        let controls = store.load_unit_controls().await.expect("load");
        let usd_control = controls
            .iter()
            .find(|control| control.unit == usd)
            .expect("usd control");
        assert!(usd_control.mint_paused);
        assert!(!usd_control.melt_paused);
        assert_eq!(usd_control.cap, 500);
        assert_eq!(usd_control.outstanding, 150);
        assert_eq!(usd_control.buffer_surplus_sats, 12);
    }
}
