//! Durable storage contracts for rate-quoted payment terms.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::PaymentIdentifier;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Direction of the outer rate-converted quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateQuoteSide {
    /// Fiat liability is issued after an incoming payment.
    Mint,
    /// Fiat liability is retired after an outgoing payment.
    Melt,
}

impl RateQuoteSide {
    /// Stable lowercase database representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Melt => "melt",
        }
    }
}

impl std::fmt::Display for RateQuoteSide {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for RateQuoteSide {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mint" => Ok(Self::Mint),
            "melt" => Ok(Self::Melt),
            other => Err(format!("invalid rate quote side: {other}")),
        }
    }
}

/// Stored immutable terms for one rate-converted payment lookup id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateQuoteRecord {
    /// Inner payment backend lookup id.
    pub payment_lookup_id: PaymentIdentifier,
    /// Direction of the outer rate-converted quote.
    pub side: RateQuoteSide,
    /// Fiat unit credited or debited by the outer mint quote.
    pub fiat_unit: CurrencyUnit,
    /// Fiat amount in that unit's minor subunits.
    pub fiat_subunits: u64,
    /// Fiat fee in that unit's minor subunits.
    #[serde(default)]
    pub fiat_fee_subunits: u64,
    /// Serialized oracle snapshot and quote metadata.
    pub snapshot_json: serde_json::Value,
    /// Sat amount requested from the inner backend.
    pub sats_invoiced: u64,
    /// Sat amount the quote would have required without the buffer. The
    /// difference between the received sats and this value is booked to the
    /// per-unit buffer-surplus reserve when the quote settles.
    #[serde(default)]
    pub sats_unbuffered: u64,
    /// Quote expiry as a Unix timestamp in seconds.
    pub expiry_unix: u64,
}

impl RateQuoteRecord {
    /// Validate a settlement intent against the immutable persisted terms.
    pub fn validate_settlement(
        &self,
        unit: &CurrencyUnit,
        settlement: RateQuoteSettlement,
    ) -> Result<(), RateQuoteStoreError> {
        if &self.fiat_unit != unit {
            return Err(RateQuoteStoreError::InvalidSettlement(format!(
                "stored unit {} does not match requested unit {unit}",
                self.fiat_unit
            )));
        }

        let (expected_side, settled_subunits) = match settlement {
            RateQuoteSettlement::MintCredit { fiat_subunits, .. } => {
                (RateQuoteSide::Mint, fiat_subunits)
            }
            RateQuoteSettlement::Melt { fiat_subunits } => (RateQuoteSide::Melt, fiat_subunits),
        };
        if self.side != expected_side {
            return Err(RateQuoteStoreError::InvalidSettlement(format!(
                "stored side {} does not match requested side {expected_side}",
                self.side
            )));
        }

        let expected_subunits = match self.side {
            RateQuoteSide::Mint => self.fiat_subunits,
            RateQuoteSide::Melt => self
                .fiat_subunits
                .checked_add(self.fiat_fee_subunits)
                .ok_or_else(|| {
                    RateQuoteStoreError::InvalidSettlement(
                        "stored fiat amount and fee overflow".to_string(),
                    )
                })?,
        };
        if settled_subunits != expected_subunits {
            return Err(RateQuoteStoreError::InvalidSettlement(format!(
                "settlement amount {settled_subunits} does not match stored amount {expected_subunits}"
            )));
        }

        Ok(())
    }
}

/// Parked payment row for fail-closed orphaned payment events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedPaymentRecord {
    /// Inner payment backend lookup id.
    pub payment_lookup_id: PaymentIdentifier,
    /// BOLT11 payment hash used as an operator reconciliation join key.
    pub bolt11_payment_hash: String,
    /// Received sat amount.
    pub received_sats: u64,
    /// Observation time as a Unix timestamp in seconds.
    pub observed_at: u64,
    /// Operator reconciliation status.
    pub resolution_status: String,
}

/// Persisted runtime control state for one rate-quoted unit.
///
/// Pause flags, the issuance cap, the outstanding issued counter
/// (issued minus melted), and the buffer-surplus reserve all survive
/// process restarts through this record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitControlRecord {
    /// Controlled unit.
    pub unit: CurrencyUnit,
    /// Refuse new mint quotes for this unit.
    pub mint_paused: bool,
    /// Refuse new melt quotes for this unit.
    pub melt_paused: bool,
    /// Issuance cap in fiat subunits. `0` refuses all new mint quotes
    /// (fail-closed) — it never means unlimited.
    pub cap: u64,
    /// Outstanding issued fiat subunits (issued minus melted).
    pub outstanding: u64,
    /// Accumulated buffer-surplus reserve in sats. Reserve, not revenue.
    pub buffer_surplus_sats: u64,
}

impl UnitControlRecord {
    /// Create an empty control record for one unit.
    pub fn new(unit: CurrencyUnit) -> Self {
        Self {
            unit,
            ..Self::default()
        }
    }
}

/// One-shot unit-control effect applied when a quote settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateQuoteSettlement {
    /// A mint invoice was paid and fiat liability was issued.
    MintCredit {
        /// Fiat subunits issued.
        fiat_subunits: u64,
        /// Sats booked into the buffer-surplus reserve.
        buffer_surplus_sats: u64,
    },
    /// A melt invoice was paid and fiat liability was retired.
    Melt {
        /// Fiat subunits retired.
        fiat_subunits: u64,
    },
}

/// Storage failure returned by [`RateQuoteStore`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum RateQuoteStoreError {
    /// Invalid unit-control request.
    #[error("invalid rate quote control request: {0}")]
    InvalidControl(String),
    /// Settlement intent conflicts with immutable quote terms.
    #[error("invalid rate quote settlement: {0}")]
    InvalidSettlement(String),
    /// A quote already exists for the payment lookup id.
    #[error("duplicate rate quote lookup id: {0}")]
    DuplicateQuote(String),
    /// Storage backend error.
    #[error("rate quote store error: {0}")]
    Storage(String),
}

/// Durable storage port for rate-converted quote terms and parked payments.
#[async_trait]
pub trait RateQuoteStore: Send + Sync {
    /// Persist immutable quoted terms before the quote is returned upstream.
    async fn insert(&self, record: RateQuoteRecord) -> Result<(), RateQuoteStoreError>;

    /// Load stored quoted terms by inner payment lookup id.
    async fn get_by_lookup_id(
        &self,
        payment_lookup_id: &PaymentIdentifier,
    ) -> Result<Option<RateQuoteRecord>, RateQuoteStoreError>;

    /// Persist an orphaned payment for operator reconciliation.
    async fn insert_parked(&self, record: ParkedPaymentRecord) -> Result<(), RateQuoteStoreError>;

    /// Atomically look up quoted terms for a received payment, parking the
    /// payment in the same storage operation when no terms exist.
    ///
    /// Returns the stored terms when the payment can be credited, or `None`
    /// when the payment was parked. The detection of the missing record and
    /// the parked-row write happen in one transaction so no orphaned payment
    /// is silently lost.
    async fn park_or_credit(
        &self,
        parked: ParkedPaymentRecord,
    ) -> Result<Option<RateQuoteRecord>, RateQuoteStoreError>;

    /// Atomically mark a quote settled. Returns `true` exactly once per
    /// lookup id — callers gate one-shot counter adjustments (outstanding,
    /// buffer surplus) on the `true` result.
    async fn mark_settled(
        &self,
        payment_lookup_id: &PaymentIdentifier,
    ) -> Result<bool, RateQuoteStoreError>;

    /// Atomically mark a quote settled and apply its one-shot unit-control
    /// effect. Returns `true` exactly once per lookup id; `false` means the
    /// quote was already settled or did not exist.
    async fn settle_quote_and_commit_unit_control(
        &self,
        payment_lookup_id: &PaymentIdentifier,
        unit: &CurrencyUnit,
        settlement: RateQuoteSettlement,
    ) -> Result<bool, RateQuoteStoreError>;

    /// Load all persisted per-unit control records.
    async fn load_unit_controls(&self) -> Result<Vec<UnitControlRecord>, RateQuoteStoreError>;

    /// Persist pause state for one unit.
    async fn set_unit_quote_state(
        &self,
        unit: &CurrencyUnit,
        mint_paused: bool,
        melt_paused: bool,
    ) -> Result<(), RateQuoteStoreError>;

    /// Persist the issuance cap for one unit.
    async fn set_unit_issuance_cap(
        &self,
        unit: &CurrencyUnit,
        cap: u64,
    ) -> Result<(), RateQuoteStoreError>;

    /// Atomically add issued fiat subunits to the unit's outstanding counter.
    async fn add_unit_outstanding(
        &self,
        unit: &CurrencyUnit,
        fiat_subunits: u64,
    ) -> Result<(), RateQuoteStoreError>;

    /// Atomically subtract melted fiat subunits from the unit's outstanding
    /// counter, flooring at zero.
    async fn subtract_unit_outstanding(
        &self,
        unit: &CurrencyUnit,
        fiat_subunits: u64,
    ) -> Result<(), RateQuoteStoreError>;

    /// Atomically add sats to the unit's buffer-surplus reserve counter.
    async fn add_unit_buffer_surplus(
        &self,
        unit: &CurrencyUnit,
        sats: u64,
    ) -> Result<(), RateQuoteStoreError>;
}

/// Shared trait-object rate quote store.
pub type DynRateQuoteStore = Arc<dyn RateQuoteStore>;

/// In-memory [`RateQuoteStore`] for tests and ephemeral development.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRateQuoteStore {
    inner: Arc<Mutex<InMemoryRateQuoteStoreState>>,
}

#[derive(Debug, Default)]
struct InMemoryRateQuoteStoreState {
    records: HashMap<String, RateQuoteRecord>,
    parked: Vec<ParkedPaymentRecord>,
    settled: HashSet<String>,
    unit_controls: HashMap<CurrencyUnit, UnitControlRecord>,
    fail_next_insert: bool,
    fail_next_settle: bool,
}

impl InMemoryRateQuoteStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cause the next quoted-terms insert to fail.
    pub async fn fail_next_insert(&self) {
        self.inner.lock().await.fail_next_insert = true;
    }

    /// Cause the next atomic settle operation to fail before applying any
    /// settled flag or unit-control effect.
    pub async fn fail_next_settle(&self) {
        self.inner.lock().await.fail_next_settle = true;
    }

    /// Return all parked payment records.
    pub async fn parked_payments(&self) -> Vec<ParkedPaymentRecord> {
        self.inner.lock().await.parked.clone()
    }
}

#[async_trait]
impl RateQuoteStore for InMemoryRateQuoteStore {
    async fn insert(&self, record: RateQuoteRecord) -> Result<(), RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        if inner.fail_next_insert {
            inner.fail_next_insert = false;
            return Err(RateQuoteStoreError::Storage(
                "forced in-memory insert failure".to_string(),
            ));
        }

        let key = record.payment_lookup_id.to_string();
        if inner.records.contains_key(&key) {
            return Err(RateQuoteStoreError::DuplicateQuote(key));
        }
        inner.records.insert(key, record);
        Ok(())
    }

    async fn get_by_lookup_id(
        &self,
        payment_lookup_id: &PaymentIdentifier,
    ) -> Result<Option<RateQuoteRecord>, RateQuoteStoreError> {
        Ok(self
            .inner
            .lock()
            .await
            .records
            .get(&payment_lookup_id.to_string())
            .cloned())
    }

    async fn insert_parked(&self, record: ParkedPaymentRecord) -> Result<(), RateQuoteStoreError> {
        self.inner.lock().await.parked.push(record);
        Ok(())
    }

    async fn park_or_credit(
        &self,
        parked: ParkedPaymentRecord,
    ) -> Result<Option<RateQuoteRecord>, RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        match inner.records.get(&parked.payment_lookup_id.to_string()) {
            Some(record) => Ok(Some(record.clone())),
            None => {
                inner.parked.push(parked);
                Ok(None)
            }
        }
    }

    async fn mark_settled(
        &self,
        payment_lookup_id: &PaymentIdentifier,
    ) -> Result<bool, RateQuoteStoreError> {
        Ok(self
            .inner
            .lock()
            .await
            .settled
            .insert(payment_lookup_id.to_string()))
    }

    async fn settle_quote_and_commit_unit_control(
        &self,
        payment_lookup_id: &PaymentIdentifier,
        unit: &CurrencyUnit,
        settlement: RateQuoteSettlement,
    ) -> Result<bool, RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        if inner.fail_next_settle {
            inner.fail_next_settle = false;
            return Err(RateQuoteStoreError::Storage(
                "forced in-memory settle failure".to_string(),
            ));
        }
        let key = payment_lookup_id.to_string();
        let Some(record) = inner.records.get(&key) else {
            return Ok(false);
        };
        record.validate_settlement(unit, settlement)?;
        if !inner.settled.insert(key) {
            return Ok(false);
        }

        let control = inner
            .unit_controls
            .entry(unit.clone())
            .or_insert_with(|| UnitControlRecord::new(unit.clone()));
        match settlement {
            RateQuoteSettlement::MintCredit {
                fiat_subunits,
                buffer_surplus_sats,
            } => {
                control.outstanding = control.outstanding.saturating_add(fiat_subunits);
                control.buffer_surplus_sats = control
                    .buffer_surplus_sats
                    .saturating_add(buffer_surplus_sats);
            }
            RateQuoteSettlement::Melt { fiat_subunits } => {
                control.outstanding = control.outstanding.saturating_sub(fiat_subunits);
            }
        }
        Ok(true)
    }

    async fn load_unit_controls(&self) -> Result<Vec<UnitControlRecord>, RateQuoteStoreError> {
        Ok(self
            .inner
            .lock()
            .await
            .unit_controls
            .values()
            .cloned()
            .collect())
    }

    async fn set_unit_quote_state(
        &self,
        unit: &CurrencyUnit,
        mint_paused: bool,
        melt_paused: bool,
    ) -> Result<(), RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        let controls = &mut inner.unit_controls;
        let control = controls
            .entry(unit.clone())
            .or_insert_with(|| UnitControlRecord::new(unit.clone()));
        control.mint_paused = mint_paused;
        control.melt_paused = melt_paused;
        Ok(())
    }

    async fn set_unit_issuance_cap(
        &self,
        unit: &CurrencyUnit,
        cap: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        let controls = &mut inner.unit_controls;
        let control = controls
            .entry(unit.clone())
            .or_insert_with(|| UnitControlRecord::new(unit.clone()));
        control.cap = cap;
        Ok(())
    }

    async fn add_unit_outstanding(
        &self,
        unit: &CurrencyUnit,
        fiat_subunits: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        let controls = &mut inner.unit_controls;
        let control = controls
            .entry(unit.clone())
            .or_insert_with(|| UnitControlRecord::new(unit.clone()));
        control.outstanding = control.outstanding.saturating_add(fiat_subunits);
        Ok(())
    }

    async fn subtract_unit_outstanding(
        &self,
        unit: &CurrencyUnit,
        fiat_subunits: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        let controls = &mut inner.unit_controls;
        let control = controls
            .entry(unit.clone())
            .or_insert_with(|| UnitControlRecord::new(unit.clone()));
        control.outstanding = control.outstanding.saturating_sub(fiat_subunits);
        Ok(())
    }

    async fn add_unit_buffer_surplus(
        &self,
        unit: &CurrencyUnit,
        sats: u64,
    ) -> Result<(), RateQuoteStoreError> {
        let mut inner = self.inner.lock().await;
        let controls = &mut inner.unit_controls;
        let control = controls
            .entry(unit.clone())
            .or_insert_with(|| UnitControlRecord::new(unit.clone()));
        control.buffer_surplus_sats = control.buffer_surplus_sats.saturating_add(sats);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(lookup_id: &str, side: RateQuoteSide) -> RateQuoteRecord {
        RateQuoteRecord {
            payment_lookup_id: PaymentIdentifier::CustomId(lookup_id.to_string()),
            side,
            fiat_unit: CurrencyUnit::Usd,
            fiat_subunits: 100,
            fiat_fee_subunits: 2,
            snapshot_json: serde_json::json!({ "rate": 1_000 }),
            sats_invoiced: 1_000,
            sats_unbuffered: 990,
            expiry_unix: 42,
        }
    }

    #[tokio::test]
    async fn memory_store_round_trips_quote_side() {
        let store = InMemoryRateQuoteStore::new();

        for expected in [
            record("mint", RateQuoteSide::Mint),
            record("melt", RateQuoteSide::Melt),
        ] {
            store.insert(expected.clone()).await.expect("insert");
            let actual = store
                .get_by_lookup_id(&expected.payment_lookup_id)
                .await
                .expect("lookup")
                .expect("stored record");
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn memory_store_rejects_duplicate_lookup_id() {
        let store = InMemoryRateQuoteStore::new();
        let first = record("duplicate", RateQuoteSide::Mint);

        store.insert(first.clone()).await.expect("first insert");
        let error = store
            .insert(first)
            .await
            .expect_err("duplicate insert must fail");

        assert!(matches!(error, RateQuoteStoreError::DuplicateQuote(_)));
    }

    #[tokio::test]
    async fn invalid_settlement_does_not_mutate_and_correct_retry_commits_once() {
        let store = InMemoryRateQuoteStore::new();
        let quote = record("settlement", RateQuoteSide::Mint);
        store.insert(quote.clone()).await.expect("insert");

        for invalid in [
            (
                CurrencyUnit::Usd,
                RateQuoteSettlement::Melt {
                    fiat_subunits: quote.fiat_subunits,
                },
            ),
            (
                CurrencyUnit::Eur,
                RateQuoteSettlement::MintCredit {
                    fiat_subunits: quote.fiat_subunits,
                    buffer_surplus_sats: 10,
                },
            ),
            (
                CurrencyUnit::Usd,
                RateQuoteSettlement::MintCredit {
                    fiat_subunits: quote.fiat_subunits + 1,
                    buffer_surplus_sats: 10,
                },
            ),
        ] {
            let error = store
                .settle_quote_and_commit_unit_control(
                    &quote.payment_lookup_id,
                    &invalid.0,
                    invalid.1,
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

        let correct = RateQuoteSettlement::MintCredit {
            fiat_subunits: quote.fiat_subunits,
            buffer_surplus_sats: 10,
        };
        assert!(store
            .settle_quote_and_commit_unit_control(
                &quote.payment_lookup_id,
                &CurrencyUnit::Usd,
                correct,
            )
            .await
            .expect("correct retry"));
        assert!(!store
            .settle_quote_and_commit_unit_control(
                &quote.payment_lookup_id,
                &CurrencyUnit::Usd,
                correct,
            )
            .await
            .expect("idempotent retry"));

        let controls = store.load_unit_controls().await.expect("controls");
        assert_eq!(controls.len(), 1);
        assert_eq!(controls[0].outstanding, quote.fiat_subunits);
        assert_eq!(controls[0].buffer_surplus_sats, 10);
    }
}
