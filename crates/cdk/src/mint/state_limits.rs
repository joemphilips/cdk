//! Bounds on request-created mint state and on value outflow.
//!
//! - Unpaid mint quotes: a global cap on unexpired unpaid quotes, and the
//!   release of the payment backend state of expired unpaid quotes. The mint
//!   keeps every quote row, so a client still reads an expired quote as UNPAID.
//! - Melt outflow: a rolling budget per hour and per day for each unit.
//! - Liabilities: the outstanding ecash of each unit, for a solvency signal.
//! - Settlement output conflict records: deleted after the request's
//!   earliest authorization expiry plus a retention time.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cdk_common::common::PaymentProcessorKey;
use cdk_common::mint::MintQuote;
use cdk_common::quote_id::QuoteId;
use cdk_common::util::unix_time;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::Mint;
use crate::error::Error;
use crate::nuts::{CurrencyUnit, Id};

/// Time after the expiry of an unpaid quote before the mint releases its
/// backend state.
///
/// LDK accepts an HTLC for an invoice until two hours after its expiry, measured
/// against the newest block time, which can lag the clock. A payment that
/// arrives after the release cannot be credited, so the delay must be well
/// above that window.
pub const UNPAID_QUOTE_RETENTION_SECS: u64 = 6 * 60 * 60;
/// Time after the earliest authorization expiry of a refused settlement
/// request before maintenance deletes its output conflict record.
///
/// The mint checks the expiry of a request before its commit transaction. A
/// copy of the request that passes that check just before the cutoff can
/// reach the transaction after it, and only the record refuses it there. So
/// the record must outlive the cutoff by more than that window.
#[cfg(feature = "conditional-tokens")]
pub const OUTPUT_CONFLICT_RETENTION_SECS: u64 = 60 * 60;
/// The number of output conflict records that one delete transaction removes.
#[cfg(feature = "conditional-tokens")]
const OUTPUT_CONFLICT_DELETE_BATCH: u64 = 500;
/// The number of quotes that one read of the release pass returns.
const RELEASE_BATCH: u64 = 500;
/// The position of the release pass: the last finished (expiry, quote id).
const RELEASE_CURSOR_NAMESPACE: &str = "state_limits";
const RELEASE_CURSOR_KEY: &str = "unpaid_release_cursor";
/// The interval of the cleanup and liability task.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const HOUR_SECS: u64 = 60 * 60;
const DAY_SECS: u64 = 24 * HOUR_SECS;

/// Fixed log token of a melt refused by the outflow budget. Alert rules match it.
pub const MELT_BUDGET_EXCEEDED_TOKEN: &str = "MINT_MELT_BUDGET_EXCEEDED";
/// Fixed log token of the periodic liability line.
pub const LIABILITIES_TOKEN: &str = "MINT_LIABILITIES";
/// Fixed log token of a keyset that redeemed more than it issued. Alert rules match it.
pub const LIABILITY_ANOMALY_TOKEN: &str = "MINT_LIABILITY_ANOMALY";

/// The counts of one release pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReleaseSummary {
    /// Quotes whose backend state was released
    pub released: usize,
    /// Quotes with a backend payment that the mint had not recorded
    pub credited: usize,
}

/// A keyset that redeemed more than it issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiabilityAnomaly {
    /// The keyset
    pub keyset: Id,
    /// Its unit
    pub unit: CurrencyUnit,
    /// The redeemed amount above the issued amount
    pub excess: u64,
}

/// The outstanding ecash of each unit, and the keysets that cannot be valued.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Liabilities {
    /// The outstanding ecash of each unit
    pub totals: HashMap<CurrencyUnit, u64>,
    /// Keysets that redeemed more than they issued. Each counts as zero in the totals.
    pub anomalies: Vec<LiabilityAnomaly>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReleaseCursor {
    expiry: u64,
    id: String,
}

/// Rolling melt outflow budget of one unit, in that unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeltBudget {
    /// The largest outflow in any rolling hour
    pub per_hour: u64,
    /// The largest outflow in any rolling day
    pub per_day: u64,
}

/// Limits on request-created state and on outflow. The default has no limit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateLimits {
    /// The largest number of unexpired unpaid mint quotes
    pub max_unpaid_mint_quotes: Option<u64>,
    /// The melt outflow budget of each unit. When it is not empty, a melt in
    /// a unit without a budget is refused.
    pub melt_budgets: HashMap<CurrencyUnit, MeltBudget>,
}

impl Mint {
    /// Refuse a new mint quote when the mint holds its maximum of unpaid quotes.
    ///
    /// Concurrent requests can pass the count together, so the cap can be
    /// exceeded by the number of concurrent quote requests.
    pub(super) async fn check_unpaid_quote_cap(&self) -> Result<(), Error> {
        let Some(cap) = self.state_limits.max_unpaid_mint_quotes else {
            return Ok(());
        };
        let unpaid = self
            .localstore
            .count_unexpired_unpaid_mint_quotes(unix_time())
            .await?;
        if unpaid >= cap {
            tracing::debug!(unpaid, cap, "unpaid mint quote cap reached");
            return Err(Error::UnpaidQuoteLimitReached);
        }
        Ok(())
    }

    /// Release the backend state of each unpaid quote that expired more than
    /// [`UNPAID_QUOTE_RETENTION_SECS`] before `now`. The quote rows stay.
    ///
    /// The pass first asks the backend for a payment. A payment event can be
    /// lost, for example while the mint starts. A reported payment is credited
    /// through the normal path and the backend state stays. Only a backend
    /// answer without a payment releases the state.
    ///
    /// A stored cursor keeps the position, so each quote is handled once. An
    /// error stops the pass at the last finished quote; the next pass retries.
    pub async fn release_expired_unpaid_quotes(&self, now: u64) -> Result<ReleaseSummary, Error> {
        let expired_before = now.saturating_sub(UNPAID_QUOTE_RETENTION_SECS);
        let start = self.release_cursor().await?;
        let mut cursor = start.clone();
        let mut summary = ReleaseSummary::default();
        let mut failure = None;
        'pages: loop {
            let page = match self
                .localstore
                .get_unpaid_mint_quotes_expired_before(
                    expired_before,
                    cursor.clone(),
                    RELEASE_BATCH,
                )
                .await
            {
                Ok(page) => page,
                Err(err) => {
                    failure = Some(Error::from(err));
                    break;
                }
            };
            let full = page.len() as u64 >= RELEASE_BATCH;
            for mut quote in page {
                if let Err(err) = self
                    .release_expired_unpaid_quote(&mut quote, &mut summary)
                    .await
                {
                    failure = Some(err);
                    break 'pages;
                }
                cursor = Some((quote.expiry, quote.id.clone()));
            }
            if !full {
                break;
            }
        }
        if cursor != start {
            if let Some((expiry, id)) = &cursor {
                let value = serde_json::to_vec(&ReleaseCursor {
                    expiry: *expiry,
                    id: id.to_string(),
                })?;
                let mut tx = self.localstore.begin_transaction().await?;
                tx.kv_write(
                    super::CDK_MINT_PRIMARY_NAMESPACE,
                    RELEASE_CURSOR_NAMESPACE,
                    RELEASE_CURSOR_KEY,
                    &value,
                )
                .await?;
                tx.commit().await?;
            }
        }
        if summary != ReleaseSummary::default() {
            tracing::info!(
                released = summary.released,
                credited = summary.credited,
                "released the backend state of expired unpaid mint quotes",
            );
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(summary),
        }
    }

    async fn release_cursor(&self) -> Result<Option<(u64, QuoteId)>, Error> {
        let Some(raw) = self
            .localstore
            .kv_read(
                super::CDK_MINT_PRIMARY_NAMESPACE,
                RELEASE_CURSOR_NAMESPACE,
                RELEASE_CURSOR_KEY,
            )
            .await?
        else {
            return Ok(None);
        };
        let cursor: ReleaseCursor = serde_json::from_slice(&raw)?;
        let id = QuoteId::from_str(&cursor.id).map_err(|_| Error::Internal)?;
        Ok(Some((cursor.expiry, id)))
    }

    async fn release_expired_unpaid_quote(
        &self,
        quote: &mut MintQuote,
        summary: &mut ReleaseSummary,
    ) -> Result<(), Error> {
        // Only a BOLT11 invoice holds backend state until it expires.
        if !quote.payment_method.is_bolt11() {
            return Ok(());
        }
        let Some(processor) = self.payment_processors.get(&PaymentProcessorKey::new(
            quote.unit.clone(),
            quote.payment_method.clone(),
        )) else {
            return Ok(());
        };
        let payments = processor
            .check_incoming_payment_status(&quote.request_lookup_id)
            .await?;
        if !payments.is_empty() {
            tracing::warn!(
                quote_id = %quote.id,
                request_lookup_id = %quote.request_lookup_id,
                "an expired unpaid quote has a backend payment; crediting it and keeping its state",
            );
            Self::record_mint_quote_payments(
                self.localstore.clone(),
                Some(self.pubsub_manager.clone()),
                quote,
                payments,
            )
            .await?;
            summary.credited += 1;
            return Ok(());
        }
        processor
            .release_incoming_payment_request(&quote.request_lookup_id)
            .await?;
        summary.released += 1;
        Ok(())
    }

    /// Refuse an external melt payment above the rolling outflow budget.
    ///
    /// The caller has already committed this quote as pending, so the sum
    /// includes it. Each concurrent melt also sees the others that committed
    /// before its check. Thus concurrent melts cannot pass the budget together.
    pub(super) async fn check_melt_budget(
        &self,
        unit: &CurrencyUnit,
        now: u64,
    ) -> Result<(), Error> {
        if self.state_limits.melt_budgets.is_empty() {
            return Ok(());
        }
        let Some(budget) = self.state_limits.melt_budgets.get(unit) else {
            tracing::warn!(
                "{} unit={} reason=no_budget",
                MELT_BUDGET_EXCEEDED_TOKEN,
                unit
            );
            return Err(Error::MeltBudgetExceeded);
        };
        for (window, limit, name) in [
            (HOUR_SECS, budget.per_hour, "hour"),
            (DAY_SECS, budget.per_day, "day"),
        ] {
            let outflow = self
                .localstore
                .melt_outflow_since(unit, now.saturating_sub(window))
                .await?;
            if outflow > limit {
                tracing::warn!(
                    "{} unit={} window={} outflow={} budget={}",
                    MELT_BUDGET_EXCEEDED_TOKEN,
                    unit,
                    name,
                    outflow,
                    limit
                );
                return Err(Error::MeltBudgetExceeded);
            }
        }
        Ok(())
    }

    /// The outstanding ecash of each unit: the issued minus the redeemed
    /// amount of each regular keyset, plus the largest payout of each
    /// condition. A condition pays out at most the conditional tokens that
    /// cover one outcome. After an enum attestation, only the winning outcome
    /// pays out.
    ///
    /// A keyset that redeemed more than it issued counts as zero, because a
    /// negative value would hide the liability of other keysets. It is
    /// reported as an anomaly: it can be forged proofs or a faulty count.
    pub async fn liabilities(&self) -> Result<Liabilities, Error> {
        let issued = self.localstore.get_total_issued().await?;
        let redeemed = self.localstore.get_total_redeemed().await?;
        let mut anomalies = Vec::new();

        let mut regular: Vec<(CurrencyUnit, u64)> = Vec::new();
        #[cfg(feature = "conditional-tokens")]
        let mut conditional: Vec<ConditionalOutstanding> = Vec::new();
        for keyset in self.keysets.load().iter() {
            let issued = issued.get(&keyset.id).copied().map(u64::from).unwrap_or(0);
            let redeemed = redeemed
                .get(&keyset.id)
                .copied()
                .map(u64::from)
                .unwrap_or(0);
            if redeemed > issued {
                anomalies.push(LiabilityAnomaly {
                    keyset: keyset.id,
                    unit: keyset.unit.clone(),
                    excess: redeemed - issued,
                });
            }
            let amount = issued.saturating_sub(redeemed);
            #[cfg(feature = "conditional-tokens")]
            if keyset.condition_id.is_some() {
                if amount == 0 {
                    continue;
                }
                let Some((condition_id, collection, _)) =
                    self.localstore.get_condition_for_keyset(&keyset.id).await?
                else {
                    // A conditional keyset without a binding cannot be valued.
                    // Count it in full, so that the signal errs on the safe side.
                    regular.push((keyset.unit.clone(), amount));
                    continue;
                };
                conditional.push(ConditionalOutstanding {
                    unit: keyset.unit.clone(),
                    condition_id,
                    outcomes: cdk_common::nuts::nut_ctf::parse_outcome_collection(&collection),
                    amount,
                });
                continue;
            }
            regular.push((keyset.unit.clone(), amount));
        }

        #[cfg(feature = "conditional-tokens")]
        let winners: HashMap<String, String> = self
            .localstore
            .get_conditions(
                None,
                None,
                &[super::conditions::STATUS_ATTESTED.to_string()],
            )
            .await?
            .into_iter()
            .filter(|condition| condition.condition_type == "enum")
            .filter_map(|condition| Some((condition.condition_id, condition.winning_outcome?)))
            .collect();
        #[cfg(not(feature = "conditional-tokens"))]
        let conditional: Vec<ConditionalOutstanding> = Vec::new();
        #[cfg(not(feature = "conditional-tokens"))]
        let winners: HashMap<String, String> = HashMap::new();

        Ok(Liabilities {
            totals: sum_liabilities(regular, conditional, &winners),
            anomalies,
        })
    }

    /// Delete the output conflict records of refused settlement requests
    /// whose cutoff is at least [`OUTPUT_CONFLICT_RETENTION_SECS`] before `now`.
    ///
    /// Each transaction deletes one bounded batch. The pass ends: a new record
    /// is written only for a request whose cutoff is after its write time.
    /// A record without a cutoff is kept, because its request has no expiry.
    #[cfg(feature = "conditional-tokens")]
    pub async fn delete_expired_output_conflicts(&self, now: u64) -> Result<u64, Error> {
        let expired_at = now.saturating_sub(OUTPUT_CONFLICT_RETENTION_SECS);
        let mut deleted = 0;
        loop {
            let mut tx = self.localstore.begin_transaction().await?;
            let batch = match tx
                .delete_expired_ctf_settlement_output_conflicts(
                    expired_at,
                    OUTPUT_CONFLICT_DELETE_BATCH,
                )
                .await
            {
                Ok(batch) => batch,
                Err(err) => {
                    tx.rollback().await?;
                    return Err(err.into());
                }
            };
            tx.commit().await?;
            deleted += batch;
            if batch < OUTPUT_CONFLICT_DELETE_BATCH {
                return Ok(deleted);
            }
        }
    }

    /// One cleanup and liability pass. Errors are logged, not returned.
    pub(super) async fn run_maintenance(&self, now: u64) {
        if let Err(err) = self.release_expired_unpaid_quotes(now).await {
            tracing::warn!("Could not release expired unpaid mint quotes: {}", err);
        }
        #[cfg(feature = "conditional-tokens")]
        match self.delete_expired_output_conflicts(now).await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(
                deleted,
                "deleted expired settlement output conflict records"
            ),
            Err(err) => tracing::warn!(
                "Could not delete expired settlement output conflict records: {}",
                err
            ),
        }
        match self.liabilities().await {
            Ok(liabilities) => {
                log_anomalies(&liabilities.anomalies);
                let mut units: Vec<_> = liabilities.totals.into_iter().collect();
                units.sort_by_key(|(unit, _)| unit.to_string());
                for (unit, amount) in units {
                    tracing::info!("{} unit={} outstanding={}", LIABILITIES_TOKEN, unit, amount);
                    #[cfg(feature = "prometheus")]
                    cdk_prometheus::METRICS.set_liabilities(&unit.to_string(), amount);
                }
            }
            Err(err) => {
                // A stale value would hide the failure: the signal reads unavailable.
                #[cfg(feature = "prometheus")]
                cdk_prometheus::METRICS.clear_liabilities();
                tracing::warn!("Could not compute the mint liabilities: {}", err);
            }
        }
    }

    /// Run [`Mint::run_maintenance`] at start and then each interval until shutdown.
    pub(super) async fn maintenance_loop(mint: Arc<Mint>, shutdown: Arc<Notify>) {
        let shutdown_wait = shutdown.notified();
        tokio::pin!(shutdown_wait);
        let mut interval = tokio::time::interval(MAINTENANCE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = &mut shutdown_wait => break,
                _ = interval.tick() => mint.run_maintenance(unix_time()).await,
            }
        }
    }
}

/// Log one fixed line for each unit with a keyset that redeemed more than it issued.
fn log_anomalies(anomalies: &[LiabilityAnomaly]) {
    let mut units: HashMap<String, (usize, u64, Id)> = HashMap::new();
    for anomaly in anomalies {
        let entry = units
            .entry(anomaly.unit.to_string())
            .or_insert((0, 0, anomaly.keyset));
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(anomaly.excess);
    }
    let mut units: Vec<_> = units.into_iter().collect();
    units.sort_by(|a, b| a.0.cmp(&b.0));
    for (unit, (keysets, excess, first)) in units {
        tracing::warn!(
            "{} unit={} keysets={} excess={} first_keyset={}",
            LIABILITY_ANOMALY_TOKEN,
            unit,
            keysets,
            excess,
            first
        );
    }
}

/// The outstanding amount of one conditional keyset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConditionalOutstanding {
    pub(crate) unit: CurrencyUnit,
    pub(crate) condition_id: String,
    /// The outcomes that the keyset tokens pay out on
    pub(crate) outcomes: Vec<String>,
    pub(crate) amount: u64,
}

/// Sum the regular outstanding amounts and the largest payout of each condition.
pub(crate) fn sum_liabilities(
    regular: Vec<(CurrencyUnit, u64)>,
    conditional: Vec<ConditionalOutstanding>,
    winners: &HashMap<String, String>,
) -> HashMap<CurrencyUnit, u64> {
    let mut totals: HashMap<CurrencyUnit, u64> = HashMap::new();
    for (unit, amount) in regular {
        let total = totals.entry(unit).or_default();
        *total = total.saturating_add(amount);
    }
    // Payout of each outcome of each condition: the tokens that cover it.
    let mut payouts: HashMap<(CurrencyUnit, String), HashMap<String, u64>> = HashMap::new();
    for keyset in conditional {
        let outcomes = payouts
            .entry((keyset.unit, keyset.condition_id))
            .or_default();
        for outcome in keyset.outcomes {
            let payout = outcomes.entry(outcome).or_default();
            *payout = payout.saturating_add(keyset.amount);
        }
    }
    for ((unit, condition_id), outcomes) in payouts {
        let payout = match winners.get(&condition_id) {
            Some(winner) => outcomes.get(winner).copied().unwrap_or(0),
            None => outcomes.values().copied().max().unwrap_or(0),
        };
        let total = totals.entry(unit).or_default();
        *total = total.saturating_add(payout);
    }
    totals
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::pin::Pin;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use bip39::Mnemonic;
    use cdk_common::nut00::KnownMethod;
    use cdk_common::payment::{
        self, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions, MakePaymentResponse,
        MintPayment, OutgoingPaymentOptions, PaymentIdentifier, PaymentQuoteResponse,
        SettingsResponse, WaitPaymentResponse,
    };
    use cdk_common::{MintQuoteBolt11Request, PaymentMethod};
    use cdk_fake_wallet::FakeWallet;
    use futures::Stream;

    use super::*;
    use crate::mint::{MintBuilder, MintMeltLimits};
    use crate::types::{FeeReserve, QuoteTTL};
    use crate::Amount;

    /// A FakeWallet that sends no payment event and records each release. A
    /// status check reports the payments in `paid`: a payment event that the
    /// mint lost. With `failing`, a status check fails.
    struct UnpaidBackend {
        inner: FakeWallet,
        released: StdMutex<Vec<PaymentIdentifier>>,
        paid: StdMutex<HashMap<String, u64>>,
        failing: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl MintPayment for UnpaidBackend {
        type Err = payment::Error;

        async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
            self.inner.get_settings().await
        }
        async fn create_incoming_payment_request(
            &self,
            options: IncomingPaymentOptions,
        ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
            self.inner.create_incoming_payment_request(options).await
        }
        async fn get_payment_quote(
            &self,
            unit: &CurrencyUnit,
            options: OutgoingPaymentOptions,
        ) -> Result<PaymentQuoteResponse, Self::Err> {
            self.inner.get_payment_quote(unit, options).await
        }
        async fn make_payment(
            &self,
            unit: &CurrencyUnit,
            options: OutgoingPaymentOptions,
        ) -> Result<MakePaymentResponse, Self::Err> {
            self.inner.make_payment(unit, options).await
        }
        async fn wait_payment_event(
            &self,
        ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
            Ok(Box::pin(futures::stream::pending()))
        }
        fn is_payment_event_stream_active(&self) -> bool {
            false
        }
        fn cancel_payment_event_stream(&self) {}
        async fn check_incoming_payment_status(
            &self,
            payment_identifier: &PaymentIdentifier,
        ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(payment::Error::Custom("backend unavailable".to_owned()));
            }
            let key = payment_identifier.to_string();
            Ok(self
                .paid
                .lock()
                .expect("paid table")
                .get(&key)
                .map(|amount| WaitPaymentResponse {
                    payment_identifier: payment_identifier.clone(),
                    payment_amount: Amount::new(*amount, CurrencyUnit::Sat),
                    payment_id: key.clone(),
                })
                .into_iter()
                .collect())
        }
        async fn check_outgoing_payment(
            &self,
            payment_identifier: &PaymentIdentifier,
        ) -> Result<MakePaymentResponse, Self::Err> {
            self.inner.check_outgoing_payment(payment_identifier).await
        }
        async fn release_incoming_payment_request(
            &self,
            payment_identifier: &PaymentIdentifier,
        ) -> Result<(), Self::Err> {
            self.released
                .lock()
                .expect("release log")
                .push(payment_identifier.clone());
            Ok(())
        }
    }

    const QUOTE_TTL: u64 = 600;

    async fn unpaid_mint(limits: StateLimits) -> (Mint, Arc<UnpaidBackend>) {
        let db = Arc::new(cdk_sqlite::mint::memory::empty().await.unwrap());
        let fee_reserve = FeeReserve {
            min_fee_reserve: 1.into(),
            percent_fee_reserve: 1.0,
        };
        let backend = Arc::new(UnpaidBackend {
            inner: FakeWallet::new(
                fee_reserve,
                HashMap::default(),
                HashSet::default(),
                0,
                CurrencyUnit::Sat,
            ),
            released: StdMutex::new(vec![]),
            paid: StdMutex::new(HashMap::new()),
            failing: std::sync::atomic::AtomicBool::new(false),
        });
        let mut builder = MintBuilder::new(db.clone());
        builder
            .add_payment_processor(
                CurrencyUnit::Sat,
                PaymentMethod::Known(KnownMethod::Bolt11),
                MintMeltLimits::new(1, 10_000),
                backend.clone(),
            )
            .await
            .unwrap();
        let mnemonic = Mnemonic::generate(12).unwrap();
        let mint = builder
            .with_state_limits(limits)
            .build_with_seed(db, &mnemonic.to_seed_normalized(""))
            .await
            .unwrap();
        mint.set_quote_ttl(QuoteTTL::new(QUOTE_TTL, QUOTE_TTL))
            .await
            .unwrap();
        (mint, backend)
    }

    async fn new_quote(
        mint: &Mint,
    ) -> Result<crate::mint::MintQuoteResponse<crate::mint::QuoteId>, Error> {
        mint.get_mint_quote(
            MintQuoteBolt11Request {
                amount: Amount::from(10),
                unit: CurrencyUnit::Sat,
                description: None,
                pubkey: None,
            }
            .into(),
        )
        .await
    }

    fn released(backend: &UnpaidBackend) -> Vec<String> {
        let mut released: Vec<String> = backend
            .released
            .lock()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        released.sort();
        released
    }

    #[tokio::test]
    async fn expired_unpaid_quotes_keep_their_rows_and_release_their_backend_state_once() {
        let (mint, backend) = unpaid_mint(StateLimits::default()).await;
        let created = unix_time();
        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(new_quote(&mint).await.unwrap().quote().clone());
        }
        let mut lookup_ids: Vec<String> = mint
            .mint_quotes()
            .await
            .unwrap()
            .iter()
            .map(|quote| quote.request_lookup_id.to_string())
            .collect();
        lookup_ids.sort();

        // Not yet expired, and then inside the retention after expiry.
        assert_eq!(
            mint.release_expired_unpaid_quotes(created).await.unwrap(),
            ReleaseSummary::default()
        );
        let inside = created + QUOTE_TTL + UNPAID_QUOTE_RETENTION_SECS - 60;
        assert_eq!(
            mint.release_expired_unpaid_quotes(inside).await.unwrap(),
            ReleaseSummary::default()
        );
        assert!(released(&backend).is_empty());

        // The clock of the quotes can be up to a few seconds after `created`.
        let after = created + QUOTE_TTL + UNPAID_QUOTE_RETENTION_SECS + 60;
        let summary = mint.release_expired_unpaid_quotes(after).await.unwrap();
        assert_eq!((summary.released, summary.credited), (5, 0));
        assert_eq!(released(&backend), lookup_ids);

        // The rows stay: a client still reads each quote as UNPAID.
        assert_eq!(mint.mint_quotes().await.unwrap().len(), 5);
        for id in &ids {
            let quote = mint.check_mint_quote(id).await.unwrap();
            assert_eq!(quote.state(), Some(cdk_common::MintQuoteState::Unpaid));
        }
        // The stored position: a later pass handles no quote again.
        assert_eq!(
            mint.release_expired_unpaid_quotes(after + 600)
                .await
                .unwrap(),
            ReleaseSummary::default()
        );
        assert_eq!(backend.released.lock().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn a_payment_that_the_mint_missed_is_credited_and_not_released() {
        let (mint, backend) = unpaid_mint(StateLimits::default()).await;
        let created = unix_time();
        let paid = new_quote(&mint).await.unwrap().quote().clone();
        let unpaid = new_quote(&mint).await.unwrap().quote().clone();
        let paid_lookup = mint
            .localstore
            .get_mint_quote(&paid)
            .await
            .unwrap()
            .unwrap()
            .request_lookup_id
            .to_string();
        // The node holds a payment, but its PaymentReceived event never reached the mint.
        backend.paid.lock().unwrap().insert(paid_lookup.clone(), 10);

        let after = created + QUOTE_TTL + UNPAID_QUOTE_RETENTION_SECS + 60;
        let summary = mint.release_expired_unpaid_quotes(after).await.unwrap();
        assert_eq!((summary.released, summary.credited), (1, 1));
        assert!(!released(&backend).contains(&paid_lookup));
        let credited = mint
            .localstore
            .get_mint_quote(&paid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(credited.state(), cdk_common::MintQuoteState::Paid);
        assert_eq!(credited.amount_paid().value(), 10);
        let other = mint
            .localstore
            .get_mint_quote(&unpaid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(other.state(), cdk_common::MintQuoteState::Unpaid);
    }

    #[tokio::test]
    async fn a_failed_backend_check_releases_nothing_and_the_next_pass_retries() {
        let (mint, backend) = unpaid_mint(StateLimits::default()).await;
        let created = unix_time();
        for _ in 0..3 {
            new_quote(&mint).await.unwrap();
        }
        let after = created + QUOTE_TTL + UNPAID_QUOTE_RETENTION_SECS + 60;
        backend
            .failing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(mint.release_expired_unpaid_quotes(after).await.is_err());
        assert!(released(&backend).is_empty());
        backend
            .failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let summary = mint.release_expired_unpaid_quotes(after).await.unwrap();
        assert_eq!((summary.released, summary.credited), (3, 0));
    }

    #[tokio::test]
    async fn the_unpaid_quote_cap_refuses_new_quotes_until_one_expires() {
        let limits = StateLimits {
            max_unpaid_mint_quotes: Some(2),
            ..StateLimits::default()
        };
        let (mint, _backend) = unpaid_mint(limits).await;
        new_quote(&mint).await.unwrap();
        new_quote(&mint).await.unwrap();
        assert!(matches!(
            new_quote(&mint).await,
            Err(Error::UnpaidQuoteLimitReached)
        ));
        assert_eq!(mint.mint_quotes().await.unwrap().len(), 2);
    }

    fn keyset(condition: &str, outcomes: &[&str], amount: u64) -> ConditionalOutstanding {
        ConditionalOutstanding {
            unit: CurrencyUnit::Msat,
            condition_id: condition.to_string(),
            outcomes: outcomes.iter().map(|o| o.to_string()).collect(),
            amount,
        }
    }

    #[tokio::test]
    async fn a_keyset_that_redeemed_more_than_it_issued_is_an_anomaly() {
        let (mint, _backend) = unpaid_mint(StateLimits::default()).await;
        assert!(mint.liabilities().await.unwrap().anomalies.is_empty());
        let keyset = mint.keysets.load()[0].clone();
        // Redeemed proofs without a matching issuance: forged proofs or a faulty count.
        let mut tx = mint.localstore.begin_transaction().await.unwrap();
        let proofs = vec![cdk_common::Proof::new(
            Amount::from(8),
            keyset.id,
            cdk_common::secret::Secret::generate(),
            cdk_common::SecretKey::generate().public_key(),
        )];
        tx.add_proofs(
            proofs.clone(),
            None,
            &cdk_common::mint::Operation::new_swap(Amount::ZERO, Amount::ZERO, Amount::ZERO),
        )
        .await
        .unwrap();
        let ys = cdk_common::ProofsMethods::ys(&proofs).unwrap();
        let mut stored = tx.get_proofs(&ys).await.unwrap();
        Mint::update_proofs_state(&mut tx, &mut stored, cdk_common::State::Spent)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let liabilities = mint.liabilities().await.unwrap();
        assert_eq!(
            liabilities.anomalies,
            vec![LiabilityAnomaly {
                keyset: keyset.id,
                unit: keyset.unit.clone(),
                excess: 8,
            }]
        );
        // The keyset counts as zero, not as a negative amount.
        assert_eq!(
            liabilities.totals.get(&keyset.unit).copied().unwrap_or(0),
            0
        );
    }

    #[test]
    fn liabilities_count_regular_tokens_and_the_largest_payout_of_each_condition() {
        // One-vs-rest keysets of a three-outcome condition after a split of 100:
        // A, B|C, B and A|C. Outcome A pays A + A|C = 160, B pays 100, C pays 140.
        let conditional = vec![
            keyset("c1", &["A"], 100),
            keyset("c1", &["B", "C"], 40),
            keyset("c1", &["B"], 60),
            keyset("c1", &["A", "C"], 60),
            keyset("c2", &["X"], 7),
        ];
        let regular = vec![(CurrencyUnit::Msat, 1000), (CurrencyUnit::Sat, 5)];
        let totals = sum_liabilities(regular.clone(), conditional.clone(), &HashMap::new());
        assert_eq!(totals[&CurrencyUnit::Msat], 1000 + 160 + 7);
        assert_eq!(totals[&CurrencyUnit::Sat], 5);

        // After the attestation of B, only the tokens that cover B pay out.
        let winners = HashMap::from([("c1".to_string(), "B".to_string())]);
        let totals = sum_liabilities(regular, conditional, &winners);
        assert_eq!(totals[&CurrencyUnit::Msat], 1000 + 100 + 7);
    }
}
