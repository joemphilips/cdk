//! Bounds on request-created mint state and on value outflow.
//!
//! - Unpaid mint quotes: a global cap on unexpired unpaid quotes, and the
//!   deletion of expired unpaid quotes with their payment backend state.
//! - Melt outflow: a rolling budget per hour and per day for each unit.
//! - Liabilities: the outstanding ecash of each unit, for a solvency signal.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use cdk_common::payment::DynMintPayment;
use cdk_common::util::unix_time;
use tokio::sync::Notify;

use super::Mint;
use crate::error::Error;
use crate::nuts::{CurrencyUnit, Id};

/// Time after the expiry of an unpaid quote before the mint deletes it.
///
/// LDK accepts an HTLC for an invoice until two hours after its expiry, measured
/// against the newest block time, which can lag the clock. A deleted quote cannot
/// be credited, so the delay must be well above that window.
pub const UNPAID_QUOTE_RETENTION_SECS: u64 = 6 * 60 * 60;
/// The largest number of quotes that one cleanup transaction deletes.
const CLEANUP_BATCH: u64 = 500;
/// The interval of the cleanup and liability task.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const HOUR_SECS: u64 = 60 * 60;
const DAY_SECS: u64 = 24 * HOUR_SECS;

/// Fixed log token of a melt refused by the outflow budget. Alert rules match it.
pub const MELT_BUDGET_EXCEEDED_TOKEN: &str = "MINT_MELT_BUDGET_EXCEEDED";
/// Fixed log token of the periodic liability line.
pub const LIABILITIES_TOKEN: &str = "MINT_LIABILITIES";

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

    /// Delete the unpaid mint quotes that expired more than
    /// [`UNPAID_QUOTE_RETENTION_SECS`] before `now`, and release their
    /// payment backend state. Returns the number of deleted quotes.
    pub async fn remove_expired_unpaid_mint_quotes(&self, now: u64) -> Result<usize, Error> {
        let expired_before = now.saturating_sub(UNPAID_QUOTE_RETENTION_SECS);
        let mut removed = 0;
        loop {
            let mut tx = self.localstore.begin_transaction().await?;
            let released = tx
                .delete_expired_unpaid_mint_quotes(expired_before, CLEANUP_BATCH)
                .await?;
            tx.commit().await?;
            removed += released.len();
            for identifier in &released {
                for processor in self.distinct_payment_processors() {
                    // A failed release leaves one backend record. The backend
                    // sweep at its next start removes it.
                    if let Err(err) = processor.release_incoming_payment_request(identifier).await {
                        tracing::warn!("Could not release an expired payment request: {}", err);
                    }
                }
            }
            if (released.len() as u64) < CLEANUP_BATCH {
                break;
            }
        }
        if removed > 0 {
            tracing::info!(removed, "deleted expired unpaid mint quotes");
        }
        Ok(removed)
    }

    fn distinct_payment_processors(&self) -> Vec<DynMintPayment> {
        let mut seen: Vec<DynMintPayment> = Vec::new();
        for processor in self.payment_processors.values() {
            if !seen.iter().any(|known| Arc::ptr_eq(known, processor)) {
                seen.push(Arc::clone(processor));
            }
        }
        seen
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
    pub async fn liabilities(&self) -> Result<HashMap<CurrencyUnit, u64>, Error> {
        let issued = self.localstore.get_total_issued().await?;
        let redeemed = self.localstore.get_total_redeemed().await?;
        let outstanding = |id: &Id| {
            let issued = issued.get(id).copied().map(u64::from).unwrap_or(0);
            let redeemed = redeemed.get(id).copied().map(u64::from).unwrap_or(0);
            // A keyset that redeemed more than it issued counts as zero. A
            // negative value would hide the liability of other keysets.
            issued.saturating_sub(redeemed)
        };

        let mut regular: Vec<(CurrencyUnit, u64)> = Vec::new();
        #[cfg(feature = "conditional-tokens")]
        let mut conditional: Vec<ConditionalOutstanding> = Vec::new();
        for keyset in self.keysets.load().iter() {
            let amount = outstanding(&keyset.id);
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

        Ok(sum_liabilities(regular, conditional, &winners))
    }

    /// One cleanup and liability pass. Errors are logged, not returned.
    pub(super) async fn run_maintenance(&self, now: u64) {
        if let Err(err) = self.remove_expired_unpaid_mint_quotes(now).await {
            tracing::warn!("Could not delete expired unpaid mint quotes: {}", err);
        }
        match self.liabilities().await {
            Ok(liabilities) => {
                let mut units: Vec<_> = liabilities.into_iter().collect();
                units.sort_by_key(|(unit, _)| unit.to_string());
                for (unit, amount) in units {
                    tracing::info!("{} unit={} outstanding={}", LIABILITIES_TOKEN, unit, amount);
                    #[cfg(feature = "prometheus")]
                    cdk_prometheus::METRICS.set_liabilities(&unit.to_string(), amount);
                }
            }
            Err(err) => tracing::warn!("Could not compute the mint liabilities: {}", err),
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

    /// A FakeWallet that never reports an incoming payment and records each release.
    struct UnpaidBackend {
        inner: FakeWallet,
        released: StdMutex<Vec<PaymentIdentifier>>,
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
            _payment_identifier: &PaymentIdentifier,
        ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
            Ok(vec![])
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

    #[tokio::test]
    async fn expired_unpaid_quotes_return_the_state_to_its_baseline() {
        let (mint, backend) = unpaid_mint(StateLimits::default()).await;
        let created = unix_time();
        for _ in 0..5 {
            new_quote(&mint).await.unwrap();
        }
        let quotes = mint.mint_quotes().await.unwrap();
        assert_eq!(quotes.len(), 5);
        let mut lookup_ids: Vec<String> = quotes
            .iter()
            .map(|quote| quote.request_lookup_id.to_string())
            .collect();
        lookup_ids.sort();

        // Not yet expired, and then inside the retention after expiry.
        assert_eq!(
            mint.remove_expired_unpaid_mint_quotes(created)
                .await
                .unwrap(),
            0
        );
        let inside = created + QUOTE_TTL + UNPAID_QUOTE_RETENTION_SECS - 60;
        assert_eq!(
            mint.remove_expired_unpaid_mint_quotes(inside)
                .await
                .unwrap(),
            0
        );
        assert!(backend.released.lock().unwrap().is_empty());

        // The clock of the quotes can be up to a few seconds after `created`.
        let after = created + QUOTE_TTL + UNPAID_QUOTE_RETENTION_SECS + 60;
        assert_eq!(
            mint.remove_expired_unpaid_mint_quotes(after).await.unwrap(),
            5
        );
        assert!(mint.mint_quotes().await.unwrap().is_empty());
        let mut released: Vec<String> = backend
            .released
            .lock()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        released.sort();
        assert_eq!(released, lookup_ids);
        assert_eq!(
            mint.remove_expired_unpaid_mint_quotes(after).await.unwrap(),
            0
        );
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
