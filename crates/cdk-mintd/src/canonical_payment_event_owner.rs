use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cdk_common::database::DynMintDatabase;
use cdk_common::mint::{MeltQuote, MintQuote};
use cdk_common::nuts::{CurrencyUnit, MeltQuoteState};
use cdk_common::payment::{
    CreateIncomingPaymentResponse, DynMintPayment, Event, IncomingPaymentOptions,
    MakePaymentResponse, MintPayment, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use cdk_exchange_rate::{
    convert_incoming_response_to_sat, convert_outgoing_response_to_unit,
    convert_rate_melt_response, convert_rate_mint_payment, sat_msat_backends,
    validate_incoming_responses, validate_outgoing_response, DynRateQuoteStore,
    ParkedPaymentRecord, RateQuoteControlHandle, RateQuoteSide, SatMsatBackends,
};
use futures::{Stream, StreamExt};

#[derive(Clone)]
struct RateEventContext {
    store: DynRateQuoteStore,
    control: RateQuoteControlHandle,
}

/// Sole lifecycle and event-stream owner for one physical Lightning backend.
#[derive(Clone)]
pub(crate) struct CanonicalPaymentEventOwner {
    inner: DynMintPayment,
    localstore: DynMintDatabase,
    native_unit: CurrencyUnit,
    rate: Arc<OnceLock<RateEventContext>>,
}

pub(crate) async fn canonical_sat_msat_backends(
    backend: DynMintPayment,
    localstore: DynMintDatabase,
) -> Result<(Arc<CanonicalPaymentEventOwner>, SatMsatBackends), cdk_common::payment::Error> {
    let settings = backend.get_settings().await?;
    let native_unit = CurrencyUnit::from_str(&settings.unit).map_err(|_| {
        cdk_common::payment::Error::Custom(format!(
            "invalid payment backend unit `{}`",
            settings.unit
        ))
    })?;
    let owner = Arc::new(CanonicalPaymentEventOwner::new(
        backend,
        localstore,
        native_unit.clone(),
    ));
    let raw = sat_msat_backends(owner.clone()).await?;
    let routed = match native_unit {
        CurrencyUnit::Sat => SatMsatBackends {
            sat: owner.clone(),
            msat: Arc::new(CallStatusOnlyPayment::new(raw.msat)),
        },
        CurrencyUnit::Msat => SatMsatBackends {
            sat: Arc::new(CallStatusOnlyPayment::new(raw.sat)),
            msat: owner.clone(),
        },
        _ => return Err(cdk_common::payment::Error::UnsupportedUnit),
    };
    Ok((owner, routed))
}

impl std::fmt::Debug for CanonicalPaymentEventOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanonicalPaymentEventOwner")
            .field("native_unit", &self.native_unit)
            .field("has_rate_context", &self.rate.get().is_some())
            .finish_non_exhaustive()
    }
}

impl CanonicalPaymentEventOwner {
    pub(crate) fn new(
        inner: DynMintPayment,
        localstore: DynMintDatabase,
        native_unit: CurrencyUnit,
    ) -> Self {
        Self {
            inner,
            localstore,
            native_unit,
            rate: Arc::new(OnceLock::new()),
        }
    }

    pub(crate) fn install_rate_context(
        &self,
        store: DynRateQuoteStore,
        control: RateQuoteControlHandle,
    ) -> Result<(), cdk_common::payment::Error> {
        self.rate
            .set(RateEventContext { store, control })
            .map_err(|_| {
                cdk_common::payment::Error::Custom(
                    "rate event context was configured more than once".to_string(),
                )
            })
    }

    async fn route_event(&self, event: Event) -> Option<Event> {
        match event {
            Event::PaymentReceived(payment) => self
                .route_incoming(payment)
                .await
                .map(Event::PaymentReceived),
            Event::PaymentSuccessful { quote_id, details } => self
                .route_outgoing(quote_id, details)
                .await
                .map(|(quote_id, details)| Event::PaymentSuccessful { quote_id, details }),
            failed @ Event::PaymentFailed { .. } => Some(failed),
        }
    }

    async fn route_outgoing(
        &self,
        quote_id: cdk_common::QuoteId,
        details: MakePaymentResponse,
    ) -> Option<(cdk_common::QuoteId, MakePaymentResponse)> {
        let quote = self.correlated_paid_melt_quote(&quote_id, &details).await?;
        let converted = if self.is_native_quote_unit(&quote.unit) {
            convert_outgoing_response_to_unit(details, &quote.unit)
                .map_err(|error| error.to_string())
        } else {
            self.convert_rate_outgoing(quote.unit, details)
                .await
                .map_err(|error| error.to_string())
        };
        match converted {
            Ok(details) => Some((quote_id, details)),
            Err(error) => {
                tracing::warn!(%quote_id, %error, "suppressing payment event after settlement or conversion failure");
                None
            }
        }
    }

    async fn correlated_paid_melt_quote(
        &self,
        quote_id: &cdk_common::QuoteId,
        details: &MakePaymentResponse,
    ) -> Option<MeltQuote> {
        if details.status != MeltQuoteState::Paid {
            tracing::warn!(%quote_id, status = ?details.status, "suppressing non-paid success event");
            return None;
        }
        if let Err(error) = validate_outgoing_response(details, None, &self.native_unit) {
            tracing::warn!(%quote_id, %error, "suppressing payment event with invalid physical result");
            return None;
        }
        let quote = match self.localstore.get_melt_quote(quote_id).await {
            Ok(Some(quote)) => quote,
            Ok(None) => {
                tracing::warn!(%quote_id, "suppressing payment event for unknown melt quote");
                return None;
            }
            Err(error) => {
                tracing::warn!(%quote_id, %error, "suppressing payment event after melt quote lookup failure");
                return None;
            }
        };
        let Some(expected_lookup_id) = quote.request_lookup_id.as_ref() else {
            tracing::warn!(%quote_id, "suppressing success event without durable lookup correlation");
            return None;
        };
        if let Err(error) =
            validate_outgoing_response(details, Some(expected_lookup_id), &self.native_unit)
        {
            tracing::warn!(
                %quote_id,
                payment_lookup_id = %details.payment_lookup_id,
                %error,
                "suppressing payment event with invalid durable correlation"
            );
            return None;
        }
        Some(quote)
    }

    async fn convert_rate_outgoing(
        &self,
        unit: CurrencyUnit,
        details: MakePaymentResponse,
    ) -> Result<MakePaymentResponse, cdk_exchange_rate::RateQuoteStoreError> {
        let rate = self.rate.get().ok_or_else(|| {
            cdk_exchange_rate::RateQuoteStoreError::InvalidSettlement(format!(
                "missing rate context for {unit}"
            ))
        })?;
        convert_rate_melt_response(rate.store.clone(), rate.control.clone(), unit, details).await
    }

    async fn route_incoming(&self, payment: WaitPaymentResponse) -> Option<WaitPaymentResponse> {
        if payment.payment_amount.unit() != &self.native_unit {
            tracing::warn!(
                payment_lookup_id = %payment.payment_identifier,
                expected_unit = %self.native_unit,
                actual_unit = %payment.payment_amount.unit(),
                "suppressing payment event with non-native physical unit"
            );
            return None;
        }

        let quote = match self.mint_quote(&payment.payment_identifier).await {
            Ok(Some(quote)) => quote,
            Ok(None) => {
                self.park_unknown_incoming(payment).await;
                return None;
            }
            Err(()) => {
                self.park_unknown_incoming(payment).await;
                return None;
            }
        };

        if self.is_native_quote_unit(&quote.unit) {
            return Some(payment);
        }

        let Some(rate) = self.rate.get() else {
            tracing::warn!(
                payment_lookup_id = %payment.payment_identifier,
                unit = %quote.unit,
                "suppressing fiat payment event without rate context"
            );
            return None;
        };
        convert_rate_mint_payment(
            rate.store.clone(),
            rate.control.clone(),
            quote.unit,
            payment,
        )
        .await
    }

    async fn mint_quote(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Option<MintQuote>, ()> {
        self.localstore
            .get_mint_quote_by_request_lookup_id(payment_identifier)
            .await
            .map_err(|error| {
                tracing::warn!(
                    payment_lookup_id = %payment_identifier,
                    %error,
                    "suppressing payment event after mint quote lookup failure"
                );
            })
    }

    async fn melt_quote_for_payment(
        &self,
        options: &OutgoingPaymentOptions,
    ) -> Result<MeltQuote, cdk_common::payment::Error> {
        let quote_id = outgoing_quote_id(options);
        self.localstore
            .get_melt_quote(quote_id)
            .await
            .map_err(|error| {
                cdk_common::payment::Error::Custom(format!(
                    "failed to load durable melt quote {quote_id}: {error}"
                ))
            })?
            .ok_or_else(|| {
                cdk_common::payment::Error::Custom(format!("missing durable melt quote {quote_id}"))
            })
    }

    async fn park_unknown_incoming(&self, payment: WaitPaymentResponse) {
        let Some(rate) = self.rate.get() else {
            tracing::warn!(
                payment_lookup_id = %payment.payment_identifier,
                "suppressing unknown native payment event"
            );
            return;
        };
        let payment = match convert_incoming_response_to_sat(payment) {
            Ok(payment) => payment,
            Err(error) => {
                tracing::warn!(%error, "cannot durably park payment with unsupported physical unit");
                return;
            }
        };
        let parked = ParkedPaymentRecord {
            payment_lookup_id: payment.payment_identifier.clone(),
            bolt11_payment_hash: payment.payment_id,
            received_sats: payment.payment_amount.value(),
            observed_at: unix_time(),
            resolution_status: "unknown_mint_quote".to_string(),
        };
        if let Err(error) = rate.store.insert_parked(parked.clone()).await {
            tracing::warn!(
                payment_lookup_id = %payment.payment_identifier,
                %error,
                "failed to persist unknown payment evidence"
            );
            return;
        }

        match rate.store.get_by_lookup_id(&parked.payment_lookup_id).await {
            Ok(None) => {}
            Ok(Some(record)) => {
                self.refine_parked_reason(&rate.store, parked, record.side)
                    .await;
            }
            Err(error) => {
                tracing::warn!(
                    payment_lookup_id = %payment.payment_identifier,
                    %error,
                    "retaining unclassified parked payment after rate lookup failure"
                );
            }
        }
    }

    async fn refine_parked_reason(
        &self,
        store: &DynRateQuoteStore,
        mut parked: ParkedPaymentRecord,
        side: RateQuoteSide,
    ) {
        // A rate quote alone does not authorize minting when the mint quote is
        // missing. The exact evidence row already exists before this refinement.
        parked.resolution_status = match side {
            RateQuoteSide::Mint => "unknown_mint_quote",
            RateQuoteSide::Melt => "wrong_side_incoming",
        }
        .to_string();
        if let Err(error) = store.insert_parked(parked.clone()).await {
            tracing::warn!(
                payment_lookup_id = %parked.payment_lookup_id,
                %error,
                "retaining initial parked evidence after classification update failure"
            );
        }
    }

    fn is_native_quote_unit(&self, quote_unit: &CurrencyUnit) -> bool {
        quote_unit == &self.native_unit
            || matches!(
                (&self.native_unit, quote_unit),
                (CurrencyUnit::Sat, CurrencyUnit::Msat) | (CurrencyUnit::Msat, CurrencyUnit::Sat)
            )
    }
}

#[async_trait]
impl MintPayment for CanonicalPaymentEventOwner {
    type Err = cdk_common::payment::Error;

    async fn start(&self) -> Result<(), Self::Err> {
        self.inner.start().await
    }

    async fn stop(&self) -> Result<(), Self::Err> {
        self.inner.stop().await
    }

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
        let quote = self.melt_quote_for_payment(&options).await?;
        let response = self.inner.make_payment(unit, options).await?;
        // BOLT12 can legitimately lack a durable backend lookup id until the
        // asynchronous payment starts. In that case we validate only the
        // physical unit and retain the returned id for later durable polling.
        validate_outgoing_response(
            &response,
            quote.request_lookup_id.as_ref(),
            &self.native_unit,
        )?;
        Ok(response)
    }

    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let stream = self.inner.wait_payment_event().await?;
        let owner = self.clone();
        Ok(Box::pin(stream.filter_map(move |event| {
            let owner = owner.clone();
            async move { owner.route_event(event).await }
        })))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.inner.is_payment_event_stream_active()
    }

    fn cancel_payment_event_stream(&self) {
        self.inner.cancel_payment_event_stream();
    }

    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        let payments = self
            .inner
            .check_incoming_payment_status(payment_identifier)
            .await?;
        validate_incoming_responses(&payments, payment_identifier, &self.native_unit)?;
        Ok(payments)
    }

    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        let response = self
            .inner
            .check_outgoing_payment(payment_identifier)
            .await?;
        validate_outgoing_response(&response, Some(payment_identifier), &self.native_unit)?;
        Ok(response)
    }
}

/// Unit facade that delegates calls and status checks without owning lifecycle
/// or consuming the physical event stream.
#[derive(Clone)]
pub(crate) struct CallStatusOnlyPayment {
    inner: DynMintPayment,
}

impl CallStatusOnlyPayment {
    pub(crate) fn new(inner: DynMintPayment) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl MintPayment for CallStatusOnlyPayment {
    type Err = cdk_common::payment::Error;

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
        Err(cdk_common::payment::Error::Custom(
            "call/status-only payment facade cannot consume events".to_string(),
        ))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        true
    }

    fn cancel_payment_event_stream(&self) {}

    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        self.inner
            .check_incoming_payment_status(payment_identifier)
            .await
    }

    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        self.inner.check_outgoing_payment(payment_identifier).await
    }
}

fn outgoing_quote_id(options: &OutgoingPaymentOptions) -> &cdk_common::QuoteId {
    match options {
        OutgoingPaymentOptions::Bolt11(options) => &options.quote_id,
        OutgoingPaymentOptions::Bolt12(options) => &options.quote_id,
        OutgoingPaymentOptions::Custom(options) => &options.quote_id,
        OutgoingPaymentOptions::Onchain(options) => &options.quote_id,
    }
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::SystemTime;

    use cdk_common::mint::{MeltPaymentRequest, MeltQuote, MintQuote};
    use cdk_common::Amount;
    use cdk_exchange_rate::{
        AggregationMeta, InMemoryRateQuoteStore, PaymentErrorAdapter, RateConvertingPayment,
        RateConvertingPaymentConfig, RateOracle, RateOracleError, RateQuoteRecord, RateQuoteSide,
        RateQuoteStore, RateSnapshot, SharedMintPayment,
    };
    use futures::stream;

    use super::*;

    #[derive(Debug)]
    struct FixedRateOracle;

    #[async_trait]
    impl RateOracle for FixedRateOracle {
        async fn snapshot(&self, fiat: &CurrencyUnit) -> Result<RateSnapshot, RateOracleError> {
            Ok(RateSnapshot {
                fiat: fiat.clone(),
                aggregated_rate: 1_000,
                source_readings: Vec::new(),
                aggregation_meta: AggregationMeta {
                    sources_fetched: 1,
                    sources_trimmed: 0,
                    sources_survived: 1,
                    median_before_trim: 1_000,
                    deviation_threshold_bps: 0,
                },
                created_at: SystemTime::now(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct CountingPayment {
        unit: CurrencyUnit,
        starts: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        waits: Arc<AtomicUsize>,
        cancels: Arc<AtomicUsize>,
        make_calls: Arc<AtomicUsize>,
        events: Vec<Event>,
        make_response: Arc<Mutex<Option<MakePaymentResponse>>>,
        incoming_status: Arc<Mutex<Vec<WaitPaymentResponse>>>,
        outgoing_status: Arc<Mutex<Option<MakePaymentResponse>>>,
    }

    impl CountingPayment {
        fn new(unit: CurrencyUnit, events: Vec<Event>) -> Self {
            Self {
                unit,
                starts: Arc::default(),
                stops: Arc::default(),
                waits: Arc::default(),
                cancels: Arc::default(),
                make_calls: Arc::default(),
                events,
                make_response: Arc::default(),
                incoming_status: Arc::default(),
                outgoing_status: Arc::default(),
            }
        }

        fn unsupported<T>() -> Result<T, cdk_common::payment::Error> {
            Err(cdk_common::payment::Error::UnsupportedPaymentOption)
        }

        fn assert_single_lifecycle_owner(&self) {
            assert_eq!(self.starts.load(Ordering::Relaxed), 1);
            assert_eq!(self.stops.load(Ordering::Relaxed), 1);
            assert_eq!(self.waits.load(Ordering::Relaxed), 1);
            assert_eq!(self.cancels.load(Ordering::Relaxed), 1);
        }
    }

    #[async_trait]
    impl MintPayment for CountingPayment {
        type Err = cdk_common::payment::Error;

        async fn start(&self) -> Result<(), Self::Err> {
            self.starts.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn stop(&self) -> Result<(), Self::Err> {
            self.stops.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
            Ok(SettingsResponse {
                unit: self.unit.to_string(),
                bolt11: None,
                bolt12: None,
                onchain: None,
                custom: Default::default(),
            })
        }

        async fn create_incoming_payment_request(
            &self,
            _options: IncomingPaymentOptions,
        ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
            Self::unsupported()
        }

        async fn get_payment_quote(
            &self,
            _unit: &CurrencyUnit,
            _options: OutgoingPaymentOptions,
        ) -> Result<PaymentQuoteResponse, Self::Err> {
            Self::unsupported()
        }

        async fn make_payment(
            &self,
            _unit: &CurrencyUnit,
            _options: OutgoingPaymentOptions,
        ) -> Result<MakePaymentResponse, Self::Err> {
            self.make_calls.fetch_add(1, Ordering::Relaxed);
            self.make_response
                .lock()
                .expect("make response")
                .clone()
                .ok_or_else(|| {
                    cdk_common::payment::Error::Custom("missing make response".to_string())
                })
        }

        async fn wait_payment_event(
            &self,
        ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
            self.waits.fetch_add(1, Ordering::Relaxed);
            Ok(Box::pin(stream::iter(self.events.clone())))
        }

        fn is_payment_event_stream_active(&self) -> bool {
            false
        }

        fn cancel_payment_event_stream(&self) {
            self.cancels.fetch_add(1, Ordering::Relaxed);
        }

        async fn check_incoming_payment_status(
            &self,
            _payment_identifier: &PaymentIdentifier,
        ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
            Ok(self
                .incoming_status
                .lock()
                .expect("incoming status")
                .clone())
        }

        async fn check_outgoing_payment(
            &self,
            _payment_identifier: &PaymentIdentifier,
        ) -> Result<MakePaymentResponse, Self::Err> {
            self.outgoing_status
                .lock()
                .expect("outgoing status")
                .clone()
                .ok_or_else(|| {
                    cdk_common::payment::Error::Custom("missing outgoing status".to_string())
                })
        }
    }

    async fn empty_owner(
        payment: CountingPayment,
    ) -> (CanonicalPaymentEventOwner, DynMintDatabase) {
        let database: DynMintDatabase =
            Arc::new(cdk_sqlite::mint::memory::empty().await.expect("database"));
        let owner = CanonicalPaymentEventOwner::new(
            Arc::new(payment.clone()),
            database.clone(),
            payment.unit,
        );
        (owner, database)
    }

    fn incoming(id: &str, amount_msat: u64) -> WaitPaymentResponse {
        WaitPaymentResponse {
            payment_identifier: PaymentIdentifier::CustomId(id.to_string()),
            payment_amount: Amount::new(amount_msat, CurrencyUnit::Msat),
            payment_id: format!("hash-{id}"),
        }
    }

    async fn add_mint_quote(
        database: &DynMintDatabase,
        lookup_id: PaymentIdentifier,
        unit: CurrencyUnit,
    ) {
        let request = format!("request-{lookup_id}");
        let quote = MintQuote::new(
            Some(cdk_common::QuoteId::new()),
            request,
            unit.clone(),
            Some(Amount::new(1, unit.clone())),
            unix_time() + 60,
            lookup_id,
            None,
            Amount::new(0, unit.clone()),
            Amount::new(0, unit),
            cdk_common::PaymentMethod::Custom("test".to_string()),
            unix_time(),
            unix_time(),
            vec![],
            vec![],
            None,
        );
        let mut transaction = database.begin_transaction().await.expect("transaction");
        transaction.add_mint_quote(quote).await.expect("mint quote");
        transaction.commit().await.expect("commit mint quote");
    }

    async fn add_melt_quote(
        database: &DynMintDatabase,
        quote_id: cdk_common::QuoteId,
        lookup_id: Option<PaymentIdentifier>,
        unit: CurrencyUnit,
    ) {
        let quote = MeltQuote::new(
            Some(quote_id),
            MeltPaymentRequest::Custom {
                method: "test".to_string(),
                request: "request".to_string(),
            },
            unit.clone(),
            Amount::new(100, unit.clone()),
            Amount::new(0, unit),
            unix_time() + 60,
            lookup_id,
            None,
            cdk_common::PaymentMethod::Custom("test".to_string()),
            None,
            None,
        );
        let mut transaction = database.begin_transaction().await.expect("transaction");
        transaction.add_melt_quote(quote).await.expect("melt quote");
        transaction.commit().await.expect("commit melt quote");
    }

    async fn add_rate_melt_quote(
        database: &DynMintDatabase,
        store: &InMemoryRateQuoteStore,
        lookup_id: &str,
        fiat_subunits: u64,
    ) -> cdk_common::QuoteId {
        let quote_id = cdk_common::QuoteId::new();
        add_melt_quote(
            database,
            quote_id.clone(),
            Some(PaymentIdentifier::CustomId(lookup_id.to_string())),
            CurrencyUnit::Usd,
        )
        .await;
        store
            .insert(rate_record(lookup_id, RateQuoteSide::Melt, fiat_subunits))
            .await
            .expect("rate terms");
        quote_id
    }

    fn rate_record(id: &str, side: RateQuoteSide, fiat_subunits: u64) -> RateQuoteRecord {
        RateQuoteRecord {
            payment_lookup_id: PaymentIdentifier::CustomId(id.to_string()),
            side,
            fiat_unit: CurrencyUnit::Usd,
            fiat_subunits,
            fiat_fee_subunits: 0,
            snapshot_json: serde_json::json!({}),
            sats_invoiced: 1,
            sats_unbuffered: 1,
            expiry_unix: unix_time() + 60,
        }
    }

    fn paid(id: &str, amount_msat: u64) -> MakePaymentResponse {
        MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::CustomId(id.to_string()),
            payment_proof: Some("proof".to_string()),
            status: cdk_common::nuts::MeltQuoteState::Paid,
            total_spent: Amount::new(amount_msat, CurrencyUnit::Msat),
        }
    }

    fn outgoing_options(quote_id: cdk_common::QuoteId) -> OutgoingPaymentOptions {
        OutgoingPaymentOptions::Custom(Box::new(
            cdk_common::payment::CustomOutgoingPaymentOptions {
                method: "test".to_string(),
                request: "request".to_string(),
                amount: None,
                max_fee_amount: None,
                timeout_secs: None,
                melt_options: None,
                extra_json: None,
                quote_id,
            },
        ))
    }

    fn fiat_status_facade(
        sat_backend: DynMintPayment,
        store: Arc<InMemoryRateQuoteStore>,
        control: RateQuoteControlHandle,
    ) -> DynMintPayment {
        let processor = RateConvertingPayment::with_control(
            SharedMintPayment::new(sat_backend),
            Arc::new(FixedRateOracle),
            store,
            RateConvertingPaymentConfig::new(CurrencyUnit::Usd, 100, 120),
            control,
        );
        let processor: DynMintPayment = Arc::new(PaymentErrorAdapter::new(processor));
        Arc::new(CallStatusOnlyPayment::new(processor))
    }

    async fn incoming_status_amount(
        backend: &DynMintPayment,
        payment_id: &PaymentIdentifier,
    ) -> Amount<CurrencyUnit> {
        backend
            .check_incoming_payment_status(payment_id)
            .await
            .expect("incoming status")
            .into_iter()
            .next()
            .expect("one status")
            .payment_amount
    }

    async fn exercise_single_lifecycle_owner(routes: &SatMsatBackends, fiat: &DynMintPayment) {
        routes.sat.start().await.expect("SAT facade start is inert");
        routes.msat.start().await.expect("native owner start");
        fiat.start().await.expect("fiat facade start is inert");
        assert!(routes.sat.is_payment_event_stream_active());
        assert!(!routes.msat.is_payment_event_stream_active());

        let mut stream = routes
            .msat
            .wait_payment_event()
            .await
            .expect("owner stream");
        assert!(stream.next().await.is_some());
        assert!(routes.sat.wait_payment_event().await.is_err());
        assert!(fiat.wait_payment_event().await.is_err());

        routes.sat.cancel_payment_event_stream();
        fiat.cancel_payment_event_stream();
        routes.msat.cancel_payment_event_stream();
        routes.sat.stop().await.expect("SAT facade stop is inert");
        fiat.stop().await.expect("fiat facade stop is inert");
        routes.msat.stop().await.expect("owner stop");
    }

    async fn assert_invalid_outgoing_does_not_mutate(
        owner: &CanonicalPaymentEventOwner,
        store: &InMemoryRateQuoteStore,
        control: &RateQuoteControlHandle,
        fiat_quote: &cdk_common::QuoteId,
    ) {
        let mut non_paid = paid("fiat-melt", 1_501);
        non_paid.status = MeltQuoteState::Unpaid;
        let mut wrong_unit = paid("fiat-melt", 1_501);
        wrong_unit.total_spent = Amount::new(2, CurrencyUnit::Sat);

        assert!(owner
            .route_outgoing(fiat_quote.clone(), non_paid)
            .await
            .is_none());
        assert!(owner
            .route_outgoing(fiat_quote.clone(), wrong_unit)
            .await
            .is_none());
        assert!(owner
            .route_outgoing(fiat_quote.clone(), paid("fiat-melt-b", 1_501))
            .await
            .is_none());
        assert!(store
            .load_unit_controls()
            .await
            .expect("unit controls")
            .is_empty());
        assert_eq!(control.outstanding(&CurrencyUnit::Usd).await, 0);
    }

    #[tokio::test]
    async fn unknown_incoming_is_parked_in_sats_even_with_rate_terms() {
        let (owner, _) = empty_owner(CountingPayment::new(CurrencyUnit::Msat, vec![])).await;
        let store = Arc::new(InMemoryRateQuoteStore::new());
        store
            .insert(RateQuoteRecord {
                payment_lookup_id: PaymentIdentifier::CustomId("stored-rate".to_string()),
                side: RateQuoteSide::Mint,
                fiat_unit: CurrencyUnit::Usd,
                fiat_subunits: 100,
                fiat_fee_subunits: 0,
                snapshot_json: serde_json::json!({}),
                sats_invoiced: 1,
                sats_unbuffered: 1,
                expiry_unix: unix_time() + 60,
            })
            .await
            .expect("rate terms");
        owner
            .install_rate_context(store.clone(), RateQuoteControlHandle::new())
            .expect("rate context");

        assert!(owner
            .route_incoming(incoming("stored-rate", 1_501))
            .await
            .is_none());
        assert!(owner
            .route_incoming(incoming("orphan", 2_999))
            .await
            .is_none());

        let parked = store.parked_payments().await;
        assert_eq!(parked.len(), 2);
        assert_eq!(parked[0].received_sats, 1);
        assert_eq!(parked[0].resolution_status, "unknown_mint_quote");
        assert_eq!(parked[1].received_sats, 2);
    }

    #[tokio::test]
    async fn parked_evidence_precedes_rate_lookup_and_reason_refinement() {
        let (owner, _) = empty_owner(CountingPayment::new(CurrencyUnit::Msat, vec![])).await;
        let store = Arc::new(InMemoryRateQuoteStore::new());
        store
            .insert(rate_record("lookup-fails", RateQuoteSide::Mint, 100))
            .await
            .expect("first rate terms");
        store
            .insert(rate_record("refine-fails", RateQuoteSide::Melt, 100))
            .await
            .expect("second rate terms");
        owner
            .install_rate_context(store.clone(), RateQuoteControlHandle::new())
            .expect("rate context");

        store.fail_next_get().await;
        assert!(owner
            .route_incoming(incoming("lookup-fails", 1_501))
            .await
            .is_none());
        store.fail_parked_insert_on_attempt(3).await;
        assert!(owner
            .route_incoming(incoming("refine-fails", 2_501))
            .await
            .is_none());

        let parked = store.parked_payments().await;
        assert_eq!(parked.len(), 2);
        assert_eq!(parked[0].received_sats, 1);
        assert_eq!(parked[1].received_sats, 2);
        assert_eq!(parked[1].resolution_status, "unknown_mint_quote");
    }

    #[tokio::test]
    async fn incoming_routes_native_exactly_and_fiat_from_stored_terms() {
        let (owner, database) = empty_owner(CountingPayment::new(CurrencyUnit::Msat, vec![])).await;
        let store = Arc::new(InMemoryRateQuoteStore::new());
        owner
            .install_rate_context(store.clone(), RateQuoteControlHandle::new())
            .expect("rate context");
        for (lookup_id, unit) in [
            ("native", CurrencyUnit::Sat),
            ("fiat", CurrencyUnit::Usd),
            ("missing-fiat", CurrencyUnit::Usd),
        ] {
            add_mint_quote(
                &database,
                PaymentIdentifier::CustomId(lookup_id.to_string()),
                unit,
            )
            .await;
        }
        store
            .insert(rate_record("fiat", RateQuoteSide::Mint, 125))
            .await
            .expect("rate terms");

        let native = owner
            .route_incoming(incoming("native", 1_501))
            .await
            .expect("native event");
        let fiat = owner
            .route_incoming(incoming("fiat", 1_501))
            .await
            .expect("fiat event");
        let replay = owner
            .route_incoming(incoming("fiat", 1_501))
            .await
            .expect("fiat replay");
        let missing = owner.route_incoming(incoming("missing-fiat", 1_501)).await;

        assert_eq!(
            native.payment_amount,
            Amount::new(1_501, CurrencyUnit::Msat)
        );
        assert_eq!(fiat.payment_amount, Amount::new(125, CurrencyUnit::Usd));
        assert_eq!(replay.payment_amount, fiat.payment_amount);
        assert!(missing.is_none());
        let parked = store.parked_payments().await;
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].received_sats, 1);
    }

    #[tokio::test]
    async fn outgoing_routes_native_and_replays_fiat_terms_idempotently() {
        let (owner, database) = empty_owner(CountingPayment::new(CurrencyUnit::Msat, vec![])).await;
        let store = Arc::new(InMemoryRateQuoteStore::new());
        let control = RateQuoteControlHandle::new();
        owner
            .install_rate_context(store.clone(), control.clone())
            .expect("rate context");
        let native_quote = cdk_common::QuoteId::new();
        add_melt_quote(
            &database,
            native_quote.clone(),
            Some(PaymentIdentifier::CustomId("native-melt".to_string())),
            CurrencyUnit::Sat,
        )
        .await;
        let fiat_quote = add_rate_melt_quote(&database, &store, "fiat-melt", 125).await;
        add_rate_melt_quote(&database, &store, "fiat-melt-b", 250).await;
        assert_invalid_outgoing_does_not_mutate(&owner, &store, &control, &fiat_quote).await;

        let native = owner
            .route_outgoing(native_quote.clone(), paid("native-melt", 1_501))
            .await
            .expect("native result");
        let fiat = owner
            .route_outgoing(fiat_quote.clone(), paid("fiat-melt", 1_501))
            .await
            .expect("fiat result");
        let replay = owner
            .route_outgoing(fiat_quote, paid("fiat-melt", 1_501))
            .await
            .expect("fiat replay");
        let mismatched = owner
            .route_outgoing(native_quote, paid("wrong-melt", 1_501))
            .await;

        assert_eq!(native.1.total_spent, Amount::new(2, CurrencyUnit::Sat));
        assert_eq!(fiat.1.total_spent, Amount::new(125, CurrencyUnit::Usd));
        assert_eq!(replay.1.total_spent, fiat.1.total_spent);
        assert!(mismatched.is_none());
        assert!(store.parked_payments().await.is_empty());
    }

    #[tokio::test]
    async fn make_payment_uses_durable_lookup_without_retrying_mismatch() {
        let payment = CountingPayment::new(CurrencyUnit::Msat, vec![]);
        let make_calls = payment.make_calls.clone();
        *payment.make_response.lock().expect("make response") = Some(paid("substitute", 1_501));
        *payment.outgoing_status.lock().expect("outgoing status") = Some(paid("expected", 1_501));
        let (owner, database) = empty_owner(payment).await;
        let quote_id = cdk_common::QuoteId::new();
        add_melt_quote(
            &database,
            quote_id.clone(),
            Some(PaymentIdentifier::CustomId("expected".to_string())),
            CurrencyUnit::Sat,
        )
        .await;

        let result = owner
            .make_payment(&CurrencyUnit::Msat, outgoing_options(quote_id))
            .await;
        assert!(result.is_err());
        assert_eq!(make_calls.load(Ordering::Relaxed), 1);
        let status = owner
            .check_outgoing_payment(&PaymentIdentifier::CustomId("expected".to_string()))
            .await
            .expect("poll durable expected id");
        assert_eq!(
            status.payment_lookup_id,
            PaymentIdentifier::CustomId("expected".to_string())
        );
    }

    #[tokio::test]
    async fn make_payment_allows_legitimately_absent_durable_lookup_id() {
        let payment = CountingPayment::new(CurrencyUnit::Msat, vec![]);
        let make_calls = payment.make_calls.clone();
        *payment.make_response.lock().expect("make response") = Some(paid("assigned-later", 1_501));
        let (owner, database) = empty_owner(payment).await;
        let async_quote = cdk_common::QuoteId::new();
        add_melt_quote(&database, async_quote.clone(), None, CurrencyUnit::Sat).await;

        let response = owner
            .make_payment(&CurrencyUnit::Msat, outgoing_options(async_quote))
            .await
            .expect("async backend may assign lookup id at payment start");
        assert_eq!(
            response.payment_lookup_id,
            PaymentIdentifier::CustomId("assigned-later".to_string())
        );
        assert_eq!(make_calls.load(Ordering::Relaxed), 1);

        let missing_quote = owner
            .make_payment(
                &CurrencyUnit::Msat,
                outgoing_options(cdk_common::QuoteId::new()),
            )
            .await;
        assert!(missing_quote.is_err());
        assert_eq!(make_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn status_checks_reject_substituted_ids_and_wrong_native_units() {
        let payment = CountingPayment::new(CurrencyUnit::Msat, vec![]);
        payment
            .incoming_status
            .lock()
            .expect("incoming status")
            .push(incoming("other", 1_501));
        *payment.outgoing_status.lock().expect("outgoing status") = Some(paid("other", 1_501));
        let (owner, _) = empty_owner(payment.clone()).await;
        let requested = PaymentIdentifier::CustomId("expected".to_string());

        assert!(owner
            .check_incoming_payment_status(&requested)
            .await
            .is_err());
        assert!(owner.check_outgoing_payment(&requested).await.is_err());

        payment
            .incoming_status
            .lock()
            .expect("incoming status")
            .clear();
        payment
            .incoming_status
            .lock()
            .expect("incoming status")
            .push(WaitPaymentResponse {
                payment_identifier: requested.clone(),
                payment_amount: Amount::new(2, CurrencyUnit::Sat),
                payment_id: "hash".to_string(),
            });
        assert!(owner
            .check_incoming_payment_status(&requested)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn facades_never_duplicate_lifecycle_or_event_consumption() {
        let failed = Event::PaymentFailed {
            quote_id: cdk_common::QuoteId::new(),
            reason: "test".to_string(),
        };
        let payment = CountingPayment::new(CurrencyUnit::Msat, vec![failed]);
        payment
            .incoming_status
            .lock()
            .expect("incoming status")
            .push(incoming("status", 1_501));
        let database: DynMintDatabase =
            Arc::new(cdk_sqlite::mint::memory::empty().await.expect("database"));
        let (_, routes) = canonical_sat_msat_backends(Arc::new(payment.clone()), database)
            .await
            .expect("canonical routes");
        let store = Arc::new(InMemoryRateQuoteStore::new());
        store
            .insert(rate_record("status", RateQuoteSide::Mint, 125))
            .await
            .expect("rate terms");
        let fiat = fiat_status_facade(routes.sat.clone(), store, RateQuoteControlHandle::new());
        let status_id = PaymentIdentifier::CustomId("status".to_string());
        assert_eq!(
            incoming_status_amount(&routes.msat, &status_id).await,
            Amount::new(1_501, CurrencyUnit::Msat)
        );
        assert_eq!(
            incoming_status_amount(&routes.sat, &status_id).await,
            Amount::new(1, CurrencyUnit::Sat)
        );
        assert_eq!(
            incoming_status_amount(&fiat, &status_id).await,
            Amount::new(125, CurrencyUnit::Usd)
        );
        exercise_single_lifecycle_owner(&routes, &fiat).await;
        payment.assert_single_lifecycle_owner();
    }
}
