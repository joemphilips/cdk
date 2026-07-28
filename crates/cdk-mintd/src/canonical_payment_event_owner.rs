use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cdk_common::database::DynMintDatabase;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{
    CreateIncomingPaymentResponse, DynMintPayment, Event, IncomingPaymentOptions,
    MakePaymentResponse, MintPayment, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use cdk_exchange_rate::{
    convert_incoming_response_to_sat, convert_outgoing_response_to_unit,
    convert_rate_melt_response, convert_rate_mint_payment, DynRateQuoteStore, ParkedPaymentRecord,
    RateQuoteControlHandle, RateQuoteSide,
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
        let quote = match self.localstore.get_melt_quote(&quote_id).await {
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
        if quote.request_lookup_id.as_ref() != Some(&details.payment_lookup_id) {
            tracing::warn!(
                %quote_id,
                payment_lookup_id = %details.payment_lookup_id,
                "suppressing payment event with mismatched melt correlation"
            );
            return None;
        }
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

        let quote = match self
            .localstore
            .get_mint_quote_by_request_lookup_id(&payment.payment_identifier)
            .await
        {
            Ok(Some(quote)) => quote,
            Ok(None) => {
                self.park_unknown_incoming(payment).await;
                return None;
            }
            Err(error) => {
                tracing::warn!(
                    payment_lookup_id = %payment.payment_identifier,
                    %error,
                    "suppressing payment event after mint quote lookup failure"
                );
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
        let mut parked = ParkedPaymentRecord {
            payment_lookup_id: payment.payment_identifier.clone(),
            bolt11_payment_hash: payment.payment_id,
            received_sats: payment.payment_amount.value(),
            observed_at: unix_time(),
            resolution_status: "unknown_mint_quote".to_string(),
        };
        match rate.store.park_or_credit(parked.clone()).await {
            Ok(None) => {}
            Ok(Some(record)) => {
                // A rate quote alone does not authorize minting when the mint
                // quote is missing. Preserve the funds for operator recovery.
                parked.resolution_status = match record.side {
                    RateQuoteSide::Mint => "unknown_mint_quote",
                    RateQuoteSide::Melt => "wrong_side_incoming",
                }
                .to_string();
                if let Err(error) = rate.store.insert_parked(parked).await {
                    tracing::warn!(
                        payment_lookup_id = %payment.payment_identifier,
                        %error,
                        "failed to park unknown payment with stored rate terms"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    payment_lookup_id = %payment.payment_identifier,
                    %error,
                    "failed to classify and park unknown payment"
                );
            }
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
        self.inner.make_payment(unit, options).await
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

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use cdk_common::mint::{MeltPaymentRequest, MeltQuote, MintQuote};
    use cdk_common::Amount;
    use cdk_exchange_rate::{
        InMemoryRateQuoteStore, RateQuoteRecord, RateQuoteSide, RateQuoteStore,
    };
    use futures::stream;

    use super::*;

    #[derive(Debug, Clone)]
    struct CountingPayment {
        unit: CurrencyUnit,
        starts: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        waits: Arc<AtomicUsize>,
        cancels: Arc<AtomicUsize>,
        events: Vec<Event>,
    }

    impl CountingPayment {
        fn new(unit: CurrencyUnit, events: Vec<Event>) -> Self {
            Self {
                unit,
                starts: Arc::default(),
                stops: Arc::default(),
                waits: Arc::default(),
                cancels: Arc::default(),
                events,
            }
        }

        fn unsupported<T>() -> Result<T, cdk_common::payment::Error> {
            Err(cdk_common::payment::Error::UnsupportedPaymentOption)
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
            Self::unsupported()
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
            Self::unsupported()
        }

        async fn check_outgoing_payment(
            &self,
            _payment_identifier: &PaymentIdentifier,
        ) -> Result<MakePaymentResponse, Self::Err> {
            Self::unsupported()
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
        lookup_id: PaymentIdentifier,
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
            Some(lookup_id),
            None,
            cdk_common::PaymentMethod::Custom("test".to_string()),
            None,
            None,
        );
        let mut transaction = database.begin_transaction().await.expect("transaction");
        transaction.add_melt_quote(quote).await.expect("melt quote");
        transaction.commit().await.expect("commit melt quote");
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
    async fn incoming_routes_native_exactly_and_fiat_from_stored_terms() {
        let (owner, database) = empty_owner(CountingPayment::new(CurrencyUnit::Msat, vec![])).await;
        let store = Arc::new(InMemoryRateQuoteStore::new());
        owner
            .install_rate_context(store.clone(), RateQuoteControlHandle::new())
            .expect("rate context");
        add_mint_quote(
            &database,
            PaymentIdentifier::CustomId("native".to_string()),
            CurrencyUnit::Sat,
        )
        .await;
        add_mint_quote(
            &database,
            PaymentIdentifier::CustomId("fiat".to_string()),
            CurrencyUnit::Usd,
        )
        .await;
        add_mint_quote(
            &database,
            PaymentIdentifier::CustomId("missing-fiat".to_string()),
            CurrencyUnit::Usd,
        )
        .await;
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
        owner
            .install_rate_context(store.clone(), RateQuoteControlHandle::new())
            .expect("rate context");
        let native_quote = cdk_common::QuoteId::new();
        let fiat_quote = cdk_common::QuoteId::new();
        add_melt_quote(
            &database,
            native_quote.clone(),
            PaymentIdentifier::CustomId("native-melt".to_string()),
            CurrencyUnit::Sat,
        )
        .await;
        add_melt_quote(
            &database,
            fiat_quote.clone(),
            PaymentIdentifier::CustomId("fiat-melt".to_string()),
            CurrencyUnit::Usd,
        )
        .await;
        store
            .insert(rate_record("fiat-melt", RateQuoteSide::Melt, 125))
            .await
            .expect("rate terms");

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
    async fn facades_never_duplicate_lifecycle_or_event_consumption() {
        let failed = Event::PaymentFailed {
            quote_id: cdk_common::QuoteId::new(),
            reason: "test".to_string(),
        };
        let payment = CountingPayment::new(CurrencyUnit::Msat, vec![failed]);
        let starts = payment.starts.clone();
        let stops = payment.stops.clone();
        let waits = payment.waits.clone();
        let cancels = payment.cancels.clone();
        let (owner, _) = empty_owner(payment).await;
        let facade = CallStatusOnlyPayment::new(Arc::new(owner.clone()));

        owner.start().await.expect("owner start");
        facade.start().await.expect("facade start is inert");
        let mut stream = owner.wait_payment_event().await.expect("owner stream");
        assert!(stream.next().await.is_some());
        assert!(facade.wait_payment_event().await.is_err());
        facade.cancel_payment_event_stream();
        owner.cancel_payment_event_stream();
        facade.stop().await.expect("facade stop is inert");
        owner.stop().await.expect("owner stop");

        assert_eq!(starts.load(Ordering::Relaxed), 1);
        assert_eq!(stops.load(Ordering::Relaxed), 1);
        assert_eq!(waits.load(Ordering::Relaxed), 1);
        assert_eq!(cancels.load(Ordering::Relaxed), 1);
    }
}
