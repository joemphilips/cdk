use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use cdk_common::database::DynMintDatabase;
use cdk_common::mint::{MeltQuote, MintQuote};
use cdk_common::nuts::{CurrencyUnit, MeltQuoteState};
use cdk_common::payment::unit_converter::{
    convert_outgoing_response_to_unit, sat_msat_backends, validate_incoming_responses,
    validate_outgoing_response, SatMsatBackends,
};
use cdk_common::payment::{
    CreateIncomingPaymentResponse, DynMintPayment, Event, IncomingPaymentOptions,
    MakePaymentResponse, MintPayment, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use futures::{Stream, StreamExt};

/// Sole lifecycle and event-stream owner for one physical Lightning backend.
#[derive(Clone)]
pub(crate) struct CanonicalPaymentEventOwner {
    inner: DynMintPayment,
    localstore: DynMintDatabase,
    native_unit: CurrencyUnit,
}

pub(crate) async fn canonical_sat_msat_backends(
    backend: DynMintPayment,
    localstore: DynMintDatabase,
) -> Result<SatMsatBackends, cdk_common::payment::Error> {
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

    match native_unit {
        CurrencyUnit::Sat => Ok(SatMsatBackends {
            sat: owner,
            msat: Arc::new(CallStatusOnlyPayment::new(raw.msat)),
        }),
        CurrencyUnit::Msat => Ok(SatMsatBackends {
            sat: Arc::new(CallStatusOnlyPayment::new(raw.sat)),
            msat: owner,
        }),
        _ => Err(cdk_common::payment::Error::UnsupportedUnit),
    }
}

impl std::fmt::Debug for CanonicalPaymentEventOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanonicalPaymentEventOwner")
            .field("native_unit", &self.native_unit)
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
        }
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
        match convert_outgoing_response_to_unit(details, &quote.unit) {
            Ok(details) => Some((quote_id, details)),
            Err(error) => {
                tracing::warn!(
                    %quote_id,
                    %error,
                    "suppressing payment event after unit conversion failure"
                );
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
            Ok(None) | Err(()) => {
                tracing::warn!(
                    payment_lookup_id = %payment.payment_identifier,
                    "suppressing payment event for unknown mint quote"
                );
                return None;
            }
        };

        match (&self.native_unit, &quote.unit) {
            (native, quoted) if native == quoted => Some(payment),
            (CurrencyUnit::Sat, CurrencyUnit::Msat) | (CurrencyUnit::Msat, CurrencyUnit::Sat) => {
                Some(payment)
            }
            _ => {
                tracing::warn!(
                    payment_lookup_id = %payment.payment_identifier,
                    native_unit = %self.native_unit,
                    quote_unit = %quote.unit,
                    "suppressing payment event for unsupported unit route"
                );
                None
            }
        }
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
    fn new(inner: DynMintPayment) -> Self {
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

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use cdk_common::mint::{MeltPaymentRequest, MeltQuote, MintQuote};
    use cdk_common::{Amount, QuoteId};
    use futures::{stream, StreamExt};

    use super::*;

    #[derive(Debug, Clone)]
    struct CountingPayment {
        unit: CurrencyUnit,
        starts: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        waits: Arc<AtomicUsize>,
        cancels: Arc<AtomicUsize>,
        make_calls: Arc<AtomicUsize>,
        events: Arc<Mutex<Vec<Event>>>,
        make_response: Arc<Mutex<Option<MakePaymentResponse>>>,
        incoming_status: Arc<Mutex<Vec<WaitPaymentResponse>>>,
        outgoing_status: Arc<Mutex<Option<MakePaymentResponse>>>,
    }

    impl CountingPayment {
        fn new(unit: CurrencyUnit) -> Self {
            Self {
                unit,
                starts: Arc::default(),
                stops: Arc::default(),
                waits: Arc::default(),
                cancels: Arc::default(),
                make_calls: Arc::default(),
                events: Arc::default(),
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
                bolt11: Some(cdk_common::payment::Bolt11Settings {
                    mpp: false,
                    amountless: false,
                    invoice_description: false,
                }),
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
            Ok(Box::pin(stream::iter(
                self.events.lock().expect("events").clone(),
            )))
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

    fn unix_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs()
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

    fn incoming(id: &str, value: u64, unit: CurrencyUnit) -> WaitPaymentResponse {
        WaitPaymentResponse {
            payment_identifier: PaymentIdentifier::CustomId(id.to_string()),
            payment_amount: Amount::new(value, unit),
            payment_id: format!("hash-{id}"),
        }
    }

    async fn add_mint_quote(
        database: &DynMintDatabase,
        lookup_id: PaymentIdentifier,
        unit: CurrencyUnit,
    ) {
        let quote = MintQuote::new(
            Some(QuoteId::new()),
            format!("request-{lookup_id}"),
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
        quote_id: QuoteId,
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

    fn paid(id: &str, value: u64, unit: CurrencyUnit) -> MakePaymentResponse {
        MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::CustomId(id.to_string()),
            payment_proof: Some("proof".to_string()),
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(value, unit),
        }
    }

    fn outgoing_options(quote_id: QuoteId) -> OutgoingPaymentOptions {
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

    #[tokio::test]
    async fn native_and_converted_routes_share_one_lifecycle_and_event_owner() {
        let payment = CountingPayment::new(CurrencyUnit::Msat);
        payment
            .events
            .lock()
            .expect("events")
            .push(Event::PaymentFailed {
                quote_id: QuoteId::new(),
                reason: "test".to_string(),
            });
        payment
            .incoming_status
            .lock()
            .expect("incoming status")
            .push(incoming("status", 1_501, CurrencyUnit::Msat));
        let database: DynMintDatabase =
            Arc::new(cdk_sqlite::mint::memory::empty().await.expect("database"));
        let routes = canonical_sat_msat_backends(Arc::new(payment.clone()), database)
            .await
            .expect("canonical routes");

        routes.sat.start().await.expect("facade start");
        routes.msat.start().await.expect("owner start");
        let status_id = PaymentIdentifier::CustomId("status".to_string());
        let sat_status = routes
            .sat
            .check_incoming_payment_status(&status_id)
            .await
            .expect("converted status");
        let msat_status = routes
            .msat
            .check_incoming_payment_status(&status_id)
            .await
            .expect("native status");
        assert_eq!(
            sat_status[0].payment_amount,
            Amount::new(1, CurrencyUnit::Sat)
        );
        assert_eq!(
            msat_status[0].payment_amount,
            Amount::new(1_501, CurrencyUnit::Msat)
        );

        assert!(routes.sat.wait_payment_event().await.is_err());
        let mut events = routes
            .msat
            .wait_payment_event()
            .await
            .expect("owner event stream");
        assert!(matches!(
            events.next().await,
            Some(Event::PaymentFailed { .. })
        ));
        routes.sat.cancel_payment_event_stream();
        routes.msat.cancel_payment_event_stream();
        routes.sat.stop().await.expect("facade stop");
        routes.msat.stop().await.expect("owner stop");

        payment.assert_single_lifecycle_owner();
    }

    #[tokio::test]
    async fn make_payment_rejects_durable_lookup_substitution_without_retry() {
        let payment = CountingPayment::new(CurrencyUnit::Msat);
        *payment.make_response.lock().expect("make response") =
            Some(paid("substitute", 1_501, CurrencyUnit::Msat));
        *payment.outgoing_status.lock().expect("outgoing status") =
            Some(paid("expected", 1_501, CurrencyUnit::Msat));
        let (owner, database) = empty_owner(payment.clone()).await;
        let quote_id = QuoteId::new();
        let expected = PaymentIdentifier::CustomId("expected".to_string());
        add_melt_quote(
            &database,
            quote_id.clone(),
            Some(expected.clone()),
            CurrencyUnit::Msat,
        )
        .await;

        assert!(owner
            .make_payment(&CurrencyUnit::Msat, outgoing_options(quote_id))
            .await
            .is_err());
        assert_eq!(payment.make_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            owner
                .check_outgoing_payment(&expected)
                .await
                .expect("durable status")
                .payment_lookup_id,
            expected
        );
    }

    #[tokio::test]
    async fn make_payment_accepts_backend_assigned_lookup_when_quote_has_none() {
        let payment = CountingPayment::new(CurrencyUnit::Msat);
        *payment.make_response.lock().expect("make response") =
            Some(paid("assigned-later", 1_501, CurrencyUnit::Msat));
        let (owner, database) = empty_owner(payment.clone()).await;
        let quote_id = QuoteId::new();
        add_melt_quote(&database, quote_id.clone(), None, CurrencyUnit::Msat).await;

        let response = owner
            .make_payment(&CurrencyUnit::Msat, outgoing_options(quote_id))
            .await
            .expect("backend may assign lookup at payment start");
        assert_eq!(
            response.payment_lookup_id,
            PaymentIdentifier::CustomId("assigned-later".to_string())
        );
        assert!(owner
            .make_payment(&CurrencyUnit::Msat, outgoing_options(QuoteId::new()))
            .await
            .is_err());
        assert_eq!(payment.make_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn status_checks_reject_substituted_ids_and_wrong_native_units() {
        let payment = CountingPayment::new(CurrencyUnit::Msat);
        payment
            .incoming_status
            .lock()
            .expect("incoming status")
            .push(incoming("other", 1_501, CurrencyUnit::Msat));
        *payment.outgoing_status.lock().expect("outgoing status") =
            Some(paid("other", 1_501, CurrencyUnit::Msat));
        let (owner, _) = empty_owner(payment.clone()).await;
        let requested = PaymentIdentifier::CustomId("expected".to_string());

        assert!(owner
            .check_incoming_payment_status(&requested)
            .await
            .is_err());
        assert!(owner.check_outgoing_payment(&requested).await.is_err());

        *payment.incoming_status.lock().expect("incoming status") =
            vec![incoming("expected", 2, CurrencyUnit::Sat)];
        assert!(owner
            .check_incoming_payment_status(&requested)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn native_msat_non_sat_path_keeps_one_correlated_event_owner() {
        let payment = CountingPayment::new(CurrencyUnit::Msat);
        payment
            .incoming_status
            .lock()
            .expect("incoming status")
            .push(incoming("expected", 1_501, CurrencyUnit::Msat));
        payment
            .events
            .lock()
            .expect("events")
            .push(Event::PaymentFailed {
                quote_id: QuoteId::new(),
                reason: "test".to_string(),
            });
        let database: DynMintDatabase =
            Arc::new(cdk_sqlite::mint::memory::empty().await.expect("database"));
        let owner = crate::canonical_non_sat_backend(
            CurrencyUnit::Msat,
            Arc::new(payment.clone()),
            database,
        )
        .await
        .expect("canonical native msat backend");
        let expected = PaymentIdentifier::CustomId("expected".to_string());

        owner.start().await.expect("owner start");
        assert_eq!(
            owner
                .check_incoming_payment_status(&expected)
                .await
                .expect("correlated status")[0]
                .payment_amount,
            Amount::new(1_501, CurrencyUnit::Msat)
        );
        assert!(owner
            .wait_payment_event()
            .await
            .expect("owner stream")
            .next()
            .await
            .is_some());
        owner.cancel_payment_event_stream();
        owner.stop().await.expect("owner stop");

        payment.assert_single_lifecycle_owner();
    }

    #[tokio::test]
    async fn same_unit_non_sat_owner_suppresses_uncorrelated_events() {
        let payment = CountingPayment::new(CurrencyUnit::Usd);
        let database: DynMintDatabase =
            Arc::new(cdk_sqlite::mint::memory::empty().await.expect("database"));
        let known = PaymentIdentifier::CustomId("known".to_string());
        add_mint_quote(&database, known, CurrencyUnit::Usd).await;
        let good_quote = QuoteId::new();
        add_melt_quote(
            &database,
            good_quote.clone(),
            Some(PaymentIdentifier::CustomId("good".to_string())),
            CurrencyUnit::Usd,
        )
        .await;
        let missing_lookup_quote = QuoteId::new();
        add_melt_quote(
            &database,
            missing_lookup_quote.clone(),
            None,
            CurrencyUnit::Usd,
        )
        .await;
        let wrong_lookup_quote = QuoteId::new();
        add_melt_quote(
            &database,
            wrong_lookup_quote.clone(),
            Some(PaymentIdentifier::CustomId("expected".to_string())),
            CurrencyUnit::Usd,
        )
        .await;
        *payment.events.lock().expect("events") = vec![
            Event::PaymentReceived(incoming("known", 100, CurrencyUnit::Usd)),
            Event::PaymentReceived(incoming("unknown", 100, CurrencyUnit::Usd)),
            Event::PaymentReceived(incoming("known", 100, CurrencyUnit::Sat)),
            Event::PaymentSuccessful {
                quote_id: good_quote,
                details: paid("good", 100, CurrencyUnit::Usd),
            },
            Event::PaymentSuccessful {
                quote_id: missing_lookup_quote,
                details: paid("assigned", 100, CurrencyUnit::Usd),
            },
            Event::PaymentSuccessful {
                quote_id: wrong_lookup_quote,
                details: paid("substitute", 100, CurrencyUnit::Usd),
            },
        ];

        let owner = crate::canonical_non_sat_backend(
            CurrencyUnit::Usd,
            Arc::new(payment.clone()),
            database,
        )
        .await
        .expect("canonical same-unit backend");
        owner.start().await.expect("owner start");
        let events = owner
            .wait_payment_event()
            .await
            .expect("owner events")
            .collect::<Vec<_>>()
            .await;
        owner.cancel_payment_event_stream();
        owner.stop().await.expect("owner stop");

        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::PaymentReceived(_)));
        assert!(matches!(events[1], Event::PaymentSuccessful { .. }));
        payment.assert_single_lifecycle_owner();
    }
}
