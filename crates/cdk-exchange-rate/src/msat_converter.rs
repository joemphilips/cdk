//! Fixed msat/sat [`MintPayment`](cdk_common::payment::MintPayment) decorator.

use std::pin::Pin;
use std::str::FromStr;

use async_trait::async_trait;
use cdk_common::amount::MSAT_IN_SAT;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{
    CreateIncomingPaymentResponse, DynMintPayment, Event, IncomingPaymentOptions,
    MakePaymentResponse, MintPayment, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use cdk_common::Amount;
use futures::{Stream, StreamExt};

use crate::payment::SharedMintPayment;

/// Exact native-unit and fixed-ratio SAT/MSAT views over one Lightning backend.
pub struct SatMsatBackends {
    /// SAT-facing backend.
    pub sat: DynMintPayment,
    /// MSAT-facing backend.
    pub msat: DynMintPayment,
}

impl std::fmt::Debug for SatMsatBackends {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SatMsatBackends")
            .finish_non_exhaustive()
    }
}

/// Build SAT and MSAT routes without converting the backend's native unit twice.
pub async fn sat_msat_backends(
    backend: DynMintPayment,
) -> Result<SatMsatBackends, cdk_common::payment::Error> {
    let settings = backend.get_settings().await?;
    let unit = CurrencyUnit::from_str(&settings.unit).map_err(|_| {
        cdk_common::payment::Error::Custom(format!(
            "invalid payment backend unit `{}`",
            settings.unit
        ))
    })?;

    match unit {
        CurrencyUnit::Sat => Ok(SatMsatBackends {
            sat: backend.clone(),
            msat: std::sync::Arc::new(MsatSatConverter::new(SharedMintPayment::new(backend))),
        }),
        CurrencyUnit::Msat => Ok(SatMsatBackends {
            sat: std::sync::Arc::new(SatMsatConverter::new(SharedMintPayment::new(
                backend.clone(),
            ))),
            msat: backend,
        }),
        _ => Err(cdk_common::payment::Error::UnsupportedUnit),
    }
}

/// Decorates a sat-denominated payment backend as an msat-denominated processor.
#[derive(Debug, Clone)]
pub struct MsatSatConverter<T> {
    inner: T,
}

impl<T> MsatSatConverter<T> {
    /// Create a new fixed-ratio msat/sat converter.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<T> MintPayment for MsatSatConverter<T>
where
    T: MintPayment<Err = cdk_common::payment::Error> + Send + Sync,
{
    type Err = cdk_common::payment::Error;

    #[tracing::instrument(skip_all)]
    async fn start(&self) -> Result<(), Self::Err> {
        self.inner.start().await
    }

    #[tracing::instrument(skip_all)]
    async fn stop(&self) -> Result<(), Self::Err> {
        self.inner.stop().await
    }

    #[tracing::instrument(skip_all)]
    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        let inner = self.inner.get_settings().await?;
        ensure_settings_unit(&inner.unit, &CurrencyUnit::Sat)?;
        Ok(SettingsResponse {
            unit: CurrencyUnit::Msat.to_string(),
            bolt11: inner.bolt11,
            bolt12: inner.bolt12,
            onchain: None,
            custom: inner.custom,
        })
    }

    #[tracing::instrument(skip_all)]
    async fn create_incoming_payment_request(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        self.inner
            .create_incoming_payment_request(convert_incoming_options_to_sat(options)?)
            .await
    }

    #[tracing::instrument(skip_all)]
    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        ensure_msat_unit(unit)?;
        let quote = self
            .inner
            .get_payment_quote(
                &CurrencyUnit::Sat,
                convert_outgoing_options_to_sat(options)?,
            )
            .await?;
        Ok(PaymentQuoteResponse {
            request_lookup_id: quote.request_lookup_id,
            amount: sats_to_msats(quote.amount)?,
            fee: sats_to_msats(quote.fee)?,
            state: quote.state,
            extra_json: quote.extra_json,
            estimated_blocks: None,
            fee_options: None,
        })
    }

    #[tracing::instrument(skip_all)]
    async fn make_payment(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        ensure_msat_unit(unit)?;
        let response = self
            .inner
            .make_payment(
                &CurrencyUnit::Sat,
                convert_outgoing_options_to_sat(options)?,
            )
            .await?;
        convert_make_payment_response_to_msat(response)
    }

    #[tracing::instrument(skip_all)]
    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let stream = self.inner.wait_payment_event().await?;
        Ok(Box::pin(stream.filter_map(|event| async move {
            match convert_event_to_msat(event) {
                Ok(msat_event) => Some(msat_event),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to convert payment event to msat; dropping event"
                    );
                    None
                }
            }
        })))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.inner.is_payment_event_stream_active()
    }

    fn cancel_payment_event_stream(&self) {
        self.inner.cancel_payment_event_stream();
    }

    #[tracing::instrument(skip_all)]
    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        self.inner
            .check_incoming_payment_status(payment_identifier)
            .await?
            .into_iter()
            .map(convert_wait_payment_response_to_msat)
            .collect()
    }

    #[tracing::instrument(skip_all)]
    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        convert_make_payment_response_to_msat(
            self.inner
                .check_outgoing_payment(payment_identifier)
                .await?,
        )
    }
}

/// Decorates an msat-denominated payment backend as a sat-denominated processor.
///
/// Incoming credit rounds down so sub-sat overpayment cannot mint an extra sat.
/// Outgoing quotes and paid costs round up so the mint never understates its
/// Lightning expense.
#[derive(Debug, Clone)]
pub struct SatMsatConverter<T> {
    inner: T,
}

impl<T> SatMsatConverter<T> {
    /// Create a new fixed-ratio sat/msat converter.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<T> MintPayment for SatMsatConverter<T>
where
    T: MintPayment<Err = cdk_common::payment::Error> + Send + Sync,
{
    type Err = cdk_common::payment::Error;

    #[tracing::instrument(skip_all)]
    async fn start(&self) -> Result<(), Self::Err> {
        self.inner.start().await
    }

    #[tracing::instrument(skip_all)]
    async fn stop(&self) -> Result<(), Self::Err> {
        self.inner.stop().await
    }

    #[tracing::instrument(skip_all)]
    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        let inner = self.inner.get_settings().await?;
        ensure_settings_unit(&inner.unit, &CurrencyUnit::Msat)?;
        Ok(SettingsResponse {
            unit: CurrencyUnit::Sat.to_string(),
            bolt11: inner.bolt11,
            bolt12: inner.bolt12,
            onchain: None,
            custom: inner.custom,
        })
    }

    #[tracing::instrument(skip_all)]
    async fn create_incoming_payment_request(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        self.inner
            .create_incoming_payment_request(convert_incoming_options_to_msat(options)?)
            .await
    }

    #[tracing::instrument(skip_all)]
    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        ensure_sat_unit(unit)?;
        let quote = self
            .inner
            .get_payment_quote(
                &CurrencyUnit::Msat,
                convert_outgoing_options_to_msat(options)?,
            )
            .await?;
        Ok(PaymentQuoteResponse {
            request_lookup_id: quote.request_lookup_id,
            amount: msats_to_sats(quote.amount)?,
            fee: msats_to_sats(quote.fee)?,
            state: quote.state,
            extra_json: quote.extra_json,
            estimated_blocks: None,
            fee_options: None,
        })
    }

    #[tracing::instrument(skip_all)]
    async fn make_payment(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        ensure_sat_unit(unit)?;
        let response = self
            .inner
            .make_payment(
                &CurrencyUnit::Msat,
                convert_outgoing_options_to_msat(options)?,
            )
            .await?;
        convert_make_payment_response_to_sat(response)
    }

    #[tracing::instrument(skip_all)]
    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let stream = self.inner.wait_payment_event().await?;
        Ok(Box::pin(stream.filter_map(|event| async move {
            match convert_event_to_sat(event) {
                Ok(sat_event) => Some(sat_event),
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "failed to convert payment event to sat; dropping event"
                    );
                    None
                }
            }
        })))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.inner.is_payment_event_stream_active()
    }

    fn cancel_payment_event_stream(&self) {
        self.inner.cancel_payment_event_stream();
    }

    #[tracing::instrument(skip_all)]
    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        self.inner
            .check_incoming_payment_status(payment_identifier)
            .await?
            .into_iter()
            .map(convert_wait_payment_response_to_sat)
            .collect()
    }

    #[tracing::instrument(skip_all)]
    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        convert_make_payment_response_to_sat(
            self.inner
                .check_outgoing_payment(payment_identifier)
                .await?,
        )
    }
}

fn ensure_settings_unit(
    unit: &str,
    expected: &CurrencyUnit,
) -> Result<(), cdk_common::payment::Error> {
    let unit = CurrencyUnit::from_str(unit).map_err(|_| {
        cdk_common::payment::Error::Custom(format!("invalid payment backend unit `{unit}`"))
    })?;
    if &unit == expected {
        Ok(())
    } else {
        Err(cdk_common::payment::Error::UnsupportedUnit)
    }
}

fn ensure_msat_unit(unit: &CurrencyUnit) -> Result<(), cdk_common::payment::Error> {
    if unit == &CurrencyUnit::Msat {
        Ok(())
    } else {
        Err(cdk_common::payment::Error::UnsupportedUnit)
    }
}

fn ensure_sat_unit(unit: &CurrencyUnit) -> Result<(), cdk_common::payment::Error> {
    if unit == &CurrencyUnit::Sat {
        Ok(())
    } else {
        Err(cdk_common::payment::Error::UnsupportedUnit)
    }
}

fn msats_to_sats(
    amount: Amount<CurrencyUnit>,
) -> Result<Amount<CurrencyUnit>, cdk_common::payment::Error> {
    if amount.unit() != &CurrencyUnit::Msat {
        return Err(cdk_common::payment::Error::UnsupportedUnit);
    }
    Ok(Amount::new(
        div_ceil(amount.value(), MSAT_IN_SAT),
        CurrencyUnit::Sat,
    ))
}

fn msats_to_sats_floor(
    amount: Amount<CurrencyUnit>,
) -> Result<Amount<CurrencyUnit>, cdk_common::payment::Error> {
    if amount.unit() != &CurrencyUnit::Msat {
        return Err(cdk_common::payment::Error::UnsupportedUnit);
    }
    Ok(Amount::new(amount.value() / MSAT_IN_SAT, CurrencyUnit::Sat))
}

fn sats_to_msats(
    amount: Amount<CurrencyUnit>,
) -> Result<Amount<CurrencyUnit>, cdk_common::payment::Error> {
    if amount.unit() != &CurrencyUnit::Sat {
        return Err(cdk_common::payment::Error::UnsupportedUnit);
    }
    Ok(Amount::new(
        amount.value().checked_mul(MSAT_IN_SAT).ok_or_else(|| {
            cdk_common::payment::Error::Custom("msat amount overflow".to_string())
        })?,
        CurrencyUnit::Msat,
    ))
}

fn convert_incoming_options_to_sat(
    options: IncomingPaymentOptions,
) -> Result<IncomingPaymentOptions, cdk_common::payment::Error> {
    match options {
        IncomingPaymentOptions::Bolt11(mut options) => {
            options.amount = msats_to_sats(options.amount)?;
            Ok(IncomingPaymentOptions::Bolt11(options))
        }
        IncomingPaymentOptions::Bolt12(mut options) => {
            if let Some(amount) = options.amount {
                options.amount = Some(msats_to_sats(amount)?);
            }
            Ok(IncomingPaymentOptions::Bolt12(options))
        }
        IncomingPaymentOptions::Custom(mut options) => {
            if let Some(amount) = options.amount {
                options.amount = Some(msats_to_sats(amount)?);
            }
            Ok(IncomingPaymentOptions::Custom(options))
        }
        IncomingPaymentOptions::Onchain(_) => {
            Err(cdk_common::payment::Error::UnsupportedPaymentOption)
        }
    }
}

fn convert_outgoing_options_to_sat(
    options: OutgoingPaymentOptions,
) -> Result<OutgoingPaymentOptions, cdk_common::payment::Error> {
    match options {
        OutgoingPaymentOptions::Bolt11(mut options) => {
            if let Some(amount) = options.max_fee_amount {
                options.max_fee_amount = Some(msats_to_sats(amount)?);
            }
            Ok(OutgoingPaymentOptions::Bolt11(options))
        }
        OutgoingPaymentOptions::Bolt12(mut options) => {
            if let Some(amount) = options.max_fee_amount {
                options.max_fee_amount = Some(msats_to_sats(amount)?);
            }
            Ok(OutgoingPaymentOptions::Bolt12(options))
        }
        OutgoingPaymentOptions::Custom(mut options) => {
            if let Some(amount) = options.amount {
                options.amount = Some(msats_to_sats(amount)?);
            }
            if let Some(amount) = options.max_fee_amount {
                options.max_fee_amount = Some(msats_to_sats(amount)?);
            }
            Ok(OutgoingPaymentOptions::Custom(options))
        }
        OutgoingPaymentOptions::Onchain(_) => {
            Err(cdk_common::payment::Error::UnsupportedPaymentOption)
        }
    }
}

fn convert_incoming_options_to_msat(
    options: IncomingPaymentOptions,
) -> Result<IncomingPaymentOptions, cdk_common::payment::Error> {
    match options {
        IncomingPaymentOptions::Bolt11(mut options) => {
            options.amount = sats_to_msats(options.amount)?;
            Ok(IncomingPaymentOptions::Bolt11(options))
        }
        IncomingPaymentOptions::Bolt12(mut options) => {
            if let Some(amount) = options.amount {
                options.amount = Some(sats_to_msats(amount)?);
            }
            Ok(IncomingPaymentOptions::Bolt12(options))
        }
        IncomingPaymentOptions::Custom(mut options) => {
            if let Some(amount) = options.amount {
                options.amount = Some(sats_to_msats(amount)?);
            }
            Ok(IncomingPaymentOptions::Custom(options))
        }
        IncomingPaymentOptions::Onchain(_) => {
            Err(cdk_common::payment::Error::UnsupportedPaymentOption)
        }
    }
}

fn convert_outgoing_options_to_msat(
    options: OutgoingPaymentOptions,
) -> Result<OutgoingPaymentOptions, cdk_common::payment::Error> {
    match options {
        OutgoingPaymentOptions::Bolt11(mut options) => {
            if let Some(amount) = options.max_fee_amount {
                options.max_fee_amount = Some(sats_to_msats(amount)?);
            }
            Ok(OutgoingPaymentOptions::Bolt11(options))
        }
        OutgoingPaymentOptions::Bolt12(mut options) => {
            if let Some(amount) = options.max_fee_amount {
                options.max_fee_amount = Some(sats_to_msats(amount)?);
            }
            Ok(OutgoingPaymentOptions::Bolt12(options))
        }
        OutgoingPaymentOptions::Custom(mut options) => {
            if let Some(amount) = options.amount {
                options.amount = Some(sats_to_msats(amount)?);
            }
            if let Some(amount) = options.max_fee_amount {
                options.max_fee_amount = Some(sats_to_msats(amount)?);
            }
            Ok(OutgoingPaymentOptions::Custom(options))
        }
        OutgoingPaymentOptions::Onchain(_) => {
            Err(cdk_common::payment::Error::UnsupportedPaymentOption)
        }
    }
}

fn convert_event_to_msat(event: Event) -> Result<Event, cdk_common::payment::Error> {
    match event {
        Event::PaymentReceived(payment) => Ok(Event::PaymentReceived(
            convert_wait_payment_response_to_msat(payment)?,
        )),
        Event::PaymentSuccessful { quote_id, details } => Ok(Event::PaymentSuccessful {
            quote_id,
            details: convert_make_payment_response_to_msat(details)?,
        }),
        Event::PaymentFailed { quote_id, reason } => Ok(Event::PaymentFailed { quote_id, reason }),
    }
}

fn convert_event_to_sat(event: Event) -> Result<Event, cdk_common::payment::Error> {
    match event {
        Event::PaymentReceived(payment) => Ok(Event::PaymentReceived(
            convert_wait_payment_response_to_sat(payment)?,
        )),
        Event::PaymentSuccessful { quote_id, details } => Ok(Event::PaymentSuccessful {
            quote_id,
            details: convert_make_payment_response_to_sat(details)?,
        }),
        Event::PaymentFailed { quote_id, reason } => Ok(Event::PaymentFailed { quote_id, reason }),
    }
}

fn convert_wait_payment_response_to_msat(
    payment: WaitPaymentResponse,
) -> Result<WaitPaymentResponse, cdk_common::payment::Error> {
    Ok(WaitPaymentResponse {
        payment_identifier: payment.payment_identifier,
        payment_amount: sats_to_msats(payment.payment_amount)?,
        payment_id: payment.payment_id,
    })
}

fn convert_make_payment_response_to_msat(
    response: MakePaymentResponse,
) -> Result<MakePaymentResponse, cdk_common::payment::Error> {
    Ok(MakePaymentResponse {
        payment_lookup_id: response.payment_lookup_id,
        payment_proof: response.payment_proof,
        status: response.status,
        total_spent: sats_to_msats(response.total_spent)?,
    })
}

fn convert_wait_payment_response_to_sat(
    payment: WaitPaymentResponse,
) -> Result<WaitPaymentResponse, cdk_common::payment::Error> {
    Ok(WaitPaymentResponse {
        payment_identifier: payment.payment_identifier,
        payment_amount: msats_to_sats_floor(payment.payment_amount)?,
        payment_id: payment.payment_id,
    })
}

fn convert_make_payment_response_to_sat(
    response: MakePaymentResponse,
) -> Result<MakePaymentResponse, cdk_common::payment::Error> {
    Ok(MakePaymentResponse {
        payment_lookup_id: response.payment_lookup_id,
        payment_proof: response.payment_proof,
        status: response.status,
        total_spent: msats_to_sats(response.total_spent)?,
    })
}

/// Convert an incoming payment result to SAT without overstating credit.
///
/// Native MSAT credit rounds down when represented as SAT. A SAT response is
/// returned unchanged.
pub fn convert_incoming_response_to_sat(
    payment: WaitPaymentResponse,
) -> Result<WaitPaymentResponse, cdk_common::payment::Error> {
    match payment.payment_amount.unit() {
        CurrencyUnit::Sat => Ok(payment),
        CurrencyUnit::Msat => convert_wait_payment_response_to_sat(payment),
        _ => Err(cdk_common::payment::Error::UnsupportedUnit),
    }
}

/// Convert an outgoing payment result to the quote unit.
///
/// Native MSAT costs round up when represented as SAT so the mint never
/// understates its Lightning expense. SAT to MSAT conversion is exact.
pub fn convert_outgoing_response_to_unit(
    response: MakePaymentResponse,
    target_unit: &CurrencyUnit,
) -> Result<MakePaymentResponse, cdk_common::payment::Error> {
    match (response.total_spent.unit(), target_unit) {
        (source, target) if source == target => Ok(response),
        (CurrencyUnit::Msat, CurrencyUnit::Sat) => convert_make_payment_response_to_sat(response),
        (CurrencyUnit::Sat, CurrencyUnit::Msat) => convert_make_payment_response_to_msat(response),
        _ => Err(cdk_common::payment::Error::UnsupportedUnit),
    }
}

fn div_ceil(numerator: u64, denominator: u64) -> u64 {
    numerator / denominator + u64::from(numerator % denominator != 0)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cdk_common::nuts::MeltQuoteState;
    use cdk_common::payment::{
        Bolt11IncomingPaymentOptions, CustomOutgoingPaymentOptions, OnchainIncomingPaymentOptions,
        OnchainOutgoingPaymentOptions,
    };
    use cdk_common::QuoteId;
    use futures::stream;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct MockSatPayment {
        unit: CurrencyUnit,
        incoming_amounts: Arc<Mutex<Vec<Amount<CurrencyUnit>>>>,
        quote_options: Arc<Mutex<Vec<OutgoingPaymentOptions>>>,
        make_options: Arc<Mutex<Vec<OutgoingPaymentOptions>>>,
        quote: Arc<Mutex<Option<PaymentQuoteResponse>>>,
        incoming_status: Arc<Mutex<Vec<WaitPaymentResponse>>>,
        make_response: Arc<Mutex<Option<MakePaymentResponse>>>,
        check_response: Arc<Mutex<Option<MakePaymentResponse>>>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    #[async_trait]
    impl MintPayment for MockSatPayment {
        type Err = cdk_common::payment::Error;

        async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
            Ok(SettingsResponse {
                unit: self.unit.to_string(),
                bolt11: None,
                bolt12: None,
                onchain: Some(Default::default()),
                custom: Default::default(),
            })
        }

        async fn create_incoming_payment_request(
            &self,
            options: IncomingPaymentOptions,
        ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
            let IncomingPaymentOptions::Bolt11(options) = options else {
                return Err(cdk_common::payment::Error::UnsupportedPaymentOption);
            };
            if options.amount.unit() != &self.unit {
                return Err(cdk_common::payment::Error::UnsupportedUnit);
            }
            self.incoming_amounts
                .lock()
                .expect("incoming amounts mutex should not be poisoned")
                .push(options.amount);
            Ok(CreateIncomingPaymentResponse {
                request_lookup_id: PaymentIdentifier::CustomId("quote".to_string()),
                request: "invoice".to_string(),
                expiry: None,
                extra_json: None,
            })
        }

        async fn get_payment_quote(
            &self,
            unit: &CurrencyUnit,
            options: OutgoingPaymentOptions,
        ) -> Result<PaymentQuoteResponse, Self::Err> {
            if unit != &self.unit {
                return Err(cdk_common::payment::Error::UnsupportedUnit);
            }
            self.quote_options
                .lock()
                .expect("quote options mutex should not be poisoned")
                .push(options);
            self.quote
                .lock()
                .expect("quote mutex should not be poisoned")
                .clone()
                .ok_or_else(|| cdk_common::payment::Error::Custom("missing quote".to_string()))
        }

        async fn make_payment(
            &self,
            unit: &CurrencyUnit,
            options: OutgoingPaymentOptions,
        ) -> Result<MakePaymentResponse, Self::Err> {
            if unit != &self.unit {
                return Err(cdk_common::payment::Error::UnsupportedUnit);
            }
            self.make_options
                .lock()
                .expect("make options mutex should not be poisoned")
                .push(options);
            self.make_response
                .lock()
                .expect("make response mutex should not be poisoned")
                .clone()
                .ok_or_else(|| cdk_common::payment::Error::Custom("missing response".to_string()))
        }

        async fn wait_payment_event(
            &self,
        ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
            Ok(Box::pin(stream::iter(
                self.events
                    .lock()
                    .expect("events mutex should not be poisoned")
                    .clone(),
            )))
        }

        fn is_payment_event_stream_active(&self) -> bool {
            false
        }

        fn cancel_payment_event_stream(&self) {}

        async fn check_incoming_payment_status(
            &self,
            _payment_identifier: &PaymentIdentifier,
        ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
            Ok(self
                .incoming_status
                .lock()
                .expect("incoming status mutex should not be poisoned")
                .clone())
        }

        async fn check_outgoing_payment(
            &self,
            _payment_identifier: &PaymentIdentifier,
        ) -> Result<MakePaymentResponse, Self::Err> {
            self.check_response
                .lock()
                .expect("check response mutex should not be poisoned")
                .clone()
                .ok_or_else(|| cdk_common::payment::Error::Custom("missing response".to_string()))
        }
    }

    fn custom_outgoing_options() -> OutgoingPaymentOptions {
        OutgoingPaymentOptions::Custom(Box::new(CustomOutgoingPaymentOptions {
            method: "test".to_string(),
            request: "request".to_string(),
            amount: None,
            max_fee_amount: None,
            timeout_secs: None,
            melt_options: None,
            extra_json: None,
            quote_id: QuoteId::new(),
        }))
    }

    fn native_msat_backend() -> MockSatPayment {
        let backend = MockSatPayment {
            unit: CurrencyUnit::Msat,
            ..Default::default()
        };
        *backend
            .quote
            .lock()
            .expect("quote mutex should not be poisoned") = Some(PaymentQuoteResponse {
            request_lookup_id: Some(PaymentIdentifier::CustomId("quote".to_string())),
            amount: Amount::new(1_501, CurrencyUnit::Msat),
            fee: Amount::new(1_001, CurrencyUnit::Msat),
            state: MeltQuoteState::Unpaid,
            extra_json: None,
            estimated_blocks: None,
            fee_options: None,
        });
        let paid = MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::CustomId("paid".to_string()),
            payment_proof: Some("proof".to_string()),
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(1_501, CurrencyUnit::Msat),
        };
        *backend
            .make_response
            .lock()
            .expect("make response mutex should not be poisoned") = Some(paid.clone());
        *backend
            .check_response
            .lock()
            .expect("check response mutex should not be poisoned") = Some(paid.clone());
        backend
            .incoming_status
            .lock()
            .expect("incoming status mutex should not be poisoned")
            .push(WaitPaymentResponse {
                payment_identifier: PaymentIdentifier::CustomId("received".to_string()),
                payment_amount: Amount::new(1_501, CurrencyUnit::Msat),
                payment_id: "payment-id".to_string(),
            });
        backend
            .events
            .lock()
            .expect("events mutex should not be poisoned")
            .extend([
                Event::PaymentReceived(WaitPaymentResponse {
                    payment_identifier: PaymentIdentifier::CustomId("received".to_string()),
                    payment_amount: Amount::new(1_501, CurrencyUnit::Msat),
                    payment_id: "payment-id".to_string(),
                }),
                Event::PaymentSuccessful {
                    quote_id: QuoteId::new(),
                    details: paid,
                },
            ]);
        backend
    }

    fn native_sat_backend() -> MockSatPayment {
        let backend = MockSatPayment {
            unit: CurrencyUnit::Sat,
            ..Default::default()
        };
        *backend
            .quote
            .lock()
            .expect("quote mutex should not be poisoned") = Some(PaymentQuoteResponse {
            request_lookup_id: Some(PaymentIdentifier::CustomId("quote".to_string())),
            amount: Amount::new(2, CurrencyUnit::Sat),
            fee: Amount::new(2, CurrencyUnit::Sat),
            state: MeltQuoteState::Unpaid,
            extra_json: None,
            estimated_blocks: None,
            fee_options: None,
        });
        *backend
            .make_response
            .lock()
            .expect("make response mutex should not be poisoned") = Some(MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::CustomId("paid".to_string()),
            payment_proof: Some("proof".to_string()),
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(2, CurrencyUnit::Sat),
        });
        backend
    }

    fn custom_outgoing_with_amounts(
        amount: u64,
        max_fee_amount: u64,
        unit: CurrencyUnit,
    ) -> OutgoingPaymentOptions {
        OutgoingPaymentOptions::Custom(Box::new(CustomOutgoingPaymentOptions {
            amount: Some(Amount::new(amount, unit.clone())),
            max_fee_amount: Some(Amount::new(max_fee_amount, unit)),
            ..match custom_outgoing_options() {
                OutgoingPaymentOptions::Custom(options) => *options,
                _ => unreachable!("helper always returns custom options"),
            }
        }))
    }

    #[tokio::test]
    async fn msat_settings_do_not_advertise_onchain_payments() {
        let settings = MsatSatConverter::new(MockSatPayment::default())
            .get_settings()
            .await
            .expect("settings should load");

        assert!(settings.onchain.is_none());
    }

    #[test]
    fn custom_outgoing_amounts_convert_to_sats() {
        let options = OutgoingPaymentOptions::Custom(Box::new(CustomOutgoingPaymentOptions {
            amount: Some(Amount::new(1_001, CurrencyUnit::Msat)),
            max_fee_amount: Some(Amount::new(2_001, CurrencyUnit::Msat)),
            ..match custom_outgoing_options() {
                OutgoingPaymentOptions::Custom(options) => *options,
                _ => unreachable!("helper always returns custom options"),
            }
        }));

        let OutgoingPaymentOptions::Custom(converted) =
            convert_outgoing_options_to_sat(options).expect("custom amounts should convert")
        else {
            panic!("expected custom options");
        };

        assert_eq!(converted.amount, Some(Amount::new(2, CurrencyUnit::Sat)));
        assert_eq!(
            converted.max_fee_amount,
            Some(Amount::new(3, CurrencyUnit::Sat))
        );
    }

    #[test]
    fn msat_converter_rejects_onchain_options() {
        let incoming = IncomingPaymentOptions::Onchain(OnchainIncomingPaymentOptions {
            quote_id: QuoteId::new(),
        });
        let outgoing = OutgoingPaymentOptions::Onchain(Box::new(OnchainOutgoingPaymentOptions {
            address: "bcrt1qexample".to_string(),
            amount: Amount::new(1_000, CurrencyUnit::Msat),
            max_fee_amount: None,
            quote_id: QuoteId::new(),
            fee_index: None,
            metadata: None,
        }));

        assert!(convert_incoming_options_to_sat(incoming).is_err());
        assert!(convert_outgoing_options_to_sat(outgoing).is_err());
    }

    #[tokio::test]
    async fn incoming_msat_amounts_round_up_to_sats() {
        let backend = MockSatPayment::default();
        let converter = MsatSatConverter::new(backend.clone());

        converter
            .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
                Bolt11IncomingPaymentOptions {
                    amount: Amount::new(1_001, CurrencyUnit::Msat),
                    ..Default::default()
                },
            ))
            .await
            .expect("1001 msat quote should be converted");
        converter
            .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
                Bolt11IncomingPaymentOptions {
                    amount: Amount::new(1_000, CurrencyUnit::Msat),
                    ..Default::default()
                },
            ))
            .await
            .expect("1000 msat quote should be converted");

        let amounts = backend
            .incoming_amounts
            .lock()
            .expect("incoming amounts mutex should not be poisoned");
        assert_eq!(amounts[0], Amount::new(2, CurrencyUnit::Sat));
        assert_eq!(amounts[1], Amount::new(1, CurrencyUnit::Sat));
    }

    #[tokio::test]
    async fn incoming_zero_msat_converts_to_zero_sats() {
        let backend = MockSatPayment::default();
        let converter = MsatSatConverter::new(backend.clone());

        converter
            .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
                Bolt11IncomingPaymentOptions {
                    amount: Amount::new(0, CurrencyUnit::Msat),
                    ..Default::default()
                },
            ))
            .await
            .expect("zero msat quote should be converted without forcing a minimum");

        let amounts = backend
            .incoming_amounts
            .lock()
            .expect("incoming amounts mutex should not be poisoned");
        assert_eq!(amounts[0], Amount::new(0, CurrencyUnit::Sat));
    }

    #[tokio::test]
    async fn incoming_sat_status_converts_exactly_to_msats() {
        let backend = MockSatPayment::default();
        backend
            .incoming_status
            .lock()
            .expect("incoming status mutex should not be poisoned")
            .push(WaitPaymentResponse {
                payment_identifier: PaymentIdentifier::CustomId("paid".to_string()),
                payment_amount: Amount::new(1, CurrencyUnit::Sat),
                payment_id: "payment-id".to_string(),
            });
        let converter = MsatSatConverter::new(backend);

        let payments = converter
            .check_incoming_payment_status(&PaymentIdentifier::CustomId("paid".to_string()))
            .await
            .expect("sat status should convert to msat");

        assert_eq!(
            payments[0].payment_amount,
            Amount::new(1_000, CurrencyUnit::Msat)
        );
    }

    #[tokio::test]
    async fn native_msat_route_remains_exact_for_non_divisible_amounts() {
        let backend = native_msat_backend();
        let routes = sat_msat_backends(Arc::new(backend.clone()))
            .await
            .expect("native MSAT backend should be routed");

        routes
            .msat
            .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
                Bolt11IncomingPaymentOptions {
                    amount: Amount::new(1_001, CurrencyUnit::Msat),
                    ..Default::default()
                },
            ))
            .await
            .expect("native incoming request should stay in msat");
        let quote = routes
            .msat
            .get_payment_quote(&CurrencyUnit::Msat, custom_outgoing_options())
            .await
            .expect("native quote should stay in msat");
        let made = routes
            .msat
            .make_payment(&CurrencyUnit::Msat, custom_outgoing_options())
            .await
            .expect("native payment should stay in msat");
        let incoming = routes
            .msat
            .check_incoming_payment_status(&PaymentIdentifier::CustomId("received".to_string()))
            .await
            .expect("native incoming status should stay in msat");
        let checked = routes
            .msat
            .check_outgoing_payment(&PaymentIdentifier::CustomId("paid".to_string()))
            .await
            .expect("native outgoing status should stay in msat");

        assert_eq!(quote.amount, Amount::new(1_501, CurrencyUnit::Msat));
        assert_eq!(quote.fee, Amount::new(1_001, CurrencyUnit::Msat));
        assert_eq!(made.total_spent, Amount::new(1_501, CurrencyUnit::Msat));
        assert_eq!(
            incoming[0].payment_amount,
            Amount::new(1_501, CurrencyUnit::Msat)
        );
        assert_eq!(checked.total_spent, Amount::new(1_501, CurrencyUnit::Msat));
        assert_eq!(
            backend
                .incoming_amounts
                .lock()
                .expect("incoming amounts mutex should not be poisoned")[0],
            Amount::new(1_001, CurrencyUnit::Msat)
        );
    }

    #[tokio::test]
    async fn native_msat_event_route_remains_exact_for_non_divisible_amounts() {
        let routes = sat_msat_backends(Arc::new(native_msat_backend()))
            .await
            .expect("native MSAT backend should be routed");
        let mut events = routes
            .msat
            .wait_payment_event()
            .await
            .expect("native payment event stream should start");

        let Event::PaymentReceived(received) =
            events.next().await.expect("received event should exist")
        else {
            panic!("expected payment received event");
        };
        assert_eq!(
            received.payment_amount,
            Amount::new(1_501, CurrencyUnit::Msat)
        );
        let Event::PaymentSuccessful { details, .. } =
            events.next().await.expect("successful event should exist")
        else {
            panic!("expected payment successful event");
        };
        assert_eq!(details.total_spent, Amount::new(1_501, CurrencyUnit::Msat));
    }

    #[tokio::test]
    async fn native_msat_sat_facade_rounds_all_response_paths_conservatively() {
        let backend = native_msat_backend();
        let routes = sat_msat_backends(Arc::new(backend.clone()))
            .await
            .expect("native MSAT backend should be routed");
        routes
            .sat
            .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
                Bolt11IncomingPaymentOptions {
                    amount: Amount::new(2, CurrencyUnit::Sat),
                    ..Default::default()
                },
            ))
            .await
            .expect("SAT incoming request should use the facade");
        let quote = routes
            .sat
            .get_payment_quote(&CurrencyUnit::Sat, custom_outgoing_options())
            .await
            .expect("SAT quote should use the facade");
        let made = routes
            .sat
            .make_payment(&CurrencyUnit::Sat, custom_outgoing_options())
            .await
            .expect("SAT payment should use the facade");
        let incoming = routes
            .sat
            .check_incoming_payment_status(&PaymentIdentifier::CustomId("received".to_string()))
            .await
            .expect("SAT incoming status should use the facade");
        let checked = routes
            .sat
            .check_outgoing_payment(&PaymentIdentifier::CustomId("paid".to_string()))
            .await
            .expect("SAT outgoing status should use the facade");
        let mut events = routes
            .sat
            .wait_payment_event()
            .await
            .expect("payment event stream should start");

        assert_eq!(quote.amount, Amount::new(2, CurrencyUnit::Sat));
        assert_eq!(quote.fee, Amount::new(2, CurrencyUnit::Sat));
        assert_eq!(made.total_spent, Amount::new(2, CurrencyUnit::Sat));
        assert_eq!(
            incoming[0].payment_amount,
            Amount::new(1, CurrencyUnit::Sat)
        );
        assert_eq!(checked.total_spent, Amount::new(2, CurrencyUnit::Sat));
        assert_eq!(
            backend
                .incoming_amounts
                .lock()
                .expect("incoming amounts mutex should not be poisoned")[0],
            Amount::new(2_000, CurrencyUnit::Msat)
        );
        let Event::PaymentReceived(received) =
            events.next().await.expect("received event should exist")
        else {
            panic!("expected payment received event");
        };
        assert_eq!(received.payment_amount, Amount::new(1, CurrencyUnit::Sat));
        let Event::PaymentSuccessful { details, .. } =
            events.next().await.expect("successful event should exist")
        else {
            panic!("expected payment successful event");
        };
        assert_eq!(details.total_spent, Amount::new(2, CurrencyUnit::Sat));
    }

    #[tokio::test]
    async fn native_sat_factory_keeps_sat_exact_and_converts_msat_options() {
        let backend = native_sat_backend();
        let routes = sat_msat_backends(Arc::new(backend.clone()))
            .await
            .expect("native SAT backend should be routed");

        let native = routes
            .sat
            .get_payment_quote(
                &CurrencyUnit::Sat,
                custom_outgoing_with_amounts(1_001, 1_501, CurrencyUnit::Sat),
            )
            .await
            .expect("native SAT quote");
        routes
            .msat
            .get_payment_quote(
                &CurrencyUnit::Msat,
                custom_outgoing_with_amounts(1_001, 1_501, CurrencyUnit::Msat),
            )
            .await
            .expect("MSAT facade quote");
        routes
            .msat
            .make_payment(
                &CurrencyUnit::Msat,
                custom_outgoing_with_amounts(1_001, 1_501, CurrencyUnit::Msat),
            )
            .await
            .expect("MSAT facade payment");

        assert_eq!(native.amount, Amount::new(2, CurrencyUnit::Sat));
        let quote_options = backend
            .quote_options
            .lock()
            .expect("quote options mutex should not be poisoned");
        assert_custom_amounts(&quote_options[0], 1_001, 1_501, CurrencyUnit::Sat);
        assert_custom_amounts(&quote_options[1], 2, 2, CurrencyUnit::Sat);
        let make_options = backend
            .make_options
            .lock()
            .expect("make options mutex should not be poisoned");
        assert_custom_amounts(&make_options[0], 2, 2, CurrencyUnit::Sat);
    }

    fn assert_custom_amounts(
        options: &OutgoingPaymentOptions,
        amount: u64,
        max_fee_amount: u64,
        unit: CurrencyUnit,
    ) {
        let OutgoingPaymentOptions::Custom(options) = options else {
            panic!("expected custom options");
        };
        assert_eq!(options.amount, Some(Amount::new(amount, unit.clone())));
        assert_eq!(
            options.max_fee_amount,
            Some(Amount::new(max_fee_amount, unit))
        );
    }

    #[test]
    fn native_msat_incoming_credit_rounds_down_to_sats() {
        let payment = WaitPaymentResponse {
            payment_identifier: PaymentIdentifier::CustomId("paid".to_string()),
            payment_amount: Amount::new(1_999, CurrencyUnit::Msat),
            payment_id: "payment-id".to_string(),
        };

        let converted =
            convert_wait_payment_response_to_sat(payment).expect("msat credit should convert");

        assert_eq!(converted.payment_amount, Amount::new(1, CurrencyUnit::Sat));
    }

    #[test]
    fn native_msat_outgoing_cost_rounds_up_to_sats() {
        let response = MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::CustomId("paid".to_string()),
            payment_proof: None,
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(1_001, CurrencyUnit::Msat),
        };

        let converted =
            convert_make_payment_response_to_sat(response).expect("msat cost should convert");

        assert_eq!(converted.total_spent, Amount::new(2, CurrencyUnit::Sat));
    }

    #[tokio::test]
    async fn quote_fee_converts_from_sats_to_msats() {
        let backend = MockSatPayment::default();
        *backend
            .quote
            .lock()
            .expect("quote mutex should not be poisoned") = Some(PaymentQuoteResponse {
            request_lookup_id: Some(PaymentIdentifier::CustomId("melt".to_string())),
            amount: Amount::new(2, CurrencyUnit::Sat),
            fee: Amount::new(1, CurrencyUnit::Sat),
            state: MeltQuoteState::Unpaid,
            extra_json: None,
            estimated_blocks: None,
            fee_options: None,
        });
        let converter = MsatSatConverter::new(backend);

        let quote = converter
            .get_payment_quote(
                &CurrencyUnit::Msat,
                OutgoingPaymentOptions::Custom(Box::new(CustomOutgoingPaymentOptions {
                    method: "test".to_string(),
                    request: "request".to_string(),
                    amount: None,
                    max_fee_amount: None,
                    timeout_secs: None,
                    melt_options: None,
                    extra_json: None,
                    quote_id: QuoteId::new(),
                })),
            )
            .await
            .expect("sat quote should convert to msat");

        assert_eq!(quote.amount, Amount::new(2_000, CurrencyUnit::Msat));
        assert_eq!(quote.fee, Amount::new(1_000, CurrencyUnit::Msat));
    }

    #[test]
    fn payment_successful_event_converts_sat_amount_to_msat() {
        let quote_id = QuoteId::new();
        let event = Event::PaymentSuccessful {
            quote_id: quote_id.clone(),
            details: MakePaymentResponse {
                payment_lookup_id: PaymentIdentifier::CustomId("payment".to_string()),
                payment_proof: Some("proof".to_string()),
                status: MeltQuoteState::Paid,
                total_spent: Amount::new(3, CurrencyUnit::Sat),
            },
        };

        let converted = convert_event_to_msat(event).expect("event should convert");

        match converted {
            Event::PaymentSuccessful {
                quote_id: id,
                details,
            } => {
                assert_eq!(id, quote_id);
                assert_eq!(details.total_spent, Amount::new(3_000, CurrencyUnit::Msat));
            }
            _ => panic!("expected payment successful event"),
        }
    }

    #[test]
    fn payment_failed_event_passes_through_without_amount() {
        let quote_id = QuoteId::new();
        let event = Event::PaymentFailed {
            quote_id: quote_id.clone(),
            reason: "failed".to_string(),
        };

        let converted = convert_event_to_msat(event).expect("event should pass through");

        match converted {
            Event::PaymentFailed {
                quote_id: id,
                reason,
            } => {
                assert_eq!(id, quote_id);
                assert_eq!(reason, "failed");
            }
            _ => panic!("expected payment failed event"),
        }
    }

    #[test]
    fn sats_to_msats_overflow_fails_gracefully() {
        let result = sats_to_msats(Amount::new(u64::MAX / 2, CurrencyUnit::Sat));

        assert!(result.is_err());
    }

    #[test]
    fn ensure_msat_unit_rejects_non_msat_amounts() {
        assert!(ensure_msat_unit(&CurrencyUnit::Sat).is_err());
        assert!(ensure_msat_unit(&CurrencyUnit::Msat).is_ok());
    }

    #[tokio::test]
    async fn make_payment_response_converts_total_spent_to_msat() {
        let backend = MockSatPayment::default();
        *backend
            .make_response
            .lock()
            .expect("make response mutex should not be poisoned") = Some(MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::CustomId("payment".to_string()),
            payment_proof: None,
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(4, CurrencyUnit::Sat),
        });
        let converter = MsatSatConverter::new(backend);

        let response = converter
            .make_payment(&CurrencyUnit::Msat, custom_outgoing_options())
            .await
            .expect("sat response should convert to msat");

        assert_eq!(response.total_spent, Amount::new(4_000, CurrencyUnit::Msat));
    }

    #[tokio::test]
    async fn check_outgoing_payment_response_converts_total_spent_to_msat() {
        let backend = MockSatPayment::default();
        *backend
            .check_response
            .lock()
            .expect("check response mutex should not be poisoned") = Some(MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::CustomId("payment".to_string()),
            payment_proof: None,
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(5, CurrencyUnit::Sat),
        });
        let converter = MsatSatConverter::new(backend);

        let response = converter
            .check_outgoing_payment(&PaymentIdentifier::CustomId("payment".to_string()))
            .await
            .expect("sat response should convert to msat");

        assert_eq!(response.total_spent, Amount::new(5_000, CurrencyUnit::Msat));
    }
}
