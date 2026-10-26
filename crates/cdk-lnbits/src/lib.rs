//! CDK Lightning backend for a hosted LNbits wallet.

#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{
    self, Bolt11Settings, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions,
    MakePaymentResponse, MintPayment, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use futures::Stream;
use tokio_util::sync::CancellationToken;

mod amount;
mod api;
mod config;
mod error;
mod events;
mod incoming;
mod outgoing;
mod recovery;
mod transport;

#[cfg(test)]
mod tests;

pub use config::{ApiKey, ApiOrigin, FeePolicy, LnbitsConfig, OutgoingPayments, TransportLimits};
pub use error::{Error, TransportError};
pub use recovery::{
    NoRecoveryContext, OutgoingExpectation, OutgoingRecoveryContext, RecoveryContextError,
};
use transport::{HttpsTransport, Transport};

/// Adapter settings that remain after the transport takes the keys.
#[derive(Debug, Clone, Copy)]
struct Policy {
    network: bitcoin::Network,
    fee_policy: FeePolicy,
    outgoing: OutgoingPayments,
}

/// LNbits payment backend. Native unit: sat.
#[derive(Clone)]
pub struct LNbits {
    transport: Arc<dyn Transport>,
    recovery: Arc<dyn OutgoingRecoveryContext>,
    policy: Policy,
    cancel: CancellationToken,
    stream_active: Arc<AtomicBool>,
    fee_excess_events: Arc<AtomicU64>,
    now: fn() -> u64,
}

impl std::fmt::Debug for LNbits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LNbits")
            .field("network", &self.policy.network)
            .field("fee_policy", &self.policy.fee_policy)
            .field("outgoing", &self.policy.outgoing)
            .finish_non_exhaustive()
    }
}

impl LNbits {
    /// Create the backend with the HTTPS transport.
    pub fn new(
        config: LnbitsConfig,
        recovery: Arc<dyn OutgoingRecoveryContext>,
    ) -> Result<Self, Error> {
        let transport = HttpsTransport::new(&config)?;
        Ok(Self::from_parts(&config, Arc::new(transport), recovery))
    }

    fn from_parts(
        config: &LnbitsConfig,
        transport: Arc<dyn Transport>,
        recovery: Arc<dyn OutgoingRecoveryContext>,
    ) -> Self {
        Self {
            transport,
            recovery,
            policy: Policy {
                network: config.network,
                fee_policy: config.fee_policy,
                outgoing: config.outgoing,
            },
            cancel: CancellationToken::new(),
            stream_active: Arc::new(AtomicBool::new(false)),
            fee_excess_events: Arc::new(AtomicU64::new(0)),
            now: cdk_common::util::unix_time,
        }
    }

    /// Number of fee excess events since this backend was created.
    ///
    /// An event is counted each time a verified paid result has a fee above
    /// the quoted reserve. A payment that is reported by `make_payment` and
    /// again by `check_outgoing_payment` is counted twice; deduplicate by
    /// payment hash when an exact count is needed.
    pub fn fee_excess_event_count(&self) -> u64 {
        self.fee_excess_events.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl MintPayment for LNbits {
    type Err = payment::Error;

    async fn stop(&self) -> Result<(), Self::Err> {
        self.cancel.cancel();
        Ok(())
    }

    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        Ok(SettingsResponse {
            unit: CurrencyUnit::Sat.to_string(),
            bolt11: Some(Bolt11Settings {
                mpp: false,
                amountless: false,
                invoice_description: true,
            }),
            bolt12: None,
            onchain: None,
            custom: HashMap::new(),
        })
    }

    async fn create_incoming_payment_request(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        Ok(self.create_incoming(options).await?)
    }

    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        Ok(self.quote_outgoing(unit, options).await?)
    }

    async fn make_payment(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        Ok(self.pay_outgoing(unit, options).await?)
    }

    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        Ok(self.open_events().await?)
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.stream_active.load(Ordering::SeqCst)
    }

    fn cancel_payment_event_stream(&self) {
        self.cancel.cancel();
    }

    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        Ok(self.incoming_status(payment_identifier).await?)
    }

    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        Ok(self.check_outgoing(payment_identifier).await?)
    }
}
