//! Adapter tests with controlled transport fixtures. No test uses a network
//! service other than an owned loopback listener.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use cdk_common::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use cdk_common::util::hex;
use cdk_common::Bolt11Invoice;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::config::{
    ApiKey, ApiOrigin, FeePolicy, LnbitsConfig, OutgoingPayments, TransportLimits,
};
use crate::error::TransportError;
use crate::recovery::{OutgoingExpectation, OutgoingRecoveryContext, RecoveryContextError};
use crate::transport::{HintStream, HttpReply, Transport};
use crate::LNbits;

mod conversion;
mod incoming;
mod logging;
mod outgoing;
mod quote;
mod stream;
mod transport;

/// Fixed adapter clock for deterministic expiry checks.
pub(crate) const NOW: u64 = 1_800_000_000;
/// Admin key canary. It must never appear in a log or an error.
pub(crate) const ADMIN_KEY: &str = "adminKEYcanary0000000000000000aa";
/// Invoice key canary. It must never appear in a log or an error.
pub(crate) const INVOICE_KEY: &str = "invoiceKEYcanary00000000000000bb";

fn fixed_now() -> u64 {
    NOW
}

pub(crate) fn config(outgoing: OutgoingPayments) -> LnbitsConfig {
    LnbitsConfig {
        api_origin: ApiOrigin::parse("https://lnbits.example").expect("origin"),
        admin_key: ApiKey::new(ADMIN_KEY.to_string()).expect("admin key"),
        invoice_key: ApiKey::new(INVOICE_KEY.to_string()).expect("invoice key"),
        network: bitcoin::Network::Bitcoin,
        fee_policy: FeePolicy {
            min_fee_reserve_sat: 2,
            fee_reserve_ppm: 5_000,
        },
        outgoing,
        limits: TransportLimits::default(),
    }
}

/// Build an adapter over a fixture transport and a recovery context.
pub(crate) fn adapter(
    transport: Arc<FixtureTransport>,
    recovery: Arc<dyn OutgoingRecoveryContext>,
) -> LNbits {
    adapter_with(
        config(OutgoingPayments::MintPaysFeeAboveReserve),
        transport,
        recovery,
    )
}

pub(crate) fn adapter_with(
    config: LnbitsConfig,
    transport: Arc<FixtureTransport>,
    recovery: Arc<dyn OutgoingRecoveryContext>,
) -> LNbits {
    let mut lnbits = LNbits::from_parts(&config, transport, recovery);
    lnbits.now = fixed_now;
    lnbits
}

/// A signed test invoice and its secrets.
#[derive(Clone)]
pub(crate) struct TestInvoice {
    pub(crate) invoice: Bolt11Invoice,
    pub(crate) hash: [u8; 32],
    pub(crate) preimage: [u8; 32],
}

impl TestInvoice {
    pub(crate) fn bolt11(&self) -> String {
        self.invoice.to_string()
    }

    pub(crate) fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }

    pub(crate) fn preimage_hex(&self) -> String {
        hex::encode(self.preimage)
    }
}

/// Signed invoice with a preimage derived from `seed`.
pub(crate) fn invoice(seed: u8, amount_msat: Option<u64>, currency: Currency) -> TestInvoice {
    invoice_at(seed, amount_msat, currency, NOW, 3_600)
}

pub(crate) fn invoice_at(
    seed: u8,
    amount_msat: Option<u64>,
    currency: Currency,
    timestamp: u64,
    expiry_secs: u64,
) -> TestInvoice {
    let preimage = [seed; 32];
    let hash = sha256::Hash::hash(&preimage);
    let key = SecretKey::from_slice(&[0x42; 32]).expect("secret key");
    let builder = InvoiceBuilder::new(currency)
        .description("fixture".to_string())
        .payment_hash(hash)
        .payment_secret(PaymentSecret([7; 32]))
        .duration_since_epoch(Duration::from_secs(timestamp))
        .expiry_time(Duration::from_secs(expiry_secs))
        .min_final_cltv_expiry_delta(144);
    let invoice = match amount_msat {
        Some(amount) => builder
            .amount_milli_satoshis(amount)
            .build_signed(|message| Secp256k1::new().sign_ecdsa_recoverable(message, &key)),
        None => {
            builder.build_signed(|message| Secp256k1::new().sign_ecdsa_recoverable(message, &key))
        }
    }
    .expect("signed invoice");
    TestInvoice {
        invoice,
        hash: hash.to_byte_array(),
        preimage,
    }
}

/// Load a recorded profile fixture.
pub(crate) fn fixture(name: &str) -> Value {
    let text = match name {
        "create-invoice-201" => {
            include_str!("../../fixtures/lnbits-v1.6.2/create-invoice-201.json")
        }
        "fee-reserve-200" => include_str!("../../fixtures/lnbits-v1.6.2/fee-reserve-200.json"),
        "pay-invoice-201-pending" => {
            include_str!("../../fixtures/lnbits-v1.6.2/pay-invoice-201-pending.json")
        }
        "pay-invoice-201-success" => {
            include_str!("../../fixtures/lnbits-v1.6.2/pay-invoice-201-success.json")
        }
        "payment-error-520" => include_str!("../../fixtures/lnbits-v1.6.2/payment-error-520.json"),
        "status-check-error-details" => {
            include_str!("../../fixtures/lnbits-v1.6.2/status-check-error-details.json")
        }
        "status-failed-details" => {
            include_str!("../../fixtures/lnbits-v1.6.2/status-failed-details.json")
        }
        "status-not-found-404" => {
            include_str!("../../fixtures/lnbits-v1.6.2/status-not-found-404.json")
        }
        "status-pending-details" => {
            include_str!("../../fixtures/lnbits-v1.6.2/status-pending-details.json")
        }
        "status-success-details" => {
            include_str!("../../fixtures/lnbits-v1.6.2/status-success-details.json")
        }
        "status-success-public" => {
            include_str!("../../fixtures/lnbits-v1.6.2/status-success-public.json")
        }
        "ws-wallet-notification" => {
            include_str!("../../fixtures/lnbits-v1.6.2/ws-wallet-notification.json")
        }
        other => panic!("unknown fixture {other}"),
    };
    serde_json::from_str(text).expect("fixture JSON")
}

/// Set a JSON pointer value in a fixture.
pub(crate) fn set(value: &mut Value, pointer: &str, new_value: Value) {
    *value.pointer_mut(pointer).expect("fixture field") = new_value;
}

/// Bind the payment fields of a `Payment` model at `base` to an invoice.
pub(crate) fn bind_payment(value: &mut Value, base: &str, invoice: &TestInvoice) {
    set(
        value,
        &format!("{base}/payment_hash"),
        Value::from(invoice.hash_hex()),
    );
    set(
        value,
        &format!("{base}/checking_id"),
        Value::from(invoice.hash_hex()),
    );
    set(
        value,
        &format!("{base}/bolt11"),
        Value::from(invoice.bolt11()),
    );
    set(
        value,
        &format!("{base}/payment_request"),
        Value::from(invoice.bolt11()),
    );
}

/// Outgoing payment record for `invoice` from a fixture.
pub(crate) fn outgoing_record(name: &str, invoice: &TestInvoice, fee_msat: i64) -> Value {
    let mut value = fixture(name);
    let base = match value.get("details") {
        Some(_) => "/details",
        None => "",
    };
    bind_payment(&mut value, base, invoice);
    let amount = invoice.invoice.amount_milli_satoshis().expect("amount") as i64;
    set(&mut value, &format!("{base}/amount"), Value::from(-amount));
    set(&mut value, &format!("{base}/fee"), Value::from(-fee_msat));
    if value
        .pointer(&format!("{base}/preimage"))
        .is_some_and(|p| !p.is_null())
    {
        set(
            &mut value,
            &format!("{base}/preimage"),
            Value::from(invoice.preimage_hex()),
        );
    }
    if value.get("preimage").is_some_and(|p| !p.is_null()) {
        set(&mut value, "/preimage", Value::from(invoice.preimage_hex()));
    }
    value
}

/// Incoming payment record for `invoice` from a fixture.
pub(crate) fn incoming_record(name: &str, invoice: &TestInvoice) -> Value {
    let mut value = outgoing_record(name, invoice, 0);
    let base = match value.get("details") {
        Some(_) => "/details",
        None => "",
    };
    let amount = invoice.invoice.amount_milli_satoshis().expect("amount") as i64;
    set(&mut value, &format!("{base}/amount"), Value::from(amount));
    value
}

pub(crate) fn reply(status: u16, value: &Value) -> Step {
    Step::Reply(HttpReply {
        status,
        body: serde_json::to_vec(value).expect("JSON"),
    })
}

pub(crate) fn raw_reply(status: u16, body: &[u8]) -> Step {
    Step::Reply(HttpReply {
        status,
        body: body.to_vec(),
    })
}

/// One scripted transport result.
pub(crate) enum Step {
    Reply(HttpReply),
    Fail(TransportError),
    /// Signal `started`, then wait for the test to release a result.
    Gate {
        started: oneshot::Sender<()>,
        release: oneshot::Receiver<Result<HttpReply, TransportError>>,
    },
}

/// A request that the fixture transport received.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Call {
    GetPayment(String),
    FeeReserve(String),
    CreateInvoice(Value),
    PayInvoice(Value),
    Connect,
}

type HintReceiver = mpsc::UnboundedReceiver<Result<String, TransportError>>;

/// Scripted transport. An unscripted request fails with a protocol error.
#[derive(Default)]
pub(crate) struct FixtureTransport {
    get_payment: Mutex<VecDeque<Step>>,
    fee_reserve: Mutex<VecDeque<Step>>,
    create_invoice: Mutex<VecDeque<Step>>,
    pay_invoice: Mutex<VecDeque<Step>>,
    connections: Mutex<VecDeque<Result<HintReceiver, TransportError>>>,
    calls: Mutex<Vec<Call>>,
}

impl FixtureTransport {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn on_get_payment(&self, step: Step) {
        self.get_payment.lock().expect("lock").push_back(step);
    }

    pub(crate) fn on_fee_reserve(&self, step: Step) {
        self.fee_reserve.lock().expect("lock").push_back(step);
    }

    pub(crate) fn on_create_invoice(&self, step: Step) {
        self.create_invoice.lock().expect("lock").push_back(step);
    }

    pub(crate) fn on_pay_invoice(&self, step: Step) {
        self.pay_invoice.lock().expect("lock").push_back(step);
    }

    /// Script one websocket connection and return its message sender.
    pub(crate) fn on_connect(&self) -> mpsc::UnboundedSender<Result<String, TransportError>> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.connections
            .lock()
            .expect("lock")
            .push_back(Ok(receiver));
        sender
    }

    pub(crate) fn on_connect_failure(&self, error: TransportError) {
        self.connections.lock().expect("lock").push_back(Err(error));
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("lock").clone()
    }

    pub(crate) fn count(&self, predicate: impl Fn(&Call) -> bool) -> usize {
        self.calls().iter().filter(|call| predicate(call)).count()
    }

    fn record(&self, call: Call) {
        self.calls.lock().expect("lock").push(call);
    }

    async fn run(queue: &Mutex<VecDeque<Step>>) -> Result<HttpReply, TransportError> {
        let step = queue.lock().expect("lock").pop_front();
        match step {
            Some(Step::Reply(reply)) => Ok(reply),
            Some(Step::Fail(error)) => Err(error),
            Some(Step::Gate { started, release }) => {
                let _ = started.send(());
                release.await.unwrap_or(Err(TransportError::Protocol))
            }
            None => Err(TransportError::Protocol),
        }
    }
}

#[async_trait]
impl Transport for FixtureTransport {
    async fn get_payment(&self, payment_hash_hex: &str) -> Result<HttpReply, TransportError> {
        self.record(Call::GetPayment(payment_hash_hex.to_string()));
        Self::run(&self.get_payment).await
    }

    async fn get_fee_reserve(&self, bolt11: &str) -> Result<HttpReply, TransportError> {
        self.record(Call::FeeReserve(bolt11.to_string()));
        Self::run(&self.fee_reserve).await
    }

    async fn create_invoice(&self, body: Vec<u8>) -> Result<HttpReply, TransportError> {
        self.record(Call::CreateInvoice(
            serde_json::from_slice(&body).expect("request JSON"),
        ));
        Self::run(&self.create_invoice).await
    }

    async fn pay_invoice(&self, body: Vec<u8>) -> Result<HttpReply, TransportError> {
        self.record(Call::PayInvoice(
            serde_json::from_slice(&body).expect("request JSON"),
        ));
        Self::run(&self.pay_invoice).await
    }

    async fn connect_hints(&self) -> Result<HintStream, TransportError> {
        self.record(Call::Connect);
        let next = self.connections.lock().expect("lock").pop_front();
        let receiver = next.unwrap_or(Err(TransportError::Connect))?;
        Ok(Box::pin(futures::stream::unfold(
            receiver,
            |mut receiver| async move {
                let item = receiver.recv().await?;
                Some((item, receiver))
            },
        )))
    }
}

/// Recovery context with a fixed answer.
pub(crate) struct StaticRecovery(pub(crate) Result<Vec<OutgoingExpectation>, RecoveryContextError>);

#[async_trait]
impl OutgoingRecoveryContext for StaticRecovery {
    async fn expectations(
        &self,
        _payment_hash: &[u8; 32],
    ) -> Result<Vec<OutgoingExpectation>, RecoveryContextError> {
        self.0.clone()
    }
}

pub(crate) fn recovery_for(invoice: &TestInvoice, fee_reserve_msat: u64) -> Arc<StaticRecovery> {
    Arc::new(StaticRecovery(Ok(vec![OutgoingExpectation {
        bolt11: invoice.invoice.clone(),
        fee_reserve_msat,
    }])))
}

pub(crate) fn no_recovery() -> Arc<crate::recovery::NoRecoveryContext> {
    Arc::new(crate::recovery::NoRecoveryContext)
}

/// Bounded wait that fails the test instead of hanging.
pub(crate) async fn within<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("operation did not complete within the test bound")
}
