//! The call deadline of the client, against a processor that does not answer,
//! and the event stream of the server, against a client that goes away.
//!
//! The client and the server are the real ones, on a loopback socket. The real
//! socket excludes a paused clock, so these tests use a short deadline. A call
//! that must succeed never depends on it: a processor without a closed gate
//! answers at once, and the tests of the mint use a longer deadline.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cdk::amount::SplitTarget;
use cdk::dhke::construct_proofs;
use cdk::mint::{Mint, MintBuilder, MintInput, MintMeltLimits};
use cdk::nuts::{
    CurrencyUnit, MeltQuoteState, MeltRequest, MintQuoteState, PaymentMethod, PreMintSecrets,
    Proofs, ProofsMethods, State,
};
use cdk::subscription::{Params, SubId};
use cdk::types::QuoteTTL;
use cdk_common::grpc::{create_version_check_interceptor, VERSION_HEADER};
use cdk_common::melt::MeltQuoteRequest;
use cdk_common::mint::MeltQuote;
use cdk_common::nut00::KnownMethod;
use cdk_common::nuts::nut17::{Kind, NotificationPayload};
use cdk_common::payment::{
    self, Bolt11IncomingPaymentOptions, Bolt11OutgoingPaymentOptions, Bolt11Settings,
    CreateIncomingPaymentResponse, Event, IncomingPaymentOptions, MakePaymentResponse, MintPayment,
    OutgoingPaymentOptions, PaymentIdentifier, PaymentQuoteResponse, SettingsResponse,
    WaitPaymentResponse,
};
use cdk_common::{
    Amount, Bolt11Invoice, MeltQuoteBolt11Request, MintQuoteBolt11Request, MintQuoteBolt11Response,
    MintRequest, QuoteId,
};
use cdk_fake_wallet::create_fake_invoice;
use futures::{Stream, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use super::client::{PaymentProcessorClient, CALL_DEADLINE};
use super::server::PaymentProcessorServer;
use crate::proto;
use crate::proto::cdk_payment_processor_server::CdkPaymentProcessorServer;

/// A deadline for calls that never get an answer.
const SHORT_DEADLINE: Duration = Duration::from_millis(100);
/// A deadline for a mint that also makes calls that must succeed.
const MINT_DEADLINE: Duration = Duration::from_secs(2);
/// Detects a hang.
const TEST_LIMIT: Duration = Duration::from_secs(30);

const MELT_SATS: u64 = 9_000;

/// Fails the test instead of hanging it.
async fn within<F>(what: &str, future: F) -> F::Output
where
    F: std::future::IntoFuture,
{
    match tokio::time::timeout(TEST_LIMIT, future).await {
        Ok(output) => output,
        Err(_) => panic!("{what} hangs"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Call {
    Settings,
    CreatePayment,
    PaymentQuote,
    Send,
    CheckIncoming,
    CheckOutgoing,
    EventStream,
}

/// Holds the calls of one kind while it is closed.
#[derive(Debug)]
struct Gate {
    open: watch::Sender<bool>,
    entered: watch::Sender<usize>,
    left: watch::Sender<usize>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            open: watch::Sender::new(true),
            entered: watch::Sender::new(0),
            left: watch::Sender::new(0),
        }
    }
}

/// Counts a call that ended, also when the server dropped it.
struct Left<'a>(&'a Gate);

impl Drop for Left<'_> {
    fn drop(&mut self) {
        self.0.left.send_modify(|count| *count += 1);
    }
}

impl Gate {
    async fn pass(&self) -> Left<'_> {
        let left = Left(self);
        self.entered.send_modify(|count| *count += 1);
        self.open
            .subscribe()
            .wait_for(|open| *open)
            .await
            .expect("gate lives as long as the processor");
        left
    }
}

/// A processor whose calls can be held, with scripted payment results.
#[derive(Debug, Default)]
struct Processor {
    gates: HashMap<Call, Gate>,
    /// The result of a send. Without one, the send answers an error.
    send_status: Mutex<Option<MeltQuoteState>>,
    /// The status that a check reports. A check takes it when the call arrives.
    outgoing_status: Mutex<Option<MeltQuoteState>>,
    /// The payments that a status check reports: each new invoice is paid.
    paid_invoices: Mutex<HashMap<PaymentIdentifier, WaitPaymentResponse>>,
    /// Every open event stream takes its events from this one queue.
    events: Arc<tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<Event>>>>,
    open_streams: Arc<watch::Sender<usize>>,
}

/// Counts an open event stream of the backend.
struct OpenStream(Arc<watch::Sender<usize>>);

impl OpenStream {
    fn new(count: &Arc<watch::Sender<usize>>) -> Self {
        count.send_modify(|count| *count += 1);
        Self(Arc::clone(count))
    }
}

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count -= 1);
    }
}

impl Processor {
    fn new() -> (Arc<Self>, mpsc::UnboundedSender<Event>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let gates = [
            Call::Settings,
            Call::CreatePayment,
            Call::PaymentQuote,
            Call::Send,
            Call::CheckIncoming,
            Call::CheckOutgoing,
            Call::EventStream,
        ]
        .into_iter()
        .map(|call| (call, Gate::default()))
        .collect();
        (
            Arc::new(Self {
                gates,
                events: Arc::new(tokio::sync::Mutex::new(Some(receiver))),
                ..Default::default()
            }),
            sender,
        )
    }

    fn gate(&self, call: Call) -> &Gate {
        &self.gates[&call]
    }

    fn hang(&self, call: Call) {
        self.gate(call).open.send_replace(false);
    }

    fn resume(&self, call: Call) {
        self.gate(call).open.send_replace(true);
    }

    /// The number of calls of this kind that arrived.
    fn arrived(&self, call: Call) -> usize {
        *self.gate(call).entered.borrow()
    }

    async fn wait_arrived(&self, call: Call, count: usize) {
        within("the arrival of a call", async {
            self.gate(call)
                .entered
                .subscribe()
                .wait_for(|entered| *entered >= count)
                .await
                .expect("gate lives");
        })
        .await;
    }

    /// Waits until no call of this kind is in progress.
    async fn wait_idle(&self, call: Call) {
        let gate = self.gate(call);
        let entered = *gate.entered.borrow();
        within("the end of the held calls", async {
            gate.left
                .subscribe()
                .wait_for(|left| *left >= entered)
                .await
                .expect("gate lives");
        })
        .await;
    }

    async fn wait_open_streams(&self, count: usize) {
        within(&format!("a wait for {count} open event streams"), async {
            self.open_streams
                .subscribe()
                .wait_for(|open| *open == count)
                .await
                .expect("the processor lives");
        })
        .await;
    }

    fn set_send(&self, status: Option<MeltQuoteState>) {
        *self.send_status.lock().expect("lock") = status;
    }

    fn set_outgoing(&self, status: MeltQuoteState) {
        *self.outgoing_status.lock().expect("lock") = Some(status);
    }

    fn payment(lookup_id: PaymentIdentifier, status: MeltQuoteState) -> MakePaymentResponse {
        let spent = match status {
            MeltQuoteState::Paid => MELT_SATS,
            _ => 0,
        };
        MakePaymentResponse {
            payment_lookup_id: lookup_id,
            payment_proof: None,
            status,
            total_spent: Amount::new(spent, CurrencyUnit::Sat),
        }
    }
}

fn lookup_id(invoice: &Bolt11Invoice) -> PaymentIdentifier {
    PaymentIdentifier::PaymentHash(*invoice.payment_hash().as_ref())
}

#[async_trait]
impl MintPayment for Processor {
    type Err = payment::Error;

    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        let _left = self.gate(Call::Settings).pass().await;
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
        let _left = self.gate(Call::CreatePayment).pass().await;
        let IncomingPaymentOptions::Bolt11(options) = options else {
            return Err(payment::Error::UnsupportedPaymentOption);
        };
        let invoice = create_fake_invoice(options.amount.value() * 1_000, String::new());
        let payment_identifier = lookup_id(&invoice);
        self.paid_invoices.lock().expect("lock").insert(
            payment_identifier.clone(),
            WaitPaymentResponse {
                payment_identifier: payment_identifier.clone(),
                payment_amount: options.amount,
                payment_id: invoice.payment_hash().to_string(),
            },
        );
        Ok(CreateIncomingPaymentResponse {
            request_lookup_id: payment_identifier,
            request: invoice.to_string(),
            expiry: options.unix_expiry,
            extra_json: None,
        })
    }

    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        let _left = self.gate(Call::PaymentQuote).pass().await;
        let OutgoingPaymentOptions::Bolt11(options) = options else {
            return Err(payment::Error::UnsupportedPaymentOption);
        };
        Ok(PaymentQuoteResponse {
            request_lookup_id: Some(lookup_id(&options.bolt11)),
            amount: Amount::new(
                options.bolt11.amount_milli_satoshis().expect("amount") / 1_000,
                unit.clone(),
            ),
            fee: Amount::new(0, unit.clone()),
            state: MeltQuoteState::Unpaid,
            extra_json: None,
            estimated_blocks: None,
            fee_options: None,
        })
    }

    async fn make_payment(
        &self,
        _unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        let _left = self.gate(Call::Send).pass().await;
        let OutgoingPaymentOptions::Bolt11(options) = options else {
            return Err(payment::Error::UnsupportedPaymentOption);
        };
        let status = *self.send_status.lock().expect("lock");
        match status {
            Some(status) => Ok(Self::payment(lookup_id(&options.bolt11), status)),
            None => Err(payment::Error::UnknownPaymentState),
        }
    }

    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let state = (
            Arc::clone(&self.events),
            OpenStream::new(&self.open_streams),
        );
        Ok(Box::pin(futures::stream::unfold(
            state,
            |state| async move {
                let event = state.0.lock().await.as_mut()?.recv().await?;
                Some((event, state))
            },
        )))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        false
    }

    fn cancel_payment_event_stream(&self) {}

    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        let _left = self.gate(Call::CheckIncoming).pass().await;
        Ok(self
            .paid_invoices
            .lock()
            .expect("lock")
            .get(payment_identifier)
            .cloned()
            .into_iter()
            .collect())
    }

    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        let status = *self.outgoing_status.lock().expect("lock");
        let _left = self.gate(Call::CheckOutgoing).pass().await;
        match status {
            Some(status) => Ok(Self::payment(payment_identifier.clone(), status)),
            None => Err(payment::Error::UnknownPaymentState),
        }
    }
}

/// The server opens the stream of the backend in its own task and answers at
/// once. This wrapper holds the answer, as a frozen processor does.
#[derive(Clone)]
struct HeldEventStream {
    inner: PaymentProcessorServer,
    processor: Arc<Processor>,
}

#[tonic::async_trait]
impl proto::cdk_payment_processor_server::CdkPaymentProcessor for HeldEventStream {
    async fn get_settings(
        &self,
        request: Request<proto::EmptyRequest>,
    ) -> Result<Response<proto::SettingsResponse>, Status> {
        self.inner.get_settings(request).await
    }

    async fn create_payment(
        &self,
        request: Request<proto::CreatePaymentRequest>,
    ) -> Result<Response<proto::CreatePaymentResponse>, Status> {
        self.inner.create_payment(request).await
    }

    async fn get_payment_quote(
        &self,
        request: Request<proto::PaymentQuoteRequest>,
    ) -> Result<Response<proto::PaymentQuoteResponse>, Status> {
        self.inner.get_payment_quote(request).await
    }

    async fn make_payment(
        &self,
        request: Request<proto::MakePaymentRequest>,
    ) -> Result<Response<proto::MakePaymentResponse>, Status> {
        self.inner.make_payment(request).await
    }

    async fn check_incoming_payment(
        &self,
        request: Request<proto::CheckIncomingPaymentRequest>,
    ) -> Result<Response<proto::CheckIncomingPaymentResponse>, Status> {
        self.inner.check_incoming_payment(request).await
    }

    async fn check_outgoing_payment(
        &self,
        request: Request<proto::CheckOutgoingPaymentRequest>,
    ) -> Result<Response<proto::MakePaymentResponse>, Status> {
        self.inner.check_outgoing_payment(request).await
    }

    type WaitPaymentEventStream =
        <PaymentProcessorServer as proto::cdk_payment_processor_server::CdkPaymentProcessor>::WaitPaymentEventStream;

    async fn wait_payment_event(
        &self,
        request: Request<proto::EmptyRequest>,
    ) -> Result<Response<Self::WaitPaymentEventStream>, Status> {
        let _left = self.processor.gate(Call::EventStream).pass().await;
        self.inner.wait_payment_event(request).await
    }
}

/// A processor behind a real server.
struct TestServer {
    processor: Arc<Processor>,
    events: mpsc::UnboundedSender<Event>,
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    fn start() -> Self {
        let (processor, events) = Processor::new();
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().expect("address"))
            .expect("bind a loopback port");
        let port = incoming.local_addr().expect("local address").port();
        let server = HeldEventStream {
            inner: PaymentProcessorServer::new(processor.clone(), "127.0.0.1", port)
                .expect("server"),
            processor: processor.clone(),
        };
        let service = CdkPaymentProcessorServer::with_interceptor(
            server,
            create_version_check_interceptor(
                VERSION_HEADER,
                cdk_common::PAYMENT_PROCESSOR_PROTOCOL_VERSION,
            ),
        );
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
                .expect("serve");
        });
        Self {
            processor,
            events,
            port,
            task,
        }
    }

    /// A client with the deadline of a deployed mint.
    async fn client(&self) -> PaymentProcessorClient {
        PaymentProcessorClient::new("127.0.0.1", self.port, None)
            .await
            .expect("connect")
    }

    async fn client_with_deadline(&self, deadline: Duration) -> PaymentProcessorClient {
        let mut client = self.client().await;
        client.call_deadline = deadline;
        client
    }

    async fn mint(&self) -> Mint {
        let db = Arc::new(cdk_sqlite::mint::memory::empty().await.expect("database"));
        let mut builder = MintBuilder::new(db.clone());
        builder
            .add_payment_processor(
                CurrencyUnit::Sat,
                PaymentMethod::Known(KnownMethod::Bolt11),
                MintMeltLimits::new(1, 100_000),
                Arc::new(self.client_with_deadline(MINT_DEADLINE).await),
            )
            .await
            .expect("add the processor");
        let mint = builder
            .with_name("test mint".to_string())
            .with_urls(vec!["https://test-mint".to_string()])
            .build_with_seed(db, &[7; 64])
            .await
            .expect("build the mint");
        mint.set_quote_ttl(QuoteTTL::new(10_000, 10_000))
            .await
            .expect("set the quote TTL");
        within("the mint start", mint.start())
            .await
            .expect("start the mint");
        mint
    }
}

fn incoming_options() -> IncomingPaymentOptions {
    IncomingPaymentOptions::Bolt11(Bolt11IncomingPaymentOptions {
        description: None,
        amount: Amount::new(10, CurrencyUnit::Sat),
        unix_expiry: None,
    })
}

fn outgoing_options(invoice: &Bolt11Invoice) -> OutgoingPaymentOptions {
    OutgoingPaymentOptions::Bolt11(Box::new(Bolt11OutgoingPaymentOptions {
        bolt11: invoice.clone(),
        max_fee_amount: None,
        timeout_secs: None,
        melt_options: None,
        quote_id: QuoteId::new(),
    }))
}

fn assert_deadline<T>(call: Call, result: Result<T, payment::Error>) {
    match result {
        Err(payment::Error::Custom(message)) => assert!(
            message.contains("deadline"),
            "{call:?}: the error must name the deadline, got: {message}"
        ),
        Err(other) => panic!("{call:?}: unexpected error {other}"),
        Ok(_) => panic!("{call:?}: a hung call must not succeed"),
    }
}

#[tokio::test]
async fn a_client_has_the_default_deadline() {
    let server = TestServer::start();
    assert_eq!(server.client().await.call_deadline, CALL_DEADLINE);
}

#[tokio::test]
async fn every_call_except_the_send_ends_at_the_deadline() {
    let server = TestServer::start();
    let client = server.client_with_deadline(SHORT_DEADLINE).await;
    let invoice = create_fake_invoice(10_000, String::new());
    let id = lookup_id(&invoice);

    for call in [
        Call::Settings,
        Call::CreatePayment,
        Call::PaymentQuote,
        Call::CheckIncoming,
        Call::CheckOutgoing,
        Call::EventStream,
    ] {
        server.processor.hang(call);
        let what = format!("{call:?}");
        match call {
            Call::Settings => {
                assert_deadline(call, within(&what, client.get_settings()).await);
            }
            Call::CreatePayment => assert_deadline(
                call,
                within(
                    &what,
                    client.create_incoming_payment_request(incoming_options()),
                )
                .await,
            ),
            Call::PaymentQuote => assert_deadline(
                call,
                within(
                    &what,
                    client.get_payment_quote(&CurrencyUnit::Sat, outgoing_options(&invoice)),
                )
                .await,
            ),
            Call::CheckIncoming => assert_deadline(
                call,
                within(&what, client.check_incoming_payment_status(&id)).await,
            ),
            Call::CheckOutgoing => {
                assert_deadline(
                    call,
                    within(&what, client.check_outgoing_payment(&id)).await,
                );
            }
            Call::EventStream => {
                assert_deadline(call, within(&what, client.wait_payment_event()).await);
                assert!(!client.is_payment_event_stream_active());
            }
            Call::Send => unreachable!("the send has no deadline"),
        }
    }
}

#[tokio::test]
async fn the_send_has_no_deadline() {
    let server = TestServer::start();
    let client = server.client_with_deadline(SHORT_DEADLINE).await;
    let invoice = create_fake_invoice(10_000, String::new());
    server.processor.set_send(Some(MeltQuoteState::Paid));
    server.processor.hang(Call::Send);
    server.processor.hang(Call::Settings);

    let send = tokio::spawn({
        let client = client.clone();
        let options = outgoing_options(&invoice);
        async move { client.make_payment(&CurrencyUnit::Sat, options).await }
    });
    server.processor.wait_arrived(Call::Send, 1).await;

    // Two other calls pass their deadline while the send is in progress. They
    // share its connection, and their end does not cancel it.
    for _ in 0..2 {
        assert_deadline(
            Call::Settings,
            within("a hung call", client.get_settings()).await,
        );
    }
    assert!(!send.is_finished(), "the send must not end");

    server.processor.resume(Call::Send);
    let response = within("the send", send)
        .await
        .expect("send task")
        .expect("the send succeeds");
    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(server.processor.arrived(Call::Send), 1);
}

/// A loopback proxy that holds the bytes of each direction while it is frozen.
/// To the client, the processor is then a stopped process. To the server, the
/// held frames arrive together at the thaw.
struct FreezableProxy {
    port: u16,
    frozen: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FreezableProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FreezableProxy {
    async fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let frozen = watch::Sender::new(false);
        let state = frozen.subscribe();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((client, _)) = listener.accept().await {
                let server = TcpStream::connect(("127.0.0.1", upstream))
                    .await
                    .expect("connect to the server");
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                connections.spawn(Self::pump(client_read, server_write, state.clone()));
                connections.spawn(Self::pump(server_read, client_write, state.clone()));
            }
        });
        Self { port, frozen, task }
    }

    /// Reads at all times, so that a peer never blocks. Writes when not frozen.
    async fn pump(
        mut from: OwnedReadHalf,
        mut to: OwnedWriteHalf,
        mut frozen: watch::Receiver<bool>,
    ) {
        let mut held = Vec::new();
        let mut ended = false;
        while !ended || !held.is_empty() {
            tokio::select! {
                read = from.read_buf(&mut held), if !ended => {
                    ended = !matches!(read, Ok(count) if count > 0);
                }
                thawed = async { frozen.wait_for(|frozen| !*frozen).await.is_ok() },
                    if !held.is_empty() =>
                {
                    if !thawed {
                        return;
                    }
                    if to.write_all(&held).await.is_err() {
                        return;
                    }
                    held.clear();
                }
            }
        }
        // The peer is gone. The end of the connection passes on only after it.
        let _ = to.shutdown().await;
    }
}

/// A call past its deadline resets its stream. A server that thaws receives
/// these resets together with their requests. The HTTP/2 library of the server
/// then closes the connection after 20 of them. A send in progress must not
/// end with that connection.
#[tokio::test]
async fn many_calls_past_their_deadline_do_not_end_a_send() {
    let server = TestServer::start();
    let proxy = FreezableProxy::start(server.port).await;
    let mut client = PaymentProcessorClient::new("127.0.0.1", proxy.port, None)
        .await
        .expect("connect");
    let invoice = create_fake_invoice(10_000, String::new());
    server.processor.set_send(Some(MeltQuoteState::Paid));
    server.processor.hang(Call::Send);
    let send = tokio::spawn({
        let client = client.clone();
        let options = outgoing_options(&invoice);
        async move { client.make_payment(&CurrencyUnit::Sat, options).await }
    });
    server.processor.wait_arrived(Call::Send, 1).await;

    proxy.frozen.send_replace(true);
    client.call_deadline = Duration::from_millis(20);
    for _ in 0..40 {
        assert_deadline(
            Call::Settings,
            within("a frozen call", client.get_settings()).await,
        );
    }
    proxy.frozen.send_replace(false);

    // A success proves that the server handled the held frames. A call can end
    // with the closed connection. The next call gets a new one.
    client.call_deadline = CALL_DEADLINE;
    within("a call after the thaw", async {
        while client.get_settings().await.is_err() {}
    })
    .await;
    assert!(!send.is_finished(), "the send must not end");

    server.processor.resume(Call::Send);
    let response = within("the send", send)
        .await
        .expect("send task")
        .expect("the send succeeds");
    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(server.processor.arrived(Call::Send), 1);
}

#[tokio::test]
async fn an_open_event_stream_outlives_the_deadline() {
    let server = TestServer::start();
    let mut client = server.client().await;
    let mut stream = within("the event stream", client.wait_payment_event())
        .await
        .expect("open the stream");

    // More than one deadline passes while the stream is open and idle.
    client.call_deadline = SHORT_DEADLINE;
    server.processor.hang(Call::Settings);
    for _ in 0..2 {
        assert_deadline(
            Call::Settings,
            within("a hung call", client.get_settings()).await,
        );
    }

    let invoice = create_fake_invoice(10_000, String::new());
    server
        .events
        .send(Event::PaymentReceived(WaitPaymentResponse {
            payment_identifier: lookup_id(&invoice),
            payment_amount: Amount::new(10, CurrencyUnit::Sat),
            payment_id: "payment".to_string(),
        }))
        .expect("the processor lives");
    let event = within("the event", stream.next())
        .await
        .expect("the stream is open");
    assert!(matches!(event, Event::PaymentReceived(_)));
    assert!(client.is_payment_event_stream_active());
}

/// A client that drops its stream ends the server task of that stream. A task
/// that stays takes events from the backend and discards them.
#[tokio::test]
async fn a_dropped_event_stream_takes_no_event_of_the_next_stream() {
    let server = TestServer::start();
    let client = server.client().await;
    for _ in 0..3 {
        let stream = within("the event stream", client.wait_payment_event())
            .await
            .expect("open the stream");
        server.processor.wait_open_streams(1).await;
        drop(stream);
        server.processor.wait_open_streams(0).await;
    }

    let mut live = within("the event stream", client.wait_payment_event())
        .await
        .expect("open the stream");
    let sent: Vec<_> = (0..12).map(|number| format!("payment-{number}")).collect();
    for payment_id in &sent {
        server
            .events
            .send(Event::PaymentReceived(WaitPaymentResponse {
                payment_identifier: PaymentIdentifier::CustomId(payment_id.clone()),
                payment_amount: Amount::new(1, CurrencyUnit::Sat),
                payment_id: payment_id.clone(),
            }))
            .expect("the processor lives");
    }
    let mut received = Vec::new();
    while received.len() < sent.len() {
        match within("the next event", live.next()).await {
            Some(Event::PaymentReceived(payment)) => received.push(payment.payment_id),
            _ => panic!("unexpected event after {received:?}"),
        }
    }
    assert_eq!(received, sent, "every event arrives exactly once, in order");
    assert_eq!(*server.processor.open_streams.borrow(), 1);
}

/// The answer of a call that passed its deadline is never the answer of a later
/// call.
#[tokio::test]
async fn a_late_answer_does_not_reach_a_later_call() {
    let server = TestServer::start();
    let mut client = server.client_with_deadline(SHORT_DEADLINE).await;
    let id = lookup_id(&create_fake_invoice(10_000, String::new()));

    server.processor.set_outgoing(MeltQuoteState::Failed);
    server.processor.hang(Call::CheckOutgoing);
    assert_deadline(
        Call::CheckOutgoing,
        within("a hung check", client.check_outgoing_payment(&id)).await,
    );

    server.processor.set_outgoing(MeltQuoteState::Paid);
    server.processor.resume(Call::CheckOutgoing);
    server.processor.wait_idle(Call::CheckOutgoing).await;
    // The same connection, with a deadline that a prompt answer cannot pass.
    client.call_deadline = CALL_DEADLINE;
    let response = within("a later check", client.check_outgoing_payment(&id))
        .await
        .expect("the processor answers");
    assert_eq!(response.status, MeltQuoteState::Paid);
}

fn mint_quote_request(sats: u64) -> MintQuoteBolt11Request {
    MintQuoteBolt11Request {
        amount: Amount::from(sats),
        unit: CurrencyUnit::Sat,
        description: None,
        pubkey: None,
    }
}

async fn mint_quote(mint: &Mint, sats: u64) -> MintQuoteBolt11Response<QuoteId> {
    within(
        "a mint quote",
        mint.get_mint_quote(mint_quote_request(sats).into()),
    )
    .await
    .expect("mint quote")
    .try_into()
    .expect("BOLT11 mint quote")
}

fn melt_quote_request(invoice: Bolt11Invoice) -> MeltQuoteRequest {
    MeltQuoteRequest::Bolt11(MeltQuoteBolt11Request {
        request: invoice,
        unit: CurrencyUnit::Sat,
        options: None,
    })
}

async fn fund(mint: &Mint, sats: u64) -> Proofs {
    let quote = mint_quote(mint, sats).await;
    within(
        "the status of a paid mint quote",
        mint.check_mint_quotes(std::slice::from_ref(&quote.quote)),
    )
    .await
    .expect("check the mint quote");

    let keyset_id = *mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .expect("active keyset");
    let keys = mint
        .keyset_pubkeys(&keyset_id)
        .expect("keys")
        .keysets
        .first()
        .expect("keyset")
        .keys
        .clone();
    let amounts = keys.iter().map(|(amount, _)| amount.to_u64()).collect();
    let secrets = PreMintSecrets::random(
        keyset_id,
        Amount::from(sats),
        &SplitTarget::None,
        &(0, amounts).into(),
    )
    .expect("secrets");
    let response = mint
        .process_mint_request(MintInput::Single(MintRequest {
            quote: quote.quote,
            outputs: secrets.blinded_messages(),
            signature: None,
        }))
        .await
        .expect("mint");
    construct_proofs(response.signatures, secrets.rs(), secrets.secrets(), &keys).expect("proofs")
}

/// A funded melt that is ready to be sent.
struct Melt {
    mint: Mint,
    quote: MeltQuote,
    proofs: Proofs,
}

impl Melt {
    async fn prepare(mint: &Mint) -> Self {
        let proofs = fund(mint, MELT_SATS).await;
        let invoice = create_fake_invoice(MELT_SATS * 1_000, String::new());
        let response = within(
            "a melt quote",
            mint.get_melt_quote(melt_quote_request(invoice)),
        )
        .await
        .expect("melt quote");
        let quote_id = response.quote().expect("quote ID").clone();
        let quote = mint
            .localstore()
            .get_melt_quote(&quote_id)
            .await
            .expect("database")
            .expect("melt quote");
        Self {
            mint: mint.clone(),
            quote,
            proofs,
        }
    }

    fn request(&self) -> MeltRequest<QuoteId> {
        MeltRequest::new(self.quote.id.clone(), self.proofs.clone(), None)
    }

    async fn quote_state(&self) -> MeltQuoteState {
        self.mint
            .localstore()
            .get_melt_quote(&self.quote.id)
            .await
            .expect("database")
            .expect("melt quote")
            .state
    }

    async fn assert_pending(&self, when: &str) {
        assert_eq!(self.quote_state().await, MeltQuoteState::Pending, "{when}");
        assert!(
            self.mint
                .localstore()
                .get_melt_saga_by_quote_id(&self.quote.id)
                .await
                .expect("database")
                .is_some(),
            "{when}: the saga must remain"
        );
        self.assert_proofs(State::Pending, when).await;
    }

    async fn assert_paid(&self, when: &str) {
        assert_eq!(self.quote_state().await, MeltQuoteState::Paid, "{when}");
        self.assert_proofs(State::Spent, when).await;
    }

    async fn assert_proofs(&self, expected: State, when: &str) {
        let ys = self.proofs.ys().expect("proof Ys");
        let states = self
            .mint
            .localstore()
            .get_proofs_states(&ys)
            .await
            .expect("database");
        assert_eq!(states.len(), ys.len());
        assert!(
            states.iter().all(|state| *state == Some(expected)),
            "{when}: expected {expected}, got {states:?}"
        );
    }
}

#[tokio::test]
async fn a_hung_processor_does_not_hang_a_mint_quote() {
    let server = TestServer::start();
    let mint = server.mint().await;

    for call in [Call::Settings, Call::CreatePayment] {
        server.processor.hang(call);
        within(
            &format!("a mint quote with a hung {call:?}"),
            mint.get_mint_quote(mint_quote_request(10).into()),
        )
        .await
        .expect_err("a mint quote needs the processor");

        server.processor.resume(call);
        server.processor.wait_idle(call).await;
        within("settings", mint.get_custom_payment_methods())
            .await
            .expect("the processor answers");
        assert!(
            mint.mint_quotes().await.expect("quotes").is_empty(),
            "a late answer of {call:?} must not create a quote"
        );
    }

    let quote = mint_quote(&mint, 10).await;
    assert_eq!(mint.mint_quotes().await.expect("quotes").len(), 1);

    // The status of the quote.
    server.processor.hang(Call::CheckIncoming);
    within(
        "a mint quote status",
        mint.check_mint_quotes(std::slice::from_ref(&quote.quote)),
    )
    .await
    .expect_err("the status check needs the processor");
    server.processor.resume(Call::CheckIncoming);
    server.processor.wait_idle(Call::CheckIncoming).await;
    within("settings", mint.get_custom_payment_methods())
        .await
        .expect("the processor answers");
    let stored = mint.mint_quotes().await.expect("quotes");
    assert_eq!(
        stored[0].state(),
        MintQuoteState::Unpaid,
        "a late answer must not credit the quote"
    );
    mint.stop().await.expect("stop the mint");
}

#[tokio::test]
async fn a_hung_processor_does_not_hang_a_melt_quote() {
    let server = TestServer::start();
    let mint = server.mint().await;
    let invoice = create_fake_invoice(MELT_SATS * 1_000, String::new());

    server.processor.hang(Call::PaymentQuote);
    within(
        "a melt quote",
        mint.get_melt_quote(melt_quote_request(invoice.clone())),
    )
    .await
    .expect_err("a melt quote needs the processor");

    server.processor.resume(Call::PaymentQuote);
    server.processor.wait_idle(Call::PaymentQuote).await;
    within("settings", mint.get_custom_payment_methods())
        .await
        .expect("the processor answers");
    assert!(mint.melt_quotes().await.expect("quotes").is_empty());

    within(
        "a melt quote",
        mint.get_melt_quote(melt_quote_request(invoice)),
    )
    .await
    .expect("the same invoice gets a quote later");
    mint.stop().await.expect("stop the mint");
}

/// The melt is in flight, and the status check hangs. The late answer is the
/// most dangerous one: it says that the payment failed.
#[tokio::test]
async fn a_status_check_past_its_deadline_keeps_the_melt_pending() {
    let server = TestServer::start();
    let mint = server.mint().await;
    let melt = Melt::prepare(&mint).await;
    server.processor.set_send(Some(MeltQuoteState::Pending));
    server.processor.set_outgoing(MeltQuoteState::Pending);

    drop(
        within("the melt", mint.melt(&melt.request()))
            .await
            .expect("melt"),
    );
    // The status waits for the end of the dispatch.
    within("the melt status", mint.check_melt_quote(&melt.quote.id))
        .await
        .expect("melt status");
    melt.assert_pending("after the dispatch").await;

    server.processor.set_outgoing(MeltQuoteState::Failed);
    server.processor.hang(Call::CheckOutgoing);
    within("the melt status", mint.check_melt_quote(&melt.quote.id))
        .await
        .expect_err("the status is unknown");
    melt.assert_pending("after the deadline").await;

    server.processor.set_outgoing(MeltQuoteState::Paid);
    server.processor.resume(Call::CheckOutgoing);
    server.processor.wait_idle(Call::CheckOutgoing).await;
    within("settings", mint.get_custom_payment_methods())
        .await
        .expect("the processor answers");
    melt.assert_pending("after the late answer").await;

    within("the melt status", mint.check_melt_quote(&melt.quote.id))
        .await
        .expect("melt status");
    melt.assert_paid("after the processor answers").await;
    assert_eq!(server.processor.arrived(Call::Send), 1);
    mint.stop().await.expect("stop the mint");
}

/// The processor sent the payment, but its answer was an error. The melt saga
/// then asks for the status, and that call hangs.
#[tokio::test]
async fn a_sent_melt_is_not_failed_by_a_later_deadline() {
    let server = TestServer::start();
    let mint = server.mint().await;
    let melt = Melt::prepare(&mint).await;
    server.processor.set_send(None);
    server.processor.set_outgoing(MeltQuoteState::Failed);
    server.processor.hang(Call::CheckOutgoing);

    let pending = within("the melt", mint.melt(&melt.request()))
        .await
        .expect("the mint accepts the melt");
    within("the melt result", pending)
        .await
        .expect_err("the result is unknown");
    melt.assert_pending("after the deadline").await;

    // A restart of the mint asks again, and the processor still hangs.
    mint.stop().await.expect("stop the mint");
    within("the mint start", mint.start())
        .await
        .expect("start the mint");
    melt.assert_pending("after the restart").await;

    server.processor.set_outgoing(MeltQuoteState::Paid);
    server.processor.resume(Call::CheckOutgoing);
    server.processor.wait_idle(Call::CheckOutgoing).await;
    melt.assert_pending("after the late answers").await;

    within("the melt status", mint.check_melt_quote(&melt.quote.id))
        .await
        .expect("melt status");
    melt.assert_paid("after the processor answers").await;
    assert_eq!(server.processor.arrived(Call::Send), 1);
    mint.stop().await.expect("stop the mint");
}

/// The send itself takes longer than the deadline of the other calls.
#[tokio::test]
async fn a_slow_send_ends_the_melt_as_paid() {
    let server = TestServer::start();
    let mint = server.mint().await;
    let melt = Melt::prepare(&mint).await;
    server.processor.set_send(Some(MeltQuoteState::Paid));
    server.processor.hang(Call::Send);

    let pending = within("the melt", mint.melt(&melt.request()))
        .await
        .expect("the mint accepts the melt");
    server.processor.wait_arrived(Call::Send, 1).await;

    // A quote passes its deadline while the send is in progress.
    server.processor.hang(Call::Settings);
    within(
        "a mint quote",
        mint.get_mint_quote(mint_quote_request(10).into()),
    )
    .await
    .expect_err("a mint quote needs the processor");
    server.processor.resume(Call::Settings);
    melt.assert_pending("while the send is in progress").await;

    server.processor.resume(Call::Send);
    within("the melt result", pending).await.expect("paid");
    melt.assert_paid("after the send").await;
    assert_eq!(server.processor.arrived(Call::Send), 1);
    mint.stop().await.expect("stop the mint");
}

/// The watcher opens the event stream while the processor hangs. It must try
/// again, and it must then credit a deposit without a wallet call.
#[tokio::test]
async fn a_hung_processor_does_not_hang_the_event_watcher() {
    let server = TestServer::start();
    server.processor.hang(Call::EventStream);
    let mint = server.mint().await;
    server.processor.wait_arrived(Call::EventStream, 2).await;
    server.processor.resume(Call::EventStream);

    let quote = mint_quote(&mint, 10).await;
    // A status check, also the one of a new subscription, finds no payment.
    // Thus only the event can credit the deposit.
    server.processor.paid_invoices.lock().expect("lock").clear();
    let mut subscription = mint
        .pubsub_manager()
        .subscribe(Params {
            id: Arc::new(SubId::from("watcher".to_string())),
            kind: Kind::Bolt11MintQuote,
            filters: vec![quote.quote.to_string()],
        })
        .expect("subscribe");
    let invoice: Bolt11Invoice = quote.request.parse().expect("invoice");
    server
        .events
        .send(Event::PaymentReceived(WaitPaymentResponse {
            payment_identifier: lookup_id(&invoice),
            payment_amount: Amount::new(10, CurrencyUnit::Sat),
            payment_id: "payment".to_string(),
        }))
        .expect("the processor lives");
    within("the credit of the deposit", async {
        while let Some(event) = subscription.recv().await {
            if let NotificationPayload::MintQuoteBolt11Response(response) = event.into_inner() {
                if response.state == MintQuoteState::Paid {
                    return;
                }
            }
        }
        panic!("the subscription ended");
    })
    .await;
    mint.stop().await.expect("stop the mint");
}
