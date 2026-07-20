//! Run a Signatory in a embedded environment, inside a CDK instance, but this wrapper makes sure to
//! run the Signatory in another thread, isolated form the main CDK, communicating through messages
#[cfg(feature = "conditional-tokens")]
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use cdk_common::{BlindSignature, BlindedMessage, Error, Proof};
#[cfg(feature = "conditional-tokens")]
use cdk_common::{CurrencyUnit, Id};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[cfg(feature = "conditional-tokens")]
use crate::signatory::{
    ConditionalKeysetInstallReservation, ConditionalKeysetInstallReservationIssuer,
    PreparedConditionalKeySet,
};
use crate::signatory::{RotateKeyArguments, Signatory, SignatoryKeySet, SignatoryKeysets};

#[cfg(feature = "conditional-tokens")]
#[allow(clippy::type_complexity)]
type PrepareConditionalKeysetRequest = (
    CurrencyUnit,
    String,
    String,
    String,
    Vec<u64>,
    u64,
    Option<u64>,
    oneshot::Sender<Result<PreparedConditionalKeySet, Error>>,
);

#[cfg(feature = "conditional-tokens")]
type InstallConditionalKeysetsRequest = (
    Vec<cdk_common::mint::MintKeySetInfo>,
    ConditionalKeysetInstallReservation,
    oneshot::Sender<Result<Vec<SignatoryKeySet>, Error>>,
);

enum Request {
    BlindSign(
        (
            Vec<BlindedMessage>,
            oneshot::Sender<Result<Vec<BlindSignature>, Error>>,
        ),
    ),
    VerifyProof((Vec<Proof>, oneshot::Sender<Result<(), Error>>)),
    Keysets(oneshot::Sender<Result<SignatoryKeysets, Error>>),
    RotateKeyset(
        (
            RotateKeyArguments,
            oneshot::Sender<Result<SignatoryKeySet, Error>>,
        ),
    ),
    #[cfg(feature = "conditional-tokens")]
    PrepareConditionalKeyset(PrepareConditionalKeysetRequest),
    #[cfg(feature = "conditional-tokens")]
    InstallConditionalKeysets(InstallConditionalKeysetsRequest),
    #[cfg(feature = "conditional-tokens")]
    ReloadKeysetsFromStorage(oneshot::Sender<Result<(), Error>>),
}

#[cfg(feature = "conditional-tokens")]
const CONDITIONAL_INSTALL_QUEUE_CAPACITY: usize = 2;
#[cfg(feature = "conditional-tokens")]
const CONDITIONAL_INSTALL_ADMISSION_CAPACITY: usize = CONDITIONAL_INSTALL_QUEUE_CAPACITY + 1;
#[cfg(feature = "conditional-tokens")]
const CONDITIONAL_DEFERRED_REQUEST_CAPACITY: usize = 64;

#[cfg(feature = "conditional-tokens")]
struct ConditionalInstallJob {
    keyset_ids: Vec<Id>,
    keysets: Vec<cdk_common::mint::MintKeySetInfo>,
    _reservation: ConditionalKeysetInstallReservation,
    response: oneshot::Sender<Result<Vec<SignatoryKeySet>, Error>>,
}

#[cfg(feature = "conditional-tokens")]
struct ConditionalInstallCompletion {
    keyset_ids: Vec<Id>,
}

/// Creates a service-like to wrap an implementation of the Signatory
///
/// This implements the actor model, ensuring the Signatory and their private key is moved from the
/// main thread to their own tokio task, and communicates with the main program by passing messages,
/// an extra layer of security to move the keys to another layer.
#[allow(missing_debug_implementations)]
pub struct Service {
    pipeline: mpsc::Sender<Request>,
    runner: Option<JoinHandle<()>>,
    #[cfg(feature = "conditional-tokens")]
    install_worker: Option<JoinHandle<()>>,
    #[cfg(feature = "conditional-tokens")]
    install_admission: Arc<tokio::sync::Semaphore>,
    #[cfg(feature = "conditional-tokens")]
    install_reservations: ConditionalKeysetInstallReservationIssuer,
}

impl Drop for Service {
    fn drop(&mut self) {
        #[cfg(feature = "conditional-tokens")]
        if let Some(install_worker) = self.install_worker.take() {
            install_worker.abort();
        }
        if let Some(runner) = self.runner.take() {
            runner.abort();
        }
    }
}

impl Service {
    /// Takes a signatory and spawns it into a Tokio task, isolating its implementation with the
    /// main thread, communicating with it through messages
    pub fn new(handler: Arc<dyn Signatory + Send + Sync>) -> Self {
        let (tx, rx) = mpsc::channel(10_000);

        #[cfg(feature = "conditional-tokens")]
        let service = {
            let (install_tx, install_rx) = mpsc::channel(CONDITIONAL_INSTALL_QUEUE_CAPACITY);
            let (completion_tx, completion_rx) = mpsc::unbounded_channel();
            let install_admission = Arc::new(tokio::sync::Semaphore::new(
                CONDITIONAL_INSTALL_ADMISSION_CAPACITY,
            ));
            let install_reservations = ConditionalKeysetInstallReservationIssuer::new();
            let install_worker = Some(tokio::spawn(Self::conditional_install_worker(
                install_rx,
                completion_tx,
                handler.clone(),
            )));
            let runner = Some(tokio::spawn(Self::runner(
                rx,
                handler,
                install_tx,
                completion_rx,
            )));

            Self {
                pipeline: tx,
                runner,
                install_worker,
                install_admission,
                install_reservations,
            }
        };

        #[cfg(not(feature = "conditional-tokens"))]
        let service = Self {
            pipeline: tx,
            runner: Some(tokio::spawn(Self::runner(rx, handler))),
        };

        service
    }

    #[cfg(not(feature = "conditional-tokens"))]
    #[tracing::instrument(skip_all)]
    async fn runner(
        mut receiver: mpsc::Receiver<Request>,
        handler: Arc<dyn Signatory + Send + Sync>,
    ) {
        while let Some(request) = receiver.recv().await {
            match request {
                Request::BlindSign((blinded_message, response)) => {
                    let output = handler.blind_sign(blinded_message).await;
                    if let Err(err) = response.send(output) {
                        tracing::error!("Error sending response: {:?}", err);
                    }
                }
                Request::VerifyProof((proof, response)) => {
                    let output = handler.verify_proofs(proof).await;
                    if let Err(err) = response.send(output) {
                        tracing::error!("Error sending response: {:?}", err);
                    }
                }
                Request::Keysets(response) => {
                    let output = handler.keysets().await;
                    if let Err(err) = response.send(output) {
                        tracing::error!("Error sending response: {:?}", err);
                    }
                }
                Request::RotateKeyset((args, response)) => {
                    let output = handler.rotate_keyset(args).await;
                    if let Err(err) = response.send(output) {
                        tracing::error!("Error sending response: {:?}", err);
                    }
                }
            }
        }
    }

    #[cfg(feature = "conditional-tokens")]
    #[tracing::instrument(skip_all)]
    async fn runner(
        mut receiver: mpsc::Receiver<Request>,
        handler: Arc<dyn Signatory + Send + Sync>,
        install_sender: mpsc::Sender<ConditionalInstallJob>,
        mut install_completions: mpsc::UnboundedReceiver<ConditionalInstallCompletion>,
    ) {
        let mut pending_installs = HashMap::<Id, usize>::new();
        let mut deferred = VecDeque::<Request>::new();

        loop {
            tokio::select! {
                Some(completion) = install_completions.recv() => {
                    for keyset_id in completion.keyset_ids {
                        if let Some(count) = pending_installs.get_mut(&keyset_id) {
                            *count -= 1;
                            if *count == 0 {
                                pending_installs.remove(&keyset_id);
                            }
                        }
                    }
                    Self::dispatch_ready_requests(
                        &mut deferred,
                        &mut pending_installs,
                        &install_sender,
                        &handler,
                    )
                    .await;
                }
                request = receiver.recv() => {
                    let Some(request) = request else {
                        break;
                    };
                    if Self::request_depends_on_pending_install(&request, &pending_installs) {
                        if deferred.len() < CONDITIONAL_DEFERRED_REQUEST_CAPACITY {
                            deferred.push_back(request);
                        } else {
                            Self::reject_deferred_request(request);
                        }
                    } else {
                        Self::dispatch_request(
                            request,
                            &mut pending_installs,
                            &install_sender,
                            &handler,
                        )
                        .await;
                    }
                }
            }
        }
    }

    #[cfg(feature = "conditional-tokens")]
    async fn conditional_install_worker(
        mut receiver: mpsc::Receiver<ConditionalInstallJob>,
        completion_sender: mpsc::UnboundedSender<ConditionalInstallCompletion>,
        handler: Arc<dyn Signatory + Send + Sync>,
    ) {
        while let Some(job) = receiver.recv().await {
            let output = handler.install_conditional_keysets(job.keysets).await;
            if let Err(err) = job.response.send(output) {
                tracing::error!("Error sending conditional install response: {:?}", err);
            }
            if completion_sender
                .send(ConditionalInstallCompletion {
                    keyset_ids: job.keyset_ids,
                })
                .is_err()
            {
                break;
            }
        }
    }

    #[cfg(feature = "conditional-tokens")]
    fn request_depends_on_pending_install(
        request: &Request,
        pending_installs: &HashMap<Id, usize>,
    ) -> bool {
        match request {
            Request::BlindSign((messages, _)) => messages
                .iter()
                .any(|message| pending_installs.contains_key(&message.keyset_id)),
            Request::VerifyProof((proofs, _)) => proofs
                .iter()
                .any(|proof| pending_installs.contains_key(&proof.keyset_id)),
            // These operations observe or mutate the complete keyset set and
            // therefore must remain ordered behind every earlier install.
            Request::Keysets(_)
            | Request::RotateKeyset(_)
            | Request::ReloadKeysetsFromStorage(_) => !pending_installs.is_empty(),
            Request::PrepareConditionalKeyset(_) | Request::InstallConditionalKeysets(_) => false,
        }
    }

    #[cfg(feature = "conditional-tokens")]
    fn reject_deferred_request(request: Request) {
        fn error() -> Error {
            Error::SendError("conditional install dependency queue is saturated".to_string())
        }

        match request {
            Request::BlindSign((_, response)) => {
                let _ = response.send(Err(error()));
            }
            Request::VerifyProof((_, response)) => {
                let _ = response.send(Err(error()));
            }
            Request::Keysets(response) => {
                let _ = response.send(Err(error()));
            }
            Request::RotateKeyset((_, response)) => {
                let _ = response.send(Err(error()));
            }
            Request::PrepareConditionalKeyset((_, _, _, _, _, _, _, response)) => {
                let _ = response.send(Err(error()));
            }
            Request::InstallConditionalKeysets((_, _, response)) => {
                let _ = response.send(Err(error()));
            }
            Request::ReloadKeysetsFromStorage(response) => {
                let _ = response.send(Err(error()));
            }
        }
    }

    #[cfg(feature = "conditional-tokens")]
    async fn dispatch_ready_requests(
        deferred: &mut VecDeque<Request>,
        pending_installs: &mut HashMap<Id, usize>,
        install_sender: &mpsc::Sender<ConditionalInstallJob>,
        handler: &Arc<dyn Signatory + Send + Sync>,
    ) {
        let queued = deferred.len();
        for _ in 0..queued {
            let request = deferred
                .pop_front()
                .expect("deferred request count should remain stable");
            if Self::request_depends_on_pending_install(&request, pending_installs) {
                deferred.push_back(request);
            } else {
                Self::dispatch_request(request, pending_installs, install_sender, handler).await;
            }
        }
    }

    #[cfg(feature = "conditional-tokens")]
    async fn dispatch_request(
        request: Request,
        pending_installs: &mut HashMap<Id, usize>,
        install_sender: &mpsc::Sender<ConditionalInstallJob>,
        handler: &Arc<dyn Signatory + Send + Sync>,
    ) {
        match request {
            Request::BlindSign((blinded_message, response)) => {
                let output = handler.blind_sign(blinded_message).await;
                if let Err(err) = response.send(output) {
                    tracing::error!("Error sending response: {:?}", err);
                }
            }
            Request::VerifyProof((proof, response)) => {
                let output = handler.verify_proofs(proof).await;
                if let Err(err) = response.send(output) {
                    tracing::error!("Error sending response: {:?}", err);
                }
            }
            Request::Keysets(response) => {
                let output = handler.keysets().await;
                if let Err(err) = response.send(output) {
                    tracing::error!("Error sending response: {:?}", err);
                }
            }
            Request::RotateKeyset((args, response)) => {
                let output = handler.rotate_keyset(args).await;
                if let Err(err) = response.send(output) {
                    tracing::error!("Error sending response: {:?}", err);
                }
            }
            Request::PrepareConditionalKeyset((
                unit,
                condition_id,
                outcome_collection,
                outcome_collection_id,
                amounts,
                input_fee_ppk,
                final_expiry,
                response,
            )) => {
                let output = handler
                    .prepare_conditional_keyset(
                        unit,
                        &condition_id,
                        &outcome_collection,
                        &outcome_collection_id,
                        amounts,
                        input_fee_ppk,
                        final_expiry,
                    )
                    .await;
                if let Err(err) = response.send(output) {
                    tracing::error!("Error sending response: {:?}", err);
                }
            }
            Request::InstallConditionalKeysets((keysets, reservation, response)) => {
                let keyset_ids = keysets
                    .iter()
                    .map(|keyset| keyset.id)
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let pending_keyset_ids = keyset_ids.clone();
                let job = ConditionalInstallJob {
                    keyset_ids,
                    keysets,
                    _reservation: reservation,
                    response,
                };
                match install_sender.send(job).await {
                    Ok(()) => {
                        for keyset_id in pending_keyset_ids {
                            *pending_installs.entry(keyset_id).or_default() += 1;
                        }
                    }
                    Err(error) => {
                        let job = error.0;
                        let _ = job.response.send(Err(Error::SendError(
                            "conditional keyset install worker is unavailable".to_string(),
                        )));
                    }
                }
            }
            Request::ReloadKeysetsFromStorage(response) => {
                let output = handler.reload_keysets_from_storage().await;
                if let Err(err) = response.send(output) {
                    tracing::error!("Error sending response: {:?}", err);
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Signatory for Service {
    fn name(&self) -> String {
        "Embedded".to_owned()
    }

    #[tracing::instrument(skip_all)]
    async fn blind_sign(
        &self,
        blinded_messages: Vec<BlindedMessage>,
    ) -> Result<Vec<BlindSignature>, Error> {
        let (tx, rx) = oneshot::channel();
        self.pipeline
            .send(Request::BlindSign((blinded_messages, tx)))
            .await
            .map_err(|e| Error::SendError(e.to_string()))?;

        rx.await.map_err(|e| Error::RecvError(e.to_string()))?
    }

    #[tracing::instrument(skip_all)]
    async fn verify_proofs(&self, proofs: Vec<Proof>) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.pipeline
            .send(Request::VerifyProof((proofs, tx)))
            .await
            .map_err(|e| Error::SendError(e.to_string()))?;

        rx.await.map_err(|e| Error::RecvError(e.to_string()))?
    }

    #[tracing::instrument(skip_all)]
    async fn keysets(&self) -> Result<SignatoryKeysets, Error> {
        let (tx, rx) = oneshot::channel();
        self.pipeline
            .send(Request::Keysets(tx))
            .await
            .map_err(|e| Error::SendError(e.to_string()))?;

        rx.await.map_err(|e| Error::RecvError(e.to_string()))?
    }

    #[tracing::instrument(skip(self))]
    async fn rotate_keyset(&self, args: RotateKeyArguments) -> Result<SignatoryKeySet, Error> {
        let (tx, rx) = oneshot::channel();
        self.pipeline
            .send(Request::RotateKeyset((args, tx)))
            .await
            .map_err(|e| Error::SendError(e.to_string()))?;

        rx.await.map_err(|e| Error::RecvError(e.to_string()))?
    }

    #[cfg(feature = "conditional-tokens")]
    #[tracing::instrument(skip(self))]
    async fn prepare_conditional_keyset(
        &self,
        unit: CurrencyUnit,
        condition_id: &str,
        outcome_collection: &str,
        outcome_collection_id: &str,
        amounts: Vec<u64>,
        input_fee_ppk: u64,
        final_expiry: Option<u64>,
    ) -> Result<PreparedConditionalKeySet, Error> {
        let (tx, rx) = oneshot::channel();
        self.pipeline
            .send(Request::PrepareConditionalKeyset((
                unit,
                condition_id.to_string(),
                outcome_collection.to_string(),
                outcome_collection_id.to_string(),
                amounts,
                input_fee_ppk,
                final_expiry,
                tx,
            )))
            .await
            .map_err(|e| Error::SendError(e.to_string()))?;

        rx.await.map_err(|e| Error::RecvError(e.to_string()))?
    }

    #[cfg(feature = "conditional-tokens")]
    async fn reserve_conditional_keyset_install(
        &self,
    ) -> Result<ConditionalKeysetInstallReservation, Error> {
        self.install_admission
            .clone()
            .try_acquire_owned()
            .map(|permit| self.install_reservations.reserve(permit))
            .map_err(|_| {
                Error::SendError("conditional keyset install admission is saturated".to_string())
            })
    }

    #[cfg(feature = "conditional-tokens")]
    async fn install_reserved_conditional_keysets(
        &self,
        reservation: ConditionalKeysetInstallReservation,
        keysets: Vec<cdk_common::mint::MintKeySetInfo>,
    ) -> Result<Vec<SignatoryKeySet>, Error> {
        self.install_reservations.validate(&reservation)?;
        let (tx, rx) = oneshot::channel();
        self.pipeline
            .send(Request::InstallConditionalKeysets((
                keysets,
                reservation,
                tx,
            )))
            .await
            .map_err(|e| Error::SendError(e.to_string()))?;

        rx.await.map_err(|e| Error::RecvError(e.to_string()))?
    }

    #[cfg(feature = "conditional-tokens")]
    #[tracing::instrument(skip_all, fields(keyset_count = keysets.len()))]
    async fn install_conditional_keysets(
        &self,
        keysets: Vec<cdk_common::mint::MintKeySetInfo>,
    ) -> Result<Vec<SignatoryKeySet>, Error> {
        let reservation = self.reserve_conditional_keyset_install().await?;
        self.install_reserved_conditional_keysets(reservation, keysets)
            .await
    }

    #[cfg(feature = "conditional-tokens")]
    async fn reload_keysets_from_storage(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.pipeline
            .send(Request::ReloadKeysetsFromStorage(tx))
            .await
            .map_err(|e| Error::SendError(e.to_string()))?;

        rx.await.map_err(|e| Error::RecvError(e.to_string()))?
    }
}

#[cfg(all(test, feature = "conditional-tokens"))]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use cdk_common::mint::MintKeySetInfo;
    use cdk_common::nuts::Id;
    use cdk_common::{Amount, PublicKey};
    use tokio::sync::Notify;

    use super::*;

    struct DispatchProbeSignatory {
        install_started: Notify,
        release_install: Notify,
        blind_sign_called: AtomicBool,
        installs_completed: AtomicUsize,
        active_installs: AtomicUsize,
        max_active_installs: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Signatory for DispatchProbeSignatory {
        fn name(&self) -> String {
            "dispatch-probe".to_string()
        }

        async fn blind_sign(
            &self,
            _blinded_messages: Vec<BlindedMessage>,
        ) -> Result<Vec<BlindSignature>, Error> {
            self.blind_sign_called.store(true, Ordering::SeqCst);
            Ok(Vec::new())
        }

        async fn verify_proofs(&self, _proofs: Vec<Proof>) -> Result<(), Error> {
            Ok(())
        }

        async fn keysets(&self) -> Result<SignatoryKeysets, Error> {
            Err(Error::Custom("unused in dispatch probe".to_string()))
        }

        async fn rotate_keyset(&self, _args: RotateKeyArguments) -> Result<SignatoryKeySet, Error> {
            Err(Error::Custom("unused in dispatch probe".to_string()))
        }

        async fn install_conditional_keysets(
            &self,
            keysets: Vec<MintKeySetInfo>,
        ) -> Result<Vec<SignatoryKeySet>, Error> {
            assert_eq!(keysets.len(), 256);
            assert!(keysets.iter().all(|keyset| keyset.amounts.len() == 32));
            let active = self.active_installs.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_installs.fetch_max(active, Ordering::SeqCst);
            self.install_started.notify_one();
            self.release_install.notified().await;
            self.active_installs.fetch_sub(1, Ordering::SeqCst);
            self.installs_completed.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    fn dispatch_probe() -> Arc<DispatchProbeSignatory> {
        Arc::new(DispatchProbeSignatory {
            install_started: Notify::new(),
            release_install: Notify::new(),
            blind_sign_called: AtomicBool::new(false),
            installs_completed: AtomicUsize::new(0),
            active_installs: AtomicUsize::new(0),
            max_active_installs: AtomicUsize::new(0),
        })
    }

    fn representative_keysets() -> Vec<MintKeySetInfo> {
        let template = MintKeySetInfo {
            id: Id::from_str("00916bbf7ef91a36").expect("keyset id should parse"),
            unit: CurrencyUnit::Sat,
            active: true,
            valid_from: 0,
            derivation_path: Default::default(),
            derivation_path_index: Some(1),
            amounts: (0..32).map(|index| 1_u64 << index).collect(),
            input_fee_ppk: 0,
            final_expiry: None,
            issuer_version: None,
            condition_id: Some("ab".repeat(32)),
            outcome_collection: Some("YES".to_string()),
            outcome_collection_id: Some("cd".repeat(32)),
        };
        vec![template; 256]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conditional_install_does_not_stall_signing_dispatch() {
        let handler = dispatch_probe();
        let service = Arc::new(Service::new(handler.clone()));
        let installing = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .install_conditional_keysets(representative_keysets())
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), handler.install_started.notified())
            .await
            .expect("install should reach the instrumented slow phase");

        tokio::time::timeout(Duration::from_millis(250), async {
            service.blind_sign(Vec::new()).await?;
            service.verify_proofs(Vec::new()).await
        })
        .await
        .expect("blind-sign and verify dispatch must continue during installation")
        .expect("probe signing operations should succeed");

        handler.release_install.notify_waiters();
        installing
            .await
            .expect("install task should join")
            .expect("probe install should complete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dependent_blind_sign_cannot_overtake_install_visibility() {
        let handler = dispatch_probe();
        let service = Service::new(handler.clone());
        let (install_tx, install_rx) = oneshot::channel();
        let reservation = service
            .reserve_conditional_keyset_install()
            .await
            .expect("install admission should reserve");
        service
            .pipeline
            .send(Request::InstallConditionalKeysets((
                representative_keysets(),
                reservation,
                install_tx,
            )))
            .await
            .expect("install request should enqueue");
        tokio::time::timeout(Duration::from_secs(1), handler.install_started.notified())
            .await
            .expect("install should enter its slow phase");

        let keyset_id = Id::from_str("00916bbf7ef91a36").expect("keyset id should parse");
        let blinded_secret = PublicKey::from_hex(
            "024aebe0f8be04b1ba1d7d6b7fe454c9ae43e0fa22b2fdc88b172f3c5a0d19aaa4",
        )
        .expect("public key should parse");
        let (sign_tx, mut sign_rx) = oneshot::channel();
        service
            .pipeline
            .send(Request::BlindSign((
                vec![BlindedMessage::new(
                    Amount::from(1_u64),
                    keyset_id,
                    blinded_secret,
                )],
                sign_tx,
            )))
            .await
            .expect("blind-sign request should enqueue");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut sign_rx)
                .await
                .is_err(),
            "dependent signing must wait for installation"
        );
        assert!(!handler.blind_sign_called.load(Ordering::SeqCst));

        handler.release_install.notify_waiters();
        install_rx
            .await
            .expect("install response should arrive")
            .expect("install should succeed");
        sign_rx
            .await
            .expect("blind-sign response should arrive")
            .expect("blind-sign should succeed after install");
        assert!(handler.blind_sign_called.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_service_cancels_owned_install_without_late_mutation() {
        let handler = dispatch_probe();
        let service = Service::new(handler.clone());
        let (install_tx, install_rx) = oneshot::channel();
        let reservation = service
            .reserve_conditional_keyset_install()
            .await
            .expect("install admission should reserve");
        service
            .pipeline
            .send(Request::InstallConditionalKeysets((
                representative_keysets(),
                reservation,
                install_tx,
            )))
            .await
            .expect("install request should enqueue");
        tokio::time::timeout(Duration::from_secs(1), handler.install_started.notified())
            .await
            .expect("install should enter its slow phase");

        drop(service);
        handler.release_install.notify_waiters();
        assert!(
            install_rx.await.is_err(),
            "dropping Service must cancel the owned install response"
        );
        tokio::task::yield_now().await;
        assert_eq!(handler.installs_completed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conditional_install_queue_is_bounded_and_single_worker_ordered() {
        let handler = dispatch_probe();
        let service = Arc::new(Service::new(handler.clone()));
        let mut installing = Vec::new();

        for _ in 0..CONDITIONAL_INSTALL_ADMISSION_CAPACITY {
            let service = service.clone();
            installing.push(tokio::spawn(async move {
                service
                    .install_conditional_keysets(representative_keysets())
                    .await
            }));
        }

        tokio::time::timeout(Duration::from_secs(1), handler.install_started.notified())
            .await
            .expect("the owned install worker should start the first batch");
        let saturated = tokio::time::timeout(Duration::from_secs(1), async {
            service
                .install_conditional_keysets(representative_keysets())
                .await
        })
        .await
        .expect("saturation must fail fast")
        .expect_err("queue capacity must reject excess installation work");
        assert!(saturated.to_string().contains("saturated"));
        assert_eq!(handler.max_active_installs.load(Ordering::SeqCst), 1);

        for task in installing {
            task.abort();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conditional_install_rejects_cross_service_reservation() {
        let first = Service::new(dispatch_probe());
        let second_handler = dispatch_probe();
        let second = Service::new(second_handler.clone());
        let reservation = first
            .reserve_conditional_keyset_install()
            .await
            .expect("first service should reserve its own admission");

        let error = tokio::time::timeout(
            Duration::from_millis(250),
            second.install_reserved_conditional_keysets(reservation, representative_keysets()),
        )
        .await
        .expect("foreign reservation must fail before actor enqueue")
        .expect_err("one service must reject another service's reservation");

        assert!(error.to_string().contains("reservation"));
        assert_eq!(second_handler.active_installs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conditional_install_rejects_default_reservation() {
        let default_signatory = dispatch_probe();
        let reservation = default_signatory
            .reserve_conditional_keyset_install()
            .await
            .expect("unbounded default signatory should return its permissive token");
        let service_handler = dispatch_probe();
        let service = Service::new(service_handler.clone());

        let error = tokio::time::timeout(
            Duration::from_millis(250),
            service.install_reserved_conditional_keysets(reservation, representative_keysets()),
        )
        .await
        .expect("default reservation must fail before actor enqueue")
        .expect_err("bounded service must reject an unbranded default reservation");

        assert!(error.to_string().contains("reservation"));
        assert_eq!(service_handler.active_installs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hung_install_cannot_retain_unbounded_dependent_requests() {
        let handler = dispatch_probe();
        let service = Service::new(handler.clone());
        let (install_tx, _install_rx) = oneshot::channel();
        let reservation = service
            .reserve_conditional_keyset_install()
            .await
            .expect("install admission should reserve");
        service
            .pipeline
            .send(Request::InstallConditionalKeysets((
                representative_keysets(),
                reservation,
                install_tx,
            )))
            .await
            .expect("install request should enqueue");
        tokio::time::timeout(Duration::from_secs(1), handler.install_started.notified())
            .await
            .expect("install should enter its hung phase");

        let keyset_id = Id::from_str("00916bbf7ef91a36").expect("keyset id should parse");
        let blinded_secret = PublicKey::from_hex(
            "024aebe0f8be04b1ba1d7d6b7fe454c9ae43e0fa22b2fdc88b172f3c5a0d19aaa4",
        )
        .expect("public key should parse");
        let mut responses = Vec::new();
        for _ in 0..=CONDITIONAL_DEFERRED_REQUEST_CAPACITY {
            let (response, receiver) = oneshot::channel();
            service
                .pipeline
                .send(Request::BlindSign((
                    vec![BlindedMessage::new(
                        Amount::from(1_u64),
                        keyset_id,
                        blinded_secret,
                    )],
                    response,
                )))
                .await
                .expect("dependent request should enter the actor pipeline");
            responses.push(receiver);
        }

        let saturated = tokio::time::timeout(
            Duration::from_millis(250),
            responses
                .pop()
                .expect("overflow response should be retained"),
        )
        .await
        .expect("overflow must be rejected while install remains hung")
        .expect("actor should send the overflow result")
        .expect_err("deferred capacity must reject excess dependent work");
        assert!(saturated
            .to_string()
            .contains("dependency queue is saturated"));
        assert!(!handler.blind_sign_called.load(Ordering::SeqCst));
    }
}
