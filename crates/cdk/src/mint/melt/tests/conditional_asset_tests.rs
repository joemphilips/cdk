use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use cdk_common::amount::SplitTarget;
use cdk_common::dhke::construct_proofs;
use cdk_common::mint::MeltQuote;
use cdk_common::nut00::KnownMethod;
use cdk_common::nuts::nut_ctf::test_helpers::{
    create_oracle_witness, create_test_announcement, create_test_oracle,
};
use cdk_common::nuts::nut_ctf::{
    CtfConvertRequest, NutCtfSettings, RedeemOutcomeRequest, RegisterConditionRequest,
    RegistrationFeeSetting,
};
use cdk_common::nuts::{Id, MeltQuoteState, MeltRequest, PreMintSecrets, Proofs, Witness};
use cdk_common::payment::{
    self, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions, MakePaymentResponse,
    MintPayment, OutgoingPaymentOptions, PaymentIdentifier, PaymentQuoteResponse, SettingsResponse,
    WaitPaymentResponse,
};
use cdk_common::{Amount, CurrencyUnit, MeltQuoteBolt11Request, PaymentMethod, ProofsMethods};
use cdk_fake_wallet::{create_fake_invoice, FakeInvoiceDescription, FakeWallet};
use futures::Stream;

use crate::mint::melt::melt_saga::MeltSaga;
use crate::mint::{Mint, MintBuilder, MintMeltLimits, UnitConfig};
use crate::test_helpers::mint::mint_test_proofs;
use crate::types::FeeReserve;
use crate::Error;

struct CountingBackend {
    inner: FakeWallet,
    payments: AtomicUsize,
}

#[async_trait]
impl MintPayment for CountingBackend {
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
        self.payments.fetch_add(1, Ordering::SeqCst);
        self.inner.make_payment(unit, options).await
    }

    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        self.inner.wait_payment_event().await
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.inner.is_payment_event_stream_active()
    }

    fn cancel_payment_event_stream(&self) {
        self.inner.cancel_payment_event_stream();
    }

    async fn check_incoming_payment_status(
        &self,
        identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        self.inner.check_incoming_payment_status(identifier).await
    }

    async fn check_outgoing_payment(
        &self,
        identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        self.inner.check_outgoing_payment(identifier).await
    }
}

async fn test_mint() -> (Mint, Arc<CountingBackend>) {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await.unwrap());
    let backend = Arc::new(CountingBackend {
        inner: FakeWallet::new(
            FeeReserve {
                min_fee_reserve: Amount::from(1),
                percent_fee_reserve: 1.0,
            },
            HashMap::new(),
            HashSet::new(),
            2,
            CurrencyUnit::Sat,
        ),
        payments: AtomicUsize::new(0),
    });
    let mut builder = MintBuilder::new(db.clone());
    builder
        .configure_unit(
            CurrencyUnit::Sat,
            UnitConfig {
                input_fee_ppk: 1000,
                ..UnitConfig::default()
            },
        )
        .unwrap();
    builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 10_000),
            backend.clone(),
        )
        .await
        .unwrap();
    let mint = builder.build_with_seed(db, &[42; 64]).await.unwrap();
    let mut info = mint.mint_info().await.unwrap();
    info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![RegistrationFeeSetting {
            unit: "sat".to_string(),
            registration_fee_base: 0,
            registration_fee_per_keyset: 0,
        }],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(info).await.unwrap();
    mint.start().await.unwrap();
    (mint, backend)
}

fn premint(mint: &Mint, id: Id, amount: Amount, split: SplitTarget) -> PreMintSecrets {
    let keys = mint.keyset_pubkeys(&id).unwrap().keysets[0].keys.clone();
    let amounts: (u64, Vec<u64>) = (0, keys.iter().map(|(value, _)| value.to_u64()).collect());
    PreMintSecrets::random(id, amount, &split, &amounts.into()).unwrap()
}

async fn split_collateral(mint: &Mint, resolved: bool) -> HashMap<String, Proofs> {
    let regular = *mint.get_active_keysets().get(&CurrencyUnit::Sat).unwrap();
    let collateral = mint_test_proofs(mint, Amount::from(8194)).await.unwrap();
    let oracle = create_test_oracle();
    let (_, announcement) = create_test_announcement(&oracle, &["YES", "NO"], "melt-assets");
    let condition = mint
        .register_condition(RegisterConditionRequest {
            threshold: 1,
            tags: vec![],
            announcements: vec![announcement],
            collateral: Some("sat".to_string()),
            outcome_collections: Some(vec!["YES".to_string(), "NO".to_string()]),
            fee: None,
            outputs: None,
            condition_type: "enum".to_string(),
            lo_bound: None,
            hi_bound: None,
            precision: None,
        })
        .await
        .unwrap();
    let outputs: HashMap<_, _> = ["YES", "NO"]
        .into_iter()
        .map(|outcome| {
            (
                outcome.to_string(),
                premint(
                    mint,
                    condition.keysets[outcome],
                    Amount::from(8192),
                    SplitTarget::Values(vec![Amount::from(4096); 2]),
                ),
            )
        })
        .collect();
    let response = mint
        .process_ctf_convert(CtfConvertRequest {
            condition_id: condition.condition_id,
            parent_collection_id: None,
            inputs: HashMap::from([("*".to_string(), collateral)]),
            outputs: outputs
                .iter()
                .map(|(outcome, premint)| (outcome.clone(), premint.blinded_messages()))
                .collect(),
        })
        .await
        .unwrap();
    let mut proofs: HashMap<_, _> = outputs
        .into_iter()
        .map(|(outcome, premint)| {
            let keys = mint
                .keyset_pubkeys(&condition.keysets[&outcome])
                .unwrap()
                .keysets[0]
                .keys
                .clone();
            let proofs = construct_proofs(
                response.signatures[&outcome].clone(),
                premint.rs(),
                premint.secrets(),
                &keys,
            )
            .unwrap();
            (outcome, proofs)
        })
        .collect();
    if resolved {
        let mut winner = proofs.get_mut("YES").unwrap().pop().unwrap();
        winner.witness = Some(Witness::OracleWitness(create_oracle_witness(
            &oracle, "YES",
        )));
        mint.process_redeem_outcome(RedeemOutcomeRequest {
            inputs: vec![winner],
            outputs: premint(mint, regular, Amount::from(4095), SplitTarget::None)
                .blinded_messages(),
        })
        .await
        .unwrap();
    }
    proofs
}

async fn melt_quote(mint: &Mint) -> MeltQuote {
    let description = FakeInvoiceDescription {
        pay_invoice_state: MeltQuoteState::Paid,
        check_payment_state: MeltQuoteState::Paid,
        pay_err: false,
        check_err: false,
    };
    let response = mint
        .get_melt_quote(
            MeltQuoteBolt11Request {
                request: create_fake_invoice(
                    2_000_000,
                    serde_json::to_string(&description).unwrap(),
                ),
                unit: CurrencyUnit::Sat,
                options: None,
            }
            .into(),
        )
        .await
        .unwrap();
    mint.localstore()
        .get_melt_quote(response.quote().unwrap())
        .await
        .unwrap()
        .unwrap()
}

async fn assert_unchanged(
    mint: &Mint,
    backend: &CountingBackend,
    request: &MeltRequest<cdk_common::QuoteId>,
    quote: &MeltQuote,
) {
    assert_eq!(backend.payments.load(Ordering::SeqCst), 0);
    assert!(mint
        .localstore()
        .get_proofs_states(&request.inputs().ys().unwrap())
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    let blinded: Vec<_> = request
        .outputs()
        .into_iter()
        .flatten()
        .map(|output| output.blinded_secret)
        .collect();
    assert!(mint
        .localstore()
        .get_blind_signatures(&blinded)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    assert_eq!(
        mint.localstore()
            .get_melt_quote(&quote.id)
            .await
            .unwrap()
            .as_ref(),
        Some(quote)
    );
}

#[tokio::test]
async fn melt_rejects_conditional_payment_inputs_before_mutation() {
    for resolved in [false, true] {
        let (mint, backend) = test_mint().await;
        let regular = *mint.get_active_keysets().get(&CurrencyUnit::Sat).unwrap();
        let proofs = split_collateral(&mint, resolved).await;
        for outcome in ["YES", "NO"] {
            let quote = melt_quote(&mint).await;
            let request = MeltRequest::new(
                quote.id.clone(),
                vec![proofs[outcome][0].clone()],
                Some(
                    PreMintSecrets::blank(regular, Amount::from(4096))
                        .unwrap()
                        .blinded_messages(),
                ),
            );
            let result = mint.melt(&request).await;
            assert!(
                matches!(result, Err(Error::OutputsMustUseRegularKeyset)),
                "conditional {outcome} input (resolved={resolved}): {result:?}"
            );
            assert_unchanged(&mint, &backend, &request, &quote).await;

            let verification = mint.verify_inputs(request.inputs()).await.unwrap();
            let saga = MeltSaga::new(
                Arc::new(mint.clone()),
                mint.localstore(),
                mint.pubsub_manager(),
            );
            assert!(matches!(
                saga.setup_melt(&request, verification, quote.payment_method.clone())
                    .await,
                Err(Error::OutputsMustUseRegularKeyset)
            ));
            assert_unchanged(&mint, &backend, &request, &quote).await;
        }
    }
}

#[tokio::test]
async fn melt_rejects_conditional_and_mixed_change_before_payment() {
    let (mint, backend) = test_mint().await;
    let regular = *mint.get_active_keysets().get(&CurrencyUnit::Sat).unwrap();
    let source = mint_test_proofs(&mint, Amount::from(4096)).await.unwrap();
    let conditional = split_collateral(&mint, false).await;
    for mixed in [false, true] {
        let quote = melt_quote(&mint).await;
        let mut outputs = PreMintSecrets::blank(conditional["YES"][0].keyset_id, Amount::from(32))
            .unwrap()
            .blinded_messages();
        if mixed {
            outputs.extend(
                PreMintSecrets::blank(regular, Amount::from(32))
                    .unwrap()
                    .blinded_messages(),
            );
        }
        let request = MeltRequest::new(quote.id.clone(), source.clone(), Some(outputs));
        let result = mint.melt(&request).await;
        assert!(
            matches!(result, Err(Error::OutputsMustUseRegularKeyset)),
            "conditional change (mixed={mixed}): {result:?}"
        );
        assert_unchanged(&mint, &backend, &request, &quote).await;
    }
}

#[tokio::test]
async fn melt_accepts_regular_payment_and_change_after_condition_registration() {
    let (mint, backend) = test_mint().await;
    let regular = *mint.get_active_keysets().get(&CurrencyUnit::Sat).unwrap();
    let proofs = mint_test_proofs(&mint, Amount::from(4096)).await.unwrap();
    split_collateral(&mint, false).await;
    let ys = proofs.ys().unwrap();
    let quote = melt_quote(&mint).await;
    let request = MeltRequest::new(
        quote.id.clone(),
        proofs,
        Some(
            PreMintSecrets::blank(regular, Amount::from(4096))
                .unwrap()
                .blinded_messages(),
        ),
    );
    let response = mint.melt(&request).await.unwrap().await.unwrap();
    assert_eq!(response.state(), MeltQuoteState::Paid);
    assert_eq!(backend.payments.load(Ordering::SeqCst), 1);
    assert!(mint
        .localstore()
        .get_proofs_states(&ys)
        .await
        .unwrap()
        .iter()
        .all(|state| *state == Some(cdk_common::State::Spent)));
    let change = mint
        .localstore()
        .get_blind_signatures_for_quote(&quote.id)
        .await
        .unwrap();
    assert!(!change.is_empty());
    assert!(change
        .iter()
        .all(|signature| signature.keyset_id == regular));
}
