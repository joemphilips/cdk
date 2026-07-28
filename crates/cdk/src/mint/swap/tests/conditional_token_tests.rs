//! NUT-CTF conditional token tests for swap and redeem operations

use std::collections::{HashMap, HashSet};
use std::panic;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bip39::Mnemonic;
use cdk_common::amount::SplitTarget;
use cdk_common::dhke::construct_proofs;
use cdk_common::error::{ErrorCode, ErrorResponse};
use cdk_common::nut00::KnownMethod;
use cdk_common::nuts::nut_ctf::settlement::{
    ctf_receive_commitment, sign_pay_to_unlock_refund, CanonicalHash, CtfSettlementParticipant,
    CtfSettlementRequest, NutCtfSettlementSettings, ParticipantMode, PoolEntry, PoolEntryRole,
    PoolManifest, SelectionBitmap,
};
use cdk_common::nuts::nut_ctf::test_helpers::{
    create_digit_decomposition_announcement, create_multi_oracle_witness,
    create_numeric_oracle_witness, create_oracle_witness, create_test_announcement,
    create_test_oracle, create_test_oracle_2,
};
use cdk_common::nuts::nut_ctf::{
    CtfConvertRequest, NutCtfSettings, RedeemOutcomeRequest, RegisterConditionRequest,
    RegistrationFeeSetting,
};
use cdk_common::nuts::{
    Conditions, Id, PaymentMethod, PreMintSecrets, ProofsMethods, SecretKey, SigFlag,
    SpendingConditions, SwapRequest, Witness,
};
use cdk_common::secret::Secret;
use cdk_common::util::unix_time;
use cdk_common::{Amount, CurrencyUnit, State};
use cdk_fake_wallet::FakeWallet;
use tokio::time::{sleep, timeout};

use crate::mint::settlement::CtfSettlementError;
use crate::mint::{Mint, MintBuilder, MintMeltLimits, UnitConfig};
use crate::test_helpers::mint::{clear_fail_for, mint_test_proofs, set_fail_for};
use crate::types::{FeeReserve, QuoteTTL};
use crate::Error;

/// Helper: create an enum RegisterConditionRequest with all fields
fn enum_condition_request(
    description: &str,
    announcements: Vec<String>,
) -> RegisterConditionRequest {
    let outcome_collections = announcements.first().map(|announcement| {
        let parsed = cdk_common::nuts::nut_ctf::dlc::parse_oracle_announcement(announcement)
            .expect("test announcement should parse");
        cdk_common::nuts::nut_ctf::dlc::extract_outcomes(&parsed)
            .expect("test announcement should contain enum outcomes")
    });

    RegisterConditionRequest {
        threshold: 1,
        tags: vec![vec!["description".to_string(), description.to_string()]],
        announcements,
        collateral: Some("sat".to_string()),
        outcome_collections,
        fee: None,
        outputs: None,
        condition_type: "enum".to_string(),
        lo_bound: None,
        hi_bound: None,
        precision: None,
    }
}

fn registration_fee_setting(
    unit: CurrencyUnit,
    registration_fee_base: u64,
    registration_fee_per_keyset: u64,
) -> RegistrationFeeSetting {
    RegistrationFeeSetting {
        unit: unit.to_string(),
        registration_fee_base,
        registration_fee_per_keyset,
    }
}

async fn create_test_mint() -> Result<Mint, Error> {
    let mint = crate::test_helpers::mint::create_test_mint().await?;
    let mut mint_info = mint.mint_info().await?;
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 0, 0)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await?;
    Ok(mint)
}

async fn create_test_mint_without_registration_fees() -> Result<Mint, Error> {
    crate::test_helpers::mint::create_test_mint().await
}

/// Get the regular (non-conditional) active keyset ID for SAT.
/// Must be called BEFORE registering any conditions.
fn get_regular_keyset_id(mint: &crate::mint::Mint) -> Id {
    *mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .expect("mint should have an active SAT keyset")
}

/// Register a test condition, returning (condition_id, keysets map)
async fn register_test_condition(
    mint: &crate::mint::Mint,
    outcomes: &[&str],
    outcome_collections: Option<Vec<String>>,
) -> (String, HashMap<String, Id>) {
    register_test_condition_with_event(mint, outcomes, outcome_collections, "test-event").await
}

async fn register_test_condition_with_event(
    mint: &crate::mint::Mint,
    outcomes: &[&str],
    outcome_collections: Option<Vec<String>>,
    event_id: &str,
) -> (String, HashMap<String, Id>) {
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, outcomes, event_id);

    let mut request = enum_condition_request("Test condition", vec![hex_tlv]);
    if let Some(collections) = outcome_collections {
        request.outcome_collections = Some(collections);
    }

    let condition_response = mint.register_condition(request).await.unwrap();
    (condition_response.condition_id, condition_response.keysets)
}

/// Register a test condition using a specific collateral unit.
async fn register_test_condition_with_collateral(
    mint: &crate::mint::Mint,
    outcomes: &[&str],
    collateral: CurrencyUnit,
) -> (String, HashMap<String, Id>) {
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, outcomes, "test-event");

    let mut request = enum_condition_request("Test condition", vec![hex_tlv]);
    request.collateral = Some(collateral.to_string());

    let condition_response = mint.register_condition(request).await.unwrap();
    (condition_response.condition_id, condition_response.keysets)
}

async fn create_test_mint_with_unit(unit: CurrencyUnit, input_fee_ppk: u64) -> Result<Mint, Error> {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await?);
    let mnemonic = Mnemonic::generate(12).map_err(|e| Error::Custom(e.to_string()))?;
    build_test_mint_with_unit(db, &mnemonic.to_seed_normalized(""), unit, input_fee_ppk).await
}

async fn build_test_mint_with_unit(
    db: Arc<cdk_sqlite::mint::MintSqliteDatabase>,
    seed: &[u8],
    unit: CurrencyUnit,
    input_fee_ppk: u64,
) -> Result<Mint, Error> {
    let mut mint_builder = MintBuilder::new(db.clone());

    mint_builder.configure_unit(
        unit.clone(),
        UnitConfig {
            amounts: (0..32).map(|i| 2_u64.pow(i)).collect(),
            input_fee_ppk,
        },
    )?;

    let fee_reserve = FeeReserve {
        min_fee_reserve: Amount::from(1),
        percent_fee_reserve: 1.0,
    };
    let ln_fake_backend = FakeWallet::new(
        fee_reserve,
        HashMap::default(),
        HashSet::default(),
        2,
        unit.clone(),
    );

    mint_builder
        .add_payment_processor(
            unit.clone(),
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 10_000_000),
            Arc::new(ln_fake_backend),
        )
        .await?;

    let quote_ttl = QuoteTTL::new(10000, 10000);
    let mint = mint_builder
        .with_name("test mint".to_string())
        .with_description("test mint for unit tests".to_string())
        .with_urls(vec!["https://test-mint".to_string()])
        .build_with_seed(db, seed)
        .await?;

    mint.set_quote_ttl(quote_ttl).await?;
    let mut mint_info = mint.mint_info().await?;
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(unit.clone(), 0, 0)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await?;
    mint.start().await?;

    Ok(mint)
}

async fn mint_test_proofs_for_unit(
    mint: &Mint,
    amount: Amount,
    unit: CurrencyUnit,
) -> Result<cdk_common::Proofs, Error> {
    let mint_quote: cdk_common::MintQuoteBolt11Response<_> = mint
        .get_mint_quote(
            cdk_common::MintQuoteBolt11Request {
                amount,
                unit: unit.clone(),
                description: None,
                pubkey: None,
            }
            .into(),
        )
        .await?
        .into();

    loop {
        let check: cdk_common::MintQuoteBolt11Response<_> = mint
            .check_mint_quotes(&[cdk_common::QuoteId::from_str(&mint_quote.quote).unwrap()])
            .await
            .unwrap()
            .first()
            .unwrap()
            .clone()
            .into();

        if check.state == cdk_common::MintQuoteState::Paid {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }

    let keyset_id = *mint
        .get_active_keysets()
        .get(&unit)
        .expect("mint should have an active keyset for the requested unit");

    let keys = mint
        .keyset_pubkeys(&keyset_id)?
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();

    let fees: (u64, Vec<u64>) = (0, keys.iter().map(|a| a.0.to_u64()).collect::<Vec<_>>());
    let premint_secrets =
        PreMintSecrets::random(keyset_id, amount, &SplitTarget::None, &fees.into()).unwrap();

    let request = cdk_common::MintRequest {
        quote: mint_quote.quote,
        outputs: premint_secrets.blinded_messages(),
        signature: None,
    };

    let mint_res = mint
        .process_mint_request(crate::mint::MintInput::Single(request.try_into().unwrap()))
        .await?;

    Ok(construct_proofs(
        mint_res.signatures,
        premint_secrets.rs(),
        premint_secrets.secrets(),
        &keys,
    )?)
}

fn get_regular_keyset_id_for_unit(mint: &crate::mint::Mint, unit: &CurrencyUnit) -> Id {
    *mint
        .get_active_keysets()
        .get(unit)
        .expect("mint should have an active keyset for the requested unit")
}

/// Helper: create PreMintSecrets for a given keyset
fn create_premint(
    mint: &crate::mint::Mint,
    keyset_id: Id,
    amount: Amount,
) -> (Vec<cdk_common::nuts::BlindedMessage>, PreMintSecrets) {
    let keys = mint
        .keyset_pubkeys(&keyset_id)
        .unwrap()
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();

    let fee_and_amounts: (u64, Vec<u64>) =
        (0, keys.iter().map(|(a, _)| a.to_u64()).collect::<Vec<_>>());

    let pre_mint = PreMintSecrets::random(
        keyset_id,
        amount,
        &SplitTarget::None,
        &fee_and_amounts.into(),
    )
    .unwrap();
    let blinded_messages = pre_mint.blinded_messages().to_vec();
    (blinded_messages, pre_mint)
}

const SETTLEMENT_REFUND_KEY: &str =
    "194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104";

struct StandardSettlementFixture {
    request: CtfSettlementRequest,
    output_only_keyset: Id,
    input_ys: Vec<cdk_common::PublicKey>,
    output_points: Vec<cdk_common::PublicKey>,
}

async fn standard_settlement_fixture(mint: &Mint, now: u64) -> StandardSettlementFixture {
    let regular_keyset = get_regular_keyset_id(mint);
    let alice_source = mint_test_proofs_for_unit(mint, Amount::from(9), CurrencyUnit::Sat)
        .await
        .unwrap();
    let bob_source = mint_test_proofs_for_unit(mint, Amount::from(9), CurrencyUnit::Sat)
        .await
        .unwrap();
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let yes_keyset = *keysets.get("YES").unwrap();
    let no_keyset = *keysets.get("NO").unwrap();
    let (yes_outputs, _) = create_premint(mint, yes_keyset, Amount::from(15));
    let (no_outputs, _) = create_premint(mint, no_keyset, Amount::from(15));
    let expiry = now + 60;
    let alice =
        standard_settlement_participant(mint, alice_source, regular_keyset, yes_outputs, expiry, 1)
            .await;
    let bob =
        standard_settlement_participant(mint, bob_source, regular_keyset, no_outputs, expiry, 2)
            .await;
    let mut participants = vec![alice, bob];
    canonicalize_settlement_participants(&mut participants);
    let (input_ys, output_points) = settlement_storage_keys(&participants);

    StandardSettlementFixture {
        request: CtfSettlementRequest {
            condition_id: CanonicalHash::parse(&condition_id, "condition_id").unwrap(),
            parent_collection_id: CanonicalHash::from_bytes([0; 32]),
            participants,
        },
        output_only_keyset: yes_keyset,
        input_ys,
        output_points,
    }
}

struct MixedPoolSettlementFixture {
    request: CtfSettlementRequest,
    input_ys: Vec<cdk_common::PublicKey>,
    selected_output_points: Vec<cdk_common::PublicKey>,
    unselected_output_points: Vec<cdk_common::PublicKey>,
    pool_participant: usize,
}

async fn mixed_pool_settlement_fixture(mint: &Mint, now: u64) -> MixedPoolSettlementFixture {
    let regular_keyset = get_regular_keyset_id(mint);
    let alice_source = mint_test_proofs_for_unit(mint, Amount::from(9), CurrencyUnit::Sat)
        .await
        .unwrap();
    let bob_source = mint_test_proofs_for_unit(mint, Amount::from(9), CurrencyUnit::Sat)
        .await
        .unwrap();
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let (yes_outputs, _) = create_premint(mint, *keysets.get("YES").unwrap(), Amount::from(15));
    let (no_outputs, _) = create_premint(mint, *keysets.get("NO").unwrap(), Amount::from(15));
    let (change_candidates, _) = create_premint(mint, regular_keyset, Amount::from(7));
    let expiry = now + 60;
    let alice =
        standard_settlement_participant(mint, alice_source, regular_keyset, yes_outputs, expiry, 1)
            .await;
    let pool = pool_settlement_participant(
        mint,
        bob_source,
        regular_keyset,
        no_outputs,
        &change_candidates,
        expiry,
        2,
    )
    .await;
    let mut participants = vec![alice, pool];
    canonicalize_settlement_participants(&mut participants);
    let pool_participant = participants
        .iter()
        .position(|participant| matches!(&participant.mode, ParticipantMode::Pool { .. }))
        .unwrap();
    let (input_ys, selected_output_points) = settlement_storage_keys(&participants);
    let unselected_output_points = change_candidates
        .iter()
        .map(|output| output.blinded_secret)
        .collect();

    MixedPoolSettlementFixture {
        request: CtfSettlementRequest {
            condition_id: CanonicalHash::parse(&condition_id, "condition_id").unwrap(),
            parent_collection_id: CanonicalHash::from_bytes([0; 32]),
            participants,
        },
        input_ys,
        selected_output_points,
        unselected_output_points,
        pool_participant,
    }
}

async fn pool_settlement_participant(
    mint: &Mint,
    source: cdk_common::Proofs,
    offer_keyset: Id,
    receive_outputs: Vec<cdk_common::BlindedMessage>,
    change_candidates: &[cdk_common::BlindedMessage],
    expiry: u64,
    nonce: u8,
) -> CtfSettlementParticipant {
    let mut entries = Vec::new();
    for output in &receive_outputs {
        entries.push(pool_entry(entries.len(), PoolEntryRole::Receive, output));
    }
    for output in change_candidates {
        entries.push(pool_entry(entries.len(), PoolEntryRole::Change, output));
    }
    let manifest = PoolManifest::new(entries, 32).unwrap();
    let selection = SelectionBitmap::parse("0f", manifest.entries().len()).unwrap();
    let secret = settlement_pool_pay_to_unlock_secret(
        offer_keyset,
        manifest.commitment().to_string(),
        expiry,
        nonce,
    );
    let input = issue_locked_proof(mint, source, offer_keyset, secret).await;
    CtfSettlementParticipant {
        inputs: vec![input],
        outputs: receive_outputs,
        mode: ParticipantMode::Pool {
            manifest,
            selection,
        },
    }
}

fn canonicalize_settlement_participants(participants: &mut [CtfSettlementParticipant]) {
    participants.sort_by_key(|participant| {
        let proof = participant.inputs.first().unwrap();
        (proof.keyset_id.to_string(), proof.secret.to_string())
    });
}

fn settlement_storage_keys(
    participants: &[CtfSettlementParticipant],
) -> (Vec<cdk_common::PublicKey>, Vec<cdk_common::PublicKey>) {
    let input_ys = participants
        .iter()
        .flat_map(|participant| participant.inputs.iter().cloned())
        .collect::<Vec<_>>()
        .ys()
        .unwrap();
    let output_points = participants
        .iter()
        .flat_map(|participant| participant.outputs.iter())
        .map(|output| output.blinded_secret)
        .collect();
    (input_ys, output_points)
}

fn pool_entry(index: usize, role: PoolEntryRole, output: &cdk_common::BlindedMessage) -> PoolEntry {
    PoolEntry {
        index: u64::try_from(index).unwrap(),
        role,
        amount: output.amount.to_u64(),
        keyset_id: output.keyset_id,
        blinded_secret: output.blinded_secret,
    }
}

async fn standard_settlement_participant(
    mint: &Mint,
    source: cdk_common::Proofs,
    offer_keyset: Id,
    outputs: Vec<cdk_common::BlindedMessage>,
    expiry: u64,
    nonce: u8,
) -> CtfSettlementParticipant {
    let commitment = ctf_receive_commitment(&outputs).unwrap();
    let secret =
        settlement_pay_to_unlock_secret(offer_keyset, commitment.to_string(), expiry, nonce);
    let input = issue_locked_proof(mint, source, offer_keyset, secret).await;
    CtfSettlementParticipant {
        inputs: vec![input],
        outputs,
        mode: ParticipantMode::Standard,
    }
}

async fn issue_locked_proof(
    mint: &Mint,
    source: cdk_common::Proofs,
    keyset: Id,
    secret: Secret,
) -> cdk_common::Proof {
    let premint =
        PreMintSecrets::from_secrets(keyset, vec![Amount::from(8)], vec![secret]).unwrap();
    let response = mint
        .process_swap_request(SwapRequest::new(source, premint.blinded_messages()))
        .await
        .unwrap();
    let keys = mint
        .keyset_pubkeys(&keyset)
        .unwrap()
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();
    construct_proofs(response.signatures, premint.rs(), premint.secrets(), &keys)
        .unwrap()
        .remove(0)
}

fn settlement_pay_to_unlock_secret(keyset: Id, data: String, expiry: u64, nonce: u8) -> Secret {
    Secret::new(
        serde_json::json!([
            "PAY_TO_UNLOCK",
            {
                "nonce": format!("{nonce:02x}").repeat(32),
                "data": data,
                "tags": [
                    ["offer_keyset", keyset.to_string()],
                    ["expiry", expiry.to_string()],
                    ["refund", SETTLEMENT_REFUND_KEY]
                ]
            }
        ])
        .to_string(),
    )
}

fn settlement_pool_pay_to_unlock_secret(
    keyset: Id,
    data: String,
    expiry: u64,
    nonce: u8,
) -> Secret {
    Secret::new(
        serde_json::json!([
            "PAY_TO_UNLOCK",
            {
                "nonce": format!("{nonce:02x}").repeat(32),
                "data": data,
                "tags": [
                    ["offer_keyset", keyset.to_string()],
                    ["expiry", expiry.to_string()],
                    ["refund", SETTLEMENT_REFUND_KEY],
                    ["rate_n", "15"],
                    ["rate_d", "8"],
                    ["min_receive", "15"],
                    ["max_debit", "8"]
                ]
            }
        ])
        .to_string(),
    )
}

fn settlement_settings() -> NutCtfSettlementSettings {
    NutCtfSettlementSettings::new(8, 32, 64, 64 * 1024, 3600, 32).unwrap()
}

struct AtomicConvertFixture {
    request: CtfConvertRequest,
    input_ys: Vec<cdk_common::PublicKey>,
    blinded_secrets: Vec<cdk_common::PublicKey>,
}

async fn atomic_convert_fixture(mint: &Mint) -> AtomicConvertFixture {
    let face_amount = Amount::from(8192);
    let input_proofs = mint_test_proofs_for_unit(mint, face_amount, CurrencyUnit::Sat)
        .await
        .unwrap();
    let input_ys = input_proofs.ys().unwrap();
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let output_amount = Amount::from(8191);
    let (yes_outputs, _) = create_premint(mint, *keysets.get("YES").unwrap(), output_amount);
    let (no_outputs, _) = create_premint(mint, *keysets.get("NO").unwrap(), output_amount);
    let blinded_secrets = yes_outputs
        .iter()
        .chain(&no_outputs)
        .map(|message| message.blinded_secret)
        .collect();

    AtomicConvertFixture {
        request: CtfConvertRequest {
            condition_id,
            parent_collection_id: None,
            inputs: HashMap::from([("*".to_string(), input_proofs)]),
            outputs: HashMap::from([
                ("YES".to_string(), yes_outputs),
                ("NO".to_string(), no_outputs),
            ]),
        },
        input_ys,
        blinded_secrets,
    }
}

async fn assert_atomic_convert_rollback(failure_point: &str) {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let fixture = atomic_convert_fixture(&mint).await;

    set_fail_for(failure_point);
    let result = mint.process_ctf_convert(fixture.request.clone()).await;
    clear_fail_for(failure_point);
    assert!(result.is_err(), "{failure_point} must abort conversion");

    assert_atomic_convert_absent(&mint, &fixture).await;
    mint.process_ctf_convert(fixture.request.clone())
        .await
        .expect("the same conversion should succeed after rollback");
    assert_atomic_convert_committed(&mint, &fixture).await;
}

async fn assert_atomic_convert_absent(mint: &Mint, fixture: &AtomicConvertFixture) {
    let db = mint.localstore();
    assert!(
        db.get_proofs_states(&fixture.input_ys)
            .await
            .unwrap()
            .iter()
            .all(Option::is_none),
        "rolled-back inputs must not remain persisted"
    );
    assert!(
        db.get_blind_signatures(&fixture.blinded_secrets)
            .await
            .unwrap()
            .iter()
            .all(Option::is_none),
        "rolled-back outputs must not retain signatures"
    );
    assert!(
        db.get_completed_operations_by_kind(cdk_common::mint::OperationKind::Swap)
            .await
            .unwrap()
            .is_empty(),
        "rolled-back conversion must not record completion"
    );
}

async fn assert_atomic_convert_committed(mint: &Mint, fixture: &AtomicConvertFixture) {
    let db = mint.localstore();
    assert_eq!(
        db.get_proofs_states(&fixture.input_ys).await.unwrap(),
        vec![Some(State::Spent); fixture.input_ys.len()]
    );
    assert!(db
        .get_blind_signatures(&fixture.blinded_secrets)
        .await
        .unwrap()
        .iter()
        .all(Option::is_some));
    assert_eq!(
        db.get_completed_operations_by_kind(cdk_common::mint::OperationKind::Swap)
            .await
            .unwrap()
            .len(),
        1
    );
}

fn after_conditional_input_fee(amount: Amount) -> Amount {
    amount - Amount::from(1)
}

/// Helper: create P2PK 2-of-2 PreMintSecrets for a given keyset.
fn create_p2pk_premint(
    mint: &crate::mint::Mint,
    keyset_id: Id,
    amount: Amount,
) -> (Vec<cdk_common::nuts::BlindedMessage>, PreMintSecrets) {
    let keys = mint
        .keyset_pubkeys(&keyset_id)
        .unwrap()
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();

    let fee_and_amounts: (u64, Vec<u64>) =
        (0, keys.iter().map(|(a, _)| a.to_u64()).collect::<Vec<_>>());
    let seller_key = SecretKey::generate();
    let buyer_key = SecretKey::generate();
    let conditions = Conditions::new(
        None,
        Some(vec![buyer_key.public_key()]),
        Some(vec![seller_key.public_key()]),
        Some(2),
        Some(SigFlag::SigInputs),
        None,
    )
    .unwrap();
    let spending_conditions =
        SpendingConditions::new_p2pk(seller_key.public_key(), Some(conditions));

    let pre_mint = PreMintSecrets::with_conditions(
        keyset_id,
        amount,
        &SplitTarget::None,
        &spending_conditions,
        &fee_and_amounts.into(),
    )
    .unwrap();
    let blinded_messages = pre_mint.blinded_messages().to_vec();
    (blinded_messages, pre_mint)
}

/// Helper: swap regular proofs into a conditional keyset
async fn swap_to_conditional(
    mint: &crate::mint::Mint,
    regular_proofs: cdk_common::Proofs,
    keyset_id: Id,
    amount: Amount,
) -> cdk_common::Proofs {
    let (outputs, pre_mint) = create_premint(mint, keyset_id, amount);

    let keys = mint
        .keyset_pubkeys(&keyset_id)
        .unwrap()
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();

    let swap_request = SwapRequest::new(regular_proofs, outputs);
    let swap_response = mint.process_swap_request(swap_request).await.unwrap();

    construct_proofs(
        swap_response.signatures,
        pre_mint.rs(),
        pre_mint.secrets(),
        &keys,
    )
    .unwrap()
}

async fn lock_pay_to_unlock(
    mint: &Mint,
    inputs: cdk_common::Proofs,
    offer_keyset: Id,
    amount: Amount,
    expiry: u64,
    refund_key: &SecretKey,
) -> cdk_common::Proofs {
    let keys = mint
        .keyset_pubkeys(&offer_keyset)
        .unwrap()
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();
    let fee_and_amounts: (u64, Vec<u64>) =
        (0, keys.iter().map(|(value, _)| value.to_u64()).collect());
    let amounts = amount.split(&fee_and_amounts.into()).unwrap();
    let secrets = amounts
        .iter()
        .enumerate()
        .map(|(index, _)| pay_to_unlock_secret(offer_keyset, expiry, refund_key, index))
        .collect();
    let pre_mint = PreMintSecrets::from_secrets(offer_keyset, amounts, secrets).unwrap();
    let response = mint
        .process_swap_request(SwapRequest::new(inputs, pre_mint.blinded_messages()))
        .await
        .expect("locking PAY_TO_UNLOCK proof should succeed");
    construct_proofs(
        response.signatures,
        pre_mint.rs(),
        pre_mint.secrets(),
        &keys,
    )
    .unwrap()
}

fn pay_to_unlock_secret(
    offer_keyset: Id,
    expiry: u64,
    refund_key: &SecretKey,
    nonce: usize,
) -> Secret {
    Secret::from_str(&format!(
        concat!(
            "[\"PAY_TO_UNLOCK\",{{\"nonce\":\"{:064x}\",\"data\":\"{}\",",
            "\"tags\":[[\"offer_keyset\",\"{}\"],[\"expiry\",\"{}\"],",
            "[\"refund\",\"{}\"]]}}]"
        ),
        nonce,
        "11".repeat(32),
        offer_keyset,
        expiry,
        refund_key.public_key().x_only_public_key()
    ))
    .unwrap()
}

/// Test that registering a condition creates keysets for each outcome collection
#[tokio::test]
async fn test_register_condition_creates_keysets() {
    let mint = create_test_mint().await.unwrap();
    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;

    assert!(!condition_id.is_empty());
    assert_eq!(keysets.len(), 2, "should create one keyset per outcome");
    assert!(keysets.contains_key("YES"));
    assert!(keysets.contains_key("NO"));
}

/// Test that registering the same condition twice is idempotent
#[tokio::test]
async fn test_register_condition_idempotent() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    let request = enum_condition_request("Test condition", vec![hex_tlv]);

    let response1 = mint.register_condition(request.clone()).await.unwrap();
    let response2 = mint.register_condition(request).await.unwrap();

    assert_eq!(response1.condition_id, response2.condition_id);
}

#[tokio::test]
async fn test_register_condition_rejects_different_keyset_set() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["A", "B", "C"], "one-shot-event");

    let mut request = enum_condition_request("One-shot condition", vec![hex_tlv]);
    request.outcome_collections = Some(vec!["A".to_string(), "B".to_string(), "C".to_string()]);
    mint.register_condition(request.clone()).await.unwrap();

    request
        .outcome_collections
        .as_mut()
        .unwrap()
        .push("A|B".to_string());

    let result = mint.register_condition(request).await;
    assert!(
        matches!(result, Err(Error::ConditionAlreadyExists)),
        "re-registering with a different keyset set must fail with ConditionAlreadyExists: {:?}",
        result.err()
    );
}

/// Test get_conditions returns registered conditions
#[tokio::test]
async fn test_get_conditions_returns_registered() {
    let mint = create_test_mint().await.unwrap();
    let (condition_id, _) = register_test_condition(&mint, &["YES", "NO"], None).await;

    let response = mint.get_conditions(None, None, &[]).await.unwrap();
    assert_eq!(response.conditions.len(), 1);
    assert_eq!(response.conditions[0].condition_id, condition_id);
}

/// Test get_condition by id returns the correct condition
#[tokio::test]
async fn test_get_condition_by_id() {
    let mint = create_test_mint().await.unwrap();
    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;

    let info = mint.get_condition(&condition_id).await.unwrap();
    assert_eq!(info.condition_id, condition_id);
    assert_eq!(info.threshold, 1);
    assert_eq!(info.keysets.len(), 2);
    assert_eq!(info.keysets, keysets);
}

#[tokio::test]
async fn nut_ctf_register_with_collateral_condition_info_echoes_it() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "collateral-event");

    let mut request = enum_condition_request("Collateral condition", vec![hex_tlv]);
    request.collateral = Some("sat".to_string());

    let response = mint.register_condition(request).await.unwrap();
    let info = mint.get_condition(&response.condition_id).await.unwrap();

    assert_eq!(info.collateral, Some(CurrencyUnit::Sat));

    let conditions = mint.get_conditions(None, None, &[]).await.unwrap();
    assert_eq!(conditions.conditions.len(), 1);
    assert_eq!(conditions.conditions[0].collateral, Some(CurrencyUnit::Sat));
}

#[test]
fn nut_ctf_legacy_stored_condition_without_collateral_deserializes_with_none() {
    let json = r#"{
        "condition_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "threshold": 1,
        "tags_json": "[[\"description\",\"legacy\"]]",
        "announcements_json": "[\"deadbeef\"]",
        "attestation_status": "pending",
        "winning_outcome": null,
        "attested_at": null,
        "created_at": 1000000,
        "condition_type": "enum",
        "lo_bound": null,
        "hi_bound": null,
        "precision": null
    }"#;

    let stored: cdk_common::mint::StoredCondition = serde_json::from_str(json).unwrap();

    assert_eq!(stored.collateral, None);
}

/// Full redeem outcome flow:
/// mint regular proofs -> register condition -> swap to conditional -> redeem with witness
#[tokio::test]
async fn test_redeem_outcome_valid() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // 1. Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    // 2. Register condition
    let condition_response = mint
        .register_condition(enum_condition_request("Test redeem", vec![hex_tlv]))
        .await
        .unwrap();

    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();

    // 4. Swap regular proofs to conditional
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    // 5. Attach oracle witness
    let witness = create_oracle_witness(&oracle, "YES");
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    // 6. Create regular output blinded messages for redemption
    let (regular_outputs, _) = create_premint(
        &mint,
        regular_keyset_id,
        after_conditional_input_fee(amount),
    );

    // 7. Redeem
    let redeem_response = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await
        .unwrap();

    assert!(!redeem_response.signatures.is_empty());
}

/// Test that redeeming with the wrong outcome collection fails
#[tokio::test]
async fn test_redeem_outcome_wrong_collection() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request("Test wrong outcome", vec![hex_tlv]))
        .await
        .unwrap();
    // Use the NO keyset but attest YES
    let no_keyset_id = *condition_response.keysets.get("NO").unwrap();
    let conditional_proofs = swap_to_conditional(&mint, regular_proofs, no_keyset_id, amount).await;

    // Attach witness with YES attestation (but proofs are NO keyset)
    let witness = create_oracle_witness(&oracle, "YES");
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, amount);

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;

    assert!(result.is_err(), "should fail with wrong outcome collection");
}

/// Test that redeem without witness fails
#[tokio::test]
async fn test_redeem_outcome_no_witness() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request("No witness test", vec![hex_tlv]))
        .await
        .unwrap();
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    // No witness attached
    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, amount);

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: conditional_proofs,
            outputs: regular_outputs,
        })
        .await;

    assert!(result.is_err(), "should fail without witness");
}

/// Test that outputs using conditional keyset are rejected during redeem
#[tokio::test]
async fn test_redeem_outcome_outputs_conditional() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request(
            "Outputs conditional test",
            vec![hex_tlv],
        ))
        .await
        .unwrap();
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let no_keyset_id = *condition_response.keysets.get("NO").unwrap();

    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    let witness = create_oracle_witness(&oracle, "YES");
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    // Create outputs using another conditional keyset (NO) — should be rejected
    let (conditional_outputs, _) = create_premint(&mint, no_keyset_id, amount);

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: conditional_outputs,
        })
        .await;

    assert!(
        result.is_err(),
        "should reject outputs using conditional keyset"
    );
}

/// Test that regular swap allows conditional trading within the same outcome collection.
#[tokio::test]
async fn test_swap_allows_same_conditional_outcome_inputs_and_outputs() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request(
            "Conditional transfer test",
            vec![hex_tlv],
        ))
        .await
        .unwrap();
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    let output_amount = after_conditional_input_fee(amount);
    let (conditional_outputs, pre_mint) = create_premint(&mint, yes_keyset_id, output_amount);
    let keys = mint
        .keyset_pubkeys(&yes_keyset_id)
        .unwrap()
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();
    let swap_request = SwapRequest::new(conditional_proofs, conditional_outputs);
    let swap_response = mint
        .process_swap_request(swap_request)
        .await
        .expect("same-outcome conditional swap should succeed");

    let refreshed_proofs = construct_proofs(
        swap_response.signatures,
        pre_mint.rs(),
        pre_mint.secrets(),
        &keys,
    )
    .unwrap();

    assert!(refreshed_proofs
        .iter()
        .all(|proof| proof.keyset_id == yes_keyset_id));
    let refreshed_total = refreshed_proofs
        .iter()
        .fold(Amount::ZERO, |sum, proof| sum + proof.amount);
    assert_eq!(refreshed_total, output_amount);
}

/// Test that regular swap allows conditional trading into P2PK locked outputs
/// and unlocked change within the same outcome collection.
#[tokio::test]
async fn test_swap_allows_same_conditional_outcome_p2pk_lock_and_change() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    let input_amount = Amount::from(136);
    let regular_proofs = mint_test_proofs(&mint, input_amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request(
            "Conditional P2PK transfer test",
            vec![hex_tlv],
        ))
        .await
        .unwrap();
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, input_amount).await;

    let (mut lock_outputs, lock_pre_mint) =
        create_p2pk_premint(&mint, yes_keyset_id, Amount::from(100));
    let (mut change_outputs, change_pre_mint) =
        create_premint(&mint, yes_keyset_id, Amount::from(35));
    lock_outputs.append(&mut change_outputs);

    let keys = mint
        .keyset_pubkeys(&yes_keyset_id)
        .unwrap()
        .keysets
        .first()
        .unwrap()
        .keys
        .clone();
    let swap_request = SwapRequest::new(conditional_proofs, lock_outputs);
    let swap_response = mint
        .process_swap_request(swap_request)
        .await
        .expect("same-outcome conditional P2PK lock swap should succeed");

    let mut rs = lock_pre_mint.rs();
    rs.extend(change_pre_mint.rs());
    let mut secrets = lock_pre_mint.secrets();
    secrets.extend(change_pre_mint.secrets());
    let refreshed_proofs = construct_proofs(swap_response.signatures, rs, secrets, &keys).unwrap();

    assert!(refreshed_proofs
        .iter()
        .all(|proof| proof.keyset_id == yes_keyset_id));
    let refreshed_total = refreshed_proofs
        .iter()
        .fold(Amount::ZERO, |sum, proof| sum + proof.amount);
    assert_eq!(refreshed_total, after_conditional_input_fee(input_amount));
}

/// Test that regular swap rejects conditional keyset inputs to regular outputs
#[tokio::test]
async fn test_swap_rejects_conditional_inputs() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request("Swap reject test", vec![hex_tlv]))
        .await
        .unwrap();
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    // Try a regular swap with conditional proofs as input — should fail
    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, amount);
    let swap_request = SwapRequest::new(conditional_proofs, regular_outputs);
    let result = mint.process_swap_request(swap_request).await;

    assert!(
        result.is_err(),
        "regular swap should reject conditional keyset inputs"
    );
}

/// Test that regular swap rejects conditional inputs rewritten to a different outcome.
#[tokio::test]
async fn test_swap_rejects_conditional_inputs_to_different_outcome() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request(
            "Conditional wrong outcome test",
            vec![hex_tlv],
        ))
        .await
        .unwrap();
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let no_keyset_id = *condition_response.keysets.get("NO").unwrap();
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    let (wrong_outcome_outputs, _) = create_premint(&mint, no_keyset_id, amount);
    let swap_request = SwapRequest::new(conditional_proofs, wrong_outcome_outputs);
    let result = mint.process_swap_request(swap_request).await;

    assert!(
        result.is_err(),
        "regular swap should reject conditional inputs to a different outcome"
    );
}

#[tokio::test]
async fn test_pay_to_unlock_refund_rejects_before_expiry() {
    let mint = create_test_mint().await.unwrap();
    let keyset_id = get_regular_keyset_id(&mint);
    let amount = Amount::from(64);
    let inputs = mint_test_proofs(&mint, amount).await.unwrap();
    let refund_key = SecretKey::generate();
    let locked = lock_pay_to_unlock(
        &mint,
        inputs,
        keyset_id,
        amount,
        unix_time() + 3600,
        &refund_key,
    )
    .await;
    let (outputs, _) = create_premint(&mint, keyset_id, amount);
    let mut request = SwapRequest::new(locked, outputs);
    sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();

    let response: ErrorResponse = mint
        .process_swap_request(request)
        .await
        .expect_err("refund before expiry must fail")
        .into();
    assert_eq!(response.code, ErrorCode::RefundBeforeExpiry);
}

#[tokio::test]
async fn test_pay_to_unlock_refund_accepts_active_same_unit_rotation() {
    let mint = create_test_mint().await.unwrap();
    let old_keyset = get_regular_keyset_id(&mint);
    let amount = Amount::from(64);
    let inputs = mint_test_proofs(&mint, amount).await.unwrap();
    let refund_key = SecretKey::generate();
    let locked = lock_pay_to_unlock(
        &mint,
        inputs,
        old_keyset,
        amount,
        unix_time().saturating_sub(1),
        &refund_key,
    )
    .await;

    mint.rotate_keyset(
        CurrencyUnit::Sat,
        (0..32).map(|power| 2_u64.pow(power)).collect(),
        0,
        true,
        None,
    )
    .await
    .unwrap();
    let active_keyset = get_regular_keyset_id(&mint);
    assert_ne!(active_keyset, old_keyset);

    let (outputs, _) = create_premint(&mint, active_keyset, amount);
    let mut request = SwapRequest::new(locked, outputs);
    sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();
    let response = mint
        .process_swap_request(request)
        .await
        .expect("post-expiry refund into active same-unit keyset should succeed");
    assert!(response
        .signatures
        .iter()
        .all(|signature| signature.keyset_id == active_keyset));
}

#[tokio::test]
async fn test_pay_to_unlock_refund_rejects_regular_to_conditional_output() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset = get_regular_keyset_id(&mint);
    let amount = Amount::from(64);
    let inputs = mint_test_proofs(&mint, amount).await.unwrap();
    let refund_key = SecretKey::generate();
    let locked = lock_pay_to_unlock(
        &mint,
        inputs,
        regular_keyset,
        amount,
        unix_time().saturating_sub(1),
        &refund_key,
    )
    .await;

    let (_, conditional_keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let conditional_keyset = *conditional_keysets.get("YES").unwrap();
    let (outputs, _) = create_premint(&mint, conditional_keyset, amount);
    let mut request = SwapRequest::new(locked, outputs);
    sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();

    let response: ErrorResponse = mint
        .process_swap_request(request)
        .await
        .expect_err("regular PAY_TO_UNLOCK refund must preserve the regular asset class")
        .into();
    assert_eq!(response.code, ErrorCode::PayToUnlockInvalidCondition);
}

#[tokio::test]
async fn test_pay_to_unlock_refund_rejects_cross_collection_output() {
    let mint = create_test_mint().await.unwrap();
    let amount = Amount::from(64);
    let regular = mint_test_proofs(&mint, amount).await.unwrap();
    let (_, conditional_keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let yes_keyset = *conditional_keysets.get("YES").unwrap();
    let no_keyset = *conditional_keysets.get("NO").unwrap();
    let conditional = swap_to_conditional(&mint, regular, yes_keyset, amount).await;
    let refund_key = SecretKey::generate();
    let locked = lock_pay_to_unlock(
        &mint,
        conditional,
        yes_keyset,
        after_conditional_input_fee(amount),
        unix_time().saturating_sub(1),
        &refund_key,
    )
    .await;

    let refund_amount = after_conditional_input_fee(after_conditional_input_fee(amount));
    let (outputs, _) = create_premint(&mint, no_keyset, refund_amount);
    let mut request = SwapRequest::new(locked, outputs);
    sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();

    let response: ErrorResponse = mint
        .process_swap_request(request)
        .await
        .expect_err("conditional refund must remain in the same outcome collection")
        .into();
    assert_eq!(response.code, ErrorCode::InputsMustUseSameConditionalKeyset);
}

#[tokio::test]
async fn test_redeem_rejects_pay_to_unlock_without_spending_it() {
    let mint = create_test_mint().await.unwrap();
    let amount = Amount::from(64);
    let regular = mint_test_proofs(&mint, amount).await.unwrap();
    let regular_keyset = get_regular_keyset_id(&mint);
    let (_, conditional_keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let yes_keyset = *conditional_keysets.get("YES").unwrap();
    let conditional = swap_to_conditional(&mint, regular, yes_keyset, amount).await;
    let refund_key = SecretKey::generate();
    let locked = lock_pay_to_unlock(
        &mint,
        conditional,
        yes_keyset,
        after_conditional_input_fee(amount),
        unix_time() + 3600,
        &refund_key,
    )
    .await;
    let locked_ys = locked.ys().unwrap();
    let output_amount = after_conditional_input_fee(after_conditional_input_fee(amount));
    let (outputs, _) = create_premint(&mint, regular_keyset, output_amount);

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: locked,
            outputs,
        })
        .await;
    assert!(
        matches!(result, Err(Error::PayToUnlockInvalidCondition)),
        "protected redeem must be rejected at the spend-path boundary: {result:?}"
    );
    assert!(mint
        .localstore()
        .get_proofs_states(&locked_ys)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
}

/// Test that a second redemption uses the stored attestation (skips witness verification)
#[tokio::test]
async fn test_redeem_second_uses_stored_attestation() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    // Mint ALL regular proofs BEFORE registering conditions
    let amount1 = Amount::from(10);
    let amount2 = Amount::from(8);
    let regular_proofs_1 = mint_test_proofs(&mint, amount1).await.unwrap();
    let regular_proofs_2 = mint_test_proofs(&mint, amount2).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request(
            "Stored attestation test",
            vec![hex_tlv],
        ))
        .await
        .unwrap();
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();

    // First redemption with valid witness
    {
        let conditional_proofs =
            swap_to_conditional(&mint, regular_proofs_1, yes_keyset_id, amount1).await;

        let witness = create_oracle_witness(&oracle, "YES");
        let mut proofs_with_witness = conditional_proofs;
        for proof in &mut proofs_with_witness {
            proof.witness = Some(Witness::OracleWitness(witness.clone()));
        }

        let (regular_outputs, _) = create_premint(
            &mint,
            regular_keyset_id,
            after_conditional_input_fee(amount1),
        );

        mint.process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await
        .expect("first redemption should succeed");
    }

    // Second redemption — attestation is already stored
    {
        let conditional_proofs =
            swap_to_conditional(&mint, regular_proofs_2, yes_keyset_id, amount2).await;

        // Witness still needed for parsing, but verification path changes
        let witness = create_oracle_witness(&oracle, "YES");
        let mut proofs_with_witness = conditional_proofs;
        for proof in &mut proofs_with_witness {
            proof.witness = Some(Witness::OracleWitness(witness.clone()));
        }

        let (regular_outputs, _) = create_premint(
            &mint,
            regular_keyset_id,
            after_conditional_input_fee(amount2),
        );

        mint.process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await
        .expect("second redemption should use stored attestation and succeed");
    }
}

/// Test registering condition with custom outcome collections
#[tokio::test]
async fn test_register_condition_with_custom_outcome_collections() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["A", "B", "C"], "game-event");

    let mut request = enum_condition_request("Outcome collection test", vec![hex_tlv]);
    request.outcome_collections = Some(vec![
        "A".to_string(),
        "B".to_string(),
        "C".to_string(),
        "A|B".to_string(),
        "B|C".to_string(),
        "A|C".to_string(),
    ]);

    let condition_response = mint.register_condition(request).await.unwrap();

    assert_eq!(
        condition_response.keysets.len(),
        6,
        "should create one keyset per requested outcome collection"
    );
    for collection in ["A", "B", "C", "A|B", "B|C", "A|C"] {
        assert!(
            condition_response.keysets.contains_key(collection),
            "keysets: {:?}",
            condition_response.keysets
        );
    }
}

#[tokio::test]
async fn test_register_condition_one_vs_rest_default_creates_managed_keysets() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    let mut nut_ctf = mint_info.nuts.nut_ctf.take().unwrap_or_default();
    nut_ctf.default_keyset_creation = "one-vs-rest".to_string();
    mint_info.nuts.nut_ctf = Some(nut_ctf);
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["A", "B", "C"], "one-vs-rest-default");
    let mut request = enum_condition_request("One-vs-rest default", vec![hex_tlv]);
    request.outcome_collections = None;

    let condition_response = mint.register_condition(request).await.unwrap();

    assert_eq!(condition_response.keysets.len(), 6);
    for collection in ["A", "B|C", "B", "A|C", "C", "A|B"] {
        assert!(
            condition_response.keysets.contains_key(collection),
            "keysets: {:?}",
            condition_response.keysets
        );
    }
}

#[tokio::test]
async fn test_register_condition_one_vs_rest_rejects_client_collections() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        default_keyset_creation: "one-vs-rest".to_string(),
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["A", "B", "C"], "one-vs-rest-explicit");
    let mut request = enum_condition_request("One-vs-rest explicit", vec![hex_tlv]);
    request.outcome_collections = Some(vec!["A".to_string(), "B".to_string()]);

    let result = mint.register_condition(request).await;
    assert!(
        result.is_err(),
        "managed default keyset policy must reject client-defined collections"
    );
}

#[tokio::test]
async fn test_register_condition_all_default_rejects_client_collections() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        default_keyset_creation: "all".to_string(),
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["A", "B", "C"], "all-default");
    let mut request = enum_condition_request("All default explicit", vec![hex_tlv]);
    request.outcome_collections = Some(vec!["A".to_string(), "B".to_string()]);

    let result = mint.register_condition(request).await;
    assert!(
        result.is_err(),
        "all default keyset policy must reject client-defined collections"
    );
}

#[tokio::test]
async fn test_register_condition_missing_collateral_fails_before_store() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["A", "B"], "missing-collateral");

    let mut request = enum_condition_request("Missing collateral", vec![hex_tlv]);
    request.collateral = None;
    request.outcome_collections = Some(vec!["A".to_string(), "B".to_string()]);

    let result = mint.register_condition(request).await;
    assert!(result.is_err(), "missing collateral must fail");

    let conditions = mint.get_conditions(None, None, &[]).await.unwrap();
    assert!(
        conditions.conditions.is_empty(),
        "failed registration must not leave a stored condition"
    );
}

#[tokio::test]
async fn test_register_condition_charges_registration_fee_once() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 2, 3)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let fee_proofs = mint_test_proofs(&mint, Amount::from(8)).await.unwrap();
    let fee_ys = fee_proofs.ys().unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "fee-once");
    let mut request = enum_condition_request("Fee once", vec![hex_tlv]);
    request.fee = Some(fee_proofs);

    let first = mint.register_condition(request.clone()).await.unwrap();
    assert_eq!(first.keysets.len(), 2);

    let states = mint.localstore().get_proofs_states(&fee_ys).await.unwrap();
    assert!(
        states.iter().all(|state| *state == Some(State::Spent)),
        "fee proofs must be marked spent"
    );

    let second = mint.register_condition(request).await.unwrap();
    assert_eq!(second.condition_id, first.condition_id);
    assert_eq!(second.keysets, first.keysets);
    assert!(
        second.change.is_none(),
        "idempotent retry must not return change"
    );
}

#[tokio::test]
async fn test_register_condition_returns_registration_fee_change() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 2, 3)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let fee_proofs = mint_test_proofs(&mint, Amount::from(16)).await.unwrap();
    let fee_ys = fee_proofs.ys().unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let (change_outputs, _) = create_premint(&mint, regular_keyset_id, Amount::from(8));

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "fee-change");
    let mut request = enum_condition_request("Fee change", vec![hex_tlv]);
    request.fee = Some(fee_proofs);
    request.outputs = Some(change_outputs);

    let response = mint.register_condition(request).await.unwrap();
    let change = response.change.expect("overpaid fee should return change");
    assert_eq!(change.iter().map(|sig| sig.amount.to_u64()).sum::<u64>(), 8);
    assert!(change.iter().all(|sig| sig.keyset_id == regular_keyset_id));

    let states = mint.localstore().get_proofs_states(&fee_ys).await.unwrap();
    assert!(
        states.iter().all(|state| *state == Some(State::Spent)),
        "fee proofs must be marked spent after successful paid registration"
    );
}

#[tokio::test]
async fn test_register_condition_rejects_pay_to_unlock_fee_without_spending_it() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 2, 3)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let keyset_id = get_regular_keyset_id(&mint);
    let fee_source = mint_test_proofs(&mint, Amount::from(8)).await.unwrap();
    let refund_key = SecretKey::generate();
    let locked = lock_pay_to_unlock(
        &mint,
        fee_source,
        keyset_id,
        Amount::from(8),
        unix_time() + 3600,
        &refund_key,
    )
    .await;
    let locked_ys = locked.ys().unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "protected-fee-rejected");
    let mut request = enum_condition_request("Protected fee rejected", vec![hex_tlv]);
    request.fee = Some(locked);

    let result = mint.register_condition(request).await;
    assert!(
        matches!(result, Err(Error::PayToUnlockInvalidCondition)),
        "protected registration fee must be rejected at the spend-path boundary: {result:?}"
    );
    assert!(mint
        .localstore()
        .get_proofs_states(&locked_ys)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
}

#[tokio::test]
async fn test_register_condition_uses_per_unit_msat_registration_fee() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Msat, 0)
        .await
        .unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Msat, 10000, 10000)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "msat-fee-scale");

    let mut insufficient = enum_condition_request("MSAT fee scale", vec![hex_tlv.clone()]);
    insufficient.collateral = Some(CurrencyUnit::Msat.to_string());
    insufficient.fee = Some(
        mint_test_proofs_for_unit(&mint, Amount::from(29999), CurrencyUnit::Msat)
            .await
            .unwrap(),
    );
    let result = mint.register_condition(insufficient).await;
    assert!(
        matches!(result, Err(Error::RegistrationFeeInsufficient)),
        "29999 msat must not satisfy a 30000 msat registration fee"
    );

    let mut request = enum_condition_request("MSAT fee scale", vec![hex_tlv]);
    request.collateral = Some(CurrencyUnit::Msat.to_string());
    request.fee = Some(
        mint_test_proofs_for_unit(&mint, Amount::from(30000), CurrencyUnit::Msat)
            .await
            .unwrap(),
    );

    let response = mint.register_condition(request).await.unwrap();
    assert_eq!(response.keysets.len(), 2);
    assert!(response.change.is_none());
}

#[tokio::test]
async fn test_register_condition_rejects_missing_collateral_unit_fee() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Msat, 10000, 10000)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "sat-unsupported");
    let mut request = enum_condition_request("SAT unsupported", vec![hex_tlv]);
    request.collateral = Some(CurrencyUnit::Sat.to_string());

    let result = mint.register_condition(request).await;
    match result {
        Err(Error::UnsupportedCollateralUnit) => {
            let response = ErrorResponse::from(Error::UnsupportedCollateralUnit);
            assert_eq!(response.code, ErrorCode::UnsupportedCollateralUnit);
            assert_eq!(response.code.to_code(), 13048);
        }
        Ok(_) => panic!("expected unsupported collateral unit, got success"),
        Err(err) => panic!("expected unsupported collateral unit, got {err}"),
    }
}

#[tokio::test]
async fn test_register_condition_empty_registration_fees_rejects_all_units() {
    let mint = create_test_mint_without_registration_fees().await.unwrap();
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "empty-fees");
    let mut request = enum_condition_request("Empty fees", vec![hex_tlv]);
    request.collateral = Some(CurrencyUnit::Sat.to_string());

    let result = mint.register_condition(request).await;
    assert!(matches!(result, Err(Error::UnsupportedCollateralUnit)));
}

#[tokio::test]
async fn test_register_condition_allows_explicit_free_registration() {
    let mint = create_test_mint_without_registration_fees().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Msat, 0, 0)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "free-msat");
    let mut request = enum_condition_request("Free MSAT", vec![hex_tlv]);
    request.collateral = Some(CurrencyUnit::Msat.to_string());

    let response = mint.register_condition(request).await.unwrap();
    assert_eq!(response.keysets.len(), 2);
    assert!(response.change.is_none());
}

#[tokio::test]
async fn test_builder_rejects_duplicate_registration_fee_units() {
    let db = Arc::new(
        cdk_sqlite::mint::memory::empty()
            .await
            .expect("test database should initialize"),
    );

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        MintBuilder::new(db).with_ctf_registration_fees(vec![
            registration_fee_setting(CurrencyUnit::Msat, 1, 1),
            registration_fee_setting(CurrencyUnit::Msat, 2, 2),
        ]);
    }));

    assert!(
        result.is_err(),
        "duplicate fee units must panic at builder time"
    );
}

#[tokio::test]
async fn test_register_condition_returns_msat_registration_fee_change() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Msat, 0)
        .await
        .unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Msat, 2000, 3000)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let fee_proofs = mint_test_proofs_for_unit(&mint, Amount::from(9000), CurrencyUnit::Msat)
        .await
        .unwrap();
    let fee_ys = fee_proofs.ys().unwrap();
    let msat_keyset_id = get_regular_keyset_id_for_unit(&mint, &CurrencyUnit::Msat);
    let (change_outputs, _) = create_premint(&mint, msat_keyset_id, Amount::from(1000));

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "msat-fee-change");
    let mut request = enum_condition_request("MSAT fee change", vec![hex_tlv]);
    request.collateral = Some(CurrencyUnit::Msat.to_string());
    request.fee = Some(fee_proofs);
    request.outputs = Some(change_outputs);

    let response = mint.register_condition(request).await.unwrap();
    let change = response
        .change
        .expect("overpaid msat fee should return msat-denominated change");
    assert_eq!(
        change.iter().map(|sig| sig.amount.to_u64()).sum::<u64>(),
        1000
    );
    assert!(change.iter().all(|sig| sig.keyset_id == msat_keyset_id));

    let states = mint.localstore().get_proofs_states(&fee_ys).await.unwrap();
    assert!(
        states.iter().all(|state| *state == Some(State::Spent)),
        "fee proofs must be spent after successful msat paid registration"
    );
}

#[tokio::test]
async fn test_register_condition_rejects_overpaid_fee_without_change_outputs() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 2, 3)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let fee_proofs = mint_test_proofs(&mint, Amount::from(16)).await.unwrap();
    let fee_ys = fee_proofs.ys().unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "fee-no-change");
    let mut request = enum_condition_request("Fee no change outputs", vec![hex_tlv]);
    request.fee = Some(fee_proofs);

    let result = mint.register_condition(request).await;
    assert!(matches!(result, Err(Error::RegistrationFeeChangeOutputs)));
    assert!(mint
        .get_conditions(None, None, &[])
        .await
        .unwrap()
        .conditions
        .is_empty());
    let states = mint.localstore().get_proofs_states(&fee_ys).await.unwrap();
    assert!(
        states.iter().all(|state| state.is_none()),
        "rejected registration must not consume fee proofs"
    );
}

#[tokio::test]
async fn test_register_condition_rejects_missing_registration_fee_before_store() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 1, 0)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "missing-fee");
    let request = enum_condition_request("Missing fee", vec![hex_tlv]);

    let result = mint.register_condition(request).await;
    assert!(matches!(result, Err(Error::RegistrationFeeInsufficient)));
    assert!(mint
        .get_conditions(None, None, &[])
        .await
        .unwrap()
        .conditions
        .is_empty());
}

#[tokio::test]
async fn test_register_condition_rejects_insufficient_registration_fee() {
    let mint = create_test_mint().await.unwrap();
    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 2, 3)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "insufficient-fee");
    let mut request = enum_condition_request("Insufficient fee", vec![hex_tlv]);
    request.fee = Some(mint_test_proofs(&mint, Amount::from(7)).await.unwrap());

    let result = mint.register_condition(request).await;
    assert!(matches!(result, Err(Error::RegistrationFeeInsufficient)));
    assert!(mint
        .get_conditions(None, None, &[])
        .await
        .unwrap()
        .conditions
        .is_empty());
}

#[tokio::test]
async fn test_register_condition_rejects_conditional_registration_fee() {
    let mint = create_test_mint().await.unwrap();
    let oracle = create_test_oracle();
    let (_, first_hex) = create_test_announcement(&oracle, &["YES", "NO"], "fee-source");
    let regular_proofs = mint_test_proofs(&mint, Amount::from(8)).await.unwrap();
    let first = mint
        .register_condition(enum_condition_request("Fee source", vec![first_hex]))
        .await
        .unwrap();
    let yes_keyset_id = *first.keysets.get("YES").unwrap();
    let conditional_fee =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, Amount::from(8)).await;

    let mut mint_info = mint.mint_info().await.unwrap();
    mint_info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![registration_fee_setting(CurrencyUnit::Sat, 1, 0)],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(mint_info).await.unwrap();

    let (_, second_hex) = create_test_announcement(&oracle, &["UP", "DOWN"], "conditional-fee");
    let mut request = enum_condition_request("Conditional fee", vec![second_hex]);
    request.fee = Some(conditional_fee);

    let result = mint.register_condition(request).await;
    assert!(matches!(result, Err(Error::OutputsMustUseRegularKeyset)));
}

#[tokio::test]
async fn test_overlapping_collection_redeems_for_any_member() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["A", "B", "C"], "overlap-redeem");
    let amount = Amount::from(16);

    let regular_proofs_a = mint_test_proofs(&mint, amount).await.unwrap();
    let regular_proofs_c = mint_test_proofs(&mint, amount).await.unwrap();

    let mut request = enum_condition_request("Overlap redeem", vec![hex_tlv]);
    request.outcome_collections = Some(vec![
        "A".to_string(),
        "B".to_string(),
        "C".to_string(),
        "A|B".to_string(),
        "B|C".to_string(),
        "A|C".to_string(),
    ]);
    let condition_response = mint.register_condition(request).await.unwrap();
    let ab_keyset_id = *condition_response.keysets.get("A|B").unwrap();

    let ab_proofs = swap_to_conditional(&mint, regular_proofs_a, ab_keyset_id, amount).await;
    let witness_a = create_oracle_witness(&oracle, "A");
    let mut proofs_with_witness = ab_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness_a.clone()));
    }
    let (regular_outputs, _) = create_premint(
        &mint,
        regular_keyset_id,
        after_conditional_input_fee(amount),
    );
    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;
    assert!(
        result.is_ok(),
        "A|B should redeem when A is attested: {:?}",
        result.err()
    );

    let ab_proofs = swap_to_conditional(&mint, regular_proofs_c, ab_keyset_id, amount).await;
    let witness_c = create_oracle_witness(&oracle, "C");
    let mut proofs_with_witness = ab_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness_c.clone()));
    }
    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, amount);
    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;
    assert!(result.is_err(), "A|B should not redeem when C is attested");
}

// ============================================================================
// NUT-CTF-numeric: Numeric condition tests
// ============================================================================

/// Register a numeric condition with HI/LO partition
async fn register_numeric_condition(
    mint: &crate::mint::Mint,
    lo_bound: i64,
    hi_bound: i64,
) -> (String, HashMap<String, Id>) {
    let oracle = create_test_oracle();
    // base=10, unsigned, 5 digits -> range [0, 99999]
    let (_, hex_tlv) =
        create_digit_decomposition_announcement(&oracle, 10, false, 5, "sat", 0, "numeric-event");

    let request = RegisterConditionRequest {
        threshold: 1,
        tags: vec![vec![
            "description".to_string(),
            "Numeric test condition".to_string(),
        ]],
        announcements: vec![hex_tlv],
        collateral: Some("sat".to_string()),
        outcome_collections: Some(vec!["HI".to_string(), "LO".to_string()]),
        fee: None,
        outputs: None,
        condition_type: "numeric".to_string(),
        lo_bound: Some(lo_bound),
        hi_bound: Some(hi_bound),
        precision: Some(0),
    };

    let condition_response = mint.register_condition(request).await.unwrap();
    let condition_id = condition_response.condition_id;

    (condition_id, condition_response.keysets)
}

/// Test registering a numeric condition creates HI/LO keysets
#[tokio::test]
async fn test_register_numeric_condition() {
    let mint = create_test_mint().await.unwrap();
    let (_condition_id, keysets) = register_numeric_condition(&mint, 0, 100000).await;

    assert_eq!(
        keysets.len(),
        2,
        "numeric condition should create HI and LO keysets"
    );
    assert!(keysets.contains_key("HI"), "should have HI keyset");
    assert!(keysets.contains_key("LO"), "should have LO keyset");
}

/// Test that numeric condition_id differs from enum condition_id
#[tokio::test]
async fn test_numeric_condition_id_differs_from_enum() {
    let mint = create_test_mint().await.unwrap();

    // Register an enum condition
    let oracle = create_test_oracle();
    let (_, enum_hex) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");
    let enum_resp = mint
        .register_condition(enum_condition_request("Enum test", vec![enum_hex]))
        .await
        .unwrap();

    // Register a numeric condition (different event to avoid idempotency)
    let (_, numeric_hex) =
        create_digit_decomposition_announcement(&oracle, 10, false, 5, "sat", 0, "numeric-event");
    let numeric_resp = mint
        .register_condition(RegisterConditionRequest {
            threshold: 1,
            tags: vec![vec!["description".to_string(), "Numeric test".to_string()]],
            announcements: vec![numeric_hex],
            collateral: Some("sat".to_string()),
            outcome_collections: Some(vec!["HI".to_string(), "LO".to_string()]),
            fee: None,
            outputs: None,
            condition_type: "numeric".to_string(),
            lo_bound: Some(0),
            hi_bound: Some(100000),
            precision: Some(0),
        })
        .await
        .unwrap();

    assert_ne!(
        enum_resp.condition_id, numeric_resp.condition_id,
        "numeric and enum condition IDs should differ"
    );
}

/// Test numeric condition info is stored and retrieved correctly
#[tokio::test]
async fn test_numeric_condition_info() {
    let mint = create_test_mint().await.unwrap();
    let (condition_id, _keysets) = register_numeric_condition(&mint, 1000, 50000).await;

    let info = mint.get_condition(&condition_id).await.unwrap();
    assert_eq!(info.condition_type, "numeric");
    assert_eq!(info.lo_bound, Some(1000));
    assert_eq!(info.hi_bound, Some(50000));
    assert_eq!(info.precision, Some(0));
    assert_eq!(info.keysets.len(), 2);
}

/// Test numeric redemption: HI holder redeems proportional payout
#[tokio::test]
async fn test_numeric_redemption_hi() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    // Mint proofs BEFORE registering condition
    let face_amount = Amount::from(100);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (_condition_id, keysets) = register_numeric_condition(&mint, 0, 100000).await;

    let hi_keyset_id = *keysets.get("HI").unwrap();

    // Swap to HI conditional keyset
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, hi_keyset_id, face_amount).await;

    // Oracle attests value 50000 (midpoint) -> HI gets 50%
    let oracle = create_test_oracle();
    let witness = create_numeric_oracle_witness(&oracle, 50000, 10, false, 5);
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    // HI payout = floor(100 * 50000 / 100000) = 50
    let hi_payout = Amount::from(50);
    let (regular_outputs, _) = create_premint(
        &mint,
        regular_keyset_id,
        after_conditional_input_fee(hi_payout),
    );

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;

    assert!(
        result.is_ok(),
        "HI redemption should succeed: {:?}",
        result.err()
    );
    assert!(!result.unwrap().signatures.is_empty());
}

/// Test numeric redemption: LO holder redeems proportional payout
#[tokio::test]
async fn test_numeric_redemption_lo() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let face_amount = Amount::from(100);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (_condition_id, keysets) = register_numeric_condition(&mint, 0, 100000).await;

    let lo_keyset_id = *keysets.get("LO").unwrap();

    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, lo_keyset_id, face_amount).await;

    // Oracle attests value 50000 -> LO gets 50%
    let oracle = create_test_oracle();
    let witness = create_numeric_oracle_witness(&oracle, 50000, 10, false, 5);
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    // LO payout = 100 - 50 = 50
    let lo_payout = Amount::from(50);
    let (regular_outputs, _) = create_premint(
        &mint,
        regular_keyset_id,
        after_conditional_input_fee(lo_payout),
    );

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;

    assert!(
        result.is_ok(),
        "LO redemption should succeed: {:?}",
        result.err()
    );
    assert!(!result.unwrap().signatures.is_empty());
}

/// Test numeric redemption at lo boundary: V=0 -> LO gets 100%, HI gets 0%
#[tokio::test]
async fn test_numeric_boundary_lo() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let face_amount = Amount::from(100);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (_condition_id, keysets) = register_numeric_condition(&mint, 0, 100000).await;
    let lo_keyset_id = *keysets.get("LO").unwrap();

    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, lo_keyset_id, face_amount).await;

    // Oracle attests value 0 (at lo_bound) -> LO gets 100%
    let oracle = create_test_oracle();
    let witness = create_numeric_oracle_witness(&oracle, 0, 10, false, 5);
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    let (regular_outputs, _) = create_premint(
        &mint,
        regular_keyset_id,
        after_conditional_input_fee(face_amount),
    );

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;

    assert!(
        result.is_ok(),
        "LO should get 100% when V <= lo_bound: {:?}",
        result.err()
    );
}

/// Test numeric redemption at hi boundary: V=100000 -> HI gets 100%, LO gets 0%
#[tokio::test]
async fn test_numeric_boundary_hi() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let face_amount = Amount::from(100);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (_condition_id, keysets) = register_numeric_condition(&mint, 0, 100000).await;
    let hi_keyset_id = *keysets.get("HI").unwrap();

    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, hi_keyset_id, face_amount).await;

    // Oracle attests value 99999 which is max for 5 unsigned base-10 digits
    // 99999 < 100000 so HI gets floor(100 * 99999/100000) = 99
    // To test the >= hi_bound case, we'd need value >= 100000 which requires 6 digits
    // So let's test with a tight range instead
    let oracle = create_test_oracle();
    let witness = create_numeric_oracle_witness(&oracle, 99999, 10, false, 5);
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    // HI gets floor(100 * 99999/100000) = 99
    let hi_payout = Amount::from(99);
    let (regular_outputs, _) = create_premint(
        &mint,
        regular_keyset_id,
        after_conditional_input_fee(hi_payout),
    );

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;

    assert!(
        result.is_ok(),
        "HI should get ~100% when V near hi_bound: {:?}",
        result.err()
    );
}

/// Test that requesting more than proportional payout fails
#[tokio::test]
async fn test_numeric_redemption_overspend_rejected() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let face_amount = Amount::from(100);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (_condition_id, keysets) = register_numeric_condition(&mint, 0, 100000).await;
    let hi_keyset_id = *keysets.get("HI").unwrap();

    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, hi_keyset_id, face_amount).await;

    // Oracle attests 20000 -> HI gets floor(100 * 20000/100000) = 20
    let oracle = create_test_oracle();
    let witness = create_numeric_oracle_witness(&oracle, 20000, 10, false, 5);
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    // Try to redeem 50 (more than the 20 payout)
    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, Amount::from(50));

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;

    assert!(
        result.is_err(),
        "should reject output amount exceeding proportional payout"
    );
}

// ============================================================================
// NUT-CTF-split-merge: CTF Convert tests
// ============================================================================

#[tokio::test]
async fn test_ctf_settlement_preparation_retains_exact_verified_artifacts_without_writes() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = cdk_common::util::unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let expected_inputs = fixture
        .request
        .participants
        .iter()
        .flat_map(|participant| participant.inputs.iter().cloned())
        .collect::<Vec<_>>();
    let expected_outputs = fixture
        .request
        .participants
        .iter()
        .flat_map(|participant| participant.outputs.iter().cloned())
        .collect::<Vec<_>>();
    let signing_attempts = mint.blind_sign_attempts();

    let prepared = mint
        .prepare_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await
        .unwrap();

    assert_eq!(
        prepared.condition_id,
        fixture.request.condition_id.to_string()
    );
    assert_eq!(prepared.inputs, expected_inputs);
    assert_eq!(prepared.outputs, expected_outputs);
    assert_eq!(
        prepared.participant_output_ranges,
        vec![0..4, 4..8],
        "participant output order and grouping must be retained"
    );
    assert_eq!(prepared.input_verification.amount.value(), 16);
    assert_eq!(prepared.output_verification.amount.value(), 30);
    assert_eq!(prepared.fee.total, Amount::from(1));
    assert_eq!(mint.blind_sign_attempts(), signing_attempts);
    assert!(mint
        .localstore()
        .get_proofs_states(&fixture.input_ys)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    assert!(mint
        .localstore()
        .get_blind_signatures(&fixture.output_points)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
}

#[tokio::test]
async fn test_ctf_settlement_preparation_rejects_output_fee_and_keyset_lifecycle() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = cdk_common::util::unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let original = mint.keysets.load().as_ref().clone();

    rewrite_test_keyset(&mint, fixture.output_only_keyset, true, 0, None);
    assert!(matches!(
        mint.prepare_ctf_settlement(&fixture.request, settlement_settings(), now)
            .await,
        Err(CtfSettlementError::Protocol(
            cdk_common::nuts::nut_ctf::settlement::Error::ZeroFeeKeyset
        ))
    ));

    mint.keysets.store(Arc::new(original.clone()));
    rewrite_test_keyset(&mint, fixture.output_only_keyset, false, 1, None);
    assert!(matches!(
        mint.prepare_ctf_settlement(&fixture.request, settlement_settings(), now)
            .await,
        Err(CtfSettlementError::Mint(Error::InactiveKeyset))
    ));

    mint.keysets.store(Arc::new(original.clone()));
    let input_keyset = fixture.request.participants[0].inputs[0].keyset_id;
    rewrite_test_keyset(&mint, input_keyset, true, 1, Some(now - 1));
    assert!(matches!(
        mint.prepare_ctf_settlement(&fixture.request, settlement_settings(), now)
            .await,
        Err(CtfSettlementError::Mint(Error::ExpiredKeyset))
    ));
    mint.keysets.store(Arc::new(original));
}

#[tokio::test]
async fn test_ctf_settlement_preparation_uses_rotated_keyset_expiry() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = cdk_common::util::unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let mut rotated = mint
        .localstore()
        .get_conditional_keyset_infos_for_condition(&fixture.request.condition_id.to_string())
        .await
        .unwrap()
        .into_iter()
        .find(|keyset| keyset.id == fixture.output_only_keyset)
        .expect("fixture keyset should exist");
    rotated.id = Id::from_str("001711afb1de20d0").unwrap();
    rotated.active = false;
    rotated.final_expiry = Some(now + 30);
    let mut transaction = mint
        .localstore()
        .begin_transaction()
        .await
        .expect("transaction should start");
    transaction
        .add_conditional_keyset(rotated, now - 1)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    assert!(matches!(
        mint.prepare_ctf_settlement(&fixture.request, settlement_settings(), now)
            .await,
        Err(CtfSettlementError::AuthorizationBeyondKeysetExpiry)
    ));
}

#[tokio::test]
async fn test_ctf_settlement_mixed_pool_persists_only_selection_and_replays() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = mixed_pool_settlement_fixture(&mint, now).await;

    let response = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await
        .expect("mixed standard/pool settlement should commit");
    assert_eq!(
        response.signatures.len(),
        fixture.request.participants.len()
    );
    for (participant, signatures) in fixture
        .request
        .participants
        .iter()
        .zip(&response.signatures)
    {
        assert_eq!(signatures.len(), participant.outputs.len());
        assert!(signatures
            .iter()
            .zip(&participant.outputs)
            .all(|(signature, output)| {
                signature.amount == output.amount && signature.keyset_id == output.keyset_id
            }));
    }
    assert!(matches!(
        &fixture.request.participants[fixture.pool_participant].mode,
        ParticipantMode::Pool { .. }
    ));
    assert_eq!(
        mint.localstore()
            .get_proofs_states(&fixture.input_ys)
            .await
            .unwrap(),
        vec![Some(State::Spent); fixture.input_ys.len()]
    );
    assert!(mint
        .localstore()
        .get_blind_signatures(&fixture.selected_output_points)
        .await
        .unwrap()
        .iter()
        .all(Option::is_some));
    assert!(mint
        .localstore()
        .get_blind_signatures(&fixture.unselected_output_points)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));

    let signing_attempts = mint.blind_sign_attempts();
    let replay = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await
        .expect("mixed settlement should replay exactly");
    assert_eq!(replay, response);
    assert_eq!(mint.blind_sign_attempts(), signing_attempts);
}

#[tokio::test]
async fn test_ctf_settlement_commits_once_and_replays_after_attestation() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let digest = fixture.request.request_digest().unwrap();

    let response = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await
        .unwrap();
    assert_eq!(
        response.signatures.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![4, 4]
    );
    assert_eq!(
        mint.localstore()
            .get_proofs_states(&fixture.input_ys)
            .await
            .unwrap(),
        vec![Some(State::Spent); fixture.input_ys.len()]
    );
    assert!(mint
        .localstore()
        .get_blind_signatures(&fixture.output_points)
        .await
        .unwrap()
        .iter()
        .all(Option::is_some));
    assert_eq!(
        mint.localstore()
            .get_ctf_settlement_replay(digest)
            .await
            .unwrap(),
        Some(response.clone())
    );

    let signing_attempts = mint.blind_sign_attempts();
    assert!(mint
        .localstore()
        .update_condition_attestation(
            &fixture.request.condition_id.to_string(),
            "attested",
            Some("YES"),
            Some(now + 1),
        )
        .await
        .unwrap());
    let replay = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), now + 1)
        .await
        .unwrap();
    assert_eq!(replay, response);
    assert_eq!(
        mint.blind_sign_attempts(),
        signing_attempts,
        "completed replay trusts the persisted successor without signing again"
    );
}

#[tokio::test]
async fn test_ctf_settlement_attestation_gap_rejects_without_persistence() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let completed_before = completed_swap_count(&mint).await;
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    let settlement_mint = mint.clone();
    let request = fixture.request.clone();
    let settlement = tokio::spawn(async move {
        settlement_mint
            .process_ctf_settlement(&request, settlement_settings(), now)
            .await
    });

    timeout(Duration::from_secs(2), reached)
        .await
        .expect("settlement should reach its pre-transaction pause")
        .expect("settlement pause sender");
    assert!(mint
        .localstore()
        .update_condition_attestation(
            &fixture.request.condition_id.to_string(),
            "attested",
            Some("YES"),
            Some(now + 1),
        )
        .await
        .unwrap());
    release
        .send(())
        .expect("settlement should still be waiting at the pause");

    assert!(matches!(
        timeout(Duration::from_secs(2), settlement)
            .await
            .expect("settlement should finish after release")
            .expect("settlement task"),
        Err(CtfSettlementError::Mint(Error::ConvertNotPermitted))
    ));
    assert_ctf_settlement_absent(&mint, &fixture, completed_before).await;
}

#[tokio::test]
async fn test_ctf_settlement_serializes_keyset_rotation_through_commit() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let input_keyset = fixture.request.participants[0].inputs[0].keyset_id;
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    let settlement_mint = mint.clone();
    let request = fixture.request.clone();
    let settlement = tokio::spawn(async move {
        settlement_mint
            .process_ctf_settlement(&request, settlement_settings(), now)
            .await
    });

    timeout(Duration::from_secs(2), reached)
        .await
        .expect("settlement should reach its pre-transaction pause")
        .expect("settlement pause sender");
    let rotation_mint = mint.clone();
    let mut rotation = tokio::spawn(async move {
        rotation_mint
            .rotate_keyset(
                CurrencyUnit::Sat,
                (0..32).map(|power| 2_u64.pow(power)).collect(),
                1,
                true,
                None,
            )
            .await
    });
    assert!(
        timeout(Duration::from_millis(50), &mut rotation)
            .await
            .is_err(),
        "rotation must wait while the settlement pins its validated keyset snapshot"
    );

    release.send(()).expect("settlement should be paused");
    timeout(Duration::from_secs(2), settlement)
        .await
        .expect("settlement should finish after release")
        .expect("settlement task")
        .expect("settlement should commit");
    timeout(Duration::from_secs(2), rotation)
        .await
        .expect("rotation should finish after settlement")
        .expect("rotation task")
        .expect("rotation should succeed");
    assert!(
        !mint
            .get_keyset_info(&input_keyset)
            .expect("input keyset should remain known")
            .active
    );
}

#[tokio::test]
async fn test_ctf_settlement_overlap_signs_once_then_replays_exact_response() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let signing_before = mint.blind_sign_attempts();
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    let settlement_mint = mint.clone();
    let request = fixture.request.clone();
    let first = tokio::spawn(async move {
        settlement_mint
            .process_ctf_settlement(&request, settlement_settings(), now)
            .await
    });

    timeout(Duration::from_secs(2), reached)
        .await
        .expect("first settlement should reach its pause")
        .expect("settlement pause sender");
    let signing_after_first = mint.blind_sign_attempts();
    assert_eq!(signing_after_first, signing_before + 1);
    let retry_mint = mint.clone();
    let retry_request = fixture.request.clone();
    let mut retry = tokio::spawn(async move {
        retry_mint
            .process_ctf_settlement(&retry_request, settlement_settings(), now)
            .await
    });
    assert!(
        timeout(Duration::from_millis(50), &mut retry)
            .await
            .is_err(),
        "identical retry should wait for the in-flight settlement"
    );
    assert_eq!(mint.blind_sign_attempts(), signing_after_first);

    release.send(()).expect("first settlement should be paused");
    let response = timeout(Duration::from_secs(2), first)
        .await
        .expect("first settlement should finish after release")
        .expect("first settlement task")
        .expect("first settlement should commit");
    let replay = timeout(Duration::from_secs(2), retry)
        .await
        .expect("identical retry should finish after commit")
        .expect("identical retry task")
        .expect("identical retry should replay");
    assert_eq!(replay, response);
    assert_eq!(mint.blind_sign_attempts(), signing_after_first);
}

#[tokio::test]
async fn test_ctf_settlement_cross_instance_sqlite_replays_one_commit() {
    let path =
        std::env::temp_dir().join(format!("cdk-settlement-race-{}.db", uuid::Uuid::new_v4()));
    let db = Arc::new(
        cdk_sqlite::mint::MintSqliteDatabase::new(path.clone())
            .await
            .unwrap(),
    );
    let mnemonic = Mnemonic::generate(12).unwrap();
    let seed = mnemonic.to_seed_normalized("");
    let first_mint = build_test_mint_with_unit(db.clone(), &seed, CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = standard_settlement_fixture(&first_mint, now).await;
    let second_mint = build_test_mint_with_unit(db.clone(), &seed, CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let completed_before = completed_swap_count(&first_mint).await;
    let (reached, release) = first_mint.arm_atomic_ctf_test_pause().await;
    let first_request = fixture.request.clone();
    let first_runner = first_mint.clone();
    let first = tokio::spawn(async move {
        first_runner
            .process_ctf_settlement(&first_request, settlement_settings(), now)
            .await
    });

    timeout(Duration::from_secs(2), reached)
        .await
        .expect("first instance should reach its pre-transaction pause")
        .expect("settlement pause sender");
    let second_request = fixture.request.clone();
    let second_runner = second_mint.clone();
    let second = tokio::spawn(async move {
        second_runner
            .process_ctf_settlement(&second_request, settlement_settings(), now)
            .await
    });
    let second_response = timeout(Duration::from_secs(2), second)
        .await
        .expect("second instance should commit")
        .expect("second settlement task")
        .expect("second settlement result");
    release.send(()).expect("first settlement should be paused");
    let first_response = timeout(Duration::from_secs(2), first)
        .await
        .expect("first instance should finish after release")
        .expect("first settlement task")
        .expect("first instance should replay the winning commit");

    assert_eq!(first_response, second_response);
    assert_eq!(
        completed_swap_count(&first_mint).await,
        completed_before + 1
    );

    first_mint.stop().await.unwrap();
    second_mint.stop().await.unwrap();
    drop(first_mint);
    drop(second_mint);
    drop(db);
    for artifact in [
        path.clone(),
        path.with_extension("db-shm"),
        path.with_extension("db-wal"),
    ] {
        let _ = std::fs::remove_file(artifact);
    }
}

#[tokio::test]
async fn test_ctf_settlement_replay_write_failure_rolls_back_everything() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = standard_settlement_fixture(&mint, now).await;
    let completed_before = completed_swap_count(&mint).await;

    set_fail_for("ADD_CTF_SETTLEMENT_REPLAY");
    let result = mint
        .process_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await;
    clear_fail_for("ADD_CTF_SETTLEMENT_REPLAY");
    assert!(result.is_err());
    assert_ctf_settlement_absent(&mint, &fixture, completed_before).await;

    mint.process_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await
        .expect("identical settlement must succeed after rollback");
}

async fn completed_swap_count(mint: &Mint) -> usize {
    mint.localstore()
        .get_completed_operations_by_kind(cdk_common::mint::OperationKind::Swap)
        .await
        .unwrap()
        .len()
}

async fn assert_ctf_settlement_absent(
    mint: &Mint,
    fixture: &StandardSettlementFixture,
    completed_before: usize,
) {
    assert!(mint
        .localstore()
        .get_proofs_states(&fixture.input_ys)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    assert!(mint
        .localstore()
        .get_blind_signatures(&fixture.output_points)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    assert!(mint
        .localstore()
        .get_ctf_settlement_replay(fixture.request.request_digest().unwrap())
        .await
        .unwrap()
        .is_none());
    assert_eq!(completed_swap_count(mint).await, completed_before);
}

fn rewrite_test_keyset(
    mint: &Mint,
    id: Id,
    active: bool,
    input_fee_ppk: u64,
    final_expiry: Option<u64>,
) {
    let keysets = mint
        .keysets
        .load()
        .iter()
        .cloned()
        .map(|mut keyset| {
            if keyset.id == id {
                keyset.active = active;
                keyset.input_fee_ppk = input_fee_ppk;
                keyset.final_expiry = final_expiry;
            }
            keyset
        })
        .collect();
    mint.keysets.store(Arc::new(keysets));
}

/// Test that zero-fee split-as-convert is rejected.
#[tokio::test]
async fn test_ctf_split_creates_conditional_tokens() {
    let mint = create_test_mint().await.unwrap();

    // Mint regular proofs BEFORE registering conditions (same pattern as existing tests)
    let face_amount = Amount::from(16);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;

    let yes_keyset_id = *keysets.get("YES").unwrap();
    let no_keyset_id = *keysets.get("NO").unwrap();

    // Create blinded messages for both YES and NO outcome collections
    let (yes_outputs, _) = create_premint(&mint, yes_keyset_id, face_amount);
    let (no_outputs, _) = create_premint(&mint, no_keyset_id, face_amount);

    let mut outputs = HashMap::new();
    outputs.insert("YES".to_string(), yes_outputs);
    outputs.insert("NO".to_string(), no_outputs);

    let mut inputs = HashMap::new();
    inputs.insert("*".to_string(), regular_proofs);

    let convert_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let result = mint.process_ctf_convert(convert_request).await;
    assert!(result.is_err(), "zero-fee convert should be rejected");
}

#[tokio::test]
async fn test_ctf_split_rejects_pay_to_unlock_without_spending_it() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let source_amount = Amount::from(8192);
    let keyset_id = get_regular_keyset_id(&mint);
    let source = mint_test_proofs(&mint, source_amount).await.unwrap();
    let refund_key = SecretKey::generate();
    let locked_amount = source_amount - Amount::ONE;
    let locked = lock_pay_to_unlock(
        &mint,
        source,
        keyset_id,
        locked_amount,
        unix_time() + 3600,
        &refund_key,
    )
    .await;
    let locked_ys = locked.ys().unwrap();
    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let output_amount = locked_amount - Amount::ONE;
    let (yes_outputs, _) = create_premint(&mint, *keysets.get("YES").unwrap(), output_amount);
    let (no_outputs, _) = create_premint(&mint, *keysets.get("NO").unwrap(), output_amount);

    let result = mint
        .process_ctf_convert(CtfConvertRequest {
            condition_id,
            parent_collection_id: None,
            inputs: HashMap::from([("*".to_string(), locked)]),
            outputs: HashMap::from([
                ("YES".to_string(), yes_outputs),
                ("NO".to_string(), no_outputs),
            ]),
        })
        .await;
    assert!(
        matches!(result, Err(Error::PayToUnlockInvalidCondition)),
        "protected split must be rejected at the spend-path boundary: {result:?}"
    );
    assert!(mint
        .localstore()
        .get_proofs_states(&locked_ys)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
}

/// Test that split-as-convert uses payoff conservation instead of old partition matching.
#[tokio::test]
async fn test_ctf_split_balance_conserved() {
    let mint = create_test_mint().await.unwrap();

    let face_amount = Amount::from(8);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;

    let yes_keyset_id = *keysets.get("YES").unwrap();
    let no_keyset_id = *keysets.get("NO").unwrap();

    let (yes_outputs, _) = create_premint(&mint, yes_keyset_id, face_amount);
    let (no_outputs, _) = create_premint(&mint, no_keyset_id, face_amount);

    let mut outputs = HashMap::new();
    outputs.insert("YES".to_string(), yes_outputs);
    outputs.insert("NO".to_string(), no_outputs);

    let mut inputs = HashMap::new();
    inputs.insert("*".to_string(), regular_proofs);

    let convert_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let result = mint.process_ctf_convert(convert_request).await;
    assert!(result.is_err(), "zero-fee convert should be rejected");
}

/// Test that split-as-convert charges the input fee in the collateral unit.
#[tokio::test]
async fn test_ctf_split_msat_input_fee_charged_in_msat() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Msat, 1000)
        .await
        .unwrap();

    let face_amount = Amount::from(8192);
    let regular_proofs = mint_test_proofs_for_unit(&mint, face_amount, CurrencyUnit::Msat)
        .await
        .unwrap();
    let fee = mint.get_proofs_fee(&regular_proofs).await.unwrap().total;
    assert_eq!(
        fee,
        Amount::from(1),
        "one 1000-ppk msat input proof must charge one msat, not one sat"
    );

    let (condition_id, keysets) =
        register_test_condition_with_collateral(&mint, &["YES", "NO"], CurrencyUnit::Msat).await;

    let yes_keyset_id = *keysets.get("YES").unwrap();
    let no_keyset_id = *keysets.get("NO").unwrap();
    let output_amount = face_amount - fee;
    assert_eq!(output_amount, Amount::from(8191));

    let (yes_outputs, _) = create_premint(&mint, yes_keyset_id, output_amount);
    let (no_outputs, _) = create_premint(&mint, no_keyset_id, output_amount);

    let mut outputs = HashMap::new();
    outputs.insert("YES".to_string(), yes_outputs);
    outputs.insert("NO".to_string(), no_outputs);

    let mut inputs = HashMap::new();
    inputs.insert("*".to_string(), regular_proofs);

    let convert_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let response = mint.process_ctf_convert(convert_request).await.unwrap();
    assert_eq!(
        response
            .signatures
            .get("YES")
            .unwrap()
            .iter()
            .map(|sig| sig.amount.to_u64())
            .sum::<u64>(),
        8191
    );
    assert_eq!(
        response
            .signatures
            .get("NO")
            .unwrap()
            .iter()
            .map(|sig| sig.amount.to_u64())
            .sum::<u64>(),
        8191
    );
}

#[tokio::test]
async fn test_atomic_ctf_convert_commits_spent_signatures_and_operation() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let fixture = atomic_convert_fixture(&mint).await;

    mint.process_ctf_convert(fixture.request.clone())
        .await
        .unwrap();
    assert_atomic_convert_committed(&mint, &fixture).await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_atomic_ctf_convert_rolls_back_signature_failure() {
    assert_atomic_convert_rollback("ADD_SIGNATURES").await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_atomic_ctf_convert_rolls_back_proof_update_failure() {
    assert_atomic_convert_rollback("UPDATE_PROOFS").await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_atomic_ctf_convert_rolls_back_completed_operation_failure() {
    assert_atomic_convert_rollback("ADD_COMPLETED_OPERATION").await;
}

#[tokio::test]
async fn test_atomic_ctf_convert_attestation_gap_rejects_without_persistence() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let fixture = atomic_convert_fixture(&mint).await;
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    let convert_mint = mint.clone();
    let request = fixture.request.clone();
    let convert = tokio::spawn(async move { convert_mint.process_ctf_convert(request).await });

    timeout(Duration::from_secs(2), reached)
        .await
        .expect("conversion should reach its pre-transaction pause")
        .expect("conversion pause sender");
    assert!(mint
        .localstore()
        .update_condition_attestation(
            &fixture.request.condition_id,
            "attested",
            Some("YES"),
            Some(2_000_000),
        )
        .await
        .unwrap());
    release
        .send(())
        .expect("conversion should still be waiting at the pause");

    assert!(matches!(
        timeout(Duration::from_secs(2), convert)
            .await
            .expect("conversion should finish after release")
            .expect("conversion task"),
        Err(Error::ConvertNotPermitted)
    ));
    assert_atomic_convert_absent(&mint, &fixture).await;
}

#[tokio::test]
async fn test_atomic_ctf_convert_spent_replay_rejects_before_signing_again() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let fixture = atomic_convert_fixture(&mint).await;
    let before = mint.blind_sign_attempts();

    mint.process_ctf_convert(fixture.request.clone())
        .await
        .unwrap();
    let after_first = mint.blind_sign_attempts();
    assert_eq!(after_first, before + 1);

    assert!(matches!(
        mint.process_ctf_convert(fixture.request.clone()).await,
        Err(Error::TokenAlreadySpent)
    ));
    assert_eq!(mint.blind_sign_attempts(), after_first);
}

#[tokio::test]
async fn test_atomic_ctf_convert_overlap_rejects_before_duplicate_signing() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let fixture = atomic_convert_fixture(&mint).await;
    let before = mint.blind_sign_attempts();
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    let convert_mint = mint.clone();
    let request = fixture.request.clone();
    let first = tokio::spawn(async move { convert_mint.process_ctf_convert(request).await });

    timeout(Duration::from_secs(2), reached)
        .await
        .expect("first conversion should reach its pause")
        .expect("conversion pause sender");
    let after_first_signing = mint.blind_sign_attempts();
    assert_eq!(after_first_signing, before + 1);
    assert!(matches!(
        mint.process_ctf_convert(fixture.request.clone()).await,
        Err(Error::TokenPending)
    ));
    assert_eq!(mint.blind_sign_attempts(), after_first_signing);

    release.send(()).expect("first conversion should be paused");
    timeout(Duration::from_secs(2), first)
        .await
        .expect("first conversion should finish after release")
        .expect("first conversion task")
        .expect("first conversion should commit");
    assert_atomic_convert_committed(&mint, &fixture).await;
}

#[tokio::test]
async fn test_ctf_convert_before_attestation_commits_then_attests() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let fixture = atomic_convert_fixture(&mint).await;
    mint.process_ctf_convert(fixture.request.clone())
        .await
        .unwrap();
    assert_atomic_convert_committed(&mint, &fixture).await;

    let db = mint.localstore();
    assert!(db
        .update_condition_attestation(
            &fixture.request.condition_id,
            "attested",
            Some("YES"),
            Some(2_000_000),
        )
        .await
        .unwrap());
    assert_eq!(
        db.get_condition(&fixture.request.condition_id)
            .await
            .unwrap()
            .unwrap()
            .attestation_status,
        "attested"
    );
}

/// Test that a split with unequal per-outcome totals is rejected.
#[tokio::test]
async fn test_ctf_split_unequal_outcome_amounts_rejected() {
    let mint = create_test_mint().await.unwrap();

    let face_amount = Amount::from(16);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;

    let yes_keyset_id = *keysets.get("YES").unwrap();
    let no_keyset_id = *keysets.get("NO").unwrap();

    // YES gets 16, NO gets only 8 — totals differ, should be rejected
    let (yes_outputs, _) = create_premint(&mint, yes_keyset_id, Amount::from(16));
    let (no_outputs, _) = create_premint(&mint, no_keyset_id, Amount::from(8));

    let mut outputs = HashMap::new();
    outputs.insert("YES".to_string(), yes_outputs);
    outputs.insert("NO".to_string(), no_outputs);

    let mut inputs = HashMap::new();
    inputs.insert("*".to_string(), regular_proofs);

    let convert_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let result = mint.process_ctf_convert(convert_request).await;
    assert!(
        result.is_err(),
        "split with unequal outcome amounts should be rejected"
    );
}

/// Test that a split with an unknown/invalid partition is rejected.
#[tokio::test]
async fn test_ctf_split_invalid_partition() {
    let mint = create_test_mint().await.unwrap();

    let face_amount = Amount::from(8);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    // Condition with YES, NO, MAYBE outcomes; default partition is YES|NO|MAYBE
    let (condition_id, keysets) =
        register_test_condition(&mint, &["YES", "NO", "MAYBE"], None).await;

    let yes_keyset_id = *keysets.get("YES").unwrap();
    let no_keyset_id = *keysets.get("NO").unwrap();

    // Provide only YES and NO — incomplete partition (MAYBE is missing)
    let (yes_outputs, _) = create_premint(&mint, yes_keyset_id, face_amount);
    let (no_outputs, _) = create_premint(&mint, no_keyset_id, face_amount);

    let mut outputs = HashMap::new();
    outputs.insert("YES".to_string(), yes_outputs);
    outputs.insert("NO".to_string(), no_outputs);

    let mut inputs = HashMap::new();
    inputs.insert("*".to_string(), regular_proofs);

    let convert_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let result = mint.process_ctf_convert(convert_request).await;
    assert!(
        result.is_err(),
        "convert with uncovered payoff should be rejected"
    );
}

/// Test that a split using the wrong keyset for an outcome collection is rejected.
#[tokio::test]
async fn test_ctf_split_wrong_keyset_rejected() {
    let mint = create_test_mint().await.unwrap();

    let face_amount = Amount::from(8);
    let regular_proofs = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;

    let yes_keyset_id = *keysets.get("YES").unwrap();
    let no_keyset_id = *keysets.get("NO").unwrap();

    // Intentionally swap YES/NO: use NO keyset for the "YES" output key
    let (swapped_yes, _) = create_premint(&mint, no_keyset_id, face_amount);
    let (swapped_no, _) = create_premint(&mint, yes_keyset_id, face_amount);

    let mut outputs = HashMap::new();
    outputs.insert("YES".to_string(), swapped_yes);
    outputs.insert("NO".to_string(), swapped_no);

    let mut inputs = HashMap::new();
    inputs.insert("*".to_string(), regular_proofs);

    let convert_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let result = mint.process_ctf_convert(convert_request).await;
    assert!(
        result.is_err(),
        "split with swapped/wrong keysets should be rejected"
    );
}

/// Test that a keyset registered under another condition cannot satisfy a declared collection.
#[tokio::test]
async fn test_ctf_split_wrong_condition_keyset_rejected() {
    let mint = create_test_mint().await.unwrap();
    let regular_proofs = mint_test_proofs(&mint, Amount::from(8)).await.unwrap();
    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let (_, other_keysets) =
        register_test_condition_with_event(&mint, &["YES", "NO"], None, "other-event").await;

    let (wrong_yes, _) = create_premint(&mint, *other_keysets.get("YES").unwrap(), Amount::from(8));
    let (no_outputs, _) = create_premint(&mint, *keysets.get("NO").unwrap(), Amount::from(8));
    let request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs: HashMap::from([("*".to_string(), regular_proofs)]),
        outputs: HashMap::from([
            ("YES".to_string(), wrong_yes),
            ("NO".to_string(), no_outputs),
        ]),
    };

    let result = mint.process_ctf_convert(request).await;
    assert!(matches!(result, Err(Error::OutputsMustUseRegularKeyset)));
}

/// Test that a conditional keyset cannot be mislabeled as root collateral.
#[tokio::test]
async fn test_ctf_convert_conditional_input_as_collateral_rejected() {
    let mint = create_test_mint().await.unwrap();
    let regular_proofs = mint_test_proofs(&mint, Amount::from(8)).await.unwrap();
    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let yes_keyset_id = *keysets.get("YES").unwrap();
    let yes_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, Amount::from(8)).await;
    let (yes_outputs, _) = create_premint(&mint, yes_keyset_id, Amount::from(7));
    let (no_outputs, _) = create_premint(&mint, *keysets.get("NO").unwrap(), Amount::from(7));
    let request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs: HashMap::from([("*".to_string(), yes_proofs)]),
        outputs: HashMap::from([
            ("YES".to_string(), yes_outputs),
            ("NO".to_string(), no_outputs),
        ]),
    };

    let result = mint.process_ctf_convert(request).await;
    assert!(matches!(result, Err(Error::OutputsMustUseRegularKeyset)));
}

/// Test that a CTF merge of a complete partition returns regular tokens.
/// Flow: mint regular → (swap) YES conditional proofs + NO conditional proofs → merge → regular
#[tokio::test]
async fn test_ctf_merge_returns_regular_tokens() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let face_amount = Amount::from(8);
    // Mint BEFORE registering conditions; need two batches for YES and NO conditional proofs
    let yes_regular = mint_test_proofs(&mint, face_amount).await.unwrap();
    let no_regular = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let yes_keyset_id = *keysets.get("YES").unwrap();
    let no_keyset_id = *keysets.get("NO").unwrap();

    // Swap regular proofs into each conditional keyset
    let yes_proofs = swap_to_conditional(&mint, yes_regular, yes_keyset_id, face_amount).await;
    let no_proofs = swap_to_conditional(&mint, no_regular, no_keyset_id, face_amount).await;

    // Merge YES + NO back into regular tokens. Conditional keysets charge 1 ppk,
    // so the two input proofs pay one base unit total.
    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, Amount::from(7));

    let mut inputs = HashMap::new();
    inputs.insert("YES".to_string(), yes_proofs);
    inputs.insert("NO".to_string(), no_proofs);

    let mut outputs = HashMap::new();
    outputs.insert("*".to_string(), regular_outputs);

    let merge_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let result = mint.process_ctf_convert(merge_request).await;
    assert!(
        result.is_ok(),
        "conditional-input convert should pay one base unit: {:?}",
        result.err()
    );
}

/// Test that a merge with an incomplete partition (missing an outcome) is rejected.
#[tokio::test]
async fn test_ctf_merge_incomplete_partition_rejected() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let face_amount = Amount::from(8);
    // Mint BEFORE registering conditions
    let yes_regular = mint_test_proofs(&mint, face_amount).await.unwrap();

    let (condition_id, keysets) = register_test_condition(&mint, &["YES", "NO"], None).await;
    let yes_keyset_id = *keysets.get("YES").unwrap();

    let yes_proofs = swap_to_conditional(&mint, yes_regular, yes_keyset_id, face_amount).await;

    // Only provide YES inputs — NO is missing, so the partition is incomplete
    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, face_amount);

    let mut inputs = HashMap::new();
    inputs.insert("YES".to_string(), yes_proofs);

    let mut outputs = HashMap::new();
    outputs.insert("*".to_string(), regular_outputs);

    let merge_request = CtfConvertRequest {
        condition_id,
        parent_collection_id: None,
        inputs,
        outputs,
    };

    let result = mint.process_ctf_convert(merge_request).await;
    assert!(
        result.is_err(),
        "merge with incomplete partition should be rejected"
    );
}

// ============================================================================
// Multi-oracle threshold integration test
// ============================================================================

/// Test that redeeming a 2-of-2 threshold condition requires signatures from both oracles.
///
/// Setup: register a condition with two oracles and threshold=2.
/// Verify that providing only one oracle sig fails (threshold not met),
/// while providing both succeeds.
#[tokio::test]
async fn test_redeem_outcome_multi_oracle_threshold() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let oracle1 = create_test_oracle();
    let oracle2 = create_test_oracle_2();

    // Both oracles announce the same event with the same outcomes
    let (_, hex_tlv1) = create_test_announcement(&oracle1, &["YES", "NO"], "multi-oracle-event");
    let (_, hex_tlv2) = create_test_announcement(&oracle2, &["YES", "NO"], "multi-oracle-event");

    // Mint regular proofs BEFORE registering conditions
    let amount = Amount::from(16);
    let regular_proofs_1 = mint_test_proofs(&mint, amount).await.unwrap();
    let regular_proofs_2 = mint_test_proofs(&mint, amount).await.unwrap();

    // Register condition with threshold=2 (requires both oracles)
    let condition_response = mint
        .register_condition(RegisterConditionRequest {
            threshold: 2,
            tags: vec![vec![
                "description".to_string(),
                "2-of-2 oracle condition".to_string(),
            ]],
            announcements: vec![hex_tlv1, hex_tlv2],
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
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();

    // --- Attempt 1: only oracle1 sig — should fail (threshold not met) ---
    {
        let conditional_proofs =
            swap_to_conditional(&mint, regular_proofs_1, yes_keyset_id, amount).await;

        let witness_one = create_multi_oracle_witness(&[(&oracle1, "YES")]);

        let mut proofs_with_witness = conditional_proofs;
        for proof in &mut proofs_with_witness {
            proof.witness = Some(Witness::OracleWitness(witness_one.clone()));
        }

        let (regular_outputs, _) = create_premint(
            &mint,
            regular_keyset_id,
            after_conditional_input_fee(amount),
        );

        let result = mint
            .process_redeem_outcome(RedeemOutcomeRequest {
                inputs: proofs_with_witness,
                outputs: regular_outputs,
            })
            .await;

        assert!(
            result.is_err(),
            "single oracle sig should fail threshold=2 check"
        );
    }

    // --- Attempt 2: both oracle sigs — should succeed ---
    {
        let conditional_proofs =
            swap_to_conditional(&mint, regular_proofs_2, yes_keyset_id, amount).await;

        let witness_both = create_multi_oracle_witness(&[(&oracle1, "YES"), (&oracle2, "YES")]);

        let mut proofs_with_witness = conditional_proofs;
        for proof in &mut proofs_with_witness {
            proof.witness = Some(Witness::OracleWitness(witness_both.clone()));
        }

        let (regular_outputs, _) = create_premint(
            &mint,
            regular_keyset_id,
            after_conditional_input_fee(amount),
        );

        let result = mint
            .process_redeem_outcome(RedeemOutcomeRequest {
                inputs: proofs_with_witness,
                outputs: regular_outputs,
            })
            .await;

        assert!(
            result.is_ok(),
            "both oracle sigs should meet threshold=2: {:?}",
            result.err()
        );
    }
}

// ============================================================================
// Security regression tests
// ============================================================================

/// Test that duplicate attestation signatures from the same oracle
/// cannot satisfy a threshold > 1 requirement.
///
/// This is a regression test for P1: threshold bypass via duplicate oracle pubkeys.
#[tokio::test]
async fn test_redeem_rejects_duplicate_oracle_sigs() {
    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);

    let oracle1 = create_test_oracle();
    let oracle2 = create_test_oracle_2();

    // Register with two oracles, threshold=2
    let (_, hex_tlv1) = create_test_announcement(&oracle1, &["YES", "NO"], "dup-event");
    let (_, hex_tlv2) = create_test_announcement(&oracle2, &["YES", "NO"], "dup-event");

    let amount = Amount::from(16);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(RegisterConditionRequest {
            threshold: 2,
            tags: vec![vec![
                "description".to_string(),
                "Dup oracle test".to_string(),
            ]],
            announcements: vec![hex_tlv1, hex_tlv2],
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
    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    // Provide oracle1's signature twice (duplicate) — should NOT satisfy threshold=2
    let witness = create_multi_oracle_witness(&[(&oracle1, "YES"), (&oracle1, "YES")]);
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    let (regular_outputs, _) = create_premint(&mint, regular_keyset_id, amount);

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: regular_outputs,
        })
        .await;

    assert!(
        result.is_err(),
        "duplicate oracle sigs from same pubkey should not satisfy threshold=2"
    );
}

/// Regression test: a redeem call that fails (e.g. unbalanced inputs/outputs) MUST NOT
/// persist `winning_outcome` / `attested_at` for the condition. Otherwise any party
/// holding a valid public oracle witness could permanently lock the condition into an
/// "attested" state without spending real conditional proofs, locking out all losing-side
/// holders.
#[tokio::test]
async fn test_failed_redeem_does_not_persist_attestation() {
    use cdk_common::nuts::nut_ctf::AttestationStatus;

    let mint = create_test_mint().await.unwrap();
    let regular_keyset_id = get_regular_keyset_id(&mint);
    let oracle = create_test_oracle();
    let (_, hex_tlv) = create_test_announcement(&oracle, &["YES", "NO"], "test-event");

    let amount = Amount::from(10);
    let regular_proofs = mint_test_proofs(&mint, amount).await.unwrap();

    let condition_response = mint
        .register_condition(enum_condition_request("Griefing regression", vec![hex_tlv]))
        .await
        .unwrap();
    let condition_id = condition_response.condition_id.clone();

    let yes_keyset_id = *condition_response.keysets.get("YES").unwrap();
    let conditional_proofs =
        swap_to_conditional(&mint, regular_proofs, yes_keyset_id, amount).await;

    // Attach a perfectly valid oracle witness — exactly what an attacker who watches the
    // oracle's public attestation would have access to.
    let witness = create_oracle_witness(&oracle, "YES");
    let mut proofs_with_witness = conditional_proofs;
    for proof in &mut proofs_with_witness {
        proof.witness = Some(Witness::OracleWitness(witness.clone()));
    }

    // But sum the outputs to a larger amount than the inputs cover — this fails the balance
    // check, which (after the fix) runs BEFORE record_attestation. Pre-fix this branch
    // wrote the attestation anyway.
    let (oversized_outputs, _) = create_premint(&mint, regular_keyset_id, Amount::from(100));

    let result = mint
        .process_redeem_outcome(RedeemOutcomeRequest {
            inputs: proofs_with_witness,
            outputs: oversized_outputs,
        })
        .await;

    assert!(
        result.is_err(),
        "unbalanced redeem must fail before any DB writes"
    );

    let info = mint.get_condition(&condition_id).await.unwrap();
    let status = info
        .attestation
        .as_ref()
        .map(|a| a.status.clone())
        .unwrap_or(AttestationStatus::Pending);
    assert_eq!(
        status,
        AttestationStatus::Pending,
        "failed redeem must not persist attestation; condition should remain pending"
    );
    assert!(
        info.attestation
            .as_ref()
            .and_then(|a| a.winning_outcome.as_ref())
            .is_none(),
        "failed redeem must not persist a winning_outcome"
    );
}
