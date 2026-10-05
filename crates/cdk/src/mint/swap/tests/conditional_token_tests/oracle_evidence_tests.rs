//! Real mint regressions for durable oracle evidence and independent numeric floors.

use super::*;
use cdk_common::nuts::nut_ctf::{OracleSig, OracleWitness};

struct EvidenceFixture {
    condition_id: String,
    yes: cdk_common::Proofs,
    no: cdk_common::Proofs,
    first: OracleWitness,
    second: OracleWitness,
}

async fn evidence_fixture(mint: &Mint, event: &str) -> EvidenceFixture {
    rotate_test_regular_fee(mint, CurrencyUnit::Sat, 0).await;
    let oracle = create_test_oracle();
    let other = create_test_oracle_2();
    let (_, announcement) = create_test_announcement(&oracle, &["YES", "NO"], event);
    let (_, other_announcement) = create_test_announcement(&other, &["YES", "NO"], event);
    let response = mint
        .register_condition(enum_condition_request(
            event,
            vec![announcement, other_announcement],
        ))
        .await
        .unwrap();
    // The conditional keysets retain zero fees. Convert requires a fee-backed input.
    rotate_test_regular_fee(mint, CurrencyUnit::Sat, 1).await;
    let funding = mint_test_proofs(mint, Amount::from(16)).await.unwrap();
    let mut premints = HashMap::new();
    for collection in ["YES", "NO"] {
        premints.insert(
            collection.to_string(),
            create_premint(mint, response.keysets[collection], Amount::from(15)).1,
        );
    }
    let converted = mint
        .process_ctf_convert(CtfConvertRequest {
            condition_id: response.condition_id.clone(),
            parent_collection_id: None,
            inputs: HashMap::from([("*".to_string(), funding)]),
            outputs: premints
                .iter()
                .map(|(collection, premint)| (collection.clone(), premint.blinded_messages()))
                .collect(),
        })
        .await
        .unwrap();
    let mut proofs = HashMap::new();
    for (collection, premint) in premints {
        let keys = mint
            .keyset_pubkeys(&response.keysets[&collection])
            .unwrap()
            .keysets
            .remove(0)
            .keys;
        proofs.insert(
            collection.clone(),
            construct_proofs(
                converted.signatures[&collection].clone(),
                premint.rs(),
                premint.secrets(),
                &keys,
            )
            .unwrap(),
        );
    }
    EvidenceFixture {
        condition_id: response.condition_id,
        yes: proofs.remove("YES").unwrap(),
        no: proofs.remove("NO").unwrap(),
        first: create_oracle_witness(&oracle, "YES"),
        second: create_oracle_witness(&other, "YES"),
    }
}

fn redemption(
    mint: &Mint,
    mut inputs: cdk_common::Proofs,
    witness: Option<&OracleWitness>,
) -> RedeemOutcomeRequest {
    for proof in &mut inputs {
        proof.witness = witness.cloned().map(Witness::OracleWitness);
    }
    let amount = inputs.total_amount().unwrap();
    // Conditional keysets in this fixture have zero input fees.
    let outputs = create_premint(mint, get_regular_keyset_id(mint), amount).0;
    RedeemOutcomeRequest { inputs, outputs }
}

async fn assert_pending_and_unspent(mint: &Mint, fixture: &EvidenceFixture) {
    let stored = mint
        .localstore()
        .get_condition(&fixture.condition_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.attestation_status, "pending");
    assert!(stored.winning_outcome.is_none());
    assert!(stored.attested_at.is_none());
    assert!(stored.oracle_sigs.is_none());
    assert!(mint
        .localstore()
        .get_proofs_states(&fixture.yes.ys().unwrap())
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
}

#[tokio::test]
async fn test_d2_every_supplied_enum_witness_is_validated() {
    let mint = create_test_mint().await.unwrap();
    let fixture = evidence_fixture(&mint, "invalid-evidence").await;
    let mut cases = Vec::new();
    let mut witness = fixture.first.clone();
    // A valid signature using an unregistered nonce must fail.
    let mut wrong_nonce = create_test_oracle();
    wrong_nonce.nonce_secret = CoordinatorSecretKey::from_slice(&[43; 32]).unwrap();
    wrong_nonce.nonce_public = wrong_nonce
        .nonce_secret
        .x_only_public_key(&Secp256k1::new())
        .0;
    cases.push(create_oracle_witness(&wrong_nonce, "YES"));
    witness.oracle_sigs[0].oracle_pubkey = "44".repeat(32);
    cases.push(witness);
    cases.push(create_oracle_witness(&create_test_oracle(), "UNKNOWN"));
    let mut witness = fixture.first.clone();
    witness.oracle_sigs.push(witness.oracle_sigs[0].clone());
    cases.push(witness);
    let mut witness = fixture.first.clone();
    witness.oracle_sigs[0].digit_sigs = Some(vec!["55".repeat(64)]);
    cases.push(witness);
    let mut witness = fixture.first.clone();
    witness.oracle_sigs[0].outcome = None;
    cases.push(witness);
    let mut witness = fixture.first.clone();
    witness.oracle_sigs[0].oracle_sig = Some("00".repeat(64));
    cases.push(witness);
    for (index, witness) in cases.iter().enumerate() {
        let before = mint.blind_sign_attempts();
        let result = mint
            .process_redeem_outcome(redemption(&mint, fixture.yes.clone(), Some(witness)))
            .await;
        assert!(result.is_err(), "invalid evidence case {index}: {result:?}");
        assert_eq!(mint.blind_sign_attempts(), before);
        assert_pending_and_unspent(&mint, &fixture).await;
    }
    let mut missing = redemption(&mint, fixture.yes.clone(), Some(&fixture.first));
    missing.inputs.last_mut().unwrap().witness = None;
    assert!(matches!(
        mint.process_redeem_outcome(missing).await,
        Err(Error::ConditionalKeysetRequiresWitness)
    ));
    assert_pending_and_unspent(&mint, &fixture).await;
    // Checking only the first proof witness would accept the invalid later proof.
    let mut request = redemption(&mint, fixture.yes.clone(), Some(&fixture.first));
    request.inputs.last_mut().unwrap().witness = Some(Witness::OracleWitness(cases[0].clone()));
    assert!(mint.process_redeem_outcome(request).await.is_err());
    assert_pending_and_unspent(&mint, &fixture).await;
    let mut inconsistent = fixture.first.clone();
    inconsistent
        .oracle_sigs
        .extend(create_oracle_witness(&create_test_oracle_2(), "NO").oracle_sigs);
    assert!(matches!(
        mint.process_redeem_outcome(redemption(&mint, fixture.yes.clone(), Some(&inconsistent)))
            .await,
        Err(Error::ConflictingOracleAttestations)
    ));
    assert_pending_and_unspent(&mint, &fixture).await;
    mint.process_redeem_outcome(redemption(&mint, fixture.yes.clone(), Some(&fixture.first)))
        .await
        .unwrap();
    let original = mint
        .localstore()
        .get_condition(&fixture.condition_id)
        .await
        .unwrap()
        .unwrap();
    for witness in cases {
        assert!(mint
            .process_redeem_outcome(redemption(&mint, fixture.yes.clone(), Some(&witness)))
            .await
            .is_err());
        let preserved = mint
            .localstore()
            .get_condition(&fixture.condition_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(preserved.oracle_sigs, original.oracle_sigs);
        assert_eq!(preserved.attested_at, original.attested_at);
        assert_eq!(preserved.winning_outcome, original.winning_outcome);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_d2_payout_failure_retains_first_evidence_and_retry_keeps_it() {
    let mint = create_test_mint().await.unwrap();
    let fixture = evidence_fixture(&mint, "payout-failure").await;
    let request = redemption(&mint, fixture.yes.clone(), Some(&fixture.first));
    // Trigger the existing signer failure after the first-result transaction.
    set_fail_for("GENERAL");
    let result = mint.process_redeem_outcome(request.clone()).await;
    clear_fail_for("GENERAL");
    assert!(
        result.is_err(),
        "the payout failure must execute: {result:?}"
    );
    let first = mint
        .localstore()
        .get_condition(&fixture.condition_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.oracle_sigs.as_ref(), Some(&fixture.first.oracle_sigs));
    assert_eq!(first.winning_outcome.as_deref(), Some("YES"));
    assert!(first.attested_at.is_some());
    assert!(mint
        .localstore()
        .get_proofs_states(&fixture.yes.ys().unwrap())
        .await
        .unwrap()
        .iter()
        .all(|state| *state != Some(State::Spent)));
    mint.process_redeem_outcome(redemption(&mint, fixture.yes, Some(&fixture.second)))
        .await
        .unwrap();
    let retried = mint
        .localstore()
        .get_condition(&fixture.condition_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried.oracle_sigs, first.oracle_sigs);
    assert_eq!(retried.attested_at, first.attested_at);
}

async fn provider_first_resolution_races_and_roundtrip<DB>(
    db: Arc<DB>,
    name: &str,
) -> (String, Vec<OracleSig>, u64)
where
    DB: cdk_common::database::MintDatabase<cdk_common::database::Error>
        + MintKeysDatabase<Err = cdk_common::database::Error>
        + Send
        + Sync
        + 'static,
{
    let mint = build_test_mint_with_units(db, &[7; 64], &[(CurrencyUnit::Sat, 0)])
        .await
        .unwrap();
    let fixture = evidence_fixture(&mint, &format!("same-{name}")).await;
    let a = redemption(&mint, vec![fixture.yes[0].clone()], Some(&fixture.first));
    let b = redemption(&mint, vec![fixture.yes[1].clone()], Some(&fixture.second));
    let (a, b) = tokio::join!(
        mint.process_redeem_outcome(a),
        mint.process_redeem_outcome(b)
    );
    assert!(a.is_ok(), "{a:?}");
    assert!(b.is_ok(), "{b:?}");
    let first = mint
        .localstore()
        .get_condition(&fixture.condition_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        first.oracle_sigs.as_ref() == Some(&fixture.first.oracle_sigs)
            || first.oracle_sigs.as_ref() == Some(&fixture.second.oracle_sigs)
    );
    mint.process_redeem_outcome(redemption(&mint, vec![fixture.yes[2].clone()], None))
        .await
        .unwrap();
    let retry = mint
        .localstore()
        .get_condition(&fixture.condition_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry.oracle_sigs, first.oracle_sigs);
    assert_eq!(retry.attested_at, first.attested_at);
    let omitted =
        serde_json::to_value(mint.get_condition(&fixture.condition_id).await.unwrap()).unwrap();
    assert!(omitted["attestation"].get("oracle_sigs").is_none());
    let included = mint
        .get_condition_with_oracle_sigs(&fixture.condition_id, true)
        .await
        .unwrap();
    assert_eq!(included.attestation.unwrap().oracle_sigs, first.oracle_sigs);

    // Prepare a different event before either oracle result is recorded.
    let conflict = evidence_fixture(&mint, &format!("conflict-{name}")).await;
    let yes = redemption(&mint, vec![conflict.yes[0].clone()], Some(&conflict.first));
    let no_witness = create_oracle_witness(&create_test_oracle_2(), "NO");
    let no = redemption(&mint, vec![conflict.no[0].clone()], Some(&no_witness));
    let (yes_result, no_result) = tokio::join!(
        mint.process_redeem_outcome(yes),
        mint.process_redeem_outcome(no)
    );
    assert_ne!(
        yes_result.is_ok(),
        no_result.is_ok(),
        "exactly one result wins: {yes_result:?} {no_result:?}"
    );
    let yes_won = yes_result.is_ok();
    let refused = if yes_result.is_err() {
        yes_result.unwrap_err()
    } else {
        no_result.unwrap_err()
    };
    assert!(matches!(refused, Error::ConflictingOracleAttestations));
    let error: ErrorResponse = refused.into();
    assert_eq!(error.code.to_code(), 13049);
    let stored = mint
        .localstore()
        .get_condition(&conflict.condition_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.winning_outcome.as_deref(),
        Some(if yes_won { "YES" } else { "NO" })
    );
    assert_eq!(
        stored.oracle_sigs.as_ref(),
        Some(if yes_won {
            &conflict.first.oracle_sigs
        } else {
            &no_witness.oracle_sigs
        })
    );
    mint.stop().await.unwrap();
    (
        fixture.condition_id,
        first.oracle_sigs.unwrap(),
        first.attested_at.unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_d2_sqlite_real_mint_reopen_races_and_evidence() {
    let path = std::env::temp_dir().join(format!("cdk-d2-evidence-{}.db", uuid::Uuid::new_v4()));
    let db = Arc::new(
        cdk_sqlite::mint::MintSqliteDatabase::new(path.clone())
            .await
            .unwrap(),
    );
    let (condition, evidence, timestamp) =
        provider_first_resolution_races_and_roundtrip(db, "sqlite").await;
    let reopened = Arc::new(
        cdk_sqlite::mint::MintSqliteDatabase::new(path.clone())
            .await
            .unwrap(),
    );
    let mint = build_test_mint_with_units(reopened, &[7; 64], &[(CurrencyUnit::Sat, 0)])
        .await
        .unwrap();
    let info = mint
        .get_condition_with_oracle_sigs(&condition, true)
        .await
        .unwrap();
    let attestation = info.attestation.as_ref().unwrap();
    assert_eq!(attestation.oracle_sigs.as_ref(), Some(&evidence));
    assert_eq!(attestation.attested_at, Some(timestamp));
    if let Ok(directory) = std::env::var("CDK_D2_FIXTURE_DIR") {
        std::fs::write(
            std::path::Path::new(&directory).join("sqlite-condition-info.json"),
            serde_json::to_string_pretty(&info).unwrap(),
        )
        .unwrap();
    }
    mint.stop().await.unwrap();
    drop(mint);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the disposable PostgreSQL fixture in PG_DB_URL"]
async fn test_d2_postgres_real_mint_reopen_races_and_evidence() {
    let Some(url) = std::env::var("PG_DB_URL").ok() else {
        panic!("PG_DB_URL is required for the real provider test");
    };
    let url = format!("{url} schema=d2_mint_{}", uuid::Uuid::new_v4().simple());
    let db = Arc::new(
        cdk_postgres::MintPgDatabase::new(url.as_str())
            .await
            .unwrap(),
    );
    let (condition, evidence, timestamp) =
        provider_first_resolution_races_and_roundtrip(db, "postgres").await;
    let reopened = Arc::new(
        cdk_postgres::MintPgDatabase::new(url.as_str())
            .await
            .unwrap(),
    );
    let mint = build_test_mint_with_units(reopened, &[7; 64], &[(CurrencyUnit::Sat, 0)])
        .await
        .unwrap();
    let info = mint
        .get_condition_with_oracle_sigs(&condition, true)
        .await
        .unwrap();
    let attestation = info.attestation.as_ref().unwrap();
    assert_eq!(attestation.oracle_sigs.as_ref(), Some(&evidence));
    assert_eq!(attestation.attested_at, Some(timestamp));
    if let Ok(directory) = std::env::var("CDK_D2_FIXTURE_DIR") {
        std::fs::write(
            std::path::Path::new(&directory).join("postgres-condition-info.json"),
            serde_json::to_string_pretty(&info).unwrap(),
        )
        .unwrap();
    }
    mint.stop().await.unwrap();
}

#[tokio::test]
async fn test_d2_numeric_shape_digit_positions_and_conflict() {
    let mint = create_test_mint().await.unwrap();
    let funding = mint_test_proofs(&mint, Amount::from(16)).await.unwrap();
    let (condition, keysets) = register_numeric_condition(&mint, 0, 100000).await;
    let inputs = convert_to_conditional(&mint, funding, keysets["HI"], Amount::from(16)).await;
    let oracle = create_test_oracle();
    let witness = create_numeric_oracle_witness(&oracle, 50000, 10, false, 5);
    assert!(witness.oracle_sigs[0].outcome.is_none());
    let json = serde_json::to_value(&witness).unwrap();
    assert!(json["oracle_sigs"][0].get("outcome").is_none());
    assert!(json["oracle_sigs"][0].get("oracle_sig").is_none());
    let decoded: OracleWitness = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, witness);
    let mut cases = Vec::new();
    let mut bad = witness.clone();
    bad.oracle_sigs[0].outcome = Some("50000".to_string());
    cases.push(bad);
    let mut bad = witness.clone();
    bad.oracle_sigs[0].oracle_sig = Some("00".repeat(64));
    cases.push(bad);
    let mut bad = witness.clone();
    bad.oracle_sigs[0].digit_sigs.as_mut().unwrap().swap(0, 1);
    cases.push(bad);
    let mut bad = witness.clone();
    bad.oracle_sigs[0].digit_sigs.as_mut().unwrap().pop();
    cases.push(bad);
    let mut bad = witness.clone();
    bad.oracle_sigs.push(bad.oracle_sigs[0].clone());
    cases.push(bad);
    for bad in cases {
        let mut request = redemption(&mint, inputs.clone(), Some(&bad));
        request.outputs = create_premint(&mint, get_regular_keyset_id(&mint), Amount::from(8)).0;
        assert!(mint.process_redeem_outcome(request).await.is_err());
        assert!(mint
            .localstore()
            .get_condition(&condition)
            .await
            .unwrap()
            .unwrap()
            .oracle_sigs
            .is_none());
        assert!(mint
            .localstore()
            .get_proofs_states(&inputs.ys().unwrap())
            .await
            .unwrap()
            .iter()
            .all(Option::is_none));
    }
    // Evidence is checked before the spent-proof retry checks too.
    let mut request = redemption(&mint, inputs.clone(), Some(&witness));
    request.outputs = create_premint(&mint, get_regular_keyset_id(&mint), Amount::from(8)).0;
    mint.process_redeem_outcome(request).await.unwrap();
    let original = mint
        .localstore()
        .get_condition(&condition)
        .await
        .unwrap()
        .unwrap();
    let conflicting = create_numeric_oracle_witness(&oracle, 60000, 10, false, 5);
    assert!(matches!(
        mint.process_redeem_outcome(redemption(&mint, inputs, Some(&conflicting)))
            .await,
        Err(Error::ConflictingOracleAttestations)
    ));
    let preserved = mint
        .localstore()
        .get_condition(&condition)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.oracle_sigs, original.oracle_sigs);
    assert_eq!(preserved.attested_at, original.attested_at);
}

#[tokio::test]
async fn test_d2_numeric_request_aggregation_and_separate_floors() {
    // One face-6 request pays 3 units. Two face-3 requests pay 1 unit each.
    for (collection, aggregate) in [("HI", true), ("LO", true), ("HI", false), ("LO", false)] {
        let mint = create_test_mint().await.unwrap();
        let funding = mint_test_proofs(&mint, Amount::from(7)).await.unwrap();
        let (_condition, keysets) = register_numeric_condition(&mint, 0, 100000).await;
        let keyset = keysets[collection];
        let keys = mint.keyset_pubkeys(&keyset).unwrap().keysets.remove(0).keys;
        let fees = (
            0,
            keys.iter()
                .map(|(amount, _)| amount.to_u64())
                .collect::<Vec<_>>(),
        );
        let premint = PreMintSecrets::random(
            keyset,
            Amount::from(7),
            &SplitTarget::Value(Amount::ONE),
            &fees.into(),
        )
        .unwrap();
        let mut inputs = convert_to_conditional_premint(&mint, funding, premint).await;
        assert_eq!(inputs.len(), 7);
        assert!(inputs.iter().all(|proof| proof.amount == Amount::ONE));
        let witness = create_numeric_oracle_witness(&create_test_oracle(), 50000, 10, false, 5);
        let single = inputs.pop().unwrap();
        let single_y = single.y().unwrap();
        assert!(matches!(
            mint.process_redeem_outcome(redemption(&mint, vec![single], Some(&witness)))
                .await,
            Err(Error::TransactionUnbalanced(0, 1, 0))
        ));
        assert_eq!(
            mint.localstore()
                .get_proofs_states(&[single_y])
                .await
                .unwrap(),
            vec![None]
        );
        let group_size = if aggregate { 6 } else { 3 };
        let payout = if aggregate { 3 } else { 1 };
        let mut received = 0u64;
        for group in inputs.chunks(group_size) {
            assert_eq!(
                mint.get_proofs_fee(&group.to_vec()).await.unwrap().total,
                Amount::ZERO
            );
            let ys = group.to_vec().ys().unwrap();
            if !aggregate {
                let mut overpay = redemption(&mint, group.to_vec(), Some(&witness));
                overpay.outputs =
                    create_premint(&mint, get_regular_keyset_id(&mint), Amount::from(2)).0;
                assert!(matches!(
                    mint.process_redeem_outcome(overpay).await,
                    Err(Error::TransactionUnbalanced(1, 2, 0))
                ));
                assert!(mint
                    .localstore()
                    .get_proofs_states(&ys)
                    .await
                    .unwrap()
                    .iter()
                    .all(Option::is_none));
            }
            let mut request = redemption(&mint, group.to_vec(), Some(&witness));
            request.outputs =
                create_premint(&mint, get_regular_keyset_id(&mint), Amount::from(payout)).0;
            let result = mint.process_redeem_outcome(request).await.unwrap();
            assert!(mint
                .localstore()
                .get_proofs_states(&ys)
                .await
                .unwrap()
                .iter()
                .all(|state| *state == Some(State::Spent)));
            received += result
                .signatures
                .iter()
                .map(|signature| u64::from(signature.amount))
                .sum::<u64>();
        }
        assert_eq!(received, if aggregate { 3 } else { 2 });
    }
}
