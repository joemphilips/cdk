//! Provider evidence for competing swaps with one fixed output and distinct change.
//! These tests do not implement a wallet allocation or disaster recovery policy.

use super::*;
use cdk_common::dhke::blind_message;
use cdk_common::nuts::{BlindedMessage, PreMint, Proofs, RestoreRequest};
use futures::FutureExt;

use crate::mint::swap::swap_saga::SwapSaga;

const DEADLINE: Duration = Duration::from_secs(20);
const VECTOR_SEED: [u8; 64] = [73; 64];

fn output(id: Id, counter: u32, amount: u64, seed: &[u8; 64]) -> PreMint {
    let secret = Secret::from_seed(seed, id, counter).unwrap();
    let r = SecretKey::from_seed(seed, id, counter).unwrap();
    let (blinded, r) = blind_message(&secret.to_bytes(), Some(r)).unwrap();
    PreMint {
        blinded_message: BlindedMessage::new(Amount::from(amount), id, blinded),
        secret,
        r,
        amount: Amount::from(amount),
        derivation_index: Some(counter),
    }
}

fn fixed_vector(id: Id, net: u64) -> PreMintSecrets {
    fixed_vector_at(id, net, 0)
}

fn fixed_vector_at(id: Id, net: u64, block: u32) -> PreMintSecrets {
    assert!(net > 0);
    let base = block * 300;
    let mut result = PreMintSecrets::new(id);
    for bit in 0..64 {
        if (net - 1) & (1_u64 << bit) != 0 {
            result
                .secrets
                .push(output(id, base + 235 + bit, 1_u64 << bit, &VECTOR_SEED));
        }
    }
    result.secrets.push(output(id, base + 299, 1, &VECTOR_SEED));
    result
}

async fn inputs(mint: &Mint, id: Id, amount: u64, nonce: u8) -> Proofs {
    // Issue a valid fixture signature directly. The test targets swap persistence,
    // not invoice polling. Distinct public fixture seeds give disjoint inputs.
    let material = output(id, 0, amount, &[nonce; 64]);
    let signatures = mint
        .signatory
        .blind_sign(vec![material.blinded_message])
        .await
        .unwrap();
    let keys = mint.keyset_pubkeys(&id).unwrap().keysets[0].keys.clone();
    construct_proofs(signatures, vec![material.r], vec![material.secret], &keys).unwrap()
}

async fn assert_unspent(mint: &Mint, proofs: &Proofs) {
    let states = mint
        .localstore()
        .get_proofs_states(&proofs.ys().unwrap())
        .await
        .unwrap();
    assert!(
        states.iter().all(Option::is_none),
        "losing request changed its inputs"
    );
}

async fn assert_spent(mint: &Mint, proofs: &Proofs) {
    let states = mint
        .localstore()
        .get_proofs_states(&proofs.ys().unwrap())
        .await
        .unwrap();
    assert!(states.iter().all(|s| *s == Some(State::Spent)));
}

async fn restore_vector(mint: &Mint, id: Id, expected: &PreMintSecrets) -> Proofs {
    let block = expected
        .secrets
        .first()
        .and_then(|p| p.derivation_index)
        .unwrap_or(0)
        / 300;
    restore_vector_at(mint, id, expected, block).await
}

async fn restore_vector_at(mint: &Mint, id: Id, expected: &PreMintSecrets, block: u32) -> Proofs {
    let base = block * 300;
    let candidates = (base + 235..=base + 299)
        .map(|counter| output(id, counter, 0, &VECTOR_SEED))
        .collect::<Vec<_>>();
    let response = mint
        .restore(RestoreRequest {
            outputs: candidates
                .iter()
                .map(|p| p.blinded_message.clone())
                .collect(),
        })
        .await
        .unwrap();
    assert_eq!(response.signatures.len(), expected.secrets.len());
    assert_eq!(response.outputs.len(), expected.secrets.len());
    let expected_points = expected
        .secrets
        .iter()
        .map(|p| p.blinded_message.blinded_secret)
        .collect::<std::collections::HashSet<_>>();
    let actual_points = response
        .outputs
        .iter()
        .map(|p| p.blinded_secret)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        actual_points, expected_points,
        "restore must include each selected output exactly once"
    );
    let mut result = Vec::new();
    let keys = mint.keyset_pubkeys(&id).unwrap().keysets[0].keys.clone();
    for (message, signature) in response.outputs.iter().zip(response.signatures) {
        let matching = expected
            .secrets
            .iter()
            .find(|p| p.blinded_message.blinded_secret == message.blinded_secret)
            .expect("restore returned an unselected vector slot");
        assert_eq!(signature.amount, matching.amount);
        assert_eq!(signature.keyset_id, id);
        result.extend(
            construct_proofs(
                vec![signature],
                vec![matching.r.clone()],
                vec![matching.secret.clone()],
                &keys,
            )
            .unwrap(),
        );
    }
    if !result.is_empty() {
        mint.verify_inputs(&result)
            .await
            .expect("restored proofs must verify");
    }
    result
}

async fn pending_conflict(mint: &Mint, conditional: bool) {
    let regular = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    let id = if conditional {
        let (_, keys) =
            register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Msat).await;
        *keys.get("YES").unwrap()
    } else {
        regular
    };
    let first = inputs(mint, id, 16, 81).await;
    let second = inputs(mint, id, 32, 82).await;
    let fee_a = mint.get_proofs_fee(&first).await.unwrap().total.to_u64();
    let fee_b = mint.get_proofs_fee(&second).await.unwrap().total.to_u64();
    let outputs_a = fixed_vector(id, 16 - fee_a);
    let outputs_b = fixed_vector(id, 32 - fee_b);
    let verification = mint.verify_inputs(&first).await.unwrap();
    let saga = SwapSaga::new(mint, mint.localstore(), mint.pubsub_manager())
        .setup_swap(&first, &outputs_a.blinded_messages(), None, verification)
        .await
        .unwrap();
    restore_vector(mint, id, &PreMintSecrets::new(id)).await;
    let loser = mint
        .process_swap_request(SwapRequest::new(
            second.clone(),
            outputs_b.blinded_messages(),
        ))
        .await;
    assert!(
        matches!(loser, Err(Error::DuplicateOutputs)),
        "different input must collide on fixed closing output"
    );
    assert_unspent(mint, &second).await;
    saga.sign_outputs().await.unwrap().finalize().await.unwrap();
    assert_spent(mint, &first).await;
    restore_vector(mint, id, &outputs_a).await;
    // Same late request after committed winner must not charge another input.
    assert!(mint
        .process_swap_request(SwapRequest::new(
            second.clone(),
            outputs_b.blinded_messages()
        ))
        .await
        .is_err());
    assert_unspent(mint, &second).await;
}

struct Conversion {
    request: CtfConvertRequest,
    proofs: Proofs,
    outputs: Vec<PreMintSecrets>,
}

async fn conversion(
    mint: &Mint,
    condition: &str,
    keys: &HashMap<String, Id>,
    amount: u64,
    nonce: u8,
) -> Conversion {
    conversion_at(mint, condition, keys, amount, nonce, 0).await
}

async fn conversion_at(
    mint: &Mint,
    condition: &str,
    keys: &HashMap<String, Id>,
    amount: u64,
    nonce: u8,
    block: u32,
) -> Conversion {
    let regular = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    let proofs = inputs(mint, regular, amount, nonce).await;
    conversion_material(mint, condition, keys, proofs, block).await
}

async fn conversion_material(
    mint: &Mint,
    condition: &str,
    keys: &HashMap<String, Id>,
    proofs: Proofs,
    block: u32,
) -> Conversion {
    let regular = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    let amount = proofs.iter().map(|p| p.amount.to_u64()).sum::<u64>();
    let fee = mint.get_proofs_fee(&proofs).await.unwrap().total.to_u64();
    assert!(amount > fee);
    let mut output_groups = HashMap::new();
    let mut outputs = Vec::new();
    for name in ["YES", "NO"] {
        let pre = fixed_vector_at(*keys.get(name).unwrap(), 1, block);
        output_groups.insert(name.to_string(), pre.blinded_messages());
        outputs.push(pre);
    }
    if amount - fee > 1 {
        let pre = fixed_vector_at(regular, amount - fee - 1, block);
        output_groups.insert("*".to_string(), pre.blinded_messages());
        outputs.push(pre);
    }
    Conversion {
        request: CtfConvertRequest {
            condition_id: condition.to_string(),
            parent_collection_id: None,
            inputs: HashMap::from([("*".to_string(), proofs.clone())]),
            outputs: output_groups,
        },
        proofs,
        outputs,
    }
}

async fn assert_conversion(mint: &Mint, fixture: &Conversion) {
    assert_spent(mint, &fixture.proofs).await;
    for outputs in &fixture.outputs {
        restore_vector(mint, outputs.keyset_id, outputs).await;
    }
}

async fn conversion_race(mint: &Mint) {
    let (condition, keys) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Msat).await;
    let first = conversion(mint, &condition, &keys, 32, 83).await;
    let winner = conversion(mint, &condition, &keys, 16, 84).await;
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    // Poll both futures in this test. Cancellation drops both; no detached
    // request task can outlive fixture cleanup.
    let driver = async {
        let arrived = timeout(Duration::from_secs(5), reached).await;
        if !matches!(arrived, Ok(Ok(()))) {
            let _ = release.send(());
            return Err("conversion barrier failed");
        }
        let second = timeout(
            Duration::from_secs(5),
            mint.process_ctf_convert(winner.request.clone()),
        )
        .await;
        let _ = release.send(());
        Ok(second)
    };
    let (first_result, second) =
        tokio::join!(mint.process_ctf_convert(first.request.clone()), driver);
    assert!(second
        .expect("barrier")
        .expect("second request deadline")
        .is_ok());
    assert!(matches!(first_result, Err(Error::DuplicateOutputs)));
    assert_unspent(mint, &first.proofs).await;
    assert_conversion(mint, &winner).await;
}

struct ClearFault;
impl Drop for ClearFault {
    fn drop(&mut self) {
        for name in ["ADD_SIGNATURES", "UPDATE_PROOFS", "ADD_COMPLETED_OPERATION"] {
            clear_fail_for(name);
        }
    }
}

async fn conversion_failures(mint: &Mint) {
    for (index, fault) in ["ADD_SIGNATURES", "UPDATE_PROOFS", "ADD_COMPLETED_OPERATION"]
        .into_iter()
        .enumerate()
    {
        let (condition, keys) =
            register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Msat).await;
        // Each successful retry closes a distinct permanent block.
        let fixture =
            conversion_at(mint, &condition, &keys, 16, 90 + index as u8, index as u32).await;
        let baseline = mint
            .localstore()
            .get_completed_operations_by_kind(cdk_common::mint::OperationKind::Swap)
            .await
            .unwrap()
            .len();
        set_fail_for(fault);
        let guard = ClearFault;
        let result = mint.process_ctf_convert(fixture.request.clone()).await;
        drop(guard);
        assert!(result.is_err());
        assert_unspent(mint, &fixture.proofs).await;
        for output in &fixture.outputs {
            restore_vector_at(
                mint,
                output.keyset_id,
                &PreMintSecrets::new(output.keyset_id),
                index as u32,
            )
            .await;
        }
        assert_eq!(
            mint.localstore()
                .get_completed_operations_by_kind(cdk_common::mint::OperationKind::Swap)
                .await
                .unwrap()
                .len(),
            baseline
        );
        mint.process_ctf_convert(fixture.request.clone())
            .await
            .unwrap();
        assert_conversion(mint, &fixture).await;
    }
}

async fn lost_response(mint: &Mint) {
    let (condition, keys) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Msat).await;
    let first = conversion(mint, &condition, &keys, 16, 95).await;
    let late = conversion(mint, &condition, &keys, 32, 96).await;
    mint.process_ctf_convert(first.request.clone())
        .await
        .unwrap(); // response deliberately discarded
    assert_conversion(mint, &first).await;
    assert!(mint.process_ctf_convert(late.request).await.is_err());
    assert_unspent(mint, &late.proofs).await;
    let regular = first.outputs.last().unwrap();
    let proofs = restore_vector(mint, regular.keyset_id, regular).await;
    let net = proofs.iter().map(|p| p.amount.to_u64()).sum::<u64>()
        - mint.get_proofs_fee(&proofs).await.unwrap().total.to_u64();
    let (fresh, _) = create_premint(mint, regular.keyset_id, Amount::from(net));
    mint.process_swap_request(SwapRequest::new(proofs.clone(), fresh))
        .await
        .unwrap();
    assert_spent(mint, &proofs).await;
    restore_vector(mint, regular.keyset_id, regular).await;
}

async fn restart(mint: &Mint) {
    let id = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    let first = inputs(mint, id, 16, 97).await;
    let material = fixed_vector(id, 15);
    let verification = mint.verify_inputs(&first).await.unwrap();
    let saga = SwapSaga::new(mint, mint.localstore(), mint.pubsub_manager())
        .setup_swap(&first, &material.blinded_messages(), None, verification)
        .await
        .unwrap();
    drop(saga); // model process loss at durable TX1, with no live request task
    mint.stop().await.unwrap();
    mint.start().await.unwrap();
    assert_unspent(mint, &first).await;
    restore_vector(mint, id, &PreMintSecrets::new(id)).await;
    mint.process_swap_request(SwapRequest::new(first.clone(), material.blinded_messages()))
        .await
        .unwrap();
    mint.stop().await.unwrap();
    mint.start().await.unwrap();
    assert_spent(mint, &first).await;
    restore_vector(mint, id, &material).await;
}

async fn late_ordinary(mint: &Mint) {
    let id = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    let old_inputs = inputs(mint, id, 8, 101).await;
    let mut old_outputs = PreMintSecrets::new(id);
    for (counter, amount) in [(7, 1), (8, 2), (9, 4)] {
        old_outputs
            .secrets
            .push(output(id, counter, amount, &VECTOR_SEED));
    }
    let verification = mint.verify_inputs(&old_inputs).await.unwrap();
    let old = SwapSaga::new(mint, mint.localstore(), mint.pubsub_manager())
        .setup_swap(
            &old_inputs,
            &old_outputs.blinded_messages(),
            None,
            verification,
        )
        .await
        .unwrap();
    let query = RestoreRequest {
        outputs: old_outputs.blinded_messages(),
    };
    assert!(mint
        .restore(query.clone())
        .await
        .unwrap()
        .signatures
        .is_empty());

    let new_inputs = inputs(mint, id, 16, 102).await;
    let closing = fixed_vector(id, 15);
    mint.process_swap_request(SwapRequest::new(new_inputs, closing.blinded_messages()))
        .await
        .unwrap();
    restore_vector(mint, id, &closing).await;
    assert!(mint
        .restore(query.clone())
        .await
        .unwrap()
        .signatures
        .is_empty());

    // Closing evidence permits allocation. It does not make an earlier balance
    // scan complete: this disjoint request can still finish below the anchor.
    old.sign_outputs().await.unwrap().finalize().await.unwrap();
    assert_spent(mint, &old_inputs).await;
    let response = mint.restore(query).await.unwrap();
    assert_eq!(response.signatures.len(), 3);
    assert_eq!(response.outputs, old_outputs.blinded_messages());
    let keys = mint.keyset_pubkeys(&id).unwrap().keysets[0].keys.clone();
    let proofs = construct_proofs(
        response.signatures,
        old_outputs.rs(),
        old_outputs.secrets(),
        &keys,
    )
    .unwrap();
    mint.verify_inputs(&proofs).await.unwrap();
    restore_vector(mint, id, &closing).await;
}

async fn small_conversion(mint: &Mint, net: u64) {
    let (condition, keys) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Msat).await;
    let regular = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    let mut proofs = inputs(mint, regular, 2, 110).await;
    if net == 2 {
        proofs.extend(inputs(mint, regular, 2, 111).await);
    }
    let fee = mint.get_proofs_fee(&proofs).await.unwrap().total.to_u64();
    assert_eq!(
        proofs.iter().map(|p| p.amount.to_u64()).sum::<u64>() - fee,
        net
    );
    let fixture = conversion_material(mint, &condition, &keys, proofs, 0).await;
    if net == 1 {
        assert!(!fixture.request.outputs.contains_key("*"));
    } else {
        assert_eq!(fixture.request.outputs["*"].len(), 1);
        assert_eq!(fixture.request.outputs["*"][0].amount, Amount::from(1));
    }
    mint.process_ctf_convert(fixture.request.clone())
        .await
        .unwrap();
    assert_conversion(mint, &fixture).await;
    if net == 1 {
        restore_vector(mint, regular, &PreMintSecrets::new(regular)).await;
    }
}

async fn shared_regular_replan(mint: &Mint) {
    let (condition_a, keys_a) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Msat).await;
    let oracle = create_test_oracle();
    let (_, announcement) =
        create_test_announcement(&oracle, &["YES", "NO"], "fixed-anchor-second-condition");
    let mut request = enum_condition_request("Second fixed anchor condition", vec![announcement]);
    request.collateral = Some(CurrencyUnit::Msat.to_string());
    let second = mint.register_condition(request).await.unwrap();
    let (condition_b, keys_b) = (second.condition_id, second.keysets);
    assert_ne!(condition_a, condition_b);
    assert_ne!(keys_a["YES"], keys_b["YES"]);
    let winner = conversion(mint, &condition_a, &keys_a, 16, 112).await;
    let mut loser = conversion(mint, &condition_b, &keys_b, 32, 113).await;
    let conditional_intent = loser
        .request
        .outputs
        .iter()
        .filter(|(name, _)| name.as_str() != "*")
        .map(|(name, values)| (name.clone(), values.clone()))
        .collect::<HashMap<_, _>>();
    mint.process_ctf_convert(winner.request.clone())
        .await
        .unwrap();
    assert!(matches!(
        mint.process_ctf_convert(loser.request.clone()).await,
        Err(Error::DuplicateOutputs)
    ));
    assert_unspent(mint, &loser.proofs).await;
    assert_conversion(mint, &winner).await;
    for name in ["YES", "NO"] {
        let id = keys_b[name];
        restore_vector(mint, id, &PreMintSecrets::new(id)).await;
    }
    // Only the collided regular block changes. The conditional output intent
    // remains exact, and no output is admitted from the refused conversion.
    let regular = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    let next = fixed_vector_at(regular, 30, 1);
    loser
        .request
        .outputs
        .insert("*".to_string(), next.blinded_messages());
    *loser.outputs.last_mut().unwrap() = next;
    for (name, values) in conditional_intent {
        assert_eq!(loser.request.outputs[&name], values);
    }
    mint.process_ctf_convert(loser.request.clone())
        .await
        .unwrap();
    assert_conversion(mint, &loser).await;
    assert_conversion(mint, &winner).await;
}

async fn run_scenario(postgres: bool, scenario: u8) {
    let mint = timeout(DEADLINE, async {
        if postgres {
            let url = std::env::var("PG_DB_URL").expect("owned disposable PostgreSQL required");
            let url = format!(
                "{url} schema=fixed_anchor_{}",
                uuid::Uuid::new_v4().simple()
            );
            let db = Arc::new(
                cdk_postgres::MintPgDatabase::new(url.as_str())
                    .await
                    .unwrap(),
            );
            build_test_mint_with_units(db, &[74; 32], &[(CurrencyUnit::Msat, 1000)])
                .await
                .unwrap()
        } else {
            create_test_mint_with_unit(CurrencyUnit::Msat, 1000)
                .await
                .unwrap()
        }
    })
    .await
    .expect("fixture deadline");
    let result = panic::AssertUnwindSafe(timeout(DEADLINE, async {
        match scenario {
            0 => pending_conflict(&mint, false).await,
            1 => pending_conflict(&mint, true).await,
            2 => conversion_race(&mint).await,
            3 => conversion_failures(&mint).await,
            4 => lost_response(&mint).await,
            5 => restart(&mint).await,
            6 => late_ordinary(&mint).await,
            7 => small_conversion(&mint, 1).await,
            8 => small_conversion(&mint, 2).await,
            9 => shared_regular_replan(&mint).await,
            _ => unreachable!(),
        }
    }))
    .catch_unwind()
    .await;
    let stopped = timeout(Duration::from_secs(5), mint.stop()).await;
    if let Err(error) = result {
        panic::resume_unwind(error);
    }
    result.unwrap().expect("scenario deadline");
    stopped.expect("cleanup deadline").expect("stop owned mint");
}

macro_rules! cases {
    ($($sqlite:ident, $postgres:ident, $number:expr;)*) => {$ (
        #[tokio::test(flavor = "current_thread")]
        async fn $sqlite() { run_scenario(false, $number).await; }
        #[tokio::test(flavor = "current_thread")]
        #[ignore = "requires owned disposable PostgreSQL in PG_DB_URL"]
        async fn $postgres() { run_scenario(true, $number).await; }
    )*};
}

cases! {
    fixed_anchor_pending_regular, fixed_anchor_postgres_pending_regular, 0;
    fixed_anchor_pending_conditional, fixed_anchor_postgres_pending_conditional, 1;
    fixed_anchor_conversion_race, fixed_anchor_postgres_conversion_race, 2;
    fixed_anchor_conversion_failures, fixed_anchor_postgres_conversion_failures, 3;
    fixed_anchor_lost_response, fixed_anchor_postgres_lost_response, 4;
    fixed_anchor_restart, fixed_anchor_postgres_restart, 5;
    fixed_anchor_late_ordinary, fixed_anchor_postgres_late_ordinary, 6;
    fixed_anchor_net_one, fixed_anchor_postgres_net_one, 7;
    fixed_anchor_net_two, fixed_anchor_postgres_net_two, 8;
    fixed_anchor_shared_regular_replan, fixed_anchor_postgres_shared_regular_replan, 9;
}
