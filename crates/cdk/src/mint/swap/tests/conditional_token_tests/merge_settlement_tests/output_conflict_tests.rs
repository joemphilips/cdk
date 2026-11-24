//! Output conflict detail of a refused settlement request.
//!
//! When an output of request R is signed, or is pending in another
//! operation, the mint refuses R and lists each such output with its state.
//! In the same transaction it records that R can never commit. Until R's
//! earliest authorization expiry, a later copy of R gets the same refusal,
//! also after the other operation is removed.

use cdk_common::database::mint::OutputConflictRecord;
use cdk_common::melt::MeltQuoteRequest;
use cdk_common::nuts::nut_ctf::settlement::{
    NutCtfSplitMergeSettings, OutputConflict, OutputConflictState, OutputConflicts,
};
use cdk_common::nuts::{MeltQuoteBolt11Request, MeltRequest};
use cdk_fake_wallet::{create_fake_invoice, FakeInvoiceDescription};

use super::*;
use crate::mint::melt::melt_saga::MeltSaga;
use crate::mint::state_limits::{
    StateLimits, MAX_OUTPUT_CONFLICT_RECORDS, SETTLEMENT_RECORD_RETENTION_SECS,
};

fn conflict(output: &BlindedMessage, state: OutputConflictState) -> OutputConflict {
    OutputConflict {
        blinded_secret: output.blinded_secret,
        state,
    }
}

fn outputs_in_request_order(request: &CtfSettlementRequest) -> Vec<BlindedMessage> {
    request
        .participants
        .iter()
        .flat_map(|participant| participant.outputs.iter().cloned())
        .collect()
}

/// Set up a melt and hold it before payment, as a participant can do.
///
/// The returned saga keeps its change outputs pending until it is released.
async fn hold_melt(mint: &Mint, change: Vec<BlindedMessage>) -> impl Send {
    let inputs = mint_test_proofs_for_unit(mint, Amount::from(1_000), CurrencyUnit::Sat)
        .await
        .unwrap();
    let invoice = create_fake_invoice(
        100_000,
        serde_json::to_string(&FakeInvoiceDescription::default()).unwrap(),
    );
    let quote = mint
        .get_melt_quote(MeltQuoteRequest::Bolt11(MeltQuoteBolt11Request {
            request: invoice,
            unit: CurrencyUnit::Sat,
            options: None,
        }))
        .await
        .unwrap();
    let quote_id = quote.quote().expect("single-quote method").clone();
    let request = MeltRequest::new(quote_id, inputs, Some(change));
    let verification = mint.verify_inputs(request.inputs()).await.unwrap();
    MeltSaga::new(
        Arc::new(mint.clone()),
        mint.localstore(),
        mint.pubsub_manager(),
    )
    .setup_melt(
        &request,
        verification,
        PaymentMethod::Known(KnownMethod::Bolt11),
    )
    .await
    .expect("the melt holds its change outputs pending")
}

/// End a held melt as a mint restart does: compensation removes its change outputs.
async fn compensate_held_melt(mint: &Mint, melt: impl Send) {
    drop(melt);
    mint.recover_from_incomplete_melt_sagas()
        .await
        .expect("held melt compensation");
}

/// Sign one regular output with an ordinary NUT-03 swap.
async fn sign_with_swap(mint: &Mint, output: &BlindedMessage) {
    let regular = get_regular_keyset_id(mint);
    assert_eq!(output.keyset_id, regular);
    let funding = mint_test_proofs_for_unit(mint, Amount::from(64), CurrencyUnit::Sat)
        .await
        .unwrap();
    let fee = u64::from(mint.get_proofs_fee(&funding).await.unwrap().total);
    let mut outputs = vec![output.clone()];
    outputs.extend(
        create_premint(
            mint,
            regular,
            Amount::from(64 - fee - u64::from(output.amount)),
        )
        .0,
    );
    mint.process_swap_request(SwapRequest::new(funding, outputs))
        .await
        .expect("the swap signs the output");
}

async fn refuse_with_conflicts(
    mint: &Mint,
    request: &CtfSettlementRequest,
    now: u64,
) -> OutputConflicts {
    match mint
        .process_ctf_settlement(request, settlement_settings(), now)
        .await
    {
        Err(CtfSettlementError::OutputConflict(conflicts)) => conflicts,
        other => panic!("expected an output conflict refusal, got {other:?}"),
    }
}

async fn recorded_outcome(
    mint: &Mint,
    request: &CtfSettlementRequest,
) -> Option<CtfSettlementReplay> {
    mint.localstore()
        .get_ctf_settlement_replay(request.request_digest().unwrap())
        .await
        .unwrap()
}

/// The request has a no-commit record that ends at `cutoff` and lists `conflicts`.
///
/// The record stores two bits for each output, so it is rebuilt from the
/// request's own outputs.
async fn assert_conflict_record(
    mint: &Mint,
    request: &CtfSettlementRequest,
    conflicts: &OutputConflicts,
    cutoff: u64,
) {
    let outputs = outputs_in_request_order(request);
    match recorded_outcome(mint, request).await {
        Some(CtfSettlementReplay::RejectedOutputConflict {
            record,
            cutoff: recorded,
        }) => {
            assert_eq!(recorded, cutoff);
            assert_eq!(record.output_count(), outputs.len());
            assert_eq!(record.packed_states().len(), outputs.len().div_ceil(4));
            let points = outputs
                .iter()
                .map(|output| output.blinded_secret)
                .collect::<Vec<_>>();
            assert_eq!(&record.conflicts(&points).unwrap(), conflicts);
        }
        other => panic!("expected a no-commit record, got {other:?}"),
    }
}

/// The refused request spent no input, kept no row for its other outputs,
/// and completed no swap.
async fn assert_no_other_writes(
    mint: &Mint,
    request: &CtfSettlementRequest,
    conflicting: &[BlindedMessage],
    completed_before: usize,
) {
    let (input_ys, _) = settlement_storage_keys(&request.participants);
    assert!(mint
        .localstore()
        .get_proofs_states(&input_ys)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    let own_outputs = outputs_in_request_order(request)
        .into_iter()
        .filter(|output| !conflicting.contains(output))
        .collect::<Vec<_>>();
    assert!(!own_outputs.is_empty());
    assert_outputs_have_no_rows(mint, &own_outputs).await;
    assert_eq!(completed_swap_count(mint).await, completed_before);
}

/// The bare seller's single collateral output of a two-party MERGE.
fn bare_seller_output(fixture: &TwoPartyMergeFixture) -> BlindedMessage {
    let outputs = fixture.collateral_receipts[1].1.blinded_messages();
    assert_eq!(outputs.len(), 1, "the bare seller receives one 4 output");
    outputs[0].clone()
}

/// A participant's held melt reuses a settlement output as its change output.
async fn assert_pending_conflict_is_listed_and_recorded(mint: Mint) {
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = &fixture.request;
    let reused = bare_seller_output(&fixture);
    let melt = hold_melt(&mint, vec![reused.clone()]).await;
    let completed_before = completed_swap_count(&mint).await;

    let conflicts = refuse_with_conflicts(&mint, request, now).await;
    assert_eq!(
        conflicts.outputs(),
        &[conflict(&reused, OutputConflictState::Pending)]
    );
    // The locked seller's authorization expires first; the bare seller has none.
    assert_conflict_record(&mint, request, &conflicts, now + OFFER_LIFETIME_SECONDS).await;
    assert_no_other_writes(
        &mint,
        request,
        std::slice::from_ref(&reused),
        completed_before,
    )
    .await;

    compensate_held_melt(&mint, melt).await;
    assert_outputs_have_no_rows(&mint, std::slice::from_ref(&reused)).await;

    // The record, not the removed row, refuses the copy.
    assert_eq!(refuse_with_conflicts(&mint, request, now).await, conflicts);
    assert_no_other_writes(
        &mint,
        request,
        std::slice::from_ref(&reused),
        completed_before,
    )
    .await;
}

#[tokio::test]
async fn test_ctf_settlement_output_pending_in_a_held_melt_is_listed_and_recorded() {
    assert_pending_conflict_is_listed_and_recorded(
        create_test_mint_with_unit(CurrencyUnit::Sat, 1)
            .await
            .unwrap(),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL database in PG_DB_URL"]
async fn test_postgres_ctf_settlement_output_pending_in_a_held_melt_is_listed_and_recorded() {
    let url = std::env::var("PG_DB_URL").expect("isolated PostgreSQL test database");
    let url = format!(
        "{url} schema=ctf_output_conflict_{}",
        uuid::Uuid::new_v4().simple()
    );
    let db = Arc::new(
        cdk_postgres::MintPgDatabase::new(url.as_str())
            .await
            .unwrap(),
    );
    let mint = build_test_mint_with_units(db, &[34; 32], &[(CurrencyUnit::Sat, 1)])
        .await
        .unwrap();
    assert_pending_conflict_is_listed_and_recorded(mint.clone()).await;
    mint.stop().await.unwrap();
}

/// The mint checks every output and lists each conflict once, in request order.
///
/// The bare seller declares its outputs in descending `B_` order, so request
/// order is not the order of the stored rows.
#[tokio::test]
async fn test_ctf_settlement_mixed_conflicts_are_listed_in_request_order() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let mut request = fixture.request.clone();
    let bare = participant_with_outputs(
        &request,
        std::slice::from_ref(&bare_seller_output(&fixture)),
    );
    // The bare seller receives 1 + 1 + 2 instead of one 4.
    let mut outputs = [1, 1, 2]
        .map(|amount| {
            create_premint(&mint, fixture.regular_keyset, Amount::from(amount))
                .0
                .remove(0)
        })
        .to_vec();
    outputs.sort_by_key(|output| std::cmp::Reverse(output.blinded_secret.to_bytes()));
    request.participants[bare].outputs = outputs.clone();
    let (high, middle, low) = (&outputs[0], &outputs[1], &outputs[2]);

    sign_with_swap(&mint, low).await;
    let _melt = hold_melt(&mint, vec![high.clone()]).await;
    let completed_before = completed_swap_count(&mint).await;

    let conflicts = refuse_with_conflicts(&mint, &request, now).await;
    assert_eq!(
        conflicts.outputs(),
        &[
            conflict(high, OutputConflictState::Pending),
            conflict(low, OutputConflictState::Signed),
        ]
    );
    assert!(conflicts.any_pending());
    assert_no_other_writes(
        &mint,
        &request,
        &[high.clone(), low.clone()],
        completed_before,
    )
    .await;
    assert_outputs_have_no_rows(&mint, std::slice::from_ref(middle)).await;
}

/// A copy of R that waits behind R, and a retry after R commits, replay R's response.
///
/// R's own signed outputs are never a conflict with R.
#[tokio::test]
async fn test_ctf_settlement_identical_copy_is_not_a_conflict_with_itself() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = fixture.request.clone();

    // R holds its request lock at the pause, so the copy waits for R's outcome.
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    let first_mint = mint.clone();
    let first_request = request.clone();
    let first = tokio::spawn(async move {
        first_mint
            .process_ctf_settlement(&first_request, settlement_settings(), now)
            .await
    });
    timeout(Duration::from_secs(5), reached)
        .await
        .expect("R must reach the pause before its commit transaction")
        .expect("pause sender");
    let copy_mint = mint.clone();
    let copy_request = request.clone();
    let copy = tokio::spawn(async move {
        copy_mint
            .process_ctf_settlement(&copy_request, settlement_settings(), now)
            .await
    });
    release.send(()).expect("R must still wait at the pause");

    let committed = timeout(Duration::from_secs(5), first)
        .await
        .expect("R must finish after release")
        .expect("R task")
        .expect("R commits");
    let copied = timeout(Duration::from_secs(5), copy)
        .await
        .expect("the copy must finish after R")
        .expect("copy task")
        .expect("the copy replays R");
    assert_eq!(copied, committed);
    assert_eq!(
        mint.process_ctf_settlement(&request, settlement_settings(), now)
            .await
            .expect("a retry replays R"),
        committed
    );
    assert_eq!(
        recorded_outcome(&mint, &request).await,
        Some(CtfSettlementReplay::Committed(committed))
    );
}

/// The mint refuses the request before it signs, and writes no record for it.
async fn refuse_before_signing_without_record(
    mint: &Mint,
    request: &CtfSettlementRequest,
    now: u64,
) -> CtfSettlementError {
    let signing_before = mint.blind_sign_attempts();
    let error = mint
        .process_ctf_settlement(request, settlement_settings(), now)
        .await
        .expect_err("an invalid request must be refused");
    assert_eq!(mint.blind_sign_attempts(), signing_before, "{error:?}");
    assert_eq!(recorded_outcome(mint, request).await, None, "{error:?}");
    error
}

/// A request that fails input or spending-condition verification writes no record.
#[tokio::test]
async fn test_ctf_settlement_request_without_valid_inputs_writes_no_conflict_record() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let reused = bare_seller_output(&fixture);
    let foreign = create_premint(&mint, fixture.regular_keyset, Amount::from(2)).0;
    let mut held_change = foreign.clone();
    held_change.push(reused.clone());
    let _melt = hold_melt(&mint, held_change).await;
    let bare = participant_with_outputs(&fixture.request, std::slice::from_ref(&reused));
    let locked = 1 - bare;

    // The bare seller's proof carries a signature that the mint did not make.
    let mut forged_signature = fixture.request.clone();
    forged_signature.participants[bare].inputs[0].c = SecretKey::generate().public_key();
    // The locked seller's authorization commits to other outputs than these
    // pending ones.
    let mut foreign_outputs = fixture.request.clone();
    foreign_outputs.participants[locked].outputs = foreign;

    let error = refuse_before_signing_without_record(&mint, &forged_signature, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Mint(Error::DHKE(cdk_common::dhke::Error::TokenNotVerified))
        ),
        "forged input signature: {error:?}"
    );
    let error = refuse_before_signing_without_record(&mint, &foreign_outputs, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Protocol(SettlementError::OutputCommitmentMismatch)
        ),
        "outputs outside the authorization: {error:?}"
    );
    assert_eq!(recorded_outcome(&mint, &fixture.request).await, None);
}

/// At and after R's cutoff, a copy of R gets the expiry refusal.
#[tokio::test]
async fn test_ctf_settlement_conflict_record_answers_expiry_from_the_cutoff() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let cutoff = now + OFFER_LIFETIME_SECONDS;
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = &fixture.request;
    let _melt = hold_melt(&mint, vec![bare_seller_output(&fixture)]).await;
    let conflicts = refuse_with_conflicts(&mint, request, now).await;

    assert_eq!(
        refuse_with_conflicts(&mint, request, cutoff - 1).await,
        conflicts
    );
    for at in [cutoff, cutoff + 1] {
        let error = mint
            .process_ctf_settlement(request, settlement_settings(), at)
            .await
            .expect_err("an expired request cannot commit");
        assert!(
            matches!(error, CtfSettlementError::AuthorizationExpired),
            "at {at}: {error:?}"
        );
    }
}

/// Maintenance deletes a record only after the cutoff plus the retention time.
///
/// After the deletion, a copy of R takes the ordinary expiry path. Its retention
/// has ended, so that refusal has no record either.
#[tokio::test]
async fn test_ctf_settlement_maintenance_deletes_a_conflict_record_after_its_retention() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let cutoff = now + OFFER_LIFETIME_SECONDS;
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = &fixture.request;
    let melt = hold_melt(&mint, vec![bare_seller_output(&fixture)]).await;
    let conflicts = refuse_with_conflicts(&mint, request, now).await;
    compensate_held_melt(&mint, melt).await;
    let deleted_at = cutoff + SETTLEMENT_RECORD_RETENTION_SECS;

    mint.run_maintenance(deleted_at - 1).await;
    assert_conflict_record(&mint, request, &conflicts, cutoff).await;

    mint.run_maintenance(deleted_at).await;
    assert_eq!(recorded_outcome(&mint, request).await, None);
    let error = mint
        .process_ctf_settlement(request, settlement_settings(), deleted_at)
        .await
        .expect_err("an expired request cannot commit");
    assert!(
        matches!(error, CtfSettlementError::AuthorizationExpired),
        "{error:?}"
    );
    assert_eq!(recorded_outcome(&mint, request).await, None);
}

/// Two bare sellers MERGE 8 YES and 8 NO into 4 + 3 collateral. No input is locked.
async fn bare_only_merge_request(
    mint: &Mint,
    receive: Vec<BlindedMessage>,
) -> CtfSettlementRequest {
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let regular = get_regular_keyset_id(mint);
    let [yes_funding, no_funding]: [Proofs; 2] = issue_regular_premints(
        mint,
        &[conversion_funding(mint, 8), conversion_funding(mint, 8)],
    )
    .await
    .try_into()
    .unwrap();
    let yes = convert_to_conditional(mint, yes_funding, keysets["YES"], Amount::from(8)).await;
    let no = convert_to_conditional(mint, no_funding, keysets["NO"], Amount::from(8)).await;
    let request = settlement_request(
        &condition_id,
        vec![
            settlement_record(yes, receive),
            settlement_record(no, create_premint(mint, regular, Amount::from(3)).0),
        ],
    );
    assert!(request
        .validated_authorizations(settlement_settings().structural_limits().unwrap())
        .unwrap()
        .is_empty());
    request
}

/// A request without a `PAY_TO_UNLOCK` input has no expiry, so a record for
/// it could never be deleted. The mint answers 11008 without a list, and
/// writes no record.
#[tokio::test]
async fn test_ctf_settlement_request_without_a_locked_input_gets_the_plain_refusal() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let reused = create_premint(&mint, get_regular_keyset_id(&mint), Amount::from(4)).0;
    let request = bare_only_merge_request(&mint, reused.clone()).await;
    let _melt = hold_melt(&mint, reused).await;

    let error = mint
        .process_ctf_settlement(&request, settlement_settings(), now)
        .await
        .expect_err("a reused output cannot commit");
    assert!(
        matches!(error, CtfSettlementError::Mint(Error::DuplicateOutputs)),
        "{error:?}"
    );
    assert_eq!(recorded_outcome(&mint, &request).await, None);
}

/// The settings that the mint serves in `/v1/info` are the settings of the
/// request handler. No field and no setting turns the conflict list on.
#[tokio::test]
async fn test_ctf_settlement_lists_conflicts_with_the_advertised_settings_alone() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let mut info = mint.mint_info().await.unwrap();
    info.nuts.nut_ctf_split_merge = Some(
        NutCtfSplitMergeSettings::single_party(true)
            .with_multi_party(settlement_settings())
            .unwrap(),
    );
    mint.set_mint_info(info).await.unwrap();
    let info = mint.mint_info().await.unwrap();
    let advertised = serde_json::to_value(&info).unwrap()["nuts"]["CTF-split-merge"].clone();
    assert_eq!(advertised["idempotent_retries"], true);
    assert!(
        advertised.get("output_conflict_detail").is_none(),
        "{advertised}"
    );
    let settings = info
        .nuts
        .nut_ctf_split_merge
        .and_then(|settings| settings.multi_party())
        .expect("multi-party settlement");

    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = &fixture.request;
    let reused = bare_seller_output(&fixture);
    let _melt = hold_melt(&mint, vec![reused.clone()]).await;

    let conflicts = match mint.process_ctf_settlement(request, settings, now).await {
        Err(CtfSettlementError::OutputConflict(conflicts)) => conflicts,
        other => panic!("expected an output conflict refusal, got {other:?}"),
    };
    assert_eq!(
        conflicts.outputs(),
        &[conflict(&reused, OutputConflictState::Pending)]
    );
    assert_conflict_record(&mint, request, &conflicts, now + OFFER_LIFETIME_SECONDS).await;
}

/// A record stays binding after the other operation is removed.
///
/// Until cleanup, an identical copy is refused with the recorded list. After
/// cleanup the copy can only take the expiry path, because cleanup waits past
/// the request's cutoff.
#[tokio::test]
async fn test_ctf_settlement_record_stays_binding_after_the_other_operation_is_removed() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let cutoff = now + OFFER_LIFETIME_SECONDS;
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = &fixture.request;
    let reused = bare_seller_output(&fixture);
    let melt = hold_melt(&mint, vec![reused.clone()]).await;
    let conflicts = refuse_with_conflicts(&mint, request, now).await;
    compensate_held_melt(&mint, melt).await;
    assert_outputs_have_no_rows(&mint, std::slice::from_ref(&reused)).await;

    let completed_before = completed_swap_count(&mint).await;
    for at in [now, cutoff - 1] {
        assert_eq!(
            refuse_with_conflicts(&mint, request, at).await,
            conflicts,
            "at {at}"
        );
    }
    assert_no_other_writes(
        &mint,
        request,
        std::slice::from_ref(&reused),
        completed_before,
    )
    .await;
    assert_conflict_record(&mint, request, &conflicts, cutoff).await;

    let deleted_at = cutoff + SETTLEMENT_RECORD_RETENTION_SECS;
    mint.run_maintenance(deleted_at).await;
    assert_eq!(recorded_outcome(&mint, request).await, None);
    let error = mint
        .process_ctf_settlement(request, settlement_settings(), deleted_at)
        .await
        .expect_err("an expired request cannot commit");
    assert!(
        matches!(error, CtfSettlementError::AuthorizationExpired),
        "{error:?}"
    );
    assert_eq!(completed_swap_count(&mint).await, completed_before);
}

/// Another operation can insert an output row after the conflict scan.
///
/// PostgreSQL then refuses the insert as a duplicate. The mint scans again in
/// a new transaction, so it still lists the conflict and writes the record.
#[tokio::test]
async fn test_ctf_settlement_conflict_inserted_after_the_scan_is_found_on_retry() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = &fixture.request;
    let reused = bare_seller_output(&fixture);
    let _melt = hold_melt(&mint, vec![reused.clone()]).await;

    // The first scan sees no row, as when the other insert commits after it.
    set_fail_for("MISS_OUTPUT_CONFLICT_SCAN_ONCE");
    let result = mint
        .process_ctf_settlement(request, settlement_settings(), now)
        .await;
    clear_fail_for("MISS_OUTPUT_CONFLICT_SCAN_ONCE");

    match result {
        Err(CtfSettlementError::OutputConflict(conflicts)) => assert_eq!(
            conflicts.outputs(),
            &[conflict(&reused, OutputConflictState::Pending)]
        ),
        other => panic!("expected an output conflict refusal, got {other:?}"),
    }
    assert!(matches!(
        recorded_outcome(&mint, request).await,
        Some(CtfSettlementReplay::RejectedOutputConflict { .. })
    ));
}

/// When every attempt misses a row, the mint has no record, so it must not
/// answer with a definitive refusal. The identical request later resolves.
#[tokio::test]
async fn test_ctf_settlement_conflict_missed_in_every_attempt_is_not_definitive() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let request = &fixture.request;
    let reused = bare_seller_output(&fixture);
    let _melt = hold_melt(&mint, vec![reused.clone()]).await;
    let completed_before = completed_swap_count(&mint).await;

    set_fail_for("MISS_OUTPUT_CONFLICT_SCAN");
    let result = mint
        .process_ctf_settlement(request, settlement_settings(), now)
        .await;
    clear_fail_for("MISS_OUTPUT_CONFLICT_SCAN");

    assert!(
        matches!(result, Err(CtfSettlementError::OutputConflictUnresolved)),
        "{result:?}"
    );
    assert_eq!(recorded_outcome(&mint, request).await, None);
    assert_no_other_writes(
        &mint,
        request,
        std::slice::from_ref(&reused),
        completed_before,
    )
    .await;

    let conflicts = refuse_with_conflicts(&mint, request, now).await;
    assert_eq!(
        conflicts.outputs(),
        &[conflict(&reused, OutputConflictState::Pending)]
    );
}

/// Store a record of another request, with a chosen cutoff.
async fn store_foreign_record(mint: &Mint, digest: u8, cutoff: u64) {
    let record = OutputConflictRecord::from_states(&[Some(OutputConflictState::Signed)]).unwrap();
    let mut tx = mint.localstore().begin_transaction().await.unwrap();
    tx.add_ctf_settlement_output_conflict(CanonicalHash::from_bytes([digest; 32]), &record, cutoff)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// The mint refuses the request with its conflicts, but writes no record.
async fn refuse_without_record(
    mint: &Mint,
    request: &CtfSettlementRequest,
    now: u64,
) -> OutputConflicts {
    let completed_before = completed_swap_count(mint).await;
    let conflicts = match mint
        .process_ctf_settlement(request, settlement_settings(), now)
        .await
    {
        Err(CtfSettlementError::OutputConflictUnrecorded(conflicts)) => conflicts,
        other => panic!("expected a refusal without a record, got {other:?}"),
    };
    assert_eq!(recorded_outcome(mint, request).await, None);
    let conflicting = outputs_in_request_order(request)
        .into_iter()
        .filter(|output| {
            conflicts
                .outputs()
                .iter()
                .any(|conflict| conflict.blinded_secret == output.blinded_secret)
        })
        .collect::<Vec<_>>();
    assert_no_other_writes(mint, request, &conflicting, completed_before).await;
    conflicts
}

/// The mint keeps at most its cap of live conflict records.
async fn assert_record_cap(mint: Mint) {
    let now = unix_time();
    // Two records count: the fixture request's own, and one that is past its
    // cutoff but not past its retention. One record that cleanup can delete
    // does not count.
    let mint = mint.with_state_limits(StateLimits {
        max_output_conflict_records: 2,
        ..StateLimits::default()
    });
    store_foreign_record(&mint, 0x01, now - SETTLEMENT_RECORD_RETENTION_SECS - 1).await;

    let recorded = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let _recorded_melt = hold_melt(&mint, vec![bare_seller_output(&recorded)]).await;
    store_foreign_record(&mint, 0x02, now - 1).await;
    // One record below the cap: the refusal has its list and its record.
    let recorded_conflicts = refuse_with_conflicts(&mint, &recorded.request, now).await;
    let cutoff = now + OFFER_LIFETIME_SECONDS;
    assert_conflict_record(&mint, &recorded.request, &recorded_conflicts, cutoff).await;

    // At the cap: the same refusal has no record.
    let refused = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let reused = bare_seller_output(&refused);
    let melt = hold_melt(&mint, vec![reused.clone()]).await;
    let signing_before = mint.blind_sign_attempts();
    let conflicts = refuse_without_record(&mint, &refused.request, now).await;
    assert_eq!(
        conflicts.outputs(),
        &[conflict(&reused, OutputConflictState::Pending)]
    );
    assert_eq!(mint.blind_sign_attempts(), signing_before + 1);
    assert_eq!(
        refuse_without_record(&mint, &refused.request, now).await,
        conflicts
    );
    // A stored record still answers with its list.
    assert_eq!(
        refuse_with_conflicts(&mint, &recorded.request, now).await,
        recorded_conflicts
    );

    // Cleanup frees no live record. With one more, the identical request gets
    // its list and its record.
    mint.run_maintenance(now).await;
    refuse_without_record(&mint, &refused.request, now).await;
    let raised = mint.clone().with_state_limits(StateLimits {
        max_output_conflict_records: 3,
        ..StateLimits::default()
    });
    let raised_conflicts = refuse_with_conflicts(&raised, &refused.request, now).await;
    assert_eq!(raised_conflicts, conflicts);
    assert_conflict_record(&raised, &refused.request, &conflicts, cutoff).await;
    compensate_held_melt(&mint, melt).await;
}

#[tokio::test]
async fn test_ctf_settlement_conflict_records_have_a_cap() {
    assert_eq!(
        StateLimits::default().max_output_conflict_records,
        MAX_OUTPUT_CONFLICT_RECORDS
    );
    assert_record_cap(
        create_test_mint_with_unit(CurrencyUnit::Sat, 1)
            .await
            .unwrap(),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL database in PG_DB_URL"]
async fn test_postgres_ctf_settlement_conflict_records_have_a_cap() {
    let url = std::env::var("PG_DB_URL").expect("isolated PostgreSQL test database");
    let url = format!(
        "{url} schema=ctf_output_conflict_cap_{}",
        uuid::Uuid::new_v4().simple()
    );
    let db = Arc::new(
        cdk_postgres::MintPgDatabase::new(url.as_str())
            .await
            .unwrap(),
    );
    let mint = build_test_mint_with_units(db, &[35; 32], &[(CurrencyUnit::Sat, 1)])
        .await
        .unwrap();
    assert_record_cap(mint.clone()).await;
    mint.stop().await.unwrap();
}

/// A refusal without a record is not definitive: the request commits after the
/// other operation is removed.
#[tokio::test]
async fn test_ctf_settlement_refused_at_the_record_cap_commits_after_the_conflict_ends() {
    let now = unix_time();
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap()
        .with_state_limits(StateLimits {
            max_output_conflict_records: 0,
            ..StateLimits::default()
        });
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 8).await;
    let melt = hold_melt(&mint, vec![bare_seller_output(&fixture)]).await;
    refuse_without_record(&mint, &fixture.request, now).await;

    compensate_held_melt(&mint, melt).await;
    commit_and_check(&mint, &fixture.request, now, 1).await;
}
