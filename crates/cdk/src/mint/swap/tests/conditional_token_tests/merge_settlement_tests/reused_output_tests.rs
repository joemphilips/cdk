//! Mint premises for the attribution of a reused settlement output.
//!
//! An attribution reads a refused request R with one NUT-09 restore. It
//! relies on these mint facts: the mint refuses an already signed output in
//! the transaction that commits, after it takes the condition row lock; the
//! refusal lists that output as signed, and the same transaction records
//! that R can never commit; a commit stores the signature of every output of
//! R or of none; a stored signature is permanent; and the restore returns
//! the stored signature of the operation that signed the output.

use cdk_common::nuts::nut_ctf::settlement::{OutputConflict, OutputConflictState};
use cdk_common::nuts::{RestoreRequest, RestoreResponse};

use super::*;

/// Two locked buyers MINT one complete set of 8.
///
/// The YES buyer locks 4 collateral and receives `yes_receive`. The NO buyer
/// locks 1 + 4 collateral and receives 8 NO. Three 1-ppk input proofs pay 1.
async fn mint_pair_request(
    mint: &Mint,
    condition_id: &str,
    keysets: &HashMap<String, Id>,
    yes_receive: &[BlindedMessage],
    now: u64,
    first_nonce: u8,
) -> CtfSettlementRequest {
    let regular = get_regular_keyset_id(mint);
    let no_receive = create_premint(mint, keysets["NO"], Amount::from(8)).0;
    let expiry = now + OFFER_LIFETIME_SECONDS;
    let [yes_inputs, no_inputs]: [Proofs; 2] = issue_regular_premints(
        mint,
        &[
            pay_to_unlock_premint(regular, &[4], yes_receive, expiry, first_nonce),
            pay_to_unlock_premint(regular, &[1, 4], &no_receive, expiry, first_nonce + 1),
        ],
    )
    .await
    .try_into()
    .unwrap();
    settlement_request(
        condition_id,
        vec![
            settlement_record(yes_inputs, yes_receive.to_vec()),
            settlement_record(no_inputs, no_receive),
        ],
    )
}

fn request_outputs(request: &CtfSettlementRequest) -> Vec<BlindedMessage> {
    request
        .participants
        .iter()
        .flat_map(|participant| participant.outputs.iter().cloned())
        .collect()
}

async fn restore(mint: &Mint, outputs: Vec<BlindedMessage>) -> RestoreResponse {
    mint.restore(RestoreRequest { outputs }).await.unwrap()
}

/// Request R reuses one output that request W signs first, as one seed open on two devices does.
///
/// R reaches its commit transaction after W commits. In that transaction the
/// mint refuses R, lists the reused output as signed, and records that R can
/// never commit. It writes nothing else for R and keeps W's signature. A
/// retry of R gets the same refusal.
async fn assert_reused_output_is_refused_at_commit(mint: Mint) {
    let now = unix_time();
    let (condition_id, keysets) =
        register_test_condition_with_collateral(&mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let coverage = binary_coverage(get_regular_keyset_id(&mint), keysets["YES"], keysets["NO"]);
    let shared = create_premint(&mint, keysets["YES"], Amount::from(8)).0;
    let reused = mint_pair_request(&mint, &condition_id, &keysets, &shared, now, 0x10).await;
    let winner = mint_pair_request(&mint, &condition_id, &keysets, &shared, now, 0x20).await;
    for request in [&reused, &winner] {
        assert_eq!(
            outcome_totals(request, &coverage),
            totals(&[("NO", (9, 8)), ("YES", (9, 8))])
        );
    }
    let reused_only = request_outputs(&reused)
        .into_iter()
        .filter(|output| !shared.contains(output))
        .collect::<Vec<_>>();
    assert!(!reused_only.is_empty());
    let (reused_ys, _) = settlement_storage_keys(&reused.participants);
    let completed_before = completed_swap_count(&mint).await;

    // R signs every output in memory, then pauses before its commit transaction.
    let (reached, release) = mint.arm_atomic_ctf_test_pause().await;
    let reused_mint = mint.clone();
    let reused_request = reused.clone();
    let reused_task = tokio::spawn(async move {
        reused_mint
            .process_ctf_settlement(&reused_request, settlement_settings(), now)
            .await
    });
    timeout(Duration::from_secs(5), reached)
        .await
        .expect("R must reach the pause before its commit transaction")
        .expect("pause sender");
    let winning = commit_and_check(&mint, &winner, now, 1).await;
    release.send(()).expect("R must still wait at the pause");
    let error = timeout(Duration::from_secs(5), reused_task)
        .await
        .expect("R must finish after release")
        .expect("R task")
        .expect_err("R must not commit an output that W signed");
    // `shared` is one YES 8 output, the only output that W also signed.
    let signed_conflicts = vec![OutputConflict {
        blinded_secret: shared[0].blinded_secret,
        state: OutputConflictState::Signed,
    }];
    assert_eq!(shared.len(), 1);
    assert!(
        matches!(
            &error,
            CtfSettlementError::OutputConflict(conflicts)
                if conflicts.outputs() == signed_conflicts.as_slice()
        ),
        "{error:?}"
    );

    let shared_signature = winning.signatures[participant_with_outputs(&winner, &shared)].clone();
    let trace = ReusedRequestTrace {
        request: &reused,
        input_ys: reused_ys,
        own_outputs: reused_only,
        completed_after_winner: completed_before + 1,
        shared_outputs: shared,
        shared_signatures: shared_signature,
        conflicts: signed_conflicts,
        cutoff: now + OFFER_LIFETIME_SECONDS,
    };
    trace
        .assert_refused(&mint, "after the paused attempt")
        .await;

    let error = mint
        .process_ctf_settlement(&reused, settlement_settings(), now)
        .await
        .expect_err("a request with a signed output can never commit");
    assert!(
        matches!(
            &error,
            CtfSettlementError::OutputConflict(conflicts)
                if conflicts.outputs() == trace.conflicts.as_slice()
        ),
        "{error:?}"
    );
    trace.assert_refused(&mint, "after a retry").await;
}

/// The stored facts of a reused-output request R that the mint refused.
struct ReusedRequestTrace<'a> {
    request: &'a CtfSettlementRequest,
    input_ys: Vec<cdk_common::PublicKey>,
    /// R's outputs that no other request uses.
    own_outputs: Vec<BlindedMessage>,
    completed_after_winner: usize,
    /// R's outputs that the winning request signed, and their signatures.
    shared_outputs: Vec<BlindedMessage>,
    shared_signatures: Vec<cdk_common::BlindSignature>,
    /// The refusal's conflict list.
    conflicts: Vec<OutputConflict>,
    /// R's earliest authorization expiry.
    cutoff: u64,
}

impl ReusedRequestTrace<'_> {
    async fn assert_refused(&self, mint: &Mint, attempt: &str) {
        let db = mint.localstore();
        assert!(
            db.get_proofs_states(&self.input_ys)
                .await
                .unwrap()
                .iter()
                .all(Option::is_none),
            "{attempt}: R's inputs must stay unrecorded"
        );
        let own_points = self
            .own_outputs
            .iter()
            .map(|output| output.blinded_secret)
            .collect::<Vec<_>>();
        assert!(
            db.get_blind_signatures(&own_points)
                .await
                .unwrap()
                .iter()
                .all(Option::is_none),
            "{attempt}: R's own outputs must stay unsigned"
        );
        // A refused R must not leave pending rows that block its own outputs.
        assert_outputs_have_no_rows(mint, &self.own_outputs).await;
        assert_eq!(
            completed_swap_count(mint).await,
            self.completed_after_winner,
            "{attempt}: only the winning request completed"
        );
        match db
            .get_ctf_settlement_replay(self.request.request_digest().unwrap())
            .await
            .unwrap()
        {
            Some(CtfSettlementReplay::RejectedOutputConflict { conflicts, cutoff }) => {
                assert_eq!(conflicts.outputs(), self.conflicts.as_slice(), "{attempt}");
                assert_eq!(cutoff, Some(self.cutoff), "{attempt}");
            }
            other => panic!("{attempt}: R must have its no-commit record, got {other:?}"),
        }
        // One NUT-09 read of all of R's outputs: the reused output is signed and the others are not.
        assert_eq!(
            restore(mint, request_outputs(self.request)).await,
            RestoreResponse {
                outputs: self.shared_outputs.clone(),
                signatures: self.shared_signatures.clone(),
            },
            "{attempt}: the stored signature of the winning request is permanent"
        );
    }
}

#[tokio::test]
async fn test_ctf_settlement_reused_output_is_refused_in_the_commit_transaction() {
    assert_reused_output_is_refused_at_commit(
        create_test_mint_with_unit(CurrencyUnit::Sat, 1)
            .await
            .unwrap(),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL database in PG_DB_URL"]
async fn test_postgres_ctf_settlement_reused_output_is_refused_in_the_commit_transaction() {
    let url = std::env::var("PG_DB_URL").expect("isolated PostgreSQL test database");
    let url = format!(
        "{url} schema=ctf_reused_output_{}",
        uuid::Uuid::new_v4().simple()
    );
    let db = Arc::new(
        cdk_postgres::MintPgDatabase::new(url.as_str())
            .await
            .unwrap(),
    );
    let mint = build_test_mint_with_units(db, &[33; 32], &[(CurrencyUnit::Sat, 1)])
        .await
        .unwrap();
    assert_reused_output_is_refused_at_commit(mint.clone()).await;
    mint.stop().await.unwrap();
}

/// A commit stores every output signature of the request or none of them.
///
/// Each failure point lies inside the commit transaction. It follows the
/// in-memory signing of every output.
#[tokio::test]
async fn test_ctf_settlement_commit_stores_every_output_signature_or_none() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    // Eight 1-ppk input proofs pay ceil(8 / 1000) = 1, so S2 receives 10 - 1.
    let fixture = match_bundle_fixture(&mint, now, None, 9).await;
    let request = &fixture.request;
    assert_eq!(
        outcome_totals(request, &fixture.coverage()),
        totals(&[("NO", (28, 27)), ("YES", (36, 35))])
    );
    let outputs = request_outputs(request);
    let completed_before = completed_swap_count(&mint).await;
    for failure_point in [
        "ADD_SIGNATURES",
        "UPDATE_PROOFS",
        "ADD_COMPLETED_OPERATION",
        "ADD_CTF_SETTLEMENT_REPLAY",
    ] {
        let signing_before = mint.blind_sign_attempts();
        set_fail_for(failure_point);
        let failed = mint
            .process_ctf_settlement(request, settlement_settings(), now)
            .await;
        clear_fail_for(failure_point);
        assert!(failed.is_err(), "{failure_point}");
        assert_eq!(
            mint.blind_sign_attempts(),
            signing_before + 1,
            "{failure_point}: the attempt signs before its commit transaction"
        );
        assert_request_absent(&mint, request, completed_before).await;
        assert_eq!(
            restore(&mint, outputs.clone()).await,
            RestoreResponse {
                outputs: Vec::new(),
                signatures: Vec::new(),
            },
            "{failure_point}: no output signature may remain"
        );
    }

    let response = commit_and_check(&mint, request, now, 1).await;
    assert_eq!(
        restore(&mint, outputs.clone()).await,
        RestoreResponse {
            outputs,
            signatures: response.signatures.concat(),
        },
        "a commit stores the signature of every output"
    );
}
