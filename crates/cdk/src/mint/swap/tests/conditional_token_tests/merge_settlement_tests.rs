//! Mint evidence for multi-party CTF MERGE and mixed match bundles.
//!
//! Every request goes through the multi-party `/v1/ctf/convert` path. Each
//! test states the expected input and output value per outcome. The tests
//! compute that table from a hand-written keyset coverage table, not from the
//! mint's coverage resolver.

use std::collections::{BTreeMap, BTreeSet};

use cdk_common::mint::OperationKind;
use cdk_common::nuts::nut_ctf::settlement::{CtfSettlementResponse, Error as SettlementError};
use cdk_common::nuts::{BlindedMessage, Keys, Proofs};

use super::*;
use crate::mint::settlement::PreparedCtfSettlement;

mod bundle_shape_tests;
mod output_conflict_tests;
mod production_limit_tests;
mod reused_output_tests;

const OFFER_LIFETIME_SECONDS: u64 = 60;
static EIGHT_OUTCOMES: [&str; 8] = ["A", "B", "C", "D", "E", "F", "G", "H"];
/// The registered one-vs-rest complement of `B`. It is not the complement of `A`.
static REST_OF_B: [&str; 7] = ["A", "C", "D", "E", "F", "G", "H"];

type Coverage<'a> = [(Id, &'a [&'a str])];

fn keyset_keys(mint: &Mint, keyset: Id) -> Keys {
    mint.keyset_pubkeys(&keyset).unwrap().keysets.remove(0).keys
}

/// Issue every premint as regular proofs with one paid quote and one NUT-03 swap.
///
/// The quote adds slack for the swap fee. The swap returns the rest as change.
async fn issue_regular_premints(mint: &Mint, premints: &[PreMintSecrets]) -> Vec<Proofs> {
    const SLACK: u64 = 64;
    let regular = get_regular_keyset_id(mint);
    assert!(premints.iter().all(|premint| premint.keyset_id == regular));
    let requested = premints
        .iter()
        .map(|premint| u64::from(premint.total_amount().unwrap()))
        .sum::<u64>();
    let funding =
        mint_test_proofs_for_unit(mint, Amount::from(requested + SLACK), CurrencyUnit::Sat)
            .await
            .unwrap();
    let fee = u64::from(mint.get_proofs_fee(&funding).await.unwrap().total);
    let mut outputs = premints
        .iter()
        .flat_map(PreMintSecrets::blinded_messages)
        .collect::<Vec<_>>();
    outputs.extend(create_premint(mint, regular, Amount::from(SLACK - fee)).0);
    let response = mint
        .process_swap_request(SwapRequest::new(funding, outputs))
        .await
        .unwrap();
    let keys = keyset_keys(mint, regular);
    let mut signatures = response.signatures.into_iter();
    premints
        .iter()
        .map(|premint| {
            let issued = signatures.by_ref().take(premint.len()).collect();
            construct_proofs(issued, premint.rs(), premint.secrets(), &keys).unwrap()
        })
        .collect()
}

/// Regular funding that converts to exactly `converted` at the active regular fee.
fn conversion_funding(mint: &Mint, converted: u64) -> PreMintSecrets {
    let regular = get_regular_keyset_id(mint);
    let fee_ppk = mint.get_keyset_info(&regular).unwrap().input_fee_ppk;
    // `create_premint` splits an amount into one proof per set bit.
    let funding = (converted + 1..converted + 64)
        .find(|funding| {
            funding - (u64::from(funding.count_ones()) * fee_ppk).div_ceil(1000) == converted
        })
        .expect("a funding amount that pays the conversion fee exactly");
    create_premint(mint, regular, Amount::from(funding)).1
}

/// PAY_TO_UNLOCK premints that offer one keyset for one exact output list.
///
/// All proofs share one standard authorization. Each proof has its own nonce.
fn pay_to_unlock_premint(
    offer_keyset: Id,
    amounts: &[u64],
    receive: &[BlindedMessage],
    expiry: u64,
    first_nonce: u8,
) -> PreMintSecrets {
    let commitment = ctf_receive_commitment(receive).unwrap().to_string();
    let secrets = (0..amounts.len())
        .map(|index| {
            let nonce = first_nonce + u8::try_from(index).unwrap();
            settlement_pay_to_unlock_secret(offer_keyset, commitment.clone(), expiry, nonce, None)
        })
        .collect();
    let amounts = amounts.iter().copied().map(Amount::from).collect();
    PreMintSecrets::from_secrets(offer_keyset, amounts, secrets).unwrap()
}

fn unit_premint(keyset: Id, count: usize) -> PreMintSecrets {
    let secrets = (0..count).map(|_| Secret::generate()).collect();
    PreMintSecrets::from_secrets(keyset, vec![Amount::ONE; count], secrets).unwrap()
}

/// One standard record. The input secrets decide whether it is locked or bare.
fn settlement_record(mut inputs: Proofs, outputs: Vec<BlindedMessage>) -> CtfSettlementParticipant {
    inputs.sort_by_key(|proof| (proof.keyset_id.to_string(), proof.secret.to_string()));
    CtfSettlementParticipant {
        inputs,
        outputs,
        mode: ParticipantMode::Standard,
    }
}

fn settlement_request(
    condition_id: &str,
    mut participants: Vec<CtfSettlementParticipant>,
) -> CtfSettlementRequest {
    canonicalize_settlement_participants(&mut participants);
    CtfSettlementRequest {
        condition_id: CanonicalHash::parse(condition_id, "condition_id").unwrap(),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants,
        coordinator_sig: None,
    }
}

fn participant_with_outputs(request: &CtfSettlementRequest, outputs: &[BlindedMessage]) -> usize {
    request
        .participants
        .iter()
        .position(|participant| participant.outputs == outputs)
        .expect("participant with these outputs")
}

fn binary_coverage(regular: Id, yes: Id, no: Id) -> [(Id, &'static [&'static str]); 3] {
    [(regular, &["YES", "NO"]), (yes, &["YES"]), (no, &["NO"])]
}

/// Sum input and output value per outcome from an explicit keyset coverage table.
fn outcome_totals(
    request: &CtfSettlementRequest,
    coverage: &Coverage<'_>,
) -> BTreeMap<String, (u64, u64)> {
    let covered = |keyset: Id| {
        coverage
            .iter()
            .find(|(id, _)| *id == keyset)
            .map(|(_, outcomes)| *outcomes)
            .expect("every request keyset is in the coverage table")
    };
    let mut totals = BTreeMap::<String, (u64, u64)>::new();
    for participant in &request.participants {
        for proof in &participant.inputs {
            for outcome in covered(proof.keyset_id) {
                totals.entry(outcome.to_string()).or_default().0 += u64::from(proof.amount);
            }
        }
        for output in &participant.outputs {
            for outcome in covered(output.keyset_id) {
                totals.entry(outcome.to_string()).or_default().1 += u64::from(output.amount);
            }
        }
    }
    totals
}

fn totals(entries: &[(&str, (u64, u64))]) -> BTreeMap<String, (u64, u64)> {
    entries
        .iter()
        .map(|(outcome, value)| (outcome.to_string(), *value))
        .collect()
}

fn keyset_set(keysets: impl IntoIterator<Item = Id>) -> BTreeSet<Id> {
    keysets.into_iter().collect()
}

fn input_proof_count(request: &CtfSettlementRequest, keyset: Id) -> usize {
    request
        .participants
        .iter()
        .flat_map(|participant| &participant.inputs)
        .filter(|proof| proof.keyset_id == keyset)
        .count()
}

/// The request fee is charged once and is allocated only to input keysets.
fn assert_request_fee(prepared: &PreparedCtfSettlement, expected: u64, input_keysets: &[Id]) {
    assert_eq!(prepared.fee.total, Amount::from(expected));
    assert_eq!(
        prepared
            .fee
            .per_keyset
            .values()
            .map(|fee| u64::from(*fee))
            .sum::<u64>(),
        expected,
        "the per-keyset allocation must account for the complete request fee"
    );
    assert_eq!(
        keyset_set(prepared.fee.per_keyset.keys().copied()),
        keyset_set(input_keysets.iter().copied())
    );
}

/// Commit the request, then check signatures, proof states, and the recorded fee.
async fn commit_and_check(
    mint: &Mint,
    request: &CtfSettlementRequest,
    now: u64,
    expected_fee: u64,
) -> CtfSettlementResponse {
    commit_and_check_with(mint, request, settlement_settings(), now, expected_fee).await
}

/// [`commit_and_check`] under an explicit advertised settlement capability.
async fn commit_and_check_with(
    mint: &Mint,
    request: &CtfSettlementRequest,
    settings: NutCtfSettlementSettings,
    now: u64,
    expected_fee: u64,
) -> CtfSettlementResponse {
    let db = mint.localstore();
    let before = db
        .get_completed_operations_by_kind(OperationKind::Swap)
        .await
        .unwrap();
    let response = mint
        .process_ctf_settlement(request, settings, now)
        .await
        .expect("the settlement must commit");

    assert_eq!(response.signatures.len(), request.participants.len());
    for (participant, signatures) in request.participants.iter().zip(&response.signatures) {
        assert_eq!(signatures.len(), participant.outputs.len());
        assert!(signatures
            .iter()
            .zip(&participant.outputs)
            .all(|(signature, output)| signature.amount == output.amount
                && signature.keyset_id == output.keyset_id));
    }
    let (input_ys, output_points) = settlement_storage_keys(&request.participants);
    assert_eq!(
        db.get_proofs_states(&input_ys).await.unwrap(),
        vec![Some(State::Spent); input_ys.len()]
    );
    assert!(db
        .get_blind_signatures(&output_points)
        .await
        .unwrap()
        .iter()
        .all(Option::is_some));
    let after = db
        .get_completed_operations_by_kind(OperationKind::Swap)
        .await
        .unwrap();
    let added = after
        .iter()
        .filter(|operation| before.iter().all(|old| old.id() != operation.id()))
        .collect::<Vec<_>>();
    assert_eq!(added.len(), 1, "one settlement records one completed swap");
    assert_eq!(added[0].fee_collected(), Amount::from(expected_fee));
    response
}

/// The request left no proof state, signature, completed swap, or replay record.
async fn assert_request_absent(
    mint: &Mint,
    request: &CtfSettlementRequest,
    completed_before: usize,
) {
    let (input_ys, output_points) = settlement_storage_keys(&request.participants);
    let db = mint.localstore();
    assert!(db
        .get_proofs_states(&input_ys)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    assert!(db
        .get_blind_signatures(&output_points)
        .await
        .unwrap()
        .iter()
        .all(Option::is_none));
    let outputs = request
        .participants
        .iter()
        .flat_map(|participant| participant.outputs.iter().cloned())
        .collect::<Vec<_>>();
    assert_outputs_have_no_rows(mint, &outputs).await;
    assert_eq!(completed_swap_count(mint).await, completed_before);
    assert_ctf_settlement_replay_absent(mint, request).await;
}

/// No signed or pending `blind_signature` row exists for any of the outputs.
///
/// A signature read sees only signed rows. A pending row has no signature, but
/// it still makes a new insert of its output fail.
async fn assert_outputs_have_no_rows(mint: &Mint, outputs: &[BlindedMessage]) {
    let probe = Operation::new_swap(Amount::ZERO, Amount::ZERO, Amount::ZERO);
    let mut tx = mint.localstore().begin_transaction().await.unwrap();
    let inserted = tx.add_blinded_messages(None, outputs, &probe).await;
    tx.rollback().await.unwrap();
    assert!(
        inserted.is_ok(),
        "an output still has a signed or pending row: {inserted:?}"
    );
}

/// The mint refuses the request before it signs or persists anything.
async fn refuse_without_writes(
    mint: &Mint,
    request: &CtfSettlementRequest,
    now: u64,
) -> CtfSettlementError {
    refuse_without_writes_with(mint, request, settlement_settings(), now).await
}

/// [`refuse_without_writes`] under an explicit advertised settlement capability.
async fn refuse_without_writes_with(
    mint: &Mint,
    request: &CtfSettlementRequest,
    settings: NutCtfSettlementSettings,
    now: u64,
) -> CtfSettlementError {
    let signing_before = mint.blind_sign_attempts();
    let completed_before = completed_swap_count(mint).await;
    let error = mint
        .process_ctf_settlement(request, settings, now)
        .await
        .expect_err("the settlement must be refused");
    assert_eq!(mint.blind_sign_attempts(), signing_before);
    assert_request_absent(mint, request, completed_before).await;
    error
}

/// The authorization form of the locked NO seller in a two-party MERGE.
#[derive(Debug, Clone, Copy)]
enum LockedSeller {
    /// One exact receive bundle.
    Standard,
    /// A range order that the request fills completely with collateral only.
    Pool,
}

struct TwoPartyMergeFixture {
    request: CtfSettlementRequest,
    regular_keyset: Id,
    yes_keyset: Id,
    no_keyset: Id,
    /// Each seller's participant index and collateral premint.
    collateral_receipts: Vec<(usize, PreMintSecrets)>,
    /// Pool candidates that the request does not select.
    unselected_outputs: Vec<cdk_common::PublicKey>,
}

/// A pool PAY_TO_UNLOCK secret with an explicit range policy.
fn pool_pay_to_unlock_secret(
    offer_keyset: Id,
    manifest: &PoolManifest,
    expiry: u64,
    nonce: u8,
    (rate_n, rate_d): (u64, u64),
    min_receive: u64,
    max_debit: u64,
) -> Secret {
    Secret::new(
        serde_json::json!([
            "PAY_TO_UNLOCK",
            {
                "nonce": format!("{nonce:02x}").repeat(32),
                "data": manifest.commitment().to_string(),
                "tags": [
                    ["offer_keyset", offer_keyset.to_string()],
                    ["expiry", expiry.to_string()],
                    ["refund", SETTLEMENT_REFUND_KEY],
                    ["rate_n", rate_n.to_string()],
                    ["rate_d", rate_d.to_string()],
                    ["min_receive", min_receive.to_string()],
                    ["max_debit", max_debit.to_string()]
                ]
            }
        ])
        .to_string(),
    )
}

/// Party A locks 8 NO for 3 collateral. Party B submits bare YES for 4 collateral.
async fn two_party_merge_fixture(
    mint: &Mint,
    now: u64,
    seller: LockedSeller,
    bare_yes_amount: u64,
) -> TwoPartyMergeFixture {
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let regular_keyset = get_regular_keyset_id(mint);
    let (yes_keyset, no_keyset) = (keysets["YES"], keysets["NO"]);
    let expiry = now + OFFER_LIFETIME_SECONDS;
    let (locked_receive, locked_premint) = create_premint(mint, regular_keyset, Amount::from(3));
    let (bare_receive, bare_premint) = create_premint(mint, regular_keyset, Amount::from(4));
    let (locked_offer, locked_mode, unselected_outputs) = match seller {
        LockedSeller::Standard => (
            pay_to_unlock_premint(no_keyset, &[8], &locked_receive, expiry, 1),
            ParticipantMode::Standard,
            Vec::new(),
        ),
        LockedSeller::Pool => {
            let spare_receive = create_premint(mint, regular_keyset, Amount::from(4)).0;
            let change = create_premint(mint, no_keyset, Amount::from(4)).0;
            let mut entries = Vec::new();
            for output in locked_receive.iter().chain(&spare_receive) {
                entries.push(pool_entry(entries.len(), PoolEntryRole::Receive, output));
            }
            for output in &change {
                entries.push(pool_entry(entries.len(), PoolEntryRole::Change, output));
            }
            let manifest = PoolManifest::new(entries, 32).unwrap();
            // Select only the first two receive entries: 3 collateral for all 8 NO.
            assert_eq!(locked_receive.len(), 2);
            let selection = SelectionBitmap::parse("03", manifest.entries().len()).unwrap();
            // The limit price is 3 / 8 collateral per NO.
            let secret = pool_pay_to_unlock_secret(no_keyset, &manifest, expiry, 1, (3, 8), 3, 8);
            let unselected = spare_receive
                .iter()
                .chain(&change)
                .map(|output| output.blinded_secret)
                .collect();
            (
                PreMintSecrets::from_secrets(no_keyset, vec![Amount::from(8)], vec![secret])
                    .unwrap(),
                ParticipantMode::Pool {
                    manifest,
                    selection,
                },
                unselected,
            )
        }
    };
    let [locked_funding, bare_funding]: [Proofs; 2] = issue_regular_premints(
        mint,
        &[
            conversion_funding(mint, 8),
            conversion_funding(mint, bare_yes_amount),
        ],
    )
    .await
    .try_into()
    .unwrap();
    let locked_no = convert_to_conditional_premint(mint, locked_funding, locked_offer).await;
    let bare_yes = convert_to_conditional(
        mint,
        bare_funding,
        yes_keyset,
        Amount::from(bare_yes_amount),
    )
    .await;
    let request = settlement_request(
        &condition_id,
        vec![
            CtfSettlementParticipant {
                mode: locked_mode,
                ..settlement_record(locked_no, locked_receive.clone())
            },
            settlement_record(bare_yes, bare_receive.clone()),
        ],
    );
    let collateral_receipts = vec![
        (
            participant_with_outputs(&request, &locked_receive),
            locked_premint,
        ),
        (
            participant_with_outputs(&request, &bare_receive),
            bare_premint,
        ),
    ];
    TwoPartyMergeFixture {
        request,
        regular_keyset,
        yes_keyset,
        no_keyset,
        collateral_receipts,
        unselected_outputs,
    }
}

/// Two sellers MERGE complementary positions in one request and receive only collateral.
#[tokio::test]
async fn test_ctf_settlement_two_party_merge_pays_sellers_collateral_only() {
    assert_two_party_merge_pays_collateral_only(LockedSeller::Standard).await;
}

/// A fully filled pool NO seller and a bare YES seller MERGE to collateral only.
#[tokio::test]
async fn test_ctf_settlement_two_party_merge_with_pool_seller_pays_collateral_only() {
    assert_two_party_merge_pays_collateral_only(LockedSeller::Pool).await;
}

async fn assert_two_party_merge_pays_collateral_only(seller: LockedSeller) {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, seller, 8).await;
    let request = &fixture.request;
    let coverage = binary_coverage(
        fixture.regular_keyset,
        fixture.yes_keyset,
        fixture.no_keyset,
    );

    assert_eq!(
        request
            .validated_authorizations(settlement_settings().structural_limits().unwrap())
            .unwrap()
            .len(),
        1,
        "party A is the one locked record and party B is a bare record"
    );
    assert!(request
        .participants
        .iter()
        .flat_map(|participant| &participant.inputs)
        .all(|proof| proof.keyset_id != fixture.regular_keyset));
    assert!(request
        .participants
        .iter()
        .flat_map(|participant| &participant.outputs)
        .all(|output| output.keyset_id == fixture.regular_keyset));
    // Two 1-ppk input proofs pay ceil(2 / 1000) = 1.
    assert_eq!(
        outcome_totals(request, &coverage),
        totals(&[("NO", (8, 7)), ("YES", (8, 7))])
    );

    let prepared = mint
        .prepare_ctf_settlement(request, settlement_settings(), now)
        .await
        .expect("an exact-complement MERGE must conserve every outcome");
    assert_request_fee(&prepared, 1, &[fixture.yes_keyset, fixture.no_keyset]);

    let response = commit_and_check(&mint, request, now, 1).await;
    // A standard record has no candidates, and the store refuses an empty lookup.
    if !fixture.unselected_outputs.is_empty() {
        assert!(
            mint.localstore()
                .get_blind_signatures(&fixture.unselected_outputs)
                .await
                .unwrap()
                .iter()
                .all(Option::is_none),
            "{seller:?}: unselected pool candidates must stay unsigned"
        );
    }

    // Each seller unblinds ordinary collateral and spends it through NUT-03.
    let keys = keyset_keys(&mint, fixture.regular_keyset);
    for (index, premint) in &fixture.collateral_receipts {
        let collateral = construct_proofs(
            response.signatures[*index].clone(),
            premint.rs(),
            premint.secrets(),
            &keys,
        )
        .unwrap();
        let fee = mint.get_proofs_fee(&collateral).await.unwrap().total;
        let change = create_premint(
            &mint,
            fixture.regular_keyset,
            collateral.total_amount().unwrap() - fee,
        )
        .0;
        mint.process_swap_request(SwapRequest::new(collateral, change))
            .await
            .expect("MERGE collateral must be spendable regular ecash");
    }
}

/// A MERGE that leaves YES short is refused: its collateral outputs exceed the YES input.
#[tokio::test]
async fn test_ctf_settlement_merge_with_short_outcome_is_refused_without_writes() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = two_party_merge_fixture(&mint, now, LockedSeller::Standard, 4).await;
    let coverage = binary_coverage(
        fixture.regular_keyset,
        fixture.yes_keyset,
        fixture.no_keyset,
    );
    assert_eq!(
        outcome_totals(&fixture.request, &coverage),
        totals(&[("NO", (8, 7)), ("YES", (4, 7))])
    );

    let error = refuse_without_writes(&mint, &fixture.request, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Mint(Error::ConvertPayoffFeeViolation)
        ),
        "{error:?}"
    );
}

struct MatchBundleFixture {
    request: CtfSettlementRequest,
    regular_keyset: Id,
    yes_keyset: Id,
    no_keyset: Id,
    bare_taker: usize,
}

impl MatchBundleFixture {
    fn coverage(&self) -> [(Id, &'static [&'static str]); 3] {
        binary_coverage(self.regular_keyset, self.yes_keyset, self.no_keyset)
    }
}

/// One request with a MINT, a MERGE, and a COMPLEMENTARY match.
///
/// | match         | record          | gives              | receives               |
/// |---------------|-----------------|--------------------|------------------------|
/// | MINT          | M1 locked       | collateral 1 + 4   | YES 8                  |
/// | MINT          | M2 locked       | collateral 1 + 2   | NO 8                   |
/// | MERGE         | S1 locked       | NO 16              | collateral 6           |
/// | MERGE         | S2 bare (taker) | YES 16             | `bare_taker_collateral`|
/// | COMPLEMENTARY | C1 locked       | collateral 4       | YES 8                  |
/// | COMPLEMENTARY | C2 locked       | YES 8              | collateral 4           |
///
/// Without a fee, S2 receives 10. The request fee reduces S2's collateral.
async fn match_bundle_fixture(
    mint: &Mint,
    now: u64,
    regular_fee_ppk: Option<u64>,
    bare_taker_collateral: u64,
) -> MatchBundleFixture {
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    if let Some(fee_ppk) = regular_fee_ppk {
        // The conditional keysets keep the fee that applied at registration.
        rotate_test_regular_fee(mint, CurrencyUnit::Sat, fee_ppk).await;
    }
    let regular_keyset = get_regular_keyset_id(mint);
    let (yes_keyset, no_keyset) = (keysets["YES"], keysets["NO"]);
    let expiry = now + OFFER_LIFETIME_SECONDS;

    let m1_receive = create_premint(mint, yes_keyset, Amount::from(8)).0;
    let m2_receive = create_premint(mint, no_keyset, Amount::from(8)).0;
    let s1_receive = create_premint(mint, regular_keyset, Amount::from(6)).0;
    let s2_receive = create_premint(mint, regular_keyset, Amount::from(bare_taker_collateral)).0;
    let c1_receive = create_premint(mint, yes_keyset, Amount::from(8)).0;
    let c2_receive = create_premint(mint, regular_keyset, Amount::from(4)).0;

    let [m1_inputs, m2_inputs, c1_inputs, s1_funding, s2_funding, c2_funding]: [Proofs; 6] =
        issue_regular_premints(
            mint,
            &[
                pay_to_unlock_premint(regular_keyset, &[1, 4], &m1_receive, expiry, 0x10),
                pay_to_unlock_premint(regular_keyset, &[1, 2], &m2_receive, expiry, 0x20),
                pay_to_unlock_premint(regular_keyset, &[4], &c1_receive, expiry, 0x30),
                conversion_funding(mint, 16),
                conversion_funding(mint, 16),
                conversion_funding(mint, 8),
            ],
        )
        .await
        .try_into()
        .unwrap();
    let s1_inputs = convert_to_conditional_premint(
        mint,
        s1_funding,
        pay_to_unlock_premint(no_keyset, &[16], &s1_receive, expiry, 0x40),
    )
    .await;
    let s2_inputs = convert_to_conditional(mint, s2_funding, yes_keyset, Amount::from(16)).await;
    let c2_inputs = convert_to_conditional_premint(
        mint,
        c2_funding,
        pay_to_unlock_premint(yes_keyset, &[8], &c2_receive, expiry, 0x50),
    )
    .await;

    let request = settlement_request(
        &condition_id,
        vec![
            settlement_record(m1_inputs, m1_receive),
            settlement_record(m2_inputs, m2_receive),
            settlement_record(s1_inputs, s1_receive),
            settlement_record(s2_inputs, s2_receive.clone()),
            settlement_record(c1_inputs, c1_receive),
            settlement_record(c2_inputs, c2_receive),
        ],
    );
    let bare_taker = participant_with_outputs(&request, &s2_receive);
    MatchBundleFixture {
        request,
        regular_keyset,
        yes_keyset,
        no_keyset,
        bare_taker,
    }
}

/// MINT, MERGE, and COMPLEMENTARY legs settle as one atomic swap.
#[tokio::test]
async fn test_ctf_settlement_mint_merge_and_complementary_legs_commit_as_one_swap() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    // Eight 1-ppk input proofs pay ceil(8 / 1000) = 1, so S2 receives 10 - 1.
    let fixture = match_bundle_fixture(&mint, now, None, 9).await;
    let request = &fixture.request;
    assert_eq!(
        request
            .validated_authorizations(settlement_settings().structural_limits().unwrap())
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        outcome_totals(request, &fixture.coverage()),
        totals(&[("NO", (28, 27)), ("YES", (36, 35))])
    );

    let prepared = mint
        .prepare_ctf_settlement(request, settlement_settings(), now)
        .await
        .expect("mixed match legs must conserve every outcome together");
    assert_eq!(prepared.inputs.len(), 8);
    assert_request_fee(
        &prepared,
        1,
        &[
            fixture.regular_keyset,
            fixture.yes_keyset,
            fixture.no_keyset,
        ],
    );

    // A failure at the last write of the commit must undo every leg.
    let completed_before = completed_swap_count(&mint).await;
    set_fail_for("ADD_CTF_SETTLEMENT_REPLAY");
    let failed = mint
        .process_ctf_settlement(request, settlement_settings(), now)
        .await;
    clear_fail_for("ADD_CTF_SETTLEMENT_REPLAY");
    assert!(failed.is_err());
    assert_request_absent(&mint, request, completed_before).await;

    commit_and_check(&mint, request, now, 1).await;
}

/// A bare record can hold and receive collateral and several conditional keysets.
#[tokio::test]
async fn test_ctf_settlement_bare_record_spans_collateral_and_conditional_keysets() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let (condition_id, keysets) =
        register_test_condition_with_collateral(&mint, &["A", "B", "C"], CurrencyUnit::Sat).await;
    let regular = get_regular_keyset_id(&mint);
    let (a, b, c) = (keysets["A"], keysets["B"], keysets["C"]);

    // The locked seller offers 8 C for 4 collateral.
    let seller_receive = create_premint(&mint, regular, Amount::from(4)).0;
    let seller_offer =
        pay_to_unlock_premint(c, &[8], &seller_receive, now + OFFER_LIFETIME_SECONDS, 1);
    let [bare_collateral, a_funding, b_funding, c_funding]: [Proofs; 4] = issue_regular_premints(
        &mint,
        &[
            create_premint(&mint, regular, Amount::from(4)).1,
            conversion_funding(&mint, 8),
            conversion_funding(&mint, 4),
            conversion_funding(&mint, 8),
        ],
    )
    .await
    .try_into()
    .unwrap();
    // The bare record gives 4 collateral, 8 A, and 4 B.
    let mut bare_inputs = bare_collateral;
    bare_inputs.extend(convert_to_conditional(&mint, a_funding, a, Amount::from(8)).await);
    bare_inputs.extend(convert_to_conditional(&mint, b_funding, b, Amount::from(4)).await);
    // The bare record receives 3 collateral, 4 A, and 4 C.
    let mut bare_outputs = create_premint(&mint, regular, Amount::from(3)).0;
    bare_outputs.extend(create_premint(&mint, a, Amount::from(4)).0);
    bare_outputs.extend(create_premint(&mint, c, Amount::from(4)).0);
    let seller_inputs = convert_to_conditional_premint(&mint, c_funding, seller_offer).await;
    let request = settlement_request(
        &condition_id,
        vec![
            settlement_record(bare_inputs, bare_outputs.clone()),
            settlement_record(seller_inputs, seller_receive),
        ],
    );

    let bare = &request.participants[participant_with_outputs(&request, &bare_outputs)];
    assert_eq!(
        keyset_set(bare.inputs.iter().map(|proof| proof.keyset_id)),
        keyset_set([regular, a, b])
    );
    assert_eq!(
        keyset_set(bare.outputs.iter().map(|output| output.keyset_id)),
        keyset_set([regular, a, c])
    );
    assert_eq!(
        request
            .validated_authorizations(settlement_settings().structural_limits().unwrap())
            .unwrap()
            .len(),
        1,
        "only the seller is a locked record"
    );
    // Four 1-ppk input proofs pay ceil(4 / 1000) = 1.
    let coverage: [(Id, &[&str]); 4] = [
        (regular, &["A", "B", "C"]),
        (a, &["A"]),
        (b, &["B"]),
        (c, &["C"]),
    ];
    assert_eq!(
        outcome_totals(&request, &coverage),
        totals(&[("A", (12, 11)), ("B", (8, 7)), ("C", (12, 11))])
    );

    let prepared = mint
        .prepare_ctf_settlement(&request, settlement_settings(), now)
        .await
        .expect("a bare record across keysets must conserve every outcome");
    assert_request_fee(&prepared, 1, &[regular, a, b, c]);
    commit_and_check(&mint, &request, now, 1).await;
}

/// The request fee is the NUT-02 fee of all input proofs together.
///
/// Regular input proofs pay 1000 ppk. The conditional keysets keep 1 ppk.
/// Five regular and three conditional input proofs pay
/// ceil((5 * 1000 + 3 * 1) / 1000) = 6. A separate charge per participant
/// would be 2 + 2 + 1 + 1 + 1 + 1 = 8. A truncated fee would be 5.
#[tokio::test]
async fn test_ctf_settlement_fee_is_charged_once_per_input_proof_across_legs() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = match_bundle_fixture(&mint, now, Some(1000), 10 - 6).await;
    for (keyset, fee_ppk) in [
        (fixture.regular_keyset, 1000),
        (fixture.yes_keyset, 1),
        (fixture.no_keyset, 1),
    ] {
        assert_eq!(
            mint.get_keyset_info(&keyset).unwrap().input_fee_ppk,
            fee_ppk
        );
    }
    assert_eq!(
        input_proof_count(&fixture.request, fixture.regular_keyset),
        5
    );
    assert_eq!(input_proof_count(&fixture.request, fixture.yes_keyset), 2);
    assert_eq!(input_proof_count(&fixture.request, fixture.no_keyset), 1);

    for wrong_fee in [8, 5] {
        let mut variant = fixture.request.clone();
        variant.participants[fixture.bare_taker].outputs =
            create_premint(&mint, fixture.regular_keyset, Amount::from(10 - wrong_fee)).0;
        let signing_before = mint.blind_sign_attempts();
        let result = mint
            .prepare_ctf_settlement(&variant, settlement_settings(), now)
            .await;
        assert!(
            matches!(
                result,
                Err(CtfSettlementError::Mint(Error::ConvertPayoffFeeViolation))
            ),
            "outputs for a fee of {wrong_fee}: {:?}",
            result.err()
        );
        assert_eq!(mint.blind_sign_attempts(), signing_before);
    }

    assert_eq!(
        outcome_totals(&fixture.request, &fixture.coverage()),
        totals(&[("NO", (28, 22)), ("YES", (36, 30))])
    );
    let prepared = mint
        .prepare_ctf_settlement(&fixture.request, settlement_settings(), now)
        .await
        .expect("outputs for the exact request fee must conserve");
    assert_request_fee(
        &prepared,
        6,
        &[
            fixture.regular_keyset,
            fixture.yes_keyset,
            fixture.no_keyset,
        ],
    );
    commit_and_check(&mint, &fixture.request, now, 6).await;
}

struct EightOutcomeMergeFixture {
    request: CtfSettlementRequest,
    regular_keyset: Id,
    singleton_keyset: Id,
    collection_keyset: Id,
    collection: &'static [&'static str],
}

impl EightOutcomeMergeFixture {
    fn coverage(&self) -> [(Id, &'static [&'static str]); 3] {
        [
            (self.regular_keyset, &EIGHT_OUTCOMES),
            (self.singleton_keyset, &["A"]),
            (self.collection_keyset, self.collection),
        ]
    }
}

/// Register an eight-outcome condition with one-vs-rest keysets.
async fn register_eight_outcome_condition(mint: &Mint) -> (String, HashMap<String, Id>) {
    register_one_vs_rest_condition(mint, &EIGHT_OUTCOMES, "eight-outcome-merge").await
}

/// Register a categorical condition with one singleton and one rest keyset per outcome.
async fn register_one_vs_rest_condition(
    mint: &Mint,
    outcomes: &[&str],
    event_id: &str,
) -> (String, HashMap<String, Id>) {
    let mut mint_info = mint.mint_info().await.unwrap();
    let mut nut_ctf = mint_info.nuts.nut_ctf.take().unwrap_or_default();
    nut_ctf.default_keyset_creation = "one-vs-rest".to_string();
    mint_info.nuts.nut_ctf = Some(nut_ctf);
    mint.set_mint_info(mint_info).await.unwrap();
    let (_, announcement) = create_test_announcement(&create_test_oracle(), outcomes, event_id);
    let mut request = enum_condition_request("One-vs-rest condition", vec![announcement]);
    request.outcome_collections = None;
    let registered = mint.register_condition(request).await.unwrap();
    assert_eq!(registered.keysets.len(), 2 * outcomes.len());
    (registered.condition_id, registered.keysets)
}

/// Party A locks 16 one-unit `A` proofs for 5 collateral.
/// Party B submits 16 bare one-unit proofs of `collection` for 10 collateral.
async fn eight_outcome_merge_fixture(
    mint: &Mint,
    now: u64,
    collection: &'static [&'static str],
) -> EightOutcomeMergeFixture {
    let (condition_id, keysets) = register_eight_outcome_condition(mint).await;
    let regular_keyset = get_regular_keyset_id(mint);
    let singleton_keyset = keysets["A"];
    let collection_keyset = keysets[&collection.join("|")];
    let locked_receive = create_premint(mint, regular_keyset, Amount::from(5)).0;
    let bare_receive = create_premint(mint, regular_keyset, Amount::from(10)).0;
    let locked_offer = pay_to_unlock_premint(
        singleton_keyset,
        &[1; 16],
        &locked_receive,
        now + OFFER_LIFETIME_SECONDS,
        1,
    );
    let [locked_funding, bare_funding]: [Proofs; 2] = issue_regular_premints(
        mint,
        &[conversion_funding(mint, 16), conversion_funding(mint, 16)],
    )
    .await
    .try_into()
    .unwrap();
    let locked_inputs = convert_to_conditional_premint(mint, locked_funding, locked_offer).await;
    let bare_inputs =
        convert_to_conditional_premint(mint, bare_funding, unit_premint(collection_keyset, 16))
            .await;
    EightOutcomeMergeFixture {
        request: settlement_request(
            &condition_id,
            vec![
                settlement_record(locked_inputs, locked_receive),
                settlement_record(bare_inputs, bare_receive),
            ],
        ),
        regular_keyset,
        singleton_keyset,
        collection_keyset,
        collection,
    }
}

/// The module's advertised settlement capability with another input limit.
fn settlement_settings_with_max_inputs(max_inputs: u64) -> NutCtfSettlementSettings {
    NutCtfSettlementSettings::new(8, max_inputs, 64, 64 * 1024, 3600, 32).unwrap()
}

/// An eight-outcome exact-complement MERGE settles at the advertised input limit.
#[tokio::test]
async fn test_ctf_settlement_eight_outcome_exact_complement_merge_at_input_limit() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = eight_outcome_merge_fixture(&mint, now, &EIGHT_OUTCOMES[1..]).await;
    let request = &fixture.request;
    let max_inputs = settlement_settings()
        .structural_limits()
        .unwrap()
        .max_inputs;
    assert_eq!(
        settlement_settings_with_max_inputs(32),
        settlement_settings()
    );
    assert_eq!(
        request
            .participants
            .iter()
            .map(|participant| participant.inputs.len())
            .sum::<usize>(),
        max_inputs
    );
    // Thirty-two 1-ppk input proofs pay ceil(32 / 1000) = 1.
    let expected = EIGHT_OUTCOMES
        .iter()
        .map(|outcome| (*outcome, (16, 15)))
        .collect::<Vec<_>>();
    assert_eq!(
        outcome_totals(request, &fixture.coverage()),
        totals(&expected)
    );

    let signing_before = mint.blind_sign_attempts();
    let below_limit = settlement_settings_with_max_inputs(u64::try_from(max_inputs - 1).unwrap());
    assert!(matches!(
        mint.prepare_ctf_settlement(request, below_limit, now).await,
        Err(CtfSettlementError::Protocol(
            SettlementError::LimitExceeded("inputs")
        ))
    ));
    assert_eq!(mint.blind_sign_attempts(), signing_before);

    let prepared = mint
        .prepare_ctf_settlement(request, settlement_settings(), now)
        .await
        .expect("an outcome and its exact complement must MERGE to collateral");
    assert_request_fee(
        &prepared,
        1,
        &[fixture.singleton_keyset, fixture.collection_keyset],
    );
    commit_and_check(&mint, request, now, 1).await;
}

/// A MERGE of `A` with the complement of `B` double-counts `A` and misses `B`.
#[tokio::test]
async fn test_ctf_settlement_eight_outcome_merge_of_non_complements_is_refused() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = eight_outcome_merge_fixture(&mint, now, &REST_OF_B).await;
    let mut expected = EIGHT_OUTCOMES
        .iter()
        .map(|outcome| (*outcome, (16, 15)))
        .collect::<Vec<_>>();
    expected[0].1 = (32, 15);
    expected[1].1 = (0, 15);
    assert_eq!(
        outcome_totals(&fixture.request, &fixture.coverage()),
        totals(&expected)
    );

    let error = refuse_without_writes(&mint, &fixture.request, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Mint(Error::ConvertPayoffFeeViolation)
        ),
        "{error:?}"
    );
}
