//! Mint evidence for the bundle shapes of `MERGE` and per-batch net capacity.
//!
//! The bot holds each outcome as a singleton keyset and submits one bare
//! record. Users submit locked records. The net-capacity tests take the bot's
//! net bundle from the batch terms `r_j`, `P`, the selectable holdings `c` and
//! `I_j`, and the split or merge count `s` of each test's table.

use super::*;

/// The key of the regular collateral keyset in a [`Leg`].
const COLLATERAL: &str = "*";
static THREE_OUTCOMES: [&str; 3] = ["A", "B", "C"];

/// Map a [`Leg`] key to its keyset.
fn leg_keyset(keysets: &HashMap<String, Id>, regular: Id, key: &str) -> Id {
    if key == COLLATERAL {
        regular
    } else {
        keysets[key]
    }
}

fn premint_with_amounts(keyset: Id, amounts: &[u64]) -> PreMintSecrets {
    let secrets = amounts.iter().map(|_| Secret::generate()).collect();
    let amounts = amounts.iter().copied().map(Amount::from).collect();
    PreMintSecrets::from_secrets(keyset, amounts, secrets).unwrap()
}

/// Bare proofs of exact amounts in one keyset.
async fn bare_proofs(mint: &Mint, keyset: Id, amounts: &[u64]) -> Proofs {
    let premint = premint_with_amounts(keyset, amounts);
    if keyset == get_regular_keyset_id(mint) {
        return issue_regular_premints(mint, &[premint]).await.remove(0);
    }
    let funding = issue_regular_premints(mint, &[conversion_funding(mint, amounts.iter().sum())])
        .await
        .remove(0);
    convert_to_conditional_premint(mint, funding, premint).await
}

/// One record: proof amounts per keyset key, and output value per keyset key.
#[derive(Clone, Copy)]
struct Leg<'a> {
    inputs: &'a [(&'a str, &'a [u64])],
    outputs: &'a [(&'a str, u64)],
}

fn leg_outputs(
    mint: &Mint,
    keysets: &HashMap<String, Id>,
    regular: Id,
    leg: Leg<'_>,
) -> Vec<BlindedMessage> {
    leg.outputs
        .iter()
        .flat_map(|(key, amount)| {
            create_premint(
                mint,
                leg_keyset(keysets, regular, key),
                Amount::from(*amount),
            )
            .0
        })
        .collect()
}

struct UsersAndBot {
    request: CtfSettlementRequest,
    regular_keyset: Id,
    keysets: HashMap<String, Id>,
    /// The participant index of each user record, in the order of the user legs.
    users: Vec<usize>,
    bot: usize,
}

impl UsersAndBot {
    fn coverage(&self) -> Vec<(Id, &'static [&'static str])> {
        let mut coverage = vec![(self.regular_keyset, &THREE_OUTCOMES[..])];
        for (index, outcome) in THREE_OUTCOMES.iter().enumerate() {
            coverage.push((self.keysets[*outcome], &THREE_OUTCOMES[index..=index]));
        }
        coverage
    }

    fn keyset(&self, key: &str) -> Id {
        leg_keyset(&self.keysets, self.regular_keyset, key)
    }
}

/// Locked user records and one bare bot record on a new three-outcome condition.
///
/// Each user locks proofs of one keyset for its exact outputs. The bot record
/// holds the bot's net bundle. With `regular_fee_after_registration`, the
/// conditional keysets keep the registration fee and the regular keyset
/// rotates to the given fee.
async fn users_and_bot(
    mint: &Mint,
    now: u64,
    regular_fee_after_registration: Option<u64>,
    users: &[Leg<'_>],
    bot: Leg<'_>,
) -> UsersAndBot {
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &THREE_OUTCOMES, CurrencyUnit::Sat).await;
    if let Some(fee_ppk) = regular_fee_after_registration {
        rotate_test_regular_fee(mint, CurrencyUnit::Sat, fee_ppk).await;
    }
    let regular = get_regular_keyset_id(mint);
    let mut records = Vec::with_capacity(users.len() + 1);
    let mut user_receives = Vec::with_capacity(users.len());
    for (index, user) in users.iter().enumerate() {
        let [(offer_key, offer_amounts)] = user.inputs else {
            panic!("a user locks proofs of one keyset");
        };
        let offer = leg_keyset(&keysets, regular, offer_key);
        let receive = leg_outputs(mint, &keysets, regular, *user);
        // Every locked proof of the request needs its own nonce.
        let first_nonce = 1 + 16 * u8::try_from(index).unwrap();
        let locked = pay_to_unlock_premint(
            offer,
            offer_amounts,
            &receive,
            now + OFFER_LIFETIME_SECONDS,
            first_nonce,
        );
        let inputs = if offer == regular {
            issue_regular_premints(mint, &[locked]).await.remove(0)
        } else {
            let funding = issue_regular_premints(
                mint,
                &[conversion_funding(mint, offer_amounts.iter().sum())],
            )
            .await
            .remove(0);
            convert_to_conditional_premint(mint, funding, locked).await
        };
        records.push(settlement_record(inputs, receive.clone()));
        user_receives.push(receive);
    }
    let mut bot_inputs = Vec::new();
    for (key, amounts) in bot.inputs {
        bot_inputs.extend(bare_proofs(mint, leg_keyset(&keysets, regular, key), amounts).await);
    }
    let bot_receive = leg_outputs(mint, &keysets, regular, bot);
    records.push(settlement_record(bot_inputs, bot_receive.clone()));
    let request = settlement_request(&condition_id, records);
    UsersAndBot {
        users: user_receives
            .iter()
            .map(|receive| participant_with_outputs(&request, receive))
            .collect(),
        bot: participant_with_outputs(&request, &bot_receive),
        request,
        regular_keyset: regular,
        keysets,
    }
}

fn input_keysets(participant: &CtfSettlementParticipant) -> BTreeSet<Id> {
    keyset_set(participant.inputs.iter().map(|proof| proof.keyset_id))
}

fn output_keysets(participant: &CtfSettlementParticipant) -> BTreeSet<Id> {
    keyset_set(participant.outputs.iter().map(|output| output.keyset_id))
}

/// Party A locks 16 `A` for 5 collateral. The bot gives its holding form of
/// the complement: one bare proof of 16 in each singleton keyset `B` to `G`,
/// and bare proofs of `h_amounts` in the singleton keyset `H`.
async fn singleton_complement_request(
    mint: &Mint,
    now: u64,
    h_amounts: &[u64],
) -> (CtfSettlementRequest, Id, HashMap<String, Id>) {
    let component = |outcome: &str| if outcome == "H" { h_amounts } else { &[16] };
    let (condition_id, keysets) = register_eight_outcome_condition(mint).await;
    let regular = get_regular_keyset_id(mint);
    let user_receive = create_premint(mint, regular, Amount::from(5)).0;
    let user_offer = pay_to_unlock_premint(
        keysets["A"],
        &[16],
        &user_receive,
        now + OFFER_LIFETIME_SECONDS,
        1,
    );
    let mut fundings = vec![conversion_funding(mint, 16)];
    for outcome in &EIGHT_OUTCOMES[1..] {
        fundings.push(conversion_funding(mint, component(outcome).iter().sum()));
    }
    let mut fundings = issue_regular_premints(mint, &fundings).await.into_iter();
    let user_inputs =
        convert_to_conditional_premint(mint, fundings.next().unwrap(), user_offer).await;
    let mut bot_inputs = Vec::new();
    for outcome in &EIGHT_OUTCOMES[1..] {
        bot_inputs.extend(
            convert_to_conditional_premint(
                mint,
                fundings.next().unwrap(),
                premint_with_amounts(keysets[*outcome], component(outcome)),
            )
            .await,
        );
    }
    let bot_receive = create_premint(mint, regular, Amount::from(10)).0;
    let request = settlement_request(
        &condition_id,
        vec![
            settlement_record(user_inputs, user_receive),
            settlement_record(bot_inputs, bot_receive),
        ],
    );
    (request, regular, keysets)
}

fn singleton_coverage(
    regular: Id,
    keysets: &HashMap<String, Id>,
) -> Vec<(Id, &'static [&'static str])> {
    let mut coverage = vec![(regular, &EIGHT_OUTCOMES[..])];
    for (index, outcome) in EIGHT_OUTCOMES.iter().enumerate() {
        coverage.push((keysets[*outcome], &EIGHT_OUTCOMES[index..=index]));
    }
    coverage
}

/// An eight-outcome MERGE settles against a complement of seven singleton components.
#[tokio::test]
async fn test_ctf_settlement_eight_outcome_merge_with_seven_singleton_components() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let (request, regular, keysets) = singleton_complement_request(&mint, now, &[16]).await;
    let bot = request
        .participants
        .iter()
        .find(|participant| participant.inputs.len() == 7)
        .expect("the bot record holds seven proofs");
    assert_eq!(
        input_keysets(bot),
        keyset_set(EIGHT_OUTCOMES[1..].iter().map(|outcome| keysets[*outcome])),
        "the bot holds one singleton proof of each outcome B to H"
    );
    assert_eq!(
        request
            .validated_authorizations(settlement_settings().structural_limits().unwrap())
            .unwrap()
            .len(),
        1,
        "the user is the one locked record"
    );
    // Eight 1-ppk input proofs pay ceil(8 / 1000) = 1.
    let expected = EIGHT_OUTCOMES
        .iter()
        .map(|outcome| (*outcome, (16, 15)))
        .collect::<Vec<_>>();
    assert_eq!(
        outcome_totals(&request, &singleton_coverage(regular, &keysets)),
        totals(&expected)
    );

    let prepared = mint
        .prepare_ctf_settlement(&request, settlement_settings(), now)
        .await
        .expect("an outcome and its seven complementary singletons must MERGE");
    let singletons = EIGHT_OUTCOMES
        .iter()
        .map(|outcome| keysets[*outcome])
        .collect::<Vec<_>>();
    assert_request_fee(&prepared, 1, &singletons);
    commit_and_check(&mint, &request, now, 1).await;
}

/// A singleton complement one unit short in `H` is refused without writes.
#[tokio::test]
async fn test_ctf_settlement_singleton_complement_short_in_one_component_is_refused() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let (request, regular, keysets) = singleton_complement_request(&mint, now, &[8, 4, 2, 1]).await;
    let mut expected = EIGHT_OUTCOMES
        .iter()
        .map(|outcome| (*outcome, (16, 15)))
        .collect::<Vec<_>>();
    expected[7].1 = (15, 15);
    assert_eq!(
        outcome_totals(&request, &singleton_coverage(regular, &keysets)),
        totals(&expected)
    );

    let error = refuse_without_writes(&mint, &request, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Mint(Error::ConvertPayoffFeeViolation)
        ),
        "{error:?}"
    );
}

struct PartialPoolFixture {
    request: CtfSettlementRequest,
    regular_keyset: Id,
    yes_keyset: Id,
    no_keyset: Id,
    pool: usize,
    selected_receive: BlindedMessage,
    selected_change: BlindedMessage,
    unselected: Vec<cdk_common::PublicKey>,
}

/// A pool NO seller locks 16 NO at a limit of 1/4 collateral per NO.
///
/// Every keyset charges 1000 ppk, so each of the two input proofs pays 1.
/// The pool seller sells 8 NO and keeps 8 NO as change. The bare YES seller
/// sells 8 YES. The MERGE of 8 sets pays 8 collateral less the fee of 2.
///
/// | seller   | gives | gross collateral | fee share | receives        |
/// |----------|-------|------------------|-----------|-----------------|
/// | pool NO  | 16 NO | 3                | 1         | 2 + 8 NO change |
/// | bare YES | 8 YES | 5                | 1         | `bare_receive`  |
///
/// `receive_entry` selects the receive entry of 2 (index 0) or 1 (index 1).
async fn partial_pool_fixture(
    mint: &Mint,
    now: u64,
    receive_entry: usize,
    bare_receive: u64,
) -> PartialPoolFixture {
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let regular_keyset = get_regular_keyset_id(mint);
    let (yes_keyset, no_keyset) = (keysets["YES"], keysets["NO"]);
    let receive = [
        create_premint(mint, regular_keyset, Amount::from(2)).0,
        create_premint(mint, regular_keyset, Amount::ONE).0,
    ]
    .concat();
    let change = [
        create_premint(mint, no_keyset, Amount::from(8)).0,
        create_premint(mint, no_keyset, Amount::from(4)).0,
    ]
    .concat();
    let mut entries = Vec::new();
    for output in &receive {
        entries.push(pool_entry(entries.len(), PoolEntryRole::Receive, output));
    }
    for output in &change {
        entries.push(pool_entry(entries.len(), PoolEntryRole::Change, output));
    }
    let manifest = PoolManifest::new(entries, 32).unwrap();
    // Entry 2 is the change of 8 NO.
    let bitmap = format!("{:02x}", (1u8 << receive_entry) | (1 << 2));
    let selection = SelectionBitmap::parse(&bitmap, manifest.entries().len()).unwrap();
    let secret = pool_pay_to_unlock_secret(
        no_keyset,
        &manifest,
        now + OFFER_LIFETIME_SECONDS,
        1,
        (1, 4),
        1,
        16,
    );
    let pool_offer =
        PreMintSecrets::from_secrets(no_keyset, vec![Amount::from(16)], vec![secret]).unwrap();
    let [pool_funding, bare_funding]: [Proofs; 2] = issue_regular_premints(
        mint,
        &[conversion_funding(mint, 16), conversion_funding(mint, 8)],
    )
    .await
    .try_into()
    .unwrap();
    let pool_inputs = convert_to_conditional_premint(mint, pool_funding, pool_offer).await;
    let bare_inputs = convert_to_conditional(mint, bare_funding, yes_keyset, Amount::from(8)).await;
    let pool_outputs = vec![receive[receive_entry].clone(), change[0].clone()];
    let bare_outputs = create_premint(mint, regular_keyset, Amount::from(bare_receive)).0;
    let request = settlement_request(
        &condition_id,
        vec![
            CtfSettlementParticipant {
                mode: ParticipantMode::Pool {
                    manifest,
                    selection,
                },
                ..settlement_record(pool_inputs, pool_outputs.clone())
            },
            settlement_record(bare_inputs, bare_outputs),
        ],
    );
    PartialPoolFixture {
        pool: participant_with_outputs(&request, &pool_outputs),
        request,
        regular_keyset,
        yes_keyset,
        no_keyset,
        selected_receive: receive[receive_entry].clone(),
        selected_change: change[0].clone(),
        unselected: [&receive[1 - receive_entry], &change[1]]
            .iter()
            .map(|output| output.blinded_secret)
            .collect(),
    }
}

/// A partially filled pool seller receives collateral and change and pays a fee share.
#[tokio::test]
async fn test_ctf_settlement_partial_pool_seller_with_change_and_fee_share() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = partial_pool_fixture(&mint, now, 0, 4).await;
    for keyset in [
        fixture.regular_keyset,
        fixture.yes_keyset,
        fixture.no_keyset,
    ] {
        assert_eq!(mint.get_keyset_info(&keyset).unwrap().input_fee_ppk, 1000);
    }
    let request = &fixture.request;
    let pool = &request.participants[fixture.pool];
    assert_eq!(pool.inputs.len(), 1);
    assert_eq!(pool.inputs[0].amount, Amount::from(16));
    // The pool seller debits 16 - 8 = 8 NO for 2 collateral: exactly its limit of 1/4.
    assert_eq!(
        pool.outputs,
        vec![
            fixture.selected_receive.clone(),
            fixture.selected_change.clone()
        ]
    );
    assert_eq!(
        (
            fixture.selected_receive.keyset_id,
            fixture.selected_receive.amount
        ),
        (fixture.regular_keyset, Amount::from(2))
    );
    assert_eq!(
        (
            fixture.selected_change.keyset_id,
            fixture.selected_change.amount
        ),
        (fixture.no_keyset, Amount::from(8))
    );
    let coverage = binary_coverage(
        fixture.regular_keyset,
        fixture.yes_keyset,
        fixture.no_keyset,
    );
    assert_eq!(
        outcome_totals(request, &coverage),
        totals(&[("NO", (16, 14)), ("YES", (8, 6))])
    );

    let prepared = mint
        .prepare_ctf_settlement(request, settlement_settings(), now)
        .await
        .expect("a partial pool fill with change must conserve every outcome");
    assert_request_fee(&prepared, 2, &[fixture.yes_keyset, fixture.no_keyset]);
    commit_and_check(&mint, request, now, 2).await;
    assert!(
        mint.localstore()
            .get_blind_signatures(&fixture.unselected)
            .await
            .unwrap()
            .iter()
            .all(Option::is_none),
        "unselected pool candidates must stay unsigned"
    );
}

/// A pool selection below the seller's limit is refused even when value conserves.
#[tokio::test]
async fn test_ctf_settlement_partial_pool_seller_below_its_limit_is_refused() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let now = unix_time();
    // The pool seller receives 1 for 8 NO. The bare seller takes the difference.
    let fixture = partial_pool_fixture(&mint, now, 1, 5).await;
    let coverage = binary_coverage(
        fixture.regular_keyset,
        fixture.yes_keyset,
        fixture.no_keyset,
    );
    assert_eq!(
        outcome_totals(&fixture.request, &coverage),
        totals(&[("NO", (16, 14)), ("YES", (8, 6))])
    );

    let error = refuse_without_writes(&mint, &fixture.request, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Protocol(SettlementError::InvalidPoolPolicy(
                "selected rate is below the limit"
            ))
        ),
        "{error:?}"
    );
}

struct CategoricalBundleFixture {
    request: CtfSettlementRequest,
    regular_keyset: Id,
    keysets: HashMap<String, Id>,
    bot: usize,
}

impl CategoricalBundleFixture {
    fn coverage(&self) -> Vec<(Id, &'static [&'static str])> {
        vec![
            (self.regular_keyset, &THREE_OUTCOMES[..]),
            (self.keysets["A"], &THREE_OUTCOMES[0..1]),
            (self.keysets["B"], &THREE_OUTCOMES[1..2]),
            (self.keysets["C"], &THREE_OUTCOMES[2..3]),
            (self.keysets["B|C"], &THREE_OUTCOMES[1..3]),
        ]
    }
}

/// One three-outcome request with a MINT, a MERGE, and a COMPLEMENTARY match.
///
/// | match         | record      | gives            | receives       |
/// |---------------|-------------|------------------|----------------|
/// | MINT          | M1 locked   | collateral 1 + 2 | A 8            |
/// | MINT          | M2 locked   | collateral 1 + 4 | B\|C 8         |
/// | MERGE         | S1 locked   | A 16             | collateral 6   |
/// | MERGE         | S2 bare bot | B 16 and C 16    | collateral 9   |
/// | COMPLEMENTARY | C1 locked   | collateral 4     | B 8            |
/// | COMPLEMENTARY | C2 locked   | B 8              | collateral 4   |
///
/// Nine 1-ppk input proofs pay 1. Without a fee, S2 receives 10.
async fn categorical_bundle_fixture(mint: &Mint, now: u64) -> CategoricalBundleFixture {
    let (condition_id, keysets) =
        register_one_vs_rest_condition(mint, &THREE_OUTCOMES, "categorical-mixed-bundle").await;
    let regular_keyset = get_regular_keyset_id(mint);
    let expiry = now + OFFER_LIFETIME_SECONDS;
    let m1_receive = create_premint(mint, keysets["A"], Amount::from(8)).0;
    let m2_receive = create_premint(mint, keysets["B|C"], Amount::from(8)).0;
    let s1_receive = create_premint(mint, regular_keyset, Amount::from(6)).0;
    let s2_receive = create_premint(mint, regular_keyset, Amount::from(9)).0;
    let c1_receive = create_premint(mint, keysets["B"], Amount::from(8)).0;
    let c2_receive = create_premint(mint, regular_keyset, Amount::from(4)).0;

    let [m1_inputs, m2_inputs, c1_inputs, s1_funding, s2_b_funding, s2_c_funding, c2_funding]: [Proofs; 7] =
        issue_regular_premints(
            mint,
            &[
                pay_to_unlock_premint(regular_keyset, &[1, 2], &m1_receive, expiry, 0x10),
                pay_to_unlock_premint(regular_keyset, &[1, 4], &m2_receive, expiry, 0x20),
                pay_to_unlock_premint(regular_keyset, &[4], &c1_receive, expiry, 0x30),
                conversion_funding(mint, 16),
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
        pay_to_unlock_premint(keysets["A"], &[16], &s1_receive, expiry, 0x40),
    )
    .await;
    let mut s2_inputs =
        convert_to_conditional(mint, s2_b_funding, keysets["B"], Amount::from(16)).await;
    s2_inputs
        .extend(convert_to_conditional(mint, s2_c_funding, keysets["C"], Amount::from(16)).await);
    let c2_inputs = convert_to_conditional_premint(
        mint,
        c2_funding,
        pay_to_unlock_premint(keysets["B"], &[8], &c2_receive, expiry, 0x50),
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
    CategoricalBundleFixture {
        bot: participant_with_outputs(&request, &s2_receive),
        request,
        regular_keyset,
        keysets,
    }
}

/// MINT, MERGE, and COMPLEMENTARY legs of a categorical market settle as one swap.
#[tokio::test]
async fn test_ctf_settlement_categorical_mint_merge_and_complementary_legs() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = categorical_bundle_fixture(&mint, now).await;
    let request = &fixture.request;
    assert_eq!(
        request
            .validated_authorizations(settlement_settings().structural_limits().unwrap())
            .unwrap()
            .len(),
        5,
        "the bot is the one bare record"
    );
    assert_eq!(
        input_keysets(&request.participants[fixture.bot]),
        keyset_set([fixture.keysets["B"], fixture.keysets["C"]])
    );
    assert_eq!(
        outcome_totals(request, &fixture.coverage()),
        totals(&[("A", (28, 27)), ("B", (36, 35)), ("C", (28, 27))])
    );

    // The bot record without its C component leaves C short.
    let mut short = request.clone();
    short.participants[fixture.bot]
        .inputs
        .retain(|proof| proof.keyset_id != fixture.keysets["C"]);
    canonicalize_settlement_participants(&mut short.participants);
    assert_eq!(
        outcome_totals(&short, &fixture.coverage()),
        totals(&[("A", (28, 27)), ("B", (36, 35)), ("C", (12, 27))])
    );
    let error = refuse_without_writes(&mint, &short, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Mint(Error::ConvertPayoffFeeViolation)
        ),
        "{error:?}"
    );

    let prepared = mint
        .prepare_ctf_settlement(request, settlement_settings(), now)
        .await
        .expect("categorical mixed legs must conserve every outcome together");
    assert_eq!(prepared.inputs.len(), 9);
    assert_request_fee(
        &prepared,
        1,
        &[
            fixture.regular_keyset,
            fixture.keysets["A"],
            fixture.keysets["B"],
            fixture.keysets["C"],
        ],
    );
    commit_and_check(&mint, request, now, 1).await;
}

/// Check the record shapes, the per-outcome totals, and the fee, then commit.
async fn assert_net_bundle_commits(
    mint: &Mint,
    now: u64,
    fixture: &UsersAndBot,
    expected: &[(&str, (u64, u64))],
    expected_fee: u64,
) {
    let request = &fixture.request;
    assert_eq!(
        request
            .validated_authorizations(settlement_settings().structural_limits().unwrap())
            .unwrap()
            .len(),
        fixture.users.len(),
        "every user record is locked and the bot record is bare"
    );
    assert_eq!(
        outcome_totals(request, &fixture.coverage()),
        totals(expected)
    );
    let prepared = mint
        .prepare_ctf_settlement(request, settlement_settings(), now)
        .await
        .expect("the net bundle must conserve every outcome");
    let request_input_keysets = request
        .participants
        .iter()
        .flat_map(input_keysets)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    assert_request_fee(&prepared, expected_fee, &request_input_keysets);
    commit_and_check(mint, request, now, expected_fee).await;
}

/// s < 0 at `s = clamp(0, lower, upper)`: the bot merges 4 sets of the outcomes it does not buy.
///
/// A taker sells 8 `A` to the bot at 3/8 and receives 3. The bot pays the
/// whole request fee of 1. Three 1-ppk input proofs pay 1.
///
/// | term  | value                                                  |
/// |-------|--------------------------------------------------------|
/// | r     | r_A = -8, r_B = 0, r_C = 0                             |
/// | P     | -3 - 1 = -4                                            |
/// | c, I  | c = 0, I_A = 0, I_B = 16, I_C = 16                     |
/// | s     | clamp(0, max(-8 - 0, 0 - 16, 0 - 16), c + P) = -4      |
/// | input | collateral max(0, s - P) = 0, B 4, C 4, A 0            |
/// | output| collateral max(0, P - s) = 0, A s - r_A = 4, B 0, C 0  |
#[tokio::test]
async fn test_ctf_settlement_net_merge_bundle_at_the_clamped_count() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = users_and_bot(
        &mint,
        now,
        None,
        &[Leg {
            inputs: &[("A", &[8])],
            outputs: &[(COLLATERAL, 3)],
        }],
        Leg {
            inputs: &[("B", &[4]), ("C", &[4])],
            outputs: &[("A", 4)],
        },
    )
    .await;
    let bot = &fixture.request.participants[fixture.bot];
    assert_eq!(
        input_keysets(bot),
        keyset_set([fixture.keyset("B"), fixture.keyset("C")])
    );
    assert_eq!(output_keysets(bot), keyset_set([fixture.keyset("A")]));
    assert_net_bundle_commits(
        &mint,
        now,
        &fixture,
        &[("A", (8, 7)), ("B", (4, 3)), ("C", (4, 3))],
        1,
    )
    .await;
}

/// s < 0 below the clamped count: the bot inputs tokens of every outcome.
///
/// The trade and the fee are those of the clamped test. The bot also holds
/// 16 `A`, so `lower = max(-8 - 16, -16, -16) = -16`. The bot takes the
/// admissible `s = -9` and merges 9 sets: `A` 1, `B` 9, `C` 9. It receives
/// collateral `P - s = 5`. Six 1-ppk input proofs pay 1.
#[tokio::test]
async fn test_ctf_settlement_net_merge_bundle_with_every_outcome_input() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = users_and_bot(
        &mint,
        now,
        None,
        &[Leg {
            inputs: &[("A", &[8])],
            outputs: &[(COLLATERAL, 3)],
        }],
        Leg {
            inputs: &[("A", &[1]), ("B", &[8, 1]), ("C", &[8, 1])],
            outputs: &[(COLLATERAL, 5)],
        },
    )
    .await;
    let bot = &fixture.request.participants[fixture.bot];
    assert_eq!(
        input_keysets(bot),
        keyset_set(THREE_OUTCOMES.iter().map(|outcome| fixture.keyset(outcome)))
    );
    assert_eq!(output_keysets(bot), keyset_set([fixture.regular_keyset]));
    assert_net_bundle_commits(
        &mint,
        now,
        &fixture,
        &[("A", (9, 8)), ("B", (9, 8)), ("C", (9, 8))],
        1,
    )
    .await;
}

/// s < 0 at the clamped count with an input of every outcome leaves the bot record without outputs.
///
/// With `s = c + P < 0`, the bot inputs every outcome only when `r_j > s` for
/// every `j`. Then every net output `max(0, s - r_j)` and `max(0, P - s)` is
/// zero. The mint requires an output in every record, so it refuses the
/// request although the request conserves every outcome.
///
/// Every conditional keyset charges 1000 ppk. A taker sells 8 `A` at 7/8 and
/// receives 7. The bot pays the whole fee of 10, one for each input proof.
///
/// | term  | value                                                 |
/// |-------|-------------------------------------------------------|
/// | r     | r_A = -8, r_B = 0, r_C = 0                            |
/// | P     | -7 - 10 = -17                                         |
/// | c, I  | c = 0, I_A = I_B = I_C = 32                           |
/// | s     | clamp(0, max(-8 - 32, 0 - 32, 0 - 32), c + P) = -17   |
/// | input | A 9 as 4 + 4 + 1, B 17 as 8 + 8 + 1, C 17 the same    |
/// | output| none                                                  |
#[tokio::test]
async fn test_ctf_settlement_net_merge_bot_record_without_outputs_is_refused() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap();
    let now = unix_time();
    // The conditional keysets keep 1000 ppk. The regular keyset that funds
    // the conversions rotates to 1 ppk, so every conversion amount is exact.
    // The fixture needs a bot output to build its records. The test removes it.
    let mut fixture = users_and_bot(
        &mint,
        now,
        Some(1),
        &[Leg {
            inputs: &[("A", &[8])],
            outputs: &[(COLLATERAL, 7)],
        }],
        Leg {
            inputs: &[("A", &[4, 4, 1]), ("B", &[8, 8, 1]), ("C", &[8, 8, 1])],
            outputs: &[(COLLATERAL, 1)],
        },
    )
    .await;
    fixture.request.participants[fixture.bot].outputs.clear();
    // The refusal is structural, so check the fee facts of the table directly.
    for outcome in THREE_OUTCOMES {
        assert_eq!(
            mint.get_keyset_info(&fixture.keyset(outcome))
                .unwrap()
                .input_fee_ppk,
            1000
        );
    }
    assert_eq!(
        mint.get_keyset_info(&fixture.regular_keyset)
            .unwrap()
            .input_fee_ppk,
        1
    );
    let inputs = fixture
        .request
        .participants
        .iter()
        .flat_map(|participant| participant.inputs.iter().cloned())
        .collect::<Proofs>();
    assert_eq!(inputs.len(), 10);
    assert!(inputs
        .iter()
        .all(|proof| proof.keyset_id != fixture.regular_keyset));
    assert_eq!(
        mint.get_proofs_fee(&inputs).await.unwrap().total,
        Amount::from(10)
    );
    assert_eq!(
        outcome_totals(&fixture.request, &fixture.coverage()),
        totals(&[("A", (17, 7)), ("B", (17, 7)), ("C", (17, 7))])
    );

    let error = refuse_without_writes(&mint, &fixture.request, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Protocol(SettlementError::InvalidStructure(
                "each participant requires inputs and outputs"
            ))
        ),
        "{error:?}"
    );
}

/// s > 0: the bot splits collateral and keeps the outcomes that no user receives.
///
/// A taker buys 8 `A` from the bot at 5/8 and pays 5. The bot pays the whole
/// request fee of 1. Three 1-ppk input proofs pay 1.
///
/// | term  | value                                                  |
/// |-------|--------------------------------------------------------|
/// | r     | r_A = 8, r_B = 0, r_C = 0                              |
/// | P     | 5 - 1 = 4                                              |
/// | c, I  | c = 4, I_A = I_B = I_C = 0                             |
/// | s     | clamp(0, max(8 - 0, 0 - 0, 0 - 0), c + P) = 8          |
/// | input | collateral s - P = 4, tokens none                      |
/// | output| collateral 0, A s - r_A = 0, B 8, C 8                 |
#[tokio::test]
async fn test_ctf_settlement_net_split_bundle_outputs_outcomes_no_user_receives() {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    let now = unix_time();
    let fixture = users_and_bot(
        &mint,
        now,
        None,
        &[Leg {
            inputs: &[(COLLATERAL, &[1, 4])],
            outputs: &[("A", 8)],
        }],
        Leg {
            inputs: &[(COLLATERAL, &[4])],
            outputs: &[("B", 8), ("C", 8)],
        },
    )
    .await;
    let bot = &fixture.request.participants[fixture.bot];
    assert_eq!(input_keysets(bot), keyset_set([fixture.regular_keyset]));
    assert_eq!(
        output_keysets(bot),
        keyset_set([fixture.keyset("B"), fixture.keyset("C")])
    );
    assert_eq!(
        output_keysets(&fixture.request.participants[fixture.users[0]]),
        keyset_set([fixture.keyset("A")]),
        "no user receives B or C"
    );
    assert_net_bundle_commits(
        &mint,
        now,
        &fixture,
        &[("A", (9, 8)), ("B", (9, 8)), ("C", (9, 8))],
        1,
    )
    .await;
}

/// A mint whose regular and conditional keysets all charge 1000 ppk.
///
/// Each input proof then pays a fee of exactly 1, so each record's fee share
/// is its input proof count. The users pay their own shares, and the bot pays
/// the residual share for its inputs, as in `bot-residual-fee-v1`.
async fn mint_with_unit_fee_per_input() -> Mint {
    create_test_mint_with_unit(CurrencyUnit::Sat, 1000)
        .await
        .unwrap()
}

fn assert_every_keyset_charges_one_per_input(mint: &Mint, fixture: &UsersAndBot) {
    for key in [COLLATERAL, "A", "B", "C"] {
        assert_eq!(
            mint.get_keyset_info(&fixture.keyset(key))
                .unwrap()
                .input_fee_ppk,
            1000,
            "keyset {key}"
        );
    }
}

/// s < 0 with two user records: the bot merges 7 sets and keeps token change.
///
/// Two users each sell 8 tokens to the bot at 3/8. Each user pays a fee share
/// of 1 from its gross receipt of 3. The bot pays its fee share of 1 inside
/// `P`. The bot holds one proof of 8 `C` and no cash. The cash leg
/// `P - s` is 0, so the bot record has no cash output.
///
/// | term  | value                                                    |
/// |-------|----------------------------------------------------------|
/// | r     | r_A = -8, r_B = -8, r_C = 0                              |
/// | P     | -3 - 3 - 1 = -7                                          |
/// | c, I  | c = 0, I_A = 0, I_B = 0, I_C = 8                         |
/// | s     | clamp(0, max(-8 - 0, -8 - 0, 0 - 8), c + P) = -7         |
/// | input | collateral max(0, s - P) = 0, C r_C - s = 7 of the 8     |
/// | output| collateral 0, A s - r_A = 1, B 1, C change 8 - 7 = 1    |
///
/// Three input proofs pay 3.
#[tokio::test]
async fn test_ctf_settlement_net_merge_bot_record_with_two_user_records() {
    let mint = mint_with_unit_fee_per_input().await;
    let now = unix_time();
    let fixture = users_and_bot(
        &mint,
        now,
        None,
        &[
            Leg {
                inputs: &[("A", &[8])],
                outputs: &[(COLLATERAL, 2)],
            },
            Leg {
                inputs: &[("B", &[8])],
                outputs: &[(COLLATERAL, 2)],
            },
        ],
        Leg {
            inputs: &[("C", &[8])],
            outputs: &[("A", 1), ("B", 1), ("C", 1)],
        },
    )
    .await;
    assert_every_keyset_charges_one_per_input(&mint, &fixture);
    let bot = &fixture.request.participants[fixture.bot];
    assert_eq!(input_keysets(bot), keyset_set([fixture.keyset("C")]));
    assert_eq!(
        output_keysets(bot),
        keyset_set(["A", "B", "C"].map(|outcome| fixture.keyset(outcome))),
        "the bot record has no cash output"
    );
    assert_net_bundle_commits(
        &mint,
        now,
        &fixture,
        &[("A", (8, 5)), ("B", (8, 5)), ("C", (8, 5))],
        3,
    )
    .await;
}

/// s > 0 with two user records: the bot splits 8 sets and keeps cash change.
///
/// Two users buy 8 `A` and 8 `B` from the bot. The first locks 6 in two
/// proofs and pays a fee share of 2, so its gross payment is 4. The second
/// locks 4 in one proof, so its gross payment is 3. The bot holds one proof
/// of 4 cash and no tokens. No user receives `C`.
///
/// | term  | value                                                    |
/// |-------|----------------------------------------------------------|
/// | r     | r_A = 8, r_B = 8, r_C = 0                                |
/// | P     | 4 + 3 - 1 = 6                                            |
/// | c, I  | c = 4, I_A = I_B = I_C = 0                               |
/// | s     | clamp(0, max(8 - 0, 8 - 0, 0 - 0), c + P) = 8            |
/// | input | collateral s - P = 2 of the 4, tokens none               |
/// | output| A s - r_A = 0, B 0, C 8, collateral change 4 - 2 = 2    |
///
/// Four input proofs pay 4.
#[tokio::test]
async fn test_ctf_settlement_net_split_bot_record_with_two_user_records() {
    let mint = mint_with_unit_fee_per_input().await;
    let now = unix_time();
    let fixture = users_and_bot(
        &mint,
        now,
        None,
        &[
            Leg {
                inputs: &[(COLLATERAL, &[4, 2])],
                outputs: &[("A", 8)],
            },
            Leg {
                inputs: &[(COLLATERAL, &[4])],
                outputs: &[("B", 8)],
            },
        ],
        Leg {
            inputs: &[(COLLATERAL, &[4])],
            outputs: &[("C", 8), (COLLATERAL, 2)],
        },
    )
    .await;
    assert_every_keyset_charges_one_per_input(&mint, &fixture);
    let bot = &fixture.request.participants[fixture.bot];
    assert_eq!(input_keysets(bot), keyset_set([fixture.regular_keyset]));
    assert_eq!(
        output_keysets(bot),
        keyset_set([fixture.keyset("C"), fixture.regular_keyset])
    );
    assert_net_bundle_commits(
        &mint,
        now,
        &fixture,
        &[("A", (14, 10)), ("B", (14, 10)), ("C", (14, 10))],
        4,
    )
    .await;
}

/// The bot sells 8 `A` for a gross 3 and buys 8 `B` for a gross `3 - receive`.
///
/// The first user locks one proof of 4 cash for 8 `A` and pays a fee share
/// of 1. The second user locks one proof of 8 `B` and receives
/// `3 - receive - 1`. The bot holds one proof of 8 `A` and the cash proofs
/// `bot_cash`, and receives 8 `B`. Its fee share is its input proof count.
/// The bot record has no cash output.
async fn bot_cash_for_the_fee_fixture(
    mint: &Mint,
    now: u64,
    receive: u64,
    bot_cash: &[u64],
) -> UsersAndBot {
    users_and_bot(
        mint,
        now,
        None,
        &[
            Leg {
                inputs: &[(COLLATERAL, &[4])],
                outputs: &[("A", 8)],
            },
            Leg {
                inputs: &[("B", &[8])],
                outputs: &[(COLLATERAL, 2 - receive)],
            },
        ],
        Leg {
            inputs: &[("A", &[8]), (COLLATERAL, bot_cash)],
            outputs: &[("B", 8)],
        },
    )
    .await
}

/// A net bot record whose cash input the fee uses completely.
///
/// The bot's cash receive before the fee is `R`, and its fee share `f` is 2
/// for its two input proofs. Its cash input `f - R` and the receive pay the
/// fee exactly, so the cash output would be 0 and the record has none. Its
/// one output is the token receipt of 8 `B`. The case `R = 0` is a cash
/// input that equals the fee. The case `R = 1` is a cash receive above 0
/// and not above `f`.
///
/// | term  | value                                                    |
/// |-------|----------------------------------------------------------|
/// | r     | r_A = 8, r_B = -8, r_C = 0                               |
/// | P     | R - f = R - 2                                            |
/// | c, I  | c = 2 - R, I_A = 8, I_B = I_C = 0                        |
/// | s     | clamp(0, max(8 - 8, -8 - 0, 0 - 0), c + P) = 0           |
/// | input | collateral s - P = 2 - R (all of c), A r_A - s = 8       |
/// | output| B s - r_B = 8, collateral max(0, P - s) = 0              |
///
/// Four input proofs pay 4.
#[tokio::test]
async fn test_ctf_settlement_net_bot_cash_input_spent_by_the_fee() {
    for receive in [0, 1] {
        let mint = mint_with_unit_fee_per_input().await;
        let now = unix_time();
        let bot_cash = [2 - receive];
        let fixture = bot_cash_for_the_fee_fixture(&mint, now, receive, &bot_cash).await;
        assert_every_keyset_charges_one_per_input(&mint, &fixture);
        let bot = &fixture.request.participants[fixture.bot];
        assert_eq!(
            input_keysets(bot),
            keyset_set([fixture.regular_keyset, fixture.keyset("A")]),
            "R = {receive}"
        );
        assert_eq!(bot.outputs.len(), 1, "R = {receive}");
        assert_eq!(
            output_keysets(bot),
            keyset_set([fixture.keyset("B")]),
            "R = {receive}: the bot record has one token output and no cash output"
        );
        assert_net_bundle_commits(
            &mint,
            now,
            &fixture,
            &[
                ("A", (14 - receive, 10 - receive)),
                ("B", (14 - receive, 10 - receive)),
                ("C", (6 - receive, 2 - receive)),
            ],
            4,
        )
        .await;
    }
}

/// A net bot record whose inputs pay less than the request fee is refused.
///
/// This is the mint side of a fee loop that does not settle. The trade is
/// that of [`test_ctf_settlement_net_bot_cash_input_spent_by_the_fee`] with
/// `R = 0`, but the bot holds only 1-sat cash proofs. Each 1-sat proof pays
/// its own fee of 1, so another proof never closes the gap of 1.
///
/// | bot cash | bot fee share | fee | inputs - outputs per outcome |
/// |----------|---------------|-----|------------------------------|
/// | 1        | 2             | 4   | 3                            |
/// | 1 + 1    | 3             | 5   | 4                            |
#[tokio::test]
async fn test_ctf_settlement_net_bot_record_short_of_its_fee_is_refused() {
    for (bot_cash, fee, expected) in [
        (
            &[1][..],
            4,
            [("A", (13, 10)), ("B", (13, 10)), ("C", (5, 2))],
        ),
        (
            &[1, 1][..],
            5,
            [("A", (14, 10)), ("B", (14, 10)), ("C", (6, 2))],
        ),
    ] {
        let mint = mint_with_unit_fee_per_input().await;
        let now = unix_time();
        let fixture = bot_cash_for_the_fee_fixture(&mint, now, 0, bot_cash).await;
        assert_every_keyset_charges_one_per_input(&mint, &fixture);
        let inputs = fixture
            .request
            .participants
            .iter()
            .flat_map(|participant| participant.inputs.iter().cloned())
            .collect::<Proofs>();
        assert_eq!(
            mint.get_proofs_fee(&inputs).await.unwrap().total,
            Amount::from(fee),
            "bot cash {bot_cash:?}"
        );
        assert_eq!(
            outcome_totals(&fixture.request, &fixture.coverage()),
            totals(&expected),
            "bot cash {bot_cash:?}"
        );

        let error = refuse_without_writes(&mint, &fixture.request, now).await;
        assert!(
            matches!(
                error,
                CtfSettlementError::Mint(Error::ConvertPayoffFeeViolation)
            ),
            "bot cash {bot_cash:?}: {error:?}"
        );
    }
}

/// A net bot record without inputs is refused although the request conserves.
///
/// This is the no-input edge `max_j r_j <= s <= P`. The bot buys 8 `A` from
/// one user for a gross 3 and sells them to another user for a gross 7. The
/// users pay their fee shares of 1 each. The bot has no fee share.
///
/// | term  | value                                     |
/// |-------|-------------------------------------------|
/// | r     | r_A = -8 + 8 = 0, r_B = 0, r_C = 0        |
/// | P     | 7 - 3 - 0 = 4                             |
/// | s     | 0                                         |
/// | input | none                                      |
/// | output| collateral P - s = 4                      |
///
/// The mint requires an input in every record. See
/// [`test_ctf_settlement_net_merge_bot_record_without_outputs_is_refused`]
/// for the record without outputs.
#[tokio::test]
async fn test_ctf_settlement_net_bot_record_without_inputs_is_refused() {
    let mint = mint_with_unit_fee_per_input().await;
    let now = unix_time();
    // The fixture needs a bot input to order its records. The test removes it.
    let mut fixture = users_and_bot(
        &mint,
        now,
        None,
        &[
            Leg {
                inputs: &[("A", &[8])],
                outputs: &[(COLLATERAL, 2)],
            },
            Leg {
                inputs: &[(COLLATERAL, &[8])],
                outputs: &[("A", 8)],
            },
        ],
        Leg {
            inputs: &[(COLLATERAL, &[1])],
            outputs: &[(COLLATERAL, 4)],
        },
    )
    .await;
    fixture.request.participants[fixture.bot].inputs.clear();
    assert_every_keyset_charges_one_per_input(&mint, &fixture);
    let inputs = fixture
        .request
        .participants
        .iter()
        .flat_map(|participant| participant.inputs.iter().cloned())
        .collect::<Proofs>();
    assert_eq!(
        mint.get_proofs_fee(&inputs).await.unwrap().total,
        Amount::from(2)
    );
    assert_eq!(
        outcome_totals(&fixture.request, &fixture.coverage()),
        totals(&[("A", (16, 14)), ("B", (8, 6)), ("C", (8, 6))])
    );

    let error = refuse_without_writes(&mint, &fixture.request, now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Protocol(SettlementError::InvalidStructure(
                "each participant requires inputs and outputs"
            ))
        ),
        "{error:?}"
    );
}
