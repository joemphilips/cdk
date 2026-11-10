//! Mint evidence at the multi-party settlement limits that the deployed mint advertises.
//!
//! The deployment advertises 64 participants, 4096 inputs, 8192 outputs, a
//! 1 MiB request, a 24-hour authorization lifetime, and 128 pool entries. It
//! also sets the NUT-03 transaction limits of the mint to 4096 inputs and 8192
//! outputs, so each settlement input count meets two bounds.

use cdk_common::nuts::nut_ctf::settlement::CtfSettlementLimits;

use super::*;

const PRODUCTION_MAX_PARTICIPANTS: u64 = 64;
const PRODUCTION_MAX_INPUTS: u64 = 4096;
const PRODUCTION_MAX_OUTPUTS: u64 = 8192;
const PRODUCTION_MAX_REQUEST_BYTES: usize = 1024 * 1024;

fn production_settings_with(max_participants: u64, max_inputs: u64) -> NutCtfSettlementSettings {
    NutCtfSettlementSettings::new(
        max_participants,
        max_inputs,
        PRODUCTION_MAX_OUTPUTS,
        u64::try_from(PRODUCTION_MAX_REQUEST_BYTES).unwrap(),
        24 * 60 * 60,
        128,
    )
    .unwrap()
}

fn production_settings() -> NutCtfSettlementSettings {
    production_settings_with(PRODUCTION_MAX_PARTICIPANTS, PRODUCTION_MAX_INPUTS)
}

fn production_limits() -> CtfSettlementLimits {
    production_settings().structural_limits().unwrap()
}

/// A mint with the deployed NUT-03 transaction limits.
fn with_transaction_limits(mint: &Mint, max_inputs: usize, max_outputs: usize) -> Mint {
    let mut limited = mint.clone();
    limited.max_inputs = max_inputs;
    limited.max_outputs = max_outputs;
    limited
}

async fn production_limit_mint() -> Mint {
    let mint = create_test_mint_with_unit(CurrencyUnit::Sat, 1)
        .await
        .unwrap();
    with_transaction_limits(&mint, 4096, 8192)
}

fn total_inputs(request: &CtfSettlementRequest) -> usize {
    request
        .participants
        .iter()
        .map(|participant| participant.inputs.len())
        .sum()
}

/// Encode the request with leading JSON whitespace to exactly `length` bytes.
fn padded_wire(request: &CtfSettlementRequest, length: usize) -> Vec<u8> {
    let encoded = serde_json::to_vec(request).unwrap();
    let mut padded = vec![b' '; length - encoded.len()];
    padded.extend(encoded);
    padded
}

/// Wallets keep the NUT-12 DLEQ proof locally. The settlement request does not need it.
fn without_dleq(mut proofs: Proofs) -> Proofs {
    for proof in &mut proofs {
        proof.dleq = None;
    }
    proofs
}

struct InputLimitFixture {
    /// 4096 input proofs.
    at_limit: CtfSettlementRequest,
    /// `at_limit` with one more regular input proof and one more collateral output.
    over_limit: CtfSettlementRequest,
    /// `at_limit` with the DLEQ proof that each input received at issuance.
    at_limit_with_dleq: CtfSettlementRequest,
    regular_keyset: Id,
    yes_keyset: Id,
    no_keyset: Id,
}

/// A locked seller offers one YES proof of 4096 for 2048 collateral.
///
/// The bare bot record MERGEs 4095 NO proofs: 4094 proofs of 1 and one of 2.
/// 4096 one-ppk inputs pay ceil(4096 / 1000) = 5, so the bot receives
/// 4096 - 5 - 2048 = 2043 collateral.
async fn input_limit_fixture(mint: &Mint, now: u64) -> InputLimitFixture {
    let (condition_id, keysets) =
        register_test_condition_with_collateral(mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let regular_keyset = get_regular_keyset_id(mint);
    let (yes_keyset, no_keyset) = (keysets["YES"], keysets["NO"]);
    let seller_receive = create_premint(mint, regular_keyset, Amount::from(2048)).0;
    let seller_offer = pay_to_unlock_premint(
        yes_keyset,
        &[4096],
        &seller_receive,
        now + OFFER_LIFETIME_SECONDS,
        1,
    );
    let mut bot_amounts = vec![Amount::ONE; 4094];
    bot_amounts.push(Amount::from(2));
    let bot_secrets = bot_amounts.iter().map(|_| Secret::generate()).collect();
    let bot_premint = PreMintSecrets::from_secrets(no_keyset, bot_amounts, bot_secrets).unwrap();
    let [seller_funding, bot_funding, extra_collateral]: [Proofs; 3] = issue_regular_premints(
        mint,
        &[
            conversion_funding(mint, 4096),
            conversion_funding(mint, 4096),
            create_premint(mint, regular_keyset, Amount::ONE).1,
        ],
    )
    .await
    .try_into()
    .unwrap();
    let seller_inputs = convert_to_conditional_premint(mint, seller_funding, seller_offer).await;
    let bot_inputs = convert_to_conditional_premint(mint, bot_funding, bot_premint).await;
    let bot_receive = create_premint(mint, regular_keyset, Amount::from(2043)).0;

    let request = |seller: Proofs, bot: Proofs, bot_receive: Vec<BlindedMessage>| {
        settlement_request(
            &condition_id,
            vec![
                settlement_record(seller, seller_receive.clone()),
                settlement_record(bot, bot_receive),
            ],
        )
    };
    let at_limit_with_dleq = request(
        seller_inputs.clone(),
        bot_inputs.clone(),
        bot_receive.clone(),
    );
    let at_limit = request(
        without_dleq(seller_inputs.clone()),
        without_dleq(bot_inputs.clone()),
        bot_receive.clone(),
    );
    let mut over_inputs = without_dleq(bot_inputs);
    over_inputs.extend(without_dleq(extra_collateral));
    let mut over_receive = bot_receive;
    over_receive.extend(create_premint(mint, regular_keyset, Amount::ONE).0);
    let over_limit = request(without_dleq(seller_inputs), over_inputs, over_receive);
    InputLimitFixture {
        at_limit,
        over_limit,
        at_limit_with_dleq,
        regular_keyset,
        yes_keyset,
        no_keyset,
    }
}

/// A MERGE at 4096 inputs and a 1 MiB request commits. One more input or byte is refused.
#[tokio::test]
async fn test_ctf_settlement_at_production_input_and_byte_limits() {
    let mint = production_limit_mint().await;
    let now = unix_time();
    let fixture = input_limit_fixture(&mint, now).await;
    let coverage = binary_coverage(
        fixture.regular_keyset,
        fixture.yes_keyset,
        fixture.no_keyset,
    );
    assert_eq!(total_inputs(&fixture.at_limit), 4096);
    assert_eq!(total_inputs(&fixture.over_limit), 4097);
    // 4096 and 4097 one-ppk inputs both pay a fee of 5.
    assert_eq!(
        outcome_totals(&fixture.at_limit, &coverage),
        totals(&[("NO", (4096, 4091)), ("YES", (4096, 4091))])
    );
    assert_eq!(
        outcome_totals(&fixture.over_limit, &coverage),
        totals(&[("NO", (4097, 4092)), ("YES", (4097, 4092))])
    );

    // One input over the advertised settlement limit.
    let error =
        refuse_without_writes_with(&mint, &fixture.over_limit, production_settings(), now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Protocol(SettlementError::LimitExceeded("inputs"))
        ),
        "{error:?}"
    );
    // The count is the only defect: one more allowed input admits the same request.
    let signing_before = mint.blind_sign_attempts();
    let wider = with_transaction_limits(&mint, 4097, 8192);
    let prepared = wider
        .prepare_ctf_settlement(
            &fixture.over_limit,
            production_settings_with(PRODUCTION_MAX_PARTICIPANTS, 4097),
            now,
        )
        .await
        .expect("the over-limit request must otherwise conserve every outcome");
    assert_request_fee(
        &prepared,
        5,
        &[
            fixture.regular_keyset,
            fixture.yes_keyset,
            fixture.no_keyset,
        ],
    );
    // The NUT-03 transaction limit is a second bound on the same count.
    let narrow = with_transaction_limits(&mint, 4095, 8192);
    let error = narrow
        .prepare_ctf_settlement(&fixture.at_limit, production_settings(), now)
        .await
        .err()
        .expect("the transaction input limit must refuse 4096 inputs");
    assert!(
        matches!(
            error,
            CtfSettlementError::Mint(Error::MaxInputsExceeded {
                actual: 4096,
                max: 4095
            })
        ),
        "{error:?}"
    );
    assert_eq!(mint.blind_sign_attempts(), signing_before);

    // 4096 inputs fit in 1 MiB only without the DLEQ proofs of the inputs.
    let encoded = serde_json::to_vec(&fixture.at_limit).unwrap().len();
    let encoded_with_dleq = serde_json::to_vec(&fixture.at_limit_with_dleq)
        .unwrap()
        .len();
    assert!(
        encoded <= PRODUCTION_MAX_REQUEST_BYTES,
        "{encoded} bytes without input DLEQ proofs"
    );
    assert!(
        encoded_with_dleq > PRODUCTION_MAX_REQUEST_BYTES,
        "{encoded_with_dleq} bytes with input DLEQ proofs"
    );
    // The HTTP handler decodes the body with this function and the advertised limits.
    let over_byte_limit = padded_wire(&fixture.at_limit, PRODUCTION_MAX_REQUEST_BYTES + 1);
    assert!(matches!(
        CtfSettlementRequest::decode(&over_byte_limit, production_limits()),
        Err(SettlementError::LimitExceeded("request bytes"))
    ));
    let at_byte_limit = padded_wire(&fixture.at_limit, PRODUCTION_MAX_REQUEST_BYTES);
    let decoded = CtfSettlementRequest::decode(&at_byte_limit, production_limits())
        .expect("a request of exactly 1 MiB must decode");
    assert_eq!(decoded, fixture.at_limit);

    let prepared = mint
        .prepare_ctf_settlement(&decoded, production_settings(), now)
        .await
        .expect("4096 inputs must conserve every outcome");
    assert_request_fee(&prepared, 5, &[fixture.yes_keyset, fixture.no_keyset]);
    commit_and_check_with(&mint, &decoded, production_settings(), now, 5).await;
}

/// `participants - 1` locked users and one bare bot record MERGE complete sets.
///
/// The users alternate: one sells 4 YES and the next sells 4 NO. Each user
/// receives 2 collateral. The bot completes every set with its own YES and NO
/// and receives the remaining collateral.
async fn participant_limit_request(
    mint: &Mint,
    condition_id: &str,
    keysets: &HashMap<String, Id>,
    now: u64,
    participants: usize,
) -> CtfSettlementRequest {
    let regular = get_regular_keyset_id(mint);
    let (yes, no) = (keysets["YES"], keysets["NO"]);
    let users = participants - 1;
    let yes_users = users.div_ceil(2);
    let no_users = users / 2;
    let bot_yes = 4 * (1 + no_users.saturating_sub(yes_users));
    let bot_no = 4 * (1 + yes_users.saturating_sub(no_users));
    // `users + 2` one-ppk inputs pay 1. Every user receives 2.
    let bot_collateral = 4 * yes_users + bot_yes - 1 - 2 * users;

    let mut fundings = (0..users)
        .map(|_| conversion_funding(mint, 4))
        .collect::<Vec<_>>();
    fundings.push(conversion_funding(mint, u64::try_from(bot_yes).unwrap()));
    fundings.push(conversion_funding(mint, u64::try_from(bot_no).unwrap()));
    let mut fundings = issue_regular_premints(mint, &fundings).await.into_iter();
    let expiry = now + OFFER_LIFETIME_SECONDS;
    let mut records = Vec::with_capacity(participants);
    for user in 0..users {
        let offer = if user % 2 == 0 { yes } else { no };
        let receive = create_premint(mint, regular, Amount::from(2)).0;
        let nonce = u8::try_from(user + 1).unwrap();
        let locked = pay_to_unlock_premint(offer, &[4], &receive, expiry, nonce);
        let inputs = convert_to_conditional_premint(mint, fundings.next().unwrap(), locked).await;
        records.push(settlement_record(inputs, receive));
    }
    let mut bot_inputs = convert_to_conditional(
        mint,
        fundings.next().unwrap(),
        yes,
        Amount::from(u64::try_from(bot_yes).unwrap()),
    )
    .await;
    bot_inputs.extend(
        convert_to_conditional(
            mint,
            fundings.next().unwrap(),
            no,
            Amount::from(u64::try_from(bot_no).unwrap()),
        )
        .await,
    );
    let bot_receive = create_premint(
        mint,
        regular,
        Amount::from(u64::try_from(bot_collateral).unwrap()),
    )
    .0;
    records.push(settlement_record(bot_inputs, bot_receive));
    settlement_request(condition_id, records)
}

/// A MERGE of 64 participants commits. A request of 65 participants is refused.
#[tokio::test]
async fn test_ctf_settlement_at_production_participant_limit() {
    let mint = production_limit_mint().await;
    let now = unix_time();
    let (condition_id, keysets) =
        register_test_condition_with_collateral(&mint, &["YES", "NO"], CurrencyUnit::Sat).await;
    let regular = get_regular_keyset_id(&mint);
    let (yes, no) = (keysets["YES"], keysets["NO"]);
    let coverage = binary_coverage(regular, yes, no);
    let at_limit = participant_limit_request(&mint, &condition_id, &keysets, now, 64).await;
    let over_limit = participant_limit_request(&mint, &condition_id, &keysets, now, 65).await;
    assert_eq!(at_limit.participants.len(), 64);
    assert_eq!(over_limit.participants.len(), 65);
    assert_eq!(
        at_limit
            .validated_authorizations(production_limits())
            .unwrap()
            .len(),
        63,
        "every user is a locked record and the bot is the one bare record"
    );
    // 64: 32 YES users, 31 NO users, and a bot that gives 4 YES and 8 NO.
    // 65: 32 YES users, 32 NO users, and a bot that gives 4 YES and 4 NO.
    // Each request has fewer than 1000 one-ppk inputs, so it pays 1.
    for request in [&at_limit, &over_limit] {
        assert_eq!(
            outcome_totals(request, &coverage),
            totals(&[("NO", (132, 131)), ("YES", (132, 131))])
        );
    }

    let error = refuse_without_writes_with(&mint, &over_limit, production_settings(), now).await;
    assert!(
        matches!(
            error,
            CtfSettlementError::Protocol(SettlementError::LimitExceeded("participants"))
        ),
        "{error:?}"
    );
    // The count is the only defect: one more allowed participant admits the same request.
    let prepared = mint
        .prepare_ctf_settlement(&over_limit, production_settings_with(65, 4096), now)
        .await
        .expect("the over-limit request must otherwise conserve every outcome");
    assert_request_fee(&prepared, 1, &[yes, no]);

    let prepared = mint
        .prepare_ctf_settlement(&at_limit, production_settings(), now)
        .await
        .expect("64 participants must conserve every outcome");
    assert_request_fee(&prepared, 1, &[yes, no]);
    commit_and_check_with(&mint, &at_limit, production_settings(), now, 1).await;
}
