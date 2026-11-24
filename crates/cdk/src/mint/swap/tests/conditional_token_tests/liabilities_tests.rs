//! The liabilities of a mint with regular and conditional tokens.
//!
//! The mint reads them with one query. These tests compare its result with
//! known totals, and with the same rule applied to separate reads of each
//! fact.

use cdk_common::nuts::nut_ctf::OracleWitness;

use super::*;
use crate::mint::state_limits::LiabilityAnomaly;

/// Issue `amount` of one keyset, as a signed output does.
async fn issue(mint: &Mint, keyset_id: Id, amount: u64) {
    let mut tx = mint.localstore().begin_transaction().await.unwrap();
    tx.add_blind_signatures(
        &[SecretKey::generate().public_key()],
        &[cdk_common::BlindSignature {
            amount: Amount::from(amount),
            keyset_id,
            c: SecretKey::generate().public_key(),
            dleq: None,
        }],
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Redeem `amount` of one keyset, as a spent input does.
async fn redeem(mint: &Mint, keyset_id: Id, amount: u64) {
    let proofs = vec![cdk_common::Proof::new(
        Amount::from(amount),
        keyset_id,
        Secret::generate(),
        SecretKey::generate().public_key(),
    )];
    let mut tx = mint.localstore().begin_transaction().await.unwrap();
    tx.add_proofs(
        proofs.clone(),
        None,
        &Operation::new_swap(Amount::ZERO, Amount::ZERO, Amount::ZERO),
    )
    .await
    .unwrap();
    let mut stored = tx.get_proofs(&proofs.ys().unwrap()).await.unwrap();
    Mint::update_proofs_state(&mut tx, &mut stored, State::Spent)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn register(
    mint: &Mint,
    event: &str,
    outcomes: &[&str],
    collections: &[&str],
    unit: CurrencyUnit,
) -> (String, HashMap<String, Id>) {
    let (_, announcement) = create_test_announcement(&create_test_oracle(), outcomes, event);
    let mut request = enum_condition_request("Test condition", vec![announcement]);
    request.collateral = Some(unit.to_string());
    request.outcome_collections = Some(collections.iter().map(ToString::to_string).collect());
    let registered = mint.register_condition(request).await.unwrap();
    (registered.condition_id, registered.keysets)
}

async fn attest(mint: &Mint, condition_id: &str, winner: &str, witness: OracleWitness) {
    assert!(mint
        .localstore()
        .update_condition_attestation(
            condition_id,
            "attested",
            Some(winner),
            Some(unix_time()),
            &witness.oracle_sigs,
        )
        .await
        .unwrap());
}

/// The liabilities of each unit from one read for each fact: the totals, the
/// binding of each conditional keyset and the attestation of its condition.
async fn totals_from_separate_reads(mint: &Mint) -> HashMap<CurrencyUnit, u64> {
    let store = mint.localstore();
    let issued = store.get_total_issued().await.unwrap();
    let redeemed = store.get_total_redeemed().await.unwrap();
    let mut totals = HashMap::<CurrencyUnit, u64>::new();
    let mut payouts = HashMap::<(CurrencyUnit, String), HashMap<String, u64>>::new();
    for keyset in mint.keysets.load().iter() {
        let sum = |totals: &HashMap<Id, Amount>| totals.get(&keyset.id).map_or(0, |a| a.to_u64());
        let amount = sum(&issued).saturating_sub(sum(&redeemed));
        let binding = match keyset.condition_id {
            Some(_) => store.get_condition_for_keyset(&keyset.id).await.unwrap(),
            None => None,
        };
        match binding {
            None => *totals.entry(keyset.unit.clone()).or_default() += amount,
            Some((condition_id, collection, _)) => {
                let outcomes = payouts
                    .entry((keyset.unit.clone(), condition_id))
                    .or_default();
                for outcome in collection.split('|') {
                    *outcomes.entry(outcome.to_owned()).or_default() += amount;
                }
            }
        }
    }
    for ((unit, condition_id), outcomes) in payouts {
        let condition = store.get_condition(&condition_id).await.unwrap().unwrap();
        let payout = match condition.winning_outcome {
            Some(winner) if condition.condition_type == "enum" => {
                outcomes.get(&winner).copied().unwrap_or(0)
            }
            _ => outcomes.values().copied().max().unwrap_or(0),
        };
        *totals.entry(unit).or_default() += payout;
    }
    totals
}

async fn assert_liabilities(mint: &Mint) {
    let sat = CurrencyUnit::Sat;
    let msat = CurrencyUnit::Msat;
    assert_eq!(
        mint.liabilities().await.unwrap().totals,
        HashMap::from([(sat.clone(), 0), (msat.clone(), 0)]),
        "a new mint has no liabilities"
    );

    let regular_sat = get_regular_keyset_id_for_unit(mint, &sat);
    let regular_msat = get_regular_keyset_id_for_unit(mint, &msat);
    issue(mint, regular_sat, 1_000).await;
    redeem(mint, regular_sat, 40).await;
    issue(mint, regular_msat, 5_000).await;

    // Pending: A pays 100 + 60, B pays 60 + 40, C pays 40 + 60.
    let (_, pending) = register(
        mint,
        "pending",
        &["A", "B", "C"],
        &["A", "B|C", "B", "A|C"],
        sat.clone(),
    )
    .await;
    for (collection, amount) in [("A", 100), ("B|C", 40), ("B", 60), ("A|C", 60)] {
        issue(mint, pending[collection], amount).await;
    }
    // Resolved for YES: only the YES tokens that are not redeemed pay out.
    let (resolved_id, resolved) = register(
        mint,
        "resolved",
        &["YES", "NO"],
        &["YES", "NO"],
        sat.clone(),
    )
    .await;
    issue(mint, resolved["YES"], 70).await;
    issue(mint, resolved["NO"], 500).await;
    redeem(mint, resolved["YES"], 30).await;
    let oracle = create_test_oracle();
    attest(
        mint,
        &resolved_id,
        "YES",
        create_oracle_witness(&oracle, "YES"),
    )
    .await;
    // Pending, in the other unit.
    let (_, other_unit) = register(
        mint,
        "other-unit",
        &["YES", "NO"],
        &["YES", "NO"],
        msat.clone(),
    )
    .await;
    issue(mint, other_unit["YES"], 7).await;
    issue(mint, other_unit["NO"], 9).await;
    // Resolved for an outcome without tokens.
    let (worthless_id, worthless) = register(
        mint,
        "worthless",
        &["YES", "NO"],
        &["YES", "NO"],
        msat.clone(),
    )
    .await;
    issue(mint, worthless["YES"], 11).await;
    attest(
        mint,
        &worthless_id,
        "NO",
        create_oracle_witness(&oracle, "NO"),
    )
    .await;
    // An attested numeric condition has no winning outcome: the larger side counts.
    let (numeric_id, numeric) = register_numeric_condition(mint, 0, 100_000).await;
    issue(mint, numeric["HI"], 80).await;
    issue(mint, numeric["LO"], 30).await;
    attest(
        mint,
        &numeric_id,
        "50000",
        create_numeric_oracle_witness(&oracle, 50_000, 10, false, 5),
    )
    .await;
    // Without tokens, and with more redeemed than issued.
    let (_, empty) = register(mint, "empty", &["YES", "NO"], &["YES", "NO"], sat.clone()).await;
    redeem(mint, empty["YES"], 3).await;

    let liabilities = mint.liabilities().await.unwrap();
    assert_eq!(
        liabilities.totals,
        HashMap::from([
            (sat.clone(), 960 + 160 + 40 + 80),
            (msat.clone(), 5_000 + 9)
        ])
    );
    assert_eq!(liabilities.totals, totals_from_separate_reads(mint).await);
    let anomaly = LiabilityAnomaly {
        keyset: empty["YES"],
        unit: sat.clone(),
        excess: 3,
    };
    assert_eq!(liabilities.anomalies, vec![anomaly.clone()]);

    // A conditional keyset without a binding cannot be valued: it counts in full.
    let unbound = mint
        .keysets
        .load()
        .iter()
        .cloned()
        .map(|mut keyset| {
            if keyset.id == regular_msat {
                keyset.condition_id = Some("ff".repeat(32));
            }
            keyset
        })
        .collect();
    mint.keysets.store(Arc::new(unbound));
    let unbound = mint.liabilities().await.unwrap();
    assert_eq!(unbound.totals, liabilities.totals);
    assert_eq!(unbound.totals, totals_from_separate_reads(mint).await);
    assert_eq!(unbound.anomalies, vec![anomaly]);
}

const UNITS: [(CurrencyUnit, u64); 2] = [(CurrencyUnit::Sat, 1), (CurrencyUnit::Msat, 1)];

#[tokio::test]
async fn test_liabilities_of_regular_and_conditional_tokens() {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await.unwrap());
    let mint = build_test_mint_with_units(db, &[51; 32], &UNITS)
        .await
        .unwrap();
    assert_liabilities(&mint).await;
    mint.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL database in PG_DB_URL"]
async fn test_postgres_liabilities_of_regular_and_conditional_tokens() {
    let mint = postgres_test_mint("liabilities", 52, &UNITS).await;
    assert_liabilities(&mint).await;
    mint.stop().await.unwrap();
}
