use std::io::Cursor;

use serde_json::{json, Value};

use super::*;

fn frames(records: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        let raw = serde_json::to_vec(record).unwrap();
        bytes.extend((raw.len() as u32).to_be_bytes());
        bytes.extend(raw);
    }
    bytes.extend(0u32.to_be_bytes());
    bytes
}

fn fixture() -> Vec<Value> {
    use ctf::test_helpers::{create_test_announcement, create_test_oracle};
    let (announcement, encoded) =
        create_test_announcement(&create_test_oracle(), &["A", "B", "C"], "maintenance-test");
    let id = ctf::compute_condition_id(
        &[ctf::dlc::extract_oracle_pubkey(&announcement)],
        "maintenance-test",
        3,
    );
    let binding = |collection: &str| {
        json!({"condition":ctf::to_hex(&id),"collection":collection,
        "collection_id":ctf::to_hex(&ctf::compute_outcome_collection_id(&[0;32], &id, collection).unwrap())})
    };
    vec![
        json!({"kind":"header","version":1}),
        json!({"kind":"condition","stored":{"condition_id":ctf::to_hex(&id),"threshold":1,"tags_json":"[]",
            "announcements_json":serde_json::to_string(&vec![encoded]).unwrap(),"collateral":"msat","attestation_status":"pending",
            "winning_outcome":null,"attested_at":null,"oracle_sigs":null,"created_at":1,"condition_type":"enum",
            "lo_bound":null,"hi_bound":null,"precision":null}}),
        json!({"kind":"keyset","id":"inactive-regular","unit":"sat","issued":20,"redeemed":3,"signed_ledger":20,"spent_ledger":3,"binding":null}),
        json!({"kind":"keyset","id":"conditional-ab","unit":"msat","issued":10,"redeemed":1,"signed_ledger":10,"spent_ledger":1,"binding":binding("A|B")}),
        json!({"kind":"keyset","id":"conditional-b","unit":"msat","issued":5,"redeemed":0,"signed_ledger":5,"spent_ledger":0,"binding":binding("B")}),
        json!({"kind":"quote","id":"expired-quote","unit":"msat","paid":8,"issued":3,"payment_ledger":8,"issuance_ledger":3}),
        json!({"kind":"end","conditions":1,"keysets":3,"quotes":1}),
    ]
}

#[test]
fn combines_regular_conditional_and_only_unissued_credit() {
    let result = evaluate(Cursor::new(frames(&fixture()))).unwrap();
    assert!(!result.authorizing);
    assert_eq!(result.sat.total, 17);
    assert_eq!(result.msat.conditional, 14);
    assert_eq!(result.msat.paid_unissued, 5);
    assert_eq!(result.total_msat, 17_019);
}

#[test]
fn winner_reduces_payout_but_numeric_winner_is_refused() {
    let mut input = fixture();
    input[1]["stored"]["winning_outcome"] = json!("C");
    input[1]["stored"]["attestation_status"] = json!("attested");
    input[1]["stored"]["attested_at"] = json!(2);
    input[1]["stored"]["oracle_sigs"] = json!(
        ctf::test_helpers::create_oracle_witness(&ctf::test_helpers::create_test_oracle(), "C")
            .oracle_sigs
    );
    assert_eq!(
        evaluate(Cursor::new(frames(&input)))
            .unwrap()
            .msat
            .conditional,
        0
    );
    input[1]["stored"]["condition_type"] = json!("numeric");
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
}

#[test]
fn every_counter_and_quote_ledger_is_checked() {
    for (index, field) in [
        (2, "issued"),
        (2, "redeemed"),
        (2, "signed_ledger"),
        (2, "spent_ledger"),
        (5, "paid"),
        (5, "issued"),
        (5, "payment_ledger"),
        (5, "issuance_ledger"),
    ] {
        let mut input = fixture();
        input[index][field] = json!(99);
        assert_eq!(
            evaluate(Cursor::new(frames(&input))),
            Err(Refusal::Ledger),
            "{field}"
        );
    }
}

#[test]
fn duplicate_ids_and_unbound_or_noncanonical_collections_refuse() {
    let mut input = fixture();
    input[4]["id"] = input[3]["id"].clone();
    assert_eq!(
        evaluate(Cursor::new(frames(&input))),
        Err(Refusal::Identity)
    );
    for collection in ["", "B|A", "A|A", "A|B|C", "unknown"] {
        let mut input = fixture();
        input[3]["binding"]["collection"] = json!(collection);
        assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
    }
    let mut input = fixture();
    input[3]["binding"]["condition"] = json!("missing");
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
}

#[test]
fn ordinary_saturation_is_never_accepted_by_maintenance() {
    let mut input = fixture();
    input[3]["issued"] = json!(u64::MAX);
    input[3]["signed_ledger"] = json!(u64::MAX);
    input[3]["redeemed"] = json!(0);
    input[3]["spent_ledger"] = json!(0);
    assert_eq!(
        evaluate(Cursor::new(frames(&input))),
        Err(Refusal::Overflow)
    );
    let mut input = fixture();
    input[2]["issued"] = json!(u64::MAX);
    input[2]["signed_ledger"] = json!(u64::MAX);
    assert_eq!(
        evaluate(Cursor::new(frames(&input))),
        Err(Refusal::Overflow)
    );
}

#[test]
fn framing_and_limits_refuse_before_unadmitted_body_read() {
    struct HeaderOnly {
        header: Cursor<[u8; 4]>,
    }
    impl Read for HeaderOnly {
        fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                self.header.position() < 4,
                "body was requested before admission"
            );
            self.header.read(target)
        }
    }
    assert_eq!(
        evaluate(HeaderOnly {
            header: Cursor::new((MAX_FRAME as u32 + 1).to_be_bytes())
        }),
        Err(Refusal::Limit)
    );
    let bytes = frames(&fixture());
    assert_eq!(
        evaluate_with_limits(
            Cursor::new(&bytes),
            bytes.len() - 1,
            MAX_RECORDS,
            MAX_ASSOCIATIONS
        ),
        Err(Refusal::Limit)
    );
    assert_eq!(
        evaluate_with_limits(Cursor::new(&bytes), MAX_BYTES, 2, MAX_ASSOCIATIONS),
        Err(Refusal::Limit)
    );
    assert_eq!(
        evaluate_with_limits(Cursor::new(&bytes), MAX_BYTES, MAX_RECORDS, 3),
        Err(Refusal::Limit)
    );
    assert_eq!(
        evaluate(Cursor::new(&bytes[..bytes.len() - 1])),
        Err(Refusal::Framing)
    );
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(evaluate(Cursor::new(extra)), Err(Refusal::Framing));
    let mut input = fixture();
    input.pop();
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Framing));
}

#[test]
fn unknown_duplicate_fields_units_and_declared_counts_refuse() {
    let mut input = fixture();
    input[2]["secret"] = json!("never permitted");
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Shape));
    let mut input = fixture();
    input[2]["unit"] = json!("usd");
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Shape));
    let mut input = fixture();
    input[6]["keysets"] = json!(0);
    assert_eq!(
        evaluate(Cursor::new(frames(&input))),
        Err(Refusal::Identity)
    );
    let raw = br#"{"kind":"header","version":1,"version":1}"#;
    let mut bytes = Vec::from((raw.len() as u32).to_be_bytes());
    bytes.extend(raw);
    assert_eq!(evaluate(Cursor::new(bytes)), Err(Refusal::Shape));
}

fn attested_fixture() -> Vec<Value> {
    let mut input = fixture();
    input[1]["stored"]["winning_outcome"] = json!("C");
    input[1]["stored"]["attestation_status"] = json!("attested");
    input[1]["stored"]["attested_at"] = json!(2);
    input[1]["stored"]["oracle_sigs"] = json!(
        ctf::test_helpers::create_oracle_witness(&ctf::test_helpers::create_test_oracle(), "C")
            .oracle_sigs
    );
    input
}

#[test]
fn structurally_valid_forged_winner_never_erases_liability() {
    let mut input = attested_fixture();
    input[1]["stored"]["oracle_sigs"][0]["oracle_sig"] = json!("00".repeat(64));
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
}

#[test]
fn wrong_registered_key_or_announced_nonce_refuses() {
    let mut input = attested_fixture();
    input[1]["stored"]["oracle_sigs"] = json!(
        ctf::test_helpers::create_oracle_witness(&ctf::test_helpers::create_test_oracle_2(), "C")
            .oracle_sigs
    );
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
    let mut input = attested_fixture();
    let original = input[1]["stored"]["oracle_sigs"][0]["oracle_sig"]
        .as_str()
        .unwrap();
    let mut signature = original.to_owned();
    signature.replace_range(..64, &"11".repeat(32));
    input[1]["stored"]["oracle_sigs"][0]["oracle_sig"] = json!(signature);
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
}

#[test]
fn insufficient_threshold_duplicate_signer_and_conflicting_winner_refuse() {
    let mut input = attested_fixture();
    input[1]["stored"]["threshold"] = json!(2);
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
    let mut input = attested_fixture();
    let signature = input[1]["stored"]["oracle_sigs"][0].clone();
    input[1]["stored"]["oracle_sigs"]
        .as_array_mut()
        .unwrap()
        .push(signature);
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
    let mut input = attested_fixture();
    input[1]["stored"]["winning_outcome"] = json!("A");
    assert_eq!(evaluate(Cursor::new(frames(&input))), Err(Refusal::Binding));
}
