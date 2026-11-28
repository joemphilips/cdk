use std::io::Cursor;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use lightning::offers::offer::{Amount as OfferAmount, Offer, OfferBuilder, Quantity};
use lightning::util::ser::Writeable;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use serde_json::{json, Value};

use super::*;

fn make_invoice(amount: Option<u64>, seed: u8) -> Bolt11Invoice {
    make_invoice_on_chain(amount, seed, Currency::Regtest)
}
fn make_invoice_on_chain(amount: Option<u64>, seed: u8, currency: Currency) -> Bolt11Invoice {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[seed; 32]).unwrap();
    let builder = InvoiceBuilder::new(currency)
        .description("synthetic original-generation invoice".to_owned())
        .payment_hash(sha256::Hash::hash(&[seed]))
        .payment_secret(PaymentSecret([seed; 32]))
        .duration_since_epoch(Duration::from_secs(1))
        .expiry_time(Duration::from_secs(1))
        .min_final_cltv_expiry_delta(18);
    let builder = match amount {
        Some(value) => builder.amount_milli_satoshis(value),
        None => builder,
    };
    builder
        .build_signed(|message| secp.sign_ecdsa_recoverable(message, &key))
        .unwrap()
}
fn offer(amount: Option<u64>) -> Offer {
    let key = SecretKey::from_slice(&[42; 32]).unwrap();
    let builder = OfferBuilder::new(key.public_key(&Secp256k1::new()))
        .chain(Network::Regtest)
        .description("synthetic offer".to_owned());
    match amount {
        Some(value) => builder.amount_msats(value).build().unwrap(),
        None => builder.build().unwrap(),
    }
}
fn mint(id: &str, method: &str, request: String, lookup: String, amount: Option<u64>) -> Value {
    json!({"kind":"request","fact":{"id":id,"side":"mint","unit":"msat","method":method,"request":request,
        "amount":amount,"state":null,"lookup_kind":if method=="bolt11" {"payment_hash"} else {"offer_id"},"lookup":lookup,"options":null}})
}
fn melt(
    id: &str,
    method: &str,
    request: String,
    lookup: Option<String>,
    amount: u64,
    options: Option<String>,
) -> Value {
    json!({"kind":"request","fact":{"id":id,"side":"melt","unit":"msat","method":method,"request":request,
        "amount":amount,"state":"PAID","lookup_kind":lookup.as_ref().map(|_|if method=="bolt11" {"payment_hash"} else {"payment_id"}),"lookup":lookup,"options":options}})
}
fn credit(id: &str, quote: &str, payment: &str, amount: u64) -> Value {
    json!({"kind":"credit","fact":{"id":id,"quote":quote,"payment":payment,"amount":amount}})
}
fn receipt(
    id: u8,
    method: &str,
    hash: Option<String>,
    offer: Option<String>,
    inbound: bool,
    amount: u64,
) -> Value {
    json!({"kind":"receipt","fact":{"id":format!("{id:064x}"),"kind":method,"direction":if inbound {"INBOUND"} else {"OUTBOUND"},
        "status":"SUCCEEDED","amount_msat":amount,"hash":hash,"offer":offer}})
}
fn quote(id: &str, paid: u64) -> Value {
    json!({"kind":"quote","id":id,"unit":"msat","paid":paid,"issued":0,"payment_ledger":paid,"issuance_ledger":0})
}
fn encode(facts: Vec<Value>) -> Vec<u8> {
    encode_chain(facts, "regtest")
}
fn encode_chain(mut facts: Vec<Value>, chain: &str) -> Vec<u8> {
    let anchors = facts.iter().filter(|r| r["kind"]=="request" && r["fact"]["side"]=="melt")
        .map(|r|json!({"kind":"melt_quote","id":r["fact"]["id"],"unit":r["fact"]["unit"],"amount":r["fact"]["amount"],"state":r["fact"]["state"]})).collect::<Vec<_>>();
    facts.extend(anchors);
    encode_records(facts, chain)
}
fn encode_records(mut facts: Vec<Value>, chain: &str) -> Vec<u8> {
    let count = |kind| facts.iter().filter(|r| r["kind"] == kind).count();
    let end = json!({"kind":"end","conditions":0,"keysets":0,"quotes":count("quote"),"melts":count("melt_quote"),"requests":count("request"),"credits":count("credit"),"receipts":count("receipt")});
    facts.insert(0, json!({"kind":"header","version":2,"chain":chain}));
    facts.push(end);
    let mut output = Vec::new();
    for fact in facts {
        let frame = serde_json::to_vec(&fact).unwrap();
        output.extend((frame.len() as u32).to_be_bytes());
        output.extend(frame);
    }
    output.extend(0u32.to_be_bytes());
    output
}
fn incoming() -> Vec<Value> {
    let invoice = make_invoice(Some(5), 7);
    let hash = invoice.payment_hash().to_string();
    vec![
        quote("original", 9),
        mint(
            "original",
            "bolt11",
            invoice.to_string(),
            hash.clone(),
            Some(5),
        ),
        credit("credit", "original", &hash, 9),
        receipt(1, "bolt11", Some(hash), None, true, 9),
    ]
}

#[test]
fn original_expired_signed_invoice_keeps_late_overpayment_and_exact_frame_commitment() {
    let input = encode(incoming());
    let result = evaluate(Cursor::new(&input)).unwrap();
    assert_eq!(result.total_msat, 9);
    assert_eq!(result.request_complete, Some(true));
    assert!(!result.authorizing);
    assert_eq!(
        result.input_sha256,
        Some(sha256::Hash::hash(&input).to_string())
    );
    assert_eq!(result.request_counts.as_ref().unwrap().receipts, 1);
    assert!(serde_json::to_vec(&result).unwrap().len() < 65536);
}

#[test]
fn signed_invoice_lookup_method_chain_amount_and_encoding_must_bind() {
    for field in ["lookup", "method", "amount", "request"] {
        let mut facts = incoming();
        facts[1]["fact"][field] = match field {
            "amount" => json!(6),
            "method" => json!("bolt12"),
            "request" => json!("lnbcrt1invalid"),
            _ => json!("00".repeat(32)),
        };
        assert!(evaluate(Cursor::new(encode(facts))).is_err(), "{field}");
    }
    assert!(evaluate(Cursor::new(encode_chain(incoming(), "signet"))).is_err());
    let mut facts = incoming();
    let wrong = make_invoice(Some(5), 8);
    facts[1]["fact"]["request"] = json!(wrong.to_string());
    assert!(evaluate(Cursor::new(encode(facts))).is_err());
}

#[test]
fn unsupported_incoming_amountless_invoice_does_not_produce_request_complete() {
    let mut facts = incoming();
    let invoice = make_invoice(None, 7);
    facts[1]["fact"]["request"] = json!(invoice.to_string());
    facts[1]["fact"]["amount"] = Value::Null;
    assert!(evaluate(Cursor::new(encode(facts))).is_err());
}

#[test]
fn outgoing_amountless_invoice_binds_strict_options_and_actual_node_amount() {
    let invoice = make_invoice(None, 9);
    let hash = invoice.payment_hash().to_string();
    let raw = serde_json::to_string(&json!({"Bolt11":{"bolt11":invoice.to_string()}})).unwrap();
    let facts = vec![
        melt(
            "melt",
            "bolt11",
            raw,
            Some(hash.clone()),
            13,
            Some("{\"amountless\":{\"amount_msat\":13}}".to_owned()),
        ),
        receipt(2, "bolt11", Some(hash), None, false, 13),
    ];
    assert!(evaluate(Cursor::new(encode(facts.clone()))).is_ok());
    for options in [
        Value::Null,
        json!("{}"),
        json!("{\"mpp\":{\"amount\":13}}"),
        json!("{\"amountless\":{\"amount_msat\":13,\"extra\":0}}"),
        json!("{\"amountless\":{\"amount_msat\":14}}"),
    ] {
        let mut changed = facts.clone();
        changed[0]["fact"]["options"] = options;
        assert!(evaluate(Cursor::new(encode(changed))).is_err());
    }
    let mut changed = facts;
    changed[1]["fact"]["amount_msat"] = json!(14);
    assert!(evaluate(Cursor::new(encode(changed))).is_err());
}

#[test]
fn fixed_invoice_override_and_native_sat_floor_are_exact() {
    let invoice = make_invoice(Some(1500), 10);
    let hash = invoice.payment_hash().to_string();
    let mut facts = vec![
        melt(
            "m",
            "bolt11",
            invoice.to_string(),
            Some(hash.clone()),
            1,
            None,
        ),
        receipt(2, "bolt11", Some(hash), None, false, 1500),
    ];
    facts[0]["fact"]["unit"] = json!("sat");
    assert!(evaluate(Cursor::new(encode(facts.clone()))).is_ok());
    facts[0]["fact"]["options"] = json!("{\"amountless\":{\"amount_msat\":1499}}");
    assert!(evaluate(Cursor::new(encode(facts))).is_err());
}

#[test]
fn internal_melt_decodes_json_and_legacy_without_external_payment() {
    let invoice = make_invoice(Some(7), 11);
    let hash = invoice.payment_hash().to_string();
    for request in [
        invoice.to_string(),
        serde_json::to_string(&json!({"Bolt11":{"bolt11":invoice.to_string()}})).unwrap(),
    ] {
        let facts = vec![
            quote("mint", 7),
            mint("mint", "bolt11", invoice.to_string(), hash.clone(), Some(7)),
            melt("melt", "bolt11", request, Some(hash.clone()), 7, None),
            credit("c", "mint", "melt", 7),
        ];
        assert!(evaluate(Cursor::new(encode(facts.clone()))).is_ok());
        let mut changed = facts;
        let other = make_invoice(Some(7), 12);
        changed[2]["fact"]["request"] = json!(other.to_string());
        changed[2]["fact"]["lookup"] = json!(other.payment_hash().to_string());
        assert!(evaluate(Cursor::new(encode(changed))).is_err());
    }
}

#[test]
fn amountless_offer_supports_multiple_unique_receipts_and_hash_fallback() {
    let offer = offer(None);
    let id = offer.id().to_string();
    let hash = "15".repeat(32);
    let fallback = format!("{:064x}", 2);
    let facts = vec![
        quote("offer", 20),
        mint("offer", "bolt12", offer.to_string(), id.clone(), None),
        credit("c1", "offer", &hash, 7),
        credit("c2", "offer", &fallback, 13),
        receipt(1, "bolt12_offer", Some(hash), Some(id.clone()), true, 7),
        receipt(2, "bolt12_offer", None, Some(id), true, 13),
    ];
    assert!(evaluate(Cursor::new(encode(facts.clone()))).is_ok());
    let mut changed = facts;
    changed[5]["fact"]["offer"] = json!("00".repeat(32));
    assert!(evaluate(Cursor::new(encode(changed))).is_err());
}

#[test]
fn outgoing_offer_binds_offer_id_payment_id_and_fixed_or_explicit_amount() {
    for amount in [None, Some(17)] {
        let offer = offer(amount);
        let raw = serde_json::to_string(&json!({"Bolt12":{"offer":offer.to_string()}})).unwrap();
        let payment = format!("{:064x}", 3);
        let facts = vec![
            melt(
                "m",
                "bolt12",
                raw,
                Some(payment),
                17,
                amount
                    .is_none()
                    .then(|| "{\"amountless\":{\"amount_msat\":17}}".to_owned()),
            ),
            receipt(
                3,
                "bolt12_offer",
                None,
                Some(offer.id().to_string()),
                false,
                17,
            ),
        ];
        assert!(evaluate(Cursor::new(encode(facts.clone()))).is_ok());
        for field in ["id", "offer"] {
            let mut changed = facts.clone();
            changed[1]["fact"][field] = json!("00".repeat(32));
            assert!(evaluate(Cursor::new(encode(changed))).is_err());
        }
    }
}

#[test]
fn internal_amountless_offer_requires_explicit_bound_selection() {
    let offer = offer(None);
    let raw = serde_json::to_string(&json!({"Bolt12":{"offer":offer.to_string()}})).unwrap();
    let facts = vec![
        quote("mint", 19),
        mint(
            "mint",
            "bolt12",
            offer.to_string(),
            offer.id().to_string(),
            None,
        ),
        melt(
            "melt",
            "bolt12",
            raw,
            None,
            19,
            Some("{\"amountless\":{\"amount_msat\":19}}".to_owned()),
        ),
        credit("c", "mint", "melt", 19),
    ];
    assert!(evaluate(Cursor::new(encode(facts.clone()))).is_ok());
    let mut changed = facts;
    changed[2]["fact"]["options"] = Value::Null;
    assert!(evaluate(Cursor::new(encode(changed))).is_err());
}

#[test]
fn quantity_offer_and_wrong_chain_are_refused() {
    let key = SecretKey::from_slice(&[42; 32]).unwrap();
    for offer in [
        OfferBuilder::new(key.public_key(&Secp256k1::new()))
            .chain(Network::Regtest)
            .supported_quantity(Quantity::Unbounded)
            .build()
            .unwrap(),
        OfferBuilder::new(key.public_key(&Secp256k1::new()))
            .build()
            .unwrap(),
    ] {
        let facts = vec![
            quote("mint", 0),
            mint(
                "mint",
                "bolt12",
                offer.to_string(),
                offer.id().to_string(),
                None,
            ),
        ];
        assert!(evaluate(Cursor::new(encode(facts))).is_err());
    }
}

#[test]
fn missing_duplicate_orphan_and_pending_request_evidence_refuse() {
    for remove in 1..4 {
        let mut facts = incoming();
        facts.remove(remove);
        assert!(evaluate(Cursor::new(encode(facts))).is_err());
    }
    for duplicate in 1..4 {
        let mut facts = incoming();
        facts.push(facts[duplicate].clone());
        assert!(evaluate(Cursor::new(encode(facts))).is_err());
    }
    let mut facts = incoming();
    facts[3]["fact"]["status"] = json!("PENDING");
    assert!(evaluate(Cursor::new(encode(facts))).is_err());
    let mut facts = incoming();
    facts[2]["fact"]["quote"] = json!("missing");
    assert!(evaluate(Cursor::new(encode(facts))).is_err());
}

#[test]
fn request_and_receipt_frames_share_original_total_and_record_caps() {
    let input = encode(incoming());
    assert_eq!(
        evaluate_with_limits(Cursor::new(&input), input.len() - 1, 100, 100),
        Err(Refusal::Limit)
    );
    assert_eq!(
        evaluate_with_limits(Cursor::new(&input), input.len(), 5, 100),
        Err(Refusal::Limit)
    );
    assert!(evaluate_with_limits(Cursor::new(&input), input.len(), 6, 100).is_ok());
}

#[test]
fn checksum_valid_invoice_with_invalid_payee_signature_is_refused() {
    let secp = Secp256k1::new();
    let original = SecretKey::from_slice(&[30; 32]).unwrap();
    let attacker = SecretKey::from_slice(&[31; 32]).unwrap();
    let raw = InvoiceBuilder::new(Currency::Regtest)
        .description("synthetic mismatched signer".to_owned())
        .payment_hash(sha256::Hash::hash(&[7]))
        .payment_secret(PaymentSecret([7; 32]))
        .payee_pub_key(original.public_key(&secp))
        .amount_milli_satoshis(5)
        .duration_since_epoch(Duration::from_secs(1))
        .min_final_cltv_expiry_delta(18)
        .build_raw()
        .unwrap();
    let forged = raw
        .sign(|message| Ok::<_, ()>(secp.sign_ecdsa_recoverable(message, &attacker)))
        .unwrap();
    let mut facts = incoming();
    facts[1]["fact"]["request"] = json!(forged.to_string());
    assert!(evaluate(Cursor::new(encode(facts))).is_err());
}

#[test]
fn v1_serialized_result_retains_exact_value_only_shape() {
    let mut input = Vec::new();
    for record in [
        json!({"kind":"header","version":1}),
        json!({"kind":"end","conditions":0,"keysets":0,"quotes":0}),
    ] {
        let raw = serde_json::to_vec(&record).unwrap();
        input.extend((raw.len() as u32).to_be_bytes());
        input.extend(raw);
    }
    input.extend(0u32.to_be_bytes());
    let result = evaluate(Cursor::new(input)).unwrap();
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 10);
    assert!(value.get("request_complete").is_none());
    assert!(value.get("input_sha256").is_none());
}

#[test]
fn parsed_nonbitcoin_offer_is_refused_even_on_the_bound_chain() {
    // Pinned LDK's valid currency offer vector; add the same maintained regtest
    // chain TLV emitted by its builder, then parse with LDK again.
    let currency:Offer="lno1qcp4256ypqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj".parse().unwrap();
    let chain = offer(None).encode();
    assert_eq!(&chain[..2], &[2, 32]);
    let mut encoded = chain[..34].to_vec();
    encoded.extend(currency.encode());
    let currency = Offer::try_from(encoded).unwrap();
    assert!(matches!(
        currency.amount(),
        Some(OfferAmount::Currency { .. })
    ));
    let facts = vec![
        quote("mint", 0),
        mint(
            "mint",
            "bolt12",
            currency.to_string(),
            currency.id().to_string(),
            None,
        ),
    ];
    assert!(evaluate(Cursor::new(encode(facts))).is_err());
}

#[test]
fn every_retained_unpaid_melt_has_exactly_one_bound_request() {
    let invoice = make_invoice(Some(5), 24);
    let mut request = melt(
        "unpaid",
        "bolt11",
        invoice.to_string(),
        Some(invoice.payment_hash().to_string()),
        5,
        None,
    );
    request["fact"]["state"] = json!("UNPAID");
    let anchor =
        json!({"kind":"melt_quote","id":"unpaid","unit":"msat","amount":5,"state":"UNPAID"});
    let facts = vec![anchor.clone(), request.clone()];
    assert!(evaluate(Cursor::new(encode_records(facts.clone(), "regtest"))).is_ok());
    for only in [anchor, request] {
        assert!(evaluate(Cursor::new(encode_records(vec![only], "regtest"))).is_err());
    }
    for (field, value) in [
        ("id", json!("orphan")),
        ("unit", json!("sat")),
        ("amount", json!(6)),
        ("state", json!("PENDING")),
    ] {
        let mut changed = facts.clone();
        changed[0][field] = value;
        assert!(
            evaluate(Cursor::new(encode_records(changed, "regtest"))).is_err(),
            "{field}"
        );
    }
    let mut duplicated = facts;
    duplicated.push(duplicated[0].clone());
    assert!(evaluate(Cursor::new(encode_records(duplicated, "regtest"))).is_err());
}

#[test]
fn protected_mainnet_signet_and_regtest_bind_both_request_methods() {
    for (chain, currency, network) in [
        ("mainnet", Currency::Bitcoin, Network::Bitcoin),
        ("signet", Currency::Signet, Network::Signet),
        ("regtest", Currency::Regtest, Network::Regtest),
    ] {
        let invoice = make_invoice_on_chain(Some(7), 25, currency);
        let key = SecretKey::from_slice(&[26; 32]).unwrap();
        let offer = OfferBuilder::new(key.public_key(&Secp256k1::new()))
            .chain(network)
            .description("synthetic protected-network offer".to_owned())
            .amount_msats(7)
            .build()
            .unwrap();
        let facts = vec![
            quote("invoice", 0),
            quote("offer", 0),
            mint(
                "invoice",
                "bolt11",
                invoice.to_string(),
                invoice.payment_hash().to_string(),
                Some(7),
            ),
            mint(
                "offer",
                "bolt12",
                offer.to_string(),
                offer.id().to_string(),
                Some(7),
            ),
        ];
        assert!(
            evaluate(Cursor::new(encode_chain(facts.clone(), chain))).is_ok(),
            "{chain}"
        );
        for wrong in ["mainnet", "signet", "regtest"] {
            if wrong != chain {
                assert!(
                    evaluate(Cursor::new(encode_chain(facts.clone(), wrong))).is_err(),
                    "{chain}/{wrong}"
                );
            }
        }
    }
}
