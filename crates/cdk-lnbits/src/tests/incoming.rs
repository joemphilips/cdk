//! Incoming invoices and incoming status checks.

use cdk_common::lightning_invoice::Currency;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{
    Bolt11IncomingPaymentOptions, IncomingPaymentOptions, MintPayment,
    OnchainIncomingPaymentOptions, PaymentIdentifier,
};
use cdk_common::{Amount, QuoteId};
use serde_json::{json, Value};

use super::*;

fn bolt11_options(
    amount: Amount<CurrencyUnit>,
    unix_expiry: Option<u64>,
) -> IncomingPaymentOptions {
    IncomingPaymentOptions::Bolt11(Bolt11IncomingPaymentOptions {
        description: Some("mint quote".to_string()),
        amount,
        unix_expiry,
    })
}

fn created_reply(invoice: &TestInvoice) -> Value {
    let mut value = fixture("create-invoice-201");
    bind_payment(&mut value, "", invoice);
    let amount = invoice.invoice.amount_milli_satoshis().expect("amount") as i64;
    set(&mut value, "/amount", Value::from(amount));
    value
}

#[tokio::test]
async fn create_invoice_sends_integer_sat_and_returns_verified_lookup_hash() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let expected = invoice(1, Some(21_000), Currency::Bitcoin);
    transport.on_create_invoice(reply(201, &created_reply(&expected)));

    let response = lnbits
        .create_incoming_payment_request(bolt11_options(
            Amount::new(21, CurrencyUnit::Sat),
            Some(NOW + 3_600),
        ))
        .await
        .expect("invoice");

    assert_eq!(
        transport.calls(),
        vec![Call::CreateInvoice(json!({
            "out": false,
            "amount": 21,
            "unit": "sat",
            "memo": "mint quote",
            "expiry": 3_600,
        }))]
    );
    assert_eq!(
        response.request_lookup_id,
        PaymentIdentifier::PaymentHash(expected.hash)
    );
    assert_eq!(response.request, expected.bolt11());
    // The fixture invoice was signed at NOW with a 3_600 second expiry.
    assert_eq!(response.expiry, Some(NOW + 3_600));
}

#[tokio::test]
async fn create_invoice_refuses_unsupported_input_before_any_request() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());

    let cases = vec![
        bolt11_options(Amount::new(0, CurrencyUnit::Sat), None),
        bolt11_options(Amount::new(21_000, CurrencyUnit::Msat), None),
        bolt11_options(Amount::new(21, CurrencyUnit::Usd), None),
        bolt11_options(Amount::new(u64::MAX, CurrencyUnit::Sat), None),
        bolt11_options(
            Amount::new(i64::MAX as u64 / 1_000 + 1, CurrencyUnit::Sat),
            None,
        ),
        bolt11_options(Amount::new(21, CurrencyUnit::Sat), Some(NOW)),
        bolt11_options(Amount::new(21, CurrencyUnit::Sat), Some(NOW - 1)),
        IncomingPaymentOptions::Bolt11(Bolt11IncomingPaymentOptions {
            description: Some("x".repeat(641)),
            amount: Amount::new(21, CurrencyUnit::Sat),
            unix_expiry: None,
        }),
        IncomingPaymentOptions::Onchain(OnchainIncomingPaymentOptions {
            quote_id: QuoteId::new(),
        }),
    ];
    for options in cases {
        assert!(lnbits
            .create_incoming_payment_request(options)
            .await
            .is_err());
    }
    assert!(transport.calls().is_empty());
}

#[tokio::test]
async fn create_invoice_rejects_a_reply_that_does_not_match_the_request() {
    let requested = invoice(1, Some(21_000), Currency::Bitcoin);
    let wrong_amount = invoice(2, Some(22_000), Currency::Bitcoin);
    let wrong_network = invoice(3, Some(21_000), Currency::Regtest);
    let late_expiry = invoice_at(4, Some(21_000), Currency::Bitcoin, NOW, 7_200);
    let expired = invoice_at(5, Some(21_000), Currency::Bitcoin, NOW - 7_200, 3_600);
    let other = invoice(6, Some(21_000), Currency::Bitcoin);

    let mut replies = vec![
        created_reply(&wrong_amount),
        created_reply(&wrong_network),
        created_reply(&late_expiry),
        created_reply(&expired),
    ];
    // Reply hash differs from the signed invoice hash.
    let mut hash_mismatch = created_reply(&requested);
    set(
        &mut hash_mismatch,
        "/payment_hash",
        Value::from(other.hash_hex()),
    );
    replies.push(hash_mismatch);
    // Reply amount differs from the signed invoice amount.
    let mut record_amount = created_reply(&requested);
    set(&mut record_amount, "/amount", Value::from(20_000));
    replies.push(record_amount);
    // An outgoing record is not an incoming invoice.
    let mut outgoing = created_reply(&requested);
    set(&mut outgoing, "/amount", Value::from(-21_000));
    replies.push(outgoing);
    // The signature does not verify after one character changes.
    let mut tampered = created_reply(&requested);
    let mut text = requested.bolt11();
    let last = text.pop().expect("character");
    text.push(if last == 'q' { 'p' } else { 'q' });
    set(&mut tampered, "/bolt11", Value::from(text));
    replies.push(tampered);

    for value in replies {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), no_recovery());
        transport.on_create_invoice(reply(201, &value));
        let result = lnbits
            .create_incoming_payment_request(bolt11_options(
                Amount::new(21, CurrencyUnit::Sat),
                Some(NOW + 3_600),
            ))
            .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn create_invoice_maps_provider_errors_without_retry() {
    for step in [
        raw_reply(401, br#"{"detail":"Invalid key"}"#),
        raw_reply(429, b"slow down"),
        raw_reply(500, b"<html>error</html>"),
        raw_reply(201, b"not json"),
        Step::Fail(TransportError::Timeout),
    ] {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), no_recovery());
        transport.on_create_invoice(step);
        let result = lnbits
            .create_incoming_payment_request(bolt11_options(
                Amount::new(21, CurrencyUnit::Sat),
                None,
            ))
            .await;
        assert!(result.is_err());
        assert_eq!(transport.calls().len(), 1);
    }
}

#[tokio::test]
async fn incoming_status_credits_only_a_verified_paid_record_rounded_down() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let paid = invoice(1, Some(1_500), Currency::Bitcoin);
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-success-details", &paid),
    ));

    let payments = lnbits
        .check_incoming_payment_status(&PaymentIdentifier::PaymentHash(paid.hash))
        .await
        .expect("status");

    assert_eq!(transport.calls(), vec![Call::GetPayment(paid.hash_hex())]);
    assert_eq!(payments.len(), 1);
    assert_eq!(
        payments[0].payment_identifier,
        PaymentIdentifier::PaymentHash(paid.hash)
    );
    assert_eq!(
        payments[0].payment_amount,
        Amount::new(1, CurrencyUnit::Sat)
    );
    assert_eq!(payments[0].payment_id, paid.hash_hex());
}

#[tokio::test]
async fn incoming_status_returns_no_credit_for_pending_or_failed_records() {
    let pending = invoice(1, Some(21_000), Currency::Bitcoin);
    for name in [
        "status-pending-details",
        "status-failed-details",
        "status-check-error-details",
    ] {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), no_recovery());
        transport.on_get_payment(reply(200, &incoming_record(name, &pending)));
        let payments = lnbits
            .check_incoming_payment_status(&PaymentIdentifier::PaymentHash(pending.hash))
            .await
            .expect("status");
        assert!(payments.is_empty(), "{name} must not credit");
    }
}

#[tokio::test]
async fn incoming_status_rejects_records_that_are_not_bound_to_the_request() {
    let requested = invoice(1, Some(21_000), Currency::Bitcoin);
    let other = invoice(2, Some(21_000), Currency::Bitcoin);
    // Same preimage, so the same hash, on another network.
    let regtest = invoice(1, Some(21_000), Currency::Regtest);

    let mut cases: Vec<Step> = Vec::new();
    // Public reply without wallet details.
    let mut public = fixture("status-success-public");
    set(
        &mut public,
        "/preimage",
        Value::from(requested.preimage_hex()),
    );
    cases.push(reply(200, &public));
    // Record for another hash.
    cases.push(reply(
        200,
        &incoming_record("status-success-details", &other),
    ));
    // Outgoing record for the requested hash.
    cases.push(reply(
        200,
        &outgoing_record("status-success-details", &requested, 0),
    ));
    // Record amount differs from the invoice amount.
    let mut amount = incoming_record("status-success-details", &requested);
    set(&mut amount, "/details/amount", Value::from(22_000));
    cases.push(reply(200, &amount));
    // Signed minimum amount.
    let mut minimum = incoming_record("status-success-details", &requested);
    set(&mut minimum, "/details/amount", Value::from(i64::MIN));
    cases.push(reply(200, &minimum));
    // Paid flag without a success state.
    let mut inconsistent = incoming_record("status-pending-details", &requested);
    set(&mut inconsistent, "/paid", Value::from(true));
    cases.push(reply(200, &inconsistent));
    // Invoice on another network with the requested hash.
    cases.push(reply(
        200,
        &incoming_record("status-success-details", &regtest),
    ));
    // Unknown hash, provider errors, malformed body and transport failure.
    cases.push(reply(404, &fixture("status-not-found-404")));
    cases.push(raw_reply(401, b"{}"));
    cases.push(raw_reply(429, b"{}"));
    cases.push(raw_reply(500, b"{}"));
    cases.push(raw_reply(200, b"{\"paid\":"));
    cases.push(Step::Fail(TransportError::Connect));

    for step in cases {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), no_recovery());
        transport.on_get_payment(step);
        let result = lnbits
            .check_incoming_payment_status(&PaymentIdentifier::PaymentHash(requested.hash))
            .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn incoming_status_refuses_identifiers_that_are_not_payment_hashes() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let result = lnbits
        .check_incoming_payment_status(&PaymentIdentifier::CustomId("x".to_string()))
        .await;
    assert!(result.is_err());
    assert!(transport.calls().is_empty());
}
