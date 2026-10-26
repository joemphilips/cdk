//! Outgoing payment dispatch, finality and recovery.

use std::sync::Arc;

use cdk_common::lightning_invoice::Currency;
use cdk_common::nuts::{CurrencyUnit, MeltOptions, MeltQuoteState};
use cdk_common::payment::{MakePaymentResponse, MintPayment, PaymentIdentifier};
use cdk_common::Amount;
use serde_json::{json, Value};

use super::quote::outgoing;
use super::*;

fn is_pay(call: &Call) -> bool {
    matches!(call, Call::PayInvoice(_))
}

fn is_status(call: &Call) -> bool {
    matches!(call, Call::GetPayment(_))
}

fn assert_uncertain(response: &MakePaymentResponse, target: &TestInvoice) {
    assert!(
        matches!(
            response.status,
            MeltQuoteState::Pending | MeltQuoteState::Unknown
        ),
        "uncertain outcome returned {:?}",
        response.status
    );
    assert_eq!(response.total_spent, Amount::new(0, CurrencyUnit::Sat));
    assert_eq!(
        response.payment_lookup_id,
        PaymentIdentifier::PaymentHash(target.hash)
    );
    assert!(response.payment_proof.is_none());
}

async fn pay(lnbits: &LNbits, target: &TestInvoice, max_fee_sat: u64) -> MakePaymentResponse {
    lnbits
        .make_payment(
            &CurrencyUnit::Sat,
            outgoing(target, Some(max_fee_sat), None),
        )
        .await
        .expect("make_payment returns a response for every dispatched payment")
}

#[tokio::test]
async fn paid_reply_returns_the_verified_preimage_and_the_combined_cost() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(reply(
        201,
        &outgoing_record("pay-invoice-201-success", &target, 1_300),
    ));

    let response = pay(&lnbits, &target, 3).await;

    assert_eq!(
        transport.calls(),
        vec![Call::PayInvoice(
            json!({ "out": true, "bolt11": target.bolt11() })
        )]
    );
    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(
        response.payment_lookup_id,
        PaymentIdentifier::PaymentHash(target.hash)
    );
    assert_eq!(response.payment_proof, Some(target.preimage_hex()));
    assert_ne!(response.payment_proof, Some(target.hash_hex()));
    // 100_000 + 1_300 msat = 101.3 sat, rounded up once.
    assert_eq!(response.total_spent, Amount::new(102, CurrencyUnit::Sat));
    assert_eq!(lnbits.fee_excess_event_count(), 0);
}

#[tokio::test]
async fn pending_reply_reconciles_once_and_stays_pending() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(reply(
        201,
        &outgoing_record("pay-invoice-201-pending", &target, 2_000),
    ));
    transport.on_get_payment(reply(
        200,
        &outgoing_record("status-pending-details", &target, 2_000),
    ));

    let response = pay(&lnbits, &target, 3).await;

    assert_eq!(response.status, MeltQuoteState::Pending);
    assert_uncertain(&response, &target);
    assert_eq!(transport.count(is_pay), 1);
    assert_eq!(transport.calls()[1], Call::GetPayment(target.hash_hex()));
}

#[tokio::test]
async fn lost_reply_reconciles_through_status_without_a_second_payment_request() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);

    // The request was accepted but the reply was lost; status shows success.
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(Step::Fail(TransportError::Timeout));
    transport.on_get_payment(reply(
        200,
        &outgoing_record("status-success-details", &target, 1_000),
    ));
    let response = pay(&lnbits, &target, 3).await;
    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(response.total_spent, Amount::new(101, CurrencyUnit::Sat));
    assert_eq!(transport.count(is_pay), 1);

    // The reply was lost and the status read cannot find the record.
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(Step::Fail(TransportError::Protocol));
    transport.on_get_payment(reply(404, &fixture("status-not-found-404")));
    let response = pay(&lnbits, &target, 3).await;
    assert_eq!(response.status, MeltQuoteState::Unknown);
    assert_uncertain(&response, &target);
    assert_eq!(transport.count(is_pay), 1);

    // The status read also fails. It must not fall through to a new request.
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(Step::Fail(TransportError::Timeout));
    transport.on_get_payment(Step::Fail(TransportError::Timeout));
    let response = pay(&lnbits, &target, 3).await;
    assert_eq!(response.status, MeltQuoteState::Unknown);
    assert_eq!(transport.count(is_pay), 1);
    assert_eq!(transport.count(is_status), 1);
}

#[tokio::test]
async fn duplicate_payment_request_reconciles_the_existing_record() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);

    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(reply(520, &fixture("payment-error-520")));
    transport.on_get_payment(reply(
        200,
        &outgoing_record("status-pending-details", &target, 2_000),
    ));
    let response = pay(&lnbits, &target, 3).await;
    assert_eq!(response.status, MeltQuoteState::Pending);

    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(reply(
        520,
        &json!({ "detail": "Payment already paid.", "status": "success" }),
    ));
    transport.on_get_payment(reply(
        200,
        &outgoing_record("status-success-details", &target, 1_000),
    ));
    let response = pay(&lnbits, &target, 3).await;
    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(response.payment_proof, Some(target.preimage_hex()));
    assert_eq!(transport.count(is_pay), 1);
}

#[tokio::test]
async fn http_errors_and_provider_failure_never_become_terminal_failure() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let failed_reply = json!({ "detail": "Payment failed: no route", "status": "failed" });
    let posts = [
        raw_reply(401, br#"{"detail":"Invalid adminkey."}"#),
        raw_reply(404, b"{}"),
        raw_reply(429, b"{}"),
        raw_reply(500, b"<html></html>"),
        reply(520, &failed_reply),
        raw_reply(302, b""),
        raw_reply(201, b"{\"amount\":"),
    ];
    let statuses = || {
        vec![
            reply(200, &outgoing_record("status-failed-details", &target, 0)),
            reply(404, &fixture("status-not-found-404")),
            raw_reply(401, b"{}"),
            raw_reply(429, b"{}"),
            raw_reply(500, b"{}"),
            raw_reply(200, b"[]"),
            Step::Fail(TransportError::Timeout),
            reply(
                200,
                &outgoing_record("status-check-error-details", &target, 0),
            ),
        ]
    };
    for post in posts {
        for status in statuses() {
            let transport = FixtureTransport::new();
            let lnbits = adapter(transport.clone(), no_recovery());
            transport.on_pay_invoice(match &post {
                Step::Reply(reply) => Step::Reply(reply.clone()),
                _ => unreachable!("posts are replies"),
            });
            transport.on_get_payment(status);
            let response = pay(&lnbits, &target, 3).await;
            assert_uncertain(&response, &target);
            assert_eq!(transport.count(is_pay), 1);
        }
    }
}

#[tokio::test]
async fn success_without_required_evidence_stays_uncertain() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let other = invoice(2, Some(100_000), Currency::Bitcoin);

    let mut cases: Vec<Value> = Vec::new();
    let mut no_preimage = outgoing_record("status-success-details", &target, 1_000);
    set(&mut no_preimage, "/preimage", Value::Null);
    set(&mut no_preimage, "/details/preimage", Value::Null);
    cases.push(no_preimage);
    let mut wrong_preimage = outgoing_record("status-success-details", &target, 1_000);
    set(
        &mut wrong_preimage,
        "/preimage",
        Value::from(other.preimage_hex()),
    );
    set(
        &mut wrong_preimage,
        "/details/preimage",
        Value::from(other.preimage_hex()),
    );
    cases.push(wrong_preimage);
    let mut short_preimage = outgoing_record("status-success-details", &target, 1_000);
    set(&mut short_preimage, "/preimage", Value::from("abcd"));
    cases.push(short_preimage);
    let mut disagreeing = outgoing_record("status-success-details", &target, 1_000);
    set(
        &mut disagreeing,
        "/details/preimage",
        Value::from(other.preimage_hex()),
    );
    cases.push(disagreeing);
    let mut public = fixture("status-success-public");
    set(&mut public, "/preimage", Value::from(target.preimage_hex()));
    cases.push(public);
    let mut not_paid = outgoing_record("status-success-details", &target, 1_000);
    set(&mut not_paid, "/paid", Value::from(false));
    cases.push(not_paid);
    let mut unknown_state = outgoing_record("status-success-details", &target, 1_000);
    set(
        &mut unknown_state,
        "/details/status",
        Value::from("settled"),
    );
    cases.push(unknown_state);

    for status in cases {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), no_recovery());
        transport.on_pay_invoice(Step::Fail(TransportError::Timeout));
        transport.on_get_payment(reply(200, &status));
        let response = pay(&lnbits, &target, 3).await;
        assert_eq!(response.status, MeltQuoteState::Unknown);
        assert_uncertain(&response, &target);
    }
}

#[tokio::test]
async fn records_not_bound_to_the_invoice_stay_uncertain() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let other = invoice(2, Some(100_000), Currency::Bitcoin);

    let mut cases: Vec<Value> = Vec::new();
    cases.push(outgoing_record("status-success-details", &other, 1_000));
    let mut wrong_amount = outgoing_record("status-success-details", &target, 1_000);
    set(&mut wrong_amount, "/details/amount", Value::from(-99_000));
    cases.push(wrong_amount);
    let mut incoming = outgoing_record("status-success-details", &target, 1_000);
    set(&mut incoming, "/details/amount", Value::from(100_000));
    cases.push(incoming);
    let mut other_invoice = outgoing_record("status-success-details", &target, 1_000);
    set(
        &mut other_invoice,
        "/details/bolt11",
        Value::from(other.bolt11()),
    );
    cases.push(other_invoice);
    let mut minimum = outgoing_record("status-success-details", &target, 1_000);
    set(&mut minimum, "/details/amount", Value::from(i64::MIN));
    cases.push(minimum);
    let mut minimum_fee = outgoing_record("status-success-details", &target, 1_000);
    set(&mut minimum_fee, "/details/fee", Value::from(i64::MIN));
    cases.push(minimum_fee);

    for status in cases {
        // The payment reply carries the same unbound record.
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), no_recovery());
        let mut post = status.get("details").cloned().expect("details");
        set(&mut post, "/status", Value::from("success"));
        transport.on_pay_invoice(reply(201, &post));
        transport.on_get_payment(reply(200, &status));
        let response = pay(&lnbits, &target, 3).await;
        assert_eq!(response.status, MeltQuoteState::Unknown);
        assert_uncertain(&response, &target);
        assert_eq!(transport.count(is_pay), 1);
    }
}

#[tokio::test]
async fn payment_is_validated_before_dispatch() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let amountless = invoice(2, None, Currency::Bitcoin);
    let regtest = invoice(3, Some(100_000), Currency::Regtest);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());

    let cases = vec![
        (CurrencyUnit::Msat, outgoing(&target, Some(3), None)),
        (
            CurrencyUnit::Sat,
            outgoing(
                &target,
                Some(3),
                Some(MeltOptions::new_amountless(100_000_u64)),
            ),
        ),
        (CurrencyUnit::Sat, outgoing(&amountless, Some(3), None)),
        (CurrencyUnit::Sat, outgoing(&regtest, Some(3), None)),
        (CurrencyUnit::Sat, outgoing(&target, Some(u64::MAX), None)),
    ];
    for (unit, options) in cases {
        assert!(lnbits.make_payment(&unit, options).await.is_err());
    }
    assert!(transport.calls().is_empty());
}

#[tokio::test]
async fn fee_above_the_reserve_reports_the_actual_cost_and_emits_the_excess_event() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(reply(
        201,
        &outgoing_record("pay-invoice-201-success", &target, 5_500),
    ));

    let response = pay(&lnbits, &target, 3).await;

    assert_eq!(response.status, MeltQuoteState::Paid);
    // Actual cost: 100_000 + 5_500 msat = 105.5 sat, rounded up to 106 sat.
    // The quoted reserve was 3 sat; the adapter does not clamp to 103 sat.
    assert_eq!(response.total_spent, Amount::new(106, CurrencyUnit::Sat));
    assert_eq!(lnbits.fee_excess_event_count(), 1);
}

#[tokio::test]
async fn fee_within_the_reserve_emits_no_excess_event() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_pay_invoice(reply(
        201,
        &outgoing_record("pay-invoice-201-success", &target, 3_000),
    ));

    let response = pay(&lnbits, &target, 3).await;

    assert_eq!(response.total_spent, Amount::new(103, CurrencyUnit::Sat));
    assert_eq!(lnbits.fee_excess_event_count(), 0);
}

#[tokio::test]
async fn fee_observation_change_between_quote_and_payment_is_reported() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_fee_reserve(reply(200, &json!({ "fee_reserve": 2_000 })));
    let quote = lnbits
        .get_payment_quote(&CurrencyUnit::Sat, outgoing(&target, None, None))
        .await
        .expect("quote");
    assert_eq!(quote.fee, Amount::new(2, CurrencyUnit::Sat));

    // The provider raises its fee after the quote.
    transport.on_pay_invoice(reply(
        201,
        &outgoing_record("pay-invoice-201-success", &target, 4_000),
    ));
    let response = pay(&lnbits, &target, quote.fee.value()).await;

    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(response.total_spent, Amount::new(104, CurrencyUnit::Sat));
    assert_eq!(lnbits.fee_excess_event_count(), 1);
}

#[tokio::test]
async fn status_check_with_unique_context_returns_verified_paid_result() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), recovery_for(&target, 1_000));
    transport.on_get_payment(reply(
        200,
        &outgoing_record("status-success-details", &target, 1_500),
    ));

    let response = lnbits
        .check_outgoing_payment(&PaymentIdentifier::PaymentHash(target.hash))
        .await
        .expect("status");

    assert_eq!(transport.calls(), vec![Call::GetPayment(target.hash_hex())]);
    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(response.payment_proof, Some(target.preimage_hex()));
    assert_eq!(response.total_spent, Amount::new(102, CurrencyUnit::Sat));
    // The context reserve was 1_000 msat; the actual fee was 1_500 msat.
    assert_eq!(lnbits.fee_excess_event_count(), 1);
}

#[tokio::test]
async fn status_check_without_context_stays_unknown_and_sends_no_request() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());

    let response = lnbits
        .check_outgoing_payment(&PaymentIdentifier::PaymentHash(target.hash))
        .await
        .expect("status");

    assert_eq!(response.status, MeltQuoteState::Unknown);
    assert_uncertain(&response, &target);
    assert!(transport.calls().is_empty());
}

#[tokio::test]
async fn conflicting_or_unavailable_context_stays_unknown() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let same_hash_other_amount = invoice(1, Some(90_000), Currency::Bitcoin);
    let same_hash_regtest = invoice(1, Some(100_000), Currency::Regtest);
    let other_hash = invoice(2, Some(100_000), Currency::Bitcoin);
    let expectation = |invoice: &TestInvoice| OutgoingExpectation {
        bolt11: invoice.invoice.clone(),
        fee_reserve_msat: 1_000,
    };

    let contexts: Vec<Arc<StaticRecovery>> = vec![
        Arc::new(StaticRecovery(Ok(vec![
            expectation(&target),
            expectation(&same_hash_other_amount),
        ]))),
        Arc::new(StaticRecovery(Ok(vec![expectation(&other_hash)]))),
        Arc::new(StaticRecovery(Ok(vec![expectation(&same_hash_regtest)]))),
        Arc::new(StaticRecovery(Err(RecoveryContextError))),
    ];
    for context in contexts {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), context);
        transport.on_get_payment(reply(
            200,
            &outgoing_record("status-success-details", &target, 1_000),
        ));
        let response = lnbits
            .check_outgoing_payment(&PaymentIdentifier::PaymentHash(target.hash))
            .await
            .expect("status");
        assert_eq!(response.status, MeltQuoteState::Unknown);
        assert_uncertain(&response, &target);
        assert!(transport.calls().is_empty());
    }
}

#[tokio::test]
async fn duplicate_quotes_for_one_invoice_resolve_with_the_lowest_reserve() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let context = Arc::new(StaticRecovery(Ok(vec![
        OutgoingExpectation {
            bolt11: target.invoice.clone(),
            fee_reserve_msat: 5_000,
        },
        OutgoingExpectation {
            bolt11: target.invoice.clone(),
            fee_reserve_msat: 3_000,
        },
    ])));
    let lnbits = adapter(transport.clone(), context);
    transport.on_get_payment(reply(
        200,
        &outgoing_record("status-success-details", &target, 4_000),
    ));

    let response = lnbits
        .check_outgoing_payment(&PaymentIdentifier::PaymentHash(target.hash))
        .await
        .expect("status");

    assert_eq!(response.status, MeltQuoteState::Paid);
    assert_eq!(response.total_spent, Amount::new(104, CurrencyUnit::Sat));
    assert_eq!(lnbits.fee_excess_event_count(), 1);
}

#[tokio::test]
async fn status_check_never_returns_terminal_failure() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let steps = vec![
        (
            reply(
                200,
                &outgoing_record("status-pending-details", &target, 2_000),
            ),
            MeltQuoteState::Pending,
        ),
        (
            reply(200, &outgoing_record("status-failed-details", &target, 0)),
            MeltQuoteState::Unknown,
        ),
        (
            reply(
                200,
                &outgoing_record("status-check-error-details", &target, 0),
            ),
            MeltQuoteState::Pending,
        ),
        (
            reply(404, &fixture("status-not-found-404")),
            MeltQuoteState::Unknown,
        ),
        (raw_reply(401, b"{}"), MeltQuoteState::Unknown),
        (raw_reply(429, b"{}"), MeltQuoteState::Unknown),
        (raw_reply(500, b"{}"), MeltQuoteState::Unknown),
        (raw_reply(200, b"not json"), MeltQuoteState::Unknown),
        (Step::Fail(TransportError::Timeout), MeltQuoteState::Unknown),
        (
            Step::Fail(TransportError::BodyTooLarge),
            MeltQuoteState::Unknown,
        ),
    ];
    for (step, expected) in steps {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), recovery_for(&target, 3_000));
        transport.on_get_payment(step);
        let response = lnbits
            .check_outgoing_payment(&PaymentIdentifier::PaymentHash(target.hash))
            .await
            .expect("status");
        assert_eq!(response.status, expected);
        assert_uncertain(&response, &target);
    }
}

#[tokio::test]
async fn status_check_refuses_identifiers_that_are_not_payment_hashes() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let result = lnbits
        .check_outgoing_payment(&PaymentIdentifier::CustomId("x".to_string()))
        .await;
    assert!(result.is_err());
    assert!(transport.calls().is_empty());
}
