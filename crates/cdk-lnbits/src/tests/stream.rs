//! Websocket wake hints, lifecycle and cancellation.

use cdk_common::lightning_invoice::Currency;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{Event, MintPayment, PaymentIdentifier};
use cdk_common::Amount;
use futures::StreamExt;
use serde_json::Value;

use super::*;

fn hint(invoice: &TestInvoice, amount_msat: i64) -> String {
    let mut value = fixture("ws-wallet-notification");
    bind_payment(&mut value, "/payment", invoice);
    set(&mut value, "/payment/amount", Value::from(amount_msat));
    value.to_string()
}

fn received(event: Event) -> (PaymentIdentifier, Amount<CurrencyUnit>, String) {
    match event {
        Event::PaymentReceived(payment) => (
            payment.payment_identifier,
            payment.payment_amount,
            payment.payment_id,
        ),
        other => panic!("unexpected event {other:?}"),
    }
}

#[tokio::test]
async fn hint_triggers_an_authenticated_status_read_before_credit() {
    let paid = invoice(1, Some(21_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let sender = transport.on_connect();
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-success-details", &paid),
    ));

    let mut events = lnbits.wait_payment_event().await.expect("stream");
    assert!(lnbits.is_payment_event_stream_active());
    sender.send(Ok(hint(&paid, 21_000))).expect("send hint");
    let event = within(events.next()).await.expect("event");

    assert_eq!(
        received(event),
        (
            PaymentIdentifier::PaymentHash(paid.hash),
            Amount::new(21, CurrencyUnit::Sat),
            paid.hash_hex()
        )
    );
    assert_eq!(
        transport.calls(),
        vec![Call::Connect, Call::GetPayment(paid.hash_hex())]
    );
}

#[tokio::test]
async fn forged_outgoing_malformed_and_unrelated_hints_emit_no_credit() {
    let forged = invoice(1, Some(21_000), Currency::Bitcoin);
    let unrelated = invoice(2, Some(21_000), Currency::Bitcoin);
    let outgoing = invoice(3, Some(21_000), Currency::Bitcoin);
    let paid = invoice(4, Some(5_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let sender = transport.on_connect();
    // Forged hint: the authenticated record is still pending.
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-pending-details", &forged),
    ));
    // Unrelated hint: the wallet has no such payment.
    transport.on_get_payment(reply(404, &fixture("status-not-found-404")));
    // Final valid hint.
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-success-details", &paid),
    ));

    let mut events = lnbits.wait_payment_event().await.expect("stream");
    for message in [
        hint(&forged, 21_000),
        hint(&unrelated, 21_000),
        hint(&outgoing, -21_000),
        "{not json".to_string(),
        r#"{"payment":{"payment_hash":"zz","amount":1000}}"#.to_string(),
        r#"{"pending":false,"status":"success"}"#.to_string(),
        hint(&paid, 5_000),
    ] {
        sender.send(Ok(message)).expect("send hint");
    }
    let event = within(events.next()).await.expect("event");

    assert_eq!(received(event).0, PaymentIdentifier::PaymentHash(paid.hash));
    // Outgoing and malformed hints cause no status read.
    assert_eq!(
        transport.calls(),
        vec![
            Call::Connect,
            Call::GetPayment(forged.hash_hex()),
            Call::GetPayment(unrelated.hash_hex()),
            Call::GetPayment(paid.hash_hex()),
        ]
    );
}

#[tokio::test]
async fn duplicate_hints_carry_the_same_payment_id_for_mint_deduplication() {
    let paid = invoice(1, Some(21_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let sender = transport.on_connect();
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-success-details", &paid),
    ));
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-success-details", &paid),
    ));

    let mut events = lnbits.wait_payment_event().await.expect("stream");
    sender.send(Ok(hint(&paid, 21_000))).expect("send hint");
    sender.send(Ok(hint(&paid, 21_000))).expect("send hint");
    let first = received(within(events.next()).await.expect("first"));
    let second = received(within(events.next()).await.expect("second"));

    assert_eq!(first, second);
    assert_eq!(first.2, paid.hash_hex());
}

#[tokio::test]
async fn disconnect_ends_the_stream_clears_active_state_and_allows_reconnect() {
    let paid = invoice(1, Some(21_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());

    let first_sender = transport.on_connect();
    let mut first = lnbits.wait_payment_event().await.expect("first stream");
    assert!(lnbits.is_payment_event_stream_active());
    // A second subscription is refused while one is active.
    assert!(lnbits.wait_payment_event().await.is_err());
    drop(first_sender);
    assert!(within(first.next()).await.is_none());
    assert!(!lnbits.is_payment_event_stream_active());

    // A transport error also ends the stream.
    let second_sender = transport.on_connect();
    let mut second = lnbits.wait_payment_event().await.expect("second stream");
    second_sender
        .send(Err(TransportError::Protocol))
        .expect("send error");
    assert!(within(second.next()).await.is_none());
    assert!(!lnbits.is_payment_event_stream_active());

    // A payment made while disconnected is found by the next status check.
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-success-details", &paid),
    ));
    let missed = lnbits
        .check_incoming_payment_status(&PaymentIdentifier::PaymentHash(paid.hash))
        .await
        .expect("status");
    assert_eq!(missed.len(), 1);

    let third_sender = transport.on_connect();
    let mut third = lnbits.wait_payment_event().await.expect("third stream");
    transport.on_get_payment(reply(
        200,
        &incoming_record("status-success-details", &paid),
    ));
    third_sender
        .send(Ok(hint(&paid, 21_000)))
        .expect("send hint");
    assert!(within(third.next()).await.is_some());
}

#[tokio::test]
async fn connect_failure_leaves_the_stream_inactive() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_connect_failure(TransportError::Connect);

    assert!(lnbits.wait_payment_event().await.is_err());
    assert!(!lnbits.is_payment_event_stream_active());
}

#[tokio::test]
async fn cancellation_terminates_the_stream_and_its_in_flight_status_read() {
    let paid = invoice(1, Some(21_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let sender = transport.on_connect();
    let (started_sender, started) = oneshot::channel();
    let (release, release_receiver) = oneshot::channel();
    transport.on_get_payment(Step::Gate {
        started: started_sender,
        release: release_receiver,
    });

    let mut events = lnbits.wait_payment_event().await.expect("stream");
    sender.send(Ok(hint(&paid, 21_000))).expect("send hint");
    let next = tokio::spawn(async move {
        let event = events.next().await;
        (event.is_none(), events)
    });
    within(started).await.expect("status read started");

    lnbits.cancel_payment_event_stream();
    let (ended, _events) = within(next).await.expect("stream task");

    assert!(ended);
    assert!(!lnbits.is_payment_event_stream_active());
    // The owned status read was dropped, so its release channel is closed.
    assert!(release.is_closed());
    // A cancelled backend refuses a new subscription.
    assert!(lnbits.wait_payment_event().await.is_err());
}

#[tokio::test]
async fn stop_cancels_the_stream() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let _sender = transport.on_connect();
    let mut events = lnbits.wait_payment_event().await.expect("stream");

    lnbits.stop().await.expect("stop");

    assert!(within(events.next()).await.is_none());
    assert!(!lnbits.is_payment_event_stream_active());
}
