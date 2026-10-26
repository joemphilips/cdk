//! Secret-safe errors and logs.

use std::io::Write;
use std::sync::{Arc, Mutex};

use cdk_common::lightning_invoice::Currency;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{
    Bolt11IncomingPaymentOptions, IncomingPaymentOptions, MintPayment, PaymentIdentifier,
};
use cdk_common::Amount;
use serde_json::json;

use super::quote::outgoing;
use super::*;

/// Canary placed in provider bodies. It must never reach a log or an error.
const BODY_CANARY: &str = "BODYcanaryDETAIL";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn assert_clean(text: &str, secrets: &[String]) {
    for secret in secrets {
        assert!(
            !text.contains(secret.as_str()),
            "secret leaked into: {text}"
        );
    }
}

#[tokio::test]
async fn logs_and_errors_never_contain_keys_bodies_preimages_or_invoices() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    // With one scoped subscriber as the only registered dispatcher, a callsite
    // that another test thread registers caches that thread's empty interest
    // and never reaches this capture. A second registered dispatcher makes
    // every thread compute interest from all dispatchers.
    let _ = tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::default());
    let _guard = tracing::subscriber::set_default(subscriber);

    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let incoming = invoice(2, Some(21_000), Currency::Bitcoin);
    let secrets = vec![
        ADMIN_KEY.to_string(),
        INVOICE_KEY.to_string(),
        BODY_CANARY.to_string(),
        target.preimage_hex(),
        target.bolt11(),
        incoming.preimage_hex(),
        incoming.bolt11(),
    ];
    let mut errors = Vec::new();

    // Payment with an error reply, then a paid status above the reserve.
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), recovery_for(&target, 1_000));
    transport.on_pay_invoice(reply(
        520,
        &json!({ "detail": BODY_CANARY, "status": "failed" }),
    ));
    transport.on_get_payment(reply(
        200,
        &outgoing_record("status-success-details", &target, 5_000),
    ));
    let paid = lnbits
        .make_payment(&CurrencyUnit::Sat, outgoing(&target, Some(1), None))
        .await
        .expect("payment");
    assert_eq!(lnbits.fee_excess_event_count(), 1);
    // The proof is returned to the mint, but it is never logged.
    assert_eq!(paid.payment_proof, Some(target.preimage_hex()));
    assert!(!format!("{paid:?}").contains(&target.preimage_hex()));

    // Uncertain status, provider error text and malformed bodies.
    transport.on_get_payment(raw_reply(500, BODY_CANARY.as_bytes()));
    lnbits
        .check_outgoing_payment(&PaymentIdentifier::PaymentHash(target.hash))
        .await
        .expect("status");
    transport.on_get_payment(raw_reply(200, BODY_CANARY.as_bytes()));
    errors.push(
        lnbits
            .check_incoming_payment_status(&PaymentIdentifier::PaymentHash(incoming.hash))
            .await
            .expect_err("malformed")
            .to_string(),
    );
    transport.on_create_invoice(raw_reply(401, BODY_CANARY.as_bytes()));
    errors.push(
        lnbits
            .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
                Bolt11IncomingPaymentOptions {
                    description: None,
                    amount: Amount::new(21, CurrencyUnit::Sat),
                    unix_expiry: None,
                },
            ))
            .await
            .expect_err("unauthorized")
            .to_string(),
    );
    transport.on_fee_reserve(raw_reply(400, BODY_CANARY.as_bytes()));
    errors.push(
        lnbits
            .get_payment_quote(&CurrencyUnit::Sat, outgoing(&target, None, None))
            .await
            .expect_err("observation refused")
            .to_string(),
    );

    let logs = String::from_utf8(capture.0.lock().expect("lock").clone()).expect("UTF-8");
    assert!(logs.contains("lnbits_fee_above_reserve"));
    assert!(logs.contains("excess_msat=4000"));
    assert_clean(&logs, &secrets);
    for error in errors {
        assert_clean(&error, &secrets);
    }
}
