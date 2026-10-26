//! Melt quotes and the outgoing enablement gate.

use cdk_common::lightning_invoice::Currency;
use cdk_common::nuts::{CurrencyUnit, MeltOptions, MeltQuoteState, Mpp};
use cdk_common::payment::{
    Bolt11OutgoingPaymentOptions, CustomOutgoingPaymentOptions, MintPayment,
    OutgoingPaymentOptions, PaymentIdentifier,
};
use cdk_common::{Amount, QuoteId};
use serde_json::json;

use super::*;

pub(crate) fn outgoing(
    invoice: &TestInvoice,
    max_fee_sat: Option<u64>,
    melt_options: Option<MeltOptions>,
) -> OutgoingPaymentOptions {
    OutgoingPaymentOptions::Bolt11(Box::new(Bolt11OutgoingPaymentOptions {
        bolt11: invoice.invoice.clone(),
        max_fee_amount: max_fee_sat.map(|fee| Amount::new(fee, CurrencyUnit::Sat)),
        timeout_secs: None,
        melt_options,
        quote_id: QuoteId::new(),
    }))
}

#[tokio::test]
async fn quote_uses_the_larger_reserve_and_rounds_up_to_sat() {
    let target = invoice(1, Some(100_500), Currency::Bitcoin);
    // Policy: max(2 sat, 0.5 % of 100_500 msat = 503 msat) = 2_000 msat.
    // Observation: 2_500 msat. The quote uses 2_500 msat, so 3 sat.
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_fee_reserve(reply(200, &fixture("fee-reserve-200")));

    let quote = lnbits
        .get_payment_quote(&CurrencyUnit::Sat, outgoing(&target, None, None))
        .await
        .expect("quote");

    assert_eq!(transport.calls(), vec![Call::FeeReserve(target.bolt11())]);
    assert_eq!(
        quote.request_lookup_id,
        Some(PaymentIdentifier::PaymentHash(target.hash))
    );
    assert_eq!(quote.amount, Amount::new(101, CurrencyUnit::Sat));
    assert_eq!(quote.fee, Amount::new(3, CurrencyUnit::Sat));
    assert_eq!(quote.state, MeltQuoteState::Unpaid);

    // A smaller observation keeps the policy reserve.
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    transport.on_fee_reserve(reply(200, &json!({ "fee_reserve": 10 })));
    let quote = lnbits
        .get_payment_quote(&CurrencyUnit::Sat, outgoing(&target, None, None))
        .await
        .expect("quote");
    assert_eq!(quote.fee, Amount::new(2, CurrencyUnit::Sat));
}

#[tokio::test]
async fn quote_refuses_unsupported_requests_before_any_request() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let amountless = invoice(2, None, Currency::Bitcoin);
    let regtest = invoice(3, Some(100_000), Currency::Regtest);
    let expired = invoice_at(4, Some(100_000), Currency::Bitcoin, NOW - 7_200, 3_600);
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());

    let custom = OutgoingPaymentOptions::Custom(Box::new(CustomOutgoingPaymentOptions {
        method: "paypal".to_string(),
        request: "x".to_string(),
        amount: None,
        max_fee_amount: None,
        timeout_secs: None,
        melt_options: None,
        extra_json: None,
        quote_id: QuoteId::new(),
    }));
    let cases = vec![
        (CurrencyUnit::Msat, outgoing(&target, None, None)),
        (CurrencyUnit::Usd, outgoing(&target, None, None)),
        (
            CurrencyUnit::Sat,
            outgoing(
                &target,
                None,
                Some(MeltOptions::Mpp {
                    mpp: Mpp {
                        amount: cdk_common::Amount::from(50_000),
                    },
                }),
            ),
        ),
        (
            CurrencyUnit::Sat,
            outgoing(
                &target,
                None,
                Some(MeltOptions::new_amountless(100_000_u64)),
            ),
        ),
        (CurrencyUnit::Sat, outgoing(&amountless, None, None)),
        (CurrencyUnit::Sat, outgoing(&regtest, None, None)),
        (CurrencyUnit::Sat, outgoing(&expired, None, None)),
        (CurrencyUnit::Sat, custom),
    ];
    for (unit, options) in cases {
        assert!(lnbits.get_payment_quote(&unit, options).await.is_err());
    }
    assert!(transport.calls().is_empty());
}

#[tokio::test]
async fn disabled_outgoing_payments_refuse_quotes_and_payments_before_any_request() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    let transport = FixtureTransport::new();
    let lnbits = adapter_with(
        config(OutgoingPayments::Disabled),
        transport.clone(),
        no_recovery(),
    );

    let quote = lnbits
        .get_payment_quote(&CurrencyUnit::Sat, outgoing(&target, None, None))
        .await;
    let payment = lnbits
        .make_payment(&CurrencyUnit::Sat, outgoing(&target, Some(3), None))
        .await;

    assert!(quote.is_err());
    assert!(payment.is_err());
    assert!(transport.calls().is_empty());
}

#[tokio::test]
async fn quote_fails_closed_when_the_fee_observation_is_unusable() {
    let target = invoice(1, Some(100_000), Currency::Bitcoin);
    for step in [
        raw_reply(500, b"{}"),
        raw_reply(400, br#"{"detail":"Invoice has no amount."}"#),
        raw_reply(200, b"{}"),
        reply(200, &json!({ "fee_reserve": -1 })),
        reply(200, &json!({ "fee_reserve": "1000" })),
        Step::Fail(TransportError::Timeout),
    ] {
        let transport = FixtureTransport::new();
        let lnbits = adapter(transport.clone(), no_recovery());
        transport.on_fee_reserve(step);
        let result = lnbits
            .get_payment_quote(&CurrencyUnit::Sat, outgoing(&target, None, None))
            .await;
        assert!(result.is_err());
    }
}
