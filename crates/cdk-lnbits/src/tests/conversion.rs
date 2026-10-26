//! Settings, amount conversion and rounding.

use cdk_common::lightning_invoice::Currency;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::unit_converter::MsatSatConverter;
use cdk_common::payment::{
    Bolt11IncomingPaymentOptions, Bolt11OutgoingPaymentOptions, IncomingPaymentOptions,
    MintPayment, OutgoingPaymentOptions,
};
use cdk_common::{Amount, QuoteId};
use serde_json::{json, Value};

use super::*;
use crate::amount::{
    msat_to_sat_ceil, msat_to_sat_floor, outgoing_total_sat, policy_reserve_msat,
    provider_abs_msat, sat_to_msat,
};

#[tokio::test]
async fn settings_advertise_native_sat_bolt11_only() {
    let lnbits = adapter(FixtureTransport::new(), no_recovery());
    let settings = lnbits.get_settings().await.expect("settings");

    assert_eq!(settings.unit, "sat");
    let bolt11 = settings.bolt11.expect("bolt11 settings");
    assert!(!bolt11.mpp);
    assert!(!bolt11.amountless);
    assert!(settings.bolt12.is_none());
    assert!(settings.onchain.is_none());
    assert!(settings.custom.is_empty());
}

#[test]
fn incoming_credit_rounds_msat_down() {
    assert_eq!(msat_to_sat_floor(0), 0);
    assert_eq!(msat_to_sat_floor(999), 0);
    assert_eq!(msat_to_sat_floor(1_999), 1);
    assert_eq!(msat_to_sat_floor(2_000), 2);
}

#[test]
fn outgoing_cost_rounds_the_combined_total_up_once() {
    // 1_000_400 msat principal plus 300 msat fee is 1_000_700 msat, so 1_001
    // sat. Rounding each part first would give 1_001 + 1 = 1_002 sat.
    assert_eq!(outgoing_total_sat(1_000_400, 300).expect("total"), 1_001);
    assert_eq!(outgoing_total_sat(1_000_000, 0).expect("total"), 1_000);
    assert_eq!(outgoing_total_sat(1_000_000, 1).expect("total"), 1_001);
    assert_eq!(msat_to_sat_ceil(1), 1);
    assert!(outgoing_total_sat(u64::MAX, 1).is_err());
}

#[test]
fn signed_provider_amounts_use_checked_absolute_values() {
    assert_eq!(provider_abs_msat(-5).expect("abs"), 5);
    assert_eq!(provider_abs_msat(7).expect("abs"), 7);
    assert_eq!(provider_abs_msat(i64::MAX).expect("abs"), i64::MAX as u64);
    assert!(provider_abs_msat(i64::MIN).is_err());
}

#[test]
fn sat_to_msat_refuses_overflow_and_unstorable_values() {
    assert_eq!(sat_to_msat(21).expect("msat"), 21_000);
    assert!(sat_to_msat(u64::MAX).is_err());
    let largest_storable_sat = i64::MAX as u64 / 1_000;
    assert!(sat_to_msat(largest_storable_sat).is_ok());
    assert!(sat_to_msat(largest_storable_sat + 1).is_err());
}

#[test]
fn policy_reserve_uses_checked_rounded_up_ppm_and_minimum() {
    let policy = FeePolicy {
        min_fee_reserve_sat: 2,
        fee_reserve_ppm: 5_000,
    };
    // 0.5 % of 100_000 msat is 500 msat; the 2 sat minimum is larger.
    assert_eq!(
        policy_reserve_msat(&policy, 100_000).expect("reserve"),
        2_000
    );
    // 0.5 % of 1_000_001 msat is 5_000.005 msat, rounded up to 5_001.
    assert_eq!(
        policy_reserve_msat(&policy, 1_000_001).expect("reserve"),
        5_001
    );
    let unbounded = FeePolicy {
        min_fee_reserve_sat: 0,
        fee_reserve_ppm: u32::MAX,
    };
    assert!(policy_reserve_msat(&unbounded, u64::MAX).is_err());
    let huge_minimum = FeePolicy {
        min_fee_reserve_sat: u64::MAX,
        fee_reserve_ppm: 0,
    };
    assert!(policy_reserve_msat(&huge_minimum, 1).is_err());
}

/// The msat facade owns rounding for msat quotes backed by this sat adapter.
/// This records the existing shared converter behavior: an msat invoice
/// request rounds up to whole sat, and an msat melt quote is the rounded-up
/// sat quote expressed in msat.
#[tokio::test]
async fn msat_quotes_use_the_shared_converter_rounding() {
    let transport = FixtureTransport::new();
    let lnbits = adapter(transport.clone(), no_recovery());
    let msat_backend = MsatSatConverter::new(lnbits);

    let created = invoice(9, Some(2_000), Currency::Bitcoin);
    let mut created_reply = fixture("create-invoice-201");
    bind_payment(&mut created_reply, "", &created);
    set(&mut created_reply, "/amount", Value::from(2_000));
    transport.on_create_invoice(reply(201, &created_reply));
    msat_backend
        .create_incoming_payment_request(IncomingPaymentOptions::Bolt11(
            Bolt11IncomingPaymentOptions {
                description: None,
                amount: Amount::new(1_500, CurrencyUnit::Msat),
                unix_expiry: None,
            },
        ))
        .await
        .expect("msat invoice through the shared converter");

    let paid = invoice(10, Some(1_500), Currency::Bitcoin);
    transport.on_fee_reserve(reply(200, &json!({ "fee_reserve": 0 })));
    let quote = msat_backend
        .get_payment_quote(
            &CurrencyUnit::Msat,
            OutgoingPaymentOptions::Bolt11(Box::new(Bolt11OutgoingPaymentOptions {
                bolt11: paid.invoice.clone(),
                max_fee_amount: None,
                timeout_secs: None,
                melt_options: None,
                quote_id: QuoteId::new(),
            })),
        )
        .await
        .expect("msat quote through the shared converter");

    assert_eq!(
        transport.calls()[0],
        Call::CreateInvoice(json!({ "out": false, "amount": 2, "unit": "sat" }))
    );
    assert_eq!(quote.amount, Amount::new(2_000, CurrencyUnit::Msat));
    assert_eq!(quote.fee, Amount::new(2_000, CurrencyUnit::Msat));
}
