//! Melt quotes, payment dispatch and outgoing finality.
//!
//! `Unpaid` and `Failed` let the mint release reserved proofs. Under the
//! pinned profile no provider state excludes a later success, so this module
//! never returns them. Every outcome that is not a verified payment is
//! `Pending` or `Unknown`.

use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use cdk_common::nuts::{CurrencyUnit, MeltOptions, MeltQuoteState};
use cdk_common::payment::{
    Bolt11OutgoingPaymentOptions, MakePaymentResponse, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse,
};
use cdk_common::util::hex;
use cdk_common::{Amount, Bolt11Invoice};

use crate::amount::{
    msat_to_sat_ceil, outgoing_total_sat, policy_reserve_msat, provider_abs_msat, sat_to_msat,
};
use crate::api::{
    parse_hex32, parse_json, PayInvoiceBody, ProviderState, WireFeeReserve, WirePayment,
    WireStatus, STATUS_CREATED, STATUS_OK,
};
use crate::config::OutgoingPayments;
use crate::error::Error;
use crate::recovery::{resolve, Expected, Resolution};
use crate::LNbits;

/// Result of checking one provider record against the expected payment.
enum Evaluation {
    Paid {
        preimage: [u8; 32],
        fee_msat: u64,
        total_sat: u64,
    },
    Pending,
    Uncertain(&'static str),
}

impl LNbits {
    pub(crate) async fn quote_outgoing(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Error> {
        self.ensure_outgoing_enabled()?;
        ensure_sat(unit)?;
        let options = bolt11_outgoing(options)?;
        let (payment_hash, amount_msat) =
            self.validate_outgoing_invoice(&options.bolt11, options.melt_options.as_ref())?;
        if options
            .bolt11
            .would_expire(Duration::from_secs((self.now)()))
        {
            return Err(Error::InvalidInvoice("invoice is expired"));
        }

        let observed_msat = self
            .observe_fee_reserve(&payment_hash, &options.bolt11.to_string())
            .await?;
        let reserve_msat =
            policy_reserve_msat(&self.policy.fee_policy, amount_msat)?.max(observed_msat);

        Ok(PaymentQuoteResponse {
            request_lookup_id: Some(PaymentIdentifier::PaymentHash(payment_hash)),
            amount: Amount::new(msat_to_sat_ceil(amount_msat), CurrencyUnit::Sat),
            fee: Amount::new(msat_to_sat_ceil(reserve_msat), CurrencyUnit::Sat),
            state: MeltQuoteState::Unpaid,
            extra_json: None,
            estimated_blocks: None,
            fee_options: None,
        })
    }

    pub(crate) async fn pay_outgoing(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Error> {
        self.ensure_outgoing_enabled()?;
        ensure_sat(unit)?;
        let options = bolt11_outgoing(options)?;
        let (payment_hash, amount_msat) =
            self.validate_outgoing_invoice(&options.bolt11, options.melt_options.as_ref())?;
        let fee_reserve_msat = match &options.max_fee_amount {
            Some(fee) => {
                ensure_sat(fee.unit())?;
                sat_to_msat(fee.value())?
            }
            None => 0,
        };
        let expected = Expected {
            payment_hash,
            bolt11: options.bolt11.to_string(),
            amount_msat,
            fee_reserve_msat,
        };
        let body = serde_json::to_vec(&PayInvoiceBody {
            out: true,
            bolt11: &expected.bolt11,
        })
        .map_err(|_| Error::InvalidInvoice("invoice cannot be encoded"))?;
        let hash_hex = hex::encode(payment_hash);

        // The payment request is sent once. Every reply other than a bound,
        // verified success is reconciled through one status read. A failed
        // status read never leads to another payment request.
        tracing::info!(payment_hash = %hash_hex, "sending LNbits payment request");
        match self.transport.pay_invoice(body).await {
            Ok(reply) if reply.status == STATUS_CREATED => {
                match parse_json::<WirePayment>(&reply.body) {
                    Ok(record) => {
                        let evaluation =
                            evaluate(&expected, &record, true, record.preimage.as_deref(), None);
                        match evaluation {
                            Evaluation::Paid {
                                preimage,
                                fee_msat,
                                total_sat,
                            } => return Ok(self.paid(&expected, preimage, fee_msat, total_sat)),
                            Evaluation::Pending | Evaluation::Uncertain(_) => {
                                tracing::info!(
                                    payment_hash = %hash_hex,
                                    "LNbits payment reply is not final; reading status"
                                );
                            }
                        }
                    }
                    Err(_) => tracing::warn!(
                        payment_hash = %hash_hex,
                        "LNbits payment reply is malformed; reading status"
                    ),
                }
            }
            Ok(reply) => tracing::warn!(
                payment_hash = %hash_hex,
                http_status = reply.status,
                "LNbits payment request was not accepted as final; reading status"
            ),
            Err(error) => tracing::warn!(
                payment_hash = %hash_hex,
                transport_error = %error,
                "LNbits payment reply was not received; reading status"
            ),
        }

        Ok(self.reconcile_outgoing(&expected).await)
    }

    pub(crate) async fn check_outgoing(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Error> {
        let payment_hash = expect_payment_hash(payment_identifier)?;
        let hash_hex = hex::encode(payment_hash);
        let resolution = match self.recovery.expectations(&payment_hash).await {
            Ok(expectations) => resolve(&payment_hash, self.policy.network, &expectations),
            Err(_) => {
                tracing::warn!(
                    payment_hash = %hash_hex,
                    "recovery context is unavailable; the payment stays unknown"
                );
                return Ok(uncertain(payment_hash, MeltQuoteState::Unknown));
            }
        };
        match resolution {
            Resolution::Unique(expected) => Ok(self.reconcile_outgoing(&expected).await),
            Resolution::Absent => {
                tracing::warn!(
                    payment_hash = %hash_hex,
                    "no durable melt quote matches this payment; the payment stays unknown"
                );
                Ok(uncertain(payment_hash, MeltQuoteState::Unknown))
            }
            Resolution::Conflicting => {
                tracing::warn!(
                    payment_hash = %hash_hex,
                    "durable melt quotes disagree for this payment; the payment stays unknown"
                );
                Ok(uncertain(payment_hash, MeltQuoteState::Unknown))
            }
        }
    }

    /// Read the authenticated status once and bind it to `expected`.
    async fn reconcile_outgoing(&self, expected: &Expected) -> MakePaymentResponse {
        let hash_hex = hex::encode(expected.payment_hash);
        let unknown = || uncertain(expected.payment_hash, MeltQuoteState::Unknown);
        let reply = match self.transport.get_payment(&hash_hex).await {
            Ok(reply) => reply,
            Err(error) => {
                tracing::warn!(
                    payment_hash = %hash_hex,
                    transport_error = %error,
                    "LNbits status read failed; the payment stays unknown"
                );
                return unknown();
            }
        };
        if reply.status != STATUS_OK {
            tracing::warn!(
                payment_hash = %hash_hex,
                http_status = reply.status,
                "LNbits status read was refused; the payment stays unknown"
            );
            return unknown();
        }
        let status: WireStatus = match parse_json(&reply.body) {
            Ok(status) => status,
            Err(_) => {
                tracing::warn!(
                    payment_hash = %hash_hex,
                    "LNbits status reply is malformed; the payment stays unknown"
                );
                return unknown();
            }
        };
        let Some(record) = status.details.as_ref() else {
            tracing::warn!(
                payment_hash = %hash_hex,
                "LNbits status reply has no wallet details; the payment stays unknown"
            );
            return unknown();
        };
        match evaluate(
            expected,
            record,
            status.paid,
            status.preimage.as_deref(),
            record.preimage.as_deref(),
        ) {
            Evaluation::Paid {
                preimage,
                fee_msat,
                total_sat,
            } => self.paid(expected, preimage, fee_msat, total_sat),
            Evaluation::Pending => uncertain(expected.payment_hash, MeltQuoteState::Pending),
            Evaluation::Uncertain(reason) => {
                tracing::warn!(
                    payment_hash = %hash_hex,
                    reason,
                    "LNbits status is not verified evidence; the payment stays unknown"
                );
                unknown()
            }
        }
    }

    fn paid(
        &self,
        expected: &Expected,
        preimage: [u8; 32],
        fee_msat: u64,
        total_sat: u64,
    ) -> MakePaymentResponse {
        if fee_msat > expected.fee_reserve_msat {
            self.record_fee_excess(expected, fee_msat);
        }
        MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::PaymentHash(expected.payment_hash),
            payment_proof: Some(hex::encode(preimage)),
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(total_sat, CurrencyUnit::Sat),
        }
    }

    /// Record a paid fee above the quoted reserve. The reported cost is not
    /// changed; the mint pays the excess.
    fn record_fee_excess(&self, expected: &Expected, fee_msat: u64) {
        let excess_msat = fee_msat.saturating_sub(expected.fee_reserve_msat);
        self.fee_excess_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(
            target: "cdk_lnbits::fee_excess",
            event = "lnbits_fee_above_reserve",
            payment_hash = %hex::encode(expected.payment_hash),
            fee_reserve_msat = expected.fee_reserve_msat,
            actual_fee_msat = fee_msat,
            excess_msat,
            "LNbits fee exceeded the quoted reserve; the mint pays the excess"
        );
    }

    async fn observe_fee_reserve(
        &self,
        payment_hash: &[u8; 32],
        bolt11: &str,
    ) -> Result<u64, Error> {
        let hash_hex = hex::encode(payment_hash);
        let reply = self
            .transport
            .get_fee_reserve(bolt11)
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    payment_hash = %hash_hex,
                    transport_error = %error,
                    "LNbits fee reserve observation failed"
                );
            })?;
        if reply.status != STATUS_OK {
            tracing::warn!(
                payment_hash = %hash_hex,
                http_status = reply.status,
                "LNbits fee reserve observation was refused"
            );
            return Err(Error::ProviderStatus(reply.status));
        }
        let observation: WireFeeReserve = parse_json(&reply.body)?;
        u64::try_from(observation.fee_reserve).map_err(|_| Error::MalformedResponse)
    }

    fn ensure_outgoing_enabled(&self) -> Result<(), Error> {
        match self.policy.outgoing {
            OutgoingPayments::MintPaysFeeAboveReserve => Ok(()),
            OutgoingPayments::Disabled => Err(Error::OutgoingDisabled),
        }
    }

    /// Validate an outgoing invoice before any request. Returns the payment
    /// hash and the principal in msat.
    fn validate_outgoing_invoice(
        &self,
        invoice: &Bolt11Invoice,
        melt_options: Option<&MeltOptions>,
    ) -> Result<([u8; 32], u64), Error> {
        if melt_options.is_some() {
            return Err(Error::UnsupportedPaymentOption);
        }
        if invoice.network() != self.policy.network {
            return Err(Error::InvalidInvoice("invoice uses another network"));
        }
        let amount_msat = invoice
            .amount_milli_satoshis()
            .filter(|amount| *amount > 0)
            .ok_or(Error::InvalidInvoice("invoice has no amount"))?;
        if i64::try_from(amount_msat).is_err() {
            return Err(Error::AmountOverflow);
        }
        Ok((invoice.payment_hash().to_byte_array(), amount_msat))
    }
}

/// Check one provider record against the expected payment.
///
/// `preimage` is the primary preimage field. `other_preimage`, when present,
/// must agree with it.
fn evaluate(
    expected: &Expected,
    record: &WirePayment,
    paid: bool,
    preimage: Option<&str>,
    other_preimage: Option<&str>,
) -> Evaluation {
    if parse_hex32(&record.payment_hash) != Some(expected.payment_hash) {
        return Evaluation::Uncertain("record hash does not match");
    }
    if record.amount >= 0 {
        return Evaluation::Uncertain("record is not outgoing");
    }
    let Ok(principal_msat) = provider_abs_msat(record.amount) else {
        return Evaluation::Uncertain("record amount is malformed");
    };
    if principal_msat != expected.amount_msat {
        return Evaluation::Uncertain("record principal does not match");
    }
    if !record.bolt11.trim().eq_ignore_ascii_case(&expected.bolt11) {
        return Evaluation::Uncertain("record invoice does not match");
    }

    match ProviderState::parse(&record.status) {
        ProviderState::Pending => match paid {
            false => Evaluation::Pending,
            true => Evaluation::Uncertain("paid flag on a pending record"),
        },
        ProviderState::Failed => {
            // A repeated payment request can still mark a failed record
            // successful under the pinned profile, so failure is not final.
            Evaluation::Uncertain("provider failure is not terminal")
        }
        ProviderState::Unrecognized => Evaluation::Uncertain("provider state is not recognized"),
        ProviderState::Success => {
            if !paid {
                return Evaluation::Uncertain("success record without paid flag");
            }
            let Some(preimage) = preimage.and_then(parse_hex32) else {
                return Evaluation::Uncertain("success record without a valid preimage");
            };
            if other_preimage.is_some_and(|other| parse_hex32(other) != Some(preimage)) {
                return Evaluation::Uncertain("preimage fields disagree");
            }
            if sha256::Hash::hash(&preimage).to_byte_array() != expected.payment_hash {
                return Evaluation::Uncertain("preimage does not match the payment hash");
            }
            let Ok(fee_msat) = provider_abs_msat(record.fee) else {
                return Evaluation::Uncertain("record fee is malformed");
            };
            let Ok(total_sat) = outgoing_total_sat(principal_msat, fee_msat) else {
                return Evaluation::Uncertain("record cost overflows");
            };
            Evaluation::Paid {
                preimage,
                fee_msat,
                total_sat,
            }
        }
    }
}

fn bolt11_outgoing(
    options: OutgoingPaymentOptions,
) -> Result<Box<Bolt11OutgoingPaymentOptions>, Error> {
    match options {
        OutgoingPaymentOptions::Bolt11(options) => Ok(options),
        OutgoingPaymentOptions::Bolt12(_)
        | OutgoingPaymentOptions::Custom(_)
        | OutgoingPaymentOptions::Onchain(_) => Err(Error::UnsupportedPaymentOption),
    }
}

pub(crate) fn ensure_sat(unit: &CurrencyUnit) -> Result<(), Error> {
    match unit {
        CurrencyUnit::Sat => Ok(()),
        _ => Err(Error::UnsupportedUnit),
    }
}

pub(crate) fn expect_payment_hash(identifier: &PaymentIdentifier) -> Result<[u8; 32], Error> {
    match identifier {
        PaymentIdentifier::PaymentHash(hash) => Ok(*hash),
        _ => Err(Error::UnsupportedIdentifier),
    }
}

fn uncertain(payment_hash: [u8; 32], status: MeltQuoteState) -> MakePaymentResponse {
    MakePaymentResponse {
        payment_lookup_id: PaymentIdentifier::PaymentHash(payment_hash),
        payment_proof: None,
        status,
        total_spent: Amount::new(0, CurrencyUnit::Sat),
    }
}
