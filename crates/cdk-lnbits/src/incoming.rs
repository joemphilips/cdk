//! Incoming invoices and incoming credit.

use bitcoin::hashes::Hash;
use cdk_common::nuts::CurrencyUnit;
use cdk_common::payment::{
    CreateIncomingPaymentResponse, IncomingPaymentOptions, PaymentIdentifier, WaitPaymentResponse,
};
use cdk_common::util::hex;
use cdk_common::{Amount, Bolt11Invoice};

use crate::amount::{msat_to_sat_floor, provider_abs_msat, sat_to_msat};
use crate::api::{
    parse_hex32, parse_json, CreateInvoiceBody, ProviderState, WirePayment, WireStatus,
    MAX_MEMO_CHARS, STATUS_CREATED, STATUS_OK,
};
use crate::error::Error;
use crate::outgoing::{ensure_sat, expect_payment_hash};
use crate::LNbits;

/// Clock skew allowed between the requested expiry and the signed invoice.
const EXPIRY_TOLERANCE_SECS: u64 = 60;

impl LNbits {
    pub(crate) async fn create_incoming(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Error> {
        let options = match options {
            IncomingPaymentOptions::Bolt11(options) => options,
            IncomingPaymentOptions::Bolt12(_)
            | IncomingPaymentOptions::Custom(_)
            | IncomingPaymentOptions::Onchain(_) => return Err(Error::UnsupportedPaymentOption),
        };
        ensure_sat(options.amount.unit())?;
        let amount_sat = options.amount.value();
        if amount_sat == 0 {
            return Err(Error::ZeroAmount);
        }
        let amount_msat = sat_to_msat(amount_sat)?;
        let now = (self.now)();
        let relative_expiry = match options.unix_expiry {
            Some(at) => Some(
                at.checked_sub(now)
                    .filter(|seconds| *seconds > 0)
                    .ok_or(Error::InvalidExpiry)?,
            ),
            None => None,
        };
        if options
            .description
            .as_ref()
            .is_some_and(|memo| memo.chars().count() > MAX_MEMO_CHARS)
        {
            return Err(Error::DescriptionTooLong);
        }

        let body = serde_json::to_vec(&CreateInvoiceBody {
            out: false,
            amount: amount_sat,
            unit: "sat",
            memo: options.description.clone(),
            expiry: relative_expiry,
        })
        .map_err(|_| Error::InvalidConfig("invoice request cannot be encoded"))?;
        let reply = self.transport.create_invoice(body).await?;
        if reply.status != STATUS_CREATED {
            tracing::warn!(
                http_status = reply.status,
                "LNbits refused to create an invoice"
            );
            return Err(Error::ProviderStatus(reply.status));
        }
        let record: WirePayment = parse_json(&reply.body)?;
        let invoice: Bolt11Invoice = record
            .bolt11
            .trim()
            .parse()
            .map_err(|_| Error::InvalidInvoice("invoice encoding or signature is not valid"))?;
        let payment_hash = invoice.payment_hash().to_byte_array();
        if parse_hex32(&record.payment_hash) != Some(payment_hash) {
            return Err(Error::InconsistentResponse(
                "record hash does not match the invoice",
            ));
        }
        if invoice.network() != self.policy.network {
            return Err(Error::InvalidInvoice("invoice uses another network"));
        }
        if invoice.amount_milli_satoshis() != Some(amount_msat) {
            return Err(Error::AmountMismatch);
        }
        if i64::try_from(amount_msat).ok() != Some(record.amount) {
            return Err(Error::InconsistentResponse(
                "record amount does not match the invoice",
            ));
        }
        let expires_at = invoice
            .expires_at()
            .ok_or(Error::InvalidInvoice("invoice expiry is not valid"))?
            .as_secs();
        if expires_at <= now {
            return Err(Error::InvalidInvoice("invoice is expired"));
        }
        if let Some(at) = options.unix_expiry {
            if expires_at > at.saturating_add(EXPIRY_TOLERANCE_SECS) {
                return Err(Error::InvalidInvoice(
                    "invoice expires after the requested expiry",
                ));
            }
        }

        Ok(CreateIncomingPaymentResponse {
            request_lookup_id: PaymentIdentifier::PaymentHash(payment_hash),
            request: invoice.to_string(),
            expiry: Some(expires_at),
            extra_json: None,
        })
    }

    pub(crate) async fn incoming_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Error> {
        let payment_hash = expect_payment_hash(payment_identifier)?;
        let hash_hex = hex::encode(payment_hash);
        let reply = self.transport.get_payment(&hash_hex).await?;
        if reply.status != STATUS_OK {
            return Err(Error::ProviderStatus(reply.status));
        }
        let status: WireStatus = parse_json(&reply.body)?;
        let record = status.details.ok_or(Error::InconsistentResponse(
            "status reply has no wallet details",
        ))?;
        let amount_msat = self.bind_incoming(&payment_hash, &record)?;

        match (ProviderState::parse(&record.status), status.paid) {
            (ProviderState::Success, true) => {
                let credit_sat = msat_to_sat_floor(amount_msat);
                if credit_sat == 0 {
                    return Ok(Vec::new());
                }
                Ok(vec![WaitPaymentResponse {
                    payment_identifier: PaymentIdentifier::PaymentHash(payment_hash),
                    payment_amount: Amount::new(credit_sat, CurrencyUnit::Sat),
                    payment_id: hash_hex,
                }])
            }
            (ProviderState::Pending | ProviderState::Failed, false) => Ok(Vec::new()),
            _ => Err(Error::InconsistentResponse("paid flag and state disagree")),
        }
    }

    /// Bind an incoming record to the requested hash. Returns the invoice
    /// amount in msat.
    fn bind_incoming(&self, payment_hash: &[u8; 32], record: &WirePayment) -> Result<u64, Error> {
        if parse_hex32(&record.payment_hash) != Some(*payment_hash) {
            return Err(Error::InconsistentResponse("record hash does not match"));
        }
        if record.amount <= 0 {
            return Err(Error::InconsistentResponse("record is not incoming"));
        }
        let amount_msat = provider_abs_msat(record.amount)?;
        let invoice: Bolt11Invoice = record
            .bolt11
            .trim()
            .parse()
            .map_err(|_| Error::InvalidInvoice("invoice encoding or signature is not valid"))?;
        if invoice.payment_hash().to_byte_array() != *payment_hash {
            return Err(Error::InconsistentResponse("invoice hash does not match"));
        }
        if invoice.network() != self.policy.network {
            return Err(Error::InvalidInvoice("invoice uses another network"));
        }
        if invoice.amount_milli_satoshis() != Some(amount_msat) {
            return Err(Error::AmountMismatch);
        }
        Ok(amount_msat)
    }
}
