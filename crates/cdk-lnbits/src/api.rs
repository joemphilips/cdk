//! Wire shapes of the pinned LNbits API profile.
//!
//! The adapter supports LNbits `v1.6.2` (commit
//! `9349da153c223b008f7d80453b53a54e09c8ed3d`). See the crate README for the
//! endpoints and the recorded response fixtures. Unknown fields are ignored.
//! A missing required field is a malformed response.

use cdk_common::util::hex;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// HTTP status of a created invoice or an accepted payment request.
pub(crate) const STATUS_CREATED: u16 = 201;
/// HTTP status of a status or fee reserve read.
pub(crate) const STATUS_OK: u16 = 200;
/// Maximum memo length that the provider accepts.
pub(crate) const MAX_MEMO_CHARS: usize = 640;

/// Body of `POST /api/v1/payments` that creates an incoming invoice.
#[derive(Serialize)]
pub(crate) struct CreateInvoiceBody {
    /// Must be `false`. The provider default is `true`.
    pub(crate) out: bool,
    pub(crate) amount: u64,
    pub(crate) unit: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) memo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expiry: Option<u64>,
}

/// Body of `POST /api/v1/payments` that pays an invoice.
#[derive(Serialize)]
pub(crate) struct PayInvoiceBody<'a> {
    pub(crate) out: bool,
    pub(crate) bolt11: &'a str,
}

/// The provider `Payment` model fields that the adapter uses.
#[derive(Deserialize)]
pub(crate) struct WirePayment {
    pub(crate) payment_hash: String,
    pub(crate) amount: i64,
    pub(crate) fee: i64,
    pub(crate) bolt11: String,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) preimage: Option<String>,
}

/// Reply of `GET /api/v1/payments/{payment_hash}`.
///
/// `details` is present only when the request has a key of the owning wallet.
#[derive(Deserialize)]
pub(crate) struct WireStatus {
    pub(crate) paid: bool,
    #[serde(default)]
    pub(crate) preimage: Option<String>,
    #[serde(default)]
    pub(crate) details: Option<WirePayment>,
}

/// Reply of `GET /api/v1/payments/fee-reserve`.
#[derive(Deserialize)]
pub(crate) struct WireFeeReserve {
    pub(crate) fee_reserve: i64,
}

/// Websocket wallet notification. Only the fields of a wake hint are read.
#[derive(Deserialize)]
pub(crate) struct WireHint {
    pub(crate) payment: WireHintPayment,
}

/// Payment fields of a websocket wake hint.
#[derive(Deserialize)]
pub(crate) struct WireHintPayment {
    pub(crate) payment_hash: String,
    pub(crate) amount: i64,
}

/// Provider payment state of the pinned profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderState {
    Pending,
    Success,
    Failed,
    Unrecognized,
}

impl ProviderState {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "pending" => Self::Pending,
            "success" => Self::Success,
            "failed" => Self::Failed,
            _ => Self::Unrecognized,
        }
    }
}

/// Parse a JSON body. The error never includes body text.
pub(crate) fn parse_json<T>(body: &[u8]) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(body).map_err(|_| Error::MalformedResponse)
}

/// Parse a 32-byte hex value such as a payment hash or a preimage.
pub(crate) fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}
