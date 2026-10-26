//! Fixed, secret-safe errors for the LNbits backend.
//!
//! Every message is a static string. No variant carries provider text, an
//! HTTP body, a URL, a header, an invoice, a preimage or a key, so an error
//! can be logged or returned to a wallet without disclosing them.

use thiserror::Error;

/// Transport failure kind. The kind is the only detail that is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransportError {
    /// The request or the connection did not complete in time.
    #[error("LNbits request timed out")]
    Timeout,
    /// The connection could not be opened.
    #[error("LNbits connection failed")]
    Connect,
    /// The response was larger than the configured bound.
    #[error("LNbits response exceeded the size limit")]
    BodyTooLarge,
    /// Any other transport or protocol failure.
    #[error("LNbits transport failed")]
    Protocol,
}

/// LNbits backend error.
#[derive(Debug, Error)]
pub enum Error {
    /// The configuration is not valid.
    #[error("invalid LNbits configuration: {0}")]
    InvalidConfig(&'static str),
    /// The requested unit is not the native sat unit.
    #[error("unsupported unit")]
    UnsupportedUnit,
    /// The requested payment option is not supported.
    #[error("unsupported payment option")]
    UnsupportedPaymentOption,
    /// Outgoing payments are disabled by configuration.
    #[error("outgoing LNbits payments are disabled")]
    OutgoingDisabled,
    /// The amount is zero.
    #[error("amount must be greater than zero")]
    ZeroAmount,
    /// An amount calculation overflowed.
    #[error("amount overflow")]
    AmountOverflow,
    /// An amount does not match the expected amount.
    #[error("amount mismatch")]
    AmountMismatch,
    /// The expiry is not valid.
    #[error("invalid expiry")]
    InvalidExpiry,
    /// The description is longer than the provider accepts.
    #[error("description is too long")]
    DescriptionTooLong,
    /// The invoice is not valid for this backend.
    #[error("invalid invoice: {0}")]
    InvalidInvoice(&'static str),
    /// The payment identifier is not a payment hash.
    #[error("unsupported payment identifier")]
    UnsupportedIdentifier,
    /// The provider returned an HTTP status that this profile does not accept.
    #[error("LNbits returned HTTP status {0}")]
    ProviderStatus(u16),
    /// The provider response does not match the supported API profile.
    #[error("LNbits response is malformed")]
    MalformedResponse,
    /// The provider response is not bound to the requested payment.
    #[error("LNbits response is inconsistent: {0}")]
    InconsistentResponse(&'static str),
    /// A payment event stream is already active.
    #[error("LNbits payment event stream is already active")]
    StreamAlreadyActive,
    /// The payment event stream was cancelled.
    #[error("LNbits payment event stream is cancelled")]
    StreamCancelled,
    /// Transport failure.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl From<Error> for cdk_common::payment::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::UnsupportedUnit => Self::UnsupportedUnit,
            Error::UnsupportedPaymentOption => Self::UnsupportedPaymentOption,
            Error::AmountMismatch => Self::AmountMismatch,
            Error::InvalidExpiry => Self::InvalidExpiry,
            other => Self::Backend(Box::new(other)),
        }
    }
}
