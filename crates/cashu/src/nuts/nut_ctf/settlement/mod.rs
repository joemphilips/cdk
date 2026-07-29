//! Wire and validation primitives for multi-party NUT-CTF settlement.
//!
//! These primitives do not mutate mint state. Atomic spending, signing, and
//! idempotent response persistence are implemented by the mint layer.

mod canonical;
mod condition;
mod manifest;
mod refund;
mod request;
mod settings;

pub use canonical::{ctf_receive_commitment, CanonicalHash};
pub use condition::{PayToUnlockAuthorization, PayToUnlockCondition, PayToUnlockMode, PoolPolicy};
pub use manifest::{PoolEntry, PoolEntryRole, PoolManifest, SelectionBitmap};
pub use refund::{
    pay_to_unlock_refund_digest, reject_pay_to_unlock_inputs, sign_pay_to_unlock_refund,
    verify_pay_to_unlock_refund,
};
pub use request::{
    validate_ctf_range_authorization, CtfConvertAdmission, CtfConvertMode, CtfSettlementLimits,
    CtfSettlementParticipant, CtfSettlementRequest, CtfSettlementResponse, ParticipantMode,
};
pub use settings::{
    NutCtfSettlementSettings, NutCtfSettlementSettingsError, NutCtfSplitMergeSettings,
};

/// Errors produced while decoding or validating multi-party CTF settlement.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A fixed-width hash was not canonical lowercase hexadecimal.
    #[error("{field} must be exactly 32 bytes of lowercase hexadecimal")]
    InvalidHash {
        /// Field containing the invalid hash.
        field: &'static str,
    },
    /// The v1 parent collection was not the root collection.
    #[error("parent_collection_id must be omitted or all zero in v1")]
    NonRootParentCollection,
    /// A decimal string was not the minimal unsigned representation.
    #[error("{field} must be a minimal unsigned decimal string")]
    InvalidDecimal {
        /// Field containing the invalid decimal.
        field: &'static str,
    },
    /// A keyset identifier was not in its canonical form.
    #[error("{field} contains a non-canonical keyset id")]
    InvalidKeysetId {
        /// Field containing the invalid keyset identifier.
        field: &'static str,
    },
    /// A public key was not in its canonical lowercase form.
    #[error("{field} contains a non-canonical public key")]
    InvalidPublicKey {
        /// Field containing the invalid public key.
        field: &'static str,
    },
    /// The PAY_TO_UNLOCK secret was malformed.
    #[error("invalid PAY_TO_UNLOCK condition: {0}")]
    InvalidCondition(&'static str),
    /// A required PAY_TO_UNLOCK tag was absent.
    #[error("missing PAY_TO_UNLOCK tag: {0}")]
    MissingTag(&'static str),
    /// A PAY_TO_UNLOCK tag appeared more than once.
    #[error("duplicate PAY_TO_UNLOCK tag")]
    DuplicateTag,
    /// A PAY_TO_UNLOCK tag is not defined by CTF settlement.
    #[error("unknown PAY_TO_UNLOCK tag")]
    UnknownTag,
    /// Standard and pool tags were mixed.
    #[error("pool tags must be all present or all absent")]
    PartialPoolTags,
    /// A pool numeric policy was invalid.
    #[error("invalid pool policy: {0}")]
    InvalidPoolPolicy(&'static str),
    /// Checked settlement arithmetic overflowed.
    #[error("settlement arithmetic overflow")]
    ArithmeticOverflow,
    /// The manifest was structurally invalid.
    #[error("invalid pool manifest: {0}")]
    InvalidManifest(&'static str),
    /// The pool selection bitmap was not canonical.
    #[error("invalid pool selection: {0}")]
    InvalidSelection(&'static str),
    /// Selected outputs did not exactly match the manifest selection.
    #[error("selected outputs do not exactly match the manifest selection")]
    SelectionMismatch,
    /// A standard participant's output commitment did not match its condition.
    #[error("standard output commitment does not match PAY_TO_UNLOCK data")]
    OutputCommitmentMismatch,
    /// A pool participant's manifest commitment did not match its condition.
    #[error("pool manifest commitment does not match PAY_TO_UNLOCK data")]
    ManifestCommitmentMismatch,
    /// A request or participant exceeded an advertised structural limit.
    #[error("settlement limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A request or participant was empty or otherwise incomplete.
    #[error("invalid settlement structure: {0}")]
    InvalidStructure(&'static str),
    /// An input did not use the keyset named by its condition.
    #[error("input keyset does not match offer_keyset")]
    OfferKeysetMismatch,
    /// Standard outputs did not use one non-offer receive keyset.
    #[error("standard outputs must share one non-offer receive keyset")]
    OfferReceiveKeysetMismatch,
    /// Inputs in one participant did not share the same authorization.
    #[error("participant inputs do not share one authorization")]
    InconsistentAuthorization,
    /// A proof or authorization nonce was repeated.
    #[error("duplicate proof or authorization nonce")]
    DuplicateInput,
    /// A blinded output was repeated.
    #[error("duplicate blinded output")]
    DuplicateOutput,
    /// Participants were not in canonical order.
    #[error("participants are not in canonical order")]
    NonCanonicalParticipantOrder,
    /// Inputs were not in canonical order.
    #[error("participant inputs are not in canonical order")]
    NonCanonicalInputOrder,
    /// A participating keyset did not have a positive input fee.
    #[error("participating keyset must have a positive input_fee_ppk")]
    ZeroFeeKeyset,
    /// A participating keyset could not be resolved.
    #[error("participating keyset is unknown")]
    UnknownKeyset,
    /// A manifest entry amount is not published by its signing keyset.
    #[error("pool manifest contains an unsupported denomination")]
    UnsupportedDenomination,
    /// A settlement request arrived at or after its authorization expiry.
    #[error("settlement authorization has expired")]
    SettlementAfterExpiry,
    /// A refund request arrived before its authorization expiry.
    #[error("PAY_TO_UNLOCK refund is not yet available")]
    RefundBeforeExpiry,
    /// A refund witness was missing, malformed, or invalid.
    #[error("PAY_TO_UNLOCK refund witness is missing or invalid")]
    RefundWitnessMissingOrInvalid,
    /// JSON decoding failed.
    #[error("invalid settlement JSON: {0}")]
    Json(String),
    /// An admitted request was decoded as the wrong convert mode.
    #[error("CTF convert request mode does not match the requested decoder")]
    WrongRequestMode,
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value.to_string())
    }
}

#[cfg(test)]
mod tests;
