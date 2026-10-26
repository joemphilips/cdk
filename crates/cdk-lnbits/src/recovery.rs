//! Read-only recovery context for outgoing status checks.
//!
//! [`cdk_common::payment::MintPayment::check_outgoing_payment`] receives only
//! a payment hash. Hash equality alone cannot bind a provider record to the
//! invoice and principal that the mint quoted. The mint owns that durable
//! fact in its melt quotes. This module defines the narrow read-only query
//! that the adapter needs and the rules that resolve its answer.

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use cdk_common::Bolt11Invoice;

/// One durable outgoing expectation for a payment hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingExpectation {
    /// The invoice that the mint quoted.
    pub bolt11: Bolt11Invoice,
    /// The fee reserve that the mint quoted, in msat.
    pub fee_reserve_msat: u64,
}

/// The recovery context source failed. It carries no detail by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("recovery context is unavailable")]
pub struct RecoveryContextError;

/// Read-only source of durable outgoing expectations.
///
/// An implementation returns every durable melt quote expectation that uses
/// the payment hash, in any order. It must not create, change or delete
/// state.
#[async_trait]
pub trait OutgoingRecoveryContext: Send + Sync {
    /// Return all durable expectations that share `payment_hash`.
    async fn expectations(
        &self,
        payment_hash: &[u8; 32],
    ) -> Result<Vec<OutgoingExpectation>, RecoveryContextError>;
}

/// Recovery context that knows no durable expectation.
///
/// With this context a status check cannot bind a paid record, so it keeps
/// the payment uncertain.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRecoveryContext;

#[async_trait]
impl OutgoingRecoveryContext for NoRecoveryContext {
    async fn expectations(
        &self,
        _payment_hash: &[u8; 32],
    ) -> Result<Vec<OutgoingExpectation>, RecoveryContextError> {
        Ok(Vec::new())
    }
}

/// The expected outgoing payment that a provider record must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expected {
    pub(crate) payment_hash: [u8; 32],
    pub(crate) bolt11: String,
    pub(crate) amount_msat: u64,
    pub(crate) fee_reserve_msat: u64,
}

/// Result of resolving durable expectations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// Exactly one invoice and principal is expected.
    Unique(Expected),
    /// No durable expectation exists.
    Absent,
    /// Durable expectations disagree or do not match the hash.
    Conflicting,
}

/// Resolve durable expectations for `payment_hash`.
///
/// Several melt quotes can use one invoice. They resolve to one expectation
/// only when every quote uses the same invoice for this hash and network. The
/// lowest quoted reserve is used for the fee excess event, so the event fires
/// when the actual fee exceeds any quoted reserve.
pub(crate) fn resolve(
    payment_hash: &[u8; 32],
    network: bitcoin::Network,
    expectations: &[OutgoingExpectation],
) -> Resolution {
    let mut resolved: Option<Expected> = None;
    for expectation in expectations {
        let invoice = &expectation.bolt11;
        if invoice.payment_hash().to_byte_array() != *payment_hash || invoice.network() != network {
            return Resolution::Conflicting;
        }
        let Some(amount_msat) = invoice.amount_milli_satoshis().filter(|amount| *amount > 0) else {
            return Resolution::Conflicting;
        };
        let bolt11 = invoice.to_string();
        match resolved.as_mut() {
            None => {
                resolved = Some(Expected {
                    payment_hash: *payment_hash,
                    bolt11,
                    amount_msat,
                    fee_reserve_msat: expectation.fee_reserve_msat,
                });
            }
            Some(current) => {
                if !current.bolt11.eq_ignore_ascii_case(&bolt11)
                    || current.amount_msat != amount_msat
                {
                    return Resolution::Conflicting;
                }
                current.fee_reserve_msat =
                    current.fee_reserve_msat.min(expectation.fee_reserve_msat);
            }
        }
    }
    match resolved {
        Some(expected) => Resolution::Unique(expected),
        None => Resolution::Absent,
    }
}
