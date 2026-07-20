//! Atomic wallet storage contract for ordinary NUT-09 recovery.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::Error;
use crate::mint_url::MintUrl;
use crate::nuts::{CurrencyUnit, Id, State};
use crate::wallet::ProofInfo;

/// Proof evidence and derivation progress admitted atomically for one ordinary keyset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrdinaryRestoreAdmission {
    /// Mint which owns the recovered proofs.
    pub mint_url: MintUrl,
    /// Wallet unit which owns the recovered proofs.
    pub unit: CurrencyUnit,
    /// Ordinary keyset being recovered.
    pub keyset_id: Id,
    /// Recovered held proofs. Only unspent or pending proofs are accepted.
    pub proofs: Vec<ProofInfo>,
    /// Authenticated spent evidence. Missing proof bodies are never hydrated.
    pub spent_proofs: Vec<ProofInfo>,
    /// Absolute derivation-counter floor, never an increment.
    pub counter_floor: u32,
}

impl OrdinaryRestoreAdmission {
    /// Validate proof ownership and response states before any backend mutation.
    pub fn validate(&self) -> Result<(), Error> {
        if self.counter_floor == 0 || self.proofs.is_empty() && self.spent_proofs.is_empty() {
            return Err(invalid("ordinary restore admission contains no progress"));
        }

        let mut ys = HashSet::with_capacity(self.proofs.len() + self.spent_proofs.len());
        for (proof, valid_state) in self
            .proofs
            .iter()
            .map(|proof| {
                (
                    proof,
                    matches!(proof.state, State::Unspent | State::Pending),
                )
            })
            .chain(
                self.spent_proofs
                    .iter()
                    .map(|proof| (proof, proof.state == State::Spent)),
            )
        {
            let derived_spending_condition: Option<crate::nuts::SpendingConditions> =
                (&proof.proof.secret).try_into().ok();
            if proof.mint_url != self.mint_url
                || proof.unit != self.unit
                || proof.proof.keyset_id != self.keyset_id
                || !valid_state
                || proof
                    .proof
                    .y()
                    .map_err(|_| invalid("ordinary proof secret is invalid"))?
                    != proof.y
                || derived_spending_condition != proof.spending_condition
                || !ys.insert(proof.y)
            {
                return Err(invalid(
                    "ordinary proof ownership, state, classification, or Y is invalid",
                ));
            }
        }

        Ok(())
    }
}

/// Join authenticated recovery evidence with an existing local proof lifecycle.
pub fn join_restore_proof_state(existing: State, incoming: State) -> State {
    match (existing, incoming) {
        (_, State::Spent) => State::Spent,
        (State::Unspent, State::Pending) => State::Pending,
        (existing, _) => existing,
    }
}

fn invalid(detail: &str) -> Error {
    Error::InvalidOrdinaryRestore(detail.to_string())
}
