//! Atomic wallet storage contract for conditional-token recovery.

use std::collections::HashSet;
use std::str::FromStr;

use cashu::nuts::nut02::KeySetVersion;
use cashu::nuts::nut_ctf::{compute_outcome_collection_id, ConditionalKeySetInfo};
use cashu::{CurrencyUnit, Id, KeySet, KeySetInfo, State};
use serde::{Deserialize, Serialize};

use super::Error;
use crate::database::conditional::validate_conditional_keyset_catalogue_fields;
use crate::mint_url::MintUrl;
use crate::wallet::ProofInfo;

/// All data admitted atomically for one recovered conditional keyset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalRestoreAdmission {
    /// Mint which owns the recovered keyset and proofs.
    pub mint_url: MintUrl,
    /// Wallet unit which owns the recovered keyset and proofs.
    pub unit: CurrencyUnit,
    /// Current wall-clock observation used to advance the rollback-resistant fence.
    pub observed_wall_time: u64,
    /// Whether this batch restores held proofs or advances an all-spent scan.
    pub mode: ConditionalRestoreAdmissionMode,
    /// Immutable conditional catalogue metadata.
    pub conditional_keyset: ConditionalKeySetInfo,
    /// Standard NUT-02 keyset metadata stored for ordinary wallet inspection.
    pub keyset: KeySetInfo,
    /// Public amount keys fetched for this keyset.
    pub keys: KeySet,
    /// Recovered proofs to admit. Only unspent or pending proofs are accepted.
    pub proofs: Vec<ProofInfo>,
    /// Authenticated spent evidence. These rows may only advance an exact
    /// already-persisted proof to `Spent`; they are never hydrated as new proofs.
    pub spent_proofs: Vec<ProofInfo>,
    /// Absolute derivation-counter floor, never an increment.
    pub counter_floor: u32,
}

impl ConditionalRestoreAdmission {
    /// Validate ownership and immutable metadata before any backend mutation.
    pub fn validate(&self) -> Result<(), Error> {
        let conditional_unit = CurrencyUnit::from_str(&self.conditional_keyset.unit)
            .map_err(|_| invalid("conditional keyset unit is invalid"))?;
        validate_conditional_keyset_catalogue_fields(
            &self.conditional_keyset.unit,
            &self.conditional_keyset.condition_id,
            &self.conditional_keyset.outcome_collection,
            &self.conditional_keyset.outcome_collection_id,
        )
        .map_err(invalid)?;
        let input_fee_ppk = self.conditional_keyset.input_fee_ppk.unwrap_or_default();
        if self.conditional_keyset.final_expiry == Some(0) {
            return Err(invalid("conditional keyset final expiry is not canonical"));
        }
        let final_expiry = self.conditional_keyset.final_expiry;

        if self.conditional_keyset.id.get_version() != KeySetVersion::Version01 {
            return Err(invalid(
                "conditional restore requires a supported v2 keyset id",
            ));
        }
        let condition_id = cashu::util::hex::decode(&self.conditional_keyset.condition_id)
            .map_err(|_| invalid("conditional condition id is invalid"))?;
        let condition_id = <[u8; 32]>::try_from(condition_id.as_slice())
            .map_err(|_| invalid("conditional condition id is invalid"))?;
        let expected_outcome_collection_id = compute_outcome_collection_id(
            &[0_u8; 32],
            &condition_id,
            &self.conditional_keyset.outcome_collection,
        )
        .map_err(|_| invalid("conditional outcome collection id cannot be derived"))?;
        if cashu::util::hex::encode(expected_outcome_collection_id)
            != self.conditional_keyset.outcome_collection_id
        {
            return Err(invalid(
                "conditional outcome collection id does not bind its condition and label",
            ));
        }

        if self.conditional_keyset.id != self.keyset.id
            || self.keyset.id != self.keys.id
            || conditional_unit != self.unit
            || self.conditional_keyset.unit != self.unit.to_string()
            || self.keyset.unit != self.unit
            || self.keys.unit != self.unit
            || self.keyset.active
            || self.keys.active != Some(self.conditional_keyset.active)
            || input_fee_ppk != self.keyset.input_fee_ppk
            || self.keys.input_fee_ppk != self.keyset.input_fee_ppk
            || self.keyset.final_expiry != final_expiry
            || self.keys.final_expiry != final_expiry
        {
            return Err(invalid(
                "conditional, standard, and public keyset metadata do not agree",
            ));
        }

        let derived_id = Id::v2_from_data_conditional(
            &self.keys.keys,
            &self.unit,
            input_fee_ppk,
            final_expiry,
            &self.conditional_keyset.condition_id,
            &self.conditional_keyset.outcome_collection_id,
        );
        if derived_id != self.keyset.id {
            return Err(invalid(
                "conditional keyset id does not bind the persisted metadata and public keys",
            ));
        }

        match self.mode {
            ConditionalRestoreAdmissionMode::HeldProofs if self.proofs.is_empty() => {
                return Err(invalid(
                    "held-proof conditional restore admission has no proofs",
                ));
            }
            ConditionalRestoreAdmissionMode::ProgressOnly if !self.proofs.is_empty() => {
                return Err(invalid(
                    "progress-only conditional restore admission contains proofs",
                ));
            }
            ConditionalRestoreAdmissionMode::HeldProofs
            | ConditionalRestoreAdmissionMode::ProgressOnly => {}
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
            // CTF ownership is keyset-level, so a normal recovered secret
            // correctly derives `None`; this only rejects a forged denormalized
            // NUT-10 classification on `ProofInfo`.
            let derived_spending_condition: Option<cashu::SpendingConditions> =
                (&proof.proof.secret).try_into().ok();
            if proof.mint_url != self.mint_url
                || proof.unit != self.unit
                || proof.proof.keyset_id != self.keyset.id
                || !valid_state
                || !self.keys.keys.contains_key(&proof.proof.amount)
                || proof
                    .proof
                    .y()
                    .map_err(|_| invalid("conditional proof secret is invalid"))?
                    != proof.y
                || derived_spending_condition != proof.spending_condition
                || !ys.insert(proof.y)
            {
                return Err(invalid(
                    "conditional proof ownership, state, amount, or Y is invalid",
                ));
            }
        }

        Ok(())
    }

    /// Optional final expiry after canonical validation.
    pub fn final_expiry(&self) -> Result<Option<u64>, Error> {
        match self.conditional_keyset.final_expiry {
            Some(0) => Err(invalid("conditional keyset final expiry is not canonical")),
            expiry => Ok(expiry),
        }
    }
}

/// Storage effect requested for one validated conditional restore batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionalRestoreAdmissionMode {
    /// Persist held unspent or pending proofs and hydrate their conditional keyset.
    HeldProofs,
    /// Persist the time fence/counter floor and apply exact existing spent evidence,
    /// without hydrating keysets, keys, or missing proofs.
    ProgressOnly,
}

/// Outcome of one atomic conditional restore admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionalRestoreAdmissionResult {
    /// Held proofs, keyset metadata, keys, counter floor, and time fence were committed.
    HeldProofs {
        /// Effective monotonic time used for the expiry decision.
        effective_time: u64,
    },
    /// The counter floor, time fence, and any exact existing spent transitions were committed.
    ProgressOnly {
        /// Effective monotonic time used for the expiry decision.
        effective_time: u64,
    },
    /// The high-water fence was committed, but the expired admission data was not.
    Expired {
        /// Effective monotonic time which reached or crossed final expiry.
        effective_time: u64,
    },
}

/// Join fresh mint evidence with an existing local proof lifecycle monotonically.
pub fn join_conditional_restore_proof_state(existing: State, incoming: State) -> State {
    match (existing, incoming) {
        (_, State::Spent) => State::Spent,
        (State::Unspent, State::Pending) => State::Pending,
        (existing, _) => existing,
    }
}

fn invalid(detail: &str) -> Error {
    Error::InvalidConditionalRestore(detail.to_string())
}
