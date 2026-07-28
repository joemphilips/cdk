//! NUT-CTF-split-merge CTF convert operation.
//!
//! Convert is the unified payoff-preserving operation for split, merge,
//! recombine, and collateral-crossing conversion.

use std::collections::{HashMap, HashSet};

use cdk_common::nuts::nut00::{BlindedMessage, Proof};
use cdk_common::nuts::nut_ctf::{CtfConvertRequest, CtfConvertResponse, ZERO_COLLECTION_ID};
use tracing::instrument;

use super::conditions::STATUS_PENDING;
use super::ctf_conservation::{condition_outcomes, CtfCoverageResolver, OutcomeConservation};
use super::swap::atomic::execute_atomic_ctf_convert;
use super::Mint;
use crate::Error;

struct CollectedOutputs {
    messages: Vec<BlindedMessage>,
    ranges: HashMap<String, (usize, usize)>,
}

impl Mint {
    /// Process a CTF convert request (POST /v1/ctf/convert).
    #[instrument(skip_all)]
    pub async fn process_ctf_convert(
        &self,
        request: CtfConvertRequest,
    ) -> Result<CtfConvertResponse, Error> {
        if request.inputs.is_empty() || request.outputs.is_empty() {
            return Err(Error::TransactionUnbalanced(0, 0, 0));
        }

        let condition = self
            .localstore
            .get_condition(&request.condition_id)
            .await?
            .ok_or(Error::ConditionNotFound)?;

        if condition.attestation_status != STATUS_PENDING {
            return Err(Error::ConvertNotPermitted);
        }

        let parent_collection_id = request
            .parent_collection_id
            .as_deref()
            .unwrap_or(ZERO_COLLECTION_ID);
        if parent_collection_id != ZERO_COLLECTION_ID {
            return Err(Error::ConvertPayoffFeeViolation);
        }
        let outcomes = condition_outcomes(&condition)?;
        let resolver = CtfCoverageResolver::new(self, &request.condition_id, &outcomes)?;
        let mut conservation = OutcomeConservation::new(&outcomes);
        let all_input_proofs =
            collect_inputs(&resolver, &request.inputs, &mut conservation).await?;
        let collected_outputs =
            collect_outputs(&resolver, &request.outputs, &mut conservation).await?;

        let all_input_proofs = proofs_sorted_by_y(all_input_proofs)?;
        let fee_breakdown = self.get_proofs_fee(&all_input_proofs).await?;
        let fee: u64 = fee_breakdown.total.into();
        conservation.validate(fee)?;

        let input_verification = self.verify_inputs(&all_input_proofs).await?;
        let all_sigs = execute_atomic_ctf_convert(
            self,
            &request.condition_id,
            &all_input_proofs,
            &collected_outputs.messages,
            input_verification,
        )
        .await?;
        let mut signatures = HashMap::new();
        for (key, (start, end)) in collected_outputs.ranges {
            signatures.insert(key, all_sigs[start..end].to_vec());
        }

        Ok(CtfConvertResponse { signatures })
    }
}

async fn collect_inputs(
    resolver: &CtfCoverageResolver<'_>,
    entries: &HashMap<String, Vec<Proof>>,
    conservation: &mut OutcomeConservation,
) -> Result<Vec<Proof>, Error> {
    let mut all_proofs = Vec::new();
    let mut seen_secrets = HashSet::new();
    for (key, proofs) in entries {
        if proofs.is_empty() {
            return Err(Error::TransactionUnbalanced(0, 0, 0));
        }
        let coverage = resolver.resolve_input_entry(key, proofs).await?;
        conservation.add_inputs(&coverage, proofs)?;
        for proof in proofs {
            if !seen_secrets.insert(proof.secret.to_string()) {
                return Err(Error::DuplicateInputs);
            }
            all_proofs.push(proof.clone());
        }
    }
    Ok(all_proofs)
}

async fn collect_outputs(
    resolver: &CtfCoverageResolver<'_>,
    entries: &HashMap<String, Vec<BlindedMessage>>,
    conservation: &mut OutcomeConservation,
) -> Result<CollectedOutputs, Error> {
    let mut collected = CollectedOutputs {
        messages: Vec::new(),
        ranges: HashMap::new(),
    };
    for (key, outputs) in entries {
        if outputs.is_empty() {
            return Err(Error::TransactionUnbalanced(0, 0, 0));
        }
        let coverage = resolver.resolve_output_entry(key, outputs).await?;
        conservation.add_outputs(&coverage, outputs)?;
        let start = collected.messages.len();
        collected.messages.extend(outputs.iter().cloned());
        collected
            .ranges
            .insert(key.clone(), (start, collected.messages.len()));
    }
    Ok(collected)
}

fn proofs_sorted_by_y(proofs: Vec<Proof>) -> Result<Vec<Proof>, Error> {
    let mut keyed = proofs
        .into_iter()
        .map(|proof| Ok((proof.y()?.to_bytes(), proof)))
        .collect::<Result<Vec<_>, Error>>()?;
    keyed.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, proof)| proof).collect())
}
