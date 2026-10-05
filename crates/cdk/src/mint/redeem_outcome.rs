//! NUT-CTF Redeem outcome processing

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use cdk_common::nuts::nut_ctf::dlc;
use cdk_common::nuts::nut_ctf::{
    compute_numeric_payout, from_hex, normalize_outcome, parse_outcome_collection, to_hex,
    OracleWitness, RedeemOutcomeRequest, RedeemOutcomeResponse,
};
use cdk_common::nuts::Witness;
use tracing::instrument;

use super::conditions::STATUS_ATTESTED;
use super::Mint;
use crate::Error;

/// Parse announcements JSON and build a pubkey-to-hex-string lookup map.
/// Returns (parsed announcement hex strings, pubkey->index map).
fn parse_announcements_with_index(
    announcements_json: &str,
) -> Result<(Vec<String>, HashMap<String, usize>), Error> {
    let hex_strings: Vec<String> = serde_json::from_str(announcements_json)?;
    let mut pubkey_index = HashMap::with_capacity(hex_strings.len());
    for (i, hex) in hex_strings.iter().enumerate() {
        let ann = dlc::parse_oracle_announcement(hex)?;
        let pubkey_hex = to_hex(&dlc::extract_oracle_pubkey(&ann));
        pubkey_index.insert(pubkey_hex, i);
    }
    Ok((hex_strings, pubkey_index))
}

/// Validate all supplied signatures against the registered oracle announcements.
fn verify_threshold(
    condition: &cdk_common::mint::StoredCondition,
    witness: &OracleWitness,
) -> Result<String, Error> {
    let numeric = condition.condition_type == "numeric";
    witness.validate_shape(numeric)?;
    let (announcements, index) = parse_announcements_with_index(&condition.announcements_json)?;
    let mut result: Option<String> = None;
    for entry in &witness.oracle_sigs {
        let key = from_hex(&entry.oracle_pubkey)?;
        let registered_key = to_hex(&key);
        let idx = index
            .get(&registered_key)
            .ok_or(Error::InvalidOracleSignature)?;
        let announcement = dlc::parse_oracle_announcement(&announcements[*idx])?;
        let nonces = dlc::extract_nonce_points(&announcement.oracle_event);
        let value = if numeric {
            let descriptor = dlc::extract_digit_decomposition(&announcement)?;
            let expected_nonces = descriptor.nb_digits + usize::from(descriptor.is_signed);
            if nonces.len() != expected_nonces {
                return Err(Error::InvalidOracleSignature);
            }
            let digits = entry
                .digit_sigs
                .as_ref()
                .ok_or(Error::InvalidOracleSignature)?;
            let signatures = digits
                .iter()
                .map(|value| from_hex(value))
                .collect::<Result<Vec<_>, _>>()?;
            dlc::verify_digit_attestation(
                &key,
                &signatures,
                &nonces,
                descriptor.base,
                descriptor.is_signed,
            )?
            .to_string()
        } else {
            if nonces.len() != 1 {
                return Err(Error::InvalidOracleSignature);
            }
            let outcome = entry
                .outcome
                .as_deref()
                .ok_or(Error::InvalidOracleSignature)?;
            let normalized = normalize_outcome(outcome);
            if !dlc::extract_outcomes(&announcement)?
                .iter()
                .any(|value| normalize_outcome(value) == normalized)
            {
                return Err(Error::OracleNotAttestedOutcome);
            }
            let signature = from_hex(
                entry
                    .oracle_sig
                    .as_deref()
                    .ok_or(Error::InvalidOracleSignature)?,
            )?;
            dlc::verify_oracle_attestation(&key, &signature, outcome, &nonces[0])?;
            normalized
        };
        if result.as_ref().is_some_and(|previous| previous != &value) {
            tracing::warn!(condition_id = %condition.condition_id, "Conflicting valid oracle attestations");
            return Err(Error::ConflictingOracleAttestations);
        }
        result = Some(value);
    }
    if witness.oracle_sigs.len() < condition.threshold as usize {
        return Err(Error::OracleThresholdNotMet);
    }
    result.ok_or(Error::ConditionalKeysetRequiresWitness)
}

/// Verify every supplied proof witness, including evidence sent after resolution.
fn attestation_for_inputs(
    condition: &cdk_common::mint::StoredCondition,
    inputs: &cdk_common::Proofs,
) -> Result<(String, Option<OracleWitness>), Error> {
    let mut accepted: Option<(String, OracleWitness)> = None;
    for proof in inputs {
        if condition.attestation_status != STATUS_ATTESTED
            && !matches!(proof.witness, Some(Witness::OracleWitness(_)))
        {
            return Err(Error::ConditionalKeysetRequiresWitness);
        }
        if let Some(Witness::OracleWitness(witness)) = &proof.witness {
            let value = verify_threshold(condition, witness)?;
            if accepted
                .as_ref()
                .is_some_and(|(previous, _)| previous != &value)
                || condition
                    .winning_outcome
                    .as_ref()
                    .is_some_and(|recorded| recorded != &value)
            {
                tracing::warn!(condition_id = %condition.condition_id, "Conflicting valid oracle attestations");
                return Err(Error::ConflictingOracleAttestations);
            }
            if accepted.is_none() {
                accepted = Some((value, witness.clone()));
            }
        }
    }
    match accepted {
        Some((value, witness)) => Ok((value, Some(witness))),
        None if condition.attestation_status == STATUS_ATTESTED => Ok((
            condition
                .winning_outcome
                .clone()
                .ok_or(Error::OracleNotAttestedOutcome)?,
            None,
        )),
        None => Err(Error::ConditionalKeysetRequiresWitness),
    }
}

/// Preserve the first result and evidence under the same lock used by convert.
async fn record_attestation(
    localstore: &(dyn cdk_common::database::MintDatabase<cdk_common::database::Error>
          + Send
          + Sync),
    condition_id: &str,
    winning_value: &str,
    witness: &OracleWitness,
) -> Result<(), Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Custom("System clock precedes Unix epoch".to_string()))?
        .as_secs();
    let mut tx = localstore.begin_transaction().await?;
    let condition = tx
        .get_condition_for_update(condition_id)
        .await?
        .ok_or(Error::ConditionNotFound)?;
    if condition.attestation_status == STATUS_ATTESTED {
        if condition.winning_outcome.as_deref() != Some(winning_value) {
            tracing::warn!(condition_id, "Conflicting valid oracle attestations");
            return Err(Error::ConflictingOracleAttestations);
        }
    } else if condition.attestation_status != super::conditions::STATUS_PENDING {
        return Err(Error::OracleNotAttestedOutcome);
    } else {
        tx.record_condition_attestation(&condition, winning_value, now, &witness.oracle_sigs)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

impl Mint {
    /// Process a redeem outcome request (POST /v1/redeem_outcome)
    #[instrument(skip_all)]
    pub async fn process_redeem_outcome(
        &self,
        request: RedeemOutcomeRequest,
    ) -> Result<RedeemOutcomeResponse, Error> {
        let inputs = &request.inputs;
        let outputs = &request.outputs;

        if inputs.is_empty() {
            return Err(Error::TransactionUnbalanced(0, 0, 0));
        }
        super::reject_pay_to_unlock_spend(inputs)?;
        super::verify_individual_spending_conditions(inputs)?;

        // 1. Verify all inputs use the same conditional keyset
        let input_keyset_ids: HashSet<_> = inputs.iter().map(|p| p.keyset_id).collect();
        if input_keyset_ids.len() != 1 {
            return Err(Error::InputsMustUseSameConditionalKeyset);
        }
        let input_keyset_id = inputs[0].keyset_id;

        // 2. Look up the condition for this keyset
        let (condition_id, outcome_collection, _outcome_collection_id) = self
            .localstore
            .get_condition_for_keyset(&input_keyset_id)
            .await?
            .ok_or(Error::ConditionNotFound)?;

        let condition = self
            .localstore
            .get_condition(&condition_id)
            .await?
            .ok_or(Error::ConditionNotFound)?;

        // 3. This version supports root-level conditional keysets only; redemption
        // outputs must use regular keysets in the same unit.
        let output_keyset_ids: HashSet<_> = outputs.iter().map(|o| o.keyset_id).collect();
        for oid in &output_keyset_ids {
            let keyset_info = self.get_keyset_info(oid).ok_or(Error::UnknownKeySet)?;
            if !keyset_info.active {
                return Err(Error::InactiveKeyset);
            }
            if self
                .localstore
                .get_condition_for_keyset(oid)
                .await?
                .is_some()
            {
                return Err(Error::OutputsMustUseRegularKeyset);
            }
        }

        // Branch on condition type
        let is_numeric = condition.condition_type == "numeric";

        if is_numeric {
            // --- NUT-CTF-numeric: Numeric proportional redemption ---
            self.process_numeric_redemption(
                &condition,
                &condition_id,
                &outcome_collection,
                inputs,
                outputs,
            )
            .await
        } else {
            // --- NUT-CTF: Enum winner-take-all redemption ---
            self.process_enum_redemption(
                &condition,
                &condition_id,
                &outcome_collection,
                inputs,
                outputs,
            )
            .await
        }
    }

    /// NUT-CTF: Enum winner-take-all redemption
    async fn process_enum_redemption(
        &self,
        condition: &cdk_common::mint::StoredCondition,
        condition_id: &str,
        outcome_collection: &str,
        inputs: &cdk_common::Proofs,
        outputs: &[cdk_common::nuts::nut00::BlindedMessage],
    ) -> Result<RedeemOutcomeResponse, Error> {
        let (attested_outcome, witness) = attestation_for_inputs(condition, inputs)?;

        let covered = parse_outcome_collection(outcome_collection);
        if !covered.iter().any(|outcome| outcome == &attested_outcome) {
            return Err(Error::OracleNotAttestedOutcome);
        }

        let input_amount: u64 = inputs
            .iter()
            .try_fold(0u64, |sum, proof| sum.checked_add(u64::from(proof.amount)))
            .ok_or(Error::AmountOverflow)?;
        let output_amount: u64 = outputs
            .iter()
            .try_fold(0u64, |sum, output| {
                sum.checked_add(u64::from(output.amount))
            })
            .ok_or(Error::AmountOverflow)?;

        if input_amount < output_amount {
            return Err(Error::TransactionUnbalanced(input_amount, output_amount, 0));
        }

        let input_verification = self.verify_inputs(inputs).await?;

        if let Some(witness) = witness {
            record_attestation(&*self.localstore, condition_id, &attested_outcome, &witness)
                .await?;
        }

        let init_saga = crate::mint::swap::swap_saga::SwapSaga::new(
            self,
            self.localstore.clone(),
            self.pubsub_manager.clone(),
        );

        let setup_saga = init_saga
            .setup_swap(inputs, outputs, None, input_verification)
            .await?;

        let signed_saga = setup_saga.sign_outputs().await?;
        let swap_response = signed_saga.finalize().await?;

        Ok(RedeemOutcomeResponse {
            signatures: swap_response.signatures,
        })
    }

    /// NUT-CTF-numeric: Numeric proportional redemption
    async fn process_numeric_redemption(
        &self,
        condition: &cdk_common::mint::StoredCondition,
        condition_id: &str,
        outcome_collection: &str,
        inputs: &cdk_common::Proofs,
        outputs: &[cdk_common::nuts::nut00::BlindedMessage],
    ) -> Result<RedeemOutcomeResponse, Error> {
        // Validate outcome collection is HI or LO
        if outcome_collection != "HI" && outcome_collection != "LO" {
            return Err(Error::OracleNotAttestedOutcome);
        }

        let lo_bound = condition
            .lo_bound
            .ok_or_else(|| Error::Custom("Numeric condition missing lo_bound".into()))?;
        let hi_bound = condition
            .hi_bound
            .ok_or_else(|| Error::Custom("Numeric condition missing hi_bound".into()))?;

        let (attested_result, witness) = attestation_for_inputs(condition, inputs)?;
        let attested_value = attested_result
            .parse::<i64>()
            .map_err(|_| Error::OracleNotAttestedOutcome)?;

        // Compute proportional payout
        let input_amount: u64 = inputs
            .iter()
            .try_fold(0u64, |sum, proof| sum.checked_add(u64::from(proof.amount)))
            .ok_or(Error::AmountOverflow)?;
        let (hi_payout, lo_payout) =
            compute_numeric_payout(input_amount, attested_value, lo_bound, hi_bound)?;

        let my_payout = if outcome_collection == "HI" {
            hi_payout
        } else {
            lo_payout
        };

        // Balance check: output_amount <= my_payout (fees handled by swap saga)
        let output_amount: u64 = outputs
            .iter()
            .try_fold(0u64, |sum, output| {
                sum.checked_add(u64::from(output.amount))
            })
            .ok_or(Error::AmountOverflow)?;
        let fee_breakdown = self.get_proofs_fee(inputs).await?;
        let fee: u64 = fee_breakdown.total.into();

        if my_payout < fee || output_amount > (my_payout - fee) {
            return Err(Error::TransactionUnbalanced(my_payout, output_amount, fee));
        }

        // Verify inputs and execute via unbalanced swap saga
        let input_verification = self.verify_inputs(inputs).await?;

        if let Some(witness) = witness {
            record_attestation(&*self.localstore, condition_id, &attested_result, &witness).await?;
        }

        let init_saga = crate::mint::swap::swap_saga::SwapSaga::new(
            self,
            self.localstore.clone(),
            self.pubsub_manager.clone(),
        );

        let setup_saga = init_saga
            .setup_swap_unbalanced(inputs, outputs, None, input_verification)
            .await?;

        let signed_saga = setup_saga.sign_outputs().await?;
        let swap_response = signed_saga.finalize().await?;

        Ok(RedeemOutcomeResponse {
            signatures: swap_response.signatures,
        })
    }
}
