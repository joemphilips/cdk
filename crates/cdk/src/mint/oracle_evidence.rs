//! Shared verification of retained and submitted oracle evidence.

use std::collections::HashMap;

use cdk_common::nuts::nut_ctf::{dlc, from_hex, normalize_outcome, to_hex, OracleWitness};

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
pub(crate) fn verify_threshold(
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
