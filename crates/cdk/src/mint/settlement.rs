//! Side-effect-free preparation for multi-party CTF settlement.

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;
use std::sync::{Arc, Weak};

use cdk_common::mint::MintKeySetInfo;
use cdk_common::nuts::nut00::{BlindedMessage, Proofs};
use cdk_common::nuts::nut02::Id;
use cdk_common::nuts::nut_ctf::settlement::{
    CtfSettlementRequest, CtfSettlementResponse, Error as SettlementError,
    NutCtfSettlementSettings, NutCtfSettlementSettingsError, ParticipantMode,
    PayToUnlockAuthorization,
};
use cdk_common::CurrencyUnit;

use super::conditions::STATUS_PENDING;
use super::ctf_conservation::{
    condition_outcomes, CtfCoverageResolver, OutcomeConservation, ResolvedCoverage,
};
use super::swap::atomic::execute_atomic_ctf_settlement;
use super::{Mint, Verification};
use crate::fees::ProofsFeeBreakdown;
use crate::Error;

/// Prepared facts required by a later atomic multi-party settlement execution.
pub(super) struct PreparedCtfSettlement {
    pub(super) condition_id: String,
    pub(super) participant_output_ranges: Vec<Range<usize>>,
    pub(super) inputs: Proofs,
    pub(super) outputs: Vec<BlindedMessage>,
    pub(super) input_verification: Verification,
    pub(super) output_verification: Verification,
    pub(super) fee: ProofsFeeBreakdown,
}

#[derive(Debug, thiserror::Error)]
/// Validation, configuration, or persistence failure for CTF settlement.
pub enum CtfSettlementError {
    /// The request violates the NUT-CTF-settle wire protocol.
    #[error(transparent)]
    Protocol(#[from] SettlementError),
    /// The advertised settlement capability is internally inconsistent.
    #[error(transparent)]
    Settings(#[from] NutCtfSettlementSettingsError),
    /// Mint verification, signing, or persistence failed.
    #[error(transparent)]
    Mint(#[from] Error),
    /// The condition predates mandatory collateral-unit persistence.
    #[error("condition is missing its collateral unit")]
    MissingCollateralUnit,
    /// An involved keyset does not use the condition collateral unit.
    #[error("settlement keyset unit does not match condition collateral")]
    CollateralUnitMismatch,
    /// At least one participant authorization has already expired.
    #[error("settlement authorization has expired")]
    AuthorizationExpired,
    /// A participant authorization outlives the refundable keyset horizon.
    #[error("settlement authorization does not precede the effective keyset expiry ceiling")]
    AuthorizationBeyondKeysetExpiry,
    /// Computing the bounded authorization horizon overflowed.
    #[error("settlement expiry arithmetic overflow")]
    ExpiryOverflow,
}

impl Mint {
    /// Atomically execute or replay one validated multi-party CTF settlement.
    pub async fn process_ctf_settlement(
        &self,
        request: &CtfSettlementRequest,
        settings: NutCtfSettlementSettings,
        now: u64,
    ) -> Result<CtfSettlementResponse, CtfSettlementError> {
        let request_digest = request.request_digest()?;
        if let Some(response) = self
            .localstore
            .get_ctf_settlement_replay(request_digest)
            .await
            .map_err(Error::from)?
        {
            return Ok(response);
        }

        let flight = self.ctf_settlement_flight(request_digest);
        let _flight_guard = flight.lock().await;
        if let Some(response) = self
            .localstore
            .get_ctf_settlement_replay(request_digest)
            .await
            .map_err(Error::from)?
        {
            return Ok(response);
        }

        let _keyset_snapshot = self.keyset_store_lock.read().await;
        let prepared = self.prepare_ctf_settlement(request, settings, now).await?;
        execute_atomic_ctf_settlement(
            self,
            &prepared.condition_id,
            request_digest,
            &prepared.inputs,
            &prepared.outputs,
            &prepared.participant_output_ranges,
            prepared.input_verification,
            prepared.output_verification,
            prepared.fee,
        )
        .await
        .map_err(CtfSettlementError::Mint)
    }

    fn ctf_settlement_flight(
        &self,
        request_digest: cdk_common::nuts::nut_ctf::settlement::CanonicalHash,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let mut flights = match self.ctf_settlement_flights.lock() {
            Ok(flights) => flights,
            Err(poisoned) => poisoned.into_inner(),
        };
        flights.retain(|_, flight| flight.strong_count() > 0);
        if let Some(flight) = flights.get(&request_digest).and_then(Weak::upgrade) {
            return flight;
        }
        let flight = Arc::new(tokio::sync::Mutex::new(()));
        flights.insert(request_digest, Arc::downgrade(&flight));
        flight
    }

    pub(super) async fn prepare_ctf_settlement(
        &self,
        request: &CtfSettlementRequest,
        settings: NutCtfSettlementSettings,
        now: u64,
    ) -> Result<PreparedCtfSettlement, CtfSettlementError> {
        let limits = settings.structural_limits()?;
        if !request.parent_collection_id.is_zero() {
            return Err(SettlementError::NonRootParentCollection.into());
        }
        let authorizations = request.validated_authorizations(limits)?;
        let condition_id = request.condition_id.to_string();
        let condition = self.load_pending_condition(&condition_id).await?;
        let collateral = condition
            .collateral
            .clone()
            .ok_or(CtfSettlementError::MissingCollateralUnit)?;
        let outcomes = condition_outcomes(&condition)?;
        let effective_expiry_ceiling = self
            .settlement_expiry_ceiling(&condition_id, settings, now)
            .await?;
        validate_authorization_expiries(&authorizations, now, effective_expiry_ceiling)?;

        let resolver = CtfCoverageResolver::new(self, &condition_id, &outcomes)?;
        let coverages = self
            .resolve_settlement_keysets(request, &resolver, &collateral, now)
            .await?;
        let flat = flatten_settlement(request, &coverages, &outcomes)?;
        let fee = self.get_proofs_fee(&flat.inputs).await?;
        flat.conservation.validate(fee.total.into())?;
        let input_verification = self.verify_inputs(&flat.inputs).await?;
        let output_verification = self.verify_outputs(&flat.outputs)?;

        Ok(PreparedCtfSettlement {
            condition_id,
            participant_output_ranges: flat.output_ranges,
            inputs: flat.inputs,
            outputs: flat.outputs,
            input_verification,
            output_verification,
            fee,
        })
    }

    async fn load_pending_condition(
        &self,
        condition_id: &str,
    ) -> Result<cdk_common::mint::StoredCondition, CtfSettlementError> {
        let condition = self
            .localstore
            .get_condition(condition_id)
            .await
            .map_err(Error::from)?
            .ok_or(Error::ConditionNotFound)?;
        if condition.attestation_status != STATUS_PENDING {
            return Err(Error::ConvertNotPermitted.into());
        }
        Ok(condition)
    }

    async fn settlement_expiry_ceiling(
        &self,
        condition_id: &str,
        settings: NutCtfSettlementSettings,
        now: u64,
    ) -> Result<u64, CtfSettlementError> {
        let keysets = self
            .localstore
            .get_conditional_keyset_infos_for_condition(condition_id)
            .await
            .map_err(Error::from)?;
        if keysets.is_empty() {
            return Err(Error::ConditionNotFound.into());
        }
        let expiries = keysets
            .iter()
            .map(|keyset| keyset.final_expiry)
            .collect::<Vec<_>>();
        effective_expiry_ceiling(&expiries, now, settings.max_expiry_seconds())
    }

    async fn resolve_settlement_keysets(
        &self,
        request: &CtfSettlementRequest,
        resolver: &CtfCoverageResolver<'_>,
        collateral: &CurrencyUnit,
        now: u64,
    ) -> Result<HashMap<Id, ResolvedCoverage>, CtfSettlementError> {
        let mut resolved = HashMap::new();
        for id in involved_keysets(request) {
            let info = self.get_keyset_info(&id).ok_or(Error::UnknownKeySet)?;
            validate_involved_keyset(&info, collateral)?;
            resolved.insert(id, resolver.resolve_keyset_at(&id, now).await?);
        }
        Ok(resolved)
    }
}

struct FlatSettlement {
    inputs: Proofs,
    outputs: Vec<BlindedMessage>,
    output_ranges: Vec<Range<usize>>,
    conservation: OutcomeConservation,
}

fn flatten_settlement(
    request: &CtfSettlementRequest,
    coverages: &HashMap<Id, ResolvedCoverage>,
    outcomes: &[String],
) -> Result<FlatSettlement, CtfSettlementError> {
    let mut flat = FlatSettlement {
        inputs: Vec::new(),
        outputs: Vec::new(),
        output_ranges: Vec::with_capacity(request.participants.len()),
        conservation: OutcomeConservation::new(outcomes),
    };
    for participant in &request.participants {
        for proof in &participant.inputs {
            let coverage = coverage_for(coverages, proof.keyset_id)?;
            flat.conservation
                .add_inputs(coverage, std::slice::from_ref(proof))?;
            flat.inputs.push(proof.clone());
        }
        let start = flat.outputs.len();
        for output in &participant.outputs {
            let coverage = coverage_for(coverages, output.keyset_id)?;
            flat.conservation
                .add_outputs(coverage, std::slice::from_ref(output))?;
            flat.outputs.push(output.clone());
        }
        flat.output_ranges.push(start..flat.outputs.len());
    }
    Ok(flat)
}

fn coverage_for(
    coverages: &HashMap<Id, ResolvedCoverage>,
    keyset_id: Id,
) -> Result<&ResolvedCoverage, Error> {
    coverages.get(&keyset_id).ok_or(Error::UnknownKeySet)
}

fn involved_keysets(request: &CtfSettlementRequest) -> BTreeSet<Id> {
    let mut keysets = BTreeSet::new();
    for participant in &request.participants {
        keysets.extend(participant.inputs.iter().map(|proof| proof.keyset_id));
        keysets.extend(participant.outputs.iter().map(|output| output.keyset_id));
        if let ParticipantMode::Pool { manifest, .. } = &participant.mode {
            keysets.extend(manifest.entries().iter().map(|entry| entry.keyset_id));
        }
    }
    keysets
}

fn validate_involved_keyset(
    info: &MintKeySetInfo,
    collateral: &CurrencyUnit,
) -> Result<(), CtfSettlementError> {
    if &info.unit != collateral {
        return Err(CtfSettlementError::CollateralUnitMismatch);
    }
    if info.input_fee_ppk == 0 {
        return Err(SettlementError::ZeroFeeKeyset.into());
    }
    Ok(())
}

fn effective_expiry_ceiling(
    expiries: &[Option<u64>],
    now: u64,
    max_expiry_seconds: u64,
) -> Result<u64, CtfSettlementError> {
    let fallback = now
        .checked_add(max_expiry_seconds)
        .ok_or(CtfSettlementError::ExpiryOverflow)?;
    let explicit = expiries.iter().flatten().copied().min();
    if expiries.iter().any(Option::is_none) {
        Ok(explicit.map_or(fallback, |expiry| expiry.min(fallback)))
    } else {
        explicit.ok_or(CtfSettlementError::ExpiryOverflow)
    }
}

fn validate_authorization_expiries(
    authorizations: &[PayToUnlockAuthorization],
    now: u64,
    ceiling: u64,
) -> Result<(), CtfSettlementError> {
    if authorizations
        .iter()
        .any(|authorization| authorization.expiry <= now)
    {
        return Err(CtfSettlementError::AuthorizationExpired);
    }
    if authorizations
        .iter()
        .any(|authorization| authorization.expiry >= ceiling)
    {
        return Err(CtfSettlementError::AuthorizationBeyondKeysetExpiry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cdk_common::nuts::nut02::Id;
    use cdk_common::nuts::nut_ctf::settlement::{PayToUnlockAuthorization, PayToUnlockCondition};
    use cdk_common::secret::Secret;
    use serde_json::json;

    use super::{effective_expiry_ceiling, validate_authorization_expiries, CtfSettlementError};

    const KEYSET: &str = "00deadbeef123456";
    const REFUND_KEY: &str = "194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104";

    #[test]
    fn effective_expiry_ceiling_matches_explicit_and_fallback_rules() {
        let cases = [
            (vec![Some(150), Some(140)], 200, 140),
            (vec![Some(250), None], 200, 200),
            (vec![Some(150), None], 200, 150),
            (vec![None, None], 200, 200),
        ];
        for (expiries, max_expiry_seconds, expected) in cases {
            assert_eq!(
                effective_expiry_ceiling(&expiries, 0, max_expiry_seconds).unwrap(),
                expected
            );
        }
        assert!(matches!(
            effective_expiry_ceiling(&[None], u64::MAX, 1),
            Err(CtfSettlementError::ExpiryOverflow)
        ));
    }

    #[test]
    fn authorization_expiry_is_strict_at_now_and_ceiling() {
        let now = 100;
        let ceiling = 200;
        assert!(validate_authorization_expiries(&[authorization(101)], now, ceiling).is_ok());
        assert!(matches!(
            validate_authorization_expiries(&[authorization(now)], now, ceiling),
            Err(CtfSettlementError::AuthorizationExpired)
        ));
        assert!(matches!(
            validate_authorization_expiries(&[authorization(ceiling)], now, ceiling),
            Err(CtfSettlementError::AuthorizationBeyondKeysetExpiry)
        ));
    }

    fn authorization(expiry: u64) -> PayToUnlockAuthorization {
        let secret = Secret::new(
            json!([
                "PAY_TO_UNLOCK",
                {
                    "nonce": "01".repeat(32),
                    "data": "02".repeat(32),
                    "tags": [
                        ["offer_keyset", Id::from_str(KEYSET).unwrap().to_string()],
                        ["expiry", expiry.to_string()],
                        ["refund", REFUND_KEY]
                    ]
                }
            ])
            .to_string(),
        );
        PayToUnlockCondition::parse(&secret)
            .unwrap()
            .authorization()
    }
}
