//! Reusable CTF keyset coverage and per-outcome conservation.

use std::collections::HashMap;

use cdk_common::mint::{MintKeySetInfo, StoredCondition};
use cdk_common::nuts::nut00::{BlindedMessage, Proof};
use cdk_common::nuts::nut02::Id;
use cdk_common::nuts::nut_ctf::{
    canonical_outcome_collection, compute_outcome_collection_id, from_hex,
    parse_outcome_collection, to_hex, ZERO_COLLECTION_ID,
};
use cdk_common::CurrencyUnit;

use super::Mint;
use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
enum AssetKind {
    Collateral,
    Conditional {
        collection: String,
        collection_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssetCoverage {
    kind: AssetKind,
    outcomes: Vec<String>,
    unit: CurrencyUnit,
}

/// Resolves mint keysets to their CTF payoff coverage.
pub(super) struct CtfCoverageResolver<'a> {
    mint: &'a Mint,
    condition_id: &'a str,
    condition_id_bytes: [u8; 32],
    outcomes: &'a [String],
}

impl<'a> CtfCoverageResolver<'a> {
    pub(super) fn new(
        mint: &'a Mint,
        condition_id: &'a str,
        outcomes: &'a [String],
    ) -> Result<Self, Error> {
        Ok(Self {
            mint,
            condition_id,
            condition_id_bytes: hex_32(condition_id)?,
            outcomes,
        })
    }

    pub(super) async fn resolve_input_entry(
        &self,
        key: &str,
        proofs: &[Proof],
    ) -> Result<ResolvedCoverage, Error> {
        self.resolve_declared_keysets(key, proofs.iter().map(|proof| &proof.keyset_id))
            .await
    }

    pub(super) async fn resolve_output_entry(
        &self,
        key: &str,
        outputs: &[BlindedMessage],
    ) -> Result<ResolvedCoverage, Error> {
        self.resolve_declared_keysets(key, outputs.iter().map(|output| &output.keyset_id))
            .await
    }

    async fn resolve_declared_keysets<'b>(
        &self,
        key: &str,
        keysets: impl Iterator<Item = &'b Id>,
    ) -> Result<ResolvedCoverage, Error> {
        let expected = self.expected_asset(key)?;
        let mut resolved = None;
        for keyset in keysets {
            let coverage = self.resolve_keyset(keyset).await?;
            if coverage.kind != expected {
                return Err(Error::OutputsMustUseRegularKeyset);
            }
            check_unit(&mut resolved, coverage)?;
        }
        resolved.map(ResolvedCoverage).ok_or(Error::UnknownKeySet)
    }

    fn expected_asset(&self, key: &str) -> Result<AssetKind, Error> {
        if key == "*" {
            return Ok(AssetKind::Collateral);
        }
        let collection = canonical_collection(key, self.outcomes)?;
        if collection != key {
            return Err(Error::ConvertPayoffFeeViolation);
        }
        Ok(AssetKind::Conditional {
            collection: collection.clone(),
            collection_id: root_collection_id(&self.condition_id_bytes, &collection)?,
        })
    }

    pub(super) async fn resolve_keyset_at(
        &self,
        keyset: &Id,
        now: u64,
    ) -> Result<ResolvedCoverage, Error> {
        let keyset_info = self.active_keyset_info(keyset, now)?;
        let binding = self
            .mint
            .localstore
            .get_condition_for_keyset(keyset)
            .await?;
        let kind = self.resolve_binding(binding)?;
        let outcomes = match &kind {
            AssetKind::Collateral => self.outcomes.to_vec(),
            AssetKind::Conditional { collection, .. } => parse_outcome_collection(collection),
        };
        Ok(ResolvedCoverage(AssetCoverage {
            kind,
            outcomes,
            unit: keyset_info.unit,
        }))
    }

    async fn resolve_keyset(&self, keyset: &Id) -> Result<AssetCoverage, Error> {
        Ok(self
            .resolve_keyset_at(keyset, cdk_common::util::unix_time())
            .await?
            .0)
    }

    fn resolve_binding(
        &self,
        binding: Option<(String, String, String)>,
    ) -> Result<AssetKind, Error> {
        match binding {
            None => Ok(AssetKind::Collateral),
            Some((condition_id, collection, collection_id))
                if condition_id == self.condition_id =>
            {
                let canonical = canonical_collection(&collection, self.outcomes)
                    .map_err(|_| Error::OutputsMustUseRegularKeyset)?;
                let expected = root_collection_id(&self.condition_id_bytes, &canonical)
                    .map_err(|_| Error::OutputsMustUseRegularKeyset)?;
                if collection != canonical || collection_id != expected {
                    return Err(Error::OutputsMustUseRegularKeyset);
                }
                Ok(AssetKind::Conditional {
                    collection,
                    collection_id,
                })
            }
            _ => Err(Error::OutputsMustUseRegularKeyset),
        }
    }

    fn active_keyset_info(&self, keyset: &Id, now: u64) -> Result<MintKeySetInfo, Error> {
        let info = self
            .mint
            .get_keyset_info(keyset)
            .ok_or(Error::UnknownKeySet)?;
        if !info.active {
            return Err(Error::InactiveKeyset);
        }
        if info.final_expiry.is_some_and(|expiry| expiry < now) {
            return Err(Error::ExpiredKeyset);
        }
        Ok(info)
    }
}

/// Coverage resolved from one declared CTF input or output entry.
#[derive(Clone)]
pub(super) struct ResolvedCoverage(AssetCoverage);

/// Checked aggregate input/output value for every possible outcome.
pub(super) struct OutcomeConservation {
    balances: HashMap<String, OutcomeBalance>,
    unit: Option<CurrencyUnit>,
}

#[derive(Debug, Clone, Copy, Default)]
struct OutcomeBalance {
    inputs: u64,
    outputs: u64,
}

impl OutcomeConservation {
    pub(super) fn new(outcomes: &[String]) -> Self {
        Self {
            balances: outcomes
                .iter()
                .map(|outcome| (outcome.clone(), OutcomeBalance::default()))
                .collect(),
            unit: None,
        }
    }

    pub(super) fn add_inputs(
        &mut self,
        coverage: &ResolvedCoverage,
        proofs: &[Proof],
    ) -> Result<(), Error> {
        let amount = checked_amount_sum(proofs.iter().map(|proof| u64::from(proof.amount)))?;
        self.add(coverage, amount, BalanceSide::Input)
    }

    pub(super) fn add_outputs(
        &mut self,
        coverage: &ResolvedCoverage,
        outputs: &[BlindedMessage],
    ) -> Result<(), Error> {
        let amount = checked_amount_sum(outputs.iter().map(|output| u64::from(output.amount)))?;
        self.add(coverage, amount, BalanceSide::Output)
    }

    pub(super) fn validate(&self, fee: u64) -> Result<(), Error> {
        if fee == 0 {
            return Err(Error::ConvertPayoffFeeViolation);
        }
        for balance in self.balances.values() {
            if balance.inputs < fee || balance.outputs != balance.inputs - fee {
                return Err(Error::ConvertPayoffFeeViolation);
            }
        }
        Ok(())
    }

    fn add(
        &mut self,
        coverage: &ResolvedCoverage,
        amount: u64,
        side: BalanceSide,
    ) -> Result<(), Error> {
        if amount == 0 {
            return Err(Error::ConvertPayoffFeeViolation);
        }
        check_currency_unit(&mut self.unit, &coverage.0.unit)?;
        for outcome in &coverage.0.outcomes {
            let balance = self
                .balances
                .get_mut(outcome)
                .ok_or(Error::ConvertPayoffFeeViolation)?;
            let value = match side {
                BalanceSide::Input => &mut balance.inputs,
                BalanceSide::Output => &mut balance.outputs,
            };
            *value = value
                .checked_add(amount)
                .ok_or(Error::ConvertPayoffFeeViolation)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum BalanceSide {
    Input,
    Output,
}

pub(super) fn condition_outcomes(condition: &StoredCondition) -> Result<Vec<String>, Error> {
    if condition.condition_type == "numeric" {
        return Ok(vec!["HI".to_string(), "LO".to_string()]);
    }
    let announcements: Vec<String> = serde_json::from_str(&condition.announcements_json)?;
    let first = announcements.first().ok_or(Error::ConditionNotFound)?;
    let announcement = cdk_common::nuts::nut_ctf::dlc::parse_oracle_announcement(first)?;
    cdk_common::nuts::nut_ctf::dlc::extract_outcomes(&announcement).map_err(Error::from)
}

fn check_unit(resolved: &mut Option<AssetCoverage>, coverage: AssetCoverage) -> Result<(), Error> {
    match resolved {
        Some(current) if current.kind != coverage.kind => Err(Error::OutputsMustUseRegularKeyset),
        Some(current) if current.unit != coverage.unit => Err(Error::MultipleUnits),
        Some(_) => Ok(()),
        None => {
            *resolved = Some(coverage);
            Ok(())
        }
    }
}

fn check_currency_unit(
    expected: &mut Option<CurrencyUnit>,
    actual: &CurrencyUnit,
) -> Result<(), Error> {
    match expected {
        Some(unit) if unit != actual => Err(Error::MultipleUnits),
        Some(_) => Ok(()),
        None => {
            *expected = Some(actual.clone());
            Ok(())
        }
    }
}

fn checked_amount_sum(mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    amounts.try_fold(0u64, |sum, amount| {
        sum.checked_add(amount)
            .ok_or(Error::ConvertPayoffFeeViolation)
    })
}

fn canonical_collection(key: &str, outcomes: &[String]) -> Result<String, Error> {
    let members = parse_outcome_collection(key);
    canonical_outcome_collection(outcomes, &members).map_err(Error::from)
}

fn root_collection_id(condition_id: &[u8; 32], canonical: &str) -> Result<String, Error> {
    let zero_parent = hex_32(ZERO_COLLECTION_ID)?;
    let id = compute_outcome_collection_id(&zero_parent, condition_id, canonical)?;
    Ok(to_hex(&id))
}

fn hex_32(hex: &str) -> Result<[u8; 32], Error> {
    let bytes = from_hex(hex)?;
    bytes.try_into().map_err(|_| Error::InvalidConditionId)
}
