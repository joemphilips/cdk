//! Strict seed recovery for ordinary and conditional wallet keysets.

use std::collections::{HashMap, HashSet};
#[cfg(feature = "conditional-tokens")]
use std::str::FromStr;

use cdk_common::database::wallet::OrdinaryRestoreAdmission;
#[cfg(feature = "conditional-tokens")]
use cdk_common::database::wallet::{
    ConditionalRestoreAdmission, ConditionalRestoreAdmissionMode, ConditionalRestoreAdmissionResult,
};
use cdk_common::wallet::{ProofInfo, Restored};
use tracing::instrument;

use super::Wallet;
#[cfg(feature = "conditional-tokens")]
use super::{
    validate_conditional_keyset_catalogue_request, validate_conditional_keyset_catalogue_response,
    MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES,
};
use crate::dhke::construct_proofs;
#[cfg(test)]
use crate::nuts::nut00::BlindSignature;
#[cfg(feature = "conditional-tokens")]
use crate::nuts::nut02::KeySetVersion;
#[cfg(feature = "conditional-tokens")]
use crate::nuts::nut_ctf::{
    compute_outcome_collection_id, ConditionalKeySetInfo, ConditionalKeysetCatalogueSettings,
    GetConditionalKeysetsRequest,
};
use crate::nuts::{
    CheckStateRequest, CheckStateResponse, Id, KeySet, KeySetInfo, Keys, PreMintSecrets, Proof,
    ProofState, RestoreRequest, RestoreResponse, State,
};
#[cfg(test)]
use crate::Amount;
use crate::Error;

const RESTORE_BATCH_SIZE: u32 = 100;
const MAX_CONSECUTIVE_EMPTY_BATCHES: u8 = 3;
const MAX_RESTORE_BATCHES_PER_KEYSET: u32 = 10_000;
const MAX_RESTORE_KEYSETS: usize = 10_000;
const MAX_RESTORE_KEYS_PER_KEYSET: usize = 1_024;
const MAX_RESTORE_TOTAL_PROOFS: usize = 100_000;
const MAX_RESTORE_TOTAL_BYTES: usize = 64 * 1_024 * 1_024;
const MAX_RESTORE_TOTAL_WORK_UNITS: usize = 1_000_000;

#[cfg(feature = "conditional-tokens")]
const MAX_CONDITIONAL_CATALOGUE_PAGES: usize = 1_000;
#[cfg(feature = "conditional-tokens")]
const MAX_CONDITIONAL_CATALOGUE_KEYSETS: usize = 10_000;
#[cfg(feature = "conditional-tokens")]
const MAX_CONDITIONAL_CATALOGUE_TOTAL_BYTES: usize = 64 * 1_024 * 1_024;

#[derive(Debug)]
struct BoundRestoreProof {
    proof: Proof,
    state: State,
}

#[derive(Debug)]
struct BoundRestoreBatch {
    proofs: Vec<BoundRestoreProof>,
    counter_floor: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct RestoreLimits {
    proofs: usize,
    bytes: usize,
    work_units: usize,
}

impl Default for RestoreLimits {
    fn default() -> Self {
        Self {
            proofs: MAX_RESTORE_TOTAL_PROOFS,
            bytes: MAX_RESTORE_TOTAL_BYTES,
            work_units: MAX_RESTORE_TOTAL_WORK_UNITS,
        }
    }
}

#[derive(Debug)]
struct RestoreBudget {
    limits: RestoreLimits,
    proofs: usize,
    bytes: usize,
    work_units: usize,
}

impl RestoreBudget {
    fn new(limits: RestoreLimits) -> Self {
        Self {
            limits,
            proofs: 0,
            bytes: 0,
            work_units: 0,
        }
    }

    fn charge_proofs(&mut self, count: usize) -> Result<(), Error> {
        self.proofs = checked_budget_add(self.proofs, count, self.limits.proofs, "proof")?;
        Ok(())
    }

    fn charge_work(&mut self, count: usize) -> Result<(), Error> {
        self.work_units =
            checked_budget_add(self.work_units, count, self.limits.work_units, "work")?;
        Ok(())
    }

    fn charge_serialized<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize,
    {
        let bytes = serde_json::to_vec(value)?.len();
        self.bytes = checked_budget_add(self.bytes, bytes, self.limits.bytes, "byte")?;
        Ok(())
    }

    fn charge_keyset(&mut self, keyset: &KeySet) -> Result<(), Error> {
        if keyset.keys.len() > MAX_RESTORE_KEYS_PER_KEYSET {
            return Err(invalid_restore(
                "restore keyset exceeded its amount-key bound",
            ));
        }
        self.charge_work(keyset.keys.len().saturating_add(1))?;
        self.charge_serialized(keyset)
    }
}

#[derive(Debug)]
enum RestoreKeysetInput {
    Ordinary {
        keyset: KeySetInfo,
        keys: KeySet,
    },
    #[cfg(feature = "conditional-tokens")]
    Conditional {
        conditional_keyset: ConditionalKeySetInfo,
        keyset: KeySetInfo,
        keys: KeySet,
    },
}

impl RestoreKeysetInput {
    fn keyset(&self) -> &KeySetInfo {
        match self {
            Self::Ordinary { keyset, .. } => keyset,
            #[cfg(feature = "conditional-tokens")]
            Self::Conditional { keyset, .. } => keyset,
        }
    }

    fn keys(&self) -> &KeySet {
        match self {
            Self::Ordinary { keys, .. } => keys,
            #[cfg(feature = "conditional-tokens")]
            Self::Conditional { keys, .. } => keys,
        }
    }
}

impl Wallet {
    /// Restore proofs deterministically derived from this wallet's seed.
    ///
    /// Clones of this wallet are serialized for the full recovery scan. The
    /// caller must additionally ensure that no independently constructed
    /// wallet/profile using the same seed, storage, mint, and unit mutates the
    /// profile until this call returns.
    #[instrument(skip(self))]
    pub async fn restore(&self) -> Result<Restored, Error> {
        let _restore_guard = self.restore_lock.lock().await;
        self.restore_with_limits(RestoreLimits::default()).await
    }

    async fn restore_with_limits(&self, limits: RestoreLimits) -> Result<Restored, Error> {
        let mut budget = RestoreBudget::new(limits);
        // Recovery decisions must use one fresh metadata snapshot. In
        // particular, do not call `fetch_mint_info`: its optional clock-skew
        // check would make recovery depend on a field the protocol does not
        // require a mint to advertise.
        let metadata = self
            .metadata_cache
            .load_from_mint_for_recovery(&self.localstore, &self.client, MAX_RESTORE_KEYSETS)
            .await?;
        budget.charge_serialized(&metadata.mint_info)?;

        #[cfg(feature = "conditional-tokens")]
        let (conditional_catalogue, effective_time) = self
            .scan_conditional_catalogue(&metadata.mint_info, &mut budget)
            .await?;

        #[cfg(not(feature = "conditional-tokens"))]
        let conditional_catalogue: Vec<()> = Vec::new();

        if metadata.ordinary_keyset_ids.len() > MAX_RESTORE_KEYSETS
            || metadata
                .ordinary_keyset_ids
                .len()
                .checked_add(conditional_catalogue.len())
                .is_none_or(|count| count > MAX_RESTORE_KEYSETS)
        {
            return Err(invalid_restore("mint advertised too many recovery keysets"));
        }

        #[cfg(feature = "conditional-tokens")]
        let conditional_ids: HashSet<Id> = conditional_catalogue
            .iter()
            .map(|keyset| keyset.id)
            .collect();
        #[cfg(not(feature = "conditional-tokens"))]
        let conditional_ids: HashSet<Id> = HashSet::new();

        #[cfg(feature = "conditional-tokens")]
        validate_restore_namespaces(&metadata.ordinary_keyset_ids, &conditional_catalogue)?;

        let mut inputs = Vec::new();
        #[cfg(feature = "conditional-tokens")]
        let mut deliberately_skipped_expired_keyset = false;
        for keyset_id in &metadata.ordinary_keyset_ids {
            let keyset = metadata.keysets.get(keyset_id).ok_or_else(|| {
                invalid_restore("fresh ordinary keyset listing was missing from metadata")
            })?;
            if keyset.unit != self.unit || conditional_ids.contains(&keyset.id) {
                continue;
            }
            let keys = metadata.keys.get(&keyset.id).ok_or(Error::UnknownKeySet)?;
            let input = prepare_ordinary_restore_keyset(keyset, keys)?;
            budget.charge_keyset(input.keys())?;
            inputs.push(input);
        }

        #[cfg(feature = "conditional-tokens")]
        for conditional_keyset in conditional_catalogue {
            let keyset_unit = validate_conditional_keyset_semantics(&conditional_keyset)?;
            if keyset_unit != self.unit {
                continue;
            }
            let current_effective_time = self
                .localstore
                .advance_conditional_restore_high_water(
                    self.mint_url.clone(),
                    self.unit.clone(),
                    crate::util::unix_time(),
                )
                .await?
                .max(effective_time);
            if conditional_keyset
                .final_expiry
                .is_some_and(|expiry| expiry <= current_effective_time)
            {
                deliberately_skipped_expired_keyset = true;
                continue;
            }

            inputs.push(
                self.prepare_conditional_restore_keyset(conditional_keyset)
                    .await
                    .and_then(|input| {
                        budget.charge_keyset(input.keys())?;
                        Ok(input)
                    })?,
            );
        }

        if inputs.len() > MAX_RESTORE_KEYSETS {
            return Err(invalid_restore(
                "mint advertised too many applicable keysets",
            ));
        }

        if inputs.is_empty() {
            #[cfg(feature = "conditional-tokens")]
            if deliberately_skipped_expired_keyset {
                return Ok(Restored::default());
            }
            return Err(Error::UnknownKeySet);
        }

        let mut restored = Restored::default();
        for input in inputs {
            self.restore_keyset(input, &mut restored, &mut budget)
                .await?;
        }
        Ok(restored)
    }

    async fn restore_keyset(
        &self,
        input: RestoreKeysetInput,
        restored: &mut Restored,
        budget: &mut RestoreBudget,
    ) -> Result<(), Error> {
        let mut start_counter = 0_u32;
        let mut empty_batches = 0_u8;
        let mut batches = 0_u32;

        while empty_batches < MAX_CONSECUTIVE_EMPTY_BATCHES {
            #[cfg(feature = "conditional-tokens")]
            if let RestoreKeysetInput::Conditional {
                conditional_keyset, ..
            } = &input
            {
                let effective_time = self
                    .localstore
                    .advance_conditional_restore_high_water(
                        self.mint_url.clone(),
                        self.unit.clone(),
                        crate::util::unix_time(),
                    )
                    .await?;
                if conditional_keyset
                    .final_expiry
                    .is_some_and(|expiry| expiry <= effective_time)
                {
                    return Ok(());
                }
            }
            if batches >= MAX_RESTORE_BATCHES_PER_KEYSET {
                return Err(invalid_restore(
                    "restore scan exceeded its per-keyset bound",
                ));
            }
            batches = batches
                .checked_add(1)
                .ok_or_else(|| invalid_restore("restore batch counter overflow"))?;
            let end_counter = start_counter
                .checked_add(RESTORE_BATCH_SIZE)
                .ok_or_else(|| invalid_restore("restore derivation counter overflow"))?;
            budget.charge_work(RESTORE_BATCH_SIZE as usize)?;
            let premint = PreMintSecrets::restore_batch(
                input.keyset().id,
                &self.seed,
                start_counter,
                end_counter,
            )?;

            let response = self
                .client
                .post_restore(RestoreRequest {
                    outputs: premint.blinded_messages(),
                })
                .await?;
            budget.charge_serialized(&response)?;
            budget.charge_proofs(response.outputs.len())?;
            let matched =
                bind_restore_response(&premint, response, &input.keys().keys, start_counter)?;

            if matched.proofs.is_empty() {
                empty_batches = empty_batches
                    .checked_add(1)
                    .ok_or_else(|| invalid_restore("empty restore batch counter overflow"))?;
                start_counter = end_counter;
                continue;
            }

            empty_batches = 0;
            let states = self
                .client
                .post_check_state(CheckStateRequest {
                    ys: matched
                        .proofs
                        .iter()
                        .map(|bound| bound.proof.y())
                        .collect::<Result<Vec<_>, _>>()?,
                })
                .await?;
            budget.charge_serialized(&states)?;
            budget.charge_work(states.states.len())?;
            let bound = bind_check_state_response(matched, states)?;

            match &input {
                RestoreKeysetInput::Ordinary { keyset, .. } => {
                    self.commit_ordinary_restore_batch(keyset, &bound, restored)
                        .await?;
                }
                #[cfg(feature = "conditional-tokens")]
                RestoreKeysetInput::Conditional {
                    conditional_keyset,
                    keyset,
                    keys,
                } => {
                    self.commit_conditional_restore_batch(
                        conditional_keyset,
                        keyset,
                        keys,
                        &bound,
                        restored,
                    )
                    .await?;
                }
            }

            start_counter = end_counter;
        }

        Ok(())
    }

    async fn commit_ordinary_restore_batch(
        &self,
        keyset: &KeySetInfo,
        bound: &BoundRestoreBatch,
        restored: &mut Restored,
    ) -> Result<(), Error> {
        let candidate_restored = tallied_restored(restored, &bound.proofs)?;
        let proof_infos = proof_infos(bound, self, &keyset.unit)?;
        let held = proof_infos
            .iter()
            .filter(|proof| matches!(proof.state, State::Unspent | State::Pending))
            .cloned()
            .collect();
        let spent_proofs = proof_infos
            .iter()
            .filter(|proof| proof.state == State::Spent)
            .cloned()
            .collect();
        let counter_floor = bound
            .counter_floor
            .ok_or_else(|| invalid_restore("non-empty restore batch had no counter floor"))?;
        self.localstore
            .commit_ordinary_restore(OrdinaryRestoreAdmission {
                mint_url: self.mint_url.clone(),
                unit: keyset.unit.clone(),
                keyset_id: keyset.id,
                proofs: held,
                spent_proofs,
                counter_floor,
            })
            .await?;
        *restored = candidate_restored;
        Ok(())
    }

    #[cfg(feature = "conditional-tokens")]
    async fn scan_conditional_catalogue(
        &self,
        mint_info: &crate::nuts::MintInfo,
        budget: &mut RestoreBudget,
    ) -> Result<(Vec<ConditionalKeySetInfo>, u64), Error> {
        let Some(ctf) = mint_info.nuts.nut_ctf.as_ref() else {
            return Ok((Vec::new(), crate::util::unix_time()));
        };
        if !ctf.supported {
            return Ok((Vec::new(), crate::util::unix_time()));
        }
        let capability = ctf.conditional_keyset_catalogue.ok_or_else(|| {
            invalid_catalogue("mint supports conditional tokens without authenticated recovery")
        })?;
        validate_frozen_capability(capability)?;

        // Persist the rollback-resistant clock observation before the first
        // catalogue request. A crash or hostile response cannot roll it back.
        let effective_time = self
            .localstore
            .advance_conditional_restore_high_water(
                self.mint_url.clone(),
                self.unit.clone(),
                crate::util::unix_time(),
            )
            .await?;

        let mut cursor = None;
        let mut seen_cursors = HashSet::new();
        let mut seen_keysets = HashMap::new();
        let mut keysets = Vec::new();
        let mut total_bytes = 0_usize;

        for _ in 0..MAX_CONDITIONAL_CATALOGUE_PAGES {
            let request = GetConditionalKeysetsRequest {
                catalogue_version: Some(capability.version),
                limit: Some(capability.max_page_size),
                cursor: cursor.clone(),
                ..Default::default()
            };
            validate_conditional_keyset_catalogue_request(&request, capability.max_page_size)?;
            let mut response = self
                .client
                .get_conditional_keysets_page(request.clone())
                .await?;
            budget.charge_serialized(&response)?;
            budget.charge_work(response.keysets.len().saturating_add(1))?;
            let response_bytes = serde_json::to_vec(&response)?.len();
            if response_bytes > MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES {
                return Err(invalid_catalogue("catalogue page exceeded its byte bound"));
            }
            total_bytes = total_bytes
                .checked_add(response_bytes)
                .ok_or_else(|| invalid_catalogue("catalogue byte count overflow"))?;
            if total_bytes > MAX_CONDITIONAL_CATALOGUE_TOTAL_BYTES {
                return Err(invalid_catalogue(
                    "catalogue scan exceeded its total byte bound",
                ));
            }

            validate_conditional_keyset_catalogue_response(
                &request,
                &mut response,
                capability.max_page_size,
            )?;
            for keyset in response.keysets {
                if let Some(index) = seen_keysets.get(&keyset.id).copied() {
                    if keysets[index] != keyset {
                        return Err(invalid_catalogue(
                            "catalogue repeated a keyset id with conflicting metadata",
                        ));
                    }
                    continue;
                }
                if keysets.len() >= MAX_CONDITIONAL_CATALOGUE_KEYSETS {
                    return Err(invalid_catalogue(
                        "catalogue scan exceeded its keyset bound",
                    ));
                }
                seen_keysets.insert(keyset.id, keysets.len());
                keysets.push(keyset);
            }

            if response.complete {
                let current = self
                    .client
                    .get_mint_info()
                    .await?
                    .nuts
                    .nut_ctf
                    .filter(|settings| settings.supported)
                    .and_then(|settings| settings.conditional_keyset_catalogue);
                if current != Some(capability) {
                    return Err(invalid_catalogue(
                        "mint changed catalogue capability during recovery",
                    ));
                }
                return Ok((keysets, effective_time));
            }

            let next = response
                .next_cursor
                .ok_or_else(|| invalid_catalogue("incomplete catalogue page omitted its cursor"))?;
            if !seen_cursors.insert(next.clone()) {
                return Err(invalid_catalogue("catalogue cursor cycle detected"));
            }
            cursor = Some(next);
        }

        Err(invalid_catalogue("catalogue scan exceeded its page bound"))
    }

    #[cfg(feature = "conditional-tokens")]
    async fn prepare_conditional_restore_keyset(
        &self,
        conditional_keyset: ConditionalKeySetInfo,
    ) -> Result<RestoreKeysetInput, Error> {
        let conditional_unit = validate_conditional_keyset_semantics(&conditional_keyset)?;
        if conditional_unit != self.unit {
            return Err(invalid_restore(
                "conditional keyset was prepared for the wrong wallet unit",
            ));
        }
        let keys = self.client.get_mint_keyset(conditional_keyset.id).await?;
        validate_conditional_keys(&conditional_keyset, &keys, &self.unit)?;
        let keyset = KeySetInfo {
            id: conditional_keyset.id,
            unit: self.unit.clone(),
            active: false,
            input_fee_ppk: conditional_keyset.input_fee_ppk.unwrap_or_default(),
            final_expiry: conditional_keyset.final_expiry,
        };
        Ok(RestoreKeysetInput::Conditional {
            conditional_keyset,
            keyset,
            keys,
        })
    }

    #[cfg(feature = "conditional-tokens")]
    async fn commit_conditional_restore_batch(
        &self,
        conditional_keyset: &ConditionalKeySetInfo,
        keyset: &KeySetInfo,
        keys: &KeySet,
        bound: &BoundRestoreBatch,
        restored: &mut Restored,
    ) -> Result<(), Error> {
        let candidate_restored = tallied_restored(restored, &bound.proofs)?;
        let proof_infos = proof_infos(bound, self, &keyset.unit)?;
        let held: Vec<_> = proof_infos
            .iter()
            .filter(|proof| matches!(proof.state, State::Unspent | State::Pending))
            .cloned()
            .collect();
        let spent_proofs = proof_infos
            .iter()
            .filter(|proof| proof.state == State::Spent)
            .cloned()
            .collect();
        let mode = if held.is_empty() {
            ConditionalRestoreAdmissionMode::ProgressOnly
        } else {
            ConditionalRestoreAdmissionMode::HeldProofs
        };
        let counter_floor = bound
            .counter_floor
            .ok_or_else(|| invalid_restore("non-empty restore batch had no counter floor"))?;
        let admission = ConditionalRestoreAdmission {
            mint_url: self.mint_url.clone(),
            unit: self.unit.clone(),
            observed_wall_time: crate::util::unix_time(),
            mode,
            conditional_keyset: conditional_keyset.clone(),
            keyset: keyset.clone(),
            keys: keys.clone(),
            proofs: held,
            spent_proofs,
            counter_floor,
        };
        match self
            .localstore
            .commit_conditional_restore(admission)
            .await?
        {
            ConditionalRestoreAdmissionResult::HeldProofs { .. } => {
                self.metadata_cache
                    .install_recovered_keyset(
                        conditional_keyset.clone(),
                        keyset.clone(),
                        keys.keys.clone(),
                    )
                    .await?;
                *restored = candidate_restored;
                Ok(())
            }
            ConditionalRestoreAdmissionResult::ProgressOnly { .. } => {
                *restored = candidate_restored;
                Ok(())
            }
            ConditionalRestoreAdmissionResult::Expired { .. } => Ok(()),
        }
    }
}

fn bind_restore_response(
    premint: &PreMintSecrets,
    response: RestoreResponse,
    keys: &Keys,
    start_counter: u32,
) -> Result<BoundRestoreBatch, Error> {
    if response.outputs.len() != response.signatures.len() {
        return Err(invalid_restore(
            "restore response output and signature lengths differ",
        ));
    }
    if response.outputs.len() > premint.secrets.len() {
        return Err(invalid_restore("restore response exceeded request length"));
    }

    let mut requested = HashMap::with_capacity(premint.secrets.len());
    for (index, secret) in premint.secrets.iter().enumerate() {
        if requested
            .insert(secret.blinded_message.blinded_secret, (index, secret))
            .is_some()
        {
            return Err(invalid_restore(
                "restore request contained duplicate outputs",
            ));
        }
    }

    let mut matched = Vec::with_capacity(response.outputs.len());
    let mut seen_outputs = HashSet::with_capacity(response.outputs.len());
    let mut seen_signatures = HashSet::with_capacity(response.signatures.len());
    for (output, signature) in response.outputs.into_iter().zip(response.signatures) {
        if !seen_outputs.insert(output.blinded_secret) {
            return Err(invalid_restore("restore response repeated an output"));
        }
        if !seen_signatures.insert(signature.c) {
            return Err(invalid_restore("restore response repeated a signature"));
        }
        let (index, secret) = requested
            .get(&output.blinded_secret)
            .copied()
            .ok_or_else(|| invalid_restore("restore response contained a foreign output"))?;
        if output != secret.blinded_message {
            return Err(invalid_restore("restore response mutated output metadata"));
        }
        if signature.keyset_id != premint.keyset_id {
            return Err(invalid_restore("restore signature used a foreign keyset"));
        }
        let amount_key = keys
            .get(&signature.amount)
            .copied()
            .ok_or_else(|| invalid_restore("restore signature used an unknown amount"))?;
        // NUT-09 echoes the blank restore output (amount zero); the recovered
        // denomination exists only on the signature. Bind it to an advertised
        // amount key and verify DLEQ whenever the mint supplied one.
        match signature.verify_dleq(amount_key, output.blinded_secret) {
            Ok(()) | Err(crate::nuts::nut12::Error::MissingDleqProof) => {}
            Err(_) => return Err(Error::CouldNotVerifyDleq),
        }
        matched.push((index, secret, signature));
    }
    matched.sort_by_key(|(index, _, _)| *index);

    let counter_floor = matched
        .last()
        .map(|(index, _, _)| {
            u32::try_from(*index)
                .ok()
                .and_then(|index| start_counter.checked_add(index))
                .and_then(|counter| counter.checked_add(1))
                .ok_or_else(|| invalid_restore("restore counter floor overflow"))
        })
        .transpose()?;
    let proofs = construct_proofs(
        matched
            .iter()
            .map(|(_, _, signature)| signature.clone())
            .collect(),
        matched
            .iter()
            .map(|(_, secret, _)| secret.r.clone())
            .collect(),
        matched
            .iter()
            .map(|(_, secret, _)| secret.secret.clone())
            .collect(),
        keys,
    )?;
    Ok(BoundRestoreBatch {
        proofs: proofs
            .into_iter()
            .map(|proof| BoundRestoreProof {
                proof,
                state: State::Unspent,
            })
            .collect(),
        counter_floor,
    })
}

fn bind_check_state_response(
    mut batch: BoundRestoreBatch,
    response: CheckStateResponse,
) -> Result<BoundRestoreBatch, Error> {
    if response.states.len() != batch.proofs.len() {
        return Err(invalid_restore(
            "check-state response did not contain the exact requested set",
        ));
    }
    let mut states = HashMap::with_capacity(response.states.len());
    for ProofState { y, state, .. } in response.states {
        if !matches!(state, State::Spent | State::Unspent | State::Pending) {
            return Err(invalid_restore(
                "check-state response contained a wallet-local state",
            ));
        }
        if states.insert(y, state).is_some() {
            return Err(invalid_restore("check-state response repeated a proof Y"));
        }
    }
    for bound in &mut batch.proofs {
        let y = bound.proof.y()?;
        bound.state = states
            .remove(&y)
            .ok_or_else(|| invalid_restore("check-state response omitted a proof Y"))?;
    }
    if !states.is_empty() {
        return Err(invalid_restore(
            "check-state response contained a foreign proof Y",
        ));
    }
    Ok(batch)
}

fn proof_infos(
    batch: &BoundRestoreBatch,
    wallet: &Wallet,
    unit: &crate::nuts::CurrencyUnit,
) -> Result<Vec<ProofInfo>, Error> {
    batch
        .proofs
        .iter()
        .map(|bound| {
            ProofInfo::new(
                bound.proof.clone(),
                wallet.mint_url.clone(),
                bound.state,
                unit.clone(),
            )
        })
        .collect()
}

fn prepare_ordinary_restore_keyset(
    keyset: &KeySetInfo,
    keys: &Keys,
) -> Result<RestoreKeysetInput, Error> {
    let keys = KeySet {
        id: keyset.id,
        unit: keyset.unit.clone(),
        active: Some(keyset.active),
        keys: keys.clone(),
        input_fee_ppk: keyset.input_fee_ppk,
        final_expiry: keyset.final_expiry,
    };
    keys.verify_id()?;
    Ok(RestoreKeysetInput::Ordinary {
        keyset: keyset.clone(),
        keys,
    })
}

fn tally_restored(restored: &mut Restored, proofs: &[BoundRestoreProof]) -> Result<(), Error> {
    for proof in proofs {
        let total = match proof.state {
            State::Spent => &mut restored.spent,
            State::Unspent => &mut restored.unspent,
            State::Pending => &mut restored.pending,
            State::Reserved | State::PendingSpent => {
                return Err(invalid_restore("invalid state reached restore tally"));
            }
        };
        *total = total
            .checked_add(proof.proof.amount)
            .ok_or(Error::AmountOverflow)?;
    }
    Ok(())
}

fn tallied_restored(restored: &Restored, proofs: &[BoundRestoreProof]) -> Result<Restored, Error> {
    let mut candidate = restored.clone();
    tally_restored(&mut candidate, proofs)?;
    Ok(candidate)
}

fn invalid_restore(detail: impl Into<String>) -> Error {
    Error::InvalidMintResponse(detail.into())
}

fn checked_budget_add(
    current: usize,
    count: usize,
    limit: usize,
    kind: &str,
) -> Result<usize, Error> {
    let next = current
        .checked_add(count)
        .ok_or_else(|| invalid_restore(format!("restore {kind} budget overflow")))?;
    if next > limit {
        return Err(invalid_restore(format!(
            "restore exceeded its global {kind} budget"
        )));
    }
    Ok(next)
}

#[cfg(feature = "conditional-tokens")]
fn invalid_catalogue(detail: impl Into<String>) -> Error {
    Error::InvalidConditionalKeysetCatalogueResponse(detail.into())
}

#[cfg(feature = "conditional-tokens")]
fn validate_frozen_capability(capability: ConditionalKeysetCatalogueSettings) -> Result<(), Error> {
    validate_conditional_keyset_catalogue_request(
        &GetConditionalKeysetsRequest {
            catalogue_version: Some(capability.version),
            limit: Some(capability.max_page_size),
            ..Default::default()
        },
        capability.max_page_size,
    )?;
    Ok(())
}

#[cfg(feature = "conditional-tokens")]
fn validate_restore_namespaces(
    ordinary_ids: &HashSet<Id>,
    conditional: &[ConditionalKeySetInfo],
) -> Result<(), Error> {
    if conditional
        .iter()
        .any(|keyset| ordinary_ids.contains(&keyset.id))
    {
        return Err(invalid_catalogue(
            "conditional catalogue id collided with an ordinary keyset",
        ));
    }
    Ok(())
}

#[cfg(feature = "conditional-tokens")]
fn validate_conditional_keyset_semantics(
    keyset: &ConditionalKeySetInfo,
) -> Result<crate::nuts::CurrencyUnit, Error> {
    if keyset.id.get_version() != KeySetVersion::Version01 {
        return Err(invalid_restore(
            "conditional restore supports only keyset id version 01",
        ));
    }
    let unit = crate::nuts::CurrencyUnit::from_str(&keyset.unit)
        .map_err(|_| invalid_restore("conditional keyset unit is invalid"))?;
    if keyset.final_expiry == Some(0) {
        return Err(invalid_restore(
            "conditional keyset metadata is not canonical",
        ));
    }
    let condition_id = crate::util::hex::decode(&keyset.condition_id)
        .map_err(|_| invalid_restore("conditional keyset condition id is invalid"))?;
    let condition_id = <[u8; 32]>::try_from(condition_id.as_slice())
        .map_err(|_| invalid_restore("conditional keyset condition id is invalid"))?;
    let expected =
        compute_outcome_collection_id(&[0_u8; 32], &condition_id, &keyset.outcome_collection)
            .map_err(|_| invalid_restore("conditional outcome collection cannot be derived"))?;
    if crate::util::hex::encode(expected) != keyset.outcome_collection_id {
        return Err(invalid_restore(
            "conditional outcome collection does not use the zero parent",
        ));
    }
    Ok(unit)
}

#[cfg(feature = "conditional-tokens")]
fn validate_conditional_keys(
    conditional: &ConditionalKeySetInfo,
    keys: &KeySet,
    unit: &crate::nuts::CurrencyUnit,
) -> Result<(), Error> {
    let fee = conditional.input_fee_ppk.unwrap_or_default();
    if keys.id != conditional.id
        || keys.unit != *unit
        || keys.active != Some(conditional.active)
        || keys.input_fee_ppk != fee
        || keys.final_expiry != conditional.final_expiry
        || keys.keys.is_empty()
    {
        return Err(invalid_restore(
            "conditional public keys do not match catalogue metadata",
        ));
    }
    let derived = Id::v2_from_data_conditional(
        &keys.keys,
        unit,
        fee,
        conditional.final_expiry,
        &conditional.condition_id,
        &conditional.outcome_collection_id,
    );
    if derived != conditional.id {
        return Err(invalid_restore(
            "conditional keyset id does not bind its public keys and metadata",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    #[cfg(feature = "conditional-tokens")]
    use std::str::FromStr;
    use std::sync::Arc;

    use super::*;
    use crate::dhke::sign_message;
    use crate::nuts::nut01::SecretKey;
    #[cfg(feature = "conditional-tokens")]
    use crate::nuts::nut_ctf::{
        ConditionalKeysetCatalogueSettings, ConditionalKeysetsResponse, NutCtfSettings,
    };
    use crate::wallet::test_utils::{create_test_wallet_with_mock, test_keyset, MockMintConnector};

    fn restore_fixture() -> (PreMintSecrets, Keys, Vec<SecretKey>, RestoreResponse) {
        let keyset_id = Id::from_bytes(&[0_u8; 8]).expect("test keyset id");
        let seed = [7_u8; 64];
        let premint = PreMintSecrets::restore_batch(keyset_id, &seed, 0, 3)
            .expect("restore secrets should derive");
        let mint_keys: Vec<_> = (0..3).map(|_| SecretKey::generate()).collect();
        let amounts = [Amount::from(1), Amount::from(2), Amount::from(4)];
        let keys = Keys::new(
            amounts
                .iter()
                .copied()
                .zip(mint_keys.iter().map(SecretKey::public_key))
                .collect(),
        );
        let signatures = premint
            .secrets
            .iter()
            .zip(amounts)
            .zip(&mint_keys)
            .map(|((secret, amount), mint_key)| BlindSignature {
                amount,
                keyset_id,
                c: sign_message(mint_key, &secret.blinded_message.blinded_secret)
                    .expect("test signature"),
                dleq: None,
            })
            .collect();
        let response = RestoreResponse {
            outputs: premint.blinded_messages(),
            signatures,
        };
        (premint, keys, mint_keys, response)
    }

    #[tokio::test]
    async fn restore_stops_after_three_consecutive_empty_batches() {
        let mock = Arc::new(MockMintConnector::new());
        for _ in 0..3 {
            mock.enqueue_restore_response(Ok(RestoreResponse {
                outputs: Vec::new(),
                signatures: Vec::new(),
            }));
        }
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;

        assert_eq!(
            wallet.restore().await.expect("empty restore"),
            Restored::default()
        );
    }

    #[tokio::test]
    async fn recovery_keyset_bound_fails_before_restore_work() {
        let mock = Arc::new(MockMintConnector::new());
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;

        assert!(wallet
            .metadata_cache
            .load_from_mint_for_recovery(&wallet.localstore, &wallet.client, 0)
            .await
            .is_err());
        assert_eq!(
            mock.post_restore_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        let mock = Arc::new(MockMintConnector::new());
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;
        wallet
            .metadata_cache
            .load_from_mint(&wallet.localstore, &wallet.client)
            .await
            .expect("seed local metadata");
        assert!(wallet
            .metadata_cache
            .load_from_mint_for_recovery(&wallet.localstore, &wallet.client, 0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn ordinary_keyset_listing_deduplicates_identical_metadata() {
        let mock = Arc::new(MockMintConnector::new());
        let keyset = mock.keyset.lock().expect("mint keyset").clone();
        let keyset_info = KeySetInfo {
            id: keyset.id,
            unit: keyset.unit,
            active: keyset.active.unwrap_or_default(),
            input_fee_ppk: keyset.input_fee_ppk,
            final_expiry: keyset.final_expiry,
        };
        mock.set_ordinary_keyset_infos(vec![keyset_info.clone(), keyset_info]);
        for _ in 0..3 {
            mock.enqueue_restore_response(Ok(RestoreResponse {
                outputs: Vec::new(),
                signatures: Vec::new(),
            }));
        }
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;

        assert_eq!(
            wallet.restore().await.expect("deduplicated restore"),
            Restored::default()
        );
        assert_eq!(
            mock.post_restore_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[tokio::test]
    async fn ordinary_keyset_listing_rejects_conflicting_duplicate_before_restore() {
        let mock = Arc::new(MockMintConnector::new());
        let keyset = mock.keyset.lock().expect("mint keyset").clone();
        let keyset_info = KeySetInfo {
            id: keyset.id,
            unit: keyset.unit,
            active: keyset.active.unwrap_or_default(),
            input_fee_ppk: keyset.input_fee_ppk,
            final_expiry: keyset.final_expiry,
        };
        let mut conflicting = keyset_info.clone();
        conflicting.active = !conflicting.active;
        mock.set_ordinary_keyset_infos(vec![keyset_info, conflicting]);
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;

        assert!(wallet.restore().await.is_err());
        assert_eq!(
            mock.post_restore_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn restore_without_an_applicable_keyset_preserves_unknown_keyset_error() {
        let mock = Arc::new(MockMintConnector::new());
        mock.keyset.lock().expect("mint keyset").unit = crate::nuts::CurrencyUnit::Usd;
        let keyset = mock.keyset.lock().expect("mint keyset").clone();
        mock.set_ordinary_keyset_infos(vec![KeySetInfo {
            id: keyset.id,
            unit: crate::nuts::CurrencyUnit::Usd,
            active: keyset.active.unwrap_or_default(),
            input_fee_ppk: keyset.input_fee_ppk,
            final_expiry: keyset.final_expiry,
        }]);
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;

        let result = wallet.restore().await;
        assert!(matches!(result, Err(Error::UnknownKeySet)), "{result:?}");
        assert_eq!(
            mock.post_restore_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn global_restore_budget_rejections_do_not_persist_proofs_or_counters() {
        for (limits, expected_restore_calls) in [
            (
                RestoreLimits {
                    proofs: usize::MAX,
                    bytes: 0,
                    work_units: usize::MAX,
                },
                0,
            ),
            (
                RestoreLimits {
                    proofs: usize::MAX,
                    bytes: usize::MAX,
                    work_units: 0,
                },
                0,
            ),
            (
                RestoreLimits {
                    proofs: 0,
                    bytes: usize::MAX,
                    work_units: usize::MAX,
                },
                1,
            ),
        ] {
            let mock = Arc::new(MockMintConnector::new());
            let db = Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            );
            let wallet = create_test_wallet_with_mock(db, mock.clone()).await;

            if expected_restore_calls == 1 {
                let mint_keys = BTreeMap::from([(Amount::ONE, SecretKey::generate())]);
                let keys = Keys::new(
                    mint_keys
                        .iter()
                        .map(|(amount, secret)| (*amount, secret.public_key()))
                        .collect(),
                );
                let keyset_id = Id::v2_from_data(&keys, &crate::nuts::CurrencyUnit::Sat, 0, None);
                let keyset = KeySet {
                    id: keyset_id,
                    unit: crate::nuts::CurrencyUnit::Sat,
                    active: Some(true),
                    keys,
                    input_fee_ppk: 0,
                    final_expiry: None,
                };
                mock.set_active_keyset(keyset.clone());
                let (response, _) =
                    signed_restore_batch(&wallet, &keyset, &mint_keys, &[State::Unspent]);
                mock.enqueue_restore_response(Ok(response));
            }

            assert!(wallet.restore_with_limits(limits).await.is_err());
            assert!(wallet
                .localstore
                .get_proofs(
                    Some(wallet.mint_url.clone()),
                    Some(wallet.unit.clone()),
                    None,
                    None,
                )
                .await
                .expect("stored proofs")
                .is_empty());
            let keyset_id = mock.keyset.lock().expect("mint keyset").id;
            assert_eq!(
                wallet
                    .localstore
                    .increment_keyset_counter(&keyset_id, 0)
                    .await
                    .expect("counter"),
                0
            );
            assert_eq!(
                mock.post_restore_calls
                    .load(std::sync::atomic::Ordering::Relaxed),
                expected_restore_calls
            );
        }
    }

    #[test]
    fn restore_binder_accepts_bound_out_of_order_subset() {
        let (premint, keys, _, response) = restore_fixture();
        let response = RestoreResponse {
            outputs: vec![response.outputs[2].clone(), response.outputs[0].clone()],
            signatures: vec![
                response.signatures[2].clone(),
                response.signatures[0].clone(),
            ],
        };
        let bound = bind_restore_response(&premint, response, &keys, 0).expect("valid response");
        assert_eq!(bound.proofs.len(), 2);
        assert_eq!(bound.proofs[0].proof.amount, Amount::from(1));
        assert_eq!(bound.proofs[1].proof.amount, Amount::from(4));
        assert_eq!(bound.counter_floor, Some(3));
    }

    #[test]
    fn restore_binder_uses_absolute_nonzero_counter_floor() {
        let (premint, keys, _, response) = restore_fixture();
        let response = RestoreResponse {
            outputs: vec![response.outputs[2].clone()],
            signatures: vec![response.signatures[2].clone()],
        };
        let bound = bind_restore_response(&premint, response, &keys, 200).expect("valid response");
        assert_eq!(bound.counter_floor, Some(203));
    }

    #[test]
    fn restored_amount_overflow_fails_before_mutating_result() {
        let (premint, keys, _, response) = restore_fixture();
        let batch = bind_restore_response(
            &premint,
            RestoreResponse {
                outputs: vec![response.outputs[0].clone()],
                signatures: vec![response.signatures[0].clone()],
            },
            &keys,
            0,
        )
        .expect("valid batch");
        let original = Restored {
            unspent: Amount::from(u64::MAX),
            ..Default::default()
        };
        assert!(tallied_restored(&original, &batch.proofs).is_err());
        assert_eq!(original.unspent, Amount::from(u64::MAX));
    }

    #[test]
    fn ordinary_restore_revalidates_cached_public_keys() {
        let keyset = test_keyset();
        let info = KeySetInfo {
            id: keyset.id,
            unit: keyset.unit,
            active: keyset.active.unwrap_or_default(),
            input_fee_ppk: keyset.input_fee_ppk,
            final_expiry: keyset.final_expiry,
        };
        assert!(prepare_ordinary_restore_keyset(&info, &keyset.keys).is_ok());
        let mut corrupted_map: BTreeMap<_, _> = keyset.keys.iter().map(|(a, k)| (*a, *k)).collect();
        corrupted_map.insert(Amount::from(1), SecretKey::generate().public_key());
        let corrupted = Keys::new(corrupted_map);
        assert!(prepare_ordinary_restore_keyset(&info, &corrupted).is_err());
    }

    #[test]
    fn restore_binder_rejects_length_duplicate_foreign_and_metadata_mutation() {
        let (premint, keys, _, response) = restore_fixture();

        let mut invalid = response.clone();
        invalid.signatures.pop();
        assert!(bind_restore_response(&premint, invalid, &keys, 0).is_err());

        let mut invalid = response.clone();
        invalid.outputs[1] = invalid.outputs[0].clone();
        assert!(bind_restore_response(&premint, invalid, &keys, 0).is_err());

        let mut invalid = response.clone();
        invalid.outputs[0].blinded_secret = SecretKey::generate().public_key();
        assert!(bind_restore_response(&premint, invalid, &keys, 0).is_err());

        let mut invalid = response;
        invalid.outputs[0].amount = Amount::ONE;
        assert!(bind_restore_response(&premint, invalid, &keys, 0).is_err());
    }

    #[test]
    fn restore_binder_rejects_signature_keyset_amount_and_duplicate_c() {
        let (premint, keys, _, response) = restore_fixture();

        let mut invalid = response.clone();
        invalid.signatures[0].keyset_id =
            Id::from_bytes(&[0, 1, 2, 3, 4, 5, 6, 7]).expect("foreign id");
        assert!(bind_restore_response(&premint, invalid, &keys, 0).is_err());

        let mut invalid = response.clone();
        invalid.signatures[0].amount = Amount::from(8);
        assert!(bind_restore_response(&premint, invalid, &keys, 0).is_err());

        let mut invalid = response;
        invalid.signatures[1].c = invalid.signatures[0].c;
        assert!(bind_restore_response(&premint, invalid, &keys, 0).is_err());
    }

    #[test]
    fn restore_binder_rejects_tampered_supplied_dleq() {
        let (premint, keys, mint_keys, mut response) = restore_fixture();
        let signature = &response.signatures[0];
        response.signatures[0] = BlindSignature::new(
            signature.amount,
            signature.c,
            signature.keyset_id,
            &response.outputs[0].blinded_secret,
            mint_keys[0].clone(),
        )
        .expect("valid DLEQ");
        response.signatures[0].amount = Amount::from(2);
        assert!(matches!(
            bind_restore_response(&premint, response, &keys, 0),
            Err(Error::CouldNotVerifyDleq)
        ));
    }

    #[test]
    fn state_binder_reorders_exact_y_set_and_rejects_invalid_shapes() {
        let (premint, keys, _, response) = restore_fixture();
        let batch =
            bind_restore_response(&premint, response.clone(), &keys, 0).expect("valid batch");
        let ys: Vec<_> = batch
            .proofs
            .iter()
            .map(|bound| bound.proof.y().expect("proof Y"))
            .collect();
        let bound = bind_check_state_response(
            batch,
            CheckStateResponse {
                states: vec![
                    (ys[2], State::Spent).into(),
                    (ys[0], State::Unspent).into(),
                    (ys[1], State::Pending).into(),
                ],
            },
        )
        .expect("exact reordered set");
        assert_eq!(bound.proofs[0].state, State::Unspent);
        assert_eq!(bound.proofs[1].state, State::Pending);
        assert_eq!(bound.proofs[2].state, State::Spent);

        let batch =
            bind_restore_response(&premint, response.clone(), &keys, 0).expect("valid batch");
        assert!(bind_check_state_response(
            batch,
            CheckStateResponse {
                states: vec![(ys[0], State::Unspent).into()]
            }
        )
        .is_err());

        let (premint, keys, _, response) = restore_fixture();
        let batch =
            bind_restore_response(&premint, response.clone(), &keys, 0).expect("valid batch");
        let foreign = SecretKey::generate().public_key();
        assert!(bind_check_state_response(
            batch,
            CheckStateResponse {
                states: vec![
                    (ys[0], State::Unspent).into(),
                    (foreign, State::Pending).into(),
                    (ys[2], State::Spent).into(),
                ]
            }
        )
        .is_err());

        let batch =
            bind_restore_response(&premint, response.clone(), &keys, 0).expect("valid batch");
        assert!(bind_check_state_response(
            batch,
            CheckStateResponse {
                states: vec![
                    (ys[0], State::Unspent).into(),
                    (ys[0], State::Pending).into(),
                    (ys[2], State::Spent).into(),
                ]
            }
        )
        .is_err());

        let batch = bind_restore_response(&premint, response, &keys, 0).expect("valid batch");
        assert!(bind_check_state_response(
            batch,
            CheckStateResponse {
                states: vec![
                    (ys[0], State::Reserved).into(),
                    (ys[1], State::Pending).into(),
                    (ys[2], State::Spent).into(),
                ]
            }
        )
        .is_err());
    }

    #[cfg(feature = "conditional-tokens")]
    #[test]
    fn conditional_semantics_require_v2_and_zero_parent_outcome() {
        let condition_id = [1_u8; 32];
        let outcome_id =
            compute_outcome_collection_id(&[0_u8; 32], &condition_id, "YES").expect("outcome id");
        let mut keyset = ConditionalKeySetInfo {
            id: Id::from_bytes(&[0_u8; 8]).expect("v1 id"),
            unit: "sat".to_string(),
            active: false,
            input_fee_ppk: Some(0),
            final_expiry: None,
            condition_id: crate::util::hex::encode(condition_id),
            outcome_collection: "YES".to_string(),
            outcome_collection_id: crate::util::hex::encode(outcome_id),
            registered_at: 1,
        };
        assert!(validate_conditional_keyset_semantics(&keyset).is_err());

        keyset.id = Id::v2_from_data_conditional(
            &Keys::new(BTreeMap::new()),
            &crate::nuts::CurrencyUnit::Sat,
            0,
            None,
            &keyset.condition_id,
            &keyset.outcome_collection_id,
        );
        keyset.outcome_collection_id = "00".repeat(32);
        assert!(validate_conditional_keyset_semantics(&keyset).is_err());
    }

    #[cfg(feature = "conditional-tokens")]
    fn catalogue_keyset(id: &str) -> ConditionalKeySetInfo {
        ConditionalKeySetInfo {
            id: Id::from_str(id).expect("catalogue id"),
            unit: "sat".to_string(),
            active: false,
            input_fee_ppk: Some(0),
            final_expiry: None,
            condition_id: "11".repeat(32),
            outcome_collection: "YES".to_string(),
            outcome_collection_id: "22".repeat(32),
            registered_at: 1,
        }
    }

    #[cfg(feature = "conditional-tokens")]
    fn valid_catalogue_keyset(
        keys: &Keys,
        unit: crate::nuts::CurrencyUnit,
        final_expiry: Option<u64>,
    ) -> ConditionalKeySetInfo {
        let condition_id = [3_u8; 32];
        let outcome_collection = "YES".to_string();
        let outcome_id =
            compute_outcome_collection_id(&[0_u8; 32], &condition_id, &outcome_collection)
                .expect("outcome collection id");
        let condition_id = crate::util::hex::encode(condition_id);
        let outcome_collection_id = crate::util::hex::encode(outcome_id);
        ConditionalKeySetInfo {
            id: Id::v2_from_data_conditional(
                keys,
                &unit,
                0,
                final_expiry,
                &condition_id,
                &outcome_collection_id,
            ),
            unit: unit.to_string(),
            active: false,
            input_fee_ppk: Some(0),
            final_expiry,
            condition_id,
            outcome_collection,
            outcome_collection_id,
            registered_at: 1,
        }
    }

    #[cfg(feature = "conditional-tokens")]
    fn conditional_fixture() -> (ConditionalKeySetInfo, KeySet, BTreeMap<Amount, SecretKey>) {
        let mint_keys = BTreeMap::from([
            (Amount::from(1), SecretKey::generate()),
            (Amount::from(2), SecretKey::generate()),
        ]);
        let keys = Keys::new(
            mint_keys
                .iter()
                .map(|(amount, secret)| (*amount, secret.public_key()))
                .collect(),
        );
        let info = valid_catalogue_keyset(&keys, crate::nuts::CurrencyUnit::Sat, None);
        let keyset = KeySet {
            id: info.id,
            unit: crate::nuts::CurrencyUnit::Sat,
            active: Some(info.active),
            keys,
            input_fee_ppk: info.input_fee_ppk.unwrap_or_default(),
            final_expiry: info.final_expiry,
        };
        (info, keyset, mint_keys)
    }

    fn signed_restore_batch(
        wallet: &Wallet,
        keyset: &KeySet,
        mint_keys: &BTreeMap<Amount, SecretKey>,
        states: &[State],
    ) -> (RestoreResponse, CheckStateResponse) {
        let premint = PreMintSecrets::restore_batch(keyset.id, &wallet.seed, 0, 100)
            .expect("conditional restore secrets");
        let amounts = [Amount::from(1), Amount::from(2)];
        let selected: Vec<_> = premint.secrets.iter().take(states.len()).collect();
        let signatures: Vec<_> = selected
            .iter()
            .zip(amounts)
            .map(|(premint, amount)| BlindSignature {
                amount,
                keyset_id: keyset.id,
                c: sign_message(
                    mint_keys.get(&amount).expect("amount key"),
                    &premint.blinded_message.blinded_secret,
                )
                .expect("blind signature"),
                dleq: None,
            })
            .collect();
        let proofs = construct_proofs(
            signatures.clone(),
            selected.iter().map(|premint| premint.r.clone()).collect(),
            selected
                .iter()
                .map(|premint| premint.secret.clone())
                .collect(),
            &keyset.keys,
        )
        .expect("proofs");
        let check_state = CheckStateResponse {
            states: proofs
                .iter()
                .zip(states)
                .map(|(proof, state)| (proof.y().expect("proof Y"), *state).into())
                .collect(),
        };
        (
            RestoreResponse {
                outputs: selected
                    .iter()
                    .map(|premint| premint.blinded_message.clone())
                    .collect(),
                signatures,
            },
            check_state,
        )
    }

    #[cfg(feature = "conditional-tokens")]
    fn queue_ordinary_empty_then_conditional(
        mock: &MockMintConnector,
        response: RestoreResponse,
        check_state: CheckStateResponse,
    ) {
        for _ in 0..3 {
            mock.enqueue_restore_response(Ok(RestoreResponse {
                outputs: Vec::new(),
                signatures: Vec::new(),
            }));
        }
        mock.enqueue_restore_response(Ok(response));
        mock.enqueue_check_state_response(Ok(check_state));
        for _ in 0..3 {
            mock.enqueue_restore_response(Ok(RestoreResponse {
                outputs: Vec::new(),
                signatures: Vec::new(),
            }));
        }
    }

    #[cfg(feature = "conditional-tokens")]
    fn advertise_catalogue(mock: &MockMintConnector) -> crate::nuts::MintInfo {
        let mut info = mock.mint_info.lock().expect("mint info lock");
        info.nuts.nut_ctf = Some(NutCtfSettings {
            supported: true,
            conditional_keyset_catalogue: Some(ConditionalKeysetCatalogueSettings {
                version: 1,
                max_page_size: 100,
            }),
            ..Default::default()
        });
        info.clone()
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn catalogue_scan_deduplicates_identical_cross_page_metadata() {
        let mock = Arc::new(MockMintConnector::new());
        let info = advertise_catalogue(&mock);
        let keyset = catalogue_keyset("00916bbf7ef91a36");
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![keyset.clone()],
            next_cursor: Some("page-two".to_string()),
            complete: false,
        }));
        mock.enqueue_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![keyset.clone()],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock,
        )
        .await;

        let (keysets, _) = wallet
            .scan_conditional_catalogue(&info, &mut RestoreBudget::new(RestoreLimits::default()))
            .await
            .expect("stable catalogue");
        assert_eq!(keysets, vec![keyset]);
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn catalogue_scan_rejects_conflicting_cross_page_metadata_and_cursor_cycles() {
        let mock = Arc::new(MockMintConnector::new());
        let info = advertise_catalogue(&mock);
        let keyset = catalogue_keyset("00916bbf7ef91a36");
        let mut conflicting = keyset.clone();
        conflicting.active = true;
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![keyset],
            next_cursor: Some("page-two".to_string()),
            complete: false,
        }));
        mock.enqueue_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![conflicting],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock,
        )
        .await;
        assert!(wallet
            .scan_conditional_catalogue(&info, &mut RestoreBudget::new(RestoreLimits::default()))
            .await
            .is_err());

        let mock = Arc::new(MockMintConnector::new());
        let info = advertise_catalogue(&mock);
        for cursor in ["a", "b", "a"] {
            mock.enqueue_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
                keysets: Vec::new(),
                next_cursor: Some(cursor.to_string()),
                complete: false,
            }));
        }
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock,
        )
        .await;
        assert!(wallet
            .scan_conditional_catalogue(&info, &mut RestoreBudget::new(RestoreLimits::default()))
            .await
            .is_err());
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn fresh_ordinary_namespace_rejects_overlap_but_hydrated_conditional_cache_does_not() {
        let mock = Arc::new(MockMintConnector::new());
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock,
        )
        .await;
        let metadata = wallet
            .metadata_cache
            .load_from_mint(&wallet.localstore, &wallet.client)
            .await
            .expect("fresh metadata");
        let ordinary_id = *metadata
            .ordinary_keyset_ids
            .iter()
            .next()
            .expect("ordinary keyset id");
        assert!(validate_restore_namespaces(
            &metadata.ordinary_keyset_ids,
            &[catalogue_keyset(&ordinary_id.to_string())]
        )
        .is_err());

        let ordinary_keys = metadata
            .keys
            .get(&ordinary_id)
            .expect("ordinary keys")
            .as_ref()
            .clone();
        let conditional =
            valid_catalogue_keyset(&ordinary_keys, crate::nuts::CurrencyUnit::Sat, None);
        let conditional_id = conditional.id;
        wallet
            .metadata_cache
            .install_recovered_keyset(
                conditional,
                KeySetInfo {
                    id: conditional_id,
                    unit: crate::nuts::CurrencyUnit::Sat,
                    active: false,
                    input_fee_ppk: 0,
                    final_expiry: None,
                },
                ordinary_keys,
            )
            .await
            .expect("conditional cache install");
        let cached = wallet
            .metadata_cache
            .load(&wallet.localstore, &wallet.client, None)
            .await
            .expect("cached metadata");
        assert!(cached.keysets.contains_key(&conditional_id));
        assert!(!cached.ordinary_keyset_ids.contains(&conditional_id));
        assert!(validate_restore_namespaces(
            &cached.ordinary_keyset_ids,
            &[catalogue_keyset(&conditional_id.to_string())]
        )
        .is_ok());
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn valid_wrong_unit_and_expired_keysets_skip_key_fetch() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        mock.keyset.lock().expect("mint keyset").unit = crate::nuts::CurrencyUnit::Usd;
        let ordinary = mock.keyset.lock().expect("mint keyset").clone();
        let keys = ordinary.keys.clone();
        mock.set_ordinary_keyset_infos(vec![KeySetInfo {
            id: ordinary.id,
            unit: crate::nuts::CurrencyUnit::Usd,
            active: ordinary.active.unwrap_or_default(),
            input_fee_ppk: ordinary.input_fee_ppk,
            final_expiry: ordinary.final_expiry,
        }]);
        let wrong_unit = valid_catalogue_keyset(&keys, crate::nuts::CurrencyUnit::Usd, None);
        let expired = valid_catalogue_keyset(
            &keys,
            crate::nuts::CurrencyUnit::Sat,
            Some(crate::util::unix_time().saturating_sub(1)),
        );
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![wrong_unit, expired],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;

        assert_eq!(
            wallet.restore().await.expect("bounded restore"),
            Restored::default()
        );
        assert_eq!(
            mock.post_restore_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn malformed_skipped_catalogue_entries_fail_before_restore_requests() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        let keys = mock.keyset.lock().expect("mint keyset").keys.clone();
        let mut malformed = valid_catalogue_keyset(
            &keys,
            crate::nuts::CurrencyUnit::Usd,
            Some(crate::util::unix_time().saturating_sub(1)),
        );
        malformed.outcome_collection_id = "00".repeat(32);
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![malformed],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock,
        )
        .await;
        assert!(wallet.restore().await.is_err());

        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        let mut unsupported = catalogue_keyset("00916bbf7ef91a36");
        unsupported.unit = "usd".to_string();
        unsupported.final_expiry = Some(crate::util::unix_time().saturating_sub(1));
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![unsupported],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock,
        )
        .await;
        assert!(wallet.restore().await.is_err());
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn conditional_held_restore_commits_hydrates_and_tallies() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        let (info, keyset, mint_keys) = conditional_fixture();
        mock.set_additional_keyset(keyset.clone());
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![info.clone()],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;
        let (response, check_state) = signed_restore_batch(
            &wallet,
            &keyset,
            &mint_keys,
            &[State::Unspent, State::Pending],
        );
        queue_ordinary_empty_then_conditional(&mock, response, check_state);

        let restored = wallet.restore().await.expect("conditional restore");
        assert_eq!(restored.unspent, Amount::from(1));
        assert_eq!(restored.pending, Amount::from(2));
        assert_eq!(restored.spent, Amount::ZERO);
        assert_eq!(
            wallet
                .localstore
                .increment_keyset_counter(&info.id, 0)
                .await
                .expect("counter"),
            2
        );
        let stored = wallet
            .localstore
            .get_keyset_by_id(&info.id)
            .await
            .expect("stored keyset")
            .expect("conditional keyset");
        assert!(!stored.active);
        assert!(wallet
            .localstore
            .get_keys(&info.id)
            .await
            .expect("stored keys")
            .is_some());
        let stored_proofs = wallet
            .localstore
            .get_proofs(
                Some(wallet.mint_url.clone()),
                Some(wallet.unit.clone()),
                None,
                None,
            )
            .await
            .expect("stored proofs");
        let states: HashSet<_> = stored_proofs
            .iter()
            .filter(|proof| proof.proof.keyset_id == info.id)
            .map(|proof| proof.state)
            .collect();
        assert_eq!(states, HashSet::from([State::Unspent, State::Pending]));
        let cached = wallet
            .metadata_cache
            .load(&wallet.localstore, &wallet.client, None)
            .await
            .expect("cached metadata");
        assert!(!cached.keysets.get(&info.id).expect("cached keyset").active);
        assert!(!cached
            .active_keysets
            .iter()
            .any(|active| active.id == info.id));

        let ordinary_keys = mock.keyset.lock().expect("ordinary keyset").keys.clone();
        let next_ordinary_id =
            Id::v2_from_data(&ordinary_keys, &crate::nuts::CurrencyUnit::Sat, 1, None);
        mock.set_active_keyset(KeySet {
            id: next_ordinary_id,
            unit: crate::nuts::CurrencyUnit::Sat,
            active: Some(true),
            keys: ordinary_keys,
            input_fee_ppk: 1,
            final_expiry: None,
        });
        wallet
            .metadata_cache
            .load_from_mint(&wallet.localstore, &wallet.client)
            .await
            .expect("ordinary refresh after conditional hydration");
        assert!(wallet
            .localstore
            .get_keyset_by_id(&next_ordinary_id)
            .await
            .expect("refreshed ordinary keyset")
            .is_some());
        assert!(wallet
            .localstore
            .get_keyset_by_id(&info.id)
            .await
            .expect("conditional keyset after refresh")
            .is_some());
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn conditional_all_spent_restore_advances_without_hydration() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        let (info, keyset, mint_keys) = conditional_fixture();
        mock.set_additional_keyset(keyset.clone());
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![info.clone()],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;
        let (response, check_state) =
            signed_restore_batch(&wallet, &keyset, &mint_keys, &[State::Spent]);
        queue_ordinary_empty_then_conditional(&mock, response, check_state);

        let restored = wallet.restore().await.expect("conditional restore");
        assert_eq!(restored.spent, Amount::from(1));
        assert_eq!(
            wallet
                .localstore
                .increment_keyset_counter(&info.id, 0)
                .await
                .expect("counter"),
            1
        );
        assert!(wallet
            .localstore
            .get_keyset_by_id(&info.id)
            .await
            .expect("stored keyset")
            .is_none());
        assert!(wallet
            .localstore
            .get_keys(&info.id)
            .await
            .expect("stored keys")
            .is_none());
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn invalid_conditional_state_and_key_metadata_do_not_commit() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        let (info, keyset, mint_keys) = conditional_fixture();
        mock.set_additional_keyset(keyset.clone());
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![info.clone()],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;
        let (response, check_state) =
            signed_restore_batch(&wallet, &keyset, &mint_keys, &[State::Reserved]);
        queue_ordinary_empty_then_conditional(&mock, response, check_state);
        assert!(wallet.restore().await.is_err());
        assert!(wallet
            .localstore
            .get_keyset_by_id(&info.id)
            .await
            .expect("stored keyset")
            .is_none());

        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        let (info, mut keyset, _) = conditional_fixture();
        keyset.active = Some(!info.active);
        mock.set_additional_keyset(keyset);
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![info.clone()],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;
        assert!(wallet.restore().await.is_err());
        assert_eq!(
            mock.post_restore_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(wallet
            .localstore
            .get_keyset_by_id(&info.id)
            .await
            .expect("stored keyset")
            .is_none());
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn catalogue_failure_precedes_every_restore_request() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock);
        let keyset = catalogue_keyset("00916bbf7ef91a36");
        let mut conflicting = keyset.clone();
        conflicting.active = true;
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![keyset],
            next_cursor: Some("next".to_string()),
            complete: false,
        }));
        mock.enqueue_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![conflicting],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("test database"),
            ),
            mock.clone(),
        )
        .await;

        assert!(wallet.restore().await.is_err());
        assert_eq!(
            mock.post_restore_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(
            wallet
                .localstore
                .advance_conditional_restore_high_water(
                    wallet.mint_url.clone(),
                    wallet.unit.clone(),
                    0,
                )
                .await
                .expect("persisted high-water")
                > 0
        );
    }
}
