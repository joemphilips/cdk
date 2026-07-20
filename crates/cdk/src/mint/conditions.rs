//! NUT-CTF Conditional token condition registration and query logic

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cdk_common::database::mint::{
    validate_conditional_keyset_catalogue_fields, ConditionsDatabase,
    CONDITIONAL_KEYSET_CATALOGUE_VERSION as SHARED_CONDITIONAL_KEYSET_CATALOGUE_VERSION,
    MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH, MAX_CONDITIONAL_KEYSET_CATALOGUE_PAGE_SIZE,
    MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH,
};
use cdk_common::mint::StoredCondition;
use cdk_common::nuts::nut_ctf::{
    canonical_outcome_collection, compute_condition_id, compute_condition_id_numeric,
    compute_outcome_collection_id, dlc, parse_outcome_collection, to_hex, AttestationState,
    AttestationStatus, ConditionInfo, ConditionalKeysetsResponse, GetConditionalKeysetsRequest,
    GetConditionsResponse, RegisterConditionRequest, RegisterConditionResponse, MAX_ANNOUNCEMENTS,
    MAX_ANNOUNCEMENT_HEX_LENGTH, MAX_OUTCOMES, MAX_OUTCOME_COLLECTIONS, MAX_TAGS_JSON_LENGTH,
};
use cdk_common::nuts::{BlindSignature, BlindedMessage};
use cdk_common::CurrencyUnit;
use cdk_signatory::signatory::ConditionalKeysetInstallReservation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::instrument;
use zeroize::{Zeroize, Zeroizing};

use super::Mint;
use crate::Error;

/// Maximum number of items returned per paginated request.
pub(super) const MAX_PAGE_SIZE: u64 = MAX_CONDITIONAL_KEYSET_CATALOGUE_PAGE_SIZE;

/// Server-side default and maximum for the legacy raw-listing endpoint.
///
/// Legacy responses retain their historical shape, but an omitted limit no
/// longer authorizes an unbounded table read.
const LEGACY_MAX_PAGE_SIZE: u64 = MAX_PAGE_SIZE;

/// Version of the signed conditional-keyset catalogue cursor claims.
pub(super) const CONDITIONAL_KEYSET_CATALOGUE_VERSION: u8 =
    SHARED_CONDITIONAL_KEYSET_CATALOGUE_VERSION;

const CONDITIONAL_KEYSET_CURSOR_TYPE: &str = "CTF-KSC";
const CONDITIONAL_KEYSET_CURSOR_ALGORITHM: &str = "HS256";
const CONDITIONAL_KEYSET_CURSOR_HEADER: &[u8] = br#"{"typ":"CTF-KSC","alg":"HS256"}"#;
const MAX_SIGNED_SQL_INTEGER: u64 = 9_223_372_036_854_775_807;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionalKeysetCatalogueCursor {
    version: u8,
    snapshot: u64,
    after: u64,
    since: Option<u64>,
    active: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionalKeysetCursorHeader {
    typ: String,
    alg: String,
}

fn conditional_keyset_cursor_mac(key: &[u8; 32], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut inner_pad = Zeroizing::new([0x36_u8; 64]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; 64]);
    for (index, key_byte) in key.iter().enumerate() {
        inner_pad[index] ^= key_byte;
        outer_pad[index] ^= key_byte;
    }

    let mut hasher = Sha256::new();
    hasher.update(inner_pad.as_slice());
    hasher.update(message);
    let mut inner_result = hasher.finalize_reset();
    let mut inner_digest = Zeroizing::new([0_u8; 32]);
    inner_digest.copy_from_slice(inner_result.as_slice());
    inner_result.zeroize();

    hasher.update(outer_pad.as_slice());
    hasher.update(inner_digest.as_slice());
    let mut outer_result = hasher.finalize_reset();
    let mut tag = Zeroizing::new([0_u8; 32]);
    tag.copy_from_slice(outer_result.as_slice());
    outer_result.zeroize();
    tag
}

/// Valid values for the `status` query parameter on conditions.
const VALID_CONDITION_STATUSES: &[&str] = &["pending", "attested", "expired", "violation"];

/// Attestation status string constants matching DB storage values.
pub(super) const STATUS_PENDING: &str = "pending";
pub(super) const STATUS_ATTESTED: &str = "attested";

const CONDITION_TYPE_ENUM: &str = "enum";
const CONDITION_TYPE_NUMERIC: &str = "numeric";
const KEYSET_POLICY_NONE: &str = "none";
const KEYSET_POLICY_ONE_VS_REST: &str = "one-vs-rest";
const KEYSET_POLICY_ALL: &str = "all";

struct RegistrationFeeVerification {
    proofs: cdk_common::Proofs,
    amount: cdk_common::Amount<cdk_common::CurrencyUnit>,
    change_messages: Vec<BlindedMessage>,
    change_blinded_secrets: Vec<cdk_common::PublicKey>,
    change: Vec<BlindSignature>,
}

fn validate_registration_fee_input_count(
    fee: Option<&cdk_common::Proofs>,
    max_inputs: usize,
) -> Result<(), Error> {
    let actual = fee.map_or(0, Vec::len);
    if actual > max_inputs {
        return Err(Error::MaxInputsExceeded {
            actual,
            max: max_inputs,
        });
    }
    Ok(())
}

async fn validate_registration_fee_condition_lookups<D>(
    database: &D,
    fee: &cdk_common::Proofs,
    max_inputs: usize,
) -> Result<(), Error>
where
    D: ConditionsDatabase<Err = cdk_common::database::Error> + ?Sized,
{
    validate_registration_fee_input_count(Some(fee), max_inputs)?;
    for proof in fee {
        if database
            .get_condition_for_keyset(&proof.keyset_id)
            .await?
            .is_some()
        {
            return Err(Error::OutputsMustUseRegularKeyset);
        }
    }
    Ok(())
}

impl Mint {
    /// Register a new condition (POST /v1/conditions)
    ///
    /// Registers the condition and creates any requested outcome-collection keysets.
    #[instrument(skip_all)]
    pub async fn register_condition(
        &self,
        request: RegisterConditionRequest,
    ) -> Result<RegisterConditionResponse, Error> {
        // 0. Input size validation
        validate_registration_fee_input_count(request.fee.as_ref(), self.max_inputs)?;
        if request.announcements.is_empty() || request.announcements.len() > MAX_ANNOUNCEMENTS {
            return Err(Error::Custom(format!(
                "Number of announcements must be between 1 and {}",
                MAX_ANNOUNCEMENTS
            )));
        }
        let tags_json = serde_json::to_string(&request.tags)?;
        if tags_json.len() > MAX_TAGS_JSON_LENGTH {
            return Err(Error::Custom(format!(
                "Tags JSON exceeds maximum length of {}",
                MAX_TAGS_JSON_LENGTH
            )));
        }
        for tag in &request.tags {
            if tag.is_empty() {
                return Err(Error::Custom(
                    "Each tag must contain at least one element".to_string(),
                ));
            }
        }
        for ann_hex in &request.announcements {
            if ann_hex.len() > MAX_ANNOUNCEMENT_HEX_LENGTH {
                return Err(Error::Custom(format!(
                    "Announcement hex exceeds maximum length of {}",
                    MAX_ANNOUNCEMENT_HEX_LENGTH
                )));
            }
        }

        // 1. Parse and verify announcements
        let announcements: Vec<_> = request
            .announcements
            .iter()
            .map(|hex| dlc::parse_oracle_announcement(hex))
            .collect::<Result<Vec<_>, _>>()?;

        for ann in &announcements {
            dlc::verify_announcement_signature(ann)?;
        }

        // 2. Extract info from announcements
        let oracle_pubkeys: Vec<Vec<u8>> = announcements
            .iter()
            .map(|a| dlc::extract_oracle_pubkey(a).to_vec())
            .collect();
        let event_id = dlc::extract_event_id(&announcements[0]);

        // 3. Branch on condition_type
        if request.condition_type != CONDITION_TYPE_ENUM
            && request.condition_type != CONDITION_TYPE_NUMERIC
        {
            return Err(Error::Custom(format!(
                "Unsupported condition_type: {}",
                request.condition_type
            )));
        }
        let is_numeric = request.condition_type == CONDITION_TYPE_NUMERIC;
        let (outcomes, _outcome_count, condition_id_bytes) = if is_numeric {
            // NUT-CTF-numeric: numeric condition
            let lo_bound = request
                .lo_bound
                .ok_or_else(|| Error::Custom("lo_bound required for numeric conditions".into()))?;
            let hi_bound = request
                .hi_bound
                .ok_or_else(|| Error::Custom("hi_bound required for numeric conditions".into()))?;
            if lo_bound >= hi_bound {
                return Err(Error::Custom(format!(
                    "lo_bound ({}) must be less than hi_bound ({})",
                    lo_bound, hi_bound
                )));
            }
            let precision = request.precision.unwrap_or(0);

            // Verify it's actually a digit decomposition announcement
            dlc::extract_digit_decomposition(&announcements[0])?;

            // Numeric conditions always have 2 outcome collections: HI, LO
            let outcomes = vec!["HI".to_string(), "LO".to_string()];
            let cid = compute_condition_id_numeric(
                &oracle_pubkeys,
                &event_id,
                2,
                lo_bound,
                hi_bound,
                precision,
            );
            (outcomes, 2u8, cid)
        } else {
            // NUT-CTF: enum condition
            let outcomes = dlc::extract_outcomes(&announcements[0])?;
            if outcomes.len() > self.max_outcomes_per_condition {
                return Err(Error::Custom(format!(
                    "Outcome count {} exceeds configured maximum of {}",
                    outcomes.len(),
                    self.max_outcomes_per_condition
                )));
            }
            let outcome_count = u8::try_from(outcomes.len()).map_err(|_| {
                Error::Custom(format!(
                    "Outcome count {} exceeds protocol maximum of {}",
                    outcomes.len(),
                    MAX_OUTCOMES
                ))
            })?;
            let cid = compute_condition_id(&oracle_pubkeys, &event_id, outcome_count);
            (outcomes, outcome_count, cid)
        };
        let condition_id = to_hex(&condition_id_bytes);
        let default_keyset_creation = self.default_keyset_creation_policy().await?;
        let requested_collections = self.requested_outcome_collections(
            &outcomes,
            &request,
            is_numeric,
            &default_keyset_creation,
        )?;
        let collateral_unit = request
            .collateral
            .as_deref()
            .map(CurrencyUnit::from_str)
            .transpose()
            .map_err(|_| {
                Error::Custom(format!(
                    "Invalid collateral unit: {}",
                    request.collateral.as_deref().unwrap_or_default()
                ))
            })?;
        let required_fee = self
            .required_registration_fee(
                requested_collections.len(),
                collateral_unit.as_ref().unwrap_or(&CurrencyUnit::Sat),
            )
            .await?;

        // 4. Check for existing condition (idempotency or conflict)
        if let Some(existing) = self.localstore.get_condition(&condition_id).await? {
            // Validate parameters match for true idempotency. condition_id binds to
            // the *sorted* oracle pubkeys, so two requests with the same announcement
            // set in different submission orders produce the same condition_id —
            // compare announcement and tag arrays as multisets, not in submission order.
            let mut existing_announcements: Vec<String> =
                serde_json::from_str(&existing.announcements_json)?;
            let mut existing_tags: Vec<Vec<String>> =
                serde_json::from_str(&existing.tags_json).unwrap_or_default();
            existing_announcements.sort();
            existing_tags.sort();
            let mut request_announcements = request.announcements.clone();
            let mut request_tags = request.tags.clone();
            request_announcements.sort();
            request_tags.sort();
            if existing.threshold != request.threshold
                || existing_tags != request_tags
                || existing.condition_type != request.condition_type
                || existing_announcements != request_announcements
                || existing.lo_bound != request.lo_bound
                || existing.hi_bound != request.hi_bound
                || existing.precision != request.precision
                || existing.collateral != collateral_unit
            {
                return Err(Error::ConditionAlreadyExists);
            }

            let existing_keysets = self
                .localstore
                .get_conditional_keysets_for_condition(&condition_id)
                .await?;
            let existing_set: HashSet<String> = existing_keysets.keys().cloned().collect();
            let requested_set: HashSet<String> = requested_collections.iter().cloned().collect();
            if existing_set != requested_set {
                return Err(Error::ConditionAlreadyExists);
            }

            // A previous caller may have committed before its process stopped
            // during in-memory publication. Idempotent retries do not verify or
            // spend fee proofs again; they reconcile durable keysets first.
            let committed_keysets = self
                .localstore
                .get_conditional_mint_keyset_infos_for_condition(&condition_id)
                .await?;
            let committed_ids = committed_keysets
                .iter()
                .map(|info| info.id)
                .collect::<HashSet<_>>();
            let expected_ids = existing_keysets.values().copied().collect::<HashSet<_>>();
            if committed_ids != expected_ids {
                return Err(Error::Internal);
            }
            if !self.conditional_keyset_cache_is_healthy(&committed_keysets) {
                let reservation = self.signatory.reserve_conditional_keyset_install().await?;
                self.install_committed_conditional_keysets(reservation, committed_keysets)
                    .await?;
            }

            return Ok(RegisterConditionResponse {
                condition_id,
                keysets: existing_keysets,
                change: None,
            });
        }

        if !requested_collections.is_empty() || required_fee > 0 {
            let collateral = request.collateral.as_deref().ok_or_else(|| {
                Error::Custom(
                    "collateral is required when creating keysets or paying registration fees"
                        .to_string(),
                )
            })?;
            if collateral_unit.is_none() {
                return Err(Error::Custom(format!(
                    "Invalid collateral unit: {}",
                    collateral
                )));
            }
        }

        // Reserve bounded signatory capacity before fee verification, key
        // derivation, or the registration transaction. The owned reservation
        // survives commit and makes the post-commit enqueue non-saturating.
        let install_reservation = if requested_collections.is_empty() {
            None
        } else {
            Some(self.signatory.reserve_conditional_keyset_install().await?)
        };

        let fee_verification = if required_fee > 0 {
            let collateral = request
                .collateral
                .as_deref()
                .ok_or(Error::RegistrationFeeInsufficient)?;
            Some(
                self.verify_registration_fee(
                    request.fee.as_ref(),
                    request.outputs.as_deref(),
                    collateral,
                    required_fee,
                )
                .await?,
            )
        } else {
            None
        };

        // 5. Store the condition
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stored = StoredCondition {
            condition_id: condition_id.clone(),
            threshold: request.threshold,
            tags_json,
            announcements_json: serde_json::to_string(&request.announcements)?,
            collateral: collateral_unit,
            attestation_status: STATUS_PENDING.to_string(),
            winning_outcome: None,
            attested_at: None,
            created_at: now,
            condition_type: request.condition_type.clone(),
            lo_bound: request.lo_bound,
            hi_bound: request.hi_bound,
            precision: request.precision,
        };

        let prepared_keysets = self
            .prepare_condition_keysets(
                &condition_id,
                &condition_id_bytes,
                &requested_collections,
                request.collateral.as_deref(),
            )
            .await?;
        let keysets = prepared_keysets
            .iter()
            .map(|(collection, prepared)| (collection.clone(), prepared.keyset.id))
            .collect::<HashMap<_, _>>();

        let mut tx = self.localstore.begin_transaction().await?;
        if let Some(fee_verification) = &fee_verification {
            let operation = cdk_common::mint::Operation::new(
                uuid::Uuid::new_v4(),
                cdk_common::mint::OperationKind::Swap,
                cdk_common::Amount::ZERO,
                fee_verification.amount.clone().into(),
                fee_verification.amount.clone().into(),
                None,
                None,
            );
            let mut fee_records = match tx
                .add_proofs(fee_verification.proofs.clone(), None, &operation)
                .await
            {
                Ok(records) => records,
                Err(err) => {
                    tx.rollback().await?;
                    return Err(err.into());
                }
            };
            if let Err(err) = crate::Mint::update_proofs_state(
                &mut tx,
                &mut fee_records,
                cdk_common::State::Spent,
            )
            .await
            {
                tx.rollback().await?;
                return Err(err);
            }
            if !fee_verification.change_messages.is_empty() {
                if let Err(err) = tx
                    .add_blinded_messages(None, &fee_verification.change_messages, &operation)
                    .await
                {
                    tx.rollback().await?;
                    return Err(err.into());
                }
                if let Err(err) = tx
                    .add_blind_signatures(
                        &fee_verification.change_blinded_secrets,
                        &fee_verification.change,
                        None,
                    )
                    .await
                {
                    tx.rollback().await?;
                    return Err(err.into());
                }
            }
        }
        if let Err(err) = tx.add_condition(stored).await {
            tx.rollback().await?;
            return Err(err.into());
        }
        let committed_keysets = prepared_keysets
            .into_iter()
            .map(|(_, prepared)| prepared.info)
            .collect::<Vec<_>>();
        let catalogue_batch = committed_keysets
            .iter()
            .cloned()
            .map(|info| (info, now))
            .collect();
        if let Err(err) = tx.add_conditional_keysets(catalogue_batch).await {
            tx.rollback().await?;
            return Err(err.into());
        }
        tx.commit().await?;

        if let Some(reservation) = install_reservation {
            self.install_committed_conditional_keysets(reservation, committed_keysets)
                .await?;
        }

        Ok(RegisterConditionResponse {
            condition_id,
            keysets,
            change: fee_verification.and_then(|verification| {
                (!verification.change.is_empty()).then_some(verification.change)
            }),
        })
    }

    async fn install_committed_conditional_keysets(
        &self,
        reservation: ConditionalKeysetInstallReservation,
        committed_keysets: Vec<cdk_common::mint::MintKeySetInfo>,
    ) -> Result<(), Error> {
        let installed = self
            .signatory
            .install_reserved_conditional_keysets(reservation, committed_keysets.clone())
            .await?;
        let installed =
            Self::validate_installed_conditional_keysets(&committed_keysets, installed)?;
        super::merge_keyset_cache(&self.keysets, &installed);
        Ok(())
    }

    fn validate_installed_conditional_keysets(
        committed: &[cdk_common::mint::MintKeySetInfo],
        installed: Vec<cdk_signatory::signatory::SignatoryKeySet>,
    ) -> Result<
        Vec<(
            cdk_common::nuts::Id,
            std::sync::Arc<cdk_signatory::signatory::SignatoryKeySet>,
        )>,
        Error,
    > {
        if installed.len() != committed.len() {
            return Err(Error::Custom(
                "signatory returned an unexpected conditional keyset count".to_string(),
            ));
        }
        let mut expected = HashMap::with_capacity(committed.len());
        for info in committed {
            if expected.insert(info.id, info).is_some() {
                return Err(Error::Custom(
                    "committed conditional keyset metadata contains duplicate IDs".to_string(),
                ));
            }
        }

        let mut validated = Vec::with_capacity(installed.len());
        let mut returned_ids = HashSet::with_capacity(installed.len());
        for keyset in installed {
            if !returned_ids.insert(keyset.id) {
                return Err(Error::Custom(
                    "signatory returned duplicate conditional keyset IDs".to_string(),
                ));
            }
            let info = expected.remove(&keyset.id).ok_or_else(|| {
                Error::Custom("signatory returned an unexpected conditional keyset ID".to_string())
            })?;
            cdk_signatory::signatory::validate_keyset_info_binding(info, &keyset)?;
            validated.push((keyset.id, std::sync::Arc::new(keyset)));
        }
        if !expected.is_empty() {
            return Err(Error::Custom(
                "signatory omitted committed conditional keyset IDs".to_string(),
            ));
        }
        Ok(validated)
    }

    fn conditional_keyset_cache_is_healthy(
        &self,
        committed: &[cdk_common::mint::MintKeySetInfo],
    ) -> bool {
        let cache = self.keysets.load();
        committed.iter().all(|info| {
            let Some(live) = cache.get(&info.id) else {
                return false;
            };
            cdk_signatory::signatory::validate_keyset_info_binding(info, live).is_ok()
        })
    }

    async fn required_registration_fee(
        &self,
        num_keysets: usize,
        collateral_unit: &CurrencyUnit,
    ) -> Result<u64, Error> {
        let settings = self.mint_info().await?.nuts.nut_ctf.unwrap_or_default();
        let fee_setting = settings
            .registration_fees
            .iter()
            .find(|fee| fee.unit == collateral_unit.to_string())
            .ok_or(Error::UnsupportedCollateralUnit)?;
        let per_keyset = fee_setting
            .registration_fee_per_keyset
            .checked_mul(num_keysets as u64)
            .ok_or(Error::AmountOverflow)?;
        fee_setting
            .registration_fee_base
            .checked_add(per_keyset)
            .ok_or(Error::AmountOverflow)
    }

    async fn verify_registration_fee(
        &self,
        fee: Option<&cdk_common::Proofs>,
        outputs: Option<&[BlindedMessage]>,
        collateral: &str,
        required_fee: u64,
    ) -> Result<RegistrationFeeVerification, Error> {
        let fee = fee.ok_or(Error::RegistrationFeeInsufficient)?;
        validate_registration_fee_input_count(Some(fee), self.max_inputs)?;
        if fee.is_empty() {
            return Err(Error::RegistrationFeeInsufficient);
        }

        let collateral_unit = cdk_common::CurrencyUnit::from_str(collateral)
            .map_err(|_| Error::Custom(format!("Invalid collateral unit: {}", collateral)))?;

        validate_registration_fee_condition_lookups(self.localstore.as_ref(), fee, self.max_inputs)
            .await?;
        for proof in fee {
            let keyset_info = self
                .get_keyset_info(&proof.keyset_id)
                .ok_or(Error::UnknownKeySet)?;
            if keyset_info.unit != collateral_unit {
                return Err(Error::OutputsMustUseRegularKeyset);
            }
        }

        let verification = self.verify_inputs(fee).await?;
        if verification.amount.value() < required_fee {
            return Err(Error::RegistrationFeeInsufficient);
        }

        let change_amount = verification
            .amount
            .value()
            .checked_sub(required_fee)
            .ok_or(Error::AmountOverflow)?;
        let (change_messages, change_blinded_secrets, change) = if change_amount > 0 {
            self.sign_registration_fee_change(outputs, collateral_unit, change_amount)
                .await?
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        Ok(RegistrationFeeVerification {
            proofs: fee.clone(),
            amount: verification.amount,
            change_messages,
            change_blinded_secrets,
            change,
        })
    }

    async fn sign_registration_fee_change(
        &self,
        outputs: Option<&[BlindedMessage]>,
        collateral_unit: cdk_common::CurrencyUnit,
        change_amount: u64,
    ) -> Result<
        (
            Vec<BlindedMessage>,
            Vec<cdk_common::PublicKey>,
            Vec<BlindSignature>,
        ),
        Error,
    > {
        let outputs = outputs.ok_or(Error::RegistrationFeeChangeOutputs)?;
        if outputs.is_empty() {
            return Err(Error::RegistrationFeeChangeOutputs);
        }
        if outputs.len() > self.max_outputs {
            return Err(Error::RegistrationFeeChangeOutputs);
        }
        Mint::check_outputs_unique(outputs).map_err(|_| Error::RegistrationFeeChangeOutputs)?;
        let output_unit = self.verify_outputs_keyset(outputs)?;
        if output_unit != collateral_unit {
            return Err(Error::OutputsMustUseRegularKeyset);
        }
        for output in outputs {
            if self
                .localstore
                .get_condition_for_keyset(&output.keyset_id)
                .await?
                .is_some()
            {
                return Err(Error::OutputsMustUseRegularKeyset);
            }
        }

        let fee_and_amounts =
            super::melt::shared::get_keyset_fee_and_amounts(&self.keysets, outputs);
        let amounts = cdk_common::Amount::from(change_amount)
            .split(&fee_and_amounts)
            .map_err(|_| Error::RegistrationFeeChangeOutputs)?;
        if outputs.len() < amounts.len() {
            return Err(Error::RegistrationFeeChangeOutputs);
        }

        let change_messages = amounts
            .iter()
            .zip(outputs.iter().cloned())
            .map(|(amount, mut output)| {
                output.amount = *amount;
                output
            })
            .collect::<Vec<_>>();
        let change_blinded_secrets = change_messages
            .iter()
            .map(|message| message.blinded_secret)
            .collect::<Vec<_>>();
        let change = self.blind_sign(change_messages.clone()).await?;

        Ok((change_messages, change_blinded_secrets, change))
    }

    fn requested_outcome_collections(
        &self,
        outcomes: &[String],
        request: &RegisterConditionRequest,
        is_numeric: bool,
        default_keyset_creation: &str,
    ) -> Result<Vec<String>, Error> {
        if request.outcome_collections.is_some()
            && matches!(
                default_keyset_creation,
                KEYSET_POLICY_ONE_VS_REST | KEYSET_POLICY_ALL
            )
        {
            return Err(Error::Custom(format!(
                "outcome_collections must be omitted when default_keyset_creation is {}",
                default_keyset_creation
            )));
        };

        let raw = match (is_numeric, request.outcome_collections.as_ref()) {
            (true, Some(collections)) => collections.clone(),
            (true, None) => vec!["HI".to_string(), "LO".to_string()],
            (false, Some(collections)) => collections.clone(),
            (false, None) => self.default_outcome_collections(outcomes, default_keyset_creation)?,
        };

        if raw.len() > MAX_OUTCOME_COLLECTIONS {
            return Err(Error::Custom(format!(
                "Outcome collections exceed maximum of {}",
                MAX_OUTCOME_COLLECTIONS
            )));
        }

        let mut canonical = Vec::with_capacity(raw.len());
        let mut seen = HashSet::with_capacity(raw.len());
        for key in raw {
            let members = parse_outcome_collection(&key);
            let collection =
                canonical_outcome_collection(outcomes, &members).map_err(Error::from)?;
            if collection.len() > MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH {
                return Err(Error::Custom(format!(
                    "Outcome collection exceeds maximum byte length of {}",
                    MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH
                )));
            }
            if !seen.insert(collection.clone()) {
                return Err(Error::OverlappingOutcomeCollections);
            }
            canonical.push(collection);
        }

        if is_numeric {
            let expected: HashSet<String> =
                ["HI".to_string(), "LO".to_string()].into_iter().collect();
            let actual: HashSet<String> = canonical.iter().cloned().collect();
            if actual != expected {
                return Err(Error::Custom(
                    "Numeric conditions only support HI and LO outcome collections".to_string(),
                ));
            }
        }

        Ok(canonical)
    }

    async fn default_keyset_creation_policy(&self) -> Result<String, Error> {
        let policy = self
            .mint_info()
            .await?
            .nuts
            .nut_ctf
            .map(|settings| settings.default_keyset_creation)
            .unwrap_or_else(|| KEYSET_POLICY_NONE.to_string());

        match policy.as_str() {
            KEYSET_POLICY_NONE | KEYSET_POLICY_ONE_VS_REST | KEYSET_POLICY_ALL => Ok(policy),
            _ => Err(Error::Custom(format!(
                "Unsupported default_keyset_creation policy: {}",
                policy
            ))),
        }
    }

    fn default_outcome_collections(
        &self,
        outcomes: &[String],
        policy: &str,
    ) -> Result<Vec<String>, Error> {
        match policy {
            KEYSET_POLICY_NONE => Ok(Vec::new()),
            KEYSET_POLICY_ONE_VS_REST => self.one_vs_rest_collections(outcomes),
            KEYSET_POLICY_ALL => self.all_non_full_collections(outcomes),
            _ => Err(Error::Custom(format!(
                "Unsupported default_keyset_creation policy: {}",
                policy
            ))),
        }
    }

    fn one_vs_rest_collections(&self, outcomes: &[String]) -> Result<Vec<String>, Error> {
        let mut collections = Vec::with_capacity(outcomes.len().saturating_mul(2));
        let mut seen = HashSet::new();

        for outcome in outcomes {
            let singleton = canonical_outcome_collection(outcomes, std::slice::from_ref(outcome))
                .map_err(Error::from)?;
            if seen.insert(singleton.clone()) {
                collections.push(singleton);
            }

            let complement_members = outcomes
                .iter()
                .filter(|candidate| *candidate != outcome)
                .cloned()
                .collect::<Vec<_>>();
            if complement_members.is_empty() {
                continue;
            }
            let complement =
                canonical_outcome_collection(outcomes, &complement_members).map_err(Error::from)?;
            if seen.insert(complement.clone()) {
                collections.push(complement);
            }
        }

        if collections.len() > MAX_OUTCOME_COLLECTIONS {
            return Err(Error::Custom(format!(
                "default_keyset_creation one-vs-rest expands to {} outcome collections, exceeding maximum of {}",
                collections.len(),
                MAX_OUTCOME_COLLECTIONS
            )));
        }

        Ok(collections)
    }

    fn all_non_full_collections(&self, outcomes: &[String]) -> Result<Vec<String>, Error> {
        if outcomes.len() >= usize::BITS as usize {
            return Err(Error::Custom(
                "default_keyset_creation all exceeds platform subset capacity".to_string(),
            ));
        }

        let count = (1usize << outcomes.len()).saturating_sub(2);
        if count > MAX_OUTCOME_COLLECTIONS {
            return Err(Error::Custom(format!(
                "default_keyset_creation all expands to {} outcome collections, exceeding maximum of {}",
                count,
                MAX_OUTCOME_COLLECTIONS
            )));
        }

        let mut collections = Vec::with_capacity(count);
        for mask in 1usize..((1usize << outcomes.len()) - 1) {
            let members = outcomes
                .iter()
                .enumerate()
                .filter_map(|(index, outcome)| {
                    if mask & (1usize << index) != 0 {
                        Some(outcome.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            collections
                .push(canonical_outcome_collection(outcomes, &members).map_err(Error::from)?);
        }

        Ok(collections)
    }

    async fn prepare_condition_keysets(
        &self,
        condition_id: &str,
        condition_id_bytes: &[u8; 32],
        outcome_collections: &[String],
        collateral: Option<&str>,
    ) -> Result<Vec<(String, cdk_signatory::signatory::PreparedConditionalKeySet)>, Error> {
        if outcome_collections.is_empty() {
            return Ok(Vec::new());
        }

        let collateral = collateral.ok_or_else(|| {
            Error::Custom(
                "collateral is required when creating outcome collection keysets".to_string(),
            )
        })?;
        let unit = cdk_common::CurrencyUnit::from_str(collateral)
            .map_err(|_| Error::Custom(format!("Invalid collateral unit: {}", collateral)))?;
        let parent_collection_id_bytes = [0u8; 32];
        let amounts = (0..32).map(|n| 2u64.pow(n)).collect::<Vec<u64>>();
        let mut keysets = Vec::with_capacity(outcome_collections.len());

        for outcome_collection_string in outcome_collections {
            let outcome_collection_id_bytes = compute_outcome_collection_id(
                &parent_collection_id_bytes,
                condition_id_bytes,
                outcome_collection_string,
            )?;
            let outcome_collection_id = to_hex(&outcome_collection_id_bytes);
            validate_conditional_keyset_catalogue_fields(
                &unit.to_string(),
                condition_id,
                outcome_collection_string,
                &outcome_collection_id,
            )
            .map_err(|detail| Error::Custom(detail.to_string()))?;

            let keyset = self
                .signatory
                .prepare_conditional_keyset(
                    unit.clone(),
                    condition_id,
                    outcome_collection_string,
                    &outcome_collection_id,
                    amounts.clone(),
                    1,
                    None,
                )
                .await?;

            keysets.push((outcome_collection_string.clone(), keyset));
        }

        Ok(keysets)
    }

    /// Get all conditions (GET /v1/conditions)
    ///
    /// Supports cursor-based pagination via `since`+`limit` and repeatable `status` filter.
    #[instrument(skip_all)]
    pub async fn get_conditions(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        status: &[String],
    ) -> Result<GetConditionsResponse, Error> {
        // Validate status filter values
        for s in status {
            if !VALID_CONDITION_STATUSES.contains(&s.as_str()) {
                return Err(Error::Custom(format!(
                    "Invalid status filter value: '{}'. Valid values are: {}",
                    s,
                    VALID_CONDITION_STATUSES.join(", ")
                )));
            }
        }

        // Cap limit to MAX_PAGE_SIZE
        let limit = limit.map(|l| l.min(MAX_PAGE_SIZE));

        let conditions = self.localstore.get_conditions(since, limit, status).await?;
        let mut infos = Vec::new();

        // TODO: N+1 query — build_condition_info loads keysets per condition.
        // Batch when condition count grows.
        for condition in conditions {
            let info = self.build_condition_info(condition).await?;
            infos.push(info);
        }

        Ok(GetConditionsResponse { conditions: infos })
    }

    /// Get a specific condition (GET /v1/conditions/{condition_id})
    #[instrument(skip_all)]
    pub async fn get_condition(&self, condition_id: &str) -> Result<ConditionInfo, Error> {
        let condition = self
            .localstore
            .get_condition(condition_id)
            .await?
            .ok_or(Error::ConditionNotFound)?;

        self.build_condition_info(condition).await
    }

    /// Build a ConditionInfo from a StoredCondition, including keysets
    async fn build_condition_info(
        &self,
        condition: StoredCondition,
    ) -> Result<ConditionInfo, Error> {
        let announcements: Vec<String> = serde_json::from_str(&condition.announcements_json)?;

        let keysets = self
            .localstore
            .get_conditional_keysets_for_condition(&condition.condition_id)
            .await?;

        Ok(ConditionInfo {
            condition_id: condition.condition_id,
            threshold: condition.threshold,
            tags: serde_json::from_str(&condition.tags_json).unwrap_or_default(),
            announcements,
            collateral: condition.collateral,
            keysets,
            attestation: Some(AttestationState {
                status: match condition.attestation_status.as_str() {
                    STATUS_ATTESTED => AttestationStatus::Attested,
                    "expired" => AttestationStatus::Expired,
                    "violation" => AttestationStatus::Violation,
                    _ => AttestationStatus::Pending,
                },
                winning_outcome: condition.winning_outcome,
                attested_at: condition.attested_at,
            }),
            condition_type: condition.condition_type,
            lo_bound: condition.lo_bound,
            hi_bound: condition.hi_bound,
            precision: condition.precision,
            registered_at: condition.created_at,
        })
    }

    /// Get conditional keysets through the legacy raw-listing contract.
    #[instrument(skip_all)]
    pub async fn get_conditional_keysets(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
    ) -> Result<ConditionalKeysetsResponse, Error> {
        let limit = limit.unwrap_or(LEGACY_MAX_PAGE_SIZE);
        if limit == 0 || limit > LEGACY_MAX_PAGE_SIZE {
            return Err(Error::ConditionalKeysetCataloguePageLimitExceeded {
                requested: limit,
                max: LEGACY_MAX_PAGE_SIZE,
            });
        }
        let keysets = self
            .localstore
            .get_all_conditional_keyset_infos(since, Some(limit), active)
            .await?;
        for keyset in &keysets {
            validate_conditional_keyset_catalogue_fields(
                &keyset.unit,
                &keyset.condition_id,
                &keyset.outcome_collection,
                &keyset.outcome_collection_id,
            )
            .map_err(|detail| {
                Error::InvalidConditionalKeysetCatalogueResponse(detail.to_string())
            })?;
        }
        Ok(ConditionalKeysetsResponse {
            keysets,
            next_cursor: None,
            complete: false,
        })
    }

    /// Get one bounded, mint-authenticated page over an immutable snapshot.
    #[instrument(skip_all)]
    pub async fn get_conditional_keysets_catalogue_page(
        &self,
        request: GetConditionalKeysetsRequest,
    ) -> Result<ConditionalKeysetsResponse, Error> {
        if !self.conditional_keyset_catalogue_available
            || request.catalogue_version != Some(CONDITIONAL_KEYSET_CATALOGUE_VERSION)
        {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        }
        let limit = request.limit.unwrap_or(MAX_PAGE_SIZE);
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(Error::ConditionalKeysetCataloguePageLimitExceeded {
                requested: limit,
                max: MAX_PAGE_SIZE,
            });
        }
        if request
            .since
            .is_some_and(|since| since > MAX_SIGNED_SQL_INTEGER)
        {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        }

        let cursor = match request.cursor.as_deref() {
            Some(cursor) => Some(self.decode_conditional_keyset_cursor(cursor).await?),
            None => None,
        };
        let (snapshot, after, since, active) = match cursor {
            Some(cursor) => {
                if request.since.is_some() && request.since != cursor.since
                    || request.active.is_some() && request.active != cursor.active
                {
                    return Err(Error::InvalidConditionalKeysetCatalogueCursor);
                }
                (
                    Some(cursor.snapshot),
                    cursor.after,
                    cursor.since,
                    cursor.active,
                )
            }
            None => (None, 0, request.since, request.active),
        };

        let page = self
            .localstore
            .get_conditional_keyset_catalogue_page(snapshot, after, limit)
            .await?;
        if page.keysets.len() > limit as usize {
            return Err(Error::InvalidConditionalKeysetCatalogueResponse(
                "page exceeded requested limit".to_string(),
            ));
        }
        if snapshot.is_some_and(|snapshot| page.snapshot != snapshot)
            || page.snapshot > MAX_SIGNED_SQL_INTEGER
            || page.snapshot < after
        {
            return Err(Error::InvalidConditionalKeysetCatalogueResponse(
                "database returned an invalid catalogue snapshot".to_string(),
            ));
        }

        let mut last_scanned = after;
        for entry in &page.keysets {
            validate_conditional_keyset_catalogue_fields(
                &entry.keyset.unit,
                &entry.keyset.condition_id,
                &entry.keyset.outcome_collection,
                &entry.keyset.outcome_collection_id,
            )
            .map_err(|detail| {
                Error::InvalidConditionalKeysetCatalogueResponse(detail.to_string())
            })?;
            let expected = last_scanned.checked_add(1).ok_or(
                Error::InvalidConditionalKeysetCatalogueResponse(
                    "database catalogue sequence overflowed".to_string(),
                ),
            )?;
            if entry.sequence != expected || entry.sequence > page.snapshot {
                return Err(Error::InvalidConditionalKeysetCatalogueResponse(
                    "database returned non-contiguous catalogue sequences".to_string(),
                ));
            }
            last_scanned = entry.sequence;
        }

        if !page.has_more && last_scanned != page.snapshot {
            return Err(Error::InvalidConditionalKeysetCatalogueResponse(
                "database completed before the catalogue snapshot boundary".to_string(),
            ));
        }

        let next_cursor = if page.has_more {
            if last_scanned == after {
                return Err(Error::ConditionalKeysetCatalogueNoProgress);
            }
            Some(
                self.encode_conditional_keyset_cursor(&ConditionalKeysetCatalogueCursor {
                    version: CONDITIONAL_KEYSET_CATALOGUE_VERSION,
                    snapshot: page.snapshot,
                    after: last_scanned,
                    since,
                    active,
                })
                .await?,
            )
        } else {
            None
        };

        let keysets = page
            .keysets
            .into_iter()
            .map(|entry| entry.keyset)
            .filter(|keyset| {
                since.is_none_or(|since| keyset.registered_at >= since)
                    && active.is_none_or(|active| keyset.active == active)
            })
            .collect();

        Ok(ConditionalKeysetsResponse {
            keysets,
            next_cursor,
            complete: !page.has_more,
        })
    }

    pub(super) async fn conditional_keyset_cursor_key(&self) -> Result<&[u8; 32], Error> {
        let key = self
            .conditional_keyset_cursor_key
            .get_or_try_init(|| async {
                let mut candidate = Zeroizing::new([0_u8; 32]);
                getrandom::getrandom(&mut *candidate)
                    .map_err(|err| Error::Custom(format!("secure random source failed: {err}")))?;
                let stored = self
                    .localstore
                    .get_or_create_conditional_keyset_cursor_key(candidate)
                    .await?;
                if stored.iter().all(|byte| *byte == 0) {
                    return Err(Error::Internal);
                }
                Ok(stored)
            })
            .await?;
        Ok(&**key)
    }

    async fn encode_conditional_keyset_cursor(
        &self,
        cursor: &ConditionalKeysetCatalogueCursor,
    ) -> Result<String, Error> {
        let header = URL_SAFE_NO_PAD.encode(CONDITIONAL_KEYSET_CURSOR_HEADER);
        let claims = serde_json::to_vec(cursor).map_err(|_| Error::Internal)?;
        let payload = URL_SAFE_NO_PAD.encode(claims);
        let signing_input = format!("{header}.{payload}");
        let tag = conditional_keyset_cursor_mac(
            self.conditional_keyset_cursor_key().await?,
            signing_input.as_bytes(),
        );
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(tag.as_slice())
        ))
    }

    async fn decode_conditional_keyset_cursor(
        &self,
        cursor: &str,
    ) -> Result<ConditionalKeysetCatalogueCursor, Error> {
        if cursor.is_empty() || cursor.len() > MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        }
        let mut segments = cursor.split('.');
        let (Some(header_segment), Some(payload_segment), Some(tag_segment), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        };
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_segment)
            .map_err(|_| Error::InvalidConditionalKeysetCatalogueCursor)?;
        let header: ConditionalKeysetCursorHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| Error::InvalidConditionalKeysetCatalogueCursor)?;
        if header.alg != CONDITIONAL_KEYSET_CURSOR_ALGORITHM
            || header.typ != CONDITIONAL_KEYSET_CURSOR_TYPE
        {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        }
        let tag = URL_SAFE_NO_PAD
            .decode(tag_segment)
            .map_err(|_| Error::InvalidConditionalKeysetCatalogueCursor)?;
        if tag.len() != 32 {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        }
        let signing_input = format!("{header_segment}.{payload_segment}");
        let expected_tag = conditional_keyset_cursor_mac(
            self.conditional_keyset_cursor_key().await?,
            signing_input.as_bytes(),
        );
        if !bool::from(expected_tag.as_slice().ct_eq(tag.as_slice())) {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        }
        let claims_bytes = URL_SAFE_NO_PAD
            .decode(payload_segment)
            .map_err(|_| Error::InvalidConditionalKeysetCatalogueCursor)?;
        let claims: ConditionalKeysetCatalogueCursor = serde_json::from_slice(&claims_bytes)
            .map_err(|_| Error::InvalidConditionalKeysetCatalogueCursor)?;
        if claims.version != CONDITIONAL_KEYSET_CATALOGUE_VERSION
            || claims.after > claims.snapshot
            || claims.snapshot > MAX_SIGNED_SQL_INTEGER
            || claims.after > MAX_SIGNED_SQL_INTEGER
            || claims
                .since
                .is_some_and(|since| since > MAX_SIGNED_SQL_INTEGER)
        {
            return Err(Error::InvalidConditionalKeysetCatalogueCursor);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::remove_file;
    use std::str::FromStr;
    #[cfg(feature = "test-utils")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use bitcoin::bip32::DerivationPath;
    #[cfg(feature = "test-utils")]
    use cdk_common::amount::SplitTarget;
    use cdk_common::mint::{MintKeySetInfo, StoredCondition};
    #[cfg(feature = "test-utils")]
    use cdk_common::nuts::nut_ctf::test_helpers::{create_test_announcement, create_test_oracle};
    #[cfg(feature = "test-utils")]
    use cdk_common::nuts::nut_ctf::RegisterConditionRequest;
    use cdk_common::nuts::nut_ctf::{
        GetConditionalKeysetsRequest, NutCtfSettings, RegistrationFeeSetting,
    };
    #[cfg(feature = "test-utils")]
    use cdk_common::nuts::{PreMintSecrets, ProofsMethods};
    #[cfg(feature = "test-utils")]
    use cdk_common::Amount;
    use cdk_common::{CurrencyUnit, Id};

    use super::*;

    #[cfg(feature = "test-utils")]
    struct CountingConditionsDatabase {
        condition_lookups: AtomicUsize,
    }

    #[cfg(feature = "test-utils")]
    #[async_trait::async_trait]
    impl ConditionsDatabase for CountingConditionsDatabase {
        type Err = cdk_common::database::Error;

        async fn add_condition(&self, _condition: StoredCondition) -> Result<(), Self::Err> {
            unreachable!("not used by fee lookup admission test")
        }

        async fn get_condition(
            &self,
            _condition_id: &str,
        ) -> Result<Option<StoredCondition>, Self::Err> {
            unreachable!("not used by fee lookup admission test")
        }

        async fn get_conditions(
            &self,
            _since: Option<u64>,
            _limit: Option<u64>,
            _status: &[String],
        ) -> Result<Vec<StoredCondition>, Self::Err> {
            unreachable!("not used by fee lookup admission test")
        }

        async fn update_condition_attestation(
            &self,
            _condition_id: &str,
            _status: &str,
            _winning_outcome: Option<&str>,
            _attested_at: Option<u64>,
        ) -> Result<bool, Self::Err> {
            unreachable!("not used by fee lookup admission test")
        }

        async fn get_conditional_keysets_for_condition(
            &self,
            _condition_id: &str,
        ) -> Result<HashMap<String, Id>, Self::Err> {
            unreachable!("not used by fee lookup admission test")
        }

        async fn get_all_conditional_keyset_infos(
            &self,
            _since: Option<u64>,
            _limit: Option<u64>,
            _active: Option<bool>,
        ) -> Result<Vec<cdk_common::nuts::nut_ctf::ConditionalKeySetInfo>, Self::Err> {
            unreachable!("not used by fee lookup admission test")
        }

        async fn get_condition_for_keyset(
            &self,
            _keyset_id: &Id,
        ) -> Result<Option<(String, String, String)>, Self::Err> {
            self.condition_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    async fn mint_with_registration_fee(base: u64, per_keyset: u64) -> Mint {
        let mint = crate::test_helpers::mint::create_test_mint()
            .await
            .expect("test mint should be created");
        let mut mint_info = mint.mint_info().await.expect("mint info should load");
        mint_info.nuts.nut_ctf = Some(NutCtfSettings {
            registration_fees: vec![RegistrationFeeSetting {
                unit: CurrencyUnit::Sat.to_string(),
                registration_fee_base: base,
                registration_fee_per_keyset: per_keyset,
            }],
            ..NutCtfSettings::default()
        });
        mint.set_mint_info(mint_info)
            .await
            .expect("mint info should be updated");
        mint
    }

    async fn mint_with_shared_database(
        db: Arc<cdk_sqlite::mint::MintSqliteDatabase>,
        seed: &[u8; 64],
    ) -> Mint {
        let mut builder = super::super::MintBuilder::new(db.clone());
        builder
            .configure_unit(
                CurrencyUnit::Sat,
                super::super::UnitConfig {
                    amounts: vec![1, 2, 4, 8],
                    input_fee_ppk: 0,
                },
            )
            .expect("unit should be configured");
        builder
            .build_with_seed(db, seed)
            .await
            .expect("mint should build")
    }

    fn stored_condition(condition_id: &str) -> StoredCondition {
        StoredCondition {
            condition_id: condition_id.to_string(),
            threshold: 1,
            tags_json: "[]".to_string(),
            announcements_json: "[]".to_string(),
            collateral: Some(CurrencyUnit::Sat),
            attestation_status: STATUS_PENDING.to_string(),
            winning_outcome: None,
            attested_at: None,
            created_at: 1_000,
            condition_type: CONDITION_TYPE_ENUM.to_string(),
            lo_bound: None,
            hi_bound: None,
            precision: None,
        }
    }

    fn catalogue_request() -> GetConditionalKeysetsRequest {
        GetConditionalKeysetsRequest {
            catalogue_version: Some(CONDITIONAL_KEYSET_CATALOGUE_VERSION),
            ..Default::default()
        }
    }

    fn conditional_keyset(
        id: &str,
        condition_id: &str,
        outcome: &str,
        outcome_id: &str,
    ) -> MintKeySetInfo {
        MintKeySetInfo {
            id: Id::from_str(id).expect("keyset id should parse"),
            unit: CurrencyUnit::Sat,
            active: false,
            valid_from: 0,
            derivation_path: DerivationPath::from_str("m/0'/0'/0'")
                .expect("derivation path should parse"),
            derivation_path_index: Some(0),
            amounts: vec![1, 2, 4, 8],
            input_fee_ppk: 0,
            final_expiry: None,
            issuer_version: None,
            condition_id: Some(condition_id.to_string()),
            outcome_collection: Some(outcome.to_string()),
            outcome_collection_id: Some(outcome_id.to_string()),
        }
    }

    async fn insert_catalogue_fixture(
        mint: &Mint,
        condition_id: &str,
        keysets: Vec<MintKeySetInfo>,
    ) {
        let condition_exists = mint
            .localstore
            .get_condition(condition_id)
            .await
            .expect("condition lookup should succeed")
            .is_some();
        let mut tx = mint
            .localstore
            .begin_transaction()
            .await
            .expect("transaction should start");
        if !condition_exists {
            tx.add_condition(stored_condition(condition_id))
                .await
                .expect("condition should be inserted");
        }
        for keyset in keysets {
            tx.add_conditional_keyset(keyset, 1_000)
                .await
                .expect("conditional keyset should be inserted");
        }
        tx.commit().await.expect("transaction should commit");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn oversized_registration_fee_skips_per_proof_database_lookups() {
        let mint = mint_with_registration_fee(1, 0).await;
        let fee = crate::test_helpers::mint::mint_test_proofs(&mint, Amount::from(3))
            .await
            .expect("two fee proofs should mint");
        assert_eq!(fee.len(), 2);
        let database = CountingConditionsDatabase {
            condition_lookups: AtomicUsize::new(0),
        };

        let error = validate_registration_fee_condition_lookups(&database, &fee, 1)
            .await
            .expect_err("fee count should reject before database lookup");
        assert!(matches!(
            error,
            Error::MaxInputsExceeded { actual: 2, max: 1 }
        ));
        assert_eq!(database.condition_lookups.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn idempotent_registration_reconciles_committed_keysets_without_charging_fee() {
        let mint = mint_with_registration_fee(2, 3).await;
        let fee_proofs = crate::test_helpers::mint::mint_test_proofs(&mint, Amount::from(8))
            .await
            .expect("fee proofs should mint");
        let fee_ys = fee_proofs.ys().expect("fee proof Ys should derive");
        let oracle = create_test_oracle();
        let (_, announcement) =
            create_test_announcement(&oracle, &["YES", "NO"], "committed-orphan");
        let request = RegisterConditionRequest {
            threshold: 1,
            tags: vec![vec![
                "description".to_string(),
                "Committed orphan".to_string(),
            ]],
            announcements: vec![announcement.clone()],
            collateral: Some(CurrencyUnit::Sat.to_string()),
            outcome_collections: Some(vec!["YES".to_string(), "NO".to_string()]),
            fee: Some(fee_proofs),
            outputs: None,
            condition_type: CONDITION_TYPE_ENUM.to_string(),
            lo_bound: None,
            hi_bound: None,
            precision: None,
        };

        let parsed =
            dlc::parse_oracle_announcement(&announcement).expect("test announcement should parse");
        let oracle_pubkeys = vec![dlc::extract_oracle_pubkey(&parsed).to_vec()];
        let event_id = dlc::extract_event_id(&parsed);
        let condition_id_bytes = compute_condition_id(&oracle_pubkeys, &event_id, 2);
        let condition_id = to_hex(&condition_id_bytes);
        let prepared = mint
            .prepare_condition_keysets(
                &condition_id,
                &condition_id_bytes,
                &["YES".to_string(), "NO".to_string()],
                Some("sat"),
            )
            .await
            .expect("conditional keysets should prepare without installation");
        let expected_keysets = prepared
            .iter()
            .map(|(collection, keyset)| (collection.clone(), keyset.keyset.id))
            .collect::<HashMap<_, _>>();
        let committed_keysets = prepared
            .into_iter()
            .map(|(_, keyset)| keyset.info)
            .collect::<Vec<_>>();

        let mut tx = mint
            .localstore
            .begin_transaction()
            .await
            .expect("transaction should start");
        tx.add_condition(StoredCondition {
            condition_id: condition_id.clone(),
            threshold: request.threshold,
            tags_json: serde_json::to_string(&request.tags).expect("tags should serialize"),
            announcements_json: serde_json::to_string(&request.announcements)
                .expect("announcements should serialize"),
            collateral: Some(CurrencyUnit::Sat),
            attestation_status: STATUS_PENDING.to_string(),
            winning_outcome: None,
            attested_at: None,
            created_at: 1_000,
            condition_type: request.condition_type.clone(),
            lo_bound: None,
            hi_bound: None,
            precision: None,
        })
        .await
        .expect("condition should commit");
        tx.add_conditional_keysets(
            committed_keysets
                .into_iter()
                .map(|keyset| (keyset, 1_000))
                .collect(),
        )
        .await
        .expect("conditional keysets should commit");
        tx.commit().await.expect("orphan transaction should commit");

        let response = mint
            .register_condition(request)
            .await
            .expect("idempotent retry should reconcile the committed keysets");
        assert_eq!(response.condition_id, condition_id);
        assert_eq!(response.keysets, expected_keysets);
        assert!(response.change.is_none());
        assert!(
            mint.localstore
                .get_proofs_states(&fee_ys)
                .await
                .expect("fee proof states should load")
                .iter()
                .all(Option::is_none),
            "idempotent reconciliation must not charge the fee"
        );

        for keyset_id in response.keysets.values() {
            let keys = mint
                .keyset_pubkeys(keyset_id)
                .expect("reconciliation should publish the keyset in the mint cache")
                .keysets
                .first()
                .expect("keyset response should contain one entry")
                .keys
                .clone();
            let fee_and_amounts: (u64, Vec<u64>) =
                (0, keys.iter().map(|(amount, _)| amount.to_u64()).collect());
            let premint = PreMintSecrets::random(
                *keyset_id,
                Amount::from(1),
                &SplitTarget::None,
                &fee_and_amounts.into(),
            )
            .expect("premint should build for the reconciled keyset");
            let signatures = mint
                .blind_sign(premint.blinded_messages())
                .await
                .expect("reconciled keyset should be immediately signable");
            assert_eq!(signatures.len(), 1);
        }
    }

    #[tokio::test]
    async fn conditional_keyset_catalogue_rejects_forged_cursor() {
        let mint = mint_with_registration_fee(0, 0).await;

        let result = mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some("v1.not-a-mint-authenticated-cursor".to_string()),
                limit: Some(1),
                ..catalogue_request()
            })
            .await;

        assert!(matches!(
            result,
            Err(Error::InvalidConditionalKeysetCatalogueCursor)
        ));

        let condition_id = "fa".repeat(32);
        insert_catalogue_fixture(
            &mint,
            &condition_id,
            vec![
                conditional_keyset("00916bbf7ef91a36", &condition_id, "YES", &"f1".repeat(32)),
                conditional_keyset("009a1f293253e41e", &condition_id, "NO", &"f2".repeat(32)),
            ],
        )
        .await;
        let first = mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                limit: Some(1),
                ..catalogue_request()
            })
            .await
            .expect("first page should produce a valid cursor");
        let mut altered = first
            .next_cursor
            .expect("two rows should require continuation")
            .into_bytes();
        let signature_start = altered
            .iter()
            .rposition(|byte| *byte == b'.')
            .expect("JWT cursor should have a signature segment")
            + 1;
        altered[signature_start] = if altered[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let result = mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some(String::from_utf8(altered).expect("cursor remains base64url text")),
                limit: Some(1),
                ..catalogue_request()
            })
            .await;
        assert!(matches!(
            result,
            Err(Error::InvalidConditionalKeysetCatalogueCursor)
        ));
    }

    #[tokio::test]
    async fn legacy_listing_remains_raw_without_catalogue_capability() {
        let mint = mint_with_registration_fee(0, 0).await;
        let condition_id = "fd".repeat(32);
        insert_catalogue_fixture(
            &mint,
            &condition_id,
            vec![conditional_keyset(
                "00916bbf7ef91a36",
                &condition_id,
                "YES",
                &"f3".repeat(32),
            )],
        )
        .await;

        let response = mint
            .get_conditional_keysets(None, Some(1), None)
            .await
            .expect("legacy raw listing should succeed");
        assert_eq!(response.keysets.len(), 1);
        assert!(!response.complete);
        assert!(response.next_cursor.is_none());
    }

    #[tokio::test]
    async fn mint_info_omits_catalogue_without_ctf_or_backend_authority() {
        let ordinary = crate::test_helpers::mint::create_test_mint()
            .await
            .expect("ordinary mint should build");
        let mut ordinary_info = ordinary.mint_info().await.expect("mint info should load");
        ordinary_info.nuts.nut_ctf = None;
        ordinary
            .set_mint_info(ordinary_info)
            .await
            .expect("ordinary mint info should persist");
        assert!(ordinary
            .mint_info()
            .await
            .expect("ordinary mint info should remain available")
            .nuts
            .nut_ctf
            .is_none());

        let mut no_authority = mint_with_registration_fee(0, 0).await;
        no_authority.conditional_keyset_catalogue_available = false;
        let info = no_authority
            .mint_info()
            .await
            .expect("CTF mint info must remain available without catalogue authority");
        assert!(info
            .nuts
            .nut_ctf
            .expect("CTF settings remain available")
            .conditional_keyset_catalogue
            .is_none());
        assert!(matches!(
            no_authority
                .get_conditional_keysets_catalogue_page(catalogue_request())
                .await,
            Err(Error::InvalidConditionalKeysetCatalogueCursor)
        ));
    }

    #[tokio::test]
    async fn conditional_keyset_catalogue_snapshot_excludes_same_timestamp_late_registration() {
        let mint = mint_with_registration_fee(0, 0).await;
        let condition_id = "aa".repeat(32);
        insert_catalogue_fixture(
            &mint,
            &condition_id,
            vec![
                conditional_keyset("00916bbf7ef91a36", &condition_id, "YES", &"01".repeat(32)),
                conditional_keyset("009a1f293253e41e", &condition_id, "NO", &"02".repeat(32)),
            ],
        )
        .await;

        let first = mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                limit: Some(1),
                ..catalogue_request()
            })
            .await
            .expect("first page should succeed");
        assert_eq!(first.keysets.len(), 1);
        assert!(!first.complete);
        let cursor = first.next_cursor.expect("first page should continue");

        insert_catalogue_fixture(
            &mint,
            &condition_id,
            vec![conditional_keyset(
                "0095000000000000",
                &condition_id,
                "MAYBE",
                &"03".repeat(32),
            )],
        )
        .await;

        let second = mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some(cursor),
                limit: Some(1),
                ..catalogue_request()
            })
            .await
            .expect("second page should succeed");

        assert_eq!(second.keysets.len(), 1);
        assert!(second.complete);
        assert!(second.next_cursor.is_none());
        assert_ne!(second.keysets[0].id.to_string(), "0095000000000000");
    }

    #[tokio::test]
    async fn conditional_keyset_catalogue_cursor_survives_other_instance_and_restart() {
        let file = std::env::temp_dir().join(format!(
            "cdk_catalogue_restart_{}.sqlite",
            std::process::id()
        ));
        let _ = remove_file(&file);
        let db = Arc::new(
            cdk_sqlite::mint::MintSqliteDatabase::new(file.to_string_lossy().as_ref())
                .await
                .expect("file-backed database should open"),
        );
        let seed = [0x42; 64];
        let first_mint = mint_with_shared_database(db.clone(), &seed).await;
        let second_mint = mint_with_shared_database(db.clone(), &seed).await;
        let mut info = first_mint.mint_info().await.expect("mint info should load");
        info.nuts.nut_ctf = Some(NutCtfSettings::default());
        first_mint
            .set_mint_info(info)
            .await
            .expect("mint info should persist");

        let (first_info, second_info) =
            tokio::join!(first_mint.mint_info(), second_mint.mint_info());
        for info in [first_info.unwrap(), second_info.unwrap()] {
            let capability = info
                .nuts
                .nut_ctf
                .and_then(|settings| settings.conditional_keyset_catalogue)
                .expect("CTF mint should advertise catalogue capability");
            assert_eq!(capability.version, CONDITIONAL_KEYSET_CATALOGUE_VERSION);
            assert_eq!(capability.max_page_size, MAX_PAGE_SIZE);
        }

        let condition_id_bytes = [0xbb; 32];
        let condition_id = to_hex(&condition_id_bytes);
        let prepared = first_mint
            .prepare_condition_keysets(
                &condition_id,
                &condition_id_bytes,
                &["YES".to_string(), "NO".to_string()],
                Some("sat"),
            )
            .await
            .expect("restart fixture keysets should derive from the mint seed");
        insert_catalogue_fixture(
            &first_mint,
            &condition_id,
            prepared
                .into_iter()
                .map(|(_, keyset)| keyset.info)
                .collect(),
        )
        .await;
        let first = first_mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                limit: Some(1),
                ..catalogue_request()
            })
            .await
            .unwrap();
        let cursor = first.next_cursor.expect("scan should continue");

        let continued = second_mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some(cursor.clone()),
                limit: Some(1),
                ..catalogue_request()
            })
            .await
            .expect("other mint instance should validate cursor");
        assert!(continued.complete);

        drop(first_mint);
        drop(second_mint);
        drop(db);
        let reopened = Arc::new(
            cdk_sqlite::mint::MintSqliteDatabase::new(file.to_string_lossy().as_ref())
                .await
                .expect("file-backed database should reopen"),
        );
        let restarted = mint_with_shared_database(reopened.clone(), &seed).await;
        let continued = restarted
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some(cursor),
                limit: Some(1),
                ..catalogue_request()
            })
            .await
            .expect("restarted mint should validate cursor");
        assert!(continued.complete);
        drop(restarted);
        drop(reopened);
        let _ = remove_file(file);
    }

    #[tokio::test]
    async fn conditional_keyset_catalogue_rejects_cursor_and_limit_contract_violations() {
        let mint = mint_with_registration_fee(0, 0).await;
        for limit in [0, MAX_PAGE_SIZE + 1] {
            assert!(matches!(
                mint.get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                    limit: Some(limit),
                    ..catalogue_request()
                })
                .await,
                Err(Error::ConditionalKeysetCataloguePageLimitExceeded { .. })
            ));
        }
        assert!(matches!(
            mint.get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some("x".repeat(MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH + 1)),
                ..catalogue_request()
            })
            .await,
            Err(Error::InvalidConditionalKeysetCatalogueCursor)
        ));

        let wrong_version = mint
            .encode_conditional_keyset_cursor(&ConditionalKeysetCatalogueCursor {
                version: CONDITIONAL_KEYSET_CATALOGUE_VERSION + 1,
                snapshot: 1,
                after: 0,
                since: None,
                active: None,
            })
            .await
            .unwrap();
        let invalid_bounds = mint
            .encode_conditional_keyset_cursor(&ConditionalKeysetCatalogueCursor {
                version: CONDITIONAL_KEYSET_CATALOGUE_VERSION,
                snapshot: 1,
                after: 2,
                since: None,
                active: None,
            })
            .await
            .unwrap();
        for cursor in [wrong_version, invalid_bounds] {
            assert!(matches!(
                mint.get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                    cursor: Some(cursor),
                    ..catalogue_request()
                })
                .await,
                Err(Error::InvalidConditionalKeysetCatalogueCursor)
            ));
        }
    }

    #[tokio::test]
    async fn conditional_keyset_catalogue_binds_filters_and_exhausts_cleanly() {
        let mint = mint_with_registration_fee(0, 0).await;
        let empty = mint
            .get_conditional_keysets_catalogue_page(catalogue_request())
            .await
            .unwrap();
        assert!(empty.keysets.is_empty());
        assert!(empty.complete);
        assert!(empty.next_cursor.is_none());

        let condition_id = "cc".repeat(32);
        insert_catalogue_fixture(
            &mint,
            &condition_id,
            vec![
                conditional_keyset("00916bbf7ef91a36", &condition_id, "YES", &"51".repeat(32)),
                conditional_keyset("009a1f293253e41e", &condition_id, "NO", &"52".repeat(32)),
            ],
        )
        .await;
        let first = mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                limit: Some(1),
                active: Some(false),
                ..catalogue_request()
            })
            .await
            .unwrap();
        let cursor = first.next_cursor.expect("scan should continue");
        assert!(matches!(
            mint.get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some(cursor.clone()),
                limit: Some(1),
                active: Some(true),
                ..catalogue_request()
            })
            .await,
            Err(Error::InvalidConditionalKeysetCatalogueCursor)
        ));

        let final_page = mint
            .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some(cursor),
                limit: Some(1),
                ..catalogue_request()
            })
            .await
            .unwrap();
        assert_eq!(final_page.keysets.len(), 1);
        assert!(final_page.complete);
        assert!(final_page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn conditional_keyset_catalogue_sparse_filter_advances_bounded_raw_windows() {
        const TOTAL: usize = 10_001;
        const PAGE_SIZE: u64 = 100;

        let mint = mint_with_registration_fee(0, 0).await;
        let condition_id = "ce".repeat(32);
        let mut tx = mint
            .localstore
            .begin_transaction()
            .await
            .expect("transaction should start");
        tx.add_condition(stored_condition(&condition_id))
            .await
            .expect("condition should insert");
        for chunk_start in (0..TOTAL).step_by(MAX_OUTCOME_COLLECTIONS) {
            let chunk_end = (chunk_start + MAX_OUTCOME_COLLECTIONS).min(TOTAL);
            let batch = (chunk_start..chunk_end)
                .map(|index| {
                    let mut keyset = conditional_keyset(
                        &format!("00{:014x}", index + 1),
                        &condition_id,
                        &format!("OUTCOME-{index}"),
                        &format!("{:064x}", index + 1),
                    );
                    keyset.active = index % 1_000 == 0;
                    (keyset, if index % 1_000 == 0 { 2_000 } else { 1_000 })
                })
                .collect();
            tx.add_conditional_keysets(batch)
                .await
                .expect("catalogue chunk should insert");
        }
        tx.commit().await.expect("catalogue fixture should commit");

        let mut cursor = None;
        let mut previous_after = 0;
        let mut calls = 0;
        let mut matching = Vec::new();
        loop {
            let page = mint
                .get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                    since: Some(2_000),
                    active: Some(true),
                    limit: Some(PAGE_SIZE),
                    cursor,
                    ..catalogue_request()
                })
                .await
                .expect("bounded sparse page should succeed");
            calls += 1;
            matching.extend(page.keysets);
            if page.complete {
                assert!(page.next_cursor.is_none());
                break;
            }

            let next = page.next_cursor.expect("incomplete page must advance");
            let claims = mint
                .decode_conditional_keyset_cursor(&next)
                .await
                .expect("mint cursor should decode");
            assert!(claims.after > previous_after, "cursor must make progress");
            assert!(
                claims.after - previous_after <= PAGE_SIZE,
                "one database call scanned more than the requested raw window"
            );
            previous_after = claims.after;
            cursor = Some(next);
        }

        assert_eq!(calls, 101, "10,001 rows require 101 bounded raw windows");
        assert_eq!(matching.len(), 11);
        assert!(matching.iter().all(|keyset| keyset.active));
        assert!(matching.iter().all(|keyset| keyset.registered_at >= 2_000));
    }

    #[tokio::test]
    async fn conditional_keyset_catalogue_rejects_unsigned_cursor_and_filter_overflow() {
        let mint = mint_with_registration_fee(0, 0).await;
        let oversized_cursor = mint
            .encode_conditional_keyset_cursor(&ConditionalKeysetCatalogueCursor {
                version: CONDITIONAL_KEYSET_CATALOGUE_VERSION,
                snapshot: u64::MAX,
                after: 0,
                since: None,
                active: None,
            })
            .await
            .expect("syntactically valid cursor should encode");

        assert!(matches!(
            mint.get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                cursor: Some(oversized_cursor),
                ..catalogue_request()
            })
            .await,
            Err(Error::InvalidConditionalKeysetCatalogueCursor)
        ));
        assert!(
            mint.get_conditional_keysets_catalogue_page(GetConditionalKeysetsRequest {
                since: Some(u64::MAX),
                ..catalogue_request()
            })
            .await
            .is_err(),
            "strict since must reject values outside signed SQL range"
        );
    }

    #[tokio::test]
    async fn required_registration_fee_overflows_when_max_base_is_added_to_per_keyset_fee() {
        let mint = mint_with_registration_fee(u64::MAX, 1).await;

        let result = mint.required_registration_fee(1, &CurrencyUnit::Sat).await;

        assert!(matches!(result, Err(Error::AmountOverflow)));
    }

    #[tokio::test]
    async fn required_registration_fee_overflows_when_max_per_keyset_is_multiplied() {
        let mint = mint_with_registration_fee(0, u64::MAX).await;

        let result = mint.required_registration_fee(2, &CurrencyUnit::Sat).await;

        assert!(matches!(result, Err(Error::AmountOverflow)));
    }

    #[tokio::test]
    async fn required_registration_fee_overflows_for_large_num_keysets() {
        let mint = mint_with_registration_fee(1, (u64::MAX / 2) + 1).await;

        let result = mint.required_registration_fee(2, &CurrencyUnit::Sat).await;

        assert!(matches!(result, Err(Error::AmountOverflow)));
    }
}
