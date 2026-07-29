use std::collections::HashSet;
use std::fmt;

use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

use super::canonical::{write_canonical_json, CTF_REQUEST_DOMAIN};
use super::manifest::{strict_keyset_id, strict_public_key};
use super::{
    ctf_receive_commitment, CanonicalHash, Error, PayToUnlockAuthorization, PayToUnlockCondition,
    PayToUnlockMode, PoolEntry, PoolManifest, SelectionBitmap,
};
use crate::nuts::nut00::{BlindSignature, BlindedMessage, Proof, Proofs, Witness};
use crate::nuts::nut01::PublicKey;
use crate::nuts::nut02::Id;
use crate::nuts::nut12::ProofDleq;
use crate::nuts::nut_ctf::CtfConvertRequest;
use crate::secret::Secret;
use crate::Amount;

/// Advertised structural limits applied before expensive settlement validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtfSettlementLimits {
    /// Maximum complete serialized request size.
    pub max_request_bytes: usize,
    /// Maximum participant records in one request.
    pub max_participants: usize,
    /// Maximum input proofs across the complete request.
    pub max_inputs: usize,
    /// Maximum selected outputs across the complete request.
    pub max_outputs: usize,
    /// Maximum manifest entries in any one pool participant.
    pub max_pool_entries: usize,
}

/// Wire mode selected by the presence of the top-level `participants` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtfConvertMode {
    /// Existing single-party split/merge request.
    SingleParty,
    /// Multi-party standard/pool settlement request.
    MultiParty,
}

/// A request that passed raw byte and cheap structural admission.
pub struct CtfConvertAdmission<'a> {
    bytes: &'a [u8],
    mode: CtfConvertMode,
}

impl fmt::Debug for CtfConvertAdmission<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CtfConvertAdmission")
            .field("request_bytes", &self.bytes.len())
            .field("mode", &self.mode)
            .finish()
    }
}

impl<'a> CtfConvertAdmission<'a> {
    /// Classify a convert request and apply cheap multi-party count limits.
    ///
    /// This does not parse proofs, public keys, signatures, or conditions.
    pub fn preflight(bytes: &'a [u8], limits: CtfSettlementLimits) -> Result<Self, Error> {
        Self::preflight_convert(
            bytes,
            limits,
            limits.max_request_bytes,
            limits.max_inputs,
            limits.max_outputs,
        )
    }

    /// Classify a convert request with separate legacy request limits.
    ///
    /// Multi-party requests use the advertised settlement byte and count
    /// limits. Legacy requests retain their mint-configured byte and transaction
    /// limits.
    pub fn preflight_convert(
        bytes: &'a [u8],
        limits: CtfSettlementLimits,
        legacy_max_request_bytes: usize,
        legacy_max_inputs: usize,
        legacy_max_outputs: usize,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if legacy_max_request_bytes == 0 || legacy_max_inputs == 0 || legacy_max_outputs == 0 {
            return Err(Error::InvalidStructure(
                "legacy request limits must be positive",
            ));
        }
        enforce_request_bytes(
            bytes,
            limits.max_request_bytes.max(legacy_max_request_bytes),
        )?;
        let value: Value = serde_json::from_slice(bytes)?;
        let mode = if value.get("participants").is_some() {
            enforce_request_bytes(bytes, limits.max_request_bytes)?;
            preflight_multi_party_value(&value, limits)?;
            CtfConvertMode::MultiParty
        } else {
            enforce_request_bytes(bytes, legacy_max_request_bytes)?;
            preflight_legacy_value(&value, legacy_max_inputs, legacy_max_outputs)?;
            CtfConvertMode::SingleParty
        };
        Ok(Self { bytes, mode })
    }

    /// Return the admitted wire mode.
    pub const fn mode(&self) -> CtfConvertMode {
        self.mode
    }

    /// Strictly decode an admitted multi-party request.
    pub fn decode_multi_party(self) -> Result<CtfSettlementRequest, Error> {
        if self.mode != CtfConvertMode::MultiParty {
            return Err(Error::WrongRequestMode);
        }
        CtfSettlementRequest::decode_admitted(self.bytes)
    }

    /// Decode an admitted legacy single-party request without changing its wire.
    pub fn decode_single_party(self) -> Result<CtfConvertRequest, Error> {
        if self.mode != CtfConvertMode::SingleParty {
            return Err(Error::WrongRequestMode);
        }
        Ok(serde_json::from_slice(self.bytes)?)
    }
}

impl CtfSettlementLimits {
    fn validate(self) -> Result<(), Error> {
        if self.max_request_bytes == 0 || self.max_participants < 2 {
            return Err(Error::InvalidStructure(
                "request bytes must be positive and max_participants at least two",
            ));
        }
        if self.max_inputs < 2 || self.max_outputs < 2 || self.max_pool_entries < 2 {
            return Err(Error::InvalidStructure(
                "input, output, and pool limits must be at least two",
            ));
        }
        Ok(())
    }
}

/// Closed standard or pool participant representation.
#[derive(Clone, PartialEq, Eq)]
pub enum ParticipantMode {
    /// Exact standard output bundle.
    Standard,
    /// Full manifest and its exact selection.
    Pool {
        /// Complete owner-created output manifest.
        manifest: PoolManifest,
        /// Canonical bitmap selecting the declared outputs.
        selection: SelectionBitmap,
    },
}

impl fmt::Debug for ParticipantMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Standard => "Standard",
            Self::Pool { .. } => "Pool { .. }",
        })
    }
}

/// One participant in an atomic multi-party CTF convert.
#[derive(Clone, PartialEq, Eq)]
pub struct CtfSettlementParticipant {
    /// Fixed proof inputs.
    pub inputs: Proofs,
    /// Exact outputs selected for signing.
    pub outputs: Vec<BlindedMessage>,
    /// Closed standard or pool representation.
    pub mode: ParticipantMode,
}

impl fmt::Debug for CtfSettlementParticipant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match &self.mode {
            ParticipantMode::Standard => "standard",
            ParticipantMode::Pool { .. } => "pool",
        };
        formatter
            .debug_struct("CtfSettlementParticipant")
            .field("input_count", &self.inputs.len())
            .field("output_count", &self.outputs.len())
            .field("mode", &mode)
            .finish()
    }
}

impl CtfSettlementParticipant {
    /// Return the canonical participant JSON used by the pinned exchange draft.
    ///
    /// Inputs are sorted by `(id, secret)`, outputs retain declared order, and
    /// proof/output amounts are encoded as decimal strings.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut inputs = self.inputs.iter().collect::<Vec<_>>();
        inputs.sort_by_key(|proof| input_order_key(proof));
        let input_values = inputs
            .into_iter()
            .map(canonical_proof_value)
            .collect::<Result<Vec<_>, _>>()?;
        let output_values = self
            .outputs
            .iter()
            .map(canonical_output_value)
            .collect::<Vec<_>>();

        let mut participant = Map::new();
        participant.insert("inputs".to_string(), Value::Array(input_values));
        participant.insert("outputs".to_string(), Value::Array(output_values));
        if let ParticipantMode::Pool {
            manifest,
            selection,
        } = &self.mode
        {
            participant.insert("pool_manifest".to_string(), serde_json::to_value(manifest)?);
            participant.insert(
                "pool_selection".to_string(),
                Value::String(selection.to_hex()),
            );
        }

        let mut encoded = Vec::new();
        write_canonical_json(&Value::Object(participant), &mut encoded)?;
        Ok(encoded)
    }
}

/// Strict multi-party request for `POST /v1/ctf/convert`.
#[derive(Clone, PartialEq, Eq)]
pub struct CtfSettlementRequest {
    /// Shared condition identifier.
    pub condition_id: CanonicalHash,
    /// Root parent collection. Nested conditions are not supported in v1.
    pub parent_collection_id: CanonicalHash,
    /// Canonically ordered standard and pool participants.
    pub participants: Vec<CtfSettlementParticipant>,
}

/// Successful multi-party settlement response, grouped in participant order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CtfSettlementResponse {
    /// One blind-signature array for each request participant.
    pub signatures: Vec<Vec<BlindSignature>>,
}

impl fmt::Debug for CtfSettlementRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CtfSettlementRequest")
            .field("participant_count", &self.participants.len())
            .finish()
    }
}

impl CtfSettlementRequest {
    /// Bound raw JSON structure before strictly decoding keys and proofs.
    pub fn decode(bytes: &[u8], limits: CtfSettlementLimits) -> Result<Self, Error> {
        CtfConvertAdmission::preflight(bytes, limits)?.decode_multi_party()
    }

    fn decode_admitted(bytes: &[u8]) -> Result<Self, Error> {
        let wire: SettlementRequestWire = serde_json::from_slice(bytes)?;
        let condition_id = CanonicalHash::parse(&wire.condition_id, "condition_id")?;
        let parent_collection_id = match wire.parent_collection_id {
            Some(parent) => CanonicalHash::parse(&parent, "parent_collection_id")?,
            None => CanonicalHash::from_bytes([0; 32]),
        };
        if !parent_collection_id.is_zero() {
            return Err(Error::NonRootParentCollection);
        }
        let participants = wire
            .participants
            .into_iter()
            .map(CtfSettlementParticipant::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            condition_id,
            parent_collection_id,
            participants,
        })
    }

    /// Validate protocol-pure structure, commitments, selections, and policies.
    pub fn validate(&self, limits: CtfSettlementLimits) -> Result<(), Error> {
        self.validated_authorizations(limits).map(drop)
    }

    /// Compute the canonical idempotency key for this exact settlement request.
    ///
    /// Top-level identifiers contribute their decoded 32-byte representations;
    /// each participant contributes its self-delimiting canonical JSON record.
    pub fn request_digest(&self) -> Result<CanonicalHash, Error> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&self.condition_id.to_bytes());
        canonical.extend_from_slice(&self.parent_collection_id.to_bytes());
        for participant in &self.participants {
            canonical.extend_from_slice(&participant.canonical_bytes()?);
        }
        Ok(CanonicalHash::from_bytes(
            crate::nuts::nut_ctf::tagged_hash(CTF_REQUEST_DOMAIN, &canonical),
        ))
    }

    /// Validate the request and return one shared authorization per participant.
    ///
    /// Returned authorizations preserve canonical participant order. Each
    /// authorization has already been checked against every input in its
    /// participant and deliberately excludes proof-local nonces.
    pub fn validated_authorizations(
        &self,
        limits: CtfSettlementLimits,
    ) -> Result<Vec<PayToUnlockAuthorization>, Error> {
        limits.validate()?;
        if self.participants.len() < 2 {
            return Err(Error::InvalidStructure(
                "at least two participants are required",
            ));
        }
        if self.participants.len() > limits.max_participants {
            return Err(Error::LimitExceeded("participants"));
        }

        let input_count = checked_count(
            self.participants
                .iter()
                .map(|participant| participant.inputs.len()),
        )?;
        let output_count = checked_count(
            self.participants
                .iter()
                .map(|participant| participant.outputs.len()),
        )?;
        if input_count > limits.max_inputs {
            return Err(Error::LimitExceeded("inputs"));
        }
        if output_count > limits.max_outputs {
            return Err(Error::LimitExceeded("outputs"));
        }

        let mut proof_secrets = HashSet::with_capacity(input_count);
        let mut condition_nonces = HashSet::with_capacity(input_count);
        let mut output_points = HashSet::with_capacity(output_count);
        let mut previous_participant_key = None;
        let mut authorizations = Vec::with_capacity(self.participants.len());
        for participant in &self.participants {
            let (participant_key, authorization) = validate_participant(
                participant,
                limits.max_pool_entries,
                &mut proof_secrets,
                &mut condition_nonces,
                &mut output_points,
            )?;
            if previous_participant_key
                .as_ref()
                .is_some_and(|previous| previous >= &participant_key)
            {
                return Err(Error::NonCanonicalParticipantOrder);
            }
            previous_participant_key = Some(participant_key);
            authorizations.push(authorization);
        }
        Ok(authorizations)
    }

    /// Require every participating input keyset to advertise a positive fee.
    pub fn validate_positive_input_fees(
        &self,
        mut input_fee_ppk: impl FnMut(Id) -> Option<u64>,
    ) -> Result<(), Error> {
        let keysets = self
            .participants
            .iter()
            .flat_map(|participant| participant.inputs.iter())
            .map(|proof| proof.keyset_id)
            .collect::<HashSet<_>>();
        for keyset in keysets {
            match input_fee_ppk(keyset) {
                Some(fee) if fee > 0 => {}
                Some(_) => return Err(Error::ZeroFeeKeyset),
                None => return Err(Error::UnknownKeyset),
            }
        }
        Ok(())
    }
}

/// Validate one fixed-input CTF pool authorization before a settlement selection exists.
///
/// Raw request-byte admission is deliberately outside this typed primitive because the
/// pinned NUT does not define a standalone range-authorization wire artifact. Callers must
/// bound their own wire body before decoding `inputs` and `manifest`.
pub fn validate_ctf_range_authorization(
    inputs: &[Proof],
    manifest: &PoolManifest,
    limits: CtfSettlementLimits,
) -> Result<PayToUnlockAuthorization, Error> {
    limits.validate()?;
    if inputs.is_empty() {
        return Err(Error::InvalidStructure(
            "a range authorization requires inputs",
        ));
    }
    if inputs.len() > limits.max_inputs {
        return Err(Error::LimitExceeded("inputs"));
    }
    if manifest.entries().len() > limits.max_pool_entries {
        return Err(Error::LimitExceeded("pool manifest entries"));
    }

    ensure_input_order(inputs)?;
    let mut proof_secrets = HashSet::with_capacity(inputs.len());
    let mut condition_nonces = HashSet::with_capacity(inputs.len());
    let authorization =
        parse_authorization_inputs(inputs, &mut proof_secrets, &mut condition_nonces)?;
    validate_pool_authorization(inputs, manifest, &authorization)?;
    Ok(authorization.authorization())
}

fn enforce_request_bytes(bytes: &[u8], maximum: usize) -> Result<(), Error> {
    if bytes.len() > maximum {
        return Err(Error::LimitExceeded("request bytes"));
    }
    Ok(())
}

fn preflight_legacy_value(
    value: &Value,
    max_inputs: usize,
    max_outputs: usize,
) -> Result<(), Error> {
    let request = value
        .as_object()
        .ok_or(Error::InvalidStructure("request must be an object"))?;
    let input_count = checked_legacy_count(request, "inputs")?;
    let output_count = checked_legacy_count(request, "outputs")?;
    if input_count > max_inputs {
        return Err(Error::LimitExceeded("inputs"));
    }
    if output_count > max_outputs {
        return Err(Error::LimitExceeded("outputs"));
    }
    Ok(())
}

fn checked_legacy_count(request: &Map<String, Value>, field: &'static str) -> Result<usize, Error> {
    request
        .get(field)
        .and_then(Value::as_object)
        .ok_or(Error::InvalidStructure(match field {
            "inputs" => "inputs must be an object",
            "outputs" => "outputs must be an object",
            _ => "legacy request field must be an object",
        }))?
        .values()
        .try_fold(0usize, |count, entries| {
            let entries = entries.as_array().ok_or(Error::InvalidStructure(
                "legacy input/output map values must be arrays",
            ))?;
            count
                .checked_add(entries.len())
                .ok_or(Error::LimitExceeded(field))
        })
}

fn preflight_multi_party_value(value: &Value, limits: CtfSettlementLimits) -> Result<(), Error> {
    let participants = value
        .get("participants")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidStructure("participants must be an array"))?;
    if participants.len() < 2 {
        return Err(Error::InvalidStructure(
            "at least two participants are required",
        ));
    }
    if participants.len() > limits.max_participants {
        return Err(Error::LimitExceeded("participants"));
    }

    let mut input_count = 0usize;
    let mut output_count = 0usize;
    for participant in participants {
        let participant = participant
            .as_object()
            .ok_or(Error::InvalidStructure("participant must be an object"))?;
        input_count = checked_preflight_count(participant, "inputs", input_count)?;
        output_count = checked_preflight_count(participant, "outputs", output_count)?;
        if participant
            .get("pool_manifest")
            .and_then(Value::as_array)
            .is_some_and(|manifest| manifest.len() > limits.max_pool_entries)
        {
            return Err(Error::LimitExceeded("pool manifest entries"));
        }
    }
    if input_count > limits.max_inputs {
        return Err(Error::LimitExceeded("inputs"));
    }
    if output_count > limits.max_outputs {
        return Err(Error::LimitExceeded("outputs"));
    }
    Ok(())
}

fn checked_preflight_count(
    participant: &Map<String, Value>,
    field: &'static str,
    current: usize,
) -> Result<usize, Error> {
    let count = participant
        .get(field)
        .and_then(Value::as_array)
        .ok_or(Error::InvalidStructure(match field {
            "inputs" => "inputs must be an array",
            _ => "outputs must be an array",
        }))?
        .len();
    current.checked_add(count).ok_or(Error::ArithmeticOverflow)
}

impl Serialize for CtfSettlementRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut request = serializer.serialize_struct("CtfSettlementRequest", 3)?;
        request.serialize_field("condition_id", &self.condition_id)?;
        request.serialize_field("parent_collection_id", &self.parent_collection_id)?;
        request.serialize_field("participants", &ParticipantSlice(&self.participants))?;
        request.end()
    }
}

struct ParticipantSlice<'a>(&'a [CtfSettlementParticipant]);

impl Serialize for ParticipantSlice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for participant in self.0 {
            sequence.serialize_element(&ParticipantRef(participant))?;
        }
        sequence.end()
    }
}

struct ParticipantRef<'a>(&'a CtfSettlementParticipant);

impl Serialize for ParticipantRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = match self.0.mode {
            ParticipantMode::Standard => 2,
            ParticipantMode::Pool { .. } => 4,
        };
        let mut participant = serializer.serialize_map(Some(field_count))?;
        participant.serialize_entry("inputs", &self.0.inputs)?;
        participant.serialize_entry("outputs", &self.0.outputs)?;
        if let ParticipantMode::Pool {
            manifest,
            selection,
        } = &self.0.mode
        {
            participant.serialize_entry("pool_manifest", manifest)?;
            participant.serialize_entry("pool_selection", selection)?;
        }
        participant.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementRequestWire {
    condition_id: String,
    #[serde(default, deserialize_with = "deserialize_present")]
    parent_collection_id: Option<String>,
    participants: Vec<ParticipantWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParticipantWire {
    inputs: Vec<ProofWire>,
    outputs: Vec<OutputWire>,
    #[serde(default, deserialize_with = "deserialize_present")]
    pool_manifest: Option<Vec<PoolEntry>>,
    #[serde(default, deserialize_with = "deserialize_present")]
    pool_selection: Option<String>,
}

impl TryFrom<ParticipantWire> for CtfSettlementParticipant {
    type Error = Error;

    fn try_from(wire: ParticipantWire) -> Result<Self, Self::Error> {
        let inputs = wire
            .inputs
            .into_iter()
            .map(Proof::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = wire
            .outputs
            .into_iter()
            .map(BlindedMessage::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let mode = match (wire.pool_manifest, wire.pool_selection) {
            (None, None) => ParticipantMode::Standard,
            (Some(entries), Some(selection)) => {
                let manifest = PoolManifest::new(entries, usize::MAX)?;
                let selection = SelectionBitmap::parse(&selection, manifest.entries().len())?;
                ParticipantMode::Pool {
                    manifest,
                    selection,
                }
            }
            _ => {
                return Err(Error::InvalidStructure(
                    "pool_manifest and pool_selection must appear together",
                ));
            }
        };
        Ok(Self {
            inputs,
            outputs,
            mode,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofWire {
    amount: Amount,
    #[serde(rename = "id")]
    keyset_id: String,
    secret: Secret,
    #[serde(rename = "C")]
    c: String,
    #[serde(default)]
    witness: Option<Witness>,
    #[serde(default)]
    dleq: Option<ProofDleq>,
    #[serde(default)]
    p2pk_e: Option<String>,
}

impl TryFrom<ProofWire> for Proof {
    type Error = Error;

    fn try_from(wire: ProofWire) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: wire.amount,
            keyset_id: strict_keyset_id(&wire.keyset_id, "inputs.id")?,
            secret: wire.secret,
            c: strict_public_key(&wire.c, "inputs.C")?,
            witness: wire.witness,
            dleq: wire.dleq,
            p2pk_e: wire
                .p2pk_e
                .map(|key| strict_public_key(&key, "inputs.p2pk_e"))
                .transpose()?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputWire {
    amount: Amount,
    #[serde(rename = "id")]
    keyset_id: String,
    #[serde(rename = "B_")]
    blinded_secret: String,
}

fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl TryFrom<OutputWire> for BlindedMessage {
    type Error = Error;

    fn try_from(wire: OutputWire) -> Result<Self, Self::Error> {
        Ok(Self::new(
            wire.amount,
            strict_keyset_id(&wire.keyset_id, "outputs.id")?,
            strict_public_key(&wire.blinded_secret, "outputs.B_")?,
        ))
    }
}

fn validate_participant(
    participant: &CtfSettlementParticipant,
    max_pool_entries: usize,
    proof_secrets: &mut HashSet<Secret>,
    condition_nonces: &mut HashSet<CanonicalHash>,
    output_points: &mut HashSet<PublicKey>,
) -> Result<((String, String), PayToUnlockAuthorization), Error> {
    if participant.inputs.is_empty() || participant.outputs.is_empty() {
        return Err(Error::InvalidStructure(
            "each participant requires inputs and outputs",
        ));
    }
    ensure_input_order(&participant.inputs)?;
    validate_unique_outputs(participant, output_points)?;
    let authorization = parse_authorization(participant, proof_secrets, condition_nonces)?;
    validate_participant_mode(participant, max_pool_entries, &authorization)?;

    let participant_key = input_order_key(
        participant
            .inputs
            .first()
            .ok_or(Error::InvalidStructure("participant inputs are empty"))?,
    );
    Ok((participant_key, authorization.authorization()))
}

fn validate_unique_outputs(
    participant: &CtfSettlementParticipant,
    output_points: &mut HashSet<PublicKey>,
) -> Result<(), Error> {
    for output in &participant.outputs {
        if output.witness.is_some() {
            return Err(Error::InvalidStructure(
                "settlement outputs cannot carry witnesses",
            ));
        }
        if !output_points.insert(output.blinded_secret) {
            return Err(Error::DuplicateOutput);
        }
    }
    Ok(())
}

fn parse_authorization(
    participant: &CtfSettlementParticipant,
    proof_secrets: &mut HashSet<Secret>,
    condition_nonces: &mut HashSet<CanonicalHash>,
) -> Result<PayToUnlockCondition, Error> {
    parse_authorization_inputs(&participant.inputs, proof_secrets, condition_nonces)
}

fn parse_authorization_inputs(
    inputs: &[Proof],
    proof_secrets: &mut HashSet<Secret>,
    condition_nonces: &mut HashSet<CanonicalHash>,
) -> Result<PayToUnlockCondition, Error> {
    let mut conditions = inputs
        .iter()
        .map(|proof| {
            if !proof_secrets.insert(proof.secret.clone()) {
                return Err(Error::DuplicateInput);
            }
            let condition = PayToUnlockCondition::parse(&proof.secret)?;
            if !condition_nonces.insert(condition.nonce) {
                return Err(Error::DuplicateInput);
            }
            if proof.keyset_id != condition.offer_keyset {
                return Err(Error::OfferKeysetMismatch);
            }
            Ok(condition)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let authorization = conditions
        .pop()
        .ok_or(Error::InvalidStructure("participant inputs are empty"))?;
    if conditions
        .iter()
        .any(|condition| !condition.has_same_authorization(&authorization))
    {
        return Err(Error::InconsistentAuthorization);
    }
    Ok(authorization)
}

fn validate_participant_mode(
    participant: &CtfSettlementParticipant,
    max_pool_entries: usize,
    authorization: &PayToUnlockCondition,
) -> Result<(), Error> {
    match (&participant.mode, authorization.mode) {
        (ParticipantMode::Standard, PayToUnlockMode::Standard) => {
            if ctf_receive_commitment(&participant.outputs)? != authorization.data {
                return Err(Error::OutputCommitmentMismatch);
            }
            validate_standard_output_keyset(participant, authorization.offer_keyset)?;
        }
        (
            ParticipantMode::Pool {
                manifest,
                selection,
            },
            PayToUnlockMode::Pool(policy),
        ) => {
            if manifest.entries().len() > max_pool_entries {
                return Err(Error::LimitExceeded("pool manifest entries"));
            }
            validate_pool_authorization(&participant.inputs, manifest, authorization)?;
            manifest.validate_selection(selection, &participant.outputs)?;
            let input_total = participant.inputs.iter().try_fold(0u128, |sum, proof| {
                sum.checked_add(u128::from(u64::from(proof.amount)))
                    .ok_or(Error::ArithmeticOverflow)
            })?;
            let (receive_total, change_total) = manifest.selected_totals(selection)?;
            policy.validate_totals(input_total, receive_total, change_total)?;
        }
        _ => {
            return Err(Error::InvalidStructure(
                "participant wire mode does not match PAY_TO_UNLOCK tags",
            ));
        }
    }
    Ok(())
}

fn validate_pool_authorization(
    inputs: &[Proof],
    manifest: &PoolManifest,
    authorization: &PayToUnlockCondition,
) -> Result<(), Error> {
    let policy = match authorization.mode {
        PayToUnlockMode::Pool(policy) => policy,
        PayToUnlockMode::Standard => {
            return Err(Error::InvalidStructure(
                "range authorization requires pool PAY_TO_UNLOCK tags",
            ));
        }
    };
    if manifest.commitment() != authorization.data {
        return Err(Error::ManifestCommitmentMismatch);
    }
    manifest.validate_keysets(authorization.offer_keyset)?;
    let input_total = inputs.iter().try_fold(0u128, |sum, proof| {
        sum.checked_add(u128::from(u64::from(proof.amount)))
            .ok_or(Error::ArithmeticOverflow)
    })?;
    policy.validate_input_total(input_total)
}

fn validate_standard_output_keyset(
    participant: &CtfSettlementParticipant,
    offer_keyset: Id,
) -> Result<(), Error> {
    let receive_keyset = participant
        .outputs
        .first()
        .ok_or(Error::InvalidStructure("participant outputs are empty"))?
        .keyset_id;
    if receive_keyset == offer_keyset
        || participant
            .outputs
            .iter()
            .any(|output| output.keyset_id != receive_keyset)
    {
        return Err(Error::OfferReceiveKeysetMismatch);
    }
    Ok(())
}

fn ensure_input_order(inputs: &[Proof]) -> Result<(), Error> {
    if inputs
        .windows(2)
        .any(|pair| input_order_key(&pair[0]) >= input_order_key(&pair[1]))
    {
        return Err(Error::NonCanonicalInputOrder);
    }
    Ok(())
}

fn input_order_key(proof: &Proof) -> (String, String) {
    (proof.keyset_id.to_string(), proof.secret.to_string())
}

fn checked_count(mut counts: impl Iterator<Item = usize>) -> Result<usize, Error> {
    counts.try_fold(0usize, |total, count| {
        total.checked_add(count).ok_or(Error::ArithmeticOverflow)
    })
}

fn canonical_proof_value(proof: &Proof) -> Result<Value, Error> {
    let mut value = serde_json::to_value(proof)?;
    let object = value
        .as_object_mut()
        .ok_or(Error::InvalidStructure("proof must encode as an object"))?;
    object.insert(
        "amount".to_string(),
        Value::String(u64::from(proof.amount).to_string()),
    );
    Ok(value)
}

fn canonical_output_value(output: &BlindedMessage) -> Value {
    let mut value = Map::new();
    value.insert(
        "B_".to_string(),
        Value::String(output.blinded_secret.to_string()),
    );
    value.insert(
        "amount".to_string(),
        Value::String(u64::from(output.amount).to_string()),
    );
    value.insert(
        "id".to_string(),
        Value::String(output.keyset_id.to_string()),
    );
    Value::Object(value)
}
