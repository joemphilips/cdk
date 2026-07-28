use std::collections::HashSet;

use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

use super::manifest::{strict_keyset_id, strict_public_key};
use super::{
    ctf_receive_commitment, CanonicalHash, Error, PayToUnlockCondition, PayToUnlockMode, PoolEntry,
    PoolManifest, SelectionBitmap,
};
use crate::nuts::nut00::{BlindedMessage, Proof, Proofs, Witness};
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
#[derive(Debug)]
pub struct CtfConvertAdmission<'a> {
    bytes: &'a [u8],
    mode: CtfConvertMode,
}

impl<'a> CtfConvertAdmission<'a> {
    /// Classify a convert request and apply cheap multi-party count limits.
    ///
    /// This does not parse proofs, public keys, signatures, or conditions.
    pub fn preflight(bytes: &'a [u8], limits: CtfSettlementLimits) -> Result<Self, Error> {
        limits.validate()?;
        if bytes.len() > limits.max_request_bytes {
            return Err(Error::LimitExceeded("request bytes"));
        }
        let value: Value = serde_json::from_slice(bytes)?;
        let mode = if value.get("participants").is_some() {
            preflight_multi_party_value(&value, limits)?;
            CtfConvertMode::MultiParty
        } else {
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
        if self.max_inputs == 0 || self.max_outputs == 0 || self.max_pool_entries < 2 {
            return Err(Error::InvalidStructure(
                "input, output, and pool limits must be positive",
            ));
        }
        Ok(())
    }
}

/// Closed standard or pool participant representation.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// One participant in an atomic multi-party CTF convert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtfSettlementParticipant {
    /// Fixed proof inputs.
    pub inputs: Proofs,
    /// Exact outputs selected for signing.
    pub outputs: Vec<BlindedMessage>,
    /// Closed standard or pool representation.
    pub mode: ParticipantMode,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtfSettlementRequest {
    /// Shared condition identifier.
    pub condition_id: CanonicalHash,
    /// Root parent collection. Nested conditions are not supported in v1.
    pub parent_collection_id: CanonicalHash,
    /// Canonically ordered standard and pool participants.
    pub participants: Vec<CtfSettlementParticipant>,
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
        for participant in &self.participants {
            let participant_key = validate_participant(
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
        }
        Ok(())
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementRequestWire {
    condition_id: String,
    #[serde(default)]
    parent_collection_id: Option<String>,
    participants: Vec<ParticipantWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParticipantWire {
    inputs: Vec<ProofWire>,
    outputs: Vec<OutputWire>,
    #[serde(default)]
    pool_manifest: Option<Vec<PoolEntry>>,
    #[serde(default)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputWire {
    amount: Amount,
    #[serde(rename = "id")]
    keyset_id: String,
    #[serde(rename = "B_")]
    blinded_secret: String,
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
) -> Result<(String, String), Error> {
    if participant.inputs.is_empty() || participant.outputs.is_empty() {
        return Err(Error::InvalidStructure(
            "each participant requires inputs and outputs",
        ));
    }
    ensure_input_order(&participant.inputs)?;
    validate_unique_outputs(participant, output_points)?;
    let authorization = parse_authorization(participant, proof_secrets, condition_nonces)?;
    validate_participant_mode(participant, max_pool_entries, &authorization)?;

    Ok(input_order_key(participant.inputs.first().ok_or(
        Error::InvalidStructure("participant inputs are empty"),
    )?))
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
    let mut conditions = participant
        .inputs
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
            if manifest.commitment() != authorization.data {
                return Err(Error::ManifestCommitmentMismatch);
            }
            manifest.validate_keysets(authorization.offer_keyset)?;
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

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => serde_json::to_writer(output, string)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}
