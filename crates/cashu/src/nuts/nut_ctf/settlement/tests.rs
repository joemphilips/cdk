use std::str::FromStr;

use serde_json::{json, Value};

use super::*;
use crate::nuts::nut00::{BlindedMessage, Proof};
use crate::nuts::nut01::PublicKey;
use crate::nuts::nut02::Id;
use crate::secret::Secret;
use crate::Amount;

const KEYSET_A: &str = "00deadbeef123456";
const KEYSET_B: &str = "00bfa73302d12ffd";
const POINT_A: &str = "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104";
const POINT_B: &str = "02c97ee3d1db41cf0a3ddb601724be8711a032950811bf326f8219c50c4808d3cd";
const POINT_C: &str = "03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc";
const POINT_D: &str = "03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de";
const POINT_E: &str = "02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303";
const REFUND_KEY: &str = "194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104";

#[test]
fn receive_commitment_has_stable_ctf_vector() {
    let outputs = vec![
        output(1, KEYSET_A, POINT_A),
        output(u64::MAX, KEYSET_B, POINT_B),
    ];

    assert_eq!(
        ctf_receive_commitment(&outputs)
            .expect("valid commitment")
            .to_string(),
        "3ba10a26e99d6efd25b08265ad699c5ce0e81e715ef273f98a68c24070862279"
    );
}

#[test]
fn condition_parser_accepts_reduced_pool_policy() {
    let valid_condition = condition(
        "01",
        &"11".repeat(32),
        KEYSET_A,
        &[
            ("rate_n", "5"),
            ("rate_d", "3"),
            ("min_receive", "1"),
            ("max_debit", "100"),
        ],
    );
    assert!(matches!(
        PayToUnlockCondition::parse(&valid_condition)
            .expect("valid pool condition")
            .mode,
        PayToUnlockMode::Pool(PoolPolicy {
            rate_n: 5,
            rate_d: 3,
            min_receive: 1,
            max_debit: 100,
        })
    ));
}

#[test]
fn condition_parser_rejects_invalid_pool_numbers() {
    let partial = condition("02", &"22".repeat(32), KEYSET_A, &[("rate_n", "5")]);
    assert_eq!(
        PayToUnlockCondition::parse(&partial),
        Err(Error::PartialPoolTags)
    );

    let nonminimal = condition(
        "03",
        &"33".repeat(32),
        KEYSET_A,
        &[
            ("rate_n", "05"),
            ("rate_d", "3"),
            ("min_receive", "1"),
            ("max_debit", "100"),
        ],
    );
    assert_eq!(
        PayToUnlockCondition::parse(&nonminimal),
        Err(Error::InvalidDecimal { field: "rate_n" })
    );

    let unreduced = condition(
        "07",
        &"77".repeat(32),
        KEYSET_A,
        &[
            ("rate_n", "10"),
            ("rate_d", "6"),
            ("min_receive", "1"),
            ("max_debit", "100"),
        ],
    );
    assert_eq!(
        PayToUnlockCondition::parse(&unreduced),
        Err(Error::InvalidPoolPolicy(
            "rate_n/rate_d must be a reduced fraction"
        ))
    );
}

#[test]
fn condition_parser_rejects_closed_tag_violations() {
    let cases = [
        (
            json!([
                ["offer_keyset", KEYSET_A],
                ["expiry", "100"],
                ["refund", REFUND_KEY],
                ["allow_change"]
            ]),
            Error::UnknownTag,
        ),
        (
            json!([["offer_keyset", KEYSET_A], ["expiry", "100"]]),
            Error::MissingTag("refund"),
        ),
        (
            json!([
                ["offer_keyset", KEYSET_A],
                ["expiry", "100"],
                ["expiry", "101"],
                ["refund", REFUND_KEY]
            ]),
            Error::DuplicateTag,
        ),
    ];

    for (index, (tags, expected)) in cases.into_iter().enumerate() {
        let secret = Secret::new(
            json!([
                "PAY_TO_UNLOCK",
                {
                    "nonce": format!("{:02x}", index + 4).repeat(32),
                    "data": "44".repeat(32),
                    "tags": tags
                }
            ])
            .to_string(),
        );
        assert_eq!(PayToUnlockCondition::parse(&secret), Err(expected));
    }
}

#[test]
fn manifest_and_bitmap_have_stable_vectors() {
    let entries = vec![
        pool_entry(0, PoolEntryRole::Receive, 1, KEYSET_B, POINT_A),
        pool_entry(1, PoolEntryRole::Receive, 2, KEYSET_B, POINT_B),
        pool_entry(2, PoolEntryRole::Change, 4, KEYSET_A, POINT_C),
        pool_entry(3, PoolEntryRole::Change, 8, KEYSET_A, POINT_D),
        pool_entry(4, PoolEntryRole::Change, 16, KEYSET_A, POINT_E),
    ];
    let manifest = PoolManifest::new(entries, 8).expect("valid manifest");
    assert_eq!(
        manifest.commitment().to_string(),
        "991646fd99d2f3a0a6267e392a4338cad780b2e3566135247c992a76539e1aab"
    );
    assert_eq!(
        manifest.validate_keysets(Id::from_str(KEYSET_A).expect("valid keyset")),
        Ok(Id::from_str(KEYSET_B).expect("valid keyset"))
    );

    let selection = SelectionBitmap::parse("15", 5).expect("valid bitmap");
    assert!(selection.is_selected(0));
    assert!(!selection.is_selected(1));
    assert!(selection.is_selected(2));
    assert!(selection.is_selected(4));
    assert_eq!(selection.to_hex(), "15");
    assert_eq!(
        SelectionBitmap::parse("95", 5),
        Err(Error::InvalidSelection("unused trailing bits must be zero"))
    );
    assert_eq!(
        SelectionBitmap::parse("0x15", 5),
        Err(Error::InvalidSelection("incorrect byte length"))
    );
    assert_eq!(
        manifest.validate_selection(
            &selection,
            &[output(1, KEYSET_B, POINT_A), output(4, KEYSET_A, POINT_C)]
        ),
        Err(Error::SelectionMismatch)
    );

    let wrong_keysets = PoolManifest::new(
        vec![
            pool_entry(0, PoolEntryRole::Receive, 1, KEYSET_A, POINT_A),
            pool_entry(1, PoolEntryRole::Change, 1, KEYSET_A, POINT_B),
        ],
        2,
    )
    .expect("structurally valid manifest");
    assert_eq!(
        wrong_keysets.validate_keysets(Id::from_str(KEYSET_A).expect("valid keyset")),
        Err(Error::InvalidManifest(
            "receive keyset must differ from offer_keyset"
        ))
    );
}

#[test]
fn selection_round_trips_for_bounded_manifest_sizes() {
    for entry_count in 1usize..=256 {
        let byte_count = entry_count.div_ceil(8);
        let mut bytes = vec![0u8; byte_count];
        for index in 0..entry_count {
            if (index * 17 + entry_count) % 3 == 0 {
                bytes[index / 8] |= 1 << (index % 8);
            }
        }
        let encoded = crate::util::hex::encode(bytes);
        let selection =
            SelectionBitmap::parse(&encoded, entry_count).expect("generated bitmap is valid");
        for index in 0..entry_count {
            assert_eq!(
                selection.is_selected(index),
                (index * 17 + entry_count) % 3 == 0
            );
        }
    }
}

#[test]
fn pool_policy_accepts_boundary_and_rejects_overflow() {
    let policy = PoolPolicy {
        rate_n: 5,
        rate_d: 3,
        min_receive: 6,
        max_debit: 10,
    };
    assert_eq!(policy.validate_totals(10, 10, 4), Ok(()));
    assert_eq!(
        policy.validate_totals(10, 9, 4),
        Err(Error::InvalidPoolPolicy("selected rate is below the limit"))
    );

    let overflowing = PoolPolicy {
        rate_n: u128::MAX,
        rate_d: u128::MAX,
        min_receive: 1,
        max_debit: u128::MAX,
    };
    assert_eq!(
        overflowing.validate_totals(u128::MAX, 2, 0),
        Err(Error::ArithmeticOverflow)
    );
}

#[test]
fn strict_request_rejects_unknown_and_partial_pool_fields() {
    let base = json!({
        "condition_id": "11".repeat(32),
        "participants": [
            {"inputs": [], "outputs": []},
            {"inputs": [], "outputs": []}
        ]
    });

    let mut unknown = base.clone();
    unknown
        .as_object_mut()
        .expect("object")
        .insert("unexpected".to_string(), json!(true));
    assert!(matches!(
        CtfSettlementRequest::decode(
            &serde_json::to_vec(&unknown).expect("serializable request"),
            limits()
        ),
        Err(Error::Json(_))
    ));

    let partial = json!({
        "condition_id": "11".repeat(32),
        "participants": [
            {"inputs": [], "outputs": [], "pool_manifest": []},
            {"inputs": [], "outputs": []}
        ]
    });
    assert_eq!(
        CtfSettlementRequest::decode(
            &serde_json::to_vec(&partial).expect("serializable request"),
            limits()
        ),
        Err(Error::InvalidStructure(
            "pool_manifest and pool_selection must appear together"
        ))
    );
}

#[test]
fn strict_request_rejects_explicit_null_optional_fields() {
    let mut request =
        serde_json::to_value(valid_standard_request()).expect("serializable settlement");
    request["parent_collection_id"] = Value::Null;
    assert!(matches!(
        CtfSettlementRequest::decode(
            &serde_json::to_vec(&request).expect("serializable request"),
            limits()
        ),
        Err(Error::Json(_))
    ));

    for field in ["pool_manifest", "pool_selection"] {
        let mut request =
            serde_json::to_value(valid_standard_request()).expect("serializable settlement");
        request["participants"][0][field] = Value::Null;
        assert!(matches!(
            CtfSettlementRequest::decode(
                &serde_json::to_vec(&request).expect("serializable request"),
                limits()
            ),
            Err(Error::Json(_))
        ));
    }
}

#[test]
fn preflight_rejects_bytes_and_counts_before_key_parsing() {
    let malformed_keys = json!({
        "condition_id": "11".repeat(32),
        "participants": [
            {"inputs": [{"id": "not-a-key"}], "outputs": []},
            {"inputs": [], "outputs": []},
            {"inputs": [], "outputs": []}
        ]
    });
    let encoded = serde_json::to_vec(&malformed_keys).expect("serializable request");
    let mut strict_limits = limits();
    strict_limits.max_participants = 2;
    assert!(matches!(
        CtfConvertAdmission::preflight(&encoded, strict_limits),
        Err(Error::LimitExceeded("participants"))
    ));

    strict_limits = limits();
    strict_limits.max_request_bytes = encoded.len() - 1;
    assert!(matches!(
        CtfConvertAdmission::preflight(&encoded, strict_limits),
        Err(Error::LimitExceeded("request bytes"))
    ));
}

#[test]
fn admission_defers_typed_key_parsing() {
    let malformed_multi = json!({
        "condition_id": "11".repeat(32),
        "participants": [
            {"inputs": [{"id": "not-a-key"}], "outputs": []},
            {"inputs": [], "outputs": []}
        ]
    });
    let encoded = serde_json::to_vec(&malformed_multi).expect("serializable request");
    let admission =
        CtfConvertAdmission::preflight(&encoded, limits()).expect("cheap admission succeeds");
    assert_eq!(admission.mode(), CtfConvertMode::MultiParty);
    assert!(admission.decode_multi_party().is_err());
}

#[test]
fn admission_preserves_legacy_convert_wire_decode() {
    let legacy = json!({
        "condition_id": "11".repeat(32),
        "inputs": {},
        "outputs": {}
    });
    let encoded = serde_json::to_vec(&legacy).expect("serializable request");
    let direct: crate::nuts::nut_ctf::CtfConvertRequest =
        serde_json::from_slice(&encoded).expect("legacy request");
    let admission =
        CtfConvertAdmission::preflight(&encoded, limits()).expect("cheap admission succeeds");

    assert_eq!(admission.mode(), CtfConvertMode::SingleParty);
    assert_eq!(
        serde_json::to_value(admission.decode_single_party().expect("legacy request"))
            .expect("serializable request"),
        serde_json::to_value(direct).expect("serializable request")
    );
}

#[test]
fn admission_counts_exact_raw_bytes_per_convert_mode() {
    let multi = serde_json::to_vec(&json!({
        "condition_id": "11".repeat(32),
        "participants": [
            {"inputs": [], "outputs": []},
            {"inputs": [], "outputs": []}
        ]
    }))
    .expect("serializable request");
    let legacy = serde_json::to_vec(&json!({
        "condition_id": "11".repeat(32),
        "inputs": {},
        "outputs": {}
    }))
    .expect("serializable request");
    let limits = CtfSettlementLimits {
        max_request_bytes: 1024,
        ..limits()
    };

    let padded_multi = left_pad_json(multi, 1025);
    assert!(matches!(
        CtfConvertAdmission::preflight_convert(&padded_multi, limits, 2048),
        Err(Error::LimitExceeded("request bytes"))
    ));

    let padded_legacy = left_pad_json(legacy, 1025);
    let admission = CtfConvertAdmission::preflight_convert(&padded_legacy, limits, 2048)
        .expect("legacy retains its larger transport limit");
    assert_eq!(admission.mode(), CtfConvertMode::SingleParty);
    admission
        .decode_single_party()
        .expect("whitespace-padded legacy request");
}

#[test]
fn legacy_admission_bounds_counts_before_typed_key_parsing() {
    let malformed_inputs = (0..17)
        .map(|_| json!({"id": "not-a-key"}))
        .collect::<Vec<_>>();
    let legacy = serde_json::to_vec(&json!({
        "condition_id": "11".repeat(32),
        "inputs": {"*": malformed_inputs},
        "outputs": {}
    }))
    .expect("serializable request");

    assert!(matches!(
        CtfConvertAdmission::preflight_convert(&legacy, limits(), 16 * 1024),
        Err(Error::LimitExceeded("inputs"))
    ));
}

#[test]
fn standard_request_round_trips_and_validates() {
    let request = valid_standard_request();
    let encoded = serde_json::to_vec(&request).expect("serializable request");
    let decoded = CtfSettlementRequest::decode(&encoded, limits()).expect("strict request");
    decoded
        .validate(CtfSettlementLimits {
            max_request_bytes: 16 * 1024,
            max_participants: 8,
            max_inputs: 16,
            max_outputs: 16,
            max_pool_entries: 32,
        })
        .expect("valid standard settlement");
    assert!(decoded
        .participants
        .iter()
        .all(|participant| participant.canonical_bytes().is_ok()));
    assert_eq!(decoded.validate_positive_input_fees(|_| Some(1)), Ok(()));
    assert_eq!(
        decoded.validate_positive_input_fees(|_| Some(0)),
        Err(Error::ZeroFeeKeyset)
    );
}

#[test]
fn request_rejects_duplicates_and_noncanonical_order() {
    let mut duplicate_proof = valid_standard_request();
    let repeated = duplicate_proof.participants[0].inputs[0].clone();
    duplicate_proof.participants[1].inputs.insert(0, repeated);
    assert_eq!(
        duplicate_proof.validate(limits()),
        Err(Error::DuplicateInput)
    );

    let mut duplicate_output = valid_standard_request();
    duplicate_output.participants[1].outputs[0] =
        duplicate_output.participants[0].outputs[0].clone();
    assert_eq!(
        duplicate_output.validate(limits()),
        Err(Error::DuplicateOutput)
    );

    let mut noncanonical = valid_standard_request();
    noncanonical.participants.reverse();
    assert_eq!(
        noncanonical.validate(limits()),
        Err(Error::NonCanonicalParticipantOrder)
    );
}

#[test]
fn nut06_default_retains_legacy_single_party_only() {
    let settings = NutCtfSplitMergeSettings::default();
    let value = serde_json::to_value(&settings).expect("serialize settings");
    let decoded: NutCtfSplitMergeSettings =
        serde_json::from_value(value.clone()).expect("legacy settings decode");

    assert_eq!(value, json!({"supported": true}));
    assert_eq!(decoded, settings);
    assert!(settings.multi_party().is_none());
}

#[test]
fn nut06_multi_party_is_complete_and_round_trips() {
    let multi_party = NutCtfSettlementSettings::new(64, 4096, 8192, 1_048_576, 3600, 256)
        .expect("valid multi-party settings");
    let settings = NutCtfSplitMergeSettings::default()
        .with_multi_party(multi_party)
        .expect("legacy convert is enabled");
    let value = serde_json::to_value(&settings).expect("serialize settings");
    let decoded: NutCtfSplitMergeSettings =
        serde_json::from_value(value.clone()).expect("deserialize settings");

    assert_eq!(value["max_participants"], 64);
    assert_eq!(value["idempotent_retries"], true);
    assert_eq!(value["partial_fill"], true);
    assert_eq!(decoded, settings);
    assert_eq!(
        decoded
            .multi_party()
            .expect("multi-party advertised")
            .structural_limits()
            .expect("limits fit this platform")
            .max_pool_entries,
        256
    );
}

#[test]
fn nut06_rejects_limits_that_cannot_hold_one_valid_multi_request() {
    for limits in [(2, 1, 2, 2), (2, 2, 1, 2), (2, 2, 2, 1)] {
        assert!(
            NutCtfSettlementSettings::new(limits.0, limits.1, limits.2, 1024, 60, limits.3)
                .is_err()
        );
    }
}

#[test]
fn nut06_rejects_partial_unknown_or_disabled_multi_party_fields() {
    assert!(serde_json::from_value::<NutCtfSplitMergeSettings>(json!({
        "supported": true,
        "max_participants": 64
    }))
    .is_err());
    assert!(serde_json::from_value::<NutCtfSplitMergeSettings>(json!({
        "supported": true,
        "unexpected": 1
    }))
    .is_err());

    for (idempotent_retries, partial_fill) in [(false, true), (true, false)] {
        assert!(serde_json::from_value::<NutCtfSplitMergeSettings>(json!({
            "supported": true,
            "max_participants": 64,
            "max_inputs": 4096,
            "max_outputs": 8192,
            "max_request_bytes": 1048576,
            "idempotent_retries": idempotent_retries,
            "max_expiry_seconds": 3600,
            "partial_fill": partial_fill,
            "max_pool_entries": 256
        }))
        .is_err());
    }
}

#[test]
fn nut06_rejects_multi_party_when_legacy_convert_is_disabled() {
    let mut value = serde_json::to_value(
        NutCtfSplitMergeSettings::default()
            .with_multi_party(
                NutCtfSettlementSettings::new(64, 4096, 8192, 1_048_576, 3600, 256)
                    .expect("valid multi-party settings"),
            )
            .expect("legacy convert is enabled"),
    )
    .expect("serialize settings");
    value["supported"] = json!(false);

    assert!(serde_json::from_value::<NutCtfSplitMergeSettings>(value).is_err());
}

#[test]
fn mixed_standard_and_pool_request_validates_exact_selection() {
    let standard = standard_participant(KEYSET_B, KEYSET_A, POINT_B, POINT_B, 6, 6, "02");
    let entries = vec![
        pool_entry(0, PoolEntryRole::Receive, 4, KEYSET_B, POINT_C),
        pool_entry(1, PoolEntryRole::Receive, 6, KEYSET_B, POINT_D),
        pool_entry(2, PoolEntryRole::Change, 4, KEYSET_A, POINT_E),
        pool_entry(3, PoolEntryRole::Change, 6, KEYSET_A, POINT_A),
    ];
    let manifest = PoolManifest::new(entries, 8).expect("valid manifest");
    let selection = SelectionBitmap::parse("06", 4).expect("valid selection");
    let selected_outputs = vec![output(6, KEYSET_B, POINT_D), output(4, KEYSET_A, POINT_E)];
    manifest
        .validate_selection(&selection, &selected_outputs)
        .expect("outputs exactly match selected entries");
    let pool_proof = Proof::new(
        Amount::from(10),
        Id::from_str(KEYSET_A).expect("valid keyset"),
        condition(
            "03",
            &manifest.commitment().to_string(),
            KEYSET_A,
            &[
                ("rate_n", "1"),
                ("rate_d", "1"),
                ("min_receive", "6"),
                ("max_debit", "6"),
            ],
        ),
        PublicKey::from_str(POINT_A).expect("valid point"),
    );
    let pool = CtfSettlementParticipant {
        inputs: vec![pool_proof],
        outputs: selected_outputs,
        mode: ParticipantMode::Pool {
            manifest,
            selection,
        },
    };
    let request = CtfSettlementRequest {
        condition_id: CanonicalHash::parse(&"11".repeat(32), "condition_id").expect("valid hash"),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants: vec![standard, pool],
    };

    request
        .validate(CtfSettlementLimits {
            max_request_bytes: 16 * 1024,
            max_participants: 2,
            max_inputs: 2,
            max_outputs: 3,
            max_pool_entries: 4,
        })
        .expect("mixed request is valid");

    let mut wrong_commitment = request;
    wrong_commitment.participants[1].inputs[0].secret = condition(
        "03",
        &"00".repeat(32),
        KEYSET_A,
        &[
            ("rate_n", "1"),
            ("rate_d", "1"),
            ("min_receive", "6"),
            ("max_debit", "6"),
        ],
    );
    assert_eq!(
        wrong_commitment.validate(limits()),
        Err(Error::ManifestCommitmentMismatch)
    );
}

fn limits() -> CtfSettlementLimits {
    CtfSettlementLimits {
        max_request_bytes: 16 * 1024,
        max_participants: 8,
        max_inputs: 16,
        max_outputs: 16,
        max_pool_entries: 32,
    }
}

fn left_pad_json(mut json: Vec<u8>, target_len: usize) -> Vec<u8> {
    let mut padded = vec![b' '; target_len.saturating_sub(json.len())];
    padded.append(&mut json);
    padded
}

fn valid_standard_request() -> CtfSettlementRequest {
    let participant_a = standard_participant(KEYSET_A, KEYSET_B, POINT_A, POINT_B, 10, 9, "01");
    let participant_b = standard_participant(KEYSET_B, KEYSET_A, POINT_B, POINT_A, 9, 8, "02");
    CtfSettlementRequest {
        condition_id: CanonicalHash::parse(&"11".repeat(32), "condition_id").expect("valid hash"),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants: vec![participant_b, participant_a],
    }
}

fn standard_participant(
    offer_keyset: &str,
    receive_keyset: &str,
    input_point: &str,
    output_point: &str,
    input_amount: u64,
    output_amount: u64,
    nonce_byte: &str,
) -> CtfSettlementParticipant {
    let outputs = vec![output(output_amount, receive_keyset, output_point)];
    let commitment = ctf_receive_commitment(&outputs)
        .expect("valid outputs")
        .to_string();
    let proof = Proof::new(
        Amount::from(input_amount),
        Id::from_str(offer_keyset).expect("valid keyset"),
        condition(nonce_byte, &commitment, offer_keyset, &[]),
        PublicKey::from_str(input_point).expect("valid point"),
    );
    CtfSettlementParticipant {
        inputs: vec![proof],
        outputs,
        mode: ParticipantMode::Standard,
    }
}

fn condition(
    nonce_byte: &str,
    data: &str,
    offer_keyset: &str,
    extra_tags: &[(&str, &str)],
) -> Secret {
    let mut tags = vec![
        json!(["offer_keyset", offer_keyset]),
        json!(["expiry", "100"]),
        json!(["refund", REFUND_KEY]),
    ];
    tags.extend(extra_tags.iter().map(|(name, value)| json!([name, value])));
    Secret::new(
        json!([
            "PAY_TO_UNLOCK",
            {
                "nonce": nonce_byte.repeat(32),
                "data": data,
                "tags": tags
            }
        ])
        .to_string(),
    )
}

fn output(amount: u64, keyset: &str, point: &str) -> BlindedMessage {
    BlindedMessage::new(
        Amount::from(amount),
        Id::from_str(keyset).expect("valid keyset"),
        PublicKey::from_str(point).expect("valid point"),
    )
}

fn pool_entry(
    index: u64,
    role: PoolEntryRole,
    amount: u64,
    keyset: &str,
    point: &str,
) -> PoolEntry {
    PoolEntry {
        index,
        role,
        amount,
        keyset_id: Id::from_str(keyset).expect("valid keyset"),
        blinded_secret: PublicKey::from_str(point).expect("valid point"),
    }
}
