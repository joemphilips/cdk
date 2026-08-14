use std::str::FromStr;

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{json, Value};

use super::*;
use crate::nuts::nut00::{BlindedMessage, Proof};
use crate::nuts::nut01::{PublicKey, SecretKey as DleqSecretKey};
use crate::nuts::nut02::Id;
use crate::nuts::nut10::{Conditions, SpendingConditions};
use crate::nuts::nut11::SigFlag;
use crate::nuts::nut12::ProofDleq;
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
const COORDINATOR_KEY: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const OTHER_COORDINATOR_KEY: &str =
    "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

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
fn condition_parser_accepts_optional_coordinator_key_in_standard_and_pool_modes() {
    let standard = condition(
        "08",
        &"88".repeat(32),
        KEYSET_A,
        &[("coordinator_pubkey", COORDINATOR_KEY)],
    );
    assert_eq!(
        PayToUnlockCondition::parse(&standard)
            .expect("coordinator-bound standard condition")
            .coordinator_pubkey
            .expect("coordinator key")
            .to_string(),
        COORDINATOR_KEY
    );

    let pool = condition(
        "09",
        &"99".repeat(32),
        KEYSET_A,
        &[
            ("rate_n", "5"),
            ("rate_d", "3"),
            ("min_receive", "1"),
            ("max_debit", "100"),
            ("coordinator_pubkey", COORDINATOR_KEY),
        ],
    );
    assert_eq!(
        PayToUnlockCondition::parse(&pool)
            .expect("coordinator-bound pool condition")
            .coordinator_pubkey
            .expect("coordinator key")
            .to_string(),
        COORDINATOR_KEY
    );
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
        CtfConvertAdmission::preflight_convert(&padded_multi, limits, 2048, 16, 16),
        Err(Error::LimitExceeded("request bytes"))
    ));

    let padded_legacy = left_pad_json(legacy, 1025);
    let admission = CtfConvertAdmission::preflight_convert(&padded_legacy, limits, 2048, 16, 16)
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
        CtfConvertAdmission::preflight_convert(&legacy, limits(), 16 * 1024, 16, 16),
        Err(Error::LimitExceeded("inputs"))
    ));
}

#[test]
fn standard_request_round_trips_and_validates() {
    let request = valid_standard_request();
    let encoded = serde_json::to_vec(&request).expect("serializable request");
    let decoded = CtfSettlementRequest::decode(&encoded, limits()).expect("strict request");
    let authorizations = decoded
        .validated_authorizations(CtfSettlementLimits {
            max_request_bytes: 16 * 1024,
            max_participants: 8,
            max_inputs: 16,
            max_outputs: 16,
            max_pool_entries: 32,
        })
        .expect("valid standard settlement");
    assert_eq!(authorizations.len(), decoded.participants.len());
    for (authorization, participant) in authorizations.iter().zip(&decoded.participants) {
        assert_eq!(authorization.offer_keyset, participant.inputs[0].keyset_id);
    }
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
fn settlement_request_digest_has_stable_binary_id_vector() {
    let request = valid_standard_request();
    assert_eq!(
        request
            .request_digest()
            .expect("canonical request")
            .to_string(),
        "48f6e7b04945ed9fd11700f14740ca13714de6b7c68f45183e60df2565ef6c26"
    );

    let mut different_parent = request.clone();
    different_parent.parent_collection_id = CanonicalHash::from_bytes([1; 32]);
    assert_ne!(
        request.request_digest().expect("canonical request"),
        different_parent
            .request_digest()
            .expect("canonical request with another parent")
    );

    let mut different_output = request.clone();
    different_output.participants[0].outputs[0].amount += Amount::ONE;
    assert_ne!(
        request.request_digest().expect("canonical request"),
        different_output
            .request_digest()
            .expect("canonical request with another output")
    );
}

#[test]
fn coordinator_digest_and_signature_have_stable_vectors() {
    let mut request = valid_standard_request();
    bind_participant(&mut request.participants[0], COORDINATOR_KEY);
    sign_request(&mut request, [0; 32]);

    assert_eq!(
        request
            .coordinator_digest()
            .expect("canonical coordinator digest")
            .to_string(),
        "36f97a2f4c9729822f03e2d37722564efd31fa3accb5419d996b22dc64a27d91"
    );
    assert_eq!(
        request
            .coordinator_sig
            .expect("coordinator signature")
            .to_string(),
        "9e88f34f2c98e02771b16c132785cfa20944909d6305e1343169cf445c49692534173186514fbb6c91892373ea07371f3c9659306f166667f4d0344416c09380"
    );
    request
        .verify_coordinator_authentication()
        .expect("stable vector authenticates");
}

#[test]
fn coordinator_auth_accepts_mixed_bound_and_unbound_but_rejects_conflicting_keys() {
    let mut mixed = valid_standard_request();
    bind_participant(&mut mixed.participants[0], COORDINATOR_KEY);
    sign_request(&mut mixed, [1; 32]);
    mixed
        .verify_coordinator_authentication()
        .expect("generic CDK accepts mixed bound and unbound participants");

    let mut conflicting = valid_standard_request();
    bind_participant(&mut conflicting.participants[0], COORDINATOR_KEY);
    bind_participant(&mut conflicting.participants[1], OTHER_COORDINATOR_KEY);
    sign_request(&mut conflicting, [2; 32]);
    assert_eq!(
        conflicting.verify_coordinator_authentication(),
        Err(Error::CoordinatorAuthentication)
    );
}

#[test]
fn coordinator_auth_rejects_missing_unexpected_and_noncanonical_authority() {
    let mut missing_signature = valid_standard_request();
    bind_participant(&mut missing_signature.participants[0], COORDINATOR_KEY);
    assert_eq!(
        missing_signature.verify_coordinator_authentication(),
        Err(Error::CoordinatorAuthentication)
    );

    let mut unexpected_signature = valid_standard_request();
    sign_request(&mut unexpected_signature, [4; 32]);
    assert_eq!(
        unexpected_signature.verify_coordinator_authentication(),
        Err(Error::CoordinatorAuthentication)
    );

    for malformed in [COORDINATOR_KEY.to_uppercase(), "00".repeat(32)] {
        let mut request = valid_standard_request();
        bind_participant(&mut request.participants[0], &malformed);
        assert_eq!(
            request.verify_coordinator_authentication(),
            Err(Error::CoordinatorAuthentication)
        );
        assert_eq!(
            request.validate(limits()),
            Err(Error::CoordinatorAuthentication)
        );
    }
}

#[test]
fn pool_coordinator_digest_authenticates_and_commits_to_all_request_fields() {
    let mut request = valid_mixed_pool_request();
    bind_participant(&mut request.participants[1], COORDINATOR_KEY);
    sign_request(&mut request, [5; 32]);

    assert_eq!(
        request
            .coordinator_digest()
            .expect("pool coordinator digest")
            .to_string(),
        "08f81f67d68ba9cd0b8c50876e86d14a12a24d9afc3835fb6eaf3f5b612aa64f"
    );
    request
        .verify_coordinator_authentication()
        .expect("pool request authenticates");

    let mut mutations = Vec::new();
    let mut condition = request.clone();
    condition.condition_id = CanonicalHash::from_bytes([0x22; 32]);
    mutations.push(condition);
    let mut parent = request.clone();
    parent.parent_collection_id = CanonicalHash::from_bytes([0x33; 32]);
    mutations.push(parent);
    let mut participant = request.clone();
    participant.participants[0].outputs[0].amount += Amount::ONE;
    mutations.push(participant);
    let mut selection = request.clone();
    if let ParticipantMode::Pool { selection, .. } = &mut selection.participants[1].mode {
        *selection = SelectionBitmap::parse("07", 4).expect("different canonical selection");
    }
    mutations.push(selection);
    let mut manifest = request.clone();
    if let ParticipantMode::Pool {
        manifest: pool_manifest,
        ..
    } = &mut manifest.participants[1].mode
    {
        let mut entries = pool_manifest.entries().to_vec();
        entries[0].amount += 1;
        *pool_manifest = PoolManifest::new(entries, 8).expect("different canonical manifest");
    }
    mutations.push(manifest);

    for mutation in mutations {
        assert_eq!(
            mutation.verify_coordinator_authentication(),
            Err(Error::CoordinatorAuthentication)
        );
    }
}

#[test]
fn coordinator_precheck_is_auth_only_while_validate_remains_complete() {
    let mut request = valid_standard_request();
    bind_participant(&mut request.participants[0], COORDINATOR_KEY);
    request.participants[0].outputs[0].amount += Amount::ONE;
    sign_request(&mut request, [6; 32]);

    request
        .verify_coordinator_authentication()
        .expect("auth-only precheck accepts a correctly signed request");
    assert_eq!(
        request.validate(limits()),
        Err(Error::OutputCommitmentMismatch)
    );
}

#[test]
fn coordinator_signature_is_strict_and_signature_independent_of_request_digest() {
    let mut request = valid_standard_request();
    bind_participant(&mut request.participants[0], COORDINATOR_KEY);
    let digest = request.request_digest().expect("request digest");
    sign_request(&mut request, [3; 32]);
    assert_eq!(
        request.request_digest().expect("signed request digest"),
        digest
    );

    let mut wire = serde_json::to_value(&request).expect("request wire");
    wire["coordinator_sig"] = Value::String(
        request
            .coordinator_sig
            .expect("coordinator signature")
            .to_string()
            .to_uppercase(),
    );
    assert_eq!(
        CtfSettlementRequest::decode(&serde_json::to_vec(&wire).expect("request bytes"), limits()),
        Err(Error::CoordinatorAuthentication)
    );
}

#[test]
fn participant_authorization_excludes_only_proof_nonce() {
    let mut request = valid_standard_request();
    let (commitment, offer_keyset, expected) = {
        let participant = &mut request.participants[0];
        let commitment = ctf_receive_commitment(&participant.outputs)
            .expect("valid outputs")
            .to_string();
        let offer_keyset = participant.inputs[0].keyset_id;
        participant.inputs.push(Proof::new(
            Amount::from(1),
            offer_keyset,
            condition("03", &commitment, &offer_keyset.to_string(), &[]),
            PublicKey::from_str(POINT_C).expect("valid point"),
        ));
        participant
            .inputs
            .sort_by_key(|proof| (proof.keyset_id.to_string(), proof.secret.to_string()));
        let expected = PayToUnlockCondition::parse(&participant.inputs[0].secret)
            .expect("valid condition")
            .authorization();
        (commitment, offer_keyset, expected)
    };

    let authorizations = request
        .validated_authorizations(limits())
        .expect("distinct proof nonces share one participant authorization");
    assert_eq!(authorizations[0], expected);

    let participant = &mut request.participants[0];
    participant.inputs[1].secret =
        condition_with_expiry("03", &commitment, &offer_keyset.to_string(), "101", &[]);
    participant
        .inputs
        .sort_by_key(|proof| (proof.keyset_id.to_string(), proof.secret.to_string()));
    assert_eq!(
        request.validated_authorizations(limits()),
        Err(Error::InconsistentAuthorization)
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
fn standard_locked_record_allows_individual_condition_input() {
    let mut request = valid_standard_request();
    request.participants[0]
        .inputs
        .push(p2pk_proof(KEYSET_A, POINT_C, SigFlag::SigInputs));
    sort_request(&mut request);

    request
        .validate(limits())
        .expect("standard locked records accept individual condition inputs");
    assert_eq!(
        request
            .validated_authorizations(limits())
            .expect("locked authorizations")
            .len(),
        2
    );
}

#[test]
fn bare_records_accept_ordinary_p2pk_and_htlc_inputs() {
    let mut request = CtfSettlementRequest {
        condition_id: CanonicalHash::parse(&"11".repeat(32), "condition_id").expect("hash"),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants: vec![
            bare_participant(
                vec![
                    ordinary_proof(KEYSET_A, POINT_A, "ordinary-bare-a"),
                    p2pk_proof(KEYSET_A, POINT_B, SigFlag::SigInputs),
                    htlc_proof(KEYSET_A, POINT_C, SigFlag::SigInputs),
                ],
                output(1, KEYSET_A, POINT_D),
            ),
            bare_participant(
                vec![ordinary_proof(KEYSET_B, POINT_B, "ordinary-bare-b")],
                output(1, KEYSET_B, POINT_E),
            ),
        ],
        coordinator_sig: None,
    };
    sort_request(&mut request);

    request
        .validate(limits())
        .expect("all-bare records accept ordinary and individual inputs");
    assert_eq!(
        request
            .validated_authorizations(limits())
            .expect("bare records have no locked authorization"),
        Vec::new()
    );
}

#[test]
fn pool_record_rejects_non_pool_inputs() {
    let extra_inputs = [
        ordinary_proof(KEYSET_A, POINT_C, "ordinary-pool"),
        p2pk_proof(KEYSET_A, POINT_C, SigFlag::SigInputs),
        htlc_proof(KEYSET_A, POINT_C, SigFlag::SigInputs),
    ];

    for extra in extra_inputs {
        let mut request = valid_mixed_pool_request();
        request.participants[1].inputs.push(extra);
        sort_request(&mut request);
        assert_eq!(
            request.validate(limits()),
            Err(Error::InvalidStructure(
                "pool records require only pool PAY_TO_UNLOCK inputs"
            )),
            "pool records reject every bare or individual input before later validation"
        );
    }

    let mut standard_authorization = valid_mixed_pool_request();
    standard_authorization.participants[1].inputs =
        vec![
            standard_participant(KEYSET_A, KEYSET_B, POINT_C, POINT_D, 1, 1, "04").inputs[0]
                .clone(),
        ];
    sort_request(&mut standard_authorization);
    assert_eq!(
        standard_authorization.validate(limits()),
        Err(Error::InvalidStructure(
            "participant wire mode does not match PAY_TO_UNLOCK tags"
        )),
        "a standard PAY_TO_UNLOCK authorization cannot use the pool wire mode"
    );
}

#[test]
fn pool_fields_reject_on_standard_locked_and_bare_records() {
    let pool_mode = valid_mixed_pool_request().participants[1].mode.clone();

    let mut standard = valid_standard_request();
    standard.participants[0].mode = pool_mode.clone();
    assert_eq!(
        standard.validate(limits()),
        Err(Error::InvalidStructure(
            "participant wire mode does not match PAY_TO_UNLOCK tags"
        ))
    );

    let mut bare = CtfSettlementRequest {
        condition_id: CanonicalHash::parse(&"11".repeat(32), "condition_id").expect("hash"),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants: vec![
            bare_participant(
                vec![ordinary_proof(KEYSET_A, POINT_A, "ordinary-pool-fields")],
                output(1, KEYSET_A, POINT_C),
            ),
            bare_participant(
                vec![ordinary_proof(
                    KEYSET_B,
                    POINT_B,
                    "ordinary-pool-fields-second",
                )],
                output(1, KEYSET_B, POINT_D),
            ),
        ],
        coordinator_sig: None,
    };
    bare.participants[0].mode = pool_mode;
    sort_request(&mut bare);
    assert_eq!(
        bare.validate(limits()),
        Err(Error::InvalidStructure(
            "pool records require only pool PAY_TO_UNLOCK inputs"
        ))
    );
}

#[test]
fn p2pk_and_htlc_sig_all_are_endpoint_rejected() {
    let p2pk = p2pk_proof(KEYSET_A, POINT_A, SigFlag::SigAll);
    assert!(matches!(
        p2pk.verify_p2pk(),
        Err(crate::nuts::nut11::Error::SigAllNotSupportedHere)
    ));

    let htlc = htlc_proof(KEYSET_A, POINT_B, SigFlag::SigAll);
    assert!(matches!(
        htlc.verify_htlc(),
        Err(crate::nuts::nut14::Error::SigAllNotSupportedHere)
    ));
}

#[test]
fn proof_dleq_r_round_trips_and_binds_ctf_digests() {
    let mut request = valid_standard_request();
    request.participants[0].inputs[0].dleq = Some(ProofDleq::new(
        dleq_secret_key(1),
        dleq_secret_key(2),
        dleq_secret_key(3),
    ));
    let encoded = serde_json::to_vec(&request).expect("request wire");
    let decoded = CtfSettlementRequest::decode(&encoded, limits()).expect("strict request");
    assert_eq!(
        decoded.participants[0].inputs[0].dleq,
        request.participants[0].inputs[0].dleq
    );
    assert_eq!(
        serde_json::to_value(&decoded).expect("request value")["participants"][0]["inputs"][0]
            ["dleq"]["r"],
        serde_json::to_value(&request).expect("request value")["participants"][0]["inputs"][0]
            ["dleq"]["r"]
    );

    let mut removed = request.clone();
    removed.participants[0].inputs[0].dleq = None;
    let mut changed = request.clone();
    changed.participants[0].inputs[0].dleq = Some(ProofDleq::new(
        dleq_secret_key(1),
        dleq_secret_key(2),
        dleq_secret_key(4),
    ));
    for mutation in [removed, changed] {
        assert_ne!(
            request.request_digest().expect("request digest"),
            mutation.request_digest().expect("changed digest")
        );
        assert_ne!(
            request.coordinator_digest().expect("coordinator digest"),
            mutation.coordinator_digest().expect("changed digest")
        );
    }
}

#[test]
fn all_locked_and_pool_requests_retain_62d59b01_bytes_and_digests() {
    let standard = valid_standard_request();
    assert_eq!(
        standard
            .request_digest()
            .expect("standard digest")
            .to_string(),
        "48f6e7b04945ed9fd11700f14740ca13714de6b7c68f45183e60df2565ef6c26"
    );

    let mut pool = valid_mixed_pool_request();
    bind_participant(&mut pool.participants[1], COORDINATOR_KEY);
    sign_request(&mut pool, [5; 32]);
    assert_eq!(
        pool.coordinator_digest().expect("pool digest").to_string(),
        "08f81f67d68ba9cd0b8c50876e86d14a12a24d9afc3835fb6eaf3f5b612aa64f"
    );
}

#[test]
fn locked_and_bare_records_keep_authorization_order() {
    let mut request = mixed_locked_and_bare_request();
    sort_request(&mut request);
    let expected = request.participants[1]
        .inputs
        .iter()
        .find_map(|proof| PayToUnlockCondition::parse_optional(&proof.secret).expect("condition"))
        .expect("locked input")
        .authorization();

    let authorizations = request
        .validated_authorizations(limits())
        .expect("mixed request is valid");
    assert_eq!(authorizations, vec![expected]);
}

#[test]
fn validated_authorizations_returns_locked_records_only() {
    let mut request = mixed_locked_and_bare_request();
    sort_request(&mut request);
    assert_eq!(
        request
            .validated_authorizations(limits())
            .expect("mixed request is valid")
            .len(),
        1
    );

    let mut all_bare = bare_request();
    sort_request(&mut all_bare);
    assert_eq!(
        all_bare
            .validated_authorizations(limits())
            .expect("all-bare request is valid"),
        Vec::new()
    );
}

#[test]
fn validate_mixed_records_is_separate_from_locked_authorization_extraction() {
    let mut mixed = mixed_locked_and_bare_request();
    sort_request(&mut mixed);
    mixed.validate(limits()).expect("mixed request validates");
    assert_eq!(
        mixed
            .validated_authorizations(limits())
            .expect("locked extraction")
            .len(),
        1
    );

    let mut all_bare = bare_request();
    sort_request(&mut all_bare);
    all_bare
        .validate(limits())
        .expect("all-bare request validates");
    assert_eq!(
        all_bare
            .validated_authorizations(limits())
            .expect("all-bare extraction"),
        Vec::new()
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
    let request = valid_mixed_pool_request();

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

#[test]
fn standalone_range_authorization_validates_without_a_selection() {
    let manifest = PoolManifest::new(
        vec![
            pool_entry(0, PoolEntryRole::Receive, 4, KEYSET_B, POINT_C),
            pool_entry(1, PoolEntryRole::Receive, 6, KEYSET_B, POINT_D),
            pool_entry(2, PoolEntryRole::Change, 4, KEYSET_A, POINT_E),
            pool_entry(3, PoolEntryRole::Change, 6, KEYSET_A, POINT_A),
        ],
        4,
    )
    .expect("valid manifest");
    let proof = Proof::new(
        Amount::from(10),
        Id::from_str(KEYSET_A).expect("valid keyset"),
        condition(
            "03",
            &manifest.commitment().to_string(),
            KEYSET_A,
            &[
                ("rate_n", "1"),
                ("rate_d", "1"),
                ("min_receive", "1"),
                ("max_debit", "10"),
            ],
        ),
        PublicKey::from_str(POINT_A).expect("valid point"),
    );

    let authorization =
        validate_ctf_range_authorization(std::slice::from_ref(&proof), &manifest, limits())
            .expect("fixed inputs and full manifest are sufficient for admission");
    assert!(matches!(authorization.mode, PayToUnlockMode::Pool(_)));

    let count_limited = CtfSettlementLimits {
        max_inputs: 2,
        ..limits()
    };
    assert_eq!(
        validate_ctf_range_authorization(
            &[proof.clone(), proof.clone(), proof.clone()],
            &manifest,
            count_limited,
        ),
        Err(Error::LimitExceeded("inputs"))
    );
    let manifest_limited = CtfSettlementLimits {
        max_pool_entries: 2,
        ..limits()
    };
    assert_eq!(
        validate_ctf_range_authorization(std::slice::from_ref(&proof), &manifest, manifest_limited,),
        Err(Error::LimitExceeded("pool manifest entries"))
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
        coordinator_sig: None,
    }
}

fn valid_mixed_pool_request() -> CtfSettlementRequest {
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
    CtfSettlementRequest {
        condition_id: CanonicalHash::parse(&"11".repeat(32), "condition_id").expect("valid hash"),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants: vec![standard, pool],
        coordinator_sig: None,
    }
}

fn bind_participant(participant: &mut CtfSettlementParticipant, coordinator_key: &str) {
    for proof in &mut participant.inputs {
        let mut condition: Value =
            serde_json::from_slice(proof.secret.as_bytes()).expect("condition JSON");
        condition[1]["tags"]
            .as_array_mut()
            .expect("condition tags")
            .push(json!(["coordinator_pubkey", coordinator_key]));
        proof.secret = Secret::new(condition.to_string());
    }
}

fn sign_request(request: &mut CtfSettlementRequest, aux_rand: [u8; 32]) {
    let secp = Secp256k1::new();
    let mut secret_bytes = [0; 32];
    secret_bytes[31] = 3;
    let secret_key = SecretKey::from_slice(&secret_bytes).expect("coordinator secret");
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let digest = request
        .coordinator_digest()
        .expect("canonical coordinator digest");
    let message = Message::from_digest(digest.to_bytes());
    request.coordinator_sig = Some(secp.sign_schnorr_with_aux_rand(&message, &keypair, &aux_rand));
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
    condition_with_expiry(nonce_byte, data, offer_keyset, "100", extra_tags)
}

fn condition_with_expiry(
    nonce_byte: &str,
    data: &str,
    offer_keyset: &str,
    expiry: &str,
    extra_tags: &[(&str, &str)],
) -> Secret {
    let mut tags = vec![
        json!(["offer_keyset", offer_keyset]),
        json!(["expiry", expiry]),
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

fn dleq_secret_key(byte: u8) -> DleqSecretKey {
    DleqSecretKey::from_slice(&[byte; 32]).expect("valid DLEQ secret key")
}

fn ordinary_proof(keyset: &str, point: &str, secret: &str) -> Proof {
    Proof::new(
        Amount::from(1),
        Id::from_str(keyset).expect("valid keyset"),
        Secret::new(secret),
        PublicKey::from_str(point).expect("valid point"),
    )
}

fn p2pk_proof(keyset: &str, point: &str, sig_flag: SigFlag) -> Proof {
    let conditions = Conditions::new(None, None, None, None, Some(sig_flag), None)
        .expect("valid P2PK conditions");
    let secret = SpendingConditions::new_p2pk(
        PublicKey::from_str(POINT_E).expect("valid P2PK public key"),
        Some(conditions),
    )
    .try_into()
    .expect("serializable P2PK secret");
    Proof::new(
        Amount::from(1),
        Id::from_str(keyset).expect("valid keyset"),
        secret,
        PublicKey::from_str(point).expect("valid point"),
    )
}

fn htlc_proof(keyset: &str, point: &str, sig_flag: SigFlag) -> Proof {
    let conditions = Conditions::new(None, None, None, None, Some(sig_flag), None)
        .expect("valid HTLC conditions");
    let secret = SpendingConditions::new_htlc_hash(&"01".repeat(32), Some(conditions))
        .expect("valid HTLC condition")
        .try_into()
        .expect("serializable HTLC secret");
    Proof::new(
        Amount::from(1),
        Id::from_str(keyset).expect("valid keyset"),
        secret,
        PublicKey::from_str(point).expect("valid point"),
    )
}

fn bare_participant(inputs: Vec<Proof>, output: BlindedMessage) -> CtfSettlementParticipant {
    CtfSettlementParticipant {
        inputs,
        outputs: vec![output],
        mode: ParticipantMode::Standard,
    }
}

fn bare_request() -> CtfSettlementRequest {
    CtfSettlementRequest {
        condition_id: CanonicalHash::parse(&"11".repeat(32), "condition_id").expect("hash"),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants: vec![
            bare_participant(
                vec![ordinary_proof(KEYSET_A, POINT_A, "ordinary-bare-request-a")],
                output(1, KEYSET_A, POINT_C),
            ),
            bare_participant(
                vec![ordinary_proof(KEYSET_B, POINT_B, "ordinary-bare-request-b")],
                output(1, KEYSET_B, POINT_D),
            ),
        ],
        coordinator_sig: None,
    }
}

fn mixed_locked_and_bare_request() -> CtfSettlementRequest {
    let mut request = valid_standard_request();
    request.participants.remove(0);
    request.participants.push(bare_participant(
        vec![ordinary_proof(KEYSET_B, POINT_B, "ordinary-mixed-bare")],
        output(1, KEYSET_B, POINT_D),
    ));
    request
}

fn sort_request(request: &mut CtfSettlementRequest) {
    for participant in &mut request.participants {
        participant
            .inputs
            .sort_by_key(|proof| (proof.keyset_id.to_string(), proof.secret.to_string()));
    }
    request.participants.sort_by_key(|participant| {
        let first = participant.inputs.first().expect("participant has input");
        (first.keyset_id.to_string(), first.secret.to_string())
    });
}
