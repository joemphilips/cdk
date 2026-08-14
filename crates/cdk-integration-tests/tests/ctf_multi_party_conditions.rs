#![cfg(feature = "conditional-tokens")]

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use cashu::nuts::nut00::{BlindedMessage, Proof};
use cashu::nuts::nut02::Id;
use cashu::nuts::nut10::SpendingConditions;
use cashu::nuts::nut12::ProofDleq;
use cashu::nuts::nut_ctf::settlement::{
    CanonicalHash, CtfConvertAdmission, CtfConvertMode, CtfSettlementLimits,
    CtfSettlementParticipant, CtfSettlementRequest, ParticipantMode,
};
use cashu::nuts::{PublicKey, SecretKey};
use cashu::secret::Secret;
use cashu::Amount;
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::nuts::nut00::KnownMethod;
use cdk::nuts::{CurrencyUnit, PaymentMethod};
use cdk::types::FeeReserve;
use cdk_common::error::{ErrorCode, ErrorResponse};
use cdk_fake_wallet::FakeWallet;
use tower_service::Service;

const KEYSET: &str = "00deadbeef123456";
const POINT_A: &str = "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104";
const POINT_B: &str = "02c97ee3d1db41cf0a3ddb601724be8711a032950811bf326f8219c50c4808d3cd";
const POINT_C: &str = "03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc";
const POINT_D: &str = "03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de";

fn limits() -> CtfSettlementLimits {
    CtfSettlementLimits {
        max_request_bytes: 64 * 1024,
        max_participants: 8,
        max_inputs: 32,
        max_outputs: 32,
        max_pool_entries: 32,
    }
}

fn keyset() -> Id {
    Id::from_str(KEYSET).expect("valid keyset")
}

fn point(value: &str) -> PublicKey {
    PublicKey::from_str(value).expect("valid compressed point")
}

fn output(value: &str) -> BlindedMessage {
    BlindedMessage::new(Amount::from(1), keyset(), point(value))
}

fn proof(secret: Secret, point_value: &str) -> Proof {
    Proof::new(Amount::from(1), keyset(), secret, point(point_value))
}

fn public_mixed_request() -> CtfSettlementRequest {
    let p2pk: Secret = SpendingConditions::new_p2pk(point(POINT_C), None)
        .try_into()
        .expect("serializable P2PK secret");
    CtfSettlementRequest {
        condition_id: CanonicalHash::parse(&"11".repeat(32), "condition_id").expect("hash"),
        parent_collection_id: CanonicalHash::from_bytes([0; 32]),
        participants: vec![
            CtfSettlementParticipant {
                inputs: vec![proof(p2pk, POINT_A)],
                outputs: vec![output(POINT_C)],
                mode: ParticipantMode::Standard,
            },
            CtfSettlementParticipant {
                inputs: vec![proof(Secret::new("ordinary-bare-input"), POINT_B)],
                outputs: vec![output(POINT_D)],
                mode: ParticipantMode::Standard,
            },
        ],
        coordinator_sig: None,
    }
}

fn dleq_secret_key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("valid DLEQ scalar")
}

async fn ctf_router() -> axum::Router {
    let database = Arc::new(
        cdk_sqlite::mint::memory::empty()
            .await
            .expect("mint database"),
    );
    let mnemonic = bip39::Mnemonic::generate(12).expect("mint seed");
    let payment = FakeWallet::new(
        FeeReserve {
            min_fee_reserve: 1.into(),
            percent_fee_reserve: 0.0,
        },
        HashMap::new(),
        HashSet::new(),
        0,
        CurrencyUnit::Sat,
    );
    let mut builder = MintBuilder::new(database.clone());
    builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 10_000),
            Arc::new(payment),
        )
        .await
        .expect("payment processor");
    let mint = builder
        .with_limits(32, 32)
        .with_ctf_settlement_settings(
            cashu::nuts::nut_ctf::settlement::NutCtfSettlementSettings::new(
                8,
                32,
                32,
                64 * 1024,
                3600,
                32,
            )
            .expect("CTF settlement settings"),
        )
        .expect("CTF settlement advertisement")
        .build_with_seed(database, &mnemonic.to_seed_normalized(""))
        .await
        .expect("mint");
    mint.start().await.expect("mint start");
    cdk_axum::create_mint_router(Arc::new(mint), Vec::new())
        .await
        .expect("CTF router")
}

async fn decode_error(response: axum::response::Response) -> (String, ErrorResponse) {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let text = String::from_utf8(body.to_vec()).expect("UTF-8 response");
    let error = serde_json::from_str(&text).expect("Cashu error response");
    (text, error)
}

#[test]
fn ctf_multi_party_conditions_public_bare_and_mixed_record() {
    let request = public_mixed_request();
    let raw = serde_json::to_vec(&request).expect("wire bytes");
    let admission = CtfConvertAdmission::preflight(&raw, limits()).expect("raw admission");

    assert_eq!(admission.mode(), CtfConvertMode::MultiParty);
    let decoded = admission
        .decode_multi_party()
        .expect("strict multi-party decode");
    decoded
        .validate(limits())
        .expect("bare and mixed records pass public validation");
    assert!(decoded
        .validated_authorizations(limits())
        .expect("locked extraction")
        .is_empty());
}

#[test]
fn ctf_multi_party_conditions_single_party_wire_is_unchanged() {
    let raw = serde_json::to_vec(&serde_json::json!({
        "condition_id": "11".repeat(32),
        "inputs": {"*": []},
        "outputs": {"*": []}
    }))
    .expect("legacy wire bytes");
    let admission = CtfConvertAdmission::preflight(&raw, limits()).expect("legacy admission");

    assert_eq!(admission.mode(), CtfConvertMode::SingleParty);
    admission
        .decode_single_party()
        .expect("legacy wire remains decodable");
}

#[test]
fn ctf_multi_party_conditions_dleq_r_round_trips_through_raw_admission() {
    let mut request = public_mixed_request();
    request.participants[0].inputs[0].dleq = Some(ProofDleq::new(
        dleq_secret_key(1),
        dleq_secret_key(2),
        dleq_secret_key(3),
    ));
    let raw = serde_json::to_vec(&request).expect("wire bytes with r");
    let decoded = CtfConvertAdmission::preflight(&raw, limits())
        .expect("raw admission accepts r")
        .decode_multi_party()
        .expect("strict decode accepts r");

    assert_eq!(
        decoded.participants[0].inputs[0].dleq,
        request.participants[0].inputs[0].dleq
    );
    let mut changed = request.clone();
    changed.participants[0].inputs[0].dleq = Some(ProofDleq::new(
        dleq_secret_key(1),
        dleq_secret_key(2),
        dleq_secret_key(4),
    ));
    assert_ne!(
        request.request_digest().expect("digest"),
        changed.request_digest().expect("digest")
    );
}

#[tokio::test]
async fn ctf_convert_route_maps_invalid_individual_witness_to_static_20008() {
    let mut router = ctf_router().await;
    let mut request = public_mixed_request();
    request.participants[0].inputs[0].dleq = Some(ProofDleq::new(
        dleq_secret_key(1),
        dleq_secret_key(2),
        dleq_secret_key(3),
    ));
    let raw = serde_json::to_vec(&request).expect("wire request");
    let raw_value: serde_json::Value = serde_json::from_slice(&raw).expect("wire JSON");
    let dleq_r = raw_value["participants"][0]["inputs"][0]["dleq"]["r"]
        .as_str()
        .expect("request must carry DLEQ r")
        .to_owned();
    let secret = request.participants[0].inputs[0].secret.to_string();

    let response = router
        .call(
            Request::post("/v1/ctf/convert")
                .header("content-type", "application/json")
                .body(Body::from(raw))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (body, error) = decode_error(response).await;
    assert_eq!(error.code, ErrorCode::WitnessMissingOrInvalid);
    assert_eq!(error.detail, "individual condition witness is invalid");
    assert!(!body.contains(&dleq_r));
    assert!(!body.contains(&secret));
}

#[tokio::test]
async fn ctf_convert_route_keeps_single_party_dispatch_and_has_no_exchange_route() {
    let mut router = ctf_router().await;
    let legacy = serde_json::json!({
        "condition_id": "11".repeat(32),
        "inputs": {},
        "outputs": {}
    });
    let response = router
        .call(
            Request::post("/v1/ctf/convert")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&legacy).expect("legacy request"),
                ))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (_, error) = decode_error(response).await;
    assert_eq!(error.code, ErrorCode::TransactionUnbalanced);

    let response = router
        .call(
            Request::post("/v1/exchange")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
