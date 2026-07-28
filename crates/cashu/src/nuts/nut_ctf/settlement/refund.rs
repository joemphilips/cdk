use std::str::FromStr;

use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use serde_json::{Map, Value};

use super::canonical::write_canonical_json;
use super::{Error, PayToUnlockCondition};
use crate::nuts::nut00::{BlindedMessage, Proof, Witness};
use crate::nuts::nut01::SecretKey;
use crate::nuts::nut03::SwapRequest;
use crate::nuts::nut11::P2PKWitness;
use crate::nuts::nut_ctf::tagged_hash;
use crate::SECP256K1;

const REFUND_DOMAIN: &str = "Cashu/PAY_TO_UNLOCK/refund";

/// Compute the witness-free canonical digest signed by every refunded input.
pub fn pay_to_unlock_refund_digest(request: &SwapRequest) -> Result<[u8; 32], Error> {
    let mut request_value = Map::new();
    request_value.insert(
        "inputs".to_string(),
        Value::Array(
            request
                .inputs()
                .iter()
                .map(canonical_refund_input)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    request_value.insert(
        "outputs".to_string(),
        Value::Array(
            request
                .outputs()
                .iter()
                .map(canonical_refund_output)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );

    let mut canonical = Vec::new();
    write_canonical_json(&Value::Object(request_value), &mut canonical)?;
    Ok(tagged_hash(REFUND_DOMAIN, &canonical))
}

/// Sign one `PAY_TO_UNLOCK` input's refund path over the complete swap request.
pub fn sign_pay_to_unlock_refund(
    request: &mut SwapRequest,
    input_index: usize,
    refund_key: &SecretKey,
) -> Result<(), Error> {
    let proof = request
        .inputs()
        .get(input_index)
        .ok_or(Error::InvalidStructure(
            "refund input index is out of range",
        ))?;
    let condition = PayToUnlockCondition::parse_optional(&proof.secret)?
        .ok_or(Error::InvalidCondition("input is not PAY_TO_UNLOCK"))?;
    if condition.refund != refund_key.public_key().x_only_public_key() {
        return Err(Error::RefundWitnessMissingOrInvalid);
    }

    let digest = pay_to_unlock_refund_digest(request)?;
    let message = Message::from_digest(digest);
    let keypair = Keypair::from_secret_key(&SECP256K1, refund_key);
    let signature = SECP256K1.sign_schnorr(&message, &keypair);
    request.inputs_mut()[input_index].witness = Some(Witness::P2PKWitness(P2PKWitness {
        signatures: vec![signature.to_string()],
    }));
    Ok(())
}

/// Verify every `PAY_TO_UNLOCK` input's post-expiry refund authorization.
///
/// Returns `true` when the request contains at least one such input. Other
/// input kinds remain subject to their ordinary NUT-03 spending checks.
pub fn verify_pay_to_unlock_refund(request: &SwapRequest, now: u64) -> Result<bool, Error> {
    let mut protected = Vec::new();
    for proof in request.inputs() {
        if let Some(condition) = PayToUnlockCondition::parse_optional(&proof.secret)? {
            protected.push((proof, condition));
        }
    }
    if protected.is_empty() {
        return Ok(false);
    }
    if protected.len() != request.inputs().len() {
        return Err(Error::InvalidCondition(
            "refund inputs must all use PAY_TO_UNLOCK",
        ));
    }

    let digest = pay_to_unlock_refund_digest(request)?;
    for (proof, condition) in protected {
        if condition.offer_keyset != proof.keyset_id {
            return Err(Error::OfferKeysetMismatch);
        }
        if now < condition.expiry {
            return Err(Error::RefundBeforeExpiry);
        }
        verify_refund_signature(proof, condition.refund, digest)?;
    }
    Ok(true)
}

/// Reject `PAY_TO_UNLOCK` proofs on a spend path that is neither settlement nor refund.
pub fn reject_pay_to_unlock_inputs(inputs: &[Proof]) -> Result<(), Error> {
    for proof in inputs {
        if PayToUnlockCondition::parse_optional(&proof.secret)?.is_some() {
            return Err(Error::InvalidCondition(
                "PAY_TO_UNLOCK is not valid on this spend path",
            ));
        }
    }
    Ok(())
}

fn canonical_refund_input(proof: &Proof) -> Result<Value, Error> {
    let mut value = serde_json::to_value(proof)?;
    let object = value
        .as_object_mut()
        .ok_or(Error::InvalidStructure("proof must encode as an object"))?;
    object.remove("witness");
    stringify_amount(object, u64::from(proof.amount));
    Ok(value)
}

fn canonical_refund_output(output: &BlindedMessage) -> Result<Value, Error> {
    let mut value = serde_json::to_value(output)?;
    let object = value.as_object_mut().ok_or(Error::InvalidStructure(
        "blinded message must encode as an object",
    ))?;
    stringify_amount(object, u64::from(output.amount));
    Ok(value)
}

fn stringify_amount(object: &mut Map<String, Value>, amount: u64) {
    object.insert("amount".to_string(), Value::String(amount.to_string()));
}

fn verify_refund_signature(
    proof: &Proof,
    refund: bitcoin::secp256k1::XOnlyPublicKey,
    digest: [u8; 32],
) -> Result<(), Error> {
    let signatures = match proof.witness.as_ref() {
        Some(Witness::P2PKWitness(witness)) if witness.signatures.len() == 1 => &witness.signatures,
        _ => return Err(Error::RefundWitnessMissingOrInvalid),
    };
    let signature =
        Signature::from_str(&signatures[0]).map_err(|_| Error::RefundWitnessMissingOrInvalid)?;
    let message = Message::from_digest(digest);
    SECP256K1
        .verify_schnorr(&signature, &message, &refund)
        .map_err(|_| Error::RefundWitnessMissingOrInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nuts::nut01::SecretKey;
    use crate::nuts::nut02::Id;
    use crate::secret::Secret;
    use crate::Amount;

    const KEYSET_ID: &str = "009a1f293253e41e";
    const LARGE_AMOUNT: u64 = 9_007_199_254_740_993;

    #[test]
    fn refund_digest_matches_witness_free_decimal_string_vector() {
        let (request, _) = unsigned_request(42);
        let proof = &request.inputs()[0];
        let output = &request.outputs()[0];
        let secret_json = serde_json::to_string(&proof.secret.to_string()).unwrap();
        let expected = format!(
            concat!(
                "{{\"inputs\":[{{\"C\":\"{}\",\"amount\":\"9007199254740993\",",
                "\"id\":\"009a1f293253e41e\",\"secret\":{}}}],",
                "\"outputs\":[{{\"B_\":\"{}\",\"amount\":\"9007199254740993\",",
                "\"id\":\"009a1f293253e41e\"}}]}}"
            ),
            proof.c, secret_json, output.blinded_secret
        );

        assert_eq!(
            pay_to_unlock_refund_digest(&request).unwrap(),
            tagged_hash(REFUND_DOMAIN, expected.as_bytes())
        );
    }

    #[test]
    fn refund_verifies_at_expiry_and_ignores_witness_in_preimage() {
        let (mut request, refund_key) = unsigned_request(42);
        let digest = pay_to_unlock_refund_digest(&request).unwrap();
        sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();

        assert_eq!(pay_to_unlock_refund_digest(&request).unwrap(), digest);
        assert_eq!(verify_pay_to_unlock_refund(&request, 42), Ok(true));
    }

    #[test]
    fn refund_rejects_before_expiry() {
        let (mut request, refund_key) = unsigned_request(42);
        sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();

        assert_eq!(
            verify_pay_to_unlock_refund(&request, 41),
            Err(Error::RefundBeforeExpiry)
        );
    }

    #[test]
    fn refund_signature_commits_to_outputs() {
        let (mut request, refund_key) = unsigned_request(42);
        sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();
        request.outputs_mut()[0].amount = Amount::from(LARGE_AMOUNT - 1);

        assert_eq!(
            verify_pay_to_unlock_refund(&request, 42),
            Err(Error::RefundWitnessMissingOrInvalid)
        );
    }

    #[test]
    fn refund_requires_exactly_one_signature_per_protected_input() {
        let (mut request, refund_key) = unsigned_request(42);
        sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();
        let Witness::P2PKWitness(witness) = request.inputs_mut()[0].witness.as_mut().unwrap()
        else {
            panic!("refund witness must use the signature-only wire shape");
        };
        witness.signatures.push(witness.signatures[0].clone());

        assert_eq!(
            verify_pay_to_unlock_refund(&request, 42),
            Err(Error::RefundWitnessMissingOrInvalid)
        );
    }

    #[test]
    fn non_pay_to_unlock_request_is_left_to_ordinary_swap_validation() {
        let (request, _) = unsigned_request(42);
        let output = request.outputs()[0].clone();
        let plain = Proof::new(
            Amount::from(LARGE_AMOUNT),
            Id::from_str(KEYSET_ID).unwrap(),
            Secret::from_str("ordinary bearer secret").unwrap(),
            test_public_key(4),
        );

        assert_eq!(
            verify_pay_to_unlock_refund(&SwapRequest::new(vec![plain], vec![output]), 42),
            Ok(false)
        );
    }

    #[test]
    fn every_protected_input_signs_the_same_complete_request() {
        let (mut request, first_key) = unsigned_request(42);
        let second_key = test_secret_key(5);
        request.inputs_mut().push(pay_to_unlock_proof(
            42,
            &second_key,
            "22",
            test_public_key(4),
        ));

        sign_pay_to_unlock_refund(&mut request, 0, &first_key).unwrap();
        assert_eq!(
            verify_pay_to_unlock_refund(&request, 42),
            Err(Error::RefundWitnessMissingOrInvalid)
        );
        sign_pay_to_unlock_refund(&mut request, 1, &second_key).unwrap();
        assert_eq!(verify_pay_to_unlock_refund(&request, 42), Ok(true));
    }

    #[test]
    fn refund_rejects_mixed_protected_and_ordinary_inputs() {
        let (mut request, refund_key) = unsigned_request(42);
        request.inputs_mut().push(Proof::new(
            Amount::ONE,
            Id::from_str(KEYSET_ID).unwrap(),
            Secret::from_str("ordinary bearer secret").unwrap(),
            test_public_key(4),
        ));
        sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();

        assert!(matches!(
            verify_pay_to_unlock_refund(&request, 42),
            Err(Error::InvalidCondition(_))
        ));
    }

    #[test]
    fn refund_rejects_offer_keyset_mismatch() {
        let (mut request, refund_key) = unsigned_request(42);
        request.inputs_mut()[0].keyset_id = Id::from_str("0011223344556677").unwrap();
        sign_pay_to_unlock_refund(&mut request, 0, &refund_key).unwrap();

        assert_eq!(
            verify_pay_to_unlock_refund(&request, 42),
            Err(Error::OfferKeysetMismatch)
        );
    }

    #[test]
    fn malformed_pay_to_unlock_kind_fails_closed() {
        let (request, _) = unsigned_request(42);
        let malformed = Proof::new(
            Amount::ONE,
            Id::from_str(KEYSET_ID).unwrap(),
            Secret::from_str(r#"["PAY_TO_UNLOCK",{"nonce":"bad"}]"#).unwrap(),
            test_public_key(4),
        );
        let request = SwapRequest::new(vec![malformed], request.outputs().clone());

        assert!(matches!(
            verify_pay_to_unlock_refund(&request, 42),
            Err(Error::InvalidCondition(_))
        ));
    }

    #[test]
    fn protected_input_is_rejected_on_other_spend_paths() {
        let (request, _) = unsigned_request(42);
        assert!(matches!(
            reject_pay_to_unlock_inputs(request.inputs()),
            Err(Error::InvalidCondition(_))
        ));
    }

    fn unsigned_request(expiry: u64) -> (SwapRequest, SecretKey) {
        let refund_key = test_secret_key(1);
        let proof = pay_to_unlock_proof(expiry, &refund_key, "00", test_public_key(2));
        let keyset_id = Id::from_str(KEYSET_ID).unwrap();
        let output = BlindedMessage::new(Amount::from(LARGE_AMOUNT), keyset_id, test_public_key(3));
        (SwapRequest::new(vec![proof], vec![output]), refund_key)
    }

    fn pay_to_unlock_proof(
        expiry: u64,
        refund_key: &SecretKey,
        nonce_byte: &str,
        c: crate::PublicKey,
    ) -> Proof {
        let secret = Secret::from_str(&format!(
            concat!(
                "[\"PAY_TO_UNLOCK\",{{\"nonce\":\"{}\",\"data\":\"{}\",",
                "\"tags\":[[\"offer_keyset\",\"{}\"],[\"expiry\",\"{}\"],",
                "[\"refund\",\"{}\"]]}}]"
            ),
            nonce_byte.repeat(32),
            "11".repeat(32),
            KEYSET_ID,
            expiry,
            refund_key.public_key().x_only_public_key()
        ))
        .unwrap();
        Proof::new(
            Amount::from(LARGE_AMOUNT),
            Id::from_str(KEYSET_ID).unwrap(),
            secret,
            c,
        )
    }

    fn test_secret_key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn test_public_key(byte: u8) -> crate::PublicKey {
        test_secret_key(byte).public_key()
    }
}
