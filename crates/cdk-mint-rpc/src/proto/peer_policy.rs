use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use rustls::pki_types::{DnsName, ServerName};
use thiserror::Error;
use tonic::{Request, Status};

/// Immutable identity policy for a peer on the mint management channel.
///
/// The policy requires the authenticated leaf certificate to contain the
/// configured DNS SAN and to use the configured public key. The pin is the
/// lowercase hexadecimal SHA-256 digest of the complete SPKI DER value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPolicy {
    expected_dns_name: DnsName<'static>,
    expected_spki_sha256: [u8; 32],
}

/// Errors returned when constructing a [`PeerPolicy`].
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PeerPolicyError {
    /// The expected peer DNS SAN is not a valid DNS name.
    #[error("expected peer DNS SAN is invalid")]
    InvalidDnsName,
    /// The expected SPKI pin is not exactly 64 lowercase hexadecimal characters.
    #[error("expected peer SPKI SHA-256 pin must be 64 lowercase hexadecimal characters")]
    InvalidSpkiPin,
}

impl PeerPolicy {
    /// Creates an immutable peer identity policy.
    ///
    /// The DNS name is used as a DNS SAN reference. The pin must contain the
    /// lowercase hexadecimal SHA-256 digest of the complete SPKI DER value.
    pub fn new(
        expected_dns_name: &str,
        expected_spki_sha256: &str,
    ) -> Result<Self, PeerPolicyError> {
        let expected_dns_name = DnsName::try_from(expected_dns_name)
            .map_err(|_| PeerPolicyError::InvalidDnsName)?
            .to_owned();
        let expected_spki_sha256 = parse_spki_pin(expected_spki_sha256)?;

        Ok(Self {
            expected_dns_name,
            expected_spki_sha256,
        })
    }

    pub(crate) fn validate_request(&self, request: &Request<()>) -> Result<(), Status> {
        let peer_certs = request
            .peer_certs()
            .ok_or(PeerValidationError::MissingCertificate)
            .map_err(PeerValidationError::into_status)?;
        let leaf = peer_certs
            .first()
            .ok_or(PeerValidationError::MissingCertificate)
            .map_err(PeerValidationError::into_status)?;
        let leaf = webpki::EndEntityCert::try_from(leaf)
            .map_err(|_| PeerValidationError::InvalidCertificate)
            .map_err(PeerValidationError::into_status)?;
        let expected_name = ServerName::DnsName(self.expected_dns_name.clone());

        leaf.verify_is_valid_for_subject_name(&expected_name)
            .map_err(|_| PeerValidationError::SanMismatch)
            .map_err(PeerValidationError::into_status)?;

        let actual_spki_sha256 = sha256::Hash::hash(leaf.subject_public_key_info().as_ref());
        if actual_spki_sha256.to_byte_array() != self.expected_spki_sha256 {
            return Err(PeerValidationError::SpkiMismatch.into_status());
        }

        Ok(())
    }
}

fn parse_spki_pin(value: &str) -> Result<[u8; 32], PeerPolicyError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PeerPolicyError::InvalidSpkiPin);
    }

    <[u8; 32]>::from_hex(value).map_err(|_| PeerPolicyError::InvalidSpkiPin)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum PeerValidationError {
    #[error("peer certificate is missing")]
    MissingCertificate,
    #[error("peer certificate is invalid")]
    InvalidCertificate,
    #[error("peer certificate DNS SAN does not match the configured identity")]
    SanMismatch,
    #[error("peer certificate SPKI pin does not match the configured identity")]
    SpkiMismatch,
}

impl PeerValidationError {
    pub(crate) fn into_status(self) -> Status {
        Status::permission_denied(self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_a_lowercase_sha256_pin() {
        let policy = PeerPolicy::new("orchard", VALID_PIN);

        assert!(policy.is_ok());
    }

    #[test]
    fn rejects_non_lowercase_or_wrong_length_pins() {
        let uppercase_pin = VALID_PIN.to_uppercase();

        assert_eq!(
            PeerPolicy::new("orchard", uppercase_pin.as_str()),
            Err(PeerPolicyError::InvalidSpkiPin)
        );
        assert_eq!(
            PeerPolicy::new("orchard", "00"),
            Err(PeerPolicyError::InvalidSpkiPin)
        );
    }

    #[test]
    fn rejects_an_invalid_dns_name() {
        assert_eq!(
            PeerPolicy::new("", VALID_PIN),
            Err(PeerPolicyError::InvalidDnsName)
        );
    }

    #[test]
    fn missing_peer_certificate_is_permission_denied() {
        let policy = PeerPolicy::new("orchard", VALID_PIN).expect("test policy");
        let error = policy
            .validate_request(&Request::new(()))
            .expect_err("missing peer certificate must fail closed");

        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn lowercase_spki_pin_parser_round_trips_bytes() {
        let policy = PeerPolicy::new("orchard", VALID_PIN).expect("test policy");

        assert_eq!(
            policy.expected_spki_sha256,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef,
            ]
        );
    }
}
