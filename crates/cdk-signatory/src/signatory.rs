//! Signatory mod
//!
//! This module abstract all the key related operations, defining an interface for the necessary
//! operations, to be implemented by the different signatory implementations.
//!
//! There is an in memory implementation, when the keys are stored in memory, in the same process,
//! but it is isolated from the rest of the application, and they communicate through a channel with
//! the defined API.
use cdk_common::common::IssuerVersion;
use cdk_common::error::Error;
use cdk_common::mint::MintKeySetInfo;
use cdk_common::nuts::nut02::KeySetVersion;
use cdk_common::{
    BlindSignature, BlindedMessage, CurrencyUnit, Id, KeySet, Keys, MintKeySet, Proof, PublicKey,
};

#[derive(Debug)]
/// Type alias to make the keyset info API more useful, queryable by unit and Id
pub enum KeysetIdentifier {
    /// Mint Keyset by unit
    Unit(CurrencyUnit),
    /// Mint Keyset by Id
    Id(Id),
}

impl From<Id> for KeysetIdentifier {
    fn from(id: Id) -> Self {
        Self::Id(id)
    }
}

impl From<CurrencyUnit> for KeysetIdentifier {
    fn from(unit: CurrencyUnit) -> Self {
        Self::Unit(unit)
    }
}

/// RotateKeyArguments
///
/// This struct is used to pass the arguments to the rotate_keyset function
///
/// TODO: Change argument to accept a vector of Amount instead of max_order.
#[derive(Debug, Clone)]
pub struct RotateKeyArguments {
    /// Unit
    pub unit: CurrencyUnit,
    /// List of amounts to support
    pub amounts: Vec<u64>,
    /// Input fee
    pub input_fee_ppk: u64,
    /// KeySet Version
    pub keyset_id_type: KeySetVersion,
    /// FinalExpiry
    pub final_expiry: Option<u64>,
}

#[derive(Debug, Clone)]
/// Signatory keysets
pub struct SignatoryKeysets {
    /// The public key
    pub pubkey: PublicKey,
    /// The list of keysets
    pub keysets: Vec<SignatoryKeySet>,
}

#[derive(Debug, Clone)]
/// SignatoryKeySet
///
/// This struct is used to represent a keyset and its info, pretty much all the information but the
/// private key, that will never leave the signatory
pub struct SignatoryKeySet {
    /// The keyset Id
    pub id: Id,
    /// The Currency Unit
    pub unit: CurrencyUnit,
    /// Whether to set it as active or not
    pub active: bool,
    /// The list of public keys
    pub keys: Keys,
    /// Amounts supported by the keyset
    pub amounts: Vec<u64>,
    /// Input fee for the keyset (parts per thousand)
    pub input_fee_ppk: u64,
    /// Final expiry of the keyset (unix timestamp in the future)
    pub final_expiry: Option<u64>,
    /// Issuer Version
    pub issuer_version: Option<IssuerVersion>,
    /// Version is the derivation_path_index
    pub version: u32,
    /// If this is a NUT-CTF conditional keyset, the hex-encoded 32-byte
    /// condition identifier it is bound to; otherwise `None`.
    ///
    /// Conditional keysets must never appear in the plain `GET /v1/keys` and
    /// `GET /v1/keysets` list endpoints — they are only enumerated via the
    /// NUT-CTF `GET /v1/conditional/keysets` endpoint. Per-ID lookups
    /// (`GET /v1/keys/{id}`) remain open so wallets holding a conditional
    /// token can still fetch its keys. The in-memory signing map keeps them
    /// alongside primary keysets so signing/verification continues to work.
    #[cfg(feature = "conditional-tokens")]
    pub condition_id: Option<String>,
}

#[cfg(feature = "conditional-tokens")]
#[derive(Debug, Clone)]
/// Conditional keyset material prepared by the signatory.
///
/// The mint persists `info` in its registration transaction and returns
/// `keyset` on the wire. The signatory reloads from storage after the
/// transaction commits, so failed registrations do not leave in-memory
/// signing keys without matching database rows.
pub struct PreparedConditionalKeySet {
    /// Public keyset response data
    pub keyset: SignatoryKeySet,
    /// Full keyset metadata row to persist transactionally
    pub info: MintKeySetInfo,
}

#[cfg(feature = "conditional-tokens")]
#[derive(Debug, Clone)]
/// Arguments for preparing a conditional keyset.
pub struct PrepareConditionalKeysetArguments {
    /// Collateral unit.
    pub unit: CurrencyUnit,
    /// Condition identifier.
    pub condition_id: String,
    /// Canonical outcome collection.
    pub outcome_collection: String,
    /// Outcome collection identifier.
    pub outcome_collection_id: String,
    /// Supported denominations.
    pub amounts: Vec<u64>,
    /// Input fee in parts per thousand.
    pub input_fee_ppk: u64,
    /// Optional final keyset expiry.
    pub final_expiry: Option<u64>,
}

impl SignatoryKeySet {
    /// Returns true if `final_expiry` is set and strictly in the past.
    pub fn is_expired(&self) -> bool {
        self.final_expiry
            .is_some_and(|expiry| expiry < cdk_common::util::unix_time())
    }
}

impl From<&SignatoryKeySet> for KeySet {
    fn from(val: &SignatoryKeySet) -> Self {
        val.to_owned().into()
    }
}

impl From<SignatoryKeySet> for KeySet {
    fn from(val: SignatoryKeySet) -> Self {
        KeySet {
            id: val.id,
            unit: val.unit,
            active: Some(val.active),
            keys: val.keys,
            input_fee_ppk: val.input_fee_ppk,
            final_expiry: val.final_expiry,
        }
    }
}

impl From<&SignatoryKeySet> for MintKeySetInfo {
    fn from(val: &SignatoryKeySet) -> Self {
        val.to_owned().into()
    }
}

impl From<SignatoryKeySet> for MintKeySetInfo {
    fn from(val: SignatoryKeySet) -> Self {
        MintKeySetInfo {
            id: val.id,
            unit: val.unit,
            active: val.active,
            input_fee_ppk: val.input_fee_ppk,
            derivation_path: Default::default(),
            derivation_path_index: Default::default(),
            amounts: val.amounts,
            final_expiry: val.final_expiry,
            issuer_version: val.issuer_version,
            valid_from: 0,
            #[cfg(feature = "conditional-tokens")]
            condition_id: None,
            #[cfg(feature = "conditional-tokens")]
            outcome_collection: None,
            #[cfg(feature = "conditional-tokens")]
            outcome_collection_id: None,
        }
    }
}

impl From<&(MintKeySetInfo, MintKeySet)> for SignatoryKeySet {
    fn from((info, key): &(MintKeySetInfo, MintKeySet)) -> Self {
        Self {
            id: info.id,
            unit: key.unit.clone(),
            active: info.active,
            input_fee_ppk: info.input_fee_ppk,
            amounts: info.amounts.clone(),
            keys: key.keys.clone().into(),
            version: info.derivation_path_index.unwrap_or(1),
            final_expiry: key.final_expiry,
            issuer_version: info.issuer_version.clone(),
            #[cfg(feature = "conditional-tokens")]
            condition_id: info.condition_id.clone(),
        }
    }
}

#[async_trait::async_trait]
/// Signatory trait
pub trait Signatory {
    /// The Signatory implementation name. This may be exposed, so being as discrete as possible is
    /// advised.
    fn name(&self) -> String;

    /// Blind sign a message.
    ///
    /// The message can be for a coin or an auth token.
    async fn blind_sign(
        &self,
        blinded_messages: Vec<BlindedMessage>,
    ) -> Result<Vec<BlindSignature>, Error>;

    /// Verify [`Proof`] meets conditions and is signed by the mint (ignores P2PK/HTLC signatures"
    async fn verify_proofs(&self, proofs: Vec<Proof>) -> Result<(), Error>;

    /// Retrieve the list of all mint keysets
    async fn keysets(&self) -> Result<SignatoryKeysets, Error>;

    /// Subscribe to keyset updates.
    ///
    /// The returned receiver holds the latest full set of keysets. The current
    /// set is available immediately and the value is replaced on every
    /// rotation. Consumers should treat each value as the complete current
    /// state, not a delta.
    async fn subscribe_keysets(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<SignatoryKeysets>, Error>;

    /// Add current keyset to inactive keysets
    /// Generate new keyset
    async fn rotate_keyset(&self, args: RotateKeyArguments) -> Result<SignatoryKeySet, Error>;

    /// Prepare a conditional keyset for a specific condition and outcome collection (NUT-CTF).
    ///
    /// This does not persist the keyset or add it to the in-memory signing map.
    /// The mint must commit the returned `info` in its registration transaction
    /// and then call `reload_keysets_from_storage`.
    #[cfg(feature = "conditional-tokens")]
    async fn prepare_conditional_keyset(
        &self,
        args: PrepareConditionalKeysetArguments,
    ) -> Result<PreparedConditionalKeySet, Error> {
        let _ = args;
        Err(Error::Custom(
            "Conditional keyset preparation is not supported by this signatory".to_string(),
        ))
    }

    /// Reload keysets from persistent storage after an external transaction commits.
    #[cfg(feature = "conditional-tokens")]
    async fn reload_keysets_from_storage(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use cdk_common::nuts::nut01::Keys;
    use cdk_common::util::unix_time;
    use cdk_common::{CurrencyUnit, Id};

    use super::*;

    fn dummy_signatory_keyset(final_expiry: Option<u64>) -> SignatoryKeySet {
        SignatoryKeySet {
            id: Id::from_str("009a1f293253e41e").unwrap(),
            unit: CurrencyUnit::Sat,
            active: true,
            keys: Keys::new(BTreeMap::new()),
            amounts: vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512],
            input_fee_ppk: 0,
            final_expiry,
            issuer_version: None,
            version: 0,
            #[cfg(feature = "conditional-tokens")]
            condition_id: None,
        }
    }

    #[test]
    fn test_is_expired_none() {
        let ks = dummy_signatory_keyset(None);
        assert!(!ks.is_expired());
    }

    #[test]
    fn test_is_expired_far_future() {
        let ks = dummy_signatory_keyset(Some(unix_time() + 1_000_000));
        assert!(!ks.is_expired());
    }

    #[test]
    fn test_is_expired_exactly_now_is_not_expired() {
        // strict less-than: expiry == now is not yet expired
        let ks = dummy_signatory_keyset(Some(unix_time()));
        assert!(!ks.is_expired());
    }

    #[test]
    fn test_is_expired_one_second_ago() {
        let ks = dummy_signatory_keyset(Some(unix_time() - 1));
        assert!(ks.is_expired());
    }

    #[test]
    fn test_is_expired_zero() {
        let ks = dummy_signatory_keyset(Some(0));
        assert!(ks.is_expired());
    }
}
