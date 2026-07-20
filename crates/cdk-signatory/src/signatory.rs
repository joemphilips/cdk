//! Signatory mod
//!
//! This module abstract all the key related operations, defining an interface for the necessary
//! operations, to be implemented by the different signatory implementations.
//!
//! There is an in memory implementation, when the keys are stored in memory, in the same process,
//! but it is isolated from the rest of the application, and they communicate through a channel with
//! the defined API.
#[cfg(feature = "conditional-tokens")]
use std::sync::Arc;

use cdk_common::common::IssuerVersion;
use cdk_common::error::Error;
use cdk_common::mint::MintKeySetInfo;
use cdk_common::nuts::nut02::KeySetVersion;
use cdk_common::{
    Amount, BlindSignature, BlindedMessage, CurrencyUnit, Id, KeySet, Keys, MintKeySet, Proof,
    PublicKey,
};

#[cfg(feature = "conditional-tokens")]
trait ConditionalKeysetInstallGuard: Send {}

#[cfg(feature = "conditional-tokens")]
impl<T> ConditionalKeysetInstallGuard for T where T: Send {}

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

/// Validate that public keyset material exactly matches persisted metadata.
///
/// For conditional keysets this recomputes the conditional V2 identifier,
/// including its condition and outcome-collection bindings. Fields that are
/// intentionally absent from [`SignatoryKeySet`] (`valid_from`, derivation
/// path, outcome expression, and outcome-collection ID) remain authoritative
/// in `info`; the outcome-collection ID is still consumed by the identifier
/// computation.
pub fn validate_keyset_info_binding(
    info: &MintKeySetInfo,
    keyset: &SignatoryKeySet,
) -> Result<(), Error> {
    let public_amounts_match = keyset.keys.len() == info.amounts.len()
        && info
            .amounts
            .iter()
            .all(|amount| keyset.keys.get(&Amount::from(*amount)).is_some());
    let represented_metadata_matches = keyset.id == info.id
        && keyset.unit == info.unit
        && keyset.active == info.active
        && keyset.amounts == info.amounts
        && public_amounts_match
        && keyset.input_fee_ppk == info.input_fee_ppk
        && keyset.final_expiry == info.final_expiry
        && keyset.issuer_version == info.issuer_version
        && keyset.version == info.derivation_path_index.unwrap_or(1);
    if !represented_metadata_matches {
        return Err(Error::Custom(format!(
            "keyset public metadata does not match persisted keyset {}",
            info.id
        )));
    }

    #[cfg(feature = "conditional-tokens")]
    let derived_id = match (
        &info.condition_id,
        &info.outcome_collection,
        &info.outcome_collection_id,
    ) {
        (Some(condition_id), Some(_), Some(outcome_collection_id)) => {
            if keyset.condition_id.as_ref() != Some(condition_id) {
                return Err(Error::Custom(format!(
                    "conditional keyset condition does not match persisted keyset {}",
                    info.id
                )));
            }
            Id::v2_from_data_conditional(
                &keyset.keys,
                &keyset.unit,
                keyset.input_fee_ppk,
                keyset.final_expiry,
                condition_id,
                outcome_collection_id,
            )
        }
        (None, None, None) if keyset.condition_id.is_none() => match info.id.get_version() {
            KeySetVersion::Version00 => Id::v1_from_keys(&keyset.keys),
            KeySetVersion::Version01 => Id::v2_from_data(
                &keyset.keys,
                &keyset.unit,
                keyset.input_fee_ppk,
                keyset.final_expiry,
            ),
        },
        _ => {
            return Err(Error::Custom(format!(
                "keyset condition metadata is incomplete for persisted keyset {}",
                info.id
            )));
        }
    };

    #[cfg(not(feature = "conditional-tokens"))]
    let derived_id = match info.id.get_version() {
        KeySetVersion::Version00 => Id::v1_from_keys(&keyset.keys),
        KeySetVersion::Version01 => Id::v2_from_data(
            &keyset.keys,
            &keyset.unit,
            keyset.input_fee_ppk,
            keyset.final_expiry,
        ),
    };

    if derived_id != info.id {
        return Err(Error::Custom(format!(
            "derived public keys do not match persisted keyset {}",
            info.id
        )));
    }
    Ok(())
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

/// Owned admission for one conditional-keyset installation.
///
/// Bounded signatories issue branded tokens with
/// [`ConditionalKeysetInstallReservationIssuer`]. The opaque guard is retained
/// until installation completes or the token is dropped. Unbounded signatories
/// use the trait's private permissive default token.
#[cfg(feature = "conditional-tokens")]
#[allow(missing_debug_implementations)]
#[must_use = "dropping the reservation releases conditional install capacity"]
pub struct ConditionalKeysetInstallReservation {
    provenance: ConditionalKeysetInstallReservationProvenance,
    _guard: Box<dyn ConditionalKeysetInstallGuard>,
}

#[cfg(feature = "conditional-tokens")]
enum ConditionalKeysetInstallReservationProvenance {
    PermissiveDefault,
    Branded(Arc<()>),
}

/// Issues and validates owned conditional-keyset installation reservations.
///
/// An out-of-tree bounded signatory should keep one issuer per admission
/// domain, call [`Self::reserve`] with its owned capacity guard, and validate
/// the consumed token in its `install_reserved_conditional_keysets` override
/// before enqueueing work.
#[cfg(feature = "conditional-tokens")]
#[derive(Debug, Clone)]
pub struct ConditionalKeysetInstallReservationIssuer {
    brand: Arc<()>,
}

#[cfg(feature = "conditional-tokens")]
impl Default for ConditionalKeysetInstallReservationIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "conditional-tokens")]
impl ConditionalKeysetInstallReservationIssuer {
    /// Create an independent reservation issuer.
    pub fn new() -> Self {
        Self {
            brand: Arc::new(()),
        }
    }

    /// Brand an owned admission guard as one reservation.
    pub fn reserve<G>(&self, guard: G) -> ConditionalKeysetInstallReservation
    where
        G: Send + 'static,
    {
        ConditionalKeysetInstallReservation {
            provenance: ConditionalKeysetInstallReservationProvenance::Branded(self.brand.clone()),
            _guard: Box::new(guard),
        }
    }

    /// Validate that a reservation was issued by this admission domain.
    pub fn validate(&self, reservation: &ConditionalKeysetInstallReservation) -> Result<(), Error> {
        match &reservation.provenance {
            ConditionalKeysetInstallReservationProvenance::Branded(brand)
                if Arc::ptr_eq(&self.brand, brand) =>
            {
                Ok(())
            }
            ConditionalKeysetInstallReservationProvenance::PermissiveDefault
            | ConditionalKeysetInstallReservationProvenance::Branded(_) => Err(Error::SendError(
                "conditional keyset install reservation mismatch".to_string(),
            )),
        }
    }
}

#[cfg(feature = "conditional-tokens")]
impl ConditionalKeysetInstallReservation {
    pub(crate) fn immediate() -> Self {
        Self {
            provenance: ConditionalKeysetInstallReservationProvenance::PermissiveDefault,
            _guard: Box::new(()),
        }
    }

    fn is_permissive_default(&self) -> bool {
        matches!(
            self.provenance,
            ConditionalKeysetInstallReservationProvenance::PermissiveDefault
        )
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
        Self::from((info, key))
    }
}

impl From<(&MintKeySetInfo, &MintKeySet)> for SignatoryKeySet {
    fn from((info, key): (&MintKeySetInfo, &MintKeySet)) -> Self {
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

    /// Add current keyset to inactive keysets
    /// Generate new keyset
    async fn rotate_keyset(&self, args: RotateKeyArguments) -> Result<SignatoryKeySet, Error>;

    /// Prepare a conditional keyset for a specific condition and outcome collection (NUT-CTF).
    ///
    /// This does not persist the keyset or add it to the in-memory signing map.
    /// The mint must commit the returned `info` in its registration transaction
    /// and then call [`Signatory::install_conditional_keysets`].
    #[cfg(feature = "conditional-tokens")]
    #[allow(clippy::too_many_arguments)]
    async fn prepare_conditional_keyset(
        &self,
        unit: CurrencyUnit,
        condition_id: &str,
        outcome_collection: &str,
        outcome_collection_id: &str,
        amounts: Vec<u64>,
        input_fee_ppk: u64,
        final_expiry: Option<u64>,
    ) -> Result<PreparedConditionalKeySet, Error> {
        let _ = (
            unit,
            condition_id,
            outcome_collection,
            outcome_collection_id,
            amounts,
            input_fee_ppk,
            final_expiry,
        );
        Err(Error::Custom(
            "Conditional keyset preparation is not supported by this signatory".to_string(),
        ))
    }

    /// Install only conditional keysets whose metadata was already committed.
    ///
    /// Implementations must not make the keysets available for signing before
    /// the caller's database transaction commits.
    #[cfg(feature = "conditional-tokens")]
    async fn reserve_conditional_keyset_install(
        &self,
    ) -> Result<ConditionalKeysetInstallReservation, Error> {
        Ok(ConditionalKeysetInstallReservation::immediate())
    }

    /// Consume pre-transaction admission to install committed keysets.
    #[cfg(feature = "conditional-tokens")]
    async fn install_reserved_conditional_keysets(
        &self,
        reservation: ConditionalKeysetInstallReservation,
        keysets: Vec<MintKeySetInfo>,
    ) -> Result<Vec<SignatoryKeySet>, Error> {
        if !reservation.is_permissive_default() {
            return Err(Error::SendError(
                "bounded conditional install reservation requires issuer validation".to_string(),
            ));
        }
        drop(reservation);
        self.install_conditional_keysets(keysets).await
    }

    /// Install committed conditional keysets without a pre-existing caller reservation.
    #[cfg(feature = "conditional-tokens")]
    async fn install_conditional_keysets(
        &self,
        keysets: Vec<MintKeySetInfo>,
    ) -> Result<Vec<SignatoryKeySet>, Error> {
        let _ = keysets;
        Err(Error::Custom(
            "Incremental conditional keyset installation is not supported by this signatory"
                .to_string(),
        ))
    }

    /// Reload keysets from persistent storage after an external transaction commits.
    #[cfg(feature = "conditional-tokens")]
    async fn reload_keysets_from_storage(&self) -> Result<(), Error> {
        Ok(())
    }
}
