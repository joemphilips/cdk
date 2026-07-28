use std::collections::HashSet;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::canonical::{parse_minimal_u64, CTF_MANIFEST_DOMAIN};
use super::{CanonicalHash, Error};
use crate::nuts::nut00::BlindedMessage;
use crate::nuts::nut01::PublicKey;
use crate::nuts::nut02::Id;
use crate::nuts::nut_ctf::tagged_hash;
use crate::Amount;

/// Role of one owner-created pool entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoolEntryRole {
    /// Value received in the opposing keyset.
    Receive,
    /// Unspent value returned in the offered keyset.
    Change,
}

impl PoolEntryRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Change => "change",
        }
    }
}

/// One exact entry in a pool-mode output manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolEntry {
    /// Zero-based position in the complete manifest.
    pub index: u64,
    /// Receive or change role.
    pub role: PoolEntryRole,
    /// Face-value amount in the keyset's minor unit.
    pub amount: u64,
    /// Signing keyset.
    pub keyset_id: Id,
    /// Owner-created blinded message.
    pub blinded_secret: PublicKey,
}

impl PoolEntry {
    fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"B_\":\"{}\",\"amount\":\"{}\",\"id\":\"{}\",\"index\":\"{}\",\"role\":\"{}\"}}",
            self.blinded_secret,
            self.amount,
            self.keyset_id,
            self.index,
            self.role.as_str()
        )
        .into_bytes()
    }

    fn as_blinded_message(&self) -> BlindedMessage {
        BlindedMessage::new(
            Amount::from(self.amount),
            self.keyset_id,
            self.blinded_secret,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolEntryWire {
    index: String,
    role: PoolEntryRole,
    amount: String,
    #[serde(rename = "id")]
    keyset_id: String,
    #[serde(rename = "B_")]
    blinded_secret: String,
}

impl Serialize for PoolEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PoolEntryWire {
            index: self.index.to_string(),
            role: self.role,
            amount: self.amount.to_string(),
            keyset_id: self.keyset_id.to_string(),
            blinded_secret: self.blinded_secret.to_string(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PoolEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PoolEntryWire::deserialize(deserializer)?;
        let index =
            parse_minimal_u64(&wire.index, "pool_manifest.index").map_err(D::Error::custom)?;
        let amount =
            parse_minimal_u64(&wire.amount, "pool_manifest.amount").map_err(D::Error::custom)?;
        let keyset_id =
            strict_keyset_id(&wire.keyset_id, "pool_manifest.id").map_err(D::Error::custom)?;
        let blinded_secret = strict_public_key(&wire.blinded_secret, "pool_manifest.B_")
            .map_err(D::Error::custom)?;
        Ok(Self {
            index,
            role: wire.role,
            amount,
            keyset_id,
            blinded_secret,
        })
    }
}

/// A structurally valid complete pool manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolManifest(Vec<PoolEntry>);

impl PoolManifest {
    /// Validate indices, ordering, roles, and duplicate entries.
    pub fn new(entries: Vec<PoolEntry>, max_entries: usize) -> Result<Self, Error> {
        if entries.len() > max_entries {
            return Err(Error::LimitExceeded("pool manifest entries"));
        }
        if entries.len() < 2 {
            return Err(Error::InvalidManifest(
                "receive and change entries are both required",
            ));
        }

        let mut saw_receive = false;
        let mut saw_change = false;
        let mut blinded_secrets = HashSet::with_capacity(entries.len());
        for (expected_index, entry) in entries.iter().enumerate() {
            if entry.index
                != u64::try_from(expected_index).map_err(|_| Error::ArithmeticOverflow)?
            {
                return Err(Error::InvalidManifest(
                    "indices must be unique and contiguous",
                ));
            }
            match entry.role {
                PoolEntryRole::Receive if saw_change => {
                    return Err(Error::InvalidManifest(
                        "all receive entries must precede change entries",
                    ));
                }
                PoolEntryRole::Receive => saw_receive = true,
                PoolEntryRole::Change => saw_change = true,
            }
            if !blinded_secrets.insert(entry.blinded_secret) {
                return Err(Error::InvalidManifest("duplicate blinded message"));
            }
        }
        if !saw_receive || !saw_change {
            return Err(Error::InvalidManifest(
                "receive and change entries are both required",
            ));
        }

        Ok(Self(entries))
    }

    /// Borrow the complete ordered entry list.
    pub fn entries(&self) -> &[PoolEntry] {
        &self.0
    }

    /// Compute the CTF-specific manifest commitment.
    pub fn commitment(&self) -> CanonicalHash {
        let mut canonical = Vec::with_capacity(self.0.len().saturating_mul(160));
        for entry in &self.0 {
            canonical.extend_from_slice(&entry.canonical_bytes());
        }
        CanonicalHash::from_bytes(tagged_hash(CTF_MANIFEST_DOMAIN, &canonical))
    }

    /// Validate offer/change and receive-keyset roles across the full manifest.
    pub fn validate_keysets(&self, offer_keyset: Id) -> Result<Id, Error> {
        let mut receive_keyset = None;
        for entry in &self.0 {
            match entry.role {
                PoolEntryRole::Receive => match receive_keyset {
                    Some(id) if id != entry.keyset_id => {
                        return Err(Error::InvalidManifest(
                            "all receive entries must share one keyset",
                        ));
                    }
                    None => receive_keyset = Some(entry.keyset_id),
                    _ => {}
                },
                PoolEntryRole::Change if entry.keyset_id != offer_keyset => {
                    return Err(Error::InvalidManifest(
                        "change entries must use offer_keyset",
                    ));
                }
                PoolEntryRole::Change => {}
            }
        }

        let receive_keyset =
            receive_keyset.ok_or(Error::InvalidManifest("receive keyset is missing"))?;
        if receive_keyset == offer_keyset {
            return Err(Error::InvalidManifest(
                "receive keyset must differ from offer_keyset",
            ));
        }
        Ok(receive_keyset)
    }

    /// Validate that the selected entries exactly equal the declared outputs.
    pub fn validate_selection(
        &self,
        selection: &SelectionBitmap,
        outputs: &[BlindedMessage],
    ) -> Result<(), Error> {
        if selection.entry_count != self.0.len() {
            return Err(Error::InvalidSelection(
                "bitmap was decoded for a different manifest length",
            ));
        }
        let selected: Vec<_> = self
            .0
            .iter()
            .enumerate()
            .filter(|(index, _)| selection.is_selected(*index))
            .map(|(_, entry)| entry.as_blinded_message())
            .collect();
        if selected != outputs {
            return Err(Error::SelectionMismatch);
        }
        Ok(())
    }

    /// Compute checked selected receive and change totals.
    pub fn selected_totals(&self, selection: &SelectionBitmap) -> Result<(u128, u128), Error> {
        if selection.entry_count != self.0.len() {
            return Err(Error::InvalidSelection(
                "bitmap was decoded for a different manifest length",
            ));
        }
        let mut receive_total = 0u128;
        let mut change_total = 0u128;
        for (index, entry) in self.0.iter().enumerate() {
            if !selection.is_selected(index) {
                continue;
            }
            let total = match entry.role {
                PoolEntryRole::Receive => &mut receive_total,
                PoolEntryRole::Change => &mut change_total,
            };
            *total = total
                .checked_add(u128::from(entry.amount))
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok((receive_total, change_total))
    }
}

impl Serialize for PoolManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// A canonical LSB-first bitmap over one exact manifest length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionBitmap {
    bytes: Vec<u8>,
    entry_count: usize,
}

impl SelectionBitmap {
    /// Strictly decode lowercase even-length hexadecimal for `entry_count`.
    pub fn parse(value: &str, entry_count: usize) -> Result<Self, Error> {
        let expected_bytes = entry_count
            .checked_add(7)
            .ok_or(Error::ArithmeticOverflow)?
            / 8;
        if value.len() != expected_bytes.saturating_mul(2) {
            return Err(Error::InvalidSelection("incorrect byte length"));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::InvalidSelection(
                "bitmap must be lowercase hexadecimal without a prefix",
            ));
        }
        let bytes =
            crate::util::hex::decode(value).map_err(|_| Error::InvalidSelection("invalid hex"))?;
        if let Some(last) = bytes.last() {
            let used_bits = entry_count % 8;
            if used_bits != 0 && last >> used_bits != 0 {
                return Err(Error::InvalidSelection("unused trailing bits must be zero"));
            }
        }
        Ok(Self { bytes, entry_count })
    }

    /// Whether manifest entry `index` is selected.
    pub fn is_selected(&self, index: usize) -> bool {
        index < self.entry_count && (self.bytes[index / 8] & (1 << (index % 8))) != 0
    }

    /// Return the canonical lowercase hexadecimal representation.
    pub fn to_hex(&self) -> String {
        crate::util::hex::encode(&self.bytes)
    }
}

impl Serialize for SelectionBitmap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

pub(crate) fn strict_keyset_id(value: &str, field: &'static str) -> Result<Id, Error> {
    let id = Id::from_str(value).map_err(|_| Error::InvalidKeysetId { field })?;
    if id.to_string() != value {
        return Err(Error::InvalidKeysetId { field });
    }
    Ok(id)
}

pub(crate) fn strict_public_key(value: &str, field: &'static str) -> Result<PublicKey, Error> {
    let key = PublicKey::from_str(value).map_err(|_| Error::InvalidPublicKey { field })?;
    if key.to_string() != value {
        return Err(Error::InvalidPublicKey { field });
    }
    Ok(key)
}
