use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::Error;
use crate::nuts::nut00::BlindedMessage;
use crate::nuts::nut_ctf::tagged_hash;

pub(crate) const CTF_RECEIVE_DOMAIN: &str = "Cashu/ctf/convert/recv";
pub(crate) const CTF_MANIFEST_DOMAIN: &str = "Cashu/ctf/convert/manifest";

/// A canonical lowercase 32-byte hexadecimal value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalHash([u8; 32]);

impl CanonicalHash {
    /// Decode a canonical lowercase 32-byte hexadecimal field.
    pub fn parse(value: &str, field: &'static str) -> Result<Self, Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::InvalidHash { field });
        }

        let bytes = crate::util::hex::decode(value).map_err(|_| Error::InvalidHash { field })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidHash { field })?;
        Ok(Self(bytes))
    }

    /// Construct a hash from its binary representation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the binary representation.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Whether this value is the all-zero root collection.
    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Display for CanonicalHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&crate::util::hex::encode(self.0))
    }
}

impl Serialize for CanonicalHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value, "hash").map_err(D::Error::custom)
    }
}

pub(crate) fn parse_minimal_u64(value: &str, field: &'static str) -> Result<u64, Error> {
    validate_minimal_decimal(value, field)?;
    value.parse().map_err(|_| Error::InvalidDecimal { field })
}

pub(crate) fn parse_minimal_u128(value: &str, field: &'static str) -> Result<u128, Error> {
    validate_minimal_decimal(value, field)?;
    value.parse().map_err(|_| Error::InvalidDecimal { field })
}

fn validate_minimal_decimal(value: &str, field: &'static str) -> Result<(), Error> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(Error::InvalidDecimal { field });
    }
    Ok(())
}

pub(crate) fn canonical_output_entry(output: &BlindedMessage) -> Vec<u8> {
    format!(
        "{{\"B_\":\"{}\",\"amount\":\"{}\",\"id\":\"{}\"}}",
        output.blinded_secret,
        u64::from(output.amount),
        output.keyset_id
    )
    .into_bytes()
}

pub(super) fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => serde_json::to_writer(output, string)?,
        Value::Array(values) => write_canonical_array(values, output)?,
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

fn write_canonical_array(values: &[Value], output: &mut Vec<u8>) -> Result<(), Error> {
    output.push(b'[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        write_canonical_json(value, output)?;
    }
    output.push(b']');
    Ok(())
}

/// Compute the CTF-specific commitment for one declared output bundle.
pub fn ctf_receive_commitment(outputs: &[BlindedMessage]) -> Result<CanonicalHash, Error> {
    let count = u32::try_from(outputs.len()).map_err(|_| Error::LimitExceeded("output count"))?;
    let mut canonical = Vec::with_capacity(4 + outputs.len().saturating_mul(128));
    canonical.extend_from_slice(&count.to_le_bytes());
    for output in outputs {
        canonical.extend_from_slice(&canonical_output_entry(output));
    }
    Ok(CanonicalHash::from_bytes(tagged_hash(
        CTF_RECEIVE_DOMAIN,
        &canonical,
    )))
}
