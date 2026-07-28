use serde::{Deserialize, Deserializer, Serialize};

use super::CtfSettlementLimits;

/// Multi-party range-settlement capability advertised with CTF convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct NutCtfSettlementSettings {
    max_participants: u64,
    max_inputs: u64,
    max_outputs: u64,
    max_request_bytes: u64,
    idempotent_retries: bool,
    max_expiry_seconds: u64,
    partial_fill: bool,
    max_pool_entries: u64,
}

impl NutCtfSettlementSettings {
    /// Construct a complete, internally consistent multi-party capability.
    pub fn new(
        max_participants: u64,
        max_inputs: u64,
        max_outputs: u64,
        max_request_bytes: u64,
        max_expiry_seconds: u64,
        max_pool_entries: u64,
    ) -> Result<Self, NutCtfSettlementSettingsError> {
        if max_participants < 2 {
            return Err(NutCtfSettlementSettingsError::InvalidLimit(
                "max_participants must be at least two",
            ));
        }
        if max_inputs < 2 || max_outputs < 2 || max_pool_entries < 2 {
            return Err(NutCtfSettlementSettingsError::InvalidLimit(
                "input, output, and pool-entry limits must be at least two",
            ));
        }
        if max_request_bytes == 0 || max_expiry_seconds == 0 {
            return Err(NutCtfSettlementSettingsError::InvalidLimit(
                "request-byte and expiry limits must be positive",
            ));
        }
        Ok(Self {
            max_participants,
            max_inputs,
            max_outputs,
            max_request_bytes,
            idempotent_retries: true,
            max_expiry_seconds,
            partial_fill: true,
            max_pool_entries,
        })
    }

    /// Maximum authorization lifetime.
    pub const fn max_expiry_seconds(self) -> u64 {
        self.max_expiry_seconds
    }

    /// Convert advertised values into in-process structural limits.
    pub fn structural_limits(self) -> Result<CtfSettlementLimits, NutCtfSettlementSettingsError> {
        Ok(CtfSettlementLimits {
            max_request_bytes: usize_limit(self.max_request_bytes, "max_request_bytes")?,
            max_participants: usize_limit(self.max_participants, "max_participants")?,
            max_inputs: usize_limit(self.max_inputs, "max_inputs")?,
            max_outputs: usize_limit(self.max_outputs, "max_outputs")?,
            max_pool_entries: usize_limit(self.max_pool_entries, "max_pool_entries")?,
        })
    }
}

/// Invalid NUT-06 multi-party CTF settlement capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NutCtfSettlementSettingsError {
    /// A structural or lifetime limit is invalid.
    #[error("invalid CTF settlement limit: {0}")]
    InvalidLimit(&'static str),
    /// Atomic identical-request retry support is mandatory.
    #[error("multi-party CTF settlement requires idempotent_retries=true")]
    IdempotencyRequired,
    /// The pinned range-settlement dialect requires pool support.
    #[error("multi-party CTF settlement requires partial_fill=true")]
    PartialFillRequired,
    /// Only a subset of the all-or-none capability fields was supplied.
    #[error("multi-party CTF settlement settings must be all present or all absent")]
    PartialSettings,
}

/// NUT-06 mint info extension for NUT-CTF-split-merge (convert).
///
/// `supported` retains the legacy single-party convert capability. Multi-party
/// fields are omitted until atomic idempotent response persistence is available.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct NutCtfSplitMergeSettings {
    /// Whether legacy single-party CTF convert is supported.
    pub supported: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    multi_party: Option<NutCtfSettlementSettings>,
}

impl NutCtfSplitMergeSettings {
    /// Construct legacy single-party settings without multi-party advertising.
    pub const fn single_party(supported: bool) -> Self {
        Self {
            supported,
            multi_party: None,
        }
    }

    /// Add a complete multi-party range-settlement capability.
    pub fn with_multi_party(
        mut self,
        settings: NutCtfSettlementSettings,
    ) -> Result<Self, NutCtfSettlementSettingsError> {
        if !self.supported {
            return Err(NutCtfSettlementSettingsError::InvalidLimit(
                "multi-party settlement requires supported=true",
            ));
        }
        self.multi_party = Some(settings);
        Ok(self)
    }

    /// Return the advertised multi-party capability, if enabled.
    pub const fn multi_party(&self) -> Option<NutCtfSettlementSettings> {
        self.multi_party
    }
}

impl Default for NutCtfSplitMergeSettings {
    fn default() -> Self {
        Self::single_party(true)
    }
}

impl<'de> Deserialize<'de> for NutCtfSplitMergeSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = NutCtfSplitMergeSettingsWire::deserialize(deserializer)?;
        let multi_party = decode_multi_party(&raw).map_err(serde::de::Error::custom)?;
        if multi_party.is_some() && !raw.supported {
            return Err(serde::de::Error::custom(
                "multi-party CTF settlement requires supported=true",
            ));
        }
        Ok(Self {
            supported: raw.supported,
            multi_party,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NutCtfSplitMergeSettingsWire {
    supported: bool,
    max_participants: Option<u64>,
    max_inputs: Option<u64>,
    max_outputs: Option<u64>,
    max_request_bytes: Option<u64>,
    idempotent_retries: Option<bool>,
    max_expiry_seconds: Option<u64>,
    partial_fill: Option<bool>,
    max_pool_entries: Option<u64>,
}

fn decode_multi_party(
    raw: &NutCtfSplitMergeSettingsWire,
) -> Result<Option<NutCtfSettlementSettings>, NutCtfSettlementSettingsError> {
    match (
        raw.max_participants,
        raw.max_inputs,
        raw.max_outputs,
        raw.max_request_bytes,
        raw.idempotent_retries,
        raw.max_expiry_seconds,
        raw.partial_fill,
        raw.max_pool_entries,
    ) {
        (None, None, None, None, None, None, None, None) => Ok(None),
        (
            Some(max_participants),
            Some(max_inputs),
            Some(max_outputs),
            Some(max_request_bytes),
            Some(idempotent_retries),
            Some(max_expiry_seconds),
            Some(partial_fill),
            Some(max_pool_entries),
        ) => {
            if !idempotent_retries {
                return Err(NutCtfSettlementSettingsError::IdempotencyRequired);
            }
            if !partial_fill {
                return Err(NutCtfSettlementSettingsError::PartialFillRequired);
            }
            NutCtfSettlementSettings::new(
                max_participants,
                max_inputs,
                max_outputs,
                max_request_bytes,
                max_expiry_seconds,
                max_pool_entries,
            )
            .map(Some)
        }
        _ => Err(NutCtfSettlementSettingsError::PartialSettings),
    }
}

fn usize_limit(value: u64, field: &'static str) -> Result<usize, NutCtfSettlementSettingsError> {
    usize::try_from(value).map_err(|_| NutCtfSettlementSettingsError::InvalidLimit(field))
}
