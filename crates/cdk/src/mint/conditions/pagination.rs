use bitcoin::base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bitcoin::base64::Engine;
use cdk_common::nuts::Id;
use serde::{Deserialize, Serialize};

use crate::Error;

const MAX_CURSOR_LENGTH: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "endpoint", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ListingFilter {
    Conditions { since: u64, status: Vec<String> },
    ConditionalKeysets { since: u64, active: ActiveFilter },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ActiveFilter {
    All,
    Active,
    Inactive,
}

impl From<Option<bool>> for ActiveFilter {
    fn from(value: Option<bool>) -> Self {
        match value {
            None => Self::All,
            Some(true) => Self::Active,
            Some(false) => Self::Inactive,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    last_created_at: u64,
    last_id: String,
    filter: ListingFilter,
}

fn invalid_cursor() -> Error {
    Error::Custom("Invalid listing cursor".to_string())
}

pub(super) fn validate_since(since: Option<u64>) -> Result<(), Error> {
    if since.is_some_and(|timestamp| timestamp > i64::MAX as u64) {
        return Err(Error::Custom(
            "Registration filter exceeds supported timestamp range".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn page_limit(limit: Option<u64>) -> Result<u64, Error> {
    match limit {
        Some(0) => Err(Error::Custom("Listing limit must be positive".to_string())),
        Some(limit) => Ok(limit.min(super::MAX_PAGE_SIZE)),
        None => Ok(super::MAX_PAGE_SIZE),
    }
}

impl ListingFilter {
    pub(super) fn decode(&self, value: Option<&str>) -> Result<Option<(u64, String)>, Error> {
        let Some(value) = value else {
            return Ok(None);
        };
        if value.is_empty() || value.len() > MAX_CURSOR_LENGTH {
            return Err(invalid_cursor());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| invalid_cursor())?;
        let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid_cursor())?;
        let valid_id = match self {
            Self::Conditions { .. } => {
                cursor.last_id.len() == 64
                    && cursor
                        .last_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
            Self::ConditionalKeysets { .. } => {
                cursor.last_id.len() <= 66
                    && cursor
                        .last_id
                        .parse::<Id>()
                        .is_ok_and(|id| id.to_string() == cursor.last_id)
            }
        };
        if cursor.version != 1
            || cursor.filter != *self
            || cursor.last_created_at > i64::MAX as u64
            || !valid_id
        {
            return Err(invalid_cursor());
        }
        Ok(Some((cursor.last_created_at, cursor.last_id)))
    }

    pub(super) fn encode(&self, timestamp: u64, id: String) -> Result<String, Error> {
        let cursor = Cursor {
            version: 1,
            last_created_at: timestamp,
            last_id: id,
            filter: self.clone(),
        };
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor)?))
    }
}
