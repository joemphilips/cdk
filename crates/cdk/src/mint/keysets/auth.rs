//! Auth keyset functions

use cdk_common::{CurrencyUnit, KeySetInfo};
use tracing::instrument;

use crate::mint::{KeysResponse, KeysetResponse};
use crate::{Error, Mint};

impl Mint {
    /// Retrieve the auth public keys of the active keyset for distribution to wallet
    /// clients
    #[instrument(skip_all)]
    pub fn auth_pubkeys(&self) -> Result<KeysResponse, Error> {
        let key = self
            .keysets
            .load()
            .values()
            .find(|key| key.unit == CurrencyUnit::Auth)
            .cloned()
            .ok_or(Error::NoActiveKeyset)?;

        Ok(KeysResponse {
            keysets: vec![key.as_ref().into()],
        })
    }

    /// Return a list of auth keysets
    #[instrument(skip_all)]
    pub fn auth_keysets(&self) -> KeysetResponse {
        KeysetResponse {
            keysets: self
                .keysets
                .load()
                .values()
                .filter_map(|key| {
                    if key.unit == CurrencyUnit::Auth {
                        Some(KeySetInfo {
                            id: key.id,
                            unit: key.unit.clone(),
                            active: key.active,
                            input_fee_ppk: key.input_fee_ppk,
                            final_expiry: key.final_expiry,
                        })
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}
