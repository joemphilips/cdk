use std::collections::HashSet;

use anyhow::{bail, Result};
use cdk::nuts::CurrencyUnit;

use crate::config::{LnBackend, OnchainBackend, Settings};

pub(crate) fn configured_units(settings: &Settings) -> Result<HashSet<CurrencyUnit>> {
    let mut units = HashSet::new();
    for rail in &settings.ln {
        if rail.ln_backend != LnBackend::None {
            units.insert(rail.unit.clone());
            if rail.unit == CurrencyUnit::Sat {
                units.insert(CurrencyUnit::Msat);
            }
        }
    }

    if let Some(onchain) = &settings.onchain {
        match onchain.onchain_backend {
            OnchainBackend::None => {}
            #[cfg(feature = "bdk")]
            OnchainBackend::Bdk => {
                units.insert(CurrencyUnit::Sat);
            }
            #[cfg(feature = "fakewallet")]
            OnchainBackend::FakeWallet if units.is_empty() => {
                if let Some(fake) = &settings.fake_wallet {
                    units.extend(fake.supported_units.iter().cloned());
                }
            }
            #[cfg(feature = "fakewallet")]
            OnchainBackend::FakeWallet => {}
        }
    }

    if units.contains(&CurrencyUnit::Auth) {
        bail!("Auth cannot be configured as a monetary payment unit");
    }
    #[cfg(feature = "conditional-tokens")]
    if settings
        .mint_info
        .ctf_registration_fees
        .as_ref()
        .is_some_and(|fees| {
            fees.iter()
                .any(|fee| !units.iter().any(|unit| unit.to_string() == fee.unit))
        })
    {
        bail!("CTF registration fee unit is outside the configured monetary payment units");
    }
    #[cfg(feature = "fakewallet")]
    if settings
        .ln
        .iter()
        .any(|rail| rail.ln_backend == LnBackend::FakeWallet)
    {
        if let Some(fake) = &settings.fake_wallet {
            if fake.keyset_rotations.iter().any(|rotation| {
                rotation.unit != CurrencyUnit::Auth && !units.contains(&rotation.unit)
            }) {
                bail!("Keyset rotation unit is outside the configured monetary payment units");
            }
        }
    }
    Ok(units)
}

#[cfg(all(test, feature = "fakewallet"))]
mod tests {
    use super::*;
    use crate::config::Ln;

    #[test]
    fn explicit_msat_does_not_enable_sat() {
        let settings = Settings {
            ln: vec![Ln {
                ln_backend: LnBackend::FakeWallet,
                unit: CurrencyUnit::Msat,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            configured_units(&settings).unwrap(),
            HashSet::from([CurrencyUnit::Msat])
        );
    }

    #[test]
    fn generic_sat_keeps_its_existing_msat_adapter() {
        let settings = Settings {
            ln: vec![Ln {
                ln_backend: LnBackend::FakeWallet,
                unit: CurrencyUnit::Sat,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            configured_units(&settings).unwrap(),
            HashSet::from([CurrencyUnit::Sat, CurrencyUnit::Msat])
        );
    }

    #[test]
    fn auth_is_not_a_payment_rail() {
        let settings = Settings {
            ln: vec![Ln {
                ln_backend: LnBackend::FakeWallet,
                unit: CurrencyUnit::Auth,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(configured_units(&settings).is_err());
    }
}
