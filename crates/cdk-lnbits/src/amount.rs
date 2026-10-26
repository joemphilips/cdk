//! Checked msat and sat arithmetic for the native sat adapter.

use cdk_common::amount::MSAT_IN_SAT;

use crate::config::FeePolicy;
use crate::error::Error;

/// Largest msat value that the provider can store as a signed 64-bit integer.
const MAX_PROVIDER_MSAT: u64 = i64::MAX as u64;

/// Convert sat to msat. Fails on overflow and on values the provider cannot
/// store.
pub(crate) fn sat_to_msat(sat: u64) -> Result<u64, Error> {
    let msat = sat.checked_mul(MSAT_IN_SAT).ok_or(Error::AmountOverflow)?;
    if msat > MAX_PROVIDER_MSAT {
        return Err(Error::AmountOverflow);
    }
    Ok(msat)
}

/// Round msat down to sat. Used for incoming credit.
pub(crate) fn msat_to_sat_floor(msat: u64) -> u64 {
    msat / MSAT_IN_SAT
}

/// Round msat up to sat. Used for outgoing cost.
pub(crate) fn msat_to_sat_ceil(msat: u64) -> u64 {
    msat / MSAT_IN_SAT + u64::from(msat % MSAT_IN_SAT != 0)
}

/// Absolute value of a signed provider msat amount.
///
/// `i64::MIN` has no positive `i64` value and is refused as malformed.
pub(crate) fn provider_abs_msat(value: i64) -> Result<u64, Error> {
    value
        .checked_abs()
        .map(i64::unsigned_abs)
        .ok_or(Error::MalformedResponse)
}

/// Combined outgoing cost in sat: principal plus fee, rounded up once.
pub(crate) fn outgoing_total_sat(principal_msat: u64, fee_msat: u64) -> Result<u64, Error> {
    let total = principal_msat
        .checked_add(fee_msat)
        .ok_or(Error::AmountOverflow)?;
    Ok(msat_to_sat_ceil(total))
}

/// Mint-side fee reserve in msat for an invoice principal.
pub(crate) fn policy_reserve_msat(policy: &FeePolicy, amount_msat: u64) -> Result<u64, Error> {
    let minimum = sat_to_msat(policy.min_fee_reserve_sat)?;
    let numerator = u128::from(amount_msat)
        .checked_mul(u128::from(policy.fee_reserve_ppm))
        .ok_or(Error::AmountOverflow)?;
    let proportional = numerator.div_ceil(1_000_000);
    let proportional = u64::try_from(proportional).map_err(|_| Error::AmountOverflow)?;
    Ok(minimum.max(proportional))
}
