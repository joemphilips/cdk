use std::fmt;
use std::str::FromStr;

use bitcoin::secp256k1::XOnlyPublicKey;
use serde::Deserialize;

use super::canonical::{parse_minimal_u128, parse_minimal_u64};
use super::{CanonicalHash, Error};
use crate::nuts::nut02::Id;
use crate::secret::Secret;

const OFFER_KEYSET: &str = "offer_keyset";
const EXPIRY: &str = "expiry";
const REFUND: &str = "refund";
const RATE_N: &str = "rate_n";
const RATE_D: &str = "rate_d";
const MIN_RECEIVE: &str = "min_receive";
const MAX_DEBIT: &str = "max_debit";

/// Numeric owner policy for a pool-mode range authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolPolicy {
    /// Minimum receive-rate numerator.
    pub rate_n: u128,
    /// Minimum receive-rate denominator.
    pub rate_d: u128,
    /// Minimum selected receive amount.
    pub min_receive: u128,
    /// Maximum amount debited from the fixed input set.
    pub max_debit: u128,
}

impl PoolPolicy {
    fn new(rate_n: &str, rate_d: &str, min_receive: &str, max_debit: &str) -> Result<Self, Error> {
        let policy = Self {
            rate_n: parse_minimal_u128(rate_n, RATE_N)?,
            rate_d: parse_minimal_u128(rate_d, RATE_D)?,
            min_receive: parse_minimal_u128(min_receive, MIN_RECEIVE)?,
            max_debit: parse_minimal_u128(max_debit, MAX_DEBIT)?,
        };
        if policy.rate_d == 0 {
            return Err(Error::InvalidPoolPolicy("rate_d must be positive"));
        }
        if greatest_common_divisor(policy.rate_n, policy.rate_d) != 1 {
            return Err(Error::InvalidPoolPolicy(
                "rate_n/rate_d must be a reduced fraction",
            ));
        }
        if policy.min_receive == 0 {
            return Err(Error::InvalidPoolPolicy("min_receive must be positive"));
        }
        Ok(policy)
    }

    /// Validate selected totals using checked unsigned arithmetic.
    pub fn validate_totals(
        self,
        input_total: u128,
        receive_total: u128,
        change_total: u128,
    ) -> Result<(), Error> {
        if self.max_debit > input_total {
            return Err(Error::InvalidPoolPolicy(
                "max_debit exceeds the fixed input total",
            ));
        }
        let debit_total = input_total
            .checked_sub(change_total)
            .ok_or(Error::InvalidPoolPolicy(
                "selected change exceeds the fixed input total",
            ))?;
        let receive_side = receive_total
            .checked_mul(self.rate_d)
            .ok_or(Error::ArithmeticOverflow)?;
        let debit_side = debit_total
            .checked_mul(self.rate_n)
            .ok_or(Error::ArithmeticOverflow)?;
        if receive_side < debit_side {
            return Err(Error::InvalidPoolPolicy("selected rate is below the limit"));
        }
        if receive_total < self.min_receive {
            return Err(Error::InvalidPoolPolicy(
                "selected receive amount is below min_receive",
            ));
        }
        if debit_total > self.max_debit {
            return Err(Error::InvalidPoolPolicy("selected debit exceeds max_debit"));
        }
        Ok(())
    }
}

/// The closed standard or pool authorization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayToUnlockMode {
    /// One exact ordered receive-output bundle.
    Standard,
    /// One committed output manifest and numeric range policy.
    Pool(PoolPolicy),
}

/// A validated CTF `PAY_TO_UNLOCK` condition.
#[derive(Clone, PartialEq, Eq)]
pub struct PayToUnlockCondition {
    /// Unique nonce for this proof.
    pub nonce: CanonicalHash,
    /// CTF receive or manifest commitment.
    pub data: CanonicalHash,
    /// Keyset of the proof carrying this condition.
    pub offer_keyset: Id,
    /// Last unix second before which settlement is valid.
    pub expiry: u64,
    /// Fresh BIP-340 x-only refund public key.
    pub refund: XOnlyPublicKey,
    /// Closed standard or pool authorization.
    pub mode: PayToUnlockMode,
}

impl fmt::Debug for PayToUnlockCondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PayToUnlockCondition")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl PayToUnlockCondition {
    /// Strictly decode and validate one CTF `PAY_TO_UNLOCK` proof secret.
    pub fn parse(secret: &Secret) -> Result<Self, Error> {
        let (kind, data): (String, StrictSecretData) = serde_json::from_slice(secret.as_bytes())
            .map_err(|_| Error::InvalidCondition("condition wire is malformed"))?;
        if kind != "PAY_TO_UNLOCK" {
            return Err(Error::InvalidCondition("kind must be PAY_TO_UNLOCK"));
        }

        let nonce = CanonicalHash::parse(&data.nonce, "nonce")?;
        let commitment = CanonicalHash::parse(&data.data, "data")?;
        let tags = ConditionTags::parse(data.tags)?;
        let offer_keyset = parse_keyset_id(&tags.offer_keyset)?;
        let expiry = parse_minimal_u64(&tags.expiry, EXPIRY)?;
        let refund = parse_refund_key(&tags.refund)?;
        let mode = tags.mode()?;

        Ok(Self {
            nonce,
            data: commitment,
            offer_keyset,
            expiry,
            refund,
            mode,
        })
    }

    /// Whether two proof-local conditions describe the same authorization.
    ///
    /// The nonce is intentionally excluded because it must be unique per proof.
    pub fn has_same_authorization(&self, other: &Self) -> bool {
        self.data == other.data
            && self.offer_keyset == other.offer_keyset
            && self.expiry == other.expiry
            && self.refund == other.refund
            && self.mode == other.mode
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictSecretData {
    nonce: String,
    data: String,
    tags: Vec<Vec<String>>,
}

#[derive(Debug)]
struct ConditionTags {
    offer_keyset: String,
    expiry: String,
    refund: String,
    rate_n: Option<String>,
    rate_d: Option<String>,
    min_receive: Option<String>,
    max_debit: Option<String>,
}

impl ConditionTags {
    fn parse(tags: Vec<Vec<String>>) -> Result<Self, Error> {
        let mut parsed = PartialConditionTags::default();
        for tag in tags {
            let Some(name) = tag.first() else {
                return Err(Error::UnknownTag);
            };
            match name.as_str() {
                OFFER_KEYSET => set_tag(&mut parsed.offer_keyset, &tag)?,
                EXPIRY => set_tag(&mut parsed.expiry, &tag)?,
                REFUND => set_tag(&mut parsed.refund, &tag)?,
                RATE_N => set_tag(&mut parsed.rate_n, &tag)?,
                RATE_D => set_tag(&mut parsed.rate_d, &tag)?,
                MIN_RECEIVE => set_tag(&mut parsed.min_receive, &tag)?,
                MAX_DEBIT => set_tag(&mut parsed.max_debit, &tag)?,
                _ => return Err(Error::UnknownTag),
            }
        }

        Ok(Self {
            offer_keyset: parsed.offer_keyset.ok_or(Error::MissingTag(OFFER_KEYSET))?,
            expiry: parsed.expiry.ok_or(Error::MissingTag(EXPIRY))?,
            refund: parsed.refund.ok_or(Error::MissingTag(REFUND))?,
            rate_n: parsed.rate_n,
            rate_d: parsed.rate_d,
            min_receive: parsed.min_receive,
            max_debit: parsed.max_debit,
        })
    }

    fn mode(&self) -> Result<PayToUnlockMode, Error> {
        match (
            self.rate_n.as_deref(),
            self.rate_d.as_deref(),
            self.min_receive.as_deref(),
            self.max_debit.as_deref(),
        ) {
            (None, None, None, None) => Ok(PayToUnlockMode::Standard),
            (Some(rate_n), Some(rate_d), Some(min_receive), Some(max_debit)) => Ok(
                PayToUnlockMode::Pool(PoolPolicy::new(rate_n, rate_d, min_receive, max_debit)?),
            ),
            _ => Err(Error::PartialPoolTags),
        }
    }
}

#[derive(Debug, Default)]
struct PartialConditionTags {
    offer_keyset: Option<String>,
    expiry: Option<String>,
    refund: Option<String>,
    rate_n: Option<String>,
    rate_d: Option<String>,
    min_receive: Option<String>,
    max_debit: Option<String>,
}

fn set_tag(destination: &mut Option<String>, tag: &[String]) -> Result<(), Error> {
    if tag.len() != 2 {
        return Err(Error::InvalidCondition(
            "each tag must contain exactly one value",
        ));
    }
    if destination.replace(tag[1].clone()).is_some() {
        return Err(Error::DuplicateTag);
    }
    Ok(())
}

fn greatest_common_divisor(mut lhs: u128, mut rhs: u128) -> u128 {
    while rhs != 0 {
        let remainder = lhs % rhs;
        lhs = rhs;
        rhs = remainder;
    }
    lhs
}

fn parse_keyset_id(value: &str) -> Result<Id, Error> {
    let id = Id::from_str(value).map_err(|_| Error::InvalidKeysetId {
        field: OFFER_KEYSET,
    })?;
    if id.to_string() != value {
        return Err(Error::InvalidKeysetId {
            field: OFFER_KEYSET,
        });
    }
    Ok(id)
}

fn parse_refund_key(value: &str) -> Result<XOnlyPublicKey, Error> {
    let key =
        XOnlyPublicKey::from_str(value).map_err(|_| Error::InvalidPublicKey { field: REFUND })?;
    if key.to_string() != value {
        return Err(Error::InvalidPublicKey { field: REFUND });
    }
    Ok(key)
}
