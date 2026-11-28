//! Length-admitted fact protocol. The caller must prove source and completeness.
use std::collections::{HashMap, HashSet};
use std::io::Read;

use cdk_common::mint::StoredCondition;
use cdk_common::nuts::nut_ctf as ctf;
use cdk_common::nuts::nut_ctf::{canonical_outcome_collection, parse_outcome_collection};
use cdk_common::nuts::CurrencyUnit;
use serde::{Deserialize, Serialize};

use super::liability_value::{sum_liabilities, ConditionalOutstanding};

const MAX_FRAME: usize = 64 * 1024;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_ASSOCIATIONS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    Framing,
    Limit,
    Shape,
    Identity,
    Ledger,
    Binding,
    Overflow,
}

impl Refusal {
    pub(super) fn token(self) -> &'static str {
        match self {
            Self::Framing => "framing",
            Self::Limit => "limit",
            Self::Shape => "shape",
            Self::Identity => "identity",
            Self::Ledger => "ledger",
            Self::Binding => "binding",
            Self::Overflow => "overflow",
        }
    }
}

type Result<T> = std::result::Result<T, Refusal>;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Unit {
    Sat,
    Msat,
}
impl Unit {
    fn cashu(self) -> CurrencyUnit {
        match self {
            Self::Sat => CurrencyUnit::Sat,
            Self::Msat => CurrencyUnit::Msat,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Header {
        version: u8,
    },
    Condition {
        stored: ConditionFact,
    },
    Keyset {
        id: String,
        unit: Unit,
        issued: u64,
        redeemed: u64,
        signed_ledger: u64,
        spent_ledger: u64,
        binding: Option<Binding>,
    },
    Quote {
        id: String,
        unit: Unit,
        paid: u64,
        issued: u64,
        payment_ledger: u64,
        issuance_ledger: u64,
    },
    End {
        conditions: usize,
        keysets: usize,
        quotes: usize,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    condition: String,
    collection: String,
    collection_id: String,
}

#[derive(Debug)]
struct Condition {
    outcomes: Vec<String>,
    id: [u8; 32],
    collateral: CurrencyUnit,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionFact {
    condition_id: String,
    threshold: u32,
    tags_json: String,
    announcements_json: String,
    collateral: Unit,
    attestation_status: String,
    winning_outcome: Option<String>,
    attested_at: Option<u64>,
    oracle_sigs: Option<Vec<OracleFact>>,
    created_at: u64,
    condition_type: String,
    lo_bound: Option<i64>,
    hi_bound: Option<i64>,
    precision: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleFact {
    oracle_pubkey: String,
    oracle_sig: Option<String>,
    outcome: Option<String>,
    digit_sigs: Option<Vec<String>>,
}

fn condition_fact(fact: ConditionFact) -> Result<(String, Condition, Option<String>)> {
    let stored = StoredCondition {
        condition_id: fact.condition_id,
        threshold: fact.threshold,
        tags_json: fact.tags_json,
        announcements_json: fact.announcements_json,
        collateral: Some(fact.collateral.cashu()),
        attestation_status: fact.attestation_status,
        winning_outcome: fact.winning_outcome,
        attested_at: fact.attested_at,
        oracle_sigs: fact.oracle_sigs.map(|items| {
            items
                .into_iter()
                .map(|item| ctf::OracleSig {
                    oracle_pubkey: item.oracle_pubkey,
                    oracle_sig: item.oracle_sig,
                    outcome: item.outcome,
                    digit_sigs: item.digit_sigs,
                })
                .collect()
        }),
        created_at: fact.created_at,
        condition_type: fact.condition_type,
        lo_bound: fact.lo_bound,
        hi_bound: fact.hi_bound,
        precision: fact.precision,
    };
    stored.validate().map_err(|_| Refusal::Binding)?;
    if let Some(signatures) = &stored.oracle_sigs {
        let verified = super::oracle_evidence::verify_threshold(
            &stored,
            &ctf::OracleWitness {
                oracle_sigs: signatures.clone(),
            },
        )
        .map_err(|_| Refusal::Binding)?;
        if stored.winning_outcome.as_deref() != Some(verified.as_str()) {
            return Err(Refusal::Binding);
        }
    }
    let encoded: Vec<String> =
        serde_json::from_str(&stored.announcements_json).map_err(|_| Refusal::Binding)?;
    let announcements = encoded
        .iter()
        .map(|value| ctf::dlc::parse_oracle_announcement(value))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Refusal::Binding)?;
    ctf::dlc::validate_announcement_set(&announcements, stored.threshold)
        .map_err(|_| Refusal::Binding)?;
    for announcement in &announcements {
        ctf::dlc::verify_announcement_signature(announcement).map_err(|_| Refusal::Binding)?;
    }
    let first = announcements.first().ok_or(Refusal::Binding)?;
    let keys = announcements
        .iter()
        .map(ctf::dlc::extract_oracle_pubkey)
        .collect::<Vec<_>>();
    let event = ctf::dlc::extract_event_id(first);
    let (outcomes, id) = if stored.condition_type == "numeric" {
        ctf::dlc::extract_digit_decomposition(first).map_err(|_| Refusal::Binding)?;
        (
            vec!["HI".to_owned(), "LO".to_owned()],
            ctf::compute_condition_id_numeric(
                &keys,
                &event,
                2,
                stored.lo_bound.ok_or(Refusal::Binding)?,
                stored.hi_bound.ok_or(Refusal::Binding)?,
                stored.precision.ok_or(Refusal::Binding)?,
            ),
        )
    } else {
        let outcomes = ctf::dlc::extract_outcomes(first).map_err(|_| Refusal::Binding)?;
        let count = u8::try_from(outcomes.len()).map_err(|_| Refusal::Binding)?;
        let id = ctf::compute_condition_id(&keys, &event, count);
        (outcomes, id)
    };
    if ctf::to_hex(&id) != stored.condition_id {
        return Err(Refusal::Binding);
    }
    let winner = if stored.condition_type == "enum" && stored.attestation_status == "attested" {
        stored.winning_outcome
    } else {
        None
    };
    Ok((
        stored.condition_id,
        Condition {
            outcomes,
            id,
            collateral: fact.collateral.cashu(),
        },
        winner,
    ))
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(super) struct Amounts {
    regular: u64,
    conditional: u64,
    paid_unissued: u64,
    total: u64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct Valuation {
    version: u8,
    authorizing: bool,
    sat: Amounts,
    msat: Amounts,
    total_msat: u64,
    conditions: usize,
    keysets: usize,
    quotes: usize,
    records: usize,
    bytes: usize,
}

fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right).ok_or(Refusal::Overflow)
}
fn identity(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Refusal::Identity);
    }
    Ok(())
}

pub(super) fn evaluate<R: Read>(reader: R) -> Result<Valuation> {
    evaluate_with_limits(reader, MAX_BYTES, MAX_RECORDS, MAX_ASSOCIATIONS)
}

fn evaluate_with_limits<R: Read>(
    mut reader: R,
    max_bytes: usize,
    max_records: usize,
    max_associations: usize,
) -> Result<Valuation> {
    let mut bytes = 0usize;
    let mut records = 0usize;
    let mut associations = 0usize;
    let mut conditions = HashMap::<String, Condition>::new();
    let mut winners = HashMap::new();
    let mut keysets = HashSet::new();
    let mut quotes = HashSet::new();
    let mut regular = Vec::new();
    let mut conditional = Vec::new();
    let mut regular_totals = HashMap::<CurrencyUnit, u64>::new();
    let mut paid_totals = HashMap::<CurrencyUnit, u64>::new();
    let mut payouts = HashMap::<(CurrencyUnit, String), HashMap<String, u64>>::new();
    let mut ended = false;
    let mut data_started = false;
    loop {
        if bytes.checked_add(4).ok_or(Refusal::Limit)? > max_bytes {
            return Err(Refusal::Limit);
        }
        let mut header = [0u8; 4];
        reader
            .read_exact(&mut header)
            .map_err(|_| Refusal::Framing)?;
        bytes += 4;
        let size = u32::from_be_bytes(header) as usize;
        if size == 0 {
            let mut trailing = [0u8; 1];
            if !ended || reader.read(&mut trailing).map_err(|_| Refusal::Framing)? != 0 {
                return Err(Refusal::Framing);
            }
            break;
        }
        if ended
            || size > MAX_FRAME
            || records >= max_records
            || bytes.checked_add(size).ok_or(Refusal::Limit)? > max_bytes
        {
            return Err(Refusal::Limit);
        }
        // All allocation is preceded by frame/count/aggregate admission.
        let mut frame = vec![0u8; size];
        reader
            .read_exact(&mut frame)
            .map_err(|_| Refusal::Framing)?;
        bytes += size;
        records += 1;
        let record: Record = serde_json::from_slice(&frame).map_err(|_| Refusal::Shape)?;
        if records == 1 && !matches!(record, Record::Header { version: 1 }) {
            return Err(Refusal::Shape);
        }
        match record {
            Record::Header { version: 1 } if records == 1 => (),
            Record::Header { .. } => return Err(Refusal::Shape),
            Record::Condition { stored } => {
                let (id, condition, winner) = condition_fact(stored)?;
                let outcomes = &condition.outcomes;
                if data_started
                    || conditions.contains_key(&id)
                    || outcomes.len() < 2
                    || outcomes.len() > 255
                {
                    return Err(Refusal::Binding);
                }
                associations = associations
                    .checked_add(outcomes.len())
                    .ok_or(Refusal::Limit)?;
                if associations > max_associations {
                    return Err(Refusal::Limit);
                }
                let mut seen = HashSet::new();
                for outcome in outcomes {
                    identity(outcome)?;
                    if outcome == "*" || !seen.insert(outcome) {
                        return Err(Refusal::Binding);
                    }
                    if canonical_outcome_collection(outcomes, &[outcome.clone()])
                        .map_err(|_| Refusal::Binding)?
                        != ctf::escape_outcome_component(outcome)
                    {
                        return Err(Refusal::Binding);
                    }
                }
                if let Some(winner) = winner {
                    if !seen.contains(&winner) {
                        return Err(Refusal::Binding);
                    }
                    winners.insert(id.clone(), winner);
                }
                conditions.insert(id, condition);
            }
            Record::Keyset {
                id,
                unit,
                issued,
                redeemed,
                signed_ledger,
                spent_ledger,
                binding,
            } => {
                data_started = true;
                identity(&id)?;
                if !keysets.insert(id) {
                    return Err(Refusal::Identity);
                }
                if issued != signed_ledger || redeemed != spent_ledger || redeemed > issued {
                    return Err(Refusal::Ledger);
                }
                let amount = issued - redeemed;
                let unit = unit.cashu();
                match binding {
                    None => {
                        let total = regular_totals.entry(unit.clone()).or_default();
                        *total = add(*total, amount)?;
                        regular.push((unit, amount));
                    }
                    Some(binding) => {
                        let condition =
                            conditions.get(&binding.condition).ok_or(Refusal::Binding)?;
                        if unit != condition.collateral
                            || ctf::to_hex(
                                &ctf::compute_outcome_collection_id(
                                    &[0; 32],
                                    &condition.id,
                                    &binding.collection,
                                )
                                .map_err(|_| Refusal::Binding)?,
                            ) != binding.collection_id
                        {
                            return Err(Refusal::Binding);
                        }
                        let outcomes = parse_outcome_collection(&binding.collection);
                        associations = associations
                            .checked_add(outcomes.len())
                            .ok_or(Refusal::Limit)?;
                        if associations > max_associations {
                            return Err(Refusal::Limit);
                        }
                        if canonical_outcome_collection(&condition.outcomes, &outcomes)
                            .map_err(|_| Refusal::Binding)?
                            != binding.collection
                        {
                            return Err(Refusal::Binding);
                        }
                        let by_outcome = payouts
                            .entry((unit.clone(), binding.condition.clone()))
                            .or_default();
                        for outcome in &outcomes {
                            let total = by_outcome.entry(outcome.clone()).or_default();
                            *total = add(*total, amount)?;
                        }
                        conditional.push(ConditionalOutstanding {
                            unit,
                            condition_id: binding.condition,
                            outcomes,
                            amount,
                        });
                    }
                }
            }
            Record::Quote {
                id,
                unit,
                paid,
                issued,
                payment_ledger,
                issuance_ledger,
            } => {
                data_started = true;
                identity(&id)?;
                if !quotes.insert(id) {
                    return Err(Refusal::Identity);
                }
                if paid != payment_ledger || issued != issuance_ledger || issued > paid {
                    return Err(Refusal::Ledger);
                }
                let total = paid_totals.entry(unit.cashu()).or_default();
                *total = add(*total, paid - issued)?;
            }
            Record::End {
                conditions: condition_count,
                keysets: keyset_count,
                quotes: quote_count,
            } => {
                if condition_count != conditions.len()
                    || keyset_count != keysets.len()
                    || quote_count != quotes.len()
                {
                    return Err(Refusal::Identity);
                }
                ended = true;
            }
        }
    }
    // Check the final per-unit accumulator before invoking the unchanged saturating fold.
    let mut conditional_totals = HashMap::<CurrencyUnit, u64>::new();
    for ((unit, condition), outcomes) in payouts {
        let amount = match winners.get(&condition) {
            Some(winner) => outcomes.get(winner).copied().unwrap_or_default(),
            None => outcomes.values().copied().max().unwrap_or_default(),
        };
        let total = conditional_totals.entry(unit).or_default();
        *total = add(*total, amount)?;
    }
    let folded_regular = sum_liabilities(regular, Vec::new(), &HashMap::new());
    let folded_conditional = sum_liabilities(Vec::new(), conditional, &winners);
    if folded_regular != regular_totals || folded_conditional != conditional_totals {
        return Err(Refusal::Ledger);
    }
    let amount = |unit: CurrencyUnit| -> Result<Amounts> {
        let regular = folded_regular.get(&unit).copied().unwrap_or_default();
        let conditional = folded_conditional.get(&unit).copied().unwrap_or_default();
        let paid_unissued = paid_totals.get(&unit).copied().unwrap_or_default();
        let total = add(add(regular, conditional)?, paid_unissued)?;
        Ok(Amounts {
            regular,
            conditional,
            paid_unissued,
            total,
        })
    };
    let sat = amount(CurrencyUnit::Sat)?;
    let msat = amount(CurrencyUnit::Msat)?;
    let total_msat = add(
        sat.total.checked_mul(1000).ok_or(Refusal::Overflow)?,
        msat.total,
    )?;
    Ok(Valuation {
        version: 1,
        authorizing: false,
        sat,
        msat,
        total_msat,
        conditions: conditions.len(),
        keysets: keysets.len(),
        quotes: quotes.len(),
        records,
        bytes,
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
