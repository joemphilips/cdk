//! Pure ecash valuation shared by mint accounting and private maintenance tooling.
//!
//! This fold preserves the ordinary mint's saturating arithmetic. It does not validate
//! inventory completeness, ledger consistency, outcome bindings or caller authority.
//! Maintenance callers must perform their bounded, checked validation before this fold.

use std::collections::HashMap;

use cdk_common::nuts::CurrencyUnit;

/// The outstanding amount of one conditional keyset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConditionalOutstanding {
    pub(crate) unit: CurrencyUnit,
    pub(crate) condition_id: String,
    /// The outcomes that the keyset tokens pay out on
    pub(crate) outcomes: Vec<String>,
    pub(crate) amount: u64,
}

/// Sum the regular outstanding amounts and the largest payout of each condition.
pub(crate) fn sum_liabilities(
    regular: Vec<(CurrencyUnit, u64)>,
    conditional: Vec<ConditionalOutstanding>,
    winners: &HashMap<String, String>,
) -> HashMap<CurrencyUnit, u64> {
    let mut totals: HashMap<CurrencyUnit, u64> = HashMap::new();
    for (unit, amount) in regular {
        let total = totals.entry(unit).or_default();
        *total = total.saturating_add(amount);
    }
    // Payout of each outcome of each condition: the tokens that cover it.
    let mut payouts: HashMap<(CurrencyUnit, String), HashMap<String, u64>> = HashMap::new();
    for keyset in conditional {
        let outcomes = payouts
            .entry((keyset.unit, keyset.condition_id))
            .or_default();
        for outcome in keyset.outcomes {
            let payout = outcomes.entry(outcome).or_default();
            *payout = payout.saturating_add(keyset.amount);
        }
    }
    for ((unit, condition_id), outcomes) in payouts {
        let payout = match winners.get(&condition_id) {
            Some(winner) => outcomes.get(winner).copied().unwrap_or(0),
            None => outcomes.values().copied().max().unwrap_or(0),
        };
        let total = totals.entry(unit).or_default();
        *total = total.saturating_add(payout);
    }
    totals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(
        unit: CurrencyUnit,
        condition: &str,
        outcomes: &[&str],
        amount: u64,
    ) -> ConditionalOutstanding {
        ConditionalOutstanding {
            unit,
            condition_id: condition.to_owned(),
            outcomes: outcomes
                .iter()
                .map(|outcome| (*outcome).to_owned())
                .collect(),
            amount,
        }
    }

    #[test]
    fn outcome_labels_do_not_merge_distinct_conditions_or_units() {
        let conditional = vec![
            position(CurrencyUnit::Msat, "first", &["A"], 7),
            position(CurrencyUnit::Msat, "first", &["B"], 11),
            position(CurrencyUnit::Msat, "second", &["A"], 13),
            position(CurrencyUnit::Sat, "first", &["A"], 3),
        ];
        let totals = sum_liabilities(Vec::new(), conditional, &HashMap::new());
        assert_eq!(totals[&CurrencyUnit::Msat], 24);
        assert_eq!(totals[&CurrencyUnit::Sat], 3);
    }

    #[test]
    fn attested_loser_only_holdings_have_no_payout() {
        let conditional = vec![position(CurrencyUnit::Msat, "condition", &["loser"], 900)];
        let winners = HashMap::from([("condition".to_owned(), "winner".to_owned())]);
        let totals = sum_liabilities(vec![(CurrencyUnit::Msat, 19)], conditional, &winners);
        assert_eq!(totals[&CurrencyUnit::Msat], 19);
    }

    #[test]
    fn ordinary_valuation_preserves_saturation_in_each_accumulator() {
        // Maintenance refuses these inputs before folding. The ordinary solvency signal
        // must keep its existing saturation behavior during this extraction.
        let regular = vec![(CurrencyUnit::Sat, u64::MAX), (CurrencyUnit::Sat, 1)];
        let conditional = vec![
            position(CurrencyUnit::Msat, "first", &["A"], u64::MAX),
            position(CurrencyUnit::Msat, "first", &["A"], 1),
            position(CurrencyUnit::Msat, "second", &["B"], 1),
        ];
        let totals = sum_liabilities(regular, conditional, &HashMap::new());
        assert_eq!(totals[&CurrencyUnit::Sat], u64::MAX);
        assert_eq!(totals[&CurrencyUnit::Msat], u64::MAX);
    }
}
