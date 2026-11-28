//! Private request/receipt consistency checks, never source or host authority.
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use bitcoin::constants::ChainHash;
use bitcoin::Network;
use lightning::offers::offer::{Amount, Offer};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

use super::records::{Refusal, Unit};

type Result<T> = std::result::Result<T, Refusal>;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Chain {
    Mainnet,
    Signet,
    Regtest,
}
impl Chain {
    fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Side {
    Mint,
    Melt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub id: String,
    pub side: Side,
    pub unit: Unit,
    pub method: String,
    pub request: String,
    pub amount: Option<u64>,
    pub state: Option<String>,
    pub lookup_kind: Option<String>,
    pub lookup: Option<String>,
    pub options: Option<String>,
}

#[derive(Debug)]
pub(super) struct MeltAnchor {
    pub unit: Unit,
    pub amount: u64,
    pub state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Credit {
    pub id: String,
    pub quote: String,
    pub payment: String,
    pub amount: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub id: String,
    pub kind: String,
    pub direction: String,
    pub status: String,
    pub amount_msat: Option<u64>,
    pub hash: Option<String>,
    pub offer: Option<String>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(super) struct Counts {
    pub requests: usize,
    pub credits: usize,
    pub receipts: usize,
}

// The stored enum is the maintained MeltPaymentRequest shape. This strict mirror
// rejects unknown fields before the maintained typed parsers are invoked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum StoredRequest {
    Bolt11 { bolt11: String },
    Bolt12 { offer: String },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Amountless {
    amount_msat: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    amountless: Amountless,
}

#[derive(Debug)]
struct Parsed {
    canonical: String,
    lookup: String,
    selected_msat: Option<u64>,
}

fn fail<T>() -> Result<T> {
    Err(Refusal::Binding)
}
fn identifier(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Refusal::Identity);
    }
    Ok(())
}
fn hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Refusal::Identity);
    }
    Ok(())
}
fn lookup(request: &Request, kind: &str, value: &str) -> bool {
    request.lookup_kind.as_deref() == Some(kind) && request.lookup.as_deref() == Some(value)
}
fn native(msat: u64, unit: Unit) -> u64 {
    match unit {
        Unit::Sat => msat / 1000,
        Unit::Msat => msat,
    }
}
fn msat(amount: u64, unit: Unit) -> Result<u64> {
    match unit {
        Unit::Sat => amount.checked_mul(1000).ok_or(Refusal::Overflow),
        Unit::Msat => Ok(amount),
    }
}
fn parse(request: &Request, chain: Chain) -> Result<Parsed> {
    identifier(&request.id)?;
    if !matches!(request.method.as_str(), "bolt11" | "bolt12") {
        return fail();
    }
    let encoded = match request.side {
        Side::Mint => {
            if request.options.is_some() || request.state.is_some() {
                return fail();
            }
            request.request.clone()
        }
        Side::Melt => match serde_json::from_str::<StoredRequest>(&request.request) {
            Ok(StoredRequest::Bolt11 { bolt11 }) if request.method == "bolt11" => bolt11,
            Ok(StoredRequest::Bolt12 { offer }) if request.method == "bolt12" => offer,
            // The ordinary SQL loader supports legacy raw BOLT11 only.
            Err(_)
                if request.method == "bolt11" && !request.request.trim_start().starts_with('{') =>
            {
                request.request.clone()
            }
            _ => return fail(),
        },
    };
    let (canonical, payment_lookup, nominal) = if request.method == "bolt11" {
        let invoice = Bolt11Invoice::from_str(&encoded).map_err(|_| Refusal::Binding)?;
        if invoice.network() != chain.network() {
            return fail();
        }
        (
            invoice.to_string(),
            invoice.payment_hash().to_string(),
            invoice.amount_milli_satoshis(),
        )
    } else {
        let offer = Offer::from_str(&encoded).map_err(|_| Refusal::Binding)?;
        if !offer.supports_chain(ChainHash::using_genesis_block(chain.network()))
            || offer.offer_features().requires_unknown_bits()
            || offer.expects_quantity()
        {
            return fail();
        }
        let amount = match offer.amount() {
            Some(Amount::Bitcoin { amount_msats }) => Some(amount_msats),
            None => None,
            _ => return fail(),
        };
        (offer.to_string(), offer.id().to_string(), amount)
    };
    let selected_msat = match request.side {
        Side::Mint => {
            let wanted = request
                .amount
                .map(|amount| msat(amount, request.unit))
                .transpose()?;
            if nominal != wanted || (request.method == "bolt11" && wanted.is_none()) {
                return fail();
            }
            let kind = if request.method == "bolt11" {
                "payment_hash"
            } else {
                "offer_id"
            };
            if !lookup(request, kind, &payment_lookup) {
                return fail();
            }
            // The paid counter is authoritative for liability; expiry and nominal
            // amount never erase late credits or overpayments.
            nominal
        }
        Side::Melt => {
            if !matches!(
                request.state.as_deref(),
                Some("UNPAID" | "PENDING" | "PAID")
            ) {
                return fail();
            }
            let override_amount = request
                .options
                .as_ref()
                .map(|raw| {
                    serde_json::from_str::<Options>(raw)
                        .map(|value| value.amountless.amount_msat)
                        .map_err(|_| Refusal::Binding)
                })
                .transpose()?;
            if let (Some(fixed), Some(explicit)) = (nominal, override_amount) {
                if fixed != explicit {
                    return fail();
                }
            }
            let amount = override_amount.or(nominal).ok_or(Refusal::Binding)?;
            if request.amount != Some(native(amount, request.unit)) {
                return fail();
            }
            if request.method == "bolt11" {
                if !lookup(request, "payment_hash", &payment_lookup) {
                    return fail();
                }
            } else if let Some(value) = &request.lookup {
                hash(value)?;
                if request.lookup_kind.as_deref() != Some("payment_id") {
                    return fail();
                }
            } else if request.lookup_kind.is_some() {
                return fail();
            }
            Some(amount)
        }
    };
    Ok(Parsed {
        canonical,
        lookup: payment_lookup,
        selected_msat,
    })
}

#[derive(Default)]
pub(super) struct Facts {
    requests: HashMap<(bool, String), Request>,
    credits: HashMap<String, Credit>,
    receipts: HashMap<String, Receipt>,
}
impl Facts {
    pub fn request(&mut self, request: Request) -> Result<()> {
        identifier(&request.id)?;
        let key = (request.side == Side::Mint, request.id.clone());
        if self.requests.insert(key, request).is_some() {
            return Err(Refusal::Identity);
        }
        Ok(())
    }
    pub fn credit(&mut self, credit: Credit) -> Result<()> {
        for value in [&credit.id, &credit.quote, &credit.payment] {
            identifier(value)?;
        }
        if self.credits.insert(credit.id.clone(), credit).is_some() {
            return Err(Refusal::Identity);
        }
        Ok(())
    }
    pub fn receipt(&mut self, receipt: Receipt) -> Result<()> {
        hash(&receipt.id)?;
        if let Some(value) = &receipt.hash {
            hash(value)?;
        }
        if let Some(value) = &receipt.offer {
            hash(value)?;
        }
        if !matches!(receipt.kind.as_str(), "bolt11" | "bolt12_offer" | "onchain")
            || !matches!(receipt.direction.as_str(), "INBOUND" | "OUTBOUND")
            || !matches!(receipt.status.as_str(), "SUCCEEDED" | "FAILED" | "PENDING")
            || (receipt.kind == "bolt11" && (receipt.hash.is_none() || receipt.offer.is_some()))
            || (receipt.kind == "bolt12_offer" && receipt.offer.is_none())
            || self.receipts.contains_key(&receipt.id)
        {
            return Err(Refusal::Identity);
        }
        self.receipts.insert(receipt.id.clone(), receipt);
        Ok(())
    }
    pub fn counts(&self) -> Counts {
        Counts {
            requests: self.requests.len(),
            credits: self.credits.len(),
            receipts: self.receipts.len(),
        }
    }
    pub fn verify(
        &self,
        chain: Chain,
        quotes: &HashMap<String, (Unit, u64)>,
        melts: &HashMap<String, MeltAnchor>,
    ) -> Result<()> {
        let mut parsed = HashMap::new();
        let mut mint_count = 0;
        let mut melt_count = 0;
        let mut inbound = HashMap::new();
        let mut outbound = HashMap::new();
        for (key, request) in &self.requests {
            let value = parse(request, chain)?;
            if key.0 {
                mint_count += 1;
                if quotes.get(&request.id).map(|entry| entry.0) != Some(request.unit)
                    || inbound
                        .insert((request.method.as_str(), value.lookup.clone()), request)
                        .is_some()
                {
                    return fail();
                }
            } else {
                melt_count += 1;
                let anchor = melts.get(&request.id).ok_or(Refusal::Binding)?;
                if anchor.unit != request.unit
                    || Some(anchor.amount) != request.amount
                    || Some(anchor.state.as_str()) != request.state.as_deref()
                {
                    return fail();
                }
                if let Some(lookup) = &request.lookup {
                    // Unpaid retries can share a lookup. Only the retained PAID
                    // allocation must be unique; the SQL schema enforces this too.
                    if request.state.as_deref() == Some("PAID")
                        && outbound
                            .insert((request.method.as_str(), lookup.clone()), request)
                            .is_some()
                    {
                        return fail();
                    }
                }
            }
            parsed.insert(key.clone(), value);
        }
        if mint_count != quotes.len() || melt_count != melts.len() {
            return fail();
        }
        let mut by_payment = HashMap::new();
        let mut credit_sums = HashMap::<&str, u64>::new();
        for credit in self.credits.values() {
            if !quotes.contains_key(&credit.quote)
                || by_payment.insert(credit.payment.as_str(), credit).is_some()
            {
                return fail();
            }
            let sum = credit_sums.entry(&credit.quote).or_default();
            *sum = sum.checked_add(credit.amount).ok_or(Refusal::Overflow)?;
        }
        for (id, (_, paid)) in quotes {
            if credit_sums.get(id.as_str()).copied().unwrap_or_default() != *paid {
                return Err(Refusal::Ledger);
            }
        }
        let mut used_credits = HashSet::new();
        let mut paid_external = HashSet::new();
        for receipt in self.receipts.values() {
            if receipt.kind == "onchain" {
                continue;
            } // Separate coordinator claim reconciliation remains mandatory.
            if receipt.status == "PENDING" {
                return fail();
            }
            if receipt.status != "SUCCEEDED" {
                continue;
            } // Failed attempts cannot discharge an obligation.
            let method = if receipt.kind == "bolt11" {
                "bolt11"
            } else {
                "bolt12"
            };
            let request_lookup = if method == "bolt11" {
                receipt.hash.as_ref()
            } else {
                receipt.offer.as_ref()
            }
            .ok_or(Refusal::Binding)?;
            let amount = receipt.amount_msat.ok_or(Refusal::Binding)?;
            if receipt.direction == "INBOUND" {
                let request = inbound
                    .get(&(method, request_lookup.clone()))
                    .ok_or(Refusal::Binding)?;
                let credit_id = receipt.hash.as_ref().unwrap_or(&receipt.id);
                let credit = by_payment.get(credit_id.as_str()).ok_or(Refusal::Binding)?;
                if credit.quote != request.id
                    || credit.amount != native(amount, request.unit)
                    || !used_credits.insert(credit.id.as_str())
                {
                    return fail();
                }
            } else {
                let id = if method == "bolt11" {
                    receipt.hash.as_ref().ok_or(Refusal::Binding)?
                } else {
                    &receipt.id
                };
                let request = outbound
                    .get(&(method, id.clone()))
                    .ok_or(Refusal::Binding)?;
                let value = parsed
                    .get(&(false, request.id.clone()))
                    .ok_or(Refusal::Binding)?;
                if value.lookup != *request_lookup
                    || value.selected_msat != Some(amount)
                    || !paid_external.insert(request.id.as_str())
                {
                    return fail();
                }
            }
        }
        let mut internal = HashSet::new();
        for credit in self.credits.values() {
            if used_credits.contains(credit.id.as_str()) {
                continue;
            }
            let mint_key = (true, credit.quote.clone());
            let melt_key = (false, credit.payment.clone());
            let mint = self.requests.get(&mint_key).ok_or(Refusal::Binding)?;
            let melt = self.requests.get(&melt_key).ok_or(Refusal::Binding)?;
            let mint_parsed = parsed.get(&mint_key).ok_or(Refusal::Binding)?;
            let melt_parsed = parsed.get(&melt_key).ok_or(Refusal::Binding)?;
            if melt.state.as_deref() != Some("PAID")
                || mint.unit != melt.unit
                || mint.method != melt.method
                || mint_parsed.canonical != melt_parsed.canonical
                || melt.amount != Some(credit.amount)
                || paid_external.contains(melt.id.as_str())
                || !internal.insert(melt.id.as_str())
            {
                return fail();
            }
        }
        for request in self.requests.values() {
            if request.side == Side::Melt
                && request.state.as_deref() == Some("PAID")
                && !paid_external.contains(request.id.as_str())
                && !internal.contains(request.id.as_str())
            {
                return fail();
            }
        }
        Ok(())
    }
}
