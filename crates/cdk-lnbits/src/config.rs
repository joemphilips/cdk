//! Typed LNbits adapter configuration.

use std::time::Duration;

use url::Url;

use crate::error::Error;

/// Validated HTTPS origin of the hosted LNbits API.
///
/// The origin must use `https`, must have a host, and must not contain user
/// information, a path, a query or a fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiOrigin(Url);

impl ApiOrigin {
    /// Parse and validate an HTTPS API origin.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let url = Url::parse(value).map_err(|_| Error::InvalidConfig("API origin is not a URL"))?;
        if url.scheme() != "https" {
            return Err(Error::InvalidConfig("API origin must use https"));
        }
        Self::validate_shape(url).map(Self)
    }

    /// Build a loopback HTTP origin for the isolated test transport only.
    #[cfg(test)]
    pub(crate) fn loopback_for_tests(address: std::net::SocketAddr) -> Self {
        let url = Url::parse(&format!("http://{address}/")).expect("loopback URL");
        Self(url)
    }

    fn validate_shape(url: Url) -> Result<Url, Error> {
        if url.host_str().is_none() {
            return Err(Error::InvalidConfig("API origin must have a host"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::InvalidConfig(
                "API origin must not contain credentials",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(Error::InvalidConfig(
                "API origin must not contain a query or fragment",
            ));
        }
        if url.path() != "/" {
            return Err(Error::InvalidConfig("API origin must not contain a path"));
        }
        Ok(url)
    }

    pub(crate) fn url(&self) -> &Url {
        &self.0
    }
}

/// LNbits wallet API key.
///
/// The value is never shown by `Debug` and has no `Display` implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey(String);

impl ApiKey {
    /// Maximum accepted key length.
    pub const MAX_LEN: usize = 128;

    /// Validate an API key value.
    ///
    /// A key must contain 1 to 128 ASCII letters or digits. The invoice key is
    /// also a websocket path segment, so other characters are refused.
    pub fn new(value: String) -> Result<Self, Error> {
        if value.is_empty() || value.len() > Self::MAX_LEN {
            return Err(Error::InvalidConfig("API key has an invalid length"));
        }
        if !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(Error::InvalidConfig(
                "API key contains unsupported characters",
            ));
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey([REDACTED])")
    }
}

/// Mint-side fee reserve policy for outgoing payments.
///
/// The quoted reserve is the larger of this policy and the provider's fee
/// reserve observation for the invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicy {
    /// Minimum fee reserve in sat.
    pub min_fee_reserve_sat: u64,
    /// Proportional fee reserve in parts per million of the invoice amount.
    pub fee_reserve_ppm: u32,
}

/// Outgoing payment enablement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutgoingPayments {
    /// Melt quotes and payments are refused before any provider request.
    Disabled,
    /// Outgoing payments are enabled. The pinned LNbits API cannot cap the
    /// fee of one payment, so the mint pays any provider fee above the quoted
    /// reserve. The adapter reports the actual cost and emits a fee excess
    /// event.
    MintPaysFeeAboveReserve,
}

/// Transport bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    /// Total time limit of one HTTP request, including the body.
    pub request_timeout: Duration,
    /// Time limit to open a connection, including the websocket handshake.
    pub connect_timeout: Duration,
    /// Maximum HTTP response body size in bytes.
    pub max_response_bytes: usize,
    /// Maximum websocket message and frame size in bytes.
    pub max_hint_bytes: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            max_response_bytes: 256 * 1024,
            max_hint_bytes: 64 * 1024,
        }
    }
}

/// Complete LNbits adapter configuration.
#[derive(Debug, Clone)]
pub struct LnbitsConfig {
    /// HTTPS origin of the hosted LNbits API.
    pub api_origin: ApiOrigin,
    /// Admin key. Used only for the payment request.
    pub admin_key: ApiKey,
    /// Invoice key. Used for invoices, status reads and the websocket.
    pub invoice_key: ApiKey,
    /// Bitcoin network that invoices must use.
    pub network: bitcoin::Network,
    /// Mint-side fee reserve policy.
    pub fee_policy: FeePolicy,
    /// Outgoing payment enablement.
    pub outgoing: OutgoingPayments,
    /// Transport bounds.
    pub limits: TransportLimits,
}
