//! Per-client request rate limits for the mint HTTP API.
//!
//! Each request gets one class from its method and matched route. Each class
//! has one token bucket for each client. The client is the peer address. When
//! the peer is a configured trusted proxy, the client is the right-most
//! `X-Forwarded-For` entry, because only that entry comes from the proxy.
//! Configured engine addresses get a separate class with their own limit and
//! no extra body cap.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

/// Upper bound of tracked buckets. One client uses at most one bucket per class.
const MAX_TRACKED_BUCKETS: usize = 100_000;
/// A full table is pruned at most once in this interval.
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);
/// Bounds that keep the bucket arithmetic exact.
const MAX_PER_MINUTE: u32 = 1_000_000;
const MAX_BURST: u32 = 1_000_000;

/// Rate limit configuration. The limits are off when this table is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Request body cap for every class except the engine class.
    pub max_body_bytes: usize,
    /// Peers whose right-most `X-Forwarded-For` entry names the client.
    pub trusted_proxies: Vec<IpAddr>,
    /// Client addresses that use the engine class.
    pub engine_addresses: Vec<IpAddr>,
    /// Swap, mint, melt and the conditional-token write routes.
    pub value_write: ClassLimit,
    /// Mint and melt quote creation.
    pub quote: ClassLimit,
    /// NUT-09 restore, NUT-07 check state and the batch mint quote check.
    pub recovery: ClassLimit,
    /// Every other request.
    pub read: ClassLimit,
    /// Every request from an engine address.
    pub engine: ClassLimit,
}

/// Token bucket of one class: a sustained rate and a burst size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassLimit {
    /// Sustained requests per minute for one client.
    pub per_minute: u32,
    /// Requests that one idle client can send at once.
    pub burst: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RequestClass {
    ValueWrite,
    Quote,
    Recovery,
    Read,
    Engine,
}

/// Generic cell rate parameters of one class.
#[derive(Debug, Clone, Copy)]
struct Rate {
    interval: Duration,
    tolerance: Duration,
}

impl Rate {
    fn new(name: &str, limit: ClassLimit) -> Result<Self, String> {
        if !(1..=MAX_PER_MINUTE).contains(&limit.per_minute)
            || !(1..=MAX_BURST).contains(&limit.burst)
        {
            return Err(format!(
                "rate_limit.{name}: per_minute must be 1 to {MAX_PER_MINUTE} and burst 1 to {MAX_BURST}"
            ));
        }
        let interval = Duration::from_secs(60) / limit.per_minute;
        Ok(Self {
            interval,
            tolerance: interval * (limit.burst - 1),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Rates {
    value_write: Rate,
    quote: Rate,
    recovery: Rate,
    read: Rate,
    engine: Rate,
}

impl Rates {
    fn of(&self, class: RequestClass) -> Rate {
        match class {
            RequestClass::ValueWrite => self.value_write,
            RequestClass::Quote => self.quote,
            RequestClass::Recovery => self.recovery,
            RequestClass::Read => self.read,
            RequestClass::Engine => self.engine,
        }
    }
}

#[derive(Debug)]
struct Buckets {
    /// The theoretical arrival time of each bucket. A time not after now is a full bucket.
    arrival: HashMap<(RequestClass, IpAddr), Instant>,
    next_prune: Option<Instant>,
}

/// Shared rate limiter state for the mint router.
#[derive(Debug)]
pub struct RateLimiter {
    max_body_bytes: usize,
    trusted_proxies: HashSet<IpAddr>,
    engine_addresses: HashSet<IpAddr>,
    rates: Rates,
    capacity: usize,
    buckets: Mutex<Buckets>,
}

impl RateLimiter {
    /// Validate the configuration and build the limiter.
    pub fn new(config: &Config) -> Result<Self, String> {
        Self::with_capacity(config, MAX_TRACKED_BUCKETS)
    }

    fn with_capacity(config: &Config, capacity: usize) -> Result<Self, String> {
        if config.max_body_bytes == 0 {
            return Err("rate_limit.max_body_bytes must be positive".to_string());
        }
        let trusted_proxies: HashSet<IpAddr> = config
            .trusted_proxies
            .iter()
            .map(IpAddr::to_canonical)
            .collect();
        let engine_addresses: HashSet<IpAddr> = config
            .engine_addresses
            .iter()
            .map(IpAddr::to_canonical)
            .collect();
        if !trusted_proxies.is_disjoint(&engine_addresses) {
            return Err(
                "rate_limit: an address cannot be both a trusted proxy and an engine address"
                    .to_string(),
            );
        }
        let rates = Rates {
            value_write: Rate::new("value_write", config.value_write)?,
            quote: Rate::new("quote", config.quote)?,
            recovery: Rate::new("recovery", config.recovery)?,
            read: Rate::new("read", config.read)?,
            engine: Rate::new("engine", config.engine)?,
        };
        Ok(Self {
            max_body_bytes: config.max_body_bytes,
            trusted_proxies,
            engine_addresses,
            rates,
            capacity,
            buckets: Mutex::new(Buckets {
                arrival: HashMap::new(),
                next_prune: None,
            }),
        })
    }

    /// The client address under the trust rule.
    fn client(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.trusted_proxies.contains(&peer) {
            return peer;
        }
        // A trusted proxy appends the address that it sees as the last entry.
        // Earlier entries come from the client. Without a valid last entry the
        // proxy itself is the client, never the engine.
        headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit(',').next())
            .and_then(|entry| {
                let entry = entry.trim();
                let entry = entry
                    .strip_prefix('[')
                    .and_then(|inner| inner.strip_suffix(']'))
                    .unwrap_or(entry);
                entry.parse::<IpAddr>().ok()
            })
            .map(|address| address.to_canonical())
            .unwrap_or(peer)
    }

    /// Take one token. On refusal, return the wait until a token is free.
    fn check(&self, class: RequestClass, key: IpAddr, now: Instant) -> Result<(), Duration> {
        let rate = self.rates.of(class);
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let entry = (class, key);
        if !buckets.arrival.contains_key(&entry) && buckets.arrival.len() >= self.capacity {
            if buckets.next_prune.is_none_or(|next| now >= next) {
                // A full bucket holds no state, so removing it changes no decision.
                buckets.arrival.retain(|_, arrival| *arrival > now);
                buckets.next_prune = Some(now + PRUNE_INTERVAL);
            }
            if buckets.arrival.len() >= self.capacity {
                // Fail closed: a new client waits while every tracked bucket is in use.
                return Err(PRUNE_INTERVAL);
            }
        }
        let arrival = buckets.arrival.get(&entry).copied().unwrap_or(now).max(now);
        let ahead = arrival - now;
        if ahead > rate.tolerance {
            return Err(ahead - rate.tolerance);
        }
        buckets.arrival.insert(entry, arrival + rate.interval);
        Ok(())
    }
}

/// One bucket key for each IPv4 address and for each IPv6 /64 prefix, because
/// one host can use every address of its /64.
fn bucket_key(client: IpAddr) -> IpAddr {
    match client {
        IpAddr::V4(_) => client,
        IpAddr::V6(address) => {
            let prefix = u128::from(address) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(prefix))
        }
    }
}

fn classify(method: &Method, matched_path: Option<&str>) -> RequestClass {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return RequestClass::Read;
    }
    match matched_path {
        Some("/v1/mint/quote/{method}" | "/v1/melt/quote/{method}") => RequestClass::Quote,
        Some("/v1/restore" | "/v1/checkstate" | "/v1/mint/quote/{method}/check") => {
            RequestClass::Recovery
        }
        // Every other write, also an unknown route, gets the strictest class.
        _ => RequestClass::ValueWrite,
    }
}

fn too_many_requests(retry_after: Duration) -> Response {
    let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({ "code": 0, "detail": "Too many requests" })),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
    // Browsers expose Retry-After to a cross-origin page only with this header.
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("retry-after"),
    );
    response
}

fn payload_too_large() -> Response {
    (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response()
}

/// Read the body up to the cap, so that a body without a length is also bounded.
async fn capped(request: Request, max_body_bytes: usize) -> Result<Request, Response> {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > max_body_bytes as u64) {
        return Err(payload_too_large());
    }
    let (parts, body) = request.into_parts();
    // A read failure also refuses the request: its body is not usable.
    let bytes = axum::body::to_bytes(body, max_body_bytes)
        .await
        .map_err(|_| payload_too_large())?;
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

/// Axum middleware that applies the limiter. The server must provide
/// `ConnectInfo<SocketAddr>`; without it every request is refused.
pub async fn middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(ConnectInfo(peer)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    else {
        tracing::error!("Rate limiter has no peer address; serve with connect info");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let client = limiter.client(peer.ip(), request.headers());
    let engine = limiter.engine_addresses.contains(&client);
    let class = if engine {
        RequestClass::Engine
    } else {
        classify(
            request.method(),
            request
                .extensions()
                .get::<MatchedPath>()
                .map(MatchedPath::as_str),
        )
    };
    let key = if engine { client } else { bucket_key(client) };
    if let Err(retry_after) = limiter.check(class, key, Instant::now()) {
        return too_many_requests(retry_after);
    }
    let request = if engine || matches!(*request.method(), Method::GET | Method::HEAD) {
        request
    } else {
        match capped(request, limiter.max_body_bytes).await {
            Ok(request) => request,
            Err(response) => return response,
        }
    };
    next.run(request).await
}

#[cfg(test)]
mod tests;
