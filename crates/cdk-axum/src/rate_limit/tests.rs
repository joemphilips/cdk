use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use cdk::mint::MintBuilder;
use cdk::nuts::CurrencyUnit;
use futures::StreamExt;
use tower::ServiceExt;

use super::{ClassLimit, Config, RateLimiter, RequestClass};

const PROXY: &str = "172.18.0.1";
const ENGINE: &str = "203.0.113.10";
const CLIENT: &str = "198.51.100.7";
const OTHER_CLIENT: &str = "198.51.100.8";
const BODY_CAP: usize = 1024;

fn config(burst: u32) -> Config {
    let limit = ClassLimit {
        per_minute: 1,
        burst,
    };
    Config {
        max_body_bytes: BODY_CAP,
        trusted_proxies: vec![PROXY.parse().unwrap()],
        engine_addresses: vec![ENGINE.parse().unwrap()],
        value_write: limit,
        quote: limit,
        recovery: limit,
        read: limit,
        engine: ClassLimit {
            per_minute: 1,
            burst: 50,
        },
    }
}

async fn router(config: Config) -> Router {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await.unwrap());
    let mut builder = MintBuilder::new(db.clone());
    builder
        .configure_unit(
            CurrencyUnit::Sat,
            cdk::mint::UnitConfig {
                amounts: vec![1, 2, 4, 8],
                input_fee_ppk: 0,
            },
        )
        .unwrap();
    let mint = Arc::new(builder.build_with_seed(db, &[8; 64]).await.unwrap());
    crate::create_mint_router_with_custom_cache(
        mint,
        Default::default(),
        vec!["bolt11".to_string()],
        false,
        Some(Arc::new(RateLimiter::new(&config).unwrap())),
    )
    .await
    .unwrap()
}

struct Call<'a> {
    method: Method,
    path: &'a str,
    peer: &'a str,
    forwarded: &'a [&'a str],
    body: Body,
}

fn post<'a>(path: &'a str, peer: &'a str) -> Call<'a> {
    Call {
        method: Method::POST,
        path,
        peer,
        forwarded: &[],
        body: Body::from("{}"),
    }
}

fn get<'a>(path: &'a str, peer: &'a str) -> Call<'a> {
    Call {
        method: Method::GET,
        body: Body::empty(),
        ..post(path, peer)
    }
}

async fn send(router: &Router, call: Call<'_>) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(call.method)
        .uri(call.path)
        .header(header::CONTENT_TYPE, "application/json");
    for value in call.forwarded {
        builder = builder.header("x-forwarded-for", *value);
    }
    let mut request = builder.body(call.body).unwrap();
    let peer: IpAddr = call.peer.parse().unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer, 40_000)));
    router.clone().oneshot(request).await.unwrap()
}

async fn status(router: &Router, call: Call<'_>) -> StatusCode {
    send(router, call).await.status()
}

/// One route of each class. A route with burst 1 empties the bucket of its class only.
fn representatives() -> [(&'static str, Call<'static>); 4] {
    [
        ("value_write", post("/v1/swap", CLIENT)),
        ("quote", post("/v1/mint/quote/bolt11", CLIENT)),
        ("recovery", post("/v1/restore", CLIENT)),
        ("read", get("/v1/keysets", CLIENT)),
    ]
}

#[tokio::test]
async fn each_route_uses_its_class_bucket() {
    #[cfg_attr(not(feature = "conditional-tokens"), allow(unused_mut))]
    let mut routes = vec![
        ("value_write", post("/v1/swap", CLIENT)),
        ("value_write", post("/v1/mint/bolt11", CLIENT)),
        ("value_write", post("/v1/mint/bolt11/batch", CLIENT)),
        ("value_write", post("/v1/melt/bolt11", CLIENT)),
        ("quote", post("/v1/mint/quote/bolt11", CLIENT)),
        ("quote", post("/v1/melt/quote/bolt11", CLIENT)),
        ("recovery", post("/v1/restore", CLIENT)),
        ("recovery", post("/v1/checkstate", CLIENT)),
        ("recovery", post("/v1/mint/quote/bolt11/check", CLIENT)),
        ("read", get("/v1/info", CLIENT)),
        ("read", get("/v1/keys", CLIENT)),
        ("read", get("/v1/keysets", CLIENT)),
        ("read", get("/v1/mint/quote/bolt11/abc", CLIENT)),
    ];
    #[cfg(feature = "conditional-tokens")]
    routes.extend([
        ("value_write", post("/v1/ctf/convert", CLIENT)),
        ("value_write", post("/v1/redeem_outcome", CLIENT)),
        ("value_write", post("/v1/conditions", CLIENT)),
        ("read", get("/v1/conditions", CLIENT)),
        ("read", get("/v1/conditional_keysets", CLIENT)),
    ]);
    for (class, call) in routes {
        let path = call.path;
        let router = router(config(1)).await;
        assert_ne!(
            status(&router, call).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{path}"
        );
        for (other, representative) in representatives() {
            let expected_refusal = other == class;
            assert_eq!(
                status(&router, representative).await == StatusCode::TOO_MANY_REQUESTS,
                expected_refusal,
                "{path} is in {class}; checked {other}"
            );
        }
    }
}

#[tokio::test]
async fn refusal_has_retry_after_that_a_browser_can_read() {
    let router = router(config(1)).await;
    assert_ne!(
        status(&router, post("/v1/swap", CLIENT)).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    let response = send(&router, post("/v1/swap", CLIENT)).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // One token each 60 s. The first request took the only token less than 60 s ago.
    let retry_after: u64 = response.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry_after), "{retry_after}");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "retry-after"
    );
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn engine_address_gets_the_engine_class_only_from_a_trusted_peer() {
    let router = router(config(1)).await;
    // Direct from the engine address, and through the trusted proxy.
    for _ in 0..3 {
        assert_ne!(
            status(&router, post("/v1/swap", ENGINE)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        let mut call = post("/v1/swap", PROXY);
        call.forwarded = &[ENGINE];
        assert_ne!(status(&router, call).await, StatusCode::TOO_MANY_REQUESTS);
    }
    // A client that is not a trusted proxy cannot claim the engine address.
    for (attempt, expected) in [(0, false), (1, true)] {
        let mut call = post("/v1/swap", CLIENT);
        call.forwarded = &[ENGINE];
        assert_eq!(
            status(&router, call).await == StatusCode::TOO_MANY_REQUESTS,
            expected,
            "attempt {attempt}"
        );
    }
}

#[tokio::test]
async fn only_the_entry_that_the_trusted_proxy_appends_names_the_client() {
    let forged_cases: [&[&str]; 2] = [
        // The client sent the left entry; the proxy appended the right entry.
        &["203.0.113.10, 198.51.100.7"],
        // The proxy appended a second header line.
        &["203.0.113.10", "198.51.100.7"],
    ];
    for forwarded in forged_cases {
        let router = router(config(1)).await;
        for expected in [false, true] {
            let mut call = post("/v1/swap", PROXY);
            call.forwarded = forwarded;
            assert_eq!(
                status(&router, call).await == StatusCode::TOO_MANY_REQUESTS,
                expected,
                "{forwarded:?}"
            );
        }
        // The forwarded client has its own bucket, not the bucket of the proxy.
        let mut other = post("/v1/swap", PROXY);
        other.forwarded = &[OTHER_CLIENT];
        assert_ne!(status(&router, other).await, StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn trusted_proxy_without_a_valid_entry_is_its_own_client() {
    let invalid_cases: [&[&str]; 3] = [&[], &["unknown"], &["198.51.100.7, "]];
    for forwarded in invalid_cases {
        let router = router(config(1)).await;
        for expected in [false, true] {
            let mut call = post("/v1/swap", PROXY);
            call.forwarded = forwarded;
            assert_eq!(
                status(&router, call).await == StatusCode::TOO_MANY_REQUESTS,
                expected,
                "{forwarded:?}"
            );
        }
    }
}

#[tokio::test]
async fn ipv6_clients_share_one_bucket_per_64_prefix() {
    let router = router(config(1)).await;
    assert_ne!(
        status(&router, post("/v1/swap", "2001:db8:1:2::1")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        status(&router, post("/v1/swap", "2001:db8:1:2:ffff::2")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_ne!(
        status(&router, post("/v1/swap", "2001:db8:1:3::1")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // An IPv4-mapped peer is the IPv4 client.
    for _ in 0..3 {
        assert_ne!(
            status(&router, post("/v1/swap", "::ffff:203.0.113.10")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}

fn padded(length: usize) -> Bytes {
    Bytes::from(vec![b' '; length])
}

#[tokio::test]
async fn client_body_is_capped_and_engine_body_is_not() {
    let router = router(config(10)).await;
    let mut declared = post("/v1/swap", CLIENT);
    declared.body = Body::from(padded(BODY_CAP + 1));
    assert_eq!(
        status(&router, declared).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let mut streamed = post("/v1/swap", CLIENT);
    streamed.body = Body::from_stream(futures::stream::iter([
        Ok::<_, std::io::Error>(padded(BODY_CAP)),
        Ok(padded(1)),
    ]));
    assert_eq!(
        status(&router, streamed).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let mut at_cap = post("/v1/swap", CLIENT);
    at_cap.body = Body::from_stream(futures::stream::iter([Ok::<_, std::io::Error>(padded(
        BODY_CAP,
    ))]));
    assert_ne!(status(&router, at_cap).await, StatusCode::PAYLOAD_TOO_LARGE);

    let mut engine = post("/v1/swap", ENGINE);
    engine.body = Body::from(padded(BODY_CAP * 4));
    let engine_status = status(&router, engine).await;
    assert_ne!(engine_status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_ne!(engine_status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn request_without_peer_address_is_refused() {
    let router = router(config(10)).await;
    let request = Request::builder()
        .uri("/v1/info")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn bucket_refills_at_the_configured_rate() {
    let mut config = config(2);
    config.value_write = ClassLimit {
        per_minute: 60,
        burst: 2,
    };
    let limiter = RateLimiter::new(&config).unwrap();
    let client: IpAddr = CLIENT.parse().unwrap();
    let start = Instant::now();
    let at = |seconds: u64, millis: u64| {
        start + Duration::from_secs(seconds) + Duration::from_millis(millis)
    };
    let check = |now| limiter.check(RequestClass::ValueWrite, client, now);
    assert_eq!(check(at(0, 0)), Ok(()));
    assert_eq!(check(at(0, 0)), Ok(()));
    assert_eq!(check(at(0, 0)), Err(Duration::from_secs(1)));
    assert_eq!(check(at(0, 400)), Err(Duration::from_millis(600)));
    assert_eq!(check(at(1, 0)), Ok(()));
    assert_eq!(check(at(1, 0)), Err(Duration::from_secs(1)));
    // After two idle intervals the bucket holds its full burst again, and no more.
    assert_eq!(check(at(4, 0)), Ok(()));
    assert_eq!(check(at(4, 0)), Ok(()));
    assert_eq!(check(at(4, 0)), Err(Duration::from_secs(1)));
}

#[test]
fn full_table_refuses_a_new_client_until_a_bucket_is_full_again() {
    let limiter = RateLimiter::with_capacity(&config(1), 2).unwrap();
    let start = Instant::now();
    let address = |text: &str| text.parse::<IpAddr>().unwrap();
    let check = |text: &str, now| limiter.check(RequestClass::Read, address(text), now);
    assert_eq!(check("198.51.100.1", start), Ok(()));
    assert_eq!(check("198.51.100.2", start), Ok(()));
    assert_eq!(check("198.51.100.3", start), Err(Duration::from_secs(1)));
    // A known client still uses its own bucket.
    assert_eq!(check("198.51.100.1", start), Err(Duration::from_secs(60)));
    // One token each 60 s: after that both buckets are full and hold no state.
    let later = start + Duration::from_secs(60);
    assert_eq!(check("198.51.100.3", later), Ok(()));
}

#[test]
fn full_table_still_admits_the_engine() {
    let limiter = RateLimiter::with_capacity(&config(1), 1).unwrap();
    let start = Instant::now();
    let client: IpAddr = CLIENT.parse().unwrap();
    let engine: IpAddr = ENGINE.parse().unwrap();
    assert_eq!(limiter.check(RequestClass::Read, client, start), Ok(()));
    assert_eq!(
        limiter.check(RequestClass::Read, OTHER_CLIENT.parse().unwrap(), start),
        Err(Duration::from_secs(1))
    );
    // The engine bucket is not counted, so the table stays full for other clients.
    for _ in 0..3 {
        assert_eq!(limiter.check(RequestClass::Engine, engine, start), Ok(()));
    }
    assert_eq!(
        limiter.check(RequestClass::Read, OTHER_CLIENT.parse().unwrap(), start),
        Err(Duration::from_secs(1))
    );
}

#[tokio::test]
async fn stalled_client_body_is_refused_within_the_read_timeout() {
    let router = router(config(10)).await;
    // The paused clock advances only when every task waits, so the timeout
    // fires at once in virtual time, with no real-time wait.
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let mut stalled = post("/v1/swap", CLIENT);
    stalled.body = Body::from_stream(
        futures::stream::iter([Ok::<_, std::io::Error>(padded(10))])
            .chain(futures::stream::pending()),
    );
    // A bounded wait: without the read timeout the request never ends.
    let answered = tokio::time::timeout(super::BODY_READ_TIMEOUT * 2, status(&router, stalled))
        .await
        .expect("the limiter must answer a stalled body");
    assert_eq!(answered, StatusCode::REQUEST_TIMEOUT);
    // The timer wheel rounds a deadline up to the next millisecond.
    let elapsed = start.elapsed();
    assert!(
        elapsed >= super::BODY_READ_TIMEOUT
            && elapsed < super::BODY_READ_TIMEOUT + Duration::from_secs(1),
        "{elapsed:?}"
    );
}

#[test]
fn invalid_configuration_is_refused() {
    let zero = ClassLimit {
        per_minute: 0,
        burst: 1,
    };
    let mut cases = Vec::new();
    let mut value = config(1);
    value.max_body_bytes = 0;
    cases.push(value);
    let mut value = config(1);
    value.read = zero;
    cases.push(value);
    let mut value = config(1);
    value.engine = ClassLimit {
        per_minute: 1,
        burst: 0,
    };
    cases.push(value);
    let mut value = config(1);
    value.quote = ClassLimit {
        per_minute: 1_000_001,
        burst: 1,
    };
    cases.push(value);
    let mut value = config(1);
    value.engine_addresses.push(PROXY.parse().unwrap());
    cases.push(value);
    let mut value = config(1);
    // The IPv4-mapped form of the proxy is the same address.
    value.engine_addresses = vec!["::ffff:172.18.0.1".parse().unwrap()];
    cases.push(value);
    for case in cases {
        assert!(RateLimiter::new(&case).is_err(), "{case:?}");
    }
    assert!(RateLimiter::new(&config(1)).is_ok());
}
