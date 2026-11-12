//! Access control of the node web UI (MS2).
//!
//! The UI can spend the node funds. Every request must:
//! - name the loopback host and the configured port in `Host`, so that a
//!   DNS-rebinding page cannot reach the UI;
//! - carry the per-start access token as the HTTP Basic password, so that a
//!   local process without the token cannot use the UI;
//! - for a state change, come from the UI origin (`Origin`, or
//!   `Sec-Fetch-Site: same-origin` when the browser sends no `Origin`).
//!
//! The CSRF token of each form is an HMAC of the session cookie under a
//! process key, so a cookie that another local origin sets cannot pass.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cdk_common::bitcoin::base64::engine::general_purpose::STANDARD;
use cdk_common::bitcoin::base64::Engine;
use cdk_common::bitcoin::hashes::hmac::{Hmac, HmacEngine};
use cdk_common::bitcoin::hashes::{sha256, Hash, HashEngine};
use rand::Rng;

const SEC_FETCH_SITE: &str = "sec-fetch-site";
const LOOPBACK_HOSTS: [&str; 2] = ["127.0.0.1", "localhost"];
/// The shortest access token. A per-start token has 32 random bytes.
pub const MIN_TOKEN_LEN: usize = 32;

/// The access token, the UI port and the CSRF key of one process.
pub struct WebAccess {
    token: String,
    port: u16,
    csrf_key: [u8; 32],
}

impl std::fmt::Debug for WebAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAccess")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// The CSRF key of the request, set by [`require_access`].
#[derive(Clone)]
pub struct CsrfKey(Arc<WebAccess>);

impl CsrfKey {
    /// The key of `access`.
    #[cfg(test)]
    pub(crate) fn new(access: Arc<WebAccess>) -> Self {
        Self(access)
    }

    /// The form token that belongs to a session cookie value.
    pub fn form_token(&self, session: &str) -> String {
        let mut engine = HmacEngine::<sha256::Hash>::new(&self.0.csrf_key);
        engine.input(b"ldk-node-dashboard-csrf\0");
        engine.input(session.as_bytes());
        Hmac::<sha256::Hash>::from_engine(engine).to_string()
    }
}

impl WebAccess {
    /// Accept requests that present `token` on loopback `port`.
    ///
    /// # Errors
    /// Returns an error when the token is shorter than [`MIN_TOKEN_LEN`] or
    /// is not printable ASCII.
    pub fn new(token: String, port: u16) -> Result<Self, &'static str> {
        if token.len() < MIN_TOKEN_LEN || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err("web UI access token must be at least 32 printable ASCII characters");
        }
        Ok(Self {
            token,
            port,
            csrf_key: rand::rng().random::<[u8; 32]>(),
        })
    }

    fn host_allowed(&self, headers: &HeaderMap) -> bool {
        let Some(host) = headers.get(HOST).and_then(|value| value.to_str().ok()) else {
            return false;
        };
        let port = self.port.to_string();
        LOOPBACK_HOSTS.iter().any(|name| {
            host.split_once(':')
                .is_some_and(|(h, p)| h.eq_ignore_ascii_case(name) && p == port)
        })
    }

    fn origin_allowed(&self, headers: &HeaderMap) -> bool {
        match headers.get(ORIGIN) {
            Some(origin) => {
                let port = self.port.to_string();
                origin.to_str().is_ok_and(|origin| {
                    LOOPBACK_HOSTS.iter().any(|name| {
                        origin
                            .strip_prefix("http://")
                            .and_then(|rest| rest.split_once(':'))
                            .is_some_and(|(h, p)| h.eq_ignore_ascii_case(name) && p == port)
                    })
                })
            }
            None => headers
                .get(SEC_FETCH_SITE)
                .is_some_and(|site| site.as_bytes() == b"same-origin"),
        }
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let Some(encoded) = value.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
            return false;
        };
        // Any user name. The password is the token.
        let Some(position) = decoded.iter().position(|byte| *byte == b':') else {
            return false;
        };
        constant_time_eq(&decoded[position + 1..], self.token.as_bytes())
    }
}

/// Compare two byte strings without an early exit on the first difference.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

/// Refuse a request with a wrong host, without the token, or, for a state
/// change, from another origin. Admit the rest with the CSRF key.
pub async fn require_access(
    State(access): State<Arc<WebAccess>>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    if !access.host_allowed(headers) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    if !access.authorized(headers) {
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"ldk-node\", charset=\"UTF-8\""),
        );
        return response;
    }
    let safe = matches!(*request.method(), Method::GET | Method::HEAD);
    if !safe && !access.origin_allowed(headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    request.extensions_mut().insert(CsrfKey(access));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app() -> Router {
        let access = Arc::new(WebAccess::new(TOKEN.to_owned(), 8091).unwrap());
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/pay", post(|| async { "paid" }))
            .layer(axum::middleware::from_fn_with_state(access, require_access))
    }

    fn basic(password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("operator:{password}")))
    }

    async fn status(request: Request<Body>) -> StatusCode {
        app().oneshot(request).await.unwrap().status()
    }

    #[test]
    fn a_short_token_is_refused() {
        assert!(WebAccess::new("short".to_owned(), 8091).is_err());
        assert!(WebAccess::new(format!("{TOKEN} space"), 8091).is_err());
    }

    #[tokio::test]
    async fn a_request_without_the_token_is_refused() {
        let response = app()
            .oneshot(
                Request::get("/")
                    .header("host", "127.0.0.1:8091")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Basic "));
        let wrong = Request::get("/")
            .header("host", "127.0.0.1:8091")
            .header("authorization", basic(&TOKEN.replace('0', "1")))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(wrong).await, StatusCode::UNAUTHORIZED);
        let right = Request::get("/")
            .header("host", "localhost:8091")
            .header("authorization", basic(TOKEN))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(right).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_wrong_host_is_refused_before_the_token_check() {
        for host in [
            "attacker.example:8091",
            "127.0.0.1:8092",
            "127.0.0.1",
            "[::1]:8091",
            "127.0.0.1.attacker.example:8091",
        ] {
            let request = Request::get("/")
                .header("host", host)
                .header("authorization", basic(TOKEN))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status(request).await,
                StatusCode::MISDIRECTED_REQUEST,
                "{host}"
            );
        }
        let missing = Request::get("/")
            .header("authorization", basic(TOKEN))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(missing).await, StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn a_cross_site_post_is_refused() {
        let post = |origin: Option<&str>, site: Option<&str>| {
            let mut builder = Request::post("/pay")
                .header("host", "127.0.0.1:8091")
                .header("authorization", basic(TOKEN));
            if let Some(origin) = origin {
                builder = builder.header("origin", origin);
            }
            if let Some(site) = site {
                builder = builder.header("sec-fetch-site", site);
            }
            builder.body(Body::empty()).unwrap()
        };
        for (origin, site) in [
            (Some("http://127.0.0.1:3000"), None),
            (Some("http://attacker.example:8091"), Some("same-origin")),
            (Some("null"), None),
            (Some("https://127.0.0.1:8091"), None),
            (None, Some("same-site")),
            (None, Some("cross-site")),
            (None, None),
        ] {
            assert_eq!(
                status(post(origin, site)).await,
                StatusCode::FORBIDDEN,
                "{origin:?} {site:?}"
            );
        }
        assert_eq!(
            status(post(Some("http://127.0.0.1:8091"), None)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(post(Some("http://localhost:8091"), None)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(post(None, Some("same-origin"))).await,
            StatusCode::OK
        );
    }

    #[test]
    fn the_form_token_depends_on_the_process_key() {
        let one = CsrfKey(Arc::new(WebAccess::new(TOKEN.to_owned(), 8091).unwrap()));
        let two = CsrfKey(Arc::new(WebAccess::new(TOKEN.to_owned(), 8091).unwrap()));
        let session = "a".repeat(64);
        assert_eq!(one.form_token(&session), one.form_token(&session));
        assert_ne!(one.form_token(&session), two.form_token(&session));
        assert_ne!(one.form_token(&session), session);
        assert_ne!(one.form_token(&session), one.form_token(&"b".repeat(64)));
    }
}
