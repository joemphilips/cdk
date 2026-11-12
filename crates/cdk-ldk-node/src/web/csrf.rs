use axum::body::to_bytes;
use axum::extract::{FromRequest, Request};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use maud::{html, Markup};
use rand::Rng;
use serde::de::DeserializeOwned;

use crate::web::access::{constant_time_eq, CsrfKey};

const CSRF_COOKIE_NAME: &str = "ldk_node_dashboard_csrf";
const CSRF_TOKEN_BYTES: usize = 32;
const CSRF_TOKEN_HEX_LEN: usize = CSRF_TOKEN_BYTES * 2;
const FORM_BODY_LIMIT: usize = 1024 * 1024;

/// Active CSRF token for the dashboard request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfToken(String);

impl CsrfToken {
    /// Return the token value.
    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Form extractor that validates the dashboard double-submit CSRF token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfForm<T>(pub T);

impl<S, T> FromRequest<S> for CsrfForm<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = StatusCode;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let key = request
            .extensions()
            .get::<CsrfKey>()
            .cloned()
            .ok_or(StatusCode::FORBIDDEN)?;
        let session = csrf_cookie_value(request.headers()).ok_or(StatusCode::FORBIDDEN)?;
        // The form token is bound to the cookie by the process key. A cookie
        // that another local origin set has no matching form token.
        let expected = key.form_token(session);

        let body = to_bytes(request.into_body(), FORM_BODY_LIMIT)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        let fields: Vec<(String, String)> =
            serde_urlencoded::from_bytes(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        let form_token = fields
            .iter()
            .find_map(|(name, value)| (name == "_csrf").then_some(value.as_str()))
            .ok_or(StatusCode::FORBIDDEN)?;

        if !constant_time_eq(form_token.as_bytes(), expected.as_bytes()) {
            return Err(StatusCode::FORBIDDEN);
        }

        let form = serde_urlencoded::from_bytes(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        Ok(Self(form))
    }
}

/// Ensure each dashboard request has an active CSRF token available to render.
pub async fn ensure_csrf_token(mut request: Request, next: Next) -> Response {
    let Some(key) = request.extensions().get::<CsrfKey>().cloned() else {
        // The access layer sets the key. Without it, serve nothing.
        return StatusCode::FORBIDDEN.into_response();
    };
    let existing_session = csrf_cookie_value(request.headers());
    let (session, should_set_cookie) = match existing_session {
        Some(session) => (session.to_owned(), false),
        None => (generate_token(), true),
    };

    request
        .extensions_mut()
        .insert(CsrfToken(key.form_token(&session)));

    let mut response = next.run(request).await;

    if should_set_cookie {
        if let Ok(header_value) = HeaderValue::from_str(&csrf_cookie_header_value(&session)) {
            response.headers_mut().append(SET_COOKIE, header_value);
        }
    }

    response
}

/// Render a hidden CSRF form field.
pub fn csrf_input(token: &CsrfToken) -> Markup {
    html! {
        input type="hidden" name="_csrf" value=(token.value()) {}
    }
}

fn generate_token() -> String {
    let bytes = rand::rng().random::<[u8; CSRF_TOKEN_BYTES]>();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn csrf_cookie_value(headers: &HeaderMap) -> Option<&str> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;

    cookie_header
        .split(';')
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(name, value)| {
            (name == CSRF_COOKIE_NAME && is_valid_token(value)).then_some(value)
        })
}

fn csrf_cookie_header_value(token: &str) -> String {
    format!("{CSRF_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/")
}

fn is_valid_token(token: &str) -> bool {
    token.len() == CSRF_TOKEN_HEX_LEN && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::extract::Request as AxumRequest;
    use axum::http::{Request, StatusCode};
    use axum::middleware::Next;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Extension, Router};
    use serde::Deserialize;
    use tower::ServiceExt;

    use super::{ensure_csrf_token, CsrfForm, CsrfToken, CSRF_COOKIE_NAME};
    use crate::web::access::{CsrfKey, WebAccess};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestForm {
        value: String,
    }

    async fn submit(CsrfForm(form): CsrfForm<TestForm>) -> String {
        form.value
    }

    fn test_key() -> CsrfKey {
        CsrfKey::new(Arc::new(
            WebAccess::new("0123456789abcdef0123456789abcdef".to_owned(), 8091).unwrap(),
        ))
    }

    /// The access layer of the server sets the CSRF key in each admitted request.
    fn with_key(router: Router, key: CsrfKey) -> Router {
        router.layer(axum::middleware::from_fn(
            move |mut request: AxumRequest, next: Next| {
                let key = key.clone();
                async move {
                    request.extensions_mut().insert(key);
                    next.run(request).await
                }
            },
        ))
    }

    fn test_app(key: CsrfKey) -> Router {
        with_key(Router::new().route("/submit", post(submit)), key)
    }

    async fn post_form(key: CsrfKey, cookie: Option<&str>, body: String) -> Response {
        let mut request =
            Request::post("/submit").header("content-type", "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header("cookie", format!("{CSRF_COOKIE_NAME}={cookie}"));
        }
        test_app(key)
            .oneshot(
                request
                    .body(Body::from(body))
                    .expect("test request should build"),
            )
            .await
            .expect("test service should respond")
    }

    const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn missing_csrf_cookie_rejects_post() {
        let response = post_form(test_key(), None, "_csrf=abc&value=test".to_owned()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn missing_csrf_field_rejects_post() {
        let response = post_form(test_key(), Some(SESSION), "value=test".to_owned()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_tossed_cookie_with_an_equal_form_token_is_refused() {
        // Another local origin can set the cookie and submit the same value.
        let response = post_form(
            test_key(),
            Some(SESSION),
            format!("_csrf={SESSION}&value=test"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_form_token_of_another_process_key_is_refused() {
        let token = test_key().form_token(SESSION);
        let response = post_form(
            test_key(),
            Some(SESSION),
            format!("_csrf={token}&value=test"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_post_without_the_access_layer_is_refused() {
        let key = test_key();
        let token = key.form_token(SESSION);
        let response = Router::new()
            .route("/submit", post(submit))
            .oneshot(
                Request::post("/submit")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("{CSRF_COOKIE_NAME}={SESSION}"))
                    .body(Body::from(format!("_csrf={token}&value=test")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_bound_form_token_allows_form_deserialization() {
        let key = test_key();
        let token = key.form_token(SESSION);
        let response = post_form(key, Some(SESSION), format!("_csrf={token}&value=test")).await;

        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test response body should read");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"test");
    }

    #[tokio::test]
    async fn middleware_sets_cookie_and_exposes_the_bound_token_for_rendering() {
        async fn render(Extension(token): Extension<CsrfToken>) -> impl IntoResponse {
            token.value().to_owned()
        }

        let key = test_key();
        let router = Router::new()
            .route("/", get(render))
            .layer(axum::middleware::from_fn(ensure_csrf_token));
        let response = with_key(router, key.clone())
            .oneshot(
                Request::get("/")
                    .body(Body::empty())
                    .expect("test request should build"),
            )
            .await
            .expect("test service should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let cookie = response
            .headers()
            .get("set-cookie")
            .expect("csrf cookie should be set")
            .to_str()
            .expect("csrf cookie should be valid ASCII")
            .to_owned();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test response body should read");
        let rendered_token =
            String::from_utf8(body.to_vec()).expect("rendered token should be valid UTF-8");
        let session = cookie
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, value)| value.to_owned())
            .expect("cookie value");

        assert_eq!(rendered_token, key.form_token(&session));
        assert_ne!(rendered_token, session);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
    }

    #[tokio::test]
    async fn middleware_without_the_access_layer_serves_nothing() {
        let response = Router::new()
            .route("/", get(|| async { "page" }))
            .layer(axum::middleware::from_fn(ensure_csrf_token))
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
