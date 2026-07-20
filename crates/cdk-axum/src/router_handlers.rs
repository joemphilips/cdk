use anyhow::Result;
#[cfg(feature = "conditional-tokens")]
use std::convert::Infallible;
#[cfg(feature = "conditional-tokens")]
use std::io::Write;
#[cfg(feature = "conditional-tokens")]
use std::pin::Pin;
#[cfg(feature = "conditional-tokens")]
use std::task::{Context, Poll};

#[cfg(feature = "conditional-tokens")]
use axum::body::{Body, Bytes};
use axum::extract::ws::WebSocketUpgrade;
#[cfg(feature = "conditional-tokens")]
use axum::extract::Query;
use axum::extract::{Json, Path, State};
#[cfg(feature = "conditional-tokens")]
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cdk::error::ErrorResponse;
use cdk::nuts::nut21::{Method, ProtectedEndpoint, RoutePath};
use cdk::nuts::{
    CheckStateRequest, CheckStateResponse, Id, KeysResponse, KeysetResponse, MintInfo,
    RestoreRequest, RestoreResponse, SwapRequest, SwapResponse,
};
use cdk::util::unix_time;
#[cfg(feature = "conditional-tokens")]
use futures::Stream;
use paste::paste;
#[cfg(feature = "conditional-tokens")]
use tokio::sync::OwnedSemaphorePermit;
use tracing::instrument;

use crate::auth::AuthHeader;
use crate::ws::main_websocket;
use crate::MintState;

#[cfg(feature = "conditional-tokens")]
struct BoundedCatalogueWriter {
    bytes: Vec<u8>,
    limit: usize,
}

#[cfg(feature = "conditional-tokens")]
impl Write for BoundedCatalogueWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or_else(|| std::io::Error::other("catalogue response length overflowed"))?;
        if next_len > self.limit {
            return Err(std::io::Error::other(
                "catalogue response exceeded its hard byte cap",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "conditional-tokens")]
struct ConditionalKeysetCatalogueBody {
    bytes: Option<Bytes>,
    _count_permit: OwnedSemaphorePermit,
    _byte_permit: OwnedSemaphorePermit,
}

#[cfg(feature = "conditional-tokens")]
impl Stream for ConditionalKeysetCatalogueBody {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.bytes.take().map(Ok))
    }
}

#[cfg(feature = "conditional-tokens")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionalKeysetCatalogueResponseError {
    Internal,
    Saturated,
}

#[cfg(feature = "conditional-tokens")]
impl ConditionalKeysetCatalogueResponseError {
    fn status(self) -> StatusCode {
        match self {
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Saturated => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[cfg(feature = "conditional-tokens")]
impl IntoResponse for ConditionalKeysetCatalogueResponseError {
    fn into_response(self) -> Response {
        self.status().into_response()
    }
}

#[cfg(feature = "conditional-tokens")]
fn serialize_conditional_keyset_catalogue_response(
    response: &cdk::nuts::nut_ctf::ConditionalKeysetsResponse,
    limit: usize,
) -> Result<Vec<u8>, ConditionalKeysetCatalogueResponseError> {
    let mut writer = BoundedCatalogueWriter {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, response).map_err(|error| {
        tracing::error!("Could not serialize bounded conditional-keyset catalogue: {error}");
        ConditionalKeysetCatalogueResponseError::Internal
    })?;
    Ok(writer.bytes)
}

#[cfg(feature = "conditional-tokens")]
fn conditional_keyset_catalogue_response(
    response: &cdk::nuts::nut_ctf::ConditionalKeysetsResponse,
    count_permit: OwnedSemaphorePermit,
    byte_slots: std::sync::Arc<tokio::sync::Semaphore>,
    response_limit: usize,
) -> Result<Response, ConditionalKeysetCatalogueResponseError> {
    conditional_keyset_catalogue_response_with_serializer(
        response,
        count_permit,
        byte_slots,
        response_limit,
        serialize_conditional_keyset_catalogue_response,
    )
}

#[cfg(feature = "conditional-tokens")]
fn conditional_keyset_catalogue_response_with_serializer<F>(
    response: &cdk::nuts::nut_ctf::ConditionalKeysetsResponse,
    count_permit: OwnedSemaphorePermit,
    byte_slots: std::sync::Arc<tokio::sync::Semaphore>,
    response_limit: usize,
    serializer: F,
) -> Result<Response, ConditionalKeysetCatalogueResponseError>
where
    F: FnOnce(
        &cdk::nuts::nut_ctf::ConditionalKeysetsResponse,
        usize,
    ) -> Result<Vec<u8>, ConditionalKeysetCatalogueResponseError>,
{
    // Reserve the entire per-response budget before allocating a serialized
    // body. The global semaphore is sized for exactly two maximum responses,
    // so a third request fails before entering serialization. Retaining the
    // fixed reservation avoids unsafe permit splitting and still bounds both
    // allocation and response-body lifetime.
    let byte_count = u32::try_from(response_limit)
        .map_err(|_| ConditionalKeysetCatalogueResponseError::Internal)?;
    let byte_permit = byte_slots
        .try_acquire_many_owned(byte_count)
        .map_err(|_| ConditionalKeysetCatalogueResponseError::Saturated)?;
    let bytes = serializer(response, response_limit)?;
    let content_length = bytes.len();
    let body = Body::from_stream(ConditionalKeysetCatalogueBody {
        bytes: Some(Bytes::from(bytes)),
        _count_permit: count_permit,
        _byte_permit: byte_permit,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, content_length)
        .body(body)
        .map_err(|_| ConditionalKeysetCatalogueResponseError::Internal)
}

/// Macro to add cache to endpoint
#[macro_export]
macro_rules! post_cache_wrapper {
    ($handler:ident, $request_type:ty, $response_type:ty) => {
        paste! {
            /// Cache wrapper function for $handler:
            /// Wrap $handler into a function that caches responses using the request as key
            pub async fn [<cache_ $handler>](
                auth: AuthHeader,
                state: State<MintState>,
                payload: Json<$request_type>
            ) -> Result<Json<$response_type>, Response> {
                use std::ops::Deref;
                let json_extracted_payload = payload.deref();
                let State(mint_state) = state.clone();
                let cache_key = match mint_state.cache.calculate_key(&json_extracted_payload) {
                    Some(key) => key,
                    None => {
                        // Could not calculate key, just return the handler result
                        return $handler(auth, state, payload).await;
                    }
                };
                if let Some(cached_response) = mint_state.cache.get::<$response_type>(&cache_key).await {
                    return Ok(Json(cached_response));
                }
                let response = $handler(auth, state, payload).await?;
                mint_state.cache.set(cache_key, &response.deref()).await;
                Ok(response)
            }
        }
    };
}

/// Macro to add cache to endpoint with prefer header support (for async operations)
#[macro_export]
macro_rules! post_cache_wrapper_with_prefer {
    ($handler:ident, $request_type:ty, $response_type:ty) => {
        paste! {
            /// Cache wrapper function for $handler with PreferHeader support:
            /// Wrap $handler into a function that caches responses using the request as key
            pub async fn [<cache_ $handler>](
                auth: AuthHeader,
                prefer: PreferHeader,
                state: State<MintState>,
                payload: Json<$request_type>
            ) -> Result<Json<$response_type>, Response> {
                use std::ops::Deref;

                let json_extracted_payload = payload.deref();
                let State(mint_state) = state.clone();
                let cache_key = match mint_state.cache.calculate_key(&json_extracted_payload) {
                    Some(key) => key,
                    None => {
                        // Could not calculate key, just return the handler result
                        return $handler(auth, prefer, state, payload).await;
                    }
                };
                if let Some(cached_response) = mint_state.cache.get::<$response_type>(&cache_key).await {
                    return Ok(Json(cached_response));
                }
                let response = $handler(auth, prefer, state, payload).await?;
                mint_state.cache.set(cache_key, &response.deref()).await;
                Ok(response)
            }
        }
    };
}

post_cache_wrapper!(post_swap, SwapRequest, SwapResponse);

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    context_path = "/v1",
    path = "/keys",
    responses(
        (status = 200, description = "Successful response", body = KeysResponse, content_type = "application/json")
    )
))]
/// Get the public keys of the newest mint keyset
///
/// This endpoint returns a dictionary of all supported token values of the mint and their associated public key.
#[instrument(skip_all)]
pub(crate) async fn get_keys(
    State(state): State<MintState>,
) -> Result<Json<KeysResponse>, Response> {
    Ok(Json(state.mint.pubkeys()))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    context_path = "/v1",
    path = "/keys/{keyset_id}",
    params(
        ("keyset_id" = String, description = "The keyset ID"),
    ),
    responses(
        (status = 200, description = "Successful response", body = KeysResponse, content_type = "application/json"),
        (status = 500, description = "Server error", body = ErrorResponse, content_type = "application/json")
    )
))]
/// Get the public keys of a specific keyset
///
/// Get the public keys of the mint from a specific keyset ID.
#[instrument(skip_all, fields(keyset_id = ?keyset_id))]
pub(crate) async fn get_keyset_pubkeys(
    State(state): State<MintState>,
    Path(keyset_id): Path<Id>,
) -> Result<Json<KeysResponse>, Response> {
    let pubkeys = state.mint.keyset_pubkeys(&keyset_id).map_err(|err| {
        tracing::error!("Could not get keyset pubkeys: {}", err);
        into_response(err)
    })?;

    Ok(Json(pubkeys))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    context_path = "/v1",
    path = "/keysets",
    responses(
        (status = 200, description = "Successful response", body = KeysetResponse, content_type = "application/json"),
        (status = 500, description = "Server error", body = ErrorResponse, content_type = "application/json")
    )
))]
/// Get all active keyset IDs of the mint
///
/// This endpoint returns a list of keysets that the mint currently supports and will accept tokens from.
#[instrument(skip_all)]
pub(crate) async fn get_keysets(
    State(state): State<MintState>,
) -> Result<Json<KeysetResponse>, Response> {
    Ok(Json(state.mint.keysets()))
}

#[instrument(skip_all)]
pub(crate) async fn ws_handler(
    auth: AuthHeader,
    State(state): State<MintState>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Get, RoutePath::Ws),
        )
        .await
        .map_err(into_response)?;

    Ok(ws.on_upgrade(|ws| main_websocket(ws, state)))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    context_path = "/v1",
    path = "/checkstate",
    request_body(content = CheckStateRequest, description = "State params", content_type = "application/json"),
    responses(
        (status = 200, description = "Successful response", body = CheckStateResponse, content_type = "application/json"),
        (status = 500, description = "Server error", body = ErrorResponse, content_type = "application/json")
    )
))]
/// Check whether a proof is spent already or is pending in a transaction
///
/// Check whether a secret has been spent already or not.
#[instrument(skip_all, fields(y_count = ?payload.ys.len()))]
pub(crate) async fn post_check(
    auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<CheckStateRequest>,
) -> Result<Json<CheckStateResponse>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Post, RoutePath::Checkstate),
        )
        .await
        .map_err(into_response)?;

    let state = state.mint.check_state(&payload).await.map_err(|err| {
        tracing::error!("Could not check state of proofs");
        into_response(err)
    })?;

    Ok(Json(state))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    context_path = "/v1",
    path = "/info",
    responses(
        (status = 200, description = "Successful response", body = MintInfo)
    )
))]
/// Mint information, operator contact information, and other info
#[instrument(skip_all)]
pub(crate) async fn get_mint_info(
    State(state): State<MintState>,
) -> Result<Json<MintInfo>, Response> {
    Ok(Json(
        state
            .mint
            .mint_info()
            .await
            .map_err(|err| {
                tracing::error!("Could not get mint info: {}", err);
                into_response(err)
            })?
            .clone()
            .time(unix_time()),
    ))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    context_path = "/v1",
    path = "/swap",
    request_body(content = SwapRequest, description = "Swap params", content_type = "application/json"),
    responses(
        (status = 200, description = "Successful response", body = SwapResponse, content_type = "application/json"),
        (status = 500, description = "Server error", body = ErrorResponse, content_type = "application/json")
    )
))]
/// Swap inputs for outputs of the same value
///
/// Requests a set of Proofs to be swapped for another set of BlindSignatures.
///
/// This endpoint can be used by Alice to swap a set of proofs before making a payment to Carol. It can then used by Carol to redeem the tokens for new proofs.
#[instrument(skip_all, fields(inputs_count = ?payload.inputs().len()))]
pub(crate) async fn post_swap(
    auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<SwapRequest>,
) -> Result<Json<SwapResponse>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Post, RoutePath::Swap),
        )
        .await
        .map_err(into_response)?;

    let swap_response = state
        .mint
        .process_swap_request(payload)
        .await
        .map_err(|err| {
            tracing::error!("Could not process swap request: {}", err);
            into_response(err)
        })?;

    Ok(Json(swap_response))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    context_path = "/v1",
    path = "/restore",
    request_body(content = RestoreRequest, description = "Restore params", content_type = "application/json"),
    responses(
        (status = 200, description = "Successful response", body = RestoreResponse, content_type = "application/json"),
        (status = 500, description = "Server error", body = ErrorResponse, content_type = "application/json")
    )
))]
/// Restores blind signature for a set of outputs.
#[instrument(skip_all, fields(outputs_count = ?payload.outputs.len()))]
pub(crate) async fn post_restore(
    auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<RestoreRequest>,
) -> Result<Json<RestoreResponse>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Post, RoutePath::Restore),
        )
        .await
        .map_err(into_response)?;

    let restore_response = state.mint.restore(payload).await.map_err(|err| {
        tracing::error!("Could not process restore: {}", err);
        into_response(err)
    })?;

    Ok(Json(restore_response))
}

#[cfg(feature = "info-page")]
const CSS: &str = r#"
:root {
  --bg: #000;
  --surface: #0e0e0e;
  --surface-2: #191919;
  --border: rgba(255,255,255,0.08);
  --border-section: rgba(255,255,255,0.06);
  --text-primary: #fff;
  --text-secondary: rgba(255,255,255,0.72);
  --text-muted: rgba(255,255,255,0.45);
  --text-faint: rgba(255,255,255,0.28);
  --green: #00d632;
  --green-soft: rgba(0, 214, 50, 0.1);
  --green-glow: rgba(0, 214, 50, 0.06);
  --red: #ff5555;
  --red-soft: rgba(255, 68, 68, 0.1);
  --yellow: #ffb800;
  --yellow-soft: rgba(255, 184, 0, 0.1);
  --radius: 16px;
  --radius-sm: 12px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background: var(--bg);
  color: var(--text-primary);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}

.page {
  max-width: 520px;
  margin: 0 auto;
  padding: 0 20px 100px;
}

/* ── Topbar ── */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  position: sticky;
  top: 0;
  background: rgba(0,0,0,0.88);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  z-index: 10;
}

.cashu-wordmark {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-muted);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--green);
  background: var(--green-soft);
  padding: 5px 11px;
  border-radius: 20px;
}

.status-dot {
  width: 6px;
  height: 6px;
  background: var(--green);
  border-radius: 50%;
  animation: pulse 2.4s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

/* ── Hero ── */
.hero {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 40px 0 16px;
  position: relative;
}

.hero::before {
  content: '';
  position: absolute;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
  width: 180px;
  height: 180px;
  background: radial-gradient(circle, var(--green-glow) 0%, transparent 70%);
  pointer-events: none;
}

.avatar-ring {
  width: 88px;
  height: 88px;
  border-radius: 50%;
  padding: 2.5px;
  background: linear-gradient(135deg, var(--green) 0%, rgba(0,214,50,0.15) 100%);
  margin-bottom: 20px;
  position: relative;
  z-index: 1;
}

.avatar {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background: var(--surface-2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 34px;
  font-weight: 700;
  color: var(--green);
  overflow: hidden;
}

.avatar img { width: 100%; height: 100%; object-fit: cover; }

.mint-name {
  font-size: 30px;
  font-weight: 800;
  letter-spacing: -0.03em;
  text-align: center;
  line-height: 1.15;
  margin-bottom: 8px;
}

.mint-desc {
  font-size: 15px;
  font-weight: 400;
  color: var(--text-secondary);
  text-align: center;
  line-height: 1.5;
  max-width: 380px;
}

.mint-desc-long {
  font-size: 14px;
  font-weight: 400;
  color: var(--text-muted);
  text-align: center;
  line-height: 1.5;
  max-width: 380px;
  margin-top: 4px;
  font-style: italic;
}

.version-chip {
  font-size: 11px;
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-weight: 500;
  color: var(--text-muted);
  background: var(--surface);
  padding: 5px 12px;
  border-radius: 20px;
  border: 1px solid var(--border);
  margin-top: 14px;
}

/* ── MOTD ── */
.motd {
  background: var(--yellow-soft);
  border: 1px solid rgba(255,184,0,0.12);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  margin: 24px 0 0;
}

.motd-label {
  font-size: 10px;
  font-weight: 700;
  color: var(--yellow);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 4px;
}

.motd-text {
  font-size: 14px;
  color: rgba(255,255,255,0.85);
  line-height: 1.5;
}

/* ── Disabled banners ── */
.disabled-banner {
  background: var(--red-soft);
  border: 1px solid rgba(255,68,68,0.12);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  margin-top: 16px;
  font-size: 14px;
  font-weight: 500;
  color: var(--red);
  text-align: center;
}

/* ── URL section ── */
.url-section { margin-top: 28px; }

.url-bar {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.url-text {
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-size: 13px;
  color: var(--text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}

.extra-urls { margin-top: 8px; display: flex; flex-direction: column; gap: 6px; }

.extra-url {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 14px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.extra-url .url-text { font-size: 11px; }

.url-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-faint);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  flex-shrink: 0;
}

/* ── Detail card ── */
.detail-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-top: 28px;
  overflow: hidden;
}

.card-section-header {
  padding: 18px 20px 0;
  font-size: 15px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.01em;
}

.card-section-header.has-rule {
  border-top: 1px solid var(--border-section);
  margin-top: 16px;
  padding-top: 18px;
}

.detail-row {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  padding: 7px 20px;
  gap: 16px;
}

.detail-row:first-child,
.card-section-header + .detail-row {
  padding-top: 12px;
}

.detail-row:last-child,
.detail-row + .card-divider {
  padding-bottom: 4px;
}

.detail-row.row-last {
  padding-bottom: 16px;
}

.detail-label {
  font-size: 14px;
  font-weight: 400;
  color: var(--text-secondary);
  flex-shrink: 0;
}

.detail-value {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  text-align: right;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.detail-value-mono {
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
}

/* Tags */
.tag {
  font-size: 12px;
  font-weight: 600;
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  padding: 4px 11px;
  border-radius: 20px;
  background: var(--surface-2);
  color: var(--text-primary);
  border: 1px solid var(--border);
  display: inline-block;
  text-transform: uppercase;
}

.tag-red {
  background: var(--red-soft);
  color: var(--red);
  border-color: rgba(255,68,68,0.12);
}

/* ── Features grid ── */
.features-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  margin: 0;
}

.feature {
  padding: 12px 20px;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  border-bottom: 1px solid var(--border-section);
  border-right: 1px solid var(--border-section);
}

.feature:nth-child(2n) { border-right: none; }
.feature:nth-last-child(-n+2) { border-bottom: none; }
.feature:last-child:nth-child(odd) { border-right: none; }

.feature-dot {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--green-soft);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-top: 2px;
}

.feature-dot svg { width: 10px; height: 10px; }

.feature-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
  line-height: 1.3;
}

/* ── Contact ── */
.contact-chips { display: flex; gap: 8px; flex-wrap: wrap; padding: 4px 20px 18px; }

.contact-chip {
  font-size: 12px;
  font-weight: 600;
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  color: var(--text-primary);
  background: var(--surface-2);
  border: 1px solid var(--border);
  padding: 4px 11px;
  border-radius: 20px;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.contact-chip svg { width: 12px; height: 12px; opacity: 0.5; }

/* ── Pubkey row ── */
.pubkey-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 20px 18px;
}

.pubkey-mono {
  font-family: ui-monospace, 'SFMono-Regular', 'SF Mono', 'Cascadia Code', 'Segoe UI Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}

/* ── Info tip ── */
.info-tip {
  margin-top: 28px;
  padding: 18px 20px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.info-tip-icon {
  width: 18px; height: 18px;
  flex-shrink: 0;
  color: var(--text-muted);
  margin-top: 2px;
}

.info-tip-text {
  font-size: 13.5px;
  color: var(--text-secondary);
  line-height: 1.6;
}

.info-tip-text a {
  color: var(--text-primary);
  font-weight: 600;
  text-decoration: none;
  border-bottom: 1px solid var(--text-faint);
}

/* ── Footer ── */
.footer {
  text-align: center;
  padding: 36px 0 20px;
  font-size: 12px;
  color: var(--text-faint);
}

.footer a {
  color: var(--text-muted);
  text-decoration: none;
}
"#;

#[cfg(feature = "info-page")]
/// Get the index page
#[instrument(skip_all)]
pub(crate) async fn get_index(
    State(state): State<MintState>,
) -> Result<impl IntoResponse, Response> {
    use maud::html;

    let mint_info = state.mint.mint_info().await.map_err(into_response)?;

    let name = mint_info.name.clone().unwrap_or("CDK Mint".to_string());
    let description = mint_info.description.clone();
    let long_description = mint_info.description_long.clone();
    let motd = mint_info.motd.clone();
    let pubkey = mint_info.pubkey.map(|p| p.to_hex());
    let version = mint_info.version.as_ref().map(|v| v.to_string());
    let contact = mint_info.contact.clone().unwrap_or_default();
    let icon_url = mint_info.icon_url.clone();
    let urls = mint_info.urls.clone().unwrap_or_default();
    let units: Vec<String> = mint_info
        .supported_units()
        .into_iter()
        .map(|u| u.to_string())
        .collect();

    let mut mint_methods: Vec<String> = mint_info
        .nuts
        .nut04
        .supported_methods()
        .into_iter()
        .map(|m| m.to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    mint_methods.sort();

    let mut melt_methods: Vec<String> = mint_info
        .nuts
        .nut05
        .supported_methods()
        .into_iter()
        .map(|m| m.to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    melt_methods.sort();

    let minting_disabled = mint_info.nuts.nut04.disabled;
    let melting_disabled = mint_info.nuts.nut05.disabled;

    // Collect mint limits from nut04 methods (deduplicated)
    let mint_limits: std::collections::BTreeSet<String> = mint_info
        .nuts
        .nut04
        .methods
        .iter()
        .filter(|m| m.min_amount.is_some() || m.max_amount.is_some())
        .map(|m| {
            let parts: Vec<String> = [m.min_amount.as_ref(), m.max_amount.as_ref()]
                .iter()
                .filter_map(|a| a.map(|v| v.to_string()))
                .collect();
            format!("{} {}", parts.join(" – "), m.unit)
        })
        .collect();

    // Collect melt limits from nut05 methods (deduplicated)
    let melt_limits: std::collections::BTreeSet<String> = mint_info
        .nuts
        .nut05
        .methods
        .iter()
        .filter(|m| m.min_amount.is_some() || m.max_amount.is_some())
        .map(|m| {
            let parts: Vec<String> = [m.min_amount.as_ref(), m.max_amount.as_ref()]
                .iter()
                .filter_map(|a| a.map(|v| v.to_string()))
                .collect();
            format!("{} {}", parts.join(" – "), m.unit)
        })
        .collect();

    // Build supported features list (NUT-7+)
    let mut supported_features: Vec<(u32, &str)> = Vec::new();
    if mint_info.nuts.nut07.supported {
        supported_features.push((7, "Token state check"));
    }
    if mint_info.nuts.nut08.supported {
        supported_features.push((8, "Lightning fee returns"));
    }
    if mint_info.nuts.nut09.supported {
        supported_features.push((9, "Signature restore"));
    }
    if mint_info.nuts.nut10.supported {
        supported_features.push((10, "Spending conditions"));
    }
    if mint_info.nuts.nut11.supported {
        supported_features.push((11, "Pay-to-Pubkey"));
    }
    if mint_info.nuts.nut12.supported {
        supported_features.push((12, "DLEQ proofs"));
    }
    if mint_info.nuts.nut14.supported {
        supported_features.push((14, "HTLCs"));
    }
    if !mint_info.nuts.nut15.methods.is_empty() {
        supported_features.push((15, "Multi-path payments"));
    }
    if !mint_info.nuts.nut17.supported.is_empty() {
        supported_features.push((17, "WebSocket subscriptions"));
    }
    if !mint_info.nuts.nut19.cached_endpoints.is_empty() {
        supported_features.push((19, "Cached responses"));
    }
    if mint_info.nuts.nut20.supported {
        supported_features.push((20, "Signed mint quotes"));
    }
    if mint_info.nuts.nut21.is_some() {
        supported_features.push((21, "Clear auth"));
    }
    if mint_info.nuts.nut22.is_some() {
        supported_features.push((22, "Blind auth"));
    }
    if !mint_info.nuts.nut29.is_empty() {
        supported_features.push((29, "Batched minting"));
    }

    #[cfg(feature = "conditional-tokens")]
    {
        if mint_info.nuts.nut_ctf.is_some() {
            supported_features.push((100, "Conditional Tokens (CTF)"));
        }
        if mint_info.nuts.nut_ctf_split_merge.is_some() {
            supported_features.push((101, "CTF Split/Merge"));
        }
        if mint_info.nuts.nut_ctf_numeric.is_some() {
            supported_features.push((102, "CTF Numeric"));
        }
    }

    // Avatar fallback letter
    let avatar_letter = name
        .chars()
        .next()
        .unwrap_or('M')
        .to_uppercase()
        .to_string();

    let markup = html! {
        (maud::DOCTYPE)
        html lang="en" {
            head {
                title { (name) }
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                style { (maud::PreEscaped(CSS)) }
            }
            body {
                div class="page" {

                    // Topbar
                    div class="topbar" {
                        span class="cashu-wordmark" { "Cashu Mint" }
                        span class="status-badge" {
                            span class="status-dot" {}
                            " Online"
                        }
                    }

                    // Hero
                    div class="hero" {
                        div class="avatar-ring" {
                            div class="avatar" {
                                @if let Some(ref url) = icon_url {
                                    img src=(url) alt=(name);
                                } @else {
                                    (avatar_letter)
                                }
                            }
                        }
                        div class="mint-name" { (name) }
                        @if let Some(ref desc) = description {
                            div class="mint-desc" { (desc) }
                        }
                        @if let Some(ref long) = long_description {
                            div class="mint-desc-long" { (long) }
                        }
                        @if let Some(ref v) = version {
                            div class="version-chip" { (v) }
                        }
                    }

                    // MOTD
                    @if let Some(ref m) = motd {
                        div class="motd" {
                            div class="motd-label" { "Mint notice" }
                            div class="motd-text" { (m) }
                        }
                    }

                    // Disabled banners
                    @if minting_disabled {
                        div class="disabled-banner" { "Minting is currently disabled" }
                    }
                    @if melting_disabled {
                        div class="disabled-banner" { "Melting is currently disabled" }
                    }

                    // URL section
                    @if !urls.is_empty() {
                        div class="url-section" {
                            div class="url-bar" {
                                span class="url-text" { (urls[0]) }
                            }
                            @if urls.len() > 1 {
                                div class="extra-urls" {
                                    @for url in &urls[1..] {
                                        div class="extra-url" {
                                            span class="url-label" {
                                                @if url.as_str().contains(".onion") {
                                                    "TOR"
                                                } @else {
                                                    "ALT"
                                                }
                                            }
                                            span class="url-text" { (url) }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Unified detail card
                    div class="detail-card" {

                        // Mint details section
                        div class="card-section-header" { "Mint details" }

                        @if !units.is_empty() {
                            div class="detail-row" style="padding-top:14px" {
                                span class="detail-label" { "Units" }
                                div class="detail-value" {
                                    @for unit in &units {
                                        span class="tag" { (unit) }
                                    }
                                }
                            }
                        }

                        div class="detail-row" {
                            span class="detail-label" { "Minting" }
                            div class="detail-value" {
                                @if minting_disabled {
                                    span class="tag tag-red" { "disabled" }
                                } @else {
                                    @for method in &mint_methods {
                                        span class="tag" { (method) }
                                    }
                                }
                            }
                        }

                        div class="detail-row" {
                            span class="detail-label" { "Melting" }
                            div class="detail-value" {
                                @if melting_disabled {
                                    span class="tag tag-red" { "disabled" }
                                } @else {
                                    @for method in &melt_methods {
                                        span class="tag" { (method) }
                                    }
                                }
                            }
                        }

                        @if !mint_limits.is_empty() {
                            div class="detail-row" {
                                span class="detail-label" { "Mint limits" }
                                span class="detail-value detail-value-mono" {
                                    (mint_limits.iter().cloned().collect::<Vec<_>>().join(" · "))
                                }
                            }
                        }

                        @if !melt_limits.is_empty() {
                            div class="detail-row row-last" {
                                span class="detail-label" { "Melt limits" }
                                span class="detail-value detail-value-mono" {
                                    (melt_limits.iter().cloned().collect::<Vec<_>>().join(" · "))
                                }
                            }
                        }

                        // Supported features section
                        @if !supported_features.is_empty() {
                            div class="card-section-header has-rule" { "Supported features" }
                            div style="padding-top:12px" {
                                div class="features-grid" {
                                    @for (_nut_num, feature_name) in &supported_features {
                                        div class="feature" {
                                            div class="feature-dot" {
                                                (maud::PreEscaped(r#"<svg viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>"#))
                                            }
                                            span class="feature-name" { (feature_name) }
                                        }
                                    }
                                }
                            }
                        }

                        // Contact section
                        @if !contact.is_empty() {
                            div class="card-section-header has-rule" { "Contact" }
                            div style="padding-top:12px" {
                                div class="contact-chips" {
                                    @for c in &contact {
                                        @if c.method.to_lowercase() == "email" {
                                            a class="contact-chip" href=(format!("mailto:{}", c.info)) target="_blank" {
                                                (maud::PreEscaped(r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22,4 12,13 2,4"/></svg>"#))
                                                (c.info)
                                            }
                                        } @else if c.method.to_lowercase() == "twitter" {
                                            a class="contact-chip" href=(format!("https://x.com/{}", c.info.trim_start_matches('@'))) target="_blank" {
                                                (maud::PreEscaped(r#"<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>"#))
                                                (c.info)
                                            }
                                        } @else if c.method.to_lowercase() == "nostr" {
                                            a class="contact-chip" href=(format!("https://njump.me/{}", c.info)) target="_blank" {
                                                (maud::PreEscaped(r#"<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>"#))
                                                (c.info)
                                            }
                                        } @else {
                                            span class="contact-chip" {
                                                (c.method) ": " (c.info)
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Public key section
                        @if let Some(ref pk) = pubkey {
                            div class="card-section-header has-rule" { "Public key" }
                            div class="pubkey-row" {
                                span class="pubkey-mono" { (pk) }
                            }
                        }
                    }

                    // Info tip
                    div class="info-tip" {
                        div class="info-tip-icon" {
                            (maud::PreEscaped(r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>"#))
                        }
                        div class="info-tip-text" {
                            "To use this mint, copy the mint URL above and add it to a Cashu-compatible wallet such as "
                            a href="https://wallet.cashu.me" target="_blank" { "Cashu.me" }
                            ", "
                            a href="https://macadamia.cash" target="_blank" { "Macadamia" }
                            ", or "
                            a href="https://www.minibits.cash" target="_blank" { "Minibits" }
                            "."
                        }
                    }

                    // Footer
                    div class="footer" {
                        div {
                            "Powered by "
                            a href="https://cashudevkit.org" target="_blank" { "Cashu Development Kit (CDK)" }
                        }
                        div style="margin-top: 8px" {
                            a href="https://iscashucustodial.com/" target="_blank" { "isCashuCustodial.com" }
                        }
                    }
                }
            }
        }
    };

    Ok(markup)
}

#[instrument(skip_all)]
pub(crate) fn into_response<T>(error: T) -> Response
where
    T: Into<ErrorResponse>,
{
    let err_response: ErrorResponse = error.into();
    // Per NUT-00 spec: "In case of an error, mints respond with the HTTP status code 400"
    (StatusCode::BAD_REQUEST, Json(err_response)).into_response()
}

// --- NUT-CTF Conditional Token Endpoints ---

/// GET /v1/conditions - List all registered conditions
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn get_conditions(
    #[cfg(feature = "auth")] auth: AuthHeader,
    State(state): State<MintState>,
    Query(params): Query<cdk::nuts::nut_ctf::GetConditionsRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::GetConditionsResponse>, Response> {
    #[cfg(feature = "auth")]
    {
        state
            .mint
            .verify_auth(
                auth.into(),
                &ProtectedEndpoint::new(Method::Get, RoutePath::Conditions),
            )
            .await
            .map_err(into_response)?;
    }

    let response = state
        .mint
        .get_conditions(params.since, params.limit, &params.status)
        .await
        .map_err(|err| {
            tracing::error!("Could not get conditions: {}", err);
            into_response(err)
        })?;
    Ok(Json(response))
}

/// POST /v1/conditions - Register a new condition
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn post_conditions(
    #[cfg(feature = "auth")] auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<cdk::nuts::nut_ctf::RegisterConditionRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::RegisterConditionResponse>, Response> {
    #[cfg(feature = "auth")]
    {
        state
            .mint
            .verify_auth(
                auth.into(),
                &ProtectedEndpoint::new(Method::Post, RoutePath::Conditions),
            )
            .await
            .map_err(into_response)?;
    }

    let response = state
        .mint
        .register_condition(payload)
        .await
        .map_err(|err| {
            tracing::error!("Could not register condition: {}", err);
            into_response(err)
        })?;
    Ok(Json(response))
}

/// GET /v1/conditions/{condition_id} - Get a specific condition
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn get_condition(
    #[cfg(feature = "auth")] auth: AuthHeader,
    State(state): State<MintState>,
    Path(condition_id): Path<String>,
) -> Result<Json<cdk::nuts::nut_ctf::ConditionInfo>, Response> {
    #[cfg(feature = "auth")]
    {
        state
            .mint
            .verify_auth(
                auth.into(),
                &ProtectedEndpoint::new(Method::Get, RoutePath::Condition),
            )
            .await
            .map_err(into_response)?;
    }

    let response = state
        .mint
        .get_condition(&condition_id)
        .await
        .map_err(|err| {
            tracing::error!("Could not get condition: {}", err);
            into_response(err)
        })?;
    Ok(Json(response))
}

/// GET /v1/conditional_keysets - List all conditional keysets
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn get_conditional_keysets(
    #[cfg(feature = "auth")] auth: AuthHeader,
    State(state): State<MintState>,
    Query(params): Query<cdk::nuts::nut_ctf::GetConditionalKeysetsRequest>,
) -> Result<Response, Response> {
    #[cfg(feature = "auth")]
    {
        state
            .mint
            .verify_auth(
                auth.into(),
                &ProtectedEndpoint::new(Method::Get, RoutePath::ConditionalKeysets),
            )
            .await
            .map_err(into_response)?;
    }

    let strict_catalogue = params.catalogue_version.is_some() || params.cursor.is_some();
    let catalogue_permit = state
        .conditional_keyset_catalogue_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
    let response = if strict_catalogue {
        state
            .mint
            .get_conditional_keysets_catalogue_page(params)
            .await
    } else {
        state
            .mint
            .get_conditional_keysets(params.since, params.limit, params.active)
            .await
    }
    .map_err(|err| {
        match &err {
            cdk::Error::InvalidConditionalKeysetCatalogueCursor
            | cdk::Error::ConditionalKeysetCataloguePageLimitExceeded { .. } => {
                tracing::debug!("Rejected conditional keyset catalogue request: {}", err);
            }
            _ => tracing::error!("Could not get conditional keysets: {}", err),
        }
        into_response(err)
    })?;
    conditional_keyset_catalogue_response(
        &response,
        catalogue_permit,
        state.conditional_keyset_catalogue_bytes,
        cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES,
    )
    .map_err(IntoResponse::into_response)
}

/// POST /v1/ctf/convert - Convert conditional/collateral positions
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn post_ctf_convert(
    #[cfg(feature = "auth")] auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<cdk::nuts::nut_ctf::CtfConvertRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::CtfConvertResponse>, Response> {
    #[cfg(feature = "auth")]
    {
        state
            .mint
            .verify_auth(
                auth.into(),
                &ProtectedEndpoint::new(Method::Post, RoutePath::Swap),
            )
            .await
            .map_err(into_response)?;
    }

    let response = state
        .mint
        .process_ctf_convert(payload)
        .await
        .map_err(|err| {
            tracing::error!("Could not process CTF convert: {}", err);
            into_response(err)
        })?;
    Ok(Json(response))
}

/// POST /v1/redeem_outcome - Redeem conditional tokens
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn post_redeem_outcome(
    #[cfg(feature = "auth")] auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<cdk::nuts::nut_ctf::RedeemOutcomeRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::RedeemOutcomeResponse>, Response> {
    #[cfg(feature = "auth")]
    {
        state
            .mint
            .verify_auth(
                auth.into(),
                &ProtectedEndpoint::new(Method::Post, RoutePath::RedeemOutcome),
            )
            .await
            .map_err(into_response)?;
    }

    let response = state
        .mint
        .process_redeem_outcome(payload)
        .await
        .map_err(|err| {
            tracing::error!("Could not process redeem outcome: {}", err);
            into_response(err)
        })?;
    Ok(Json(response))
}

#[cfg(all(test, feature = "conditional-tokens"))]
mod conditional_keyset_catalogue_tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::extract::{Query, State};
    use axum::http::{Request, StatusCode};
    use cdk::error::{ErrorCode, ErrorResponse};
    use cdk::mint::{MintBuilder, MintKeySetInfo, UnitConfig};
    use cdk::nuts::nut_ctf::{
        ConditionalKeysetsResponse, GetConditionalKeysetsRequest, NutCtfSettings,
    };
    use cdk::nuts::{CurrencyUnit, Id};
    use cdk_common::mint::StoredCondition;
    use tower::ServiceExt;

    use super::{
        conditional_keyset_catalogue_response,
        conditional_keyset_catalogue_response_with_serializer, get_conditional_keysets,
        serialize_conditional_keyset_catalogue_response,
    };
    use crate::{cache::HttpCache, create_mint_router, MintState};

    async fn test_mint() -> Arc<cdk::Mint> {
        let db = Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("database should open"),
        );
        let mut builder = MintBuilder::new(db.clone());
        builder
            .configure_unit(
                CurrencyUnit::Sat,
                UnitConfig {
                    amounts: vec![1, 2, 4, 8],
                    input_fee_ppk: 0,
                },
            )
            .expect("unit should configure");
        let mint = builder
            .build_with_seed(db, &[0x63; 64])
            .await
            .expect("mint should build");
        Arc::new(mint)
    }

    async fn test_state() -> MintState {
        MintState {
            mint: test_mint().await,
            cache: Arc::new(HttpCache::default()),
            conditional_keyset_catalogue_slots: Arc::new(tokio::sync::Semaphore::new(16)),
            conditional_keyset_catalogue_bytes: Arc::new(tokio::sync::Semaphore::new(
                cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES,
            )),
        }
    }

    async fn insert_catalogue_fixture(mint: &cdk::Mint) {
        let condition_id = "ab".repeat(32);
        let mut tx = mint
            .localstore()
            .begin_transaction()
            .await
            .expect("transaction should start");
        tx.add_condition(StoredCondition {
            condition_id: condition_id.clone(),
            threshold: 1,
            tags_json: "[]".to_string(),
            announcements_json: "[]".to_string(),
            collateral: Some(CurrencyUnit::Sat),
            attestation_status: "pending".to_string(),
            winning_outcome: None,
            attested_at: None,
            created_at: 1_000,
            condition_type: "enum".to_string(),
            lo_bound: None,
            hi_bound: None,
            precision: None,
        })
        .await
        .expect("condition should insert");
        let keysets = [
            ("00916bbf7ef91a36", "YES", "01".repeat(32)),
            ("009a1f293253e41e", "NO", "02".repeat(32)),
        ]
        .into_iter()
        .map(|(id, outcome, outcome_id)| {
            (
                MintKeySetInfo {
                    id: Id::from_str(id).expect("keyset id should parse"),
                    unit: CurrencyUnit::Sat,
                    active: false,
                    valid_from: 0,
                    derivation_path: "m/0'/0'/0'".parse().expect("derivation path should parse"),
                    derivation_path_index: Some(0),
                    amounts: vec![1, 2, 4, 8],
                    input_fee_ppk: 0,
                    final_expiry: None,
                    issuer_version: None,
                    condition_id: Some(condition_id.clone()),
                    outcome_collection: Some(outcome.to_string()),
                    outcome_collection_id: Some(outcome_id),
                },
                1_000,
            )
        })
        .collect();
        tx.add_conditional_keysets(keysets)
            .await
            .expect("catalogue batch should insert");
        tx.commit().await.expect("transaction should commit");

        let mut info = mint.mint_info().await.expect("mint info should load");
        info.nuts.nut_ctf = Some(NutCtfSettings::default());
        mint.set_mint_info(info)
            .await
            .expect("CTF mint info should persist");
    }

    #[tokio::test]
    async fn forged_catalogue_cursor_returns_typed_cashu_http_error() {
        let response = get_conditional_keysets(
            State(test_state().await),
            Query(GetConditionalKeysetsRequest {
                cursor: Some("forged".to_string()),
                ..Default::default()
            }),
        )
        .await
        .expect_err("forged cursor should fail");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("response body should read");
        let error: ErrorResponse =
            serde_json::from_slice(&body).expect("Cashu error response should decode");
        assert_eq!(
            error.code,
            ErrorCode::InvalidConditionalKeysetCatalogueCursor
        );
        assert_eq!(error.code.to_code(), 13049);
    }

    #[tokio::test]
    async fn router_serializes_legacy_and_authenticated_multi_page_boundaries() {
        let mint = test_mint().await;
        insert_catalogue_fixture(&mint).await;
        let router = create_mint_router(mint, Vec::new())
            .await
            .expect("router should build");

        let legacy = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?limit=1")
                    .body(Body::empty())
                    .expect("legacy request should build"),
            )
            .await
            .expect("legacy route should respond");
        assert_eq!(legacy.status(), StatusCode::OK);
        let legacy: ConditionalKeysetsResponse = serde_json::from_slice(
            &to_bytes(legacy.into_body(), 64 * 1024)
                .await
                .expect("legacy body should read"),
        )
        .expect("legacy response should deserialize");
        assert_eq!(legacy.keysets.len(), 1);
        assert!(!legacy.complete);
        assert!(legacy.next_cursor.is_none());

        let first = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?catalogue=1&limit=1")
                    .body(Body::empty())
                    .expect("first request should build"),
            )
            .await
            .expect("first route should respond");
        assert_eq!(first.status(), StatusCode::OK);
        let first: ConditionalKeysetsResponse = serde_json::from_slice(
            &to_bytes(first.into_body(), 64 * 1024)
                .await
                .expect("first body should read"),
        )
        .expect("first response should deserialize");
        assert_eq!(first.keysets.len(), 1);
        assert!(!first.complete);
        let cursor = first.next_cursor.expect("first page should continue");

        let second = router
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/conditional_keysets?catalogue=1&limit=1&cursor={cursor}"
                    ))
                    .body(Body::empty())
                    .expect("second request should build"),
            )
            .await
            .expect("second route should respond");
        assert_eq!(second.status(), StatusCode::OK);
        let second: ConditionalKeysetsResponse = serde_json::from_slice(
            &to_bytes(second.into_body(), 64 * 1024)
                .await
                .expect("second body should read"),
        )
        .expect("second response should deserialize");
        assert_eq!(second.keysets.len(), 1);
        assert!(second.complete);
        assert!(second.next_cursor.is_none());
        assert_ne!(first.keysets[0].id, second.keysets[0].id);
    }

    #[tokio::test]
    async fn all_catalogue_routes_fail_fast_when_concurrency_bound_is_saturated() {
        let mut state = test_state().await;
        state.conditional_keyset_catalogue_slots = Arc::new(tokio::sync::Semaphore::new(1));
        let held = state
            .conditional_keyset_catalogue_slots
            .clone()
            .acquire_owned()
            .await
            .expect("test should hold the only catalogue permit");
        let router = axum::Router::new()
            .route(
                "/v1/conditional_keysets",
                axum::routing::get(get_conditional_keysets),
            )
            .with_state(state);

        let saturated = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            router.clone().oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?catalogue=1&limit=1")
                    .body(Body::empty())
                    .expect("strict request should build"),
            ),
        )
        .await
        .expect("strict overload response must not queue")
        .expect("strict overload route should respond");
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);

        let legacy = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            router.clone().oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?limit=1")
                    .body(Body::empty())
                    .expect("legacy request should build"),
            ),
        )
        .await
        .expect("legacy overload response must not queue")
        .expect("legacy overload route should respond");
        assert_eq!(legacy.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(held);
        let recovered = router
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?catalogue=1&limit=1")
                    .body(Body::empty())
                    .expect("strict recovery request should build"),
            )
            .await
            .expect("strict route should recover when capacity returns");
        assert_eq!(recovered.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn catalogue_count_admission_is_held_until_response_body_is_dropped() {
        let mut state = test_state().await;
        insert_catalogue_fixture(&state.mint).await;
        state.conditional_keyset_catalogue_slots = Arc::new(tokio::sync::Semaphore::new(1));
        let router = axum::Router::new()
            .route(
                "/v1/conditional_keysets",
                axum::routing::get(get_conditional_keysets),
            )
            .with_state(state);

        let held_body = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?catalogue=1&limit=1")
                    .body(Body::empty())
                    .expect("first request should build"),
            )
            .await
            .expect("first route should respond");
        assert_eq!(held_body.status(), StatusCode::OK);

        let saturated = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?catalogue=1&limit=1")
                    .body(Body::empty())
                    .expect("second request should build"),
            )
            .await
            .expect("second route should respond");
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(held_body);
        let recovered = router
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?catalogue=1&limit=1")
                    .body(Body::empty())
                    .expect("recovery request should build"),
            )
            .await
            .expect("route should recover after body drop");
        assert_eq!(recovered.status(), StatusCode::OK);
    }

    #[test]
    fn worst_case_escaped_catalogue_field_fits_the_shared_hard_cap() {
        let response = ConditionalKeysetsResponse {
            keysets: vec![cdk::nuts::nut_ctf::ConditionalKeySetInfo {
                id: Id::from_str("00916bbf7ef91a36").expect("keyset id should parse"),
                unit: "sat".to_string(),
                active: true,
                input_fee_ppk: Some(u64::MAX),
                final_expiry: Some(u64::MAX),
                condition_id: "ab".repeat(32),
                outcome_collection: "\u{0001}".repeat(
                    cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH,
                ),
                outcome_collection_id: "cd".repeat(32),
                registered_at: u64::MAX,
            }],
            next_cursor: Some("x".repeat(
                cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH,
            )),
            complete: false,
        };

        let serialized = serialize_conditional_keyset_catalogue_response(
            &response,
            cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES,
        )
        .expect("one maximally escaped item should fit the page cap");
        assert!(
            serialized.len()
                <= cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES
        );
    }

    #[test]
    fn catalogue_serializer_fails_closed_at_its_hard_cap() {
        let response = ConditionalKeysetsResponse {
            keysets: Vec::new(),
            next_cursor: None,
            complete: true,
        };
        let serialized = serde_json::to_vec(&response).expect("fixture should serialize");
        let error = serialize_conditional_keyset_catalogue_response(
            &response,
            serialized.len().saturating_sub(1),
        )
        .expect_err("hard byte cap must stop serialization");
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn catalogue_weighted_admission_is_held_until_response_body_is_dropped() {
        let response = ConditionalKeysetsResponse {
            keysets: Vec::new(),
            next_cursor: None,
            complete: true,
        };
        let count_slots = Arc::new(tokio::sync::Semaphore::new(2));
        let response_limit =
            cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES;
        let byte_slots = Arc::new(tokio::sync::Semaphore::new(response_limit));

        let held_body = conditional_keyset_catalogue_response(
            &response,
            count_slots
                .clone()
                .acquire_owned()
                .await
                .expect("count permit should acquire"),
            byte_slots.clone(),
            response_limit,
        )
        .expect("first response should acquire the byte budget");

        let saturated = conditional_keyset_catalogue_response(
            &response,
            count_slots
                .clone()
                .acquire_owned()
                .await
                .expect("second count permit should acquire"),
            byte_slots.clone(),
            response_limit,
        )
        .expect_err("second response must not reuse held byte admission");
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(held_body);
        conditional_keyset_catalogue_response(
            &response,
            count_slots
                .acquire_owned()
                .await
                .expect("recovery count permit should acquire"),
            byte_slots,
            response_limit,
        )
        .expect("byte admission should recover after body drop");
    }

    #[tokio::test]
    async fn third_catalogue_serialization_cannot_enter_beyond_global_budget() {
        let response = ConditionalKeysetsResponse {
            keysets: Vec::new(),
            next_cursor: None,
            complete: true,
        };
        let response_limit =
            cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES;
        let count_slots = Arc::new(tokio::sync::Semaphore::new(3));
        let byte_slots = Arc::new(tokio::sync::Semaphore::new(response_limit * 2));
        let serialization_count = Arc::new(AtomicUsize::new(0));

        let build_response = || {
            let serialization_count = serialization_count.clone();
            conditional_keyset_catalogue_response_with_serializer(
                &response,
                count_slots
                    .clone()
                    .try_acquire_owned()
                    .expect("count admission should remain available"),
                byte_slots.clone(),
                response_limit,
                move |response, limit| {
                    serialization_count.fetch_add(1, Ordering::SeqCst);
                    serialize_conditional_keyset_catalogue_response(response, limit)
                },
            )
        };

        let first = build_response().expect("first response should reserve its byte budget");
        let second = build_response().expect("second response should reserve its byte budget");
        let third = build_response().expect_err("third response must fail before serialization");

        assert_eq!(third.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(serialization_count.load(Ordering::SeqCst), 2);

        drop(first);
        build_response()
            .expect("serialization should resume after a body releases its reservation");
        assert_eq!(serialization_count.load(Ordering::SeqCst), 3);
        drop(second);
    }

    #[tokio::test]
    async fn legacy_catalogue_applies_a_default_limit_and_rejects_oversized_limit() {
        let mint = test_mint().await;
        insert_catalogue_fixture(&mint).await;
        let router = create_mint_router(mint, Vec::new())
            .await
            .expect("router should build");

        let defaulted = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets")
                    .body(Body::empty())
                    .expect("legacy request should build"),
            )
            .await
            .expect("legacy route should respond");
        assert_eq!(defaulted.status(), StatusCode::OK);

        let oversized = router
            .oneshot(
                Request::builder()
                    .uri("/v1/conditional_keysets?limit=101")
                    .body(Body::empty())
                    .expect("oversized legacy request should build"),
            )
            .await
            .expect("legacy route should respond");
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    }
}
