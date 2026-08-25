use anyhow::Result;
#[cfg(feature = "conditional-tokens")]
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
#[cfg(feature = "conditional-tokens")]
use axum::extract::Query;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
#[cfg(feature = "conditional-tokens")]
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
#[cfg(feature = "conditional-tokens")]
use cdk::error::ErrorCode;
use cdk::error::ErrorResponse;
use cdk::nuts::nut21::{Method, ProtectedEndpoint, RoutePath};
#[cfg(feature = "conditional-tokens")]
use cdk::nuts::nut_ctf::settlement::{
    CtfConvertAdmission, CtfConvertMode, CtfSettlementLimits, Error as SettlementError,
};
use cdk::nuts::{
    CheckStateRequest, CheckStateResponse, Id, KeysResponse, KeysetResponse, MintInfo,
    RestoreRequest, RestoreResponse, SwapRequest, SwapResponse,
};
use cdk::util::unix_time;
use paste::paste;
use tracing::instrument;

use crate::auth::AuthHeader;
use crate::ws::main_websocket;
use crate::MintState;

#[cfg(feature = "conditional-tokens")]
pub(crate) const MAX_CTF_CONVERT_BODY_BYTES: usize = 2 * 1024 * 1024;

#[cfg(feature = "conditional-tokens")]
const MAX_CTF_MULTI_REQUEST_BYTES: usize = 1024 * 1024;

#[cfg(feature = "conditional-tokens")]
const UNADVERTISED_MULTI_PARTY_LIMITS: CtfSettlementLimits = CtfSettlementLimits {
    max_request_bytes: MAX_CTF_MULTI_REQUEST_BYTES,
    max_participants: 64,
    max_inputs: 4096,
    max_outputs: 8192,
    max_pool_entries: 256,
};

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

/// Get the public keys of the newest mint keyset
///
/// This endpoint returns a dictionary of all supported token values of the mint and their associated public key.
#[instrument(skip_all)]
pub(crate) async fn get_keys(
    State(state): State<MintState>,
) -> Result<Json<KeysResponse>, Response> {
    Ok(Json(state.mint.pubkeys()))
}

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
    tracing::debug!(
        code = ?err_response.code,
        detail = %err_response.detail,
        "mint returning error response",
    );
    // Per NUT-00 spec: "In case of an error, mints respond with the HTTP status code 400"
    (StatusCode::BAD_REQUEST, Json(err_response)).into_response()
}

// --- NUT-CTF Conditional Token Endpoints ---

/// GET /v1/conditions - List all registered conditions
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn get_conditions(
    auth: AuthHeader,
    State(state): State<MintState>,
    Query(params): Query<cdk::nuts::nut_ctf::GetConditionsRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::GetConditionsResponse>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Get, RoutePath::Conditions),
        )
        .await
        .map_err(into_response)?;

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
    auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<cdk::nuts::nut_ctf::RegisterConditionRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::RegisterConditionResponse>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Post, RoutePath::Conditions),
        )
        .await
        .map_err(into_response)?;

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
    auth: AuthHeader,
    State(state): State<MintState>,
    Path(condition_id): Path<String>,
) -> Result<Json<cdk::nuts::nut_ctf::ConditionInfo>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Get, RoutePath::Condition),
        )
        .await
        .map_err(into_response)?;

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
    auth: AuthHeader,
    State(state): State<MintState>,
    Query(params): Query<cdk::nuts::nut_ctf::GetConditionalKeysetsRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::ConditionalKeysetsResponse>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Get, RoutePath::ConditionalKeysets),
        )
        .await
        .map_err(into_response)?;

    let response = state
        .mint
        .get_conditional_keysets(params.since, params.limit, params.active)
        .await
        .map_err(|err| {
            tracing::error!("Could not get conditional keysets: {}", err);
            into_response(err)
        })?;
    Ok(Json(response))
}

/// POST /v1/ctf/convert - Convert conditional/collateral positions
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn post_ctf_convert(
    State(state): State<MintState>,
    headers: HeaderMap,
    payload: Bytes,
) -> Result<Response, Response> {
    require_json_content_type(&headers)?;
    let mode = CtfConvertAdmission::preflight_convert(
        &payload,
        UNADVERTISED_MULTI_PARTY_LIMITS,
        MAX_CTF_CONVERT_BODY_BYTES,
        state.mint.max_inputs(),
        state.mint.max_outputs(),
    )
    .map_err(ctf_settlement_error_response)?
    .mode();
    verify_ctf_convert_auth(&state, &headers).await?;

    match mode {
        CtfConvertMode::SingleParty => process_single_party_ctf_convert(&state, &payload).await,
        CtfConvertMode::MultiParty => process_multi_party_ctf_convert(&state, &payload).await,
    }
}

#[cfg(feature = "conditional-tokens")]
async fn process_single_party_ctf_convert(
    state: &MintState,
    payload: &[u8],
) -> Result<Response, Response> {
    let Json(payload) = Json::<cdk::nuts::nut_ctf::CtfConvertRequest>::from_bytes(payload)
        .map_err(|error| error.into_response())?;
    let response = state
        .mint
        .process_ctf_convert(payload)
        .await
        .map_err(|err| {
            tracing::error!("Could not process CTF convert: {}", err);
            into_response(err)
        })?;
    Ok(Json(response).into_response())
}

#[cfg(feature = "conditional-tokens")]
async fn process_multi_party_ctf_convert(
    state: &MintState,
    payload: &[u8],
) -> Result<Response, Response> {
    let mint_info = state.mint.mint_info().await.map_err(into_response)?;
    let settings = mint_info
        .nuts
        .nut_ctf_split_merge
        .as_ref()
        .and_then(|settings| settings.multi_party())
        .ok_or_else(multi_party_unavailable_response)?;
    let limits = settings.structural_limits().map_err(|error| {
        tracing::error!("Invalid advertised multi-party CTF settings: {error}");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;
    let admission =
        CtfConvertAdmission::preflight(payload, limits).map_err(ctf_settlement_error_response)?;
    let request = admission
        .decode_multi_party()
        .map_err(ctf_settlement_error_response)?;
    let response = state
        .mint
        .process_ctf_settlement(&request, settings, unix_time())
        .await
        .map_err(ctf_settlement_execution_error_response)?;
    Ok(Json(response).into_response())
}

#[cfg(feature = "conditional-tokens")]
async fn verify_ctf_convert_auth(state: &MintState, headers: &HeaderMap) -> Result<(), Response> {
    let auth = AuthHeader::from_headers(headers).map_err(|error| error.into_response())?;
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Post, RoutePath::Swap),
        )
        .await
        .map_err(into_response)
}

#[cfg(feature = "conditional-tokens")]
fn require_json_content_type(headers: &HeaderMap) -> Result<(), Response> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .is_some_and(|content_type| {
            content_type.type_() == "application"
                && (content_type.subtype() == "json"
                    || content_type.suffix().is_some_and(|suffix| suffix == "json"))
        });
    if is_json {
        Ok(())
    } else {
        Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected request with `Content-Type: application/json`",
        )
            .into_response())
    }
}

#[cfg(feature = "conditional-tokens")]
fn ctf_settlement_error_response(error: cdk::nuts::nut_ctf::settlement::Error) -> Response {
    let code = match &error {
        SettlementError::DuplicateInput => ErrorCode::DuplicateInputs,
        SettlementError::DuplicateOutput => ErrorCode::DuplicateOutputs,
        SettlementError::UnknownKeyset => ErrorCode::KeysetNotFound,
        SettlementError::LimitExceeded(_) => ErrorCode::Unknown(15009),
        SettlementError::OutputCommitmentMismatch => ErrorCode::Unknown(15003),
        SettlementError::OfferKeysetMismatch | SettlementError::OfferReceiveKeysetMismatch => {
            ErrorCode::Unknown(15004)
        }
        SettlementError::ManifestCommitmentMismatch => ErrorCode::Unknown(15011),
        SettlementError::InvalidSelection(_) | SettlementError::SelectionMismatch => {
            ErrorCode::Unknown(15012)
        }
        SettlementError::InvalidManifest(_) => ErrorCode::Unknown(15013),
        SettlementError::InvalidPoolPolicy(_) | SettlementError::ArithmeticOverflow => {
            ErrorCode::Unknown(15014)
        }
        SettlementError::CoordinatorAuthentication => ErrorCode::CoordinatorAuthentication,
        SettlementError::SettlementAfterExpiry => ErrorCode::SettlementAfterExpiry,
        SettlementError::RefundBeforeExpiry => ErrorCode::RefundBeforeExpiry,
        SettlementError::RefundWitnessMissingOrInvalid => ErrorCode::RefundWitnessMissingOrInvalid,
        _ => ErrorCode::PayToUnlockInvalidCondition,
    };
    let detail = match &error {
        SettlementError::CoordinatorAuthentication => {
            "Coordinator authentication failed".to_owned()
        }
        _ => error.to_string(),
    };
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse::new(code, detail)),
    )
        .into_response()
}

#[cfg(feature = "conditional-tokens")]
fn ctf_settlement_execution_error_response(error: cdk::mint::CtfSettlementError) -> Response {
    use cdk::mint::CtfSettlementError;

    match error {
        CtfSettlementError::Protocol(error) => ctf_settlement_error_response(error),
        CtfSettlementError::AuthorizationExpired => {
            ctf_settlement_error_response(SettlementError::SettlementAfterExpiry)
        }
        CtfSettlementError::AuthorizationBeyondKeysetExpiry => ctf_settlement_error_response(
            SettlementError::InvalidCondition("authorization exceeds refundable keyset lifetime"),
        ),
        CtfSettlementError::CollateralUnitMismatch => into_response(cdk::Error::UnitMismatch),
        CtfSettlementError::Mint(cdk::Error::NUT11(_) | cdk::Error::NUT14(_)) => {
            individual_condition_witness_error_response()
        }
        CtfSettlementError::Mint(error) => into_response(error),
        CtfSettlementError::Settings(error) => {
            tracing::error!("Invalid multi-party CTF settings: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        error
        @ (CtfSettlementError::MissingCollateralUnit | CtfSettlementError::ExpiryOverflow) => {
            tracing::error!("Invalid persisted multi-party CTF state: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(feature = "conditional-tokens")]
fn individual_condition_witness_error_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse::new(
            ErrorCode::WitnessMissingOrInvalid,
            "individual condition witness is invalid".to_string(),
        )),
    )
        .into_response()
}

#[cfg(feature = "conditional-tokens")]
fn multi_party_unavailable_response() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse::new(
            ErrorCode::PayToUnlockInvalidCondition,
            "multi-party CTF settlement is not enabled".to_string(),
        )),
    )
        .into_response()
}

/// POST /v1/redeem_outcome - Redeem conditional tokens
#[cfg(feature = "conditional-tokens")]
#[instrument(skip_all)]
pub(crate) async fn post_redeem_outcome(
    auth: AuthHeader,
    State(state): State<MintState>,
    Json(payload): Json<cdk::nuts::nut_ctf::RedeemOutcomeRequest>,
) -> Result<Json<cdk::nuts::nut_ctf::RedeemOutcomeResponse>, Response> {
    state
        .mint
        .verify_auth(
            auth.into(),
            &ProtectedEndpoint::new(Method::Post, RoutePath::RedeemOutcome),
        )
        .await
        .map_err(into_response)?;

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
mod ctf_convert_admission_tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::extract::DefaultBodyLimit;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use bip39::Mnemonic;
    use cdk::amount::SplitTarget;
    use cdk::cdk_database::MintAuthDatabase;
    use cdk::dhke::construct_proofs;
    use cdk::mint::{CtfSettlementError, Mint, MintBuilder, MintMeltLimits};
    use cdk::nuts::nut00::KnownMethod;
    use cdk::nuts::{BlindAuthToken, CurrencyUnit, PaymentMethod, PreMintSecrets};
    use cdk::types::FeeReserve;
    use cdk_fake_wallet::FakeWallet;
    use tower::ServiceExt;

    use super::*;

    async fn accept_json(headers: HeaderMap, _payload: Bytes) -> Result<StatusCode, Response> {
        require_json_content_type(&headers)?;
        Ok(StatusCode::OK)
    }

    fn admission_router() -> Router {
        Router::new()
            .route("/", post(accept_json))
            .layer(DefaultBodyLimit::max(MAX_CTF_CONVERT_BODY_BYTES))
    }

    async fn decode_error(response: Response) -> ErrorResponse {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error body");
        serde_json::from_slice(&body).expect("error response")
    }

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("header"),
        );
        headers
    }

    fn auth_headers(token: &BlindAuthToken) -> HeaderMap {
        let mut headers = json_headers();
        headers.insert(
            "Blind-auth",
            token.to_string().parse().expect("auth header"),
        );
        headers
    }

    async fn auth_protected_state_with_limits(
        max_inputs: usize,
        max_outputs: usize,
    ) -> (MintState, Arc<cdk_sqlite::mint::MintSqliteAuthDatabase>) {
        let mint_db = Arc::new(cdk_sqlite::mint::memory::empty().await.expect("mint db"));
        let auth_db = Arc::new(
            cdk_sqlite::mint::MintSqliteAuthDatabase::new(":memory:")
                .await
                .expect("auth db"),
        );
        let protected_endpoint = ProtectedEndpoint::new(Method::Post, RoutePath::Swap);
        let mnemonic = Mnemonic::generate(12).expect("mnemonic");
        let mut builder = MintBuilder::new(mint_db.clone());
        let payment = FakeWallet::new(
            FeeReserve {
                min_fee_reserve: 1.into(),
                percent_fee_reserve: 0.0,
            },
            HashMap::new(),
            HashSet::new(),
            0,
            CurrencyUnit::Sat,
        );
        builder
            .add_payment_processor(
                CurrencyUnit::Sat,
                PaymentMethod::Known(KnownMethod::Bolt11),
                MintMeltLimits::new(1, 10_000),
                Arc::new(payment),
            )
            .await
            .expect("payment processor");
        let mint = builder
            .with_limits(max_inputs, max_outputs)
            .with_auth(
                auth_db.clone(),
                "https://example.com/.well-known/openid-configuration".to_string(),
                "test-client".to_string(),
                Vec::new(),
            )
            .with_blind_auth(50, vec![protected_endpoint])
            .build_with_seed(mint_db, &mnemonic.to_seed_normalized(""))
            .await
            .expect("mint");
        (
            MintState {
                mint: Arc::new(mint),
                cache: Arc::new(crate::cache::HttpCache::default()),
            },
            auth_db,
        )
    }

    async fn auth_protected_state() -> (MintState, Arc<cdk_sqlite::mint::MintSqliteAuthDatabase>) {
        auth_protected_state_with_limits(1000, 1000).await
    }

    async fn blind_auth_token(mint: &Mint) -> BlindAuthToken {
        let keyset_id = mint
            .get_active_keysets()
            .get(&CurrencyUnit::Auth)
            .copied()
            .expect("active auth keyset");
        let keys = mint
            .keyset_pubkeys(&keyset_id)
            .expect("auth keys")
            .keysets
            .into_iter()
            .next()
            .expect("auth keyset")
            .keys;
        let premint = PreMintSecrets::random(
            keyset_id,
            1.into(),
            &SplitTarget::Value(1.into()),
            &(0, vec![1]).into(),
        )
        .expect("premint");
        let signatures = vec![mint
            .auth_blind_sign(
                premint
                    .blinded_messages()
                    .first()
                    .expect("blinded auth output"),
            )
            .await
            .expect("blind auth signature")];
        let proof = construct_proofs(signatures, premint.rs(), premint.secrets(), &keys)
            .expect("auth proof")
            .pop()
            .expect("one auth proof")
            .try_into()
            .expect("auth proof shape");
        BlindAuthToken::new(proof).without_dleq()
    }

    async fn assert_rejected_without_auth_spend_at_limits(
        body: serde_json::Value,
        expected_status: StatusCode,
        max_inputs: usize,
        max_outputs: usize,
    ) {
        assert_rejected_with_auth_state(body, expected_status, max_inputs, max_outputs, None).await;
    }

    async fn assert_rejected_after_auth_spend(
        body: serde_json::Value,
        expected_status: StatusCode,
    ) {
        assert_rejected_with_auth_state(
            body,
            expected_status,
            1000,
            1000,
            Some(cdk::nuts::State::Spent),
        )
        .await;
    }

    async fn assert_rejected_with_auth_state(
        body: serde_json::Value,
        expected_status: StatusCode,
        max_inputs: usize,
        max_outputs: usize,
        expected_auth_state: Option<cdk::nuts::State>,
    ) {
        let (state, auth_db) = auth_protected_state_with_limits(max_inputs, max_outputs).await;
        let token = blind_auth_token(&state.mint).await;
        let proof_y = token.auth_proof.y().expect("proof Y");
        let response = post_ctf_convert(
            State(state),
            auth_headers(&token),
            Bytes::from(serde_json::to_vec(&body).expect("request")),
        )
        .await
        .expect_err("request must be rejected");

        assert_eq!(response.status(), expected_status);
        assert_eq!(
            auth_db
                .get_proofs_states(&[proof_y])
                .await
                .expect("auth state"),
            vec![expected_auth_state]
        );
    }

    #[tokio::test]
    async fn legacy_preflight_uses_lower_mint_transaction_limits() {
        assert_rejected_without_auth_spend_at_limits(
            serde_json::json!({
                "condition_id": "11".repeat(32),
                "inputs": {"*": [{}, {}]},
                "outputs": {}
            }),
            StatusCode::BAD_REQUEST,
            1,
            1,
        )
        .await;
    }

    #[tokio::test]
    async fn legacy_preflight_allows_mint_limits_above_multi_party_limits() {
        let inputs = vec![serde_json::json!({}); 4097];
        let outputs = vec![serde_json::json!({}); 8193];
        assert_rejected_with_auth_state(
            serde_json::json!({
                "condition_id": "11".repeat(32),
                "inputs": {"*": inputs},
                "outputs": {"*": outputs}
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            4097,
            8193,
            Some(cdk::nuts::State::Spent),
        )
        .await;
    }

    #[tokio::test]
    async fn route_rejects_oversized_body_before_json_decode() {
        let response = admission_router()
            .oneshot(
                Request::post("/")
                    .header("content-type", "application/json")
                    .body(Body::from(vec![b' '; MAX_CTF_CONVERT_BODY_BYTES + 1]))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn route_preserves_json_content_type_contract() {
        for content_type in [None, Some("text/plain")] {
            let mut request = Request::post("/");
            if let Some(content_type) = content_type {
                request = request.header("content-type", content_type);
            }
            let response = admission_router()
                .oneshot(request.body(Body::from("{}")).expect("request"))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }

        for content_type in [
            "application/json",
            "application/json; charset=utf-8",
            "application/problem+json",
        ] {
            let response = admission_router()
                .oneshot(
                    Request::post("/")
                        .header("content-type", content_type)
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn multi_protocol_cap_counts_outer_whitespace() {
        let (state, _) = auth_protected_state().await;
        let mut request = serde_json::to_vec(&serde_json::json!({
            "condition_id": "11".repeat(32),
            "participants": [
                {"inputs": [], "outputs": []},
                {"inputs": [], "outputs": []}
            ]
        }))
        .expect("multi request");
        let mut padded = vec![b' '; MAX_CTF_MULTI_REQUEST_BYTES + 1 - request.len()];
        padded.append(&mut request);
        let response = post_ctf_convert(State(state), json_headers(), Bytes::from(padded))
            .await
            .expect_err("multi request exceeds protocol cap");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(decode_error(response).await.code, ErrorCode::Unknown(15009));
    }

    #[tokio::test]
    async fn unavailable_multi_party_uses_defined_protocol_error() {
        let response = multi_party_unavailable_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        let error = decode_error(response).await;
        assert_eq!(error.code, ErrorCode::PayToUnlockInvalidCondition);
    }

    #[tokio::test]
    async fn settlement_failures_use_existing_protocol_codes() {
        use cdk::nuts::nut_ctf::settlement::Error as SettlementError;

        let cases = [
            (SettlementError::DuplicateInput, ErrorCode::DuplicateInputs),
            (
                SettlementError::DuplicateOutput,
                ErrorCode::DuplicateOutputs,
            ),
            (SettlementError::UnknownKeyset, ErrorCode::KeysetNotFound),
            (
                SettlementError::OfferReceiveKeysetMismatch,
                ErrorCode::Unknown(15004),
            ),
            (
                SettlementError::InvalidManifest("role"),
                ErrorCode::Unknown(15013),
            ),
            (
                SettlementError::CoordinatorAuthentication,
                ErrorCode::CoordinatorAuthentication,
            ),
            (
                SettlementError::ZeroFeeKeyset,
                ErrorCode::PayToUnlockInvalidCondition,
            ),
        ];

        for (failure, expected) in cases {
            let error = decode_error(ctf_settlement_error_response(failure)).await;
            assert_eq!(error.code, expected);
        }
    }

    #[tokio::test]
    async fn malformed_coordinator_signature_uses_15015() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "condition_id": "11".repeat(32),
            "participants": [
                {"inputs": [], "outputs": []},
                {"inputs": [], "outputs": []}
            ],
            "coordinator_sig": "AA".repeat(64)
        }))
        .expect("request bytes");
        let error = cdk::nuts::nut_ctf::settlement::CtfSettlementRequest::decode(
            &payload,
            UNADVERTISED_MULTI_PARTY_LIMITS,
        )
        .expect_err("uppercase signature must be rejected");

        assert_eq!(
            decode_error(ctf_settlement_error_response(error))
                .await
                .code,
            ErrorCode::CoordinatorAuthentication
        );
    }

    #[tokio::test]
    async fn malformed_coordinator_public_key_uses_15015() {
        const KEYSET: &str = "00deadbeef123456";
        const PROOF_POINT: &str =
            "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104";
        const REFUND_KEY: &str = "194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104";
        const COORDINATOR_KEY: &str =
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

        for malformed in [COORDINATOR_KEY.to_uppercase(), "00".repeat(32)] {
            let secret = serde_json::json!([
                "PAY_TO_UNLOCK",
                {
                    "nonce": "01".repeat(32),
                    "data": "02".repeat(32),
                    "tags": [
                        ["offer_keyset", KEYSET],
                        ["expiry", "100"],
                        ["refund", REFUND_KEY],
                        ["coordinator_pubkey", malformed]
                    ]
                }
            ])
            .to_string();
            let payload = serde_json::to_vec(&serde_json::json!({
                "condition_id": "11".repeat(32),
                "participants": [
                    {
                        "inputs": [{
                            "amount": 1,
                            "id": KEYSET,
                            "secret": secret,
                            "C": PROOF_POINT
                        }],
                        "outputs": []
                    },
                    {"inputs": [], "outputs": []}
                ]
            }))
            .expect("request bytes");
            let request = cdk::nuts::nut_ctf::settlement::CtfSettlementRequest::decode(
                &payload,
                UNADVERTISED_MULTI_PARTY_LIMITS,
            )
            .expect("typed request");
            let error = request
                .verify_coordinator_authentication()
                .expect_err("malformed coordinator key must be rejected");

            assert_eq!(
                decode_error(ctf_settlement_error_response(error))
                    .await
                    .code,
                ErrorCode::CoordinatorAuthentication
            );
        }
    }

    #[tokio::test]
    async fn coordinator_authentication_uses_finalized_display_text() {
        let error = decode_error(ctf_settlement_error_response(
            SettlementError::CoordinatorAuthentication,
        ))
        .await;

        assert_eq!(error.code, ErrorCode::CoordinatorAuthentication);
        assert_eq!(error.detail, "Coordinator authentication failed");
    }

    #[tokio::test]
    async fn malformed_legacy_authenticates_before_strict_decode() {
        assert_rejected_after_auth_spend(
            serde_json::json!({
                "condition_id": "11".repeat(32),
                "inputs": {"*": [{"id": "not-a-key"}]},
                "outputs": {}
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    #[tokio::test]
    async fn unavailable_multi_authenticates_before_mint_info_read() {
        assert_rejected_after_auth_spend(
            serde_json::json!({
                "condition_id": "11".repeat(32),
                "participants": [
                    {"inputs": [{"id": "not-a-key"}], "outputs": []},
                    {"inputs": [], "outputs": []}
                ]
            }),
            StatusCode::NOT_IMPLEMENTED,
        )
        .await;
    }

    #[tokio::test]
    async fn post_ctf_convert_maps_class_c_witness_failure_to_20008() {
        let errors = [
            CtfSettlementError::Mint(cdk::Error::NUT11(
                cdk::nuts::nut11::Error::SignaturesNotProvided,
            )),
            CtfSettlementError::Mint(cdk::Error::NUT14(cdk::nuts::nut14::Error::Preimage)),
        ];

        for error in errors {
            let response = decode_error(ctf_settlement_execution_error_response(error)).await;
            assert_eq!(response.code, ErrorCode::WitnessMissingOrInvalid);
            assert_eq!(response.detail, "individual condition witness is invalid");
        }
    }

    #[tokio::test]
    async fn post_ctf_convert_r_is_accepted_and_not_exposed_in_error_detail() {
        let response = decode_error(ctf_settlement_execution_error_response(
            CtfSettlementError::Mint(cdk::Error::NUT11(cdk::nuts::nut11::Error::InvalidSignature)),
        ))
        .await;

        assert_eq!(response.code, ErrorCode::WitnessMissingOrInvalid);
        assert_eq!(response.detail, "individual condition witness is invalid");
        assert!(!response.detail.contains("dleq"));
        assert!(!response.detail.contains("secret"));
    }
}
