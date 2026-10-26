//! Bounded HTTPS and websocket transport for the pinned LNbits API.
//!
//! The transport sends no automatic retry, follows no redirect, uses no proxy
//! and accepts no compressed body. It keeps only the HTTP status and a bounded
//! body. Its errors carry only a [`TransportError`] kind, so a URL, a header
//! or a key cannot reach a log line through an error.

use std::pin::Pin;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::config::{ApiKey, LnbitsConfig, TransportLimits};
use crate::error::{Error, TransportError};

/// Header that carries the LNbits wallet key.
const API_KEY_HEADER: &str = "X-Api-Key";

/// Bounded HTTP reply.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HttpReply {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

impl std::fmt::Debug for HttpReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpReply")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Stream of raw websocket text messages. The stream ends when the
/// connection closes.
pub(crate) type HintStream = Pin<Box<dyn Stream<Item = Result<String, TransportError>> + Send>>;

/// Transport operations of the pinned LNbits API profile.
#[async_trait]
pub(crate) trait Transport: Send + Sync {
    /// `GET /api/v1/payments/{payment_hash}` with the invoice key.
    async fn get_payment(&self, payment_hash_hex: &str) -> Result<HttpReply, TransportError>;
    /// `GET /api/v1/payments/fee-reserve?invoice=...` without a key.
    async fn get_fee_reserve(&self, bolt11: &str) -> Result<HttpReply, TransportError>;
    /// `POST /api/v1/payments` with the invoice key.
    async fn create_invoice(&self, body: Vec<u8>) -> Result<HttpReply, TransportError>;
    /// `POST /api/v1/payments` with the admin key. Sent once, never retried.
    async fn pay_invoice(&self, body: Vec<u8>) -> Result<HttpReply, TransportError>;
    /// Open `/api/v1/ws/{invoice_key}`.
    async fn connect_hints(&self) -> Result<HintStream, TransportError>;
}

/// Production transport.
pub(crate) struct HttpsTransport {
    client: reqwest::Client,
    origin: Url,
    ws_origin: Url,
    admin_key: ApiKey,
    invoice_key: ApiKey,
    limits: TransportLimits,
}

impl std::fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsTransport")
            .field("origin", &self.origin.as_str())
            .finish_non_exhaustive()
    }
}

impl HttpsTransport {
    /// Build the HTTPS-only transport from a validated configuration.
    pub(crate) fn new(config: &LnbitsConfig) -> Result<Self, Error> {
        Self::build(
            config.api_origin.url().clone(),
            true,
            config.admin_key.clone(),
            config.invoice_key.clone(),
            config.limits,
        )
    }

    /// Build a loopback HTTP transport. This is the isolated test seam; it
    /// is not reachable from configuration.
    #[cfg(test)]
    pub(crate) fn loopback_for_tests(
        address: std::net::SocketAddr,
        admin_key: ApiKey,
        invoice_key: ApiKey,
        limits: TransportLimits,
    ) -> Result<Self, Error> {
        let origin = crate::config::ApiOrigin::loopback_for_tests(address);
        Self::build(origin.url().clone(), false, admin_key, invoice_key, limits)
    }

    fn build(
        origin: Url,
        https_only: bool,
        admin_key: ApiKey,
        invoice_key: ApiKey,
        limits: TransportLimits,
    ) -> Result<Self, Error> {
        install_crypto_provider();
        let client = reqwest::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .timeout(limits.request_timeout)
            .connect_timeout(limits.connect_timeout)
            .build()
            .map_err(|_| Error::InvalidConfig("HTTP client could not be built"))?;

        let mut ws_origin = origin.clone();
        let ws_scheme = if https_only { "wss" } else { "ws" };
        ws_origin
            .set_scheme(ws_scheme)
            .map_err(|_| Error::InvalidConfig("API origin has no websocket form"))?;

        Ok(Self {
            client,
            origin,
            ws_origin,
            admin_key,
            invoice_key,
            limits,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, TransportError> {
        self.origin.join(path).map_err(|_| TransportError::Protocol)
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<HttpReply, TransportError> {
        let mut response = request.send().await.map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let max = self.limits.max_response_bytes;
        if response
            .content_length()
            .is_some_and(|length| length > max as u64)
        {
            return Err(TransportError::BodyTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
            if body.len().saturating_add(chunk.len()) > max {
                return Err(TransportError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpReply { status, body })
    }
}

#[async_trait]
impl Transport for HttpsTransport {
    async fn get_payment(&self, payment_hash_hex: &str) -> Result<HttpReply, TransportError> {
        let url = self.endpoint(&format!("api/v1/payments/{payment_hash_hex}"))?;
        let request = self
            .client
            .get(url)
            .header(API_KEY_HEADER, key_header(&self.invoice_key)?);
        self.send(request).await
    }

    async fn get_fee_reserve(&self, bolt11: &str) -> Result<HttpReply, TransportError> {
        let mut url = self.endpoint("api/v1/payments/fee-reserve")?;
        url.query_pairs_mut().append_pair("invoice", bolt11);
        self.send(self.client.get(url)).await
    }

    async fn create_invoice(&self, body: Vec<u8>) -> Result<HttpReply, TransportError> {
        let url = self.endpoint("api/v1/payments")?;
        let request = self
            .client
            .post(url)
            .header(API_KEY_HEADER, key_header(&self.invoice_key)?)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(body);
        self.send(request).await
    }

    async fn pay_invoice(&self, body: Vec<u8>) -> Result<HttpReply, TransportError> {
        let url = self.endpoint("api/v1/payments")?;
        let request = self
            .client
            .post(url)
            .header(API_KEY_HEADER, key_header(&self.admin_key)?)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(body);
        self.send(request).await
    }

    async fn connect_hints(&self) -> Result<HintStream, TransportError> {
        // The provider authenticates this channel by the invoice key in the
        // path. The URL is a credential and is never logged or returned.
        let url = self
            .ws_origin
            .join("api/v1/ws/")
            .and_then(|base| base.join(self.invoice_key.expose()))
            .map_err(|_| TransportError::Protocol)?;
        let request = url
            .as_str()
            .into_client_request()
            .map_err(|_| TransportError::Protocol)?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(self.limits.max_hint_bytes))
            .max_frame_size(Some(self.limits.max_hint_bytes));
        let connect = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
        let (socket, _response) = tokio::time::timeout(self.limits.connect_timeout, connect)
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Connect)?;

        Ok(Box::pin(futures::stream::unfold(
            Some(socket),
            |state| async move {
                let mut socket = state?;
                loop {
                    match socket.next().await {
                        Some(Ok(Message::Text(text))) => {
                            return Some((Ok(text.as_str().to_string()), Some(socket)));
                        }
                        Some(Ok(Message::Close(_))) | None => return None,
                        Some(Ok(_)) => continue,
                        Some(Err(_)) => return Some((Err(TransportError::Protocol), None)),
                    }
                }
            },
        )))
    }
}

fn key_header(key: &ApiKey) -> Result<HeaderValue, TransportError> {
    let mut value = HeaderValue::from_str(key.expose()).map_err(|_| TransportError::Protocol)?;
    value.set_sensitive(true);
    Ok(value)
}

fn map_reqwest_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() {
        TransportError::Timeout
    } else if error.is_connect() {
        TransportError::Connect
    } else {
        TransportError::Protocol
    }
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Another thread can install a provider first. Either provider is
        // acceptable, so the result is ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
