//! HTTP response types

use futures::StreamExt;
use serde::de::DeserializeOwned;

use crate::error::HttpError;

/// HTTP Response type - generic over the body type R and error type E
/// This is the primary return type for all HTTP operations
pub type Response<R, E = HttpError> = Result<R, E>;

/// Raw HTTP response with status code and body access
#[derive(Debug)]
pub struct RawResponse {
    status: u16,
    inner: reqwest::Response,
}

impl RawResponse {
    /// Create a new RawResponse from a reqwest::Response
    pub(crate) fn new(response: reqwest::Response) -> Self {
        Self {
            status: response.status().as_u16(),
            inner: response,
        }
    }

    /// Get the HTTP status code
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Check if the response status is a success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check if the response status is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status)
    }

    /// Check if the response status is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status)
    }

    /// Return the server-declared response length, when present.
    pub fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }

    /// Get the response body as text
    pub async fn text(self) -> Response<String> {
        self.inner.text().await.map_err(HttpError::from)
    }

    /// Get the response body as JSON
    pub async fn json<T: DeserializeOwned>(self) -> Response<T> {
        self.inner.json().await.map_err(HttpError::from)
    }

    /// Get the response body as bytes
    pub async fn bytes(self) -> Response<Vec<u8>> {
        self.inner
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(HttpError::from)
    }

    /// Read a response body without retaining more than `max_bytes`.
    ///
    /// A declared oversized `Content-Length` is rejected before polling the
    /// body. The streamed byte count remains authoritative because responses
    /// may omit or misstate that header, or use chunked transfer encoding.
    pub async fn bytes_with_limit(self, max_bytes: usize) -> Response<Vec<u8>> {
        if self
            .inner
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(HttpError::ResponseBodyTooLarge { limit: max_bytes });
        }

        let mut body = Vec::with_capacity(
            self.inner
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or_default()
                .min(max_bytes),
        );
        let mut stream = self.inner.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(HttpError::from)?;
            let next_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or(HttpError::ResponseBodyTooLarge { limit: max_bytes })?;
            if next_len > max_bytes {
                return Err(HttpError::ResponseBodyTooLarge { limit: max_bytes });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: RawResponse tests require a real reqwest::Response,
    // so they are in tests/integration.rs using mockito.

    #[test]
    fn test_response_type_is_result() {
        // Response<R, E> is just a type alias for Result<R, E>
        let success: Response<i32> = Ok(42);
        assert!(success.is_ok());
        assert!(matches!(success, Ok(42)));

        let error: Response<i32> = Err(HttpError::Timeout);
        assert!(error.is_err());
        assert!(matches!(error, Err(HttpError::Timeout)));
    }
}
