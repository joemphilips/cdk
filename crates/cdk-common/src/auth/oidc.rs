//! Open Id Connect

use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::Deserialize;
#[cfg(feature = "wallet")]
use serde::Serialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::instrument;

use crate::{HttpClient, HttpError};

fn validate_client_id_claim(
    claim_name: &str,
    claim_value: &serde_json::Value,
    client_id: &str,
) -> Result<(), Error> {
    let Some(token_client_id) = claim_value.as_str() else {
        tracing::warn!("{} claim is not a string", claim_name);
        return Err(Error::InvalidClientId);
    };

    if token_client_id != client_id {
        tracing::warn!(
            "Client ID ({}) mismatch: expected {}, got {}",
            claim_name,
            client_id,
            token_client_id
        );
        return Err(Error::InvalidClientId);
    }

    Ok(())
}

fn validate_client_id_claims(
    claims: &HashMap<String, serde_json::Value>,
    client_id: &str,
) -> Result<(), Error> {
    match claims.get("client_id") {
        Some(token_client_id) => validate_client_id_claim("client_id", token_client_id, client_id),
        None => match claims.get("azp") {
            Some(azp) => validate_client_id_claim("azp", azp, client_id),
            None => {
                tracing::warn!("CAT missing client_id or azp claim for configured client ID");
                Err(Error::InvalidClientId)
            }
        },
    }
}

/// OIDC Error
#[derive(Debug, Error)]
pub enum Error {
    /// From HTTP error
    #[error(transparent)]
    Http(#[from] crate::HttpError),
    /// From JWT error
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// Missing kid header
    #[error("Missing kid header")]
    MissingKidHeader,
    /// Missing jwk header
    #[error("Missing jwk")]
    MissingJwkHeader,
    /// Unsupported Algo
    #[error("Unsupported signing algo")]
    UnsupportedSigningAlgo,
    /// Invalid Client ID
    #[error("Invalid Client ID")]
    InvalidClientId,
}

impl From<Error> for crate::error::Error {
    fn from(value: Error) -> Self {
        tracing::debug!("Clear auth verification failed: {}", value);
        crate::error::Error::ClearAuthFailed
    }
}

/// Open Id Config
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    /// URI for the JSON Web Key Set
    pub jwks_uri: String,
    /// Token issuer identifier
    pub issuer: String,
    /// Token endpoint URL
    pub token_endpoint: String,
    /// Device authorization endpoint URL
    pub device_authorization_endpoint: String,
}

/// Raw OIDC HTTP response.
#[derive(Debug)]
pub struct OidcHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl OidcHttpResponse {
    /// Create a raw OIDC HTTP response.
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// Get the HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Check whether the response has a successful HTTP status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Deserialize the response body as JSON without checking the status code.
    pub fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, HttpError> {
        serde_json::from_slice(&self.body).map_err(HttpError::from)
    }

    fn json_or_status_error<T: serde::de::DeserializeOwned>(self) -> Result<T, HttpError> {
        if !(200..300).contains(&self.status) {
            return Err(HttpError::Status {
                status: self.status,
                message: String::from_utf8_lossy(&self.body).to_string(),
            });
        }

        serde_json::from_slice(&self.body).map_err(HttpError::from)
    }
}

/// HTTP transport used by [`OidcClient`].
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait OidcHttpTransport: Debug + Send + Sync {
    /// HTTP GET returning raw response bytes.
    async fn get(&self, url: &str) -> Result<OidcHttpResponse, HttpError>;

    /// HTTP POST with form-encoded parameters returning raw response bytes.
    async fn post_form(
        &self,
        url: &str,
        params: Vec<(String, String)>,
    ) -> Result<OidcHttpResponse, HttpError>;
}

#[derive(Debug, Clone)]
struct DefaultOidcHttpTransport {
    client: HttpClient,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl OidcHttpTransport for DefaultOidcHttpTransport {
    async fn get(&self, url: &str) -> Result<OidcHttpResponse, HttpError> {
        let response = self.client.get_raw(url).await?;
        let status = response.status();
        let body = response.bytes().await?;
        Ok(OidcHttpResponse::new(status, body))
    }

    async fn post_form(
        &self,
        url: &str,
        params: Vec<(String, String)>,
    ) -> Result<OidcHttpResponse, HttpError> {
        let response = self.client.post(url).form(&params).send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        Ok(OidcHttpResponse::new(status, body))
    }
}

/// OIDC client.
#[derive(Debug, Clone)]
pub struct OidcClient {
    client: Arc<dyn OidcHttpTransport>,
    openid_discovery: String,
    client_id: Option<String>,
    oidc_config: Arc<RwLock<Option<OidcConfig>>>,
    jwks_set: Arc<RwLock<Option<JwkSet>>>,
}

/// OAuth2 grant type
#[cfg(feature = "wallet")]
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Refresh token grant
    RefreshToken,
}

/// Request to refresh an access token
#[cfg(feature = "wallet")]
#[derive(Debug, Clone, Serialize)]
pub struct RefreshTokenRequest {
    /// The grant type for this request
    pub grant_type: GrantType,
    /// OAuth2 client identifier
    pub client_id: String,
    /// The refresh token to exchange
    pub refresh_token: String,
}

/// Response from token endpoint
#[cfg(feature = "wallet")]
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    /// The access token issued by the authorization server
    pub access_token: String,
    /// Optional refresh token for obtaining new access tokens
    pub refresh_token: Option<String>,
    /// Optional lifetime in seconds of the access token
    pub expires_in: Option<i64>,
    /// The type of token issued (typically "Bearer")
    pub token_type: String,
}

impl OidcClient {
    /// Create new [`OidcClient`]
    pub fn new(openid_discovery: String, client_id: Option<String>) -> Self {
        Self::with_transport(
            openid_discovery,
            client_id,
            Arc::new(DefaultOidcHttpTransport {
                client: HttpClient::new(),
            }),
        )
    }

    /// Create new [`OidcClient`] with a provided HTTP transport.
    pub fn with_transport(
        openid_discovery: String,
        client_id: Option<String>,
        client: Arc<dyn OidcHttpTransport>,
    ) -> Self {
        Self {
            client,
            openid_discovery,
            client_id,
            oidc_config: Arc::new(RwLock::new(None)),
            jwks_set: Arc::new(RwLock::new(None)),
        }
    }

    /// Get client id
    pub fn client_id(&self) -> Option<String> {
        self.client_id.clone()
    }

    /// Get config from oidc server
    #[instrument(skip(self))]
    pub async fn get_oidc_config(&self) -> Result<OidcConfig, Error> {
        tracing::debug!("Getting oidc config");
        let oidc_config: OidcConfig = self
            .client
            .get(&self.openid_discovery)
            .await?
            .json_or_status_error()?;

        let mut current_config = self.oidc_config.write().await;

        *current_config = Some(oidc_config.clone());

        Ok(oidc_config)
    }

    /// Get jwk set
    #[instrument(skip(self))]
    pub async fn get_jwkset(&self, jwks_uri: &str) -> Result<JwkSet, Error> {
        tracing::debug!("Getting jwks set");
        let jwks_set: JwkSet = self.client.get(jwks_uri).await?.json_or_status_error()?;

        let mut current_set = self.jwks_set.write().await;

        *current_set = Some(jwks_set.clone());

        Ok(jwks_set)
    }

    /// Verify cat token
    #[instrument(skip_all)]
    pub async fn verify_cat(&self, cat_jwt: &str) -> Result<(), Error> {
        tracing::debug!("Verifying cat");
        let header = decode_header(cat_jwt)?;

        let kid = header.kid.ok_or(Error::MissingKidHeader)?;

        let oidc_config = {
            let locked = self.oidc_config.read().await;
            match locked.deref() {
                Some(config) => config.clone(),
                None => {
                    drop(locked);
                    self.get_oidc_config().await?
                }
            }
        };

        let jwks = {
            let locked = self.jwks_set.read().await;
            match locked.deref() {
                Some(set) => set.clone(),
                None => {
                    drop(locked);
                    self.get_jwkset(&oidc_config.jwks_uri).await?
                }
            }
        };

        let jwk = match jwks.find(&kid) {
            Some(jwk) => jwk.clone(),
            None => {
                let refreshed_jwks = self.get_jwkset(&oidc_config.jwks_uri).await?;
                refreshed_jwks
                    .find(&kid)
                    .ok_or(Error::MissingKidHeader)?
                    .clone()
            }
        };

        let decoding_key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?,
            AlgorithmParameters::EllipticCurve(ecdsa) => {
                DecodingKey::from_ec_components(&ecdsa.x, &ecdsa.y)?
            }
            _ => return Err(Error::UnsupportedSigningAlgo),
        };

        let validation = {
            let mut validation = Validation::new(header.alg);
            validation.validate_exp = true;
            validation.validate_aud = false;
            validation.set_issuer(&[oidc_config.issuer]);
            validation
        };

        match decode::<HashMap<String, serde_json::Value>>(cat_jwt, &decoding_key, &validation) {
            Ok(claims) => {
                tracing::debug!("Successfully verified cat");
                if let Some(client_id) = &self.client_id {
                    validate_client_id_claims(&claims.claims, client_id)?;
                }
            }
            Err(err) => {
                tracing::debug!("Could not verify cat: {}", err);
                return Err(err.into());
            }
        }

        Ok(())
    }

    /// POST form-encoded parameters and parse a JSON response.
    pub async fn post_form_response(
        &self,
        url: &str,
        params: Vec<(String, String)>,
    ) -> Result<OidcHttpResponse, Error> {
        self.client
            .post_form(url, params)
            .await
            .map_err(Error::from)
    }

    /// POST form-encoded parameters and parse a successful JSON response.
    pub async fn post_form<T>(&self, url: &str, params: Vec<(String, String)>) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.client
            .post_form(url, params)
            .await?
            .json_or_status_error()
            .map_err(Error::from)
    }

    /// Get new access token using refresh token
    #[cfg(feature = "wallet")]
    pub async fn refresh_access_token(
        &self,
        client_id: String,
        refresh_token: String,
    ) -> Result<TokenResponse, Error> {
        let token_url = self.get_oidc_config().await?.token_endpoint;

        let response: TokenResponse = self
            .post_form(
                &token_url,
                vec![
                    ("grant_type".to_string(), "refresh_token".to_string()),
                    ("client_id".to_string(), client_id),
                    ("refresh_token".to_string(), refresh_token),
                ],
            )
            .await?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    use super::*;

    fn claims(value: serde_json::Value) -> HashMap<String, serde_json::Value> {
        serde_json::from_value(value).expect("claims should be an object")
    }

    #[test]
    fn validate_client_id_claims_accepts_client_id() {
        let claims = claims(json!({
            "client_id": "expected-client",
            "azp": "other-client",
        }));

        assert!(validate_client_id_claims(&claims, "expected-client").is_ok());
    }

    #[test]
    fn validate_client_id_claims_accepts_azp_fallback() {
        let claims = claims(json!({
            "azp": "expected-client",
        }));

        assert!(validate_client_id_claims(&claims, "expected-client").is_ok());
    }

    #[test]
    fn validate_client_id_claims_rejects_missing_claims() {
        let claims = claims(json!({
            "sub": "user",
        }));

        assert!(matches!(
            validate_client_id_claims(&claims, "expected-client"),
            Err(Error::InvalidClientId)
        ));
    }

    #[test]
    fn validate_client_id_claims_rejects_non_string_client_id() {
        let claims = claims(json!({
            "client_id": null,
            "azp": "expected-client",
        }));

        assert!(matches!(
            validate_client_id_claims(&claims, "expected-client"),
            Err(Error::InvalidClientId)
        ));
    }

    #[test]
    fn validate_client_id_claims_rejects_non_string_azp() {
        let claims = claims(json!({
            "azp": 42,
        }));

        assert!(matches!(
            validate_client_id_claims(&claims, "expected-client"),
            Err(Error::InvalidClientId)
        ));
    }

    #[test]
    fn validate_client_id_claims_rejects_mismatch() {
        let claims = claims(json!({
            "client_id": "other-client",
        }));

        assert!(matches!(
            validate_client_id_claims(&claims, "expected-client"),
            Err(Error::InvalidClientId)
        ));
    }

    #[derive(Debug)]
    struct StaticOidcTransport {
        jwks: String,
    }

    #[async_trait]
    impl OidcHttpTransport for StaticOidcTransport {
        async fn get(&self, url: &str) -> Result<OidcHttpResponse, HttpError> {
            let body = if url == "https://issuer.example/.well-known/openid-configuration" {
                r#"{"issuer":"https://issuer.example/","jwks_uri":"https://issuer.example/keys","token_endpoint":"https://issuer.example/token","device_authorization_endpoint":"https://issuer.example/device"}"#.to_owned()
            } else if url == "https://issuer.example/keys" {
                self.jwks.clone()
            } else {
                return Err(HttpError::Other(format!("unexpected URL: {url}")));
            };
            Ok(OidcHttpResponse::new(200, body.into_bytes()))
        }

        async fn post_form(
            &self,
            _url: &str,
            _params: Vec<(String, String)>,
        ) -> Result<OidcHttpResponse, HttpError> {
            Err(HttpError::Other("unexpected POST".to_owned()))
        }
    }

    fn fixture_keys() -> serde_json::Value {
        serde_json::from_str(include_str!("fixtures/oidc_test_keys.json"))
            .expect("test signing keys should be valid JSON")
    }

    fn test_client(jwks: serde_json::Value, client_id: Option<&str>) -> OidcClient {
        OidcClient::with_transport(
            "https://issuer.example/.well-known/openid-configuration".to_owned(),
            client_id.map(str::to_owned),
            Arc::new(StaticOidcTransport {
                jwks: jwks.to_string(),
            }),
        )
    }

    fn signed_token(
        algorithm: Algorithm,
        kid: &str,
        key: &EncodingKey,
        claims: serde_json::Value,
    ) -> String {
        let mut header = Header::new(algorithm);
        header.kid = Some(kid.to_owned());
        encode(&header, &claims, key).expect("test token should encode")
    }

    #[tokio::test]
    async fn verify_cat_accepts_valid_rsa_signature_and_client_claim() {
        let keys = fixture_keys();
        let rsa = &keys["rsa"];
        let jwks = json!({"keys": [{"kty":"RSA","kid":"rsa-test","alg":"RS256","use":"sig","n":rsa["n"],"e":rsa["e"]}]});
        let token = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &EncodingKey::from_rsa_pem(
                rsa["private_pem"]
                    .as_str()
                    .expect("RSA fixture PEM")
                    .as_bytes(),
            )
            .expect("RSA fixture key"),
            json!({"iss":"https://issuer.example/","exp":2000000000,"client_id":"test-client"}),
        );

        assert!(test_client(jwks, Some("test-client"))
            .verify_cat(&token)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn verify_cat_accepts_valid_ec_signature() {
        let keys = fixture_keys();
        let ec = &keys["ec"];
        let jwks = json!({"keys": [{"kty":"EC","kid":"ec-test","alg":"ES256","use":"sig","crv":"P-256","x":ec["x"],"y":ec["y"]}]});
        let token = signed_token(
            Algorithm::ES256,
            "ec-test",
            &EncodingKey::from_ec_pem(
                ec["private_pem"]
                    .as_str()
                    .expect("EC fixture PEM")
                    .as_bytes(),
            )
            .expect("EC fixture key"),
            json!({"iss":"https://issuer.example/","exp":2000000000}),
        );

        assert!(test_client(jwks, None).verify_cat(&token).await.is_ok());
    }

    #[tokio::test]
    async fn verify_cat_rejects_bad_signature_expiry_and_client_claim() {
        let keys = fixture_keys();
        let rsa = &keys["rsa"];
        let jwks = json!({"keys": [{"kty":"RSA","kid":"rsa-test","alg":"RS256","use":"sig","n":rsa["n"],"e":rsa["e"]}]});
        let signing_key = EncodingKey::from_rsa_pem(
            rsa["private_pem"]
                .as_str()
                .expect("RSA fixture PEM")
                .as_bytes(),
        )
        .expect("RSA fixture key");
        let client = test_client(jwks, Some("test-client"));

        let valid_claims =
            json!({"iss":"https://issuer.example/","exp":2000000000,"client_id":"test-client"});
        let mut bad_signature = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &signing_key,
            valid_claims.clone(),
        );
        let signature_start = bad_signature.rfind('.').expect("JWT signature separator") + 1;
        let signature_byte = bad_signature.as_bytes()[signature_start];
        bad_signature.replace_range(
            signature_start..signature_start + 1,
            if signature_byte == b'A' { "B" } else { "A" },
        );
        assert!(client.verify_cat(&bad_signature).await.is_err());

        let expired = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &signing_key,
            json!({"iss":"https://issuer.example/","exp":1,"client_id":"test-client"}),
        );
        assert!(client.verify_cat(&expired).await.is_err());

        let malformed_exp = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &signing_key,
            json!({"iss":"https://issuer.example/","exp":"not-a-timestamp","client_id":"test-client"}),
        );
        assert!(client.verify_cat(&malformed_exp).await.is_err());

        let missing_exp = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &signing_key,
            json!({"iss":"https://issuer.example/","client_id":"test-client"}),
        );
        assert!(client.verify_cat(&missing_exp).await.is_err());

        let wrong_client = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &signing_key,
            json!({"iss":"https://issuer.example/","exp":2000000000,"client_id":42}),
        );
        assert!(matches!(
            client.verify_cat(&wrong_client).await,
            Err(Error::InvalidClientId)
        ));

        let wrong_issuer = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &signing_key,
            json!({"iss":"https://other.example/","exp":2000000000,"client_id":"test-client"}),
        );
        assert!(client.verify_cat(&wrong_issuer).await.is_err());

        // OIDC's current CAT policy intentionally does not validate aud or nbf.
        let audience_and_nbf = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &signing_key,
            json!({"iss":"https://issuer.example/","exp":2000000000,"aud":"another-client","nbf":"malformed"}),
        );
        assert!(test_client(
            json!({"keys": [{"kty":"RSA","kid":"rsa-test","alg":"RS256","use":"sig","n":rsa["n"],"e":rsa["e"]}]}),
            None,
        ).verify_cat(&audience_and_nbf).await.is_ok());
    }

    #[test]
    fn documented_nbf_validation_rejects_malformed_claim() {
        // GHSA-h395-gr6q-cpjc regression: when an application enables nbf
        // validation, a malformed nbf value must not be treated as absent.
        let keys = fixture_keys();
        let rsa = &keys["rsa"];
        let token = signed_token(
            Algorithm::RS256,
            "rsa-test",
            &EncodingKey::from_rsa_pem(
                rsa["private_pem"]
                    .as_str()
                    .expect("RSA fixture PEM")
                    .as_bytes(),
            )
            .expect("RSA fixture key"),
            json!({"exp":2000000000,"nbf":"not-a-timestamp"}),
        );
        let decoding_key = DecodingKey::from_rsa_components(
            rsa["n"].as_str().expect("RSA modulus"),
            rsa["e"].as_str().expect("RSA exponent"),
        )
        .expect("RSA public components");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_nbf = true;

        assert!(decode::<serde_json::Value>(&token, &decoding_key, &validation).is_err());
    }
}
