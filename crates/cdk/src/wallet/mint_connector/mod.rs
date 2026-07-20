//! Wallet client

#[cfg(feature = "conditional-tokens")]
use std::collections::HashMap;
use std::fmt::Debug;

use async_trait::async_trait;
#[cfg(feature = "conditional-tokens")]
use cdk_common::database::mint::validate_conditional_keyset_catalogue_fields;
#[cfg(feature = "conditional-tokens")]
pub use cdk_common::database::mint::{
    CONDITIONAL_KEYSET_CATALOGUE_VERSION, MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH,
    MAX_CONDITIONAL_KEYSET_CATALOGUE_PAGE_SIZE, MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES,
    MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH, MAX_CONDITIONAL_KEYSET_UNIT_LENGTH,
};
use cdk_common::{
    MeltQuoteCreateResponse, MeltQuoteRequest, MeltQuoteResponse, MintQuoteRequest,
    MintQuoteResponse,
};

use super::Error;
// Re-export Lightning address types for trait implementers
pub use crate::lightning_address::{LnurlPayInvoiceResponse, LnurlPayResponse};
use crate::nuts::{
    BatchCheckMintQuoteRequest, BatchMintRequest, CheckStateRequest, CheckStateResponse, Id,
    KeySet, KeysetResponse, MeltRequest, MintInfo, MintQuoteBolt11Response, MintRequest,
    MintResponse, PaymentMethod, RestoreRequest, RestoreResponse, SwapRequest, SwapResponse,
};
use crate::wallet::AuthWallet;

pub mod http_client;
pub mod transport;

#[cfg(feature = "conditional-tokens")]
fn invalid_catalogue(detail: impl Into<String>) -> Error {
    Error::InvalidConditionalKeysetCatalogueResponse(detail.into())
}

/// Validate a strict catalogue request against a trusted advertised page cap.
#[cfg(feature = "conditional-tokens")]
pub fn validate_conditional_keyset_catalogue_request(
    request: &crate::nuts::nut_ctf::GetConditionalKeysetsRequest,
    advertised_max_page_size: u64,
) -> Result<u64, Error> {
    if request.catalogue_version != Some(CONDITIONAL_KEYSET_CATALOGUE_VERSION) {
        return Err(invalid_catalogue(
            "mint advertised an unsupported catalogue version",
        ));
    }
    if advertised_max_page_size == 0
        || advertised_max_page_size > MAX_CONDITIONAL_KEYSET_CATALOGUE_PAGE_SIZE
    {
        return Err(invalid_catalogue(
            "mint advertised an unsupported catalogue page size",
        ));
    }
    if request.cursor.as_ref().is_some_and(|cursor| {
        cursor.is_empty() || cursor.len() > MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH
    }) {
        return Err(invalid_catalogue("catalogue request cursor is invalid"));
    }
    let limit = request.limit.unwrap_or(advertised_max_page_size);
    if limit == 0 || limit > advertised_max_page_size {
        return Err(invalid_catalogue(
            "catalogue request exceeds the advertised page size",
        ));
    }
    Ok(limit)
}

/// Validate and normalize one strict catalogue response at the shared wallet
/// boundary used by HTTP, direct, and custom mint connectors.
#[cfg(feature = "conditional-tokens")]
pub fn validate_conditional_keyset_catalogue_response(
    request: &crate::nuts::nut_ctf::GetConditionalKeysetsRequest,
    response: &mut crate::nuts::nut_ctf::ConditionalKeysetsResponse,
    advertised_max_page_size: u64,
) -> Result<(), Error> {
    let limit = validate_conditional_keyset_catalogue_request(request, advertised_max_page_size)?;
    let limit = usize::try_from(limit)
        .map_err(|_| invalid_catalogue("catalogue page size exceeds client address space"))?;

    // Count the raw wire items before identical-metadata deduplication. A mint
    // cannot use duplicate objects to exceed the negotiated memory/work bound.
    if response.keysets.len() > limit {
        return Err(invalid_catalogue("page exceeded requested limit"));
    }

    let mut positions = HashMap::with_capacity(response.keysets.len());
    let mut deduplicated = Vec::with_capacity(response.keysets.len());
    for keyset in response.keysets.drain(..) {
        validate_conditional_keyset_catalogue_fields(
            &keyset.unit,
            &keyset.condition_id,
            &keyset.outcome_collection,
            &keyset.outcome_collection_id,
        )
        .map_err(invalid_catalogue)?;
        if let Some(index) = positions.get(&keyset.id).copied() {
            if deduplicated[index] != keyset {
                return Err(invalid_catalogue(
                    "page contained conflicting metadata for one keyset id",
                ));
            }
        } else {
            positions.insert(keyset.id, deduplicated.len());
            deduplicated.push(keyset);
        }
    }
    response.keysets = deduplicated;

    match (response.complete, response.next_cursor.as_deref()) {
        (true, None) => Ok(()),
        (false, Some(next))
            if !next.is_empty()
                && next.len() <= MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH
                && request.cursor.as_deref() != Some(next) =>
        {
            Ok(())
        }
        (false, _) => Err(Error::ConditionalKeysetCatalogueNoProgress),
        (true, Some(_)) => Err(invalid_catalogue(
            "complete page included a continuation cursor",
        )),
    }
}

/// Auth HTTP Client with async transport
pub type AuthHttpClient = http_client::AuthHttpClient<transport::Async>;
/// Default Http Client with async transport (non-Tor)
pub type HttpClient = http_client::HttpClient<transport::Async>;
/// Tor Http Client with async transport (only when `tor` feature is enabled and not on wasm32)
#[cfg(all(feature = "tor", not(target_arch = "wasm32")))]
pub type TorHttpClient = http_client::HttpClient<transport::tor_transport::TorAsync>;

/// Interface that connects a wallet to a mint. Typically represents an [HttpClient].
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait MintConnector: Debug {
    #[cfg(all(feature = "bip353", not(target_arch = "wasm32")))]
    /// Resolve the DNS record getting the TXT value
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, Error>;

    /// Fetch Lightning address pay request data
    async fn fetch_lnurl_pay_request(
        &self,
        url: &str,
    ) -> Result<crate::lightning_address::LnurlPayResponse, Error>;

    /// Fetch invoice from Lightning address callback
    async fn fetch_lnurl_invoice(
        &self,
        url: &str,
    ) -> Result<crate::lightning_address::LnurlPayInvoiceResponse, Error>;

    /// Get Active Mint Keys [NUT-01]
    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, Error>;
    /// Get Keyset Keys [NUT-01]
    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error>;
    /// Get Keysets [NUT-02]
    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error>;
    /// Mint Quote [NUT-04, NUT-23, NUT-25]
    async fn post_mint_quote(
        &self,
        request: MintQuoteRequest,
    ) -> Result<MintQuoteResponse<String>, Error>;
    /// Mint Tokens [NUT-04]
    async fn post_mint(
        &self,
        method: &PaymentMethod,
        request: MintRequest<String>,
    ) -> Result<MintResponse, Error>;

    /// Batch check mint quote status [NUT-29]
    ///
    /// Checks the status of multiple mint quotes in a single request.
    /// The response type is `Vec<MintQuoteBolt11Response>` for bolt11 quotes.
    /// For other payment methods, the response is method-specific.
    async fn post_batch_check_mint_quote_status(
        &self,
        method: &PaymentMethod,
        request: BatchCheckMintQuoteRequest<String>,
    ) -> Result<Vec<MintQuoteBolt11Response<String>>, Error>;

    /// Batch mint tokens [NUT-29]
    ///
    /// Mints tokens for multiple quotes in a single atomic request.
    async fn post_batch_mint(
        &self,
        method: &PaymentMethod,
        request: BatchMintRequest<String>,
    ) -> Result<MintResponse, Error>;

    /// Melt Quote [NUT-05]
    async fn post_melt_quote(
        &self,
        request: MeltQuoteRequest,
    ) -> Result<MeltQuoteCreateResponse<String>, Error>;

    /// Mint Quote status with payment method
    async fn get_mint_quote_status(
        &self,
        method: PaymentMethod,
        quote_id: &str,
    ) -> Result<MintQuoteResponse<String>, Error>;

    /// Melt [NUT-05]
    /// Melt Quote Status
    async fn get_melt_quote_status(
        &self,
        method: PaymentMethod,
        quote_id: &str,
    ) -> Result<MeltQuoteResponse<String>, Error>;

    /// [Nut-08] Lightning fee return if outputs defined
    async fn post_melt(
        &self,
        method: &PaymentMethod,
        request: MeltRequest<String>,
    ) -> Result<MeltQuoteResponse<String>, Error>;

    /// Split Token [NUT-06]
    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, Error>;
    /// Get Mint Info [NUT-06]
    async fn get_mint_info(&self) -> Result<MintInfo, Error>;
    /// Spendable check [NUT-07]
    async fn post_check_state(
        &self,
        request: CheckStateRequest,
    ) -> Result<CheckStateResponse, Error>;
    /// Restore request [NUT-13]
    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, Error>;

    /// Get the auth wallet for the client
    async fn get_auth_wallet(&self) -> Option<AuthWallet>;

    /// Set auth wallet on client
    async fn set_auth_wallet(&self, wallet: Option<AuthWallet>);

    /// Get all conditions [NUT-CTF]
    #[cfg(feature = "conditional-tokens")]
    async fn get_conditions(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        status: &[String],
    ) -> Result<crate::nuts::nut_ctf::GetConditionsResponse, Error>;

    /// Get a specific condition [NUT-CTF]
    #[cfg(feature = "conditional-tokens")]
    async fn get_condition(
        &self,
        condition_id: &str,
    ) -> Result<crate::nuts::nut_ctf::ConditionInfo, Error>;

    /// Register a condition [NUT-CTF]
    #[cfg(feature = "conditional-tokens")]
    async fn post_register_condition(
        &self,
        request: crate::nuts::nut_ctf::RegisterConditionRequest,
    ) -> Result<crate::nuts::nut_ctf::RegisterConditionResponse, Error>;

    /// Get conditional keysets through the legacy raw-listing contract [NUT-CTF].
    #[cfg(feature = "conditional-tokens")]
    async fn get_conditional_keysets(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
    ) -> Result<crate::nuts::nut_ctf::ConditionalKeysetsResponse, Error>;

    /// Get one capability-gated authenticated catalogue page [NUT-CTF].
    #[cfg(feature = "conditional-tokens")]
    async fn get_conditional_keysets_page(
        &self,
        request: crate::nuts::nut_ctf::GetConditionalKeysetsRequest,
    ) -> Result<crate::nuts::nut_ctf::ConditionalKeysetsResponse, Error> {
        let _ = request;
        Err(Error::InvalidConditionalKeysetCatalogueResponse(
            "strict conditional-keyset catalogue is unsupported by this connector".to_string(),
        ))
    }

    /// CTF convert [NUT-CTF-split-merge]
    #[cfg(feature = "conditional-tokens")]
    async fn post_ctf_convert(
        &self,
        request: crate::nuts::nut_ctf::CtfConvertRequest,
    ) -> Result<crate::nuts::nut_ctf::CtfConvertResponse, Error>;

    /// Redeem outcome [NUT-CTF]
    #[cfg(feature = "conditional-tokens")]
    async fn post_redeem_outcome(
        &self,
        request: crate::nuts::nut_ctf::RedeemOutcomeRequest,
    ) -> Result<crate::nuts::nut_ctf::RedeemOutcomeResponse, Error>;
}
