//! Wallet-side CTF (Conditional Token Framework) operations

use cdk_common::nuts::nut_ctf::{
    ConditionInfo, ConditionalKeysetsResponse, CtfConvertRequest, CtfConvertResponse,
    GetConditionalKeysetsRequest, GetConditionsResponse, RedeemOutcomeRequest,
    RedeemOutcomeResponse, RegisterConditionRequest, RegisterConditionResponse,
};
use tracing::instrument;

use super::Wallet;
use super::{
    validate_conditional_keyset_catalogue_request, validate_conditional_keyset_catalogue_response,
};
use crate::error::Error;

impl Wallet {
    /// Get all conditions from the mint
    ///
    /// Supports cursor-based pagination via `since`+`limit` and repeatable `status` filter.
    #[instrument(skip(self))]
    pub async fn get_conditions(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        status: &[String],
    ) -> Result<GetConditionsResponse, Error> {
        self.client.get_conditions(since, limit, status).await
    }

    /// Get a specific condition from the mint
    #[instrument(skip(self))]
    pub async fn get_condition(&self, condition_id: &str) -> Result<ConditionInfo, Error> {
        self.client.get_condition(condition_id).await
    }

    /// Register a new condition on the mint
    #[instrument(skip(self, request))]
    pub async fn register_condition(
        &self,
        request: RegisterConditionRequest,
    ) -> Result<RegisterConditionResponse, Error> {
        self.client.post_register_condition(request).await
    }

    /// Get all conditional keysets from the mint
    ///
    /// Supports cursor-based pagination via `since`+`limit` and `active` filter.
    #[instrument(skip(self))]
    pub async fn get_conditional_keysets(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
    ) -> Result<ConditionalKeysetsResponse, Error> {
        self.client
            .get_conditional_keysets(since, limit, active)
            .await
    }

    /// Get one authenticated page from an immutable conditional-keyset catalogue snapshot.
    #[instrument(skip(self))]
    #[allow(dead_code)] // Consumed by the recovery path in the next plan slice.
    pub(crate) async fn get_conditional_keysets_page(
        &self,
        mut request: GetConditionalKeysetsRequest,
    ) -> Result<ConditionalKeysetsResponse, Error> {
        let capability = self
            .load_mint_info()
            .await?
            .nuts
            .nut_ctf
            .and_then(|settings| settings.conditional_keyset_catalogue)
            .ok_or_else(|| {
                Error::InvalidConditionalKeysetCatalogueResponse(
                    "mint did not advertise authenticated catalogue recovery".to_string(),
                )
            })?;
        request.catalogue_version = Some(capability.version);
        if request.limit.is_none() {
            request.limit = Some(capability.max_page_size);
        }
        validate_conditional_keyset_catalogue_request(&request, capability.max_page_size)?;
        let mut response = self
            .client
            .get_conditional_keysets_page(request.clone())
            .await?;
        validate_conditional_keyset_catalogue_response(
            &request,
            &mut response,
            capability.max_page_size,
        )?;
        Ok(response)
    }

    /// Convert conditional/collateral positions.
    #[instrument(skip(self, request))]
    pub async fn ctf_convert(
        &self,
        request: CtfConvertRequest,
    ) -> Result<CtfConvertResponse, Error> {
        self.client.post_ctf_convert(request).await
    }

    /// Redeem winning conditional tokens for regular tokens
    #[instrument(skip(self, request))]
    pub async fn redeem_outcome(
        &self,
        request: RedeemOutcomeRequest,
    ) -> Result<RedeemOutcomeResponse, Error> {
        self.client.post_redeem_outcome(request).await
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use crate::nuts::nut_ctf::{
        ConditionalKeySetInfo, ConditionalKeysetCatalogueSettings, NutCtfSettings,
    };
    use crate::nuts::Id;
    use crate::wallet::test_utils::{create_test_wallet_with_mock, MockMintConnector};

    use super::*;

    fn catalogue_keyset() -> ConditionalKeySetInfo {
        ConditionalKeySetInfo {
            id: Id::from_str("00916bbf7ef91a36").expect("keyset id should parse"),
            unit: "sat".to_string(),
            active: false,
            input_fee_ppk: Some(0),
            final_expiry: None,
            condition_id: "11".repeat(32),
            outcome_collection: "YES".to_string(),
            outcome_collection_id: "22".repeat(32),
            registered_at: 1_000,
        }
    }

    fn advertise_catalogue(mock: &MockMintConnector, version: u8, max_page_size: u64) {
        let mut info = mock.mint_info.lock().expect("mint info lock");
        info.nuts.nut_ctf = Some(NutCtfSettings {
            conditional_keyset_catalogue: Some(ConditionalKeysetCatalogueSettings {
                version,
                max_page_size,
            }),
            ..Default::default()
        });
    }

    #[tokio::test]
    async fn custom_connector_response_is_validated_before_identical_deduplication() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock, 1, 100);
        let keyset = catalogue_keyset();
        mock.set_conditional_keyset_page_response(Ok(ConditionalKeysetsResponse {
            keysets: vec![keyset.clone(), keyset],
            next_cursor: None,
            complete: true,
        }));
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("wallet database should open"),
            ),
            mock,
        )
        .await;

        assert!(matches!(
            wallet
                .get_conditional_keysets_page(GetConditionalKeysetsRequest {
                    limit: Some(1),
                    ..Default::default()
                })
                .await,
            Err(Error::InvalidConditionalKeysetCatalogueResponse(_))
        ));
    }

    #[tokio::test]
    async fn wallet_rejects_unsupported_catalogue_capability_before_connector_call() {
        let mock = Arc::new(MockMintConnector::new());
        advertise_catalogue(&mock, 2, 101);
        let wallet = create_test_wallet_with_mock(
            Arc::new(
                cdk_sqlite::wallet::memory::empty()
                    .await
                    .expect("wallet database should open"),
            ),
            mock,
        )
        .await;

        assert!(matches!(
            wallet
                .get_conditional_keysets_page(GetConditionalKeysetsRequest::default())
                .await,
            Err(Error::InvalidConditionalKeysetCatalogueResponse(_))
        ));
    }
}
