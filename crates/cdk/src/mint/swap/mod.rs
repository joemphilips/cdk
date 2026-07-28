#[cfg(feature = "conditional-tokens")]
use cdk_common::nuts::nut_ctf::settlement::{
    verify_pay_to_unlock_refund, Error as SettlementError,
};
#[cfg(feature = "conditional-tokens")]
use cdk_common::util::unix_time;
use cdk_common::SpendingConditionVerification;
use swap_saga::SwapSaga;
use tracing::instrument;

use super::{Mint, SwapRequest, SwapResponse};
use crate::Error;

#[cfg(feature = "conditional-tokens")]
#[derive(Clone, PartialEq, Eq)]
enum RefundAssetClass {
    Regular,
    Conditional {
        condition_id: String,
        outcome_collection_id: String,
    },
}

pub(in crate::mint) mod atomic;
pub mod swap_saga;

#[cfg(test)]
mod tests;

impl Mint {
    /// Process Swap
    #[instrument(skip_all)]
    pub async fn process_swap_request(
        &self,
        swap_request: SwapRequest,
    ) -> Result<SwapResponse, Error> {
        #[cfg(feature = "prometheus")]
        let metrics = super::MintMetricGuard::new("process_swap_request");

        let result = async {
            swap_request.input_amount()?;
            swap_request.output_amount()?;

            let input_proofs = swap_request.inputs();

            if input_proofs.is_empty() {
                return Err(Error::TransactionUnbalanced(
                    0,
                    swap_request.output_amount()?.to_u64(),
                    0,
                ));
            }

            let outputs_count = swap_request.outputs().len();
            if outputs_count > self.max_outputs {
                tracing::warn!(
                    "Swap request exceeds max outputs limit: {} > {}",
                    outputs_count,
                    self.max_outputs
                );
                return Err(Error::MaxOutputsExceeded {
                    actual: outputs_count,
                    max: self.max_outputs,
                });
            }

            // Conditional tokens may be refreshed or transferred through NUT-03
            // only within one condition outcome collection. Conditional-to-regular
            // conversion remains exclusive to the oracle-witness redemption path.
            #[cfg(feature = "conditional-tokens")]
            {
                let mut conditional_input: Option<(String, String)> = None;
                let mut saw_regular_input = false;
                let mut input_keysets: Vec<String> = Vec::new();
                let mut input_collections: Vec<String> = Vec::new();

                for proof in input_proofs {
                    input_keysets.push(proof.keyset_id.to_string());
                    match self
                        .localstore
                        .get_condition_for_keyset(&proof.keyset_id)
                        .await?
                    {
                        Some((condition_id, _outcome_collection, outcome_collection_id)) => {
                            let current = (condition_id, outcome_collection_id);
                            if conditional_input
                                .as_ref()
                                .is_some_and(|expected| expected != &current)
                            {
                                tracing::debug!(
                                    input_keysets = ?input_keysets,
                                    input_collections = ?input_collections,
                                    offending_keyset = %proof.keyset_id,
                                    offending_collection = ?current,
                                    "Rejecting conditional swap: inputs use different conditional keysets"
                                );
                                return Err(Error::InputsMustUseSameConditionalKeyset);
                            }
                            input_collections.push(format!("{}:{}", current.0, current.1));
                            conditional_input = Some(current);
                        }
                        None => saw_regular_input = true,
                    }
                }

                if let Some(expected) = conditional_input {
                    if saw_regular_input {
                        tracing::debug!(
                            input_keysets = ?input_keysets,
                            input_collections = ?input_collections,
                            expected_collection = ?expected,
                            "Rejecting conditional swap: conditional and regular inputs were mixed"
                        );
                        return Err(Error::InputsMustUseSameConditionalKeyset);
                    }

                    let mut output_keysets: Vec<String> = Vec::new();
                    let mut output_collections: Vec<String> = Vec::new();
                    for output in swap_request.outputs() {
                        output_keysets.push(output.keyset_id.to_string());
                        match self
                            .localstore
                            .get_condition_for_keyset(&output.keyset_id)
                            .await?
                        {
                            Some((
                                ref condition_id,
                                _outcome_collection,
                                ref outcome_collection_id,
                            )) if condition_id == &expected.0
                                && outcome_collection_id == &expected.1 =>
                            {
                                output_collections
                                    .push(format!("{}:{}", condition_id, outcome_collection_id));
                            }
                            other => {
                                tracing::debug!(
                                    input_keysets = ?input_keysets,
                                    input_collections = ?input_collections,
                                    output_keysets = ?output_keysets,
                                    output_collections = ?output_collections,
                                    offending_output_keyset = %output.keyset_id,
                                    offending_output_collection = ?other,
                                    expected_collection = ?expected,
                                    "Rejecting conditional swap: output keyset does not match conditional inputs"
                                );
                                return Err(Error::InputsMustUseSameConditionalKeyset);
                            }
                        }
                    }
                }
            }

            // Verify inputs (cryptographic verification, no DB needed)
            let input_verification = self.verify_inputs(input_proofs).await.map_err(|err| {
                tracing::debug!("Input verification failed: {:?}", err);
                err
            })?;

            #[cfg(feature = "conditional-tokens")]
            let is_pay_to_unlock_refund = verify_pay_to_unlock_refund(&swap_request, unix_time())
                .map_err(map_pay_to_unlock_refund_error)?;
            #[cfg(feature = "conditional-tokens")]
            if is_pay_to_unlock_refund {
                self.verify_pay_to_unlock_refund_class(&swap_request)
                    .await?;
            }

            // Verify spending conditions (NUT-10/NUT-11/NUT-14), i.e. P2PK
            // and HTLC (including SIGALL)
            #[cfg(feature = "conditional-tokens")]
            if !is_pay_to_unlock_refund {
                swap_request.verify_spending_conditions()?;
            }
            #[cfg(not(feature = "conditional-tokens"))]
            swap_request.verify_spending_conditions()?;

            // Step 1: Initialize the swap saga
            let init_saga =
                SwapSaga::new(self, self.localstore.clone(), self.pubsub_manager.clone());

            // Step 2: TX1 - Setup swap (verify balance + add inputs as pending + add output blinded messages)
            let setup_saga = init_saga
                .setup_swap(
                    swap_request.inputs(),
                    swap_request.outputs(),
                    None,
                    input_verification,
                )
                .await?;

            // Step 3: Blind sign outputs (no DB transaction)
            let signed_saga = setup_saga.sign_outputs().await?;

            // Step 4: TX2 - Finalize swap (add signatures + mark inputs spent)
            let response = signed_saga.finalize().await?;

            Ok(response)
        }
        .await;

        #[cfg(feature = "prometheus")]
        {
            metrics.record(result.is_ok());
        }

        result
    }

    #[cfg(feature = "conditional-tokens")]
    async fn verify_pay_to_unlock_refund_class(&self, request: &SwapRequest) -> Result<(), Error> {
        let first_input = request
            .inputs()
            .first()
            .ok_or(Error::PayToUnlockInvalidCondition)?;
        let expected = self.refund_asset_class(&first_input.keyset_id).await?;
        for input in request.inputs().iter().skip(1) {
            if self.refund_asset_class(&input.keyset_id).await? != expected {
                return Err(Error::PayToUnlockInvalidCondition);
            }
        }
        for output in request.outputs() {
            if self.refund_asset_class(&output.keyset_id).await? != expected {
                return Err(Error::PayToUnlockInvalidCondition);
            }
        }
        Ok(())
    }

    #[cfg(feature = "conditional-tokens")]
    async fn refund_asset_class(
        &self,
        keyset_id: &cdk_common::nuts::Id,
    ) -> Result<RefundAssetClass, Error> {
        Ok(
            match self.localstore.get_condition_for_keyset(keyset_id).await? {
                Some((condition_id, _outcome_collection, outcome_collection_id)) => {
                    RefundAssetClass::Conditional {
                        condition_id,
                        outcome_collection_id,
                    }
                }
                None => RefundAssetClass::Regular,
            },
        )
    }
}

#[cfg(feature = "conditional-tokens")]
fn map_pay_to_unlock_refund_error(error: SettlementError) -> Error {
    match error {
        SettlementError::RefundBeforeExpiry => Error::RefundBeforeExpiry,
        SettlementError::RefundWitnessMissingOrInvalid => Error::RefundWitnessMissingOrInvalid,
        _ => Error::PayToUnlockInvalidCondition,
    }
}
