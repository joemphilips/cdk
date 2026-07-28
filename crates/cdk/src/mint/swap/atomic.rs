#[cfg(feature = "conditional-tokens")]
use std::collections::HashSet;
#[cfg(feature = "conditional-tokens")]
use std::ops::Range;
#[cfg(feature = "conditional-tokens")]
use std::sync::{Arc, Mutex, MutexGuard};

use cdk_common::database::mint::Acquired;
use cdk_common::database::{self, DynMintTransaction};
use cdk_common::mint::{Operation, OperationKind, ProofsWithState};
use cdk_common::nuts::{BlindSignature, BlindedMessage};
use cdk_common::{Error, Proofs, ProofsMethods, PublicKey, State};
use uuid::Uuid;

#[cfg(feature = "conditional-tokens")]
use super::super::conditions::STATUS_PENDING;
use super::super::{Mint, Verification};
use crate::fees::ProofsFeeBreakdown;
#[cfg(feature = "conditional-tokens")]
use cdk_common::nuts::nut_ctf::settlement::{CanonicalHash, CtfSettlementResponse};

/// Controls how preparation verifies a swap's balance.
pub(super) enum BalanceCheck {
    /// Full NUT-03 balance verification.
    Full,
    /// Unit equality only; CTF conversion validates payoff conservation separately.
    #[cfg(feature = "conditional-tokens")]
    UnitEqualityOnly,
}

/// Immutable data prepared before a swap persistence transaction begins.
pub(super) struct PreparedSwap {
    pub(super) operation: Operation,
    pub(super) fee_breakdown: ProofsFeeBreakdown,
}

#[cfg(feature = "conditional-tokens")]
struct PreparedAtomicCtf {
    swap: PreparedSwap,
    signatures: Vec<BlindSignature>,
    input_ys: Vec<PublicKey>,
    blinded_secrets: Vec<PublicKey>,
    _input_reservation: CtfInputReservation,
}

#[cfg(feature = "conditional-tokens")]
impl PreparedAtomicCtf {
    async fn new(
        mint: &Mint,
        input_proofs: &Proofs,
        blinded_messages: &[BlindedMessage],
        input_verification: Verification,
    ) -> Result<Self, Error> {
        let input_ys = canonical_input_ys(input_proofs)?;
        let input_reservation = CtfInputReservation::acquire(mint, input_ys.clone())?;
        reject_persisted_inputs(mint, &input_ys).await?;
        let swap = prepare_swap(
            mint,
            Uuid::now_v7(),
            input_proofs,
            blinded_messages,
            input_verification,
            BalanceCheck::UnitEqualityOnly,
        )
        .await?;
        let signatures = mint.blind_sign(blinded_messages.to_vec()).await?;
        let blinded_secrets = blinded_messages
            .iter()
            .map(|message| message.blinded_secret)
            .collect();
        Ok(Self {
            swap,
            signatures,
            input_ys,
            blinded_secrets,
            _input_reservation: input_reservation,
        })
    }

    async fn from_verified_settlement(
        mint: &Mint,
        input_proofs: &Proofs,
        blinded_messages: &[BlindedMessage],
        input_verification: Verification,
        output_verification: Verification,
        fee_breakdown: ProofsFeeBreakdown,
    ) -> Result<Self, Error> {
        let input_ys = canonical_input_ys(input_proofs)?;
        let input_reservation = CtfInputReservation::acquire(mint, input_ys.clone())?;
        reject_persisted_inputs(mint, &input_ys).await?;
        let operation = Operation::new(
            Uuid::now_v7(),
            OperationKind::Swap,
            output_verification.amount.into(),
            input_verification.amount.into(),
            fee_breakdown.total,
            None,
            None,
        );
        let signatures = mint.blind_sign(blinded_messages.to_vec()).await?;
        let blinded_secrets = blinded_messages
            .iter()
            .map(|message| message.blinded_secret)
            .collect();
        Ok(Self {
            swap: PreparedSwap {
                operation,
                fee_breakdown,
            },
            signatures,
            input_ys,
            blinded_secrets,
            _input_reservation: input_reservation,
        })
    }
}

#[cfg(feature = "conditional-tokens")]
struct CtfInputReservation {
    shared: Arc<Mutex<HashSet<PublicKey>>>,
    input_ys: Vec<PublicKey>,
}

#[cfg(feature = "conditional-tokens")]
impl CtfInputReservation {
    fn acquire(mint: &Mint, input_ys: Vec<PublicKey>) -> Result<Self, Error> {
        let shared = Arc::clone(&mint.ctf_input_reservations);
        {
            let mut reservations = lock_reservations(&shared);
            if input_ys.iter().any(|y| reservations.contains(y)) {
                return Err(Error::TokenPending);
            }
            reservations.extend(input_ys.iter().copied());
        }
        Ok(Self { shared, input_ys })
    }
}

#[cfg(feature = "conditional-tokens")]
impl Drop for CtfInputReservation {
    fn drop(&mut self) {
        let mut reservations = lock_reservations(&self.shared);
        for y in &self.input_ys {
            reservations.remove(y);
        }
    }
}

#[cfg(feature = "conditional-tokens")]
fn lock_reservations(
    reservations: &Mutex<HashSet<PublicKey>>,
) -> MutexGuard<'_, HashSet<PublicKey>> {
    match reservations.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(feature = "conditional-tokens")]
fn canonical_input_ys(input_proofs: &Proofs) -> Result<Vec<PublicKey>, Error> {
    let mut input_ys = input_proofs.ys()?;
    input_ys.sort_unstable_by_key(PublicKey::to_bytes);
    input_ys.dedup();
    Ok(input_ys)
}

#[cfg(feature = "conditional-tokens")]
async fn reject_persisted_inputs(mint: &Mint, input_ys: &[PublicKey]) -> Result<(), Error> {
    for state in mint.localstore().get_proofs_states(input_ys).await? {
        match state {
            Some(State::Spent) => return Err(Error::TokenAlreadySpent),
            Some(_) => return Err(Error::TokenPending),
            None => {}
        }
    }
    Ok(())
}

/// One-shot deterministic pause used by atomic CTF race tests.
#[cfg(all(test, feature = "conditional-tokens"))]
#[derive(Default)]
pub(in crate::mint) struct AtomicCtfTestPause {
    gate: tokio::sync::Mutex<Option<AtomicCtfTestGate>>,
}

#[cfg(all(test, feature = "conditional-tokens"))]
struct AtomicCtfTestGate {
    reached: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

#[cfg(all(test, feature = "conditional-tokens"))]
impl AtomicCtfTestPause {
    async fn arm(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.gate.lock().await = Some(AtomicCtfTestGate {
            reached: reached_tx,
            release: release_rx,
        });
        (reached_rx, release_tx)
    }

    async fn pause_if_armed(&self) {
        let gate = self.gate.lock().await.take();
        if let Some(gate) = gate {
            let _ = gate.reached.send(());
            let _ = gate.release.await;
        }
    }
}

#[cfg(all(test, feature = "conditional-tokens"))]
impl Mint {
    /// Arm the one-shot pause immediately before the CTF persistence transaction.
    pub(crate) async fn arm_atomic_ctf_test_pause(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.atomic_ctf_test_pause.arm().await
    }
}

/// Perform reusable verification and accounting outside a persistence transaction.
pub(super) async fn prepare_swap(
    mint: &Mint,
    operation_id: Uuid,
    input_proofs: &Proofs,
    blinded_messages: &[BlindedMessage],
    input_verification: Verification,
    balance_check: BalanceCheck,
) -> Result<PreparedSwap, Error> {
    let output_verification = mint.verify_outputs(blinded_messages)?;
    match balance_check {
        BalanceCheck::Full => {
            mint.verify_transaction_balanced(
                input_verification.clone(),
                output_verification.clone(),
                input_proofs,
            )
            .await?;
        }
        #[cfg(feature = "conditional-tokens")]
        BalanceCheck::UnitEqualityOnly => {
            if output_verification.amount.unit() != input_verification.amount.unit() {
                return Err(Error::UnitMismatch);
            }
        }
    }

    let fee_breakdown = mint.get_proofs_fee(input_proofs).await?;
    let operation = Operation::new(
        operation_id,
        OperationKind::Swap,
        output_verification.amount.into(),
        input_verification.amount.into(),
        fee_breakdown.total,
        None,
        None,
    );
    Ok(PreparedSwap {
        operation,
        fee_breakdown,
    })
}

/// Persist the common final state of a prepared swap in the caller's transaction.
pub(super) async fn persist_swap_completion(
    tx: &mut DynMintTransaction,
    input_proofs: &mut Acquired<ProofsWithState>,
    blinded_secrets: &[PublicKey],
    signatures: &[BlindSignature],
    operation: &Operation,
    fee_breakdown: &ProofsFeeBreakdown,
) -> Result<(), Error> {
    fail_if_requested("ADD_SIGNATURES")?;
    tx.add_blind_signatures(blinded_secrets, signatures, None)
        .await?;

    fail_if_requested("UPDATE_PROOFS")?;
    Mint::update_proofs_state(tx, input_proofs, State::Spent).await?;
    fail_if_requested("ADD_COMPLETED_OPERATION")?;
    tx.add_completed_operation(operation, &fee_breakdown.per_keyset)
        .await?;
    Ok(())
}

/// Prepare, sign, and atomically persist one CTF conversion.
#[cfg(feature = "conditional-tokens")]
pub(in crate::mint) async fn execute_atomic_ctf_convert(
    mint: &Mint,
    condition_id: &str,
    input_proofs: &Proofs,
    blinded_messages: &[BlindedMessage],
    input_verification: Verification,
) -> Result<Vec<BlindSignature>, Error> {
    let prepared =
        PreparedAtomicCtf::new(mint, input_proofs, blinded_messages, input_verification).await?;
    #[cfg(test)]
    mint.atomic_ctf_test_pause.pause_if_armed().await;

    let mut tx = mint.localstore().begin_transaction().await?;
    let result = persist_atomic_ctf_transaction(
        &mut tx,
        AtomicCtfCommit {
            condition_id,
            input_proofs,
            blinded_messages,
            blinded_secrets: &prepared.blinded_secrets,
            signatures: &prepared.signatures,
            prepared: &prepared.swap,
        },
    )
    .await;
    if let Err(error) = result {
        tx.rollback().await?;
        return Err(error);
    }
    tx.commit().await?;

    let pubsub = mint.pubsub_manager();
    for y in prepared.input_ys {
        pubsub.proof_state((y, State::Spent));
    }
    Ok(prepared.signatures)
}

/// Prepare, sign, and atomically persist one multi-party CTF settlement.
#[cfg(feature = "conditional-tokens")]
pub(in crate::mint) async fn execute_atomic_ctf_settlement(
    mint: &Mint,
    condition_id: &str,
    request_digest: CanonicalHash,
    input_proofs: &Proofs,
    blinded_messages: &[BlindedMessage],
    participant_output_ranges: &[Range<usize>],
    input_verification: Verification,
    output_verification: Verification,
    fee_breakdown: ProofsFeeBreakdown,
) -> Result<CtfSettlementResponse, Error> {
    if let Some(response) = mint
        .localstore()
        .get_ctf_settlement_replay(request_digest)
        .await?
    {
        return Ok(response);
    }

    let canonical_inputs = canonical_input_proofs(input_proofs)?;
    let prepared = PreparedAtomicCtf::from_verified_settlement(
        mint,
        &canonical_inputs,
        blinded_messages,
        input_verification,
        output_verification,
        fee_breakdown,
    )
    .await?;
    let response = grouped_settlement_response(&prepared.signatures, participant_output_ranges)?;
    #[cfg(test)]
    mint.atomic_ctf_test_pause.pause_if_armed().await;

    finish_atomic_ctf_settlement(
        mint,
        condition_id,
        request_digest,
        &canonical_inputs,
        blinded_messages,
        prepared,
        response,
    )
    .await
}

#[cfg(feature = "conditional-tokens")]
async fn finish_atomic_ctf_settlement(
    mint: &Mint,
    condition_id: &str,
    request_digest: CanonicalHash,
    input_proofs: &Proofs,
    blinded_messages: &[BlindedMessage],
    prepared: PreparedAtomicCtf,
    response: CtfSettlementResponse,
) -> Result<CtfSettlementResponse, Error> {
    let mut tx = mint.localstore().begin_transaction().await?;
    let outcome = persist_atomic_ctf_settlement_transaction(
        &mut tx,
        AtomicCtfCommit {
            condition_id,
            input_proofs,
            blinded_messages,
            blinded_secrets: &prepared.blinded_secrets,
            signatures: &prepared.signatures,
            prepared: &prepared.swap,
        },
        request_digest,
        &response,
    )
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            tx.rollback().await?;
            return Err(error);
        }
    };
    tx.commit().await?;

    if matches!(&outcome, AtomicSettlementOutcome::Committed) {
        let pubsub = mint.pubsub_manager();
        for y in prepared.input_ys {
            pubsub.proof_state((y, State::Spent));
        }
    }
    Ok(match outcome {
        AtomicSettlementOutcome::Committed => response,
        AtomicSettlementOutcome::Replayed(response) => response,
    })
}

#[cfg(feature = "conditional-tokens")]
fn canonical_input_proofs(input_proofs: &Proofs) -> Result<Proofs, Error> {
    let mut keyed = input_proofs
        .iter()
        .cloned()
        .map(|proof| Ok((proof.y()?.to_bytes(), proof)))
        .collect::<Result<Vec<_>, Error>>()?;
    keyed.sort_unstable_by_key(|entry| entry.0);
    Ok(keyed.into_iter().map(|(_, proof)| proof).collect())
}

#[cfg(feature = "conditional-tokens")]
struct AtomicCtfCommit<'a> {
    condition_id: &'a str,
    input_proofs: &'a Proofs,
    blinded_messages: &'a [BlindedMessage],
    blinded_secrets: &'a [PublicKey],
    signatures: &'a [BlindSignature],
    prepared: &'a PreparedSwap,
}

#[cfg(feature = "conditional-tokens")]
async fn persist_atomic_ctf_transaction(
    tx: &mut DynMintTransaction,
    commit: AtomicCtfCommit<'_>,
) -> Result<(), Error> {
    acquire_pending_condition(tx, commit.condition_id).await?;
    persist_atomic_ctf_body(tx, commit).await
}

#[cfg(feature = "conditional-tokens")]
async fn persist_atomic_ctf_body(
    tx: &mut DynMintTransaction,
    commit: AtomicCtfCommit<'_>,
) -> Result<(), Error> {
    let mut input_proofs = tx
        .add_proofs(
            commit.input_proofs.clone(),
            None,
            &commit.prepared.operation,
        )
        .await
        .map_err(map_input_persistence_error)?;
    tx.add_blinded_messages(None, commit.blinded_messages, &commit.prepared.operation)
        .await
        .map_err(map_output_persistence_error)?;
    persist_swap_completion(
        tx,
        &mut input_proofs,
        commit.blinded_secrets,
        commit.signatures,
        &commit.prepared.operation,
        &commit.prepared.fee_breakdown,
    )
    .await
}

#[cfg(feature = "conditional-tokens")]
enum AtomicSettlementOutcome {
    Committed,
    Replayed(CtfSettlementResponse),
}

#[cfg(feature = "conditional-tokens")]
async fn persist_atomic_ctf_settlement_transaction(
    tx: &mut DynMintTransaction,
    commit: AtomicCtfCommit<'_>,
    request_digest: CanonicalHash,
    response: &CtfSettlementResponse,
) -> Result<AtomicSettlementOutcome, Error> {
    if let Some(replay) = tx.get_ctf_settlement_replay(request_digest).await? {
        return Ok(AtomicSettlementOutcome::Replayed(replay));
    }

    let condition = tx
        .get_condition_for_update(commit.condition_id)
        .await?
        .ok_or(Error::ConditionNotFound)?;
    if let Some(replay) = tx.get_ctf_settlement_replay(request_digest).await? {
        return Ok(AtomicSettlementOutcome::Replayed(replay));
    }
    if condition.attestation_status != STATUS_PENDING {
        return Err(Error::ConvertNotPermitted);
    }

    let operation_id = *commit.prepared.operation.id();
    persist_atomic_ctf_body(tx, commit).await?;
    fail_if_requested("ADD_CTF_SETTLEMENT_REPLAY")?;
    tx.add_ctf_settlement_replay(request_digest, &operation_id, response)
        .await?;
    Ok(AtomicSettlementOutcome::Committed)
}

#[cfg(feature = "conditional-tokens")]
async fn acquire_pending_condition(
    tx: &mut DynMintTransaction,
    condition_id: &str,
) -> Result<(), Error> {
    let condition = tx
        .get_condition_for_update(condition_id)
        .await?
        .ok_or(Error::ConditionNotFound)?;
    if condition.attestation_status != STATUS_PENDING {
        return Err(Error::ConvertNotPermitted);
    }
    Ok(())
}

#[cfg(feature = "conditional-tokens")]
fn grouped_settlement_response(
    signatures: &[BlindSignature],
    ranges: &[Range<usize>],
) -> Result<CtfSettlementResponse, Error> {
    let grouped = ranges
        .iter()
        .map(|range| {
            signatures
                .get(range.clone())
                .map(<[BlindSignature]>::to_vec)
                .ok_or(Error::Internal)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ranges
        .last()
        .is_none_or(|range| range.end != signatures.len())
    {
        return Err(Error::Internal);
    }
    Ok(CtfSettlementResponse {
        signatures: grouped,
    })
}

#[cfg(feature = "conditional-tokens")]
fn map_input_persistence_error(error: database::Error) -> Error {
    match error {
        database::Error::Duplicate => Error::TokenPending,
        database::Error::AttemptUpdateSpentProof => Error::TokenAlreadySpent,
        other => Error::Database(other),
    }
}

#[cfg(feature = "conditional-tokens")]
fn map_output_persistence_error(error: database::Error) -> Error {
    match error {
        database::Error::Duplicate => Error::DuplicateOutputs,
        other => Error::Database(other),
    }
}

fn fail_if_requested(operation: &str) -> Result<(), Error> {
    #[cfg(test)]
    if crate::test_helpers::mint::should_fail_for(operation) {
        return Err(Error::Database(database::Error::Database(
            format!("Test failure: {operation}").into(),
        )));
    }
    #[cfg(not(test))]
    let _ = operation;
    Ok(())
}
