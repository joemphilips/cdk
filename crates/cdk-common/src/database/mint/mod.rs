//! CDK Database

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use async_trait::async_trait;
use cashu::quote_id::QuoteId;
use cashu::Amount;
#[cfg(feature = "conditional-tokens")]
use zeroize::Zeroizing;

use super::{DbTransactionFinalizer, Error};
#[cfg(feature = "conditional-tokens")]
use crate::mint::StoredCondition;
use crate::mint::{
    self, MeltQuote, MintKeySetInfo, MintQuote as MintMintQuote, Operation, ProofsWithState,
};
use crate::nuts::{
    BlindSignature, BlindedMessage, CurrencyUnit, Id, MeltQuoteState, Proof, Proofs, PublicKey,
    State,
};
use crate::payment::PaymentIdentifier;

mod auth;

#[cfg(feature = "test")]
pub mod test;

pub use auth::{DynMintAuthDatabase, MintAuthDatabase, MintAuthTransaction};

// Re-export KVStore types from shared module for backward compatibility
pub use super::kvstore::{
    validate_kvstore_params, validate_kvstore_string, KVStore, KVStoreDatabase, KVStoreTransaction,
    KVSTORE_NAMESPACE_KEY_ALPHABET, KVSTORE_NAMESPACE_KEY_MAX_LEN,
};

/// A wrapper indicating that a resource has been acquired with a database lock.
///
/// This type is returned by database operations that lock rows for update
/// (e.g., `SELECT ... FOR UPDATE`). It serves as a compile-time marker that
/// the wrapped resource was properly locked before being returned, ensuring
/// that subsequent modifications are safe from race conditions.
///
/// # Usage
///
/// When you need to modify a database record, first acquire it using a locking
/// query method. The returned `Acquired<T>` guarantees the row is locked for
/// the duration of the transaction.
///
/// ```ignore
/// // Acquire a quote with a row lock
/// let mut quote: Acquired<MintQuote> = tx.get_mint_quote_for_update(&quote_id).await?;
///
/// // Safely modify the quote (row is locked)
/// quote.state = QuoteState::Paid;
///
/// // Persist the changes
/// tx.update_mint_quote(&mut quote).await?;
/// ```
///
/// # Deref Behavior
///
/// `Acquired<T>` implements `Deref` and `DerefMut`, allowing transparent access
/// to the inner value's methods and fields.
#[derive(Debug)]
pub struct Acquired<T> {
    inner: T,
}

impl<T> From<T> for Acquired<T> {
    /// Wraps a value to indicate it has been acquired with a lock.
    ///
    /// This is typically called by database layer implementations after
    /// executing a locking query.
    fn from(value: T) -> Self {
        Acquired { inner: value }
    }
}

impl<T> Acquired<T> {
    /// Consumes the wrapper and returns the inner resource.
    ///
    /// Use this when you need to take ownership of the inner value,
    /// for example when passing it to a function that doesn't accept
    /// `Acquired<T>`.
    pub fn inner(self) -> T {
        self.inner
    }
}

impl<T> Deref for Acquired<T> {
    type Target = T;

    /// Returns a reference to the inner resource.
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Acquired<T> {
    /// Returns a mutable reference to the inner resource.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Information about a melt request stored in the database
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeltRequestInfo {
    /// Total amount of all input proofs in the melt request
    pub inputs_amount: Amount<CurrencyUnit>,
    /// Fee amount associated with the input proofs
    pub inputs_fee: Amount<CurrencyUnit>,
    /// Blinded messages for change outputs
    pub change_outputs: Vec<BlindedMessage>,
}

/// Result of locking a melt quote and all related quotes atomically.
///
/// This struct is returned by [`QuotesTransaction::lock_melt_quote_and_related`]
/// and contains both the target quote and all quotes sharing the same `request_lookup_id`.
#[derive(Debug)]
pub struct LockedMeltQuotes {
    /// The target quote that was requested, if found
    pub target: Option<Acquired<MeltQuote>>,
    /// All quotes sharing the same `request_lookup_id` (including the target)
    pub all_related: Vec<Acquired<MeltQuote>>,
}

/// KeysDatabaseWriter
#[async_trait]
pub trait KeysDatabaseTransaction<'a, Error>: DbTransactionFinalizer<Err = Error> {
    /// Add Active Keyset
    async fn set_active_keyset(&mut self, unit: CurrencyUnit, id: Id) -> Result<(), Error>;

    /// Add [`MintKeySetInfo`]
    async fn add_keyset_info(&mut self, keyset: MintKeySetInfo) -> Result<(), Error>;
}

/// Mint Keys Database trait
#[async_trait]
pub trait KeysDatabase {
    /// Mint Keys Database Error
    type Err: Into<Error> + From<Error>;

    /// Begins a transaction
    async fn begin_transaction<'a>(
        &'a self,
    ) -> Result<Box<dyn KeysDatabaseTransaction<'a, Self::Err> + Send + Sync + 'a>, Error>;

    /// Get Active Keyset
    async fn get_active_keyset_id(&self, unit: &CurrencyUnit) -> Result<Option<Id>, Self::Err>;

    /// Get all Active Keyset
    async fn get_active_keysets(&self) -> Result<HashMap<CurrencyUnit, Id>, Self::Err>;

    /// Get [`MintKeySetInfo`]
    async fn get_keyset_info(&self, id: &Id) -> Result<Option<MintKeySetInfo>, Self::Err>;

    /// Get [`MintKeySetInfo`]s
    async fn get_keyset_infos(&self) -> Result<Vec<MintKeySetInfo>, Self::Err>;

    /// Add a conditional keyset row (NUT-CTF) into the dedicated `conditional_keyset` table.
    ///
    /// The `MintKeySetInfo` must have `condition_id`, `outcome_collection`, and
    /// `outcome_collection_id` all set; otherwise the implementation returns an error.
    #[cfg(feature = "conditional-tokens")]
    async fn add_conditional_keyset(
        &self,
        keyset_info: MintKeySetInfo,
        created_at: u64,
    ) -> Result<(), Self::Err> {
        let _ = (keyset_info, created_at);
        Err(
            Error::Internal("add_conditional_keyset not implemented by this backend".to_string())
                .into(),
        )
    }

    /// Load every conditional keyset row from the dedicated table.
    ///
    /// Used by the signatory's `reload_keys_from_db` path to populate the in-memory
    /// signing map for conditional keysets alongside the regular keysets.
    #[cfg(feature = "conditional-tokens")]
    async fn get_all_conditional_mint_keyset_infos(
        &self,
    ) -> Result<Vec<MintKeySetInfo>, Self::Err> {
        Ok(Vec::new())
    }
}

/// Mint Quote Database writer trait
#[async_trait]
pub trait QuotesTransaction {
    /// Mint Quotes Database Error
    type Err: Into<Error> + From<Error>;

    /// Add melt_request with quote_id, inputs_amount, and inputs_fee
    async fn add_melt_request(
        &mut self,
        quote_id: &QuoteId,
        inputs_amount: Amount<CurrencyUnit>,
        inputs_fee: Amount<CurrencyUnit>,
    ) -> Result<(), Self::Err>;

    /// Add blinded_messages for a quote_id
    async fn add_blinded_messages(
        &mut self,
        quote_id: Option<&QuoteId>,
        blinded_messages: &[BlindedMessage],
        operation: &Operation,
    ) -> Result<(), Self::Err>;

    /// Delete blinded_messages by their blinded secrets
    async fn delete_blinded_messages(
        &mut self,
        blinded_secrets: &[PublicKey],
    ) -> Result<(), Self::Err>;

    /// Get melt_request and associated blinded_messages by quote_id
    async fn get_melt_request_and_blinded_messages(
        &mut self,
        quote_id: &QuoteId,
    ) -> Result<Option<MeltRequestInfo>, Self::Err>;

    /// Delete melt_request and associated blinded_messages by quote_id
    async fn delete_melt_request(&mut self, quote_id: &QuoteId) -> Result<(), Self::Err>;

    /// Get [`MintMintQuote`] and lock it for update in this transaction
    async fn get_mint_quote(
        &mut self,
        quote_id: &QuoteId,
    ) -> Result<Option<Acquired<MintMintQuote>>, Self::Err>;

    /// Get multiple [`MintMintQuote`]s by their IDs and lock them for update in this transaction.
    ///
    /// Returns results in the same order as the input IDs, with `None` for any IDs not found.
    /// This method locks all found quotes to prevent race conditions during concurrent modifications.
    async fn get_mint_quotes_by_ids(
        &mut self,
        quote_ids: &[QuoteId],
    ) -> Result<Vec<Option<Acquired<MintMintQuote>>>, Self::Err>;

    /// Add [`MintMintQuote`]
    async fn add_mint_quote(
        &mut self,
        quote: MintMintQuote,
    ) -> Result<Acquired<MintMintQuote>, Self::Err>;

    /// Persists any pending changes made to the mint quote.
    ///
    /// This method extracts changes accumulated in the quote (via [`mint::MintQuote::take_changes`])
    /// and persists them to the database. Changes may include new payments received or new
    /// issuances recorded against the quote.
    ///
    /// If no changes are pending, this method returns successfully without performing
    /// any database operations.
    ///
    /// # Arguments
    ///
    /// * `quote` - A mutable reference to an acquired (row-locked) mint quote. The quote
    ///   must be locked to ensure transactional consistency when persisting changes.
    ///
    /// # Implementation Notes
    ///
    /// Implementations should call [`mint::MintQuote::take_changes`] to retrieve pending
    /// changes, then persist each payment and issuance record, and finally update the
    /// quote's aggregate counters (`amount_paid`, `amount_issued`) in the database.
    async fn update_mint_quote(
        &mut self,
        quote: &mut Acquired<mint::MintQuote>,
    ) -> Result<(), Self::Err>;

    /// Get [`mint::MeltQuote`] and lock it for update in this transaction
    async fn get_melt_quote(
        &mut self,
        quote_id: &QuoteId,
    ) -> Result<Option<Acquired<mint::MeltQuote>>, Self::Err>;

    /// Add [`mint::MeltQuote`]
    async fn add_melt_quote(&mut self, quote: mint::MeltQuote) -> Result<(), Self::Err>;

    /// Retrieves all melt quotes matching a payment lookup identifier and locks them for update.
    ///
    /// This method returns multiple quotes because certain payment methods (notably BOLT12 offers)
    /// can generate multiple payment attempts that share the same lookup identifier. Locking all
    /// related quotes prevents race conditions where concurrent melt operations could interfere
    /// with each other, potentially leading to double-spending or state inconsistencies.
    ///
    /// The returned quotes are locked within the current transaction to ensure safe concurrent
    /// modification. This is essential during melt saga initiation and finalization to guarantee
    /// atomic state transitions across all related quotes.
    ///
    /// # Arguments
    ///
    /// * `request_lookup_id` - The payment identifier used by the Lightning backend to track
    ///   payment state (e.g., payment hash, offer ID, or label).
    async fn get_melt_quotes_by_request_lookup_id(
        &mut self,
        request_lookup_id: &PaymentIdentifier,
    ) -> Result<Vec<Acquired<MeltQuote>>, Self::Err>;

    /// Locks a melt quote and all related quotes sharing the same request_lookup_id atomically.
    ///
    /// This method prevents deadlocks by acquiring all locks in a single query with consistent
    /// ordering, rather than locking the target quote first and then related quotes separately.
    ///
    /// # Deadlock Prevention
    ///
    /// When multiple transactions try to melt quotes sharing the same `request_lookup_id`,
    /// acquiring locks in two steps (first the target quote, then all related quotes) can cause
    /// circular wait deadlocks. This method avoids that by:
    /// 1. Using a subquery to find the `request_lookup_id` for the target quote
    /// 2. Locking ALL quotes with that `request_lookup_id` in one atomic operation
    /// 3. Ordering locks consistently by quote ID
    ///
    /// # Arguments
    ///
    /// * `quote_id` - The ID of the target melt quote
    ///
    /// # Returns
    ///
    /// A [`LockedMeltQuotes`] containing:
    /// - `target`: The target quote (if found)
    /// - `all_related`: All quotes sharing the same `request_lookup_id` (including the target)
    ///
    /// If the quote has no `request_lookup_id`, only the target quote is returned and locked.
    async fn lock_melt_quote_and_related(
        &mut self,
        quote_id: &QuoteId,
    ) -> Result<LockedMeltQuotes, Self::Err>;

    /// Updates the request lookup id for a melt quote.
    ///
    /// Requires an [`Acquired`] melt quote to ensure the row is locked before modification.
    async fn update_melt_quote_request_lookup_id(
        &mut self,
        quote: &mut Acquired<mint::MeltQuote>,
        new_request_lookup_id: &PaymentIdentifier,
    ) -> Result<(), Self::Err>;

    /// Update [`mint::MeltQuote`] state.
    ///
    /// Requires an [`Acquired`] melt quote to ensure the row is locked before modification.
    /// Returns the previous state.
    async fn update_melt_quote_state(
        &mut self,
        quote: &mut Acquired<mint::MeltQuote>,
        new_state: MeltQuoteState,
        payment_proof: Option<String>,
    ) -> Result<MeltQuoteState, Self::Err>;

    /// Get all [`MintMintQuote`]s and lock it for update in this transaction
    async fn get_mint_quote_by_request(
        &mut self,
        request: &str,
    ) -> Result<Option<Acquired<MintMintQuote>>, Self::Err>;

    /// Get all [`MintMintQuote`]s
    async fn get_mint_quote_by_request_lookup_id(
        &mut self,
        request_lookup_id: &PaymentIdentifier,
    ) -> Result<Option<Acquired<MintMintQuote>>, Self::Err>;
}

/// Mint Quote Database trait
#[async_trait]
pub trait QuotesDatabase {
    /// Mint Quotes Database Error
    type Err: Into<Error> + From<Error>;

    /// Get [`MintMintQuote`]
    async fn get_mint_quote(&self, quote_id: &QuoteId) -> Result<Option<MintMintQuote>, Self::Err>;

    /// Get multiple [`MintMintQuote`]s by their IDs.
    ///
    /// Returns results in the same order as the input IDs, with `None` for any IDs not found.
    async fn get_mint_quotes_by_ids(
        &self,
        quote_ids: &[QuoteId],
    ) -> Result<Vec<Option<MintMintQuote>>, Self::Err>;

    /// Get all [`MintMintQuote`]s
    async fn get_mint_quote_by_request(
        &self,
        request: &str,
    ) -> Result<Option<MintMintQuote>, Self::Err>;
    /// Get all [`MintMintQuote`]s
    async fn get_mint_quote_by_request_lookup_id(
        &self,
        request_lookup_id: &PaymentIdentifier,
    ) -> Result<Option<MintMintQuote>, Self::Err>;
    /// Get Mint Quotes
    async fn get_mint_quotes(&self) -> Result<Vec<MintMintQuote>, Self::Err>;
    /// Get [`mint::MeltQuote`]
    async fn get_melt_quote(
        &self,
        quote_id: &QuoteId,
    ) -> Result<Option<mint::MeltQuote>, Self::Err>;
    /// Get all [`mint::MeltQuote`]s
    async fn get_melt_quotes(&self) -> Result<Vec<mint::MeltQuote>, Self::Err>;
}

/// Mint Proof Transaction trait
#[async_trait]
pub trait ProofsTransaction {
    /// Mint Proof Database Error
    type Err: Into<Error> + From<Error>;

    /// Add  [`Proofs`]
    ///
    /// Adds proofs to the database. The database should error if the proof already exits, with a
    /// `AttemptUpdateSpentProof` if the proof is already spent or a `Duplicate` error otherwise.
    async fn add_proofs(
        &mut self,
        proof: Proofs,
        quote_id: Option<QuoteId>,
        operation: &Operation,
    ) -> Result<Acquired<ProofsWithState>, Self::Err>;

    /// Updates the proofs to the given state in the database.
    ///
    /// Also updates the `state` field on the [`ProofsWithState`] wrapper to reflect
    /// the new state after the database update succeeds.
    async fn update_proofs_state(
        &mut self,
        proofs: &mut Acquired<ProofsWithState>,
        new_state: State,
    ) -> Result<(), Self::Err>;

    /// get proofs states
    async fn get_proofs(
        &mut self,
        ys: &[PublicKey],
    ) -> Result<Acquired<ProofsWithState>, Self::Err>;

    /// Remove [`Proofs`]
    async fn remove_proofs(
        &mut self,
        ys: &[PublicKey],
        quote_id: Option<QuoteId>,
    ) -> Result<(), Self::Err>;

    /// Get ys by quote id
    async fn get_proof_ys_by_quote_id(
        &mut self,
        quote_id: &QuoteId,
    ) -> Result<Vec<PublicKey>, Self::Err>;

    /// Get proof ys by operation id
    async fn get_proof_ys_by_operation_id(
        &mut self,
        operation_id: &uuid::Uuid,
    ) -> Result<Vec<PublicKey>, Self::Err>;
}

/// Mint Proof Database trait
#[async_trait]
pub trait ProofsDatabase {
    /// Mint Proof Database Error
    type Err: Into<Error> + From<Error>;

    /// Get [`Proofs`] by ys
    async fn get_proofs_by_ys(&self, ys: &[PublicKey]) -> Result<Vec<Option<Proof>>, Self::Err>;
    /// Get ys by quote id
    async fn get_proof_ys_by_quote_id(
        &self,
        quote_id: &QuoteId,
    ) -> Result<Vec<PublicKey>, Self::Err>;
    /// Get [`Proofs`] state
    async fn get_proofs_states(&self, ys: &[PublicKey]) -> Result<Vec<Option<State>>, Self::Err>;

    /// Get [`Proofs`] by state
    async fn get_proofs_by_keyset_id(
        &self,
        keyset_id: &Id,
    ) -> Result<(Proofs, Vec<Option<State>>), Self::Err>;

    /// Get total proofs redeemed by keyset id
    async fn get_total_redeemed(&self) -> Result<HashMap<Id, Amount>, Self::Err>;

    /// Get proof ys by operation id
    async fn get_proof_ys_by_operation_id(
        &self,
        operation_id: &uuid::Uuid,
    ) -> Result<Vec<PublicKey>, Self::Err>;
}

#[async_trait]
/// Mint Signatures Transaction trait
pub trait SignaturesTransaction {
    /// Mint Signature Database Error
    type Err: Into<Error> + From<Error>;

    /// Add [`BlindSignature`]
    async fn add_blind_signatures(
        &mut self,
        blinded_messages: &[PublicKey],
        blind_signatures: &[BlindSignature],
        quote_id: Option<QuoteId>,
    ) -> Result<(), Self::Err>;

    /// Get [`BlindSignature`]s
    async fn get_blind_signatures(
        &mut self,
        blinded_messages: &[PublicKey],
    ) -> Result<Vec<Option<BlindSignature>>, Self::Err>;
}

#[async_trait]
/// Mint Signatures Database trait
pub trait SignaturesDatabase {
    /// Mint Signature Database Error
    type Err: Into<Error> + From<Error>;

    /// Get [`BlindSignature`]s
    async fn get_blind_signatures(
        &self,
        blinded_messages: &[PublicKey],
    ) -> Result<Vec<Option<BlindSignature>>, Self::Err>;

    /// Get [`BlindSignature`]s for keyset_id
    async fn get_blind_signatures_for_keyset(
        &self,
        keyset_id: &Id,
    ) -> Result<Vec<BlindSignature>, Self::Err>;

    /// Get [`BlindSignature`]s for quote
    async fn get_blind_signatures_for_quote(
        &self,
        quote_id: &QuoteId,
    ) -> Result<Vec<BlindSignature>, Self::Err>;

    /// Get total amount issued by keyset id
    async fn get_total_issued(&self) -> Result<HashMap<Id, Amount>, Self::Err>;

    /// Get blinded secrets (B values) by operation id
    async fn get_blinded_secrets_by_operation_id(
        &self,
        operation_id: &uuid::Uuid,
    ) -> Result<Vec<PublicKey>, Self::Err>;
}

#[async_trait]
/// Saga Transaction trait
pub trait SagaTransaction {
    /// Saga Database Error
    type Err: Into<Error> + From<Error>;

    /// Get saga by operation_id
    async fn get_saga(
        &mut self,
        operation_id: &uuid::Uuid,
    ) -> Result<Option<mint::Saga>, Self::Err>;

    /// Add saga
    async fn add_saga(&mut self, saga: &mint::Saga) -> Result<(), Self::Err>;

    /// Update saga state (only updates state and updated_at fields)
    async fn update_saga(
        &mut self,
        operation_id: &uuid::Uuid,
        new_state: mint::SagaStateEnum,
    ) -> Result<(), Self::Err>;

    /// Update saga state and optional finalization metadata.
    async fn update_saga_with_finalization_data(
        &mut self,
        operation_id: &uuid::Uuid,
        new_state: mint::SagaStateEnum,
        finalization_data: Option<&mint::MeltFinalizationData>,
    ) -> Result<(), Self::Err>;

    /// Delete saga
    async fn delete_saga(&mut self, operation_id: &uuid::Uuid) -> Result<(), Self::Err>;
}

#[async_trait]
/// Saga Database trait
pub trait SagaDatabase {
    /// Saga Database Error
    type Err: Into<Error> + From<Error>;

    /// Get the melt saga associated with a melt quote id
    async fn get_melt_saga_by_quote_id(
        &self,
        quote_id: &QuoteId,
    ) -> Result<Option<mint::Saga>, Self::Err>;

    /// Get all incomplete sagas for a given operation kind
    async fn get_incomplete_sagas(
        &self,
        operation_kind: mint::OperationKind,
    ) -> Result<Vec<mint::Saga>, Self::Err>;
}

#[async_trait]
/// Completed Operations Transaction trait
pub trait CompletedOperationsTransaction {
    /// Completed Operations Database Error
    type Err: Into<Error> + From<Error>;

    /// Add completed operation
    async fn add_completed_operation(
        &mut self,
        operation: &mint::Operation,
        fee_by_keyset: &std::collections::HashMap<crate::nuts::Id, crate::Amount>,
    ) -> Result<(), Self::Err>;
}

#[async_trait]
/// Completed Operations Database trait
pub trait CompletedOperationsDatabase {
    /// Completed Operations Database Error
    type Err: Into<Error> + From<Error>;

    /// Get completed operation by operation_id
    async fn get_completed_operation(
        &self,
        operation_id: &uuid::Uuid,
    ) -> Result<Option<mint::Operation>, Self::Err>;

    /// Get completed operations by operation kind
    async fn get_completed_operations_by_kind(
        &self,
        operation_kind: mint::OperationKind,
    ) -> Result<Vec<mint::Operation>, Self::Err>;

    /// Get all completed operations
    async fn get_completed_operations(&self) -> Result<Vec<mint::Operation>, Self::Err>;
}

/// Conditions Database trait (NUT-CTF)
#[cfg(feature = "conditional-tokens")]
#[async_trait]
pub trait ConditionsTransaction {
    /// Conditions transaction error
    type Err: Into<Error> + From<Error>;

    /// Add a stored condition in the current transaction.
    async fn add_condition(&mut self, condition: StoredCondition) -> Result<(), Self::Err>;

    /// Add a conditional keyset row in the current transaction.
    async fn add_conditional_keyset(
        &mut self,
        keyset_info: MintKeySetInfo,
        created_at: u64,
    ) -> Result<(), Self::Err>;

    /// Add one registration's conditional keysets as one sequence-allocation batch.
    async fn add_conditional_keysets(
        &mut self,
        keysets: Vec<(MintKeySetInfo, u64)>,
    ) -> Result<(), Self::Err> {
        for (keyset, created_at) in keysets {
            self.add_conditional_keyset(keyset, created_at).await?;
        }
        Ok(())
    }
}

/// Authenticated conditional-keyset catalogue protocol version.
#[cfg(feature = "conditional-tokens")]
pub const CONDITIONAL_KEYSET_CATALOGUE_VERSION: u8 = 1;

/// Maximum number of conditional keysets in one catalogue page.
#[cfg(feature = "conditional-tokens")]
pub const MAX_CONDITIONAL_KEYSET_CATALOGUE_PAGE_SIZE: u64 = 100;

/// Maximum encoded length of an authenticated catalogue cursor.
#[cfg(feature = "conditional-tokens")]
pub const MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH: usize = 2_048;

/// Maximum byte length of a wire-visible currency unit.
#[cfg(feature = "conditional-tokens")]
pub const MAX_CONDITIONAL_KEYSET_UNIT_LENGTH: usize = 64;

/// Maximum byte length of one canonical outcome-collection expression.
///
/// A page can contain 100 expressions and JSON escaping can expand every
/// source byte to six bytes (`\\u00xx`). Keeping the field at 16 KiB leaves
/// ample room below the shared hard response cap for all fixed metadata.
#[cfg(feature = "conditional-tokens")]
pub const MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH: usize = 16 * 1_024;

#[cfg(feature = "conditional-tokens")]
const MAX_JSON_ESCAPED_BYTES_PER_INPUT_BYTE: usize = 6;
#[cfg(feature = "conditional-tokens")]
const MAX_CONDITIONAL_KEYSET_JSON_FIXED_OVERHEAD: usize = 4_096;
#[cfg(feature = "conditional-tokens")]
const MAX_CONDITIONAL_KEYSET_RESPONSE_JSON_FIXED_OVERHEAD: usize = 1_024;

#[cfg(feature = "conditional-tokens")]
const MAX_CONDITIONAL_KEYSET_CATALOGUE_DERIVED_RESPONSE_BYTES: usize =
    MAX_CONDITIONAL_KEYSET_CATALOGUE_PAGE_SIZE as usize
        * (MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH
            * MAX_JSON_ESCAPED_BYTES_PER_INPUT_BYTE
            + MAX_CONDITIONAL_KEYSET_JSON_FIXED_OVERHEAD)
        + MAX_CONDITIONAL_KEYSET_CATALOGUE_CURSOR_LENGTH * MAX_JSON_ESCAPED_BYTES_PER_INPUT_BYTE
        + MAX_CONDITIONAL_KEYSET_RESPONSE_JSON_FIXED_OVERHEAD;

/// Hard byte cap shared by catalogue servers and HTTP transports.
///
/// This is derived from the negotiated page count, the canonical field
/// bounds, worst-case six-byte JSON escaping, and a conservative 4 KiB
/// allowance for every item's fixed fields. The compile-time assertion keeps
/// the chosen transport cap above that derived worst case. A mint enforcing
/// the canonical item bounds cannot emit a valid page that a conforming
/// strict HTTP client rejects for size.
#[cfg(feature = "conditional-tokens")]
pub const MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES: usize = 16 * 1_024 * 1_024;

#[cfg(feature = "conditional-tokens")]
const _: () = assert!(
    MAX_CONDITIONAL_KEYSET_CATALOGUE_DERIVED_RESPONSE_BYTES
        <= MAX_CONDITIONAL_KEYSET_CATALOGUE_RESPONSE_BYTES
);

/// Whether a value is the canonical lowercase encoding of a 32-byte hash.
#[cfg(feature = "conditional-tokens")]
pub fn is_canonical_conditional_keyset_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validate the bounded wire/persistence fields shared by registrations,
/// database rows, server responses, and wallet connectors.
#[cfg(feature = "conditional-tokens")]
pub fn validate_conditional_keyset_catalogue_fields(
    unit: &str,
    condition_id: &str,
    outcome_collection: &str,
    outcome_collection_id: &str,
) -> Result<(), &'static str> {
    if unit.is_empty() || unit.len() > MAX_CONDITIONAL_KEYSET_UNIT_LENGTH {
        return Err("catalogue keyset unit is invalid");
    }
    if !is_canonical_conditional_keyset_hash(condition_id)
        || !is_canonical_conditional_keyset_hash(outcome_collection_id)
    {
        return Err("catalogue keyset identifiers are not canonical lowercase 32-byte hex values");
    }
    if outcome_collection.is_empty()
        || outcome_collection.len() > MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH
    {
        return Err("catalogue outcome collection exceeds its field bound");
    }
    Ok(())
}

/// A conditional keyset paired with its immutable catalogue sequence.
#[cfg(feature = "conditional-tokens")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CataloguedConditionalKeyset {
    /// Monotonic sequence allocated in the condition-registration transaction.
    pub sequence: u64,
    /// Wire-visible conditional keyset metadata.
    pub keyset: cashu::nuts::nut_ctf::ConditionalKeySetInfo,
}

/// One bounded raw database window from an immutable conditional-keyset catalogue snapshot.
#[cfg(feature = "conditional-tokens")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalKeysetCataloguePage {
    /// Snapshot high-water sequence fixed by the first page.
    pub snapshot: u64,
    /// Ordered, unfiltered keysets whose sequence belongs to the snapshot.
    pub keysets: Vec<CataloguedConditionalKeyset>,
    /// Whether another raw sequence window exists within the same snapshot.
    pub has_more: bool,
}

/// Conditions Database trait (NUT-CTF)
#[cfg(feature = "conditional-tokens")]
#[async_trait]
pub trait ConditionsDatabase {
    /// Conditions Database Error
    type Err: Into<Error> + From<Error>;

    /// Whether this backend provides persistent authenticated catalogue authority.
    fn supports_conditional_keyset_catalogue(&self) -> bool {
        false
    }

    /// Add a stored condition
    async fn add_condition(&self, condition: StoredCondition) -> Result<(), Self::Err>;

    /// Delete a condition registration created by a failed legacy workflow.
    ///
    /// Authenticated catalogue rows are immutable, so catalogue-capable
    /// backends fail closed by default. The method remains for source
    /// compatibility with custom database implementations compiled against the
    /// earlier conditional-token API.
    #[deprecated(
        note = "conditional-keyset catalogues are append-only; registration writes must be transactional"
    )]
    async fn delete_condition_registration(&self, condition_id: &str) -> Result<(), Self::Err> {
        let _ = condition_id;
        Err(
            Error::Internal("conditional-keyset catalogue registrations are immutable".to_string())
                .into(),
        )
    }

    /// Get a condition by condition_id
    async fn get_condition(&self, condition_id: &str)
        -> Result<Option<StoredCondition>, Self::Err>;

    /// Get all conditions, with optional cursor-based pagination and status filter
    async fn get_conditions(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        status: &[String],
    ) -> Result<Vec<StoredCondition>, Self::Err>;

    /// Update condition attestation state.
    /// Only succeeds if current status is 'pending' (first-write-wins).
    /// Returns true if the update was applied, false if already attested.
    async fn update_condition_attestation(
        &self,
        condition_id: &str,
        status: &str,
        winning_outcome: Option<&str>,
        attested_at: Option<u64>,
    ) -> Result<bool, Self::Err>;

    /// Get conditional keysets for a condition (mapping outcome_collection → keyset id)
    async fn get_conditional_keysets_for_condition(
        &self,
        condition_id: &str,
    ) -> Result<HashMap<String, Id>, Self::Err>;

    /// Get full conditional keyset metadata for idempotent signatory reconciliation.
    async fn get_conditional_mint_keyset_infos_for_condition(
        &self,
        condition_id: &str,
    ) -> Result<Vec<MintKeySetInfo>, Self::Err> {
        let _ = condition_id;
        Err(Error::Internal(
            "conditional keyset reconciliation lookup is not implemented by this backend"
                .to_string(),
        )
        .into())
    }

    /// Get all conditional keyset infos (for GET /v1/conditional_keysets)
    async fn get_all_conditional_keyset_infos(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
    ) -> Result<Vec<cashu::nuts::nut_ctf::ConditionalKeySetInfo>, Self::Err>;

    /// Read a bounded raw sequence window from a stable conditional-keyset catalogue snapshot.
    ///
    /// When `snapshot` is `None`, implementations read the committed catalogue
    /// high-water mark without acquiring a writer lock. Registrations must
    /// update that mark and insert their rows atomically in one transaction.
    async fn get_conditional_keyset_catalogue_page(
        &self,
        snapshot: Option<u64>,
        after: u64,
        limit: u64,
    ) -> Result<ConditionalKeysetCataloguePage, Self::Err> {
        let _ = (snapshot, after, limit);
        Err(Error::Internal(
            "conditional keyset catalogue pagination is not implemented by this backend"
                .to_string(),
        )
        .into())
    }

    /// Atomically initialize or load the shared cursor MAC key.
    async fn get_or_create_conditional_keyset_cursor_key(
        &self,
        candidate: Zeroizing<[u8; 32]>,
    ) -> Result<Zeroizing<[u8; 32]>, Self::Err> {
        let _ = candidate;
        Err(Error::Internal(
            "conditional keyset catalogue cursor authority is not implemented by this backend"
                .to_string(),
        )
        .into())
    }

    /// Get condition info for a specific keyset ID
    /// Returns (condition_id, outcome_collection, outcome_collection_id) if this is a conditional keyset
    async fn get_condition_for_keyset(
        &self,
        keyset_id: &Id,
    ) -> Result<Option<(String, String, String)>, Self::Err>;
}

#[cfg(all(test, feature = "conditional-tokens"))]
mod conditions_database_default_tests {
    use super::*;

    struct DefaultMetadataLookupDatabase;

    #[async_trait]
    impl ConditionsDatabase for DefaultMetadataLookupDatabase {
        type Err = Error;

        async fn add_condition(&self, _condition: StoredCondition) -> Result<(), Self::Err> {
            unreachable!("not used by the default lookup test")
        }

        async fn get_condition(
            &self,
            _condition_id: &str,
        ) -> Result<Option<StoredCondition>, Self::Err> {
            unreachable!("not used by the default lookup test")
        }

        async fn get_conditions(
            &self,
            _since: Option<u64>,
            _limit: Option<u64>,
            _status: &[String],
        ) -> Result<Vec<StoredCondition>, Self::Err> {
            unreachable!("not used by the default lookup test")
        }

        async fn update_condition_attestation(
            &self,
            _condition_id: &str,
            _status: &str,
            _winning_outcome: Option<&str>,
            _attested_at: Option<u64>,
        ) -> Result<bool, Self::Err> {
            unreachable!("not used by the default lookup test")
        }

        async fn get_conditional_keysets_for_condition(
            &self,
            _condition_id: &str,
        ) -> Result<HashMap<String, Id>, Self::Err> {
            unreachable!("not used by the default lookup test")
        }

        async fn get_all_conditional_keyset_infos(
            &self,
            _since: Option<u64>,
            _limit: Option<u64>,
            _active: Option<bool>,
        ) -> Result<Vec<cashu::nuts::nut_ctf::ConditionalKeySetInfo>, Self::Err> {
            unreachable!("not used by the default lookup test")
        }

        async fn get_condition_for_keyset(
            &self,
            _keyset_id: &Id,
        ) -> Result<Option<(String, String, String)>, Self::Err> {
            unreachable!("not used by the default lookup test")
        }
    }

    #[tokio::test]
    async fn conditional_keyset_metadata_lookup_fails_closed_by_default() {
        let error = DefaultMetadataLookupDatabase
            .get_conditional_mint_keyset_infos_for_condition(&"ab".repeat(32))
            .await
            .expect_err("out-of-tree backend without reconciliation lookup must fail closed");
        assert!(matches!(error, Error::Internal(_)));
    }
}

/// Base database writer
#[cfg(not(feature = "conditional-tokens"))]
pub trait Transaction<Error>:
    DbTransactionFinalizer<Err = Error>
    + QuotesTransaction<Err = Error>
    + SignaturesTransaction<Err = Error>
    + ProofsTransaction<Err = Error>
    + KVStoreTransaction<Error>
    + SagaTransaction<Err = Error>
    + CompletedOperationsTransaction<Err = Error>
{
}

/// Base database writer with NUT-CTF condition registration writes.
#[cfg(feature = "conditional-tokens")]
pub trait Transaction<Error>:
    DbTransactionFinalizer<Err = Error>
    + QuotesTransaction<Err = Error>
    + SignaturesTransaction<Err = Error>
    + ProofsTransaction<Err = Error>
    + KVStoreTransaction<Error>
    + SagaTransaction<Err = Error>
    + CompletedOperationsTransaction<Err = Error>
    + ConditionsTransaction<Err = Error>
{
}

/// Mint Database trait
#[cfg(not(feature = "conditional-tokens"))]
#[async_trait]
pub trait Database<Error>:
    KVStoreDatabase<Err = Error>
    + QuotesDatabase<Err = Error>
    + ProofsDatabase<Err = Error>
    + SignaturesDatabase<Err = Error>
    + SagaDatabase<Err = Error>
    + CompletedOperationsDatabase<Err = Error>
{
    /// Begins a transaction
    async fn begin_transaction(&self) -> Result<Box<dyn Transaction<Error> + Send + Sync>, Error>;
}

/// Mint Database trait (with conditional tokens support)
#[cfg(feature = "conditional-tokens")]
#[async_trait]
pub trait Database<Error>:
    KVStoreDatabase<Err = Error>
    + QuotesDatabase<Err = Error>
    + ProofsDatabase<Err = Error>
    + SignaturesDatabase<Err = Error>
    + SagaDatabase<Err = Error>
    + CompletedOperationsDatabase<Err = Error>
    + ConditionsDatabase<Err = Error>
{
    /// Begins a transaction
    async fn begin_transaction(&self) -> Result<Box<dyn Transaction<Error> + Send + Sync>, Error>;
}

/// Type alias for Mint Database
pub type DynMintDatabase = std::sync::Arc<dyn Database<Error> + Send + Sync>;

/// Type alias for Mint Transaction
pub type DynMintTransaction = Box<dyn Transaction<Error> + Send + Sync>;
