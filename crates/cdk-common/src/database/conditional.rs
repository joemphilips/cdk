//! Storage-boundary validation shared by conditional-token mint and wallet databases.

/// Maximum byte length of a wire-visible currency unit.
pub const MAX_CONDITIONAL_KEYSET_UNIT_LENGTH: usize = 64;

/// Maximum byte length of one canonical outcome-collection expression.
pub const MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH: usize = 16 * 1_024;

/// Whether a value is the canonical lowercase encoding of a 32-byte hash.
pub fn is_canonical_conditional_keyset_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validate bounded fields shared by conditional catalogue wire and persistence boundaries.
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
