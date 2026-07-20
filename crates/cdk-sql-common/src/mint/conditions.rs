//! Conditions database implementation (NUT-CTF)

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use async_trait::async_trait;
use cdk_common::database::mint::{
    validate_conditional_keyset_catalogue_fields, CataloguedConditionalKeyset,
    ConditionalKeysetCataloguePage, ConditionsDatabase, ConditionsTransaction,
};
use cdk_common::database::Error;
use cdk_common::mint::{MintKeySetInfo, StoredCondition};
use cdk_common::nuts::nut_ctf::ConditionalKeySetInfo;
use cdk_common::nuts::{CurrencyUnit, Id};
use zeroize::Zeroizing;

use super::{SQLMintDatabase, SQLTransaction};
use crate::database::DatabaseExecutor;
use crate::pool::DatabasePool;
use crate::stmt::{query, Column, Statement};
use crate::{column_as_number, column_as_string, unpack_into};

fn sql_row_to_stored_condition(row: Vec<Column>) -> Result<StoredCondition, Error> {
    unpack_into!(
        let (
            condition_id,
            threshold,
            tags_json,
            announcements_json,
            collateral,
            attestation_status,
            winning_outcome,
            attested_at,
            created_at,
            condition_type,
            lo_bound,
            hi_bound,
            precision
        ) = row
    );

    let winning_outcome = match &winning_outcome {
        Column::Text(s) => Some(s.clone()),
        _ => None,
    };

    let attested_at: Option<u64> = match &attested_at {
        Column::Integer(n) => Some(u64::try_from(*n).map_err(|_| {
            Error::Internal("negative condition attested_at in database".to_string())
        })?),
        _ => None,
    };

    let threshold_val: u64 = column_as_number!(threshold);
    let created_at_val: u64 = column_as_number!(created_at);

    let condition_type_str = match &condition_type {
        Column::Text(s) => s.clone(),
        _ => "enum".to_string(),
    };

    let collateral_val = match &collateral {
        Column::Text(s) => Some(
            s.parse::<CurrencyUnit>()
                .map_err(|e| Error::Internal(format!("Invalid collateral unit: {e}")))?,
        ),
        _ => None,
    };

    let lo_bound_val: Option<i64> = match &lo_bound {
        Column::Integer(n) => Some(*n),
        _ => None,
    };

    let hi_bound_val: Option<i64> = match &hi_bound {
        Column::Integer(n) => Some(*n),
        _ => None,
    };

    let precision_val: Option<i32> = match &precision {
        Column::Integer(n) => Some(i32::try_from(*n).map_err(|_| {
            Error::Internal("condition precision is outside i32 range".to_string())
        })?),
        _ => None,
    };

    let threshold = u32::try_from(threshold_val)
        .map_err(|_| Error::Internal("condition threshold is outside u32 range".to_string()))?;

    Ok(StoredCondition {
        condition_id: column_as_string!(&condition_id),
        threshold,
        tags_json: column_as_string!(&tags_json),
        announcements_json: column_as_string!(&announcements_json),
        collateral: collateral_val,
        attestation_status: column_as_string!(&attestation_status),
        winning_outcome,
        attested_at,
        created_at: created_at_val,
        condition_type: condition_type_str,
        lo_bound: lo_bound_val,
        hi_bound: hi_bound_val,
        precision: precision_val,
    })
}

fn sql_row_to_keyset_mapping(row: Vec<Column>) -> Result<(String, Id), Error> {
    unpack_into!(
        let (
            outcome_collection,
            keyset_id
        ) = row
    );

    let oc = column_as_string!(&outcome_collection);
    let kid_str = column_as_string!(&keyset_id);
    let kid: Id = kid_str
        .parse()
        .map_err(|e| Error::Internal(format!("Invalid keyset id: {e}")))?;

    Ok((oc, kid))
}

/// Columns selected by every `conditional_keyset` read path. The first 10
/// columns match `sql_row_to_keyset_info` exactly so the base parser can be
/// reused; the last 4 are the conditional-specific fields.
pub(crate) const CONDITIONAL_KEYSET_COLUMNS: &str = "id, unit, active, valid_from, valid_to, \
     derivation_path, derivation_path_index, amounts, input_fee_ppk, issuer_version, \
     condition_id, outcome_collection, outcome_collection_id, created_at";

pub(crate) fn sql_row_to_conditional_mint_keyset_info(
    mut row: Vec<Column>,
) -> Result<(MintKeySetInfo, u64), Error> {
    if row.len() != 14 {
        return Err(Error::Internal(format!(
            "expected 14 columns for conditional_keyset, got {}",
            row.len()
        )));
    }

    // Split off the trailing 4 conditional-specific columns, leaving the
    // first 10 to be parsed by the shared base parser.
    let tail: Vec<Column> = row.split_off(10);
    let mut info = super::keys::sql_row_to_keyset_info(row)?;

    let mut tail_iter = tail.into_iter();
    let condition_id = tail_iter.next().expect("length checked above");
    let outcome_collection = tail_iter.next().expect("length checked above");
    let outcome_collection_id = tail_iter.next().expect("length checked above");
    let created_at = tail_iter.next().expect("length checked above");

    info.condition_id = Some(column_as_string!(&condition_id));
    info.outcome_collection = Some(column_as_string!(&outcome_collection));
    info.outcome_collection_id = Some(column_as_string!(&outcome_collection_id));
    validate_conditional_keyset_info(&info)?;

    let created_at_val: u64 = column_as_number!(created_at);
    Ok((info, created_at_val))
}

fn mint_keyset_info_to_conditional_keyset_info(
    info: &MintKeySetInfo,
    created_at: u64,
) -> Result<ConditionalKeySetInfo, Error> {
    let condition_id = info
        .condition_id
        .clone()
        .ok_or_else(|| Error::Internal("condition_id missing on conditional keyset".to_string()))?;
    let outcome_collection = info.outcome_collection.clone().ok_or_else(|| {
        Error::Internal("outcome_collection missing on conditional keyset".to_string())
    })?;
    let outcome_collection_id = info.outcome_collection_id.clone().ok_or_else(|| {
        Error::Internal("outcome_collection_id missing on conditional keyset".to_string())
    })?;

    Ok(ConditionalKeySetInfo {
        id: info.id,
        unit: info.unit.to_string(),
        active: info.active,
        input_fee_ppk: Some(info.input_fee_ppk),
        final_expiry: info.final_expiry,
        condition_id,
        outcome_collection,
        outcome_collection_id,
        registered_at: created_at,
    })
}

fn sql_row_to_catalogued_conditional_keyset(
    mut row: Vec<Column>,
) -> Result<CataloguedConditionalKeyset, Error> {
    if row.len() != 15 {
        return Err(Error::Internal(format!(
            "expected 15 columns for catalogued conditional keyset, got {}",
            row.len()
        )));
    }
    let sequence = row
        .pop()
        .ok_or_else(|| Error::Internal("catalogue sequence missing".to_string()))?;
    let (info, created_at) = sql_row_to_conditional_mint_keyset_info(row)?;

    Ok(CataloguedConditionalKeyset {
        sequence: column_as_number!(sequence),
        keyset: mint_keyset_info_to_conditional_keyset_info(&info, created_at)?,
    })
}

fn validate_conditional_keyset_info(
    keyset_info: &MintKeySetInfo,
) -> Result<(String, String, String), Error> {
    let condition_id = keyset_info.condition_id.as_deref().ok_or_else(|| {
        Error::Internal("add_conditional_keyset: condition_id missing".to_string())
    })?;
    let outcome_collection = keyset_info.outcome_collection.as_deref().ok_or_else(|| {
        Error::Internal("add_conditional_keyset: outcome_collection missing".to_string())
    })?;
    let outcome_collection_id = keyset_info
        .outcome_collection_id
        .as_deref()
        .ok_or_else(|| {
            Error::Internal("add_conditional_keyset: outcome_collection_id missing".to_string())
        })?;

    validate_conditional_keyset_catalogue_fields(
        &keyset_info.unit.to_string(),
        condition_id,
        outcome_collection,
        outcome_collection_id,
    )
    .map_err(|detail| Error::Internal(detail.to_string()))?;

    Ok((
        condition_id.to_string(),
        outcome_collection.to_string(),
        outcome_collection_id.to_string(),
    ))
}

fn sql_i64(field: &str, value: u64) -> Result<i64, Error> {
    i64::try_from(value)
        .map_err(|_| Error::Internal(format!("{field} exceeds the signed SQL integer range")))
}

fn optional_sql_i64(field: &str, value: Option<u64>) -> Result<Option<i64>, Error> {
    value.map(|value| sql_i64(field, value)).transpose()
}

struct PreparedConditionalKeyset {
    id: String,
    unit: String,
    active: bool,
    valid_from: i64,
    valid_to: Option<i64>,
    derivation_path: String,
    derivation_path_index: Option<u32>,
    amounts: String,
    input_fee_ppk: i64,
    issuer_version: Option<String>,
    condition_id: String,
    outcome_collection: String,
    outcome_collection_id: String,
    created_at: i64,
}

fn prepare_conditional_keyset(
    keyset_info: MintKeySetInfo,
    created_at: u64,
) -> Result<PreparedConditionalKeyset, Error> {
    let (condition_id, outcome_collection, outcome_collection_id) =
        validate_conditional_keyset_info(&keyset_info)?;
    Ok(PreparedConditionalKeyset {
        id: keyset_info.id.to_string(),
        unit: keyset_info.unit.to_string(),
        active: keyset_info.active,
        valid_from: sql_i64("conditional keyset valid_from", keyset_info.valid_from)?,
        valid_to: optional_sql_i64("conditional keyset valid_to", keyset_info.final_expiry)?,
        derivation_path: keyset_info.derivation_path.to_string(),
        derivation_path_index: keyset_info.derivation_path_index,
        amounts: serde_json::to_string(&keyset_info.amounts)
            .map_err(|err| Error::Internal(err.to_string()))?,
        input_fee_ppk: sql_i64(
            "conditional keyset input_fee_ppk",
            keyset_info.input_fee_ppk,
        )?,
        issuer_version: keyset_info
            .issuer_version
            .map(|version| version.to_string()),
        condition_id,
        outcome_collection,
        outcome_collection_id,
        created_at: sql_i64("conditional keyset created_at", created_at)?,
    })
}

async fn insert_condition<EX>(executor: &EX, condition: StoredCondition) -> Result<(), Error>
where
    EX: crate::database::DatabaseExecutor,
{
    let attested_at = optional_sql_i64("condition attested_at", condition.attested_at)?;
    let created_at = sql_i64("condition created_at", condition.created_at)?;
    query(
        r#"
        INSERT INTO conditions (
            condition_id, threshold, tags_json, announcements_json,
            collateral, attestation_status, winning_outcome, attested_at, created_at,
            condition_type, lo_bound, hi_bound, precision
        ) VALUES (
            :condition_id, :threshold, :tags_json, :announcements_json,
            :collateral, :attestation_status, :winning_outcome, :attested_at, :created_at,
            :condition_type, :lo_bound, :hi_bound, :precision
        )
        "#,
    )?
    .bind("condition_id", condition.condition_id)
    .bind("threshold", condition.threshold as i64)
    .bind("tags_json", condition.tags_json)
    .bind("announcements_json", condition.announcements_json)
    .bind(
        "collateral",
        condition.collateral.map(|unit| unit.to_string()),
    )
    .bind("attestation_status", condition.attestation_status)
    .bind("winning_outcome", condition.winning_outcome)
    .bind("attested_at", attested_at)
    .bind("created_at", created_at)
    .bind("condition_type", condition.condition_type)
    .bind("lo_bound", condition.lo_bound)
    .bind("hi_bound", condition.hi_bound)
    .bind("precision", condition.precision.map(|p| p as i64))
    .execute(executor)
    .await?;

    Ok(())
}

async fn insert_conditional_keyset_row<EX>(
    executor: &EX,
    keyset: PreparedConditionalKeyset,
    catalogue_sequence: u64,
) -> Result<(), Error>
where
    EX: crate::database::DatabaseExecutor,
{
    let catalogue_sequence = sql_i64("conditional keyset catalogue_sequence", catalogue_sequence)?;
    query(
        r#"
        INSERT INTO conditional_keyset (
            id, unit, active, valid_from, valid_to, derivation_path,
            derivation_path_index, amounts, input_fee_ppk, issuer_version,
            condition_id, outcome_collection, outcome_collection_id, created_at,
            catalogue_sequence
        ) VALUES (
            :id, :unit, :active, :valid_from, :valid_to, :derivation_path,
            :derivation_path_index, :amounts, :input_fee_ppk, :issuer_version,
            :condition_id, :outcome_collection, :outcome_collection_id, :created_at,
            :catalogue_sequence
        )
        "#,
    )?
    .bind("id", keyset.id)
    .bind("unit", keyset.unit)
    .bind("active", keyset.active)
    .bind("valid_from", keyset.valid_from)
    .bind("valid_to", keyset.valid_to)
    .bind("derivation_path", keyset.derivation_path)
    .bind("derivation_path_index", keyset.derivation_path_index)
    .bind("amounts", keyset.amounts)
    .bind("input_fee_ppk", keyset.input_fee_ppk)
    .bind("issuer_version", keyset.issuer_version)
    .bind("condition_id", keyset.condition_id)
    .bind("outcome_collection", keyset.outcome_collection)
    .bind("outcome_collection_id", keyset.outcome_collection_id)
    .bind("created_at", keyset.created_at)
    .bind("catalogue_sequence", catalogue_sequence)
    .execute(executor)
    .await?;

    Ok(())
}

pub(crate) async fn insert_conditional_keyset<EX>(
    executor: &EX,
    keyset_info: MintKeySetInfo,
    created_at: u64,
) -> Result<(), Error>
where
    EX: crate::database::DatabaseExecutor,
{
    let expected_keyset_info = keyset_info.clone();
    let prepared = prepare_conditional_keyset(keyset_info, created_at)?;

    query(
        r#"
        SELECT high_water
        FROM conditional_keyset_catalogue_state
        WHERE singleton = 1
        FOR UPDATE
        "#,
    )?
    .pluck(executor)
    .await?
    .ok_or_else(|| Error::Internal("conditional keyset catalogue state is missing".to_string()))?;

    let existing = query(&format!(
        "SELECT {} FROM conditional_keyset WHERE id = :id",
        CONDITIONAL_KEYSET_COLUMNS
    ))?
    .bind("id", expected_keyset_info.id.to_string())
    .fetch_one(executor)
    .await?;
    if let Some(existing) = existing {
        let (existing, existing_created_at) = sql_row_to_conditional_mint_keyset_info(existing)?;
        return if existing == expected_keyset_info && existing_created_at == created_at {
            Ok(())
        } else {
            Err(Error::Internal(format!(
                "conflicting conditional keyset metadata for id {}",
                expected_keyset_info.id
            )))
        };
    }

    let catalogue_sequence = query(
        r#"
        UPDATE conditional_keyset_catalogue_state
        SET high_water = high_water + 1
        WHERE singleton = 1 AND high_water < 9223372036854775807
        RETURNING high_water
        "#,
    )?
    .pluck(executor)
    .await?
    .map(|value| {
        let sequence: u64 = column_as_number!(value);
        Ok::<u64, Error>(sequence)
    })
    .transpose()?
    .ok_or_else(|| Error::Internal("conditional keyset catalogue state is missing".to_string()))?;

    insert_conditional_keyset_row(executor, prepared, catalogue_sequence).await
}

fn bind_prepared_conditional_keyset(
    mut statement: Statement,
    index: usize,
    keyset: PreparedConditionalKeyset,
    catalogue_sequence: u64,
) -> Result<Statement, Error> {
    let sequence = sql_i64("conditional keyset catalogue_sequence", catalogue_sequence)?;
    statement = statement
        .bind(format!("id_{index}"), keyset.id)
        .bind(format!("unit_{index}"), keyset.unit)
        .bind(format!("active_{index}"), keyset.active)
        .bind(format!("valid_from_{index}"), keyset.valid_from)
        .bind(format!("valid_to_{index}"), keyset.valid_to)
        .bind(format!("derivation_path_{index}"), keyset.derivation_path)
        .bind(
            format!("derivation_path_index_{index}"),
            keyset.derivation_path_index,
        )
        .bind(format!("amounts_{index}"), keyset.amounts)
        .bind(format!("input_fee_ppk_{index}"), keyset.input_fee_ppk)
        .bind(format!("issuer_version_{index}"), keyset.issuer_version)
        .bind(format!("condition_id_{index}"), keyset.condition_id)
        .bind(
            format!("outcome_collection_{index}"),
            keyset.outcome_collection,
        )
        .bind(
            format!("outcome_collection_id_{index}"),
            keyset.outcome_collection_id,
        )
        .bind(format!("created_at_{index}"), keyset.created_at)
        .bind(format!("catalogue_sequence_{index}"), sequence);
    Ok(statement)
}

async fn insert_conditional_keyset_batch<EX>(
    executor: &EX,
    keysets: Vec<(MintKeySetInfo, u64)>,
) -> Result<(), Error>
where
    EX: crate::database::DatabaseExecutor,
{
    if keysets.is_empty() {
        return Ok(());
    }
    let mut ids = HashSet::with_capacity(keysets.len());
    let mut prepared = Vec::with_capacity(keysets.len());
    for (keyset, created_at) in keysets {
        if !ids.insert(keyset.id) {
            return Err(Error::Internal(format!(
                "duplicate conditional keyset id {} in registration batch",
                keyset.id
            )));
        }
        prepared.push(prepare_conditional_keyset(keyset, created_at)?);
    }

    let count = u64::try_from(prepared.len())
        .map_err(|_| Error::Internal("conditional keyset batch is too large".to_string()))?;
    let count_i64 = i64::try_from(count)
        .map_err(|_| Error::Internal("conditional keyset batch is too large".to_string()))?;
    let end_sequence = query(
        r#"
        UPDATE conditional_keyset_catalogue_state
        SET high_water = high_water + :count
        WHERE singleton = 1 AND high_water <= 9223372036854775807 - :count
        RETURNING high_water
        "#,
    )?
    .bind("count", count_i64)
    .pluck(executor)
    .await?
    .map(|value| {
        let sequence: u64 = column_as_number!(value);
        Ok::<u64, Error>(sequence)
    })
    .transpose()?
    .ok_or_else(|| Error::Internal("conditional keyset catalogue state is missing".to_string()))?;
    let start_sequence = end_sequence
        .checked_sub(count - 1)
        .ok_or_else(|| Error::Internal("conditional keyset sequence underflow".to_string()))?;

    let mut sql = String::from(
        "INSERT INTO conditional_keyset (\
         id, unit, active, valid_from, valid_to, derivation_path, \
         derivation_path_index, amounts, input_fee_ppk, issuer_version, \
         condition_id, outcome_collection, outcome_collection_id, created_at, \
         catalogue_sequence) VALUES ",
    );
    for index in 0..prepared.len() {
        if index > 0 {
            sql.push(',');
        }
        write!(
            sql,
            "(:id_{index}, :unit_{index}, :active_{index}, :valid_from_{index}, \
             :valid_to_{index}, :derivation_path_{index}, :derivation_path_index_{index}, \
             :amounts_{index}, :input_fee_ppk_{index}, :issuer_version_{index}, \
             :condition_id_{index}, :outcome_collection_{index}, \
             :outcome_collection_id_{index}, :created_at_{index}, \
             :catalogue_sequence_{index})"
        )
        .map_err(|_| Error::Internal("failed to build conditional keyset batch SQL".to_string()))?;
    }

    let mut statement = query(&sql)?;
    for (index, (keyset, sequence)) in prepared
        .into_iter()
        .zip(start_sequence..=end_sequence)
        .enumerate()
    {
        statement = bind_prepared_conditional_keyset(statement, index, keyset, sequence)?;
    }
    statement.execute(executor).await?;
    Ok(())
}

async fn query_conditional_keyset_catalogue_page<EX>(
    executor: &EX,
    snapshot: u64,
    after: u64,
    limit: u64,
) -> Result<ConditionalKeysetCataloguePage, Error>
where
    EX: crate::database::DatabaseExecutor,
{
    if limit == 0 {
        return Err(Error::Internal(
            "conditional keyset catalogue limit must be positive".to_string(),
        ));
    }
    if after > snapshot {
        return Err(Error::Internal(
            "conditional keyset catalogue after exceeds snapshot".to_string(),
        ));
    }
    let snapshot_sql = sql_i64("conditional keyset catalogue snapshot", snapshot)?;
    let after_sql = sql_i64("conditional keyset catalogue after", after)?;
    let lookahead = limit.checked_add(1).ok_or_else(|| {
        Error::Internal("conditional keyset catalogue limit overflow".to_string())
    })?;
    let lookahead_sql = sql_i64("conditional keyset catalogue limit", lookahead)?;
    let limit_usize = usize::try_from(limit).map_err(|_| {
        Error::Internal("conditional keyset catalogue limit exceeds usize".to_string())
    })?;
    let sql = format!(
        "SELECT {}, catalogue_sequence FROM conditional_keyset \
         WHERE catalogue_sequence > :after AND catalogue_sequence <= :snapshot \
         ORDER BY catalogue_sequence ASC, id ASC LIMIT :limit",
        CONDITIONAL_KEYSET_COLUMNS
    );

    let statement = query(&sql)?
        .bind("after", after_sql)
        .bind("snapshot", snapshot_sql)
        .bind("limit", lookahead_sql);

    let mut keysets = statement
        .fetch_all(executor)
        .await?
        .into_iter()
        .map(sql_row_to_catalogued_conditional_keyset)
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = keysets.len() > limit_usize;
    if has_more {
        keysets.pop();
    }

    let mut expected = after.checked_add(1).ok_or_else(|| {
        Error::Internal("conditional keyset catalogue sequence overflow".to_string())
    })?;
    for entry in &keysets {
        if entry.sequence != expected {
            return Err(Error::Internal(format!(
                "conditional keyset catalogue sequence gap: expected {expected}, got {}",
                entry.sequence
            )));
        }
        expected = expected.checked_add(1).ok_or_else(|| {
            Error::Internal("conditional keyset catalogue sequence overflow".to_string())
        })?;
    }
    let last_scanned = expected - 1;
    if !has_more && last_scanned != snapshot {
        return Err(Error::Internal(format!(
            "conditional keyset catalogue ended at {last_scanned} before snapshot {snapshot}"
        )));
    }

    Ok(ConditionalKeysetCataloguePage {
        snapshot,
        keysets,
        has_more,
    })
}

impl<RM> SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    /// Query the `conditional_keyset` table with optional cursor pagination
    /// (`since` is strictly greater than), `limit`, and active filter. This
    /// is the shared path for both the public NUT-CTF listing endpoint and
    /// the internal `reload_keys_from_db` bootstrap.
    pub(crate) async fn query_conditional_keysets(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
    ) -> Result<Vec<(MintKeySetInfo, u64)>, Error> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;

        let mut sql = format!(
            "SELECT {} FROM conditional_keyset WHERE 1=1",
            CONDITIONAL_KEYSET_COLUMNS
        );

        if since.is_some() {
            // Cursor pagination: strictly greater than the last-seen timestamp.
            sql.push_str(" AND created_at > :since");
        }

        if active.is_some() {
            sql.push_str(" AND active = :active");
        }

        sql.push_str(" ORDER BY created_at ASC");

        if limit.is_some() {
            sql.push_str(" LIMIT :limit");
        }

        let mut stmt = query(&sql)?;

        if let Some(since_ts) = since {
            stmt = stmt.bind("since", sql_i64("conditional keyset since", since_ts)?);
        }

        if let Some(active_val) = active {
            stmt = stmt.bind("active", active_val);
        }

        if let Some(limit_val) = limit {
            stmt = stmt.bind("limit", sql_i64("conditional keyset limit", limit_val)?);
        }

        stmt.fetch_all(&*conn)
            .await?
            .into_iter()
            .map(sql_row_to_conditional_mint_keyset_info)
            .collect()
    }
}

#[async_trait]
impl<RM> ConditionsDatabase for SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    fn supports_conditional_keyset_catalogue(&self) -> bool {
        true
    }

    async fn add_condition(&self, condition: StoredCondition) -> Result<(), Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;
        insert_condition(&*conn, condition).await
    }

    async fn get_condition(
        &self,
        condition_id: &str,
    ) -> Result<Option<StoredCondition>, Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;

        let row = query(
            r#"
            SELECT condition_id, threshold, tags_json, announcements_json,
                   collateral, attestation_status, winning_outcome, attested_at, created_at,
                   condition_type, lo_bound, hi_bound, precision
            FROM conditions
            WHERE condition_id = :condition_id
            "#,
        )?
        .bind("condition_id", condition_id.to_string())
        .fetch_one(&*conn)
        .await?;

        match row {
            Some(r) => Ok(Some(sql_row_to_stored_condition(r)?)),
            None => Ok(None),
        }
    }

    async fn get_conditions(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        status: &[String],
    ) -> Result<Vec<StoredCondition>, Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;

        // Build SQL dynamically for status IN clause
        let mut sql = String::from(
            "SELECT condition_id, threshold, tags_json, announcements_json, \
             collateral, attestation_status, winning_outcome, attested_at, created_at, \
             condition_type, lo_bound, hi_bound, precision FROM conditions WHERE 1=1",
        );

        if since.is_some() {
            // Cursor pagination: strictly greater, so callers can pass the
            // last-seen `created_at` without re-receiving the boundary row.
            sql.push_str(" AND created_at > :since");
        }

        if !status.is_empty() {
            sql.push_str(" AND attestation_status IN (");
            for (i, _) in status.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!(":status_{}", i));
            }
            sql.push(')');
        }

        sql.push_str(" ORDER BY created_at ASC");

        if limit.is_some() {
            sql.push_str(" LIMIT :limit");
        }

        let mut stmt = query(&sql)?;

        if let Some(since_ts) = since {
            stmt = stmt.bind("since", sql_i64("condition since", since_ts)?);
        }

        for (i, s) in status.iter().enumerate() {
            stmt = stmt.bind(format!("status_{}", i), s.clone());
        }

        if let Some(limit_val) = limit {
            stmt = stmt.bind("limit", sql_i64("condition limit", limit_val)?);
        }

        let rows = stmt.fetch_all(&*conn).await?;

        rows.into_iter().map(sql_row_to_stored_condition).collect()
    }

    async fn update_condition_attestation(
        &self,
        condition_id: &str,
        status: &str,
        winning_outcome: Option<&str>,
        attested_at: Option<u64>,
    ) -> Result<bool, Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;

        let attested_at = optional_sql_i64("condition attested_at", attested_at)?;
        let rows_affected = query(
            r#"
            UPDATE conditions
            SET attestation_status = :status,
                winning_outcome = :winning_outcome,
                attested_at = :attested_at
            WHERE condition_id = :condition_id
              AND attestation_status = 'pending'
            "#,
        )?
        .bind("status", status.to_string())
        .bind("winning_outcome", winning_outcome.map(|w| w.to_string()))
        .bind("attested_at", attested_at)
        .bind("condition_id", condition_id.to_string())
        .execute(&*conn)
        .await?;

        Ok(rows_affected > 0)
    }

    async fn get_conditional_keysets_for_condition(
        &self,
        condition_id: &str,
    ) -> Result<HashMap<String, Id>, Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;

        let rows = query(
            r#"
            SELECT outcome_collection, id
            FROM conditional_keyset
            WHERE condition_id = :condition_id
            "#,
        )?
        .bind("condition_id", condition_id.to_string())
        .fetch_all(&*conn)
        .await?;

        let mut map = HashMap::new();
        for row in rows {
            let (oc, kid) = sql_row_to_keyset_mapping(row)?;
            map.insert(oc, kid);
        }

        Ok(map)
    }

    async fn get_conditional_mint_keyset_infos_for_condition(
        &self,
        condition_id: &str,
    ) -> Result<Vec<MintKeySetInfo>, Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;
        query(&format!(
            "SELECT {CONDITIONAL_KEYSET_COLUMNS} FROM conditional_keyset \
             WHERE condition_id = :condition_id ORDER BY catalogue_sequence"
        ))?
        .bind("condition_id", condition_id.to_string())
        .fetch_all(&*conn)
        .await?
        .into_iter()
        .map(sql_row_to_conditional_mint_keyset_info)
        .map(|result| result.map(|(info, _)| info))
        .collect()
    }

    async fn get_all_conditional_keyset_infos(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
    ) -> Result<Vec<ConditionalKeySetInfo>, Self::Err> {
        let rows = self.query_conditional_keysets(since, limit, active).await?;
        rows.into_iter()
            .map(|(info, created_at)| {
                mint_keyset_info_to_conditional_keyset_info(&info, created_at)
            })
            .collect()
    }

    async fn get_conditional_keyset_catalogue_page(
        &self,
        snapshot: Option<u64>,
        after: u64,
        limit: u64,
    ) -> Result<ConditionalKeysetCataloguePage, Self::Err> {
        match snapshot {
            Some(snapshot) => {
                let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;
                query_conditional_keyset_catalogue_page(&*conn, snapshot, after, limit).await
            }
            None => {
                let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;
                let state = query(
                    r#"
                    SELECT high_water,
                           (SELECT COALESCE(MAX(catalogue_sequence), 0)
                            FROM conditional_keyset)
                    FROM conditional_keyset_catalogue_state
                    WHERE singleton = 1
                    "#,
                )?
                .fetch_one(&*conn)
                .await?
                .ok_or_else(|| {
                    Error::Internal("conditional keyset catalogue state is missing".to_string())
                })?;
                if state.len() != 2 {
                    return Err(Error::Internal(
                        "conditional keyset catalogue state query returned an invalid shape"
                            .to_string(),
                    ));
                }
                let snapshot: u64 = column_as_number!(state[0].clone());
                let indexed_max: u64 = column_as_number!(state[1].clone());
                if snapshot != indexed_max {
                    return Err(Error::Internal(format!(
                        "conditional keyset catalogue high-water {snapshot} does not match indexed maximum {indexed_max}"
                    )));
                }
                let page =
                    query_conditional_keyset_catalogue_page(&*conn, snapshot, after, limit).await?;
                Ok(page)
            }
        }
    }

    async fn get_or_create_conditional_keyset_cursor_key(
        &self,
        candidate: Zeroizing<[u8; 32]>,
    ) -> Result<Zeroizing<[u8; 32]>, Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;
        conn.get_or_create_conditional_keyset_cursor_key(candidate)
            .await
    }

    async fn get_condition_for_keyset(
        &self,
        keyset_id: &Id,
    ) -> Result<Option<(String, String, String)>, Self::Err> {
        let conn = self.pool.get().map_err(|e| Error::Database(Box::new(e)))?;

        let row = query(
            r#"
            SELECT condition_id, outcome_collection, outcome_collection_id
            FROM conditional_keyset
            WHERE id = :id
            "#,
        )?
        .bind("id", keyset_id.to_string())
        .fetch_one(&*conn)
        .await?;

        match row {
            Some(r) => {
                unpack_into!(
                    let (condition_id, outcome_collection, outcome_collection_id) = r
                );
                Ok(Some((
                    column_as_string!(&condition_id),
                    column_as_string!(&outcome_collection),
                    column_as_string!(&outcome_collection_id),
                )))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl<RM> ConditionsTransaction for SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    async fn add_condition(&mut self, condition: StoredCondition) -> Result<(), Self::Err> {
        insert_condition(&self.inner, condition).await
    }

    async fn add_conditional_keyset(
        &mut self,
        keyset_info: MintKeySetInfo,
        created_at: u64,
    ) -> Result<(), Self::Err> {
        insert_conditional_keyset(&self.inner, keyset_info, created_at).await
    }

    async fn add_conditional_keysets(
        &mut self,
        keysets: Vec<(MintKeySetInfo, u64)>,
    ) -> Result<(), Self::Err> {
        insert_conditional_keyset_batch(&self.inner, keysets).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conditional_keyset_row(condition_id: String, outcome_collection: String) -> Vec<Column> {
        vec![
            Column::Text("00916bbf7ef91a36".to_string()),
            Column::Text("sat".to_string()),
            Column::Integer(1),
            Column::Integer(0),
            Column::Null,
            Column::Text("m/0'/0'/0'".to_string()),
            Column::Integer(0),
            Column::Text("[1]".to_string()),
            Column::Integer(0),
            Column::Null,
            Column::Text(condition_id),
            Column::Text(outcome_collection),
            Column::Text("cd".repeat(32)),
            Column::Integer(1_000),
        ]
    }

    #[test]
    fn raw_conditional_keyset_decoder_rejects_oversize_persisted_field() {
        let row = conditional_keyset_row(
            "ab".repeat(32),
            "x".repeat(
                cdk_common::database::mint::MAX_CONDITIONAL_KEYSET_OUTCOME_COLLECTION_LENGTH + 1,
            ),
        );
        assert!(sql_row_to_conditional_mint_keyset_info(row).is_err());
    }

    #[test]
    fn raw_conditional_keyset_decoder_rejects_uppercase_identifier() {
        let row = conditional_keyset_row("AB".repeat(32), "YES".to_string());
        assert!(sql_row_to_conditional_mint_keyset_info(row).is_err());
    }
}
