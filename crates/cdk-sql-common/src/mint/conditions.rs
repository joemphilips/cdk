//! Conditions database implementation (NUT-CTF)

use std::collections::HashMap;

use async_trait::async_trait;
use cdk_common::database::mint::{ConditionsDatabase, ConditionsTransaction};
use cdk_common::database::{Error, MintDatabase};
use cdk_common::mint::{MintKeySetInfo, StoredCondition};
use cdk_common::nuts::nut_ctf::ConditionalKeySetInfo;
use cdk_common::nuts::{CurrencyUnit, Id};

use super::{SQLMintDatabase, SQLTransaction};
use crate::pool::DatabasePool;
use crate::stmt::{query, Column};
use crate::{column_as_string, unpack_into};

pub(super) fn checked_sql_integer(value: u64) -> Result<i64, Error> {
    i64::try_from(value)
        .map_err(|_| Error::Internal("Registration query integer exceeds SQL range".to_string()))
}

const CONDITION_COLUMNS: &str = "condition_id, threshold, tags_json, announcements_json, \
    collateral, attestation_status, winning_outcome, attested_at, created_at, \
    condition_type, lo_bound, hi_bound, precision, oracle_sigs_json";

fn sql_row_to_stored_condition(row: Vec<Column>) -> Result<StoredCondition, Error> {
    unpack_into!(let (condition_id, threshold, tags_json, announcements_json, collateral,
        attestation_status, winning_outcome, attested_at, created_at, condition_type,
        lo_bound, hi_bound, precision, oracle_sigs_json) = row);
    let invalid = || Error::Internal("Invalid stored condition column".to_string());
    let text = |column: Column| -> Result<String, Error> {
        match column {
            Column::Text(value) => Ok(value),
            _ => Err(invalid()),
        }
    };
    let optional_text = |column: Column| -> Result<Option<String>, Error> {
        match column {
            Column::Text(value) => Ok(Some(value)),
            Column::Null => Ok(None),
            _ => Err(invalid()),
        }
    };
    let number = |column: Column| -> Result<i64, Error> {
        match column {
            Column::Integer(value) => Ok(value),
            _ => Err(invalid()),
        }
    };
    let optional_number = |column: Column| -> Result<Option<i64>, Error> {
        match column {
            Column::Integer(value) => Ok(Some(value)),
            Column::Null => Ok(None),
            _ => Err(invalid()),
        }
    };
    let condition = StoredCondition {
        condition_id: text(condition_id)?,
        threshold: u32::try_from(number(threshold)?).map_err(|_| invalid())?,
        tags_json: text(tags_json)?,
        announcements_json: text(announcements_json)?,
        collateral: optional_text(collateral)?
            .map(|value| value.parse::<CurrencyUnit>().map_err(|_| invalid()))
            .transpose()?,
        attestation_status: text(attestation_status)?,
        winning_outcome: optional_text(winning_outcome)?,
        attested_at: optional_number(attested_at)?
            .map(|value| u64::try_from(value).map_err(|_| invalid()))
            .transpose()?,
        created_at: u64::try_from(number(created_at)?).map_err(|_| invalid())?,
        condition_type: text(condition_type)?,
        lo_bound: optional_number(lo_bound)?,
        hi_bound: optional_number(hi_bound)?,
        precision: optional_number(precision)?
            .map(|value| i32::try_from(value).map_err(|_| invalid()))
            .transpose()?,
        oracle_sigs: optional_text(oracle_sigs_json)?
            .map(|value| serde_json::from_str(&value).map_err(|_| invalid()))
            .transpose()?,
    };
    condition.validate()?;
    Ok(condition)
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

    let created_at_val = match created_at {
        Column::Integer(value) => u64::try_from(value)
            .map_err(|_| Error::Internal("Invalid keyset registration time".to_string()))?,
        _ => {
            return Err(Error::Internal(
                "Invalid keyset registration time".to_string(),
            ))
        }
    };
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

    Ok((
        condition_id.to_string(),
        outcome_collection.to_string(),
        outcome_collection_id.to_string(),
    ))
}

async fn insert_condition<EX>(executor: &EX, condition: StoredCondition) -> Result<(), Error>
where
    EX: crate::database::DatabaseExecutor,
{
    condition.validate()?;
    query(
        r#"
        INSERT INTO conditions (
            condition_id, threshold, tags_json, announcements_json,
            collateral, attestation_status, winning_outcome, attested_at, created_at,
            condition_type, lo_bound, hi_bound, precision, oracle_sigs_json
        ) VALUES (
            :condition_id, :threshold, :tags_json, :announcements_json,
            :collateral, :attestation_status, :winning_outcome, :attested_at, :created_at,
            :condition_type, :lo_bound, :hi_bound, :precision, :oracle_sigs_json
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
    .bind("attested_at", condition.attested_at.map(|a| a as i64))
    .bind("created_at", checked_sql_integer(condition.created_at)?)
    .bind("condition_type", condition.condition_type)
    .bind("lo_bound", condition.lo_bound)
    .bind("hi_bound", condition.hi_bound)
    .bind("precision", condition.precision.map(|p| p as i64))
    .bind(
        "oracle_sigs_json",
        condition
            .oracle_sigs
            .map(|sigs| serde_json::to_string(&sigs))
            .transpose()
            .map_err(|err| Error::Internal(err.to_string()))?,
    )
    .execute(executor)
    .await?;

    Ok(())
}

async fn insert_conditional_keyset<EX>(
    executor: &EX,
    keyset_info: MintKeySetInfo,
    created_at: u64,
) -> Result<(), Error>
where
    EX: crate::database::DatabaseExecutor,
{
    let (condition_id, outcome_collection, outcome_collection_id) =
        validate_conditional_keyset_info(&keyset_info)?;

    query(
        r#"
        INSERT INTO conditional_keyset (
            id, unit, active, valid_from, valid_to, derivation_path,
            derivation_path_index, amounts, input_fee_ppk, issuer_version,
            condition_id, outcome_collection, outcome_collection_id, created_at
        ) VALUES (
            :id, :unit, :active, :valid_from, :valid_to, :derivation_path,
            :derivation_path_index, :amounts, :input_fee_ppk, :issuer_version,
            :condition_id, :outcome_collection, :outcome_collection_id, :created_at
        )
        ON CONFLICT(id) DO UPDATE SET
            unit = excluded.unit,
            active = excluded.active,
            valid_from = excluded.valid_from,
            valid_to = excluded.valid_to,
            derivation_path = excluded.derivation_path,
            derivation_path_index = excluded.derivation_path_index,
            amounts = excluded.amounts,
            input_fee_ppk = excluded.input_fee_ppk,
            issuer_version = excluded.issuer_version,
            condition_id = excluded.condition_id,
            outcome_collection = excluded.outcome_collection,
            outcome_collection_id = excluded.outcome_collection_id
        "#,
    )?
    .bind("id", keyset_info.id.to_string())
    .bind("unit", keyset_info.unit.to_string())
    .bind("active", keyset_info.active)
    .bind("valid_from", keyset_info.valid_from as i64)
    .bind("valid_to", keyset_info.final_expiry.map(|v| v as i64))
    .bind("derivation_path", keyset_info.derivation_path.to_string())
    .bind("derivation_path_index", keyset_info.derivation_path_index)
    .bind(
        "amounts",
        serde_json::to_string(&keyset_info.amounts).map_err(|e| Error::Internal(e.to_string()))?,
    )
    .bind("input_fee_ppk", keyset_info.input_fee_ppk as i64)
    .bind(
        "issuer_version",
        keyset_info.issuer_version.map(|v| v.to_string()),
    )
    .bind("condition_id", condition_id)
    .bind("outcome_collection", outcome_collection)
    .bind("outcome_collection_id", outcome_collection_id)
    .bind("created_at", checked_sql_integer(created_at)?)
    .execute(executor)
    .await?;

    Ok(())
}

impl<RM> SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    /// Read keysets with an inclusive registration filter and optional strict seek.
    /// Internal key reload passes no limit or seek to keep the complete read.
    pub(crate) async fn query_conditional_keysets(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
        after: Option<&(u64, String)>,
    ) -> Result<Vec<(MintKeySetInfo, u64)>, Error> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;

        let mut sql = format!(
            "SELECT {} FROM conditional_keyset WHERE 1=1",
            CONDITIONAL_KEYSET_COLUMNS
        );

        if since.is_some() {
            sql.push_str(" AND created_at >= :since");
        }

        if active.is_some() {
            sql.push_str(" AND active = :active");
        }

        if after.is_some() {
            sql.push_str(
                " AND (created_at > :after_time OR (created_at = :after_time AND id > :after_id))",
            );
        }
        sql.push_str(" ORDER BY created_at ASC, id ASC");

        if limit.is_some() {
            sql.push_str(" LIMIT :limit");
        }

        let mut stmt = query(&sql)?;

        if let Some(since_ts) = since {
            stmt = stmt.bind("since", checked_sql_integer(since_ts)?);
        }

        if let Some(active_val) = active {
            stmt = stmt.bind("active", active_val as i64);
        }

        if let Some((timestamp, id)) = after {
            stmt = stmt
                .bind("after_time", checked_sql_integer(*timestamp)?)
                .bind("after_id", id.clone());
        }

        if let Some(limit_val) = limit {
            stmt = stmt.bind("limit", checked_sql_integer(limit_val)?);
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

    async fn add_condition(&self, condition: StoredCondition) -> Result<(), Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        insert_condition(&*conn, condition).await
    }

    async fn delete_condition_registration(&self, condition_id: &str) -> Result<(), Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;

        query(
            r#"
            DELETE FROM conditional_keyset
            WHERE condition_id = :condition_id
            "#,
        )?
        .bind("condition_id", condition_id.to_string())
        .execute(&*conn)
        .await?;

        query(
            r#"
            DELETE FROM conditions
            WHERE condition_id = :condition_id
            "#,
        )?
        .bind("condition_id", condition_id.to_string())
        .execute(&*conn)
        .await?;

        Ok(())
    }

    async fn get_condition(
        &self,
        condition_id: &str,
    ) -> Result<Option<StoredCondition>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;

        let row = query(&format!(
            "SELECT {CONDITION_COLUMNS} FROM conditions WHERE condition_id = :condition_id"
        ))?
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
        self.get_conditions_page(since, limit, status, None).await
    }

    async fn get_conditions_page(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        status: &[String],
        after: Option<&(u64, String)>,
    ) -> Result<Vec<StoredCondition>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;

        // Build SQL dynamically for status IN clause
        let mut sql = format!("SELECT {CONDITION_COLUMNS} FROM conditions WHERE 1=1");

        if since.is_some() {
            sql.push_str(" AND created_at >= :since");
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

        if after.is_some() {
            sql.push_str(" AND (created_at > :after_time OR (created_at = :after_time AND condition_id > :after_id))");
        }
        sql.push_str(" ORDER BY created_at ASC, condition_id ASC");

        if limit.is_some() {
            sql.push_str(" LIMIT :limit");
        }

        let mut stmt = query(&sql)?;

        if let Some(since_ts) = since {
            stmt = stmt.bind("since", checked_sql_integer(since_ts)?);
        }

        for (i, s) in status.iter().enumerate() {
            stmt = stmt.bind(format!("status_{}", i), s.clone());
        }

        if let Some((timestamp, id)) = after {
            stmt = stmt
                .bind("after_time", checked_sql_integer(*timestamp)?)
                .bind("after_id", id.clone());
        }

        if let Some(limit_val) = limit {
            stmt = stmt.bind("limit", checked_sql_integer(limit_val)?);
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
        oracle_sigs: &[cdk_common::nuts::nut_ctf::OracleSig],
    ) -> Result<bool, Self::Err> {
        if status != "attested" {
            return Err(Error::Internal(
                "Only oracle-attested results can be recorded".to_string(),
            ));
        }
        let winning_outcome =
            winning_outcome.ok_or_else(|| Error::Internal("Missing oracle result".to_string()))?;
        let attested_at =
            attested_at.ok_or_else(|| Error::Internal("Missing attestation time".to_string()))?;
        let mut tx = self.begin_transaction().await?;
        let condition = tx
            .get_condition_for_update(condition_id)
            .await?
            .ok_or_else(|| Error::Internal("Condition not found".to_string()))?;
        let updated = tx
            .record_condition_attestation(&condition, winning_outcome, attested_at, oracle_sigs)
            .await?;
        tx.commit().await?;
        Ok(updated)
    }

    async fn get_conditional_keysets_for_condition(
        &self,
        condition_id: &str,
    ) -> Result<HashMap<String, Id>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;

        let rows = query(
            r#"
            SELECT outcome_collection, id
            FROM conditional_keyset
            WHERE condition_id = :condition_id
              AND active = :active
            ORDER BY outcome_collection ASC
            "#,
        )?
        .bind("condition_id", condition_id.to_string())
        .bind("active", true)
        .fetch_all(&*conn)
        .await?;

        let mut map = HashMap::new();
        for row in rows {
            let (oc, kid) = sql_row_to_keyset_mapping(row)?;
            map.insert(oc, kid);
        }

        Ok(map)
    }

    async fn get_conditional_keysets_for_conditions(
        &self,
        condition_ids: &[String],
    ) -> Result<HashMap<String, HashMap<String, Id>>, Self::Err> {
        if condition_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        let placeholders = (0..condition_ids.len())
            .map(|index| format!(":condition_{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT condition_id, outcome_collection, id FROM conditional_keyset WHERE active = :active AND condition_id IN ({placeholders}) ORDER BY condition_id ASC, outcome_collection ASC");
        let mut stmt = query(&sql)?.bind("active", true);
        for (index, id) in condition_ids.iter().enumerate() {
            stmt = stmt.bind(format!("condition_{index}"), id.clone());
        }
        let mut maps = HashMap::new();
        for mut row in stmt.fetch_all(&*conn).await? {
            let condition_id = match row.remove(0) {
                Column::Text(value) => value,
                _ => {
                    return Err(Error::Internal(
                        "Invalid condition keyset mapping".to_string(),
                    ))
                }
            };
            let (outcome, id) = sql_row_to_keyset_mapping(row)?;
            maps.entry(condition_id)
                .or_insert_with(HashMap::new)
                .insert(outcome, id);
        }
        Ok(maps)
    }

    async fn get_conditional_keyset_infos_for_condition(
        &self,
        condition_id: &str,
    ) -> Result<Vec<MintKeySetInfo>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        let sql = format!(
            "SELECT {} FROM conditional_keyset \
             WHERE condition_id = :condition_id \
             ORDER BY created_at ASC, id ASC",
            CONDITIONAL_KEYSET_COLUMNS
        );
        query(&sql)?
            .bind("condition_id", condition_id.to_string())
            .fetch_all(&*conn)
            .await?
            .into_iter()
            .map(sql_row_to_conditional_mint_keyset_info)
            .map(|row| row.map(|(info, _)| info))
            .collect()
    }

    async fn get_all_conditional_keyset_infos(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
    ) -> Result<Vec<ConditionalKeySetInfo>, Self::Err> {
        self.get_conditional_keyset_infos_page(since, limit, active, None)
            .await
    }

    async fn get_conditional_keyset_infos_page(
        &self,
        since: Option<u64>,
        limit: Option<u64>,
        active: Option<bool>,
        after: Option<&(u64, String)>,
    ) -> Result<Vec<ConditionalKeySetInfo>, Self::Err> {
        let rows = self
            .query_conditional_keysets(since, limit, active, after)
            .await?;
        rows.into_iter()
            .map(|(info, created_at)| {
                mint_keyset_info_to_conditional_keyset_info(&info, created_at)
            })
            .collect()
    }

    async fn get_condition_for_keyset(
        &self,
        keyset_id: &Id,
    ) -> Result<Option<(String, String, String)>, Self::Err> {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;

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

    async fn get_condition_for_update(
        &mut self,
        condition_id: &str,
    ) -> Result<Option<cdk_common::database::mint::Acquired<StoredCondition>>, Self::Err> {
        query(&format!("SELECT {CONDITION_COLUMNS} FROM conditions WHERE condition_id = :condition_id FOR UPDATE"))?
        .bind("condition_id", condition_id.to_string())
        .fetch_one(&self.inner)
        .await?
        .map(sql_row_to_stored_condition)
        .transpose()
        .map(|condition| condition.map(Into::into))
    }

    async fn record_condition_attestation(
        &mut self,
        condition: &cdk_common::database::mint::Acquired<StoredCondition>,
        winning_outcome: &str,
        attested_at: u64,
        oracle_sigs: &[cdk_common::nuts::nut_ctf::OracleSig],
    ) -> Result<bool, Self::Err> {
        let mut result = (**condition).clone();
        result.attestation_status = "attested".to_string();
        result.winning_outcome = Some(winning_outcome.to_string());
        result.attested_at = Some(attested_at);
        result.oracle_sigs = Some(oracle_sigs.to_vec());
        result.validate()?;
        if condition.attestation_status != "pending" {
            return Ok(false);
        }
        let rows = query(
            r#"
            UPDATE conditions SET attestation_status = 'attested',
                winning_outcome = :winning_outcome, attested_at = :attested_at,
                oracle_sigs_json = :oracle_sigs_json
            WHERE condition_id = :condition_id AND attestation_status = 'pending'
        "#,
        )?
        .bind("condition_id", condition.condition_id.clone())
        .bind("winning_outcome", winning_outcome.to_string())
        .bind("attested_at", attested_at as i64)
        .bind(
            "oracle_sigs_json",
            serde_json::to_string(oracle_sigs).map_err(|err| Error::Internal(err.to_string()))?,
        )
        .execute(&self.inner)
        .await?;
        Ok(rows > 0)
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_row() -> Vec<Column> {
        vec![
            Column::Text("aa".repeat(32)),
            Column::Integer(1),
            Column::Text("[]".to_string()),
            Column::Text(r#"["deadbeef"]"#.to_string()),
            Column::Text("sat".to_string()),
            Column::Text("pending".to_string()),
            Column::Null,
            Column::Null,
            Column::Integer(1),
            Column::Text("enum".to_string()),
            Column::Null,
            Column::Null,
            Column::Null,
            Column::Null,
        ]
    }

    #[test]
    fn d2_strict_condition_rows_reject_corrupt_states_types_and_evidence() {
        assert!(sql_row_to_stored_condition(pending_row()).is_ok());
        for (column, corrupt) in [
            (1, Column::Integer(-1)),
            (1, Column::Integer(i64::MAX)),
            (2, Column::Text("invalid".to_string())),
            (5, Column::Text("unknown".to_string())),
            (6, Column::Text("YES".to_string())),
            (7, Column::Integer(-1)),
            (8, Column::Integer(-1)),
            (9, Column::Null),
            (9, Column::Text("unknown".to_string())),
            (12, Column::Integer(i64::MAX)),
            (13, Column::Text("invalid".to_string())),
            (13, Column::Text("[]".to_string())),
        ] {
            let mut row = pending_row();
            row[column] = corrupt;
            assert!(
                sql_row_to_stored_condition(row).is_err(),
                "invalid column {column}"
            );
        }
        let mut row = pending_row();
        row[5] = Column::Text("attested".to_string());
        row[6] = Column::Text("YES".to_string());
        row[7] = Column::Integer(2);
        for malformed in [
            "null",
            "{}",
            "[]",
            "[{}]",
            r#"[{"oracle_pubkey":"a","oracle_sig":"b","outcome":"YES"}]"#,
        ] {
            row[13] = Column::Text(malformed.to_string());
            assert!(sql_row_to_stored_condition(row.clone()).is_err());
        }
    }
}
