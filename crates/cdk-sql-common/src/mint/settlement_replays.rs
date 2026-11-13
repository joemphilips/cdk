use std::collections::HashMap;

use async_trait::async_trait;
use cdk_common::database::mint::{
    CtfSettlementReplay, CtfSettlementReplayDatabase, CtfSettlementReplayTransaction,
};
use cdk_common::database::Error;
use cdk_common::nuts::nut_ctf::settlement::{
    CanonicalHash, CtfSettlementResponse, OutputConflictState, OutputConflicts,
};
use cdk_common::nuts::PublicKey;
use cdk_common::util::unix_time;

use super::{SQLMintDatabase, SQLTransaction};
use crate::column_as_string;
use crate::pool::DatabasePool;
use crate::stmt::{query, Column};

fn decode_replay(row: Vec<Column>) -> Result<CtfSettlementReplay, Error> {
    match row.as_slice() {
        [Column::Text(outcome_kind), response_json, Column::Null]
            if outcome_kind == "committed" =>
        {
            let response = serde_json::from_str(&column_as_string!(response_json))?;
            Ok(CtfSettlementReplay::Committed(response))
        }
        [Column::Text(outcome_kind), Column::Null, Column::Integer(cutoff)]
            if outcome_kind == "rejected_after_cutoff" =>
        {
            let cutoff = u64::try_from(*cutoff).map_err(|_| {
                Error::Internal("invalid negative settlement rejection cutoff".to_string())
            })?;
            Ok(CtfSettlementReplay::RejectedAfterCutoff { cutoff })
        }
        _ => Err(Error::Internal(
            "invalid persisted settlement replay outcome".to_string(),
        )),
    }
}

fn decode_output_conflict(row: Vec<Column>) -> Result<CtfSettlementReplay, Error> {
    match row.as_slice() {
        [conflicts_json, cutoff] => {
            let conflicts = serde_json::from_str(&column_as_string!(conflicts_json))?;
            let cutoff = match cutoff {
                Column::Null => None,
                Column::Integer(cutoff) => Some(u64::try_from(*cutoff).map_err(|_| {
                    Error::Internal("invalid negative output conflict cutoff".to_string())
                })?),
                _ => {
                    return Err(Error::Internal(
                        "invalid persisted output conflict cutoff".to_string(),
                    ))
                }
            };
            Ok(CtfSettlementReplay::RejectedOutputConflict { conflicts, cutoff })
        }
        _ => Err(Error::Internal(
            "invalid persisted output conflict record".to_string(),
        )),
    }
}

/// Read the terminal outcome of a request digest from either outcome table.
///
/// A digest has at most one outcome: every writer reads this under the
/// condition row lock before it writes.
async fn read_replay<EX>(
    executor: &EX,
    request_digest: CanonicalHash,
) -> Result<Option<CtfSettlementReplay>, Error>
where
    EX: crate::database::DatabaseExecutor,
{
    let replay = query(
        r#"
        SELECT outcome_kind, CAST(response_json AS TEXT), cutoff
        FROM ctf_settlement_replays
        WHERE request_digest = :request_digest
        "#,
    )?
    .bind("request_digest", request_digest.to_bytes().to_vec())
    .fetch_one(executor)
    .await?
    .map(decode_replay)
    .transpose()?;
    if replay.is_some() {
        return Ok(replay);
    }

    query(
        r#"
        SELECT CAST(conflicts_json AS TEXT), cutoff
        FROM ctf_settlement_output_conflicts
        WHERE request_digest = :request_digest
        "#,
    )?
    .bind("request_digest", request_digest.to_bytes().to_vec())
    .fetch_one(executor)
    .await?
    .map(decode_output_conflict)
    .transpose()
}

fn optional_i64(value: Option<u64>, field: &str) -> Result<Option<i64>, Error> {
    value
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::Internal(format!("{field} exceeds i64")))
}

#[async_trait]
impl<RM> CtfSettlementReplayTransaction for SQLTransaction<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    async fn get_ctf_settlement_replay(
        &mut self,
        request_digest: CanonicalHash,
    ) -> Result<Option<CtfSettlementReplay>, Self::Err> {
        read_replay(&self.inner, request_digest).await
    }

    async fn add_ctf_settlement_replay(
        &mut self,
        request_digest: CanonicalHash,
        operation_id: &uuid::Uuid,
        response: &CtfSettlementResponse,
    ) -> Result<(), Self::Err> {
        query(
            r#"
            INSERT INTO ctf_settlement_replays
                (request_digest, outcome_kind, operation_id, response_json, cutoff, created_at)
            VALUES
                (:request_digest, 'committed', :operation_id, :response_json, NULL, :created_at)
            "#,
        )?
        .bind("request_digest", request_digest.to_bytes().to_vec())
        .bind("operation_id", operation_id.to_string())
        .bind("response_json", serde_json::to_string(response)?)
        .bind("created_at", unix_time() as i64)
        .execute(&self.inner)
        .await?;
        Ok(())
    }

    async fn add_ctf_settlement_rejection(
        &mut self,
        request_digest: CanonicalHash,
        cutoff: u64,
    ) -> Result<(), Self::Err> {
        let cutoff = i64::try_from(cutoff)
            .map_err(|_| Error::Internal("settlement rejection cutoff exceeds i64".to_string()))?;
        query(
            r#"
            INSERT INTO ctf_settlement_replays
                (request_digest, outcome_kind, operation_id, response_json, cutoff, created_at)
            VALUES
                (:request_digest, 'rejected_after_cutoff', NULL, NULL, :cutoff, :created_at)
            "#,
        )?
        .bind("request_digest", request_digest.to_bytes().to_vec())
        .bind("cutoff", cutoff)
        .bind("created_at", unix_time() as i64)
        .execute(&self.inner)
        .await?;
        Ok(())
    }

    async fn get_ctf_output_states(
        &mut self,
        blinded_secrets: &[PublicKey],
    ) -> Result<Vec<Option<OutputConflictState>>, Self::Err> {
        if blinded_secrets.is_empty() {
            return Ok(Vec::new());
        }
        let mut states = query(
            r#"
            SELECT blinded_message, CASE WHEN c IS NULL THEN 0 ELSE 1 END
            FROM blind_signature
            WHERE blinded_message IN (:blinded_secrets)
            "#,
        )?
        .bind_vec(
            "blinded_secrets",
            blinded_secrets
                .iter()
                .map(|secret| secret.to_bytes().to_vec())
                .collect(),
        )?
        .fetch_all(&self.inner)
        .await?
        .into_iter()
        .map(|row| match row.as_slice() {
            [blinded_message, Column::Integer(signed)] => {
                let blinded_message =
                    column_as_string!(blinded_message, PublicKey::from_hex, PublicKey::from_slice);
                let state = if *signed == 0 {
                    OutputConflictState::Pending
                } else {
                    OutputConflictState::Signed
                };
                Ok((blinded_message, state))
            }
            _ => Err(Error::InvalidDbResponse),
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
        Ok(blinded_secrets
            .iter()
            .map(|secret| states.remove(secret))
            .collect())
    }

    async fn add_ctf_settlement_output_conflict(
        &mut self,
        request_digest: CanonicalHash,
        conflicts: &OutputConflicts,
        cutoff: Option<u64>,
    ) -> Result<(), Self::Err> {
        query(
            r#"
            INSERT INTO ctf_settlement_output_conflicts
                (request_digest, conflicts_json, cutoff, created_at)
            VALUES
                (:request_digest, :conflicts_json, :cutoff, :created_at)
            "#,
        )?
        .bind("request_digest", request_digest.to_bytes().to_vec())
        .bind("conflicts_json", serde_json::to_string(conflicts)?)
        .bind("cutoff", optional_i64(cutoff, "output conflict cutoff")?)
        .bind("created_at", unix_time() as i64)
        .execute(&self.inner)
        .await?;
        Ok(())
    }

    async fn delete_expired_ctf_settlement_output_conflicts(
        &mut self,
        expired_at: u64,
        limit: u64,
    ) -> Result<u64, Self::Err> {
        let expired_at = i64::try_from(expired_at)
            .map_err(|_| Error::Internal("output conflict expiry exceeds i64".to_string()))?;
        let limit = i64::try_from(limit)
            .map_err(|_| Error::Internal("output conflict delete limit exceeds i64".to_string()))?;
        let deleted = query(
            r#"
            DELETE FROM ctf_settlement_output_conflicts
            WHERE request_digest IN (
                SELECT request_digest
                FROM ctf_settlement_output_conflicts
                WHERE cutoff IS NOT NULL AND cutoff <= :expired_at
                ORDER BY cutoff, request_digest
                LIMIT :limit
            )
            "#,
        )?
        .bind("expired_at", expired_at)
        .bind("limit", limit)
        .execute(&self.inner)
        .await?;
        Ok(deleted as u64)
    }
}

#[async_trait]
impl<RM> CtfSettlementReplayDatabase for SQLMintDatabase<RM>
where
    RM: DatabasePool + 'static,
{
    type Err = Error;

    async fn get_ctf_settlement_replay(
        &self,
        request_digest: CanonicalHash,
    ) -> Result<Option<CtfSettlementReplay>, Self::Err> {
        let connection = self
            .pool
            .get()
            .await
            .map_err(|error| Error::Database(Box::new(error)))?;
        read_replay(&*connection, request_digest).await
    }
}
