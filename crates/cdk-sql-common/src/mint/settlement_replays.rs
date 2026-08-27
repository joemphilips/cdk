use async_trait::async_trait;
use cdk_common::database::mint::{
    CtfSettlementReplay, CtfSettlementReplayDatabase, CtfSettlementReplayTransaction,
};
use cdk_common::database::Error;
use cdk_common::nuts::nut_ctf::settlement::{CanonicalHash, CtfSettlementResponse};
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

async fn read_replay<EX>(
    executor: &EX,
    request_digest: CanonicalHash,
) -> Result<Option<CtfSettlementReplay>, Error>
where
    EX: crate::database::DatabaseExecutor,
{
    query(
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
    .transpose()
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
