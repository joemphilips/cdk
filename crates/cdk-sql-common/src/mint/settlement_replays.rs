use async_trait::async_trait;
use cdk_common::database::mint::{CtfSettlementReplayDatabase, CtfSettlementReplayTransaction};
use cdk_common::database::Error;
use cdk_common::nuts::nut_ctf::settlement::{CanonicalHash, CtfSettlementResponse};
use cdk_common::util::unix_time;

use super::{SQLMintDatabase, SQLTransaction};
use crate::column_as_string;
use crate::pool::DatabasePool;
use crate::stmt::{query, Column};

fn decode_response(row: Vec<Column>) -> Result<CtfSettlementResponse, Error> {
    let value = row
        .first()
        .ok_or_else(|| Error::Internal("missing settlement replay response".to_string()))?;
    serde_json::from_str(&column_as_string!(value)).map_err(Error::from)
}

async fn read_response<EX>(
    executor: &EX,
    request_digest: CanonicalHash,
) -> Result<Option<CtfSettlementResponse>, Error>
where
    EX: crate::database::DatabaseExecutor,
{
    query(
        r#"
        SELECT CAST(response_json AS TEXT)
        FROM ctf_settlement_replays
        WHERE request_digest = :request_digest
        "#,
    )?
    .bind("request_digest", request_digest.to_bytes().to_vec())
    .fetch_one(executor)
    .await?
    .map(decode_response)
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
    ) -> Result<Option<CtfSettlementResponse>, Self::Err> {
        read_response(&self.inner, request_digest).await
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
                (request_digest, operation_id, response_json, created_at)
            VALUES
                (:request_digest, :operation_id, :response_json, :created_at)
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
    ) -> Result<Option<CtfSettlementResponse>, Self::Err> {
        let connection = self
            .pool
            .get()
            .await
            .map_err(|error| Error::Database(Box::new(error)))?;
        read_response(&*connection, request_digest).await
    }
}
