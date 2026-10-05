use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cdk_common::database::Error;
use cdk_sql_common::database::{DatabaseConnector, DatabaseExecutor, DatabaseTransaction};
use cdk_sql_common::pool::{DatabaseConfig, DatabasePool};
use cdk_sql_common::stmt::{Column, Statement};

#[derive(Debug, Clone)]
pub(super) struct CountingConfig<C> {
    pub inner: C,
    pub reads: Arc<AtomicUsize>,
}

impl<C: DatabaseConfig> DatabaseConfig for CountingConfig<C> {
    fn max_size(&self) -> usize {
        self.inner.max_size()
    }
    fn default_timeout(&self) -> Duration {
        self.inner.default_timeout()
    }
}

#[derive(Debug)]
pub(super) struct CountingPool<P>(PhantomData<P>);

impl<P: DatabasePool> DatabasePool for CountingPool<P> {
    type Config = CountingConfig<P::Config>;
    type Connection = CountingConnection<P::Connection>;
    type Error = P::Error;

    fn new_resource(
        config: &Self::Config,
        stale: Arc<AtomicBool>,
        timeout: Duration,
    ) -> Result<Self::Connection, cdk_sql_common::pool::Error<Self::Error>> {
        Ok(CountingConnection {
            inner: P::new_resource(&config.inner, stale, timeout)?,
            reads: config.reads.clone(),
        })
    }
}

#[derive(Debug)]
pub(super) struct CountingConnection<C> {
    inner: C,
    reads: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl<C: DatabaseConnector> DatabaseConnector for CountingConnection<C> {
    type Transaction = CountingTransaction<C>;
}

#[async_trait::async_trait]
impl<C: DatabaseExecutor> DatabaseExecutor for CountingConnection<C> {
    fn name() -> &'static str {
        C::name()
    }
    async fn execute(&self, statement: Statement) -> Result<usize, Error> {
        self.inner.execute(statement).await
    }
    async fn fetch_one(&self, statement: Statement) -> Result<Option<Vec<Column>>, Error> {
        self.inner.fetch_one(statement).await
    }
    async fn fetch_all(&self, statement: Statement) -> Result<Vec<Vec<Column>>, Error> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch_all(statement).await
    }
    async fn pluck(&self, statement: Statement) -> Result<Option<Column>, Error> {
        self.inner.pluck(statement).await
    }
    async fn batch(&self, statement: Statement) -> Result<(), Error> {
        self.inner.batch(statement).await
    }
}

#[derive(Debug)]
pub(super) struct CountingTransaction<C>(PhantomData<C>);

#[async_trait::async_trait]
impl<C: DatabaseConnector> DatabaseTransaction<CountingConnection<C>> for CountingTransaction<C> {
    async fn commit(conn: &mut CountingConnection<C>) -> Result<(), Error> {
        C::Transaction::commit(&mut conn.inner).await
    }
    async fn begin(conn: &mut CountingConnection<C>) -> Result<(), Error> {
        C::Transaction::begin(&mut conn.inner).await
    }
    async fn rollback(conn: &mut CountingConnection<C>) -> Result<(), Error> {
        C::Transaction::rollback(&mut conn.inner).await
    }
}
