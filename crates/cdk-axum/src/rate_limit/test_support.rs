//! Request-time observations for the real-router fixtures. No backend loops run.
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cdk_common::database::Error;
use cdk_sql_common::database::{DatabaseConnector, DatabaseExecutor, DatabaseTransaction};
use cdk_sql_common::pool::{DatabaseConfig, DatabasePool};
use cdk_sql_common::stmt::{Column, Statement};

/// Each executor/transaction boundary is independently observable.
#[derive(Debug, Default)]
pub(super) struct Effects {
    armed: AtomicBool,
    sql: [AtomicUsize; 8],
    cache: [AtomicUsize; 3],
    payment: AtomicUsize,
    handlers: [AtomicUsize; 4],
}

impl Effects {
    pub(super) fn arm(&self) {
        for count in &self.sql {
            count.store(0, Ordering::SeqCst);
        }
        for count in self.cache.iter().chain(self.handlers.iter()) {
            count.store(0, Ordering::SeqCst);
        }
        self.payment.store(0, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }

    fn hit(&self, count: &AtomicUsize) {
        if self.armed.load(Ordering::SeqCst) {
            count.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(super) fn assert_external_zero(&self) {
        assert_eq!(self.sql_counts(), [0; 8]);
        assert!(self.cache.iter().all(|n| n.load(Ordering::SeqCst) == 0));
        assert_eq!(self.payment.load(Ordering::SeqCst), 0);
    }

    pub(super) fn assert_zero(&self) {
        self.assert_external_zero();
        assert!(self.handlers.iter().all(|n| n.load(Ordering::SeqCst) == 0));
    }

    pub(super) fn assert_convert_entered(&self) {
        assert!(self.handlers[3].load(Ordering::SeqCst) > 0);
    }

    fn sql(&self, index: usize) {
        if self.armed.load(Ordering::SeqCst) {
            self.sql[index].fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(super) fn sql_counts(&self) -> [usize; 8] {
        std::array::from_fn(|index| self.sql[index].load(Ordering::SeqCst))
    }
}

#[derive(Debug, Clone)]
pub(super) struct ObservedConfig<C> {
    pub inner: C,
    pub effects: Arc<Effects>,
}

impl<C> DatabaseConfig for ObservedConfig<C>
where
    C: DatabaseConfig,
{
    fn max_size(&self) -> usize {
        self.inner.max_size()
    }

    fn default_timeout(&self) -> Duration {
        self.inner.default_timeout()
    }
}

#[derive(Debug)]
pub(super) struct ObservedPool<P>(PhantomData<P>);

impl<P> DatabasePool for ObservedPool<P>
where
    P: DatabasePool,
{
    type Config = ObservedConfig<P::Config>;
    type Connection = ObservedConnection<P::Connection>;
    type Error = P::Error;

    fn new_resource(
        config: &Self::Config,
        stale: Arc<AtomicBool>,
        timeout: Duration,
    ) -> Result<Self::Connection, cdk_sql_common::pool::Error<Self::Error>> {
        Ok(ObservedConnection {
            inner: P::new_resource(&config.inner, stale, timeout)?,
            effects: config.effects.clone(),
        })
    }
}

#[derive(Debug)]
pub(super) struct ObservedConnection<C> {
    inner: C,
    effects: Arc<Effects>,
}

#[async_trait::async_trait]
impl<C> DatabaseConnector for ObservedConnection<C>
where
    C: DatabaseConnector,
{
    type Transaction = ObservedTransaction<C>;
}

#[async_trait::async_trait]
impl<C> DatabaseExecutor for ObservedConnection<C>
where
    C: DatabaseExecutor,
{
    fn name() -> &'static str {
        C::name()
    }

    async fn execute(&self, statement: Statement) -> Result<usize, Error> {
        self.effects.sql(0);
        self.inner.execute(statement).await
    }

    async fn fetch_one(&self, statement: Statement) -> Result<Option<Vec<Column>>, Error> {
        self.effects.sql(1);
        self.inner.fetch_one(statement).await
    }

    async fn fetch_all(&self, statement: Statement) -> Result<Vec<Vec<Column>>, Error> {
        self.effects.sql(2);
        self.inner.fetch_all(statement).await
    }

    async fn pluck(&self, statement: Statement) -> Result<Option<Column>, Error> {
        self.effects.sql(3);
        self.inner.pluck(statement).await
    }

    async fn batch(&self, statement: Statement) -> Result<(), Error> {
        self.effects.sql(4);
        self.inner.batch(statement).await
    }
}

#[derive(Debug)]
pub(super) struct ObservedTransaction<C>(PhantomData<C>);

#[async_trait::async_trait]
impl<C> DatabaseTransaction<ObservedConnection<C>> for ObservedTransaction<C>
where
    C: DatabaseConnector,
{
    async fn begin(conn: &mut ObservedConnection<C>) -> Result<(), Error> {
        conn.effects.sql(5);
        C::Transaction::begin(&mut conn.inner).await
    }

    async fn commit(conn: &mut ObservedConnection<C>) -> Result<(), Error> {
        conn.effects.sql(6);
        C::Transaction::commit(&mut conn.inner).await
    }

    async fn rollback(conn: &mut ObservedConnection<C>) -> Result<(), Error> {
        conn.effects.sql(7);
        C::Transaction::rollback(&mut conn.inner).await
    }
}

#[tokio::test]
async fn every_sql_observer_has_a_real_positive_control() {
    use cdk_sql_common::stmt::query;

    type Pool = ObservedPool<cdk_sqlite::SqliteConnectionManager>;
    type Transaction =
        ObservedTransaction<<cdk_sqlite::SqliteConnectionManager as DatabasePool>::Connection>;
    let effects = Arc::new(Effects::default());
    let config = ObservedConfig {
        inner: <cdk_sqlite::SqliteConnectionManager as DatabasePool>::Config::from(":memory:"),
        effects: effects.clone(),
    };
    let mut connection = Pool::new_resource(
        &config,
        Arc::new(AtomicBool::new(false)),
        Duration::from_secs(5),
    )
    .unwrap();
    connection
        .execute(query("CREATE TABLE positive_control (value INTEGER)").unwrap())
        .await
        .unwrap();
    assert_eq!(effects.sql_counts(), [0; 8]);
    effects.arm();
    connection
        .execute(query("INSERT INTO positive_control VALUES (1)").unwrap())
        .await
        .unwrap();
    connection
        .fetch_one(query("SELECT value FROM positive_control").unwrap())
        .await
        .unwrap();
    connection
        .fetch_all(query("SELECT value FROM positive_control").unwrap())
        .await
        .unwrap();
    connection
        .pluck(query("SELECT value FROM positive_control").unwrap())
        .await
        .unwrap();
    connection
        .batch(query("UPDATE positive_control SET value=2").unwrap())
        .await
        .unwrap();
    Transaction::begin(&mut connection).await.unwrap();
    Transaction::commit(&mut connection).await.unwrap();
    Transaction::begin(&mut connection).await.unwrap();
    Transaction::rollback(&mut connection).await.unwrap();
    assert_eq!(effects.sql_counts(), [1, 1, 1, 1, 1, 2, 1, 1]);
    effects.arm();
    assert_eq!(effects.sql_counts(), [0; 8]);
}

#[derive(Debug)]
pub(super) struct ObservedCache(pub Arc<Effects>);

#[async_trait::async_trait]
impl crate::cache::HttpCacheStorage for ObservedCache {
    fn set_expiration_times(&mut self, _: Duration, _: Duration) {
        self.0.hit(&self.0.cache[0]);
    }
    async fn get(&self, _: &crate::cache::HttpCacheKey) -> Option<Vec<u8>> {
        self.0.hit(&self.0.cache[1]);
        None
    }
    async fn set(&self, _: crate::cache::HttpCacheKey, _: Vec<u8>) {
        self.0.hit(&self.0.cache[2]);
    }
}

#[derive(Debug)]
pub(super) struct PoisonPayment(pub Arc<Effects>);

impl PoisonPayment {
    fn refuse<T>(&self) -> Result<T, cdk_common::payment::Error> {
        self.0.hit(&self.0.payment);
        Err(cdk_common::payment::Error::UnsupportedPaymentOption)
    }
}

#[async_trait::async_trait]
impl cdk_common::payment::MintPayment for PoisonPayment {
    type Err = cdk_common::payment::Error;
    async fn start(&self) -> Result<(), Self::Err> {
        self.refuse()
    }
    async fn stop(&self) -> Result<(), Self::Err> {
        self.refuse()
    }
    async fn get_settings(&self) -> Result<cdk_common::payment::SettingsResponse, Self::Err> {
        if self.0.armed.load(Ordering::SeqCst) {
            return self.refuse();
        }
        Ok(cdk_common::payment::SettingsResponse {
            unit: "sat".to_owned(),
            bolt11: Some(Default::default()),
            bolt12: Some(Default::default()),
            onchain: None,
            custom: Default::default(),
        })
    }
    async fn create_incoming_payment_request(
        &self,
        _: cdk_common::payment::IncomingPaymentOptions,
    ) -> Result<cdk_common::payment::CreateIncomingPaymentResponse, Self::Err> {
        self.refuse()
    }
    async fn get_payment_quote(
        &self,
        _: &cdk_common::nuts::CurrencyUnit,
        _: cdk_common::payment::OutgoingPaymentOptions,
    ) -> Result<cdk_common::payment::PaymentQuoteResponse, Self::Err> {
        self.refuse()
    }
    async fn make_payment(
        &self,
        _: &cdk_common::nuts::CurrencyUnit,
        _: cdk_common::payment::OutgoingPaymentOptions,
    ) -> Result<cdk_common::payment::MakePaymentResponse, Self::Err> {
        self.refuse()
    }
    async fn wait_payment_event(
        &self,
    ) -> Result<
        std::pin::Pin<Box<dyn futures::Stream<Item = cdk_common::payment::Event> + Send>>,
        Self::Err,
    > {
        self.refuse()
    }
    fn is_payment_event_stream_active(&self) -> bool {
        self.0.hit(&self.0.payment);
        false
    }
    fn cancel_payment_event_stream(&self) {
        self.0.hit(&self.0.payment);
    }
    async fn check_incoming_payment_status(
        &self,
        _: &cdk_common::payment::PaymentIdentifier,
    ) -> Result<Vec<cdk_common::payment::WaitPaymentResponse>, Self::Err> {
        self.refuse()
    }
    async fn release_incoming_payment_request(
        &self,
        _: &cdk_common::payment::PaymentIdentifier,
    ) -> Result<(), Self::Err> {
        self.refuse()
    }
    async fn check_outgoing_payment(
        &self,
        _: &cdk_common::payment::PaymentIdentifier,
    ) -> Result<cdk_common::payment::MakePaymentResponse, Self::Err> {
        self.refuse()
    }
}

/// Counts only the actual selected handler spans, never limiter or HTTP metrics.
#[derive(Debug)]
pub(super) struct HandlerObserver {
    effects: Arc<Effects>,
    next: AtomicUsize,
}
impl HandlerObserver {
    pub(super) fn new(effects: Arc<Effects>) -> Self {
        Self {
            effects,
            next: AtomicUsize::new(1),
        }
    }
}
impl tracing::Subscriber for HandlerObserver {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        if let Some(index) = [
            "post_swap",
            "post_mint_custom_quote",
            "post_restore",
            "post_ctf_convert",
        ]
        .iter()
        .position(|name| *name == attributes.metadata().name())
        {
            self.effects.hit(&self.effects.handlers[index]);
        }
        tracing::span::Id::from_u64(self.next.fetch_add(1, Ordering::Relaxed) as u64)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn cache_and_payment_observers_have_positive_controls() {
    use crate::cache::HttpCacheStorage;
    use cdk_common::payment::MintPayment;
    let effects = Arc::new(Effects::default());
    let mut cache = ObservedCache(effects.clone());
    let key = crate::cache::HttpCache::default()
        .calculate_key(&"positive")
        .unwrap();
    effects.arm();
    cache.set_expiration_times(Duration::from_secs(1), Duration::from_secs(1));
    cache.get(&key).await;
    cache.set(key, vec![1]).await;
    assert_eq!(
        std::array::from_fn::<_, 3, _>(|i| effects.cache[i].load(Ordering::SeqCst)),
        [1, 1, 1]
    );
    assert!(PoisonPayment(effects.clone()).get_settings().await.is_err());
    assert_eq!(effects.payment.load(Ordering::SeqCst), 1);
    effects.arm();
    effects.assert_zero();
}

pub(super) fn assert_handler_controls(effects: &Effects) {
    for count in effects.handlers.iter().take(3) {
        assert!(count.load(Ordering::SeqCst) > 0);
    }
}

/// Owns only this fixture's process and directory. Explicit stop verifies reap;
/// panic cleanup also kills and polls within a fixed bound.
pub(super) struct LocalCaddy {
    child: Option<std::process::Child>,
    directory: std::path::PathBuf,
}

impl LocalCaddy {
    pub(super) fn start(port: u16, upstream: u16) -> Self {
        assert_eq!(std::env::var("CDK_RATE_LIMIT_CADDY").as_deref(), Ok("1"));
        let binary = std::path::PathBuf::from(
            std::env::var("CDK_RATE_LIMIT_CADDY_BINARY").expect("verified local Caddy binary"),
        );
        assert!(binary.is_absolute() && binary.is_file());
        let directory =
            std::env::temp_dir().join(format!("cdk-rate-caddy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let mut owner = Self {
            child: None,
            directory: directory.clone(),
        };
        for name in ["home", "config", "data"] {
            std::fs::create_dir(directory.join(name)).unwrap();
        }
        let configuration = directory.join("Caddyfile");
        std::fs::write(&configuration, format!("{{\n admin off\n auto_https off\n}}\nhttp://127.0.0.1:{port} {{\n bind 127.0.0.1\n reverse_proxy 127.0.0.1:{upstream}\n}}\n")).unwrap();
        let child = std::process::Command::new(binary)
            .args(["run", "--config"])
            .arg(configuration)
            .args(["--adapter", "caddyfile"])
            .env_clear()
            .env("HOME", directory.join("home"))
            .env("XDG_CONFIG_HOME", directory.join("config"))
            .env("XDG_DATA_HOME", directory.join("data"))
            .env("TMPDIR", &directory)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&directory)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        owner.child = Some(child);
        owner
    }

    pub(super) fn running(&mut self) -> bool {
        self.child
            .as_mut()
            .expect("owned Caddy")
            .try_wait()
            .unwrap()
            .is_none()
    }

    pub(super) fn stop(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        let _ = child.kill();
        let end = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < end {
            if child.try_wait().ok().flatten().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }
}

impl Drop for LocalCaddy {
    fn drop(&mut self) {
        if self.stop() {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}

pub(super) struct WireResponse {
    pub status: u16,
    pub headers: String,
    pub body: Vec<u8>,
}

/// Fixed bounded HTTP/1.1 request shapes. Unknown length uses real chunk framing.
pub(super) async fn wire_request(
    port: u16,
    source: u8,
    method: &str,
    path: &str,
    forwarded: &[&str],
    size: usize,
    chunked: bool,
) -> std::io::Result<WireResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let operation = async {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(std::net::SocketAddr::from(([127, 0, 0, source], 0)))?;
        let mut stream = socket
            .connect(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .await?;
        let mut header = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Type: application/json\r\n");
        for value in forwarded {
            header.push_str(&format!("X-Forwarded-For: {value}\r\n"));
        }
        header.push_str(&if chunked {
            "Transfer-Encoding: chunked\r\n\r\n".to_owned()
        } else {
            format!("Content-Length: {size}\r\n\r\n")
        });
        stream.write_all(header.as_bytes()).await?;
        let mut bytes = vec![b' '; size];
        if let Some(first) = bytes.first_mut() {
            *first = b'{';
        }
        if chunked {
            for part in bytes.chunks(8192) {
                stream
                    .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                    .await?;
                stream.write_all(part).await?;
                stream.write_all(b"\r\n").await?;
            }
            stream.write_all(b"0\r\n\r\n").await?;
        } else {
            stream.write_all(&bytes).await?;
        }
        let mut response = Vec::new();
        stream.take(65_537).read_to_end(&mut response).await?;
        assert!(response.len() <= 65_536, "bounded fixture response");
        let boundary = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .expect("HTTP response headers");
        let headers = String::from_utf8(response[..boundary].to_vec()).unwrap();
        let status = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let mut body = response[boundary + 4..].to_vec();
        if headers
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            let mut remaining = body.as_slice();
            let mut decoded = Vec::new();
            loop {
                let end = remaining
                    .windows(2)
                    .position(|bytes| bytes == b"\r\n")
                    .unwrap();
                let length =
                    usize::from_str_radix(std::str::from_utf8(&remaining[..end]).unwrap(), 16)
                        .unwrap();
                remaining = &remaining[end + 2..];
                if length == 0 {
                    break;
                }
                assert!(length <= remaining.len().saturating_sub(2));
                decoded.extend_from_slice(&remaining[..length]);
                assert_eq!(&remaining[length..length + 2], b"\r\n");
                remaining = &remaining[length + 2..];
            }
            body = decoded;
        }
        Ok(WireResponse {
            status,
            headers,
            body,
        })
    };
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "bounded local fixture request",
            )
        })?
}

/// Aborts only the owned HTTP task even if process startup or assertions panic.
pub(super) struct AbortTask(pub tokio::task::AbortHandle);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
