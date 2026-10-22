//! Resolve connector verification and PostgreSQL negotiation from one TLS policy.

use cdk_common::database::Error;
use native_tls::{TlsConnector, TlsConnectorBuilder};
use postgres_native_tls::MakeTlsConnector;
use tokio_postgres::config::SslMode as PgSslMode;
use tokio_postgres::{Config, NoTls};

use crate::SslMode;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TlsPolicy {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl TlsPolicy {
    fn parse(value: &str) -> Result<Self, Error> {
        match value.to_ascii_lowercase().as_str() {
            "disable" => Ok(Self::Disable),
            "allow" | "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-full" => Ok(Self::VerifyFull),
            // Do not echo arbitrary connection-string contents in errors.
            _ => Err(Error::Internal("Invalid PostgreSQL TLS mode".to_owned())),
        }
    }

    fn negotiation(self) -> PgSslMode {
        match self {
            Self::Disable => PgSslMode::Disable,
            Self::Prefer => PgSslMode::Prefer,
            Self::Require | Self::VerifyCa | Self::VerifyFull => PgSslMode::Require,
        }
    }

    fn build_connector<F>(self, build: F) -> Result<SslMode, Error>
    where
        F: FnOnce(TlsConnectorBuilder) -> Result<TlsConnector, native_tls::Error>,
    {
        if matches!(self, Self::Disable) {
            return Ok(SslMode::NoTls(NoTls));
        }

        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(matches!(self, Self::Prefer | Self::Require));
        builder.danger_accept_invalid_hostnames(!matches!(self, Self::VerifyFull));
        let connector = build(builder).map_err(|err| Error::Database(Box::new(err)))?;
        Ok(SslMode::NativeTls(MakeTlsConnector::new(connector)))
    }
}

pub(super) fn configure(input: &str, explicit: Option<&str>) -> Result<(Config, SslMode), Error> {
    let (config, policy) = resolve(input, explicit)?;
    Ok((config, policy.build_connector(|builder| builder.build())?))
}

pub(super) fn resolve(input: &str, explicit: Option<&str>) -> Result<(Config, TlsPolicy), Error> {
    let (normalized, url_policy) = normalize(input)?;
    let explicit_policy = match explicit {
        Some(mode) => Some(TlsPolicy::parse(mode)?),
        None => None,
    };
    let policy = match (url_policy, explicit_policy) {
        (Some(url), Some(explicit)) if url != explicit => {
            return Err(Error::Internal(
                "Conflicting PostgreSQL TLS modes".to_owned(),
            ));
        }
        (_, Some(mode)) => mode,
        (Some(mode), None) => mode,
        (None, None) => TlsPolicy::Disable,
    };
    let mut config: Config = normalized
        .parse()
        .map_err(|err| Error::Database(Box::new(err)))?;
    config.ssl_mode(policy.negotiation());
    Ok((config, policy))
}

// tokio-postgres only parses disable/prefer/require. Extract the complete mode
// and replace it with a supported placeholder before invoking its parser. All
// modes, including overridden values, are validated to catch configuration typos.
fn normalize(input: &str) -> Result<(String, Option<TlsPolicy>), Error> {
    let mut policy = None;
    let mut output = String::new();
    if input.starts_with("postgres://") || input.starts_with("postgresql://") {
        let Some((base, query)) = input.split_once('?') else {
            return Ok((input.to_owned(), None));
        };
        if query.is_empty() {
            return Ok((input.to_owned(), None));
        }
        output.push_str(base);
        output.push('?');
        for (index, parameter) in query.split('&').enumerate() {
            if index != 0 {
                output.push('&');
            }
            let (key, value) = parameter.split_once('=').ok_or_else(invalid_parameters)?;
            let key = percent_encoding::percent_decode_str(key)
                .decode_utf8()
                .map_err(|_| invalid_parameters())?;
            if key == "sslmode" {
                if policy.is_some() {
                    return Err(invalid_parameters());
                }
                let value = percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .map_err(|_| invalid_parameters())?;
                policy = Some(TlsPolicy::parse(&value)?);
                output.push_str("sslmode=disable");
            } else {
                output.push_str(parameter);
            }
        }
    } else {
        // Respect libpq keyword syntax: whitespace around '=', quoted values,
        // and backslash escapes. Never search inside passwords or other values.
        let mut rest = input;
        while !rest.trim_start().is_empty() {
            rest = rest.trim_start();
            let start = rest;
            let key_end = rest
                .find(|ch: char| ch == '=' || ch.is_whitespace())
                .ok_or_else(invalid_parameters)?;
            let key = &rest[..key_end];
            rest = rest[key_end..].trim_start();
            rest = rest
                .strip_prefix('=')
                .ok_or_else(invalid_parameters)?
                .trim_start();
            let quoted = rest.starts_with('\'');
            if quoted {
                rest = &rest[1..];
            }
            let mut value = String::new();
            let mut chars = rest.char_indices();
            let mut end = rest.len();
            let mut closed = !quoted;
            while let Some((index, ch)) = chars.next() {
                match ch {
                    '\\' => {
                        let (_, escaped) = chars.next().ok_or_else(invalid_parameters)?;
                        value.push(escaped);
                    }
                    '\'' if quoted => {
                        end = index + 1;
                        closed = true;
                        break;
                    }
                    ch if !quoted && ch.is_whitespace() => {
                        end = index;
                        break;
                    }
                    ch => value.push(ch),
                }
            }
            if !closed || (!quoted && value.is_empty()) {
                return Err(invalid_parameters());
            }
            rest = &rest[end..];
            if key == "sslmode" {
                if policy.is_some() {
                    return Err(invalid_parameters());
                }
                policy = Some(TlsPolicy::parse(&value)?);
                output.push_str("sslmode=disable");
            } else {
                output.push_str(&start[..start.len() - rest.len()]);
            }
            output.push(' ');
        }
    }
    Ok((output, policy))
}

fn invalid_parameters() -> Error {
    Error::Internal("Invalid PostgreSQL connection parameters".to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::process::Command;
    use tokio::time::timeout;

    use super::*;
    use crate::{PgConfig, PostgresConnection};

    #[test]
    fn tls_connector_construction_errors_never_disable_tls() {
        // Inject a native TLS error because platform connector-construction
        // failures cannot be triggered portably through builder settings.
        let error = native_tls::Certificate::from_pem(b"not a certificate")
            .err()
            .expect("invalid certificate");
        let result = TlsPolicy::Require.build_connector(|_| Err(error));
        assert!(matches!(result, Err(Error::Database(_))));
    }

    #[test]
    fn tls_modes_set_connector_and_negotiation_together() {
        for (mode, negotiation) in [
            ("disable", PgSslMode::Disable),
            ("prefer", PgSslMode::Prefer),
            ("require", PgSslMode::Require),
            ("verify-ca", PgSslMode::Require),
            ("verify-full", PgSslMode::Require),
        ] {
            let (config, connector) =
                configure(&format!("host=localhost sslmode={mode}"), Some(mode))
                    .expect("explicit TLS mode");
            assert_eq!(config.get_ssl_mode(), negotiation, "{mode}");
            assert_eq!(matches!(connector, SslMode::NoTls(_)), mode == "disable");
        }
        let (config, connector) = configure("host=localhost sslmode=allow", Some("prefer"))
            .expect("allow and prefer have the same policy");
        assert_eq!(config.get_ssl_mode(), PgSslMode::Prefer);
        assert!(matches!(connector, SslMode::NativeTls(_)));

        let (config, connector) =
            configure("postgres://localhost/db?sslmode=verify-full", None).expect("URL policy");
        assert_eq!(config.get_ssl_mode(), PgSslMode::Require);
        assert!(matches!(connector, SslMode::NativeTls(_)));
        assert_eq!(
            configure("host=localhost", None)
                .expect("default")
                .0
                .get_ssl_mode(),
            PgSslMode::Disable
        );
    }

    #[test]
    fn tls_modes_reject_disagreement_between_url_and_explicit_setting() {
        for (input, explicit) in [
            ("host=localhost sslmode=require", Some("verify-full")),
            ("host=localhost sslmode=verify-full", Some("require")),
            ("host=localhost sslmode=disable", Some("verify-full")),
            (
                "postgres://localhost/db?sslmode=require",
                Some("verify-full"),
            ),
            (
                "postgres://localhost/db?%73slmode=verify-full",
                Some("require"),
            ),
        ] {
            assert!(
                resolve(input, explicit).is_err(),
                "conflicting settings must refuse: {input}"
            );
        }
    }

    #[tokio::test]
    async fn tls_real_connector_checks_server_identity_in_subprocess() {
        const CHILD: &str = "CDK_POSTGRES_TLS_FIXTURE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let url = std::env::var("CDK_POSTGRES_TLS_FIXTURE_URL").expect("fixture URL");
            let explicit = std::env::var("CDK_POSTGRES_TLS_EXPLICIT")
                .unwrap_or_else(|_| "verify-full".to_owned());
            let config = PgConfig::new(&url, Some(&explicit), None, Some(5));
            let stale = Arc::new(AtomicBool::new(false));
            let connection = PostgresConnection::new(config, Duration::from_secs(5), stale);
            let result = connection.inner().await;
            if std::env::var("CDK_POSTGRES_TLS_EXPECT").as_deref() == Ok("accept") {
                assert!(
                    result.is_ok(),
                    "trusted localhost certificate should connect"
                );
            } else {
                assert!(
                    result.is_err(),
                    "untrusted or wrong-host certificate must fail"
                );
            }
            return;
        }

        let fixture = TlsFixture::new().await;
        let cases = [
            (
                "trusted",
                fixture.ca_path(),
                "localhost",
                "verify-full",
                true,
                Some(true),
            ),
            (
                "wrong-ca",
                fixture.wrong_ca_path(),
                "localhost",
                "verify-full",
                false,
                Some(false),
            ),
            (
                "wrong-host",
                fixture.ca_path(),
                "127.0.0.1",
                "verify-full",
                false,
                Some(false),
            ),
            (
                "conflict-no-connect",
                fixture.ca_path(),
                "localhost",
                "require",
                false,
                None,
            ),
        ];
        for (name, trust, host, explicit, accept, server_result) in cases {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
            let port = listener.local_addr().expect("address").port();
            let acceptor = fixture.acceptor();
            let accept_timeout = if server_result.is_none() {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(6)
            };
            let server = tokio::spawn(async move {
                let accepted = timeout(accept_timeout, listener.accept()).await;
                let Ok(Ok((socket, _))) = accepted else {
                    return None;
                };
                let Ok(socket) = socket.into_std() else {
                    return Some(false);
                };
                if socket.set_nonblocking(false).is_err() {
                    return Some(false);
                };
                let Ok(()) = socket.set_read_timeout(Some(Duration::from_secs(3))) else {
                    return Some(false);
                };
                let Ok(()) = socket.set_write_timeout(Some(Duration::from_secs(3))) else {
                    return Some(false);
                };
                Some(
                    tokio::task::spawn_blocking(move || {
                        let mut socket = socket;
                        let mut request = [0; 8];
                        if socket.read_exact(&mut request).is_err()
                            || request != [0, 0, 0, 8, 4, 210, 22, 47]
                            || socket.write_all(b"S").is_err()
                        {
                            return false;
                        }
                        let Ok(mut stream) = acceptor.accept(socket) else {
                            return false;
                        };
                        let mut length = [0; 4];
                        if stream.read_exact(&mut length).is_err() {
                            return false;
                        }
                        let startup_len = u32::from_be_bytes(length) as usize;
                        if !(8..=4096).contains(&startup_len) {
                            return false;
                        }
                        let mut startup = vec![0; startup_len - 4];
                        if stream.read_exact(&mut startup).is_err() {
                            return false;
                        }
                        // This PostgreSQL wire stub completes protocol startup. It
                        // proves TLS identity handling, not a real SQL query.
                        stream
                            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                            .is_ok()
                    })
                    .await
                    .unwrap_or(false),
                )
            });

            let url = format!("postgres://cdk@{host}:{port}/db?sslmode=verify-full");
            let mut child = Command::new(std::env::current_exe().expect("test executable"))
                .arg("--exact")
                .arg("tls::tests::tls_real_connector_checks_server_identity_in_subprocess")
                .arg("--nocapture")
                .env(CHILD, "1")
                .env("CDK_POSTGRES_TLS_FIXTURE_URL", &url)
                .env("CDK_POSTGRES_TLS_EXPLICIT", explicit)
                .env(
                    "CDK_POSTGRES_TLS_EXPECT",
                    if accept { "accept" } else { "reject" },
                )
                .env("SSL_CERT_FILE", trust)
                .env("SSL_CERT_DIR", fixture.empty_cert_dir())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .expect("run isolated connector test");
            let child_status = match timeout(Duration::from_secs(8), child.wait()).await {
                Ok(Ok(status)) => status,
                Ok(Err(error)) => panic!("failed to wait for connector subprocess: {error}"),
                Err(_) => {
                    let _ = child.kill().await;
                    let reaped = timeout(Duration::from_secs(1), child.wait()).await;
                    assert!(
                        matches!(reaped, Ok(Ok(_))),
                        "connector subprocess was not reaped"
                    );
                    panic!("connector subprocess exceeded its 8 second deadline");
                }
            };
            let actual_server_result = timeout(Duration::from_secs(7), server)
                .await
                .expect("bounded TLS server task completion")
                .expect("TLS server task join");
            assert!(child_status.success(), "{name} connector subprocess failed");
            assert_eq!(actual_server_result, server_result, "{name} server result");
        }
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cdk-postgres-tls-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            fs::create_dir(&path).expect("create fixture directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("restrict fixture directory permissions");
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TlsFixture {
        directory: TempDirectory,
        acceptor: native_tls::TlsAcceptor,
    }

    impl TlsFixture {
        async fn new() -> Self {
            let directory = TempDirectory::new();
            let directory_path = directory.path();
            let ca_key = directory_path.join("ca.key");
            let ca = directory_path.join("ca.pem");
            let server_key = directory_path.join("server.key");
            let server_csr = directory_path.join("server.csr");
            let server_cert = directory_path.join("server.pem");
            let ext = directory_path.join("server.ext");
            let wrong_ca_key = directory_path.join("wrong-ca.key");
            let wrong_ca = directory_path.join("wrong-ca.pem");
            fs::write(
                &ext,
                "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n",
            )
            .expect("write certificate extensions");
            Self::openssl(&[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                path(&ca_key),
                "-out",
                path(&ca),
                "-subj",
                "/CN=CDK Test CA",
                "-days",
                "1",
            ])
            .await;
            Self::openssl(&[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                path(&server_key),
                "-out",
                path(&server_csr),
                "-subj",
                "/CN=localhost",
            ])
            .await;
            Self::openssl(&[
                "x509",
                "-req",
                "-in",
                path(&server_csr),
                "-CA",
                path(&ca),
                "-CAkey",
                path(&ca_key),
                "-CAcreateserial",
                "-out",
                path(&server_cert),
                "-days",
                "1",
                "-extfile",
                path(&ext),
            ])
            .await;
            Self::openssl(&[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                path(&wrong_ca_key),
                "-out",
                path(&wrong_ca),
                "-subj",
                "/CN=Wrong Test CA",
                "-days",
                "1",
            ])
            .await;
            let identity = native_tls::Identity::from_pkcs8(
                &fs::read(&server_cert).expect("read server certificate"),
                &fs::read(&server_key).expect("read server key"),
            )
            .expect("parse server identity");
            let acceptor = native_tls::TlsAcceptor::new(identity).expect("build TLS acceptor");
            fs::create_dir(directory_path.join("empty-cert-dir")).expect("create empty trust dir");
            Self {
                directory,
                acceptor,
            }
        }

        async fn openssl(args: &[&str]) {
            let mut child = Command::new("openssl")
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .expect("openssl is required for disposable TLS fixture certificates");
            let status = match timeout(Duration::from_secs(10), child.wait()).await {
                Ok(Ok(status)) => status,
                Ok(Err(error)) => panic!("failed to wait for openssl fixture command: {error}"),
                Err(_) => {
                    let _ = child.kill().await;
                    let reaped = timeout(Duration::from_secs(1), child.wait()).await;
                    assert!(
                        matches!(reaped, Ok(Ok(_))),
                        "openssl process was not reaped"
                    );
                    panic!("openssl fixture command exceeded its 10 second deadline");
                }
            };
            assert!(status.success(), "openssl fixture command failed");
        }

        fn ca_path(&self) -> PathBuf {
            self.directory.path().join("ca.pem")
        }

        fn wrong_ca_path(&self) -> PathBuf {
            self.directory.path().join("wrong-ca.pem")
        }

        fn empty_cert_dir(&self) -> PathBuf {
            self.directory.path().join("empty-cert-dir")
        }

        fn acceptor(&self) -> native_tls::TlsAcceptor {
            self.acceptor.clone()
        }
    }

    fn path(value: &Path) -> &str {
        value.to_str().expect("temporary path is valid UTF-8")
    }

    #[test]
    fn tls_modes_reject_unknown_and_malformed_settings() {
        let invalid_modes = ["", "requre"]; // typos: ignore
        for mode in invalid_modes {
            assert!(configure("host=localhost", Some(mode)).is_err());
        }
        assert!(configure("host=localhost sslmode='requre'", None).is_err()); // typos: ignore
        assert!(configure("postgres://localhost/db?sslmode=verify-full-extra", None).is_err());
        for input in [
            "host=localhost sslmode='require",
            "host=localhost sslmode=",
            "host=localhost sslmode=invalid sslmode=require",
            "postgres://localhost/db?sslmode=invalid&sslmode=require",
            "host=localhost sslmode=require sslmode=require",
            "postgres://localhost/db?sslmode=require&%73slmode=require",
            "postgres://localhost/db?%73slmode=require&sslmode=require",
        ] {
            assert!(configure(input, Some("require")).is_err());
        }
    }

    #[test]
    fn tls_modes_parse_parameters_without_matching_credentials() {
        let (config, _) = configure(
            r"host=localhost password='secret sslmode=disable \'quoted\'' sslmode = 'verify-full'",
            None,
        )
        .expect("quoted password");
        assert_eq!(
            config.get_password(),
            Some(b"secret sslmode=disable 'quoted'".as_slice())
        );
        assert_eq!(config.get_ssl_mode(), PgSslMode::Require);

        let (config, _) = configure(
            "postgres://user:sslmode=disable@localhost/db?sslmode=verify%2Dfull&application_name=sslmode%3Ddisable",
            None,
        ).expect("encoded mode");
        assert_eq!(config.get_ssl_mode(), PgSslMode::Require);
        assert_eq!(config.get_password(), Some(b"sslmode=disable".as_slice()));
        assert_eq!(config.get_application_name(), Some("sslmode=disable"));

        let (config, connector) =
            configure("host=localhost password=sslmode=require", None).expect("password");
        assert_eq!(config.get_ssl_mode(), PgSslMode::Disable);
        assert!(matches!(connector, SslMode::NoTls(_)));
    }

    #[tokio::test]
    async fn tls_strict_modes_never_send_plaintext_when_server_refuses_tls() {
        // Cover each strict mode and input path once; policy combinations are
        // checked separately above.
        for (mode, source) in [
            ("require", "explicit"),
            ("verify-ca", "keyword"),
            ("verify-full", "url"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
            let port = listener.local_addr().expect("address").port();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut request = [0; 8];
                socket.read_exact(&mut request).await.expect("SSL request");
                assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
                socket.write_all(b"N").await.expect("refuse TLS");
                let mut byte = [0];
                let read = socket.read(&mut byte).await.expect("client disconnect");
                assert_eq!(read, 0, "client sent plaintext after TLS refusal");
            });
            let config = match source {
                "explicit" => PgConfig::new(
                    &format!("host=127.0.0.1 port={port} user=cdk"),
                    Some(mode),
                    None,
                    None,
                ),
                "keyword" => PgConfig::from(
                    format!("host=127.0.0.1 port={port} user=cdk sslmode='{mode}'").as_str(),
                ),
                _ => PgConfig::from(
                    format!("postgres://cdk@127.0.0.1:{port}/db?sslmode={mode}").as_str(),
                ),
            };
            let stale = Arc::new(AtomicBool::new(false));
            let connection = PostgresConnection::new(config, Duration::from_secs(3), stale.clone());
            assert!(connection.inner().await.is_err(), "{source}: {mode}");
            timeout(Duration::from_secs(3), server)
                .await
                .expect("server completed")
                .expect("server task");
            assert!(stale.load(Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn tls_invalid_mode_fails_before_opening_a_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let port = listener.local_addr().expect("address").port();
        let config = PgConfig::new(
            &format!("host=127.0.0.1 port={port} user=cdk"),
            Some("requre"), // typos: ignore
            None,
            None,
        );
        let stale = Arc::new(AtomicBool::new(false));
        let connection = PostgresConnection::new(config, Duration::from_secs(3), stale.clone());
        let error = connection.inner().await.expect_err("invalid TLS mode");
        assert!(error.to_string().contains("Invalid PostgreSQL TLS mode"));
        assert!(stale.load(Ordering::Acquire));
        assert!(timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());

        let config = PgConfig::new(
            &format!("host=127.0.0.1 port={port} user=cdk sslmode=require"),
            Some("verify-full"),
            None,
            None,
        );
        let stale = Arc::new(AtomicBool::new(false));
        let connection = PostgresConnection::new(config, Duration::from_secs(3), stale.clone());
        let error = connection.inner().await.expect_err("conflicting TLS mode");
        assert!(error
            .to_string()
            .contains("Conflicting PostgreSQL TLS modes"));
        assert!(stale.load(Ordering::Acquire));
        assert!(timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());
    }
}
