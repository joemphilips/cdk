//! Opt-in synthetic ledger writer for the owned local obligation reader fixture.
//! This proves real CDK storage/valuation composition, not funded mint acceptance.
use super::*;
use std::io::Read;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    backend: String,
    port: Option<u16>,
    password: Option<String>,
    sqlite_path: Option<String>,
}

async fn seed(mint: &Mint) -> Result<(), &'static str> {
    let regular = get_regular_keyset_id_for_unit(mint, &CurrencyUnit::Msat);
    async fn issue(mint: &Mint, keyset: Id, amount: u64) -> Result<(), &'static str> {
        let mut tx = mint
            .localstore()
            .begin_transaction()
            .await
            .map_err(|_| "begin")?;
        tx.add_blind_signatures(
            &[SecretKey::generate().public_key()],
            &[cdk_common::BlindSignature {
                amount: Amount::from(amount),
                keyset_id: keyset,
                c: SecretKey::generate().public_key(),
                dleq: None,
            }],
            None,
        )
        .await
        .map_err(|_| "issue")?;
        tx.commit().await.map_err(|_| "commit")
    }
    issue(mint, regular, 128).await?;
    let (_, announcement) =
        create_test_announcement(&create_test_oracle(), &["YES", "NO"], "o1-provider");
    let mut request = enum_condition_request("Synthetic inventory fixture", vec![announcement]);
    request.collateral = Some("msat".to_owned());
    request.outcome_collections = Some(vec!["YES".to_owned(), "NO".to_owned()]);
    let condition = mint
        .register_condition(request)
        .await
        .map_err(|_| "register")?;
    let yes = condition.keysets["YES"];
    issue(mint, yes, 64).await?;
    issue(mint, condition.keysets["NO"], 32).await?;
    // Use the real counter and completed-operation writers. The proof bytes are
    // synthetic; this test does not claim cryptographic redemption acceptance.
    let proofs = vec![cdk_common::Proof::new(
        Amount::from(16),
        yes,
        Secret::generate(),
        SecretKey::generate().public_key(),
    )];
    let operation = Operation::new_swap(Amount::ZERO, Amount::from(16), Amount::ZERO);
    let mut tx = mint
        .localstore()
        .begin_transaction()
        .await
        .map_err(|_| "begin")?;
    tx.add_proofs(proofs.clone(), None, &operation)
        .await
        .map_err(|_| "proof")?;
    let mut stored = tx
        .get_proofs(&proofs.ys().map_err(|_| "ys")?)
        .await
        .map_err(|_| "proof-read")?;
    Mint::update_proofs_state(&mut tx, &mut stored, State::Spent)
        .await
        .map_err(|_| "spent")?;
    tx.add_completed_operation(&operation, &HashMap::new())
        .await
        .map_err(|_| "operation")?;
    tx.commit().await.map_err(|_| "commit")?;

    // The maintained FakeWallet creates a real BOLT11 and records its payment.
    // Do not issue it: the reader must retain this separate obligation of 5 msat.
    let quote: cdk_common::MintQuoteBolt11Response<_> = mint
        .get_mint_quote(
            cdk_common::MintQuoteBolt11Request {
                amount: Amount::from(5),
                unit: CurrencyUnit::Msat,
                description: None,
                pubkey: None,
            }
            .into(),
        )
        .await
        .map_err(|_| "quote")?
        .into();
    let id = cdk_common::QuoteId::from_str(&quote.quote).map_err(|_| "quote-id")?;
    loop {
        let check: cdk_common::MintQuoteBolt11Response<_> = mint
            .check_mint_quotes(&[id.clone()])
            .await
            .map_err(|_| "quote-check")?
            .first()
            .ok_or("quote-empty")?
            .clone()
            .into();
        if check.state == cdk_common::MintQuoteState::Paid {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let value = mint.liabilities().await.map_err(|_| "value")?;
    if value.totals.get(&CurrencyUnit::Msat) != Some(&176) {
        return Err("ordinary-value");
    }
    Ok(())
}

async fn write(config: Config) -> Result<(), &'static str> {
    let units = [(CurrencyUnit::Msat, 0)];
    let mint = match config.backend.as_str() {
        "postgres" => {
            if config.sqlite_path.is_some() {
                return Err("config");
            }
            let port = config.port.filter(|p| *p > 1024).ok_or("port")?;
            let password = config.password.ok_or("password")?;
            if password.len() != 40 || !password.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("password");
            }
            // The transport destination is fixed loopback. The TLS name is that
            // of the supervisor's certificate; SSL_CERT_FILE is its private CA.
            let url = format!("host=fixture.postgres.database.azure.com hostaddr=127.0.0.1 port={port} user=mintd password={password} dbname=mintdb sslmode=verify-full");
            let config = cdk_postgres::PgConfig::new(&url, Some("verify-full"), Some(2), Some(5));
            let db = Arc::new(
                cdk_postgres::MintPgDatabase::new(config)
                    .await
                    .map_err(|_| "postgres")?,
            );
            build_test_mint_with_units(db, &[42; 32], &units)
                .await
                .map_err(|_| "mint")?
        }
        "sqlite" => {
            if config.port.is_some() || config.password.is_some() {
                return Err("config");
            }
            let path = std::path::PathBuf::from(config.sqlite_path.ok_or("path")?);
            if !path.is_absolute()
                || path.exists()
                || path.file_name().and_then(|x| x.to_str()) != Some("o1-fixture.sqlite")
            {
                return Err("path");
            }
            let db = Arc::new(
                cdk_sqlite::mint::MintSqliteDatabase::new(path)
                    .await
                    .map_err(|_| "sqlite")?,
            );
            build_test_mint_with_units(db, &[42; 32], &units)
                .await
                .map_err(|_| "mint")?
        }
        _ => return Err("backend"),
    };
    let result = seed(&mint).await;
    mint.stop().await.map_err(|_| "stop")?;
    result
}

#[tokio::test]
#[ignore = "requires the reviewed owned local PG16/SQLite supervisor and private descriptor"]
async fn write_obligation_inventory_fixture() {
    assert_eq!(
        std::env::var("BITCASTER_O1_WRITER_TEST").ok().as_deref(),
        Some("1")
    );
    let fd: i32 = std::env::var("BITCASTER_O1_WRITER_FD")
        .expect("descriptor")
        .parse()
        .expect("descriptor");
    assert!(fd > 2);
    // The supervisor creates and passes this owned descriptor only to this test.
    let file = std::fs::File::open(format!("/proc/self/fd/{fd}")).expect("descriptor-open");
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .expect("descriptor-read");
    assert!(bytes.len() <= 4096);
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|_| "config")
        .expect("config");
    bytes.fill(0);
    let result = tokio::time::timeout(Duration::from_secs(60), write(config)).await;
    // Only fixed literals from this module may cross the private diagnostic pipe.
    match &result {
        Ok(Err(stage)) => println!("O1_FIXTURE_REFUSED:{stage}"),
        Err(_) => println!("O1_FIXTURE_REFUSED:timeout"),
        Ok(Ok(())) => {}
    }
    assert!(matches!(result, Ok(Ok(()))), "fixture writer failed");
    println!("O1_FIXTURE_WRITTEN regular_msat=128 conditional_msat=48 paid_unissued_msat=5 total_msat=181");
}
