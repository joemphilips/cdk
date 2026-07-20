//! SQLite Wallet Database

use cdk_sql_common::SQLWalletDatabase;

use crate::common::SqliteConnectionManager;

pub mod memory;

/// Mint SQLite implementation with rusqlite
pub type WalletSqliteDatabase = SQLWalletDatabase<SqliteConnectionManager>;

#[cfg(test)]
mod tests {
    #[cfg(feature = "conditional-tokens")]
    use cdk_common::wallet_conditional_restore_db_test;
    use cdk_common::wallet_db_test;

    use super::memory;

    async fn provide_db(_test_name: String) -> super::WalletSqliteDatabase {
        memory::empty().await.unwrap()
    }

    wallet_db_test!(provide_db);
    #[cfg(feature = "conditional-tokens")]
    wallet_conditional_restore_db_test!(provide_db);

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn conditional_restore_kind_rejects_direct_sql_mutation() {
        let path = std::env::temp_dir().join(format!(
            "cdk-conditional-restore-kind-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let _database = super::WalletSqliteDatabase::new(path.clone())
            .await
            .expect("wallet database");
        let connection = rusqlite::Connection::open(path).expect("raw SQLite connection");
        connection
            .execute(
                "INSERT INTO mint (mint_url) VALUES (?1)",
                ["https://example.com"],
            )
            .expect("mint fixture");
        connection
            .execute(
                r#"
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, restore_kind)
                VALUES (?1, ?2, 'sat', 0, 0, NULL, 'conditional')
                "#,
                [
                    format!("01{}", "11".repeat(32)),
                    "https://example.com".to_string(),
                ],
            )
            .expect("conditional namespace fixture");
        let error = connection
            .execute(
                "UPDATE keyset SET restore_kind = 'ordinary' WHERE mint_url = ?1",
                ["https://example.com"],
            )
            .expect_err("namespace discriminator mutation must fail");
        assert!(error
            .to_string()
            .contains("conditional restore keyset namespace is immutable"));
        connection
            .execute(
                "INSERT INTO conditional_restore_high_water (mint_url, unit, high_water) VALUES (?1, 'sat', ?2)",
                rusqlite::params!["https://example.com", 100_u64.to_be_bytes().to_vec()],
            )
            .expect("high-water fixture");
        connection
            .execute(
                "DELETE FROM conditional_restore_high_water WHERE mint_url = ?1",
                ["https://example.com"],
            )
            .expect_err("high-water deletion outside URL migration must fail");
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn conditional_restore_classification_rejects_unbound_direct_sql() {
        let path = std::env::temp_dir().join(format!(
            "cdk-conditional-restore-binding-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let _database = super::WalletSqliteDatabase::new(path.clone())
            .await
            .expect("wallet database");
        let connection = rusqlite::Connection::open(path).expect("raw SQLite connection");
        let id = format!("01{}", "33".repeat(32));
        connection
            .execute(
                "INSERT INTO mint (mint_url) VALUES ('https://example.com')",
                [],
            )
            .expect("mint fixture");
        connection
            .execute(
                r#"
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, restore_kind)
                VALUES (?1, 'https://example.com', 'sat', 0, 0, NULL, 'ordinary')
                "#,
                [&id],
            )
            .expect("ordinary keyset fixture");
        connection
            .execute(
                "INSERT INTO key (id, keys, restore_kind) VALUES (?1, '{}', 'ordinary')",
                [&id],
            )
            .expect("ordinary keys fixture");
        let error = connection
            .execute(
                r#"
                INSERT INTO conditional_restore_keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry,
                     condition_id, outcome_collection, outcome_collection_id, registered_at)
                VALUES (?1, 'https://example.com', 'sat', 1, NULL, NULL,
                        ?2, 'YES', ?3, 1)
                "#,
                [&id, &"11".repeat(32), &"22".repeat(32)],
            )
            .expect_err("ordinary key material cannot be classified as conditional");
        assert!(error
            .to_string()
            .contains("conditional restore classification is not bound"));
    }

    #[cfg(feature = "conditional-tokens")]
    #[tokio::test]
    async fn conditional_restore_schema_uses_utf8_byte_boundaries() {
        let path = std::env::temp_dir().join(format!(
            "cdk-conditional-restore-utf8-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let _database = super::WalletSqliteDatabase::new(path.clone())
            .await
            .expect("wallet database");
        let connection = rusqlite::Connection::open(path).expect("raw SQLite connection");
        connection
            .execute(
                "INSERT INTO mint (mint_url) VALUES ('https://example.com')",
                [],
            )
            .expect("mint fixture");

        let insert = |id: &str, unit: &str, outcome: &str| -> rusqlite::Result<()> {
            connection.execute(
                r#"
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, restore_kind)
                VALUES (?1, 'https://example.com', ?2, 0, 0, NULL, 'conditional')
                "#,
                rusqlite::params![id, unit],
            )?;
            connection.execute(
                "INSERT INTO key (id, keys, restore_kind) VALUES (?1, '{}', 'conditional')",
                [id],
            )?;
            connection.execute(
                r#"
                INSERT INTO conditional_restore_keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry,
                     condition_id, outcome_collection, outcome_collection_id, registered_at)
                VALUES (?1, 'https://example.com', ?2, 1, NULL, NULL,
                        ?3, ?4, ?5, 1)
                "#,
                rusqlite::params![id, unit, "11".repeat(32), outcome, "22".repeat(32)],
            )?;
            Ok(())
        };

        let unit_64 = "é".repeat(32);
        let outcome_16384 = format!("{}a", "界".repeat(5461));
        assert_eq!(unit_64.len(), 64);
        assert_eq!(outcome_16384.len(), 16_384);
        insert("utf8-boundary", &unit_64, &outcome_16384)
            .expect("exact UTF-8 byte limits should be accepted");
        insert("unit-too-wide", &format!("{unit_64}a"), "YES")
            .expect_err("65-byte unit must be rejected");
        insert("outcome-too-wide", "sat", &format!("{outcome_16384}a"))
            .expect_err("16385-byte outcome collection must be rejected");
    }

    #[cfg(all(feature = "conditional-tokens", not(feature = "sqlcipher")))]
    #[tokio::test]
    async fn conditional_restore_migrates_existing_sqlite_wallet_schema() {
        let path = std::env::temp_dir().join(format!(
            "cdk-conditional-restore-upgrade-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let connection = rusqlite::Connection::open(&path).expect("raw SQLite connection");
        connection
            .execute_batch(
                r#"
                CREATE TABLE migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMP);
                CREATE TABLE keyset (
                    id TEXT PRIMARY KEY, mint_url TEXT NOT NULL, unit TEXT NOT NULL,
                    active INTEGER NOT NULL, input_fee_ppk INTEGER NOT NULL,
                    final_expiry INTEGER, keyset_u32 INTEGER
                );
                CREATE TABLE key (
                    id TEXT PRIMARY KEY, keys TEXT NOT NULL, keyset_u32 INTEGER
                );
                CREATE TABLE proof (
                    mint_url TEXT, unit TEXT, state TEXT, keyset_id TEXT
                );
                INSERT INTO keyset
                    (id, mint_url, unit, active, input_fee_ppk, final_expiry, keyset_u32)
                VALUES ('legacy', 'https://example.com', 'sat', 1, 0, NULL, NULL);
                INSERT INTO key (id, keys, keyset_u32) VALUES ('legacy', '{}', NULL);
                "#,
            )
            .expect("legacy wallet schema fixture");
        let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cdk-sql-common/src/wallet/migrations/sqlite");
        for entry in std::fs::read_dir(migrations_dir).expect("wallet migrations directory") {
            let entry = entry.expect("migration entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "20260720000000_add_conditional_restore.sql" {
                connection
                    .execute("INSERT INTO migrations (name) VALUES (?1)", [&name])
                    .expect("legacy migration marker");
            }
        }
        drop(connection);

        let _database = super::WalletSqliteDatabase::new(path.clone())
            .await
            .expect("conditional restore migration should upgrade an existing wallet");
        let connection = rusqlite::Connection::open(path).expect("upgraded SQLite connection");
        let keyset_kind: String = connection
            .query_row(
                "SELECT restore_kind FROM keyset WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .expect("legacy keyset discriminator");
        let key_kind: String = connection
            .query_row(
                "SELECT restore_kind FROM key WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .expect("legacy key discriminator");
        assert_eq!(keyset_kind, "ordinary");
        assert_eq!(key_kind, "ordinary");
    }

    use std::str::FromStr;

    use cdk_common::database::WalletDatabase;
    use cdk_common::nut00::KnownMethod;
    use cdk_common::nuts::{ProofDleq, State};
    use cdk_common::secret::Secret;

    use crate::WalletSqliteDatabase;

    #[tokio::test]
    #[cfg(feature = "sqlcipher")]
    async fn test_sqlcipher() {
        use cdk_common::mint_url::MintUrl;
        use cdk_common::MintInfo;

        use super::*;
        let path = std::env::temp_dir()
            .to_path_buf()
            .join(format!("cdk-test-{}.sqlite", uuid::Uuid::new_v4()));
        let db = WalletSqliteDatabase::new((path, "password".to_string()))
            .await
            .unwrap();

        let mint_info = MintInfo::new().description("test");
        let mint_url = MintUrl::from_str("https://mint.xyz").unwrap();

        db.add_mint(mint_url.clone(), Some(mint_info.clone()))
            .await
            .unwrap();

        let res = db.get_mint(mint_url).await.unwrap();
        assert_eq!(mint_info, res.clone().unwrap());
        assert_eq!("test", &res.unwrap().description.unwrap());
    }

    #[tokio::test]
    async fn test_proof_with_dleq() {
        use cdk_common::mint_url::MintUrl;
        use cdk_common::nuts::{CurrencyUnit, Id, Proof, PublicKey, SecretKey};
        use cdk_common::wallet::ProofInfo;
        use cdk_common::Amount;

        // Create a temporary database
        let path = std::env::temp_dir()
            .to_path_buf()
            .join(format!("cdk-test-dleq-{}.sqlite", uuid::Uuid::new_v4()));

        #[cfg(feature = "sqlcipher")]
        let db = WalletSqliteDatabase::new((path, "password".to_string()))
            .await
            .unwrap();

        #[cfg(not(feature = "sqlcipher"))]
        let db = WalletSqliteDatabase::new(path).await.unwrap();

        // Create a proof with DLEQ
        let keyset_id = Id::from_str("00deadbeef123456").unwrap();
        let mint_url = MintUrl::from_str("https://example.com").unwrap();
        let secret = Secret::new("test_secret_for_dleq");

        // Create DLEQ components
        let e = SecretKey::generate();
        let s = SecretKey::generate();
        let r = SecretKey::generate();

        let dleq = ProofDleq::new(e.clone(), s.clone(), r.clone());

        let mut proof = Proof::new(
            Amount::from(64),
            keyset_id,
            secret,
            PublicKey::from_hex(
                "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .unwrap(),
        );

        // Add DLEQ to the proof
        proof.dleq = Some(dleq);

        // Create ProofInfo
        let proof_info =
            ProofInfo::new(proof, mint_url.clone(), State::Unspent, CurrencyUnit::Sat).unwrap();

        // Store the proof in the database
        db.update_proofs(vec![proof_info.clone()], vec![])
            .await
            .unwrap();

        // Retrieve the proof from the database
        let retrieved_proofs = db
            .get_proofs(
                Some(mint_url),
                Some(CurrencyUnit::Sat),
                Some(vec![State::Unspent]),
                None,
            )
            .await
            .unwrap();

        // Verify we got back exactly one proof
        assert_eq!(retrieved_proofs.len(), 1);

        // Verify the DLEQ data was preserved
        let retrieved_proof = &retrieved_proofs[0];
        assert!(retrieved_proof.proof.dleq.is_some());

        let retrieved_dleq = retrieved_proof.proof.dleq.as_ref().unwrap();

        // Verify DLEQ components match what we stored
        assert_eq!(retrieved_dleq.e.to_string(), e.to_string());
        assert_eq!(retrieved_dleq.s.to_string(), s.to_string());
        assert_eq!(retrieved_dleq.r.to_string(), r.to_string());
    }

    #[tokio::test]
    async fn test_mint_quote_payment_method_read_and_write() {
        use cdk_common::mint_url::MintUrl;
        use cdk_common::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
        use cdk_common::wallet::MintQuote;
        use cdk_common::Amount;

        // Create a temporary database
        let path = std::env::temp_dir().to_path_buf().join(format!(
            "cdk-test-migration-{}.sqlite",
            uuid::Uuid::new_v4()
        ));

        #[cfg(feature = "sqlcipher")]
        let db = WalletSqliteDatabase::new((path, "password".to_string()))
            .await
            .unwrap();

        #[cfg(not(feature = "sqlcipher"))]
        let db = WalletSqliteDatabase::new(path).await.unwrap();

        // Test PaymentMethod variants
        let mint_url = MintUrl::from_str("https://example.com").unwrap();
        let payment_methods = [
            PaymentMethod::Known(KnownMethod::Bolt11),
            PaymentMethod::Known(KnownMethod::Bolt11),
            PaymentMethod::Custom("custom".to_string()),
        ];

        for (i, payment_method) in payment_methods.iter().enumerate() {
            let quote = MintQuote {
                id: format!("test_quote_{}", i),
                mint_url: mint_url.clone(),
                amount: Some(Amount::from(100)),
                unit: CurrencyUnit::Sat,
                request: "test_request".to_string(),
                state: MintQuoteState::Unpaid,
                expiry: 1000000000,
                secret_key: None,
                payment_method: payment_method.clone(),
                amount_issued: Amount::from(0),
                amount_paid: Amount::from(0),
                used_by_operation: None,
                version: 0,
            };

            // Store the quote
            db.add_mint_quote(quote.clone()).await.unwrap();

            // Retrieve and verify
            let retrieved = db.get_mint_quote(&quote.id).await.unwrap().unwrap();
            assert_eq!(retrieved.payment_method, *payment_method);
            assert_eq!(retrieved.amount_issued, Amount::from(0));
            assert_eq!(retrieved.amount_paid, Amount::from(0));
        }
    }

    #[tokio::test]
    async fn test_get_proofs_by_ys_empty_errors() {
        use cdk_common::database::Error;

        let path = std::env::temp_dir().to_path_buf().join(format!(
            "cdk-test-proofs-by-ys-empty-{}.sqlite",
            uuid::Uuid::new_v4()
        ));

        #[cfg(feature = "sqlcipher")]
        let db = WalletSqliteDatabase::new((path, "password".to_string()))
            .await
            .unwrap();

        #[cfg(not(feature = "sqlcipher"))]
        let db = WalletSqliteDatabase::new(path).await.unwrap();

        let result = db.get_proofs_by_ys(vec![]).await;
        assert!(matches!(result, Err(Error::EmptyInClause(_))));
    }

    #[tokio::test]
    async fn test_get_proofs_by_ys() {
        use cdk_common::mint_url::MintUrl;
        use cdk_common::nuts::{CurrencyUnit, Id, Proof, SecretKey};
        use cdk_common::wallet::ProofInfo;
        use cdk_common::Amount;

        let path = std::env::temp_dir().to_path_buf().join(format!(
            "cdk-test-proofs-by-ys-{}.sqlite",
            uuid::Uuid::new_v4()
        ));

        #[cfg(feature = "sqlcipher")]
        let db = WalletSqliteDatabase::new((path, "password".to_string()))
            .await
            .unwrap();

        #[cfg(not(feature = "sqlcipher"))]
        let db = WalletSqliteDatabase::new(path).await.unwrap();

        let keyset_id = Id::from_str("00deadbeef123456").unwrap();
        let mint_url = MintUrl::from_str("https://example.com").unwrap();

        let mut proof_infos = vec![];
        let mut expected_ys = vec![];

        for _i in 0..5 {
            let secret = Secret::generate();
            let secret_key = SecretKey::generate();
            let c = secret_key.public_key();
            let proof = Proof::new(Amount::from(64), keyset_id, secret, c);
            let proof_info =
                ProofInfo::new(proof, mint_url.clone(), State::Unspent, CurrencyUnit::Sat).unwrap();

            expected_ys.push(proof_info.y);
            proof_infos.push(proof_info);
        }

        db.update_proofs(proof_infos.clone(), vec![]).await.unwrap();

        // Retrieve all proofs by their Y values
        let retrieved_proofs = db.get_proofs_by_ys(expected_ys.clone()).await.unwrap();
        assert_eq!(retrieved_proofs.len(), 5);
        for retrieved_proof in &retrieved_proofs {
            assert!(expected_ys.contains(&retrieved_proof.y));
        }

        // Retrieve subset of proofs (first 3)
        let subset_ys = expected_ys[0..3].to_vec();
        let subset_proofs = db.get_proofs_by_ys(subset_ys.clone()).await.unwrap();
        assert_eq!(subset_proofs.len(), 3);
        for retrieved_proof in &subset_proofs {
            assert!(subset_ys.contains(&retrieved_proof.y));
        }

        // Retrieve with non-existent Y values returns only existing ones
        let non_existent_secret_key = SecretKey::generate();
        let non_existent_y = non_existent_secret_key.public_key();
        let mixed_ys = vec![expected_ys[0], non_existent_y, expected_ys[1]];
        let mixed_proofs = db.get_proofs_by_ys(mixed_ys).await.unwrap();
        assert_eq!(mixed_proofs.len(), 2);

        // Verify retrieved proof data matches original
        let single_y = vec![expected_ys[2]];
        let single_proof = db.get_proofs_by_ys(single_y).await.unwrap();
        assert_eq!(single_proof.len(), 1);
        assert_eq!(single_proof[0].y, proof_infos[2].y);
        assert_eq!(single_proof[0].proof.amount, proof_infos[2].proof.amount);
        assert_eq!(single_proof[0].mint_url, proof_infos[2].mint_url);
        assert_eq!(single_proof[0].state, proof_infos[2].state);
    }

    #[tokio::test]
    async fn test_get_unissued_mint_quotes() {
        use cdk_common::mint_url::MintUrl;
        use cdk_common::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
        use cdk_common::wallet::MintQuote;
        use cdk_common::Amount;

        // Create a temporary database
        let path = std::env::temp_dir().to_path_buf().join(format!(
            "cdk-test-unpaid-quotes-{}.sqlite",
            uuid::Uuid::new_v4()
        ));

        #[cfg(feature = "sqlcipher")]
        let db = WalletSqliteDatabase::new((path, "password".to_string()))
            .await
            .unwrap();

        #[cfg(not(feature = "sqlcipher"))]
        let db = WalletSqliteDatabase::new(path).await.unwrap();

        let mint_url = MintUrl::from_str("https://example.com").unwrap();

        // Quote 1: Fully paid and issued (should NOT be returned)
        let quote1 = MintQuote {
            id: "quote_fully_paid".to_string(),
            mint_url: mint_url.clone(),
            amount: Some(Amount::from(100)),
            unit: CurrencyUnit::Sat,
            request: "test_request_1".to_string(),
            state: MintQuoteState::Paid,
            expiry: 1000000000,
            secret_key: None,
            payment_method: PaymentMethod::Known(KnownMethod::Bolt11),
            amount_issued: Amount::from(100),
            amount_paid: Amount::from(100),
            used_by_operation: None,
            version: 0,
        };

        // Quote 2: Paid but not yet issued (should be returned - has pending balance)
        let quote2 = MintQuote {
            id: "quote_pending_balance".to_string(),
            mint_url: mint_url.clone(),
            amount: Some(Amount::from(100)),
            unit: CurrencyUnit::Sat,
            request: "test_request_2".to_string(),
            state: MintQuoteState::Paid,
            expiry: 1000000000,
            secret_key: None,
            payment_method: PaymentMethod::Known(KnownMethod::Bolt11),
            amount_issued: Amount::from(0),
            amount_paid: Amount::from(100),
            used_by_operation: None,
            version: 0,
        };

        // Quote 3: Bolt12 quote with no balance (should be returned - bolt12 is reusable)
        let quote3 = MintQuote {
            id: "quote_bolt12".to_string(),
            mint_url: mint_url.clone(),
            amount: Some(Amount::from(100)),
            unit: CurrencyUnit::Sat,
            request: "test_request_3".to_string(),
            state: MintQuoteState::Unpaid,
            expiry: 1000000000,
            secret_key: None,
            payment_method: PaymentMethod::Known(KnownMethod::Bolt12),
            amount_issued: Amount::from(0),
            amount_paid: Amount::from(0),
            used_by_operation: None,
            version: 0,
        };

        // Quote 4: Unpaid bolt11 quote (should be returned - wallet needs to check with mint)
        let quote4 = MintQuote {
            id: "quote_unpaid".to_string(),
            mint_url: mint_url.clone(),
            amount: Some(Amount::from(100)),
            unit: CurrencyUnit::Sat,
            request: "test_request_4".to_string(),
            state: MintQuoteState::Unpaid,
            expiry: 1000000000,
            secret_key: None,
            payment_method: PaymentMethod::Known(KnownMethod::Bolt11),
            amount_issued: Amount::from(0),
            amount_paid: Amount::from(0),
            used_by_operation: None,
            version: 0,
        };

        // Add all quotes to the database
        db.add_mint_quote(quote1).await.unwrap();
        db.add_mint_quote(quote2.clone()).await.unwrap();
        db.add_mint_quote(quote3.clone()).await.unwrap();
        db.add_mint_quote(quote4.clone()).await.unwrap();

        // Get unissued mint quotes
        let unissued_quotes = db.get_unissued_mint_quotes().await.unwrap();

        // Should return 3 quotes: quote2, quote3, and quote4
        // - quote2: bolt11 with amount_issued = 0 (needs minting)
        // - quote3: bolt12 (always returned, reusable)
        // - quote4: bolt11 with amount_issued = 0 (check with mint if paid)
        assert_eq!(unissued_quotes.len(), 3);

        // Verify the returned quotes are the expected ones
        let quote_ids: Vec<&str> = unissued_quotes.iter().map(|q| q.id.as_str()).collect();
        assert!(quote_ids.contains(&"quote_pending_balance"));
        assert!(quote_ids.contains(&"quote_bolt12"));
        assert!(quote_ids.contains(&"quote_unpaid"));

        // Verify that fully paid and issued quote is not returned
        assert!(!quote_ids.contains(&"quote_fully_paid"));
    }
}
