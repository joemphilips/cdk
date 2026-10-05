use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use cdk::mint::MintBuilder;
use cdk::nuts::CurrencyUnit;
use cdk_common::mint::StoredCondition;
use tower::ServiceExt;

#[tokio::test]
async fn d3_same_second_http_page_has_continuation() {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await.unwrap());
    let mut builder = MintBuilder::new(db.clone());
    builder
        .configure_unit(
            CurrencyUnit::Sat,
            cdk::mint::UnitConfig {
                amounts: vec![1, 2, 4, 8],
                input_fee_ppk: 0,
            },
        )
        .unwrap();
    let mint = Arc::new(builder.build_with_seed(db, &[8; 64]).await.unwrap());
    for index in 1..=101 {
        mint.localstore()
            .add_condition(StoredCondition {
                condition_id: format!("{index:064x}"),
                threshold: 1,
                tags_json: "[]".to_string(),
                announcements_json: r#"["deadbeef"]"#.to_string(),
                collateral: Some(CurrencyUnit::Sat),
                attestation_status: "pending".to_string(),
                winning_outcome: None,
                attested_at: None,
                oracle_sigs: None,
                created_at: 1_700_000_000,
                condition_type: "enum".to_string(),
                lo_bound: None,
                hi_bound: None,
                precision: None,
            })
            .await
            .unwrap();
    }
    let router = crate::create_mint_router(mint, Vec::new()).await.unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/v1/conditions?limit=100")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["conditions"].as_array().unwrap().len(), 100);
    assert!(
        body["next_cursor"].is_string(),
        "same-second page must continue"
    );
}

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use cdk_common::database::mint::KeysDatabase;
use cdk_common::database::{Error as DatabaseError, MintDatabase};
use cdk_common::mint::MintKeySetInfo;
use cdk_sql_common::SQLMintDatabase;
use serde_json::{json, Value};

use super::pagination_test_database::{CountingConfig, CountingPool};

const BASE: u64 = 1_700_000_000;

async fn request(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "text": String::from_utf8_lossy(&bytes) }));
    (status, body)
}

fn stored_condition(index: u64, created_at: u64, announcement: &str) -> StoredCondition {
    StoredCondition {
        condition_id: format!("{index:064x}"),
        threshold: 1,
        tags_json: serde_json::to_string(&vec![vec!["description", "Pagination provider fixture"]])
            .unwrap(),
        announcements_json: serde_json::to_string(&vec![announcement]).unwrap(),
        collateral: Some(CurrencyUnit::Sat),
        attestation_status: if index <= 200 { "pending" } else { "expired" }.to_string(),
        winning_outcome: None,
        attested_at: None,
        oracle_sigs: None,
        created_at,
        condition_type: "enum".to_string(),
        lo_bound: None,
        hi_bound: None,
        precision: None,
    }
}

fn stored_keyset(index: u64) -> MintKeySetInfo {
    MintKeySetInfo {
        id: format!("00{index:014x}").parse().unwrap(),
        unit: CurrencyUnit::Sat,
        active: index <= 200,
        valid_from: 0,
        final_expiry: None,
        derivation_path: "m/0'/0'/0'".parse().unwrap(),
        derivation_path_index: Some(0),
        amounts: vec![1, 2, 4, 8],
        input_fee_ppk: 0,
        issuer_version: None,
        condition_id: Some(format!("{index:064x}")),
        outcome_collection: Some("YES".to_string()),
        outcome_collection_id: Some(format!("{index:064x}")),
    }
}

async fn seeded_router<D>(db: Arc<D>) -> (axum::Router, Arc<cdk::mint::Mint>)
where
    D: MintDatabase<DatabaseError> + KeysDatabase<Err = DatabaseError> + Send + Sync + 'static,
{
    let mut builder = MintBuilder::new(db.clone());
    builder
        .configure_unit(
            CurrencyUnit::Sat,
            cdk::mint::UnitConfig {
                amounts: vec![1, 2, 4, 8],
                input_fee_ppk: 0,
            },
        )
        .unwrap();
    let mint = Arc::new(builder.build_with_seed(db.clone(), &[8; 64]).await.unwrap());
    let oracle = cdk::nuts::nut_ctf::test_helpers::create_test_oracle();
    let (_, announcement) = cdk::nuts::nut_ctf::test_helpers::create_test_announcement(
        &oracle,
        &["YES", "NO"],
        "pagination-fixture",
    );
    // Reverse insertion prevents insertion order from satisfying the seek-order oracle.
    for index in (1..=205).rev() {
        let timestamp = match index {
            1..=201 => BASE,
            202..=203 => BASE + 1,
            204 => BASE + 2,
            205 => BASE + 3,
            _ => unreachable!(),
        };
        let mut condition = stored_condition(index, timestamp, &announcement);
        if index == 201 {
            condition.winning_outcome = Some("YES".to_string());
            condition.attested_at = Some(BASE + 20);
            condition.oracle_sigs = Some(
                cdk::nuts::nut_ctf::test_helpers::create_oracle_witness(&oracle, "YES").oracle_sigs,
            );
        }
        db.add_condition(condition).await.unwrap();
        db.add_conditional_keyset(stored_keyset(index), timestamp)
            .await
            .unwrap();
    }
    // Bootstrap reads must remain complete, including inactive historical keys.
    assert_eq!(
        db.get_all_conditional_mint_keyset_infos()
            .await
            .unwrap()
            .len(),
        205
    );
    assert_eq!(db.get_conditions(None, None, &[]).await.unwrap().len(), 205);
    (
        crate::create_mint_router(mint.clone(), Vec::new())
            .await
            .unwrap(),
        mint,
    )
}

async fn walk(router: &axum::Router, endpoint: &str, field: &str, filter: &str) -> Vec<Value> {
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    let mut ids = HashSet::new();
    loop {
        assert!(
            pages.len() < 4,
            "listing must terminate in at most three pages"
        );
        let uri = format!(
            "/v1/{endpoint}?limit=100{}{}",
            if filter.is_empty() {
                String::new()
            } else {
                format!("&{filter}")
            },
            cursor
                .as_ref()
                .map(|cursor| format!("&cursor={cursor}"))
                .unwrap_or_default()
        );
        let (status, body) = request(router, &uri).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.get("next_cursor").is_some(),
            "terminal cursor must be explicit"
        );
        let rows = body[field].as_array().unwrap();
        assert!(rows.len() <= 100);
        for row in rows {
            let id = row[if field == "conditions" {
                "condition_id"
            } else {
                "id"
            }]
            .as_str()
            .unwrap();
            assert!(ids.insert(id.to_string()), "duplicate {id}");
        }
        cursor = match &body["next_cursor"] {
            Value::String(cursor) => Some(cursor.clone()),
            Value::Null => None,
            other => panic!("invalid cursor {other}"),
        };
        pages.push(body);
        if cursor.is_none() {
            break;
        }
    }
    pages
}

fn cursor_json(cursor: &str) -> Value {
    use cdk_common::bitcoin::base64::Engine;
    let bytes = cdk_common::bitcoin::base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn encoded_cursor(value: &Value) -> String {
    use cdk_common::bitcoin::base64::Engine;
    cdk_common::bitcoin::base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(value).unwrap())
}

async fn assertions(
    router: &axum::Router,
    mint: &cdk::mint::Mint,
    keys_db: &(dyn KeysDatabase<Err = DatabaseError> + Sync),
    reads: &AtomicUsize,
    provider: &str,
) {
    let before = reads.load(Ordering::SeqCst);
    let (status, first) = request(router, "/v1/conditions?since=1700000000&limit=100").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        reads.load(Ordering::SeqCst) - before,
        2,
        "one condition read and one batched keyset read for 100 rows"
    );
    let before = reads.load(Ordering::SeqCst);
    assert_eq!(
        request(router, "/v1/conditions?limit=1").await.0,
        StatusCode::OK
    );
    assert_eq!(
        reads.load(Ordering::SeqCst) - before,
        2,
        "query count must not grow with page size"
    );
    let conditions = walk(router, "conditions", "conditions", "since=1700000000").await;
    let keysets = walk(router, "conditional_keysets", "keysets", "since=1700000000").await;
    assert_bulk_pages(&conditions, &keysets);
    assert_full_pages(router).await;
    assert_limits(router).await;
    assert_cursor_binding(router, &first, &keysets).await;
    assert_invalid_cursors(router, &first, &keysets[0]).await;
    if let Ok(directory) = std::env::var("CDK_D3_FIXTURE_DIR") {
        std::fs::write(std::path::Path::new(&directory).join(format!("cdk-pagination-{provider}.json")),serde_json::to_vec_pretty(&json!({"provider":provider,"fixture_kind":"synthetic_provider_bulk","since":BASE,"conditions_pages":conditions,"keysets_pages":keysets})).unwrap()).unwrap();
    }
    assert_exact_timestamps(router, mint, keys_db).await;
}

fn assert_bulk_pages(conditions: &[Value], keysets: &[Value]) {
    assert_eq!(
        conditions
            .iter()
            .map(|page| page["conditions"].as_array().unwrap().len())
            .collect::<Vec<_>>(),
        [100, 100, 5]
    );
    assert_eq!(
        keysets
            .iter()
            .map(|page| page["keysets"].as_array().unwrap().len())
            .collect::<Vec<_>>(),
        [100, 100, 5]
    );
    let condition_ids = conditions
        .iter()
        .flat_map(|page| page["conditions"].as_array().unwrap())
        .map(|row| row["condition_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let keyset_ids = keysets
        .iter()
        .flat_map(|page| page["keysets"].as_array().unwrap())
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        condition_ids,
        (1..=205)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        keyset_ids,
        (1..=205)
            .map(|index| format!("00{index:014x}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(conditions[1]["conditions"][99]["registered_at"], BASE);
    assert_eq!(conditions[2]["conditions"][0]["registered_at"], BASE);
    assert_eq!(conditions[2]["conditions"][4]["registered_at"], BASE + 3);
    for row in conditions
        .iter()
        .flat_map(|page| page["conditions"].as_array().unwrap())
    {
        assert!(row["attestation"].get("oracle_sigs").is_none());
        let index = u64::from_str_radix(row["condition_id"].as_str().unwrap(), 16).unwrap();
        if index <= 200 {
            assert_eq!(row["keysets"]["YES"], format!("00{index:014x}"));
        } else {
            assert!(row["keysets"].as_object().unwrap().is_empty());
        }
    }
}

async fn assert_full_pages(router: &axum::Router) {
    for (endpoint, field, filter) in [
        ("conditions", "conditions", "status=pending"),
        ("conditional_keysets", "keysets", "active=true"),
    ] {
        let full = walk(router, endpoint, field, filter).await;
        assert_eq!(full.len(), 2);
        assert_eq!(full[1][field].as_array().unwrap().len(), 100);
        assert!(full[1]["next_cursor"].is_null());
    }
}

async fn assert_limits(router: &axum::Router) {
    for (endpoint, field) in [
        ("conditions", "conditions"),
        ("conditional_keysets", "keysets"),
    ] {
        for limit in ["", "&limit=18446744073709551615"] {
            let (status, body) =
                request(router, &format!("/v1/{endpoint}?since={BASE}{limit}")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body[field].as_array().unwrap().len(), 100);
            assert!(body["next_cursor"].is_string());
        }
        let (_, inclusive) = request(router, &format!("/v1/{endpoint}?since={}", BASE + 1)).await;
        assert_eq!(inclusive[field].as_array().unwrap().len(), 4);
        assert!(inclusive["next_cursor"].is_null());
        let (_, empty) = request(router, &format!("/v1/{endpoint}?since={}", BASE + 4)).await;
        assert!(empty[field].as_array().unwrap().is_empty());
        assert!(empty.get("next_cursor").unwrap().is_null());
        for query in [
            "limit=0",
            "limit=-1",
            "limit=invalid",
            "limit=1.5",
            "limit=18446744073709551616",
            "since=18446744073709551615",
        ] {
            assert_eq!(
                request(router, &format!("/v1/{endpoint}?{query}")).await.0,
                StatusCode::BAD_REQUEST,
                "{endpoint} {query}"
            );
        }
    }
}

async fn assert_cursor_binding(router: &axum::Router, first: &Value, keysets: &[Value]) {
    let cursor = first["next_cursor"].as_str().unwrap();
    for uri in [
        format!("/v1/conditional_keysets?since={BASE}&cursor={cursor}"),
        format!("/v1/conditions?since={}&cursor={cursor}", BASE + 1),
        format!("/v1/conditions?since={BASE}&status=pending&cursor={cursor}"),
    ] {
        assert_eq!(request(router, &uri).await.0, StatusCode::BAD_REQUEST);
    }
    let key_cursor = keysets[0]["next_cursor"].as_str().unwrap();
    for uri in [
        format!("/v1/conditions?since={BASE}&cursor={key_cursor}"),
        format!("/v1/conditional_keysets?since={BASE}&active=true&cursor={key_cursor}"),
        format!(
            "/v1/conditional_keysets?since={}&cursor={key_cursor}",
            BASE + 1
        ),
    ] {
        assert_eq!(request(router, &uri).await.0, StatusCode::BAD_REQUEST);
    }
    let (_, normalized) = request(
        router,
        "/v1/conditions?since=1700000000&status=pending&status=expired&status=pending",
    )
    .await;
    let normalized_cursor = normalized["next_cursor"].as_str().unwrap();
    assert_eq!(request(router,&format!("/v1/conditions?since={BASE}&status=expired&status=pending&cursor={normalized_cursor}")).await.0,StatusCode::OK);
}

async fn assert_invalid_cursors(router: &axum::Router, first: &Value, first_keysets: &Value) {
    for (endpoint, first) in [
        ("conditions", first),
        ("conditional_keysets", first_keysets),
    ] {
        let cursor = first["next_cursor"].as_str().unwrap();
        let mut bad = vec![
            "".to_string(),
            "not-base64!".to_string(),
            "a".repeat(1025),
            encoded_cursor(&Value::Null),
            encoded_cursor(&json!([])),
        ];
        for (field, value) in [
            ("version", json!(2)),
            ("version", json!("1")),
            ("last_created_at", json!(1.5)),
            ("last_created_at", json!("1700000000")),
            ("last_created_at", json!(-1)),
            ("last_created_at", json!(u64::MAX)),
            ("last_id", json!("a".repeat(65))),
            ("last_id", json!(7)),
            ("extra", json!(1)),
            (
                "filter",
                json!({"endpoint":"conditions","since":BASE,"status":"pending"}),
            ),
        ] {
            let mut value_cursor = cursor_json(cursor);
            value_cursor[field] = value;
            bad.push(encoded_cursor(&value_cursor));
        }
        for field in ["version", "last_created_at", "last_id", "filter"] {
            let mut value_cursor = cursor_json(cursor);
            value_cursor.as_object_mut().unwrap().remove(field);
            bad.push(encoded_cursor(&value_cursor));
        }
        for cursor in &bad {
            assert_eq!(
                request(
                    router,
                    &format!("/v1/{endpoint}?since={BASE}&cursor={cursor}")
                )
                .await
                .0,
                StatusCode::BAD_REQUEST,
                "{endpoint} bad cursor"
            );
        }
    }
}

async fn assert_exact_timestamps(
    router: &axum::Router,
    mint: &cdk::mint::Mint,
    keys_db: &(dyn KeysDatabase<Err = DatabaseError> + Sync),
) {
    // JSON cursor timestamps above the JS safe-integer range remain exact in Rust and SQL.
    let exact_time = 9_007_199_254_740_993;
    for index in [206, 207] {
        mint.localstore()
            .add_condition(stored_condition(index, exact_time, "deadbeef"))
            .await
            .unwrap();
        keys_db
            .add_conditional_keyset(stored_keyset(index), exact_time)
            .await
            .unwrap();
    }
    for (endpoint, field, id_field) in [
        ("conditions", "conditions", "condition_id"),
        ("conditional_keysets", "keysets", "id"),
    ] {
        let (status, page) = request(
            router,
            &format!("/v1/{endpoint}?since={exact_time}&limit=1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page[field][0]["registered_at"].as_u64(), Some(exact_time));
        let cursor = page["next_cursor"].as_str().unwrap();
        assert_eq!(
            cursor_json(cursor)["last_created_at"].as_u64(),
            Some(exact_time)
        );
        let (status, final_page) = request(
            router,
            &format!("/v1/{endpoint}?since={exact_time}&limit=1&cursor={cursor}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(final_page["next_cursor"].is_null());
        assert_eq!(final_page[field].as_array().unwrap().len(), 1);
        assert_eq!(
            final_page[field][0][id_field],
            if id_field == "id" {
                format!("00{:014x}", 207)
            } else {
                format!("{:064x}", 207)
            }
        );
    }
}

#[tokio::test]
async fn d3_sqlite_http_pagination_provider_contract() {
    let reads = Arc::new(AtomicUsize::new(0));
    let path = std::env::temp_dir().join(format!("cdk-d3-pagination-{}.db", uuid::Uuid::new_v4()));
    let db = Arc::new(
        SQLMintDatabase::<CountingPool<cdk_sqlite::SqliteConnectionManager>>::new(CountingConfig {
            inner: path.clone().into(),
            reads: reads.clone(),
        })
        .await
        .unwrap(),
    );
    let (router, mint) = seeded_router(db.clone()).await;
    assertions(&router, &mint, db.as_ref(), &reads, "sqlite").await;
    drop(router);
    drop(mint);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL fixture via PG_DB_URL"]
async fn d3_postgres_http_pagination_provider_contract() {
    let reads = Arc::new(AtomicUsize::new(0));
    let url = format!(
        "{} schema=d3_pagination_{}",
        std::env::var("PG_DB_URL").unwrap(),
        uuid::Uuid::new_v4().simple()
    );
    let db = Arc::new(
        SQLMintDatabase::<CountingPool<cdk_postgres::PgConnectionPool>>::new(CountingConfig {
            inner: cdk_postgres::PgConfig::from(url.as_str()),
            reads: reads.clone(),
        })
        .await
        .unwrap(),
    );
    let (router, mint) = seeded_router(db.clone()).await;
    assertions(&router, &mint, db.as_ref(), &reads, "postgres").await;
}

#[tokio::test]
async fn d3_actual_registration_http_consumer_fixture() {
    use cdk::nuts::nut_ctf::{NutCtfSettings, RegisterConditionRequest, RegistrationFeeSetting};
    use cdk_sql_common::pool::Pool;
    use cdk_sql_common::stmt::query;

    let path = std::env::temp_dir().join(format!("cdk-d3-registered-{}.db", uuid::Uuid::new_v4()));
    let db = Arc::new(
        cdk_sqlite::MintSqliteDatabase::new(path.clone())
            .await
            .unwrap(),
    );
    let mut builder = MintBuilder::new(db.clone());
    builder
        .configure_unit(
            CurrencyUnit::Sat,
            cdk::mint::UnitConfig {
                amounts: (0..32).map(|n| 1 << n).collect(),
                input_fee_ppk: 0,
            },
        )
        .unwrap();
    let mint = Arc::new(builder.build_with_seed(db.clone(), &[8; 64]).await.unwrap());
    let mut info = mint.mint_info().await.unwrap();
    info.nuts.nut_ctf = Some(NutCtfSettings {
        registration_fees: vec![RegistrationFeeSetting {
            unit: "sat".to_string(),
            registration_fee_base: 0,
            registration_fee_per_keyset: 0,
        }],
        ..NutCtfSettings::default()
    });
    mint.set_mint_info(info).await.unwrap();
    let oracle = cdk::nuts::nut_ctf::test_helpers::create_test_oracle();
    let pool = Pool::<cdk_sqlite::SqliteConnectionManager>::new(path.clone().into());
    let conn = pool.get().await.unwrap();
    let mut expected_conditions = Vec::new();
    let mut expected_keysets = Vec::new();
    for index in 1..=101 {
        let (_, announcement) = cdk::nuts::nut_ctf::test_helpers::create_test_announcement(
            &oracle,
            &["YES", "NO"],
            &format!("d3-registered-{index}"),
        );
        let response = mint
            .register_condition(RegisterConditionRequest {
                threshold: 1,
                tags: vec![vec![
                    "description".to_string(),
                    format!("Real registration {index}"),
                ]],
                announcements: vec![announcement],
                collateral: Some("sat".to_string()),
                outcome_collections: Some(vec!["YES".to_string(), "NO".to_string()]),
                fee: None,
                outputs: None,
                condition_type: "enum".to_string(),
                lo_bound: None,
                hi_bound: None,
                precision: None,
            })
            .await
            .unwrap();
        // Only the registration timestamp is fixed. Oracle, condition and key bindings
        // come from the actual registration and signatory paths.
        query("UPDATE conditions SET created_at = :time WHERE condition_id = :id")
            .unwrap()
            .bind("time", BASE as i64)
            .bind("id", response.condition_id.clone())
            .execute(&*conn)
            .await
            .unwrap();
        query("UPDATE conditional_keyset SET created_at = :time WHERE condition_id = :id")
            .unwrap()
            .bind("time", BASE as i64)
            .bind("id", response.condition_id.clone())
            .execute(&*conn)
            .await
            .unwrap();
        expected_conditions.push(response.condition_id);
        expected_keysets.extend(response.keysets.values().map(|id| id.to_string()));
    }
    expected_conditions.sort();
    expected_keysets.sort();
    drop(conn);
    drop(pool);
    // Reopen the database to prove the production bootstrap also reads every key.
    drop(mint);
    let reopened = Arc::new(
        cdk_sqlite::MintSqliteDatabase::new(path.clone())
            .await
            .unwrap(),
    );
    assert_eq!(
        reopened
            .get_all_conditional_mint_keyset_infos()
            .await
            .unwrap()
            .len(),
        202
    );
    let mint = Arc::new(
        MintBuilder::new(reopened.clone())
            .build_with_seed(reopened, &[8; 64])
            .await
            .unwrap(),
    );
    let router = crate::create_mint_router(mint.clone(), Vec::new())
        .await
        .unwrap();
    let conditions = walk(&router, "conditions", "conditions", "").await;
    let keysets = walk(&router, "conditional_keysets", "keysets", "").await;
    let ids = conditions
        .iter()
        .flat_map(|page| page["conditions"].as_array().unwrap())
        .map(|row| row["condition_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(ids, expected_conditions);
    let ids = keysets
        .iter()
        .flat_map(|page| page["keysets"].as_array().unwrap())
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(ids, expected_keysets);
    assert_eq!(conditions.len(), 2);
    assert_eq!(keysets.len(), 3);
    for (endpoint, field, pages) in [
        ("conditions", "conditions", &conditions),
        ("conditional_keysets", "keysets", &keysets),
    ] {
        let (status, first) = request(&router, &format!("/v1/{endpoint}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first[field].as_array().unwrap().len(), 100);
        assert_eq!(&first, &pages[0]);
        let cursor = first["next_cursor"].as_str().unwrap();
        assert_eq!(cursor_json(cursor)["filter"]["since"], 0);

        let (status, inclusive) = request(&router, &format!("/v1/{endpoint}?since={BASE}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(inclusive[field], first[field]);
        let cursor = inclusive["next_cursor"].as_str().unwrap();
        assert_eq!(cursor_json(cursor)["filter"]["since"], BASE);
        assert_eq!(
            request(&router, &format!("/v1/{endpoint}?cursor={cursor}"))
                .await
                .0,
            StatusCode::BAD_REQUEST,
            "a filtered continuation must not work for an unfiltered consumer"
        );
        let (status, after) = request(&router, &format!("/v1/{endpoint}?since={}", BASE + 1)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(after[field].as_array().unwrap().is_empty());
        assert!(after["next_cursor"].is_null());
    }
    if let Ok(directory) = std::env::var("CDK_D3_FIXTURE_DIR") {
        let queries = |endpoint: &str, pages: &[Value]| {
            let mut cursor = None;
            pages
                .iter()
                .map(|page| {
                    let uri = format!(
                        "/v1/{endpoint}?limit=100{}",
                        cursor
                            .as_ref()
                            .map(|cursor| format!("&cursor={cursor}"))
                            .unwrap_or_default()
                    );
                    cursor = page["next_cursor"].as_str().map(str::to_string);
                    uri
                })
                .collect::<Vec<_>>()
        };
        let body = json!({"provider":"sqlite","fixture_kind":"real_registration","timestamp_setup":"Test-only update of registration timestamps in an isolated database. Condition IDs, announcements and keyset IDs remain from actual mint registration.","since":null,"condition_ids":expected_conditions,"keyset_ids":expected_keysets,"conditions_queries":queries("conditions",&conditions),"keysets_queries":queries("conditional_keysets",&keysets),"conditions_pages":conditions,"keysets_pages":keysets});
        std::fs::write(
            std::path::Path::new(&directory).join("cdk-pagination-real-registration-sqlite.json"),
            serde_json::to_vec_pretty(&body).unwrap(),
        )
        .unwrap();
    }
    drop(router);
    drop(mint);
    drop(db);
    std::fs::remove_file(path).unwrap();
}
