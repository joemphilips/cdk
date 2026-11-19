//! Local provider fixtures for LDK's actual SQLite store. No node or service starts.
//! The values are synthetic bytes, not serialized channel or wallet state.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ldk_node::io::sqlite_store::{SqliteStore, KV_TABLE_NAME, SQLITE_DB_FILE_NAME};
use ldk_node::lightning::util::persist::{KVStore, KVStoreSync};
use rusqlite::{Connection, OpenFlags};

// (primary namespace, secondary namespace, key, value)
type Record = (&'static str, &'static str, String, Vec<u8>);

fn open_store(directory: &Path) -> SqliteStore {
    SqliteStore::new(
        directory.to_path_buf(),
        Some(SQLITE_DB_FILE_NAME.to_owned()),
        Some(KV_TABLE_NAME.to_owned()),
    )
    .expect("open the disposable LDK store")
}

fn assert_records(store: &SqliteStore, records: &[Record]) {
    let mut namespaces: BTreeMap<(&str, &str), Vec<String>> = BTreeMap::new();
    for (primary, secondary, key, value) in records {
        assert_eq!(
            KVStoreSync::read(store, primary, secondary, key).expect("read persisted record"),
            *value,
            "record {primary}/{secondary}/{key}"
        );
        namespaces
            .entry((primary, secondary))
            .or_default()
            .push(key.clone());
    }
    for ((primary, secondary), mut expected) in namespaces {
        expected.sort();
        let mut actual = KVStoreSync::list(store, primary, secondary).expect("list namespace");
        actual.sort();
        assert_eq!(actual, expected, "namespace {primary}/{secondary}");
    }
}

fn assert_database(directory: &Path, expected_rows: usize) {
    let connection = Connection::open_with_flags(
        directory.join(SQLITE_DB_FILE_NAME),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("inspect the closed database without creating one");
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("check persisted database integrity");
    assert_eq!(integrity, "ok");
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("read schema version");
    assert_eq!(version, 2, "the patch must preserve LDK's schema");
    let count: usize = connection
        .query_row("SELECT count(*) FROM ldk_node_data", [], |row| row.get(0))
        .expect("count persisted records");
    assert_eq!(count, expected_rows);
}

#[tokio::test]
async fn populated_store_survives_close_reopen_update_and_remove() {
    let directory = tempfile::tempdir().expect("create disposable store directory");
    let mut records = vec![
        ("", "", "shared".to_owned(), vec![0, 255, 1, 0, 128]),
        ("monitors", "archive", "shared".to_owned(), vec![17; 16_384]),
        ("payments", "", "empty".to_owned(), Vec::new()),
    ];
    for index in 0..64_u8 {
        records.push((
            "payments",
            "",
            format!("payment-{index:02}"),
            (0..=255_u8).map(|byte| byte ^ index).collect(),
        ));
    }
    {
        let store = open_store(directory.path());
        for (primary, secondary, key, value) in &records {
            KVStore::write(&store, primary, secondary, key, value.clone())
                .await
                .expect("persist synthetic record through the async store API");
        }
    }
    assert_database(directory.path(), records.len());
    {
        let store = open_store(directory.path());
        assert_records(&store, &records);
        // Replace a value larger than a page; keep the same key in another namespace.
        records[1].3 = vec![231; 24_577];
        let (primary, secondary, key, value) = &records[1];
        KVStore::write(&store, primary, secondary, key, value.clone())
            .await
            .expect("replace persisted value");
        let removed = records.remove(3);
        KVStore::remove(&store, removed.0, removed.1, &removed.2, false)
            .await
            .expect("remove persisted record");
        assert_eq!(
            KVStore::read(&store, removed.0, removed.1, &removed.2)
                .await
                .expect_err("removed record must be absent")
                .kind(),
            ldk_node::lightning::io::ErrorKind::NotFound
        );
        let mut keys = KVStore::list(&store, "payments", "")
            .await
            .expect("list async payment namespace");
        keys.sort();
        assert_eq!(keys.len(), 64);
        assert!(!keys.contains(&removed.2));
        let added = ("payments", "", "after-restart".to_owned(), vec![9, 0, 9]);
        KVStoreSync::write(&store, added.0, added.1, &added.2, added.3.clone())
            .expect("write through the synchronous store API after reopen");
        records.push(added);
    }
    assert_database(directory.path(), records.len());
    let store = open_store(directory.path());
    assert_records(&store, &records);
    assert_eq!(
        KVStoreSync::read(&store, "payments", "", "payment-00")
            .expect_err("deletion must survive reopen")
            .kind(),
        ldk_node::lightning::io::ErrorKind::NotFound
    );
}

#[test]
fn previous_sqlite_database_remains_readable_and_writable_after_reopen() {
    // Written by the unpatched SQLite bundled in libsqlite3-sys 0.28.0.
    // The adjacent fixture README records source hashes and reproduction commands.
    let fixture = include_bytes!("fixtures/sqlite-3.45.0/ldk_node_data.sqlite");
    assert_eq!(&fixture[..16], b"SQLite format 3\0");
    assert_eq!(
        u32::from_be_bytes(fixture[96..100].try_into().unwrap()),
        3_045_000
    );
    let directory = tempfile::tempdir().expect("create disposable fixture directory");
    fs::write(directory.path().join(SQLITE_DB_FILE_NAME), fixture)
        .expect("copy the immutable old-library fixture");
    let mut records = vec![
        ("", "", "shared".to_owned(), vec![0, 1, 255, 0, 127]),
        ("payments", "", "shared".to_owned(), vec![254, 0, 170, 85]),
        ("payments", "", "obsolete".to_owned(), Vec::new()),
        ("monitors", "archive", "shared".to_owned(), vec![0; 16_384]),
    ];
    assert_database(directory.path(), records.len());
    {
        let store = open_store(directory.path());
        assert_records(&store, &records);
        records[1].3 = vec![85; 8_193];
        let (primary, secondary, key, value) = &records[1];
        KVStoreSync::write(&store, primary, secondary, key, value.clone())
            .expect("update the previous-library database");
        let removed = records.remove(2);
        KVStoreSync::remove(&store, removed.0, removed.1, &removed.2, true)
            .expect("remove from the previous-library database");
        let added = ("payments", "", "new".to_owned(), vec![7, 0, 255]);
        KVStoreSync::write(&store, added.0, added.1, &added.2, added.3.clone())
            .expect("insert into the previous-library database");
        records.push(added);
    }
    assert_database(directory.path(), records.len());
    let store = open_store(directory.path());
    assert_records(&store, &records);
    assert_eq!(
        KVStoreSync::read(&store, "payments", "", "obsolete")
            .expect_err("old-library deletion must survive reopen")
            .kind(),
        ldk_node::lightning::io::ErrorKind::NotFound
    );
}
