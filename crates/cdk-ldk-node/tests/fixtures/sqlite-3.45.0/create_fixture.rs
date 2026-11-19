//! Run in a separate Cargo workspace with the original registry dependencies.
use std::path::PathBuf;

use ldk_node::io::sqlite_store::{SqliteStore, KV_TABLE_NAME, SQLITE_DB_FILE_NAME};
use ldk_node::lightning::util::persist::KVStoreSync;

fn main() {
    assert_eq!(rusqlite::version_number(), 3_045_000);
    let connection = rusqlite::Connection::open_in_memory().expect("check SQLite identity");
    let source_id: String = connection
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .expect("read SQLite source ID");
    assert_eq!(
        source_id,
        "2024-01-15 17:01:13 1066602b2b1976fe58b5150777cced894af17c803e068f5918390d6915b46e1d"
    );
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("supply a new output directory"),
    );
    std::fs::create_dir(&directory).expect("refuse an existing output directory");
    let store = SqliteStore::new(
        directory,
        Some(SQLITE_DB_FILE_NAME.to_owned()),
        Some(KV_TABLE_NAME.to_owned()),
    )
    .expect("create the synthetic store with original LDK dependencies");
    for (primary, secondary, key, value) in [
        ("", "", "shared", vec![0, 1, 255, 0, 127]),
        ("payments", "", "shared", vec![254, 0, 170, 85]),
        ("payments", "", "obsolete", Vec::new()),
        ("monitors", "archive", "shared", vec![0; 16_384]),
    ] {
        store
            .write(primary, secondary, key, value)
            .expect("write synthetic record through the original LDK store");
    }
    drop(store);
}
