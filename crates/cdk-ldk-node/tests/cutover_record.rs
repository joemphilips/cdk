//! A storage directory with a cutover record never starts an embedded node.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use cdk_common::common::FeeReserve;
use cdk_ldk_node::{CdkLdkNode, CdkLdkNodeBuilder, ChainSource, GossipSource};
use ldk_node::bitcoin::Network;

const RECORD: &str = "CUTOVER.json";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

async fn build(storage_dir: &Path) -> Result<CdkLdkNode, String> {
    CdkLdkNodeBuilder::new(
        Network::Regtest,
        ChainSource::Esplora("http://127.0.0.1:1".to_string()),
        GossipSource::P2P,
        storage_dir
            .to_str()
            .expect("storage path is UTF-8")
            .to_string(),
        FeeReserve {
            min_fee_reserve: 0.into(),
            percent_fee_reserve: 0.0,
        },
        vec!["127.0.0.1:0".parse().expect("listen address")],
        Arc::new(
            cdk_sqlite::mint::memory::empty()
                .await
                .expect("in-memory store"),
        ),
    )
    .with_seed(MNEMONIC.parse().expect("mnemonic"))
    .build()
    .map_err(|err| err.to_string())
}

async fn assert_refused(storage_dir: &Path, case: &str) {
    let error = build(storage_dir)
        .await
        .err()
        .unwrap_or_else(|| panic!("{case}: the embedded node must not start"));
    let record = storage_dir.join(RECORD).display().to_string();
    assert!(
        error.contains(&record),
        "{case}: the error must name {record}, got: {error}"
    );
}

fn files(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(directory)
        .expect("list the storage directory")
        .map(|entry| {
            let path = entry.expect("directory entry").path();
            let name = path
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .to_string();
            (name, fs::read(&path).expect("read a storage file"))
        })
        .collect()
}

/// A configuration rollback selects the embedded backend again, and the old
/// SQLite file is back at its name. The state is stale after the cutover.
#[tokio::test]
async fn a_rollback_to_the_old_storage_directory_is_refused() {
    let storage = tempfile::tempdir().expect("storage directory");
    drop(
        build(storage.path())
            .await
            .expect("build before the cutover"),
    );
    fs::write(storage.path().join(RECORD), "{}").expect("write the record");
    let before = files(storage.path());
    assert!(before.contains_key("ldk_node_data.sqlite"));

    assert_refused(storage.path(), "a rollback").await;
    assert_eq!(
        files(storage.path()),
        before,
        "a refused start must not change the storage directory"
    );

    // Only the record refuses the start: a reverted move removes it.
    fs::remove_file(storage.path().join(RECORD)).expect("remove the record");
    build(storage.path())
        .await
        .expect("build without the record");
}

/// Without the guard, a directory without node data starts a new node with the
/// same keys.
#[tokio::test]
async fn a_fresh_storage_directory_with_the_record_is_refused() {
    let storage = tempfile::tempdir().expect("storage directory");
    fs::write(storage.path().join(RECORD), "{}").expect("write the record");

    assert_refused(storage.path(), "a fresh directory").await;
    assert_eq!(
        files(storage.path()).keys().collect::<Vec<_>>(),
        [RECORD],
        "a refused start must not create a node"
    );
}

#[tokio::test]
async fn the_content_of_the_record_does_not_matter() {
    for (case, content) in [
        ("an empty record", &b""[..]),
        ("a record that is not JSON", &b"\xff\x00"[..]),
        (
            "a record for another backend",
            &br#"{"backend":"ldk_node"}"#[..],
        ),
    ] {
        let storage = tempfile::tempdir().expect("storage directory");
        fs::write(storage.path().join(RECORD), content).expect("write the record");
        assert_refused(storage.path(), case).await;
    }

    let storage = tempfile::tempdir().expect("storage directory");
    fs::create_dir(storage.path().join(RECORD)).expect("create a directory at the record name");
    assert_refused(storage.path(), "a directory at the record name").await;
}

/// The guard fails closed when it cannot read the record.
#[cfg(unix)]
#[tokio::test]
async fn an_unreadable_record_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let storage = tempfile::tempdir().expect("storage directory");
    let record = storage.path().join(RECORD);
    fs::write(&record, "{}").expect("write the record");
    fs::set_permissions(&record, fs::Permissions::from_mode(0o000)).expect("remove the mode bits");
    assert_refused(storage.path(), "a record without read permission").await;

    let storage = tempfile::tempdir().expect("storage directory");
    symlink("missing-target", storage.path().join(RECORD)).expect("create a dangling link");
    assert_refused(storage.path(), "a dangling link").await;

    // The lookup of the record itself fails, with an error that is not "not found".
    let parent = tempfile::tempdir().expect("parent directory");
    let storage = parent.path().join("loop");
    symlink("loop", &storage).expect("create a link loop");
    assert_refused(&storage, "a failed lookup").await;
}

/// No record: a first start creates its storage directory, as before.
#[tokio::test]
async fn a_start_without_the_record_is_not_affected() {
    let parent = tempfile::tempdir().expect("parent directory");
    build(&parent.path().join("ldk-node"))
        .await
        .expect("first start in a new directory");
}
