//! Ordinary WAL reads and checkpoints through the mint's resolved rusqlite.

use rusqlite::{params, Connection};

#[test]
fn committed_wal_values_survive_reader_restart_and_checkpoint() {
    let directory = tempfile::tempdir().expect("create disposable database directory");
    let path = directory.path().join("ordinary-wal.sqlite");
    let mut writer = Connection::open(&path).expect("open writer");
    let mode: String = writer
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .expect("enable ordinary WAL mode");
    assert_eq!(mode, "wal");
    writer
        .execute_batch(
            "PRAGMA wal_autocheckpoint=0;
             CREATE TABLE records (id INTEGER PRIMARY KEY, value BLOB NOT NULL);",
        )
        .expect("create synthetic records table");

    let original = vec![37_u8; 12_345];
    writer
        .execute("INSERT INTO records VALUES (1, ?1)", params![original])
        .expect("commit original multi-page value");
    let reader = Connection::open(&path).expect("open independent reader");
    reader
        .execute_batch("BEGIN")
        .expect("start reader snapshot");
    let read_value = |connection: &Connection| -> Vec<u8> {
        connection
            .query_row("SELECT value FROM records WHERE id=1", [], |row| row.get(0))
            .expect("read committed value")
    };
    assert_eq!(read_value(&reader), original);

    let replacement: Vec<u8> = (0..24_577).map(|index| (index % 251) as u8).collect();
    let transaction = writer.transaction().expect("start writer transaction");
    transaction
        .execute(
            "UPDATE records SET value=?1 WHERE id=1",
            params![replacement],
        )
        .expect("write replacement value");
    transaction.commit().expect("commit replacement to WAL");
    assert_eq!(read_value(&reader), original, "reader retains its snapshot");
    reader.execute_batch("COMMIT").expect("end reader snapshot");
    drop(reader);

    let reopened = Connection::open(&path).expect("reopen reader while WAL is active");
    assert_eq!(read_value(&reopened), replacement);
    drop(reopened);
    let checkpoint: (i32, i32, i32) = writer
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("checkpoint committed state");
    assert_eq!(
        checkpoint,
        (0, 0, 0),
        "checkpoint completes without a reader"
    );
    drop(writer);

    let restarted = Connection::open(&path).expect("reopen checkpointed database");
    assert_eq!(read_value(&restarted), replacement);
    let integrity: String = restarted
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("check database integrity");
    assert_eq!(integrity, "ok");
}
