//! Refusal of an embedded start after the node state moved to another backend.

use std::io;
use std::path::Path;

use crate::error::Error;

/// The record that the state move writes in the storage directory.
const CUTOVER_RECORD: &str = "CUTOVER.json";

/// Refuse a storage directory with a cutover record.
///
/// After the move, the state in this directory is stale, and a directory
/// without state gives a new node with the same keys. Both can lose channel
/// funds. Thus the existence of the record is sufficient: the guard does not
/// read its content, and it refuses when it cannot check for the record.
pub(crate) fn refuse_after_cutover(storage_dir: &Path) -> Result<(), Error> {
    let record = storage_dir.join(CUTOVER_RECORD);
    // Not `exists`: it reports a dangling link and a failed lookup as absent.
    match std::fs::symlink_metadata(&record) {
        Ok(_) => Err(Error::CutoverRecord { record }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::CutoverRecordUnchecked { record, source }),
    }
}
