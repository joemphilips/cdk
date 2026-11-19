//! Verify the reviewed vendored sources before any native build.

use std::path::Path;

use sha2::{Digest, Sha256};

pub fn verify() {
    let root = std::env::var_os("CARGO_MANIFEST_DIR").expect("crate directory is required");
    let root = Path::new(&root);
    println!("cargo:rerun-if-changed=source-hashes.sha256");
    for line in include_str!("source-hashes.sha256").lines() {
        let (expected, relative) = line
            .split_once("  ")
            .expect("source hash record must contain a digest and a path");
        assert!(
            expected.len() == 64
                && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
                && Path::new(relative)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "invalid source hash record"
        );
        println!("cargo:rerun-if-changed={relative}");
        let data = std::fs::read(root.join(relative))
            .unwrap_or_else(|error| panic!("cannot read vendored source {relative}: {error}"));
        let actual = format!("{:x}", Sha256::digest(&data));
        assert_eq!(actual, expected, "vendored source hash mismatch: {relative}");
        if relative == "sqlite3/sqlite3.c" {
            println!("cargo:warning=Verified bundled SQLite source SHA-256 {actual}");
        }
    }
}
