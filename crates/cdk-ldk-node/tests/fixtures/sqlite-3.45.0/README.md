# Previous LDK SQLite store fixture

`ldk_node_data.sqlite` contains four synthetic records. It has no keys, funds,
payment details or valid serialized node state. The records cover empty and
binary values, a value larger than one page, and the same key in three
namespaces.

`create_fixture.rs` wrote the database through the actual `SqliteStore` API
of the published `ldk-node` 0.7.1 crate. The separate writer workspace used
`rusqlite` 0.31.0 and the original bundled `libsqlite3-sys` 0.28.0 from the
registry. It did not use the CDK workspace's patch. The generator checks the
SQLite version and source ID. Cargo metadata confirmed registry sources for
all three dependencies.

| Input or output | Identity |
| --- | --- |
| Published `ldk-node` crate checksum | `9a890a268dd7430d16ae5a867d73070414beab83fc744b07147aab3a33e38360` |
| Published `libsqlite3-sys` crate checksum | `0c10584274047cb335c23d3e61bcef8e323adae7c5c8c760540f73610177fc3f` |
| Original `sqlite3.c` SHA-256 | `7956a38f236a6be6c0bb30c96ba4f85f19e5a69f6beb6d2c62c9d246972a6775` |
| SQLite source ID | `2024-01-15 17:01:13 1066602b2b1976fe58b5150777cced894af17c803e068f5918390d6915b46e1d` |
| Fixture SHA-256 | `fbd40b431b63321afb1e79997773ee468a4c77bdacc13fdc181f2db9c5ddd04a` |

To reproduce, run from the CDK repository root. Use a separate workspace so
the writer does not inherit the SQLite patch. The generator refuses an
existing output directory. Verify the original SQLite source hash above.

```sh
fixture_dir=crates/cdk-ldk-node/tests/fixtures/sqlite-3.45.0
fixture_build=$(mktemp -d)
mkdir "$fixture_build/src"
cp "$fixture_dir/create_fixture.rs" "$fixture_build/src/main.rs"
cat > "$fixture_build/Cargo.toml" <<'TOML'
[package]
name = "original-ldk-fixture-writer"
version = "0.1.0"
edition = "2021"
[workspace]
[dependencies]
ldk-node = "=0.7.1"
rusqlite = { version = "=0.31.0", features = ["bundled"] }
libsqlite3-sys = "=0.28.0"
TOML
cargo run --manifest-path "$fixture_build/Cargo.toml" -- "$fixture_build/store"
sha256sum "$fixture_build/store/ldk_node_data.sqlite"
cmp "$fixture_dir/ldk_node_data.sqlite" "$fixture_build/store/ldk_node_data.sqlite"
```

Run the patched store tests with:

```sh
cargo test -p cdk-ldk-node --test sqlite_store_restart -- --test-threads=1
```

The tests copy the fixture to a temporary directory. The actual LDK
`SqliteStore` reads, changes and reopens that copy with the current dependency.
A separate test writes through the current store's async API and reads through
its sync API after reopen. Both tests check the schema, row count and SQLite
integrity after the store closes.

These tests prove store-level persistence and old-writer to new-reader
compatibility. They do not prove live channel recovery, node state decoding,
crash recovery or the security regression itself.
