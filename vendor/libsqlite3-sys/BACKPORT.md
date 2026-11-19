# SQLite WAL security backport

This directory contains the complete `libsqlite3-sys 0.28.0` crate archive.
`upstream-source.json` records its archive checksum and original file hashes.
The archive checksum matches both CDK lockfiles before the path override.

The upstream crate has the MIT license. Its package manifest and source license
notices remain in place. SQLite is in the public domain.

## Correction

`sqlite-wal-backport.patch` applies the SQLite correction from commit
[`e5bf119821f25be1d7f10ef0a2edbe175289166e`](https://github.com/sqlite/sqlite/commit/e5bf119821f25be1d7f10ef0a2edbe175289166e).
The corresponding Fossil check-in is
`f9b4ee369557c36c606666bd7e6d8dc4685d87531993d3ce4e7a718aa814a5ac`.
This corrects the WAL page tail initialization described by
[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html).

The change is limited to `sqlite3WalReadFrame` in `sqlite3/sqlite3.c`.
It keeps the crate version, Rust API, feature names and SQLite version string.
The bundled source still reports SQLite 3.45.0. The source hash identifies the
backport. A version-only scanner can still report this dependency.

The SQLCipher sources are unchanged. This correction does not cover a build
with `bundled-sqlcipher`. Externally linked SQLite also needs its own correction.

## Source verification

The only other upstream file changes are in `build.rs`, `Cargo.toml` and
`Cargo.toml.orig`. They add the source verification step and its pinned SHA-256
dependency. `source-hashes.sha256` records every supplied file except itself.
The build script checks these hashes before the native build. A mismatch stops
the build. The build log prints the verified bundled SQLite source hash.

Review a source change before updating the hash inventory. Keep the original
archive hashes in `upstream-source.json`. Do not replace those original hashes
with the patched hashes. Verify the resolved crate path and native build inputs
when producing an artifact. Source verification alone does not establish which
library a build that requests external linkage uses.
