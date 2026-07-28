# bitCaster synthetic-USD removal inventory

This inventory records the stopped, read-only inspection performed at commit
`a2dd47b929847c4ed7e9e14a7747ef3000b813a2` before removing bitCaster's
rate-quoted USD authority. The checkout was clean and the mint was not running.

## Rate-only objects to remove

- Workspace crate and dependency: `cdk-exchange-rate`, except for its exact
  SAT/MSAT payment adapter, which is unit-neutral and moves to `cdk-common`.
- PostgreSQL implementation and runtime-created tables:
  `rate_quote_terms`, `parked_payments`, and `rate_unit_control`.
- Mintd configuration: `[rate_quoter]`, its units, buffer, TTL, oracle sources,
  quorum/staleness controls, per-unit issuance caps, and volatile-store opt-in.
- Mintd runtime: HTTP oracle aggregation, fiat processor registration,
  rate-store allocation, pending reservation reconciliation, rate-specific
  payment-event routing, and management-RPC rate-control wiring.
- Management RPCs and messages: `SetUnitQuoteState` and
  `SetUnitIssuanceCap`.
- Rate-only fixtures and tests in the exchange-rate, PostgreSQL, mintd,
  integration-test, and management-RPC crates.

The three PostgreSQL tables contain only rate-quoted terms, parked events that
exist solely to correlate those terms, and rate pause/cap accounting. They do
not contain Cashu proofs, keys, CTF conditions, mint/melt quotes, or other
supported-unit/nonterminal custody authority, so deleting them does not reset
shared custody state.

## Mixed files requiring surgical edits

- `crates/cdk-mintd/src/canonical_payment_event_owner.rs`: retain single-owner
  lifecycle/event handling and exact SAT/MSAT conversion; remove only
  rate-context branches and rate-store access.
- `crates/cdk-mintd/src/lib.rs`: retain native SAT/MSAT backend registration,
  CTF startup, management TLS/SPKI/SAN handling, and unrelated management
  methods.
- `crates/cdk-mint-rpc/src/proto/server.rs`: retain `UpdateNut04`,
  `UpdateNut05`, `UpdateNut04Quote`, `RotateNextKeyset`, and all existing
  transport/authentication behavior.
- `crates/cdk-fake-wallet/src/lib.rs`: retain upstream generic
  cross-unit/custom-processor support; remove nothing solely because it
  mentions fiat.

## Explicitly retained generic capability

- `CurrencyUnit::Usd` and arbitrary `CurrencyUnit::Custom` protocol values.
- Generic payment processors, including upstream fake-wallet cross-unit
  behavior and gRPC processors.
- Unit-generic NUT-CTF behavior and recovery.
- The exact fixed-ratio SAT/MSAT payment adapter.
- Management mTLS, SPKI pinning, SAN validation, certificate lifecycle, and
  every management method other than the two rate-only methods named above.

Run `misc/audit-bitcaster-synthetic-usd.sh inventory` to reproduce the source
inventory. After removal, run it with `verify` to reject rate-only operational
surface while proving the retained generic symbols remain.
