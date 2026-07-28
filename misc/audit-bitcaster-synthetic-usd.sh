#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

search_roots=(Cargo.toml crates Dockerfile)
forbidden='cdk-exchange-rate|cdk_exchange_rate|rate_quoter|RateQuoter|rate_quote_terms|rate_unit_control|PostgresRateQuoteStore|SetUnitQuoteState|SetUnitIssuanceCap'

case "${1:-}" in
  inventory)
    rg -n "$forbidden" "${search_roots[@]}" || true
    ;;
  verify)
    if rg -n "$forbidden" "${search_roots[@]}"; then
      echo "rate-only operational surface remains" >&2
      exit 1
    fi

    rg -q 'Usd' crates/cashu/src/nuts/nut00/mod.rs
    rg -q 'Custom' crates/cashu/src/nuts/nut00/mod.rs
    rg -q 'SatMsatConverter|MsatSatConverter' crates/cdk-common/src
    rg -q 'UpdateNut04' crates/cdk-mint-rpc/src/proto/cdk-mint-rpc.proto
    rg -q 'UpdateNut05' crates/cdk-mint-rpc/src/proto/cdk-mint-rpc.proto
    rg -q 'RotateNextKeyset' crates/cdk-mint-rpc/src/proto/cdk-mint-rpc.proto
    ;;
  *)
    echo "usage: $0 inventory|verify" >&2
    exit 2
    ;;
esac
