#!/usr/bin/env bash
# Checks the product tag read contract on both sides of the wire with the shared fixture.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$crate_dir/../.." && pwd)"
manifest="$crate_dir/Cargo.toml"
binary="${CARGO_TARGET_DIR:-$crate_dir/target}/debug/catalog-reads"
tests_project="$repo_root/src/Tests/Nop.Tests/Nop.Tests.csproj"
filter="FullyQualifiedName~ProductTagReadContractTests"

echo "==> cargo test"
cargo test --manifest-path "$manifest"

echo "==> cargo build"
cargo build --manifest-path "$manifest"

echo "==> dotnet test, PRODUCT_TAGS_RUST=off"
PRODUCT_TAGS_RUST=off dotnet test "$tests_project" --filter "$filter"

echo "==> dotnet test, PRODUCT_TAGS_RUST=on"
PRODUCT_TAGS_RUST=on CATALOG_READS_BIN="$binary" dotnet test "$tests_project" --no-build --filter "$filter"

echo "verify-contract: all checks passed"
