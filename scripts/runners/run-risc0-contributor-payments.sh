#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RISC0_ROOT="$REPO_ROOT/risc0"
ARTIFACT_DIR="$REPO_ROOT/artifacts/smokes"
RAW_LOG="$ARTIFACT_DIR/risc0-contributor_payments.raw.log"
SMOKE_LOG="$ARTIFACT_DIR/risc0-contributor_payments.log"
HOST_CACHE="/tmp/risc0-host"
CARGO_HOME="$HOST_CACHE/cargo-home"
RUSTUP_HOME="$HOST_CACHE/rustup-home"
RZUP_HOME="/home/clawd/.risc0"
DEV_MODE="${RISC0_DEV_MODE:-0}"

mkdir -p "$ARTIFACT_DIR"
mkdir -p "$HOST_CACHE"

if [ ! -x "$CARGO_HOME/bin/rzup" ]; then
  docker run --rm -v "$HOST_CACHE:/out" rust:1.91 bash -lc "cp -a /usr/local/cargo /out/cargo-home && cp -a /usr/local/rustup /out/rustup-home"
fi

if [ ! -x "$RZUP_HOME/extensions/v3.0.5-cargo-risczero-x86_64-unknown-linux-gnu/r0vm" ]; then
  export CARGO_HOME RUSTUP_HOME RZUP_HOME
  export PATH="$CARGO_HOME/bin:$PATH"
  cargo install rzup --locked
  rzup install
fi

if [ ! -w "$RISC0_ROOT/target/release/examples/prover" ]; then
  docker run --rm -v "$RISC0_ROOT:/work" alpine sh -lc "chown -R $(id -u):$(id -g) /work"
fi

rm -f "$RAW_LOG" "$SMOKE_LOG"

DEV_ARG=()
if [ "$DEV_MODE" = "1" ] || [ "$DEV_MODE" = "true" ] || [ "$DEV_MODE" = "yes" ]; then
  DEV_ARG+=(--dev-mode)
fi

(
  cd "$RISC0_ROOT"
  export CARGO_HOME RUSTUP_HOME RZUP_HOME
  export PATH="$CARGO_HOME/bin:$RZUP_HOME/extensions/v3.0.5-cargo-risczero-x86_64-unknown-linux-gnu:$PATH"
  export RISC0_THREADS="${RISC0_THREADS:-2}"
  cargo build --release --example prover
  ./target/release/examples/prover \
    --policy-file examples/policy.json \
    --groups-file examples/groups.json \
    --allowlists-file examples/allowlists.json \
    --rule-id 2 \
    --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    --to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
    --value 0 \
    --nonce 0 \
    --data a9059cbb0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000012a05f200 \
    --private-keys 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    "${DEV_ARG[@]}"
) | tee "$RAW_LOG"

cp "$RAW_LOG" "$SMOKE_LOG"

grep -q '^BENCH_PROVE_MS=' "$SMOKE_LOG"
grep -q '^DEV_MODE=' "$SMOKE_LOG"
grep -q '^\[2\] Proved!$' "$SMOKE_LOG"
grep -q '^BENCH_VERIFY_MS=' "$SMOKE_LOG"
grep -q '^\[2\] Verified!$' "$SMOKE_LOG"

cat "$SMOKE_LOG"
