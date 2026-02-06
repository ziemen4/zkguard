#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCENARIOS_FILE="$ROOT_DIR/shared/examples/scenarios.json"
POLICY_FILE="$ROOT_DIR/shared/config/policy.json"
GROUPS_FILE="$ROOT_DIR/shared/config/groups.json"
ALLOWLISTS_FILE="$ROOT_DIR/shared/config/allowlists.json"
PYTHON_BIN="${PYTHON_BIN:-}"

if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "Missing Python interpreter. Install python3 or set PYTHON_BIN." >&2
    exit 1
  fi
fi

if [[ -z "${RISC0_DEV_MODE:-}" ]]; then
  export RISC0_DEV_MODE=1
fi

case "${RISC0_DEV_MODE,,}" in
  1|true|yes|on)
    ;;
  *)
    echo "Refusing to run risc0 examples without dev mode." >&2
    echo "Set RISC0_DEV_MODE=1 (or true) to avoid zk proving / OOM risk." >&2
    exit 1
    ;;
esac

echo "Running risc0 shared examples in dev mode (RISC0_DEV_MODE=${RISC0_DEV_MODE})"

if [[ ! -f "$SCENARIOS_FILE" ]]; then
  echo "Missing scenarios file: $SCENARIOS_FILE" >&2
  exit 1
fi

readarray -t SCENARIOS < <(
  "$PYTHON_BIN" - "$SCENARIOS_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
for name in data.keys():
    print(name)
PY
)

for SCENARIO in "${SCENARIOS[@]}"; do
  readarray -t FIELDS < <(
    "$PYTHON_BIN" - "$SCENARIOS_FILE" "$SCENARIO" <<'PY'
import json, sys
path, name = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    s = json.load(f)[name]
print(s["rule_id"])
print(s["from"])
print(s["to"])
print(s["value"])
print(s["nonce"])
print(s["data"])
for k in s["private_keys"]:
    print(f"KEY={k}")
PY
  )

  RULE_ID="${FIELDS[0]}"
  FROM_ADDR="${FIELDS[1]}"
  TO_ADDR="${FIELDS[2]}"
  VALUE="${FIELDS[3]}"
  NONCE="${FIELDS[4]}"
  DATA="${FIELDS[5]}"

  KEY_ARGS=()
  for ((i = 6; i < ${#FIELDS[@]}; i++)); do
    KEY_ARGS+=("${FIELDS[$i]#KEY=}")
  done

  echo "Running risc0 scenario: $SCENARIO"
  RISC0_DEV_MODE="$RISC0_DEV_MODE" cargo run --example prover -- \
    --policy-file "$POLICY_FILE" \
    --groups-file "$GROUPS_FILE" \
    --allowlists-file "$ALLOWLISTS_FILE" \
    --rule-id "$RULE_ID" \
    --from "$FROM_ADDR" \
    --to "$TO_ADDR" \
    --value "$VALUE" \
    --nonce "$NONCE" \
    --data "$DATA" \
    --private-keys "${KEY_ARGS[@]}"
done
