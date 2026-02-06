#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIGERO_PROVER_DIR="${LIGERO_PROVER_DIR:-$(cd "$ROOT_DIR/.." && pwd)/ligero-prover}"
VK_ICD_FILENAMES="${VK_ICD_FILENAMES:-/usr/share/vulkan/icd.d/lvp_icd.json}"

HOST_BIN="$ROOT_DIR/ligero/host/target/release/zkguard-ligero-inputs"
GUEST_WASM="$ROOT_DIR/ligero/guest/target/wasm32-wasip1/release/zkguard-ligero-guest.wasm"
PROVER_BIN="$LIGERO_PROVER_DIR/build/webgpu_prover"
VERIFIER_BIN="$LIGERO_PROVER_DIR/build/webgpu_verifier"
SHADER_PATH="$LIGERO_PROVER_DIR/shader"

POLICY_FILE="$ROOT_DIR/shared/config/policy.json"
GROUPS_FILE="$ROOT_DIR/shared/config/groups.json"
ALLOWLISTS_FILE="$ROOT_DIR/shared/config/allowlists.json"
SCENARIOS_FILE="$ROOT_DIR/shared/examples/scenarios.json"

OUT_DIR="$ROOT_DIR/ligero/proof/examples"
mkdir -p "$OUT_DIR"

if [[ ! -f "$SCENARIOS_FILE" ]]; then
  echo "Missing scenarios file: $SCENARIOS_FILE" >&2
  exit 1
fi

echo "Building Ligero guest and host..."
(
  cd "$ROOT_DIR/ligero/guest"
  cargo build --target wasm32-wasip1 --release
)
(
  cd "$ROOT_DIR/ligero/host"
  cargo build --release
)

if [[ ! -x "$PROVER_BIN" || ! -x "$VERIFIER_BIN" ]]; then
  echo "Missing Ligero prover/verifier binaries in: $LIGERO_PROVER_DIR/build" >&2
  exit 1
fi

readarray -t CASES < <(
  python - "$SCENARIOS_FILE" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
for name in data.keys():
    print(name)
PY
)

for CASE in "${CASES[@]}"; do
  echo "== Running $CASE =="

  CASE_DIR="$OUT_DIR/$CASE"
  mkdir -p "$CASE_DIR"

  readarray -t CASE_FIELDS < <(
    python - "$SCENARIOS_FILE" "$CASE" <<'PY'
import json, sys
path, name = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    scenario = json.load(f)[name]
print(scenario["rule_id"])
print(scenario["from"])
print(scenario["to"])
print(scenario["value"])
print(scenario["nonce"])
print(scenario["data"])
for k in scenario["private_keys"]:
    print(f"KEY={k}")
PY
  )

  RULE_ID="${CASE_FIELDS[0]}"
  FROM_ADDR="${CASE_FIELDS[1]}"
  TO_ADDR="${CASE_FIELDS[2]}"
  VALUE="${CASE_FIELDS[3]}"
  NONCE="${CASE_FIELDS[4]}"
  DATA="${CASE_FIELDS[5]}"

  KEY_ARGS=()
  for ((i = 6; i < ${#CASE_FIELDS[@]}; i++)); do
    KEY_LINE="${CASE_FIELDS[$i]}"
    KEY="${KEY_LINE#KEY=}"
    KEY_ARGS+=("$KEY")
  done

  "$HOST_BIN" \
    --policy-file "$POLICY_FILE" \
    --groups-file "$GROUPS_FILE" \
    --allowlists-file "$ALLOWLISTS_FILE" \
    --rule-id "$RULE_ID" \
    --from "$FROM_ADDR" \
    --to "$TO_ADDR" \
    --value "$VALUE" \
    --nonce "$NONCE" \
    --data "$DATA" \
    --private-keys "${KEY_ARGS[@]}" \
    --program "$GUEST_WASM" \
    --shader-path "$SHADER_PATH" \
    --prover-out "$CASE_DIR/prover_input.json" \
    --verifier-out "$CASE_DIR/verifier_input.json"

  VK_ICD_FILENAMES="$VK_ICD_FILENAMES" "$PROVER_BIN" "$(cat "$CASE_DIR/prover_input.json")" \
    | tee "$CASE_DIR/prover.log"
  VK_ICD_FILENAMES="$VK_ICD_FILENAMES" "$VERIFIER_BIN" "$(cat "$CASE_DIR/verifier_input.json")" \
    | tee "$CASE_DIR/verifier.log"

  grep -q "Final prove result:                  true" "$CASE_DIR/prover.log"
  grep -q "Final Verify Result:                 true" "$CASE_DIR/verifier.log"
done

echo "All shared scenarios executed successfully with Ligero."
