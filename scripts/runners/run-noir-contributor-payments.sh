#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker run --rm \
  ${ZKGUARD_DOCKER_ARGS:-} \
  -e ZKGUARD_NOIR_PROVE="${ZKGUARD_NOIR_PROVE:-1}" \
  -v "$REPO_ROOT:/repo:ro" \
  ubuntu:24.04 \
  bash -lc '
    set -euo pipefail
    apt-get update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl git jq xz-utils python3 python3-pip python3-venv >/dev/null
    cp -a /repo /tmp/zkguard
    cd /tmp/zkguard/noir
    NOIR_PROVE="${ZKGUARD_NOIR_PROVE:-1}"

    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash >/dev/null
    export PATH="$PATH:/root/.nargo/bin"
    noirup -v 1.0.0-beta.13 >/dev/null
    if [ "$NOIR_PROVE" != "0" ]; then
      curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash >/dev/null
      export PATH="$PATH:/root/.bb"
      bbup -v 0.87.0 >/dev/null
    fi

    python3 -m venv /tmp/noir-venv
    /tmp/noir-venv/bin/pip install -q -r requirements.txt
    /tmp/noir-venv/bin/python src/generate_shared_prover_toml.py --scenario contributor_payments --out Prover.toml

    phase_start() {
      date +%s%N
    }
    phase_done() {
      phase_name="$1"
      start_ns="$2"
      elapsed_ns="$(( $(date +%s%N) - start_ns ))"
      awk -v name="$phase_name" -v ns="$elapsed_ns" "BEGIN { printf(\"[phase] %s_s=%.3f\\n\", name, ns / 1000000000) }"
    }

    start_ns="$(phase_start)"
    nargo compile
    phase_done compile "$start_ns"
    artifact=target/zkguard.json
    printf "[metrics] bytecode_len=%s artifact_bytes=%s\n" \
      "$(jq -r ".bytecode | length" "$artifact")" \
      "$(wc -c < "$artifact")"

    start_ns="$(phase_start)"
    nargo execute
    phase_done execute "$start_ns"
    printf "[metrics] witness_bytes=%s\n" "$(wc -c < target/zkguard.gz)"

    if [ "$NOIR_PROVE" != "0" ]; then
      start_ns="$(phase_start)"
      bb write_vk -b ./target/zkguard.json -o target
      phase_done write_vk "$start_ns"

      start_ns="$(phase_start)"
      bb prove -b ./target/zkguard.json -w ./target/zkguard.gz -o target
      phase_done prove "$start_ns"

      start_ns="$(phase_start)"
      bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs
      phase_done verify "$start_ns"
    fi
  '
