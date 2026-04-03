#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker run --rm \
  -v "$REPO_ROOT:/repo:ro" \
  ubuntu:24.04 \
  bash -lc '
    set -euo pipefail
    apt-get update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl git jq xz-utils python3 python3-pip python3-venv >/dev/null
    cp -a /repo /tmp/zkguard
    cd /tmp/zkguard/noir

    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash >/dev/null
    curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash >/dev/null
    export PATH="$PATH:/root/.nargo/bin"
    noirup -v 1.0.0-beta.13 >/dev/null
    export PATH="$PATH:/root/.bb"
    bbup -v 0.87.0 >/dev/null

    python3 -m venv /tmp/noir-venv
    /tmp/noir-venv/bin/pip install -q -r requirements.txt
    /tmp/noir-venv/bin/python src/generate_shared_prover_toml.py --scenario contributor_payments --out Prover.toml

    nargo compile
    nargo execute
    bb write_vk -b ./target/zkguard.json -o target
    bb prove -b ./target/zkguard.json -w ./target/zkguard.gz -o target
    bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs
  '
