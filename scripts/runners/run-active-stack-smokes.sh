#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

"$REPO_ROOT/scripts/runners/run-gnark-contributor-payments.sh"
"$REPO_ROOT/scripts/runners/run-noir-contributor-payments.sh"
"$REPO_ROOT/scripts/runners/run-risc0-contributor-payments.sh"
