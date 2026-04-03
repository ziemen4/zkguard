#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker run --rm \
  -v "$REPO_ROOT:/repo:ro" \
  -w /repo/gnark \
  golang:1.23 \
  /usr/local/go/bin/go test ./src -run '^$' -bench '^BenchmarkZKGuard$' -benchmem -benchtime=1x -count=1 -timeout 30m -example contributor_payments
