#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUN_HTTP_ADAPTERS="${RUN_HTTP_ADAPTERS:-1}"
RUN_REAL_NX_TURBO_GO="${RUN_REAL_NX_TURBO_GO:-0}"
RUN_SCCACHE_BENCH="${RUN_SCCACHE_BENCH:-0}"
RUN_DUAL_PROXY="${RUN_DUAL_PROXY:-0}"
RUN_SCCACHE_IN_NX_GO="${RUN_SCCACHE_IN_NX_GO:-0}"

require_flag() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "ERROR: ${name} must be 0 or 1"
    exit 1
  fi
}

require_flag "RUN_HTTP_ADAPTERS" "$RUN_HTTP_ADAPTERS"
require_flag "RUN_REAL_NX_TURBO_GO" "$RUN_REAL_NX_TURBO_GO"
require_flag "RUN_SCCACHE_BENCH" "$RUN_SCCACHE_BENCH"
require_flag "RUN_DUAL_PROXY" "$RUN_DUAL_PROXY"
require_flag "RUN_SCCACHE_IN_NX_GO" "$RUN_SCCACHE_IN_NX_GO"

echo "=== Adapter Suite ==="
echo "RUN_HTTP_ADAPTERS=${RUN_HTTP_ADAPTERS}"
echo "RUN_REAL_NX_TURBO_GO=${RUN_REAL_NX_TURBO_GO}"
echo "RUN_SCCACHE_BENCH=${RUN_SCCACHE_BENCH}"
echo "RUN_DUAL_PROXY=${RUN_DUAL_PROXY}"
echo "RUN_SCCACHE_IN_NX_GO=${RUN_SCCACHE_IN_NX_GO}"

if [[ "$RUN_HTTP_ADAPTERS" == "1" ]]; then
  echo ""
  echo "Running HTTP adapter e2e checks..."
  bash "${SCRIPT_DIR}/required/e2e-all-adapters-http-test.sh"
fi

if [[ "$RUN_REAL_NX_TURBO_GO" == "1" ]]; then
  echo ""
  echo "Running real-client Nx/Turborepo/Go checks..."
  RUN_SCCACHE="$RUN_SCCACHE_IN_NX_GO" bash "${SCRIPT_DIR}/e2e-nx-go-test.sh"
fi

if [[ "$RUN_SCCACHE_BENCH" == "1" ]]; then
  echo ""
  echo "Running sccache efficacy/stress benchmark..."
  bash "${SCRIPT_DIR}/extended/e2e-sccache-test.sh"
fi

if [[ "$RUN_DUAL_PROXY" == "1" ]]; then
  echo ""
  echo "Running dual-proxy contention test..."
  bash "${SCRIPT_DIR}/extended/e2e-dual-proxy-contention-test.sh"
fi

echo ""
echo "Adapter suite completed."
