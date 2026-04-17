#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "usage: run-with-rust-cache-env.sh <command> [args...]" >&2
  exit 64
fi

if [[ "${BORINGCACHE_RUST_SETUP_OUTCOME:-}" == "failure" ]]; then
  unset RUSTC_WRAPPER
  unset SCCACHE_DIR
  unset SCCACHE_CACHE_SIZE
  unset SCCACHE_IDLE_TIMEOUT
  unset SCCACHE_SERVER_PORT
  unset SCCACHE_ERROR_LOG
  unset SCCACHE_LOG
  unset CC
  unset CXX
fi

exec "$@"
