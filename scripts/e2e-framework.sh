#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

resolved_rust_version() {
  if [[ -n "${RUST_VERSION:-}" ]]; then
    printf '%s\n' "${RUST_VERSION}"
    return 0
  fi
  "${SCRIPT_DIR}/rust-version.sh"
}

run_leg() {
  local leg="$1"
  local binary="$2"
  local log_dir="$3"
  local tag="gha-e2e-${leg}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
  local workspace="${GITHUB_REPOSITORY:-${WORKSPACE:-}}"

  case "$leg" in
    integrity)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      BORINGCACHE_API_URL="${BORINGCACHE_API_URL:-https://api.boringcache.com}" \
      LOG_DIR="$log_dir" \
      bash ./scripts/e2e-cli-integrity-test.sh
      ;;
    cli-core)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      BORINGCACHE_API_URL="${BORINGCACHE_API_URL:-https://api.boringcache.com}" \
      LOG_DIR="$log_dir" \
      bash ./scripts/e2e-cli-core-test.sh
      ;;
    cli-contract)
      LOG_DIR="$log_dir" \
      bash ./scripts/e2e-cli-contract-test.sh
      ;;
    security)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      BORINGCACHE_API_URL="${BORINGCACHE_API_URL:-https://api.boringcache.com}" \
      LOG_DIR="$log_dir" \
      BORINGCACHE_E2E_RESTORE_TOKEN="${BORINGCACHE_E2E_RESTORE_TOKEN:-}" \
      BORINGCACHE_E2E_SAVE_TOKEN="${BORINGCACHE_E2E_SAVE_TOKEN:-}" \
      bash ./scripts/e2e-security-test.sh
      ;;
    adapters-http)
      BINARY="$binary" \
      LOG_DIR="$log_dir" \
      TAG="$tag" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-all-adapters-http-test.sh
      ;;
    dual-proxy)
      BINARY="$binary" \
      LOG_DIR="$log_dir" \
      TAG="$tag" \
      BUDGET_CONTENTION_WALL_SECONDS_MAX="480" \
      BUDGET_TOTAL_CONFLICTS_MAX="20" \
      BUDGET_PROXY_429_MAX="0" \
      BUDGET_CACHE_OPS_GET_RECORDS_MIN="300" \
      BUDGET_CACHE_OPS_GET_HIT_RATE_MAX="100" \
      BUDGET_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX="15" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-dual-proxy-contention-test.sh
      ;;
    docker-buildkit)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      E2E_TAG_PREFIX="gha-cache-registry" \
      PORT="5000" \
      LOG_DIR="$log_dir" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-docker-buildkit-registry-test.sh
      ;;
    prefetch-readiness)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      TAG="gha-prefetch-readiness-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}" \
      BLOB_COUNT="20000" \
      BLOB_SIZE_BYTES="4096" \
      SEED_CONCURRENCY="64" \
      VERIFY_CONCURRENCY="64" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      PROXY_SHUTDOWN_WAIT_SECS="120" \
      SEED_FLUSH_TIMEOUT_SECS="240" \
      LOG_DIR="$log_dir" \
      bash ./scripts/e2e-prefetch-readiness-test.sh
      ;;
    tool-hugo)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      LOG_DIR="$log_dir" \
      PORT="5000" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-tool-hugo-test.sh
      ;;
    tool-turbo)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      LOG_DIR="$log_dir" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-tool-turbo-test.sh
      ;;
    tool-sccache)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      LOG_DIR="$log_dir" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-tool-sccache-test.sh
      ;;
    tool-bazel)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      LOG_DIR="$log_dir" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-tool-bazel-test.sh
      ;;
    tool-maven)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      LOG_DIR="$log_dir" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-tool-maven-test.sh
      ;;
    tool-gradle)
      BINARY="$binary" \
      WORKSPACE="$workspace" \
      LOG_DIR="$log_dir" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-tool-gradle-test.sh
      ;;
    *)
      echo "ERROR: unknown e2e leg: ${leg}"
      exit 1
      ;;
  esac
}

run_benchmark() {
  local backend="$1"
  local phase="$2"
  local binary="$3"
  local log_dir="$4"
  local workspace="${GITHUB_REPOSITORY:-${WORKSPACE:-}}"
  local branch_slug="${GITHUB_REF_NAME:-local}"
  local sccache_dir

  branch_slug="${branch_slug//\//-}"
  sccache_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sccache-bench-${backend}-${phase}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
  rm -rf "$sccache_dir"
  mkdir -p "$sccache_dir"

  case "$backend" in
    local|proxy)
      ;;
    *)
      echo "ERROR: unknown benchmark backend: ${backend}"
      exit 1
      ;;
  esac

  case "$phase" in
    efficacy)
      (
        export SCCACHE_BACKEND="$backend"
        export RUN_EFFICACY="1"
        export RUN_STRESS="0"
        export BUDGET_EFFICACY_RUST_HIT_RATE_MIN="95"
        export BUDGET_EFFICACY_CACHE_READ_ERRORS_MAX="0"
        export BUDGET_EFFICACY_CACHE_TIMEOUTS_MAX="0"
        export BUDGET_EFFICACY_PROXY_429_MAX="0"
        export BUDGET_EFFICACY_PROXY_CONFLICTS_MAX="0"
        if [[ "$backend" == "proxy" ]]; then
          export BUDGET_EFFICACY_REMOTE_TAG_HITS_MIN="1"
          export EFFICACY_FRESH_WARM_SCCACHE_DIR="1"
          export BUDGET_EFFICACY_WARM_REQUESTS_MIN="100"
          export BUDGET_EFFICACY_CACHE_OPS_RECORDS_MIN="100"
          export BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MIN="45"
          export BUDGET_EFFICACY_TWO_PASS_HIT_RATE_MAX="55"
          export BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MIN="45"
          export BUDGET_EFFICACY_CACHE_OPS_HIT_RATE_MAX="55"
          export BUDGET_EFFICACY_CACHE_OPS_SCCACHE_HIT_RATE_DELTA_MAX="15"
        fi
        BINARY="$binary" \
        WORKSPACE="$workspace" \
        LOG_DIR="$log_dir" \
        SCCACHE_DIR="$sccache_dir" \
        TAG="gha-cache-registry-${backend}-${phase}-rust-$(resolved_rust_version)-${branch_slug}" \
        bash ./scripts/e2e-sccache-test.sh
      )
      ;;
    stress)
      (
        export SCCACHE_BACKEND="$backend"
        export RUN_EFFICACY="0"
        export RUN_STRESS="1"
        export BUDGET_STRESS_RUST_HIT_RATE_MIN="70"
        export BUDGET_STRESS_CACHE_READ_ERRORS_MAX="0"
        export BUDGET_STRESS_CACHE_TIMEOUTS_MAX="0"
        export BUDGET_STRESS_SCCACHE_STARTUP_TIMEOUTS_MAX="0"
        export BUDGET_STRESS_SCCACHE_UNEXPECTED_SHUTDOWNS_MAX="0"
        export BUDGET_STRESS_LOCK_WAITS_MAX="0"
        export BUDGET_STRESS_PROXY_429_MAX="0"
        export BUDGET_STRESS_PROXY_CONFLICTS_MAX="0"
        BINARY="$binary" \
        WORKSPACE="$workspace" \
        LOG_DIR="$log_dir" \
        SCCACHE_DIR="$sccache_dir" \
        TAG="gha-cache-registry-${backend}-${phase}-rust-$(resolved_rust_version)-${branch_slug}" \
        bash ./scripts/e2e-sccache-test.sh
      )
      ;;
    *)
      echo "ERROR: unknown benchmark phase: ${phase}"
      exit 1
      ;;
  esac
}

markers_for_leg() {
  local leg="$1"

  case "$leg" in
    integrity)
      cat <<'EOF'
=== Phase 1: allow in-root relative symlinks ===
=== Phase 2: reject absolute symlinks ===
=== Phase 3: reject escaping relative symlinks ===
CLI integrity e2e passed
EOF
      ;;
    cli-core)
      cat <<'EOF'
=== Phase 1: Save/restore/delete (archive cache path) ===
=== Phase 1b: dashboard compact TUI smoke ===
=== Phase 2: run command cache integration ===
=== Phase 3: encryption + mount sync ===
CLI core e2e passed
EOF
      ;;
    cli-contract)
      cat <<'EOF'
=== Phase 1: Pending restore and manifest-check handling ===
=== Phase 2: Concurrent writer conflict wording ===
=== Phase 3: Pending publish completion ===
CLI contract e2e passed
EOF
      ;;
    security)
      cat <<'EOF'
=== Phase 1: Tag-name injection ===
=== Phase 2: Cache poisoning via CAS tamper ===
=== Phase 3: Cross-workspace isolation ===
=== Phase 4: Signed restore (--require-server-signature) ===
=== Phase 5: Token isolation ===
Security e2e passed
EOF
      ;;
    adapters-http)
      cat <<'EOF'
=== Phase 1: Write and read with running proxy ===
=== Phase 1b: Verify published remote tag resolves ===
=== Phase 2: Read-only verification after proxy restart ===
All adapter HTTP e2e checks passed
EOF
      ;;
    dual-proxy)
      cat <<'EOF'
=== Phase 1: Prewarm (populate baseline tag) ===
=== Phase 1b: Verify published remote tag resolves ===
=== Phase 2: Dual-Proxy Contention ===
=== Phase 2b: Verify published remote tag after contention flush ===
=== Phase 3: Verification (merged index check) ===
PASS: both proxies flushed without timeouts/drops
EOF
      ;;
    docker-buildkit)
      cat <<'EOF'
=== Phase 1: Cold build and warm import ===
=== Phase 1b: Verify published remote tag resolves ===
=== Phase 2: Restart proxy and verify persisted warm import ===
=== Phase 3: Implicit latest cache import compatibility ===
=== Phase 4: Alias publish and alias warm import ===
Docker buildkit registry e2e passed
EOF
      ;;
    prefetch-readiness)
      cat <<'EOF'
=== Phase 1: Seed
=== Phase 1b: Verify published remote tag resolves ===
=== Phase 2: Restart proxy on fresh disk cache
=== Phase 3: Verify all
Prefetch readiness e2e passed
EOF
      ;;
    tool-hugo)
      cat <<'EOF'
=== Phase 1: Cold Docker build (seed cache) ===
=== Phase 2: Warm Docker build (cache hit) ===
Hugo tool e2e passed
EOF
      ;;
    tool-turbo)
      cat <<'EOF'
=== Phase 1: Cold Turbo build (seed remote cache) ===
=== Phase 2: Warm Turbo build (remote cache hit) ===
Turbo tool e2e passed
EOF
      ;;
    tool-sccache)
      cat <<'EOF'
=== Phase 1: Cold Rust build (seed sccache via proxy) ===
=== Phase 2: Warm Rust build (sccache cache hit via proxy) ===
sccache tool e2e passed
EOF
      ;;
    tool-bazel)
      cat <<'EOF'
=== Phase 1: Cold Bazel build (seed remote cache) ===
=== Phase 2: Warm Bazel build (remote cache hit) ===
Bazel tool e2e passed
EOF
      ;;
    tool-maven)
      cat <<'EOF'
=== Phase 1: Cold Maven build (seed build cache) ===
=== Phase 2: Warm Maven build (cache hit) ===
Maven tool e2e passed
EOF
      ;;
    tool-gradle)
      cat <<'EOF'
=== Phase 1: Cold Gradle build (seed build cache) ===
=== Phase 2: Warm Gradle build (remote cache hit) ===
Gradle tool e2e passed
EOF
      ;;
    *)
      echo "ERROR: unknown e2e leg: ${leg}"
      exit 1
      ;;
  esac
}

markers_for_benchmark() {
  local backend="$1"
  local phase="$2"

  case "${backend}:${phase}" in
    local:efficacy)
      cat <<'EOF'
=== Phase 1: Key-stable efficacy ===
Phase 1 (key-stable efficacy)
all checks passed (
EOF
      ;;
    proxy:efficacy)
      cat <<'EOF'
=== Phase 1: Key-stable efficacy ===
=== Phase 1b: Verify published remote tag before efficacy warm pass ===
Phase 1 (key-stable efficacy)
all checks passed (
EOF
      ;;
    local:stress|proxy:stress)
      cat <<'EOF'
=== Phase 2: Parallel contention stress ===
Phase 2 (parallel contention stress)
all checks passed (
EOF
      ;;
    *)
      echo "ERROR: unknown benchmark target: ${backend}:${phase}"
      exit 1
      ;;
  esac
}

validate_log() {
  local kind="$1"
  local log_file="$2"
  local marker_source="$3"
  local marker
  local index=1

  if [[ ! -f "$log_file" ]]; then
    echo "ERROR: expected ${kind} log at ${log_file}"
    exit 1
  fi

  while IFS= read -r marker; do
    [[ -n "$marker" ]] || continue
    if ! grep -Fq "$marker" "$log_file"; then
      echo "ERROR: missing ${kind} marker (step${index}): ${marker}"
      echo "--- log tail ---"
      tail -n 200 "$log_file" || true
      exit 1
    fi
    index=$((index + 1))
  done < <(eval "$marker_source")
}

validate_leg() {
  local leg="$1"
  local log_file="$2"

  validate_log "scenario" "$log_file" "markers_for_leg \"$leg\""
}

validate_benchmark() {
  local backend="$1"
  local phase="$2"
  local log_file="$3"

  validate_log "benchmark" "$log_file" "markers_for_benchmark \"$backend\" \"$phase\""
}

main() {
  if [[ "$#" -lt 1 ]]; then
    echo "usage: $0 <run|validate|run-benchmark|validate-benchmark> ..."
    exit 1
  fi

  local command="$1"

  case "$command" in
    run)
      if [[ "$#" -ne 4 ]]; then
        echo "usage: $0 run <leg> <binary> <log_dir>"
        exit 1
      fi
      run_leg "$2" "$3" "$4"
      ;;
    validate)
      if [[ "$#" -ne 3 ]]; then
        echo "usage: $0 validate <leg> <log_file>"
        exit 1
      fi
      validate_leg "$2" "$3"
      ;;
    run-benchmark)
      if [[ "$#" -ne 5 ]]; then
        echo "usage: $0 run-benchmark <backend> <phase> <binary> <log_dir>"
        exit 1
      fi
      run_benchmark "$2" "$3" "$4" "$5"
      ;;
    validate-benchmark)
      if [[ "$#" -ne 4 ]]; then
        echo "usage: $0 validate-benchmark <backend> <phase> <log_file>"
        exit 1
      fi
      validate_benchmark "$2" "$3" "$4"
      ;;
    *)
      echo "ERROR: unknown command: ${command}"
      exit 1
      ;;
  esac
}

main "$@"
