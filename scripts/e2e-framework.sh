#!/usr/bin/env bash
set -euo pipefail

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
    bazel-real)
      BINARY="$binary" \
      LOG_DIR="$log_dir" \
      TAG="$tag" \
      BAZEL_BUILD_JOBS="256" \
      BAZEL_REMOTE_MAX_CONNECTIONS="64" \
      STRESS_ACTION_COUNT="96" \
      BUDGET_REMOTE_TIMEOUTS_MAX="0" \
      BUDGET_REMOTE_TAG_HITS_MIN="1" \
      bash ./scripts/e2e-bazel-real-test.sh
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
=== Phase 2: run command cache integration ===
=== Phase 3: encryption + mount sync ===
CLI core e2e passed
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
    bazel-real)
      cat <<'EOF'
=== Phase 1: Cold build (expect local execution + upload) ===
=== Phase 2: Warm build with isolated output root (expect remote hit) ===
=== Phase 2b: Verify published remote tag resolves ===
=== Phase 3: Restart proxy and verify persisted remote hit ===
=== Phase 4: High-concurrency stress warm (expect remote hits, no connect timeouts) ===
Bazel real-client e2e passed
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

validate_leg() {
  local leg="$1"
  local log_file="$2"
  local marker
  local index=1

  if [[ ! -f "$log_file" ]]; then
    echo "ERROR: expected e2e run log at ${log_file}"
    exit 1
  fi

  while IFS= read -r marker; do
    [[ -n "$marker" ]] || continue
    if ! grep -Fq "$marker" "$log_file"; then
      echo "ERROR: missing scenario marker (step${index}): ${marker}"
      echo "--- log tail ---"
      tail -n 200 "$log_file" || true
      exit 1
    fi
    index=$((index + 1))
  done < <(markers_for_leg "$leg")
}

main() {
  if [[ "$#" -lt 1 ]]; then
    echo "usage: $0 <run|validate> ..."
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
    *)
      echo "ERROR: unknown command: ${command}"
      exit 1
      ;;
  esac
}

main "$@"
