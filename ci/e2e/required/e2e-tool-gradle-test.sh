#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../e2e-helpers.sh"

CLI_REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BINARY="${BINARY:-${CLI_REPO_ROOT}/target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_PORT="${PROXY_PORT:-5061}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"
GRADLE_VERSION="${GRADLE_VERSION:-8.12}"

require_save_capable_token

for dep in java curl; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

export_resolved_cli_tokens admin

mkdir -p "${LOG_DIR}"
GRADLE_LOG_DIR="${LOG_DIR}/tool-gradle-e2e"
rm -rf "${GRADLE_LOG_DIR}"
mkdir -p "${GRADLE_LOG_DIR}"

TAG="$(e2e_tag "tool-gradle")"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

setup_e2e_traps "${BINARY}" "${WORKSPACE}"
register_tag_for_cleanup "${TAG}"

PROJECT_DIR="${GRADLE_LOG_DIR}/gradle-project"
mkdir -p "${PROJECT_DIR}/src/main/java/com/example"

cat > "${PROJECT_DIR}/settings.gradle.kts" <<EOF
rootProject.name = "gradle-e2e"

buildCache {
    local {
        isEnabled = false
    }
    remote<HttpBuildCache> {
        url = uri("${PROXY_URL}/cache/")
        isPush = true
        isAllowUntrustedServer = true
        isAllowInsecureProtocol = true
    }
}
EOF

cat > "${PROJECT_DIR}/build.gradle.kts" <<'EOF'
plugins {
    java
}

group = "com.example"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}
EOF

cat > "${PROJECT_DIR}/gradle.properties" <<'EOF'
org.gradle.caching=true
org.gradle.console=plain
EOF

cat > "${PROJECT_DIR}/src/main/java/com/example/App.java" <<'EOF'
package com.example;

public class App {
    public static void main(String[] args) {
        System.out.println("Hello from Gradle e2e!");
        System.out.println("Fibonacci(20) = " + fibonacci(20));
    }

    public static long fibonacci(int n) {
        long a = 0, b = 1;
        for (int i = 0; i < n; i++) {
            long tmp = b;
            b = a + b;
            a = tmp;
        }
        return a;
    }
}
EOF

GRADLE_WRAPPER_DIR="${GRADLE_LOG_DIR}/gradle-wrapper-dist"
if ! command -v gradle >/dev/null 2>&1; then
  echo "Installing Gradle wrapper..."
  GRADLE_DIST_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
  GRADLE_ZIP="${GRADLE_LOG_DIR}/gradle.zip"
  curl -fsSL "${GRADLE_DIST_URL}" -o "${GRADLE_ZIP}"
  unzip -q "${GRADLE_ZIP}" -d "${GRADLE_WRAPPER_DIR}"
  GRADLE_BIN="${GRADLE_WRAPPER_DIR}/gradle-${GRADLE_VERSION}/bin/gradle"
else
  GRADLE_BIN="gradle"
fi

WRAPPER_LOG="${GRADLE_LOG_DIR}/wrapper.log"
(
  cd "${PROJECT_DIR}"
  "${GRADLE_BIN}" wrapper --gradle-version "${GRADLE_VERSION}" --no-build-cache --no-daemon \
    >"${WRAPPER_LOG}" 2>&1
) || {
  echo "ERROR: failed to generate Gradle wrapper"
  tail -n 120 "${WRAPPER_LOG}" || true
  exit 1
}
tail -n 5 "${WRAPPER_LOG}" || true
GRADLEW="${PROJECT_DIR}/gradlew"
chmod +x "${GRADLEW}"

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-tool-gradle,tool=gradle"
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG}" "${PROXY_PORT}" "${GRADLE_LOG_DIR}/proxy.log"
wait_for_proxy "${PROXY_PORT}"

COLD_GRADLE_HOME="${GRADLE_LOG_DIR}/gradle-home-cold"
WARM_GRADLE_HOME="${GRADLE_LOG_DIR}/gradle-home-warm"

echo "=== Phase 1: Cold Gradle build (seed build cache) ==="
COLD_LOG="${GRADLE_LOG_DIR}/cold-build.log"
COLD_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  GRADLE_USER_HOME="${COLD_GRADLE_HOME}" \
    "${GRADLEW}" build --build-cache --no-daemon 2>&1 | tee "${COLD_LOG}"
)
COLD_END="$(date +%s)"
COLD_SECS="$((COLD_END - COLD_START))"
echo "Cold build completed in ${COLD_SECS}s"

echo "=== Phase 2: Warm Gradle build (remote cache hit) ==="
WARM_LOG="${GRADLE_LOG_DIR}/warm-build.log"
WARM_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  rm -rf build
  GRADLE_USER_HOME="${WARM_GRADLE_HOME}" \
    "${GRADLEW}" build --build-cache --no-daemon 2>&1 | tee "${WARM_LOG}"
)
WARM_END="$(date +%s)"
WARM_SECS="$((WARM_END - WARM_START))"
echo "Warm build completed in ${WARM_SECS}s"

from_cache_count=0
if grep -q "FROM-CACHE" "${WARM_LOG}" 2>/dev/null; then
  from_cache_count="$(grep -c "FROM-CACHE" "${WARM_LOG}" || echo 0)"
  echo "  Gradle cache hits: ${from_cache_count} tasks FROM-CACHE"
fi

proxy_gets="$(grep -c ' GET ' "${GRADLE_LOG_DIR}/proxy.log" 2>/dev/null || true)"
proxy_puts="$(grep -c ' PUT ' "${GRADLE_LOG_DIR}/proxy.log" 2>/dev/null || true)"
echo "  proxy traffic: PUTs=${proxy_puts} GETs=${proxy_gets}"

if [[ "${from_cache_count}" -gt 0 ]]; then
  echo "  Gradle remote cache hit confirmed"
elif [[ "${proxy_gets}" -gt 0 ]]; then
  echo "  proxy served GET requests (cache activity detected)"
else
  echo "ERROR: no Gradle FROM-CACHE tasks and no proxy GETs — remote cache not working"
  cat "${GRADLE_LOG_DIR}/proxy.log"
  exit 1
fi

stop_proxy
dump_cache_ops_summary

if [[ "${BUDGET_REMOTE_TAG_HITS_MIN}" -gt 0 ]]; then
  if ! verify_remote_tag_visible "${BINARY}" "${WORKSPACE}" "${TAG}" "${GRADLE_LOG_DIR}" \
    "${BUDGET_REMOTE_TAG_HITS_MIN}" "${REMOTE_TAG_VERIFY_ATTEMPTS}" "${REMOTE_TAG_VERIFY_SLEEP_SECS}" "$(proxy_log)"; then
    exit 1
  fi
  echo "  remote tag verified (hits=${REMOTE_TAG_CHECK_HITS:-0})"
fi

echo ""
echo "Gradle tool e2e passed. Cold=${COLD_SECS}s Warm=${WARM_SECS}s FROM-CACHE=${from_cache_count} Logs: ${GRADLE_LOG_DIR}"
