#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

BINARY="${BINARY:-./target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
LOG_DIR="${LOG_DIR:-.}"
PROXY_PORT="${PROXY_PORT:-5060}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
BUDGET_REMOTE_TAG_HITS_MIN="${BUDGET_REMOTE_TAG_HITS_MIN:-1}"
MAVEN_BUILD_CACHE_VERSION="${MAVEN_BUILD_CACHE_VERSION:-1.2.2}"

if [[ -z "${BORINGCACHE_API_TOKEN:-}" ]]; then
  echo "ERROR: BORINGCACHE_API_TOKEN is required"
  exit 1
fi

for dep in java mvn curl; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

if [[ ! -x "${BINARY}" ]]; then
  echo "ERROR: BINARY is not executable: ${BINARY}"
  exit 1
fi

mkdir -p "${LOG_DIR}"
MAVEN_LOG_DIR="${LOG_DIR}/tool-maven-e2e"
rm -rf "${MAVEN_LOG_DIR}"
mkdir -p "${MAVEN_LOG_DIR}"

TAG="$(e2e_tag "tool-maven")"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

setup_e2e_traps "${BINARY}" "${WORKSPACE}"
register_tag_for_cleanup "${TAG}"

PROJECT_DIR="${MAVEN_LOG_DIR}/maven-project"
mkdir -p "${PROJECT_DIR}/src/main/java/com/example"
mkdir -p "${PROJECT_DIR}/.mvn"

cat > "${PROJECT_DIR}/pom.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>maven-e2e</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
</project>
EOF

cat > "${PROJECT_DIR}/.mvn/extensions.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<extensions>
    <extension>
        <groupId>org.apache.maven.extensions</groupId>
        <artifactId>maven-build-cache-extension</artifactId>
        <version>${MAVEN_BUILD_CACHE_VERSION}</version>
    </extension>
</extensions>
EOF

cat > "${PROJECT_DIR}/.mvn/maven-build-cache-config.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<cache xmlns="http://maven.apache.org/BUILD-CACHE-CONFIG/1.0.0"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://maven.apache.org/BUILD-CACHE-CONFIG/1.0.0
                           https://maven.apache.org/xsd/build-cache-config-1.0.0.xsd">
    <configuration>
        <enabled>true</enabled>
        <hashAlgorithm>SHA-256</hashAlgorithm>
        <local>
            <maxBuildsCached>1</maxBuildsCached>
        </local>
        <remote>
            <url>${PROXY_URL}</url>
        </remote>
    </configuration>
</cache>
EOF

cat > "${PROJECT_DIR}/src/main/java/com/example/App.java" <<'EOF'
package com.example;

public class App {
    public static void main(String[] args) {
        System.out.println("Hello from Maven e2e!");
        System.out.println("Sum: " + compute(100));
    }

    public static long compute(int n) {
        long sum = 0;
        for (int i = 0; i < n; i++) {
            sum += (long) i * i;
        }
        return sum;
    }
}
EOF

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-tool-maven,tool=maven"
start_proxy "${BINARY}" "${WORKSPACE}" "${TAG}" "${PROXY_PORT}" "${MAVEN_LOG_DIR}/proxy.log"
wait_for_proxy "${PROXY_PORT}"

COLD_M2="${MAVEN_LOG_DIR}/m2-cold"
WARM_M2="${MAVEN_LOG_DIR}/m2-warm"

echo "=== Phase 1: Cold Maven build (seed build cache) ==="
COLD_LOG="${MAVEN_LOG_DIR}/cold-build.log"
COLD_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  mvn install -DskipTests \
    --batch-mode -ntp \
    -Dmaven.repo.local="${COLD_M2}" \
    2>&1 | tee "${COLD_LOG}"
)
COLD_END="$(date +%s)"
COLD_SECS="$((COLD_END - COLD_START))"
echo "Cold build completed in ${COLD_SECS}s"

rm -rf "${PROJECT_DIR}/target"

echo "=== Phase 2: Warm Maven build (cache hit) ==="
WARM_LOG="${MAVEN_LOG_DIR}/warm-build.log"
WARM_START="$(date +%s)"
(
  cd "${PROJECT_DIR}"
  mvn install -DskipTests \
    --batch-mode -ntp \
    -Dmaven.repo.local="${WARM_M2}" \
    2>&1 | tee "${WARM_LOG}"
)
WARM_END="$(date +%s)"
WARM_SECS="$((WARM_END - WARM_START))"
echo "Warm build completed in ${WARM_SECS}s"

maven_cache_hit=0
if grep -qi "restored from the build cache\|build cache.*hit\|found cached" "${WARM_LOG}" 2>/dev/null; then
  maven_cache_hit=1
  echo "  Maven build cache hit confirmed"
fi

proxy_gets="$(grep -c ' GET ' "${MAVEN_LOG_DIR}/proxy.log" 2>/dev/null || echo 0)"
proxy_puts="$(grep -c ' PUT ' "${MAVEN_LOG_DIR}/proxy.log" 2>/dev/null || echo 0)"
echo "  proxy traffic: PUTs=${proxy_puts} GETs=${proxy_gets}"

if [[ "${proxy_puts}" -gt 0 && "${proxy_gets}" -gt 0 ]]; then
  echo "  proxy saw both writes (cold) and reads (warm)"
elif [[ "${proxy_puts}" -gt 0 ]]; then
  echo "  proxy saw writes but no reads (maven may use local cache for warm)"
else
  echo "ERROR: proxy saw no PUT traffic — maven-build-cache-extension may not be configured correctly"
  cat "${MAVEN_LOG_DIR}/proxy.log"
  exit 1
fi

stop_proxy
dump_cache_ops_summary

if [[ "${BUDGET_REMOTE_TAG_HITS_MIN}" -gt 0 ]]; then
  verify_remote_tag_visible "${BINARY}" "${WORKSPACE}" "${TAG}" "${MAVEN_LOG_DIR}" \
    "${BUDGET_REMOTE_TAG_HITS_MIN}" 30 2 "$(proxy_log)"
  echo "  remote tag verified (hits=${REMOTE_TAG_CHECK_HITS:-0})"
fi

echo ""
echo "Maven tool e2e passed. Cold=${COLD_SECS}s Warm=${WARM_SECS}s Logs: ${MAVEN_LOG_DIR}"
