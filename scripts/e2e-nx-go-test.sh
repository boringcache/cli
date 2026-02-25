#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${WORKSPACE:-${BORINGCACHE_DEFAULT_WORKSPACE:-}}"
PORT="${PORT:-5057}"
HOST="${HOST:-127.0.0.1}"
TAG_PREFIX="${TAG_PREFIX:-bc-e2e-cli}"
REGISTRY_ROOT_TAG="${REGISTRY_ROOT_TAG:-${TAG_PREFIX}-all-$(date -u +%Y%m%d%H%M%S)}"
LOG_DIR="${LOG_DIR:-/tmp/boringcache-all-protocols-e2e-$(date +%Y%m%d-%H%M%S)}"
RUN_SCCACHE="${RUN_SCCACHE:-0}"
RUN_DOCKER="${RUN_DOCKER:-0}"
mkdir -p "${LOG_DIR}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}"
    exit 1
  fi
}

sha256_text() {
  local text="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "${text}" | sha256sum | awk '{print $1}'
  else
    printf '%s' "${text}" | shasum -a 256 | awk '{print $1}'
  fi
}

run_http() {
  local expected_status="$1"
  local output_path="$2"
  shift 2
  local status
  status=$(curl -sS -o "${output_path}" -w "%{http_code}" "$@")
  if [[ "${status}" != "${expected_status}" ]]; then
    echo "unexpected status: expected ${expected_status}, got ${status}"
    echo "curl args: $*"
    [[ -f "${output_path}" ]] && cat "${output_path}"
    exit 1
  fi
}

realpath_py() {
  python3 - "$1" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
}

require_cmd cargo
require_cmd curl
require_cmd go
require_cmd nx
require_cmd turbo
require_cmd python3
if [[ "${RUN_SCCACHE}" == "1" ]]; then
  require_cmd sccache
fi
if [[ "${RUN_DOCKER}" == "1" ]]; then
  require_cmd docker
fi

if [[ -z "${WORKSPACE}" ]]; then
  echo "missing WORKSPACE (set WORKSPACE or BORINGCACHE_DEFAULT_WORKSPACE)"
  exit 1
fi

if [[ -z "${BORINGCACHE_API_TOKEN:-}" ]]; then
  echo "missing BORINGCACHE_API_TOKEN"
  exit 1
fi

if [[ -z "${BORINGCACHE_API_URL:-}" ]]; then
  echo "missing BORINGCACHE_API_URL"
  exit 1
fi

echo "==> Tool versions"
(
  set -x
  cargo --version
  go version
  nx --version
  turbo --version
  if [[ "${RUN_SCCACHE}" == "1" ]]; then
    sccache --version
  fi
  if [[ "${RUN_DOCKER}" == "1" ]]; then
    docker --version
  fi
)

echo "==> Building boringcache CLI"
cargo build --bin boringcache >"${LOG_DIR}/build.log" 2>&1

echo "==> Starting cache-registry proxy"
SERVE_PID=""
PROXY_LOG="${LOG_DIR}/cache-registry.log"
cleanup() {
  set +e
  if [[ -n "${SERVE_PID}" ]]; then
    kill "${SERVE_PID}" >/dev/null 2>&1 || true
    wait "${SERVE_PID}" >/dev/null 2>&1 || true
    SERVE_PID=""
  fi
}
trap cleanup EXIT

./target/debug/boringcache cache-registry "${WORKSPACE}" "${REGISTRY_ROOT_TAG}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --no-platform \
  --no-git \
  --fail-on-cache-error >"${PROXY_LOG}" 2>&1 &
SERVE_PID=$!

READY=0
for _ in $(seq 1 80); do
  if curl -fsS --max-time 1 "http://${HOST}:${PORT}/v2/" >/dev/null 2>&1; then
    READY=1
    break
  fi
  if ! kill -0 "${SERVE_PID}" >/dev/null 2>&1; then
    echo "cache-registry exited before readiness"
    cat "${PROXY_LOG}"
    exit 1
  fi
  sleep 0.25
done

if [[ "${READY}" != "1" ]]; then
  echo "timed out waiting for cache-registry readiness"
  cat "${PROXY_LOG}"
  exit 1
fi

echo "==> Nx real project remote-cache checks"
NX_BIN_REAL="$(realpath_py "$(command -v nx)")"
NX_PACKAGE_DIR="$(cd "$(dirname "${NX_BIN_REAL}")/.." && pwd)"
NX_DIR="${LOG_DIR}/nx-project"
mkdir -p "${NX_DIR}/node_modules"
ln -s "${NX_PACKAGE_DIR}" "${NX_DIR}/node_modules/nx"
cat > "${NX_DIR}/package.json" <<'JSON'
{
  "name": "nx-remote-e2e",
  "private": true,
  "version": "1.0.0"
}
JSON
cat > "${NX_DIR}/nx.json" <<'JSON'
{
  "$schema": "./node_modules/nx/schemas/nx-schema.json",
  "namedInputs": {
    "default": ["{projectRoot}/**/*"]
  },
  "targetDefaults": {
    "build": {
      "cache": true
    }
  }
}
JSON
cat > "${NX_DIR}/project.json" <<'JSON'
{
  "name": "demo",
  "root": ".",
  "targets": {
    "build": {
      "executor": "nx:run-commands",
      "outputs": ["{projectRoot}/dist"],
      "options": {
        "command": "bash -lc 'count=0; [[ -f \"${MARKER_FILE}\" ]] && count=$(cat \"${MARKER_FILE}\"); count=$((count+1)); echo \"$count\" > \"${MARKER_FILE}\"; mkdir -p dist && echo nx-$count > dist/out.txt'"
      }
    }
  }
}
JSON
NX_MARKER="${LOG_DIR}/nx-marker.txt"
NX_AUTH_TOKEN="nx-local-token"
NX_CACHE_DIR_A="${NX_DIR}/.nx-cache-a"
NX_CACHE_DIR_B="${NX_DIR}/.nx-cache-b"
(
  cd "${NX_DIR}"
  MARKER_FILE="${NX_MARKER}" NX_DAEMON=false NX_CACHE_DIRECTORY="${NX_CACHE_DIR_A}" NX_SELF_HOSTED_REMOTE_CACHE_SERVER="http://${HOST}:${PORT}" NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN="${NX_AUTH_TOKEN}" \
    nx run demo:build --verbose >"${LOG_DIR}/nx-run1.log" 2>&1
)
if [[ "$(cat "${NX_MARKER}")" != "1" ]]; then
  echo "nx first run marker mismatch"
  cat "${LOG_DIR}/nx-run1.log"
  exit 1
fi
rm -rf "${NX_CACHE_DIR_A}" "${NX_CACHE_DIR_B}" "${NX_DIR}/dist"
(
  cd "${NX_DIR}"
  MARKER_FILE="${NX_MARKER}" NX_DAEMON=false NX_CACHE_DIRECTORY="${NX_CACHE_DIR_B}" NX_SELF_HOSTED_REMOTE_CACHE_SERVER="http://${HOST}:${PORT}" NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN="${NX_AUTH_TOKEN}" \
    nx run demo:build --verbose >"${LOG_DIR}/nx-run2.log" 2>&1
)
if [[ "$(cat "${NX_MARKER}")" != "1" ]]; then
  echo "nx second run executed command instead of cache hit"
  cat "${LOG_DIR}/nx-run2.log"
  exit 1
fi

echo "==> Turbo real project remote-cache checks"
TURBO_DIR="${LOG_DIR}/turbo-project"
mkdir -p "${TURBO_DIR}/apps/app1"
cat > "${TURBO_DIR}/package.json" <<'JSON'
{
  "name": "turbo-remote-e2e",
  "private": true,
  "version": "1.0.0",
  "packageManager": "npm@10.9.0",
  "workspaces": ["apps/*"]
}
JSON
cat > "${TURBO_DIR}/turbo.json" <<'JSON'
{
  "$schema": "https://turbo.build/schema.json",
  "globalEnv": ["TURBO_MARKER_FILE"],
  "tasks": {
    "build": {
      "outputs": ["dist/**"]
    }
  }
}
JSON
cat > "${TURBO_DIR}/apps/app1/package.json" <<'JSON'
{
  "name": "app1",
  "version": "1.0.0",
  "scripts": {
    "build": "bash ./build.sh"
  }
}
JSON
cat > "${TURBO_DIR}/apps/app1/build.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "${TURBO_MARKER_FILE}" ]]; then
  count=$(cat "${TURBO_MARKER_FILE}")
fi
count=$((count+1))
echo "${count}" > "${TURBO_MARKER_FILE}"
mkdir -p dist
echo "turbo-${count}" > dist/out.txt
SH
chmod +x "${TURBO_DIR}/apps/app1/build.sh"
TURBO_MARKER="${LOG_DIR}/turbo-marker.txt"
TURBO_API="http://${HOST}:${PORT}"
TURBO_TOKEN="turbo-local-token"
TURBO_TEAM="local-team"
TURBO_CACHE_DIR_A="${TURBO_DIR}/.turbo-cache-a"
TURBO_CACHE_DIR_B="${TURBO_DIR}/.turbo-cache-b"
(
  cd "${TURBO_DIR}"
  TURBO_MARKER_FILE="${TURBO_MARKER}" TURBO_API="${TURBO_API}" TURBO_TOKEN="${TURBO_TOKEN}" TURBO_TEAM="${TURBO_TEAM}" TURBO_DISABLE_ANALYTICS=1 \
    turbo run build --cache-dir="${TURBO_CACHE_DIR_A}" --output-logs=errors-only >"${LOG_DIR}/turbo-run1.log" 2>&1
)
if [[ "$(cat "${TURBO_MARKER}")" != "1" ]]; then
  echo "turbo first run marker mismatch"
  cat "${LOG_DIR}/turbo-run1.log"
  exit 1
fi
rm -rf "${TURBO_CACHE_DIR_A}" "${TURBO_CACHE_DIR_B}" "${TURBO_DIR}/apps/app1/dist"
(
  cd "${TURBO_DIR}"
  TURBO_MARKER_FILE="${TURBO_MARKER}" TURBO_API="${TURBO_API}" TURBO_TOKEN="${TURBO_TOKEN}" TURBO_TEAM="${TURBO_TEAM}" TURBO_DISABLE_ANALYTICS=1 \
    turbo run build --cache-dir="${TURBO_CACHE_DIR_B}" --output-logs=errors-only >"${LOG_DIR}/turbo-run2.log" 2>&1
)
if [[ "$(cat "${TURBO_MARKER}")" != "1" ]]; then
  echo "turbo second run executed command instead of cache hit"
  cat "${LOG_DIR}/turbo-run2.log"
  exit 1
fi

echo "==> Go GOCACHEPROG checks"
GO_DIR="${LOG_DIR}/go-prog"
mkdir -p "${GO_DIR}"
cat > "${GO_DIR}/go.mod" <<'EOF_GO'
module example.com/boringcache-local-go-prog

go 1.25
EOF_GO
cat > "${GO_DIR}/main.go" <<'EOF_GO'
package main

import "fmt"

func main() {
	fmt.Println("boringcache local gocacheprog e2e")
}
EOF_GO
GOCACHEPROG_CMD="$(pwd)/target/debug/boringcache go-cacheprog --endpoint http://${HOST}:${PORT} --verbose"
(
  cd "${GO_DIR}"
  GOCACHE="$(mktemp -d)" GOCACHEPROG="${GOCACHEPROG_CMD}" go build ./... 2> "${LOG_DIR}/go-build-1.log"
)
(
  cd "${GO_DIR}"
  GOCACHE="$(mktemp -d)" GOCACHEPROG="${GOCACHEPROG_CMD}" go build ./... 2> "${LOG_DIR}/go-build-2.log"
)
grep -q 'go-cacheprog put ok' "${LOG_DIR}/go-build-1.log"
grep -q 'go-cacheprog get hit' "${LOG_DIR}/go-build-2.log"

if [[ "${RUN_SCCACHE}" == "1" ]]; then
  echo "==> sccache real client checks"
  SCCACHE_TARGET_DIR="${LOG_DIR}/sccache-target"
  SCCACHE_PORT_A=4321
  SCCACHE_PORT_B=4322
  SCCACHE_DIR_A="${LOG_DIR}/sccache-a"
  SCCACHE_DIR_B="${LOG_DIR}/sccache-b"

  SCCACHE_SERVER_PORT="${SCCACHE_PORT_A}" sccache --stop-server >/dev/null 2>&1 || true
  SCCACHE_SERVER_PORT="${SCCACHE_PORT_B}" sccache --stop-server >/dev/null 2>&1 || true

  SCCACHE_SERVER_PORT="${SCCACHE_PORT_A}" SCCACHE_DIR="${SCCACHE_DIR_A}" SCCACHE_WEBDAV_ENDPOINT="http://${HOST}:${PORT}/" sccache --start-server >/dev/null
  SCCACHE_SERVER_PORT="${SCCACHE_PORT_A}" sccache --zero-stats >/dev/null
  (
    cd "$(pwd)"
    SCCACHE_SERVER_PORT="${SCCACHE_PORT_A}" SCCACHE_DIR="${SCCACHE_DIR_A}" SCCACHE_WEBDAV_ENDPOINT="http://${HOST}:${PORT}/" RUSTC_WRAPPER=sccache CARGO_TARGET_DIR="${SCCACHE_TARGET_DIR}" cargo build --release --locked >"${LOG_DIR}/sccache-build-1.log" 2>&1
  )
  SCCACHE_SERVER_PORT="${SCCACHE_PORT_A}" sccache --show-stats >"${LOG_DIR}/sccache-stats-1.txt" 2>&1
  SCCACHE_SERVER_PORT="${SCCACHE_PORT_A}" sccache --stop-server >/dev/null 2>&1 || true

  rm -rf "${SCCACHE_TARGET_DIR}"

  SCCACHE_SERVER_PORT="${SCCACHE_PORT_B}" SCCACHE_DIR="${SCCACHE_DIR_B}" SCCACHE_WEBDAV_ENDPOINT="http://${HOST}:${PORT}/" sccache --start-server >/dev/null
  SCCACHE_SERVER_PORT="${SCCACHE_PORT_B}" sccache --zero-stats >/dev/null
  (
    cd "$(pwd)"
    SCCACHE_SERVER_PORT="${SCCACHE_PORT_B}" SCCACHE_DIR="${SCCACHE_DIR_B}" SCCACHE_WEBDAV_ENDPOINT="http://${HOST}:${PORT}/" RUSTC_WRAPPER=sccache CARGO_TARGET_DIR="${SCCACHE_TARGET_DIR}" cargo build --release --locked >"${LOG_DIR}/sccache-build-2.log" 2>&1
  )
  SCCACHE_SERVER_PORT="${SCCACHE_PORT_B}" sccache --show-stats >"${LOG_DIR}/sccache-stats-2.txt" 2>&1
  SCCACHE_SERVER_PORT="${SCCACHE_PORT_B}" sccache --stop-server >/dev/null 2>&1 || true

  SCCACHE_HITS="$(
    awk '/^Cache hits/ {
      for (i = NF; i >= 1; i--) {
        if ($i ~ /^[0-9]+$/) {
          print $i
          exit
        }
      }
    }' "${LOG_DIR}/sccache-stats-2.txt"
  )"
  if [[ -z "${SCCACHE_HITS}" || "${SCCACHE_HITS}" == "0" ]]; then
    echo "sccache second run did not report cache hits"
    cat "${LOG_DIR}/sccache-stats-2.txt"
    exit 1
  fi
else
  echo "==> Skipping sccache checks (RUN_SCCACHE=${RUN_SCCACHE})" | tee "${LOG_DIR}/sccache-skip.txt"
fi

if [[ "${RUN_DOCKER}" == "1" ]]; then
  echo "==> Docker buildx check"
  if docker info >/dev/null 2>&1; then
    DOCKER_DIR="${LOG_DIR}/docker-proj"
    mkdir -p "${DOCKER_DIR}"
    cat > "${DOCKER_DIR}/Dockerfile" <<'DOCKER'
FROM alpine:3.20
WORKDIR /work
COPY payload.txt .
RUN sha256sum payload.txt > payload.sha
DOCKER
    printf 'docker-%s\n' "${REGISTRY_ROOT_TAG}" > "${DOCKER_DIR}/payload.txt"
    DOCKER_CACHE_REF="localhost:${PORT}/boringcache-e2e/cache:${REGISTRY_ROOT_TAG}-docker-buildkit"
    docker buildx build --progress=plain \
      --cache-from "type=registry,ref=${DOCKER_CACHE_REF}" \
      --cache-to "type=registry,ref=${DOCKER_CACHE_REF},mode=max" \
      --load \
      -t "boringcache-e2e:${REGISTRY_ROOT_TAG}" \
      "${DOCKER_DIR}" >"${LOG_DIR}/docker-build-1.log" 2>&1
    docker buildx build --progress=plain \
      --cache-from "type=registry,ref=${DOCKER_CACHE_REF}" \
      --cache-to "type=registry,ref=${DOCKER_CACHE_REF},mode=max" \
      --load \
      -t "boringcache-e2e:${REGISTRY_ROOT_TAG}" \
      "${DOCKER_DIR}" >"${LOG_DIR}/docker-build-2.log" 2>&1
    if ! grep -E 'CACHED|importing cache manifest' "${LOG_DIR}/docker-build-2.log" >/dev/null 2>&1; then
      echo "docker second build did not show cache reuse"
      tail -n 80 "${LOG_DIR}/docker-build-2.log"
      exit 1
    fi
  else
    echo "docker daemon unavailable; skipping docker check" | tee "${LOG_DIR}/docker-skip.txt"
  fi
else
  echo "==> Skipping docker checks (RUN_DOCKER=${RUN_DOCKER})" | tee "${LOG_DIR}/docker-skip.txt"
fi

echo "==> Stopping cache-registry proxy and flushing pending entries"
if [[ -n "${SERVE_PID}" ]]; then
  kill "${SERVE_PID}" >/dev/null 2>&1 || true
  wait "${SERVE_PID}" >/dev/null 2>&1 || true
  SERVE_PID=""
fi

echo "==> Verifying human alias tag is visible in workspace entries"
./target/debug/boringcache ls "${WORKSPACE}" --limit 500 --json > "${LOG_DIR}/workspace-ls.json"
python3 - "${LOG_DIR}/workspace-ls.json" "${REGISTRY_ROOT_TAG}" <<'PY'
import json
import sys

ls_path = sys.argv[1]
expected_tag = sys.argv[2]

with open(ls_path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)

entries = payload.get("entries") or []
tags = [entry.get("tag") for entry in entries if isinstance(entry, dict)]

if expected_tag not in tags:
    print(f"human alias tag not found in ls output: {expected_tag}", file=sys.stderr)
    sys.exit(1)
PY

echo "All real-client protocol e2e checks passed"
echo "Logs: ${LOG_DIR}"
