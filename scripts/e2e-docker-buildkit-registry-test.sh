#!/usr/bin/env bash
set -euo pipefail

BINARY="${BINARY:-./target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
E2E_TAG_PREFIX="${E2E_TAG_PREFIX:-bc-e2e-cli}"
PORT="${PORT:-5000}"
LOG_DIR="${LOG_DIR:-.}"

mkdir -p "${LOG_DIR}"

RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
BUILDER="bc-e2e-${RUN_ID}-${RUN_ATTEMPT}"
CACHE_TAG="${E2E_TAG_PREFIX}-docker-buildkit-${RUN_ID}-${RUN_ATTEMPT}"
CACHE_REF="localhost:${PORT}/boringcache-e2e/cache:${CACHE_TAG}"
CACHE_TAG_ALIAS="${CACHE_TAG}-alias"
CACHE_REF_ALIAS="localhost:${PORT}/boringcache-e2e/cache:${CACHE_TAG_ALIAS}"
REGISTRY_ROOT_TAG="${E2E_TAG_PREFIX}-docker-buildkit-registry-${RUN_ID}-${RUN_ATTEMPT}"
SERVE_PID=""
declare -a LOG_FILES=()

cleanup() {
  set +e
  if [[ -n "${SERVE_PID:-}" ]]; then
    kill "${SERVE_PID}" >/dev/null 2>&1 || true
    wait "${SERVE_PID}" >/dev/null 2>&1 || true
  fi
  docker buildx rm --force "${BUILDER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_proxy() {
  local log_file="$1"
  LOG_FILES+=("${log_file}")
  "${BINARY}" docker-registry "${WORKSPACE}" "${REGISTRY_ROOT_TAG}" \
    --host 127.0.0.1 \
    --port "${PORT}" \
    --no-platform \
    --no-git \
    --fail-on-cache-error > "${log_file}" 2>&1 &
  SERVE_PID=$!

  local ready=0
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/v2/" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "${SERVE_PID}" >/dev/null 2>&1; then
      echo "docker-registry exited before readiness"
      cat "${log_file}"
      exit 1
    fi
    sleep 0.5
  done

  if [[ "${ready}" != "1" ]]; then
    echo "timed out waiting for docker-registry readiness"
    cat "${log_file}"
    exit 1
  fi
}

stop_proxy() {
  if [[ -n "${SERVE_PID:-}" ]]; then
    kill "${SERVE_PID}" >/dev/null 2>&1 || true
    wait "${SERVE_PID}" >/dev/null 2>&1 || true
  fi
  SERVE_PID=""
}

run_build() {
  local log_file="$1"
  shift
  LOG_FILES+=("${log_file}")
  docker buildx build \
    --builder "${BUILDER}" \
    --progress plain \
    --load \
    --file e2e-context/Dockerfile \
    "$@" \
    e2e-context 2>&1 | tee "${log_file}"
}

is_transient_registry_export_error() {
  local log_file="$1"
  grep -Eq \
    'expected sha256:.*got sha256:e3b0|error writing layer blob|error writing manifest blob|unexpected status from PUT request.*(400 Bad Request|500 Internal Server Error)|Alias write failed .*confirm failed: Server error \(500\)' \
    "${log_file}"
}

run_build_with_retry() {
  local log_file="$1"
  shift
  local attempts=4
  local attempt
  for attempt in $(seq 1 "${attempts}"); do
    if run_build "${log_file}" "$@"; then
      return 0
    fi
    if [[ "${attempt}" -lt "${attempts}" ]] && is_transient_registry_export_error "${log_file}"; then
      echo "transient registry export error on attempt ${attempt}/${attempts}; retrying..."
      sleep $((attempt * 3))
      continue
    fi
    return 1
  done
}

create_builder() {
  docker buildx create \
    --name "${BUILDER}" \
    --driver docker-container \
    --driver-opt network=host \
    --use
  docker buildx inspect "${BUILDER}" --bootstrap
}

reset_builder() {
  docker buildx rm --force "${BUILDER}" >/dev/null 2>&1 || true
  create_builder
}

assert_cached() {
  local log_file="$1"
  if ! grep -q "CACHED" "${log_file}"; then
    echo "expected cached steps in ${log_file}"
    exit 1
  fi
}

assert_registry_import_succeeded() {
  local log_file="$1"
  if ! grep -q "importing cache manifest from" "${log_file}"; then
    echo "expected registry cache import attempt in ${log_file}"
    exit 1
  fi
  if grep -E -n "failed to configure registry cache importer|httpReadSeeker: failed open: .* not found" "${log_file}" >/tmp/e2e-import-failure.log 2>/dev/null; then
    echo "registry cache import failed in ${log_file}"
    cat /tmp/e2e-import-failure.log
    exit 1
  fi
}

fetch_manifest_with_retry() {
  local reference="$1"
  local manifest_file="$2"
  local attempts="${3:-20}"
  local url="http://127.0.0.1:${PORT}/v2/boringcache-e2e/cache/manifests/${reference}"
  local accept_header="Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS -H "${accept_header}" "${url}" -o "${manifest_file}"; then
      return 0
    fi
    sleep 1
  done

  echo "manifest did not become readable for reference ${reference} after ${attempts}s"
  return 1
}

resolve_manifest_digest_with_retry() {
  local reference="$1"
  local attempts="${2:-20}"
  local url="http://127.0.0.1:${PORT}/v2/boringcache-e2e/cache/manifests/${reference}"
  local accept_header="Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

  for _ in $(seq 1 "${attempts}"); do
    local digest
    digest=$(
      curl -fsS -I -H "${accept_header}" "${url}" 2>/dev/null \
        | awk 'tolower($1)=="docker-content-digest:" {print $2}' \
        | tr -d '\r' \
        | tail -n1
    ) || true
    if [[ -n "${digest}" ]]; then
      echo "${digest}"
      return 0
    fi
    sleep 1
  done

  echo "manifest digest header did not become readable for reference ${reference} after ${attempts}s" >&2
  return 1
}

cd "${LOG_DIR}"
reset_builder

mkdir -p e2e-context
cat > e2e-context/Dockerfile <<'EOF'
FROM scratch
COPY payload.bin /payload.bin
COPY f01.txt /f01.txt
COPY f02.txt /f02.txt
COPY f03.txt /f03.txt
COPY f04.txt /f04.txt
COPY f05.txt /f05.txt
COPY f06.txt /f06.txt
COPY f07.txt /f07.txt
COPY f08.txt /f08.txt
COPY f09.txt /f09.txt
COPY f10.txt /f10.txt
COPY f11.txt /f11.txt
COPY f12.txt /f12.txt
EOF
for i in $(seq -w 1 12); do
  printf 'layer-%s\n' "${i}" > "e2e-context/f${i}.txt"
done
dd if=/dev/zero of=e2e-context/payload.bin bs=1M count=6 status=none

start_proxy "serve-initial.log"
run_build_with_retry "first-build.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
reset_builder
run_build_with_retry "second-build.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
assert_cached "second-build.log"
assert_registry_import_succeeded "second-build.log"
run_build_with_retry "third-build-reexport.log" \
  --no-cache \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
stop_proxy

start_proxy "serve-restart.log"
reset_builder
run_build_with_retry "fourth-build-after-restart.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF},mode=max"
assert_cached "fourth-build-after-restart.log"
assert_registry_import_succeeded "fourth-build-after-restart.log"
run_build_with_retry "fifth-build-alias-export.log" \
  --cache-from "type=registry,ref=${CACHE_REF}" \
  --cache-to "type=registry,ref=${CACHE_REF_ALIAS},mode=max"
assert_registry_import_succeeded "fifth-build-alias-export.log"
run_build_with_retry "sixth-build-alias-warm.log" \
  --cache-from "type=registry,ref=${CACHE_REF_ALIAS}" \
  --cache-to "type=registry,ref=${CACHE_REF_ALIAS},mode=max"
assert_cached "sixth-build-alias-warm.log"
assert_registry_import_succeeded "sixth-build-alias-warm.log"

for tag in "${CACHE_TAG}" "${CACHE_TAG_ALIAS}"; do
  manifest_file="manifest-${tag}.json"
  LOG_FILES+=("${manifest_file}")
  fetch_manifest_with_retry "${tag}" "${manifest_file}"
  manifest_digest="$(resolve_manifest_digest_with_retry "${tag}")"
  digest_manifest_file="manifest-${tag}-digest.json"
  LOG_FILES+=("${digest_manifest_file}")
  fetch_manifest_with_retry "${manifest_digest}" "${digest_manifest_file}"
done

declare -a BAD_PATTERNS=(
  'expected sha256:.*got sha256:e3b0'
  'error writing layer blob'
  'broken pipe'
  'Validation failed on cache confirm'
  '422 Unprocessable Entity'
  'unexpected status from PUT request.*400 Bad Request'
)
for pattern in "${BAD_PATTERNS[@]}"; do
  if grep -E -n "${pattern}" "${LOG_FILES[@]}" >/tmp/e2e-pattern-hit.log 2>/dev/null; then
    echo "found bad signature pattern: ${pattern}"
    cat /tmp/e2e-pattern-hit.log
    exit 1
  fi
done
