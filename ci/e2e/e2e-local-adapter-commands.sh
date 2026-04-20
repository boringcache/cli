#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CLI_DIR}/.." && pwd)"
WEB_DIR="${WEB_DIR:-${REPO_ROOT}/web}"
BINARY="${BINARY:-${CLI_DIR}/target/debug/boringcache}"
RAILS_HOST="${RAILS_HOST:-127.0.0.1}"
RAILS_PORT="${RAILS_PORT:-3000}"
API_URL="${BORINGCACHE_API_URL:-http://${RAILS_HOST}:${RAILS_PORT}}"
LOG_ROOT="${LOG_ROOT:-${TMPDIR:-/tmp}/boringcache-local-adapter-e2e}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
LOG_DIR="${LOG_DIR:-${LOG_ROOT}/${RUN_ID}}"
RAILS_PIDFILE="${RAILS_PIDFILE:-${LOG_DIR}/rails-server.pid}"
TMP_DIR="${LOG_DIR}/tmp"
SUMMARY_FILE="${LOG_DIR}/summary.txt"
LOCAL_ADAPTER_TOOLS="${LOCAL_ADAPTER_TOOLS:-gradle,maven,turbo,nx,go,bazel,sccache}"
JAVA_TOOL_VERSION="${JAVA_TOOL_VERSION:-java@21.0.2}"
MAVEN_TOOL_VERSION="${MAVEN_TOOL_VERSION:-maven@3.9.14}"

mkdir -p "${LOG_DIR}" "${TMP_DIR}"

RAILS_PID=""
WORKSPACE=""
TOKEN=""
declare -a PASSED_TOOLS=()
declare -a SKIPPED_TOOLS=()

note() {
  printf '==> %s\n' "$1"
}

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

require_cmd() {
  local cmd="$1"
  command -v "${cmd}" >/dev/null 2>&1 || fail "missing required command: ${cmd}"
}

append_summary() {
  printf '%s\n' "$1" | tee -a "${SUMMARY_FILE}"
}

skip_tool() {
  local tool="$1"
  local reason="$2"
  SKIPPED_TOOLS+=("${tool}: ${reason}")
  append_summary "SKIP ${tool}: ${reason}"
}

pass_tool() {
  local tool="$1"
  local detail="$2"
  PASSED_TOOLS+=("${tool}")
  append_summary "PASS ${tool}: ${detail}"
}

should_run_tool() {
  local tool="$1"
  case ",${LOCAL_ADAPTER_TOOLS}," in
    *",${tool},"*) return 0 ;;
    *) return 1 ;;
  esac
}

run_selected_tool() {
  local tool="$1"
  shift
  if should_run_tool "${tool}"; then
    "$@"
  else
    skip_tool "${tool}" "not selected by LOCAL_ADAPTER_TOOLS=${LOCAL_ADAPTER_TOOLS}"
  fi
}

cleanup() {
  set +e
  if [[ -n "${RAILS_PID}" ]]; then
    kill "${RAILS_PID}" >/dev/null 2>&1 || true
    wait "${RAILS_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${RAILS_PIDFILE}" >/dev/null 2>&1 || true
}

dump_logs_on_error() {
  local status="$1"
  if [[ "${status}" -eq 0 ]]; then
    return 0
  fi
  set +e
  echo "=== Local adapter E2E logs ==="
  if [[ -d "${LOG_DIR}" ]]; then
    while IFS= read -r log_file; do
      echo "--- ${log_file} ---"
      tail -n 120 "${log_file}" || true
    done < <(find "${LOG_DIR}" -name '*.log' -type f 2>/dev/null | sort)
  fi
  echo "=== End local adapter E2E logs ==="
}

on_exit() {
  local status="$?"
  trap - EXIT
  dump_logs_on_error "${status}" || true
  cleanup || true
  exit "${status}"
}
trap on_exit EXIT

metric_summary() {
  local metrics_file="$1"
  local summary_file="${metrics_file}.summary"
  python3 "${SCRIPT_DIR}/request-metrics-summary.py" "${metrics_file}" > "${summary_file}"
  printf '%s\n' "${summary_file}"
}

assert_metric_gt_zero() {
  local summary_file="$1"
  local key="$2"
  # shellcheck source=/dev/null
  source "${summary_file}"
  local value="${!key:-0}"
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || [[ "${value}" -eq 0 ]]; then
    fail "expected ${key} > 0 in ${summary_file}"
  fi
}

wait_for_local_server() {
  local attempts=60
  local status=""
  for _ in $(seq 1 "${attempts}"); do
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${API_URL}/login" || true)"
    if [[ "${status}" == "200" || "${status}" == "302" ]]; then
      return 0
    fi
    if [[ -n "${RAILS_PID}" ]] && ! kill -0 "${RAILS_PID}" >/dev/null 2>&1; then
      tail -n 120 "${LOG_DIR}/rails-server.log" || true
      fail "Rails server exited before readiness"
    fi
    sleep 1
  done
  tail -n 120 "${LOG_DIR}/rails-server.log" || true
  fail "timed out waiting for Rails server at ${API_URL}"
}

wait_for_tag_visibility() {
  local tag="$1"
  local log_file="${LOG_DIR}/check-${tag}.log"
  for _ in $(seq 1 20); do
    if "${BINARY}" check --no-platform --no-git --fail-on-miss "${WORKSPACE}" "${tag}" \
      > "${log_file}" 2>&1; then
      return 0
    fi
    sleep 1
  done
  cat "${log_file}" || true
  fail "tag did not become visible: ${tag}"
}

delete_tag() {
  local tag="$1"
  "${BINARY}" delete --no-platform --no-git "${WORKSPACE}" "${tag}" >/dev/null 2>&1 || true
}

assert_workspace_storage_ready() {
  note "Checking workspace storage provisioning"
  local storage_output storage_type storage_provisioned storage_missing tigris_credentials
  storage_output="$(
    cd "${WEB_DIR}"
    E2E_WORKSPACE="${WORKSPACE}" \
    mise exec -- bin/rails runner '
      namespace_slug, workspace_slug = ENV.fetch("E2E_WORKSPACE").split("/", 2)
      workspace = Workspace.joins(:namespace).find_by!(namespaces: { slug: namespace_slug }, slug: workspace_slug)

      if workspace.storage_type_managed? && !workspace.storage_provisioned?
        begin
          workspace.provision_tigris_storage!
          workspace.reload
        rescue => e
          warn "STORAGE_PROVISION_ERROR=#{e.class}: #{e.message}"
          workspace.reload
        end
      end

      missing_fields = if workspace.storage_type_byoc?
        %w[byoc_endpoint byoc_bucket_name byoc_access_key byoc_secret_key byoc_region].reject do |field|
          workspace.public_send(field).present?
        end
      else
        %w[tigris_org_id bucket_name tigris_access_key tigris_secret_key tigris_endpoint].reject do |field|
          workspace.public_send(field).present?
        end
      end

      tigris_credentials = Rails.application.credentials.tigris
      credentials_state =
        if tigris_credentials&.partner_key.present? && tigris_credentials&.signing_key.present?
          "present"
        else
          "missing"
        end

      puts "STORAGE_TYPE=#{workspace.storage_type}"
      puts "STORAGE_PROVISIONED=#{workspace.storage_provisioned?}"
      puts "STORAGE_MISSING=#{missing_fields.join(",")}"
      puts "TIGRIS_CREDENTIALS=#{credentials_state}"
    ' 2>> "${LOG_DIR}/rails-storage-preflight.log"
  )"

  storage_type="$(printf '%s\n' "${storage_output}" | sed -n 's/^STORAGE_TYPE=//p' | tail -n 1)"
  storage_provisioned="$(printf '%s\n' "${storage_output}" | sed -n 's/^STORAGE_PROVISIONED=//p' | tail -n 1)"
  storage_missing="$(printf '%s\n' "${storage_output}" | sed -n 's/^STORAGE_MISSING=//p' | tail -n 1)"
  tigris_credentials="$(printf '%s\n' "${storage_output}" | sed -n 's/^TIGRIS_CREDENTIALS=//p' | tail -n 1)"

  append_summary "Workspace storage type: ${storage_type:-unknown}"
  append_summary "Workspace storage provisioned: ${storage_provisioned:-unknown}"

  if [[ "${storage_provisioned}" == "true" ]]; then
    return 0
  fi

  fail "workspace storage is not provisioned for ${WORKSPACE} (type=${storage_type:-unknown}, missing=${storage_missing:-unknown}, tigris_credentials=${tigris_credentials:-unknown}). Configure local managed storage credentials or point the workspace at BYOC storage before running this script."
}

start_local_rails() {
  note "Preparing local Rails database"
  (
    cd "${WEB_DIR}"
    mise exec -- bin/rails db:prepare > "${LOG_DIR}/rails-db-prepare.log" 2>&1
  )

  note "Provisioning local workspace token"
  local bootstrap_output
  bootstrap_output="$(
    cd "${WEB_DIR}"
    E2E_EMAIL="cli-local-adapter-e2e@example.com" \
    E2E_NAMESPACE_SLUG="cli-local-adapter-e2e" \
    E2E_WORKSPACE_SLUG="adapter-e2e" \
    mise exec -- bin/rails runner '
      user = User.find_or_initialize_by(email: ENV.fetch("E2E_EMAIL"))
      user.namespace ||= Namespace.new(user: user)
      if user.new_record?
        user.name = "CLI Local Adapter E2E"
        user.namespace_slug = ENV.fetch("E2E_NAMESPACE_SLUG")
        user.allow_reserved_slug = true
        user.email_confirmed = true
        user.email_confirmed_at = Time.current
      else
        user.name = user.name.presence || "CLI Local Adapter E2E"
        user.allow_reserved_slug = true
        user.email_confirmed = true
        user.email_confirmed_at ||= Time.current
      end
      user.namespace.name = user.name
      user.namespace.slug = ENV.fetch("E2E_NAMESPACE_SLUG")
      user.namespace.allow_reserved_slug = true
      user.save!

      workspace = Workspace.find_or_initialize_by(
        namespace: user.namespace,
        slug: ENV.fetch("E2E_WORKSPACE_SLUG")
      )
      if workspace.new_record?
        workspace.name = "Adapter E2E"
        workspace.allow_reserved_slug = true
        workspace.save!
      end

      raw_token, = ApiToken.issue!(
        name: "Local Adapter E2E #{Time.current.to_i}",
        user: user,
        workspace: workspace,
        access_level: "admin"
      )

      puts "WORKSPACE=#{workspace.full_path}"
      puts "TOKEN=#{raw_token}"
    ' 2>> "${LOG_DIR}/rails-bootstrap.log"
  )"

  WORKSPACE="$(printf '%s\n' "${bootstrap_output}" | sed -n 's/^WORKSPACE=//p' | tail -n 1)"
  TOKEN="$(printf '%s\n' "${bootstrap_output}" | sed -n 's/^TOKEN=//p' | tail -n 1)"
  [[ -n "${WORKSPACE}" ]] || fail "failed to determine local workspace"
  [[ -n "${TOKEN}" ]] || fail "failed to mint local API token"

  export WORKSPACE
  export BORINGCACHE_API_URL="${API_URL}"
  export BORINGCACHE_ADMIN_TOKEN="${TOKEN}"
  export BORINGCACHE_SAVE_TOKEN="${TOKEN}"
  export BORINGCACHE_RESTORE_TOKEN="${TOKEN}"

  assert_workspace_storage_ready

  note "Starting local Rails server on ${API_URL}"
  (
    cd "${WEB_DIR}"
    PORT="${RAILS_PORT}" mise exec -- bin/rails server -b "${RAILS_HOST}" -p "${RAILS_PORT}" \
      --pid "${RAILS_PIDFILE}" \
      > "${LOG_DIR}/rails-server.log" 2>&1
  ) &
  RAILS_PID=$!
  wait_for_local_server
  append_summary "Workspace: ${WORKSPACE}"
  append_summary "API URL: ${API_URL}"
  append_summary "Selected tools: ${LOCAL_ADAPTER_TOOLS}"
}

build_cli_binary() {
  note "Building boringcache CLI"
  (
    cd "${CLI_DIR}"
    cargo build --bin boringcache > "${LOG_DIR}/cargo-build.log" 2>&1
  )
  [[ -x "${BINARY}" ]] || fail "expected executable binary at ${BINARY}"
}

realpath_py() {
  python3 - "$1" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
}

run_turbo_e2e() {
  command -v turbo >/dev/null 2>&1 || {
    skip_tool "turbo" "turbo not installed"
    return 0
  }

  local tool_dir="${TMP_DIR}/turbo"
  local metrics_file="${tool_dir}/metrics.jsonl"
  local cold_log="${tool_dir}/cold.log"
  local warm_log="${tool_dir}/warm.log"
  local marker_file="${tool_dir}/marker.txt"
  local cache_a="${tool_dir}/cache-a"
  local cache_b="${tool_dir}/cache-b"
  local tag="local-adapter-turbo-${RUN_ID}"
  mkdir -p "${tool_dir}/apps/app1"

  cat > "${tool_dir}/package.json" <<'EOF'
{
  "name": "turbo-remote-e2e",
  "private": true,
  "version": "1.0.0",
  "packageManager": "npm@10.9.0",
  "workspaces": ["apps/*"]
}
EOF

  cat > "${tool_dir}/turbo.json" <<'EOF'
{
  "$schema": "https://turbo.build/schema.json",
  "globalEnv": ["TURBO_MARKER_FILE"],
  "tasks": {
    "build": {
      "outputs": ["dist/**"]
    }
  }
}
EOF

  cat > "${tool_dir}/apps/app1/package.json" <<'EOF'
{
  "name": "app1",
  "version": "1.0.0",
  "scripts": {
    "build": "bash ./build.sh"
  }
}
EOF

  cat > "${tool_dir}/apps/app1/build.sh" <<'EOF'
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
EOF
  chmod +x "${tool_dir}/apps/app1/build.sh"

  note "Turbo adapter E2E"
  (
    cd "${tool_dir}"
    TURBO_MARKER_FILE="${marker_file}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" turbo \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5311 \
        --no-platform \
        --no-git \
        -- turbo run build --cache-dir="${cache_a}" --output-logs=errors-only \
      > "${cold_log}" 2>&1
  )
  [[ "$(cat "${marker_file}")" == "1" ]] || fail "turbo cold run did not execute exactly once"
  wait_for_tag_visibility "${tag}"

  rm -rf "${cache_a}" "${cache_b}" "${tool_dir}/apps/app1/dist"
  (
    cd "${tool_dir}"
    TURBO_MARKER_FILE="${marker_file}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" turbo \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5311 \
        --no-platform \
        --no-git \
        -- turbo run build --cache-dir="${cache_b}" --output-logs=errors-only \
      > "${warm_log}" 2>&1
  )
  [[ "$(cat "${marker_file}")" == "1" ]] || fail "turbo warm run re-executed instead of using remote cache"

  local summary
  summary="$(metric_summary "${metrics_file}")"
  assert_metric_gt_zero "${summary}" "request_metrics_cache_ops_turborepo_get_hits"
  delete_tag "${tag}"
  pass_tool "turbo" "warm run reused remote cache"
}

run_nx_e2e() {
  command -v nx >/dev/null 2>&1 || {
    skip_tool "nx" "nx not installed"
    return 0
  }

  local tool_dir="${TMP_DIR}/nx"
  local metrics_file="${tool_dir}/metrics.jsonl"
  local cold_log="${tool_dir}/cold.log"
  local warm_log="${tool_dir}/warm.log"
  local marker_file="${TMP_DIR}/nx-marker.txt"
  local cache_dir="${TMP_DIR}/nx-cache"
  local tag="local-adapter-nx-${RUN_ID}"
  local nx_bin_real nx_package_dir
  mkdir -p "${tool_dir}/node_modules"
  rm -rf "${marker_file}" "${cache_dir}"

  nx_bin_real="$(realpath_py "$(command -v nx)")"
  nx_package_dir="$(cd "$(dirname "${nx_bin_real}")/.." && pwd)"
  ln -sf "${nx_package_dir}" "${tool_dir}/node_modules/nx"

  cat > "${tool_dir}/package.json" <<'EOF'
{
  "name": "nx-remote-e2e",
  "private": true,
  "version": "1.0.0"
}
EOF

  cat > "${tool_dir}/nx.json" <<'EOF'
{
  "$schema": "./node_modules/nx/schemas/nx-schema.json",
  "namedInputs": {
    "default": [
      "{workspaceRoot}/nx.json",
      "{projectRoot}/package.json",
      "{projectRoot}/project.json",
      "{projectRoot}/build.sh"
    ]
  },
  "targetDefaults": {
    "build": {
      "cache": true,
      "inputs": ["default"]
    }
  }
}
EOF

  cat > "${tool_dir}/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "${MARKER_FILE}" ]]; then
  count=$(cat "${MARKER_FILE}")
fi
count=$((count + 1))
echo "${count}" > "${MARKER_FILE}"
mkdir -p dist
echo "nx-${count}" > dist/out.txt
EOF
  chmod +x "${tool_dir}/build.sh"

  cat > "${tool_dir}/project.json" <<'EOF'
{
  "name": "demo",
  "root": ".",
  "targets": {
    "build": {
      "executor": "nx:run-commands",
      "outputs": ["{projectRoot}/dist"],
      "options": {
        "command": "bash ./build.sh"
      }
    }
  }
}
EOF

  note "Nx adapter E2E"
  (
    cd "${tool_dir}"
    MARKER_FILE="${marker_file}" \
    NX_DAEMON=false \
    NX_CACHE_DIRECTORY="${cache_dir}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" nx \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5312 \
        --no-platform \
        --no-git \
        -- nx run demo:build --verbose \
      > "${cold_log}" 2>&1
  )
  [[ "$(cat "${marker_file}")" == "1" ]] || fail "nx cold run did not execute exactly once"
  wait_for_tag_visibility "${tag}"

  # Nx keeps a local DB cache outside the remote adapter path; clear it before the warm run.
  (
    cd "${tool_dir}"
    NX_DAEMON=false \
    NX_CACHE_DIRECTORY="${cache_dir}" \
      nx reset --onlyCache > "${tool_dir}/reset.log" 2>&1
  )
  rm -rf "${cache_dir}" "${tool_dir}/.nx" "${tool_dir}/dist"
  (
    cd "${tool_dir}"
    MARKER_FILE="${marker_file}" \
    NX_DAEMON=false \
    NX_CACHE_DIRECTORY="${cache_dir}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" nx \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5312 \
        --no-platform \
        --no-git \
        -- nx run demo:build --verbose \
      > "${warm_log}" 2>&1
  )
  [[ "$(cat "${marker_file}")" == "1" ]] || fail "nx warm run re-executed instead of using remote cache"
  if ! grep -Eq '\[remote cache\]|remote cache' "${warm_log}"; then
    fail "nx warm run did not report remote cache reuse"
  fi

  delete_tag "${tag}"
  pass_tool "nx" "warm run reused cached output after nx reset"
}

run_go_e2e() {
  command -v go >/dev/null 2>&1 || {
    skip_tool "go" "go not installed"
    return 0
  }

  local tool_dir="${TMP_DIR}/go"
  local metrics_file="${tool_dir}/metrics.jsonl"
  local cold_log="${tool_dir}/cold.log"
  local warm_log="${tool_dir}/warm.log"
  local tag="local-adapter-go-${RUN_ID}"
  local gocache_a gocache_b
  mkdir -p "${tool_dir}"

  cat > "${tool_dir}/go.mod" <<'EOF'
module example.com/boringcache-local-go-prog

go 1.25
EOF

  cat > "${tool_dir}/main.go" <<'EOF'
package main

import "fmt"

func main() {
	fmt.Println("boringcache local gocacheprog e2e")
}
EOF

  gocache_a="$(mktemp -d "${tool_dir}/gocache-a.XXXXXX")"
  gocache_b="$(mktemp -d "${tool_dir}/gocache-b.XXXXXX")"

  note "Go adapter E2E"
  (
    cd "${tool_dir}"
    GOCACHE="${gocache_a}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" go \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5313 \
        --no-platform \
        --no-git \
        -- go build ./... \
      > "${cold_log}" 2>&1
  )
  wait_for_tag_visibility "${tag}"

  (
    cd "${tool_dir}"
    GOCACHE="${gocache_b}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" go \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5313 \
        --no-platform \
        --no-git \
        -- go build ./... \
      > "${warm_log}" 2>&1
  )

  local summary
  summary="$(metric_summary "${metrics_file}")"
  assert_metric_gt_zero "${summary}" "request_metrics_cache_ops_gocache_get_hits"
  delete_tag "${tag}"
  pass_tool "go" "warm run recorded remote gocache hits"
}

run_gradle_e2e() {
  if ! mise exec "${JAVA_TOOL_VERSION}" -- java -version >/dev/null 2>&1; then
    skip_tool "gradle" "Java runtime ${JAVA_TOOL_VERSION} not available via mise"
    return 0
  fi

  local tool_log_root="${LOG_DIR}/gradle-runtime"
  mkdir -p "${tool_log_root}"

  note "Gradle adapter runtime E2E"
  LOG_DIR="${tool_log_root}" \
  PROXY_PORT="${GRADLE_PROXY_PORT:-5316}" \
  BINARY="${BINARY}" \
    mise exec "${JAVA_TOOL_VERSION}" -- \
      bash "${SCRIPT_DIR}/required/e2e-tool-gradle-test.sh"

  pass_tool "gradle" "required runtime e2e passed"
}

run_maven_e2e() {
  if ! mise exec "${JAVA_TOOL_VERSION}" "${MAVEN_TOOL_VERSION}" -- mvn -version >/dev/null 2>&1; then
    skip_tool "maven" "Java ${JAVA_TOOL_VERSION} or Maven ${MAVEN_TOOL_VERSION} not available via mise"
    return 0
  fi

  local tool_log_root="${LOG_DIR}/maven-runtime"
  mkdir -p "${tool_log_root}"

  note "Maven adapter runtime E2E"
  LOG_DIR="${tool_log_root}" \
  PROXY_PORT="${MAVEN_PROXY_PORT:-5317}" \
  BINARY="${BINARY}" \
    mise exec "${JAVA_TOOL_VERSION}" "${MAVEN_TOOL_VERSION}" -- \
      bash "${SCRIPT_DIR}/required/e2e-tool-maven-test.sh"

  pass_tool "maven" "required runtime e2e passed"
}

run_bazel_e2e() {
  local bazel_cmd=""
  if command -v bazelisk >/dev/null 2>&1; then
    bazel_cmd="bazelisk"
  elif command -v bazel >/dev/null 2>&1; then
    bazel_cmd="bazel"
  else
    skip_tool "bazel" "bazel not installed"
    return 0
  fi

  local tool_dir="${TMP_DIR}/bazel"
  local metrics_file="${tool_dir}/metrics.jsonl"
  local cold_log="${tool_dir}/cold.log"
  local warm_log="${tool_dir}/warm.log"
  local output_base_a="${tool_dir}/output-base-a"
  local output_base_b="${tool_dir}/output-base-b"
  local tag="local-adapter-bazel-${RUN_ID}"
  mkdir -p "${tool_dir}"

  cat > "${tool_dir}/MODULE.bazel" <<'EOF'
module(name = "e2e_test", version = "0.1.0")
EOF

  cat > "${tool_dir}/BUILD.bazel" <<'EOF'
genrule(
    name = "emit",
    srcs = ["input.txt"],
    outs = ["output.txt"],
    cmd = "cp $< $@ && echo 'generated' >> $@",
)

genrule(
    name = "transform",
    srcs = ["input.txt"],
    outs = ["transformed.txt"],
    cmd = "cat $< | tr 'a-z' 'A-Z' > $@",
)

genrule(
    name = "hash",
    srcs = ["input.txt"],
    outs = ["hashed.txt"],
    cmd = "if command -v sha256sum >/dev/null 2>&1; then sha256sum $< > $@; else shasum -a 256 $< > $@; fi",
)
EOF

  printf 'hello from boringcache bazel e2e %s\n' "${RUN_ID}" > "${tool_dir}/input.txt"

  note "Bazel adapter E2E"
  (
    cd "${tool_dir}"
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" bazel \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5314 \
        --no-platform \
        --no-git \
        -- "${bazel_cmd}" \
          --output_base="${output_base_a}" \
          build \
          --remote_cache=http://127.0.0.1:5314 \
          --remote_upload_local_results \
          //:emit //:transform //:hash \
      > "${cold_log}" 2>&1
  )
  wait_for_tag_visibility "${tag}"

  (
    cd "${tool_dir}"
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" bazel \
        --workspace "${WORKSPACE}" \
        --tag "${tag}" \
        --port 5314 \
        --no-platform \
        --no-git \
        -- "${bazel_cmd}" \
          --output_base="${output_base_b}" \
          build \
          --remote_cache=http://127.0.0.1:5314 \
          --remote_upload_local_results \
          //:emit //:transform //:hash \
      > "${warm_log}" 2>&1
  )

  if ! grep -q "remote cache hit" "${warm_log}" && ! grep -q "0 processes" "${warm_log}"; then
    fail "bazel warm run did not show remote cache reuse"
  fi

  (
    cd "${tool_dir}"
    "${bazel_cmd}" --output_base="${output_base_a}" shutdown >/dev/null 2>&1 || true
    "${bazel_cmd}" --output_base="${output_base_b}" shutdown >/dev/null 2>&1 || true
  )

  local summary
  summary="$(metric_summary "${metrics_file}")"
  assert_metric_gt_zero "${summary}" "request_metrics_cache_ops_bazel_get_hits"
  delete_tag "${tag}"
  pass_tool "bazel" "warm run reused remote cache"
}

run_sccache_e2e() {
  command -v cargo >/dev/null 2>&1 || {
    skip_tool "sccache" "cargo not installed"
    return 0
  }
  command -v sccache >/dev/null 2>&1 || {
    skip_tool "sccache" "sccache not installed"
    return 0
  }

  local tool_dir="${TMP_DIR}/sccache"
  local metrics_file="${tool_dir}/metrics.jsonl"
  local cold_log="${tool_dir}/cold.log"
  local warm_log="${tool_dir}/warm.log"
  local cold_stats="${tool_dir}/cold-stats.txt"
  local warm_stats="${tool_dir}/warm-stats.txt"
  local target_dir="${tool_dir}/target"
  local sccache_dir_a="${tool_dir}/sccache-a"
  local sccache_dir_b="${tool_dir}/sccache-b"
  local sccache_server_port=4327
  local tag="local-adapter-sccache-${RUN_ID}"
  local warm_hits=""
  mkdir -p "${tool_dir}/src"

  cat > "${tool_dir}/Cargo.toml" <<'EOF'
[package]
name = "sccache-e2e-project"
version = "0.1.0"
edition = "2024"
EOF

  cat > "${tool_dir}/src/main.rs" <<'EOF'
fn main() {
    println!("result = {}", sccache_e2e_project::compute(42));
}
EOF

  cat > "${tool_dir}/src/lib.rs" <<'EOF'
pub fn compute(n: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..n {
        result = result.wrapping_add(i.wrapping_mul(i));
    }
    result
}
EOF

  note "sccache adapter E2E"
  SCCACHE_SERVER_PORT="${sccache_server_port}" sccache --stop-server >/dev/null 2>&1 || true
  rm -rf "${target_dir}" "${sccache_dir_a}" "${sccache_dir_b}"
  mkdir -p "${sccache_dir_a}" "${sccache_dir_b}"

  # Let the wrapper start the sccache server so it inherits the adapter's WebDAV env.
  (
    cd "${tool_dir}"
    SCCACHE_SERVER_PORT="${sccache_server_port}" \
    SCCACHE_DIR="${sccache_dir_a}" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="${target_dir}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" sccache \
          --workspace "${WORKSPACE}" \
          --tag "${tag}" \
          --port 5315 \
          --no-platform \
          --no-git \
          -- cargo build --release \
      > "${cold_log}" 2>&1
  )
  SCCACHE_SERVER_PORT="${sccache_server_port}" sccache --show-stats > "${cold_stats}" 2>&1
  SCCACHE_SERVER_PORT="${sccache_server_port}" sccache --stop-server >/dev/null 2>&1 || true
  wait_for_tag_visibility "${tag}"

  rm -rf "${target_dir}"
  (
    cd "${tool_dir}"
    SCCACHE_SERVER_PORT="${sccache_server_port}" \
    SCCACHE_DIR="${sccache_dir_b}" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="${target_dir}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${metrics_file}" \
      "${BINARY}" sccache \
          --workspace "${WORKSPACE}" \
          --tag "${tag}" \
          --port 5315 \
          --no-platform \
          --no-git \
          -- cargo build --release \
      > "${warm_log}" 2>&1
  )
  SCCACHE_SERVER_PORT="${sccache_server_port}" sccache --show-stats > "${warm_stats}" 2>&1
  SCCACHE_SERVER_PORT="${sccache_server_port}" sccache --stop-server >/dev/null 2>&1 || true

  warm_hits="$(
    awk '/^Cache hits/ {
      for (i = NF; i >= 1; i--) {
        if ($i ~ /^[0-9]+$/) {
          print $i
          exit
        }
      }
    }' "${warm_stats}"
  )"
  if [[ -z "${warm_hits}" || "${warm_hits}" == "0" ]]; then
    fail "sccache warm run did not report cache hits"
  fi

  local summary
  summary="$(metric_summary "${metrics_file}")"
  assert_metric_gt_zero "${summary}" "request_metrics_cache_ops_sccache_get_hits"
  delete_tag "${tag}"
  pass_tool "sccache" "warm run reported ${warm_hits} sccache hits"
}

main() {
  : > "${SUMMARY_FILE}"
  require_cmd cargo
  require_cmd curl
  require_cmd python3
  require_cmd mise

  build_cli_binary
  start_local_rails

  run_selected_tool "gradle" run_gradle_e2e
  run_selected_tool "maven" run_maven_e2e
  run_selected_tool "turbo" run_turbo_e2e
  run_selected_tool "nx" run_nx_e2e
  run_selected_tool "go" run_go_e2e
  run_selected_tool "bazel" run_bazel_e2e
  run_selected_tool "sccache" run_sccache_e2e

  append_summary ""
  append_summary "Passed tools: ${PASSED_TOOLS[*]:-none}"
  if [[ "${#SKIPPED_TOOLS[@]}" -gt 0 ]]; then
    append_summary "Skipped tools:"
    local item
    for item in "${SKIPPED_TOOLS[@]}"; do
      append_summary "  - ${item}"
    done
  fi

  note "Local adapter-command E2E completed"
  cat "${SUMMARY_FILE}"
}

main "$@"
