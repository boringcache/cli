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
RAILS_ENV_NAME="${RAILS_ENV:-development}"
USE_MISE_FOR_RAILS="${USE_MISE_FOR_RAILS:-1}"
LOG_ROOT="${LOG_ROOT:-${TMPDIR:-/tmp}/boringcache-local-adapter-e2e}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
LOG_DIR="${LOG_DIR:-${LOG_ROOT}/${RUN_ID}}"
RAILS_PIDFILE="${RAILS_PIDFILE:-${LOG_DIR}/rails-server.pid}"
TMP_DIR="${LOG_DIR}/tmp"
SUMMARY_FILE="${LOG_DIR}/summary.txt"
LOCAL_ADAPTER_TOOLS="${LOCAL_ADAPTER_TOOLS:-config-hints,docker,oci-same-alias,gradle,maven,turbo,nx,go,bazel,sccache}"
LOCAL_ADAPTER_SKIP_BUILD="${LOCAL_ADAPTER_SKIP_BUILD:-0}"
LOCAL_ADAPTER_CLEANUP="${LOCAL_ADAPTER_CLEANUP:-}"
E2E_EMAIL="${E2E_EMAIL:-cli-local-adapter-e2e@example.com}"
E2E_NAMESPACE_SLUG="${E2E_NAMESPACE_SLUG:-cli-local-adapter-e2e}"
E2E_WORKSPACE_SLUG="${E2E_WORKSPACE_SLUG:-adapter-e2e}"
E2E_WORKSPACE_NAME="${E2E_WORKSPACE_NAME:-Adapter E2E}"
JAVA_TOOL_VERSION="${JAVA_TOOL_VERSION:-java@21.0.2}"
MAVEN_TOOL_VERSION="${MAVEN_TOOL_VERSION:-maven@3.9.14}"

mkdir -p "${LOG_DIR}" "${TMP_DIR}"

if [[ -z "${LOCAL_ADAPTER_CLEANUP}" ]]; then
  if [[ "${RAILS_ENV_NAME}" == "test" ]]; then
    LOCAL_ADAPTER_CLEANUP="1"
  else
    LOCAL_ADAPTER_CLEANUP="0"
  fi
fi

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

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
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

run_web_command() {
  local -a env_args=("RAILS_ENV=${RAILS_ENV_NAME}")

  [[ -n "${RAILS_MASTER_KEY:-}" ]] && env_args+=("RAILS_MASTER_KEY=${RAILS_MASTER_KEY}")
  [[ -n "${DATABASE_URL:-}" ]] && env_args+=("DATABASE_URL=${DATABASE_URL}")
  [[ -n "${SECRET_KEY_BASE:-}" ]] && env_args+=("SECRET_KEY_BASE=${SECRET_KEY_BASE}")

  if is_truthy "${USE_MISE_FOR_RAILS}"; then
    env "${env_args[@]}" mise exec -- "$@"
  else
    env "${env_args[@]}" "$@"
  fi
}

run_selected_tool() {
  local tool="$1"
  shift
  if should_run_tool "${tool}"; then
    local started_at finished_at elapsed
    started_at="$(date +%s)"
    "$@"
    finished_at="$(date +%s)"
    elapsed=$((finished_at - started_at))
    append_summary "TIME ${tool}: ${elapsed}s"
  else
    skip_tool "${tool}" "not selected by LOCAL_ADAPTER_TOOLS=${LOCAL_ADAPTER_TOOLS}"
  fi
}

cleanup_workspace() {
  if ! is_truthy "${LOCAL_ADAPTER_CLEANUP}"; then
    return 0
  fi

  if [[ -z "${WORKSPACE}" ]]; then
    return 0
  fi

  note "Cleaning up local adapter workspace ${WORKSPACE}"
  (
    cd "${WEB_DIR}"
    E2E_WORKSPACE="${WORKSPACE}" \
      run_web_command bin/rails runner '
        namespace_slug, workspace_slug = ENV.fetch("E2E_WORKSPACE").split("/", 2)
        workspace = Workspace.unscoped.joins(:namespace).find_by(
          namespaces: { slug: namespace_slug },
          slug: workspace_slug
        )

        unless workspace
          puts "WORKSPACE_CLEANUP=missing"
          exit 0
        end

        workspace_id = workspace.id
        workspace_path = workspace.full_path
        workspace_slug = workspace.slug
        namespace_id = workspace.namespace_id

        if workspace.storage_type_managed? && workspace.tigris_provisioned?
          Tigris::DeprovisioningService.new(workspace).deprovision!
        end

        Workspaces::DeletionService.new(
          workspace_id: workspace_id,
          workspace_path: workspace_path
        ).delete_database_records

        FriendlyId::Slug.where(
          sluggable_type: "Workspace",
          slug: workspace_slug,
          scope: "namespace_id:#{namespace_id}"
        ).delete_all

        puts "WORKSPACE_CLEANUP=deleted"
      ' > "${LOG_DIR}/rails-cleanup.log" 2>&1
  )
  append_summary "Workspace cleanup: complete"
}

cleanup() {
  set +e
  cleanup_workspace || true
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

write_repo_config() {
  local config_path="$1"
  local body="$2"
  cat > "${config_path}" <<EOF
workspace = "${WORKSPACE}"

${body}
EOF
}

assert_recent_session_context() {
  local label="$1"
  local project_hint="$2"
  local phase_hint="$3"
  local scenario_hint="$4"
  local tool_hint="$5"
  local attempts="${6:-12}"
  local sessions_file="${LOG_DIR}/${label}-sessions.json"
  local error_file="${LOG_DIR}/${label}-sessions.err"

  for _ in $(seq 1 "${attempts}"); do
    if "${BINARY}" sessions "${WORKSPACE}" --period 1h --limit 50 --json \
      > "${sessions_file}" 2> "${error_file}"; then
      if python3 - "${sessions_file}" "${project_hint}" "${phase_hint}" "${scenario_hint}" "${tool_hint}" <<'PY'
import json
import sys

path, expected_project, expected_phase, expected_scenario, expected_tool = sys.argv[1:6]
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

for session in payload.get("sessions", []):
    if expected_project and session.get("project_hint") != expected_project:
        continue
    if expected_phase and session.get("phase_hint") != expected_phase:
        continue
    hints = session.get("metadata_hints") or {}
    if expected_scenario and hints.get("scenario") != expected_scenario:
        continue
    if expected_tool and hints.get("tool") != expected_tool:
        continue
    sys.exit(0)

sys.exit(1)
PY
      then
        return 0
      fi
    fi
    sleep 2
  done

  cat "${sessions_file}" 2>/dev/null || true
  cat "${error_file}" 2>/dev/null || true
  fail "did not find expected session context for ${label}"
}

run_gradle_proxy_round_trip() {
  local endpoint="$1"
  local key="$2"
  local phase_dir="$3"
  local payload_file="${phase_dir}/payload.bin"
  local output_file="${phase_dir}/output.bin"
  mkdir -p "${phase_dir}"

  printf 'gradle-%s\n' "${key}" > "${payload_file}"
  curl -fsS -X PUT --data-binary @"${payload_file}" "${endpoint}/cache/${key}" \
    > "${phase_dir}/put.out"
  curl -fsS "${endpoint}/cache/${key}" -o "${output_file}"
  cmp -s "${payload_file}" "${output_file}" || fail "gradle proxy round-trip mismatch for ${key}"
}

run_config_hints_e2e() {
  local tool_dir="${TMP_DIR}/config-hints"
  local run_dir="${tool_dir}/run-proxy"
  local standalone_dir="${tool_dir}/standalone-proxy"
  local turbo_dir="${tool_dir}/turbo-adapter"
  local run_project="config-hints-run-${RUN_ID}"
  local standalone_project="config-hints-standalone-${RUN_ID}"
  local turbo_project="config-hints-turbo-${RUN_ID}"
  local run_tag="local-config-hints-run-${RUN_ID}"
  local standalone_tag="local-config-hints-standalone-${RUN_ID}"
  local turbo_tag="local-config-hints-turbo-${RUN_ID}"
  local standalone_port="${CONFIG_HINTS_PROXY_PORT:-5322}"
  local standalone_log="${standalone_dir}/proxy.log"
  local standalone_pid=""
  local old_pwd="${PWD}"

  mkdir -p "${run_dir}" "${standalone_dir}" "${turbo_dir}/apps/app1"

  note "Config hints E2E: run --proxy with repo config"
  write_repo_config "${run_dir}/.boringcache.toml" '[proxy]
metadata-hints = ["project='"${run_project}"'","phase=repo"]'
  (
    cd "${run_dir}"
    "${BINARY}" run \
      --proxy "${run_tag}" \
      --skip-restore \
      --skip-save \
      --no-platform \
      --no-git \
      -- \
      sh -c 'set -euo pipefail
        printf "run-proxy-config\n" > payload.bin
        curl -fsS -X PUT --data-binary @payload.bin "{ENDPOINT}/cache/run-config-key" >/dev/null
        curl -fsS "{ENDPOINT}/cache/run-config-key" -o output.bin
        cmp payload.bin output.bin' \
      > "${run_dir}/run.log" 2>&1
  )
  wait_for_tag_visibility "${run_tag}"
  assert_recent_session_context "config-hints-run" "${run_project}" "repo" "" ""
  delete_tag "${run_tag}"

  note "Config hints E2E: standalone cache-registry with repo config and overrides"
  write_repo_config "${standalone_dir}/.boringcache.toml" '[proxy]
metadata-hints = ["project='"${standalone_project}"'","scenario=repo"]'
  cd "${standalone_dir}"
  BORINGCACHE_PROXY_METADATA_HINTS="scenario=env" \
    RUST_LOG="${RUST_LOG:-warn}" \
    BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
    BORINGCACHE_OBSERVABILITY_JSONL_PATH="${standalone_dir}/metrics.jsonl" \
      "${BINARY}" cache-registry "${WORKSPACE}" "${standalone_tag}" \
        --host 127.0.0.1 \
        --port "${standalone_port}" \
        --metadata-hint phase=flag \
        --no-platform \
        --no-git \
        > "${standalone_log}" 2>&1 &
  standalone_pid=$!
  cd "${old_pwd}"
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${standalone_port}/_boringcache/status" >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "${standalone_pid}" >/dev/null 2>&1; then
      tail -n 120 "${standalone_log}" || true
      fail "standalone config proxy exited before readiness"
    fi
    sleep 1
  done
  run_gradle_proxy_round_trip "http://127.0.0.1:${standalone_port}" "standalone-config-key" "${standalone_dir}"
  kill "${standalone_pid}" >/dev/null 2>&1 || true
  wait "${standalone_pid}" >/dev/null 2>&1 || true
  standalone_pid=""
  wait_for_tag_visibility "${standalone_tag}"
  assert_recent_session_context \
    "config-hints-standalone" \
    "${standalone_project}" \
    "flag" \
    "env" \
    ""
  delete_tag "${standalone_tag}"

  if command -v turbo >/dev/null 2>&1; then
    note "Config hints E2E: adapter command from repo config"
    cat > "${turbo_dir}/package.json" <<'EOF'
{
  "name": "turbo-config-hints-e2e",
  "private": true,
  "version": "1.0.0",
  "packageManager": "npm@10.9.0",
  "workspaces": ["apps/*"]
}
EOF

    cat > "${turbo_dir}/turbo.json" <<'EOF'
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

    cat > "${turbo_dir}/apps/app1/package.json" <<'EOF'
{
  "name": "app1",
  "version": "1.0.0",
  "scripts": {
    "build": "bash ./build.sh"
  }
}
EOF

    cat > "${turbo_dir}/apps/app1/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "${TURBO_MARKER_FILE}" ]]; then
  count=$(cat "${TURBO_MARKER_FILE}")
fi
count=$((count + 1))
echo "${count}" > "${TURBO_MARKER_FILE}"
mkdir -p dist
echo "turbo-${count}" > dist/out.txt
EOF
    chmod +x "${turbo_dir}/apps/app1/build.sh"

    cat > "${turbo_dir}/.boringcache.toml" <<EOF
workspace = "${WORKSPACE}"

[proxy]
metadata-hints = ["project=${turbo_project}"]

[adapters.turbo]
tag = "${turbo_tag}"
command = ["turbo", "run", "build", "--cache-dir=.turbo/cache", "--output-logs=errors-only"]
port = 5323
no-platform = true
no-git = true
metadata-hints = ["tool=turbo", "phase=warm", "scenario=adapter-config"]
EOF

    (
      cd "${turbo_dir}"
      TURBO_MARKER_FILE="${turbo_dir}/marker.txt" \
      BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
      BORINGCACHE_OBSERVABILITY_JSONL_PATH="${turbo_dir}/metrics.jsonl" \
        "${BINARY}" turbo \
        > "${turbo_dir}/cold.log" 2>&1
    )
    [[ "$(cat "${turbo_dir}/marker.txt")" == "1" ]] || fail "turbo config cold run did not execute exactly once"
    wait_for_tag_visibility "${turbo_tag}"

    rm -rf "${turbo_dir}/.turbo" "${turbo_dir}/apps/app1/dist"
    (
      cd "${turbo_dir}"
      TURBO_MARKER_FILE="${turbo_dir}/marker.txt" \
      BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS=1 \
      BORINGCACHE_OBSERVABILITY_JSONL_PATH="${turbo_dir}/metrics.jsonl" \
        "${BINARY}" turbo \
        > "${turbo_dir}/warm.log" 2>&1
    )
    [[ "$(cat "${turbo_dir}/marker.txt")" == "1" ]] || fail "turbo config warm run re-executed instead of using remote cache"
    assert_recent_session_context \
      "config-hints-turbo" \
      "${turbo_project}" \
      "warm" \
      "adapter-config" \
      "turbo"
    delete_tag "${turbo_tag}"
  else
    skip_tool "config-hints-turbo" "turbo not installed"
  fi

  if [[ -n "${standalone_pid}" ]]; then
    kill "${standalone_pid}" >/dev/null 2>&1 || true
    wait "${standalone_pid}" >/dev/null 2>&1 || true
  fi

  pass_tool "config-hints" "repo config, proxy overrides, and adapter config recorded session hints"
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
  if "${BINARY}" check --no-platform --no-git --fail-on-miss "${WORKSPACE}" "${tag}" \
    > "${log_file}" 2>&1; then
    return 0
  fi
  cat "${log_file}" || true
  fail "tag was not visible immediately after publish: ${tag}"
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
      run_web_command bin/rails runner '
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
    run_web_command bin/rails db:prepare > "${LOG_DIR}/rails-db-prepare.log" 2>&1
  )

  note "Provisioning local workspace token"
  local bootstrap_output
  bootstrap_output="$(
    cd "${WEB_DIR}"
    E2E_EMAIL="${E2E_EMAIL}" \
    E2E_NAMESPACE_SLUG="${E2E_NAMESPACE_SLUG}" \
    E2E_WORKSPACE_SLUG="${E2E_WORKSPACE_SLUG}" \
    E2E_WORKSPACE_NAME="${E2E_WORKSPACE_NAME}" \
      run_web_command bin/rails runner '
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

      workspace_slug = ENV.fetch("E2E_WORKSPACE_SLUG")
      workspace = Workspace.find_by(namespace: user.namespace, slug: workspace_slug)

      if workspace.nil?
        FriendlyId::Slug.where(
          sluggable_type: "Workspace",
          slug: workspace_slug,
          scope: "namespace_id:#{user.namespace.id}"
        ).delete_all

        workspace = Workspace.new(
          namespace: user.namespace,
          slug: workspace_slug
        )
        workspace.name = ENV.fetch("E2E_WORKSPACE_NAME")
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
    PORT="${RAILS_PORT}" run_web_command bin/rails server -b "${RAILS_HOST}" -p "${RAILS_PORT}" \
      --pid "${RAILS_PIDFILE}" \
      > "${LOG_DIR}/rails-server.log" 2>&1
  ) &
  RAILS_PID=$!
  wait_for_local_server
  append_summary "Workspace: ${WORKSPACE}"
  append_summary "API URL: ${API_URL}"
  append_summary "Rails env: ${RAILS_ENV_NAME}"
  append_summary "Rails launcher: $(if is_truthy "${USE_MISE_FOR_RAILS}"; then printf '%s' mise; else printf '%s' direct; fi)"
  append_summary "Workspace cleanup enabled: ${LOCAL_ADAPTER_CLEANUP}"
  append_summary "Selected tools: ${LOCAL_ADAPTER_TOOLS}"
}

build_cli_binary() {
  if is_truthy "${LOCAL_ADAPTER_SKIP_BUILD}"; then
    [[ -x "${BINARY}" ]] || fail "expected prebuilt executable binary at ${BINARY}"
    append_summary "CLI binary: ${BINARY} (prebuilt)"
    return 0
  fi

  note "Building boringcache CLI"
  (
    cd "${CLI_DIR}"
    cargo build --bin boringcache > "${LOG_DIR}/cargo-build.log" 2>&1
  )
  [[ -x "${BINARY}" ]] || fail "expected executable binary at ${BINARY}"
  append_summary "CLI binary: ${BINARY} (built locally)"
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

run_docker_e2e() {
  command -v docker >/dev/null 2>&1 || {
    skip_tool "docker" "docker not installed"
    return 0
  }
  if ! docker info >/dev/null 2>&1; then
    skip_tool "docker" "docker daemon unavailable"
    return 0
  fi

  local tool_log_root="${LOG_DIR}/docker-buildkit-runtime"
  local docker_port="${DOCKER_PROXY_PORT:-5318}"
  local registry_host="${DOCKER_REGISTRY_HOST:-localhost}"
  local proxy_host="${DOCKER_PROXY_HOST:-127.0.0.1}"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    registry_host="${DOCKER_REGISTRY_HOST:-host.docker.internal}"
    proxy_host="${DOCKER_PROXY_HOST:-0.0.0.0}"
  fi
  mkdir -p "${tool_log_root}"

  note "Docker BuildKit registry E2E"
  LOG_DIR="${tool_log_root}" \
  PORT="${docker_port}" \
  PROXY_PORT="${docker_port}" \
  REGISTRY_PORT="${docker_port}" \
  REGISTRY_HOST="${registry_host}" \
  PROXY_HOST="${proxy_host}" \
  E2E_TAG_PREFIX="local-adapter-${RUN_ID}" \
  GITHUB_RUN_ID="${RUN_ID}" \
  GITHUB_RUN_ATTEMPT="1" \
  BINARY="${BINARY}" \
  WORKSPACE="${WORKSPACE}" \
  BORINGCACHE_API_URL="${API_URL}" \
  BORINGCACHE_ADMIN_TOKEN="${TOKEN}" \
  BORINGCACHE_SAVE_TOKEN="${TOKEN}" \
  BORINGCACHE_RESTORE_TOKEN="${TOKEN}" \
    bash "${SCRIPT_DIR}/required/e2e-docker-buildkit-registry-test.sh"

  pass_tool "docker" "required BuildKit registry e2e passed"
}

run_oci_same_alias_e2e() {
  local tool_log_root="${LOG_DIR}/oci-same-alias-runtime"
  mkdir -p "${tool_log_root}"

  note "OCI same-alias writer runtime E2E"
  LOG_DIR="${tool_log_root}" \
  PROXY_PORT="${OCI_SAME_ALIAS_PROXY_PORT:-5319}" \
  PROXY_PORT_A="${OCI_SAME_ALIAS_PROXY_PORT_A:-5319}" \
  PROXY_PORT_B="${OCI_SAME_ALIAS_PROXY_PORT_B:-5320}" \
  PROXY_PORT_VERIFY="${OCI_SAME_ALIAS_PROXY_PORT_VERIFY:-5321}" \
  TAG="local-oci-same-alias-${RUN_ID}" \
  GITHUB_RUN_ID="${RUN_ID}" \
  GITHUB_RUN_ATTEMPT="1" \
  BINARY="${BINARY}" \
  WORKSPACE="${WORKSPACE}" \
  BORINGCACHE_API_URL="${API_URL}" \
  BORINGCACHE_ADMIN_TOKEN="${TOKEN}" \
  BORINGCACHE_SAVE_TOKEN="${TOKEN}" \
  BORINGCACHE_RESTORE_TOKEN="${TOKEN}" \
    bash "${SCRIPT_DIR}/required/e2e-oci-same-alias-writer-test.sh"

  pass_tool "oci-same-alias" "dual-proxy same-alias writer e2e passed"
}

run_oci_rooted_restore_isolation_e2e() {
  local tool_log_root="${LOG_DIR}/oci-rooted-restore-isolation-runtime"
  mkdir -p "${tool_log_root}"

  note "OCI rooted restore isolation runtime E2E"
  LOG_DIR="${tool_log_root}" \
  PROXY_PORT_A="${OCI_ROOTED_RESTORE_ISOLATION_PROXY_PORT_A:-5331}" \
  PROXY_PORT_B="${OCI_ROOTED_RESTORE_ISOLATION_PROXY_PORT_B:-5330}" \
  GITHUB_RUN_ID="${RUN_ID}" \
  GITHUB_RUN_ATTEMPT="1" \
  BINARY="${BINARY}" \
  WORKSPACE="${WORKSPACE}" \
  BORINGCACHE_API_URL="${API_URL}" \
  BORINGCACHE_ADMIN_TOKEN="${TOKEN}" \
  BORINGCACHE_SAVE_TOKEN="${TOKEN}" \
  BORINGCACHE_RESTORE_TOKEN="${TOKEN}" \
    bash "${SCRIPT_DIR}/required/e2e-oci-rooted-restore-isolation-test.sh"

  pass_tool "oci-rooted-restore-isolation" "rooted restore isolation e2e passed"
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
  local total_started_at total_finished_at total_elapsed
  : > "${SUMMARY_FILE}"
  require_cmd curl
  require_cmd python3

  total_started_at="$(date +%s)"

  if ! is_truthy "${LOCAL_ADAPTER_SKIP_BUILD}"; then
    require_cmd cargo
  fi

  if is_truthy "${USE_MISE_FOR_RAILS}" || should_run_tool "gradle" || should_run_tool "maven"; then
    require_cmd mise
  fi

  build_cli_binary
  start_local_rails

  run_selected_tool "config-hints" run_config_hints_e2e
  run_selected_tool "gradle" run_gradle_e2e
  run_selected_tool "maven" run_maven_e2e
  run_selected_tool "docker" run_docker_e2e
  run_selected_tool "oci-same-alias" run_oci_same_alias_e2e
  run_selected_tool "oci-rooted-restore-isolation" run_oci_rooted_restore_isolation_e2e
  run_selected_tool "turbo" run_turbo_e2e
  run_selected_tool "nx" run_nx_e2e
  run_selected_tool "go" run_go_e2e
  run_selected_tool "bazel" run_bazel_e2e
  run_selected_tool "sccache" run_sccache_e2e

  total_finished_at="$(date +%s)"
  total_elapsed=$((total_finished_at - total_started_at))

  append_summary ""
  append_summary "Total duration: ${total_elapsed}s"
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
