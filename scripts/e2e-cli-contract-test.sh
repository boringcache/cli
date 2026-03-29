#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

LOG_DIR="${LOG_DIR:-.}"

for dep in cargo; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: required dependency not found: ${dep}"
    exit 1
  fi
done

mkdir -p "${LOG_DIR}"
CONTRACT_LOG_DIR="${LOG_DIR}/cli-contract-e2e"
mkdir -p "${CONTRACT_LOG_DIR}"

run_contract_test() {
  local label="$1"
  shift
  local log_name
  log_name="$(printf '%s' "${label}" | tr ' /' '__')"
  echo "--- ${label} ---"
  env \
    -u BORINGCACHE_ADMIN_TOKEN \
    -u BORINGCACHE_RESTORE_TOKEN \
    -u BORINGCACHE_SAVE_TOKEN \
    -u BORINGCACHE_API_TOKEN \
    -u BORINGCACHE_API_URL \
    -u BORINGCACHE_DEFAULT_WORKSPACE \
    -u BORINGCACHE_E2E_RESTORE_TOKEN \
    -u BORINGCACHE_E2E_SAVE_TOKEN \
    "$@" 2>&1 | tee "${CONTRACT_LOG_DIR}/${log_name}.log"
}

echo "=== Phase 1: Pending restore and manifest-check handling ==="
run_contract_test \
  "mount-pending-classification" \
  cargo test manifest_check_
run_contract_test \
  "restore-404-pending-body" \
  cargo test --test api_behavior_tests test_restore_retries_on_404_with_pending_body -- --exact
run_contract_test \
  "restore-pending-entry-response" \
  cargo test --test api_behavior_tests test_restore_retries_on_pending_entries_in_response -- --exact

echo "=== Phase 2: Concurrent writer conflict wording ==="
run_contract_test \
  "bazel-lock-create" \
  cargo test --test cas_adapter_integration_tests test_save_bazel_cas_skips_on_locked_create_without_extra_api_calls -- --exact
run_contract_test \
  "oci-lock-create" \
  cargo test --test cas_adapter_integration_tests test_save_oci_skips_on_locked_create_without_extra_api_calls -- --exact
run_contract_test \
  "bazel-publish-conflict" \
  cargo test --test cas_adapter_integration_tests test_save_bazel_cas_skips_when_publish_conflicts_for_existing_entry -- --exact
run_contract_test \
  "oci-publish-conflict" \
  cargo test --test cas_adapter_integration_tests test_save_oci_skips_when_publish_conflicts_for_existing_entry -- --exact

echo "=== Phase 3: Pending publish completion ==="
run_contract_test \
  "pending-publish-polling" \
  cargo test confirm_polls_pending_publish_until_published
run_contract_test \
  "pending-publish-conflict-terminal-state" \
  cargo test normal_confirm_waits_for_pending_publish_terminal_state

echo "CLI contract e2e passed. Logs: ${CONTRACT_LOG_DIR}"
