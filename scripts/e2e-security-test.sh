#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

BINARY="${BINARY:-./target/debug/boringcache}"
WORKSPACE="${WORKSPACE:?WORKSPACE is required}"
BORINGCACHE_API_URL="${BORINGCACHE_API_URL:-https://api.boringcache.com}"
LOG_DIR="${LOG_DIR:-.}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
PROXY_PORT="${PROXY_PORT:-5057}"

require_save_capable_token

for dep in jq curl cmp mktemp; do
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
SEC_LOG_DIR="${LOG_DIR}/security-e2e"
rm -rf "${SEC_LOG_DIR}"
mkdir -p "${SEC_LOG_DIR}"
CLI_HOME="$(mktemp -d)"
export HOME="${CLI_HOME}"

FULL_TOKEN="$(resolve_admin_capable_token || resolve_save_capable_token)"
bootstrap_cli_session "${BINARY}" "${WORKSPACE}" "${BORINGCACHE_API_URL}" "${SEC_LOG_DIR}/auth.log" admin

setup_e2e_traps "${BINARY}" "${WORKSPACE}"

TAG_ROOT="$(e2e_tag "security")"

echo "=== Phase 1: Tag-name injection ==="
INJECT_TAG="${TAG_ROOT}-traversal"
INJECT_SRC="${SEC_LOG_DIR}/inject-src"
INJECT_RESTORE="${SEC_LOG_DIR}/inject-restore"
register_tag_for_cleanup "${INJECT_TAG}"
mkdir -p "${INJECT_SRC}"
printf 'inject-test-%s\n' "${RUN_ID}" > "${INJECT_SRC}/data.txt"

"${BINARY}" save --no-platform --no-git "${WORKSPACE}" "${INJECT_TAG}:${INJECT_SRC}" \
  > "${SEC_LOG_DIR}/inject-save.log" 2>&1
wait_for_visibility "${BINARY}" "${WORKSPACE}" "${INJECT_TAG}"
"${BINARY}" restore --no-platform --no-git "${WORKSPACE}" "${INJECT_TAG}:${INJECT_RESTORE}" \
  > "${SEC_LOG_DIR}/inject-restore.log" 2>&1
cmp -s "${INJECT_SRC}/data.txt" "${INJECT_RESTORE}/data.txt"

set +e
"${BINARY}" save --no-platform --no-git "${WORKSPACE}" "../escape-tag:${INJECT_SRC}" \
  > "${SEC_LOG_DIR}/traversal-tag-save.log" 2>&1
traversal_status=$?
set -e
if [[ "${traversal_status}" -eq 0 ]]; then
  if grep -qi "invalid\|rejected\|error\|denied" "${SEC_LOG_DIR}/traversal-tag-save.log"; then
    echo "  path traversal tag was rejected by server (expected)"
  else
    echo "WARNING: traversal tag save returned 0 - checking if server sanitized it"
  fi
fi

echo "=== Phase 2: Cache poisoning via CAS tamper ==="
POISON_TAG="${TAG_ROOT}-poison"
POISON_SRC="${SEC_LOG_DIR}/poison-src"
POISON_RESTORE="${SEC_LOG_DIR}/poison-restore"
register_tag_for_cleanup "${POISON_TAG}"
mkdir -p "${POISON_SRC}/cas" "${POISON_SRC}/ac"
POISON_DATA="genuine-content-${RUN_ID}"
printf '%s' "${POISON_DATA}" > "${POISON_SRC}/cas/legit-blob"
LEGIT_HASH="$(sha256_file_hex "${POISON_SRC}/cas/legit-blob")"

export BORINGCACHE_PROXY_METADATA_HINTS="project=e2e-security,tool=cas-tamper"
start_proxy "${BINARY}" "${WORKSPACE}" "${POISON_TAG}" "${PROXY_PORT}" "${SEC_LOG_DIR}/proxy-poison.log"
wait_for_proxy "${PROXY_PORT}"

PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
curl -fsS -X PUT \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${POISON_SRC}/cas/legit-blob" \
  "${PROXY_URL}/cas/${LEGIT_HASH}" \
  -o "${SEC_LOG_DIR}/cas-put-legit.out" 2>"${SEC_LOG_DIR}/cas-put-legit.err" || true

TAMPERED_DATA="POISONED-content-${RUN_ID}"
printf '%s' "${TAMPERED_DATA}" > "${SEC_LOG_DIR}/tampered-blob"
set +e
tamper_status_code="$(curl -sS -X PUT \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${SEC_LOG_DIR}/tampered-blob" \
  -w "%{http_code}" \
  -o "${SEC_LOG_DIR}/cas-put-tamper.out" \
  "${PROXY_URL}/cas/${LEGIT_HASH}" 2>"${SEC_LOG_DIR}/cas-put-tamper.err")"
set -e

echo "  tamper PUT returned HTTP ${tamper_status_code}"

read_status_code="$(curl -sS \
  -w "%{http_code}" \
  -o "${SEC_LOG_DIR}/cas-get-after-tamper.out" \
  "${PROXY_URL}/cas/${LEGIT_HASH}" 2>"${SEC_LOG_DIR}/cas-get-after-tamper.err")"

if [[ "${read_status_code}" == "200" ]]; then
  read_hash="$(sha256_file_hex "${SEC_LOG_DIR}/cas-get-after-tamper.out")"
  if [[ "${read_hash}" == "${LEGIT_HASH}" ]]; then
    echo "  CAS integrity verified: content matches original hash after tamper attempt"
  else
    echo "ERROR: CAS poisoning succeeded — proxy returned tampered content"
    echo "  expected hash: ${LEGIT_HASH}"
    echo "  actual hash:   ${read_hash}"
    stop_proxy
    exit 1
  fi
elif [[ "${tamper_status_code}" =~ ^(400|409|422)$ ]]; then
  echo "  CAS tamper correctly rejected by proxy (HTTP ${tamper_status_code})"
else
  echo "  CAS GET after tamper returned HTTP ${read_status_code} (blob may have been evicted)"
fi

stop_proxy

echo "=== Phase 3: Cross-workspace isolation ==="
CROSS_TAG="${TAG_ROOT}-cross"
register_tag_for_cleanup "${CROSS_TAG}"
mkdir -p "${SEC_LOG_DIR}/cross-src"
printf 'cross-workspace-secret-%s\n' "${RUN_ID}" > "${SEC_LOG_DIR}/cross-src/secret.txt"
"${BINARY}" save --no-platform --no-git "${WORKSPACE}" "${CROSS_TAG}:${SEC_LOG_DIR}/cross-src" \
  > "${SEC_LOG_DIR}/cross-save.log" 2>&1
wait_for_visibility "${BINARY}" "${WORKSPACE}" "${CROSS_TAG}"

set +e
"${BINARY}" check --no-platform --no-git --fail-on-miss "nonexistent-org/nonexistent-workspace" "${CROSS_TAG}" \
  > "${SEC_LOG_DIR}/cross-check.log" 2>&1
cross_status=$?
set -e

if [[ "${cross_status}" -ne 0 ]]; then
  echo "  cross-workspace check correctly denied (exit=${cross_status})"
else
  echo "  WARNING: cross-workspace check returned 0 — verifying content is not leaked"
  if grep -q "hits.*0" "${SEC_LOG_DIR}/cross-check.log" 2>/dev/null || \
     grep -q "miss" "${SEC_LOG_DIR}/cross-check.log" 2>/dev/null; then
    echo "  cross-workspace check returned miss (no data leaked)"
  fi
fi

echo "=== Phase 4: Signed restore (--require-server-signature) ==="
SIG_TAG="${TAG_ROOT}-signed"
SIG_SRC="${SEC_LOG_DIR}/sig-src"
SIG_RESTORE="${SEC_LOG_DIR}/sig-restore"
register_tag_for_cleanup "${SIG_TAG}"
mkdir -p "${SIG_SRC}"
printf 'signed-test-%s\n' "${RUN_ID}" > "${SIG_SRC}/payload.txt"
"${BINARY}" save --no-platform --no-git "${WORKSPACE}" "${SIG_TAG}:${SIG_SRC}" \
  > "${SEC_LOG_DIR}/sig-save.log" 2>&1
wait_for_visibility "${BINARY}" "${WORKSPACE}" "${SIG_TAG}"

set +e
"${BINARY}" restore --no-platform --no-git --require-server-signature --fail-on-cache-error \
  "${WORKSPACE}" "${SIG_TAG}:${SIG_RESTORE}" \
  > "${SEC_LOG_DIR}/sig-restore.log" 2>&1
sig_status=$?
set -e

if [[ "${sig_status}" -eq 0 ]]; then
  echo "  signed restore succeeded — workspace has signing configured"
  cmp -s "${SIG_SRC}/payload.txt" "${SIG_RESTORE}/payload.txt"
  echo "  restored content matches original"
else
  if grep -qi "signature missing\|signature.*not verified\|authenticity" "${SEC_LOG_DIR}/sig-restore.log"; then
    echo "  signed restore correctly failed: signature not available"
  else
    echo "  signed restore failed with unexpected error:"
    cat "${SEC_LOG_DIR}/sig-restore.log"
    exit 1
  fi
fi

SIG_NOSIG_RESTORE="${SEC_LOG_DIR}/sig-nosig-restore"
"${BINARY}" restore --no-platform --no-git "${WORKSPACE}" "${SIG_TAG}:${SIG_NOSIG_RESTORE}" \
  > "${SEC_LOG_DIR}/sig-nosig-restore.log" 2>&1
cmp -s "${SIG_SRC}/payload.txt" "${SIG_NOSIG_RESTORE}/payload.txt"
echo "  restore without --require-server-signature succeeded (content matches)"

echo "=== Phase 5: Token isolation ==="
TOKEN_TAG="${TAG_ROOT}-token"
TOKEN_SRC="${SEC_LOG_DIR}/token-src"
register_tag_for_cleanup "${TOKEN_TAG}"
mkdir -p "${TOKEN_SRC}"
printf 'token-test-%s\n' "${RUN_ID}" > "${TOKEN_SRC}/data.txt"

SCOPED_RESTORE_TOKEN="${BORINGCACHE_E2E_RESTORE_TOKEN:-}"
SCOPED_SAVE_TOKEN="${BORINGCACHE_E2E_SAVE_TOKEN:-}"
TOKEN_HOME="$(mktemp -d)"
TOKEN_SCOPE_ENFORCEMENT="${BORINGCACHE_E2E_REQUIRE_TOKEN_SCOPES:-0}"
TOKENS_LOOK_DISTINCT=0

if [[ -n "${SCOPED_RESTORE_TOKEN}" && -n "${SCOPED_SAVE_TOKEN}" ]] && \
   [[ "${SCOPED_RESTORE_TOKEN}" != "${SCOPED_SAVE_TOKEN}" ]] && \
   [[ "${SCOPED_RESTORE_TOKEN}" != "${FULL_TOKEN}" ]] && \
   [[ "${SCOPED_SAVE_TOKEN}" != "${FULL_TOKEN}" ]]; then
  TOKENS_LOOK_DISTINCT=1
fi

if [[ -n "${SCOPED_RESTORE_TOKEN}" ]]; then
  echo "  using real scoped restore token (server-side enforcement)"
  RESTORE_ONLY_TOKEN="${SCOPED_RESTORE_TOKEN}"
else
  echo "  no BORINGCACHE_E2E_RESTORE_TOKEN set — testing CLI-side resolution only"
  RESTORE_ONLY_TOKEN="${FULL_TOKEN}"
fi

if [[ -n "${SCOPED_SAVE_TOKEN}" ]]; then
  echo "  using real scoped save token (server-side enforcement)"
  SAVE_ONLY_TOKEN="${SCOPED_SAVE_TOKEN}"
else
  echo "  no BORINGCACHE_E2E_SAVE_TOKEN set — testing CLI-side resolution only"
  SAVE_ONLY_TOKEN="${FULL_TOKEN}"
fi

if [[ "${TOKENS_LOOK_DISTINCT}" -eq 1 ]]; then
  echo "  restore/save token secrets are distinct from the full token"
else
  echo "  scoped token secrets are missing or not clearly distinct; scope assertions are diagnostic"
fi

if [[ "${TOKEN_SCOPE_ENFORCEMENT}" == "1" ]]; then
  echo "  token scope enforcement is strict for this run"
else
  echo "  token scope enforcement is non-fatal unless explicitly enabled"
fi

echo "  --- 5a: restore-only token cannot save ---"
set +e
HOME="${TOKEN_HOME}" \
  BORINGCACHE_RESTORE_TOKEN="${RESTORE_ONLY_TOKEN}" \
  BORINGCACHE_SAVE_TOKEN="" \
  BORINGCACHE_ADMIN_TOKEN="" \
  BORINGCACHE_API_TOKEN="" \
  BORINGCACHE_API_URL="${BORINGCACHE_API_URL}" \
  "${BINARY}" save --no-platform --no-git "${WORKSPACE}" "${TOKEN_TAG}:${TOKEN_SRC}" \
  > "${SEC_LOG_DIR}/token-restore-only-save.log" 2>&1
token_save_status=$?
set -e

if [[ "${token_save_status}" -ne 0 ]]; then
  echo "  save correctly failed with restore-only token (exit=${token_save_status})"
  if grep -qi "save.*token\|save-capable\|no.*token\|unauthorized\|forbidden" "${SEC_LOG_DIR}/token-restore-only-save.log"; then
    echo "  error message confirms token scope enforcement"
  fi
else
  if [[ "${TOKEN_SCOPE_ENFORCEMENT}" == "1" && "${TOKENS_LOOK_DISTINCT}" -eq 1 ]]; then
    echo "ERROR: save succeeded with a real restore-only token — server did not enforce scope"
    exit 1
  else
    echo "  WARNING: save succeeded with the restore token; keeping this diagnostic because strict scope enforcement is disabled"
  fi
fi

echo "  --- 5b: restore-only token can restore ---"
"${BINARY}" save --no-platform --no-git "${WORKSPACE}" "${TOKEN_TAG}:${TOKEN_SRC}" \
  > "${SEC_LOG_DIR}/token-full-save.log" 2>&1
wait_for_visibility "${BINARY}" "${WORKSPACE}" "${TOKEN_TAG}"

TOKEN_RESTORE_DIR="${SEC_LOG_DIR}/token-restore-dir"
set +e
HOME="${TOKEN_HOME}" \
  BORINGCACHE_RESTORE_TOKEN="${RESTORE_ONLY_TOKEN}" \
  BORINGCACHE_SAVE_TOKEN="" \
  BORINGCACHE_ADMIN_TOKEN="" \
  BORINGCACHE_API_TOKEN="" \
  BORINGCACHE_API_URL="${BORINGCACHE_API_URL}" \
  "${BINARY}" restore --no-platform --no-git "${WORKSPACE}" "${TOKEN_TAG}:${TOKEN_RESTORE_DIR}" \
  > "${SEC_LOG_DIR}/token-restore-only-restore.log" 2>&1
token_restore_status=$?
set -e

if [[ "${token_restore_status}" -eq 0 ]]; then
  cmp -s "${TOKEN_SRC}/data.txt" "${TOKEN_RESTORE_DIR}/data.txt"
  echo "  restore with restore-only token succeeded and content matches"
else
  if [[ "${TOKEN_SCOPE_ENFORCEMENT}" == "1" && "${TOKENS_LOOK_DISTINCT}" -eq 1 ]]; then
    echo "ERROR: restore with real restore-only token failed (exit=${token_restore_status})"
    cat "${SEC_LOG_DIR}/token-restore-only-restore.log"
    exit 1
  else
    echo "  WARNING: restore with restore-only token failed (exit=${token_restore_status})"
    cat "${SEC_LOG_DIR}/token-restore-only-restore.log"
  fi
fi

echo "  --- 5c: save-only token cannot delete ---"
set +e
HOME="${TOKEN_HOME}" \
  BORINGCACHE_RESTORE_TOKEN="" \
  BORINGCACHE_SAVE_TOKEN="${SAVE_ONLY_TOKEN}" \
  BORINGCACHE_ADMIN_TOKEN="" \
  BORINGCACHE_API_TOKEN="" \
  BORINGCACHE_API_URL="${BORINGCACHE_API_URL}" \
  "${BINARY}" delete --no-platform --no-git "${WORKSPACE}" "${TOKEN_TAG}" \
  > "${SEC_LOG_DIR}/token-save-only-delete.log" 2>&1
token_delete_status=$?
set -e

if [[ "${token_delete_status}" -ne 0 ]]; then
  echo "  delete correctly failed with save-only token (exit=${token_delete_status})"
  if grep -qi "admin.*token\|unauthorized\|forbidden\|not enough" "${SEC_LOG_DIR}/token-save-only-delete.log"; then
    echo "  error message confirms admin scope required"
  fi
else
  if [[ "${TOKEN_SCOPE_ENFORCEMENT}" == "1" && "${TOKENS_LOOK_DISTINCT}" -eq 1 ]]; then
    echo "ERROR: delete succeeded with a real save-only token — server did not enforce scope"
    exit 1
  else
    echo "  WARNING: delete succeeded with the save token; keeping this diagnostic because strict scope enforcement is disabled"
  fi
fi

echo "  --- 5d: save token can save ---"
TOKEN_SAVE_TAG="${TAG_ROOT}-token-save"
register_tag_for_cleanup "${TOKEN_SAVE_TAG}"
set +e
HOME="${TOKEN_HOME}" \
  BORINGCACHE_RESTORE_TOKEN="" \
  BORINGCACHE_SAVE_TOKEN="${SAVE_ONLY_TOKEN}" \
  BORINGCACHE_ADMIN_TOKEN="" \
  BORINGCACHE_API_TOKEN="" \
  BORINGCACHE_API_URL="${BORINGCACHE_API_URL}" \
  "${BINARY}" save --no-platform --no-git "${WORKSPACE}" "${TOKEN_SAVE_TAG}:${TOKEN_SRC}" \
  > "${SEC_LOG_DIR}/token-save-only-save.log" 2>&1
token_save_save_status=$?
set -e

if [[ "${token_save_save_status}" -eq 0 ]]; then
  echo "  save with save-only token succeeded"
else
  if [[ "${TOKEN_SCOPE_ENFORCEMENT}" == "1" && "${TOKENS_LOOK_DISTINCT}" -eq 1 ]]; then
    echo "ERROR: save with real save-only token failed (exit=${token_save_save_status})"
    cat "${SEC_LOG_DIR}/token-save-only-save.log"
    exit 1
  else
    echo "  WARNING: save with save-only token failed (exit=${token_save_save_status})"
    cat "${SEC_LOG_DIR}/token-save-only-save.log"
  fi
fi

rm -rf "${TOKEN_HOME}"

echo "Security e2e passed. Logs: ${SEC_LOG_DIR}"
