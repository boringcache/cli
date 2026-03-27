#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

version="$(sed -nE 's/^rust = "([^"]+)"$/\1/p' "${REPO_ROOT}/mise.toml" | head -n 1)"
if [[ -z "${version}" ]]; then
  echo "ERROR: failed to read Rust version from mise.toml" >&2
  exit 1
fi

printf '%s\n' "${version}"
