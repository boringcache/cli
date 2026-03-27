#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

mise_version="$("${SCRIPT_DIR}/rust-version.sh")"
toolchain_version="$(sed -nE 's/^channel = "([^"]+)"$/\1/p' "${REPO_ROOT}/rust-toolchain.toml" | head -n 1)"

if [[ -z "${toolchain_version}" ]]; then
  echo "ERROR: failed to read Rust channel from rust-toolchain.toml" >&2
  exit 1
fi

if [[ "${mise_version}" != "${toolchain_version}" ]]; then
  echo "ERROR: Rust versions are out of sync: mise.toml=${mise_version} rust-toolchain.toml=${toolchain_version}" >&2
  exit 1
fi
