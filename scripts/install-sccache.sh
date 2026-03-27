#!/usr/bin/env bash
set -euo pipefail

version="${SCCACHE_VERSION:-v0.14.0}"
dest_dir="${1:-${HOME}/.local/bin}"

platform_triple() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)
      printf 'aarch64-apple-darwin\n'
      ;;
    Darwin-x86_64)
      printf 'x86_64-apple-darwin\n'
      ;;
    Linux-aarch64)
      printf 'aarch64-unknown-linux-musl\n'
      ;;
    Linux-x86_64)
      printf 'x86_64-unknown-linux-musl\n'
      ;;
    *)
      echo "ERROR: unsupported platform for sccache install: $(uname -s)-$(uname -m)" >&2
      exit 1
      ;;
  esac
}

triple="$(platform_triple)"
archive_name="sccache-${version}-${triple}"
url="https://github.com/mozilla/sccache/releases/download/${version}/${archive_name}.tar.gz"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

mkdir -p "${dest_dir}"
curl -fsSL "${url}" | tar xz -C "${tmp_dir}"
install "${tmp_dir}/${archive_name}/sccache" "${dest_dir}/sccache"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "${dest_dir}" >> "${GITHUB_PATH}"
fi
"${dest_dir}/sccache" --version
