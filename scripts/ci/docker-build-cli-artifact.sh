#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: scripts/ci/docker-build-cli-artifact.sh \
  --rust-version VERSION \
  --target TARGET \
  --output-path PATH \
  --workspace WORKSPACE \
  --cache-tag TAG \
  --sccache-version VERSION \
  [--musl-crt-static]
EOF
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

log() {
  printf '%s\n' "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

append_env_flag() {
  value="$1"
  flag="$2"
  if [ -n "$value" ]; then
    printf '%s %s' "$value" "$flag"
  else
    printf '%s' "$flag"
  fi
}

install_rust_toolchain() {
  if [ -f /etc/alpine-release ]; then
    apk add --no-cache bash build-base ca-certificates curl make musl-dev perl tar xz
  elif [ -f /etc/debian_version ]; then
    apt-get update
    apt-get install -y bash build-essential pkg-config libssl-dev curl ca-certificates xz-utils
  else
    fail "unsupported container image; expected Alpine or Debian"
  fi

  export PATH="/usr/local/cargo/bin:$HOME/.cargo/bin:$PATH"
  if ! has_cmd cargo; then
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "$RUST_VERSION"
  fi
}

ensure_rust_environment() {
  export PATH="/usr/local/cargo/bin:$HOME/.cargo/bin:$PATH"

  if ! has_cmd bash || ! has_cmd cargo; then
    install_rust_toolchain
  fi

  has_cmd rustup || fail "rustup is required after toolchain installation"
  rustup target add "$TARGET"
}

install_sccache_if_needed() {
  has_cmd sccache && return 0

  arch="$(uname -m)"
  case "$arch" in
    x86_64) sccache_arch="x86_64" ;;
    aarch64|arm64) sccache_arch="aarch64" ;;
    *)
      log "::warning::unsupported sccache architecture: ${arch}"
      return 0
      ;;
  esac

  archive_dir="/tmp/sccache-${SCCACHE_VERSION}-${sccache_arch}-unknown-linux-musl"
  archive_url="https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-${sccache_arch}-unknown-linux-musl.tar.gz"

  if curl -fsSL "$archive_url" | tar xz -C /tmp; then
    mv "${archive_dir}/sccache" /usr/local/bin/sccache
    chmod +x /usr/local/bin/sccache
  else
    log "::warning::failed to install sccache from ${archive_url}"
  fi
}

bootstrap_boringcache_binary() {
  bootstrap_target_dir="/tmp/boringcache-bootstrap-target"
  binary_path="${bootstrap_target_dir}/debug/boringcache"

  log "bootstrapping current boringcache CLI for adapter build"
  if ! cargo build --locked --target-dir "$bootstrap_target_dir" --bin boringcache >/dev/null; then
    log "::warning::failed to build bootstrap boringcache binary"
    return 1
  fi

  if [ -x "$binary_path" ]; then
    printf '%s\n' "$binary_path"
    return 0
  fi

  return 1
}

run_release_build() {
  flow_mode="plain"
  boringcache_binary=""

  if has_cmd sccache; then
    sccache --version >&2 || true
    if boringcache_binary="$(bootstrap_boringcache_binary)"; then
      flow_mode="boringcache"
    else
      log "::warning::failed to bootstrap current boringcache CLI; building without proxy-backed sccache"
    fi
  else
    log "::warning::sccache unavailable; building without proxy-backed sccache"
  fi

  if [ "$MUSL_CRT_STATIC" = "1" ]; then
    export RUSTFLAGS="$(append_env_flag "${RUSTFLAGS:-}" "-C target-feature=+crt-static")"
  fi

  if [ "$flow_mode" = "boringcache" ]; then
    export BORINGCACHE_CARGO_FLOW_BINARY="$boringcache_binary"
    export BORINGCACHE_CARGO_FLOW_MODE="boringcache"
    export BORINGCACHE_CARGO_WORKSPACE="$WORKSPACE"
    export BORINGCACHE_CARGO_PROXY_TAG="$CACHE_TAG"
    export BORINGCACHE_CARGO_PROXY_PORT="${BORINGCACHE_CARGO_PROXY_PORT:-4227}"
    # The sccache daemon speaks its own protocol; keep it off the proxy port.
    export SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-4228}"
  else
    export BORINGCACHE_CARGO_FLOW_MODE="plain"
  fi

  bash ./scripts/cargo-flow.sh build --release --target "$TARGET"
}

copy_artifact() {
  target_dir="${CARGO_TARGET_DIR:-$(pwd)/target}"
  artifact_path="${target_dir}/${TARGET}/release/boringcache"

  [ -f "$artifact_path" ] || fail "expected built artifact at ${artifact_path}"

  mkdir -p "$(dirname "$OUTPUT_PATH")"
  cp "$artifact_path" "$OUTPUT_PATH"
  chmod +x "$OUTPUT_PATH"
}

RUST_VERSION=""
TARGET=""
OUTPUT_PATH=""
WORKSPACE=""
CACHE_TAG=""
SCCACHE_VERSION=""
MUSL_CRT_STATIC="0"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --rust-version)
      [ "$#" -ge 2 ] || fail "missing value for --rust-version"
      RUST_VERSION="$2"
      shift 2
      ;;
    --target)
      [ "$#" -ge 2 ] || fail "missing value for --target"
      TARGET="$2"
      shift 2
      ;;
    --output-path)
      [ "$#" -ge 2 ] || fail "missing value for --output-path"
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --workspace)
      [ "$#" -ge 2 ] || fail "missing value for --workspace"
      WORKSPACE="$2"
      shift 2
      ;;
    --cache-tag)
      [ "$#" -ge 2 ] || fail "missing value for --cache-tag"
      CACHE_TAG="$2"
      shift 2
      ;;
    --sccache-version)
      [ "$#" -ge 2 ] || fail "missing value for --sccache-version"
      SCCACHE_VERSION="$2"
      shift 2
      ;;
    --musl-crt-static)
      MUSL_CRT_STATIC="1"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[ -n "$RUST_VERSION" ] || fail "--rust-version is required"
[ -n "$TARGET" ] || fail "--target is required"
[ -n "$OUTPUT_PATH" ] || fail "--output-path is required"
[ -n "$WORKSPACE" ] || fail "--workspace is required"
[ -n "$CACHE_TAG" ] || fail "--cache-tag is required"
[ -n "$SCCACHE_VERSION" ] || fail "--sccache-version is required"

ensure_rust_environment
install_sccache_if_needed
run_release_build
copy_artifact
