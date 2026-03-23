# syntax=docker/dockerfile:1
#
# ghcr.io/boringcache/base:bookworm
#
# Minimal Debian Bookworm with mise and boringcache CLI.
# Tool versions come from your project's mise.toml — not from this image.
#
# Usage:
#   FROM ghcr.io/boringcache/base:bookworm
#   WORKDIR /app
#   COPY mise.toml ./
#   RUN mise install
#
# With boringcache caching in a Dockerfile:
#   RUN --mount=type=secret,id=bc_token \
#       boringcache run my-org/app deps:node_modules -- npm ci
#
# Pass the token via BuildKit secret (never baked into any layer):
#   docker build --secret id=bc_token,env=BORINGCACHE_API_TOKEN .
#
# The CLI auto-detects /run/secrets/bc_token when mounted as a BuildKit secret.
# With a save-capable token, updated deps are pushed back to cache.
# With a restore-only token, saves are silently skipped.
# With no token at all, cache ops are skipped and the command runs directly.

FROM debian:bookworm-slim

ARG MISE_VERSION=2026.3.8
ARG BORINGCACHE_VERSION=v1.12.7
ARG TARGETARCH
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
      ca-certificates \
      curl \
      git && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

# mise — polyglot tool version manager
# Direct binary download with pinned version for reproducibility.
# TARGETARCH (amd64/arm64) is mapped to mise's naming convention (x64/arm64).
RUN MISE_ARCH=$(case "${TARGETARCH}" in amd64) echo "x64";; arm64) echo "arm64";; *) echo "Unsupported: ${TARGETARCH}" >&2; exit 1;; esac) && \
    curl -fsSL "https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${MISE_ARCH}" -o /usr/local/bin/mise && \
    chmod +x /usr/local/bin/mise

ENV MISE_DATA_DIR="/mise" \
    MISE_CACHE_DIR="/mise/cache" \
    MISE_YES="1" \
    MISE_SELF_UPDATE_AVAILABLE="false" \
    PATH="/mise/shims:/usr/local/bin:${PATH}"

RUN mkdir -p /mise/shims /mise/cache

# boringcache CLI — content-addressed artifact cache
# Auto-detects /run/secrets/bc_token for Docker BuildKit secret mounts.
# Falls back to running commands directly when no token is available.
RUN curl -fsSL "https://github.com/boringcache/cli/releases/download/${BORINGCACHE_VERSION}/boringcache-linux-${TARGETARCH}" \
      -o /usr/local/bin/boringcache && \
    chmod +x /usr/local/bin/boringcache
