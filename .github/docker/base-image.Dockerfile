ARG BASE_IMAGE=alpine:3.21
FROM ${BASE_IMAGE}

ARG RUST_VERSION
ARG RUST_TARGET
ARG SCCACHE_VERSION=v0.14.0

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:/usr/local/bin:${PATH}

RUN set -eux; \
    apk add --no-cache \
      bash \
      build-base \
      ca-certificates \
      curl \
      make \
      musl-dev \
      perl \
      tar \
      xz

RUN set -eux; \
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "${RUST_VERSION}"; \
    rustup target add "${RUST_TARGET}"

RUN set -eux; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      x86_64) sccache_arch="x86_64" ;; \
      aarch64|arm64) sccache_arch="aarch64" ;; \
      *) echo "unsupported sccache architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-${sccache_arch}-unknown-linux-musl.tar.gz" | tar xz -C /tmp; \
    mv "/tmp/sccache-${SCCACHE_VERSION}-${sccache_arch}-unknown-linux-musl/sccache" /usr/local/bin/sccache; \
    chmod +x /usr/local/bin/sccache; \
    sccache --version
