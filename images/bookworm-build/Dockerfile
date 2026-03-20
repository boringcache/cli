# syntax=docker/dockerfile:1
#
# ghcr.io/boringcache/base:bookworm-build
#
# Extends bookworm with compilation tools and development headers.
# Use as the build stage; use bookworm for the runtime stage.
#
# Usage:
#   FROM ghcr.io/boringcache/base:bookworm-build AS build
#   COPY mise.toml ./
#   RUN --mount=type=cache,target=/mise/cache mise install
#   ...
#
#   FROM ghcr.io/boringcache/base:bookworm
#   COPY --from=build /mise/installs /mise/installs
#   COPY --from=build /app /app
#   RUN mise reshim

ARG BORINGCACHE_TAG=bookworm
FROM ghcr.io/boringcache/base:${BORINGCACHE_TAG}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
      build-essential \
      pkg-config \
      autoconf \
      automake \
      libtool \
      libssl-dev \
      libyaml-dev \
      libffi-dev \
      libreadline-dev \
      libpq-dev \
      default-libmysqlclient-dev \
      libsqlite3-dev \
      zlib1g-dev \
      libjemalloc-dev && \
    rm -rf /var/lib/apt/lists /var/cache/apt/archives
