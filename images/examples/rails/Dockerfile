# syntax=docker/dockerfile:1
# check=error=true
#
# Production Rails Dockerfile — mise for tools.
#
# Build locally:
#   docker build -t my-app .
#
# CI build caching is configured with BuildKit registry-cache refs.
#
# Tool versions live in mise.toml — the same file used in local dev and CI.
# No version numbers in this Dockerfile.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM ghcr.io/boringcache/base:bookworm-build AS build
WORKDIR /rails

# 1. Install tools
COPY mise.toml .ruby-version ./
RUN --mount=type=cache,target=/mise/cache \
    mise install

# 2. Install gems
ENV BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development"

COPY Gemfile Gemfile.lock ./
RUN bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git && \
    bundle exec bootsnap precompile -j 1 --gemfile

# 3. Install node modules
COPY package.json yarn.lock ./
RUN --mount=type=cache,target=/usr/local/share/.cache/yarn \
    yarn install --frozen-lockfile

# 4. Copy source and compile (changes every commit — last for cache efficiency)
COPY . .

# -j 1 avoids a QEMU bug in multi-arch builds (bootsnap#495)
RUN bundle exec bootsnap precompile -j 1 app/ lib/

RUN SECRET_KEY_BASE_DUMMY=1 ./bin/rails assets:precompile && \
    rm -rf node_modules

# ---------------------------------------------------------------------------
# Runtime stage — no build tools, minimal footprint
# ---------------------------------------------------------------------------
FROM ghcr.io/boringcache/base:bookworm
WORKDIR /rails

RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
      curl libjemalloc2 libvips libpq5 && \
    ln -s /usr/lib/*-linux-gnu/libjemalloc.so.2 /usr/local/lib/libjemalloc.so && \
    rm -rf /var/lib/apt/lists

# Bring tool installs from build stage (no download — instant)
COPY --from=build /mise/installs /mise/installs
COPY --from=build /rails/mise.toml ./mise.toml
RUN mise reshim

ENV RAILS_ENV="production" \
    BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development" \
    LD_PRELOAD="/usr/local/lib/libjemalloc.so"

RUN groupadd --system --gid 1000 rails && \
    useradd rails --uid 1000 --gid 1000 --create-home --shell /bin/bash

COPY --chown=rails:rails --from=build "${BUNDLE_PATH}" "${BUNDLE_PATH}"
COPY --chown=rails:rails --from=build /rails /rails

USER 1000:1000

ENTRYPOINT ["/rails/bin/docker-entrypoint"]
EXPOSE 80
CMD ["./bin/thrust", "./bin/rails", "server"]
