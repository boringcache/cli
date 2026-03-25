# syntax=docker/dockerfile:1
# check=error=true
#
# Production Rails Dockerfile — mise for tools, boringcache for caching.
#
# Build with caching (restore + save — recommended for main branch):
#   docker build --secret id=bc_token,env=BORINGCACHE_API_TOKEN -t my-app .
#
# Build with restore-only caching (safer for PRs / forks):
#   docker build --secret id=bc_token,env=BORINGCACHE_RESTORE_TOKEN -t my-app .
#
# Build without caching (same Dockerfile, no token needed):
#   docker build -t my-app .
#
# The CLI auto-detects /run/secrets/bc_token when mounted as a BuildKit secret.
# With a save-capable token, updated deps are pushed back to cache.
# With a restore-only token, saves are silently skipped.
# With no token at all, boringcache run skips caching and runs the command directly.
#
# Tool versions live in mise.toml — the same file used in local dev and CI.
# No version numbers in this Dockerfile.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM ghcr.io/boringcache/base:bookworm-build AS build
WORKDIR /rails

# 1. Install tools — cached across builds via boringcache
COPY mise.toml .ruby-version ./
RUN --mount=type=secret,id=bc_token \
    --mount=type=cache,target=/mise/cache \
    boringcache run my-org/my-app mise-installs:/mise/installs --no-platform --no-git -- \
    mise install

# 2. Install gems — cached across builds via boringcache
ENV BUNDLE_DEPLOYMENT="1" \
    BUNDLE_PATH="/usr/local/bundle" \
    BUNDLE_WITHOUT="development"

COPY Gemfile Gemfile.lock ./
RUN --mount=type=secret,id=bc_token \
    boringcache run my-org/my-app bundler:/usr/local/bundle --no-platform --no-git -- \
    bundle install && \
    rm -rf ~/.bundle/ "${BUNDLE_PATH}"/ruby/*/cache "${BUNDLE_PATH}"/ruby/*/bundler/gems/*/.git && \
    bundle exec bootsnap precompile -j 1 --gemfile

# 3. Install node modules — cached across builds via boringcache
COPY package.json yarn.lock ./
RUN --mount=type=secret,id=bc_token \
    boringcache run my-org/my-app node_modules:node_modules --no-platform --no-git -- \
    yarn install --frozen-lockfile

# 4. Copy source and compile (changes every commit — last for cache efficiency)
COPY . .

# -j 1 avoids a QEMU bug in multi-arch builds (bootsnap#495)
RUN bundle exec bootsnap precompile -j 1 app/ lib/

RUN SECRET_KEY_BASE_DUMMY=1 ./bin/rails assets:precompile && \
    rm -rf node_modules

# ---------------------------------------------------------------------------
# Runtime stage — no build tools, no boringcache, minimal footprint
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
