# syntax=docker/dockerfile:1
#
# Production Next.js Dockerfile — mise for tools, boringcache for caching.
#
# Build with caching (restore + save):
#   docker build --secret id=bc_token,env=BORINGCACHE_API_TOKEN -t my-app .
#
# Build without caching:
#   docker build -t my-app .
#
# Requires output: "standalone" in next.config.ts.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM ghcr.io/boringcache/base:bookworm-build AS build
WORKDIR /app

COPY mise.toml ./
RUN --mount=type=cache,target=/mise/cache \
    mise install

COPY package.json yarn.lock ./
RUN --mount=type=secret,id=bc_token \
    boringcache run my-org/my-app node_modules:node_modules -- \
    yarn install --frozen-lockfile

COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN yarn build

# ---------------------------------------------------------------------------
# Runtime stage — standalone output, minimal image
# ---------------------------------------------------------------------------
FROM ghcr.io/boringcache/base:bookworm
WORKDIR /app

COPY --from=build /mise/installs/node /mise/installs/node
COPY mise.toml ./
RUN mise reshim

ENV NODE_ENV="production" \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

COPY --from=build /app/public ./public
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static

RUN groupadd --system --gid 1000 app && \
    useradd app --uid 1000 --gid 1000 --create-home --shell /bin/bash
USER 1000:1000

EXPOSE 3000
CMD ["node", "server.js"]
