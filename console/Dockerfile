# syntax=docker/dockerfile:1.7
# Guardrail Console + Kiro Gateway portal in one image. Build from the REPO ROOT:
#   docker build -f console/Dockerfile -t kiro-gateway-console .
# Stage 1 builds the forked APISIX dashboard from the pinned upstream commit + dashboard/patches
# (same steps as scripts/dashboard.sh build); stage 2 is the runtime (FastAPI behind uvicorn TLS).
# Base images are pinned by digest; bump tag + digest together.

# ---- stage 1: portal (forked APISIX dashboard) -------------------------------------------------
FROM node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7 AS portal
ARG UPSTREAM_REPO=https://github.com/apache/apisix-dashboard.git
ARG UPSTREAM_COMMIT=fa2fd0f60f8afffb096476333b9ba63b4c518fa3
ARG PNPM_VERSION=10.34.4
ENV CI=true HUSKY=0 COREPACK_ENABLE_DOWNLOAD_PROMPT=0
WORKDIR /src
RUN git init -q . \
 && git -c advice.detachedHead=false fetch -q --depth 1 "$UPSTREAM_REPO" "$UPSTREAM_COMMIT" \
 && git checkout -q FETCH_HEAD
COPY dashboard/patches/ /patches/
RUN git -c user.name=build -c user.email=build@localhost am -q /patches/*.patch \
 && corepack enable && corepack prepare "pnpm@${PNPM_VERSION}" --activate
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts --reporter=silent \
 # vite build first regenerates src/routeTree.gen.ts so tsc -b sees the routes our patches add
 && pnpm exec vite build --logLevel error >/dev/null \
 && pnpm build

# ---- stage 2: runtime --------------------------------------------------------------------------
FROM python:3.12.15-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
# jq/gettext/curl/git/grep: scripts/build-policy.sh + apply.sh (run by the console on rule save),
# the PCRE pattern check (grep -P) and the rule history (git, in the data dir).
# Debian packages are not version-pinned, and pending bookworm security updates are applied
# (the pinned base can lag behind them); reproducibility comes from the digest-pinned base image
# and a rebuild + Trivy scan in CI on every release.
# hadolint ignore=DL3005,DL3008
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends jq gettext-base curl git ca-certificates grep \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /console
COPY console/requirements.lock requirements.txt
# Hash-pinned lock (uv pip compile --generate-hashes console/requirements.in): nothing unpinned installs.
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt
COPY console/app ./app
COPY console/web ./web
COPY --from=portal /src/dist /dashboard
# Runs as uid 1000 so files it writes in the bind-mounted data dir keep the host user's ownership.
USER 1000:1000
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
EXPOSE 9200
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["curl", "-fsS", "-o", "/dev/null", "--cacert", "/etc/kiro-gateway/ca.crt", "https://localhost:9200/api/health"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9200", \
     "--ssl-certfile", "/tls/admin.crt", "--ssl-keyfile", "/tls/admin.key", \
     "--no-server-header", "--no-proxy-headers"]
