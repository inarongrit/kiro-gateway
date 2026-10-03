#!/usr/bin/env bash
# Forked APISIX dashboard: upstream pinned in dashboard/upstream.env + our changes as a patch series
# in dashboard/patches/ (git format-patch). The working tree dashboard/work/ is generated (git-ignored).
#
#   scripts/dashboard.sh prepare   clone upstream at the pinned commit into dashboard/work and apply patches
#                                  (each patch becomes one commit on branch 'kiro' over tag 'upstream')
#   scripts/dashboard.sh save      regenerate dashboard/patches/ from the commits in dashboard/work
#   scripts/dashboard.sh build     reproducible production build in Docker -> dashboard/dist (served at /ui/)
#   scripts/dashboard.sh check     lint + type check + unit tests in Docker
#   scripts/dashboard.sh run ARGS  any pnpm command in the pinned container (e.g. run add -E pkg@1.2.3)
set -euo pipefail
cd "$(dirname "$0")/.."
D=dashboard; W=$D/work
source $D/upstream.env
GIT=(git -C "$W" -c user.name="Kiro Gateway" -c user.email="kiro-gateway@localhost" -c advice.detachedHead=false)

prepare() {
  if [[ ! -d $W/.git ]]; then
    git init -q "$W"; "${GIT[@]}" remote add origin "$UPSTREAM_REPO"
  fi
  "${GIT[@]}" fetch -q --depth 1 origin "$UPSTREAM_COMMIT"
  "${GIT[@]}" checkout -q -B kiro FETCH_HEAD
  "${GIT[@]}" tag -f upstream FETCH_HEAD >/dev/null
  shopt -s nullglob; local patches=($D/patches/*.patch)
  if (( ${#patches[@]} )); then
    "${GIT[@]}" am -q --3way "${patches[@]/#/$PWD/}" || {
      echo "patch conflict: resolve in $W, then 'git -C $W am --continue' and run '$0 save'" >&2; exit 1; }
  fi
  echo "prepared $W at upstream $(cut -c1-7 <<<"$UPSTREAM_COMMIT") + ${#patches[@]} patch(es)"
}

save() {
  [[ -n "$("${GIT[@]}" status --porcelain)" ]] && { echo "commit your changes in $W first" >&2; exit 1; }
  rm -f $D/patches/*.patch; mkdir -p $D/patches
  "${GIT[@]}" format-patch -q --no-signature --zero-commit -N -o "$PWD/$D/patches" upstream..kiro
  ls $D/patches
}

in_node() {   # run a command in the pinned Node image against dashboard/work (as the host user)
  mkdir -p $D/.cache/pnpm-store
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e COREPACK_HOME=/tmp/corepack -e CI=true \
    -e HUSKY=0 -v "$PWD/$W:/src" -v "$PWD/$D/.cache/pnpm-store:/pnpm-store" -w /src "$NODE_IMAGE" \
    bash -euo pipefail -c "mkdir -p /tmp/bin && corepack enable --install-directory /tmp/bin pnpm && export PATH=/tmp/bin:\$PATH && \
             pnpm config set store-dir /pnpm-store && pnpm install --frozen-lockfile --ignore-scripts --reporter=silent && $1"
}

build() {
  [[ -d $W/.git ]] || prepare
  # `vite build` first regenerates src/routeTree.gen.ts (TanStack router plugin) so the
  # type check in `pnpm build` (tsc -b && vite build) sees routes added by our patches.
  in_node "pnpm exec vite build --logLevel error >/dev/null && pnpm build"
  # Replace the CONTENTS of dashboard/dist, never the directory itself: the console bind-mounts
  # it, and a new directory inode would leave the running container serving a deleted folder.
  mkdir -p $D/dist && find $D/dist -mindepth 1 -delete && cp -r $W/dist/. $D/dist/
  echo "built $D/dist ($(du -sh $D/dist | cut -f1)) from $("${GIT[@]}" describe --always --tags)"
}

check() { in_node "pnpm exec vite build --logLevel error >/dev/null && pnpm lint && pnpm exec tsc -b && pnpm test -- --run"; }

run() { shift; in_node "pnpm $*"; }   # e.g. scripts/dashboard.sh run add -E some-pkg@1.2.3

case "${1:-}" in prepare|save|build|check) "$1";; run) run "$@";; *) sed -n 2,12p "$0"; exit 2;; esac
