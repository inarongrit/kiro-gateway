# Forked APISIX dashboard

The portal at `https://<host>:9180/ui/` is the upstream APISIX dashboard plus our changes, served by the
Guardrail Console (behind its sign-in) instead of APISIX's bundled copy. The Admin API it calls is still
proxied to APISIX.

| Piece | What it is |
|---|---|
| `upstream.env` | Pinned upstream: `apache/apisix-dashboard@fa2fd0f`, the exact commit APISIX 3.19.0 ships (`APISIX_DASHBOARD_COMMIT` in apache/apisix `.requirements`), plus the pinned Node image and pnpm version |
| `patches/` | Our changes as a `git format-patch` series. **This is the source of truth for the fork** |
| `work/` | Generated working tree (git-ignored): upstream + patches, one commit per patch on branch `kiro` |
| `dist/` | Generated production build (git-ignored), mounted read-only into the console at `/dashboard` |

```bash
scripts/dashboard.sh prepare   # clone upstream @ pinned commit into dashboard/work, apply patches
# ...edit and `git commit` inside dashboard/work...
scripts/dashboard.sh save      # write commits upstream..kiro back to dashboard/patches/
scripts/dashboard.sh check     # eslint + tsc + vitest (in the pinned Node container)
scripts/dashboard.sh build     # production build -> dashboard/dist (live immediately; no restart)
```

If `dashboard/dist` is missing, the console falls back to proxying APISIX's own `/ui/`.

## Upgrading APISIX

1. Read the new release's `APISIX_DASHBOARD_COMMIT` from apache/apisix `.requirements` and set
   `UPSTREAM_COMMIT` in `upstream.env`.
2. `scripts/dashboard.sh prepare` — patches are applied with `git am --3way`. On a conflict, resolve in
   `dashboard/work`, `git -C dashboard/work am --continue`, then `scripts/dashboard.sh save`.
3. `scripts/dashboard.sh check && scripts/dashboard.sh build`, then run the portal tests.

Keep changes in new files (routes, components, API hooks, theme) and keep edits to upstream files small:
that is what keeps step 2 conflict-free.

Baseline at `fa2fd0f` with no patches: build is byte-identical to APISIX's bundled `/ui` (85/85 files);
lint clean, type check clean, 163/163 unit tests pass.
