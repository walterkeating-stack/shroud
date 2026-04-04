# Plan: Extract Docker E2E Test Harness to Standalone Repo

## Problem

Two active Shroud branches (`main`, `feature/transformer`) each carry the full Docker E2E test harness. When test infra bugs are found — warmup requests, catch-all servers, `/etc/hosts` entries, Dockerfile peer deps — the same fixes must be applied independently to both branches. Today's session demonstrated this: all compat fixes landed on `main` but don't exist on `feature/transformer`.

The Docker E2E harness has **zero dependency on Shroud source code**. It installs Shroud from npm or a tarball and tests it as a black-box OpenClaw plugin. There is no reason for it to live inside the Shroud repo.

## Dependency Map

### Moves to `shroud-e2e` (zero Shroud source dependency)

| File | Lines | Role |
|------|-------|------|
| `compat/*` | — | Dockerfiles, shell scripts, versions.json |
| `tests/harness/harness/openclaw-runner.mjs` | 1,653 | Docker E2E test runner |
| `tests/harness/harness/security-runner.mjs` | 1,204 | Security extension E2E runner |
| `tests/harness/harness/reporter.mjs` | 98 | Test result formatter |
| `tests/harness/harness/scenarios/*.json` | 55 files | All scenario data |
| `tests/harness/lib/assertions.mjs` | 312 | CGNAT/ULA leak assertions |
| `tests/harness/mock-llm/server.mjs` | 588 | Multi-provider mock LLM |
| `tests/harness/mock-slack/*` | 3 files | Mock Slack API + HTTPS proxy |
| `tests/harness/mock-whatsapp/*` | 2 files | Mock WhatsApp + Baileys intercept |
| `tests/harness/mock-catchall/server.mjs` | 28 | Catch-all HTTP server |

### Stays in Shroud (imports Shroud source)

| File | Reason |
|------|--------|
| `tests/harness/harness/runner.mjs` | APP mode — spawns Shroud directly |
| `tests/harness/lib/app-client.mjs` | Imports `app-server.mjs` |
| `tests/harness/run.mjs` | Entry point — APP path needs Shroud |
| `tests/*.test.ts` | Vitest unit tests importing TypeScript source |

## New Repo Structure

```
shroud-e2e/
├── README.md
├── package.json
├── compat/
│   ├── Dockerfile.base
│   ├── Dockerfile.test          # modified: tarball OR npm install
│   ├── Dockerfile.sandbox
│   ├── entrypoint.sh
│   ├── run-compat.sh            # modified: accepts SHROUD_TGZ / SHROUD_REF
│   ├── run-matrix.sh
│   └── versions.json
├── harness/
│   ├── run.mjs                  # --openclaw mode only
│   ├── openclaw-runner.mjs
│   ├── security-runner.mjs
│   ├── reporter.mjs
│   └── scenarios/               # all 55 JSON files
├── lib/
│   └── assertions.mjs
├── mocks/
│   ├── llm/server.mjs
│   ├── slack/server.mjs, intercept.cjs, https-proxy.mjs
│   ├── whatsapp/server.mjs, intercept.cjs
│   └── catchall/server.mjs
└── .github/workflows/
    ├── compat.yml               # migrated from Shroud
    └── on-shroud-trigger.yml    # responds to Shroud CI dispatch
```

## Three Input Modes

### Mode A: npm version (default)

```bash
SHROUD_VERSION=latest ./compat/run-compat.sh 2026.3.28
```

Installs `shroud-privacy@${SHROUD_VERSION}` from npm inside the container. This is the current behavior.

### Mode B: local tarball

```bash
cd ~/shroud && npm run build && npm pack
SHROUD_TGZ=~/shroud/shroud-privacy-2.4.0.tgz ./compat/run-compat.sh 2026.3.28
```

Copies the `.tgz` into the Docker build context. `Dockerfile.test` detects it and installs from the tarball instead of npm.

### Mode C: git ref (CI)

```bash
SHROUD_REF=feature/transformer ./compat/run-compat.sh 2026.3.28
```

The script clones Shroud at that ref, runs `npm ci && npm run build && npm pack`, then proceeds as Mode B.

### Dockerfile.test change

```dockerfile
ARG SHROUD_SOURCE=latest
COPY shroud-privacy-*.tgz /tmp/
RUN if ls /tmp/shroud-privacy-*.tgz 1>/dev/null 2>&1; then \
      npm install -g /tmp/shroud-privacy-*.tgz; \
    else \
      npm install -g shroud-privacy@${SHROUD_SOURCE}; \
    fi
```

## CI Integration

### In `shroud-e2e`

**`compat.yml`** (migrated from Shroud):
- Daily cron: polls npm for new OC releases, tests against matrix
- Push to `shroud-e2e` main: runs minimum + latest OC
- Manual dispatch: specific version or full matrix

**`on-shroud-trigger.yml`** (new):
- Triggered by `repository_dispatch` from Shroud CI
- Receives `shroud_ref` and `shroud_sha` in payload
- Clones Shroud at that ref, builds, packs, runs matrix
- Reports status back via GitHub commit status API on the Shroud SHA

### In Shroud

Replace `compat.yml` with a lightweight dispatch trigger:

```yaml
name: E2E Trigger
on:
  push:
    branches: [main, feature/*]
    paths: ['src/**']
jobs:
  trigger-e2e:
    runs-on: ubuntu-latest
    steps:
      - run: |
          gh api repos/OWNER/shroud-e2e/dispatches \
            -f event_type=shroud-ci \
            -f client_payload[shroud_ref]=${{ github.ref }} \
            -f client_payload[shroud_sha]=${{ github.sha }}
        env:
          GH_TOKEN: ${{ secrets.E2E_DISPATCH_TOKEN }}
```

## Developer Workflow

### Local testing

Thin wrapper stays in Shroud at `compat/run-e2e.sh`:

```bash
#!/bin/bash
# Build Shroud, pack, invoke shroud-e2e harness
set -euo pipefail
npm run build
npm pack
TGZ=$(ls -t shroud-privacy-*.tgz | head -1)
E2E_DIR="${SHROUD_E2E_PATH:-../shroud-e2e}"
SHROUD_TGZ="$(pwd)/$TGZ" bash "$E2E_DIR/compat/run-compat.sh" "${1:-latest}"
```

### package.json

```json
"test:docker": "bash compat/run-e2e.sh latest"
```

`npm run test:docker` still works — builds Shroud, packs, calls external harness.

## Scenario Ownership

Scenarios live in `shroud-e2e`, not in Shroud.

Rationale:
- Pure JSON data, no code imports
- Test the installed-plugin contract, not internals
- Feature branches add companion scenario PRs to `shroud-e2e`
- Skip conditions handle features not present in all Shroud versions

When `feature/transformer` adds security-specific scenarios, those go into `shroud-e2e` with a feature gate (e.g., `"requireFeature": "security-extension"`). The runner checks if the feature is available and skips gracefully.

## versions.json Ownership

Moves to `shroud-e2e` — single source of truth. The daily cron auto-maintains it. Shroud's `package.json` can declare `"openclaw": { "minVersion": "2026.3.22" }` as a soft hint.

## Implementation Phases

### Phase 1: Create `shroud-e2e` repo

1. Create repo, copy all extractable files
2. Modify `run-compat.sh` for `SHROUD_TGZ` / `SHROUD_REF` env vars
3. Modify `Dockerfile.test` for tarball detection
4. Strip `run.mjs` to `--openclaw` mode only
5. Adjust `COPY` paths in Dockerfiles (harness is now at repo root, not `tests/harness/`)
6. Set up CI workflows
7. Verify: `SHROUD_VERSION=latest ./compat/run-compat.sh 2026.3.28` passes

### Phase 2: Wire Shroud CI

1. Add `compat/run-e2e.sh` wrapper to Shroud
2. Update `package.json` `test:docker`
3. Replace `compat.yml` with dispatch trigger
4. Add `E2E_DISPATCH_TOKEN` secret
5. Verify: push to `main` triggers `shroud-e2e` and reports status

### Phase 3: Remove duplicated harness from Shroud

1. Remove `compat/Dockerfile.*`, `entrypoint*.sh`, `run-compat.sh`, `run-matrix.sh`, `versions.json`
2. Remove `tests/harness/harness/openclaw-runner.mjs`, `security-runner.mjs`
3. Remove `tests/harness/mock-*` directories
4. Keep APP runner, `app-client.mjs`, reporter, unit tests

### Phase 4: Backport to `feature/transformer`

1. Same removal on `feature/transformer`
2. Add `compat/run-e2e.sh` wrapper
3. Merge transformer-specific scenarios into `shroud-e2e`
4. Verify: `SHROUD_REF=feature/transformer ./compat/run-compat.sh latest` passes

## Risks

| Risk | Mitigation |
|------|------------|
| Scenario drift (Shroud adds feature, forgets to add scenarios) | PR template checkbox; existing scenarios still catch regressions |
| Import path breakage after extraction | Proposed structure preserves all relative paths |
| `Dockerfile.test` COPY path change | Changes from `COPY tests/harness/` to `COPY harness/` — one-line fix |
| `entrypoint.sh` internal paths | Container paths stay identical; only Dockerfile COPY source changes |
| Two repos to maintain | Harness changes rarely; most development stays in Shroud |
