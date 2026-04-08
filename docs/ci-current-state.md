# CI Current State

Last updated: 2026-04-08

## Shroud (`wkeything/shroud`)

### Workflow: `.github/workflows/compat.yml`
- Status: intentionally disabled for hosted/private Actions cost control.
- Current behavior:
  - manual placeholder only (`workflow_dispatch`).
  - points operators to local compat execution.

### Workflow: `.github/workflows/ci.yml`
- Purpose: lint/test/build and npm publish.
- Publish behavior:
  - Publishes only when `package.json` version is not yet on npm.
  - Validates tag version matches `package.json` on `v*` tag runs.
  - Runs on Node 24 with `actions/*@v5`.

## Local Compatibility Workflow (authoritative)

### Script: `compat/run-compat.sh`
- Scope:
  - works for `main` and `feature/transformer`.
  - always tests local packed Shroud tarball (not npm fallback).
- OpenClaw matrix policy:
  - test `latest` from npm.
  - test last validated baseline (`2026.3.28`).
  - explicit release-target checks may pin a specific OpenClaw version before publish.
- Focused checks supported via env:
  - `SHROUD_SCENARIO='WhatsApp E2E' bash compat/run-compat.sh 2026.3.28`
  - `SHROUD_SCENARIO='Slack E2E' bash compat/run-compat.sh latest --rebuild-base`
- Latest-channel compatibility handling:
  - OpenClaw `2026.4.7` was explicitly validated on the Slack E2E path for release `2.2.18`.
  - harness auto-skips WhatsApp E2E only when channel provisioning is unavailable.
- Base image hardening for latest OpenClaw lazy deps:
  - installs optional deps used by bundled channels (`@slack/web-api`, `@slack/bolt`,
    `@aws-sdk/client-bedrock`, `@buape/carbon`, `@larksuiteoapi/node-sdk`, `grammy`).

## Branch Rules

- `main`:
  - lint, unit, integration, build, local compat matrix validation.
  - npm publish allowed.
- `feature/transformer`:
  - same local validation path.
  - no publish to npm or merge to `main` without explicit promotion.

## Quick Verification
1. `npm ci && npm run lint && npm run test:unit && npm run test:integration && npm run build`
2. `SHROUD_SCENARIO='WhatsApp E2E' bash compat/run-compat.sh 2026.3.28`
3. `SHROUD_SCENARIO='Slack E2E' bash compat/run-compat.sh 2026.4.7 --rebuild-base`
