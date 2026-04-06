# CI Current State

Last updated: 2026-04-06

## Shroud (`wkeything/shroud`)

### Workflow: `.github/workflows/compat.yml`
- Purpose: dispatch E2E compatibility runs to `wkeything/shroud-e2e`.
- Triggers:
  - `push` to `main` and `feature/*` when matching paths change.
  - `workflow_dispatch` manual trigger.
- Required secret:
  - `E2E_DISPATCH_TOKEN` (must be able to dispatch workflows in `wkeything/shroud-e2e`).
- Behavior:
  - Fails fast with explicit error if `E2E_DISPATCH_TOKEN` is missing.
  - On success, sends `repository_dispatch` payload: `shroud_ref`, `shroud_repo`, `shroud_sha`.

### Workflow: `.github/workflows/ci.yml`
- Purpose: lint/test/build and npm publish.
- Publish behavior:
  - Publishes only when `package.json` version is not yet on npm.
  - Validates tag version matches `package.json` on `v*` tag runs.

## Shroud E2E (`wkeything/shroud-e2e`)

### Workflow: `.github/workflows/on-shroud-trigger.yml`
- Purpose: receive dispatch from Shroud, test compat matrix, and report commit status.
- Triggered by:
  - `repository_dispatch` (`event_type: shroud-ci`)
  - optional `workflow_dispatch`
- Version selection:
  - tests `latest OpenClaw from npm` + `last validated from compat/versions.json`.
- Clone behavior:
  - uses `SHROUD_STATUS_TOKEN` if present, otherwise public HTTPS clone.
- Status reporting:
  - posts status back to Shroud commit when `SHROUD_STATUS_TOKEN` is configured.

### Required secret
- `SHROUD_STATUS_TOKEN`
  - must be able to set commit status on `wkeything/shroud`.

## Known Current Outcome
- Dispatch and status plumbing are functional.
- Current compat test path can still fail on scenario/test issues (separate from CI wiring).

## Quick Verification
1. Trigger `compat.yml` in `wkeything/shroud` on `main`.
2. Confirm `on-shroud-trigger.yml` run appears in `wkeything/shroud-e2e`.
3. Confirm commit status `shroud-e2e/compat` appears on target Shroud commit.
