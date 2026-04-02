# Compat Testing Session — 2026-04-02

## Objective

Test Shroud compatibility against OpenClaw 2026.4.1 (released 2026-04-01) and verify backward compatibility with 2026.3.28.

## Test Results

| OC Version | Passed | Failed | Total | Notes |
|------------|--------|--------|-------|-------|
| 2026.3.28 | 182 | 10 | 192 | All TUI pass. Slack/WA E2E fail (missing deps in cached base image — fixable with `--rebuild-base`) |
| 2026.4.1 | 175 | 17 | 192 | 10 Slack/WA + 7 TUI failures from OC `://` dispatch bug |

## OC 2026.4.1 — `://` Dispatch Bug

### Summary

Any `sessions.create` message containing `://` (URLs, connection strings) causes the agent dispatch to silently fail. The session is created and `status: "started"` is returned, but the agent never runs — no hooks fire, no LLM call is made, the session transcript remains empty.

### Affected patterns

- `https://example.com` — FAIL
- `http://example.com` — FAIL
- `postgresql://host:5432/db` — FAIL
- `mysql://host:3306/db` — FAIL
- `mongodb://host:27017/db` — FAIL
- `example.com` (bare, no scheme) — OK
- `10.0.0.1:5432` (IP:port, no scheme) — OK
- `user@example.com` — OK
- `/usr/local/bin/test` — OK
- Plain text — OK

### Confirmed as OC bug (not Shroud)

Reproduced on bare OC 2026.4.1 with:
- No Shroud plugin
- No plugins at all
- No NODE_OPTIONS or intercepts
- Working mock LLM on localhost
- Bridge network (full DNS/internet access)

Plain text message → 6-line session (user message + LLM response).
URL message → 1-line session (session header only, empty).

### Verbose gateway analysis

With `--verbose`, a working (plain text) session produces:
```
preflightCompaction check → memoryFlush check → lane enqueue → lane dequeue →
embedded run start → before_prompt_build → embedded run prompt start →
context-diag → embedded run agent start → embedded run agent end →
session state: processing → idle → run cleared → embedded run done
```

A failing (URL) session produces: nothing. Zero diagnostic output after `sessions.create` returns. The `dispatchInboundMessage` call appears to silently fail before any agent infrastructure is invoked.

### Not network-related

Tested with:
- `/etc/hosts` entries for all test domains → still fails
- iptables DNAT (all outbound TCP → 127.0.0.1) → still fails
- Catch-all HTTP server on port 80 → still fails
- Bridge network with real DNS → still fails

The bug is in OC's dispatch code path, not in DNS/network resolution.

## Test Infrastructure Changes (main branch)

All changes are test infra only — zero core Shroud modifications.

### `compat/Dockerfile.base`
- Added `iptables` package
- Added `@slack/web-api@7`, `@slack/bolt@4`, `@aws-sdk/client-bedrock@3` as optional peer deps (OC 2026.4.1 tries to lazy-load bundled extensions; without these deps, extension load failures flood stderr)

### `compat/run-compat.sh`
- Added `--cap-add=NET_ADMIN` for iptables support

### `compat/entrypoint.sh`
- Added `/etc/hosts` entries for external domains used in test scenarios
- Added iptables DNAT rules (outbound TCP → 127.0.0.1) to prevent hangs on `--internal` network

### `tests/harness/harness/openclaw-runner.mjs`
- Added warmup request before test batch (fixes first-test race on OC 2026.4.1 where gateway is still loading extensions)
- Added `plugins.allow: ["shroud-privacy"]` to config
- Added catch-all HTTP server startup on port 80
- Enhanced "0 requests" error message to include `[agent-response]` for diagnostics
- Added `mockCatchAllProc` lifecycle (constructor, teardown)

### `tests/harness/mock-catchall/server.mjs`
- New file: minimal HTTP server returning 200 for any request (catches OC's URL processing fetches)

## Open Issues

### 1. OC 2026.4.1 `://` dispatch bug — BLOCKER for 2026.4.1 support

Messages containing `://` silently dropped. Confirmed on bare OC without any plugins. Need OC fix before we can support 2026.4.1.

**Action:** File OC issue with repro steps.

### 2. Slack/WhatsApp E2E failures on OC 2026.3.28 (cached base image)

The cached base image for 2026.3.28 doesn't have `@slack/web-api` installed. Rebuilding with `--rebuild-base` would fix this. Not a code issue.

**Action:** Rebuild 2026.3.28 base image with Slack/Bedrock deps, or accept as infra-only.

### 3. Deployed v2.4.0 has security extension transformer (prod issue)

The locally deployed Shroud v2.4.0 includes the security extension's transformer sequence predictor from `feature/security-extension`. The transformer retrains synchronously, blocking the Node.js event loop for 6+ minutes per retrain cycle. This causes all agent sessions to go stuck (`state=processing`) and channels (Slack, WhatsApp) to timeout.

**Action:** Redeploy from main branch, which does not include the transformer. The security extension should not ship in v2.4.0 — it belongs on the feature branch.

### 4. `versions.json` needs 2026.4.1 entry

Add 2026.4.1 as `"status": "blocked"` with the `://` bug documented.

**Action:** Update `versions.json`.
