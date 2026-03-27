# CLAUDE.md — Shroud Privacy Plugin

## What This Is

Shroud is a privacy obfuscation plugin for AI agents. It detects 100+ entity types (PII, network infra, credentials) and replaces them with deterministic format-preserving fakes before anything reaches the LLM. Responses are deobfuscated transparently so users and tools see real values.

- **Zero runtime dependencies** — uses only Node.js builtins

- Apache 2.0 license, published as `shroud-privacy` on npm
- Full fetch intercept with SSE per-block response deobfuscation
- Public URL filtering (DNS-based: external IPs pass through, RFC 1918/NXDOMAIN obfuscated; plus hardcoded list for YouTube, GitHub, etc.)
- APP server (`app-server.mjs`) + Python client for non-OpenClaw agents
- CLI stats tool (`shroud-stats`)
- Requires OpenClaw 2026.3.24+

> **Note:** The enterprise edition (`shroud-enterprise`) was archived read-only on 2026-03-27.
> Enterprise feature specs are preserved in `docs/enterprise-archive/` for future roadmap reference.
> This repo is the single source of truth.

## Commands

```bash
npm run build          # tsc → dist/
npm run lint           # tsc --noEmit (type-check only)
npm test               # All 3 suites: unit + harness + openclaw
npm run test:unit      # Vitest (777 tests)
npm run test:integration  # APP harness (359 tests)
npm run test:openclaw  # OpenClaw sandbox (14 tests)
npm run test:watch     # Vitest watch mode
```

## Architecture

### Core Pipeline (entirely synchronous — required for OpenClaw's sync-only hooks)

```
User input → detect (regex + context + code) → generate fakes (HMAC-SHA256) → replace
LLM response → reverse-map fakes → deobfuscate (up to 3 recursive passes)
```

### Key Files

| File | What it does |
|------|-------------|
| `src/index.ts` | Plugin entry point. Patches EventStream.prototype, registers fetch intercept, exposes shroud_status/shroud_reset tools |
| `src/hooks.ts` | 8 lifecycle hooks — the glue to OpenClaw. Includes fetch intercept (bidirectional privacy wall) |
| `src/obfuscator.ts` | Core engine. obfuscate/deobfuscate/reset/getStats. All sync |
| `src/dns-cache.ts` | DNS resolution cache for URL classification — public vs internal (RFC 1918) |
| `src/detectors/regex.ts` | 100+ regex patterns (1,345 lines). Built-in filters for docs, public URLs, DNS-based URL classification, masks |
| `src/detectors/context.ts` | Post-detection intelligence: proximity clustering, hostname propagation, learned entities |
| `src/generators/network.ts` | Format-preserving fakes: IPv4→CGNAT (100.64.0.0/10), IPv6→ULA (fd00::/8), subnet-aware deob |
| `src/config.ts` | Config resolver. Env vars > plugin config > defaults. 33 options |
| `src/store.ts` | Mapping store (real↔fake). LRU eviction support |
| `app-server.mjs` | APP server for non-OpenClaw agents. JSON-RPC over stdin/stdout |
| `clients/python/shroud_client.py` | Python client for APP |

### Fetch Intercept (the main innovation)

One `globalThis.fetch` wrapper handles everything:
- **Outbound**: Obfuscates all messages in LLM API requests (Anthropic, OpenAI, Google)
- **Inbound**: Deobfuscates SSE responses with per-block flushing (buffers text per content block, deobfuscates on `content_block_stop`)
- Re-obfuscates assistant messages from previous turns (multi-turn leak prevention)
- Strips Slack `<mailto:>` markup before obfuscation
- Zero OpenClaw file patches — pure runtime interception

### Deobfuscation Layers (4 backup paths)

1. Fetch response intercept (primary)
2. `EventStream.prototype.push()` patch
3. `globalThis.__shroudDeobfuscate` (called by OpenClaw before channel delivery)
4. `message_sending` hook (fallback)

## Release Workflow

Full chain (execute without stopping unless tests fail):
1. Bump version in `package.json` + `openclaw.plugin.json`
2. Update `CHANGELOG.md`
3. `npm run build`
4. `npm test` (all 3 suites)
5. Deploy locally (`./deploy-local.sh`)
6. Commit + tag (`vX.Y.Z`)
7. Push + push tags
8. GitHub release
9. `npm publish --provenance` (if publishing to npm)

## CI/CD

`.github/workflows/ci.yml`:
- Every push/PR: lint → test → build
- On `v*` tags: auto-publish to npm with Sigstore provenance (requires `NPM_TOKEN` secret)

## Testing Rules

- After ANY code change: build → unit tests → harness → openclaw sandbox. All green before reporting.
- Test sandbox must have 100% isolation: own OpenClaw copy, no host access, no network egress.
- Test adversarially — try to break it, don't just prove the happy path.

## Golden Baseline

**v2.2.2** is the gold standard. Do not regress:
- Fetch response deobfuscation with per-block SSE flushing
- Zero OpenClaw patches
- All channels confirmed (TUI, Slack, WhatsApp, CLI, multi-turn)
- 1,150 tests passing

**Do NOT**: add per-channel patches, use empty deltas, attempt incremental text_delta deob.

## Environment Variables

| Var | Purpose |
|-----|---------|
| `SHROUD_SECRET_KEY` | HMAC secret (auto-generated if unset) |
| `SHROUD_PERSISTENT_SALT` | Fixed salt for cross-session consistency |
| `SHROUD_STATS_FILE` | Stats dump path (default: `/tmp/shroud-stats.json`) |
| `SHROUD_PLUGIN_CONFIG` | JSON config for APP server |
