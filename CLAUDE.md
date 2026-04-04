# CLAUDE.md — Shroud Privacy Plugin

## What This Is

Shroud is a privacy obfuscation plugin for AI agents. It detects 100+ entity types (PII, network infra, credentials) and replaces them with deterministic format-preserving fakes before anything reaches the LLM. Responses are deobfuscated transparently so users and tools see real values.

- **Zero runtime dependencies** — uses only Node.js builtins

- Apache 2.0 license, published as `shroud-privacy` on npm
- Full fetch intercept with SSE per-block response deobfuscation
- Public URL filtering (DNS-based: external IPs pass through, RFC 1918/NXDOMAIN obfuscated; plus hardcoded list for YouTube, GitHub, etc.)
- APP server (`app-server.mjs`) + Python client for non-OpenClaw agents
- CLI stats tool (`shroud-stats`)
- Requires OpenClaw 2026.3.22+

> **Note:** The enterprise edition (`shroud-enterprise`) was archived read-only on 2026-03-27.
> Enterprise feature specs are preserved in `docs/enterprise-archive/` for future roadmap reference.
> This repo is the single source of truth.

## Commands

```bash
npm run build             # tsc → dist/
npm run lint              # tsc --noEmit (type-check only)
npm test                  # unit + harness (2,119 tests, no Docker needed)
npm run test:unit         # Vitest (1,760 tests)
npm run test:integration  # APP harness (359 tests)
npm run test:docker       # Docker E2E (192 tests, needs Docker)
npm run test:all          # All 3 layers (2,311 tests)
npm run pretrain          # Seed transformer weights from testbed
npm run test:watch        # Vitest watch mode
```

### Docker E2E (compat pipeline)

```bash
bash compat/run-compat.sh 2026.3.24        # Test against specific OC version
bash compat/run-compat.sh latest           # Test against latest OC release
bash compat/run-compat.sh latest --rebuild-base  # Force rebuild base image
bash compat/run-matrix.sh                  # Interactive: current or current + last 3
bash compat/run-matrix.sh --parallel       # All versions in parallel
bash compat/run-matrix.sh --latest 3       # Latest 3 versions only
bash compat/run-compat.sh latest --sandbox  # Sandbox exec tests (DinD)
SHROUD_VERSION=2.2.8 bash compat/run-compat.sh latest  # Specific Shroud version
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
| `src/security-event.ts` | SecurityEvent interface, ThreatClass enum, SecurityEventBus (in-memory event accumulator) |
| `src/detectors/injection.ts` | Injection detection engine — 40+ signatures for prompt injection, data exfil, encoding bypass |
| `src/profiler.ts` | Behavioural profiler — learns agent patterns, detects anomalies |
| `src/adaptive-thresholds.ts` | Per-agent detection threshold tuning from profiler baselines |
| `src/rule-suggestions.ts` | Auto-generated firewall rules from event patterns |
| `src/dashboard.ts` | Security dashboard (HTTP server on port 9380) — 7-tab UI: Overview, Firewall Rules, Signatures, Transformer, Events, Tripwires, Timeline |
| `src/policy.ts` | Per-agent security policy engine — allowlists, severity overrides |
| `src/config.ts` | Config resolver. Env vars > plugin config > defaults. 33 options |
| `src/store.ts` | Mapping store (real↔fake). LRU eviction support |
| `app-server.mjs` | APP server for non-OpenClaw agents. JSON-RPC over stdin/stdout |
| `clients/python/shroud_client.py` | Python client for APP |
| `compat/` | Docker-based OpenClaw compatibility pipeline (Dockerfiles, scripts, version registry) |

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

`.github/workflows/compat.yml`:
- Daily cron: polls npm for new OpenClaw releases, tests against version matrix
- Push to main (src/tests/compat changes): tests minimum + latest OC versions
- Manual dispatch: specific version or full matrix
- On success: auto-creates PR updating `compat/versions.json`
- On failure: auto-creates GitHub issue with `compat,urgent` label
- Never auto-merges or publishes — creates PRs for review

## Testing Rules

- After ANY code change: build → `npm test` (unit + harness). All green before reporting.
- Full E2E: `npm run test:docker` — runs inside Docker, tests real OpenClaw + all channels.
- Docker sandbox has 100% isolation: `--internal` network (no external routing), both OpenClaw and Shroud installed from npm.
- Test adversarially — try to break it, don't just prove the happy path.

### Test Architecture

| Layer | What | Tests | Needs Docker |
|-------|------|-------|--------------|
| Unit (Vitest) | Obfuscator, detectors, generators, store, config, security, transformer | 1,760 | No |
| APP Harness | 48 scenario files via mock LLM, no OpenClaw | 359 | No |
| Docker E2E | Real OpenClaw gateway, all channels, 153 regression scenarios | 192 | Yes |
| Sandbox E2E | Docker-in-Docker, exec.host: sandbox, tool call deob | +8 | Yes (--sandbox) |

### Docker E2E Channels

| Channel | How it works |
|---------|-------------|
| TUI | `sessions.create` → gateway → mock LLM → verify PII obfuscated + response deobfuscated |
| Slack | Webhook injection → Bolt HTTP handler → agent → `chat.postMessage` → mock Slack captures response. HTTPS proxy on port 443. Multi-channel, multi-user. |
| WhatsApp | Baileys intercept (Option A): mock `makeWASocket`, inject `messages.upsert`, capture `sendMessage`. In-process injection server. |
| Cron | `openclaw cron add` → waits for schedule to fire → verifies PII obfuscated |
| Multi-turn | Sequential `sessions.send` to same session → verifies no PII leak between turns |

### Key Test Files

| File | What |
|------|------|
| `tests/harness/harness/scenarios/docker-e2e-regression.json` | 153 regression scenarios (false positives, detection, multi-entity, production bugs) |
| `tests/harness/harness/openclaw-runner.mjs` | Docker E2E runner — single gateway, batched tests |
| `tests/harness/mock-llm/server.mjs` | Mock LLM with echo mode for deob verification |
| `tests/harness/mock-slack/server.mjs` | Mock Slack API (auth.test, chat.postMessage, users, channels) |
| `tests/harness/mock-slack/intercept.cjs` | Patches Slack SDK WebClient to use mock server |
| `tests/harness/mock-slack/https-proxy.mjs` | HTTPS proxy on port 443 for Slack SDK TLS path |
| `tests/harness/mock-whatsapp/intercept.cjs` | Patches Baileys `createWaSocket` to return mock socket |
| `tests/harness/mock-whatsapp/server.mjs` | Mock WhatsApp message capture server |
| `tests/integration-security.test.ts` | SecurityEventBus → injection detection pipeline |
| `compat/versions.json` | Supported OpenClaw version registry |

## Golden Baseline

**v2.2.2** established the architecture. **v2.4.0** is the current baseline:
- Fetch response deobfuscation with per-block SSE flushing
- Zero OpenClaw patches
- All channels confirmed (TUI, Slack, WhatsApp, CLI, multi-turn)
- OpenAI/ChatGPT tool_calls obfuscation + SDK fetch bypass fix
- Hook-level message obfuscation (works regardless of LLM SDK HTTP client)
- System prompt fingerprinting (TF-IDF cosine drift detection)
- Transformer seed pre-training (cold start bootstrap for Tiers 2+4)
- 2,311 tests passing (1,760 unit + 359 harness + 192 Docker E2E; +8 sandbox with --sandbox flag)

**Do NOT**: add per-channel patches, use empty deltas, attempt incremental text_delta deob.

## Environment Variables

| Var | Purpose |
|-----|---------|
| `SHROUD_SECRET_KEY` | HMAC secret (auto-generated if unset) |
| `SHROUD_PERSISTENT_SALT` | Fixed salt for cross-session consistency |
| `SHROUD_STATS_FILE` | Stats dump path (default: `/tmp/shroud-stats.json`) |
| `SHROUD_PLUGIN_CONFIG` | JSON config for APP server |
| `SHROUD_INJECTION_DETECTION` | Injection detection mode: `flag`, `block`, or `off` |
| `SHROUD_INJECTION_SCAN_RESPONSES` | Scan LLM responses for injections (default: false) |
| `SHROUD_INJECTION_MIN_SEVERITY` | Minimum severity to report: `low`, `medium`, `high` |
| `SHROUD_PROFILING_ENABLED` | Enable behavioural profiling (default: false) |
| `SHROUD_PROFILING_MODE` | Profiling mode: `learning` or `enforcing` |
| `SHROUD_DASHBOARD` | Enable security dashboard (default: false) |
| `SHROUD_DASHBOARD_PORT` | Dashboard HTTP port (default: 9380) |
| `SHROUD_DASHBOARD_BIND` | Dashboard bind address (default: 127.0.0.1) |
| `SHROUD_CANARY_ENABLED` | Enable canary token injection (default: false) |
| `SHROUD_CANARY_SYSTEM` | Inject canary into system prompts (default: false) |
| `SHROUD_CANARY_BEHAVIOURAL` | Behavioural canary monitoring (default: false) |
| `SHROUD_SIGNATURES_URL` | URL for external injection signature JSON |
| `SHROUD_SIGNATURES_REFRESH` | Signature poll interval in seconds (default: 3600) |
| `SHROUD_SIEM_WEBHOOK_URL` | Webhook URL for shipping security events |
| `SHROUD_SIEM_WEBHOOK_AUTH` | Auth header for SIEM webhook |
| `SHROUD_SIEM_JSONL_PATH` | JSONL file path for security event log |
| `SHROUD_DRIFT_ENABLED` | Enable semantic drift detection (auto-enables with dashboard) |
| `SHROUD_DRIFT_THRESHOLD` | Cosine similarity threshold for drift alert (default: 0.15) |
| `SHROUD_DRIFT_SUDDEN_TURN` | Delta threshold for sudden turn detection (default: 0.3) |
| `SHROUD_COHERENCE_ENABLED` | Enable causal coherence tracking (auto-enables with dashboard) |
| `SHROUD_COHERENCE_ZSCORE` | Z-score threshold for coherence anomaly (default: 2.5) |
| `SHROUD_COHERENCE_RESULT_LIMIT` | Max result categories to track (default: 100) |
| `SHROUD_VECTOR_STORE_ENABLED` | Enable workflow fingerprinting/clustering (auto-enables with dashboard) |
| `SHROUD_VECTOR_STORE_MAX` | Max stored workflows before eviction (default: 10000) |
| `SHROUD_CLUSTERING_ENABLED` | Enable workflow clustering (auto-enables with vector store) |
| `SHROUD_URL_CORRELATION_ENABLED` | Enable cross-session URL correlation (default: false) |
| `SHROUD_INTENT_CHAIN_ENABLED` | Enable multi-agent delegation coherence (auto-enables with dashboard) |
| `SHROUD_DELEGATION_DRIFT_THRESHOLD` | Drift threshold for delegated agents (default: 0.10) |
| `SHROUD_HONEYPOT_RATE` | Honeypot injection rate limit — max injections per session (default: tiered by maturity) |
| `SHROUD_TRANSFORMER_INTENT_ATTENTION_THRESHOLD` | Intent attention drop threshold for hijack detection (default: 0.15) |

## Security Extension (feature/security-extension)

### Overview

WAF/IDS layer built into the privacy plugin. Detects prompt injection, data exfiltration, encoding bypass, and privilege escalation across all channels. Adaptive per-agent thresholds tuned from profiler baselines. Auto-generated firewall rule suggestions from event patterns.

### Architecture

```
User input → injection scan (40+ signatures) → flag/block
           → canary injection (invisible tokens in system prompt)
           → behavioural profiling (per-agent pattern learning)
           → security event bus → adaptive thresholds (per-agent tuning)
           → dashboard (real-time) + SIEM export (webhook/JSONL)
           → rule suggestions (auto-generated firewall rules from patterns)

Vector-based behavioral IDS (4 horizons):
  Per-Step:       Causal Coherence — result→action pair z-scores
  Per-Session:    Intent Drift — TF-IDF trajectory vs user message
  Per-Lifetime:   Workflow Clusters — n-gram sequence vectors, PCA
  Cross-Agent:    Intent Chain — delegation drift through agent tree
```

### Key Files (Vector IDS)

| File | What |
|------|------|
| `src/detectors/drift-detector.ts` | Semantic drift: TF-IDF cosine similarity, feature hashing |
| `src/detectors/sequence-embedder.ts` | N-gram embedding for tool sequences (bi/trigrams) |
| `src/causal-coherence.ts` | Result→action pair tracking with Welford's z-score |
| `src/vector-store.ts` | Persisted workflows, clusters, URL correlation, agent baselines |
| `src/intent-chain.ts` | Multi-agent delegation chain with depth-scaled drift |
| `src/pca.ts` | Power iteration PCA for 256→3D projection (zero deps) |
| `src/detectors/honeypot.ts` | Fake credential injection — rate-limited (SHROUD_HONEYPOT_RATE), tiered by maturity, token rotation, dual format (quiet/loud) |
| `src/detectors/phantom-tools.ts` | Canary tool definitions that catch injection |
| `src/adaptive-thresholds.ts` | Per-agent detection threshold tuning from profiler baselines |
| `src/rule-suggestions.ts` | Auto-generated firewall rules from event patterns |

### Mini Transformer (feature/transformer)

Learned next-tool predictor for tool-call anomaly detection. Pure TypeScript, zero dependencies. 4-tier architecture:

**Tier 1 — Next-Tool Prediction**: Decoder-only transformer, 2 layers, 4 heads, hidden dim 64, FFN dim 256. Causal masking, pre-norm (GPT-2 style). Intent-conditioned: user message is projected (256→64 via learned projection) into position 0, so all tool tokens attend to user intent via cross-attention. ~130K parameters. Inference ~1-2ms on CPU.

**Tier 2 — Contrastive Learning**: Learns to separate normal workflow embeddings from attack traces in embedding space. Attack trace store accumulates confirmed-malicious sequences (from honeypot trips, phantom tool triggers). Embedding shift scoring detects when a session's trajectory drifts toward known attack clusters.

**Tier 3 — Intent Attention Hijack Detection**: Monitors the transformer's cross-attention weights between tool tokens and the user intent vector. When attention to user intent drops below threshold (tools stop being influenced by what the user asked for), emits `INTENT_HIJACK` events. Detects prompt injection that redirects the model's focus away from the original task.

**Tier 4 — Multi-Head Threat Specialization**: 3 specialized classification heads (exfiltration, privilege escalation, reconnaissance) that share the transformer backbone but learn threat-specific patterns. Self-labeling flywheel: high-confidence predictions from honeypot/phantom confirmations are recycled as training labels, continuously improving detection without manual labeling.

**Training**: Self-supervised next-token prediction on completed sessions from VectorStore. Adam optimizer with cosine LR decay. In-process training (~1s for 500 sequences). Cold start: neutral scores until 30 sessions accumulate, then auto-trains. Retrains every 50 new sessions.

**Scoring**: On each `before_tool_call`, feeds current session's tool sequence + user intent vector through the model. `surprise = 1 - P(actual_next_tool)`. Sliding window for session-level anomaly score. Events emitted when surprise > threshold. Softmax predictions logged for all calls.

| File | What |
|------|------|
| `src/transformer/linalg.ts` | Float64Array matrix ops: matmul, softmax, layerNorm, GELU + backward |
| `src/transformer/tokenizer.ts` | Dynamic tool vocabulary (max 128 tokens, 4 special + tools) |
| `src/transformer/model.ts` | Forward + backward pass, weight init (Xavier/sinusoidal), serialization |
| `src/transformer/trainer.ts` | Training loop, Adam optimizer, gradient clipping, LR scheduling |
| `src/transformer/scorer.ts` | Inference bridge: scoring, cold start, persistence, retraining trigger |
| `src/transformer/contrastive.ts` | Contrastive learning: attack trace store, embedding shift scoring |
| `src/transformer/threat-heads.ts` | Multi-head threat specialization (exfil/privesc/recon) |
| `src/transformer/flywheel.ts` | Self-labeling flywheel: high-confidence predictions → training labels |

**Config:**

| Var | Default | What |
|-----|---------|------|
| `SHROUD_TRANSFORMER_ENABLED` | auto (with dashboard) | Enable transformer predictor |
| `SHROUD_TRANSFORMER_THRESHOLD` | 0.85 | Surprise score to trigger event |
| `SHROUD_TRANSFORMER_WINDOW` | 10 | Sliding window for session score |
| `SHROUD_TRANSFORMER_MIN_SESSIONS` | 30 | Min sessions before first training |
| `SHROUD_TRANSFORMER_TRAIN_INTERVAL` | 50 | Sessions between retraining |
| `SHROUD_TRANSFORMER_INTENT_ATTENTION_THRESHOLD` | 0.15 | Intent attention drop threshold for hijack detection |

**Persistence**: `~/.shroud/profiles/transformer-weights.bin` (Float64 binary) + `transformer-config.json` (vocab, model config, training metadata).

### Dashboard

HTTP server on `SHROUD_DASHBOARD_PORT` (default 9380). 7-tab UI: Overview, Firewall Rules, Signatures, Transformer, Events, Tripwires, Timeline. Event summary with grouped view, rule suggestion cards.

| Endpoint | What |
|----------|------|
| `/health` | Health check |
| `/api/overview` | Stats summary |
| `/api/agents` | Agent inventory with identity, tools, model |
| `/api/events` | Security event list (grouped view) |
| `/api/events/stream` | SSE stream of real-time events |
| `/api/profiling` | Behavioural profiling data |
| `/api/calls` | LLM call log |
| `/api/rules` | Auto-generated firewall rule suggestions |
| `/api/transformer` | Transformer status, training metrics, predictions |
| `/api/timeline` | Session timeline visualization |
