# Shroud Test Handbook

## Overview

Shroud has a three-layer test architecture plus an opt-in sandbox mode. Each layer tests at a different level of integration, from pure in-memory logic up to full end-to-end channel delivery through a real OpenClaw gateway.

| Layer | Command | Tests | Needs Docker | Runtime |
|-------|---------|-------|--------------|---------|
| **Unit** (Vitest) | `npm run test:unit` | 870 | No | ~2s |
| **Integration** (APP harness) | `npm run test:integration` | 359 | No | ~5s |
| **Docker E2E** (OpenClaw gateway) | `npm run test:docker` | 192 | Yes | ~10-15 min |
| **Sandbox E2E** (DinD) | `SHROUD_E2E_PATH=/path/to/shroud-e2e bash compat/run-e2e.sh <ver> --sandbox` | 200 | Yes (privileged) | ~15-20 min |

Combined commands:

```bash
npm test              # Unit + Integration (1,229 tests)
npm run test:all      # All three layers (1,421 tests)
npm run test:watch    # Vitest in watch mode (unit only)
```

---

## Layer 1: Unit Tests (Vitest)

**Location:** `tests/*.test.ts` (17 files)

Unit tests run entirely in-memory with no child processes, no network, and no mock servers. They test the obfuscation engine, detectors, generators, store, and config in isolation.

### Test files

| File | Tests | What it covers |
|------|-------|----------------|
| `exit.test.ts` | 493 | Compiled `dist/` output. 20 sections: config, every PII category, redaction modes, allowlist/denylist, confidence filtering, dry-run, determinism, store/LRU, canary injection, subnet-aware deob, Slack mrkdwn, custom patterns, detector overrides, audit logger, multi-entity stress |
| `obfuscator.test.ts` | 67 | Core obfuscation logic, overlap resolution, confidence filtering |
| `dns-cache.test.ts` | 64 | DNS resolution cache, TTL handling, RFC 1918 classification |
| `hooks.test.ts` | 50 | Config hooks, audit logging, filter stats, exposure tracking |
| `detectors.test.ts` | 42 | Regex patterns, network detection, mask parsing, custom patterns |
| `false-positive-regression.test.ts` | 29 | Regressions: values that must NOT be obfuscated (version numbers, UUIDs, stock prices, ML weights, /tmp paths) |
| `generators.test.ts` | 19 | Fake data generators, HMAC determinism, roundtrip consistency |
| `detection-improvements.test.ts` | 20 | Detector enhancements and edge cases |
| `ipv6.test.ts` | 17 | IPv6 patterns, ULA addresses, global unicast handling |
| `slack-chain.test.ts` | 14 | Slack `<mailto:>` markup stripping, mrkdwn parsing |
| `fetch-response-deob.test.ts` | 12 | HTTP response deobfuscation, SSE stream handling (Anthropic format) |
| `store.test.ts` | 10 | Mapping store, LRU eviction |
| `audit.test.ts` | 9 | Audit logger chain, hash generation, proof logging |
| `mapping.test.ts` | 7 | Entity mapping storage and retrieval |
| `config.test.ts` | 6 | Config validation, defaults, environment variable resolution |
| `canary.test.ts` | 6 | Canary token injection, leak detection |
| `deobfuscation-corruption.test.ts` | 5 | Roundtrip fidelity, hash collisions, HMAC verification |

### Running a single test file

```bash
npx vitest run tests/obfuscator.test.ts
npx vitest run tests/exit.test.ts -t "Credit card"  # filter by test name
```

---

## Layer 2: Integration Tests (APP Harness)

**Location:** `tests/harness/`

The integration layer tests Shroud through its APP (Agent Privacy Protocol) server — the same JSON-RPC interface that non-OpenClaw agents use. It starts a mock LLM, starts the APP server, and runs 51 scenario files containing 359 test cases.

### Architecture

```
run.mjs (CLI entry point)
  └─ runner.mjs (orchestrator)
       ├─ mock-llm/server.mjs    ← Multi-provider mock LLM
       ├─ app-server.mjs         ← Shroud APP server (JSON-RPC over stdio)
       └─ scenarios/*.json       ← 51 test scenario files
```

### How it works

1. **Start mock LLM** on a random port. It logs every request for later assertion.
2. **Start APP server** via `APPClient.spawn()`. Communicates over newline-delimited JSON-RPC on stdin/stdout.
3. **For each scenario file**, restart the APP server (fresh HMAC salt to avoid collisions).
4. **For each test case** in the scenario:
   - Reset APP state
   - Clear mock LLM request log
   - Obfuscate the input text via `client.obfuscate()`
   - Send the obfuscated text to the mock LLM
   - Fetch the mock LLM's request log (what it actually received)
   - Deobfuscate via `client.deobfuscate()`
   - Run all assertions

### Scenario file format

Scenarios are JSON files in `tests/harness/harness/scenarios/`. Each file is an array of test cases:

```json
[
  {
    "name": "Email obfuscation",
    "input": "Contact john.smith@acme-corp.com for details.",
    "assertions": {
      "llm_must_not_see": ["john.smith@acme-corp.com"],
      "llm_must_see_pattern": ["[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"],
      "user_must_see": ["john.smith@acme-corp.com"],
      "entity_count_min": 1,
      "entity_count_max": 10,
      "categories": ["email"],
      "no_cgnat_leak": true,
      "no_cgnat_range_leak": true,
      "no_ula_leak": true,
      "roundtrip": true,
      "fake_phones_must_be_e164": true
    }
  }
]
```

### Assertion reference

| Assertion | What it checks |
|-----------|---------------|
| `llm_must_not_see` | Array of strings. The mock LLM's request log must not contain any of these values. Proves obfuscation worked. |
| `llm_must_see_pattern` | Array of regex strings. The LLM's request log must match these patterns. Proves format-preserving fakes were generated. |
| `user_must_see` | Array of strings. The deobfuscated output must contain these original values. Proves deobfuscation restored them. |
| `entity_count_min` / `entity_count_max` | Bounds on the number of entities detected. |
| `categories` | Array of category names that must appear in the detection result. |
| `no_cgnat_leak` | Boolean. Deobfuscated output must not contain CGNAT IPs (100.64.0.0/10). |
| `no_cgnat_range_leak` | Boolean. Catches generic CGNAT range descriptions (e.g., "100.64.x.x/24"). |
| `no_ula_leak` | Boolean. Deobfuscated output must not contain ULA IPv6 (fd00::/8). |
| `roundtrip` | Boolean. `obfuscate(input) → deobfuscate()` must exactly equal the original input. |
| `fake_phones_must_be_e164` | Boolean. All fake phone surrogates must be valid E.164 format. |

### Scenario categories (51 files, 359 tests)

| Category | Files | Description |
|----------|-------|-------------|
| **Basic PII** | `basic-pii` | Email, IP, phone, credit card, SSN, URL, person name |
| **API keys & tokens** | `api-keys-tokens` | OpenAI, Anthropic, AWS, GitHub PAT, generic tokens |
| **Credentials** | `credentials`, `connection-strings`, `network-credentials` | DB connection strings, SSH keys, JWT, .env files, SNMP communities |
| **Network infrastructure** | `network-infra`, `infrastructure-names`, `vlan-vni`, `vrf-routing` | Hostnames, VLANs, VNIs, subnets, BGP configs, VRF routing |
| **Vendor configs** | `cisco-configs`, `juniper-configs`, `paloalto-configs`, `full-config-blocks` | Full router/switch/firewall config blocks with embedded credentials |
| **NCG** | `ncg-carrier-configs`, `ncg-multivendor`, `ncg-mpls-vpn`, `ncg-change-requests`, `ncg-device-inventory`, `ncg-security-audit`, `ncg-troubleshooting` | Carrier, multi-vendor, MPLS/VPN, change requests, inventory, audits, troubleshooting |
| **Channels** | `channel-slack`, `channel-whatsapp`, `channel-discord`, `channel-teams`, `channel-telegram`, `channel-irc`, `channel-email`, `channel-signal`, `channel-matrix`, `channel-webhook`, `channel-edge-cases` | Per-channel formatting, multi-channel, multi-user, edge cases |
| **Phone variants** | `phone-variants`, `international-phones` | Country formats, +E.164, parenthesized area codes, extensions |
| **False positives** | `false-positives`, `doc-domain-filtering` | Stock prices, ML weights, /tmp paths, example.com, GitHub URLs |
| **Edge cases & stress** | `edge-cases`, `roundtrip-edge-cases`, `large-inputs`, `mixed-formats` | Determinism, empty input, large payloads, mixed document formats |
| **Subnet operations** | `subnet-operations`, `multi-subnet`, `cgnat-range-leak`, `collision-regression` | Subnet-aware deob, CGNAT collision, multi-subnet documents |
| **Other** | `email-thread`, `multi-entity`, `smart-obfuscation`, `prompt-privacy`, `tool-roundtrip`, `regulated-identifiers`, `openclaw-regression` | Email threads, multi-entity, prompt privacy, tool roundtrip, regulatory IDs |

### CLI options

```bash
node tests/harness/run.mjs                          # All 359 tests
node tests/harness/run.mjs --scenario basic-pii     # Filter by name
node tests/harness/run.mjs --verbose                # Detailed output
node tests/harness/run.mjs --report reports/r.json  # JSON report
node tests/harness/run.mjs --shroud-path /path      # Custom shroud location
```

### Mock LLM server

**File:** `tests/harness/mock-llm/server.mjs`

A zero-dependency **multi-provider** mock LLM server implementing realistic SSE streaming for three providers.

#### Endpoints

| Endpoint | Method | Provider | Purpose |
|----------|--------|----------|---------|
| `/v1/chat/completions` | POST | OpenAI | Chat completions (streaming + non-streaming) |
| `/v1/messages` | POST | Anthropic | Messages API (streaming + non-streaming) |
| `/v1beta/models/*:streamGenerateContent` | POST | Google Gemini | Streaming content generation |
| `/v1beta/models/*:generateContent` | POST | Google Gemini | Non-streaming content generation |
| `/requests` | GET | — | Retrieve all captured request bodies |
| `/requests` | DELETE | — | Clear the request log |
| `/health` | GET | — | Health check with provider list |

#### Provider-specific SSE formats

**OpenAI:** `data:` lines with `chat.completion.chunk` objects. Text in `choices[].delta.content`. Terminates with `finish_reason: "stop"` + `data: [DONE]`. Chunks ~3 words.

**Anthropic:** Named `event:` + `data:` lines. Full lifecycle:
```
event: message_start       → message metadata, usage
event: content_block_start → block index, type (text/tool_use)
event: ping                → keepalive
event: content_block_delta → text_delta or input_json_delta
event: content_block_stop  → flush trigger for Shroud's deob
event: message_delta       → stop_reason, final usage
event: message_stop        → stream complete
```
Chunks ~2 words (smaller than OpenAI, matching real Claude behavior). Supports multi-block responses (text + tool_use).

**Google Gemini:** `data:` lines with `GenerateContentResponse` objects. Text in `candidates[0].content.parts[0].text`. Larger chunks (~6 words). Includes `safetyRatings` and `usageMetadata`.

#### Modes

- **Default:** Responds with `"Based on my analysis, {user_text}. This information has been verified."`
- **Echo mode:** Returns the exact user input unchanged. Activated by `body._echo`, `X-Mock-Echo: 1` header, or `MOCK_LLM_ECHO=1` env var. Used in Docker E2E to verify deobfuscation roundtrips.
- **Tool calls:** If the request includes `tools` and text contains an IP/hostname, returns a `tool_calls` response. Suppressed by `MOCK_LLM_NO_TOOLS=1`.

### APP client (JSON-RPC)

**File:** `tests/harness/lib/app-client.mjs`

Communicates with `app-server.mjs` via newline-delimited JSON-RPC over stdin/stdout.

```
→ {"jsonrpc":"2.0","id":1,"method":"obfuscate","params":{"text":"..."}}
← {"jsonrpc":"2.0","id":1,"result":{"text":"...","entityCount":5,"categories":{...},"modified":true}}
```

Methods: `obfuscate`, `deobfuscate`, `reset`, `shutdown`.

---

## Layer 3: Docker E2E (OpenClaw Gateway)

**Location:** external `shroud-e2e` repo. This repo keeps only the APP harness and the thin `compat/run-e2e.sh` wrapper.

This layer runs Shroud inside a real OpenClaw gateway with all channels enabled. It now lives in `shroud-e2e`, which is the single source of truth for Docker/OpenClaw E2E.

### Architecture (standard mode)

```
compat/run-e2e.sh
  ├─ Resolve the external shroud-e2e checkout
  ├─ Pack the current Shroud workspace as a tarball
  └─ Delegate to shroud-e2e/compat/run-compat.sh
       ├─ Build the Docker/OpenClaw test environment
       ├─ Start mock channel services and a real OpenClaw gateway
       └─ Run the full gateway scenario set
```

### Architecture (sandbox mode — `--sandbox`)

```
compat/run-e2e.sh --sandbox
  └─ Delegate to shroud-e2e, which enables the OpenClaw sandbox container path
       → 192 standard + 8 sandbox-specific gateway tests
```

Sandbox mode tests Shroud with OpenClaw's containerized agent exec (`exec.host: "sandbox"`). Agent tool calls execute inside inner Docker containers. Shroud's fetch intercept and `before_tool_call` deobfuscation still run in the gateway process — the test validates PII never leaks through the sandbox boundary.

### Isolation guarantees

| Property | Standard | Sandbox |
|----------|----------|---------|
| **Network** | `--internal` (zero egress) | `--internal` (zero egress) |
| **Filesystem** | No volume mounts | No volume mounts |
| **Memory** | 1GB | 2GB (Docker daemon overhead) |
| **CPU** | 2 cores | 2 cores |
| **Privileges** | None | `--privileged` (for dockerd) |
| **Host access** | None | None |
| **OpenClaw** | From npm | From npm |
| **Shroud** | From npm | From npm |

### Running Docker E2E

```bash
# Single version (latest)
npm run test:docker

# Direct wrapper invocation
SHROUD_E2E_PATH=/path/to/shroud-e2e bash compat/run-e2e.sh latest
```

### Ownership

The Docker images, entrypoints, mock channel servers, OpenClaw gateway runner, sandbox plumbing, and OpenClaw version matrix now live in `shroud-e2e`, not in this repository. Shroud only provides:

- `compat/run-e2e.sh` as a thin wrapper
- optional branch-specific scenario files in `e2e-scenarios/`
- the package tarball under test

### Test scenario categories

#### Standard scenarios (192 tests)

| Category | Count | What it tests |
|----------|-------|---------------|
| PII smoke tests | 10 | Email, IP, phone, hostname, credential, BGP, connection string, IBAN, API key, public URL |
| Workspace/path passthrough | 4 | `/home`, `/tmp`, GPS false positives, channel deob |
| Multi-turn (basic) | 1 | 2-turn PII leak prevention |
| Multi-turn compaction | 9 | 4-6 turn PII accumulation, repeated PII determinism, mixed categories, network config propagation, long message pressure, AWS credentials |
| Slack E2E | 8 | Multi-channel, multi-user, deob round-trip (email, BGP, multi-entity, IBAN) |
| WhatsApp E2E | 1 | Inbound message PII obfuscation via Baileys mock |
| Cron E2E | 1 | Scheduled job fires with PII obfuscation |
| Audit & stats | 2 | Proof hash audit log, stats file written |
| Regression (JSON file) | 153 | False positives, detection, multi-entity, production bugs, Slack mailto, credentials, network configs, cloud configs |

#### Sandbox scenarios (8 additional tests, `--sandbox` only)

| Test | What it validates |
|------|-------------------|
| PII in tool call params | Tool call with IP → deobfuscated before sandbox exec |
| Workspace path passthrough | `/home` paths work inside sandbox |
| Multi-turn with exec | PII from exec results doesn't leak on next turn |
| Credentials in exec | Connection string PII in sandboxed tool call |
| Network config via exec | Hostname + IPs obfuscated through sandbox boundary |
| API key in tool call | Anthropic API key pattern in sandboxed exec |
| IBAN in financial tool | IBAN + email in sandboxed context |
| Slack upload from sandbox | File upload from sandbox reaches mock Slack |

### Channel test flows

**TUI (standard scenarios):**
1. `sessions.create` with test message via gateway RPC
2. Gateway routes to agent → Shroud fetch intercept obfuscates → mock LLM (echo mode) → Shroud deobfuscates
3. Assert: LLM never saw real PII, no CGNAT/ULA leak, deobfuscated response contains originals

**Slack:**
1. Compute HMAC-SHA256 signature using Slack signing secret
2. POST webhook event to `gateway:port/slack/events`
3. Gateway routes through Slack Bolt → agent → mock LLM
4. Mock Slack server captures `chat.postMessage` call
5. Assert: LLM never saw real PII, Slack output contains original values

**WhatsApp:**
1. Inject message via `globalThis.__mockWhatsAppInject()` (Baileys mock socket)
2. Gateway routes through WhatsApp handler → agent → mock LLM
3. Mock WhatsApp server captures `sendMessage` call
4. Assert: same as Slack, plus E.164 phone number validation on fakes

**Cron:**
1. Create a cron schedule via gateway RPC
2. Wait for the schedule to fire
3. Assert: scheduled message was obfuscated, no PII in LLM request

**Multi-turn:**
1. `sessions.create` with first message
2. `sessions.send` with subsequent messages to same session
3. Assert: PII from ALL previous turns remains obfuscated in every LLM request (multi-turn leak prevention)
4. Compaction scenarios test up to 6 turns with 6+ accumulated PII values

### Mock servers

**Mock Slack**: moved to `shroud-e2e`.

| Endpoint | Purpose |
|----------|---------|
| `POST /slack/events` | Inbound webhook receiver |
| `POST /api/chat.postMessage` | Captures outbound messages |
| `POST /api/chat.update` | Streaming message updates |
| `POST /api/auth.test` | Bot identity response |
| `POST /api/conversations.info` | Channel info |
| `POST /api/users.info` | User profile |
| `GET /messages` | Retrieve captured messages |
| `DELETE /messages` | Clear message log |

**Slack SDK intercept**: moved to `shroud-e2e`.

**Slack HTTPS proxy**: moved to `shroud-e2e`.

**Mock WhatsApp**: moved to `shroud-e2e`.

| Endpoint | Purpose |
|----------|---------|
| `POST /send` | Captures `sendMessage()` calls |
| `POST /inject` | Inject inbound messages |
| `GET /messages` | Retrieve captured outbound messages |
| `DELETE /messages` | Clear messages |

**WhatsApp intercept**: moved to `shroud-e2e`.

---

## OpenClaw Version Compatibility

### Supported versions

**Version registry:** moved to `shroud-e2e`. Check that repo for the current supported OpenClaw matrix and minimum compatible version.

### Version notes

| Version | Status | Notes |
|---------|--------|-------|
| **2026.3.22** | Supported | Earliest with plugin API. No WhatsApp channel. 182/183 passing. |
| **2026.3.23** | Retired | Gateway bug: Slack channel failure cascades to all requests. 0/183. |
| **2026.3.24** | Supported | Stable. 191/192 passing (1 known: SNMP learned entity leak, fixed in next release). |
| **2026.3.28** | Current | Latest. Adds `exec.host: "sandbox"`, `upload-file` Slack action, `requireApproval` hook. 190/192 standard, 197/200 with sandbox. |

### What changed in 2026.3.28

Key features relevant to Shroud:
- **`tools.exec.host: "sandbox"`** — agent exec inside containers. Shroud tested and working via `--sandbox` flag.
- **`upload-file` Slack action** — explicit file uploads through Slack transport.
- **Async `requireApproval` in `before_tool_call`** — plugins can pause tool execution for user approval. Not yet adopted by Shroud.
- **WhatsApp echo loop fix** — self-chat DM mode no longer re-processes bot replies.
- **Plugin SDK `moduleUrl` fix** — plugins outside openclaw dir resolve imports correctly.

The OpenClaw matrix is now owned by `shroud-e2e`.

---

## CI/CD Integration

**`.github/workflows/ci.yml`:**
- Every push/PR: `lint → test → build`
- On `v*` tags: auto-publish to npm with Sigstore provenance

Docker/OpenClaw compatibility automation now belongs with `shroud-e2e`.

---

## Writing New Tests

### Adding a unit test

Add or extend a `tests/*.test.ts` file. Unit tests use Vitest:

```typescript
import { describe, it, expect } from "vitest";
import { obfuscate, deobfuscate } from "../dist/index.js";

describe("New detection", () => {
  it("should detect and roundtrip", () => {
    const result = obfuscate("some input with PII");
    expect(result.entityCount).toBeGreaterThan(0);
    const restored = deobfuscate(result.text);
    expect(restored.text).toBe("some input with PII");
  });
});
```

### Adding an integration scenario

Create or extend a JSON file in `tests/harness/harness/scenarios/`:

```json
[
  {
    "name": "Descriptive test name",
    "input": "Text containing real-value@example.com to obfuscate",
    "assertions": {
      "llm_must_not_see": ["real-value@example.com"],
      "user_must_see": ["real-value@example.com"],
      "entity_count_min": 1,
      "categories": ["email"],
      "roundtrip": true
    }
  }
]
```

Files prefixed with `docker-` are reserved for Docker E2E in `shroud-e2e`. All remaining files here run in the APP harness.

### Adding a Docker E2E regression

Add Docker/OpenClaw regressions in the external `shroud-e2e` repo.

### Adding a multi-turn compaction or sandbox test

Docker/OpenClaw multi-turn and sandbox tests now live in `shroud-e2e`.

---

## Reporting

### Console output

The reporter prints per-scenario results with pass/fail indicators, durations, and a summary line:

```
Shroud Integration Test Results
==================================================
✔ basic-pii  8 passed  (48ms)
✔ credentials  24 passed  (99ms)
✘ edge-cases  5 passed, 1 failed  (47ms)
    ✘ Unicode roundtrip: Roundtrip failed
==================================================
Total: 358 passed, 1 failed  4542ms
```

### JSON report

Pass `--report path.json` to save a structured report:

```json
{
  "scenarios": [
    {
      "name": "basic-pii",
      "file": "basic-pii.json",
      "passed": 8,
      "failures": 0,
      "duration": 48,
      "tests": [...]
    }
  ],
  "passed": 359,
  "failed": 0,
  "skipped": 0,
  "duration": 4542
}
```

---

## Troubleshooting

**Tests fail with "Shroud app-server not found":**
Run `npm run build` first. The harness needs compiled output in `dist/`.

**Docker E2E fails before the gateway starts:**
Check `SHROUD_E2E_PATH` and verify the external `shroud-e2e` checkout is present and up to date.

**Mock LLM timeout (5s):**
The mock LLM server failed to start. Check for port conflicts or Node.js issues.

**"Gateway call failed" in Docker E2E:**
The OpenClaw gateway didn't respond. Check that the OpenClaw version supports the plugin API. Minimum supported: 2026.3.22.

**"Config invalid: Unrecognized key" in sandbox mode:**
The OC version doesn't support the config key (e.g., `tools.exec.host`). Only OC 2026.3.28+ supports sandbox exec.

**Sandbox: "Docker daemon failed to start":**
The external runner needs privileged Docker access for sandbox mode. Re-run via `compat/run-e2e.sh --sandbox` and inspect the `shroud-e2e` logs.

**CGNAT leak assertions fail:**
Fake IPv4 surrogates (100.64.x.x) appeared in deobfuscated output. This means deobfuscation missed a mapping. Check the store state and HMAC consistency.

**Roundtrip assertion fails:**
`obfuscate → deobfuscate` didn't produce the original text. Usually caused by overlapping detections or regex changes that alter entity boundaries.

**Multi-turn compaction test fails with "LLM saw real PII":**
A context-dependent entity (SNMP community, BGP password) wasn't added to the learned entity store. Check that the detector name is in the `learnableDetectors` set in `src/detectors/context.ts`.
