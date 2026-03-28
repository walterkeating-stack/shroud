# Shroud Test Handbook

## Overview

Shroud has a three-layer test architecture. Each layer tests at a different level of integration, from pure in-memory logic up to full end-to-end channel delivery through a real OpenClaw gateway.

| Layer | Command | Tests | Needs Docker | Runtime |
|-------|---------|-------|--------------|---------|
| **Unit** (Vitest) | `npm run test:unit` | 870 | No | ~2s |
| **Integration** (APP harness) | `npm run test:integration` | 359 | No | ~5s |
| **Docker E2E** (OpenClaw gateway) | `npm run test:docker` | 183 | Yes | ~2-3 min |

Combined commands:

```bash
npm test              # Unit + Integration (1,229 tests)
npm run test:all      # All three layers (1,412 tests)
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
| `fetch-response-deob.test.ts` | 12 | HTTP response deobfuscation, SSE stream handling |
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
       ├─ mock-llm/server.mjs    ← OpenAI-compatible mock LLM
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
| `categories` | Array of category names that must appear in the detection result (e.g., `email`, `ip_address`, `phone`, `credit_card`, `ssn`, `url`). |
| `no_cgnat_leak` | Boolean. Deobfuscated output must not contain CGNAT IPs (100.64.0.0/10). These are fake surrogates for the LLM only. |
| `no_cgnat_range_leak` | Boolean. Catches generic CGNAT range descriptions (e.g., "100.64.x.x/24") that a real LLM might generate. |
| `no_ula_leak` | Boolean. Deobfuscated output must not contain ULA IPv6 (fd00::/8). |
| `roundtrip` | Boolean. `obfuscate(input) → deobfuscate()` must exactly equal the original input. |
| `fake_phones_must_be_e164` | Boolean. All fake phone surrogates must be valid E.164 format. Required for WhatsApp delivery. |

### Scenario categories (51 files, 359 tests)

| Category | Files | Description |
|----------|-------|-------------|
| **Basic PII** | `basic-pii` | Email, IP, phone, credit card, SSN, URL, person name |
| **API keys & tokens** | `api-keys-tokens` | OpenAI, Anthropic, AWS, GitHub PAT, generic tokens |
| **Credentials** | `credentials`, `connection-strings`, `network-credentials` | DB connection strings, SSH keys, JWT, .env files, SNMP communities |
| **Network infrastructure** | `network-infra`, `infrastructure-names`, `vlan-vni`, `vrf-routing` | Hostnames, VLANs, VNIs, subnets, BGP configs, VRF routing |
| **Vendor configs** | `cisco-configs`, `juniper-configs`, `paloalto-configs`, `full-config-blocks` | Full router/switch/firewall config blocks with embedded credentials |
| **NCG (Network Config Gen)** | `ncg-carrier-configs`, `ncg-multivendor`, `ncg-mpls-vpn`, `ncg-change-requests`, `ncg-device-inventory`, `ncg-security-audit`, `ncg-troubleshooting` | Carrier, multi-vendor, MPLS/VPN, change requests, inventory queries, security audits, troubleshooting |
| **Channels** | `channel-slack`, `channel-whatsapp`, `channel-discord`, `channel-teams`, `channel-telegram`, `channel-irc`, `channel-email`, `channel-signal`, `channel-matrix`, `channel-webhook`, `channel-edge-cases` | Per-channel formatting, multi-channel, multi-user, edge cases |
| **Phone variants** | `phone-variants`, `international-phones` | Country formats, +E.164, parenthesized area codes, extensions |
| **False positives** | `false-positives`, `doc-domain-filtering` | Stock prices, ML weights, /tmp paths, example.com, GitHub URLs — things that must NOT be obfuscated |
| **Edge cases & stress** | `edge-cases`, `roundtrip-edge-cases`, `large-inputs`, `mixed-formats` | Determinism, empty input, large payloads, mixed document formats |
| **Subnet operations** | `subnet-operations`, `multi-subnet`, `cgnat-range-leak`, `collision-regression` | Subnet-aware deob, CGNAT collision regression, multi-subnet documents |
| **Other** | `email-thread`, `multi-entity`, `smart-obfuscation`, `prompt-privacy`, `tool-roundtrip`, `regulated-identifiers`, `openclaw-regression` | Email threads, multi-entity documents, smart obfuscation, prompt privacy, tool call roundtrip, regulatory IDs, OpenClaw-specific regressions |

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

A zero-dependency OpenAI-compatible chat completions server.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/chat/completions` | POST | Chat completions (streaming + non-streaming) |
| `/requests` | GET | Retrieve all captured request bodies |
| `/requests` | DELETE | Clear the request log |
| `/health` | GET | Health check with request count |

**Modes:**

- **Default:** Responds with `"Based on my analysis, {user_text}. This information has been verified."`
- **Echo mode:** Returns the exact user input unchanged. Activated by `body._echo`, `X-Mock-Echo: 1` header, or `MOCK_LLM_ECHO=1` env var. Used in Docker E2E to verify deobfuscation roundtrips.
- **Tool calls:** If the request includes `tools` and the text contains an IP/hostname, returns a `tool_calls` response instead of text. Suppressed by `body._no_tool_calls` or `X-No-Tool-Calls: 1`.
- **Streaming:** Enabled by default (`stream !== false`). Splits response into ~3-word SSE chunks with proper `content_block_stop` and `[DONE]` framing.

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

**Location:** `compat/` (scripts, Dockerfiles) + `tests/harness/harness/scenarios/docker-e2e-regression.json` (153 scenarios) + `tests/harness/harness/openclaw-runner.mjs` (runner)

This layer runs Shroud inside a real OpenClaw gateway with all channels enabled. It's the only layer that tests the fetch intercept, SSE deobfuscation, and channel delivery end-to-end.

### Architecture

```
run-compat.sh
  ├─ npm run build && npm pack         (build Shroud tarball)
  ├─ docker build Dockerfile.base      (Node 22 + OpenClaw, cached per version)
  ├─ docker build Dockerfile.test      (tarball + harness + entrypoint, fast)
  ├─ docker network create --internal  (no external routing)
  └─ docker run                        (isolated container, 512MB, 1 CPU)
       └─ entrypoint.sh
            ├─ /etc/hosts redirects    (api.slack.com → 127.0.0.1, etc.)
            ├─ openclaw plugins install shroud-privacy-*.tgz
            ├─ openclaw channels add --channel whatsapp
            ├─ WhatsApp mock auth state
            └─ node run.mjs --openclaw --verbose
                 └─ openclaw-runner.mjs
                      ├─ Mock LLM (echo mode)
                      ├─ Mock Slack server
                      ├─ Mock Slack HTTPS proxy (port 443)
                      ├─ Mock WhatsApp server
                      └─ ONE OpenClaw gateway process
                           → All 183 tests run through this single gateway
```

### Isolation guarantees

- **Network:** `--internal` Docker network. No packets leave the container. All mock servers on localhost.
- **Filesystem:** No volume mounts. Everything baked into the image.
- **Memory:** Capped at 512MB.
- **CPU:** Capped at 1 core.
- **No host access:** Container cannot reach the host machine.
- **Own OpenClaw:** Installed from npm inside the container. Never references the host.

### Running Docker E2E

```bash
# Single version (latest)
npm run test:docker

# Specific version
bash compat/run-compat.sh 2026.3.24

# Force rebuild base image
bash compat/run-compat.sh 2026.3.24 --rebuild-base

# Version matrix (all supported versions)
bash compat/run-matrix.sh

# Latest N versions in parallel
bash compat/run-matrix.sh --latest 2 --parallel
```

### Docker images

**`Dockerfile.base`** (cached per OpenClaw version):
- `node:22-slim` base
- Installs `python3` (OpenClaw plugin hooks need it)
- `npm install -g openclaw@${OC_VERSION}`
- Creates `/shroud/state/` directories
- Tag: `shroud-compat-base:oc-${OC_VERSION}`

**`Dockerfile.test`** (rebuilt on every Shroud change, <5s):
- Inherits from base
- Copies `shroud-privacy-*.tgz` (the npm tarball)
- Copies `tests/harness/` (scenarios + runners + mocks)
- Copies `compat/entrypoint.sh`
- Tag: `shroud-compat:oc-${OC_VERSION}`

### Container startup (entrypoint.sh)

1. Verify tarball exists
2. Add `/etc/hosts` entries: `127.0.0.1 slack.com api.slack.com web.whatsapp.com`
3. Create state directories
4. `openclaw plugins install shroud-privacy-*.tgz`
5. `openclaw channels add --channel whatsapp`
6. Write mock WhatsApp auth state (`creds.json` with pre-paired device)
7. Run `node run.mjs --openclaw --verbose`

### OpenClaw runner (openclaw-runner.mjs)

Starts a **single gateway process** and runs all 183 tests through it.

**Startup sequence:**
1. Create state directories
2. Start mock LLM (echo mode), mock Slack, mock Slack on port 443, mock WhatsApp
3. Write OpenClaw config with mock server ports
4. Start gateway with `--dev --auth token --token shroud-test-token`
5. Wait for "Plugin loaded" and "http mode listening" in gateway output
6. Run all scenarios via gateway RPC calls

**Gateway environment:**
```bash
NODE_OPTIONS="--require slack-intercept.cjs --require wa-intercept.cjs"
MOCK_SLACK_URL=http://127.0.0.1:${port}/api/
MOCK_WHATSAPP_PORT=${port}
MOCK_LLM_ECHO=1                    # Echo mode for deob verification
NODE_TLS_REJECT_UNAUTHORIZED=0     # Self-signed certs for mock HTTPS
```

### Channel test flows

**TUI (standard scenarios):**
1. `sessions.create` with test message via gateway RPC
2. Gateway routes to agent → Shroud fetch intercept obfuscates → mock LLM (echo mode) → Shroud deobfuscates
3. Assert: LLM never saw real PII, no CGNAT/ULA leak in response, deobfuscated response contains original values

**Slack:**
1. Compute HMAC-SHA256 signature using Slack signing secret
2. POST webhook event to `gateway:port/slack/events`
3. Gateway routes through Slack Bolt → agent → mock LLM
4. Mock Slack server captures `chat.postMessage` call
5. Assert: LLM never saw real PII, Slack output contains original values, no CGNAT leak

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
2. `sessions.send` with second message to same session
3. Assert: previous-turn assistant messages were re-obfuscated (multi-turn leak prevention), no PII in any LLM request

### Mock servers

**Mock Slack** (`tests/harness/mock-slack/server.mjs`):

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

**Slack SDK intercept** (`tests/harness/mock-slack/intercept.cjs`): A `--require` preload script that patches `@slack/web-api` WebClient to replace the default Slack API URL with `MOCK_SLACK_URL`.

**Slack HTTPS proxy** (`tests/harness/mock-slack/https-proxy.mjs`): Handles the Slack SDK's HTTPS fallback path. Some SDK code bypasses the URL rewrite and connects directly to `slack.com:443`.

**Mock WhatsApp** (`tests/harness/mock-whatsapp/server.mjs`):

| Endpoint | Purpose |
|----------|---------|
| `POST /send` | Captures `sendMessage()` calls |
| `POST /inject` | Inject inbound messages |
| `GET /messages` | Retrieve captured outbound messages |
| `DELETE /messages` | Clear messages |

**WhatsApp intercept** (`tests/harness/mock-whatsapp/intercept.cjs`): Patches the Baileys `makeWASocket` module. Intercepts `socket.ev.on("messages.upsert")` and `sendMessage()`. Registers `globalThis.__mockWhatsAppInject()` for message injection.

---

## Version Compatibility Matrix

**File:** `compat/versions.json`

```json
{
  "minimum": "2026.3.22",
  "versions": [
    { "version": "2026.3.22", "status": "supported", "shroudMinVersion": "2.0.0" },
    { "version": "2026.3.23", "status": "supported", "shroudMinVersion": "2.1.0" },
    { "version": "2026.3.24", "status": "current",   "shroudMinVersion": "2.2.0" }
  ]
}
```

`run-matrix.sh` reads this file and tests each version. The `--latest N` flag restricts to the most recent N versions.

---

## CI/CD Integration

**`.github/workflows/ci.yml`:**
- Every push/PR: `lint → test → build`
- On `v*` tags: auto-publish to npm with Sigstore provenance

**`.github/workflows/compat.yml`:**
- Daily cron: polls npm for new OpenClaw releases, runs matrix
- Push to main (src/tests/compat changes): tests minimum + latest versions
- Manual dispatch: specific version or full matrix
- On success: auto-creates PR updating `versions.json`
- On failure: auto-creates GitHub issue with `compat,urgent` label
- Never auto-merges or auto-publishes

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

Files prefixed with `docker-` are only run in Docker E2E mode. All other files run in the APP harness.

### Adding a Docker E2E regression

Add a test case to `tests/harness/harness/scenarios/docker-e2e-regression.json`. Docker E2E scenarios have additional fields:

```json
{
  "name": "Slack email obfuscation",
  "message": "Alert: contact admin@noc.internal",
  "realValues": ["admin@noc.internal"],
  "slackE2E": true,
  "slackChannel": "C00000001",
  "checkDeobfuscation": true
}
```

| Field | Type | Purpose |
|-------|------|---------|
| `message` | string | The raw message to send through the channel |
| `realValues` | string[] | PII values that the LLM must not see |
| `checkLlmSees` | string[] | Values that must pass through (public URLs, etc.) |
| `checkDeobfuscation` | boolean | Verify the channel output contains original values |
| `checkAudit` | boolean | Verify audit log entry was written |
| `checkStats` | boolean | Verify stats file was written |
| `slackE2E` | boolean | Run as Slack webhook injection test |
| `slackChannel` | string | Slack channel ID for the webhook event |
| `slackUser` | string | Slack user ID for the webhook event |
| `whatsAppE2E` | boolean | Run as WhatsApp Baileys injection test |
| `cronE2E` | boolean | Run as cron schedule test |
| `multiTurn` | boolean | Run as multi-turn conversation test |

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
      "tests": [
        {
          "name": "Email obfuscation",
          "status": "pass",
          "duration": 12,
          "obfuscation": { "entityCount": 1, "categories": { "email": 1 }, "modified": true },
          "deobfuscation": { "replacementCount": 1, "modified": true }
        }
      ]
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

**Docker E2E fails with "base image not found":**
The base image hasn't been built yet for this OC version. `run-compat.sh` builds it automatically on first run. Use `--rebuild-base` to force a rebuild.

**Mock LLM timeout (5s):**
The mock LLM server failed to start. Check for port conflicts or Node.js issues.

**"Gateway call failed" in Docker E2E:**
The OpenClaw gateway didn't respond. Check that the OpenClaw version supports the plugin API. Minimum supported: 2026.3.22.

**CGNAT leak assertions fail:**
Fake IPv4 surrogates (100.64.x.x) appeared in deobfuscated output. This means deobfuscation missed a mapping. Check the store state and HMAC consistency.

**Roundtrip assertion fails:**
`obfuscate → deobfuscate` didn't produce the original text. Usually caused by overlapping detections or regex changes that alter entity boundaries.
