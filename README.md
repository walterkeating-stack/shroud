<p align="center">
  <img src="logo.png" alt="Shroud" width="160" height="160">
</p>

<h1 align="center">Shroud — Community Edition</h1>

<p align="center">
  Privacy obfuscation for AI agents. Detects sensitive data (PII, network infrastructure, credentials) and replaces it with deterministic fake values before anything reaches the LLM. Tool calls still work because Shroud deobfuscates on the way back. Works with <a href="https://openclaw.ai">OpenClaw</a> (plugin) or any agent via the Agent Privacy Protocol (APP).
</p>

> **Open-source Community Edition** — free to use under Apache 2.0 license. [Enterprise Edition](#enterprise-edition) available with additional features for teams.

## What it does

1. **Detects** 100+ entity types: emails, IPs, phones, API keys, hostnames, SNMP communities, BGP ASNs, credit cards, SSNs, file paths, URLs, person/org/location names, VLANs, route-maps, ACLs, OSPF IDs, IBANs, JWTs, PEM certs, GPS coordinates, ICS/SCADA identifiers, Palo Alto/Check Point/Juniper/Fortinet/F5 config secrets, and custom regex patterns.
2. **Replaces** each value with a deterministic fake (same input + key = same fake every time). Fakes are format-preserving: IPv4 stays in CGNAT range (`100.64.0.0/10`), IPv6 uses ULA range (`fd00::/8`), emails keep `@domain` structure, credit cards pass Luhn, etc.
3. **Deobfuscates** LLM responses and tool parameters so the user sees real values and tools receive real arguments.
4. **Audit logs** every obfuscation/deobfuscation event with counts, categories, char deltas, and optional proof hashes — never logging raw sensitive values.

### Hook lifecycle

| Hook | Direction | What happens |
|------|-----------|-------------|
| `before_prompt_build` | User → LLM | Obfuscate user prompt, prepend privacy context |
| `before_message_write` | Any → History | Obfuscate non-assistant messages; deobfuscate assistant messages |
| `before_tool_call` | LLM → Tool | Deobfuscate tool parameters + track tool chain depth |
| `tool_result_persist` | Tool → History | Obfuscate tool results before storing |
| `message_sending` | Agent → User | Deobfuscate outbound messages (all channels) |
| `globalThis.__shroudDeobfuscate` | Agent → Channel | Global deobfuscation hook — called by OpenClaw before ANY channel send |

> **Privacy guarantee:** Shroud intercepts ALL outbound LLM API calls (Anthropic, OpenAI, Google, any provider) at the `fetch` level and obfuscates PII in every message — including assistant history and Slack `<mailto:>` markup — before it leaves the process. No PII reaches the LLM. On the channel delivery side, Shroud registers `globalThis.__shroudDeobfuscate` — a single function that OpenClaw calls before sending to ANY channel (Slack, WhatsApp, Signal, web, etc.). One hook, all channels, transparent no-op if Shroud isn't loaded.

> **Requires OpenClaw 2026.3.24 or later** with the channel delivery patch (see [OpenClaw patch](#openclaw-channel-delivery-patch) below).

## Install

### OpenClaw (2026.3.24+)

```bash
# Ensure you're on OpenClaw 2026.3.24 or later
openclaw --version

# Install Shroud
openclaw plugins install shroud-privacy
```

Configure in `~/.openclaw/openclaw.json` under `plugins.entries."shroud-privacy".config`. No OpenClaw file modifications needed — Shroud uses runtime prototype patches only.

### Any agent (via APP)

The **Agent Privacy Protocol** (APP) lets any AI agent add privacy obfuscation — no OpenClaw required. Shroud ships with an APP server and a Python client.

```bash
npm install shroud-privacy
```

**Python:**

```python
from shroud_client import ShroudClient

with ShroudClient() as shroud:
    # Before sending to LLM
    result = shroud.obfuscate("Contact admin@acme.com about 10.1.0.1")
    send_to_llm(result.text)  # "Contact user@example.net about 100.64.0.12"

    # After receiving from LLM
    restored = shroud.deobfuscate(llm_response)
    show_to_user(restored.text)  # original values restored
```

Copy `clients/python/shroud_client.py` into your project, or import it directly from the npm install path. Requires Node.js on the PATH.

**Any language:**

Spawn the APP server and talk JSON-RPC over stdin/stdout:

```bash
node node_modules/shroud-privacy/app-server.mjs node_modules/shroud-privacy/dist
```

Handshake (server writes on startup):
```json
{"app":"1.0","engine":"shroud","version":"2.1.0","capabilities":["obfuscate","deobfuscate","batch","stats","health","configure","audit","partitions"]}
```

Obfuscate:
```json
→ {"id":1,"method":"obfuscate","params":{"text":"Contact admin@acme.com"}}
← {"id":1,"result":{"text":"Contact user@example.net","entityCount":1,"categories":{"email":1},"modified":true}}
```

Deobfuscate:
```json
→ {"id":2,"method":"deobfuscate","params":{"text":"Contact user@example.net"}}
← {"id":2,"result":{"text":"Contact admin@acme.com","replacementCount":1,"modified":true}}
```

Other methods: `reset`, `stats`, `health`, `configure`, `shutdown`.

### From source (development)

```bash
git clone https://github.com/walterkeating-stack/shroud.git
cd shroud
npm install && npm run build
openclaw plugins install --path .
openclaw gateway restart
```

## Updating

```bash
# Remove old plugin, reinstall from npm, restart
openclaw plugins remove shroud-privacy
openclaw plugins install shroud-privacy
openclaw gateway restart
```

## Configure

Edit `~/.openclaw/openclaw.json` under `plugins.entries."shroud-privacy".config`:

```jsonc
"shroud-privacy": {
  "enabled": true,
  "config": {
    // Recommended: safe defaults for community use
    "auditEnabled": true           // audit log on — see what Shroud is doing
    // "auditIncludeProofHashes": false  // off by default (opt-in)
    // "auditMaxFakesSample": 0          // off by default (opt-in)
    // "auditLogFormat": "human"         // human-readable single lines
    // "minConfidence": 0.0              // catch everything (default)
    // "secretKey": ""                   // auto-generated if empty
    // "persistentSalt": ""              // set for cross-session consistency
    // "canaryEnabled": false            // data leakage tracking (opt-in)
  }
}
```

Restart the gateway after config changes:

```bash
openclaw gateway restart
```

### Safe defaults

Out of the box, Shroud:
- Auto-generates a secret key (per-session unless you set `secretKey`)
- Detects all entity categories at confidence >= 0.0
- Logs audit lines (counts + categories) but **not** proof hashes or fake samples
- Never logs raw values, real→fake mappings, or original text

To enable proof hashes and fake samples for deeper audit:

```jsonc
"config": {
  "auditEnabled": true,
  "auditIncludeProofHashes": true,
  "auditHashTruncate": 12,
  "auditMaxFakesSample": 3
}
```

## Config reference

### Core settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `secretKey` | string | auto | HMAC secret for deterministic mapping |
| `persistentSalt` | string | `""` | Fixed salt for cross-session consistency |
| `minConfidence` | number | `0.0` | Minimum detector confidence (0.0–1.0) |
| `allowlist` | string[] | `[]` | Values to never obfuscate |
| `denylist` | string[] | `[]` | Values to always obfuscate |
| `canaryEnabled` | boolean | `false` | Inject tracking tokens for leak detection |
| `canaryPrefix` | string | `"SHROUD-CANARY"` | Prefix for canary tokens |
| `auditEnabled` | boolean | `false` | Enable audit logging |
| `verboseLogging` | boolean | `false` | Alias for `auditEnabled` |
| `auditLogFormat` | `"human"` \| `"json"` | `"human"` | Audit output format |
| `auditIncludeProofHashes` | boolean | `false` | Include salted SHA-256 proof hashes |
| `auditHashSalt` | string | `""` | Salt for proof hashes |
| `auditHashTruncate` | number | `12` | Truncate proof hashes to N hex chars |
| `auditMaxFakesSample` | number | `0` | Include up to N fake values in audit (0 = off) |
| `logMappings` | boolean | `false` | Log mapping table (debug only) |
| `customPatterns` | array | `[]` | User-defined regex detection patterns |
| `detectorOverrides` | object | `{}` | Override built-in rules: disable or change confidence per rule name |
| `maxToolDepth` | number | `10` | Max nested tool call depth before warning |
| `redactionLevel` | `"full"` \| `"masked"` \| `"stats"` | `"full"` | Output mode: fake values, partial masking, or category placeholders |
| `dryRun` | boolean | `false` | Detect entities but don't replace (testing mode) |
| `maxStoreMappings` | number | `0` | Max mapping store size with LRU eviction (0 = unlimited) |

> **Env var overrides:** `SHROUD_SECRET_KEY` and `SHROUD_PERSISTENT_SALT` override their respective config keys (priority: env var > plugin config > default).

### Detector overrides

Disable or tune individual detection rules by name. Rule names match the built-in pattern names (e.g. `email`, `ipv4`, `phone_intl`, `cisco_enable_secret`). See `src/detectors/regex.ts` for the full list.

```jsonc
"detectorOverrides": {
  "phone_intl": { "enabled": false },         // disable international phone detection
  "file_path_unix": { "confidence": 0.5 },    // lower confidence (filtered by minConfidence)
  "snmp_community": { "confidence": 1.0 }     // boost to always match
}
```

Rules not listed keep their defaults. Overrides apply to both direct regex detection and code-aware detection.

### Conversational tools

Shroud registers tools that the LLM can call during conversations:

| Tool | What it does |
|------|-------------|
| `shroud-stats` | Show all detection rules with status, confidence, hit counts, store size, and config summary |
| `shroud_status` | Quick stats: entity counts, session info, audit status (JSON) |
| `shroud_reset` | Clear all mappings and start a fresh privacy session |

You can also run the stats CLI from the terminal:

```bash
node ~/.openclaw/extensions/shroud-privacy/scripts/shroud-stats.mjs           # live rule table
node ~/.openclaw/extensions/shroud-privacy/scripts/shroud-stats.mjs --json    # JSON output
node ~/.openclaw/extensions/shroud-privacy/scripts/shroud-stats.mjs --test "Contact john@acme.com"
```

Tip: create an alias for convenience:
```bash
alias shroud-stats="node ~/.openclaw/extensions/shroud-privacy/scripts/shroud-stats.mjs"
```

The CLI reads live stats from `/tmp/shroud-stats.json` (override with `SHROUD_STATS_FILE` env var). The stats file is updated by the running gateway on every obfuscation event.

### How privacy works

Shroud uses **one `globalThis.fetch` intercept** for both directions — no OpenClaw file modifications required:

**Outbound (PII → LLM):** The fetch intercept catches all POST requests to LLM API endpoints (`/v1/messages`, `/chat/completions`, `:generateContent`, etc.). Every message in the request body — user, assistant, system, tool results — is obfuscated before the request leaves the process. Slack `<mailto:>` markup is stripped to prevent PII leaking through chat formatting. Assistant messages from previous turns are re-obfuscated to prevent multi-turn PII leaks.

**Inbound (LLM → User):** The same fetch intercept wraps the LLM's SSE streaming response with a per-block flushing `TransformStream`. Text deltas are buffered per content block. When `content_block_stop` arrives, the accumulated text is deobfuscated and flushed — the first delta receives the full real text, subsequent deltas are emptied. Non-PII blocks stream with zero delay. PII blocks delay by ~0.5-1s (time for one content block to complete). JSON (non-streaming) responses are parsed and deobfuscated directly.

**Result:** OpenClaw receives already-deobfuscated events from the LLM response — it never sees fake text. Every delivery path (Slack, WhatsApp, TUI, Telegram, Discord, Signal, cron, subagents, web) gets real text automatically. Zero OpenClaw patches required. Works with `streaming: "on"` and `streaming: "off"`, and with every LLM provider.

**Defense-in-depth layers:**
1. `EventStream.prototype.push()` patch — deobfuscates content blocks in `message_end` events
2. `globalThis.__shroudDeobfuscate` — available for on-demand deobfuscation
3. `message_sending` hook — deobfuscates outbound message content when fired by OpenClaw
4. `before_message_write` hook — deobfuscates assistant messages in the transcript

### Rule hit counters

Shroud tracks per-rule match counts for the lifetime of the process. Counters appear in three places:

- **`shroud-stats` CLI** — see [Conversational tools](#conversational-tools) above for usage. Shows all rules with status, confidence, and hit counts from the running gateway.
- **Audit log lines** — `byRule=regex:email:3,regex:ipv4:2,...` alongside the existing `byCat` field.
- **`getStats()`** — the `ruleHits` object in the stats response, useful for programmatic access.

Counters reset on `reset()` or gateway restart.

## Redaction levels

Three output modes for different audiences:

- **`full`** (default): Replace with realistic fake values. Best for LLM interaction.
- **`masked`**: Partial masking (`j***@***.com`, `***-**-1234`). Best for human review.
- **`stats`**: Category placeholders (`[EMAIL-1]`, `[HOSTNAME-3]`). Best for dashboards.

```jsonc
"redactionLevel": "masked"
```

## Enterprise Edition

The **Shroud Enterprise Edition** adds features for teams and regulated environments:

- **Multi-tenant isolation** — per-tenant HMAC keying and mapping stores
- **SIEM integration** — real-time event streaming to webhooks (JSON/CEF)
- **Key rotation** — rotate secrets without losing existing mappings
- **Active monitoring** — anomaly detection with alerting pipeline
- **Policy-as-code** — external JSON policy files with glob/regex rules
- **Shared store** — cross-agent file-backed mapping synchronization
- **Compliance mode** — locked category enforcement with audit trail
- **Exposure tracking** — rate-of-exposure alerting per category
- **Hot-reload** — live rule updates without restart
- **Session isolation** — per-session stores and mapping engines
- **Session handoff** — encrypted export/import for session continuity
- **Provenance tagging** — invisible audit markers in output
- **Corpus pre-scanning** — batch obfuscation for RAG pipelines

Contact for licensing: https://github.com/walterkeating-stack/shroud

## Detection intelligence

Shroud includes a `ContextDetector` that wraps the regex engine with post-detection intelligence:

- **Context-aware boosting**: Text blocks containing config keywords (`interface`, `router ospf`, `hostname`) get +10% confidence for detected entities.
- **Proximity clustering**: When a name, email, and phone appear within 200 characters, each gets a confidence boost.
- **Hostname propagation**: `hostname FCNETR1` in one place → bare `FCNETR1` detected everywhere in the text.
- **Learned entities**: Hostnames and infra identifiers seen in previous messages are remembered and detected in future messages without requiring config-line context.
- **Documentation filtering**: RFC 5737 TEST-NET IPs (192.0.2.x, 198.51.100.x, 203.0.113.x), RFC 3849 IPv6 doc prefix (`2001:db8::/32`), IPv6 loopback (`::1`), `example.com` emails, and well-known placeholders are automatically skipped.
- **Common word decay**: Words like `permit`, `deny`, `default` that happen to match patterns get 50% confidence reduction.
- **Recursive deobfuscation**: Up to 3 passes for nested structures (fakes inside JSON-encoded strings).
- **Subnet-aware deobfuscation**: When an LLM derives network/broadcast addresses from fake host IPs (e.g., computing `.0` or `.255`), Shroud reverse-maps them via the SubnetMapper. Works for both CGNAT (IPv4) and ULA (IPv6) fake ranges, including LLM-compressed IPv6 forms.

## Verify it works

After restarting OpenClaw, send a message containing PII (e.g. an email or IP). Then check the logs:

```bash
tail -f ~/.openclaw/logs/openclaw.log \
  | grep -a --line-buffered '"name":"openclaw"' \
  | grep -a --line-buffered 'shroud.*audit' \
  | grep -oP --line-buffered '\[shroud\]\[audit\][^"]*'
```

You should see:

```
[shroud][audit] OBFUSCATE req=dc5f9199cfb0d835 | entities=4 | chars=1200->1218 (delta=+18) | modified=YES | byCat=email:1,ip_address:2,hostname:1 | byRule=regex:email:1,regex:ipv4:2,regex:hostname:1
```

With proof hashes enabled:

```
[shroud][audit] OBFUSCATE req=a3f1bc9e02d4e7f1 | entities=4 | chars=1200->1218 (delta=+18) | modified=YES | byCat=email:1,ip_address:2,hostname:1 | byRule=regex:email:1,regex:ipv4:2,regex:hostname:1 | proof_in=8a3c1f0e2b4d proof_out=f7d2a1c9e084 | fakes=[jsmith@corp.net|100.64.0.12|SW-LAB-01]
```

### Audit field reference

| Field | Meaning |
|-------|---------|
| `req` | Random request ID (hex) — correlates obfuscate ↔ deobfuscate |
| `entities` | Total entities detected and replaced |
| `chars` | Input → output character count |
| `delta` | Character count change (fakes may be longer/shorter) |
| `modified` | `YES` if text was changed, `NO` if pass-through |
| `byCat` | Entity counts by category |
| `byRule` | Entity counts by detector rule |
| `proof_in` | Truncated salted SHA-256 of input text (opt-in) |
| `proof_out` | Truncated salted SHA-256 of output text (opt-in) |
| `fakes` | Sample of fake replacement values (opt-in, never real values) |

### Note on log duplication

OpenClaw logs each plugin message twice (once under the plugin subsystem logger, once under the parent `openclaw` logger). This is normal OpenClaw behavior. Filter to `"name":"openclaw"` to get one line per event, as shown in the verify command above.

## Agent Privacy Protocol (APP)

APP is an open protocol for adding privacy obfuscation to any AI agent. Shroud is the reference implementation.

### Overview

```
┌─────────────────┐     stdin/stdout     ┌──────────────────┐
│   Your Agent    │ ◄──── JSON-RPC ────► │  APP Server      │
│  (any language) │                      │  (app-server.mjs)│
└─────────────────┘                      └──────────────────┘
        │                                        │
        │ 1. obfuscate(user_input)               │ detects PII,
        │ 2. send to LLM ──────────────►         │ returns fakes
        │ 3. deobfuscate(llm_response)           │ restores reals
        │ 4. show to user                        │
```

### Protocol specification

- **Transport**: Newline-delimited JSON-RPC 2.0 over stdin/stdout
- **Encoding**: UTF-8
- **Process model**: Agent spawns APP server as subprocess, one per agent instance

### Handshake

On startup, the server writes a single JSON line to stdout:

```json
{"app":"1.0","engine":"shroud","version":"2.1.0","capabilities":["obfuscate","deobfuscate","batch","stats","health","configure","audit","partitions"]}
```

The agent must read this line before sending requests. Fields:
- `app` — protocol version (always `"1.0"`)
- `engine` — implementation name
- `version` — implementation version
- `capabilities` — supported methods

### Methods

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `obfuscate` | `{text}` | `{text, entityCount, categories, modified, audit}` | Replace real values with fakes |
| `deobfuscate` | `{text}` | `{text, replacementCount, modified, audit}` | Restore fakes to real values |
| `reset` | `{}` | `{ok, summary}` | Clear all mappings |
| `stats` | `{}` | `{storeMappings, ruleHits, ...}` | Engine statistics |
| `health` | `{}` | `{uptime, requests, avgLatencyMs}` | Liveness check |
| `configure` | `{config}` | `{ok}` | Hot-reload configuration |
| `batch` | `{operations: [{direction, text}]}` | `{results: [...]}` | Batch obfuscate/deobfuscate |
| `shutdown` | `{}` | `{ok}` | Graceful shutdown (flushes stats) |

### Request/response format

```
→ {"id":1,"method":"obfuscate","params":{"text":"Server 10.1.0.1 is down"}}
← {"id":1,"result":{"text":"Server 100.64.0.12 is down","entityCount":1,"categories":{"ip_address":1},"modified":true,"audit":{"requestId":"a1b2c3","proofIn":"8a3c1f","proofOut":"f7d2a1"}}}
```

Errors:
```
← {"id":1,"error":{"code":-32602,"message":"Missing required param: text"}}
```

### Heartbeat

The server writes JSON heartbeats to stderr every 30 seconds:
```json
{"heartbeat":true,"pid":12345,"uptime":120,"requests":42,"avgLatencyMs":1.2,"storeSize":15,"memoryMB":28}
```

### Integration checklist

1. `npm install shroud-privacy`
2. Spawn: `node node_modules/shroud-privacy/app-server.mjs node_modules/shroud-privacy/dist`
3. Read handshake line from stdout
4. Before LLM: send `obfuscate`, use returned `text`
5. After LLM: send `deobfuscate`, show returned `text` to user
6. On agent shutdown: send `shutdown`

### Python client

A ready-made Python client is included at `clients/python/shroud_client.py`:

```python
from shroud_client import ShroudClient

client = ShroudClient()
client.start()

safe = client.obfuscate("Contact admin@acme.com about 10.1.0.1")
print(safe.text)          # fakes
print(safe.entity_count)  # 2
print(safe.categories)    # {"email": 1, "ip_address": 1}

real = client.deobfuscate(llm_response)
print(real.text)           # originals restored
print(real.residual_fakes) # any CGNAT/ULA IPs that survived

client.stop()
```

Supports context manager, auto-restart on crash, residual fake detection, and hot-reload via `configure()`.

## Development

```bash
npm install
npm test          # run vitest (718 tests)
npm run build     # compile TypeScript
npm run lint      # type-check without emitting
```

### Deploy after changes

```bash
npm run build
openclaw plugins install --path .
openclaw gateway restart
```

## Release workflow

### Tagging a release

```bash
# 1. Update version in package.json and openclaw.plugin.json
# 2. Update CHANGELOG.md
# 3. Commit and tag
git add -A
git commit -m "release: vX.Y.Z"
git tag vX.Y.Z
git push && git push --tags
```

Then create a GitHub Release from the tag (attach the changelog entry as notes).

### npm publish (maintainers only)

```bash
# Pre-flight (always run before publishing)
npm pack --dry-run             # verify only dist/, openclaw.plugin.json, LICENSE are included
npm run prepublishOnly         # lint + test + build (runs automatically on npm publish)

# One-time setup (when you decide to publish)
npm login
npm profile enable-2fa auth-and-writes

# Publish
npm publish                    # publishConfig.access = "public" is already set
```

**Security notes:**
- Enable 2FA for both login and publish (`auth-and-writes`). This prevents token-only takeover.
- Never commit npm tokens to git. Use `npm login` interactively or set `NPM_TOKEN` as a GitHub Actions secret.
- Use `npm publish --provenance` in CI to add Sigstore attestation (links the package to the exact source commit).

### CI

The repo includes `.github/workflows/ci.yml` which runs lint + test + build on every push and PR. The publish job is present but only triggers on `v*` tags and requires `NPM_TOKEN` as a repository secret — it will no-op until that secret is configured.

## Entity categories

`person_name`, `email`, `phone`, `ip_address`, `api_key`, `url`, `org_name`, `location`, `file_path`, `credit_card`, `ssn`, `mac_address`, `hostname`, `snmp_community`, `bgp_asn`, `network_credential`, `vlan_id`, `interface_desc`, `route_map`, `ospf_id`, `acl_name`, `iban`, `national_id`, `jwt`, `ics_identifier`, `gps_coordinate`, `certificate`, `custom`

## License

[Apache 2.0](LICENSE)
