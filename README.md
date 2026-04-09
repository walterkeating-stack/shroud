<p align="center">
  <img src="logo.png" alt="Shroud" width="160" height="160">
</p>

<h1 align="center">Shroud</h1>

<p align="center">
  <strong>Privacy and infrastructure protection for AI agents.</strong><br>
  Prevents sensitive data from reaching LLMs — PII, network topology, credentials, OT/SCADA identifiers, and internal infrastructure details are replaced with deterministic fakes before any API call leaves the process. Responses are deobfuscated transparently so users and tools see real values.
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="#why-shroud">Why Shroud</a> &middot;
  <a href="#configure">Configure</a> &middot;
  <a href="#agent-privacy-protocol-app">APP Protocol</a> &middot;
  <a href="CHANGELOG.md">Changelog</a>
</p>

> Apache 2.0 &middot; Zero runtime dependencies &middot; Anthropic + OpenAI + Google supported &middot; Prompt-caching friendly &middot; Works with [OpenClaw](https://openclaw.ai) or any agent via [APP](#agent-privacy-protocol-app)

---

## Why Shroud

Frontier LLMs are transformative for infrastructure operations — network troubleshooting, incident response, change planning, compliance audits. But every prompt you send is an API call to a third party. Without protection, you're transmitting:

- **Network topology** — subnets, VLANs, BGP ASNs, OSPF areas, interface descriptions, ACL names, route-maps
- **Device identities** — hostnames, management IPs, SNMP communities, firmware versions
- **Credentials** — API keys, connection strings, PSKs, enable secrets, TACACS/RADIUS shared keys
- **OT/SCADA identifiers** — Modbus addresses, OPC-UA endpoints, IEC 61850 IED names, historian tags, BACnet device IDs
- **Customer PII** — emails, phone numbers, national IDs, credit cards, physical addresses
- **Internal URLs** — wiki pages, Jira tickets, admin portals, API endpoints

Shroud sits between your agent and the LLM. It detects all of the above (100+ entity types), replaces each with a deterministic format-preserving fake, and reverses the mapping on the way back. The LLM reasons over realistic-looking data. Your real infrastructure stays private.

### Who needs this

| Sector | What leaks without Shroud |
|--------|--------------------------|
| **Telecoms & ISPs** | MPLS topologies, BGP peering, customer CPE configs, circuit IDs |
| **Energy & utilities** | SCADA/ICS endpoints, substation IPs, OPC-UA tags, DNP3 addresses |
| **Transport & aviation** | ATC sector IDs, NAV frequencies, signalling network topology |
| **Banking & finance** | Internal API endpoints, database connection strings, customer PII |
| **Healthcare** | Patient identifiers, internal system hostnames, API credentials |
| **Government & defence** | Classified network segments, device inventories, operational IPs |
| **Any enterprise** | Internal URLs, credentials, employee PII, customer data |

### Regulatory context

If you process personal data of EU residents, **GDPR Article 32** requires "appropriate technical measures" to protect it. Sending unredacted PII to a third-party LLM API is a data transfer — Shroud ensures detected PII never leaves your process. Similar obligations exist under CCPA, HIPAA, PCI-DSS, and sector-specific regulations (NIS2, NERC CIP, IEC 62443).

Shroud does not guarantee compliance — regex-based detection has limitations (see [SECURITY.md](SECURITY.md)). But it is a meaningful technical control that reduces exposure.

---

## What it does

1. **Detects** 100+ entity types: emails, IPs, phones, API keys, hostnames, SNMP communities, BGP ASNs, credit cards, SSNs, file paths, URLs, person/org/location names, VLANs, route-maps, ACLs, OSPF IDs, IBANs, JWTs, PEM certs, GPS coordinates, ICS/SCADA identifiers, vendor-specific secrets (Cisco, Juniper, Palo Alto, Check Point, Fortinet, F5, Arista), and custom regex patterns.
2. **Replaces** each value with a deterministic fake (same input + key = same fake every time). Fakes are format-preserving: IPv4 stays in CGNAT range (`100.64.0.0/10`), IPv6 uses ULA range (`fd00::/8`), emails keep `@domain` structure, credit cards pass Luhn, etc.
3. **Passes through public URLs** — external URLs (arxiv.org, docs.stripe.com, etc.) are not obfuscated. Shroud resolves FQDNs via DNS: public IPs pass through, RFC 1918 / NXDOMAIN / internal IPs are obfuscated. Well-known platforms (GitHub, YouTube, Wikipedia, etc.) are always passed through.
4. **Deobfuscates** LLM responses and tool parameters so the user sees real values and tools receive real arguments.
5. **Audit logs** every event with counts, categories, char deltas, and optional proof hashes — never logging raw sensitive values.
6. **Preserves prompt caching.** Obfuscation is deterministic — same input + same key = same output every turn. The system prompt prefix stays identical across turns, so provider-side prompt caching (Anthropic, OpenAI, Bedrock) works normally. No cache-busting, no extra token costs.

### Hook lifecycle

| Hook | Direction | What happens |
|------|-----------|-------------|
| `globalThis.fetch` intercept | User → LLM | Obfuscate all outbound LLM API requests; deobfuscate SSE responses per content block |
| `before_prompt_build` | User → LLM | Warm DNS cache for URL classification; pre-seed mapping store |
| `before_message_write` | Any → History | Deobfuscate assistant messages for transcript; re-obfuscate on next turn |
| `before_tool_call` | LLM → Tool | Deobfuscate tool parameters + track tool chain depth |
| `tool_result_persist` | Tool → History | Obfuscate tool results before storing |
| `message_sending` | Agent → User | Deobfuscate outbound messages (backup — fetch intercept handles primary deob) |
| `globalThis.__shroudStreamDeobfuscate` | LLM → Agent | Streaming event deobfuscation hook |
| `globalThis.__shroudDeobfuscate` | Agent → Channel | Global deobfuscation hook — called by OpenClaw before ANY channel send |

> **How it works:** Shroud intercepts ALL outbound LLM API calls (Anthropic, OpenAI, Google, any provider) at the `fetch` level and obfuscates detected entities in every message — including assistant history and Slack `<mailto:>` markup — before it leaves the process. On the response side, SSE streaming is deobfuscated per content block with buffered flushing. Every delivery path (Slack, WhatsApp, TUI, Telegram, Discord, Signal, web) gets real text automatically. Zero host patches required.

> **Requires OpenClaw 2026.3.22 or later.**

### OpenClaw support policy

- **Formal minimum supported version:** `2026.3.24` (from `openclaw.plugin.json` `minOpenClawVersion`).
- **Release validation matrix (this release):**
  - **Baseline:** `2026.3.28` (includes WhatsApp E2E path)
  - **Latest-at-release:** `2026.4.9` (full 192-scenario E2E pass)
- **Latest caveat:** on OpenClaw builds where WhatsApp provisioning via `channels add` is unsupported, latest-focused compat runs skip WhatsApp E2E and validate Slack E2E.
- **Source of truth for current matrix:** `docs/ci-current-state.md` and `CHANGELOG.md`.

---

## Install

### OpenClaw (2026.3.22+)

```bash
openclaw --version    # ensure 2026.3.22+
openclaw plugins install shroud-privacy
```

Configure in `~/.openclaw/openclaw.json` under `plugins.entries."shroud-privacy".config`. No OpenClaw file modifications needed — Shroud uses runtime interception only.

### Any agent (via APP)

The **Agent Privacy Protocol** (APP) lets any AI agent add privacy and infrastructure protection — no OpenClaw required. Shroud ships with an APP server and a Python client.

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
{"app":"1.0","engine":"shroud","version":"2.2.9","capabilities":["obfuscate","deobfuscate","batch","stats","health","configure","audit","partitions"]}
```

Obfuscate:
```json
> {"id":1,"method":"obfuscate","params":{"text":"Contact admin@acme.com"}}
< {"id":1,"result":{"text":"Contact user@example.net","entityCount":1,"categories":{"email":1},"modified":true}}
```

Deobfuscate:
```json
> {"id":2,"method":"deobfuscate","params":{"text":"Contact user@example.net"}}
< {"id":2,"result":{"text":"Contact admin@acme.com","replacementCount":1,"modified":true}}
```

Other methods: `reset`, `stats`, `health`, `configure`, `shutdown`.

### From source (development)

```bash
git clone https://github.com/wkeything/shroud.git
cd shroud
npm install && npm run build
openclaw plugins install --path .
openclaw gateway restart
```

## Updating

```bash
openclaw plugins remove shroud-privacy
openclaw plugins install shroud-privacy
openclaw gateway restart
```

---

## Configure

Edit `~/.openclaw/openclaw.json` under `plugins.entries."shroud-privacy".config`:

```jsonc
"shroud-privacy": {
  "enabled": true,
  "config": {
    "auditEnabled": true           // audit log on — see what Shroud is doing
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
- Passes through public URLs (DNS-verified) and well-known platforms
- Logs audit lines (counts + categories) but **not** proof hashes or fake samples
- Never logs raw values, real-to-fake mappings, or original text

### Config reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `secretKey` | string | auto | HMAC secret for deterministic mapping |
| `persistentSalt` | string | `""` | Fixed salt for cross-session consistency |
| `minConfidence` | number | `0.0` | Minimum detector confidence (0.0-1.0) |
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

---

## URL handling

Shroud distinguishes between internal and external URLs:

- **External URLs pass through.** When Shroud detects a URL, it checks the FQDN against a DNS cache populated in the `before_prompt_build` hook. If the domain resolves to a public IP, the URL is not obfuscated — the LLM needs to see real URLs for tool calls like `fetch` and `web_search`. Well-known platforms (GitHub, YouTube, Wikipedia, Stack Overflow, npm, PyPI, etc.) always pass through regardless of DNS.

- **Internal URLs are obfuscated.** Domains that resolve to RFC 1918 addresses (10.x, 172.16-31.x, 192.168.x), CGNAT, link-local, loopback, or that fail DNS resolution (NXDOMAIN, timeout) are treated as internal infrastructure and obfuscated.

- **DNS cache miss = obfuscate.** If the FQDN hasn't been resolved yet (first message in a session, DNS timeout), the URL is obfuscated as a safe default. The cache warms on each turn, so subsequent mentions of the same domain will pass through if it's public.

| URL | Resolves to | Action |
|-----|-------------|--------|
| `https://arxiv.org/abs/2301.12345` | 151.101.1.42 (public) | Pass through |
| `https://docs.stripe.com/api` | 52.x.x.x (public) | Pass through |
| `https://wiki.internal.corp/runbooks` | 10.0.0.50 (RFC 1918) | Obfuscate |
| `https://jira.mycompany.net/issue/123` | 172.16.1.10 (RFC 1918) | Obfuscate |
| `https://secret.local/admin` | NXDOMAIN | Obfuscate |
| `https://github.com/org/repo` | (PUBLIC_DOMAINS list) | Pass through |

### LLM agent guidance

Because Shroud replaces URLs before they reach the LLM, the LLM may see unfamiliar or fake-looking domains in the conversation context. Tool calls (fetch, read, etc.) are deobfuscated automatically before execution, so they work correctly even when the LLM sees a fake URL.

**If you are building an agent that uses Shroud, add the following to your agent's system prompt or instruction files:**

> Shroud privacy is active. URLs and domains in the conversation may appear different from what the user sent — internal URLs are replaced with fake domains to protect infrastructure. If a URL looks unfamiliar or doesn't resolve, it has likely been obfuscated. The tool call pipeline deobfuscates automatically. Do NOT tell the user a URL is invalid just because you see an unfamiliar domain. If a fetch or read tool succeeded with the URL, trust the result.

This prevents the LLM from questioning obfuscated URLs or telling the user their link is broken.

---

## Redaction levels

Three output modes for different audiences:

- **`full`** (default): Replace with realistic fake values. Best for LLM interaction.
- **`masked`**: Partial masking (`j***@***.com`, `***-**-1234`). Best for human review.
- **`stats`**: Category placeholders (`[EMAIL-1]`, `[HOSTNAME-3]`). Best for dashboards.

```jsonc
"redactionLevel": "masked"
```

---

## Detection intelligence

Shroud includes a `ContextDetector` that wraps the regex engine with post-detection intelligence:

- **Context-aware boosting**: Text blocks containing config keywords (`interface`, `router ospf`, `hostname`) get +10% confidence for detected entities.
- **Proximity clustering**: When a name, email, and phone appear within 200 characters, each gets a confidence boost.
- **Hostname propagation**: `hostname CORE-RTR-01` in one place → bare `CORE-RTR-01` detected everywhere in the text.
- **Learned entities**: Hostnames and infra identifiers seen in previous messages are remembered and detected in future messages without requiring config-line context.
- **Documentation filtering**: RFC 3849 IPv6 doc prefix (`2001:db8::/32`), IPv6 loopback (`::1`), `example.com` emails, and well-known placeholders are automatically skipped.
- **DNS-based URL classification**: External URLs pass through to the LLM; internal URLs are obfuscated. See [URL handling](#url-handling).
- **Common word decay**: Words like `permit`, `deny`, `default` that happen to match patterns get 50% confidence reduction.
- **Recursive deobfuscation**: Up to 3 passes for nested structures (fakes inside JSON-encoded strings).
- **Subnet-aware deobfuscation**: When an LLM derives network/broadcast addresses from fake host IPs, Shroud reverse-maps them via the SubnetMapper. Works for both CGNAT (IPv4) and ULA (IPv6) fake ranges.

---

## Verify it works

After restarting OpenClaw, send a message containing sensitive data (e.g. an email, IP, or config snippet). Then check the logs:

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

### Conversational tools

| Tool | What it does |
|------|-------------|
| `shroud-stats` | Show all detection rules with status, confidence, hit counts, store size, and config summary |

CLI:

```bash
shroud-stats                          # live rule table
shroud-stats --json                   # JSON output
shroud-stats --test "Contact john@acme.com"   # test detection
```

---

## Entity categories

`person_name`, `email`, `phone`, `ip_address`, `api_key`, `url`, `org_name`, `location`, `file_path`, `credit_card`, `ssn`, `mac_address`, `hostname`, `snmp_community`, `bgp_asn`, `network_credential`, `vlan_id`, `interface_desc`, `route_map`, `ospf_id`, `acl_name`, `iban`, `national_id`, `jwt`, `ics_identifier`, `gps_coordinate`, `certificate`, `custom`

---

## Agent Privacy Protocol (APP)

APP is an open protocol for adding privacy and infrastructure protection to any AI agent. Shroud is the reference implementation.

### Overview

```
+-------------------+     stdin/stdout     +------------------+
|   Your Agent      | <---- JSON-RPC ----> |  APP Server      |
|  (any language)   |                      |  (app-server.mjs)|
+-------------------+                      +------------------+
        |                                        |
        | 1. identify(agent, version)            | registers agent
        | 2. obfuscate(user_input)               | detects entities,
        | 3. send to LLM                         | returns fakes
        | 4. tool_call(tool, args)               | scans tool call
        | 5. deobfuscate(llm_response)           | restores reals
        | 6. show to user                        |
```

### Protocol specification

- **Transport**: Newline-delimited JSON-RPC 2.0 over stdin/stdout
- **Encoding**: UTF-8
- **Process model**: Agent spawns APP server as subprocess, one per agent instance

### Methods

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `identify` | `{agent, version, channel?}` | `{ok, agent, buildId}` | Identify the agent (required before obfuscate/deobfuscate) |
| `obfuscate` | `{text, partition?}` | `{text, entityCount, categories, modified, audit}` | Replace real values with fakes |
| `deobfuscate` | `{text, partition?}` | `{text, replacementCount, modified, audit}` | Restore fakes to real values |
| `tool_call` | `{tool, args?}` | `{allowed, blocked, tool, events?}` | Report a tool call for security scanning |
| `tool_result` | `{tool, result}` | `{text, replacementCount}` | Obfuscate tool result before storing |
| `reset` | `{}` | `{ok, summary}` | Clear all mappings |
| `stats` | `{}` | `{storeMappings, ruleHits, ...}` | Engine statistics |
| `health` | `{}` | `{uptime, requests, avgLatencyMs}` | Liveness check |
| `configure` | `{config}` | `{ok}` | Hot-reload configuration |
| `batch` | `{operations: [{direction, text}]}` | `{results: [...]}` | Batch obfuscate/deobfuscate |
| `setPartition` | `{partition}` | `{ok}` | Switch mapping namespace (multi-tenant) |
| `shutdown` | `{}` | `{ok}` | Graceful shutdown (flushes stats) |

Agents should call `identify` first to register themselves. `tool_call` and `tool_result` are optional — they enable per-tool privacy scanning and mapping isolation for tool arguments.

### Python client

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

---

## Development

```bash
npm install
npm run build               # compile TypeScript
npm run lint                # type-check without emitting
npm test                    # unit + harness (1,238 tests, no Docker)
npm run test:docker         # Docker E2E — real OpenClaw, all channels (192 tests)
npm run test:all            # everything (1,430 tests)
```

### Test layers

| Layer | Command | Tests | What it covers |
|-------|---------|-------|---------------|
| Unit | `npm run test:unit` | 879 | Obfuscator, detectors, generators, store, config |
| APP Harness | `npm run test:integration` | 359 | 48 scenario files via mock LLM, no OpenClaw |
| Docker E2E | `npm run test:docker` | 192 | Real OpenClaw gateway, Slack/WhatsApp/Cron/TUI channels, 153 regression scenarios |
| Sandbox E2E | `run-compat.sh <ver> --sandbox` | +8 | Docker-in-Docker, sandboxed agent exec, tool call deobfuscation |

Docker E2E runs inside an isolated container (`--internal` network, no external routing). Both OpenClaw and Shroud are installed from npm — the same path real users take. A single gateway process handles all tests via WebSocket RPC. Channel tests use mock servers with real SDK code paths (Slack via Bolt HTTP, WhatsApp via Baileys intercept).

### OpenClaw compatibility matrix

```bash
bash compat/run-compat.sh latest           # test against latest OpenClaw
bash compat/run-compat.sh latest --sandbox # include sandboxed agent exec tests
bash compat/run-matrix.sh                  # interactive: current or current + last 3
bash compat/run-matrix.sh --latest 3       # latest 3 versions
bash compat/run-matrix.sh --parallel       # parallel execution
```

Supported versions are tracked in `compat/versions.json`. CI checks for new OpenClaw releases daily.

---

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. Shroud uses regex-based detection which may not catch all sensitive data. It reduces exposure but does not eliminate it. See [SECURITY.md](SECURITY.md) for known limitations. The authors assume no responsibility for data leakage, compliance failures, or any damages arising from use of this software.

## License

[Apache 2.0](LICENSE)
