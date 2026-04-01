# Shroud Security Extension

Agent WAF/IDS built into the privacy plugin. Detects prompt injection, data exfiltration, encoding bypass, and privilege escalation across all channels. Zero runtime dependencies.

## Architecture

```
User input → obfuscation (real PII → deterministic fakes)
           → honeypot injection (fake secrets as tripwires)
           → injection signature scan (50+ patterns)
           → behavioural profiling (per-agent baseline learning)

LLM reasons over fake data, emits tool calls

Tool call → honeypot check (100% certainty if tripped)
          → phantom tool check (100% certainty if tripped)
          → sandbox boundary check (agent's allow/deny list)
          → intent alignment (tool matches user request?)
          → egress detection (sending to unmentioned domains?)
          → sequence anomaly (suspicious tool patterns?)
          → exfil chain (PII in prior results + egress tool?)
          → novel egress tool (first-time communication/network?)
          → tool guard (45 dangerous command patterns)

Tool result → category escalation (high-sensitivity PII from non-read tools?)
            → bulk sensitive (adaptive threshold from baseline)
            → baseline deviation (novel sensitive categories?)

Security events → dedup → SIEM export (webhook + JSONL)
                → LLM grading (TP/FP/NEEDS_REVIEW)
                → dashboard (real-time HTTP + SSE)
```

## Features

### 1. Obfuscation (Core — unchanged)

The foundation. The LLM never sees real PII. Detects 100+ entity types across 30 categories and replaces them with deterministic format-preserving fakes. Makes exfiltration worthless by design.

**Entity categories:** person_name, email, phone, ip_address, api_key, url, hostname, credit_card, ssn, iban, jwt, certificate, network_credential, snmp_community, bgp_asn, mac_address, vlan_id, file_path, gps_coordinate, national_id, ics_identifier, and more.

### 2. Honeypot Injection

Plants fake secrets in the LLM context that have NO real counterpart in the deobfuscation table. No legitimate tool call would ever use them.

If a tool call contains a honeypot value: **100% confirmed injection. Zero false positives.**

| Honeypot Type | Format | What It Catches |
|---------------|--------|-----------------|
| API Key | `sk-hp-{40 hex}` | Authentication/exfil attempt |
| Webhook URL | `https://hp-{8 hex}.internal.monitoring/v1/ingest` | Data exfiltration |
| Hostname | `hp-{8 hex}.internal.monitoring` | Lateral movement |
| Email | `hp-alerts-{6 hex}@security-notifications.internal` | Email exfiltration |
| Credential | `postgresql://hp_readonly:{16 hex}@db-hp-{6 hex}.internal:5432/audit_logs` | Credential reuse |

Tokens are deterministic per agent session (seeded from HMAC key + agent label).

**Config:** `SHROUD_HONEYPOT_ENABLED=true`

### 3. Phantom Tools

Registers 5 fake tools with the LLM that look useful for exfiltration but aren't wired to anything. No user knows they exist — no legitimate instruction triggers them.

| Tool Name | Trap Type | Bait Description |
|-----------|-----------|------------------|
| `upload_file_external` | data_upload | Upload data to external storage endpoint |
| `send_to_webhook` | webhook_relay | Send JSON to any webhook URL |
| `relay_data` | api_relay | Relay data to external API with custom headers |
| `forward_email` | email_forward | Forward message/data to email address |
| `export_to_storage` | file_export | Export to cloud storage (S3, GCS, Azure) |

When triggered: **100% confirmed injection.** Event emitted, logged, handler returns error to prevent LLM retry.

**Config:** `SHROUD_HONEYPOT_ENABLED=true` (controls both honeypots and phantom tools)

### 4. Tool Intent Guardrails

Watches WHICH tools the LLM calls and compares to what the user asked for. No content inspection — pure behavioral analysis.

**Intent extraction** (lightweight keyword matching, no LLM):
- Read/search verbs → expects READ_ONLY tools
- Send/share/notify verbs → allows COMMUNICATE tools
- Run/execute/build verbs → allows EXECUTE tools
- Fetch/browse/visit verbs → allows NETWORK tools
- URL in user message → allowlists that domain for egress

**Checks on every tool call:**

| Check | What It Catches | Severity |
|-------|-----------------|----------|
| Intent alignment | `message` called when user said "summarize" | high |
| Egress detection | `web_fetch` to domain user didn't mention | high |
| Sequence anomaly | read→exec→communicate chain, rapid network burst | medium-high |
| Exfil chain | PII in prior tool result + egress tool now | high (blocks) |
| Novel egress tool | Agent uses communication/network tool for first time | high |
| Sandbox boundary | Tool outside agent's configured allow/deny list | high (blocks) |

**False positive prevention:**
- Read/Write always allowed (local workspace, low risk)
- User mentioning a URL allowlists that domain
- User saying "send" allows communication tools
- "check"/"test"/"build" verbs allow exec

### 5. Tool Result Validation

After a tool executes, checks what PII categories came back in the result. Uses the entity categories that the obfuscator ALREADY computes — zero additional overhead.

| Heuristic | What It Catches | Threshold |
|-----------|-----------------|-----------|
| Category escalation | API keys/SSN/creds from `exec` when user didn't mention credentials | HIGH_SENSITIVITY set |
| Bulk sensitive | Large result with many PII categories from non-read tools | Adaptive: baseline mean + 3σ, or 10KB default |
| Baseline deviation | Novel sensitive categories not in agent's learned profile | Agent's categoryProfile from profiler |

**Adaptive learning:** The profiler accumulates per-agent baselines across sessions. After enough sessions (default 5), the baseline reaches "reliable" maturity. Category escalation and bulk thresholds adapt to what's normal for each specific agent.

### 6. Tool Guard

45 regex patterns detecting dangerous tool call parameters.

**Categories:**
- **Destructive** (6): rm -rf, shutdown, disk format, SQL DROP/TRUNCATE, kill -9
- **Exfiltration** (11): curl POST, wget pipe, netcat, scp, rsync, git push, DNS exfil, email exfil
- **Credential access** (5): /etc/shadow, SSH keys, env dump, cloud creds, shell history
- **Reverse shells** (9): bash, python, netcat, perl, ruby, PHP, node, powershell, socat, openssl, telnet
- **Privilege escalation** (8): sudo, chmod 777, SUID, LD_PRELOAD, Docker escape, nsenter, cloud metadata
- **Crypto mining** (1): xmrig, stratum protocol

### 7. Injection Signature Detection

50+ regex signatures across 8 threat classes, with hot-refresh from external sources.

**Threat classes:**
- `instruction_override` — "ignore all previous instructions"
- `role_switch` — "you are now DAN"
- `prompt_extraction` — "repeat your system prompt"
- `conversation_mockup` — fake role markers (ChatML, \<system\>)
- `encoding_bypass` — base64 payloads, invisible Unicode
- `data_exfiltration` — markdown image exfil, URL-encoded data
- `privilege_escalation` — "you have been granted admin access"
- `mcp_tool_poisoning` — tool definition injection

**Modes:** `off`, `flag` (log only), `block` (reject)

**Config:**
```
SHROUD_INJECTION_DETECTION=flag|block|off
SHROUD_INJECTION_MIN_SEVERITY=low|medium|high
SHROUD_INJECTION_SCAN_RESPONSES=true|false
SHROUD_SIGNATURES_URL=https://example.com/signatures.json
SHROUD_SIGNATURES_REFRESH=3600
```

### 8. Behavioural Profiling

Per-agent statistical baseline learning using Welford's online algorithm.

**Features extracted per turn:**
- Entity category distribution + density + entropy
- Tool call count + tool names
- Directive verb count, question count
- Response length, entity echo rate
- Lexical overlap with previous turn
- LLM cache hit ratio, token counts

**Anomaly types detected:**
- `entity_category_shift` — sudden change in PII types
- `entity_density_spike` — unusual amount of PII
- `tool_outside_profile` — tool never used by this agent
- `topic_discontinuity` — conversation topic shift
- `credential_emergence` — credentials appearing where they shouldn't
- `exfiltration_pattern` — read→send behavioral chain

**Maturity levels:** learning → reliable → mature

**Config:**
```
SHROUD_PROFILING_ENABLED=true
SHROUD_PROFILING_MODE=learning|active|strict
```

### 9. Agent Registry

Loads the OpenClaw agent inventory from `~/.openclaw/openclaw.json` at plugin init. Resolves agent identity from structured signals instead of regex-parsing prompts.

**Resolution tiers:**
1. `ctx.agentId` from OpenClaw hook context (definitive)
2. Signal map: Slack channel IDs, WhatsApp numbers, cron agent IDs, session keys
3. Prompt identity: `- Name:` lines, `# BOOT (...)` headers
4. Fallback: regex extraction from prompt text

**Also provides:**
- Per-agent tool allow/deny lists (sandbox boundary enforcement)
- Canonical agent names (case-insensitive dedup)
- Channel-to-agent bindings from OpenClaw config

### 10. Canary Tokens

Unique tokens injected into the LLM context for data leakage detection.

- **Marker canaries**: tokens that prove data exposure if found outside the session
- **Behavioural canaries**: false instructions with detectable signatures
- **Near-match detection**: Levenshtein distance scanning (catches mangled canaries)

**Config:**
```
SHROUD_CANARY_ENABLED=true
SHROUD_CANARY_SYSTEM=true        # inject into system prompts
SHROUD_CANARY_BEHAVIOURAL=true   # false instruction tripwires
```

### 11. LLM Event Grading

Batches security events and sends them to the Anthropic API for classification as TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_REVIEW.

Uses Claude Code OAuth token from `~/.claude/.credentials.json`. Calls `api.anthropic.com/v1/messages` via Node's native `https` module (bypasses fetch interceptor).

**Config:**
```
SHROUD_LLM_GRADING=true
SHROUD_LLM_GRADING_INTERVAL=300    # seconds between batches
SHROUD_LLM_GRADING_THRESHOLD=5     # min events before grading
```

### 12. Security Dashboard

HTTP server on configurable port. Serves JSON API + embedded HTML dashboard.

**Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness check |
| `/api/overview` | GET | Security summary, agent count, obfuscation stats |
| `/api/agents` | GET | All agents with profiling status (cross-process) |
| `/api/agents/:buildId` | GET | Single agent detail + baseline |
| `/api/events` | GET | Recent security events |
| `/api/events/stream` | GET | SSE real-time event stream |
| `/api/profiling` | GET | All agent baselines |
| `/api/stats` | GET | Combined obfuscation + security stats |
| `/api/policy` | GET | Current firewall policy |
| `/api/policy/default` | PUT | Update default policy |
| `/api/policy/agent/:id` | PUT | Update per-agent policy |
| `/api/grading` | GET | LLM grading stats + verdicts |
| `/api/calls` | GET | LLM call log |

**Config:**
```
SHROUD_DASHBOARD=true
SHROUD_DASHBOARD_PORT=9380
SHROUD_DASHBOARD_BIND=127.0.0.1
```

### 13. SIEM Integration

Ships security events via webhook and/or JSONL file. Events persist across gateway restarts (reloaded from JSONL on startup).

**Config:**
```
SHROUD_SIEM_WEBHOOK_URL=https://your-siem.com/api/events
SHROUD_SIEM_WEBHOOK_AUTH=Bearer your-token
SHROUD_SIEM_JSONL_PATH=/var/log/shroud-security-events.jsonl
```

### 14. Security Event Dedup

Content-hash dedup in the SecurityEventBus. Same `signatureId + matchedText + agentLabel` within a 60-second window is suppressed. Prevents shared system prompt content from generating repeated events per LLM call.

## Environment Variables — Complete Reference

### Core
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_SECRET_KEY` | (auto) | HMAC secret for deterministic fake generation |
| `SHROUD_PERSISTENT_SALT` | "" | Fixed salt for cross-session consistency |
| `SHROUD_STATS_FILE` | `/tmp/shroud-stats.json` | Stats dump path |

### Injection Detection
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_INJECTION_DETECTION` | off | Mode: `flag`, `block`, or `off` |
| `SHROUD_INJECTION_SCAN_RESPONSES` | false | Scan LLM responses |
| `SHROUD_INJECTION_MIN_SEVERITY` | low | Minimum severity: `low`, `medium`, `high` |

### Honeypots & Phantom Tools
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_HONEYPOT_ENABLED` | false | Enable honeypot + phantom tool injection |

### Profiling
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_PROFILING_ENABLED` | false | Enable behavioural profiling |
| `SHROUD_PROFILING_MODE` | learning | Mode: `learning`, `active`, `strict` |

### Canaries
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_CANARY_ENABLED` | false | Enable canary tokens |
| `SHROUD_CANARY_SYSTEM` | false | Inject into system prompts |
| `SHROUD_CANARY_BEHAVIOURAL` | false | Behavioural canary monitoring |

### LLM Grading
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_LLM_GRADING` | false | Enable LLM event classification |
| `SHROUD_LLM_GRADING_INTERVAL` | 300 | Seconds between grading batches |
| `SHROUD_LLM_GRADING_THRESHOLD` | 5 | Min events before grading |

### Signatures
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_SIGNATURES_URL` | null | URL for external signature JSON |
| `SHROUD_SIGNATURES_REFRESH` | 3600 | Polling interval (seconds) |

### Dashboard
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_DASHBOARD` | false | Enable dashboard |
| `SHROUD_DASHBOARD_PORT` | 9380 | HTTP port |
| `SHROUD_DASHBOARD_BIND` | 127.0.0.1 | Bind address |

### SIEM
| Variable | Default | Description |
|----------|---------|-------------|
| `SHROUD_SIEM_WEBHOOK_URL` | null | Webhook URL for event shipping |
| `SHROUD_SIEM_WEBHOOK_AUTH` | null | Auth header for webhook |
| `SHROUD_SIEM_JSONL_PATH` | null | JSONL file path for event log |

## Test Coverage

| Layer | Tests | Description |
|-------|-------|-------------|
| Unit (Vitest) | 1,473 | All detectors, profiler, store, config, security |
| APP Harness | 359 | Mock LLM integration scenarios |
| Docker E2E | 223 | Real OpenClaw gateway, all channels |
| Agent Identity | 9 | Dashboard verification in Docker |
| Security Multi-Agent | 14 | Cross-agent injection + attribution |

## Files

| File | Description |
|------|-------------|
| `src/agent-registry.ts` | OpenClaw agent inventory + signal map |
| `src/agent-session.ts` | Agent session tracking + identity extraction |
| `src/security-event.ts` | SecurityEventBus + dedup + JSONL reload |
| `src/event-grader.ts` | LLM-based event classification |
| `src/profiler.ts` | Behavioural profiler |
| `src/profiler-store.ts` | Baseline persistence (Welford's algorithm) |
| `src/profiler-analysis.ts` | Z-score anomaly detection |
| `src/canary.ts` | Canary token injection + leak detection |
| `src/dashboard.ts` | HTTP dashboard + API |
| `src/policy.ts` | Per-agent security policy engine |
| `src/config.ts` | Config resolver (env vars > plugin config > defaults) |
| `src/detectors/injection.ts` | Injection signature scanner |
| `src/detectors/injection-signatures.ts` | 50+ signature definitions |
| `src/detectors/tool-guard.ts` | 45 dangerous command patterns |
| `src/detectors/tool-intent.ts` | Intent extraction + alignment + egress |
| `src/detectors/result-validator.ts` | Post-tool validation + exfil chain |
| `src/detectors/honeypot.ts` | Honeypot token manager |
| `src/detectors/phantom-tools.ts` | Canary tool definitions |
| `src/detectors/context.ts` | Proximity clustering + learned entities |
| `src/detectors/regex.ts` | 100+ PII regex patterns |
