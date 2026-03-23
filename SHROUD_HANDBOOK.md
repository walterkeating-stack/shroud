# Shroud Operations Handbook

> Quick reference for every environment where Shroud is deployed — local OpenClaw, private agents (NCG), or custom integrations.

---

## Table of Contents

1. [What Shroud Does](#1-what-shroud-does)
2. [Installation & Deployment](#2-installation--deployment)
3. [Where Config Lives](#where-config-lives)
4. [Configuration Reference](#3-configuration-reference)
4. [Environment Variables](#4-environment-variables)
5. [Entity Categories](#5-entity-categories)
6. [Detection Pipeline](#6-detection-pipeline)
7. [Detectors & Patterns](#7-detectors--patterns)
8. [Detector Overrides](#8-detector-overrides)
9. [Obfuscation Pipeline](#9-obfuscation-pipeline)
10. [Deobfuscation & Reverse Mapping](#10-deobfuscation--reverse-mapping)
11. [Fake Value Generators](#11-fake-value-generators)
12. [Redaction Levels](#12-redaction-levels)
13. [Allowlist & Denylist](#13-allowlist--denylist)
14. [Dry-Run Mode](#14-dry-run-mode)
15. [Filter Stats](#15-filter-stats)
16. [Audit Logging](#16-audit-logging)
17. [Config Validation](#17-config-validation)
18. [LRU Store Eviction](#18-lru-store-eviction)
19. [OpenClaw Hooks](#19-openclaw-hooks)
20. [Registered Tools](#20-registered-tools)
21. [Enterprise Features](#21-enterprise-features)
22. [Policy-as-Code](#22-policy-as-code)
23. [Session Handoff](#23-session-handoff)
24. [Cross-Agent Shared Store](#24-cross-agent-shared-store)
25. [Multi-Tenant Isolation](#25-multi-tenant-isolation)
26. [Provenance Tagging](#26-provenance-tagging)
27. [Compliance Mode](#27-compliance-mode)
28. [Exposure Tracking](#28-exposure-tracking)
29. [Key Rotation](#29-key-rotation)
30. [SIEM Integration](#30-siem-integration)
31. [Hot-Reload](#31-hot-reload)
32. [Per-Session Isolation](#32-per-session-isolation)
33. [Active Monitoring](#33-active-monitoring)
34. [CLI Tools](#34-cli-tools)
35. [Diagnostics & Troubleshooting](#35-diagnostics--troubleshooting)
36. [Private Agent Integration (NCG)](#36-private-agent-integration-ncg)

---

## 1. What Shroud Does

Shroud is a privacy plugin that sits between the user and the LLM. It:

- **Detects** sensitive entities (emails, IPs, API keys, hostnames, credentials, etc.) in all text flowing to the LLM
- **Replaces** them with format-preserving fake values (same structure, safe content)
- **Reverses** the replacements in LLM responses so the user sees real values

The LLM never sees real sensitive data. All operations are synchronous and deterministic.

---

## 2. Installation & Deployment

### OpenClaw

```bash
openclaw plugins install shroud-privacy
```

### NCG Agent

```bash
python agent.py plugin install shroud-privacy
```

### From Source (Development)

```bash
cd shroud && npm install && npm run build
bash deploy-local.sh     # → OpenClaw (~/.openclaw/extensions/)
bash deploy-ncg.sh       # → NCG (~/.ncg/extensions/)
```

### Custom Integration

Import `Obfuscator` and `resolveConfig` directly:

```javascript
import { resolveConfig } from 'shroud-privacy/dist/config.js';
import { Obfuscator } from 'shroud-privacy/dist/obfuscator.js';

const config = resolveConfig({ secretKey: 'your-key' });
const obf = new Obfuscator(config);

// Obfuscate before sending to LLM
const result = obf.obfuscate(userText);
sendToLLM(result.obfuscated);

// Deobfuscate LLM response
const real = obf.deobfuscate(llmResponse);
```

---

## Where Config Lives

Both OpenClaw and NCG store Shroud config in the same JSON structure — only the file path differs:

| Platform | Config file |
|----------|-------------|
| OpenClaw | `~/.openclaw/openclaw.json` |
| NCG | `~/.ncg/ncg.json` |

In both cases, Shroud's settings go inside `plugins.entries."shroud-privacy".config`:

```jsonc
// ~/.openclaw/openclaw.json  OR  ~/.ncg/ncg.json
{
  "plugins": {
    "entries": {
      "shroud-privacy": {
        "enabled": true,
        "config": {
          // ← All Shroud config goes here.
          // Every JSON snippet in this handbook is shorthand
          // for a key inside this "config" block.
          "secretKey": "your-secret-key-32chars-minimum",
          "auditEnabled": true
        }
      }
    }
  }
}
```

**For custom integrations**, there is no config file — you pass the same keys as a plain object to `resolveConfig({ ... })`.

**Environment variables** (e.g. `SHROUD_SECRET_KEY`) override config file values regardless of deployment. See [Environment Variables](#4-environment-variables).

> **Reading the rest of this handbook:** Every JSON snippet shown below is shorthand for keys inside the `"config"` block above. For example, when you see:
> ```json
> { "auditEnabled": true, "auditLogFormat": "json" }
> ```
> it means add those keys to your config file at `plugins.entries."shroud-privacy".config`.

---

## 3. Configuration Reference

All config fields, types, and defaults:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `secretKey` | string | *auto-generated* | HMAC key for mapping. Set via config or `SHROUD_SECRET_KEY`. Min 16 chars, recommended 32+. |
| `persistentSalt` | string | `""` | Fixed salt for reproducible mappings across sessions. Leave empty for random per-session. |
| `minConfidence` | number | `0.0` | Minimum detector confidence [0–1] to include an entity. |
| `allowlist` | string[] | `[]` | Values to never obfuscate. Supports `*` and `?` wildcards. |
| `denylist` | string[] | `[]` | Values to always obfuscate (force-add as CUSTOM category). |
| `canaryEnabled` | boolean | `false` | Inject hidden canary tokens for leak detection. |
| `canaryPrefix` | string | `"SHROUD-CANARY"` | Prefix for canary HTML comments. |
| `auditEnabled` | boolean | `false` | Enable audit logging (never logs real values). |
| `logMappings` | boolean | `false` | Log real→fake mappings (security risk — debug only). |
| `customPatterns` | array | `[]` | User-defined patterns: `{name, pattern, category?}`. |
| `verboseLogging` | boolean | `false` | Verbose per-request audit lines. |
| `auditLogFormat` | `"human"` \| `"json"` | `"human"` | Audit output format. |
| `auditIncludeProofHashes` | boolean | `false` | SHA-256 proof hashes in audit (tamper evidence). |
| `auditHashSalt` | string | `""` | Salt for proof hashes. |
| `auditHashTruncate` | number | `12` | Truncate proof hashes to N hex chars. |
| `auditMaxFakesSample` | number | `0` | Sample N fake values in audit (0 = none). |
| `detectorOverrides` | object | `{}` | Per-rule overrides: `{ruleName: {enabled?, confidence?}}`. |
| `dryRun` | boolean | `false` | Detect but don't replace — for testing/auditing. |
| `maxStoreMappings` | number | `0` | Max store size; oldest evicted when exceeded (0 = unlimited). |
| `tenantId` | string | `""` | Multi-tenant HMAC keying. |
| `maxToolDepth` | number | `10` | Warn when tool chain exceeds this depth. |
| `lockedCategories` | Category[] | `[]` | Categories that MUST be detected (compliance). |
| `exposureWindow` | number | `60000` | Sliding window (ms) for exposure tracking. |
| `exposureThresholds` | object | `{}` | Per-category max detections per window. |
| `exposureGlobalThreshold` | number | `100` | Global detection limit per window. |
| `policyFile` | string | `""` | Path to policy-as-code JSON file. |
| `redactionLevel` | `"full"` \| `"masked"` \| `"stats"` | `"full"` | How replacements are displayed. |
| `sharedStorePath` | string | `""` | File path for cross-agent shared mappings. |
| `sharedStoreTtlMs` | number | `5000` | Cache TTL for shared store reads (ms). |
| `provenanceTagging` | boolean | `false` | Embed `«shroud:category:hash»` markers. |
| `sessionHandoff` | boolean | `false` | Enable encrypted mapping export/import. |
| `keys` | array | `[]` | Versioned keys: `[{version, key, createdAt?, expiresAt?, retired?}]`. |
| `activeKeyVersion` | number | `0` | Which key version to use for new obfuscations (0 = highest). |
| `siemWebhooks` | array | `[]` | SIEM webhook endpoints: `[{url, authHeader?, headers?, eventTypes?}]`. |
| `siemBatchSize` | number | `100` | Max events before auto-flush. |
| `siemFlushIntervalMs` | number | `30000` | Periodic flush interval (ms). |
| `siemMaxRetries` | number | `3` | Max retry attempts per HTTP flush. |
| `siemRetryBackoffMs` | number | `1000` | Initial retry backoff (doubles each retry). |
| `siemEventFormat` | `"json"` \| `"cef"` | `"json"` | SIEM event output format. |
| `hotReload` | boolean | `false` | Watch config files and reload detection rules on change. |
| `customPatternsFile` | string | `""` | Path to custom patterns JSON file (for hot-reload). |
| `hotReloadDebounceMs` | number | `1000` | Debounce interval for file changes (ms). |
| `sessionIsolation` | boolean | `false` | Enable per-session isolated mapping stores. |
| `monitorEnabled` | boolean | `false` | Enable active monitoring and alerting pipeline. |
| `monitorRateWindowMs` | number | `60000` | Rolling window for rate baseline (ms). |
| `monitorSpikeMultiplier` | number | `3.0` | Alert when rate exceeds baseline × multiplier. |
| `monitorMaxAlerts` | number | `500` | Max alerts to keep in memory. |

---

## 4. Environment Variables

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `SHROUD_SECRET_KEY` | `secretKey` | HMAC secret key |
| `SHROUD_PERSISTENT_SALT` | `persistentSalt` | Fixed salt |
| `SHROUD_TENANT_ID` | `tenantId` | Tenant ID |
| `SHROUD_SHARED_STORE` | `sharedStorePath` | Shared store file path |
| `SHROUD_STATS_FILE` | — | Stats file location (default: `/tmp/shroud-stats.json`) |
| `SHROUD_SIEM_WEBHOOK_URL` | `siemWebhooks` | Quick single-endpoint SIEM setup |
| `SHROUD_SIEM_WEBHOOK_AUTH` | — | Auth header for `SHROUD_SIEM_WEBHOOK_URL` |
| `SHROUD_KEYS` | `keys` | JSON-encoded array of versioned key objects |

Priority: env vars > plugin config > defaults.

---

## 5. Entity Categories

Shroud detects 27 entity categories:

**Core PII:** `person_name`, `email`, `phone`, `ip_address`, `url`, `file_path`, `credit_card`, `ssn`

**Network Infrastructure:** `mac_address`, `hostname`, `snmp_community`, `bgp_asn`, `network_credential`, `vlan_id`, `interface_desc`, `route_map`, `ospf_id`, `acl_name`

**Enterprise / Regulated:** `api_key`, `org_name`, `location`, `iban`, `national_id`, `jwt`, `ics_identifier`, `gps_coordinate`, `certificate`, `custom`

---

## 6. Detection Pipeline

Text flows through four detector layers:

1. **RegexDetector** — 70+ named patterns with confidence scores
2. **ContextDetector** — Wraps regex with confidence boosting:
   - Config keyword density → higher confidence
   - Proximity clustering (nearby entities boost each other)
   - Hostname extraction from config lines
   - Learned entity memory across calls
   - Confidence decay for common words (permit, deny, etc.)
3. **CodeDetector** — Extracts string literals/comments from source code, runs regex on them
4. **CustomPatternDetector** — User-defined patterns from config

---

## 7. Detectors & Patterns

### Built-in Pattern Groups (70+ rules)

**PII:** `email`, `ipv4`, `ipv6`, `phone_us`, `phone_intl`, `credit_card`, `ssn`, `url`

**API Keys & Tokens:** `api_key_generic`, `api_key_aws`, `bearer_token`, `aws_secret_key`, `gcp_api_key`, `slack_token`, `github_pat`, `gitlab_token`, `stripe_key`, `sendgrid_key`, `hashicorp_vault_token`

**Network Protocols:** `snmp_community`, `snmp_auth_priv`, `bgp_asn`, `bgp_neighbor_password`, `ospf_router_id`, `ospf_area`, `ospf_auth_key`, `vlan_name`, `vlan_range`, `interface_description`, `route_map_name`, `prefix_list_name`, `acl_name`

**Cisco Secrets:** `cisco_enable_secret`, `cisco_password_line`, `cisco_username_secret`, `cisco_password_hash_type5`, `cisco_password_hash_type8`, `cisco_password_hash_type9`, `cisco_type7`, `tacacs_key`, `radius_key`, `ntp_auth_key`, `key_string`

**Multi-Vendor:** `junos_secret`, `junos_preshared_key`, `panos_api_key`, `checkpoint_password_hash`

**Certificates & Directory:** `pem_private_key`, `pem_certificate`, `ldap_bind_dn`, `windows_sid`

**Cloud & DB:** `azure_connection_string`, `db_connection_string`, `jdbc_url`, `url_query_password`, `connection_string_password`

**Secrets:** `base64_secret_assignment`, `base64_prefixed`

**File Paths:** `file_path_unix`, `file_path_windows`

**Hostnames:** `cisco_hostname`, `device_name_dotted`, `device_name_short`, `device_name_hyphenated`

### Custom Patterns

In `~/.openclaw/openclaw.json` (inside `plugins.entries."shroud-privacy".config`):

```jsonc
// ~/.openclaw/openclaw.json → plugins.entries."shroud-privacy".config
{
  "customPatterns": [
    { "name": "employee_id", "pattern": "EMP-\\d{6}", "category": "custom" },
    { "name": "ticket", "pattern": "TICKET-[A-Z]+-\\d+", "category": "custom" }
  ]
}
```

> From here on, all JSON snippets are shorthand for keys inside this same config block.

---

## 8. Detector Overrides

Disable or tune individual detectors:

```json
{
  "detectorOverrides": {
    "email": { "enabled": false },
    "ipv4": { "confidence": 0.85 },
    "file_path_unix": { "enabled": false },
    "bgp_asn": { "confidence": 0.95 }
  }
}
```

- `enabled: false` — Suppress all matches from that rule
- `confidence: N` — Override the rule's default confidence score

The `detector` field in results shows the rule name: `regex:email`, `regex:ipv4`, etc.

---

## 9. Obfuscation Pipeline

When `obfuscate(text)` is called, 9 steps execute in order:

1. **Learn subnets** — Scan for CIDR notation (`10.0.0.0/24`) and subnet masks (`255.255.255.0`) to understand network topology
2. **Detect entities** — Run all detectors; collect all matches with positions and confidence
3. **Apply denylist** — Force-add denylist values found in text (+ policy denylist)
4. **Resolve overlaps** — Sort by position; when spans overlap, keep higher confidence
5. **Filter** — Remove entities below `minConfidence`, on allowlist (exact + wildcard), on policy allowlist, or already-known fakes
6. **Map & replace** — Right-to-left replacement preserving positions:
   - Look up or generate fake value
   - Apply redaction level formatting
   - Optionally add provenance tag
7. **Inject canary** — Append invisible HTML comment (if enabled)
8. **Compliance check** — Verify locked categories were found
9. **Exposure tracking** — Check per-category detection rates against thresholds

**Returns `ObfuscationResult`:**
```typescript
{
  original: string,         // Input text
  obfuscated: string,       // Output with fakes
  entities: DetectedEntity[], // What was replaced
  mappingsUsed: Record<string, string>,  // real → fake
  complianceReport?: ComplianceReport,
  filterStats?: FilterStats
}
```

---

## 10. Deobfuscation & Reverse Mapping

`deobfuscate(text)` reverses all known fakes back to real values:

1. Strip canary tokens and provenance tags
2. Build reverse map (fake → real), sorted longest-first
3. **Multi-pass replacement** (up to 3 passes) for nested structures
4. **Subnet-aware CGNAT residual** — Reverse-map derived fake IPs the LLM computed (network addresses, broadcasts)
5. **IPv6 ULA residual** — Handle compressed `fd00::` forms and `/64` prefix extractions

`deobfuscateWithStats(text)` returns `{ text, replacementCount }` for audit without logging content.

---

## 11. Fake Value Generators

### IP Addresses

| Type | Fake Range | Strategy |
|------|-----------|----------|
| IPv4 | `100.64.0.0/10` (CGNAT) | Subnet-preserving: network bits → CGNAT, host bits preserved exactly |
| IPv6 | `fd00::/8` (ULA) | SHA-256 derived 8-group address |

Same subnet → same fake subnet. Host `.42` stays `.42`.

### Emails

Format-preserving: matches local part length, TLD, dot patterns.
`john.doe@company.com` → `dev.ops42@nexus.dev`

### URLs

Path-depth preserving: `https://internal.corp/api/v2/users` → `https://nexus.dev/app/api/docs`

### MAC Addresses

Format-preserving (colon/dash/Cisco-dot): `aa:bb:cc:dd:ee:ff` → `02:c3:a8:91:ff:e2`

### BGP ASN

Private range: `64512–65534`

### SNMP Communities

Pool: `COMMUNITY_RO`, `COMMUNITY_RW`, `SNMP_STR_001`, etc.

### Network Credentials

Preserves hash type prefix: `$1$salt$hash` → `$1$fakesalt$fakehash`

### Hostnames

Site + role format: `SITE-A-SW-01`, `SITE-B-RTR-03`

### VLAN IDs

Numeric (100–3999) or name from pool: `MGMT`, `USERS`, `DMZ`, etc.

### Other Network Infra

- **Route maps**: `RM-PEER-IN`, `RM-TRANSIT`, `RM-EXPORT`, etc.
- **ACL names**: `ACL-MGMT`, `ACL-VPN`, `ACL-OUTSIDE`, etc.
- **Interface descriptions**: `Uplink to Core`, `Server Farm Link`, etc.
- **OSPF IDs**: IP-format or numeric area ID

### Codes & IDs

- **API keys**: Prefix-preserving (`sk-` stays `sk-`)
- **Credit cards**: Luhn-valid 16 digits, separator-preserving
- **SSN**: Valid format `XXX-XX-XXXX` (avoids invalid areas)
- **Phone**: Format-preserving (parens, country code, separators)
- **IBAN**: Country code preserved, fake digits
- **JWT**: Valid 3-part structure with fake payload
- **File paths**: Depth and extension preserved

---

## 12. Redaction Levels

| Level | Config Value | Behavior | Example |
|-------|-------------|----------|---------|
| Full | `"full"` | Replace with realistic fake | `john@co.com` → `admin@nexus.dev` |
| Masked | `"masked"` | Partial masking | `jo***@***.com` |
| Stats | `"stats"` | Category placeholder + counter | `[EMAIL-1]`, `[IP_ADDRESS-2]` |

Set via `redactionLevel` config.

---

## 13. Allowlist & Denylist

### Allowlist (never obfuscate)

```json
{
  "allowlist": [
    "localhost",
    "127.0.0.1",
    "*@mycompany.com",
    "10.0.0.*",
    "admin-??"
  ]
}
```

- Exact strings: fast Set lookup
- `*` matches any characters; `?` matches single character
- Case-insensitive for wildcards

### Denylist (always obfuscate)

```json
{
  "denylist": ["CLASSIFIED-PROJECT", "secret-codename"]
}
```

Denylist values found in text are force-added as `CUSTOM` category with confidence 1.0.

---

## 14. Dry-Run Mode

```json
{ "dryRun": true }
```

- Runs the full detection pipeline
- Returns `entities` and `filterStats` as normal
- **Does not replace text** — `obfuscated === original`
- **Does not create mappings** — store stays empty

Use for auditing what Shroud would detect without modifying anything.

---

## 15. Filter Stats

Every `ObfuscationResult` includes `filterStats`:

```typescript
{
  totalDetected: 12,      // All entities before filtering
  replaced: 8,            // Entities that made it through
  belowThreshold: 2,      // Filtered by minConfidence
  allowlisted: 1,         // Filtered by allowlist/policy
  docExamples: 0,         // Filtered as documentation values
  alreadyObfuscated: 1    // Filtered as known fakes
}
```

---

## 16. Audit Logging

### Enable

```json
{
  "auditEnabled": true,
  "verboseLogging": true,
  "auditLogFormat": "json"
}
```

### What Gets Logged

- Entity counts per category and rule
- Char count deltas (input vs output size)
- Request IDs for correlation
- Optional proof hashes (SHA-256 of input/output, truncated, salted)
- Optional fake value samples
- **Never logs real sensitive values**

### Human Format

```
[shroud][audit] OBFUSCATE req=a1b2 | entities=5 | byCat=email:2,ip_address:3 | chars=500->520 | modified=YES
```

### JSON Format

```json
{
  "event": "shroud.audit.obfuscate",
  "req": "a1b2",
  "totalEntities": 5,
  "byCategory": {"email": 2, "ip_address": 3},
  "charDelta": 20,
  "modified": true
}
```

---

## 17. Config Validation

```javascript
import { resolveConfig, validateConfig } from 'shroud-privacy/dist/config.js';

const config = resolveConfig(rawConfig);
const issues = validateConfig(config);

for (const issue of issues) {
  console.log(`[${issue.severity}] ${issue.field}: ${issue.message}`);
}
```

### Checks Performed

| Severity | Field | Condition |
|----------|-------|-----------|
| ERROR | `secretKey` | < 16 characters |
| WARNING | `secretKey` | 16–32 characters |
| ERROR | `minConfidence` | Outside [0, 1] |
| ERROR | `maxStoreMappings` | Negative |
| ERROR | `customPatterns` | Invalid regex |
| WARNING | `exposureWindow` | < 1000ms with thresholds set |
| WARNING | `policyFile` | File not found |
| WARNING | `sharedStorePath` | Conflicts with `tenantId` |
| INFO | `dryRun` | Active (text won't be modified) |
| INFO | `detectorOverrides` | N overrides configured |

Returns `ConfigIssue[]` — does not throw. Callers decide how to handle.

---

## 18. LRU Store Eviction

```json
{ "maxStoreMappings": 10000 }
```

- When the store reaches `maxStoreMappings`, the oldest mapping is evicted (FIFO)
- Updating an existing mapping does NOT trigger eviction
- `0` = unlimited (default)
- Evicted mappings can no longer be deobfuscated

Use to bound memory in long-running sessions.

---

## 19. OpenClaw Hooks

| # | Hook | Timing | Sync? | Action |
|---|------|--------|-------|--------|
| 1 | `before_prompt_build` | User prompt ready | Async | Obfuscate user prompt |
| 2 | `before_llm_send` | LLM payload ready | Async | Obfuscate all messages; install `transformResponse` to deobfuscate LLM output |
| 3 | `before_tool_call` | Tool call starting | Async | Deobfuscate tool parameters |
| 4 | `tool_result_persist` | Tool result ready | **Sync** | Obfuscate tool result |
| 5 | `message_sending` | Outbound message | Async | Deobfuscate content (fallback) |

---

## 20. Registered Tools

Shroud registers these tools in OpenClaw:

### `shroud_status`

Returns JSON with: store size, salt, canary ID, audit stats, rule hits, detections by category, replacements by category, and all enterprise feature states.

### `shroud_reset`

Clears all mappings and starts a fresh session.

### `shroud-session-export` (if `sessionHandoff: true`)

Returns an AES-256-GCM encrypted blob of all mappings.

### `shroud-session-import` (if `sessionHandoff: true`)

Restores mappings from an encrypted blob.

### `shroud-rotate-key`

Rotate the HMAC secret key at runtime. Accepts optional `key` (auto-generated if omitted) and `expiresAt`. Returns new version info.

### `shroud-key-status`

Show key ring status: active version, all versions with creation/expiry dates, retired/expired flags.

### `shroud-monitor` (if `monitorEnabled: true`)

Show active monitoring pipeline stats and recent alerts. Accepts `unacknowledgedOnly` filter.

### `shroud-sessions` (if `sessionIsolation: true`)

Manage per-session isolation. Actions: `list`, `create`, `switch`, `destroy`.

---

## 21. Enterprise Features

| # | Feature | Config | Description |
|---|---------|--------|-------------|
| 1 | Multi-tenant | `tenantId` | Separate HMAC keying per tenant |
| 2 | Session handoff | `sessionHandoff` | Encrypted export/import of mappings |
| 3 | Tool depth | `maxToolDepth` | Warn on deep tool chains |
| 4 | Compliance mode | `lockedCategories` | Require specific categories |
| 5 | Exposure tracking | `exposureThresholds` | Alert on detection spikes |
| 6 | Corpus pre-scan | `preScanCorpus()` | Batch obfuscate documents |
| 7 | Policy-as-code | `policyFile` | External allowlist/denylist JSON |
| 8 | Redaction levels | `redactionLevel` | Full / masked / stats |
| 9 | Shared store | `sharedStorePath` | Cross-agent consistency |
| 10 | Provenance | `provenanceTagging` | Origin markers for audit trail |
| 11 | Key rotation | `keys`, `activeKeyVersion` | Versioned keys with rotation, expiration, retirement |
| 12 | SIEM push | `siemWebhooks` | Real-time event streaming to SIEM endpoints |
| 13 | Hot-reload | `hotReload` | Live reload of detection rules on file change |
| 14 | Session isolation | `sessionIsolation` | Per-session isolated mapping stores |
| 15 | Active monitoring | `monitorEnabled` | Anomaly detection and alerting pipeline |

---

## 22. Policy-as-Code

Create a JSON policy file:

```json
{
  "allowlist": [
    "localhost",
    { "pattern": "192.0.2.*", "type": "glob" },
    { "pattern": "^test-.*", "type": "regex" }
  ],
  "denylist": [
    "CLASSIFIED",
    { "pattern": "secret-*", "type": "glob", "category": "api_key" }
  ]
}
```

Configure: `{ "policyFile": "/path/to/policy.json" }`

**Pattern types:** `literal` (default), `glob`, `regex`.

---

## 23. Session Handoff

Enables mapping continuity across sessions or agents:

```json
{ "sessionHandoff": true }
```

**Export:** `obfuscator.exportSession()` → encrypted Base64 blob (AES-256-GCM)
**Import:** `obfuscator.importSession(blob)` → restores all mappings

The blob contains: `[real, fake, category]` tuples + salt + tenant + timestamp. The encryption key is derived from `secretKey` via scrypt.

---

## 24. Cross-Agent Shared Store

Multiple Shroud instances share a single mapping file:

```json
{ "sharedStorePath": "/tmp/shroud-shared-store.json" }
```

- File-backed with in-memory cache (TTL: `sharedStoreTtlMs`)
- Synchronous reads (required by sync hooks)
- Writes flush immediately
- Last-write wins on conflict

---

## 25. Multi-Tenant Isolation

```json
{ "tenantId": "customer-a" }
```

- Tenant ID incorporated into HMAC seed
- Same real value → different fake per tenant
- Separate mapping stores per tenant
- Switch at runtime: `obfuscator.switchTenant("customer-b")`

---

## 26. Provenance Tagging

```json
{ "provenanceTagging": true }
```

Appends origin markers after each replacement:

```
admin@nexus.dev«shroud:email:a5c2»
```

- `«` and `»` delimiters (Unicode guillemets)
- Category + 4-char hash for traceability
- Automatically stripped during deobfuscation

---

## 27. Compliance Mode

```json
{
  "lockedCategories": ["email", "person_name", "phone"]
}
```

After obfuscation, the `complianceReport` indicates:
- `found`: Categories that were detected
- `missing`: Required categories NOT detected
- `passed`: `true` only if all locked categories found

Use for GDPR/HIPAA compliance enforcement.

---

## 28. Exposure Tracking

```json
{
  "exposureThresholds": { "email": 10, "credit_card": 3 },
  "exposureGlobalThreshold": 50,
  "exposureWindow": 60000
}
```

Sliding window tracks detection counts. `getExposureAlerts()` returns alerts when thresholds exceeded:

```typescript
{ category: "email", count: 15, threshold: 10, windowMs: 60000, message: "..." }
```

---

## 29. Key Rotation

### Overview

Key rotation allows changing the HMAC secret key without losing the ability to decode existing mappings. Old fakes remain in the mapping store and deobfuscate correctly. New obfuscations use the new key.

### How It Works

1. **KeyRing** holds multiple `VersionedKey` entries, each with a version number, key string, creation timestamp, optional expiration, and retired flag.
2. The **active key** is the highest non-expired, non-retired key (or explicitly set via `activeKeyVersion`).
3. When you rotate, a new key is added to the ring and becomes active. The old key stays for deobfuscation.
4. Session blobs encrypted with any key in the ring can be imported — Shroud tries each key until AES-GCM auth tag validation succeeds.

### Configuration

```json
{
  "keys": [
    {
      "version": 1,
      "key": "original-key-at-least-16-chars-long",
      "createdAt": "2025-01-01T00:00:00Z"
    },
    {
      "version": 2,
      "key": "rotated-key-at-least-16-chars-long",
      "createdAt": "2025-06-01T00:00:00Z",
      "expiresAt": "2026-06-01T00:00:00Z"
    }
  ],
  "activeKeyVersion": 2
}
```

If `keys` is empty or omitted, Shroud falls back to the single `secretKey` field (backward compatible).

### Env Var

`SHROUD_KEYS` — JSON-encoded array of key objects. Overrides `keys` in config when config has no keys.

### Runtime Rotation

**Programmatic:**
```typescript
const vk = obfuscator.rotateKey("new-secret-key-string", "2027-01-01T00:00:00Z");
// vk.version = 3 (auto-incremented)
// All new obfuscations now use v3
// Old mappings from v1/v2 still deobfuscate from the store
```

**Tool:** `shroud-rotate-key` — accepts optional `key` (auto-generated if omitted) and `expiresAt`. Returns new version info.

### Key Lifecycle

| Operation | Method / Tool | Effect |
|-----------|--------------|--------|
| Add key | `rotateKey()` / `shroud-rotate-key` | New version, becomes active |
| Retire key | `keyRing.retireKey(version)` | Soft-disable: not used for new obfuscation, still used for deobfuscation |
| Expire key | Set `expiresAt` | Auto-excluded from active key selection after expiry |
| Prune expired | `keyRing.pruneExpired()` | Remove expired keys from ring entirely |
| View status | `getKeyInfo()` / `shroud-key-status` | Shows active, all versions, expired, retired |

### Key Expiration

When a key expires:
- It cannot be selected as the active key
- Its mappings remain in the store (deobfuscation still works)
- It is excluded from `allKeys()` (won't be tried for session decrypt)
- Call `pruneExpired()` to remove it entirely

### SIEM Event

A `key_rotation` event is emitted when `rotateKey()` is called, containing old version, new version, and total key count.

### Config Validation

| Check | Severity |
|-------|----------|
| Duplicate versions | ERROR |
| Key < 16 chars | ERROR |
| All keys expired | ERROR |
| Some keys expired | WARNING |
| Active version is retired | WARNING |
| Active version not found | ERROR |

### Security Notes

- Old keys remain in memory (Node.js GC manages lifecycle). For high-security environments, consider process restart after key retirement.
- Key versioning is in-memory only. To persist the key ring across restarts, store the `keys` array in config or environment.
- Session export uses the active key for encryption; import tries all non-expired keys.

---

## 30. SIEM Integration

### Overview

Shroud pushes structured events to external SIEM endpoints via HTTP webhooks in real-time. Events are batched, retried with exponential backoff, and formatted as JSON or CEF.

### Architecture

```
Obfuscator.obfuscate() / hooks.ts lifecycle
        ↓
  WebhookSink.emit(event)
        ↓
  Internal buffer (batching)
        ↓  (flush timer OR batch threshold)
  HTTP POST to each configured endpoint (with retry)
```

### Configuration

```json
{
  "siemWebhooks": [
    {
      "url": "https://siem.example.com/api/events",
      "authHeader": "Bearer your-siem-token",
      "headers": { "X-Source": "shroud" },
      "eventTypes": ["exposure_alert", "compliance_violation"]
    },
    {
      "url": "https://splunk.internal:8088/services/collector",
      "authHeader": "Splunk your-hec-token"
    }
  ],
  "siemBatchSize": 100,
  "siemFlushIntervalMs": 30000,
  "siemMaxRetries": 3,
  "siemRetryBackoffMs": 1000,
  "siemEventFormat": "json"
}
```

### Quick Setup (Single Endpoint)

```bash
export SHROUD_SIEM_WEBHOOK_URL="https://siem.example.com/events"
export SHROUD_SIEM_WEBHOOK_AUTH="Bearer your-token"
```

### Event Types

| Type | Severity | When Emitted |
|------|----------|-------------|
| `obfuscation_summary` | Info (0) | After obfuscating messages in `before_llm_send` |
| `leak_detected` | High (7) | When canary token or unexpected fake appears in output |
| `exposure_alert` | High (7) | When exposure threshold is breached |
| `key_rotation` | Medium (5) | When `rotateKey()` is called |
| `compliance_violation` | High (7) | When locked categories are missing |
| `deobfuscation` | Info (0) | After deobfuscating LLM response |
| `monitor_alert` | High (7) | When the monitoring pipeline fires an alert |

### Event Structure (JSON)

```json
{
  "timestamp": "2025-06-01T12:00:00.000Z",
  "seq": 42,
  "eventType": "exposure_alert",
  "source": "tenant-abc",
  "sessionId": "a1b2c3d4e5f6",
  "requestId": "dc5f9199cfb0d835",
  "severity": 7,
  "data": {
    "category": "email",
    "count": 15,
    "threshold": 10,
    "message": "Exposure threshold exceeded"
  }
}
```

### CEF Format

```
CEF:0|Shroud|OpenClaw-Shroud|1.0.0|exposure_alert|exposure_alert|High|src=tenant-abc sessionId=a1b2 seq=42 category=email count=15
```

### Per-Endpoint Filtering

Each endpoint can subscribe to specific event types via `eventTypes`. If omitted or empty, all events are sent. This allows routing:
- High-severity alerts → PagerDuty webhook
- All events → Splunk HEC
- Compliance violations only → compliance dashboard

### Batching & Retry

- Events buffer in memory (default max 100)
- `setInterval` flush every 30 seconds (configurable, timer is `unref`'d — doesn't block process exit)
- On HTTP failure: retry with exponential backoff (1s, 2s, 4s, default max 3 retries)
- After all retries fail: event is logged to console.warn and dropped (best-effort)
- On process exit: `destroy()` drains remaining buffer

### Stats

`obfuscator.siemSink.getStats()` returns: `{ buffered, sent, failed }`.

### Config Validation

| Check | Severity |
|-------|----------|
| Non-HTTPS URL | WARNING |
| `siemBatchSize < 1` | ERROR |
| `siemFlushIntervalMs < 5000` | WARNING |

### Security Notes

- Events never contain real PII values — only categories, counts, hashes, and thresholds.
- Auth headers are sent as-is. Use HTTPS to protect tokens in transit.
- Zero external dependencies — uses Node.js built-in `fetch` (stable since Node 18).

---

## 31. Hot-Reload

### Overview

Hot-reload watches configuration files for changes and re-initializes detection rules without restarting the plugin. Useful for production environments where you want to tune detection without downtime.

### Configuration

```json
{
  "hotReload": true,
  "policyFile": "/etc/shroud/policy.json",
  "customPatternsFile": "/etc/shroud/patterns.json",
  "hotReloadDebounceMs": 1000
}
```

### What Can Be Hot-Reloaded

| Resource | File | Effect |
|----------|------|--------|
| Policy rules | `policyFile` | Allowlist/denylist patterns updated |
| Custom patterns | `customPatternsFile` | Custom regex detectors replaced |
| Detector overrides | Via `triggerReload()` API | Built-in detectors re-initialized |

### How It Works

1. `DetectorReloader` calls `fs.watchFile()` on configured paths (poll interval: 2 seconds)
2. On file change, a debounce timer waits (default 1 second) to avoid rapid reloads
3. The file is read and parsed as JSON
4. The callback on `Obfuscator` swaps the relevant detector:
   - **Policy**: `_policyRules` replaced with new rules
   - **Custom patterns**: Old `CustomPatternDetector` removed, new one added
   - **Detector overrides**: All detectors re-initialized with new overrides

### Custom Patterns File Format

```json
[
  { "name": "employee_id", "pattern": "EMP-\\d{6}", "category": "custom" },
  { "name": "project_code", "pattern": "PROJ-[A-Z]{3}-\\d+", "category": "custom" }
]
```

### Programmatic Trigger

```typescript
// Force reload without file change
obfuscator.reloader?.triggerReload("detectorOverrides", {
  email: { enabled: false },
  ipv4: { confidence: 0.9 },
});
```

### Stats

- `obfuscator.reloader.reloadCount` — number of successful reloads
- `obfuscator.reloader.isWatching` — whether file watchers are active

### Lifecycle

- Watcher starts automatically when `hotReload: true` in config
- Watcher stops on `obfuscator.shutdown()`
- File must exist at startup to be watched (non-existent files are skipped)

---

## 32. Per-Session Isolation

### Overview

Per-session isolation gives each session its own mapping store, mapping engine, salt, subnet mapper, and canary injector. Mappings from one session never leak into another. This is critical for multi-user environments where a single Obfuscator instance serves multiple conversations.

### Configuration

```json
{
  "sessionIsolation": true
}
```

### How It Works

1. On startup, `SessionManager` is created and an initial session is auto-created
2. Each session gets:
   - Its own `MemoryStore` (separate real↔fake mappings)
   - Its own `MappingEngine` (separate random salt, same secret key)
   - Its own `SubnetMapper` (separate learned subnets)
   - Its own `CanaryInjector` (if canary is enabled)
3. Switching sessions swaps the active store, engine, subnet mapper, and canary on the `Obfuscator`

### API

```typescript
// Create and switch to new session
const sessionId = obfuscator.createSession("user-123");

// Switch to existing session
obfuscator.switchSession("user-456");

// Destroy session and clear its data
obfuscator.destroySession("user-123");

// List all sessions
const sessions = obfuscator.sessionManager!.listSessions();
// → [{ id, createdAt, salt, storeSize, active }]
```

### Tool: `shroud-sessions`

Registered when `sessionIsolation: true`. Accepts:

| Action | Input | Description |
|--------|-------|-------------|
| `list` | — | Show all sessions with metadata |
| `create` | `sessionId?` | Create new session (auto-ID if omitted) |
| `switch` | `sessionId` | Switch to existing session |
| `destroy` | `sessionId` | Destroy session and clear data |

### Isolation Guarantees

- Fakes generated in session A are not deobfuscatable in session B
- Subnet learning is per-session (CIDR learned in A doesn't affect B)
- Canary tokens are per-session
- Store size limits (`maxStoreMappings`) apply per session

### Stats

`getStats()` includes:
```json
{
  "sessions": {
    "active": "user-123",
    "count": 3,
    "list": [...]
  }
}
```

---

## 33. Active Monitoring

### Overview

The active monitoring pipeline watches for anomalies in real-time and generates alerts. It detects rate spikes, new entity categories, canary leaks, repeated exposure breaches, and key expiry warnings. Alerts are stored in memory and optionally forwarded to the SIEM sink.

### Configuration

```json
{
  "monitorEnabled": true,
  "monitorRateWindowMs": 60000,
  "monitorSpikeMultiplier": 3.0,
  "monitorMaxAlerts": 500
}
```

### Alert Types

| Type | Severity | Trigger |
|------|----------|---------|
| `rate_spike` | Warning | Detection rate exceeds baseline × multiplier (and > 10 absolute) |
| `new_category` | Info | Entity category seen for the first time (after learning period) |
| `canary_leak` | Critical | Canary token detected in LLM output |
| `exposure_breach` | Warning → Critical | Exposure threshold breached (escalates on repeat) |
| `key_expiry_warning` | Warning / Critical | Key expires within threshold (critical if < 1 hour) |

### Rate Spike Detection

Uses exponential moving average (EMA) as baseline:
- `baseline = baseline * 0.9 + currentRate * 0.1`
- Alert fires when `currentRate > baseline * spikeMultiplier` AND `currentRate > 10`
- First ~5 events are a "learning period" — no new-category alerts during this time

### Exposure Breach Escalation

Consecutive breaches for the same category escalate severity:
- Breaches 1–3: `warning`
- Breach 4+: `critical`

### Alert Management

```typescript
// Get all alerts
const alerts = obfuscator.monitor!.getAlerts();

// Filter
const unacked = obfuscator.monitor!.getAlerts({ unacknowledgedOnly: true });
const canaries = obfuscator.monitor!.getAlerts({ alertType: "canary_leak" });
const recent = obfuscator.monitor!.getAlerts({ since: "2025-06-01T00:00:00Z" });

// Acknowledge
obfuscator.monitor!.acknowledge(alertId);

// Stats
const stats = obfuscator.monitor!.getStats();
// → { totalAlerts, unacknowledged, byType, currentRate, baseline, categoriesSeen }

// Reset
obfuscator.monitor!.reset();

// Disable/enable
obfuscator.monitor!.setEnabled(false);
```

### Tool: `shroud-monitor`

Shows pipeline stats and recent alerts. Accepts `unacknowledgedOnly` boolean filter.

### SIEM Integration

When both monitoring and SIEM are enabled, every monitor alert is automatically forwarded as a `monitor_alert` SIEM event containing the alert type, message, and details.

### Integration with Obfuscation Pipeline

The monitor is fed automatically during `obfuscate()`:
1. Entity count and categories are recorded after filtering
2. Exposure tracker alerts are forwarded to the monitor as breach events
3. No additional API calls needed — monitoring is transparent

---

## 34. CLI Tools

### `shroud-stats`

```bash
# Live stats from running gateway
node scripts/shroud-stats.mjs

# Test obfuscation on text
node scripts/shroud-stats.mjs --test "Email john@acme.com from 10.0.0.1"

# Machine-readable JSON
node scripts/shroud-stats.mjs --json
```

Output shows all rules with status, confidence, hit counts, store size, audit status.

---

## 35. Diagnostics & Troubleshooting

### Check If Shroud Is Active

Look for `[shroud] Plugin loaded` in logs, or call the `shroud_status` tool.

### Verify Detection

Use dry-run mode to see what would be detected:

```json
{ "dryRun": true }
```

Or test from CLI:

```bash
node scripts/shroud-stats.mjs --test "your text here"
```

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Nothing obfuscated | `minConfidence` too high | Lower to 0.0 or check `detectorOverrides` |
| Too much obfuscated | Broad detectors catching noise | Add to `allowlist` (supports wildcards) or disable rules via `detectorOverrides` |
| Deobfuscation misses values | LLM modified fake values | Expected — only exact matches reverse. Subnet-aware handles derived IPs. |
| Store growing unbounded | Long session | Set `maxStoreMappings` for LRU eviction |
| Fake IPs not in CGNAT range | IPv6 address | IPv6 uses `fd00::/8` (ULA), not CGNAT |
| Double-obfuscation | Fake sent back through pipeline | Automatically prevented — known fakes are skipped |

### Per-Category Stats

Call `getStats()` for:
- `detectionsByCategory`: How many entities detected per category
- `replacementsByCategory`: How many actually replaced
- `ruleHits`: Hit count per detector rule

---

## 36. NCG Agent Integration

### Install

```bash
python agent.py plugin install shroud-privacy
```

This installs to `~/.ncg/extensions/shroud-privacy/` and creates a default config entry in `~/.ncg/ncg.json`.

### Plugin Management

```bash
python agent.py plugin list                    # list installed plugins
python agent.py plugin enable shroud-privacy   # enable
python agent.py plugin disable shroud-privacy  # disable
python agent.py plugin uninstall shroud-privacy # remove
```

### Architecture

NCG loads Shroud via a Python adapter (`ncg_adapter.py`) that manages a Node.js bridge subprocess (`shroud_bridge.mjs`):

```
User → NCG Agent → shroud.sanitize() → LLM
LLM → shroud.desanitize() → NCG Agent → User
```

Both files ship in the npm package and are installed to the extensions directory automatically.

### Features

- Obfuscates outgoing messages (user prompts + tool results)
- Deobfuscates incoming messages (LLM responses)
- Residual detection: scans for leaked CGNAT (`100.64.x.x`) and ULA (`fd00::`) fakes
- Writes stats to `/tmp/shroud-stats.json` for monitoring
- Config from `~/.ncg/ncg.json` (same JSON structure as OpenClaw)
- 4 runtime tools: `shroud_status`, `shroud_reset`, `shroud_activate`, `shroud_deactivate`

### Configuration

Edit `~/.ncg/ncg.json` → `plugins.entries."shroud-privacy".config`. Same keys as OpenClaw — see [Configuration Reference](#3-configuration-reference).

### Verifying Deployment

```bash
# Check plugin is installed
python agent.py plugin list

# Check bridge is loaded
journalctl -u ncg-gateway.service | grep shroud

# Check version
python agent.py plugin list | grep shroud-privacy

# Check stats
cat /tmp/shroud-stats.json
```

### Development Workflow

```bash
cd /path/to/shroud
npm run build
bash deploy-ncg.sh                              # install to ~/.ncg/extensions/
sudo systemctl restart ncg-gateway.service       # pick up changes
```
