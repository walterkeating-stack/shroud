# Shroud — Community Edition

Privacy obfuscation plugin for [OpenClaw](https://openclaw.ai). Detects sensitive data (PII, network infrastructure, credentials) and replaces it with deterministic fake values before anything reaches the LLM. Tool calls still work because Shroud deobfuscates on the way back.

> **Open-source Community Edition** — free to use under MIT license. [Enterprise Edition](#enterprise-edition) available with additional features for teams.

## What it does

1. **Detects** 100+ entity types: emails, IPs, phones, API keys, hostnames, SNMP communities, BGP ASNs, credit cards, SSNs, file paths, URLs, person/org/location names, VLANs, route-maps, ACLs, OSPF IDs, IBANs, JWTs, PEM certs, GPS coordinates, ICS/SCADA identifiers, Palo Alto/Check Point/Juniper/Fortinet/F5 config secrets, and custom regex patterns.
2. **Replaces** each value with a deterministic fake (same input + key = same fake every time). Fakes are format-preserving: IPv4 stays in CGNAT range (`100.64.0.0/10`), IPv6 uses ULA range (`fd00::/8`), emails keep `@domain` structure, credit cards pass Luhn, etc.
3. **Deobfuscates** LLM responses and tool parameters so the user sees real values and tools receive real arguments.
4. **Audit logs** every obfuscation/deobfuscation event with counts, categories, char deltas, and optional proof hashes — never logging raw sensitive values.

### Hook lifecycle

| Hook | Direction | What happens |
|------|-----------|-------------|
| `before_prompt_build` | User → LLM | Obfuscate user prompt, prepend privacy context |
| `before_llm_send` | User → LLM | Obfuscate all messages + install `transformResponse` |
| `transformResponse` | LLM → User | Deobfuscate LLM output (auto-reply, WhatsApp, etc.) |
| `before_tool_call` | LLM → Tool | Deobfuscate tool parameters + track tool chain depth |
| `tool_result_persist` | Tool → History | Obfuscate tool results before storing |
| `message_sending` | Agent → User | Deobfuscate outbound messages (fallback path) |

## Install

### OpenClaw

```bash
openclaw plugins install shroud-privacy
```

That's it. Configure in `~/.openclaw/openclaw.json` under `plugins.entries."shroud-privacy".config`.

### NCG Agent

```bash
python agent.py plugin install shroud-privacy
```

Configure in `~/.ncg/ncg.json` under `plugins.entries."shroud-privacy".config`.

### From source (development)

```bash
git clone https://github.com/walterkeating-stack/shroud.git
cd shroud
npm install && npm run build

bash deploy-local.sh     # → OpenClaw (~/.openclaw/extensions/)
bash deploy-ncg.sh       # → NCG (~/.ncg/extensions/)
```

## Configure

Both OpenClaw and NCG store Shroud config in the same structure — only the file path differs:

| Platform | Config file | Config path |
|----------|-------------|-------------|
| OpenClaw | `~/.openclaw/openclaw.json` | `plugins.entries."shroud-privacy".config` |
| NCG | `~/.ncg/ncg.json` | `plugins.entries."shroud-privacy".config` |

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
openclaw gateway restart                    # OpenClaw
sudo systemctl restart ncg-gateway.service  # NCG
```

### Safe defaults

Out of the box, Shroud:
- Auto-generates a secret key (per-session unless you set `secretKey`)
- Detects all entity categories at confidence >= 0.0
- Logs audit lines (counts + categories) but **not** proof hashes or fake samples
- Never logs raw values, real→fake mappings, or original text
- All enterprise features are opt-in and disabled by default

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

### Enterprise settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tenantId` | string | `""` | Multi-tenant isolation: tenant ID for HMAC keying |
| `lockedCategories` | string[] | `[]` | Compliance mode: categories that MUST be detected |
| `maxToolDepth` | number | `10` | Max nested tool call depth before warning |
| `exposureWindow` | number | `60000` | Sliding window (ms) for exposure rate tracking |
| `exposureThresholds` | object | `{}` | Per-category max detections per window |
| `exposureGlobalThreshold` | number | `100` | Global max detections per window |
| `policyFile` | string | `""` | Path to external JSON policy file (allowlist/denylist with glob/regex) |
| `redactionLevel` | `"full"` \| `"masked"` \| `"stats"` | `"full"` | Output mode: fake values, partial masking, or category placeholders |
| `sharedStorePath` | string | `""` | File path for cross-agent shared mapping store |
| `sharedStoreTtlMs` | number | `5000` | Cache TTL for shared store reads (ms) |
| `provenanceTagging` | boolean | `false` | Embed `«shroud:category:hash»` markers in output |
| `sessionHandoff` | boolean | `false` | Enable session export/import tools |

### Key rotation settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `keys` | array | `[]` | Versioned keys: `[{version, key, createdAt?, expiresAt?, retired?}]` |
| `activeKeyVersion` | number | `0` | Which key version to use (0 = highest non-expired) |

### SIEM integration settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `siemWebhooks` | array | `[]` | Webhook endpoints: `[{url, authHeader?, headers?, eventTypes?}]` |
| `siemBatchSize` | number | `100` | Max events before auto-flush |
| `siemFlushIntervalMs` | number | `30000` | Flush interval (ms) |
| `siemMaxRetries` | number | `3` | Max retry attempts per flush |
| `siemRetryBackoffMs` | number | `1000` | Initial retry backoff (doubles each retry) |
| `siemEventFormat` | `"json"` \| `"cef"` | `"json"` | Output format for SIEM events |

### Hot-reload, session isolation, and monitoring settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hotReload` | boolean | `false` | Watch config files and reload detection rules on change |
| `customPatternsFile` | string | `""` | Path to custom patterns JSON file to watch |
| `hotReloadDebounceMs` | number | `1000` | Debounce interval for file change events |
| `sessionIsolation` | boolean | `false` | Per-session isolated stores and mapping engines |
| `monitorEnabled` | boolean | `false` | Active monitoring and alerting pipeline |
| `monitorRateWindowMs` | number | `60000` | Rolling window for rate baseline |
| `monitorSpikeMultiplier` | number | `3.0` | Alert when rate exceeds baseline × multiplier |
| `monitorMaxAlerts` | number | `500` | Max alerts to keep in memory |

> **Env var overrides:** `SHROUD_SECRET_KEY`, `SHROUD_PERSISTENT_SALT`, `SHROUD_TENANT_ID`, `SHROUD_SHARED_STORE`, `SHROUD_SIEM_WEBHOOK_URL`, `SHROUD_SIEM_WEBHOOK_AUTH`, and `SHROUD_KEYS` (JSON array) override their respective config keys (priority: env var > plugin config > default).

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

### Rule hit counters

Shroud tracks per-rule match counts for the lifetime of the process. Counters appear in three places:

- **`shroud-stats` CLI** — run `node scripts/shroud-stats.mjs` to see all rules with status, confidence, and hit counts. Shows live cumulative stats from the running gateway (NCG or OpenClaw) via `/tmp/shroud-stats.json`. Use `--test "text with PII"` to test detection against sample input.
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
[shroud][audit] OBFUSCATE req=dc5f9199cfb0d835 | entities=4 | touched=2/5 | blocks=2 | chars=1200->1218 (delta=+18) | modified=YES | byCat=email:1,ip_address:2,hostname:1
```

With proof hashes enabled:

```
[shroud][audit] OBFUSCATE req=a3f1bc9e02d4e7f1 | entities=4 | touched=2/5 | blocks=2 | chars=1200->1218 (delta=+18) | modified=YES | byCat=email:1,ip_address:2,hostname:1 | proof_in=8a3c1f0e2b4d proof_out=f7d2a1c9e084 | fakes=[jsmith@corp.net|100.64.0.12|SW-LAB-01]
```

With compliance locking:

```
[shroud][audit] OBFUSCATE req=... | ... | COMPLIANCE_WARN=missing:[credit_card]
```

### Audit field reference

| Field | Meaning |
|-------|---------|
| `req` | Random request ID (hex) — correlates obfuscate ↔ deobfuscate |
| `entities` | Total entities detected and replaced |
| `touched` | Messages with replacements / total messages |
| `blocks` | Content blocks with replacements |
| `chars` | Input → output character count |
| `delta` | Character count change (fakes may be longer/shorter) |
| `modified` | `YES` if text was changed, `NO` if pass-through |
| `byCat` | Entity counts by category |
| `byRule` | Entity counts by detector rule |
| `proof_in` | Truncated salted SHA-256 of input text |
| `proof_out` | Truncated salted SHA-256 of output text |
| `fakes` | Sample of fake replacement values (never real values) |
| `COMPLIANCE_WARN` | Missing locked categories (if compliance mode enabled) |

### Note on log duplication

OpenClaw logs each plugin message twice (once under the plugin subsystem logger, once under the parent `openclaw` logger). This is normal OpenClaw behavior. Filter to `"name":"openclaw"` to get one line per event, as shown in the verify command above.

## Development

```bash
npm install
npm test          # run vitest (303 tests)
npm run build     # compile TypeScript
npm run lint      # type-check without emitting
```

### Deploy after changes

```bash
npm run build
bash deploy-local.sh   # → OpenClaw (~/.openclaw/extensions/shroud-privacy/)
bash deploy-ncg.sh     # → NCG (~/.ncg/extensions/shroud-privacy/)

openclaw gateway restart                    # restart OpenClaw
sudo systemctl restart ncg-gateway.service  # restart NCG
```

## Release workflow

### Tagging a release

```bash
# 1. Update version in package.json and openclaw.plugin.json
# 2. Update CHANGELOG.md
# 3. Commit and tag
git add -A
git commit -m "Release v1.x.y"
git tag v1.x.y
git push && git push --tags
```

Then create a GitHub Release from the tag (attach the changelog entry as notes).

### npm publish (not published yet — maintainers only)

This package is **not published to npm**. The `package.json` is pre-configured so publishing is a single command when the time comes. Do not publish without maintainer approval.

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

[MIT](LICENSE)
