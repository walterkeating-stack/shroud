# Shroud — Community Edition

Privacy obfuscation plugin for [OpenClaw](https://openclaw.ai). Detects sensitive data (PII, network infrastructure, credentials) and replaces it with deterministic fake values before anything reaches the LLM. Tool calls still work because Shroud deobfuscates on the way back.

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
| `message_sending` | Agent → User | Deobfuscate outbound messages (fallback) |

> **Streaming deobfuscation:** On first load, Shroud patches pi-ai's EventStream to deobfuscate ALL LLM responses at the stream level — every provider (Anthropic, OpenAI, Google), every channel (Slack, WhatsApp, Telegram, etc.). A single gateway restart activates the patch.

## Install

### OpenClaw

```bash
openclaw plugins install shroud-privacy
```

That's it. Configure in `~/.openclaw/openclaw.json` under `plugins.entries."shroud-privacy".config`.

### From source (development)

```bash
git clone https://github.com/walterkeating-stack/shroud.git
cd shroud
npm install && npm run build
bash deploy-local.sh     # → OpenClaw (~/.openclaw/extensions/)
```

## Updating

OpenClaw doesn't have a `plugins update` command yet, so updating requires removing the old install first. A helper script is included:

```bash
# Update to latest version (preserves your config)
bash scripts/update-openclaw-plugin.sh

# Update to a specific version
bash scripts/update-openclaw-plugin.sh 2.0.1
```

The script saves your plugin config from `openclaw.json`, removes the old extension, reinstalls from npm, restores your config, and restarts the gateway.

### Manual update

If you prefer to do it manually:

```bash
# 1. Remove old plugin files
rm -rf ~/.openclaw/extensions/shroud-privacy

# 2. Reinstall (this resets your plugin config to defaults)
openclaw plugins install shroud-privacy

# 3. Re-apply your config in ~/.openclaw/openclaw.json
#    (under plugins.entries."shroud-privacy".config)

# 4. Restart
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

### Rule hit counters

Shroud tracks per-rule match counts for the lifetime of the process. Counters appear in three places:

- **`shroud-stats` CLI** — run `node scripts/shroud-stats.mjs` to see all rules with status, confidence, and hit counts. Shows live cumulative stats from the running OpenClaw gateway via `/tmp/shroud-stats.json`. Use `--test "text with PII"` to test detection against sample input.
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

## Development

```bash
npm install
npm test          # run vitest (210 tests)
npm run build     # compile TypeScript
npm run lint      # type-check without emitting
```

### Deploy after changes

```bash
npm run build
bash deploy-local.sh   # → OpenClaw (~/.openclaw/extensions/shroud-privacy/)
openclaw gateway restart
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
