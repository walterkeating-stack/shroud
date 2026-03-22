# Shroud

Privacy obfuscation plugin for [OpenClaw](https://openclaw.ai). Detects sensitive data (PII, network infrastructure, credentials) and replaces it with deterministic fake values before anything reaches the LLM. Tool calls still work because Shroud deobfuscates on the way back.

> **Community release** — not an official OpenClaw plugin. Use at your own risk.

## What it does

1. **Detects** emails, IPs, phones, API keys, hostnames, SNMP communities, BGP ASNs, credit cards, SSNs, file paths, URLs, person/org/location names, VLANs, route-maps, ACLs, OSPF IDs, and custom regex patterns.
2. **Replaces** each value with a deterministic fake (same input + key = same fake every time). Fakes are format-preserving: IPs stay in CGNAT range, emails keep `@domain` structure, credit cards pass Luhn, etc.
3. **Deobfuscates** LLM responses and tool parameters so the user sees real values and tools receive real arguments.
4. **Audit logs** every obfuscation/deobfuscation event with counts, categories, char deltas, and optional proof hashes — never logging raw sensitive values.

### Hook lifecycle

| Hook | Direction | What happens |
|------|-----------|-------------|
| `before_prompt_build` | User → LLM | Obfuscate user prompt, prepend privacy context |
| `before_llm_send` | User → LLM | Obfuscate all messages + install `transformResponse` |
| `transformResponse` | LLM → User | Deobfuscate LLM output (auto-reply, WhatsApp, etc.) |
| `before_tool_call` | LLM → Tool | Deobfuscate tool parameters |
| `tool_result_persist` | Tool → History | Obfuscate tool results before storing |
| `message_sending` | Agent → User | Deobfuscate outbound messages (fallback path) |

## Install

```bash
openclaw plugins install openclaw-shroud
```

Or from local path:

```bash
cd shroud && npm run build
cp -r dist package.json openclaw.plugin.json ~/.openclaw/extensions/openclaw-shroud/
```

## Configure

Add to `~/.openclaw/openclaw.json` under `plugins.entries`:

```jsonc
"openclaw-shroud": {
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
| `proof_in` | Truncated salted SHA-256 of input text |
| `proof_out` | Truncated salted SHA-256 of output text |
| `fakes` | Sample of fake replacement values (never real values) |

### Note on log duplication

OpenClaw logs each plugin message twice (once under the plugin subsystem logger, once under the parent `openclaw` logger). This is normal OpenClaw behavior. Filter to `"name":"openclaw"` to get one line per event, as shown in the verify command above.

## Development

```bash
npm install
npm test          # run vitest (114 tests)
npm run build     # compile TypeScript
npm run lint      # type-check without emitting
```

### Local deploy (no npm publish)

```bash
npm run build
bash deploy-local.sh   # copies dist/ to ~/.openclaw/extensions/openclaw-shroud/
```

## Entity categories

`person_name`, `email`, `phone`, `ip_address`, `api_key`, `url`, `org_name`, `location`, `file_path`, `credit_card`, `ssn`, `mac_address`, `hostname`, `snmp_community`, `bgp_asn`, `network_credential`, `vlan_id`, `interface_desc`, `route_map`, `ospf_id`, `acl_name`, `custom`

## License

[MIT](LICENSE)
