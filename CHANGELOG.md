# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Detector overrides** — disable or change confidence for individual built-in rules via `detectorOverrides` config. Overrides apply to both direct regex and code-aware detection.
- **Rule hit counters** — per-rule match counts tracked for the process lifetime, surfaced in `getStats().ruleHits` and audit log lines (`byRule=...`).
- **`shroud-stats` tool** — registered via OpenClaw `registerTool()`, queryable from conversation. Shows all rules with status, confidence, hit counts, store size, and audit status.
- **Wave 1 enterprise detection rules** (~60 new patterns):
  - EU/regulated: IBAN, Austrian SVNr, German Personalausweis, EU VAT number, GPS coordinates
  - Auth tokens: JWT, OAuth refresh tokens, AWS/GCP/Azure/Slack/GitHub/GitLab/Stripe/SendGrid keys
  - Database: connection strings, JDBC URLs
  - Certificates: PEM private keys and certificates
  - Directory services: LDAP bind DN/password, AD domain logins, Windows SIDs
  - Network vendors: Juniper (secrets, PSK, root-auth, community, description), Palo Alto (API key, password hash, master key, address objects, zones, rules), Check Point (password hash, SIC key, API key, objects, rules, VPN communities), Arista, F5, Fortinet
  - VPN/IPSec: pre-shared keys, transform sets
  - ICS/SCADA: OPC-UA endpoints, Modbus addresses, SCADA credentials, IEC 61850 IED names, DNP3 addresses, BACnet device IDs, historian tags
  - Aviation: ATC sector IDs, NAV frequencies, ICAO designators
  - Telecom: IMSI, IMEI, CLLI codes
- **New entity categories**: `iban`, `national_id`, `jwt`, `ics_identifier`, `gps_coordinate`, `certificate`
- **Format-preserving generators** for IBAN (preserves country code), national IDs (preserves length), JWT (valid structure), GPS coordinates, ICS identifiers, certificates
- **Network device hostname detection** — 4 new patterns: `cisco_hostname`, `device_name_dotted`, `device_name_short`, `device_name_hyphenated`
- **Enterprise agent features** (10 capabilities):
  1. **Multi-tenant isolation** — per-tenant HMAC keying and separate mapping stores (`tenantId` config, `SHROUD_TENANT_ID` env)
  2. **Session handoff** — AES-256-GCM encrypted export/import of mapping tables for cross-session continuity (`sessionHandoff` config, `shroud-session-export`/`shroud-session-import` tools)
  3. **Tool chain depth awareness** — tracks nested tool calls, warns when depth exceeds `maxToolDepth`
  4. **Compliance-mode entity locking** — `lockedCategories` config enforces that specified categories MUST be detected; compliance report in `ObfuscationResult` and audit logs
  5. **Rate-of-exposure tracking** — sliding window counter per category with configurable thresholds; alerts on exposure spikes (`exposureWindow`, `exposureThresholds`, `exposureGlobalThreshold`)
  6. **Corpus pre-scanning** — `preScanCorpus()` batch API for index-time obfuscation of RAG document collections
  7. **Policy-as-code** — load allowlist/denylist from external JSON files with glob and regex pattern support (`policyFile` config)
  8. **Redaction levels** — three output modes: `full` (fake values), `masked` (partial masking), `stats` (category placeholders like `[HOSTNAME-1]`) (`redactionLevel` config)
  9. **Cross-agent entity consistency** — file-backed shared mapping store for multiple Shroud instances (`sharedStorePath` config, `SHROUD_SHARED_STORE` env)
  10. **Provenance tagging** — optional `«shroud:category:hash»` markers in output for downstream audit trail (`provenanceTagging` config)

### Changed
- Detector `detector` field now includes rule name (e.g. `regex:email` instead of `regex`) for finer-grained audit and hit tracking.

## [1.2.0] - 2026-03-22

### Added
- **Verbose audit logging** for `before_llm_send` and `transformResponse` hooks. Per-request audit lines show entity counts, categories, char deltas, and optional proof hashes — without ever logging raw values.
- New config keys: `verboseLogging`, `auditLogFormat`, `auditIncludeProofHashes`, `auditHashSalt`, `auditHashTruncate`, `auditMaxFakesSample`.
- `deobfuscateWithStats()` method on Obfuscator for response-side audit with replacement count.
- Deobfuscation audit lines correlated with request ID from obfuscation.
- `modified=YES/NO` flag and `delta=` char count change in all audit lines.
- `proof_in`/`proof_out` truncated salted SHA-256 hashes (opt-in) for tamper evidence.
- `fakes=[...]` sample of fake replacement values in audit (opt-in, never real values).
- Plugin config schema updated in `openclaw.plugin.json` — all new keys validated.
- README, LICENSE (MIT), SECURITY.md, CHANGELOG.md for community release.

### Changed
- Migrated `before_agent_start` hook to `before_prompt_build` (resolves OpenClaw plugin compatibility warning).
- Audit log format uses `|`-separated fields for readability.

### Fixed
- Double-obfuscation: skip entities that are already known fakes in the mapping store.

## [1.1.0] - 2026-03-21

### Added
- `before_llm_send` hook with `transformResponse` for WhatsApp/auto-reply deobfuscation.
- Network infrastructure detection: VLAN IDs, OSPF IDs, ACL names, route-maps, interface descriptions.
- International phone number detection improvements.
- Local deploy script (`deploy-local.sh`).

### Fixed
- Deobfuscation for network infrastructure categories.
- International phone regex patterns.

## [1.0.2] - 2026-03-20

### Fixed
- Hook contracts to match OpenClaw plugin API.

## [1.0.1] - 2026-03-20

### Fixed
- Plugin ID mismatch: aligned manifest with npm package name.

## [1.0.0] - 2026-03-20

### Added
- Initial release: native OpenClaw privacy plugin.
- 7-step obfuscation pipeline: detect → denylist → overlap resolution → confidence filter → map → replace → canary inject.
- Deterministic HMAC-SHA256 mapping with format-preserving generators.
- 22 entity categories with regex, code-aware, and custom pattern detectors.
- Subnet-preserving IP obfuscation (CGNAT range).
- Bidirectional mapping store with longest-match-first deobfuscation.
- Canary token injection for data leakage detection.
- Tamper-evident audit logger with HMAC chain hashing.
- 5 OpenClaw lifecycle hooks.
- 114 tests (vitest).
