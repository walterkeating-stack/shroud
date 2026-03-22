# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2026-03-22

### Added
- **Key rotation** — `KeyRing` class with versioned keys, add/retire/prune, and expiration TTL. `rotateKey()` on Obfuscator adds a new key; existing mappings remain valid. Session encrypt/decrypt tries all keys for cross-rotation import. New tools: `shroud-rotate-key`, `shroud-key-status`. Config: `keys` array and `activeKeyVersion`. Env var: `SHROUD_KEYS` (JSON array).
- **SIEM webhook push** — `WebhookSink` for real-time event streaming to HTTP endpoints. Supports JSON and CEF formats, batching, exponential backoff retry, per-endpoint event type filtering, and auth headers. 7 event types: `obfuscation_summary`, `leak_detected`, `exposure_alert`, `key_rotation`, `compliance_violation`, `deobfuscation`, `monitor_alert`. Events emitted at `before_llm_send` and `transformResponse` hooks. Config: `siemWebhooks`, `siemBatchSize`, `siemFlushIntervalMs`, `siemMaxRetries`, `siemRetryBackoffMs`, `siemEventFormat`. Env vars: `SHROUD_SIEM_WEBHOOK_URL`, `SHROUD_SIEM_WEBHOOK_AUTH`.
- **Hot-reload of detection rules** — `DetectorReloader` watches policy file and custom patterns file via `fs.watchFile`. Debounced reloads. Supports reloading policy rules, custom patterns, and detector overrides without restart. Config: `hotReload`, `customPatternsFile`, `hotReloadDebounceMs`.
- **Per-session isolation** — `SessionManager` maintains separate mapping stores, engines, salts, and canary injectors per session. `createSession()`, `switchSession()`, `destroySession()` on Obfuscator. New tool: `shroud-sessions` (list/create/switch/destroy). Config: `sessionIsolation`.
- **Active monitoring pipeline** — `AlertPipeline` with rate spike detection (EMA baseline), new category alerts, canary leak recording, exposure breach escalation with severity upgrade, and key expiry warnings. Alert acknowledgement, type/time filtering. Forwards to SIEM sink. New tool: `shroud-monitor`. Config: `monitorEnabled`, `monitorRateWindowMs`, `monitorSpikeMultiplier`, `monitorMaxAlerts`.
- **Config validation** expanded for all new settings: key version uniqueness, key expiration, SIEM endpoint HTTPS checks, batch size bounds, flush interval warnings.
- 60 new tests (303 total across 17 test files).

## [1.3.0] - 2026-03-22

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
- **Detection improvements** (10 enhancements):
  1. Context-aware confidence boosting (config keyword density → higher scores)
  2. Multi-line PEM cert/key detection (captures full base64 body)
  3. Proximity-based PII clustering (nearby name+email+phone boost each other)
  4. Config-block hostname extraction (hostname X → detect bare X everywhere)
  5. SNMP/syslog source correlation (facility codes, source-interface)
  6. Description field scraping (circuit IDs, org names from description lines)
  7. Negative lookahead for documentation examples (RFC 5737 TEST-NETs, example.com)
  8. Recursive deobfuscation for nested structures (multi-pass, max 3)
  9. Learned entity propagation (cross-invocation hostname memory)
  10. Confidence decay for common English words (permit, deny, default, etc.)

### Changed
- Detector `detector` field now includes rule name (e.g. `regex:email` instead of `regex`) for finer-grained audit and hit tracking.

- **Quick wins** (10 operational improvements):
  1. **Wildcard allowlist** — allowlist entries support `*` and `?` globs (e.g. `*@acme.com`, `10.0.0.*`)
  2. **Per-category stats** — `detectionsByCategory` and `replacementsByCategory` in `getStats()`
  3. **URL credential scrubbing** — detect passwords/tokens in query params and connection strings
  4. **Network infra generators** — format-preserving fakes for VLAN IDs, OSPF IDs, ACL names, route-maps, interface descriptions
  5. **`shroud-stats --json`** — machine-readable stats export for monitoring
  6. **Dry-run mode** — `dryRun: true` detects entities without replacing text
  7. **Config validation** — `validateConfig()` returns typed issues (error/warning/info) with actionable messages
  8. **Filter stats** — `filterStats` in every `ObfuscationResult`: totalDetected, replaced, belowThreshold, allowlisted, alreadyObfuscated
  9. **Base64 secret detection** — catches `SECRET=<base64>` and `base64:<value>` patterns
  10. **LRU store eviction** — `maxStoreMappings` caps store size with FIFO eviction (0 = unlimited)

### Fixed
- **Subnet-aware deobfuscation** — LLM-derived network addresses (e.g., computing `.0` network or `.255` broadcast from a fake host IP + mask) are now reverse-mapped via the SubnetMapper to recover the correct real IP.
- **IPv6 detection** — improved regex handles full 8-group, compressed `::`, link-local `fe80::`, and ULA `fd00::` forms.
- **IPv6 documentation filtering** — RFC 3849 doc prefix (`2001:db8::/32`) and loopback (`::1`) are now correctly skipped.
- **IPv6 residual ULA deobfuscation** — `fd00::/8` fakes that the LLM compresses or derives `/64` prefixes from are normalized back to full form for store lookup.

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
