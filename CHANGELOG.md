# Changelog

All notable changes to this project will be documented in this file.

## [2.2.0] - 2026-03-26

### Added
- **`globalThis.__shroudDeobfuscate` — single global hook for all channel delivery.** Replaces per-channel deobfuscation with one function that OpenClaw calls before ANY channel send (Slack, WhatsApp, Signal, web, etc.). Transparent no-op if Shroud isn't loaded. Works on all OpenClaw releases with a one-line patch to the delivery function.
- **Real Slack HTTP test chain** — 11 tests with two real HTTP servers (mock LLM + mock Slack API). Exercises the full pipeline: real `fetch()` intercepted by fetch guard → real `http.request` to Slack. Tests include: E2E happy path, Slack mailto markup, LLM-invented CGNAT IPs, truncated fakes, non-string input, mixed real+fake, multi-turn re-obfuscation, concurrent 3-channel delivery, JSON structure preservation, two private subnets, idempotency.
- **Post-install verification** — `deploy-local.sh` now runs the Slack chain tests after deployment to verify the full pipeline works.

### Changed
- **Channel delivery architecture** — channel deobfuscation now flows through `globalThis.__shroudDeobfuscate` (one global hook) instead of relying solely on the `message_sending` hook. The `message_sending` hook remains as a backup path.
- `fetch-preload.cjs` superseded — the child-process fetch preload script is no longer needed. The global deobfuscation hook covers all channels from the main process.

## [2.1.0] - 2026-03-26

### Breaking
- **Requires OpenClaw 2026.3.24 or later.** Older versions do not call `message_sending` for Slack/WhatsApp channels, causing duplicate messages with fake tokens in channel output. Shroud 2.1+ is tested exclusively against OpenClaw 2026.3.24.

### Fixed
- **CRITICAL: PII leak via Slack `<mailto:>` markup** — Slack wraps emails as `<mailto:real@email|real@email>`. The fetch intercept obfuscated the plain email but left the `<mailto:>` tag intact, leaking real PII to the LLM. Fixed by stripping Slack link markup before obfuscation.
- **CRITICAL: Multi-turn PII leak from assistant history** — `before_message_write` deobfuscates assistant messages (fake→real) and stores them in the transcript. On subsequent turns, the fetch intercept was skipping assistant messages, letting real PII reach the LLM. Fixed: fetch intercept now re-obfuscates ALL messages including assistant content blocks.
- **EventStream class not found on some installs** — added Strategy 4 (direct file path resolution) to locate `EventStream` when `createRequire` is blocked by `exports` restrictions in pi-ai's `package.json`.
- **Test harness truly patchless** — removed vestigial `_applyPatches()` method from OpenClaw sandbox runner. Tests run against a completely unmodified OpenClaw 2026.3.24 install.

### Added
- **Multi-turn PII leak test** — OpenClaw sandbox test sends two messages in the same session, verifying the LLM does not see real PII from the first turn's deobfuscated assistant response.
- **Slack E2E simulation tests** — 5 unit tests verifying: Slack `<mailto:>` stripping, assistant content block re-obfuscation, `message_sending` deobfuscation, full Slack flow (single output, no fakes), and multi-turn assistant history re-obfuscation.
- **1,124 tests** — 751 vitest + 359 APP harness + 14 OpenClaw sandbox.

### Changed
- **OpenClaw 2026.3.24 required** — `openclaw.plugin.json` `minOpenClawVersion` updated to `2026.3.24`.
- Tool descriptions neutralized — `shroud-stats`, `shroud_status`, `shroud_reset` no longer mention "privacy" or "Shroud" in their descriptions to prevent the LLM from generating explanatory text about the obfuscation process.
- README: updated requirements, "How privacy works", install instructions, and privacy guarantee to reflect OpenClaw 2026.3.24 patchless architecture.

## [2.0.22] - 2026-03-25

### Added
- **APP server shipped in npm package** — `app-server.mjs` now included, enabling any AI agent to integrate Shroud via the Agent Privacy Protocol (JSON-RPC over stdin/stdout)
- **Standalone Python APP client** — `clients/python/shroud_client.py` with auto-restart, residual fake detection, context manager
- **APP protocol documentation** — full protocol reference in README: handshake, methods, heartbeat, integration checklist
- **Unified test process** — `npm test` runs all three layers: vitest (736) + APP harness (359) + OpenClaw sandbox (12) = 1,107 tests
- **Test harness in-repo** — moved from separate repo into `tests/harness/`
- **Comprehensive audit/logging tests** — 18 new hook lifecycle tests covering streaming deobfuscation, audit counters, format variants, proof hashes

### Fixed
- **CRITICAL: PII was reaching the LLM unobfuscated** — the `before_prompt_build` hook obfuscated the prompt but OpenClaw still sent raw user message content to the API. Fixed with `globalThis.fetch` intercept that obfuscates ALL messages (user, assistant, system, tool results) before any LLM API call. Works for every provider (Anthropic, OpenAI, Google) and every OpenClaw version.
- **Deobfuscation audit counter** — streaming and `before_message_write` paths now emit audit events
- **Streaming deobCount tracking** — count accumulated during chunks, not re-counted at message_end
- **`deploy-local.sh`** — removed redundant pi-embedded prompt override patch (fetch intercept handles it), added root-owned V8 cache clear for systemd gateway
- **OpenClaw sandbox test now verifies LLM payload** — `assertLlmDidNotSee` checks mock LLM request log for real PII values. This test would have caught the privacy leak.

### Changed
- Package description: "for OpenClaw" → "for AI agents"
- Keywords: added `ai-agent`, `app-protocol`

## [2.0.20] - 2026-03-25

### Performance
- **Span overlap detection O(n²) → O(log n)** — all three detectors (regex, patterns, code) now use sorted interval arrays with binary search instead of linear scans. New `SpanTracker` class in regex detector. Measurable on large configs with 50+ entities.

### Fixed
- **CGNAT range regex false positives** — added negative lookbehind `(?<!\d\.)(?<!\d)` to `CGNAT_RANGE_DESC_RE` to prevent matching when preceded by other IP octets

## [2.0.19] - 2026-03-24

### Fixed
- **Prompt privacy — raw PII no longer reaches LLM** — `before_prompt_build` hook now returns `{ prompt: obfuscatedText }` which fully replaces the user prompt. Previously returned `{ prependContext }` which OpenClaw appended alongside the raw prompt, sending all PII verbatim to the LLM. `deploy-local.sh` patches OpenClaw to support the `prompt` return field.
- **ACL name deobfuscation corruption** — multi-pass deobfuscation now uses sentinel placeholders to prevent cascading replacements when a real value contains a substring matching another fake value (e.g., `ACL-MGMT-FILTER` → `ACL-MGMT-FILTER-FILTER-FILTER`)
- **Tool result content block handling** — `before_message_write` hook now obfuscates/deobfuscates `block.content` (string and nested array forms) in addition to `block.text`, fixing PII leaks in Anthropic API tool_result blocks

### Changed
- `deploy-local.sh` — no longer exits early after EventStream patch; applies prompt override patch to all `pi-embedded-*.js` files independently

## [2.0.18] - 2026-03-24

### Fixed
- **CGNAT deobfuscation overhaul** — complete rewrite of the CGNAT fake IP cleanup pipeline:
  - **Subnet overlap bug** — `SubnetMapper` now uses byte-offset allocation with proper alignment, preventing /28 subnets from landing inside /24 ranges
  - **Wrong subnet match** — residual deobfuscation now uses longest-prefix match instead of first match, fixing IPs mapping to wrong real subnets
  - **Invalid octets** — input validation rejects IPs with octets > 255 before processing (prevents `10.16.26.352` corruption)
  - **`deobfuscateWithStats()` missing range cleanup** — the NCG bridge code path skipped CGNAT range description cleanup entirely, causing all `100.64.x.x/xx` patterns to leak through
  - **Hyphenated range notation** — LLM-generated ranges like `100.64.16-19.0/24` now matched and replaced
  - **3-octet short forms** — patterns like `100.64.8-14` (no fourth octet) now caught
  - **Range handler fallback** — CGNAT IPs with no subnet mapping no longer fall through both handlers
- **Tool call display** — NCG agent now shows real device names in tool call output (was showing fake SITE-X-Y-NN names)

### Added
- **Deobfuscation corruption test suite** — 5 new unit tests covering subnet overlap, wrong match, invalid octets, and end-to-end multi-subnet scenarios
- **Multi-subnet integration tests** — 5 new test harness scenarios for NCG-style network inventories with mixed prefix lengths
- **OpenClaw integration tests (Phase 2)** — 11 tests running real OpenClaw agent with Shroud plugin inside sandbox

## [2.0.17] - 2026-03-24

### Fixed
- VRF detection (6 new patterns: vrf_name_classic, vrf_definition, vrf_forwarding, vrf_junos, route_distinguisher, route_target)
- Infrastructure hostname detection (PROD-DB-01, AMS-CORE-SW-01 style)
- CGNAT range description leaks in LLM summaries
- CGNAT CIDR suffix `/10` preserved incorrectly after deobfuscation
- Doc hostname prefix exclusions (TEST-NET-*, EXAMPLE-*, DEMO-*)

## [2.0.16] - 2026-03-24

### Fixed
- VRF detection, hostname patterns, CGNAT range fixes (cherry-picked from feat/agent-protocol)

## [2.0.15] - 2026-03-24

### Fixed
- CGNAT range description leaks in deobfuscation output

## [2.0.14] - 2026-03-24

### Fixed
- Stats CLI docs for npm

## [2.0.8] – 2.0.13 - 2026-03-23

### Added
- `shroud-stats` CLI tool with rulebase view and hit counters
- APP server (Agent Privacy Protocol reference implementation)
- APP client (Python SDK, 542 lines)
- NCG adapter via APP protocol

### Fixed
- Various stats CLI path and documentation fixes

## [2.0.7] - 2026-03-23

### Added
- **Universal streaming deobfuscation** — LLM responses are deobfuscated at the pi-ai EventStream level via a global hook (`globalThis.__shroudStreamDeobfuscate`). Works for ALL LLM providers (Anthropic, OpenAI, Google) and ALL delivery channels (Slack, WhatsApp, Telegram, Discord, Signal, etc.) on any OpenClaw version. The hook is injected into pi-ai's `EventStream.push()` by `deploy-local.sh` and uses buffered streaming deobfuscation to handle token-level chunks.
- **Bidirectional `before_message_write`** — assistant messages are deobfuscated (fakes → real values) for the transcript; non-assistant messages are obfuscated as before.
- **`deploy-local.sh` auto-patches pi-ai** — patches `EventStream.push()` with the deobfuscation hook, backs up the original, and clears the Node.js V8 compile cache to ensure the patch takes effect. Idempotent.
- **`maxFakeLength()`** on Obfuscator — returns the longest fake value in the mapping store (used for streaming holdback calculation).
- **Automated test script** — `scripts/test-deobfuscation.mjs` with local round-trip and Slack end-to-end tests.

### Fixed
- **Slack mrkdwn link formatting breaking email detection** — Slack auto-links emails as `<mailto:X|display>`, which splits entity text across tag boundaries (e.g. `jj@kk.net` becomes `<mailto:jj@kk.et|jj@kk.>net`). Added `stripSlackLinks()` pre-processing in `obfuscate()` to recover plain text before entity detection.

### Removed
- Removed obsolete hook and interceptor code replaced by universal streaming deobfuscation. 210 tests.

## [2.0.6] - 2026-03-23

### Fixed
- **Cross-version hook compatibility** — improved hook registration for broader OpenClaw version support. 5 new tests.

## [2.0.5] - 2026-03-23

### Changed
- **Hook architecture** — switched to `before_message_write` for per-message obfuscation as messages are written to the session transcript. Audit logging fully preserved.

## [2.0.4] - 2026-03-23

### Fixed
- **OpenClaw compatibility** — added `before_message_write` hook to obfuscate messages as they're written to the session transcript. All messages in the LLM context window are now obfuscated regardless of OpenClaw version. Tool depth reset moved to `before_prompt_build`.
- 5 new tests for `before_message_write` hook (215 total).

## [2.0.3] - 2026-03-23

### Fixed
- **Update script** — strip `plugins.allow` and `plugins.entries` before reinstall so OpenClaw config validation doesn't block the install.

## [2.0.2] - 2026-03-23

### Added
- **Plugin update script** — `scripts/update-openclaw-plugin.sh` automates the update cycle (saves config, reinstalls from npm, restores config, restarts gateway).

### Fixed
- README: removed internal config tables from community edition, fixed license references (MIT → Apache 2.0), updated test count, removed stale "not published" notice.

## [2.0.0] - 2026-03-23

### Changed
- **Community Edition release** — Shroud is now split into Community (open-source, npm) and Enterprise (licensed) editions. This release is the Community Edition with all core privacy features intact.
- Enterprise features are available separately in the Enterprise Edition.

### Community Edition includes
- Full detection engine (27 categories, regex + context + code-aware + custom patterns)
- Deterministic obfuscation/deobfuscation with HMAC-keyed fake values
- All generators (IPs, names, emails, phones, MACs, hostnames, network infra)
- Subnet-aware deobfuscation (CGNAT IPv4 + ULA IPv6 residual recovery)
- Canary token injection for leak detection
- Tamper-evident audit logging with proof hashes
- Three redaction modes (full, masked, stats)
- Allowlist/denylist with wildcard support
- Custom regex patterns
- Dry-run mode
- Tool chain depth tracking
- LRU store eviction
- All performance optimizations from v1.5.1

## [1.5.1] - 2026-03-23

### Fixed
- **Phone number format preservation** — fake phone numbers now preserve the original separator style. Numbers without separators (e.g. `+15551234567`) produce compact fakes without spaces. Previously, spaces were always inserted, causing LLMs to strip them in tool call parameters and breaking `before_tool_call` deobfuscation — which caused WhatsApp sends via cron to fail with fake target numbers.
- **Tool chain depth counter reset** — `_toolDepth` now resets at the start of each LLM turn. Previously the counter never reset between turns, causing false "tool chain depth exceeds max" warnings after normal multi-tool conversations.

### Performance
- **Single-pass deobfuscation** — replaced O(F×M) per-fake `split/join` loop with a single combined regex pass. For 1000 mappings on 100KB text, this eliminates ~300MB of string scanning.
- **Segment-based obfuscation replacement** — replaced right-to-left `slice+slice` per entity with a single forward pass collecting segments and joining once. Eliminates O(E×M) string copies.
- **Proximity clustering O(n²) → O(n log n)** — replaced pairwise entity comparison with sorted two-pointer window scan.
- **Batch hostname/denylist/learned-entity scanning** — replaced per-string `indexOf` loops with single combined regex pass per group. Reduces O(S×M) to O(M).
- **Block splitting without re-scan** — `_splitBlocks` now uses `matchAll` to derive positions directly instead of `split` + `indexOf` re-scanning.
- **Binary search for block lookup** — context boost now uses binary search over sorted blocks instead of linear `find`.
- **Bounded wildcard cache** — capped at 500 entries with FIFO eviction to prevent unbounded memory growth.
- **Efficient learned entity eviction** — in-place deletion instead of map rebuild when cap exceeded.

## [1.5.0] - 2026-03-23

### Added
- **`compatibility` manifest field** — `minOpenClawVersion` in `openclaw.plugin.json` for version compatibility checks.

## [1.4.0] - 2026-03-22

### Added
- Advanced operational features for teams (available in Enterprise Edition)
- Config validation expanded for new settings
- 60 new tests (303 total across 17 test files)

## [1.3.0] - 2026-03-22

### Added
- **Detector overrides** — disable or change confidence for individual built-in rules via `detectorOverrides` config. Overrides apply to both direct regex and code-aware detection.
- **Rule hit counters** — per-rule match counts tracked for the process lifetime, surfaced in `getStats().ruleHits` and audit log lines (`byRule=...`).
- **`shroud-stats` tool** — registered via OpenClaw `registerTool()`, queryable from conversation. Shows all rules with status, confidence, hit counts, store size, and audit status.
- **Wave 1 extended detection rules** (~60 new patterns):
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
- Enterprise agent features (available in Enterprise Edition)
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
- **Verbose audit logging** for response deobfuscation hook for WhatsApp/auto-reply. Per-request audit lines show entity counts, categories, char deltas, and optional proof hashes — without ever logging raw values.
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
- Response deobfuscation hook for WhatsApp/auto-reply.
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
