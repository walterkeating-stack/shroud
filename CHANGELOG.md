# Changelog

All notable changes to this project will be documented in this file.

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
