# Enterprise Feature Archive

Extracted from the `shroud-enterprise` branch (March 2026) before archival. These features were **specced in config and documented in the handbook TOC** but most were never fully implemented. They represent the enterprise roadmap — future development targets for community Shroud.

## Status Summary

| Feature | Config Keys Exist | Implemented | Documented |
|---------|:-:|:-:|:-:|
| [Policy-as-Code](policy-as-code.md) | Yes | No | TOC only |
| [Multi-Tenant Isolation](multi-tenant-isolation.md) | Yes | Partial (HMAC keying) | TOC only |
| [Compliance Mode](compliance-mode.md) | Yes | No | TOC only |
| [SIEM Integration](siem-integration.md) | Yes | No | TOC only |
| [Key Rotation](key-rotation.md) | Yes | No | TOC only |
| [Exposure Tracking](exposure-tracking.md) | Yes | No | TOC only |
| [Session Handoff](session-handoff.md) | Yes | No | TOC only |
| [Cross-Agent Shared Store](shared-store.md) | Yes | No | TOC only |
| [Per-Session Isolation](session-isolation.md) | Yes | No | TOC only |
| [Provenance Tagging](provenance-tagging.md) | Yes | No | TOC only |
| [Active Monitoring](active-monitoring.md) | Yes | No | TOC only |
| [Hot-Reload](hot-reload.md) | Yes | No | TOC only |
| [NCG Adapter](ncg-adapter.md) | N/A | Yes (Python) | Yes |
| [Audit Logging](audit-logging.md) | Yes | Yes | Yes |

## What's Already in Community

- **Multi-tenant HMAC keying** — `tenantId` flows through `MappingEngine` (src/mapping.ts) and `MappingStore` (src/store.ts). Same value produces different fakes per tenant.
- **Audit logging** — Full implementation with proof hashes, chain hashing, category breakdowns. Config keys: `auditEnabled`, `auditLogFormat`, `auditIncludeProofHashes`, etc.
- **Canary tokens** — Leak detection via invisible markers.
- **LRU store eviction** — `maxStoreMappings` config.
- **Dry-run mode** — Detection without replacement.

## Code Preserved

- [ncg-adapter.md](ncg-adapter.md) — Full 531-line Python adapter (`ncg_adapter.py`)
- [enterprise-config.md](enterprise-config.md) — All enterprise config keys from `openclaw.plugin.json`
