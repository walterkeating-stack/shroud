# Policy-as-Code

> Status: Config key exists, not implemented

## Concept

External JSON policy files that define obfuscation rules declaratively — allowlists, denylists, locked categories, and per-category overrides — loaded at startup and enforced by the obfuscation pipeline.

## Config Keys

```json
{
  "policyFile": "/path/to/shroud-policy.json"
}
```

## Intended Behavior

- Load policy JSON at startup (and on hot-reload if enabled)
- Policy defines:
  - Required categories that MUST be detected (compliance)
  - Category-level allowlists/denylists (additive to config)
  - Minimum confidence overrides per category
  - Blocked actions (e.g., prevent disabling certain detectors)
- Policy violations surface in `ComplianceReport` on every `ObfuscationResult`
- Integrates with SIEM for policy violation alerting

## Implementation Notes

- `policyFile` config key defined in enterprise `openclaw.plugin.json`
- Policy allowlist/denylist referenced in obfuscation pipeline docs (steps 3, 5)
- No implementation exists in `src/` — needs full build
- Consider: JSON Schema for policy validation, policy inheritance (org → team → project)
