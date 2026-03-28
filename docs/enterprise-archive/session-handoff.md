# Session Handoff

> Status: Config key exists, not implemented

## Concept

Encrypted export/import of mapping state between Shroud instances. Enables session continuity when a user moves between agents or when an agent restarts — the new instance can deobfuscate fakes created by the previous one.

## Config Keys

```json
{
  "sessionHandoff": true
}
```

## Intended Behavior

- `export(salt, tenantId?)` serializes the mapping store with encryption
- `import(data)` restores mappings from a previous export
- Export format includes:
  - Encrypted mapping entries (real → fake)
  - Salt and tenant ID
  - Timestamp and version
  - Integrity hash
- Transport-agnostic — the caller decides how to move the blob (file, API, message)

## Implementation Notes

- `MappingStore.export()` already exists in community — serializes store with salt and tenant
- Missing: encryption layer, integrity verification, version compatibility checks
- Consider: export size limits (large stores could produce huge blobs)
- Consider: partial export (only mappings from last N minutes)
