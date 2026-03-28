# Key Rotation

> Status: Config keys exist, not implemented

## Concept

Versioned HMAC keys with lifecycle management. New obfuscations use the active key version while old mappings created with previous keys remain deobfuscatable. Supports key retirement and expiry.

## Config Keys

```json
{
  "keys": [
    {
      "version": 1,
      "key": "old-secret-key-hex",
      "createdAt": "2026-01-01T00:00:00Z",
      "expiresAt": "2026-06-01T00:00:00Z",
      "retired": true
    },
    {
      "version": 2,
      "key": "current-secret-key-hex",
      "createdAt": "2026-03-01T00:00:00Z"
    }
  ],
  "activeKeyVersion": 2
}
```

Environment variable: `SHROUD_KEYS` (JSON-encoded array)

## Intended Behavior

- `activeKeyVersion` selects which key to use for new obfuscations (0 = highest version)
- Deobfuscation tries all non-retired keys to find the correct reverse mapping
- Retired keys can still deobfuscate but won't be used for new obfuscations
- Expired keys are automatically retired
- Key metadata (version, created, expires) included in audit events

## Implementation Notes

- Current implementation uses a single `secretKey` passed to `MappingEngine`
- Rotation would require `MappingEngine` to accept multiple keys and tag each mapping with its key version
- Store serialization (`MappingStore.export()`) would need key version per entry
- Consider: key rotation trigger (API call, config change, scheduled)
- Consider: alerting when active key is approaching expiry
