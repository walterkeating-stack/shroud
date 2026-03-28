# Cross-Agent Shared Store

> Status: Config keys exist, not implemented

## Concept

File-based shared mapping store that multiple Shroud instances can read from. When one agent obfuscates a value, other agents sharing the same store can deobfuscate it. Enables consistent privacy across multi-agent workflows.

## Config Keys

```json
{
  "sharedStorePath": "/tmp/shroud-shared-store.json",
  "sharedStoreTtlMs": 5000
}
```

Environment variable: `SHROUD_SHARED_STORE`

## Intended Behavior

- Periodically write mapping store to `sharedStorePath`
- Other instances read from the same path with `sharedStoreTtlMs` cache TTL
- File-level locking to prevent corruption
- Merge semantics: new mappings are additive, conflicts resolved by timestamp

## Implementation Notes

- Config validation warns when `sharedStorePath` conflicts with `tenantId` (multi-tenant + shared store is ambiguous)
- Consider: file locking strategy (flock vs advisory vs atomic rename)
- Consider: scaling — file-based sharing works for 2-5 agents, not for fleet-scale
- Consider: network-based alternative (Redis, shared memory) for higher throughput
