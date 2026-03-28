# Per-Session Isolation

> Status: Config key exists, not implemented

## Concept

Each conversation session gets its own isolated mapping store. Prevents cross-session data leakage where fakes from one conversation could be deobfuscated using mappings from another.

## Config Keys

```json
{
  "sessionIsolation": true
}
```

## Intended Behavior

- Each new session creates a fresh `MappingStore` instance
- Session boundary detected via OpenClaw session ID or explicit reset
- Old session stores kept in memory for a configurable TTL (for late-arriving deobfuscation requests)
- Stats tracked per-session and aggregated

## Implementation Notes

- Currently Shroud uses a single global `MappingStore` shared via `globalThis.__shroudObfuscator`
- Session isolation would require a session-keyed map of stores
- Consider: memory pressure from many concurrent sessions
- Consider: interaction with shared store (per-session isolation + shared store = contradiction?)
