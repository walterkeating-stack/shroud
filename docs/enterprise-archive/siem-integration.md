# SIEM Integration

> Status: Config keys exist, not implemented

## Concept

Push obfuscation/deobfuscation audit events to external SIEM systems (Splunk, Elastic, Sentinel, etc.) via webhooks. Supports batching, retry with backoff, and CEF format for traditional SIEM pipelines.

## Config Keys

```json
{
  "siemWebhooks": [
    {
      "url": "https://siem.corp/api/events",
      "authHeader": "Bearer <token>",
      "headers": { "X-Source": "shroud" },
      "eventTypes": ["obfuscate", "deobfuscate", "compliance", "exposure"]
    }
  ],
  "siemBatchSize": 100,
  "siemFlushIntervalMs": 30000,
  "siemMaxRetries": 3,
  "siemRetryBackoffMs": 1000,
  "siemEventFormat": "json"
}
```

Environment variables:
- `SHROUD_SIEM_WEBHOOK_URL` — Quick single-endpoint setup
- `SHROUD_SIEM_WEBHOOK_AUTH` — Auth header for the above

## Intended Behavior

- Buffer audit events in memory
- Flush when batch reaches `siemBatchSize` or `siemFlushIntervalMs` elapses
- HTTP POST to each webhook endpoint
- Retry failed sends with exponential backoff (`siemRetryBackoffMs` × 2^attempt)
- Support JSON and CEF (Common Event Format) output
- Event types:
  - `obfuscate` — entity detected and replaced
  - `deobfuscate` — fake reversed to real
  - `compliance` — locked category check result
  - `exposure` — rate threshold exceeded

## Implementation Notes

- All config keys defined in enterprise `openclaw.plugin.json`
- Audit event structure already exists (proof hashes, chain hashing, category breakdowns)
- The bridge already includes audit data in JSON-RPC responses — SIEM just needs a transport layer
- Consider: async flush to avoid blocking the sync pipeline (use setImmediate/setTimeout)
- Consider: disk spill for events when webhook is down
