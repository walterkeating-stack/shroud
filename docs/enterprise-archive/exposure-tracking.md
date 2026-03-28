# Exposure Tracking

> Status: Config keys exist, not implemented

## Concept

Sliding-window rate monitoring for entity detections. Alerts when detection rates spike above thresholds — indicates either a data breach in progress or a misconfigured pipeline flooding PII into the system.

## Config Keys

```json
{
  "exposureWindow": 60000,
  "exposureThresholds": {
    "email": 50,
    "credit_card": 10,
    "ssn": 5
  },
  "exposureGlobalThreshold": 100
}
```

## Intended Behavior

- Track entity detections per category in a sliding window (`exposureWindow` ms)
- When per-category count exceeds `exposureThresholds[category]`, trigger alert
- When total detections exceed `exposureGlobalThreshold`, trigger alert
- Alerts surface in:
  - `ObfuscationResult` (per-request)
  - SIEM events (if configured)
  - Active monitoring pipeline (if enabled)
- Referenced in obfuscation pipeline step 9: "Exposure tracking — check per-category detection rates"

## Implementation Notes

- Needs a time-series ring buffer per category
- Window should be wall-clock based (not request-count based) for meaningful rate limiting
- Consider: exposure alerts should be rate-limited themselves (don't flood SIEM with "still over threshold")
- Consider: auto-escalation (warning at 80%, critical at 100% of threshold)
