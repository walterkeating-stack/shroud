# Active Monitoring

> Status: Config keys exist, not implemented

## Concept

Rolling-window rate monitoring with spike detection. Establishes a baseline detection rate and alerts when the current rate exceeds baseline by a configurable multiplier — catches anomalous PII exposure patterns in real time.

## Config Keys

```json
{
  "monitorEnabled": true,
  "monitorRateWindowMs": 60000,
  "monitorSpikeMultiplier": 3.0,
  "monitorMaxAlerts": 500
}
```

## Intended Behavior

- Track detections per second in a rolling window (`monitorRateWindowMs`)
- Compute baseline rate from the window
- Alert when current rate > baseline × `monitorSpikeMultiplier`
- Keep up to `monitorMaxAlerts` alerts in memory (ring buffer)
- Alerts available via `shroud_status` tool and SIEM integration

## Implementation Notes

- Complementary to exposure tracking (exposure = absolute thresholds, monitoring = relative spikes)
- Consider: separate baseline per category vs single global baseline
- Consider: warm-up period where no alerts fire (baseline needs data to be meaningful)
