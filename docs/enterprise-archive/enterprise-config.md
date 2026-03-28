# Enterprise Config Keys

All enterprise-specific config keys from the enterprise `openclaw.plugin.json` schema. These are the keys that exist in the enterprise config but are **not yet in community**.

Community already has: `secretKey`, `persistentSalt`, `minConfidence`, `allowlist`, `denylist`, `canaryEnabled`, `canaryPrefix`, `auditEnabled`, `verboseLogging`, `auditLogFormat`, `auditIncludeProofHashes`, `auditHashSalt`, `auditHashTruncate`, `auditMaxFakesSample`, `logMappings`, `detectorOverrides`, `customPatterns`, `maxToolDepth`, `redactionLevel`, `dryRun`, `maxStoreMappings`.

## Enterprise-Only Config Keys

### Multi-Tenant
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tenantId` | string | `""` | Multi-tenant HMAC keying (partially implemented — flows through MappingEngine) |

### Compliance
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `lockedCategories` | Category[] | `[]` | Categories that MUST be detected |
| `policyFile` | string | `""` | Path to policy-as-code JSON file |

### Exposure Tracking
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `exposureWindow` | number | `60000` | Sliding window (ms) for exposure tracking |
| `exposureThresholds` | object | `{}` | Per-category max detections per window |
| `exposureGlobalThreshold` | number | `100` | Global detection limit per window |

### Key Rotation
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `keys` | array | `[]` | Versioned keys: `[{version, key, createdAt?, expiresAt?, retired?}]` |
| `activeKeyVersion` | number | `0` | Which key version to use (0 = highest) |

### SIEM
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `siemWebhooks` | array | `[]` | Webhook endpoints: `[{url, authHeader?, headers?, eventTypes?}]` |
| `siemBatchSize` | number | `100` | Max events before auto-flush |
| `siemFlushIntervalMs` | number | `30000` | Periodic flush interval (ms) |
| `siemMaxRetries` | number | `3` | Max retry attempts per flush |
| `siemRetryBackoffMs` | number | `1000` | Initial retry backoff (doubles each retry) |
| `siemEventFormat` | `"json"` \| `"cef"` | `"json"` | SIEM event output format |

### Shared Store
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sharedStorePath` | string | `""` | File path for cross-agent shared mappings |
| `sharedStoreTtlMs` | number | `5000` | Cache TTL for shared store reads (ms) |

### Provenance
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `provenanceTagging` | boolean | `false` | Embed `«shroud:category:hash»` markers |

### Session
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sessionHandoff` | boolean | `false` | Enable encrypted mapping export/import |
| `sessionIsolation` | boolean | `false` | Per-session isolated mapping stores |

### Hot-Reload
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hotReload` | boolean | `false` | Watch config files for changes |
| `customPatternsFile` | string | `""` | Path to custom patterns JSON file |
| `hotReloadDebounceMs` | number | `1000` | Debounce interval for file changes |

### Active Monitoring
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `monitorEnabled` | boolean | `false` | Enable monitoring pipeline |
| `monitorRateWindowMs` | number | `60000` | Rolling window for rate baseline |
| `monitorSpikeMultiplier` | number | `3.0` | Alert when rate exceeds baseline × multiplier |
| `monitorMaxAlerts` | number | `500` | Max alerts in memory |

## Environment Variables (Enterprise-Only)

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `SHROUD_TENANT_ID` | `tenantId` | Tenant ID |
| `SHROUD_SHARED_STORE` | `sharedStorePath` | Shared store file path |
| `SHROUD_SIEM_WEBHOOK_URL` | `siemWebhooks` | Quick single-endpoint SIEM setup |
| `SHROUD_SIEM_WEBHOOK_AUTH` | — | Auth header for webhook URL |
| `SHROUD_KEYS` | `keys` | JSON-encoded array of versioned key objects |
