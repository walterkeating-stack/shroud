# Audit Logging

> Status: Fully implemented in both community and enterprise

## Overview

Tamper-evident audit trail for all obfuscation/deobfuscation events. Never logs real sensitive values — only counts, categories, proof hashes, and chain hashes.

## Config Keys

```json
{
  "auditEnabled": true,
  "verboseLogging": true,
  "auditLogFormat": "json",
  "auditIncludeProofHashes": true,
  "auditHashSalt": "your-audit-salt",
  "auditHashTruncate": 12,
  "auditMaxFakesSample": 3
}
```

## What Gets Logged

- Entity counts per category and rule
- Char count deltas (input vs output size)
- Request IDs for correlation
- Proof hashes: SHA-256 of input/output (truncated, salted) — proves content was processed without revealing it
- Fake value samples (only fakes, never real values)
- Chain hash: each audit entry includes hash of previous entry for tamper evidence

## Formats

### Human
```
[shroud][audit] OBFUSCATE req=a1b2 | entities=5 | byCat=email:2,ip_address:3 | chars=500->520 | modified=YES
```

### JSON
```json
{
  "event": "shroud.audit.obfuscate",
  "req": "a1b2",
  "totalEntities": 5,
  "byCategory": {"email": 2, "ip_address": 3},
  "charDelta": 20,
  "modified": true
}
```

## Bridge Implementation

The bridge (`shroud_bridge.mjs`) generates audit data on every obfuscate/deobfuscate call and includes it in the JSON-RPC response. The Python adapter formats and routes it to both console and file-based audit loggers.

Chain hash advancement:
```javascript
function advanceChain(data) {
  const payload = chainHash + JSON.stringify(data);
  chainHash = createHash("sha256").update(payload).digest("hex").slice(0, 16);
  return chainHash;
}
```
