# Multi-Tenant Isolation

> Status: Partially implemented (HMAC keying only)

## Concept

Different tenants sharing the same Shroud instance get isolated mapping spaces — the same real value produces different fake values per tenant, preventing cross-tenant data leakage.

## Config Keys

```json
{
  "tenantId": "tenant-acme-corp"
}
```

Environment variable: `SHROUD_TENANT_ID`

## What's Implemented (Community)

The HMAC-based isolation is already in community Shroud:

**src/mapping.ts** — `MappingEngine` incorporates `tenantId` into the HMAC seed:
```typescript
// HMAC message = salt + tenantId + value
// Same value + different tenantId = different fake
if (this._tenantId) {
  parts.push(Buffer.from(this._tenantId, "utf-8"));
}
```

**src/store.ts** — `MappingStore` accepts `tenantId` and includes it in serialized exports.

## What's NOT Implemented

- Per-tenant mapping store isolation (separate stores, not just different HMAC seeds)
- Tenant-aware stats and audit logging
- Tenant config inheritance (org defaults → tenant overrides)
- Tenant quota management (max mappings per tenant)
- Cross-tenant leak detection (alert if tenant A's fakes appear in tenant B's context)
