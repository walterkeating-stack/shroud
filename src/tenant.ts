/**
 * Multi-tenant store manager.
 *
 * Maintains separate MappingStore instances per tenant, ensuring
 * that obfuscation mappings never leak across tenant boundaries.
 */

import { MemoryStore, MappingStore } from "./store.js";

export class TenantStoreManager {
  private _stores: Map<string, MemoryStore> = new Map();
  private _defaultTenantId: string;

  constructor(defaultTenantId = "__default__") {
    this._defaultTenantId = defaultTenantId;
  }

  /** Get or create a store for the given tenant. */
  getStore(tenantId?: string): MemoryStore {
    const id = tenantId || this._defaultTenantId;
    let store = this._stores.get(id);
    if (!store) {
      store = new MemoryStore();
      this._stores.set(id, store);
    }
    return store;
  }

  /** List all active tenant IDs. */
  tenantIds(): string[] {
    return [...this._stores.keys()];
  }

  /** Total mappings across all tenants. */
  totalSize(): number {
    let total = 0;
    for (const store of this._stores.values()) {
      total += store.size();
    }
    return total;
  }

  /** Clear all stores for all tenants. */
  clearAll(): void {
    for (const store of this._stores.values()) {
      store.clear();
    }
    this._stores.clear();
  }

  /** Clear store for a specific tenant. */
  clearTenant(tenantId: string): void {
    const store = this._stores.get(tenantId);
    if (store) {
      store.clear();
      this._stores.delete(tenantId);
    }
  }
}
