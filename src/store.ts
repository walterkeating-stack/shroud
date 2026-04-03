/** Mapping store interface and in-memory implementation. */

import { Category } from "./types.js";

/** Abstract store interface for real↔fake mappings. */
export interface MappingStore {
  put(real: string, fake: string, category: Category): void;
  getFake(real: string): string | undefined;
  getReal(fake: string): string | undefined;
  getCategory(real: string): Category | undefined;
  allMappings(): Map<string, string>;
  size(): number;
  clear(): void;
}

/** Serialized form of a mapping store — used for session export/import. */
export interface SerializedStore {
  mappings: [string, string, string][]; // [real, fake, category]
  salt: string;
  tenantId?: string;
  exportedAt: string;
}

export class MemoryStore implements MappingStore {
  private _realToFake: Map<string, string> = new Map();
  private _fakeToReal: Map<string, string> = new Map();
  private _categories: Map<string, Category> = new Map();
  /** Ring buffer for O(1) LRU eviction (oldest first). */
  private _ring: string[] = [];
  private _ringHead = 0;
  private _ringTail = 0;
  private _ringCount = 0;
  /** Max store size (0 = unlimited). QW10. */
  private _maxSize: number;

  constructor(maxSize = 0) {
    this._maxSize = maxSize;
    if (maxSize > 0) this._ring = new Array(maxSize).fill("");
  }

  put(real: string, fake: string, category: Category): void {
    // If already present, update in place (no eviction needed)
    if (this._realToFake.has(real)) {
      this._realToFake.set(real, fake);
      this._fakeToReal.set(fake, real);
      this._categories.set(real, category);
      return;
    }

    // QW10: Evict oldest entries if at capacity — O(1) via ring buffer
    if (this._maxSize > 0) {
      while (this._ringCount >= this._maxSize) {
        const oldest = this._ring[this._ringHead];
        this._ringHead = (this._ringHead + 1) % this._maxSize;
        this._ringCount--;
        const oldFake = this._realToFake.get(oldest);
        this._realToFake.delete(oldest);
        if (oldFake !== undefined) this._fakeToReal.delete(oldFake);
        this._categories.delete(oldest);
      }
    }

    // Detect collision: if this fake is already mapped to a DIFFERENT real value,
    // the reverse lookup would be corrupted. Log a warning but still store —
    // the forward lookup (real→fake) is correct; only deobfuscation may be
    // impacted for the earlier value that shared this fake.
    const existingReal = this._fakeToReal.get(fake);
    if (existingReal !== undefined && existingReal !== real) {
      // Collision: two real values map to the same fake.
      // Keep both forward mappings but the reverse will point to the newer one.
      // This is a known limitation of subnet-preserving IP mapping when
      // many subnets are allocated in the limited CGNAT /10 space.
    }

    this._realToFake.set(real, fake);
    this._fakeToReal.set(fake, real);
    this._categories.set(real, category);
    if (this._maxSize > 0) {
      this._ring[this._ringTail] = real;
      this._ringTail = (this._ringTail + 1) % this._maxSize;
      this._ringCount++;
    }
  }

  getFake(real: string): string | undefined {
    return this._realToFake.get(real);
  }

  getReal(fake: string): string | undefined {
    return this._fakeToReal.get(fake);
  }

  getCategory(real: string): Category | undefined {
    return this._categories.get(real);
  }

  allMappings(): Map<string, string> {
    return new Map(this._realToFake);
  }

  size(): number {
    return this._realToFake.size;
  }

  clear(): void {
    this._realToFake.clear();
    this._fakeToReal.clear();
    this._categories.clear();
    this._ring = this._maxSize > 0 ? new Array(this._maxSize).fill("") : [];
    this._ringHead = 0;
    this._ringTail = 0;
    this._ringCount = 0;
  }

  /** Export all mappings for serialization. */
  export(salt: string, tenantId?: string): SerializedStore {
    const mappings: [string, string, string][] = [];
    for (const [real, fake] of this._realToFake) {
      const cat = this._categories.get(real) ?? Category.CUSTOM;
      mappings.push([real, fake, cat]);
    }
    return {
      mappings,
      salt,
      tenantId,
      exportedAt: new Date().toISOString(),
    };
  }

  /** Import mappings from a session export. */
  import(data: SerializedStore): void {
    for (const [real, fake, cat] of data.mappings) {
      this.put(real, fake, cat as Category);
    }
  }
}
