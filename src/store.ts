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

  put(real: string, fake: string, category: Category): void {
    this._realToFake.set(real, fake);
    this._fakeToReal.set(fake, real);
    this._categories.set(real, category);
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
  }

  /** Export all mappings for session handoff. */
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
