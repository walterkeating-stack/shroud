/** In-memory bidirectional mapping store. */

import { Category } from "./types.js";

export class MemoryStore {
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

  allMappings(): Map<string, string> {
    return new Map(this._realToFake);
  }

  clear(): void {
    this._realToFake.clear();
    this._fakeToReal.clear();
    this._categories.clear();
  }
}
