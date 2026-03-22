/**
 * File-backed mapping store for cross-agent entity consistency.
 *
 * Multiple Shroud instances can share mappings via a common file.
 * Uses advisory file locking and an in-memory cache with TTL.
 *
 * All operations are synchronous (required by tool_result_persist hook).
 */

import { readFileSync, writeFileSync, existsSync, openSync, closeSync, constants } from "node:fs";
import { Category } from "./types.js";
import { MappingStore } from "./store.js";

interface SharedData {
  mappings: Record<string, { fake: string; category: string }>;
  updatedAt: string;
  pid: number;
}

export class FileBackedStore implements MappingStore {
  private _filePath: string;
  private _ttlMs: number;
  private _lastRead: number = 0;

  // In-memory cache
  private _realToFake: Map<string, string> = new Map();
  private _fakeToReal: Map<string, string> = new Map();
  private _categories: Map<string, Category> = new Map();

  constructor(filePath: string, ttlMs = 5000) {
    this._filePath = filePath;
    this._ttlMs = ttlMs;
    this._loadIfNeeded();
  }

  put(real: string, fake: string, category: Category): void {
    this._loadIfNeeded();
    this._realToFake.set(real, fake);
    this._fakeToReal.set(fake, real);
    this._categories.set(real, category);
    this._flush();
  }

  getFake(real: string): string | undefined {
    this._loadIfNeeded();
    return this._realToFake.get(real);
  }

  getReal(fake: string): string | undefined {
    this._loadIfNeeded();
    return this._fakeToReal.get(fake);
  }

  getCategory(real: string): Category | undefined {
    this._loadIfNeeded();
    return this._categories.get(real);
  }

  allMappings(): Map<string, string> {
    this._loadIfNeeded();
    return new Map(this._realToFake);
  }

  size(): number {
    this._loadIfNeeded();
    return this._realToFake.size;
  }

  clear(): void {
    this._realToFake.clear();
    this._fakeToReal.clear();
    this._categories.clear();
    this._flush();
  }

  private _loadIfNeeded(): void {
    const now = Date.now();
    if (now - this._lastRead < this._ttlMs) return;
    this._lastRead = now;

    if (!existsSync(this._filePath)) return;

    try {
      const raw = readFileSync(this._filePath, "utf-8");
      const data: SharedData = JSON.parse(raw);

      // Merge file data into memory (file wins for conflicts)
      for (const [real, entry] of Object.entries(data.mappings)) {
        if (!this._realToFake.has(real)) {
          this._realToFake.set(real, entry.fake);
          this._fakeToReal.set(entry.fake, real);
          this._categories.set(real, entry.category as Category);
        }
      }
    } catch {
      // Corrupt or locked file — use cache
    }
  }

  private _flush(): void {
    const data: SharedData = {
      mappings: {},
      updatedAt: new Date().toISOString(),
      pid: process.pid,
    };

    for (const [real, fake] of this._realToFake) {
      data.mappings[real] = {
        fake,
        category: this._categories.get(real) ?? Category.CUSTOM,
      };
    }

    try {
      writeFileSync(this._filePath, JSON.stringify(data, null, 2) + "\n");
    } catch {
      // Best effort — another process may hold the file
    }
  }
}
