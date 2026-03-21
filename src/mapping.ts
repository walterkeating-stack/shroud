/**
 * Deterministic mapping engine using HMAC + salt for irreversible obfuscation.
 *
 * Uses HMAC-SHA256(secretKey, salt + value) to produce a seed, then indexes
 * into the appropriate generator's fake value pool. The salt adds randomness
 * so that the same real value produces different fake values across sessions
 * (unless the same salt is reused), preventing inference attacks.
 */

import { createHmac, randomBytes } from "node:crypto";

import { Category } from "./types.js";
import type { BaseGenerator } from "./generators/base.js";
import { NameGenerator } from "./generators/names.js";
import { NetworkGenerator, SubnetMapper } from "./generators/network.js";
import { CodeGenerator } from "./generators/codes.js";

export class MappingEngine {
  private readonly _secretKey: Buffer;
  private readonly _salt: Buffer;
  private readonly _generators: Map<Category, BaseGenerator> = new Map();

  constructor(secretKey: string, salt?: string, subnetMapper?: SubnetMapper) {
    this._secretKey = Buffer.from(secretKey, "utf-8");
    this._salt = Buffer.from(salt ?? randomBytes(16).toString("hex"), "utf-8");
    this._registerDefaults(subnetMapper);
  }

  /** Return the current salt (for persistence/restore). */
  get salt(): string {
    return this._salt.toString("utf-8");
  }

  private _registerDefaults(subnetMapper?: SubnetMapper): void {
    const generators: BaseGenerator[] = [
      new NameGenerator(),
      new NetworkGenerator(subnetMapper ?? new SubnetMapper()),
      new CodeGenerator(),
    ];
    for (const gen of generators) {
      for (const cat of gen.categories) {
        this._generators.set(cat, gen);
      }
    }
  }

  /** Register a custom generator for a category. */
  registerGenerator(category: Category, generator: BaseGenerator): void {
    this._generators.set(category, generator);
  }

  /**
   * Compute a deterministic seed from a real value using HMAC + salt.
   * Reads first 6 bytes as unsigned int (stays in safe integer range).
   */
  computeSeed(value: string): number {
    const msg = Buffer.concat([this._salt, Buffer.from(value, "utf-8")]);
    const digest = createHmac("sha256", this._secretKey).update(msg).digest();
    return digest.readUIntBE(0, 6);
  }

  /** Map a real value to a fake value, preserving format of original. */
  mapValue(value: string, category: Category): string {
    const gen = this._generators.get(category);
    if (gen === undefined) {
      // Fallback: hash-based opaque token
      const seed = this.computeSeed(value);
      return `[REDACTED-${category}-${String(seed % 10000).padStart(4, "0")}]`;
    }
    const seed = this.computeSeed(value);
    return gen.generate(category, seed, value);
  }
}
