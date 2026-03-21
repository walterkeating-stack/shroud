/**
 * Tamper-evident audit log for PII detection events (in-memory only).
 *
 * Logs what was detected (category, count, timestamp) WITHOUT storing real values.
 * Uses HMAC chaining for tamper evidence -- each log entry includes a hash of
 * the previous entry, so any modification/deletion is detectable.
 */

import { createHash, createHmac, randomBytes } from "node:crypto";

import { DetectedEntity } from "./types.js";

export interface AuditEntry {
  timestamp: number;
  timestampIso: string;
  eventType: string;
  sessionId: string;
  requestId: string;
  categories: Record<string, number>;
  totalEntities: number;
  textLength: number;
  processingTimeMs: number;
  chainHash: string;
}

interface AuditStats {
  totalObfuscationEvents: number;
  totalDeobfuscationEvents: number;
  totalEntities: number;
  totalReplacements: number;
  byCategory: Record<string, number>;
}

export class AuditLogger {
  private readonly _secret: Buffer;
  private readonly _sessionId: string;
  private readonly _maxEntries: number;
  private _lastHash: string;
  private _entries: AuditEntry[];
  private _stats: AuditStats;

  constructor(secretKey: string, maxEntries = 200) {
    this._secret = Buffer.from(secretKey, "utf-8");
    this._sessionId = createHash("sha256")
      .update(`${secretKey}:${Date.now()}`)
      .digest("hex")
      .slice(0, 12);
    this._maxEntries = maxEntries;
    this._lastHash = "0".repeat(64); // Genesis hash
    this._entries = [];
    this._stats = {
      totalObfuscationEvents: 0,
      totalDeobfuscationEvents: 0,
      totalEntities: 0,
      totalReplacements: 0,
      byCategory: {},
    };
  }

  /** Generate a unique request ID. */
  static generateRequestId(): string {
    return randomBytes(8).toString("hex");
  }

  /** Log an obfuscation event (no real values stored). */
  logObfuscation(
    entities: DetectedEntity[],
    textLength: number,
    requestId?: string,
    processingTimeMs?: number,
  ): void {
    if (entities.length === 0) return;

    // Aggregate by category
    const categories: Record<string, number> = {};
    for (const entity of entities) {
      const cat = entity.category;
      categories[cat] = (categories[cat] ?? 0) + 1;
    }

    this._writeEntry(
      "obfuscation",
      categories,
      entities.length,
      textLength,
      requestId,
      processingTimeMs,
    );

    // Update running stats
    this._stats.totalObfuscationEvents += 1;
    this._stats.totalEntities += entities.length;
    for (const [cat, count] of Object.entries(categories)) {
      this._stats.byCategory[cat] = (this._stats.byCategory[cat] ?? 0) + count;
    }
  }

  /** Log a deobfuscation event. */
  logDeobfuscation(
    replacementsMade: number,
    requestId?: string,
    processingTimeMs?: number,
  ): void {
    if (replacementsMade <= 0) return;

    this._writeEntry(
      "deobfuscation",
      {},
      replacementsMade,
      0,
      requestId,
      processingTimeMs,
    );

    // Update running stats
    this._stats.totalDeobfuscationEvents += 1;
    this._stats.totalReplacements += replacementsMade;
  }

  private _writeEntry(
    eventType: string,
    categories: Record<string, number>,
    totalEntities: number,
    textLength: number,
    requestId?: string,
    processingTimeMs?: number,
  ): void {
    const ts = Date.now();
    const tsIso = new Date(ts).toISOString();

    // Compute chain hash
    const sortedCategories = JSON.stringify(
      categories,
      Object.keys(categories).sort(),
    );
    const payload = `${this._lastHash}:${ts}:${eventType}:${sortedCategories}`;
    const chainHash = createHmac("sha256", this._secret)
      .update(payload)
      .digest("hex");

    const entry: AuditEntry = {
      timestamp: ts,
      timestampIso: tsIso,
      eventType,
      sessionId: this._sessionId,
      requestId: requestId ?? AuditLogger.generateRequestId(),
      categories,
      totalEntities,
      textLength,
      processingTimeMs: Math.round((processingTimeMs ?? 0) * 100) / 100,
      chainHash,
    };

    this._lastHash = chainHash;

    // Ring buffer: drop oldest if at capacity
    if (this._entries.length >= this._maxEntries) {
      this._entries.shift();
    }
    this._entries.push(entry);
  }

  /** Return aggregate statistics (safe to expose). */
  getStats(): object {
    return {
      sessionId: this._sessionId,
      totalEvents:
        this._stats.totalObfuscationEvents +
        this._stats.totalDeobfuscationEvents,
      totalObfuscationEvents: this._stats.totalObfuscationEvents,
      totalDeobfuscationEvents: this._stats.totalDeobfuscationEvents,
      totalEntitiesScrubbed: this._stats.totalEntities,
      totalReplacementsRestored: this._stats.totalReplacements,
      byCategory: { ...this._stats.byCategory },
    };
  }

  /**
   * Verify the integrity of the audit log chain.
   * Returns { valid, entriesChecked }.
   */
  verifyChain(): { valid: boolean; entriesChecked: number } {
    let prevHash = "0".repeat(64);
    let count = 0;

    for (const entry of this._entries) {
      count += 1;

      // Recompute expected hash
      const sortedCategories = JSON.stringify(
        entry.categories,
        Object.keys(entry.categories).sort(),
      );
      const payload = `${prevHash}:${entry.timestamp}:${entry.eventType}:${sortedCategories}`;
      const expected = createHmac("sha256", this._secret)
        .update(payload)
        .digest("hex");

      if (entry.chainHash !== expected) {
        return { valid: false, entriesChecked: count };
      }

      prevHash = entry.chainHash;
    }

    return { valid: true, entriesChecked: count };
  }
}
