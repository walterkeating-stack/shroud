/**
 * Core obfuscation engine: detect -> map -> replace / reverse-replace.
 *
 * Entirely synchronous (CPU-bound) -- this is important for the
 * tool_result_persist hook which is sync-only.
 */

import {
  Category,
  DetectedEntity,
  ObfuscationResult,
  ShroudConfig,
} from "./types.js";
import { MemoryStore } from "./store.js";
import { MappingEngine } from "./mapping.js";
import { SubnetMapper } from "./generators/network.js";
import { CanaryInjector } from "./canary.js";
import { AuditLogger } from "./audit.js";
import { BaseDetector } from "./detectors/base.js";
import { RegexDetector } from "./detectors/regex.js";
import { CustomPatternDetector } from "./detectors/patterns.js";
import { CodeDetector } from "./detectors/code.js";

export class Obfuscator {
  readonly config: ShroudConfig;
  private _store: MemoryStore;
  private _subnetMapper: SubnetMapper;
  private _mapping: MappingEngine;
  private _detectors: BaseDetector[];
  private _canary: CanaryInjector | null;
  private _audit: AuditLogger | null;

  constructor(config: ShroudConfig) {
    this.config = config;
    this._store = new MemoryStore();
    this._subnetMapper = new SubnetMapper();
    const salt = config.persistentSalt || undefined;
    this._mapping = new MappingEngine(
      config.secretKey,
      salt,
      this._subnetMapper,
    );
    this._detectors = [];
    this._canary = null;
    this._audit = null;

    if (config.canaryEnabled) {
      this._canary = new CanaryInjector(
        config.canaryPrefix,
        config.secretKey,
      );
    }

    if (config.auditEnabled) {
      this._audit = new AuditLogger(config.secretKey);
    }

    this._initDetectors();
  }

  private _initDetectors(): void {
    // Always enable the regex detector
    this._detectors.push(new RegexDetector());

    // Custom patterns if configured
    if (this.config.customPatterns.length > 0) {
      this._detectors.push(
        new CustomPatternDetector(this.config.customPatterns),
      );
    }

    // Code-aware detector (always enabled)
    this._detectors.push(new CodeDetector());
  }

  /** Add a custom detector at runtime. */
  addDetector(detector: BaseDetector): void {
    this._detectors.push(detector);
  }

  /**
   * Detect and replace all sensitive entities in text.
   *
   * The 7-step pipeline:
   * 1. Learn subnets from text (via SubnetMapper)
   * 2. Detect entities from all detectors
   * 3. Apply denylist (force-add denylist values found in text)
   * 4. Sort by position, resolve overlaps (prefer higher confidence)
   * 5. Filter by minConfidence and allowlist
   * 6. Map and replace right-to-left (check store first, then generate)
   * 7. Inject canary if enabled
   */
  obfuscate(text: string): ObfuscationResult {
    const startTime = Date.now();

    // 1. Learn subnet context from CIDR notation and masks in text
    this._subnetMapper.learnSubnetsFromText(text);

    // 2. Detect all entities from all detectors
    const allEntities: DetectedEntity[] = [];
    for (const detector of this._detectors) {
      allEntities.push(...detector.detect(text));
    }

    // 3. Apply denylist -- force-add any denylist values found in text
    for (const denied of this.config.denylist) {
      let idx = 0;
      while (true) {
        const pos = text.indexOf(denied, idx);
        if (pos === -1) break;
        allEntities.push({
          value: denied,
          start: pos,
          end: pos + denied.length,
          category: Category.CUSTOM,
          confidence: 1.0,
          detector: "denylist",
        });
        idx = pos + 1;
      }
    }

    // 4. Sort by position and resolve overlaps (prefer higher confidence, then earlier)
    allEntities.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
    const entities = resolveOverlaps(allEntities);

    // 5. Filter by confidence threshold and allowlist
    const allowSet = new Set(this.config.allowlist);
    const filtered = entities.filter(
      (e) =>
        e.confidence >= this.config.minConfidence &&
        !allowSet.has(e.value),
    );

    // 6. Map and replace (process right-to-left to preserve positions)
    let resultText = text;
    const mappingsUsed: Record<string, string> = {};

    for (let i = filtered.length - 1; i >= 0; i--) {
      const entity = filtered[i];

      // Check if we already have a mapping for this exact value
      let fake = this._store.getFake(entity.value);
      if (fake === undefined) {
        fake = this._mapping.mapValue(entity.value, entity.category);
        this._store.put(entity.value, fake, entity.category);
      }

      mappingsUsed[entity.value] = fake;
      resultText =
        resultText.slice(0, entity.start) + fake + resultText.slice(entity.end);
    }

    // 7. Inject canary token if enabled
    if (this._canary) {
      resultText = this._canary.inject(resultText);
    }

    // Audit log (no real values stored)
    if (this._audit && filtered.length > 0) {
      const elapsed = Date.now() - startTime;
      this._audit.logObfuscation(
        filtered,
        text.length,
        undefined,
        elapsed,
      );
    }

    return {
      original: text,
      obfuscated: resultText,
      entities: filtered,
      mappingsUsed,
    };
  }

  /**
   * Reverse-map fake values back to real values in text.
   *
   * Uses longest-match-first replacement to avoid partial substitutions.
   * Also strips any canary tokens from the text.
   */
  deobfuscate(text: string): string {
    const startTime = Date.now();

    // Strip canary tokens
    if (this._canary) {
      const prefix = this.config.canaryPrefix.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&",
      );
      const canaryRe = new RegExp(
        `\\n?<!-- ${prefix}-[a-f0-9]+ -->`,
        "g",
      );
      text = text.replace(canaryRe, "");
    }

    const allMappings = this._store.allMappings();
    if (allMappings.size === 0) return text;

    // Build reverse map: fake -> real, sorted by length descending
    const reverse = new Map<string, string>();
    for (const [real, fake] of allMappings) {
      reverse.set(fake, real);
    }

    let result = text;
    const fakes = [...reverse.keys()].sort((a, b) => b.length - a.length);
    let replacementCount = 0;
    for (const fake of fakes) {
      const real = reverse.get(fake)!;
      // Use split+join for safe replacement — avoids infinite loops when
      // the real value contains a substring matching another fake value.
      const parts = result.split(fake);
      if (parts.length > 1) {
        replacementCount += parts.length - 1;
        result = parts.join(real);
      }
    }

    // Audit log
    if (this._audit && replacementCount > 0) {
      const elapsed = Date.now() - startTime;
      this._audit.logDeobfuscation(replacementCount, undefined, elapsed);
    }

    return result;
  }

  /** Clear all mappings and start fresh. */
  reset(): void {
    this._store.clear();
    this._subnetMapper.reset();
    // New salt for new session
    this._mapping = new MappingEngine(
      this.config.secretKey,
      undefined,
      this._subnetMapper,
    );
    if (this._canary) {
      this._canary.reset();
    }
  }

  /** Return stats from audit logger and store. */
  getStats(): object {
    const storeSize = this._store.allMappings().size;
    const auditStats = this._audit ? this._audit.getStats() : null;

    return {
      storeMappings: storeSize,
      salt: this._mapping.salt,
      canarySessionId: this._canary?.sessionId ?? null,
      audit: auditStats,
    };
  }
}

/** Remove overlapping entities, keeping higher confidence ones. */
export function resolveOverlaps(
  entities: DetectedEntity[],
): DetectedEntity[] {
  if (entities.length === 0) return [];

  const resolved: DetectedEntity[] = [];
  let lastEnd = -1;

  for (const entity of entities) {
    if (entity.start >= lastEnd) {
      resolved.push(entity);
      lastEnd = entity.end;
    }
  }

  return resolved;
}
