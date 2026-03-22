/**
 * Core obfuscation engine: detect -> map -> replace / reverse-replace.
 *
 * Entirely synchronous (CPU-bound) -- this is important for the
 * tool_result_persist hook which is sync-only.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

import {
  Category,
  ComplianceReport,
  DetectedEntity,
  ObfuscationResult,
  ShroudConfig,
} from "./types.js";
import { MemoryStore, MappingStore, SerializedStore } from "./store.js";
import { FileBackedStore } from "./shared-store.js";
import { TenantStoreManager } from "./tenant.js";
import { MappingEngine } from "./mapping.js";
import { SubnetMapper } from "./generators/network.js";
import { CanaryInjector } from "./canary.js";
import { AuditLogger } from "./audit.js";
import { BaseDetector } from "./detectors/base.js";
import { RegexDetector } from "./detectors/regex.js";
import { CustomPatternDetector } from "./detectors/patterns.js";
import { CodeDetector } from "./detectors/code.js";
import { ExposureTracker, ExposureAlert } from "./exposure.js";
import { PolicyLoader, PolicyRules } from "./policy.js";
import { RedactionFormatter, RedactionLevel } from "./redaction.js";

/** Provenance tag delimiters. */
const PROV_OPEN = "\u00ab";
const PROV_CLOSE = "\u00bb";
const PROV_RE = /\u00abshroud:[^\u00bb]+\u00bb/g;

export class Obfuscator {
  readonly config: ShroudConfig;

  // Store: either simple MemoryStore, FileBackedStore (shared), or TenantStoreManager
  private _store: MappingStore;
  private _tenantManager: TenantStoreManager | null = null;

  private _subnetMapper: SubnetMapper;
  private _mapping: MappingEngine;
  private _detectors: BaseDetector[];
  private _canary: CanaryInjector | null;
  private _audit: AuditLogger | null;
  private _ruleHits: Map<string, number> = new Map();

  // Enterprise features
  private _exposureTracker: ExposureTracker | null = null;
  private _policyRules: PolicyRules | null = null;
  private _redactionFormatter: RedactionFormatter;
  private _toolDepth: number = 0;

  constructor(config: ShroudConfig) {
    this.config = config;

    // Feature 9: Shared store
    if (config.sharedStorePath) {
      this._store = new FileBackedStore(config.sharedStorePath, config.sharedStoreTtlMs);
    }
    // Feature 1: Multi-tenant
    else if (config.tenantId) {
      this._tenantManager = new TenantStoreManager();
      this._store = this._tenantManager.getStore(config.tenantId);
    } else {
      this._store = new MemoryStore();
    }

    this._subnetMapper = new SubnetMapper();
    const salt = config.persistentSalt || undefined;
    this._mapping = new MappingEngine(
      config.secretKey,
      salt,
      this._subnetMapper,
      config.tenantId || undefined, // Feature 1: tenant in HMAC
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

    // Feature 5: Exposure tracking
    if (
      Object.keys(config.exposureThresholds).length > 0 ||
      config.exposureGlobalThreshold < Infinity
    ) {
      this._exposureTracker = new ExposureTracker(
        config.exposureWindow,
        config.exposureThresholds,
        config.exposureGlobalThreshold,
      );
    }

    // Feature 7: Policy-as-code
    this._loadPolicy();

    // Feature 8: Redaction formatter
    this._redactionFormatter = new RedactionFormatter();

    this._initDetectors();
  }

  private _loadPolicy(): void {
    // Load from file if configured
    if (this.config.policyFile) {
      try {
        this._policyRules = PolicyLoader.loadFromFile(this.config.policyFile);
      } catch {
        console.warn(`[shroud] WARNING: Failed to load policy file: ${this.config.policyFile}`);
        this._policyRules = { allowlist: [], denylist: [] };
      }
    }
  }

  private _initDetectors(): void {
    const overrides = this.config.detectorOverrides;

    // Always enable the regex detector (with optional overrides)
    const regexDetector = new RegexDetector(undefined, overrides);
    this._detectors.push(regexDetector);

    // Custom patterns if configured
    if (this.config.customPatterns.length > 0) {
      this._detectors.push(
        new CustomPatternDetector(this.config.customPatterns),
      );
    }

    // Code-aware detector shares the same configured regex detector
    this._detectors.push(new CodeDetector(regexDetector));
  }

  /** Add a custom detector at runtime. */
  addDetector(detector: BaseDetector): void {
    this._detectors.push(detector);
  }

  /** Feature 1: Switch tenant context. */
  switchTenant(tenantId: string): void {
    if (!this._tenantManager) {
      this._tenantManager = new TenantStoreManager();
    }
    this._store = this._tenantManager.getStore(tenantId);
    // Re-create mapping engine with new tenant ID
    this._mapping = new MappingEngine(
      this.config.secretKey,
      this.config.persistentSalt || undefined,
      this._subnetMapper,
      tenantId,
    );
  }

  /** Feature 3: Track tool call depth. */
  enterToolCall(): number {
    return ++this._toolDepth;
  }

  /** Feature 3: Decrement tool depth. */
  exitToolCall(): number {
    return Math.max(0, --this._toolDepth);
  }

  /** Feature 3: Current tool depth. */
  get toolDepth(): number {
    return this._toolDepth;
  }

  /**
   * Detect and replace all sensitive entities in text.
   *
   * The pipeline:
   * 1. Learn subnets from text (via SubnetMapper)
   * 2. Detect entities from all detectors
   * 3. Apply denylist (force-add denylist values + policy denylist)
   * 4. Sort by position, resolve overlaps (prefer higher confidence)
   * 5. Filter by minConfidence, allowlist (simple + policy), and already-obfuscated
   * 6. Map and replace right-to-left (with redaction level + provenance)
   * 7. Inject canary if enabled
   * 8. Compliance check (locked categories)
   * 9. Exposure tracking
   */
  obfuscate(text: string, context?: string): ObfuscationResult {
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

    // 3b. Feature 7: Policy denylist scanning
    if (this._policyRules && this._policyRules.denylist.length > 0) {
      const policyMatches = PolicyLoader.scanDenylist(
        text,
        this._policyRules.denylist,
      );
      for (const m of policyMatches) {
        allEntities.push({
          value: m.value,
          start: m.start,
          end: m.end,
          category: m.category ?? Category.CUSTOM,
          confidence: 1.0,
          detector: "policy:denylist",
        });
      }
    }

    // 4. Sort by position and resolve overlaps (prefer higher confidence, then earlier)
    allEntities.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
    const entities = resolveOverlaps(allEntities);

    // 5. Filter by confidence threshold, allowlist, and already-obfuscated values
    const allowSet = new Set(this.config.allowlist);
    const filtered = entities.filter((e) => {
      if (e.confidence < this.config.minConfidence) return false;
      // Simple allowlist
      if (allowSet.has(e.value)) return false;
      // Feature 7: Policy allowlist
      if (
        this._policyRules &&
        PolicyLoader.isAllowed(e.value, this._policyRules.allowlist)
      ) {
        return false;
      }
      // Prevent double-obfuscation: skip values that are already known fakes
      if (this._store.getReal(e.value) !== undefined) return false;
      return true;
    });

    // 5b. Accumulate per-rule hit counts
    for (const entity of filtered) {
      this._ruleHits.set(
        entity.detector,
        (this._ruleHits.get(entity.detector) ?? 0) + 1,
      );
    }

    // Feature 5: Exposure tracking
    let exposureAlerts: ExposureAlert[] = [];
    if (this._exposureTracker) {
      for (const entity of filtered) {
        this._exposureTracker.record(entity.category, 1);
      }
      exposureAlerts = this._exposureTracker.check();
    }

    // Determine redaction level (context-specific or global)
    const level: RedactionLevel = this.config.redactionLevel;
    this._redactionFormatter.resetCounters();

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

      // Feature 8: Apply redaction level
      const replacement = this._redactionFormatter.format(
        entity.value,
        fake,
        entity.category,
        level,
      );

      // Feature 10: Provenance tagging
      let finalReplacement = replacement;
      if (this.config.provenanceTagging) {
        const seed = this._mapping.computeSeed(entity.value);
        const hash4 = (seed & 0xffff).toString(16).padStart(4, "0");
        finalReplacement = `${replacement}${PROV_OPEN}shroud:${entity.category}:${hash4}${PROV_CLOSE}`;
      }

      mappingsUsed[entity.value] = fake;
      resultText =
        resultText.slice(0, entity.start) +
        finalReplacement +
        resultText.slice(entity.end);
    }

    // 7. Inject canary token if enabled
    if (this._canary) {
      resultText = this._canary.inject(resultText);
    }

    // 8. Feature 4: Compliance check
    let complianceReport: ComplianceReport | undefined;
    if (this.config.lockedCategories.length > 0) {
      const foundCategories = new Set(filtered.map((e) => e.category));
      const found: Category[] = [];
      const missing: Category[] = [];
      for (const locked of this.config.lockedCategories) {
        if (foundCategories.has(locked)) {
          found.push(locked);
        } else {
          missing.push(locked);
        }
      }
      complianceReport = {
        found,
        missing,
        passed: missing.length === 0,
      };
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
      complianceReport,
    };
  }

  /**
   * Reverse-map fake values back to real values in text.
   *
   * Uses longest-match-first replacement to avoid partial substitutions.
   * Also strips canary tokens and provenance tags.
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

    // Feature 10: Strip provenance tags
    if (this.config.provenanceTagging) {
      text = text.replace(PROV_RE, "");
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

  /**
   * Deobfuscate text and return replacement count alongside the result.
   * Used by audit logging to report deobfuscation stats without logging text.
   */
  deobfuscateWithStats(text: string): { text: string; replacementCount: number } {
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

    // Feature 10: Strip provenance tags
    if (this.config.provenanceTagging) {
      text = text.replace(PROV_RE, "");
    }

    const allMappings = this._store.allMappings();
    if (allMappings.size === 0) return { text, replacementCount: 0 };

    const reverse = new Map<string, string>();
    for (const [real, fake] of allMappings) {
      reverse.set(fake, real);
    }

    let result = text;
    const fakes = [...reverse.keys()].sort((a, b) => b.length - a.length);
    let replacementCount = 0;
    for (const fake of fakes) {
      const real = reverse.get(fake)!;
      const parts = result.split(fake);
      if (parts.length > 1) {
        replacementCount += parts.length - 1;
        result = parts.join(real);
      }
    }

    if (this._audit && replacementCount > 0) {
      const elapsed = Date.now() - startTime;
      this._audit.logDeobfuscation(replacementCount, undefined, elapsed);
    }

    return { text: result, replacementCount };
  }

  // -------------------------------------------------------------------------
  // Feature 2: Session handoff — export / import
  // -------------------------------------------------------------------------

  /** Export mapping store as encrypted blob for session handoff. */
  exportSession(): string {
    if (!(this._store instanceof MemoryStore)) {
      throw new Error("Session export only supported with MemoryStore (not shared store)");
    }
    const data = this._store.export(
      this._mapping.salt,
      this.config.tenantId || undefined,
    );
    return this._encrypt(JSON.stringify(data));
  }

  /** Import mapping store from encrypted blob. */
  importSession(blob: string): void {
    const json = this._decrypt(blob);
    const data: SerializedStore = JSON.parse(json);
    if (this._store instanceof MemoryStore) {
      this._store.import(data);
    }
  }

  private _encrypt(plaintext: string): string {
    const key = scryptSync(this.config.secretKey, "shroud-session", 32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString("base64");
  }

  private _decrypt(blob: string): string {
    const key = scryptSync(this.config.secretKey, "shroud-session", 32);
    const buf = Buffer.from(blob, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc) + decipher.final("utf-8");
  }

  // -------------------------------------------------------------------------
  // Feature 6: Corpus pre-scanning
  // -------------------------------------------------------------------------

  /** Batch obfuscate documents for index-time corpus pre-scanning. */
  preScanCorpus(
    documents: Array<{ id: string; text: string }>,
  ): { documents: Array<{ id: string; obfuscated: string }>; mappingRef: string } {
    const results = documents.map((doc) => {
      const result = this.obfuscate(doc.text);
      return { id: doc.id, obfuscated: result.obfuscated };
    });

    // Export mappings as encrypted reference
    const mappingRef = this.exportSession();

    return { documents: results, mappingRef };
  }

  /** Clear all mappings and start fresh. */
  reset(): void {
    this._store.clear();
    this._subnetMapper.reset();
    this._ruleHits.clear();
    this._toolDepth = 0;
    if (this._exposureTracker) this._exposureTracker.reset();
    // New salt for new session
    this._mapping = new MappingEngine(
      this.config.secretKey,
      undefined,
      this._subnetMapper,
      this.config.tenantId || undefined,
    );
    if (this._canary) {
      this._canary.reset();
    }
  }

  /** Return stats from audit logger, store, and enterprise features. */
  getStats(): object {
    const storeSize = this._store.size();
    const auditStats = this._audit ? this._audit.getStats() : null;

    const stats: Record<string, unknown> = {
      storeMappings: storeSize,
      salt: this._mapping.salt,
      canarySessionId: this._canary?.sessionId ?? null,
      audit: auditStats,
      ruleHits: Object.fromEntries(this._ruleHits),
      // Enterprise
      tenantId: this.config.tenantId || null,
      toolDepth: this._toolDepth,
      redactionLevel: this.config.redactionLevel,
      provenanceTagging: this.config.provenanceTagging,
      sharedStore: !!this.config.sharedStorePath,
      sessionHandoff: this.config.sessionHandoff,
    };

    if (this.config.lockedCategories.length > 0) {
      stats.lockedCategories = this.config.lockedCategories;
    }

    if (this._exposureTracker) {
      stats.exposureAlerts = this._exposureTracker.check();
    }

    if (this._tenantManager) {
      stats.tenants = this._tenantManager.tenantIds();
      stats.totalTenantMappings = this._tenantManager.totalSize();
    }

    return stats;
  }

  /** Get exposure alerts (Feature 5). */
  getExposureAlerts(): ExposureAlert[] {
    return this._exposureTracker?.check() ?? [];
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
