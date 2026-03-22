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
  FilterStats,
  ObfuscationResult,
  ShroudConfig,
} from "./types.js";
import { MemoryStore, MappingStore, SerializedStore } from "./store.js";
import { FileBackedStore } from "./shared-store.js";
import { TenantStoreManager } from "./tenant.js";
import { MappingEngine } from "./mapping.js";
import { SubnetMapper, CGNAT_BASE, CGNAT_MASK_10, ipToInt, intToIp } from "./generators/network.js";
import { CanaryInjector } from "./canary.js";
import { AuditLogger } from "./audit.js";
import { BaseDetector } from "./detectors/base.js";
import { RegexDetector } from "./detectors/regex.js";
import { CustomPatternDetector } from "./detectors/patterns.js";
import { CodeDetector } from "./detectors/code.js";
import { ContextDetector } from "./detectors/context.js";
import { ExposureTracker, ExposureAlert } from "./exposure.js";
import { PolicyLoader, PolicyRules } from "./policy.js";
import { RedactionFormatter, RedactionLevel } from "./redaction.js";
import { KeyRing, VersionedKey } from "./keyring.js";
import { WebhookSink, SiemEventBuilder, SiemEvent, SiemSinkConfig, SiemEventType } from "./siem.js";
import { DetectorReloader } from "./hot-reload.js";
import { SessionManager } from "./session.js";
import { AlertPipeline, MonitorAlert } from "./monitor.js";

/** Provenance tag delimiters. */
const PROV_OPEN = "\u00ab";
const PROV_CLOSE = "\u00bb";
const PROV_RE = /\u00abshroud:[^\u00bb]+\u00bb/g;

/** Regex to find CGNAT IPs (100.64.0.0/10) in text. */
const CGNAT_IP_RE = /\b(100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b/g;

/** Regex to find fd00::/8 ULA IPv6 addresses (Shroud fake range) in text. */
const ULA_IPV6_RE = /(?:^|(?<=[\s,;=(\[]))fd00(?::[0-9a-fA-F]{1,4}){0,7}(?:::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)?(?=$|[\s,;)\]\/])/gi;

/**
 * Expand a compressed IPv6 address to full 8-group form.
 * e.g. "fd00:a1b2::1" → "fd00:a1b2:0000:0000:0000:0000:0000:0001"
 */
function expandIPv6(addr: string): string {
  // Remove any trailing CIDR prefix
  const cidrIdx = addr.indexOf("/");
  const clean = cidrIdx >= 0 ? addr.slice(0, cidrIdx) : addr;

  if (!clean.includes("::")) {
    // Already full form — just zero-pad each group
    const groups = clean.split(":");
    if (groups.length !== 8) return clean.toLowerCase();
    return groups.map((g) => g.padStart(4, "0")).join(":").toLowerCase();
  }

  const [left, right] = clean.split("::");
  const leftGroups = left ? left.split(":") : [];
  const rightGroups = right ? right.split(":") : [];
  const missing = 8 - leftGroups.length - rightGroups.length;
  const allGroups = [
    ...leftGroups,
    ...Array(missing).fill("0000"),
    ...rightGroups,
  ];
  return allGroups.map((g) => g.padStart(4, "0")).join(":").toLowerCase();
}

/**
 * Compress a full 8-group IPv6 address to shortest form.
 * e.g. "2001:0db8:0000:0000:0000:0000:0000:0001" → "2001:db8::1"
 */
function compressIPv6(addr: string): string {
  const groups = addr.split(":").map((g) => g.replace(/^0+/, "") || "0");

  // Find longest run of consecutive "0" groups
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen >= 2) {
    const left = groups.slice(0, bestStart).join(":");
    const right = groups.slice(bestStart + bestLen).join(":");
    return `${left}::${right}`;
  }

  return groups.join(":");
}

/**
 * Convert a simple wildcard pattern (* and ?) to a RegExp.
 * Caches compiled patterns for reuse.
 */
const _wildcardCache = new Map<string, RegExp>();
function wildcardMatch(value: string, pattern: string): boolean {
  // Fast path: no wildcards = exact match
  if (!pattern.includes("*") && !pattern.includes("?")) {
    return value === pattern;
  }
  let re = _wildcardCache.get(pattern);
  if (!re) {
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    const reStr = "^" + escaped.replace(/\*/g, ".*").replace(/\?/g, ".") + "$";
    re = new RegExp(reStr, "i");
    _wildcardCache.set(pattern, re);
  }
  return re.test(value);
}

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
  private _detectionsByCategory: Map<string, number> = new Map();
  private _replacementsByCategory: Map<string, number> = new Map();

  // Enterprise features
  private _exposureTracker: ExposureTracker | null = null;
  private _policyRules: PolicyRules | null = null;
  private _redactionFormatter: RedactionFormatter;
  private _contextDetector: ContextDetector | null = null;
  private _toolDepth: number = 0;

  // Key rotation
  private _keyRing: KeyRing;

  // SIEM
  private _siemSink: WebhookSink | null = null;

  // Hot-reload
  private _reloader: DetectorReloader | null = null;

  // Per-session isolation
  private _sessionManager: SessionManager | null = null;

  // Active monitoring
  private _monitor: AlertPipeline | null = null;

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
      this._store = new MemoryStore(config.maxStoreMappings);
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

    // --- Key rotation ---
    if (config.keys && config.keys.length > 0) {
      const vkeys: VersionedKey[] = config.keys.map((k) => ({
        version: k.version,
        key: k.key,
        createdAt: k.createdAt ?? new Date().toISOString(),
        expiresAt: k.expiresAt,
        retired: k.retired,
      }));
      this._keyRing = new KeyRing(
        vkeys,
        config.activeKeyVersion > 0 ? config.activeKeyVersion : undefined,
      );
      // Re-create mapping engine with active key
      const activeKey = this._keyRing.activeKey();
      this._mapping = new MappingEngine(
        activeKey.key,
        salt,
        this._subnetMapper,
        config.tenantId || undefined,
      );
    } else {
      this._keyRing = KeyRing.fromSingleKey(config.secretKey);
    }

    // --- SIEM sink ---
    if (config.siemWebhooks && config.siemWebhooks.length > 0) {
      this._siemSink = new WebhookSink({
        endpoints: config.siemWebhooks.map((wh) => ({
          ...wh,
          eventTypes: wh.eventTypes as SiemEventType[] | undefined,
        })),
        batchSize: config.siemBatchSize,
        flushIntervalMs: config.siemFlushIntervalMs,
        maxRetries: config.siemMaxRetries,
        retryBackoffMs: config.siemRetryBackoffMs,
        eventFormat: config.siemEventFormat,
      });
    }

    // --- Hot-reload ---
    if (config.hotReload ?? false) {
      this._reloader = new DetectorReloader(
        {
          policyFile: config.policyFile || undefined,
          customPatternsFile: config.customPatternsFile || undefined,
          debounceMs: config.hotReloadDebounceMs,
        },
        (what, data) => this._onHotReload(what, data),
      );
      this._reloader.start();
    }

    // --- Per-session isolation ---
    if (config.sessionIsolation ?? false) {
      this._sessionManager = new SessionManager({
        secretKey: this._keyRing.activeKey().key,
        canaryEnabled: config.canaryEnabled,
        canaryPrefix: config.canaryPrefix,
        maxStoreMappings: config.maxStoreMappings,
        tenantId: config.tenantId,
      });
      // Create initial session
      this._sessionManager.createSession();
      const session = this._sessionManager.getActiveSession()!;
      this._store = session.store;
      this._mapping = session.mapping;
      this._subnetMapper = session.subnetMapper;
      if (session.canary) this._canary = session.canary;
    }

    // --- Active monitoring ---
    if (config.monitorEnabled ?? false) {
      this._monitor = new AlertPipeline({
        enabled: true,
        rateWindowMs: config.monitorRateWindowMs,
        spikeMultiplier: config.monitorSpikeMultiplier,
        maxAlerts: config.monitorMaxAlerts,
        onAlert: (alert) => this._onMonitorAlert(alert),
      });
    }
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

    // Wrap with ContextDetector for confidence boosting, proximity,
    // hostname propagation, learned entities, and frequency decay
    this._contextDetector = new ContextDetector(regexDetector);
    this._detectors.push(this._contextDetector);

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
    //    Track filter reasons for FilterStats (QW8)
    //    QW1: Split allowlist into exact matches (fast set) and wildcard patterns
    const allowExact = new Set<string>();
    const allowWild: string[] = [];
    for (const a of this.config.allowlist) {
      if (a.includes("*") || a.includes("?")) allowWild.push(a);
      else allowExact.add(a);
    }
    let belowThreshold = 0;
    let allowlisted = 0;
    let alreadyObfuscated = 0;
    const filtered = entities.filter((e) => {
      if (e.confidence < this.config.minConfidence) { belowThreshold++; return false; }
      // QW1: Exact allowlist + wildcard patterns
      if (allowExact.has(e.value) || allowWild.some((p) => wildcardMatch(e.value, p))) {
        allowlisted++; return false;
      }
      // Feature 7: Policy allowlist
      if (
        this._policyRules &&
        PolicyLoader.isAllowed(e.value, this._policyRules.allowlist)
      ) {
        allowlisted++;
        return false;
      }
      // Prevent double-obfuscation: skip values that are already known fakes
      if (this._store.getReal(e.value) !== undefined) { alreadyObfuscated++; return false; }
      return true;
    });

    // QW2: Accumulate per-category detection counts (all entities before filter)
    for (const entity of entities) {
      const cat = entity.category;
      this._detectionsByCategory.set(cat, (this._detectionsByCategory.get(cat) ?? 0) + 1);
    }

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

    // Active monitoring: feed detection data
    if (this._monitor && filtered.length > 0) {
      const cats = filtered.map((e) => e.category);
      this._monitor.recordDetection(filtered.length, cats);
      // Forward exposure breaches to monitor
      for (const alert of exposureAlerts) {
        this._monitor.recordExposureBreach(
          alert.category ?? "global",
          alert.count ?? 0,
          alert.threshold ?? 0,
        );
      }
    }

    // Determine redaction level (context-specific or global)
    const level: RedactionLevel = this.config.redactionLevel;
    this._redactionFormatter.resetCounters();

    // 6. Map and replace (process right-to-left to preserve positions)
    //    QW6: In dry-run mode, compute mappings but skip text replacement.
    let resultText = text;
    const mappingsUsed: Record<string, string> = {};

    if (!this.config.dryRun) {
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

        // QW2: per-category replacement count
        this._replacementsByCategory.set(
          entity.category,
          (this._replacementsByCategory.get(entity.category) ?? 0) + 1,
        );
      }
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

    // QW8: Build filter stats
    const filterStats: FilterStats = {
      totalDetected: entities.length,
      replaced: filtered.length,
      belowThreshold,
      allowlisted,
      docExamples: 0, // doc examples are filtered inside detectors before reaching here
      alreadyObfuscated,
    };

    return {
      original: text,
      obfuscated: resultText,
      entities: filtered,
      mappingsUsed,
      complianceReport,
      filterStats,
    };
  }

  /**
   * Reverse-map fake values back to real values in text.
   *
   * Uses longest-match-first replacement to avoid partial substitutions.
   * Also strips canary tokens and provenance tags.
   * Runs multiple passes (#8 recursive deobfuscation) for nested structures.
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

    const fakes = [...reverse.keys()].sort((a, b) => b.length - a.length);

    // #8: Recursive deobfuscation — multiple passes for nested structures
    let result = text;
    let totalReplacements = 0;
    const MAX_PASSES = 3;

    // Collect known fakes that were NOT replaced (for residual pass)
    const knownFakeSet = new Set(fakes);

    for (let pass = 0; pass < MAX_PASSES; pass++) {
      let passReplacements = 0;
      for (const fake of fakes) {
        const real = reverse.get(fake)!;
        const parts = result.split(fake);
        if (parts.length > 1) {
          passReplacements += parts.length - 1;
          result = parts.join(real);
          knownFakeSet.delete(fake); // successfully replaced
        }
      }
      totalReplacements += passReplacements;
      if (passReplacements === 0) break; // No more replacements possible
    }

    // Subnet-aware deobfuscation: reverse-map CGNAT IPs the LLM derived
    // (e.g. network addresses computed from fake host IPs + masks)
    const residual = this._deobfuscateResidualCgnat(result, knownFakeSet);
    if (residual.count > 0) {
      result = residual.text;
      totalReplacements += residual.count;
    }

    // IPv6 ULA residual deobfuscation (compressed forms, /64 prefixes)
    const residualV6 = this._deobfuscateResidualUla(result, reverse);
    if (residualV6.count > 0) {
      result = residualV6.text;
      totalReplacements += residualV6.count;
    }

    // Audit log
    if (this._audit && totalReplacements > 0) {
      const elapsed = Date.now() - startTime;
      this._audit.logDeobfuscation(totalReplacements, undefined, elapsed);
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

    const fakes = [...reverse.keys()].sort((a, b) => b.length - a.length);

    // #8: Recursive deobfuscation
    let result = text;
    let replacementCount = 0;
    const MAX_PASSES = 3;
    const knownFakeSet = new Set(fakes);

    for (let pass = 0; pass < MAX_PASSES; pass++) {
      let passReplacements = 0;
      for (const fake of fakes) {
        const real = reverse.get(fake)!;
        const parts = result.split(fake);
        if (parts.length > 1) {
          passReplacements += parts.length - 1;
          result = parts.join(real);
          knownFakeSet.delete(fake);
        }
      }
      replacementCount += passReplacements;
      if (passReplacements === 0) break;
    }

    // Subnet-aware deobfuscation for LLM-derived CGNAT IPs
    const residual = this._deobfuscateResidualCgnat(result, knownFakeSet);
    if (residual.count > 0) {
      result = residual.text;
      replacementCount += residual.count;
    }

    // IPv6 ULA residual deobfuscation
    const residualV6 = this._deobfuscateResidualUla(result, reverse);
    if (residualV6.count > 0) {
      result = residualV6.text;
      replacementCount += residualV6.count;
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
    const activeKey = this._keyRing.activeKey().key;
    const key = scryptSync(activeKey, "shroud-session", 32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString("base64");
  }

  private _decrypt(blob: string): string {
    const buf = Buffer.from(blob, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);

    // Try all keys in the ring (active first, then others)
    const keysToTry = this._keyRing.allKeys();
    // Put active key first
    const activeVersion = this._keyRing.activeVersion;
    keysToTry.sort((a, b) =>
      a.version === activeVersion ? -1 : b.version === activeVersion ? 1 : 0,
    );

    for (const vk of keysToTry) {
      try {
        const key = scryptSync(vk.key, "shroud-session", 32);
        const decipher = createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(tag);
        return decipher.update(enc) + decipher.final("utf-8");
      } catch {
        // Wrong key — try next
        continue;
      }
    }
    throw new Error("Failed to decrypt session blob — no matching key found");
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

  /**
   * Subnet-aware reverse mapping for CGNAT IPs not in the store.
   *
   * When the LLM computes derived addresses (e.g. network address from
   * a host IP + mask), those derived fakes won't be in the mapping store.
   * This method uses SubnetMapper's reverse map to find the real subnet
   * and compute the correct real IP.
   *
   * Returns the number of additional replacements made.
   */
  private _deobfuscateResidualCgnat(text: string, knownFakes: Set<string>): { text: string; count: number } {
    const mapper = this._subnetMapper;
    if (mapper.subnetRev.size === 0) return { text, count: 0 };

    let count = 0;
    const result = text.replace(CGNAT_IP_RE, (match) => {
      // Skip if this IP was already deobfuscated via the store
      if (knownFakes.has(match)) return match;

      try {
        const fakeInt = ipToInt(match);

        // Check if this IP is in CGNAT range
        if ((fakeInt & CGNAT_MASK_10) !== CGNAT_BASE) return match;

        // Try each known fake subnet to find which one this IP belongs to
        for (const [fakeNetInt, key] of mapper.subnetRev) {
          const [realNetStr, prefixLenStr] = key.split(",");
          const prefixLen = parseInt(prefixLenStr, 10);
          const mask = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);

          // Check if this fake IP is in this fake subnet
          if (((fakeInt & mask) >>> 0) === fakeNetInt) {
            const hostBits = (fakeInt & (~mask >>> 0)) >>> 0;
            const realNetInt = parseInt(realNetStr, 10);
            const realIp = intToIp((realNetInt | hostBits) >>> 0);
            count++;
            return realIp;
          }
        }
      } catch {
        // skip invalid
      }
      return match;
    });

    return { text: result, count };
  }

  /**
   * Normalize-and-match deobfuscation for fd00::/8 ULA IPv6 addresses.
   *
   * Shroud generates full 8-group IPv6 fakes (fd00:xxxx:xxxx:...). But the
   * LLM may compress them (fd00:a1b2::1), extract /64 prefixes, or
   * otherwise derive new forms. This method expands any ULA IPv6 found in
   * the text to full form and checks against the mapping store.
   */
  private _deobfuscateResidualUla(text: string, reverse: Map<string, string>): { text: string; count: number } {
    // Build expanded-form lookup from existing reverse map
    const expandedReverse = new Map<string, string>();
    for (const [fake, real] of reverse) {
      if (fake.includes(":") && fake.toLowerCase().startsWith("fd00")) {
        expandedReverse.set(expandIPv6(fake), real);
      }
    }
    if (expandedReverse.size === 0) return { text, count: 0 };

    let count = 0;
    const result = text.replace(ULA_IPV6_RE, (match) => {
      // Try exact match first (already handled by normal pass, but just in case)
      if (reverse.has(match)) return match;

      try {
        const expanded = expandIPv6(match);
        const real = expandedReverse.get(expanded);
        if (real) {
          count++;
          return real;
        }

        // Try prefix match: if LLM wrote "fd00:a1b2:c3d4:e5f6::/64",
        // find any fake that shares the same prefix
        // (This handles /64 subnet prefix extraction by the LLM)
        for (const [expandedFake, realVal] of expandedReverse) {
          // Check if the residual is a prefix of a known fake (or vice versa)
          // by comparing the first N groups
          const matchGroups = expanded.split(":");
          const fakeGroups = expandedFake.split(":");
          let commonLen = 0;
          for (let i = 0; i < 8; i++) {
            if (matchGroups[i] === fakeGroups[i]) commonLen++;
            else break;
          }
          // If at least 4 groups match (a /64) and the remaining groups in
          // the match are all zeros, it's a prefix extraction
          if (commonLen >= 4) {
            const trailingZeros = matchGroups.slice(commonLen).every((g) => g === "0000");
            if (trailingZeros) {
              // Reconstruct real IP with same zero pattern
              const realExpanded = expandIPv6(realVal);
              const realGroups = realExpanded.split(":");
              const reconstructed = [
                ...realGroups.slice(0, commonLen),
                ...matchGroups.slice(commonLen),
              ].join(":");
              // Compress back to readable form
              count++;
              return compressIPv6(reconstructed);
            }
          }
        }
      } catch {
        // skip invalid
      }
      return match;
    });

    return { text: result, count };
  }

  // -------------------------------------------------------------------------
  // Key rotation
  // -------------------------------------------------------------------------

  /** Rotate to a new key. Existing mappings remain valid in the store. */
  rotateKey(newKey: string, expiresAt?: string): VersionedKey {
    const oldVersion = this._keyRing.activeVersion;
    const vk = this._keyRing.addKey(newKey, expiresAt);

    // New mapping engine for new obfuscations
    this._mapping = new MappingEngine(
      vk.key,
      this.config.persistentSalt || undefined,
      this._subnetMapper,
      this.config.tenantId || undefined,
    );

    // SIEM event
    if (this._siemSink) {
      this._siemSink.emit(SiemEventBuilder.keyRotation(
        this.config.tenantId || "default",
        this._audit?.["_sessionId"] ?? "",
        { oldVersion, newVersion: vk.version, totalKeys: this._keyRing.size },
      ));
    }

    return vk;
  }

  /** Get key ring info for status reporting. */
  getKeyInfo(): { active: number; versions: number[]; expired: number[]; retired: number[] } {
    const allRaw = this._keyRing.allKeysRaw();
    const active = this._keyRing.activeVersion;
    const versions = allRaw.map((k) => k.version);
    const expired = allRaw
      .filter((k) => k.expiresAt && new Date(k.expiresAt).getTime() <= Date.now())
      .map((k) => k.version);
    const retired = allRaw.filter((k) => k.retired).map((k) => k.version);
    return { active, versions, expired, retired };
  }

  /** Access the key ring directly. */
  get keyRing(): KeyRing {
    return this._keyRing;
  }

  // -------------------------------------------------------------------------
  // SIEM sink
  // -------------------------------------------------------------------------

  /** Access the SIEM sink for emitting events from hooks. */
  get siemSink(): WebhookSink | null {
    return this._siemSink;
  }

  /** Emit a SIEM event (convenience method). */
  emitSiemEvent(event: SiemEvent): void {
    this._siemSink?.emit(event);
  }

  /** Shutdown: flush SIEM sink and stop hot-reload watcher. */
  async shutdown(): Promise<void> {
    if (this._siemSink) await this._siemSink.destroy();
    if (this._reloader) this._reloader.stop();
  }

  // -------------------------------------------------------------------------
  // Hot-reload
  // -------------------------------------------------------------------------

  /** Access the hot-reload controller. */
  get reloader(): DetectorReloader | null {
    return this._reloader;
  }

  /** Handle hot-reload callback. */
  private _onHotReload(what: "policy" | "customPatterns" | "detectorOverrides", data?: unknown): void {
    if (what === "policy" && data) {
      try {
        this._policyRules = data as PolicyRules;
      } catch {
        console.warn("[shroud][hot-reload] Failed to apply new policy rules");
      }
    } else if (what === "customPatterns" && data) {
      try {
        const patterns = data as Array<{ name: string; pattern: string; category?: string }>;
        // Remove old custom pattern detector and add new one
        this._detectors = this._detectors.filter((d) => !(d instanceof CustomPatternDetector));
        if (patterns.length > 0) {
          this._detectors.push(new CustomPatternDetector(patterns));
        }
      } catch {
        console.warn("[shroud][hot-reload] Failed to apply new custom patterns");
      }
    } else if (what === "detectorOverrides" && data) {
      try {
        const overrides = data as Record<string, { enabled?: boolean; confidence?: number }>;
        // Re-initialize detectors with new overrides
        this._detectors = [];
        const regexDetector = new RegexDetector(undefined, overrides);
        this._contextDetector = new ContextDetector(regexDetector);
        this._detectors.push(this._contextDetector);
        if (this.config.customPatterns.length > 0) {
          this._detectors.push(new CustomPatternDetector(this.config.customPatterns));
        }
        this._detectors.push(new CodeDetector(regexDetector));
      } catch {
        console.warn("[shroud][hot-reload] Failed to apply detector overrides");
      }
    }
  }

  // -------------------------------------------------------------------------
  // Per-session isolation
  // -------------------------------------------------------------------------

  /** Access the session manager (null if session isolation is disabled). */
  get sessionManager(): SessionManager | null {
    return this._sessionManager;
  }

  /** Create a new isolated session and switch to it. */
  createSession(sessionId?: string): string {
    if (!this._sessionManager) {
      throw new Error("Session isolation is not enabled. Set sessionIsolation: true in config.");
    }
    const id = this._sessionManager.createSession(sessionId);
    const session = this._sessionManager.getActiveSession()!;
    this._store = session.store;
    this._mapping = session.mapping;
    this._subnetMapper = session.subnetMapper;
    if (session.canary) this._canary = session.canary;
    return id;
  }

  /** Switch to an existing session. */
  switchSession(sessionId: string): void {
    if (!this._sessionManager) {
      throw new Error("Session isolation is not enabled.");
    }
    this._sessionManager.switchSession(sessionId);
    const session = this._sessionManager.getActiveSession()!;
    this._store = session.store;
    this._mapping = session.mapping;
    this._subnetMapper = session.subnetMapper;
    if (session.canary) this._canary = session.canary;
  }

  /** Destroy a session and its data. */
  destroySession(sessionId: string): void {
    if (!this._sessionManager) return;
    this._sessionManager.destroySession(sessionId);
  }

  // -------------------------------------------------------------------------
  // Active monitoring
  // -------------------------------------------------------------------------

  /** Access the monitor pipeline (null if monitoring is disabled). */
  get monitor(): AlertPipeline | null {
    return this._monitor;
  }

  /** Handle monitor alert callback — forward to SIEM sink. */
  private _onMonitorAlert(alert: MonitorAlert): void {
    if (this._siemSink) {
      this._siemSink.emit(SiemEventBuilder.monitorAlert(
        this.config.tenantId || "default",
        this._audit?.["_sessionId"] ?? "",
        {
          alertType: alert.alertType,
          message: alert.message,
          details: alert.details,
        },
      ));
    }
  }

  /** Clear all mappings and start fresh. */
  reset(): void {
    this._store.clear();
    this._subnetMapper.reset();
    this._ruleHits.clear();
    this._detectionsByCategory.clear();
    this._replacementsByCategory.clear();
    this._toolDepth = 0;
    if (this._exposureTracker) this._exposureTracker.reset();
    if (this._contextDetector) this._contextDetector.reset();
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
      detectionsByCategory: Object.fromEntries(this._detectionsByCategory),
      replacementsByCategory: Object.fromEntries(this._replacementsByCategory),
      // Enterprise
      tenantId: this.config.tenantId || null,
      toolDepth: this._toolDepth,
      redactionLevel: this.config.redactionLevel,
      provenanceTagging: this.config.provenanceTagging,
      sharedStore: !!this.config.sharedStorePath,
      sessionHandoff: this.config.sessionHandoff,
      learnedEntities: this._contextDetector?.learnedCount ?? 0,
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

    // Key rotation info
    stats.keyRotation = this.getKeyInfo();

    // SIEM sink stats
    if (this._siemSink) {
      stats.siem = this._siemSink.getStats();
    }

    // Hot-reload info
    if (this._reloader) {
      stats.hotReload = {
        watching: this._reloader.isWatching,
        reloadCount: this._reloader.reloadCount,
      };
    }

    // Session isolation info
    if (this._sessionManager) {
      stats.sessions = {
        active: this._sessionManager.activeSessionId,
        count: this._sessionManager.sessionCount,
        list: this._sessionManager.listSessions(),
      };
    }

    // Active monitoring stats
    if (this._monitor) {
      stats.monitor = this._monitor.getStats();
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
