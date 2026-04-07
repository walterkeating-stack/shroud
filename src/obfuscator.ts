/**
 * Core obfuscation engine: detect -> map -> replace / reverse-replace.
 *
 * Entirely synchronous (CPU-bound) -- this is important for the
 * tool_result_persist hook which is sync-only.
 */

import {
  Category,
  DetectedEntity,
  FilterStats,
  ObfuscationResult,
  ShroudConfig,
} from "./types.js";
import { MemoryStore, MappingStore } from "./store.js";
import { MappingEngine } from "./mapping.js";
import { SubnetMapper, CGNAT_BASE, CGNAT_MASK_10, ipToInt, intToIp } from "./generators/network.js";
import { CanaryInjector } from "./canary.js";
import { AuditLogger } from "./audit.js";
import { BaseDetector } from "./detectors/base.js";
import { RegexDetector } from "./detectors/regex.js";
import { CustomPatternDetector } from "./detectors/patterns.js";
import { CodeDetector } from "./detectors/code.js";
import { ContextDetector } from "./detectors/context.js";
import { RedactionFormatter, RedactionLevel } from "./redaction.js";

/** Regex to find CGNAT IPs (100.64.0.0/10) in text. */
const CGNAT_IP_RE = /\b(100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b/g;

/**
 * Regex to find CGNAT range descriptions that LLMs generate when summarizing
 * fake networks. Catches patterns like:
 *   - "100.64.x.x/xx" or "100.64.0.x/24"
 *   - "100.64.x.x space" or "within 100.64.x.x"
 *   - "100.64.0.0/10" (the CGNAT range itself)
 *   - "100.64.x.x" (wildcard notation)
 */
// Match CGNAT range descriptions including:
// - Full IPs with wildcards: "100.64.x.x/xx", "100.64.9.x/32"
// - Hyphenated ranges: "100.64.16-19.0/24", "100.64.0-3.0"
// - Short 3-octet forms: "100.64.8-14", "100.64.9"
// - Prose references: "100.64.x.x space", "100.64.8-11"
const CGNAT_RANGE_DESC_RE = /(?<!\d\.)(?<!\d)\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.[\dx]+(?:-[\dx]+)?(?:\.[\dx]+(?:-[\dx]+)?)?)?(?:\/[\dx]+(?:-[\dx]+)?)?\b/gi;

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
 * Strip Slack/chat mrkdwn link formatting to recover plain text.
 * Slack wraps emails as `<mailto:X|DISPLAY>` and URLs as `<URL|DISPLAY>`,
 * which splits entities across tag boundaries and breaks regex detection.
 * This converts display-text links back to their visible form.
 */
function stripSlackLinks(text: string): string {
  // <mailto:X|DISPLAY> → DISPLAY  (email links)
  text = text.replace(/<mailto:[^|>]+\|([^>]*)>/g, "$1");
  // <URL|DISPLAY> → URL           (preserve real URL for passthrough checks)
  text = text.replace(/<(https?:\/\/[^|>]+)\|[^>]*>/g, "$1");
  // <URL> → URL                    (bare URL links, no display text)
  text = text.replace(/<(https?:\/\/[^>]+)>/g, "$1");
  return text;
}

/**
 * Build a single combined regex from an array of literal strings.
 * Strings are escaped and joined with alternation (|), sorted longest-first
 * so the regex engine matches greedily. Returns null for empty arrays.
 */
function buildCombinedFakeRegex(fakes: string[]): RegExp | null {
  if (fakes.length === 0) return null;
  const escaped = fakes.map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(escaped.join("|"), "g");
}

/**
 * Multi-pass deobfuscation that protects already-replaced regions.
 *
 * Uses placeholder sentinels: each replacement is temporarily stored as a
 * unique placeholder (U+FFFF-based) that cannot match any fake value regex.
 * After all passes complete, placeholders are swapped back to their real
 * values. This prevents cascading replacements when a real value contains
 * a substring that is also a fake value (e.g., fake "ACL-MGMT" maps to
 * real "ACL-MGMT-FILTER" — without protection, later passes would find
 * "ACL-MGMT" inside the restored value and replace it again).
 */
function multiPassDeobfuscate(
  text: string,
  combinedRe: RegExp | null,
  reverse: Map<string, string>,
  knownFakeSet: Set<string>,
  maxPasses: number,
): { text: string; replacements: number } {
  if (!combinedRe) return { text, replacements: 0 };

  let result = text;
  let totalReplacements = 0;

  // Map placeholder ID -> real value.  Placeholders use \uFFFF + index
  // which cannot appear in fake values (they are printable ASCII).
  const placeholders: string[] = [];

  for (let pass = 0; pass < maxPasses; pass++) {
    let passReplacements = 0;
    combinedRe.lastIndex = 0;
    result = result.replace(combinedRe, (match) => {
      const real = reverse.get(match);
      if (real !== undefined) {
        passReplacements++;
        knownFakeSet.delete(match);
        // Store real value behind a placeholder to protect it from
        // subsequent passes matching substrings within it.
        const idx = placeholders.length;
        placeholders.push(real);
        return `\uFFFF${idx}\uFFFF`;
      }
      return match;
    });
    totalReplacements += passReplacements;
    if (passReplacements === 0) break;
  }

  // Swap placeholders back to real values
  if (placeholders.length > 0) {
    result = result.replace(/\uFFFF(\d+)\uFFFF/g, (_m, idxStr) => {
      return placeholders[parseInt(idxStr, 10)] ?? _m;
    });
  }

  return { text: result, replacements: totalReplacements };
}

/**
 * Convert a simple wildcard pattern (* and ?) to a RegExp.
 * Caches compiled patterns for reuse. Bounded to 500 entries.
 */
const MAX_WILDCARD_CACHE = 500;
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
    // Evict oldest entries if cache is full
    if (_wildcardCache.size >= MAX_WILDCARD_CACHE) {
      const firstKey = _wildcardCache.keys().next().value;
      if (firstKey !== undefined) _wildcardCache.delete(firstKey);
    }
    _wildcardCache.set(pattern, re);
  }
  return re.test(value);
}

export class Obfuscator {
  readonly config: ShroudConfig;

  private _store: MappingStore;
  private _subnetMapper: SubnetMapper;
  private _mapping: MappingEngine;
  private _detectors: BaseDetector[];
  private _canary: CanaryInjector | null;
  private _audit: AuditLogger | null;
  private _ruleHits: Map<string, number> = new Map();
  private _detectionsByCategory: Map<string, number> = new Map();
  private _replacementsByCategory: Map<string, number> = new Map();
  private _obfuscationEvents = 0;
  private _deobfuscationEvents = 0;
  private _totalEntitiesObfuscated = 0;
  private _totalReplacementsDeobfuscated = 0;
  private _redactionFormatter: RedactionFormatter;
  private _contextDetector: ContextDetector | null = null;
  private _toolDepth: number = 0;

  constructor(config: ShroudConfig) {
    this.config = config;

    this._store = new MemoryStore(config.maxStoreMappings);

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

    // Redaction formatter
    this._redactionFormatter = new RedactionFormatter();

    this._initDetectors();
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

  /** Track tool call depth. */
  enterToolCall(): number {
    return ++this._toolDepth;
  }

  /** Decrement tool depth. */
  exitToolCall(): number {
    return Math.max(0, --this._toolDepth);
  }

  /** Current tool depth. */
  get toolDepth(): number {
    return this._toolDepth;
  }

  /** Reset tool depth counter (called at the start of each LLM turn). */
  resetToolDepth(): void {
    this._toolDepth = 0;
  }

  /**
   * Detect and replace all sensitive entities in text.
   *
   * The pipeline:
   * 1. Learn subnets from text (via SubnetMapper)
   * 2. Detect entities from all detectors
   * 3. Apply denylist (force-add denylist values)
   * 4. Sort by position, resolve overlaps (prefer higher confidence)
   * 5. Filter by minConfidence, allowlist, and already-obfuscated
   * 6. Map and replace (with redaction level)
   * 7. Inject canary if enabled
   */
  obfuscate(text: string, context?: string): ObfuscationResult {
    const startTime = Date.now();

    // 0. Strip Slack/chat mrkdwn link formatting so detection sees clean text.
    //    Slack wraps emails as <mailto:X|DISPLAY> and URLs as <URL|DISPLAY>,
    //    which splits entities across tag boundaries and breaks regex matching.
    text = stripSlackLinks(text);

    // 1. Learn subnet context from CIDR notation and masks in text
    this._subnetMapper.learnSubnetsFromText(text);

    // 2. Detect all entities from all detectors
    const allEntities: DetectedEntity[] = [];
    for (const detector of this._detectors) {
      allEntities.push(...detector.detect(text));
    }

    // 3. Apply denylist -- single-pass combined regex instead of per-entry indexOf
    if (this.config.denylist.length > 0) {
      const sorted = this.config.denylist.slice().sort((a, b) => b.length - a.length);
      const escaped = sorted.map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      const denyRe = new RegExp(escaped.join("|"), "g");
      let dm: RegExpExecArray | null;
      while ((dm = denyRe.exec(text)) !== null) {
        allEntities.push({
          value: dm[0],
          start: dm.index,
          end: dm.index + dm[0].length,
          category: Category.CUSTOM,
          confidence: 1.0,
          detector: "denylist",
        });
      }
    }

    // 4. Sort by position and resolve overlaps (prefer higher confidence, then earlier)
    allEntities.sort((a, b) => a.start - b.start || b.confidence - a.confidence);
    const entities = resolveOverlaps(allEntities);

    // 5. Filter by confidence threshold, allowlist, and already-obfuscated values
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
      if (allowExact.has(e.value) || allowWild.some((p) => wildcardMatch(e.value, p))) {
        allowlisted++; return false;
      }
      // Prevent double-obfuscation: skip values that are already known fakes
      if (this._store.getReal(e.value) !== undefined) { alreadyObfuscated++; return false; }
      // Safety net: never store very short values (1-2 chars) as they cause
      // catastrophic false-positive replacements during deobfuscation.
      // IPs, emails, hostnames etc. are always longer than 2 chars.
      if (e.value.length <= 2) return false;
      return true;
    });

    // Accumulate per-category detection counts (all entities before filter)
    for (const entity of entities) {
      const cat = entity.category;
      this._detectionsByCategory.set(cat, (this._detectionsByCategory.get(cat) ?? 0) + 1);
    }

    // Accumulate per-rule hit counts
    for (const entity of filtered) {
      this._ruleHits.set(
        entity.detector,
        (this._ruleHits.get(entity.detector) ?? 0) + 1,
      );
    }

    // Determine redaction level
    const level: RedactionLevel = this.config.redactionLevel;
    this._redactionFormatter.resetCounters();

    // 6. Map and replace using segment collection (single-pass, no repeated slicing).
    //    In dry-run mode, compute mappings but skip text replacement.
    let resultText = text;
    const mappingsUsed: Record<string, string> = {};

    if (!this.config.dryRun && filtered.length > 0) {
      // Collect text segments and replacements in one forward pass
      const segments: string[] = [];
      let cursor = 0;

      for (const entity of filtered) {
        // Append text before this entity
        if (entity.start > cursor) {
          segments.push(text.slice(cursor, entity.start));
        }

        // Check if we already have a mapping for this exact value
        let fake = this._store.getFake(entity.value);
        if (!fake) {
          let newFake = this._mapping.mapValue(entity.value, entity.category);
          // Collision avoidance: if this fake is already mapped to a different
          // real value, offset the fake to make it unique. This happens when
          // subnet-preserving IP mapping allocates the same CGNAT address for
          // two different real IPs with identical host bits in different subnets.
          let collisionAttempt = 0;
          let existingReal = this._store.getReal(newFake);
          while ((newFake === entity.value ||
                 (existingReal !== undefined && existingReal !== entity.value)) &&
                 collisionAttempt < 50) {
            collisionAttempt++;
            // For IPs: offset the last octet; for others: append suffix
            if (entity.category === "ip_address" && /^\d+\.\d+\.\d+\.\d+$/.test(newFake)) {
              const parts = newFake.split(".");
              parts[3] = String((parseInt(parts[3], 10) + 1) % 256);
              newFake = parts.join(".");
            } else {
              newFake = this._mapping.mapValue(
                entity.value + `\x00${collisionAttempt}`, entity.category,
              );
            }
            existingReal = this._store.getReal(newFake);
          }
          fake = newFake;
          this._store.put(entity.value, fake, entity.category);
        }

        const fakeValue = fake;
        const replacement = this._redactionFormatter.format(
          entity.value,
          fakeValue,
          entity.category,
          level,
        );

        segments.push(replacement);
        mappingsUsed[entity.value] = fakeValue;
        cursor = entity.end;

        // Per-category replacement count
        this._replacementsByCategory.set(
          entity.category,
          (this._replacementsByCategory.get(entity.category) ?? 0) + 1,
        );
      }

      // Append trailing text
      if (cursor < text.length) {
        segments.push(text.slice(cursor));
      }
      resultText = segments.join("");
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

    // Build filter stats
    const filterStats: FilterStats = {
      totalDetected: entities.length,
      replaced: filtered.length,
      belowThreshold,
      allowlisted,
      docExamples: 0, // doc examples are filtered inside detectors before reaching here
      alreadyObfuscated,
    };

    this._obfuscationEvents++;
    this._totalEntitiesObfuscated += filtered.length;

    return {
      original: text,
      obfuscated: resultText,
      entities: filtered,
      mappingsUsed,
      filterStats,
    };
  }

  /**
   * Reverse-map fake values back to real values in text.
   *
   * Uses longest-match-first replacement to avoid partial substitutions.
   * Also strips canary tokens.
   * Runs multiple passes for nested structures.
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

    // Build a single combined regex for all fakes (longest-match-first).
    const fakes = [...reverse.keys()].sort((a, b) => b.length - a.length);

    // Collect known fakes that were NOT replaced (for residual pass)
    const knownFakeSet = new Set(fakes);

    // Build combined regex: escape each fake, join with alternation
    const combinedRe = buildCombinedFakeRegex(fakes);

    // Multi-pass deobfuscation with protection against cascading replacements
    const MAX_PASSES = 3;
    const deobResult = multiPassDeobfuscate(text, combinedRe, reverse, knownFakeSet, MAX_PASSES);
    let result = deobResult.text;
    let totalReplacements = deobResult.replacements;

    // Subnet-aware deobfuscation: reverse-map CGNAT IPs the LLM derived
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

    // CGNAT range description cleanup: catch LLM-generated summaries like
    // "100.64.x.x/xx" or "100.64.0.x/24" that indicate the LLM learned
    // Shroud's fake range and is describing it generically.
    const rangeCleanup = this._deobfuscateCgnatRangeDescriptions(result);
    if (rangeCleanup.count > 0) {
      result = rangeCleanup.text;
      totalReplacements += rangeCleanup.count;
    }

    if (totalReplacements > 0) {
      this._deobfuscationEvents++;
      this._totalReplacementsDeobfuscated += totalReplacements;
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

    const allMappings = this._store.allMappings();
    if (allMappings.size === 0) return { text, replacementCount: 0 };

    const reverse = new Map<string, string>();
    for (const [real, fake] of allMappings) {
      reverse.set(fake, real);
    }

    const fakes = [...reverse.keys()].sort((a, b) => b.length - a.length);
    const knownFakeSet = new Set(fakes);
    const combinedRe = buildCombinedFakeRegex(fakes);

    // Multi-pass deobfuscation with protection against cascading replacements
    const MAX_PASSES = 3;
    const deobResult = multiPassDeobfuscate(text, combinedRe, reverse, knownFakeSet, MAX_PASSES);
    let result = deobResult.text;
    let replacementCount = deobResult.replacements;

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

    // CGNAT range description cleanup (same as in deobfuscate)
    const rangeCleanup = this._deobfuscateCgnatRangeDescriptions(result);
    if (rangeCleanup.count > 0) {
      result = rangeCleanup.text;
      replacementCount += rangeCleanup.count;
    }

    if (replacementCount > 0) {
      this._deobfuscationEvents++;
      this._totalReplacementsDeobfuscated += replacementCount;
    }

    if (this._audit && replacementCount > 0) {
      const elapsed = Date.now() - startTime;
      this._audit.logDeobfuscation(replacementCount, undefined, elapsed);
    }

    return { text: result, replacementCount };
  }

  /**
   * Subnet-aware reverse mapping for CGNAT IPs not in the store.
   */
  private _deobfuscateResidualCgnat(text: string, knownFakes: Set<string>): { text: string; count: number } {
    const mapper = this._subnetMapper;
    if (mapper.subnetRev.size === 0) return { text, count: 0 };

    let count = 0;
    const result = text.replace(CGNAT_IP_RE, (match) => {
      // Skip if this IP was already deobfuscated via the store
      if (knownFakes.has(match)) return match;

      try {
        // Validate all octets are 0-255 before processing
        const octets = match.split(".").map(s => parseInt(s, 10));
        if (octets.some(o => o > 255 || o < 0 || isNaN(o))) return match;

        const fakeInt = ipToInt(match);

        // Check if this IP is in CGNAT range
        if ((fakeInt & CGNAT_MASK_10) !== CGNAT_BASE) return match;

        // Try each known fake subnet — use longest-prefix match to avoid
        // broader subnets incorrectly claiming IPs from narrower ones.
        let bestMatch: { realIp: string; prefixLen: number } | null = null;
        for (const [fakeNetInt, key] of mapper.subnetRev) {
          const [realNetStr, prefixLenStr] = key.split(",");
          const prefixLen = parseInt(prefixLenStr, 10);
          const mask = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);

          // Check if this fake IP is in this fake subnet
          if (((fakeInt & mask) >>> 0) === fakeNetInt) {
            if (!bestMatch || prefixLen > bestMatch.prefixLen) {
              const hostBits = (fakeInt & (~mask >>> 0)) >>> 0;
              const realNetInt = parseInt(realNetStr, 10);
              const combined = (realNetInt | hostBits) >>> 0;
              // Validate: all octets must be 0-255
              const o1 = (combined >>> 24) & 0xff;
              const o2 = (combined >>> 16) & 0xff;
              const o3 = (combined >>> 8) & 0xff;
              const o4 = combined & 0xff;
              if (o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255) {
                bestMatch = { realIp: `${o1}.${o2}.${o3}.${o4}`, prefixLen };
              }
            }
          }
        }
        if (bestMatch) {
          count++;
          return bestMatch.realIp;
        }
      } catch {
        // skip invalid
      }
      return match;
    });

    return { text: result, count };
  }

  /**
   * Clean up CGNAT range descriptions that LLMs generate when summarizing
   * fake networks. The LLM sees multiple 100.64.x.y addresses and writes
   * summaries like "100.64.x.x/xx" or "within 100.64.x.x space".
   *
   * Strategy: find the most common real network prefix from the store
   * mappings and replace CGNAT range descriptions with the real prefix.
   */
  private _deobfuscateCgnatRangeDescriptions(text: string): { text: string; count: number } {
    const mapper = this._subnetMapper;
    if (mapper.subnetRev.size === 0) return { text, count: 0 };

    // Find the most common real network prefix to use as replacement
    // Build a map of real network prefixes and their frequency
    const realPrefixCounts = new Map<string, number>();
    for (const [, key] of mapper.subnetRev) {
      const [realNetStr, prefixLenStr] = key.split(",");
      const realNetInt = parseInt(realNetStr, 10);
      const prefixLen = parseInt(prefixLenStr, 10);
      const realIp = intToIp(realNetInt);
      // Extract first two octets as the prefix
      const prefix = realIp.split(".").slice(0, 2).join(".");
      realPrefixCounts.set(prefix, (realPrefixCounts.get(prefix) ?? 0) + 1);
    }

    if (realPrefixCounts.size === 0) return { text, count: 0 };

    // Find the most common real prefix
    let bestPrefix = "10.0";
    let bestCount = 0;
    for (const [prefix, count] of realPrefixCounts) {
      if (count > bestCount) {
        bestPrefix = prefix;
        bestCount = count;
      }
    }

    // Build mapping: full fake network IP → {realIp, prefixLen}
    // Key on the full IP (not just 2 octets) to avoid collisions — all
    // CGNAT subnets start with 100.64, so 2-octet keys overwrite each other.
    const fakeToRealMap = new Map<string, { realIp: string; prefixLen: number }>();
    let mostCommonPrefixLen = 24;
    const prefixLenCounts = new Map<number, number>();
    for (const [fakeNetInt, key] of mapper.subnetRev) {
      const fakeIp = intToIp(fakeNetInt);
      const [realNetStr, prefixLenStr] = key.split(",");
      const realIp = intToIp(parseInt(realNetStr, 10));
      const prefixLen = parseInt(prefixLenStr, 10);
      fakeToRealMap.set(fakeIp, { realIp, prefixLen });
      prefixLenCounts.set(prefixLen, (prefixLenCounts.get(prefixLen) ?? 0) + 1);
    }

    // Find most common prefix length
    let bestPrefixLenCount = 0;
    for (const [pLen, cnt] of prefixLenCounts) {
      if (cnt > bestPrefixLenCount) {
        mostCommonPrefixLen = pLen;
        bestPrefixLenCount = cnt;
      }
    }

    let count = 0;
    const result = text.replace(CGNAT_RANGE_DESC_RE, (match) => {
      // Skip bare IPs without CIDR/range notation ONLY if they were already
      // handled by _deobfuscateResidualCgnat (i.e., no longer contain 100.64)
      if (/^\d+\.\d+\.\d+\.\d+$/.test(match) && !match.startsWith("100.")) return match;

      // For range descriptions, try to find the best real prefix.
      // First try exact third-octet match, then fall back to best prefix.
      const matchOctets = match.split(".");
      const thirdOctet = parseInt(matchOctets[2], 10);
      let realPrefix = bestPrefix;
      let realPrefixLen = mostCommonPrefixLen;

      if (!isNaN(thirdOctet)) {
        // Try to find a fake subnet whose third octet matches
        for (const [fakeIp, info] of fakeToRealMap) {
          const fakeOctets = fakeIp.split(".");
          if (parseInt(fakeOctets[2], 10) === thirdOctet) {
            realPrefix = info.realIp.split(".").slice(0, 2).join(".");
            realPrefixLen = info.prefixLen;
            break;
          }
        }
      }

      count++;

      // Replace CGNAT first two octets with real prefix
      let replaced = match.replace(/^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])/, realPrefix);

      // Fix CIDR suffix
      replaced = replaced.replace(/\/10\b/, `/${realPrefixLen}`);
      replaced = replaced.replace(/\/xx\b/, `/${realPrefixLen}`);

      // Validate: check all numeric octets in result are 0-255
      const numericOctets = replaced.match(/\b\d{1,3}\b/g);
      if (numericOctets) {
        for (let i = 0; i < Math.min(numericOctets.length, 4); i++) {
          if (parseInt(numericOctets[i], 10) > 255) {
            count--;
            return match;
          }
        }
      }

      return replaced;
    });

    return { text: result, count };
  }

  /**
   * Normalize-and-match deobfuscation for fd00::/8 ULA IPv6 addresses.
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
      // Try exact match first
      if (reverse.has(match)) return match;

      try {
        const expanded = expandIPv6(match);
        const real = expandedReverse.get(expanded);
        if (real) {
          count++;
          return real;
        }

        // Try prefix match for /64 subnet prefix extraction by the LLM
        for (const [expandedFake, realVal] of expandedReverse) {
          const matchGroups = expanded.split(":");
          const fakeGroups = expandedFake.split(":");
          let commonLen = 0;
          for (let i = 0; i < 8; i++) {
            if (matchGroups[i] === fakeGroups[i]) commonLen++;
            else break;
          }
          if (commonLen >= 4) {
            const trailingZeros = matchGroups.slice(commonLen).every((g) => g === "0000");
            if (trailingZeros) {
              const realExpanded = expandIPv6(realVal);
              const realGroups = realExpanded.split(":");
              const reconstructed = [
                ...realGroups.slice(0, commonLen),
                ...matchGroups.slice(commonLen),
              ].join(":");
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

  /** Clear all mappings and start fresh. */
  reset(): void {
    this._store.clear();
    this._subnetMapper.reset();
    this._ruleHits.clear();
    this._detectionsByCategory.clear();
    this._replacementsByCategory.clear();
    this._toolDepth = 0;
    if (this._contextDetector) this._contextDetector.reset();
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

  /** Return the max fake value length in the store (for streaming holdback). */
  maxFakeLength(): number {
    let max = 0;
    for (const [, fake] of this._store.allMappings()) {
      if (fake.length > max) max = fake.length;
    }
    return max;
  }

  /** Return stats from audit logger and store. */
  getStats(): object {
    const storeSize = this._store.size();
    const auditStats = this._audit ? this._audit.getStats() : null;

    const stats: Record<string, unknown> = {
      storeMappings: storeSize,
      salt: this._mapping.salt,
      canarySessionId: this._canary?.sessionId ?? null,
      audit: auditStats,
      obfuscationEvents: this._obfuscationEvents,
      deobfuscationEvents: this._deobfuscationEvents,
      totalEntitiesObfuscated: this._totalEntitiesObfuscated,
      totalReplacementsDeobfuscated: this._totalReplacementsDeobfuscated,
      ruleHits: Object.fromEntries(this._ruleHits),
      detectionsByCategory: Object.fromEntries(this._detectionsByCategory),
      replacementsByCategory: Object.fromEntries(this._replacementsByCategory),
      toolDepth: this._toolDepth,
      redactionLevel: this.config.redactionLevel,
      learnedEntities: this._contextDetector?.learnedCount ?? 0,
    };

    return stats;
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
