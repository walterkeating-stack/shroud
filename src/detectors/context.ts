/**
 * Context-aware detection enhancements.
 *
 * Wraps another detector and applies post-detection intelligence:
 * 1. Context-aware confidence boosting (config keyword density)
 * 3. Proximity-based PII clustering (nearby entities boost each other)
 * 4. Config-block hostname extraction (hostname X -> detect bare X)
 * 9. Learned entity propagation (cross-invocation memory)
 * 10. Confidence decay by frequency (common words lose confidence)
 */

import { Category, DetectedEntity } from "../types.js";
import { BaseDetector } from "./base.js";

/**
 * Single-pass multi-string scanner using a combined regex.
 * Replaces per-string indexOf loops with one regex alternation pass — O(M)
 * instead of O(S*M) where S = number of strings, M = text length.
 */
function scanMultiplePatterns(
  text: string,
  values: string[],
  covered: Set<string>,
  category: Category,
  confidence: number,
  detector: string,
): DetectedEntity[] {
  if (values.length === 0) return [];
  // Sort longest-first so regex matches greedily
  const sorted = values.slice().sort((a, b) => b.length - a.length);
  const escaped = sorted.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(escaped.join("|"), "g");

  const results: DetectedEntity[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const pos = m.index;
    const val = m[0];
    const key = `${pos}:${pos + val.length}`;
    if (!covered.has(key)) {
      covered.add(key);
      results.push({
        value: val,
        start: pos,
        end: pos + val.length,
        category,
        confidence,
        detector,
      });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Config keyword sets for context boosting (#1)
// ---------------------------------------------------------------------------

const CONFIG_KEYWORDS = [
  "interface ", "router ", "ip route ", "hostname ",
  "switchport ", "vlan ", "access-list ", "route-map ",
  "ip address ", "description ", "ntp ", "snmp-server ",
  "logging ", "banner ", "crypto ", "line ",
  "set address ", "set zone ", "set security ",
  "set interfaces ", "set protocols ",
];

// ---------------------------------------------------------------------------
// PII cluster groups for proximity boosting (#3)
// ---------------------------------------------------------------------------

const CLUSTER_GROUPS: Category[][] = [
  [Category.PERSON_NAME, Category.EMAIL, Category.PHONE, Category.SSN],
  [Category.IP_ADDRESS, Category.HOSTNAME, Category.MAC_ADDRESS],
  [Category.CREDIT_CARD, Category.PERSON_NAME],
];

function getClusterPeers(category: Category): Set<Category> {
  const peers = new Set<Category>();
  for (const group of CLUSTER_GROUPS) {
    if (group.includes(category)) {
      for (const c of group) {
        if (c !== category) peers.add(c);
      }
    }
  }
  return peers;
}

// ---------------------------------------------------------------------------
// Common words that should decay in confidence (#10)
// ---------------------------------------------------------------------------

const COMMON_WORDS = new Set([
  "permit", "deny", "default", "service", "system",
  "access", "network", "global", "local", "public",
  "private", "standard", "extended", "input", "output",
  "inside", "outside", "trust", "untrust", "management",
  "control", "data", "voice", "video", "wireless",
  "primary", "secondary", "backup", "active", "standby",
]);

// ---------------------------------------------------------------------------
// Patterns for hostname extraction (#4)
// ---------------------------------------------------------------------------

const HOSTNAME_CMD_RE = /(?:^|\n)\s*hostname\s+(\S+)/gi;
const SWITCHNAME_CMD_RE = /(?:^|\n)\s*switchname\s+(\S+)/gi;

// ---------------------------------------------------------------------------
// ContextDetector
// ---------------------------------------------------------------------------

/** Proximity window in characters for PII clustering. */
const PROXIMITY_WINDOW = 200;

/** Confidence boost for context (config block). */
const CONTEXT_BOOST = 0.10;

/** Confidence boost for proximity clustering. */
const PROXIMITY_BOOST = 0.08;

export class ContextDetector implements BaseDetector {
  readonly name = "context";
  private _inner: BaseDetector;

  /** Feature 9: Learned entities from previous invocations. */
  private _learnedEntities: Map<string, Category> = new Map();

  constructor(inner: BaseDetector) {
    this._inner = inner;
  }

  detect(text: string): DetectedEntity[] {
    // Run inner detector
    let entities = this._inner.detect(text);

    // #9: Inject learned entities (from previous invocations)
    entities = this._injectLearnedEntities(text, entities);

    // #4: Extract hostnames from config lines and find bare occurrences
    entities = this._extractAndPropagateHostnames(text, entities);

    // #1: Context-aware confidence boosting
    entities = this._boostFromContext(text, entities);

    // #3: Proximity-based PII clustering
    entities = this._boostByProximity(entities);

    // #10: Confidence decay for common words
    entities = this._decayCommonWords(entities);

    // #9: Learn from this invocation for next time
    this._learnEntities(entities);

    return entities;
  }

  /** Reset learned entities (called on Obfuscator.reset()). */
  reset(): void {
    this._learnedEntities.clear();
  }

  /** Get count of learned entities. */
  get learnedCount(): number {
    return this._learnedEntities.size;
  }

  // -------------------------------------------------------------------------
  // #1: Context-aware confidence boosting
  // -------------------------------------------------------------------------

  private _boostFromContext(
    text: string,
    entities: DetectedEntity[],
  ): DetectedEntity[] {
    if (entities.length === 0) return entities;

    // Split text into blocks (paragraphs or ~20 line chunks)
    const blocks = this._splitBlocks(text);

    // Score each block for config keyword density
    const blockScores: Array<{ start: number; end: number; score: number }> = [];
    for (const block of blocks) {
      let score = 0;
      const lower = block.text.toLowerCase();
      for (const kw of CONFIG_KEYWORDS) {
        if (lower.includes(kw.toLowerCase())) {
          score++;
        }
      }
      blockScores.push({ start: block.start, end: block.end, score });
    }

    // Boost entities in high-scoring blocks.
    // Blocks are sorted by start position, so use binary search — O(log B) per entity.
    return entities.map((e) => {
      // Binary search for block containing entity
      let lo = 0, hi = blockScores.length - 1;
      let block: { start: number; end: number; score: number } | null = null;
      while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        const b = blockScores[mid];
        if (e.start >= b.start && e.end <= b.end) { block = b; break; }
        if (e.start < b.start) hi = mid - 1;
        else lo = mid + 1;
      }
      if (block && block.score >= 2) {
        return {
          ...e,
          confidence: Math.min(1.0, e.confidence + CONTEXT_BOOST),
        };
      }
      return e;
    });
  }

  private _splitBlocks(
    text: string,
  ): Array<{ text: string; start: number; end: number }> {
    const blocks: Array<{ text: string; start: number; end: number }> = [];
    // Use matchAll to find paragraph separators and derive block positions
    // without re-scanning the text with indexOf.
    const sepRe = /\n\s*\n/g;
    let lastEnd = 0;
    let m: RegExpExecArray | null;
    while ((m = sepRe.exec(text)) !== null) {
      if (m.index > lastEnd) {
        blocks.push({ text: text.slice(lastEnd, m.index), start: lastEnd, end: m.index });
      }
      lastEnd = m.index + m[0].length;
    }
    // Trailing block
    if (lastEnd < text.length) {
      blocks.push({ text: text.slice(lastEnd), start: lastEnd, end: text.length });
    }
    // If no paragraph breaks, treat whole text as one block
    if (blocks.length <= 1) {
      blocks.length = 0;
      blocks.push({ text, start: 0, end: text.length });
    }
    return blocks;
  }

  // -------------------------------------------------------------------------
  // #3: Proximity-based PII clustering
  // -------------------------------------------------------------------------

  private _boostByProximity(entities: DetectedEntity[]): DetectedEntity[] {
    if (entities.length < 2) return entities;

    // Sort by start position for two-pointer window scan — O(n log n)
    const sorted = entities.slice().sort((a, b) => a.start - b.start);

    // For each entity, count cluster peers within PROXIMITY_WINDOW using
    // a sliding window instead of O(n²) pairwise comparison.
    const nearbyCounts = new Map<DetectedEntity, number>();
    for (let i = 0; i < sorted.length; i++) {
      const e = sorted[i];
      const peers = getClusterPeers(e.category);
      if (peers.size === 0) continue;

      let count = 0;
      // Scan forward within window
      for (let j = i + 1; j < sorted.length; j++) {
        if (sorted[j].start - e.end > PROXIMITY_WINDOW) break;
        if (peers.has(sorted[j].category)) count++;
      }
      // Scan backward within window
      for (let j = i - 1; j >= 0; j--) {
        if (e.start - sorted[j].end > PROXIMITY_WINDOW) break;
        if (peers.has(sorted[j].category)) count++;
      }
      if (count > 0) nearbyCounts.set(e, count);
    }

    if (nearbyCounts.size === 0) return entities;

    return entities.map((e) => {
      const count = nearbyCounts.get(e);
      if (count) {
        return {
          ...e,
          confidence: Math.min(1.0, e.confidence + PROXIMITY_BOOST * count),
        };
      }
      return e;
    });
  }

  // -------------------------------------------------------------------------
  // #4: Config-block hostname extraction
  // -------------------------------------------------------------------------

  private _extractAndPropagateHostnames(
    text: string,
    entities: DetectedEntity[],
  ): DetectedEntity[] {
    // Find hostname values from cisco_hostname pattern matches
    const hostnames = new Set<string>();
    for (const e of entities) {
      if (
        e.detector === "regex:cisco_hostname" ||
        e.detector.endsWith(":cisco_hostname")
      ) {
        hostnames.add(e.value);
      }
    }

    // Also scan with our own regex for hostname/switchname commands
    for (const re of [HOSTNAME_CMD_RE, SWITCHNAME_CMD_RE]) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        if (m[1]) hostnames.add(m[1]);
      }
    }

    if (hostnames.size === 0) return entities;

    // Track existing entity positions
    const covered = new Set(
      entities.map((e) => `${e.start}:${e.end}`),
    );

    // Single-pass combined regex for all hostnames instead of per-hostname indexOf
    const additional = scanMultiplePatterns(
      text,
      [...hostnames],
      covered,
      Category.HOSTNAME,
      0.85,
      "context:hostname_propagation",
    );

    if (additional.length === 0) return entities;
    return [...entities, ...additional].sort(
      (a, b) => a.start - b.start,
    );
  }

  // -------------------------------------------------------------------------
  // #9: Learned entity propagation
  // -------------------------------------------------------------------------

  private _injectLearnedEntities(
    text: string,
    entities: DetectedEntity[],
  ): DetectedEntity[] {
    if (this._learnedEntities.size === 0) return entities;

    const covered = new Set(
      entities.map((e) => `${e.start}:${e.end}`),
    );

    // Group learned entities by category for batch scanning
    const byCat = new Map<Category, string[]>();
    for (const [value, category] of this._learnedEntities) {
      let arr = byCat.get(category);
      if (!arr) { arr = []; byCat.set(category, arr); }
      arr.push(value);
    }

    const additional: DetectedEntity[] = [];
    for (const [category, values] of byCat) {
      const hits = scanMultiplePatterns(
        text,
        values,
        covered,
        category,
        0.80,
        "context:learned_entity",
      );
      additional.push(...hits);
    }

    if (additional.length === 0) return entities;
    return [...entities, ...additional].sort(
      (a, b) => a.start - b.start,
    );
  }

  private _learnEntities(entities: DetectedEntity[]): void {
    // Learn high-confidence entities from config-context patterns
    const learnableDetectors = new Set([
      "regex:cisco_hostname",
      "regex:route_map_name",
      "regex:acl_name",
      "regex:prefix_list_name",
      "regex:vlan_name",
      "regex:interface_description",
      "regex:device_name_dotted",
      "regex:device_name_short",
      "context:hostname_propagation",
    ]);

    for (const e of entities) {
      if (
        e.confidence >= 0.80 &&
        (learnableDetectors.has(e.detector) ||
          e.category === Category.HOSTNAME)
      ) {
        // Only learn values that look like identifiers (not too short, not common words)
        if (e.value.length >= 3 && !COMMON_WORDS.has(e.value.toLowerCase())) {
          this._learnedEntities.set(e.value, e.category);
        }
      }
    }

    // Cap learned entities to prevent unbounded growth.
    // Delete oldest entries (Map preserves insertion order) without rebuilding.
    if (this._learnedEntities.size > 1000) {
      const toDelete = this._learnedEntities.size - 500;
      let deleted = 0;
      for (const key of this._learnedEntities.keys()) {
        if (deleted >= toDelete) break;
        this._learnedEntities.delete(key);
        deleted++;
      }
    }
  }

  // -------------------------------------------------------------------------
  // #10: Confidence decay for common words
  // -------------------------------------------------------------------------

  private _decayCommonWords(entities: DetectedEntity[]): DetectedEntity[] {
    return entities.map((e) => {
      if (COMMON_WORDS.has(e.value.toLowerCase())) {
        return {
          ...e,
          confidence: e.confidence * 0.5,
        };
      }
      return e;
    });
  }
}
