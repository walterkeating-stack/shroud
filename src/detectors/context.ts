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

    // Boost entities in high-scoring blocks
    return entities.map((e) => {
      const block = blockScores.find(
        (b) => e.start >= b.start && e.end <= b.end,
      );
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
    // Split by double newline (paragraphs)
    const parts = text.split(/\n\s*\n/);
    let pos = 0;
    for (const part of parts) {
      const idx = text.indexOf(part, pos);
      blocks.push({ text: part, start: idx, end: idx + part.length });
      pos = idx + part.length;
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

    return entities.map((e) => {
      const peers = getClusterPeers(e.category);
      if (peers.size === 0) return e;

      let nearbyCount = 0;
      for (const other of entities) {
        if (other === e) continue;
        if (!peers.has(other.category)) continue;
        const dist = Math.min(
          Math.abs(other.start - e.end),
          Math.abs(e.start - other.end),
        );
        if (dist <= PROXIMITY_WINDOW) {
          nearbyCount++;
        }
      }

      if (nearbyCount > 0) {
        return {
          ...e,
          confidence: Math.min(
            1.0,
            e.confidence + PROXIMITY_BOOST * nearbyCount,
          ),
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

    // Find bare occurrences of extracted hostnames
    const additional: DetectedEntity[] = [];
    for (const hostname of hostnames) {
      let idx = 0;
      while (true) {
        const pos = text.indexOf(hostname, idx);
        if (pos === -1) break;
        const key = `${pos}:${pos + hostname.length}`;
        if (!covered.has(key)) {
          covered.add(key);
          additional.push({
            value: hostname,
            start: pos,
            end: pos + hostname.length,
            category: Category.HOSTNAME,
            confidence: 0.85,
            detector: "context:hostname_propagation",
          });
        }
        idx = pos + 1;
      }
    }

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
    const additional: DetectedEntity[] = [];

    for (const [value, category] of this._learnedEntities) {
      let idx = 0;
      while (true) {
        const pos = text.indexOf(value, idx);
        if (pos === -1) break;
        const key = `${pos}:${pos + value.length}`;
        if (!covered.has(key)) {
          covered.add(key);
          additional.push({
            value,
            start: pos,
            end: pos + value.length,
            category,
            confidence: 0.80,
            detector: "context:learned_entity",
          });
        }
        idx = pos + 1;
      }
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

    // Cap learned entities to prevent unbounded growth
    if (this._learnedEntities.size > 1000) {
      const entries = [...this._learnedEntities.entries()];
      this._learnedEntities = new Map(entries.slice(-500));
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
