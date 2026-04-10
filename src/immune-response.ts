/**
 * Collective Immune Response — cross-agent attack propagation.
 *
 * When an attack is confirmed on any agent (honeypot hit, phantom tool
 * invocation, shadow execution block), this engine:
 *   1. Extracts an attack fingerprint (tool trigrams, signature, flagged dims)
 *   2. Creates an antibody that tightens detection for ALL agents
 *   3. Matches incoming tool sequences against active antibodies
 *   4. Decays antibodies over TTL unless re-confirmed by new attacks
 *
 * Think biological immune system: one agent gets infected, all agents
 * develop antibodies.
 *
 * Persistence: JSON file at {profileDir}/immune-state.json.
 * Zero external dependencies.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

import { SequenceEmbedder, generateNgrams } from "./detectors/sequence-embedder.js";
import type { AttackTrace } from "./transformer/contrastive.js";
import type { AgentThresholds } from "./adaptive-thresholds.js";

// ─── Types ───

export type AntibodySource = "honeypot" | "phantom" | "shadow" | "human_block";

/** An attack fingerprint extracted from a confirmed incident. */
export interface AttackFingerprint {
  id: string;
  /** Tool sequence trigrams from the attack trace. */
  trigrams: string[];
  /** N-gram embedded vector (256-dim). Stored as plain array for JSON. */
  vector: number[];
  /** Injection signature ID that triggered. */
  signatureId: string;
  /** Threat classification string from AttackTrace. */
  threatType: string;
  /** Which feature dimensions flagged anomalous during the attack. */
  flaggedDimensions: string[];
  /** Entity categories involved in the attack. */
  entityCategories: string[];
  /** Agent that was originally attacked. */
  sourceAgentBuildId: string;
  sourceAgentLabel: string;
  timestamp: number;
  source: AntibodySource;
}

/** An antibody — derived from an AttackFingerprint, applied to all agents. */
export interface Antibody {
  fingerprintId: string;
  /** Per-dimension sigma tightening: featureName → tightened sigma multiplier. */
  sigmaTightening: Record<string, number>;
  /** Tool sequence trigrams to watch for (cosine match against session sequence). */
  watchTrigrams: string[];
  /** Embedded vector of watchTrigrams for fast cosine matching. */
  watchVector: number[];
  /** Signature IDs to force-enable (never suppress) while antibody active. */
  forcedSignatures: string[];
  createdAt: number;
  expiresAt: number;
  confirmations: number;
  lastConfirmedAt: number;
  active: boolean;
}

/** Match result when checking a session against antibodies. */
export interface AntibodyMatch {
  antibody: Antibody;
  similarity: number;
  fingerprintId: string;
}

/** Persisted state for the immune response system. */
export interface ImmuneState {
  version: number;
  fingerprints: AttackFingerprint[];
  antibodies: Antibody[];
  stats: ImmuneStats;
}

export interface ImmuneStats {
  totalFingerprintsExtracted: number;
  totalAntibodiesCreated: number;
  totalPropagations: number;
  totalDecays: number;
  totalReconfirmations: number;
  totalMatches: number;
}

/** Configuration for the immune response engine. */
export interface ImmuneConfig {
  ttlSec: number;
  sigmaTightenFactor: number;
  matchThreshold: number;
  maxAntibodies: number;
}

// ─── Threat type → signature mapping ───
// Maps attack trace threat types to the signature IDs that should be
// force-enabled when an antibody from that attack is active.

const THREAT_TO_SIGNATURES: Record<string, string[]> = {
  phantom_tool_invocation: ["pt_data_upload", "pt_send_message", "pt_run_code"],
  honeypot_credential: ["hp_api_key", "hp_db_creds", "de_base64_exfil", "de_url_exfil"],
  shadow_exfil: ["de_base64_exfil", "de_url_exfil", "se_shadow_detected"],
};

// ─── Engine ───

export class ImmuneResponseEngine {
  private _profileDir: string;
  private _embedder: SequenceEmbedder;
  private _config: ImmuneConfig;
  private _fingerprints: AttackFingerprint[] = [];
  private _antibodies: Antibody[] = [];
  private _stats: ImmuneStats = {
    totalFingerprintsExtracted: 0,
    totalAntibodiesCreated: 0,
    totalPropagations: 0,
    totalDecays: 0,
    totalReconfirmations: 0,
    totalMatches: 0,
  };
  private _dirty = false;

  constructor(profileDir: string, config: ImmuneConfig) {
    this._profileDir = profileDir.startsWith("~")
      ? join(process.env.HOME || "/tmp", profileDir.slice(1))
      : profileDir;
    this._embedder = new SequenceEmbedder(256);
    this._config = config;
    this.load();
  }

  // ── Fingerprint extraction ──

  /**
   * Extract an attack fingerprint from a confirmed attack trace.
   */
  extractFingerprint(
    trace: AttackTrace,
    agentBuildId: string,
    agentLabel: string,
    source: AntibodySource,
    signatureId: string,
    flaggedDimensions: string[] = [],
    entityCategories: string[] = [],
  ): AttackFingerprint {
    const fullSequence = [...trace.legitimatePrefix, ...trace.hijackedSuffix];
    const trigrams = generateNgrams(fullSequence).filter(ng => ng.includes("\u2192"));
    const vector = Array.from(this._embedder.embedSequence(fullSequence));

    const id = createHash("sha256")
      .update(`${signatureId}:${trigrams.join(",")}:${trace.threatType}`)
      .digest("hex")
      .slice(0, 16);

    const fingerprint: AttackFingerprint = {
      id,
      trigrams,
      vector,
      signatureId,
      threatType: trace.threatType,
      flaggedDimensions,
      entityCategories,
      sourceAgentBuildId: agentBuildId,
      sourceAgentLabel: agentLabel,
      timestamp: Date.now(),
      source,
    };

    this._fingerprints.push(fingerprint);
    // Cap fingerprints
    if (this._fingerprints.length > this._config.maxAntibodies * 2) {
      this._fingerprints = this._fingerprints.slice(-this._config.maxAntibodies);
    }
    this._stats.totalFingerprintsExtracted++;
    this._dirty = true;

    return fingerprint;
  }

  // ── Antibody creation + propagation ──

  /**
   * Create an antibody from a fingerprint and activate it fleet-wide.
   * Returns the new antibody.
   */
  propagate(fingerprint: AttackFingerprint): Antibody {
    // Check for existing antibody from same fingerprint — reconfirm instead
    const existing = this._antibodies.find(
      a => a.fingerprintId === fingerprint.id && a.active,
    );
    if (existing) {
      this.reconfirm(fingerprint.id);
      return existing;
    }

    // Build per-dimension sigma tightening from flagged dimensions
    const sigmaTightening: Record<string, number> = {};
    for (const dim of fingerprint.flaggedDimensions) {
      sigmaTightening[dim] = this._config.sigmaTightenFactor;
    }
    // If no specific dimensions flagged, tighten the broad categories
    if (fingerprint.flaggedDimensions.length === 0) {
      sigmaTightening["entityDensityPer1k"] = this._config.sigmaTightenFactor;
      sigmaTightening["newVocabularyRate"] = this._config.sigmaTightenFactor;
      sigmaTightening["entityEchoRate"] = this._config.sigmaTightenFactor;
    }

    // Forced signatures from threat type
    const forcedSignatures = THREAT_TO_SIGNATURES[fingerprint.threatType] ?? [];

    // Watch vector from the hijacked suffix (the attack pattern to match)
    const watchVector = Array.from(
      this._embedder.embedSequence(fingerprint.trigrams.length > 0
        ? fingerprint.trigrams.map(t => t.replace(/\u2192/g, ",")).join(",").split(",")
        : [fingerprint.signatureId]),
    );

    const now = Date.now();
    const antibody: Antibody = {
      fingerprintId: fingerprint.id,
      sigmaTightening,
      watchTrigrams: fingerprint.trigrams.slice(0, 50), // cap stored trigrams
      watchVector,
      forcedSignatures,
      createdAt: now,
      expiresAt: now + this._config.ttlSec * 1000,
      confirmations: 1,
      lastConfirmedAt: now,
      active: true,
    };

    this._antibodies.push(antibody);
    this._stats.totalAntibodiesCreated++;
    this._stats.totalPropagations++;
    this._dirty = true;

    // LRU eviction
    this._enforceMaxAntibodies();

    return antibody;
  }

  // ── Antibody matching ──

  /**
   * Check if a current tool sequence matches any active antibody.
   * Returns matching antibodies sorted by similarity (highest first).
   */
  matchAntibodies(sessionToolSequence: string[]): AntibodyMatch[] {
    if (sessionToolSequence.length < 2) return [];

    const activeAntibodies = this._antibodies.filter(a => a.active);
    if (activeAntibodies.length === 0) return [];

    const sessionVector = this._embedder.embedSequence(sessionToolSequence);
    const matches: AntibodyMatch[] = [];

    for (const ab of activeAntibodies) {
      const abVector = Float64Array.from(ab.watchVector);
      const sim = this._embedder.similarity(sessionVector, abVector);

      if (sim >= this._config.matchThreshold) {
        matches.push({
          antibody: ab,
          similarity: sim,
          fingerprintId: ab.fingerprintId,
        });
        this._stats.totalMatches++;
      }
    }

    return matches.sort((a, b) => b.similarity - a.similarity);
  }

  // ── Sigma tightening ──

  /**
   * Get effective sigma for a feature dimension, considering all active antibodies.
   * Returns the tightest (lowest) sigma among all active antibodies.
   */
  getEffectiveSigma(baseSigma: number, featureName: string): number {
    let tightest = baseSigma;

    for (const ab of this._antibodies) {
      if (!ab.active) continue;
      const factor = ab.sigmaTightening[featureName];
      if (factor !== undefined) {
        const candidate = baseSigma * factor;
        if (candidate < tightest) {
          tightest = candidate;
        }
      }
    }

    // Hard floor: never go below 1.0 sigma
    return Math.max(1.0, tightest);
  }

  /**
   * Build a sigmaOverrides map for all active antibodies.
   * Returns featureName → effective sigma for features that have tightening.
   */
  getSigmaOverrides(baseSigma: number): Record<string, number> {
    const overrides: Record<string, number> = {};

    for (const ab of this._antibodies) {
      if (!ab.active) continue;
      for (const [feat, factor] of Object.entries(ab.sigmaTightening)) {
        const candidate = Math.max(1.0, baseSigma * factor);
        if (overrides[feat] === undefined || candidate < overrides[feat]) {
          overrides[feat] = candidate;
        }
      }
    }

    return overrides;
  }

  /**
   * Get forced (un-suppressable) signatures from all active antibodies.
   */
  getForcedSignatures(): string[] {
    const forced = new Set<string>();
    for (const ab of this._antibodies) {
      if (!ab.active) continue;
      for (const sig of ab.forcedSignatures) {
        forced.add(sig);
      }
    }
    return [...forced];
  }

  /**
   * Apply immune overrides to adaptive thresholds.
   * Tightens thresholds and removes forced signatures from suppressed list.
   */
  applyToThresholds(thresholds: AgentThresholds): AgentThresholds {
    const activeAntibodies = this._antibodies.filter(a => a.active);
    if (activeAntibodies.length === 0) return thresholds;

    const result = { ...thresholds };
    const forced = this.getForcedSignatures();

    // Remove forced signatures from suppressed list
    if (forced.length > 0) {
      result.suppressedSignatures = result.suppressedSignatures.filter(
        s => !forced.includes(s),
      );
    }

    // Tighten thresholds if any antibody flags relevant dimensions
    let hasDriftTightening = false;
    let hasCoherenceTightening = false;
    let hasTransformerTightening = false;

    for (const ab of activeAntibodies) {
      for (const dim of Object.keys(ab.sigmaTightening)) {
        if (dim === "lexicalOverlapWithPrevious" || dim === "newVocabularyRate") {
          hasDriftTightening = true;
        }
        if (dim === "toolCallCount" || dim === "directiveVerbCount") {
          hasCoherenceTightening = true;
        }
        if (dim === "entityDensityPer1k" || dim === "entityEchoRate") {
          hasTransformerTightening = true;
        }
      }
    }

    const factor = this._config.sigmaTightenFactor;
    if (hasDriftTightening) {
      // Drift fires when similarity < threshold — higher = tighter
      result.driftThreshold = Math.min(0.5, result.driftThreshold / factor);
    }
    if (hasCoherenceTightening) {
      result.coherenceZScore = Math.max(1.5, result.coherenceZScore * factor);
    }
    if (hasTransformerTightening) {
      result.transformerThreshold = Math.max(0.5, result.transformerThreshold * factor);
    }

    return result;
  }

  // ── TTL decay ──

  /**
   * Decay tick — expire antibodies past their TTL.
   * Call periodically (e.g. at session end or on a timer).
   */
  decayTick(): void {
    const now = Date.now();
    let decayed = 0;

    for (const ab of this._antibodies) {
      if (!ab.active) continue;
      if (now > ab.expiresAt) {
        ab.active = false;
        decayed++;
      }
    }

    if (decayed > 0) {
      this._stats.totalDecays += decayed;
      this._dirty = true;
    }
  }

  /**
   * Re-confirm an antibody when a similar attack is seen.
   * Resets TTL and increments confirmation count.
   */
  reconfirm(fingerprintId: string): void {
    const ab = this._antibodies.find(
      a => a.fingerprintId === fingerprintId && a.active,
    );
    if (ab) {
      ab.confirmations++;
      ab.lastConfirmedAt = Date.now();
      ab.expiresAt = Date.now() + this._config.ttlSec * 1000;
      this._stats.totalReconfirmations++;
      this._dirty = true;
    }
  }

  // ── State accessors ──

  getState(): ImmuneState {
    return {
      version: 1,
      fingerprints: this._fingerprints,
      antibodies: this._antibodies,
      stats: { ...this._stats },
    };
  }

  getActiveAntibodies(): Antibody[] {
    return this._antibodies.filter(a => a.active);
  }

  getStats(): ImmuneStats {
    return { ...this._stats };
  }

  // ── Persistence ──

  private _stateFile(): string {
    return join(this._profileDir, "immune-state.json");
  }

  flush(): void {
    if (!this._dirty) return;
    try {
      if (!existsSync(this._profileDir)) {
        mkdirSync(this._profileDir, { recursive: true });
      }
      const state: ImmuneState = {
        version: 1,
        fingerprints: this._fingerprints,
        antibodies: this._antibodies,
        stats: this._stats,
      };
      writeFileSync(this._stateFile(), JSON.stringify(state));
      this._dirty = false;
    } catch { /* persist is best-effort */ }
  }

  load(): boolean {
    try {
      const raw = readFileSync(this._stateFile(), "utf-8");
      const state = JSON.parse(raw) as ImmuneState;
      if (state.version === 1) {
        this._fingerprints = state.fingerprints || [];
        this._antibodies = state.antibodies || [];
        this._stats = state.stats || this._stats;
        // Expire stale antibodies on load
        this.decayTick();
        return true;
      }
    } catch { /* file may not exist */ }
    return false;
  }

  // ── Internal ──

  private _enforceMaxAntibodies(): void {
    const active = this._antibodies.filter(a => a.active);
    if (active.length <= this._config.maxAntibodies) return;

    // Evict oldest active antibodies with fewest confirmations
    active.sort((a, b) => {
      if (a.confirmations !== b.confirmations) return a.confirmations - b.confirmations;
      return a.createdAt - b.createdAt;
    });

    const toEvict = active.length - this._config.maxAntibodies;
    for (let i = 0; i < toEvict; i++) {
      active[i].active = false;
    }

    // Also prune inactive antibodies older than 7 days
    const weekAgo = Date.now() - 7 * 86400_000;
    this._antibodies = this._antibodies.filter(
      ab => ab.active || ab.expiresAt > weekAgo,
    );
  }
}
