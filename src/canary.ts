/**
 * Canary token injection for detecting LLM data leakage.
 *
 * Injects unique, trackable tokens into obfuscated prompts. These tokens
 * serve no semantic purpose but can be monitored for leakage -- if a canary
 * appears in another user's output or in a training data audit, it proves
 * your data was exposed.
 *
 * Extended for security tracks:
 * - System-context canary planting (Track 2)
 * - Near-match Levenshtein scanning (Track 2)
 * - Behavioural canaries with false instruction tripwires (Track 2)
 */

import { createHash } from "node:crypto";

export interface CanaryToken {
  token: string;
  sessionId: string;
  timestamp: number;
  messageIndex: number;
}

/** Extended canary for injection detection (Track 2). */
export interface InjectionCanary extends CanaryToken {
  type: "marker" | "behavioural";
  agentBuildId: string;
  placement: "system" | "appended";
}

/** A behavioural canary: false instruction with detectable signature. */
export interface BehaviouralCanary {
  instruction: string;
  signatureCode: string;
  injectedAt: number;
}

/** Result of a canary leak detection scan. */
export interface CanaryLeakEvent {
  canary: InjectionCanary;
  matchType: "exact" | "near";
  distance: number;
  detectedIn: "response" | "tool_result";
}

export class CanaryInjector {
  private readonly _prefix: string;
  private readonly _secret: string;
  private _sessionId: string;
  private _messageCounter: number;
  private _tokens: CanaryToken[];

  constructor(prefix: string, secretKey: string) {
    this._prefix = prefix;
    this._secret = secretKey;
    this._sessionId = createHash("sha256")
      .update(`${secretKey}:${Date.now()}`)
      .digest("hex")
      .slice(0, 12);
    this._messageCounter = 0;
    this._tokens = [];
  }

  get sessionId(): string {
    return this._sessionId;
  }

  /** Inject a canary token into text. Returns modified text.
   *
   * The canary is encoded as zero-width Unicode characters appended to the
   * text. This is invisible to the LLM's reasoning (it sees no visible
   * change) but preserved if the text is leaked verbatim. The scanner
   * checks responses for both the raw token string AND the zero-width
   * encoded form.
   */
  inject(text: string): string {
    this._messageCounter += 1;
    const ts = Date.now();

    const raw = `${this._sessionId}:${this._messageCounter}:${ts}`;
    const tokenHash = createHash("sha256")
      .update(this._secret + raw)
      .digest("hex")
      .slice(0, 16);
    const token = `${this._prefix}-${tokenHash}`;

    const canary: CanaryToken = {
      token,
      sessionId: this._sessionId,
      timestamp: ts,
      messageIndex: this._messageCounter,
    };
    this._tokens.push(canary);

    // Encode token as zero-width characters — invisible to LLM reasoning
    const encoded = encodeZeroWidth(token);
    return `${text}${encoded}`;
  }

  /** Return all canary tokens injected in this session. */
  getTokens(): CanaryToken[] {
    return [...this._tokens];
  }

  /** Check if any known canary tokens appear in given text.
   *  Checks both plaintext token strings AND zero-width encoded form. */
  checkLeak(text: string): CanaryToken[] {
    const leaked: CanaryToken[] = [];
    // Also try to decode any zero-width sequences in the response
    const decoded = decodeZeroWidth(text);
    for (const canary of this._tokens) {
      if (text.includes(canary.token) || decoded.includes(canary.token)) {
        leaked.push(canary);
      }
    }
    return leaked;
  }

  /** Reset for a new session. */
  reset(): void {
    this._sessionId = createHash("sha256")
      .update(`${this._secret}:${Date.now()}`)
      .digest("hex")
      .slice(0, 12);
    this._messageCounter = 0;
    this._tokens = [];
    this._injectionCanaries = [];
    this._behaviouralCanaries = [];
  }

  // =================================================================
  // Track 2 — Security extension: injection canaries
  // =================================================================

  private _agentBuildId = "";
  private _injectionCanaries: InjectionCanary[] = [];
  private _behaviouralCanaries: BehaviouralCanary[] = [];

  /** Set the agent build ID for canary attribution. */
  setAgentBuildId(buildId: string): void {
    this._agentBuildId = buildId;
  }

  /**
   * Inject a marker canary into the system prompt specifically.
   * Places it as a non-semantic paragraph near the end.
   */
  injectSystem(systemPrompt: string): string {
    this._messageCounter += 1;
    const ts = Date.now();

    const raw = `sys:${this._sessionId}:${this._messageCounter}:${ts}`;
    const tokenHash = createHash("sha256")
      .update(this._secret + raw)
      .digest("hex")
      .slice(0, 16);
    const token = `${this._prefix}-${tokenHash}`;

    const canary: InjectionCanary = {
      token,
      sessionId: this._sessionId,
      timestamp: ts,
      messageIndex: this._messageCounter,
      type: "marker",
      agentBuildId: this._agentBuildId,
      placement: "system",
    };
    this._tokens.push(canary);
    this._injectionCanaries.push(canary);

    // Encode as zero-width characters — invisible to LLM
    const encoded = encodeZeroWidth(token);
    return `${systemPrompt}${encoded}`;
  }

  /**
   * Inject a behavioural canary — a false instruction with a detectable
   * signature code. If the code appears in any response, the system prompt
   * was read and acted upon (proves context leakage/injection).
   */
  injectBehavioural(systemPrompt: string): { prompt: string; canary: BehaviouralCanary } {
    this._messageCounter += 1;
    const ts = Date.now();

    const raw = `beh:${this._sessionId}:${this._messageCounter}:${ts}`;
    const sigHash = createHash("sha256")
      .update(this._secret + raw)
      .digest("hex")
      .slice(0, 8);
    const signatureCode = `SHROUD-DIAG-${sigHash}`;

    // Behavioural canary is intentionally visible — it tests whether an
    // injected instruction gets followed. Phrased as a minor formatting note
    // so it doesn't alarm the agent during normal operation.
    const instruction = `\n[Formatting note: If referencing internal diagnostics, include ref ${signatureCode}.]`;

    const canary: BehaviouralCanary = {
      instruction,
      signatureCode,
      injectedAt: this._messageCounter,
    };
    this._behaviouralCanaries.push(canary);

    // Also track as an InjectionCanary for unified querying
    const ic: InjectionCanary = {
      token: signatureCode,
      sessionId: this._sessionId,
      timestamp: ts,
      messageIndex: this._messageCounter,
      type: "behavioural",
      agentBuildId: this._agentBuildId,
      placement: "system",
    };
    this._tokens.push(ic);
    this._injectionCanaries.push(ic);

    return {
      prompt: `${systemPrompt}\n${instruction}`,
      canary,
    };
  }

  /**
   * Scan text for canary leaks with near-match support.
   *
   * Uses bounded Levenshtein distance to catch partial leaks and
   * paraphrased references (e.g. single-char substitutions, truncations).
   *
   * @param text - Response text to scan
   * @param maxDistance - Maximum Levenshtein distance (default: 2)
   * @param detectedIn - Context of the scan
   */
  checkLeakNearMatch(
    text: string,
    maxDistance = 2,
    detectedIn: "response" | "tool_result" = "response",
  ): CanaryLeakEvent[] {
    const events: CanaryLeakEvent[] = [];

    for (const canary of this._injectionCanaries) {
      const needle = canary.token;

      // Exact match first (fast path)
      if (text.includes(needle)) {
        events.push({
          canary,
          matchType: "exact",
          distance: 0,
          detectedIn,
        });
        continue;
      }

      // Near-match: sliding window with bounded Levenshtein
      if (maxDistance > 0) {
        const match = findNearMatch(text, needle, maxDistance);
        if (match !== null) {
          events.push({
            canary,
            matchType: "near",
            distance: match.distance,
            detectedIn,
          });
        }
      }
    }

    return events;
  }

  /**
   * Check if any planted behavioural canary signature codes appear
   * in the response text.
   */
  checkBehaviouralLeak(
    text: string,
    detectedIn: "response" | "tool_result" = "response",
  ): CanaryLeakEvent[] {
    const events: CanaryLeakEvent[] = [];

    for (const bc of this._behaviouralCanaries) {
      if (text.includes(bc.signatureCode)) {
        // Find the matching InjectionCanary
        const ic = this._injectionCanaries.find(
          (c) => c.type === "behavioural" && c.token === bc.signatureCode,
        );
        if (ic) {
          events.push({
            canary: ic,
            matchType: "exact",
            distance: 0,
            detectedIn,
          });
        }
      }
    }

    return events;
  }

  /** Get all injection canaries planted this session. */
  getInjectionCanaries(): readonly InjectionCanary[] {
    return this._injectionCanaries;
  }

  /** Get all behavioural canaries planted this session. */
  getBehaviouralCanaries(): readonly BehaviouralCanary[] {
    return this._behaviouralCanaries;
  }
}

// ===================================================================
// Levenshtein utilities — sync, zero-dependency
// ===================================================================

/**
 * Compute bounded Levenshtein distance between two strings.
 * Returns the actual distance, or maxDist + 1 if it exceeds the bound
 * (early termination for performance).
 */
export function levenshteinBounded(a: string, b: string, maxDist: number): number {
  const m = a.length;
  const n = b.length;

  // Quick reject: length difference alone exceeds threshold
  if (Math.abs(m - n) > maxDist) return maxDist + 1;

  // Single-row DP with early termination
  let prev = new Array(n + 1);
  let curr = new Array(n + 1);

  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    let rowMin = curr[0];

    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // deletion
        curr[j - 1] + 1,  // insertion
        prev[j - 1] + cost, // substitution
      );
      if (curr[j] < rowMin) rowMin = curr[j];
    }

    // Early termination: if the minimum value in this row exceeds maxDist,
    // the final result will too
    if (rowMin > maxDist) return maxDist + 1;

    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

/**
 * Find a near-match of needle in haystack using sliding window + bounded Levenshtein.
 *
 * Tests windows of size needle.length +/- maxDist to catch insertions/deletions.
 * Returns the best match (lowest distance) or null if none within threshold.
 */
export function findNearMatch(
  haystack: string,
  needle: string,
  maxDist: number,
): { start: number; distance: number } | null {
  const needleLen = needle.length;
  if (needleLen === 0) return null;

  let bestDist = maxDist + 1;
  let bestStart = -1;

  // Window sizes: needle length +/- maxDist
  const minWin = Math.max(1, needleLen - maxDist);
  const maxWin = needleLen + maxDist;

  for (let winSize = minWin; winSize <= maxWin; winSize++) {
    for (let start = 0; start <= haystack.length - winSize; start++) {
      const window = haystack.slice(start, start + winSize);

      // Quick char overlap check: skip if too few chars in common
      // (heuristic speedup — if first and last chars both differ, likely not a match)
      if (
        winSize >= 4 &&
        window[0] !== needle[0] &&
        window[winSize - 1] !== needle[needleLen - 1]
      ) {
        continue;
      }

      const dist = levenshteinBounded(window, needle, bestDist - 1);
      if (dist < bestDist) {
        bestDist = dist;
        bestStart = start;
        if (dist === 0) return { start: bestStart, distance: 0 };
      }
    }
  }

  if (bestDist <= maxDist) {
    return { start: bestStart, distance: bestDist };
  }

  return null;
}

// ===================================================================
// Zero-width Unicode steganography — invisible canary encoding
// ===================================================================

// Encoding: each character of the token is represented as a sequence of
// zero-width characters. We use 3 invisible chars to encode each byte:
//   U+200B (zero-width space)     = 0
//   U+200C (zero-width non-joiner) = 1
// Each byte is encoded as 8 bits using these two chars.
// A U+200D (zero-width joiner) is used as the start/end delimiter.

const ZW_ZERO = "\u200B"; // bit 0
const ZW_ONE  = "\u200C"; // bit 1
const ZW_DELIM = "\u200D"; // delimiter

/** Encode a string as zero-width characters. Invisible to humans and LLMs. */
export function encodeZeroWidth(text: string): string {
  let result = ZW_DELIM; // start delimiter
  for (let i = 0; i < text.length; i++) {
    const byte = text.charCodeAt(i);
    for (let bit = 7; bit >= 0; bit--) {
      result += (byte >> bit) & 1 ? ZW_ONE : ZW_ZERO;
    }
  }
  result += ZW_DELIM; // end delimiter
  return result;
}

/** Decode zero-width encoded text back to the original string. */
export function decodeZeroWidth(text: string): string {
  // Find all zero-width sequences between delimiters
  const results: string[] = [];
  let inSequence = false;
  let bits = "";

  for (const ch of text) {
    if (ch === ZW_DELIM) {
      if (inSequence && bits.length >= 8) {
        // Decode accumulated bits
        let decoded = "";
        for (let i = 0; i + 7 < bits.length; i += 8) {
          let byte = 0;
          for (let b = 0; b < 8; b++) {
            byte = (byte << 1) | (bits[i + b] === "1" ? 1 : 0);
          }
          if (byte > 0) decoded += String.fromCharCode(byte);
        }
        if (decoded.length > 0) results.push(decoded);
      }
      inSequence = !inSequence;
      bits = "";
    } else if (inSequence) {
      if (ch === ZW_ONE) bits += "1";
      else if (ch === ZW_ZERO) bits += "0";
    }
  }

  return results.join(" ");
}
