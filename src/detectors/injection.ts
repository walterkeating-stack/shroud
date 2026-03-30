/**
 * Prompt injection signature detector.
 *
 * Scans text for known injection patterns on the request side
 * (direct/indirect injection) and response side (exfiltration confirmation).
 *
 * This is a standalone scanner — it does NOT integrate into the obfuscation
 * detector chain. The obfuscation pipeline remains untouched.
 */

import {
  SecurityEvent,
  SecuritySeverity,
  ThreatClass,
} from "../security-event.js";
import {
  SignatureDef,
  REQUEST_SIGNATURES,
  RESPONSE_SIGNATURES,
} from "./injection-signatures.js";
import {
  MULTILINGUAL_REQUEST_SIGNATURES,
} from "./injection-multilingual.js";

/** Configuration for the InjectionDetector. */
export interface InjectionDetectorConfig {
  /** Action mode: "flag" logs only, "block" allows caller to reject, "off" disables. */
  action: "flag" | "block" | "off";
  /** Signature IDs to skip. */
  disabledSignatures: Set<string>;
  /** Minimum severity to act on. */
  minSeverity: SecuritySeverity;
  /** Whether to scan response text. */
  scanResponses: boolean;
}

/** Injection keywords checked inside decoded Base64 payloads. */
const BASE64_INJECTION_KEYWORDS = [
  "ignore",
  "instructions",
  "system prompt",
  "override",
  "jailbreak",
  "disregard",
  "forget",
  "bypass",
  "unrestricted",
  "developer mode",
  "you are now",
  "act as",
];

const SEVERITY_RANK: Record<SecuritySeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

/**
 * Strip token smuggling characters — invisible Unicode chars that attackers
 * insert between tokens to break regex matching.
 *
 * Strips: zero-width space (U+200B), zero-width non-joiner (U+200C),
 * zero-width joiner (U+200D), byte order mark (U+FEFF), word joiner (U+2060),
 * soft hyphen (U+00AD), Mongolian vowel separator (U+180E),
 * and all variation selectors (U+FE00-FE0F).
 */
function stripTokenSmuggling(text: string): string {
  return text.replace(/[\u200B\u200C\u200D\uFEFF\u2060\u00AD\u180E\uFE00-\uFE0F]/g, "");
}

/**
 * Standalone injection scanner. Not a BaseDetector — runs parallel to
 * the obfuscation pipeline, never touches entity replacement.
 */
export class InjectionDetector {
  private _config: InjectionDetectorConfig;
  private _requestSigs: SignatureDef[];
  private _responseSigs: SignatureDef[];

  constructor(config: InjectionDetectorConfig) {
    this._config = config;
    const minRank = SEVERITY_RANK[config.minSeverity];

    // Pre-filter signatures by severity and disabled list
    // Include multilingual patterns alongside English ones
    this._requestSigs = [...REQUEST_SIGNATURES, ...MULTILINGUAL_REQUEST_SIGNATURES].filter(
      (s) =>
        !config.disabledSignatures.has(s.id) &&
        SEVERITY_RANK[s.severity] >= minRank,
    );
    this._responseSigs = RESPONSE_SIGNATURES.filter(
      (s) =>
        !config.disabledSignatures.has(s.id) &&
        SEVERITY_RANK[s.severity] >= minRank,
    );
  }

  /** Scan request/outbound text for injection patterns. */
  scanRequest(text: string): SecurityEvent[] {
    if (this._config.action === "off") return [];

    // Token smuggling defence: strip invisible characters then re-scan.
    // Attackers insert zero-width spaces, soft hyphens, word joiners etc.
    // between tokens to break regex matching: "ig​nore pre​vious in​structions"
    const cleaned = stripTokenSmuggling(text);
    const smuggled = cleaned !== text;

    const events = this._scanPatterns(text, this._requestSigs, "request");

    // If smuggling chars were present, also scan the cleaned version
    // to catch patterns that were broken by invisible chars
    if (smuggled) {
      const cleanedEvents = this._scanPatterns(cleaned, this._requestSigs, "request");
      // Add cleaned-text detections that weren't found in original
      const existingIds = new Set(events.map(e => e.signatureId));
      for (const evt of cleanedEvents) {
        if (!existingIds.has(evt.signatureId)) {
          evt.description = `[token-smuggling stripped] ${evt.description}`;
          events.push(evt);
        }
      }

      // Also flag the smuggling itself
      const action = this._config.action === "block" ? "blocked" : "flagged";
      events.push({
        timestamp: Date.now(),
        eventType: "injection_detected",
        direction: "request",
        threatClass: ThreatClass.ENCODING_BYPASS,
        signatureId: "eb_token_smuggling",
        severity: "medium",
        matchedText: `[${text.length - cleaned.length} invisible chars stripped]`,
        matchStart: 0,
        matchEnd: text.length,
        textLength: text.length,
        action,
        description: `Token smuggling: ${text.length - cleaned.length} invisible characters removed, revealing injection patterns`,
      });
    }

    // Base64 decode-and-rescan
    events.push(...this._scanEncodedPayloads(text, "request"));

    return events;
  }

  /** Scan response/inbound text for exfiltration patterns. */
  scanResponse(text: string): SecurityEvent[] {
    if (this._config.action === "off" || !this._config.scanResponses) return [];
    return this._scanPatterns(text, this._responseSigs, "response");
  }

  private _scanPatterns(
    text: string,
    signatures: SignatureDef[],
    direction: "request" | "response",
  ): SecurityEvent[] {
    const events: SecurityEvent[] = [];
    const action = this._config.action === "block" ? "blocked" : "flagged";

    for (const sig of signatures) {
      // Reset lastIndex for global regexes
      sig.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = sig.pattern.exec(text)) !== null) {
        events.push({
          timestamp: Date.now(),
          eventType: "injection_detected",
          direction,
          threatClass: sig.threatClass,
          signatureId: sig.id,
          severity: sig.severity,
          matchedText: match[0].slice(0, 200), // truncate long matches
          matchStart: match.index,
          matchEnd: match.index + match[0].length,
          textLength: text.length,
          action,
          description: sig.description,
        });

        // For non-global patterns, break after first match
        if (!sig.pattern.global) break;
      }
    }

    return events;
  }

  /**
   * Detect Base64-encoded injection payloads.
   *
   * Finds Base64-looking blocks (40+ chars), decodes them (sync via Buffer),
   * and checks if the decoded text contains injection keywords.
   */
  private _scanEncodedPayloads(
    text: string,
    direction: "request" | "response",
  ): SecurityEvent[] {
    const events: SecurityEvent[] = [];
    const action = this._config.action === "block" ? "blocked" : "flagged";
    const b64Re = /[A-Za-z0-9+/]{40,}={0,2}/g;

    let match: RegExpExecArray | null;
    while ((match = b64Re.exec(text)) !== null) {
      try {
        const decoded = Buffer.from(match[0], "base64").toString("utf-8");
        // Check if decoded text is mostly printable ASCII (heuristic for valid text)
        const printableRatio =
          decoded.replace(/[^\x20-\x7E]/g, "").length / decoded.length;
        if (printableRatio < 0.7) continue;

        const lower = decoded.toLowerCase();
        for (const keyword of BASE64_INJECTION_KEYWORDS) {
          if (lower.includes(keyword)) {
            events.push({
              timestamp: Date.now(),
              eventType: "injection_detected",
              direction,
              threatClass: ThreatClass.ENCODING_BYPASS,
              signatureId: "eb_base64_injection",
              severity: "high",
              matchedText: `[base64→"${decoded.slice(0, 100)}"]`,
              matchStart: match.index,
              matchEnd: match.index + match[0].length,
              textLength: text.length,
              action,
              description: `Encoding bypass: Base64-encoded text contains injection keyword "${keyword}"`,
            });
            break; // One event per base64 block
          }
        }
      } catch {
        // Invalid base64 — skip
      }
    }

    return events;
  }
}
