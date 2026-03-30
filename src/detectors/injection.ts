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
 * Check if a text span is inside quotation marks, backticks, or code blocks.
 * Used to reduce severity of injection patterns that are being discussed/quoted
 * rather than used as actual attacks.
 */
function isInsideQuotes(text: string, matchStart: number, matchEnd: number): boolean {
  // Look backwards from matchStart for an unmatched opening quote
  const before = text.slice(Math.max(0, matchStart - 200), matchStart);
  const after = text.slice(matchEnd, Math.min(text.length, matchEnd + 200));

  // Check for surrounding double quotes
  if (before.includes('"') && after.includes('"')) {
    const lastQuoteBefore = before.lastIndexOf('"');
    const quotesBefore = before.slice(lastQuoteBefore).split('"').length - 1;
    if (quotesBefore % 2 === 1) return true; // odd number = inside quotes
  }

  // Check for surrounding single quotes
  if (before.includes("'") && after.includes("'")) {
    const lastQuoteBefore = before.lastIndexOf("'");
    const quotesBefore = before.slice(lastQuoteBefore).split("'").length - 1;
    if (quotesBefore % 2 === 1) return true;
  }

  // Check for backticks (inline code)
  if (before.includes("`") && after.includes("`")) return true;

  // Check for parenthetical context: (DAN), (XSS), etc.
  // The match might include the closing paren, so check if before ends with (
  // or the matched text itself starts right after a (
  if (before.endsWith("(")) return true;
  if (before.trimEnd().endsWith("(")) return true;

  // Check for 'like "X"' or 'such as "X"' or 'phrases like "X"' patterns
  // These indicate the text is being discussed, not executed
  const discussionPatterns = /(?:like|such\s+as|example|e\.g\.|called|known\s+as|termed|phrase|pattern|classified|documented|described|first\s+appeared)/i;
  if (discussionPatterns.test(before.slice(-100))) return true;

  return false;
}

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
        // Skip OpenClaw system context: "System: [2026-03-30 10:11:29 GMT+2]"
        // This is structural metadata, not a conversation mockup injection.
        if (sig.id === "cm_role_markers") {
          const after = text.slice(match.index + match[0].length - 1, match.index + match[0].length + 30);
          if (/^\[\d{4}-\d{2}-\d{2}/.test(after)) continue;
        }

        // Context-aware severity reduction: if the match is inside
        // quotation marks or backticks, it's likely being discussed/quoted
        // rather than used as an attack. Reduce severity to "low".
        let severity = sig.severity;
        if (isInsideQuotes(text, match.index, match.index + match[0].length)) {
          severity = "low";
        }

        events.push({
          timestamp: Date.now(),
          eventType: "injection_detected",
          direction,
          threatClass: sig.threatClass,
          signatureId: sig.id,
          severity,
          matchedText: match[0].slice(0, 200),
          matchStart: match.index,
          matchEnd: match.index + match[0].length,
          textLength: text.length,
          action,
          description: severity !== sig.severity
            ? `[quoted context] ${sig.description}`
            : sig.description,
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
