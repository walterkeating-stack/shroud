/**
 * Tool intent matching — behavioral guardrails for LLM tool calls.
 *
 * Instead of inspecting tool call content for injection patterns (which has
 * fundamental limits), this module watches WHICH tools the LLM calls and
 * whether they match the user's stated intent.
 *
 * Three checks:
 * 1. Intent alignment: does the tool match what the user asked for?
 * 2. Egress detection: is the LLM trying to send data somewhere?
 * 3. Sequence anomaly: is the tool call pattern unusual?
 *
 * Zero content inspection. Zero false positives from text scanning.
 * Pure behavioral analysis.
 */

import type { SecurityEvent, SecuritySeverity } from "../security-event.js";
import { ThreatClass } from "../security-event.js";

// ─── Tool categories ───

/** Tool categories by risk profile. */
export enum ToolCategory {
  READ_ONLY = "read_only",         // Read, memory_search, memory_get, browser (read), sessions_list
  WRITE_LOCAL = "write_local",     // Write, Edit
  COMMUNICATE = "communicate",     // message, sessions_send, sessions_spawn
  EXECUTE = "execute",             // exec
  NETWORK = "network",             // web_fetch, browser (navigate)
  SYSTEM = "system",               // cron, session_status
}

/** Map tool names to categories. */
const TOOL_CATEGORIES: Record<string, ToolCategory> = {
  Read: ToolCategory.READ_ONLY,
  read: ToolCategory.READ_ONLY,
  read_file: ToolCategory.READ_ONLY,
  memory_search: ToolCategory.READ_ONLY,
  memory_get: ToolCategory.READ_ONLY,
  sessions_list: ToolCategory.READ_ONLY,
  sessions_history: ToolCategory.READ_ONLY,
  session_status: ToolCategory.SYSTEM,

  Write: ToolCategory.WRITE_LOCAL,
  write: ToolCategory.WRITE_LOCAL,
  Edit: ToolCategory.WRITE_LOCAL,
  edit: ToolCategory.WRITE_LOCAL,
  write_file: ToolCategory.WRITE_LOCAL,

  message: ToolCategory.COMMUNICATE,
  sessions_send: ToolCategory.COMMUNICATE,
  sessions_spawn: ToolCategory.COMMUNICATE,

  exec: ToolCategory.EXECUTE,
  code_execution: ToolCategory.EXECUTE,
  bash: ToolCategory.EXECUTE,

  web_fetch: ToolCategory.NETWORK,
  browser: ToolCategory.NETWORK,
  fetch: ToolCategory.NETWORK,
};

// ─── Intent signals ───

/** User intent signals extracted from the message. */
export interface IntentSignals {
  /** Action verbs detected in the user's message. */
  actions: Set<string>;
  /** Tool categories the user's message implies. */
  expectedCategories: Set<ToolCategory>;
  /** Whether the user explicitly asked to send/share/communicate. */
  wantsCommunication: boolean;
  /** Whether the user explicitly asked to execute/run something. */
  wantsExecution: boolean;
  /** Whether the user explicitly asked to fetch/browse/download. */
  wantsNetwork: boolean;
  /** Domains/URLs mentioned by the user (allowlisted for egress). */
  mentionedDomains: Set<string>;
}

/** Result of checking tool alignment. */
export interface ToolAlignmentResult {
  aligned: boolean;
  severity: SecuritySeverity;
  reason: string;
  /** Threat class for security event. */
  threatClass: string;
}

/** Sequence anomaly detection result. */
export interface SequenceAnomaly {
  severity: SecuritySeverity;
  reason: string;
  pattern: string;
}

// ─── Intent extraction ───

/** Action verb patterns mapped to tool categories. */
const INTENT_PATTERNS: { pattern: RegExp; categories: ToolCategory[] }[] = [
  // Read/search patterns
  { pattern: /\b(?:read|look|check|find|search|show|list|get|fetch|pull|display|view|summarize|summarise|analyze|analyse|review|inspect)\b/i,
    categories: [ToolCategory.READ_ONLY] },
  // Write patterns
  { pattern: /\b(?:write|create|save|add|append|update|modify|change|set|put|insert)\b/i,
    categories: [ToolCategory.WRITE_LOCAL] },
  // Communication patterns
  { pattern: /\b(?:send|message|notify|tell|email|slack|post|share|forward|reply|respond|alert|ping|dm)\b/i,
    categories: [ToolCategory.COMMUNICATE] },
  // Execution patterns
  { pattern: /\b(?:run|execute|exec|start|launch|deploy|install|build|compile|test|script|command|restart|stop|kill)\b/i,
    categories: [ToolCategory.EXECUTE] },
  // Network patterns
  { pattern: /\b(?:fetch|download|browse|visit|open|navigate|scrape|crawl|api|request|http|url)\b/i,
    categories: [ToolCategory.NETWORK] },
];

/** Communication verbs that explicitly indicate the user wants to send something. */
const COMMUNICATION_VERBS = /\b(?:send|message|notify|tell|email|slack|post|share|forward|reply|respond|alert|ping|dm)\b/i;

/** Execution verbs. */
const EXECUTION_VERBS = /\b(?:run|execute|exec|launch|deploy|install|build|script|command)\b/i;

/** Network verbs. */
const NETWORK_VERBS = /\b(?:fetch|download|browse|visit|scrape|crawl)\b/i;

/** Extract domains from URLs in text. */
function extractDomains(text: string): Set<string> {
  const domains = new Set<string>();
  const urlPattern = /https?:\/\/([a-z0-9][-a-z0-9.]*[a-z0-9])/gi;
  let match;
  while ((match = urlPattern.exec(text))) {
    domains.add(match[1].toLowerCase());
  }
  return domains;
}

/**
 * Extract intent signals from a user message.
 * Lightweight — no LLM, just pattern matching on action verbs.
 */
export function extractIntentSignals(userMessage: string): IntentSignals {
  const actions = new Set<string>();
  const expectedCategories = new Set<ToolCategory>();

  for (const { pattern, categories } of INTENT_PATTERNS) {
    const match = userMessage.match(pattern);
    if (match) {
      actions.add(match[0].toLowerCase());
      for (const cat of categories) expectedCategories.add(cat);
    }
  }

  // Default: if no intent signals found, assume read-only is safe
  if (expectedCategories.size === 0) {
    expectedCategories.add(ToolCategory.READ_ONLY);
  }

  return {
    actions,
    expectedCategories,
    wantsCommunication: COMMUNICATION_VERBS.test(userMessage),
    wantsExecution: EXECUTION_VERBS.test(userMessage),
    wantsNetwork: NETWORK_VERBS.test(userMessage),
    mentionedDomains: extractDomains(userMessage),
  };
}

// ─── Alignment check ───

/**
 * Check if a tool call aligns with the user's stated intent.
 *
 * Returns aligned=true if the tool category matches what the user asked for.
 * Returns aligned=false with severity + reason if it doesn't match.
 */
export function checkToolAlignment(
  toolName: string,
  intent: IntentSignals,
): ToolAlignmentResult {
  const category = TOOL_CATEGORIES[toolName];

  // Unknown tools — can't check alignment, allow
  if (!category) {
    return { aligned: true, severity: "low", reason: "", threatClass: "" };
  }

  // Read-only tools are always allowed
  if (category === ToolCategory.READ_ONLY || category === ToolCategory.SYSTEM) {
    return { aligned: true, severity: "low", reason: "", threatClass: "" };
  }

  // Write-local is generally safe (agent's own workspace)
  if (category === ToolCategory.WRITE_LOCAL) {
    return { aligned: true, severity: "low", reason: "", threatClass: "" };
  }

  // COMMUNICATE: only if user asked to send/share
  if (category === ToolCategory.COMMUNICATE && !intent.wantsCommunication) {
    return {
      aligned: false,
      severity: "high",
      reason: `Tool "${toolName}" sends data but user did not request communication`,
      threatClass: "tool_intent_mismatch",
    };
  }

  // EXECUTE: only if user asked to run something
  if (category === ToolCategory.EXECUTE && !intent.wantsExecution) {
    // Allow exec if the user asked to "check" or "test" something (common patterns)
    if (intent.actions.has("check") || intent.actions.has("test") || intent.actions.has("build")) {
      return { aligned: true, severity: "low", reason: "", threatClass: "" };
    }
    return {
      aligned: false,
      severity: "medium",
      reason: `Tool "${toolName}" executes commands but user did not request execution`,
      threatClass: "tool_intent_mismatch",
    };
  }

  // NETWORK: only if user asked to fetch/browse
  if (category === ToolCategory.NETWORK && !intent.wantsNetwork) {
    // Allow if user's message contains a URL (implicit request)
    if (intent.mentionedDomains.size > 0) {
      return { aligned: true, severity: "low", reason: "", threatClass: "" };
    }
    return {
      aligned: false,
      severity: "medium",
      reason: `Tool "${toolName}" makes network requests but user did not request network access`,
      threatClass: "tool_intent_mismatch",
    };
  }

  return { aligned: true, severity: "low", reason: "", threatClass: "" };
}

// ─── Egress detection ───

/**
 * Check if a tool call is an egress attempt (sending data out).
 *
 * This is the critical check: if the LLM is trying to send data to a domain
 * the user didn't mention, it's potentially exfiltrating data.
 */
export function checkEgressAttempt(
  toolName: string,
  params: any,
  intent: IntentSignals,
): ToolAlignmentResult | null {
  const category = TOOL_CATEGORIES[toolName];
  if (!category) return null;

  // Communication tools: check if user asked to communicate
  if (category === ToolCategory.COMMUNICATE && !intent.wantsCommunication) {
    return {
      aligned: false,
      severity: "high",
      reason: `Potential exfiltration: "${toolName}" called without user requesting communication`,
      threatClass: "tool_egress_attempt",
    };
  }

  // Network tools: check if the target domain was mentioned by the user
  if (category === ToolCategory.NETWORK) {
    const paramStr = typeof params === "string" ? params : JSON.stringify(params || "");
    const targetDomains = extractDomains(paramStr);

    for (const domain of targetDomains) {
      // Skip if user mentioned this domain
      if (intent.mentionedDomains.has(domain)) continue;
      // Skip common safe domains
      if (/^(?:github\.com|stackoverflow\.com|npmjs\.com|google\.com|wikipedia\.org)$/.test(domain)) continue;

      return {
        aligned: false,
        severity: "high",
        reason: `Potential exfiltration: "${toolName}" targeting "${domain}" which user did not mention`,
        threatClass: "tool_egress_attempt",
      };
    }
  }

  return null;
}

// ─── Sequence anomaly detection ───

/** Tool call history entry. */
interface ToolCallEntry {
  toolName: string;
  category: ToolCategory | undefined;
  timestamp: number;
}

/**
 * Tracks tool call sequences per session and detects anomalies.
 */
export class ToolSequenceTracker {
  private _history: ToolCallEntry[] = [];
  private _maxHistory = 50;

  /** Record a tool call. */
  record(toolName: string): void {
    const category = TOOL_CATEGORIES[toolName];
    this._history.push({ toolName, category, timestamp: Date.now() });
    if (this._history.length > this._maxHistory) {
      this._history.shift();
    }
  }

  /** Check for sequence anomalies. Returns null if no anomaly. */
  checkAnomaly(): SequenceAnomaly | null {
    if (this._history.length < 3) return null;

    // Check 1: Rapid network burst — >5 network calls in 60s
    const now = Date.now();
    const recentNetwork = this._history.filter(
      e => e.category === ToolCategory.NETWORK && (now - e.timestamp) < 60_000
    );
    if (recentNetwork.length > 5) {
      const domains = new Set(recentNetwork.map(e => e.toolName));
      return {
        severity: "high",
        reason: `Rapid network burst: ${recentNetwork.length} network calls in 60s`,
        pattern: `network_burst:${recentNetwork.length}`,
      };
    }

    // Check 2: Rapid communicate burst — >3 message sends in 60s
    const recentComm = this._history.filter(
      e => e.category === ToolCategory.COMMUNICATE && (now - e.timestamp) < 60_000
    );
    if (recentComm.length > 3) {
      return {
        severity: "high",
        reason: `Rapid communication burst: ${recentComm.length} sends in 60s`,
        pattern: `comm_burst:${recentComm.length}`,
      };
    }

    // Check 3: Read → exec → communicate pattern (classic exfil chain)
    const last3 = this._history.slice(-3);
    if (last3.length === 3 &&
        last3[0].category === ToolCategory.READ_ONLY &&
        last3[1].category === ToolCategory.EXECUTE &&
        last3[2].category === ToolCategory.COMMUNICATE) {
      return {
        severity: "medium",
        reason: "Suspicious sequence: read → execute → communicate (potential exfil chain)",
        pattern: "read_exec_comm",
      };
    }

    // Check 4: Read → network pattern (data grab + send)
    if (last3.length >= 2) {
      const lastTwo = this._history.slice(-2);
      if (lastTwo[0].category === ToolCategory.READ_ONLY &&
          lastTwo[1].category === ToolCategory.NETWORK) {
        // Only flag if we haven't seen this pattern before (first occurrence is often legitimate)
        const prevReadNetwork = this._history.slice(0, -2).filter(
          (e, i, arr) => e.category === ToolCategory.READ_ONLY && arr[i + 1]?.category === ToolCategory.NETWORK
        );
        if (prevReadNetwork.length > 0) {
          return {
            severity: "medium",
            reason: "Repeated read → network pattern (potential data exfiltration)",
            pattern: "repeated_read_network",
          };
        }
      }
    }

    return null;
  }

  /** Reset sequence history (e.g. on new turn). */
  reset(): void {
    this._history.length = 0;
  }

  /** Get current history length. */
  get length(): number {
    return this._history.length;
  }
}

// ─── Security event builder ───

/** Build a security event from a tool intent check result. */
export function buildToolIntentEvent(
  toolName: string,
  result: ToolAlignmentResult | SequenceAnomaly,
  action: "flagged" | "blocked" = "flagged",
): SecurityEvent {
  const isAlignment = "aligned" in result;
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: (isAlignment ? (result as ToolAlignmentResult).threatClass : "tool_sequence_anomaly") as ThreatClass,
    signatureId: isAlignment
      ? `ti_${(result as ToolAlignmentResult).threatClass}`
      : `ti_${(result as SequenceAnomaly).pattern}`,
    severity: result.severity,
    matchedText: `${toolName}: ${result.reason.slice(0, 100)}`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action,
    description: result.reason,
  };
}
