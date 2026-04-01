/**
 * Tool result validation — intent-to-result matching.
 *
 * After a tool executes, this module checks whether the result contains
 * data that doesn't match the user's stated intent. Uses PII category
 * sets from the obfuscator — no LLM, no content inspection, just
 * comparing "what categories appeared" vs "what the user asked for".
 *
 * Four heuristics:
 * 1. Category escalation: high-sensitivity PII in non-read tool results
 * 2. Exfil chain: PII-containing results followed by communication/network tools
 * 3. Bulk sensitive: large results with many PII categories from exec/network
 * 4. Baseline deviation: PII categories outside the agent's learned profile
 */

import type { SecurityEvent, SecuritySeverity } from "../security-event.js";
import { ThreatClass } from "../security-event.js";
import type { Category } from "../types.js";
import type { IntentSignals } from "./tool-intent.js";
import { ToolCategory, TOOL_CATEGORIES } from "./tool-intent.js";
import type { AgentBaseline } from "../profiler-types.js";

/** High-sensitivity PII categories that warrant extra scrutiny. */
const HIGH_SENSITIVITY: Set<string> = new Set([
  "ssn", "credit_card", "api_key", "jwt", "certificate",
  "network_credential", "iban", "national_id", "snmp_community",
]);

/** Regex for user messages that explicitly mention credentials/secrets. (Unused — using intent.mentionsCredentials instead) */
const _CREDENTIAL_INTENT = /\b(?:credentials?|secrets?|api\s*keys?|passwords?|certs?|tokens?|ssn|credit.?cards?|payment|iban|ssh\s*keys?|pgp|private.?keys?|access.?keys?)\b/i;

/** Track the intent → tool call → result chain for a single turn. */
export interface TurnContext {
  /** Intent extracted from user message. */
  intent: IntentSignals;
  /** Agent baseline from profiler (if available). */
  baseline: AgentBaseline | null;
  /** Pending tool call — set in before_tool_call, consumed in tool_result_persist. */
  pendingToolCall: {
    toolName: string;
    category: ToolCategory | undefined;
    timestamp: number;
  } | null;
  /** Results from tools that ran this turn, with their PII categories. */
  toolResults: Array<{
    toolName: string;
    category: ToolCategory | undefined;
    resultCategories: Set<string>;
    resultSize: number;
  }>;
}

/** Create a fresh turn context. */
export function createTurnContext(intent: IntentSignals, baseline?: AgentBaseline | null): TurnContext {
  return { intent, baseline: baseline ?? null, pendingToolCall: null, toolResults: [] };
}

/**
 * Validate a tool result against the user's intent.
 *
 * Called in tool_result_persist after obfuscation has identified entities.
 * Returns security events for any suspicious findings.
 */
export function validateToolResult(
  ctx: TurnContext,
  resultCategories: Set<string>,
  resultSize: number,
): SecurityEvent[] {
  const events: SecurityEvent[] = [];
  const tool = ctx.pendingToolCall;
  if (!tool) return events;

  // Heuristic 1: Category escalation
  // High-sensitivity PII in results from non-read tools, when user didn't mention credentials
  if (tool.category !== ToolCategory.READ_ONLY && tool.category !== ToolCategory.WRITE_LOCAL) {
    const sensitive = intersection(resultCategories, HIGH_SENSITIVITY);
    if (sensitive.size > 0 && !ctx.intent.mentionsCredentials) {
      events.push(buildEvent(
        tool.toolName,
        "category_escalation",
        "high",
        `Tool "${tool.toolName}" returned sensitive data (${[...sensitive].join(", ")}) unrelated to user intent`,
      ));
    }
  }

  // Heuristic 3: Bulk sensitive data from exec/network tools
  if (resultSize > 10_000 && resultCategories.size > 2
      && tool.category !== ToolCategory.READ_ONLY
      && tool.category !== ToolCategory.WRITE_LOCAL) {
    events.push(buildEvent(
      tool.toolName,
      "bulk_sensitive",
      "medium",
      `Large result (${Math.round(resultSize / 1024)}KB) with ${resultCategories.size} PII categories from "${tool.toolName}"`,
    ));
  }

  // Heuristic 4: Baseline deviation — PII categories outside agent's learned profile
  // Only fires when the profiler has a mature baseline (enough session data).
  if (ctx.baseline && ctx.baseline.maturity !== "learning" && resultCategories.size > 0) {
    const knownCategories = new Set(ctx.baseline.categoryProfile);
    const novel = new Set<string>();
    for (const cat of resultCategories) {
      if (!knownCategories.has(cat)) novel.add(cat);
    }
    // Only flag if novel categories include high-sensitivity ones.
    // Non-sensitive novel categories (e.g. a new hostname format) are expected as agents evolve.
    const novelSensitive = intersection(novel, HIGH_SENSITIVITY);
    if (novelSensitive.size > 0) {
      events.push(buildEvent(
        tool.toolName,
        "baseline_deviation",
        "medium",
        `Novel sensitive categories (${[...novelSensitive].join(", ")}) not in agent's ${ctx.baseline.sessionCount}-session baseline`,
      ));
    }
  }

  return events;
}

/**
 * Check for exfil chain: a communication/network tool is about to be called,
 * and previous tool results in this turn contained PII.
 *
 * Called in before_tool_call (before execution, so we can block).
 */
export function checkExfilChain(
  ctx: TurnContext,
  toolName: string,
): SecurityEvent | null {
  const category = TOOL_CATEGORIES[toolName];
  if (!category) return null;

  // Only check communication and network tools
  if (category !== ToolCategory.COMMUNICATE && category !== ToolCategory.NETWORK) return null;

  // If user asked for communication/network, this is expected
  if (ctx.intent.wantsCommunication && category === ToolCategory.COMMUNICATE) return null;
  if (ctx.intent.wantsNetwork && category === ToolCategory.NETWORK) return null;

  // Check if any previous tool result had PII
  const prevWithPII = ctx.toolResults.filter(r => r.resultCategories.size > 0);
  if (prevWithPII.length === 0) return null;

  const allCategories = new Set<string>();
  for (const r of prevWithPII) {
    for (const c of r.resultCategories) allCategories.add(c);
  }

  return buildEvent(
    toolName,
    "exfil_chain",
    "high",
    `"${toolName}" called after tools returned PII (${[...allCategories].slice(0, 5).join(", ")}); user did not request ${category === ToolCategory.COMMUNICATE ? "communication" : "network access"}`,
  );
}

// ─── Helpers ───

function intersection(a: Set<string>, b: Set<string>): Set<string> {
  const result = new Set<string>();
  for (const item of a) {
    if (b.has(item)) result.add(item);
  }
  return result;
}

function buildEvent(
  toolName: string,
  check: string,
  severity: SecuritySeverity,
  reason: string,
): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: check === "exfil_chain" ? ThreatClass.DATA_EXFILTRATION : ThreatClass.MCP_TOOL_POISONING,
    signatureId: `rv_${check}`,
    severity,
    matchedText: `${toolName}: ${reason.slice(0, 100)}`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action: "flagged",
    description: reason,
  };
}
