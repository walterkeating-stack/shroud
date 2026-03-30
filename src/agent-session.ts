/**
 * Agent session tracking — maps LLM API calls to local agent identities.
 *
 * Each agent has a unique identity derived from its system prompt, plugin set,
 * and model. This module tracks which agent is making each LLM call, enabling:
 * - Per-agent WAF rules (different injection policies per agent)
 * - Per-agent behavioural baselines (Track 3)
 * - Per-agent canary attribution (Track 2)
 * - Multi-agent session correlation
 */

import { createHash } from "node:crypto";

/** Represents a tracked agent session. */
export interface AgentSession {
  /** Stable identity hash: SHA256(systemPrompt + pluginList + modelId). */
  agentBuildId: string;
  /** Human-readable label extracted from system prompt (first 60 chars). */
  agentLabel: string;
  /** Session-scoped unique ID. */
  sessionId: string;
  /** When this session was first seen. */
  startedAt: number;
  /** Total LLM API calls made by this agent session. */
  llmCallCount: number;
  /** Total security events attributed to this agent. */
  securityEventCount: number;
  /** Last LLM call timestamp. */
  lastCallAt: number;
  /** LLM model ID detected from API calls (e.g. "claude-3-opus", "gpt-4"). */
  detectedModel: string;
  /** Channel source if detected (e.g. "slack:C00000001", "whatsapp:+353..."). */
  channelSource: string;
}

/**
 * Tracks agent sessions and maps LLM calls to agent identities.
 * One instance shared via globalThis across all plugin loads.
 */
export class AgentSessionTracker {
  /** Active sessions keyed by agentBuildId. */
  private _sessions: Map<string, AgentSession> = new Map();
  /** Current active agent (set by before_prompt_build). */
  private _currentBuildId = "";

  /**
   * Register or update an agent session from system prompt content.
   * Called from before_prompt_build when we have the system prompt.
   */
  registerAgent(
    systemPrompt: string,
    pluginList: string[] = [],
    modelId = "unknown",
  ): AgentSession {
    const buildId = computeBuildId(systemPrompt, pluginList, modelId);
    this._currentBuildId = buildId;

    let session = this._sessions.get(buildId);
    if (!session) {
      session = {
        agentBuildId: buildId,
        agentLabel: extractLabel(systemPrompt),
        sessionId: createHash("sha256")
          .update(`${buildId}:${Date.now()}:${Math.random()}`)
          .digest("hex")
          .slice(0, 12),
        startedAt: Date.now(),
        llmCallCount: 0,
        securityEventCount: 0,
        lastCallAt: Date.now(),
        detectedModel: modelId,
        channelSource: "",
      };
      this._sessions.set(buildId, session);
    }

    return session;
  }

  /** Update detected model from LLM API request body. */
  updateModel(model: string): void {
    const session = this._sessions.get(this._currentBuildId);
    if (session && model) {
      session.detectedModel = model;
    }
  }

  /** Update channel source (e.g. "slack:C00000001"). */
  updateChannel(source: string): void {
    const session = this._sessions.get(this._currentBuildId);
    if (session && source) {
      session.channelSource = source;
    }
  }

  /** Record an LLM API call for the current agent. */
  recordLlmCall(): AgentSession | null {
    const session = this._sessions.get(this._currentBuildId);
    if (session) {
      session.llmCallCount++;
      session.lastCallAt = Date.now();
    }
    return session ?? null;
  }

  /** Record a security event for the current agent. */
  recordSecurityEvent(count = 1): void {
    const session = this._sessions.get(this._currentBuildId);
    if (session) {
      session.securityEventCount += count;
    }
  }

  /** Get the current active agent session. */
  getCurrentSession(): AgentSession | null {
    return this._sessions.get(this._currentBuildId) ?? null;
  }

  /** Get the current agent build ID. */
  getCurrentBuildId(): string {
    return this._currentBuildId;
  }

  /** Get all tracked agent sessions. */
  getAllSessions(): AgentSession[] {
    return [...this._sessions.values()];
  }

  /** Get session by build ID. */
  getSession(buildId: string): AgentSession | null {
    return this._sessions.get(buildId) ?? null;
  }

  /** Reset all session tracking. */
  reset(): void {
    this._sessions.clear();
    this._currentBuildId = "";
  }
}

/**
 * Compute a stable agent build ID.
 *
 * Uses a "skeleton" of the system prompt rather than the full text.
 * This makes the ID resilient to:
 * - Dynamic timestamps, dates, session IDs injected into prompts
 * - User names or account-specific context
 * - Retrieved RAG snippets appended to the base prompt
 * - Minor wording tweaks during prompt iteration
 *
 * The skeleton is: first 500 chars of the prompt with numbers, dates,
 * emails, UUIDs, and hex strings normalized to placeholders.
 */
export function computeBuildId(
  systemPrompt: string,
  pluginList: string[],
  modelId: string,
): string {
  const skeleton = extractPromptSkeleton(systemPrompt);
  const components = [
    skeleton,
    pluginList.sort().join(","),
    modelId,
  ];
  return createHash("sha256")
    .update(components.join("\n"))
    .digest("hex")
    .slice(0, 16);
}

/**
 * Extract a stable "skeleton" from a system prompt by normalizing
 * dynamic content to placeholders.
 *
 * Normalizes: timestamps, dates, numbers >4 digits, emails, UUIDs,
 * hex strings >8 chars, IP addresses, URLs with path components.
 * Keeps: the structural words, role definitions, tool descriptions,
 * behavioral instructions — the parts that define the agent's identity.
 */
export function extractPromptSkeleton(prompt: string): string {
  let s = prompt;

  // Take first 2000 chars — the core identity is always at the top.
  // Appended RAG context, memory, or conversation history at the end
  // should not affect the identity.
  s = s.slice(0, 2000);

  // Normalize dynamic content to stable placeholders
  s = s.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<UUID>"); // UUIDs
  s = s.replace(/\b\d{4}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g, "<DATE>"); // ISO dates
  s = s.replace(/\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?\b/g, "<TIME>"); // times
  s = s.replace(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, "<EMAIL>"); // emails
  s = s.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "<IP>"); // IPs
  s = s.replace(/\b[0-9a-f]{12,}\b/gi, "<HEX>"); // long hex strings
  s = s.replace(/\b\d{5,}\b/g, "<NUM>"); // numbers > 4 digits
  s = s.replace(/https?:\/\/[^\s<>"']+/g, "<URL>"); // URLs

  // Collapse whitespace
  s = s.replace(/\s+/g, " ").trim();

  return s;
}

/**
 * Extract a short, snappy agent name from system prompt.
 *
 * Looks for "You are a/an [ROLE]" pattern, then distills to the core role.
 * "network security researcher at a managed security services provider" → "Security Researcher"
 */
function extractLabel(systemPrompt: string): string {
  // Try to extract role from "You are a/an [role]" pattern
  const roleMatch = systemPrompt.match(
    /[Yy]ou\s+are\s+(?:a|an)\s+(.+?)(?:\.|,|\n|$)/,
  );
  if (roleMatch) {
    let role = roleMatch[1].trim();
    // Shorten: strip "at/for/who/that..." clauses
    role = role.replace(/\s+(?:at|for|who|that|which|specializing|working|based)\s+.*/i, "");
    // Title case
    role = role.replace(/\b\w/g, (c) => c.toUpperCase());
    if (role.length > 3 && role.length < 50) return role;
  }

  // Fallback: first meaningful line, shortened
  const firstLine = systemPrompt
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.length > 5 && !l.startsWith("#") && !l.startsWith("<!--"));
  if (!firstLine) return "Unknown Agent";
  const short = firstLine.replace(/\s+(?:at|for|who|that|which)\s+.*/i, "");
  return short.length > 40 ? short.slice(0, 37) + "..." : short;
}
