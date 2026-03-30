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
      };
      this._sessions.set(buildId, session);
    }

    return session;
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
 * Changes when system prompt, plugins, or model change.
 * Excludes dynamic files (MEMORY.md) to avoid constant invalidation.
 */
export function computeBuildId(
  systemPrompt: string,
  pluginList: string[],
  modelId: string,
): string {
  const components = [
    systemPrompt,
    pluginList.sort().join(","),
    modelId,
  ];
  return createHash("sha256")
    .update(components.join("\n"))
    .digest("hex")
    .slice(0, 16);
}

/** Extract a human-readable label from system prompt (first meaningful line, max 60 chars). */
function extractLabel(systemPrompt: string): string {
  const firstLine = systemPrompt
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.length > 5 && !l.startsWith("#") && !l.startsWith("<!--"));
  if (!firstLine) return "unknown-agent";
  return firstLine.length > 60 ? firstLine.slice(0, 57) + "..." : firstLine;
}
