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
import { existsSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

/** A logged LLM API call. */
export interface LlmCallRecord {
  timestamp: number;
  agentLabel: string;
  url: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  cacheHitPct: number;
  responseTimeMs: number;
  channel: string;
  securityEvents: number;
  /** Why the call was made (slack message, heartbeat, cron, tool call, etc.) */
  reason: string;
}

/** Agent role classification derived from name, channel, and behaviour. */
export interface AgentClassification {
  /** Primary role category. */
  role: string;
  /** Confidence percentage (0-100). */
  confidencePct: number;
  /** Confidence tier for display. */
  confidence: "high" | "medium" | "low";
  /** Colour code for dashboard rendering. */
  colour: string;
  /** Keywords that triggered the classification. */
  signals: string[];
}

/** Agent health and behavioural compliance status. */
export interface AgentHealth {
  /** Overall health: "healthy", "warning", "critical". */
  status: "healthy" | "warning" | "critical";
  /** Health colour for dashboard. */
  colour: string;
  /** Is the agent behaving according to its classification? */
  compliant: boolean;
  /** Compliance detail messages. */
  issues: string[];
  /** Last active relative indicator. */
  lastActiveAgo: string;
  /** Security event rate per 100 calls. */
  eventRate: number;
}

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
  /** Inferred role classification. */
  classification: AgentClassification;
  /** Tool names available to the agent (from body.tools). */
  toolInventory: string[];
  /** SOUL.md extract — agent's core identity/instructions from early messages. */
  soulExtract: string;
  /** Per-agent LLM cache stats. */
  cache: AgentCacheStats;
  /** Active channels this agent has been seen on. */
  channels: string[];
  /** Heartbeat tracking. */
  heartbeat: AgentHeartbeat;
  /** Accumulated behavioral profile for archetype mapping. */
  behavior: AgentBehaviorProfile;
  /** Per-agent obfuscation/deobfuscation stats. */
  privacy: AgentPrivacyStats;
}

/** Per-agent obfuscation and deobfuscation counters. */
export interface AgentPrivacyStats {
  /** Number of obfuscation calls attributed to this agent. */
  obfuscationCalls: number;
  /** Number of deobfuscation calls attributed to this agent. */
  deobfuscationCalls: number;
  /** Total entities obfuscated. */
  entitiesObfuscated: number;
  /** Total replacements deobfuscated. */
  replacementsDeobfuscated: number;
  /** Per-category entity counts (category → count). */
  categoryCounts: Record<string, number>;
}

/** Per-agent heartbeat tracking. */
export interface AgentHeartbeat {
  /** Whether heartbeat has been detected for this agent. */
  enabled: boolean;
  /** Timestamps of recent heartbeats (last 10). */
  recent: number[];
  /** Average interval between heartbeats (ms). -1 if not enough data. */
  avgIntervalMs: number;
  /** Last heartbeat timestamp. */
  lastAt: number;
  /** Status: "alive", "stale" (2x interval missed), "dead" (5x missed). */
  status: "alive" | "stale" | "dead" | "unknown";
  /** Last heartbeat response (HEARTBEAT_OK or alert text). */
  lastResponse: string;
}

/** Accumulated behavioral signals for archetype mapping. */
export interface AgentBehaviorProfile {
  /** Tool call frequency map: tool name -> call count. */
  toolFrequency: Record<string, number>;
  /** Total tool calls tracked. */
  totalToolCalls: number;
  /** Running average similarity score from drift checks (0-1, EMA alpha=0.2). */
  avgSimilarity: number;
  /** Count of drift checks performed. */
  driftCheckCount: number;
  /** Recent similarity scores (last 20, for per-agent sparkline). */
  recentSimilarities: number[];
  /** Derived behavioral archetype (computed from tool patterns). */
  archetype: string;
  /** Archetype confidence (0-100). */
  archetypeConfidence: number;
}

/** Per-agent LLM cache tracking for anomaly detection. */
export interface AgentCacheStats {
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCacheRead: number;
  totalCacheWrite: number;
  /** Running average cache hit ratio (0-1). */
  avgHitRatio: number;
  /** Baseline hit ratio (from first N calls). -1 if not established. */
  baselineHitRatio: number;
  /** Number of calls contributing to the baseline. */
  baselineSamples: number;
  /** Number of calls with cache data. */
  callsWithCache: number;
}

/** Default behavior profile for new agents. */
const DEFAULT_BEHAVIOR: AgentBehaviorProfile = {
  toolFrequency: {}, totalToolCalls: 0,
  avgSimilarity: 1.0, driftCheckCount: 0,
  recentSimilarities: [], archetype: "Unknown",
  archetypeConfidence: 0,
};

/**
 * Tracks agent sessions and maps LLM calls to agent identities.
 * One instance shared via globalThis across all plugin loads.
 */
export class AgentSessionTracker {
  /** Active sessions keyed by agent label (the stable identity). */
  private _sessions: Map<string, AgentSession> = new Map();
  /** Current active agent label. */
  private _currentLabel = "";
  /** LLM call log (ring buffer, last 200 calls). */
  private _callLog: LlmCallRecord[] = [];
  /** Timestamp when the current LLM call started (for response time). */
  private _callStartTime = 0;

  /**
   * Register or update an agent session from system prompt content.
   *
   * Identity strategy: the extracted LABEL is the primary key, not the
   * prompt skeleton hash. System prompts contain too much dynamic content
   * (conversation context, RAG, tool results) to produce stable hashes.
   * The label — extracted from "- Name: X", "You are X", etc. — is the
   * stable identity that humans recognise.
   *
   * The buildId is still computed for fingerprinting but is NOT used as
   * the session key.
   */
  registerAgent(
    systemPrompt: string,
    pluginList: string[] = [],
    modelId = "unknown",
    strict = false,
    registryName?: string,
  ): AgentSession {
    // Registry-resolved name takes priority over regex extraction
    const label = registryName || (strict ? extractLabelStrict(systemPrompt) : extractLabel(systemPrompt));
    const buildId = computeBuildId(systemPrompt, pluginList, modelId, label);
    const key = normalizeLabel(label);

    // Don't create sessions for unidentifiable prompts
    if (label === "Unknown Agent") {
      // Still set current label so calls get tracked somewhere
      this._currentLabel = key;
      // Return a transient session that won't be persisted
      return this._sessions.get(key) || {
        agentBuildId: buildId, agentLabel: label, sessionId: "transient",
        startedAt: Date.now(), llmCallCount: 0, securityEventCount: 0,
        lastCallAt: Date.now(), detectedModel: modelId, channelSource: "",
        classification: { role: "Unknown", confidencePct: 0, confidence: "low", colour: "#484f58", signals: [] },
        toolInventory: [], soulExtract: "",
        cache: { totalInputTokens: 0, totalOutputTokens: 0, totalCacheRead: 0, totalCacheWrite: 0, avgHitRatio: 0, baselineHitRatio: -1, baselineSamples: 0, callsWithCache: 0 },
        channels: [],
        heartbeat: { enabled: false, recent: [], avgIntervalMs: -1, lastAt: 0, status: "unknown", lastResponse: "" },
        behavior: { ...DEFAULT_BEHAVIOR, toolFrequency: {} },
        privacy: { obfuscationCalls: 0, deobfuscationCalls: 0, entitiesObfuscated: 0, replacementsDeobfuscated: 0, categoryCounts: {} },
      };
    }

    this._currentLabel = key;

    let session = this._sessions.get(key);
    if (!session) {
      session = {
        agentBuildId: buildId,
        agentLabel: label,
        sessionId: createHash("sha256")
          .update(`${label}:${Date.now()}:${Math.random()}`)
          .digest("hex")
          .slice(0, 12),
        startedAt: Date.now(),
        llmCallCount: 0,
        securityEventCount: 0,
        lastCallAt: Date.now(),
        detectedModel: modelId,
        channelSource: "",
        classification: classifyAgent(label, systemPrompt),
        toolInventory: [],
        soulExtract: "",
        cache: {
          totalInputTokens: 0, totalOutputTokens: 0,
          totalCacheRead: 0, totalCacheWrite: 0,
          avgHitRatio: 0, baselineHitRatio: -1,
          baselineSamples: 0, callsWithCache: 0,
        },
        channels: [],
        heartbeat: {
          enabled: false, recent: [], avgIntervalMs: -1,
          lastAt: 0, status: "unknown", lastResponse: "",
        },
        behavior: { ...DEFAULT_BEHAVIOR, toolFrequency: {} },
        privacy: { obfuscationCalls: 0, deobfuscationCalls: 0, entitiesObfuscated: 0, replacementsDeobfuscated: 0, categoryCounts: {} },
      };
      this._sessions.set(key, session);
    } else {
      // Update build ID to latest (prompt may evolve, label stays stable)
      session.agentBuildId = buildId;
      // Ensure privacy stats exist for sessions created before this field existed
      if (!session.privacy) {
        session.privacy = { obfuscationCalls: 0, deobfuscationCalls: 0, entitiesObfuscated: 0, replacementsDeobfuscated: 0, categoryCounts: {} };
      }
    }

    return session;
  }

  /** Update detected model from LLM API request body. */
  updateModel(model: string): void {
    const session = this._sessions.get(this._currentLabel);
    if (session && model) {
      session.detectedModel = model;
    }
  }

  /** Update channel source (e.g. "slack:C00000001"). Normalizes to base type. */
  updateChannel(source: string): void {
    const session = this._sessions.get(this._currentLabel);
    if (!session || !source) return;

    session.channelSource = source;

    // Normalize: "slack:C00000001" → "slack", "whatsapp:direct" → "whatsapp", etc.
    const normalized = source.split(":")[0].toLowerCase();
    const channelType = normalized === "tui" ? "tui"
      : normalized === "slack" ? "slack"
      : normalized === "whatsapp" ? "whatsapp"
      : normalized === "cron" ? "cron"
      : normalized === "api" ? "api"
      : normalized;

    if (!session.channels.includes(channelType)) {
      session.channels.push(channelType);
    }
  }

  /**
   * Update per-agent cache stats from an LLM response.
   * Returns anomaly alerts if cache behaviour deviates from baseline.
   */
  updateCache(usage: {
    inputTokens: number; outputTokens: number;
    cacheReadTokens: number; cacheWriteTokens: number;
  }): { alert: string; severity: "medium" | "high" } | null {
    const session = this._sessions.get(this._currentLabel);
    if (!session || usage.inputTokens === 0) return null;

    const c = session.cache;
    c.totalInputTokens += usage.inputTokens;
    c.totalOutputTokens += usage.outputTokens;
    c.totalCacheRead += usage.cacheReadTokens;
    c.totalCacheWrite += usage.cacheWriteTokens;
    c.callsWithCache++;

    const hitRatio = usage.inputTokens > 0
      ? usage.cacheReadTokens / usage.inputTokens : 0;

    // Running average (exponential moving average, alpha=0.3)
    c.avgHitRatio = c.callsWithCache === 1
      ? hitRatio
      : c.avgHitRatio * 0.7 + hitRatio * 0.3;

    // Establish baseline from first 5 calls
    const BASELINE_WINDOW = 5;
    if (c.baselineSamples < BASELINE_WINDOW) {
      c.baselineSamples++;
      c.baselineHitRatio = c.baselineSamples === 1
        ? hitRatio
        : ((c.baselineHitRatio * (c.baselineSamples - 1)) + hitRatio) / c.baselineSamples;
      return null; // Still learning baseline
    }

    // Anomaly detection: compare current ratio to baseline
    // 1. Cache ratio drop >30% — possible prompt injection/tampering
    if (c.baselineHitRatio > 0.3 && hitRatio < c.baselineHitRatio * 0.5) {
      return {
        alert: `Cache hit ratio dropped to ${Math.round(hitRatio * 100)}% (baseline: ${Math.round(c.baselineHitRatio * 100)}%) — possible system prompt change`,
        severity: "high",
      };
    }

    // 2. Zero cache hits when baseline expects them
    if (c.baselineHitRatio > 0.5 && hitRatio === 0) {
      return {
        alert: `Zero cache hits (baseline: ${Math.round(c.baselineHitRatio * 100)}%) — system prompt may have been replaced`,
        severity: "high",
      };
    }

    // 3. Unusual cache write spike (>3x baseline write ratio)
    const baselineWriteRatio = c.totalCacheWrite / Math.max(1, c.totalInputTokens - usage.inputTokens);
    const currentWriteRatio = usage.cacheWriteTokens / Math.max(1, usage.inputTokens);
    if (c.callsWithCache > BASELINE_WINDOW && baselineWriteRatio > 0 && currentWriteRatio > baselineWriteRatio * 3) {
      return {
        alert: `Cache write spike: ${Math.round(currentWriteRatio * 100)}% of input (baseline: ${Math.round(baselineWriteRatio * 100)}%) — possible prompt stuffing`,
        severity: "medium",
      };
    }

    return null;
  }

  /** Record a heartbeat for the current agent. Returns alert if missed. */
  recordHeartbeat(response?: string): { alert: string; severity: "medium" | "high" } | null {
    const session = this._sessions.get(this._currentLabel);
    if (!session) return null;

    const hb = session.heartbeat;
    const now = Date.now();
    hb.enabled = true;
    hb.lastAt = now;
    hb.lastResponse = (response || "").slice(0, 200);
    hb.recent.push(now);
    if (hb.recent.length > 10) hb.recent.shift();
    hb.status = "alive";

    // Calculate average interval from recent timestamps
    if (hb.recent.length >= 3) {
      let totalGap = 0;
      for (let i = 1; i < hb.recent.length; i++) {
        totalGap += hb.recent[i] - hb.recent[i - 1];
      }
      hb.avgIntervalMs = totalGap / (hb.recent.length - 1);
    }

    // Check if response is an alert (not HEARTBEAT_OK)
    if (response && !response.includes("HEARTBEAT_OK") && response.trim().length > 5) {
      return {
        alert: `Heartbeat alert from ${session.agentLabel}: ${response.slice(0, 150)}`,
        severity: "medium",
      };
    }

    return null;
  }

  /** Check all agents for missed heartbeats. Call periodically. */
  checkHeartbeatHealth(): Array<{ agentLabel: string; status: string; alert: string }> {
    const alerts: Array<{ agentLabel: string; status: string; alert: string }> = [];
    const now = Date.now();

    for (const session of this._sessions.values()) {
      const hb = session.heartbeat;
      if (!hb.enabled || hb.avgIntervalMs <= 0) continue;

      const sinceLastHb = now - hb.lastAt;
      const prevStatus = hb.status;

      if (sinceLastHb > hb.avgIntervalMs * 5) {
        hb.status = "dead";
      } else if (sinceLastHb > hb.avgIntervalMs * 2) {
        hb.status = "stale";
      } else {
        hb.status = "alive";
      }

      // Alert on status transitions
      if (hb.status !== prevStatus && hb.status !== "alive") {
        alerts.push({
          agentLabel: session.agentLabel,
          status: hb.status,
          alert: `${session.agentLabel} heartbeat ${hb.status} — last seen ${Math.round(sinceLastHb / 60000)}m ago (expected every ${Math.round(hb.avgIntervalMs / 60000)}m)`,
        });
      }
    }

    return alerts;
  }

  /** Detect and record the channel from prompt metadata. */
  updateChannelFromPrompt(prompt: string): string | null {
    const session = this._sessions.get(this._currentLabel);
    if (!session) return null;
    const ch = detectChannel(prompt);
    if (ch && !session.channels.includes(ch)) {
      session.channels.push(ch);
    }
    return ch;
  }

  /** Update tool inventory from body.tools array. Only sets once (first call). */
  updateTools(tools: string[]): void {
    const session = this._sessions.get(this._currentLabel);
    if (session && tools.length > 0 && session.toolInventory.length === 0) {
      session.toolInventory = tools;
      // Re-classify with tool data for better accuracy
      session.classification = classifyAgentWithTools(
        session.agentLabel, "", session.toolInventory,
      );
    }
  }

  /** Record a tool call for behavioral archetype tracking. */
  recordToolCall(toolName: string, similarity?: number): void {
    const session = this._sessions.get(this._currentLabel);
    if (!session) return;
    const b = session.behavior;
    b.toolFrequency[toolName] = (b.toolFrequency[toolName] || 0) + 1;
    b.totalToolCalls++;
    if (similarity !== undefined) {
      b.driftCheckCount++;
      b.avgSimilarity = b.driftCheckCount === 1
        ? similarity
        : b.avgSimilarity * 0.8 + similarity * 0.2; // EMA
      b.recentSimilarities.push(similarity);
      if (b.recentSimilarities.length > 20) b.recentSimilarities.shift();
    }
    const result = computeArchetype(b);
    b.archetype = result.name;
    b.archetypeConfidence = result.confidence;
  }

  /** Update SOUL extract from early messages. Only sets once. Skips framework preamble. */
  updateSoul(soul: string): void {
    const session = this._sessions.get(this._currentLabel);
    if (session && soul && !session.soulExtract) {
      // Strip framework preamble lines — they're OpenClaw boilerplate, not the agent's identity
      const cleaned = soul.split("\n").filter(line => {
        const trimmed = line.trim().toLowerCase();
        return !FRAMEWORK_PREAMBLES.some(p => trimmed.startsWith(p));
      }).join("\n").trim();
      if (!cleaned || cleaned.length < 10) return;
      session.soulExtract = cleaned.slice(0, 500);
      // Re-classify with SOUL data
      session.classification = classifyAgentWithTools(
        session.agentLabel, session.soulExtract, session.toolInventory,
      );
    }
  }

  /** Record an LLM API call for the current agent. */
  recordLlmCall(): AgentSession | null {
    const session = this._sessions.get(this._currentLabel);
    if (session) {
      session.llmCallCount++;
      session.lastCallAt = Date.now();
    }
    return session ?? null;
  }

  /** Record a security event for the current agent. */
  recordSecurityEvent(count = 1): void {
    const session = this._sessions.get(this._currentLabel);
    if (session) {
      session.securityEventCount += count;
    }
  }

  /** Record obfuscation stats for the current agent. */
  recordObfuscation(entityCount: number, categories?: Record<string, number>): void {
    const session = this._sessions.get(this._currentLabel);
    if (!session) return;
    if (!session.privacy) {
      session.privacy = { obfuscationCalls: 0, deobfuscationCalls: 0, entitiesObfuscated: 0, replacementsDeobfuscated: 0, categoryCounts: {} };
    }
    session.privacy.obfuscationCalls++;
    session.privacy.entitiesObfuscated += entityCount;
    if (categories) {
      for (const [cat, count] of Object.entries(categories)) {
        session.privacy.categoryCounts[cat] = (session.privacy.categoryCounts[cat] || 0) + count;
      }
    }
  }

  /** Record deobfuscation stats for the current agent. */
  recordDeobfuscation(replacementCount: number): void {
    const session = this._sessions.get(this._currentLabel);
    if (!session) return;
    if (!session.privacy) {
      session.privacy = { obfuscationCalls: 0, deobfuscationCalls: 0, entitiesObfuscated: 0, replacementsDeobfuscated: 0, categoryCounts: {} };
    }
    session.privacy.deobfuscationCalls++;
    session.privacy.replacementsDeobfuscated += replacementCount;
  }

  /** Get the current active agent session. */
  getCurrentSession(): AgentSession | null {
    return this._sessions.get(this._currentLabel) ?? null;
  }

  /** Get the current agent build ID. */
  getCurrentBuildId(): string {
    const session = this._sessions.get(this._currentLabel);
    return session?.agentBuildId ?? "";
  }

  /** Get all tracked agent sessions. */
  getAllSessions(): AgentSession[] {
    return [...this._sessions.values()];
  }

  /** Get session by build ID. */
  getSession(buildId: string): AgentSession | null {
    // Search by build ID (secondary key)
    for (const session of this._sessions.values()) {
      if (session.agentBuildId === buildId) return session;
    }
    return null;
  }

  /** Get session by label (primary key, case-insensitive). */
  getSessionByLabel(label: string): AgentSession | null {
    return this._sessions.get(normalizeLabel(label)) ?? null;
  }

  /** Save all sessions to a JSON file. Survives gateway restarts. */
  saveToFile(filePath: string): void {
    try {
      const data = this.getAllSessions().map(s => ({
        agentLabel: s.agentLabel,
        agentBuildId: s.agentBuildId,
        sessionId: s.sessionId,
        llmCallCount: s.llmCallCount,
        securityEventCount: s.securityEventCount,
        detectedModel: s.detectedModel,
        channels: s.channels,
        classification: s.classification,
        toolInventory: s.toolInventory,
        startedAt: s.startedAt,
        lastCallAt: s.lastCallAt,
        soulExtract: s.soulExtract,
        behavior: s.behavior,
      }));
      const dir = dirname(filePath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(filePath, JSON.stringify(data, null, 2));
    } catch { /* best-effort */ }
  }

  /** Load sessions from a JSON file (e.g. after restart). */
  loadFromFile(filePath: string): void {
    try {
      const raw = readFileSync(filePath, "utf-8");
      const data = JSON.parse(raw) as Array<Record<string, unknown>>;
      for (const entry of data) {
        const label = entry.agentLabel as string;
        if (!label) continue;
        // Filter ghost labels on load — reject invalid labels persisted before validation existed
        if (!_isValidAgentLabel(label) || label === "Unknown Agent") continue;
        const key = normalizeLabel(label);
        if (this._sessions.has(key)) continue;
        this._sessions.set(key, {
          agentLabel: label,
          agentBuildId: (entry.agentBuildId as string) || "",
          sessionId: (entry.sessionId as string) || "",
          llmCallCount: (entry.llmCallCount as number) || 0,
          channels: (entry.channels as string[]) || [],
          classification: (entry.classification as AgentClassification) || { role: "unknown", confidence: 0 },
          toolInventory: (entry.toolInventory as string[]) || [],
          startedAt: (entry.startedAt as number) || 0,
          lastCallAt: (entry.lastCallAt as number) || 0,
          securityEventCount: (entry.securityEventCount as number) || 0,
          detectedModel: (entry.detectedModel as string) || "",
          channelSource: "",
          soulExtract: (entry.soulExtract as string) || "",
          cache: { totalInputTokens: 0, totalOutputTokens: 0, totalCacheRead: 0, totalCacheWrite: 0, avgHitRatio: 0, baselineHitRatio: -1, baselineSamples: 0, callsWithCache: 0 },
          heartbeat: { enabled: false, recent: [], avgIntervalMs: -1, lastAt: 0, status: "unknown", lastResponse: "" },
          behavior: (entry.behavior as AgentBehaviorProfile) || { ...DEFAULT_BEHAVIOR, toolFrequency: {} },
          privacy: (entry as any).privacy || { obfuscationCalls: 0, deobfuscationCalls: 0, entitiesObfuscated: 0, replacementsDeobfuscated: 0, categoryCounts: {} },
        });
      }
      // Set _currentLabel to the most recently active loaded session so that
      // events emitted before the first registerAgent() call are attributed.
      if (this._sessions.size > 0 && !this._currentLabel) {
        let best = "";
        let bestTime = 0;
        for (const s of this._sessions.values()) {
          if (s.lastCallAt > bestTime) { bestTime = s.lastCallAt; best = normalizeLabel(s.agentLabel); }
        }
        if (best) this._currentLabel = best;
      }
    } catch { /* file may not exist */ }
  }

  /** Mark the start of an LLM call (for response time tracking). */
  markCallStart(): void {
    this._callStartTime = Date.now();
  }

  /** Log a completed LLM call with full details. */
  logCall(details: {
    url: string; model: string;
    inputTokens: number; outputTokens: number;
    cacheReadTokens: number; cacheWriteTokens: number;
    channel: string; securityEvents: number;
    reason: string;
  }): void {
    const hitPct = details.inputTokens > 0
      ? Math.round((details.cacheReadTokens / details.inputTokens) * 100) : 0;
    this._callLog.push({
      timestamp: Date.now(),
      agentLabel: this._currentLabel || "Unknown",
      url: details.url,
      model: details.model,
      inputTokens: details.inputTokens,
      outputTokens: details.outputTokens,
      cacheReadTokens: details.cacheReadTokens,
      cacheWriteTokens: details.cacheWriteTokens,
      cacheHitPct: hitPct,
      responseTimeMs: this._callStartTime > 0 ? Date.now() - this._callStartTime : 0,
      channel: details.channel,
      securityEvents: details.securityEvents,
      reason: details.reason,
    });
    // Ring buffer — keep last 200
    if (this._callLog.length > 200) this._callLog.shift();
    this._callStartTime = 0;
  }

  /** Get the LLM call log. */
  getCallLog(): readonly LlmCallRecord[] {
    return this._callLog;
  }

  /** Reset all session tracking. */
  reset(): void {
    this._sessions.clear();
    this._currentLabel = "";
  }
}

/**
 * Compute a stable agent build ID from the agent label.
 *
 * The label is the only stable identity — system prompts contain too much
 * dynamic content (timestamps, RAG, conversation context) to hash reliably.
 * Previous approach (prompt skeleton hash) produced 42 different build IDs
 * for ~5 agents and caused cross-agent collisions.
 *
 * One agent = one label = one build ID = one baseline file.
 */
export function computeBuildId(
  _systemPrompt: string,
  _pluginList: string[],
  _modelId: string,
  label?: string,
): string {
  // If no label provided, fall back to extracting from prompt
  const effectiveLabel = label || extractLabel(_systemPrompt);
  const normalized = normalizeLabel(effectiveLabel);
  return createHash("sha256")
    .update(normalized)
    .digest("hex")
    .slice(0, 16);
}

/**
 * Normalize an agent label for stable identity.
 * Lowercases, trims, collapses whitespace — so "SemiconAlpha Research"
 * and "Semiconalpha Research" produce the same key.
 */
export function normalizeLabel(label: string): string {
  return label.toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * OpenClaw framework preambles that must be ignored for identity extraction.
 * These match BOTH the full "You are X" form AND the captured group (after
 * "You are a/an/the" is stripped by the regex).
 */
const FRAMEWORK_PREAMBLES = [
  "you are a personal assistant running inside openclaw",
  "you are a personal assistant",
  "you are claude code",
  "personal assistant running inside openclaw",
  "personal assistant",
  "claude code",
];

/** Returns true if a "You are X" match is just the framework preamble, not the agent's real identity. */
function isFrameworkPreamble(text: string): boolean {
  const lower = text.toLowerCase().trim();
  return FRAMEWORK_PREAMBLES.some(p => lower.startsWith(p));
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

  // --- Phase 1: Strip ALL volatile/dynamic blocks ---
  // XML-tagged blocks (system-reminder, context, memory, tool results, etc.)
  s = s.replace(/<[a-z][-a-z_]*[^>]*>[\s\S]*?<\/[a-z][-a-z_]*>/gi, "");
  // OpenClaw system context prefix — per-session metadata
  s = s.replace(/^System:\s*\[.*?\].*?\n/gm, "");
  s = s.replace(/^Sender\s*\(.*?\):.*?\n/gm, "");
  s = s.replace(/^Session\s+\w+:.*?\n/gm, "");
  s = s.replace(/^Channel:.*?\n/gm, "");
  s = s.replace(/^\[.*?\]\s*$/gm, "");
  // Conversation/chat history sections and everything after
  s = s.replace(/(?:^|\n)(?:Current conversation|Recent messages|Conversation history|Chat history|# Environment|gitStatus):?\s*\n[\s\S]*/im, "");

  // --- Phase 2: Take a SHORT identity window ---
  // Agent identity is in the first few sentences. A small window avoids
  // capturing dynamic content (tools, RAG, conversation context).
  s = s.slice(0, 500);

  // --- Phase 3: Normalize dynamic tokens ---
  s = s.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<UUID>");
  s = s.replace(/\b\d{4}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g, "<DATE>");
  s = s.replace(/\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?\b/g, "<TIME>");
  s = s.replace(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, "<EMAIL>");
  s = s.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "<IP>");
  s = s.replace(/\b[0-9a-f]{7,}\b/gi, "<HEX>");
  s = s.replace(/\b\d{4,}\b/g, "<NUM>");
  s = s.replace(/https?:\/\/[^\s<>"']+/g, "<URL>");
  s = s.replace(/(?:GMT|UTC)[+-]\d{1,2}(?::\d{2})?/g, "<TZ>");
  s = s.replace(/(?:\/[\w.-]+){2,}/g, "<PATH>");

  // Collapse whitespace
  s = s.replace(/\s+/g, " ").trim();

  return s;
}

/**
 * Extract a short, snappy agent name from system prompt.
 *
 * Handles multiple formats:
 * 1. OpenClaw IDENTITY.md: "- Name: PJ" or "- Name: Coach Alessandra"
 * 2. "You are [Name/Role]" — with or without article (a/an/the)
 * 3. "- Creature: X" (OpenClaw IDENTITY.md secondary)
 * 4. "My name is [X]" / "I am [X]" / "called [X]" patterns
 * 5. Markdown heading: "# [AgentName]"
 * 6. Fallback: first meaningful line, cleaned up
 *
 * Skips OpenClaw system context prefixes (timestamps, session metadata).
 */
function extractLabel(systemPrompt: string): string {
  // Strategy: try multiple extraction approaches in order of confidence.

  // 1. OpenClaw channel/conversation label: "#agent-name" or "conversation_label"
  //    When OpenClaw sends session context, the channel name IS the agent identity.
  const channelMatch = systemPrompt.match(/"conversation_label"\s*:\s*"#?([^"]+)"/);
  if (channelMatch) {
    let name = channelMatch[1].trim();
    name = name.replace(/-(main|dev|test|staging|prod|channel|chat|bot)$/i, "");
    name = name.replace(/[-_]/g, " ");
    name = normalizeLabelForDisplay(name);
    if (name.length > 1 && name.length < 50) return name;
  }

  // 2a. Slack channel header: "Slack message in #channel-name"
  const slackChannelMatch = systemPrompt.match(/Slack\s+message\s+in\s+#([^\s]+)/i);
  if (slackChannelMatch) {
    let name = slackChannelMatch[1].trim();
    name = name.replace(/-(main|dev|test|staging|prod|channel|chat|bot)$/i, "");
    name = name.replace(/[-_]/g, " ");
    name = normalizeLabelForDisplay(name);
    if (name.length > 1 && name.length < 50) return name;
  }

  // 2b. WhatsApp: header format or metadata JSON with e164 phone number
  const waMatch = systemPrompt.match(/WhatsApp\s+(?:message|group)\s+(?:from\s+|in\s+)?["']?([^"'\n]+)/i);
  if (waMatch) {
    const name = waMatch[1].trim().replace(/\s*\(.*?\)\s*$/, "");
    if (name.length > 1 && name.length < 50) return name;
  }
  // WhatsApp direct: metadata has e164 but no channel label — use "WA: [sender]"
  const waE164 = systemPrompt.match(/"e164"\s*:\s*"\+\d+"/);
  const waSender = systemPrompt.match(/"sender"\s*:\s*"([^"]+)"/);
  if (waE164 && waSender && !systemPrompt.includes("conversation_label")) {
    return "WA " + waSender[1].trim();
  }

  // 2c. TUI / terminal: "TUI session" or "terminal session" — use agent name from session key
  //     Session keys: "agent:main:tui:..." → extract "main"
  const tuiMatch = systemPrompt.match(/(?:TUI|terminal)\s+(?:session|message)/i);
  if (tuiMatch) {
    // Try to find agent name from session key pattern in metadata
    const agentKeyMatch = systemPrompt.match(/agent:([^:]+):/);
    if (agentKeyMatch) {
      let name = agentKeyMatch[1].trim();
      name = name.split(/[-_]/).map(w =>
        w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)
      ).join(" ");
      if (name.length > 1 && name.length < 50) return name;
    }
  }

  // 3. Cron prefix: "[cron:<uuid> <agent-name>: <schedule> <description>]"
  const cronMatch = systemPrompt.match(/\[cron:[a-f0-9-]+\s+([^:]+):/);
  if (cronMatch) {
    const name = _normalizeCronAgent(cronMatch[1].trim());
    if (name && _isValidAgentLabel(name)) return name;
  }

  // 4. BOOT.md header: "# BOOT (Agent Name)" or "# BOOT (Agent Name — Alias)"
  const bootMatch = systemPrompt.match(/# BOOT \(([^)]+)\)/);
  if (bootMatch) {
    let name = bootMatch[1].trim();
    // Take the part before " — " if present (e.g. "PJ — Main Agent" → "PJ")
    if (name.includes(" — ")) name = name.split(" — ")[0].trim();
    if (name.includes(" - ")) name = name.split(" - ")[0].trim();
    if (name.length > 1 && name.length < 50 && _isValidAgentLabel(name)) return name;
  }

  // 5. Try section-based extraction (framework preamble + agent SOUL.md)
  //    Only search identity-relevant sections — never pass the full prompt
  //    as it contains user messages that can poison the label extraction.
  const sections = systemPrompt.split(/\n---+\n/);
  const candidates = sections.length > 1
    ? [sections[sections.length - 1], sections[0]]
    : [systemPrompt.slice(0, 1000)]; // Cap to identity window

  for (const text of candidates) {
    const label = _extractLabelFromText(text);
    if (label && _isValidAgentLabel(label)) return label;
  }
  return "Unknown Agent";
}

/**
 * Strict label extraction — only high-confidence identity signals.
 *
 * Used by the hook path (before_prompt_build) where event.prompt often contains
 * user messages, boot preambles, and other noise that the full extractLabel
 * would misinterpret. Strict mode only accepts:
 *   1. Channel labels (conversation_label, Slack #channel, WhatsApp)
 *   2. "- Name:" lines (IDENTITY.md)
 *   3. Cron prefix ("[cron:<uuid> <agent>: ...]")
 *   4. BOOT.md header ("# BOOT (<Agent Name>)")
 *
 * The fetch intercept uses full extractLabel as a fallback for agents that
 * don't go through hooks (e.g. direct API calls).
 */
export function extractLabelStrict(systemPrompt: string): string {
  // 1. OpenClaw channel/conversation label
  const channelMatch = systemPrompt.match(/"conversation_label"\s*:\s*"#?([^"]+)"/);
  if (channelMatch) {
    let name = channelMatch[1].trim();
    name = name.replace(/-(main|dev|test|staging|prod|channel|chat|bot)$/i, "");
    name = name.replace(/[-_]/g, " ");
    name = normalizeLabelForDisplay(name);
    if (name.length > 1 && name.length < 50) return name;
  }

  // 2a. Slack channel header
  const slackChannelMatch = systemPrompt.match(/Slack\s+message\s+in\s+#([^\s]+)/i);
  if (slackChannelMatch) {
    let name = slackChannelMatch[1].trim();
    name = name.replace(/-(main|dev|test|staging|prod|channel|chat|bot)$/i, "");
    name = name.replace(/[-_]/g, " ");
    name = normalizeLabelForDisplay(name);
    if (name.length > 1 && name.length < 50) return name;
  }

  // 2b. WhatsApp metadata
  const waMatch = systemPrompt.match(/WhatsApp\s+(?:message|group)\s+(?:from\s+|in\s+)?["']?([^"'\n]+)/i);
  if (waMatch) {
    const name = waMatch[1].trim().replace(/\s*\(.*?\)\s*$/, "");
    if (name.length > 1 && name.length < 50) return name;
  }
  const waE164 = systemPrompt.match(/"e164"\s*:\s*"\+\d+"/);
  const waSender = systemPrompt.match(/"sender"\s*:\s*"([^"]+)"/);
  if (waE164 && waSender && !systemPrompt.includes("conversation_label")) {
    return "WA " + waSender[1].trim();
  }

  // 2c. TUI / terminal
  const tuiMatch = systemPrompt.match(/(?:TUI|terminal)\s+(?:session|message)/i);
  if (tuiMatch) {
    const agentKeyMatch = systemPrompt.match(/agent:([^:]+):/);
    if (agentKeyMatch) {
      let name = agentKeyMatch[1].trim();
      name = name.split(/[-_]/).map(w =>
        w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)
      ).join(" ");
      if (name.length > 1 && name.length < 50) return name;
    }
  }

  // 3. "- Name:" from IDENTITY.md (high confidence, no ambiguity)
  const nameMatch = systemPrompt.match(/-\s*Name:\s*(.+)/i);
  if (nameMatch) {
    const name = nameMatch[1].trim();
    if (name.length > 1 && name.length < 60 && _isValidAgentLabel(name)) return name;
  }

  // 4. Cron prefix
  const cronMatch = systemPrompt.match(/\[cron:[a-f0-9-]+\s+([^:]+):/);
  if (cronMatch) {
    const name = _normalizeCronAgent(cronMatch[1].trim());
    if (name && _isValidAgentLabel(name)) return name;
  }

  // 5. BOOT.md header
  const bootMatch = systemPrompt.match(/# BOOT \(([^)]+)\)/);
  if (bootMatch) {
    let name = bootMatch[1].trim();
    if (name.includes(" — ")) name = name.split(" — ")[0].trim();
    if (name.includes(" - ")) name = name.split(" - ")[0].trim();
    if (name.length > 1 && name.length < 50 && _isValidAgentLabel(name)) return name;
  }

  // Strict mode: no "You are", no headings, no fallbacks
  return "Unknown Agent";
}

/** Map cron short names to canonical agent labels. */
function _normalizeCronAgent(shortName: string): string | null {
  const lower = shortName.toLowerCase().trim();
  // Known agent short names from OpenClaw cron configs
  const CRON_AGENT_MAP: Record<string, string> = {
    "pj": "PJ",
    "endurance-coach": "Coach Alessandra",
    "semiconalpha": "SemiconAlpha Research",
    "shroud-research": "Shroud Research",
  };
  if (CRON_AGENT_MAP[lower]) return CRON_AGENT_MAP[lower];
  // Unknown cron agent — title-case the short name
  const name = lower.replace(/[-_]/g, " ");
  return normalizeLabelForDisplay(name);
}

/** Reject labels that look like action phrases, boot tasks, or system noise. */
export function _isValidAgentLabel(label: string): boolean {
  const lower = label.toLowerCase();
  // Gerund phrases: "Running A Boot Check", "Checking System Status"
  if (/^(?:running|checking|starting|loading|initializing|booting|processing|executing|performing|waiting|connecting)\b/i.test(label)) return false;
  // Boot/system tasks
  if (/\b(?:boot\s*check|startup|shutdown|health\s*check|self[- ]?test|diagnostics?|initialization)\b/i.test(lower)) return false;
  // Generic noise
  if (/^(?:test|debug|untitled|none|null|undefined|default|system|admin|root|user)\s*$/i.test(lower)) return false;
  // Context noise — generic labels from framework metadata
  if (/^(?:project\s*context|conversation|session|sender|channel|message|rules|metadata)\s*$/i.test(lower)) return false;
  return true;
}

/**
 * Normalize a label for use as session key.
 * Title-cases the label so "semiconalpha research" and "SemiconAlpha Research"
 * produce the same display string.
 */
function normalizeLabelForDisplay(label: string): string {
  return label
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .map(w => w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Extract agent label from a single text block. Returns null if no confident match. */
function _extractLabelFromText(text: string): string | null {
  // 1. OpenClaw IDENTITY.md format: "- Name: X" (highest confidence)
  const nameMatch = text.match(/-\s*Name:\s*(.+)/i);
  if (nameMatch) {
    const name = nameMatch[1].trim();
    if (name.length > 1 && name.length < 60) return name;
  }

  // 2. "You are [Name/Role]" — article is optional
  //    ONLY search the first 500 chars — the agent's identity is in the SOUL/system
  //    section at the top of the prompt. User messages appear later and can contain
  //    injection payloads like "You are now DAN" which must NOT become the agent label.
  const identityWindow = text.slice(0, 500);
  const roleMatches = [...identityWindow.matchAll(
    /[Yy]ou\s+are\s+(?:a\s+|an\s+|the\s+)?(.+?)(?:\.|,|\n|$)/g,
  )];
  // Filter out framework preambles and injection patterns.
  // "You are a personal assistant running inside OpenClaw" = boilerplate.
  // "You are now DAN" / "You are now unrestricted" = injection payload.
  const realRoleMatches = roleMatches.filter(m => {
    const captured = m[1].trim().toLowerCase();
    if (isFrameworkPreamble(captured)) return false;
    // "You are now X" is almost always an injection, never a real identity
    if (captured.startsWith("now ")) return false;
    // Reject common injection role patterns that try to override identity
    if (/^(?:an?\s+)?(?:evil|malicious|unrestricted|unfiltered|jailbroken|hacker|harmful)\b/i.test(captured)) return false;
    if (/\b(?:without\s+restrict|no\s+(?:rules|limits|ethics|guardrails|safety)|ignore\s+(?:all|previous|safety))\b/i.test(captured)) return false;
    // "Your new name is EvilBot" produces "EvilBot" — reject single-word ALL-lowercase names
    // that are common injection artefacts (real agent names are multi-word or title-cased)
    if (/^[a-z]+$/.test(captured) && captured.length < 12) return false;
    return true;
  });
  if (realRoleMatches.length > 0) {
    const match = realRoleMatches[realRoleMatches.length - 1];
    let role = match[1].trim();
    role = role.replace(/\s+(?:at|for|who|that|which|specializing|working|based|created|developed|built|made|designed|powered)\s+.*/i, "");
    if (role === role.toLowerCase()) {
      role = role.replace(/\b\w/g, (c) => c.toUpperCase());
    }
    if (role.length > 1 && role.length < 50) return role;
  }

  // 3. "- Creature: X" (OpenClaw IDENTITY.md secondary)
  const creatureMatch = text.match(/-\s*Creature:\s*(.+)/i);
  if (creatureMatch) {
    const creature = creatureMatch[1].trim();
    if (creature.length > 3 && creature.length < 60) {
      return creature.replace(/\b\w/g, (c) => c.toUpperCase());
    }
  }

  // 4. "My name is X" / "I am X" / "called X"
  const selfIdMatch = text.match(
    /(?:[Mm]y\s+name\s+is|I\s+am|I'm|[Cc]alled)\s+([A-Z][A-Za-z0-9 _-]{1,40})(?:\.|,|\n|$)/,
  );
  if (selfIdMatch) {
    const name = selfIdMatch[1].trim();
    if (name.length > 1 && name.length < 50) return name;
  }

  // 5. Markdown heading: "# AgentName"
  const headingMatch = text.match(/^#\s+(.{2,40})$/m);
  if (headingMatch) {
    const heading = headingMatch[1].trim();
    if (heading.length > 1 && heading.length < 50 &&
        !/^(system|instructions|config|settings|readme)/i.test(heading)) {
      return heading;
    }
  }

  // 6. Fallback — disabled.
  // The fallback was the source of all ghost agents. Every prompt variation
  // that didn't match patterns 1-5 would grab the first short line as a name,
  // producing ghosts like "```json", "❌ Wrong: NO_REPLY", "Rules:", etc.
  // If none of the confident patterns (channel label, - Name:, You are,
  // heading) match, return null → "Unknown Agent" which is filtered from
  // persistence and display.
  return null;
}

// ===================================================================
// Agent role classifier — keyword-based, zero dependencies
// ===================================================================

/** Role taxonomy with keyword signals. Ordered by specificity (most specific first). */
const ROLE_TAXONOMY: { role: string; keywords: RegExp }[] = [
  { role: "Security Research",    keywords: /security|threat|vulnerab|pentest|exploit|malware|incident|forensic|soc\b|siem|ids|ips|firewall/i },
  { role: "DevOps / SRE",        keywords: /devops|sre\b|deploy|infra|kubernetes|k8s|docker|terraform|ansible|ci\s*\/?\s*cd|pipeline|monitoring|grafana|prometheus/i },
  { role: "System Admin",        keywords: /sysadmin|system\s*admin|server|linux|network\s*admin|dns|dhcp|ldap|active\s*directory/i },
  { role: "Network Engineering",  keywords: /network|router|switch|vlan|bgp|ospf|firewall\s*rule|palo\s*alto|juniper|cisco/i },
  { role: "Software Engineering", keywords: /software|develop|program|code|engineer|fullstack|backend|frontend|api\b|microservice/i },
  { role: "Data / Analytics",     keywords: /data\s*scien|analytics|machine\s*learn|ml\b|ai\b|model|dataset|pipeline|etl|warehouse/i },
  { role: "Customer Support",     keywords: /support|customer|helpdesk|ticket|billing|account\s*issue|service\s*desk|crm/i },
  { role: "Sales / Outreach",     keywords: /sales|outreach|prospect|lead\s*gen|crm|pipeline|deal|quota|revenue/i },
  { role: "Research",             keywords: /research|investigat|analy[sz]|report|study|academic|paper|journal|semicond|alpha/i },
  { role: "Coaching / Training",  keywords: /coach|train|mentor|fitness|endurance|athlete|workout|nutrition|performance/i },
  { role: "Writing / Content",    keywords: /writing|writer|copywriting|ghostwrit|content\s*creat|blog|article|copy\s*edit|editor|journalist|marketing\s*content/i },
  { role: "Legal / Compliance",   keywords: /legal|compliance|regulat|audit|policy|gdpr|hipaa|sox\b|contract/i },
  { role: "Finance",              keywords: /financ|accounting|budget|invest|portfolio|trading|revenue|forecast/i },
  { role: "Healthcare / Therapy", keywords: /therap|counsel|mental\s*health|psycholog|wellbeing|well-being|mindful|meditat|symptom|diagnos|patient|clinical|healthcare|medical/i },
  { role: "Education / Tutoring", keywords: /tutor|teach|educat|learn|student|lesson|curriculum|homework|quiz|exam|instruct|classroom|professor|lecture/i },
  { role: "E-commerce",           keywords: /shop|e-?commerce|product|cart|checkout|order|catalog|merchant|storefront|retail|inventory|pricing/i },
  { role: "Entertainment / Adult", keywords: /roleplay|erotic|nsfw|adult|companion|intimat|flirt|seduct|sexual|dating|girlfriend|boyfriend|waifu/i },
  { role: "Gaming",               keywords: /game|gaming|rpg|dungeon|quest|player|npc|character\s*sheet|inventory|combat|level\s*up|multiplayer/i },
  { role: "Chatbot / Conversational", keywords: /chatbot|chat\s*bot|conversat|companion|friend|casual\s*chat|social|chit-?chat|talk\s*to\s*me/i },
  { role: "Personal Assistant",   keywords: /personal|assistant|scheduler|organiz|reminder|task\s*manag|daily|general\s*purpose/i },
];

/**
 * Classify an agent's role from its label and system prompt content.
 * Uses keyword matching against a role taxonomy — no LLM call needed.
 *
 * Strategy: check the LABEL first (high confidence), then fall back to
 * the system prompt (inferred). This prevents noisy metadata in the
 * prompt from overriding the agent's actual identity.
 */
/** Build a classification result with colour and confidence percentage. */
function makeClassification(
  role: string, pct: number, signals: string[],
): AgentClassification {
  const confidence = pct >= 80 ? "high" : pct >= 50 ? "medium" : "low";
  // Colour: green for high, blue for medium, grey for low
  const colour = pct >= 80 ? "#3fb950" : pct >= 50 ? "#58a6ff" : "#8b949e";
  return { role, confidencePct: pct, confidence, colour, signals };
}

// ── Behavioral Archetype Mapping ──
// Derived from runtime tool call patterns — builds over time as the agent works.
// Unlike role classification (from label/prompt keywords), archetypes reflect
// what the agent actually *does*.

interface ArchetypeRule {
  name: string;
  /** Return a score 0-100. Highest wins. */
  score: (b: AgentBehaviorProfile) => number;
  colour: string;
}

const ARCHETYPE_RULES: ArchetypeRule[] = [
  {
    name: "Deep Researcher",
    colour: "#a78bfa",
    score: (b) => {
      const search = ["web_fetch", "fetch", "browser", "search", "web_search", "memory_search", "Read"];
      const pct = search.reduce((s, t) => s + (b.toolFrequency[t] || 0), 0) / Math.max(b.totalToolCalls, 1);
      return pct > 0.3 ? 60 + Math.min(20, Math.round(pct * 30)) : Math.round(pct * 180);
    },
  },
  {
    name: "Builder",
    colour: "#f97316",
    score: (b) => {
      const build = ["Write", "Edit", "write", "edit", "exec", "bash", "Bash", "code_execution"];
      const pct = build.reduce((s, t) => s + (b.toolFrequency[t] || 0), 0) / Math.max(b.totalToolCalls, 1);
      return pct > 0.35 ? 60 + Math.min(20, Math.round(pct * 25)) : Math.round(pct * 160);
    },
  },
  {
    name: "Conversationalist",
    colour: "#06b6d4",
    score: (b) => {
      const msg = ["message", "sessions_send", "slack_send", "whatsapp_send", "reply"];
      const msgPct = msg.reduce((s, t) => s + (b.toolFrequency[t] || 0), 0) / Math.max(b.totalToolCalls, 1);
      return msgPct > 0.3 ? 55 + Math.round(msgPct * 30) : Math.round(msgPct * 160);
    },
  },
  {
    name: "Explorer",
    colour: "#eab308",
    score: (b) => {
      const unique = Object.keys(b.toolFrequency).length;
      if (unique < 4) return 0;
      const max = Math.max(...Object.values(b.toolFrequency));
      const spread = 1 - (max / b.totalToolCalls);
      return spread > 0.6 ? 50 + Math.round(spread * 30) : Math.round(spread * 70);
    },
  },
  {
    name: "Operator",
    colour: "#22c55e",
    score: (b) => {
      const ops = ["exec", "bash", "Bash", "deploy", "restart", "kill", "cron"];
      const pct = ops.reduce((s, t) => s + (b.toolFrequency[t] || 0), 0) / Math.max(b.totalToolCalls, 1);
      return pct > 0.4 ? 55 + Math.round(pct * 25) : Math.round(pct * 120);
    },
  },
];

/** Archetype colour lookup for dashboard rendering. */
export const ARCHETYPE_COLOURS: Record<string, string> = Object.fromEntries(
  ARCHETYPE_RULES.map(r => [r.name, r.colour]),
);
ARCHETYPE_COLOURS["General"] = "#64748b";
ARCHETYPE_COLOURS["Unknown"] = "#484f58";

function computeArchetype(b: AgentBehaviorProfile): { name: string; confidence: number } {
  if (b.totalToolCalls < 3) return { name: "Unknown", confidence: 0 };
  let best = { name: "General", score: 0 };
  for (const rule of ARCHETYPE_RULES) {
    const s = rule.score(b);
    if (s > best.score) best = { name: rule.name, score: s };
  }
  if (best.score < 25) return { name: "General", confidence: Math.round(best.score) };
  const dataPenalty = Math.min(1, b.totalToolCalls / 20);
  return { name: best.name, confidence: Math.round(Math.min(95, best.score * dataPenalty)) };
}

/**
 * Classify an agent's role from its label and system prompt content.
 * Uses keyword matching against a role taxonomy — no LLM call needed.
 *
 * Confidence scoring:
 *   90% — role keyword in agent label (explicit naming)
 *   70% — role keyword in SOUL.md "You are a [role]" declaration
 *   40% — role keyword found in general prompt metadata
 *   10% — no match, "General Agent"
 *
 * Multiple signal matches boost confidence by 5% each (capped at 95%).
 */
export function classifyAgent(label: string, systemPrompt: string): AgentClassification {
  // 1. Match against label first — highest confidence signal
  const labelLower = label.toLowerCase();
  for (const { role, keywords } of ROLE_TAXONOMY) {
    const matches = [...labelLower.matchAll(new RegExp(keywords.source, "gi"))];
    if (matches.length > 0) {
      const pct = Math.min(95, 90 + (matches.length - 1) * 5);
      return makeClassification(role, pct, matches.map(m => m[0]));
    }
  }

  // 2. Extract SOUL.md content — look for "You are a [role]" patterns
  //    Skip framework preambles like "You are a personal assistant running inside OpenClaw"
  const soulMatches = [...systemPrompt.matchAll(
    /[Yy]ou\s+are\s+(?:a\s+|an\s+|the\s+)?(.{10,200})(?:\.|$)/gm,
  )].filter(m => !isFrameworkPreamble(m[1]));
  const soulText = soulMatches.length > 0 ? soulMatches[soulMatches.length - 1][1].toLowerCase() : "";

  if (soulText) {
    for (const { role, keywords } of ROLE_TAXONOMY) {
      const matches = [...soulText.matchAll(new RegExp(keywords.source, "gi"))];
      if (matches.length > 0) {
        const pct = Math.min(85, 70 + (matches.length - 1) * 5);
        return makeClassification(role, pct, matches.map(m => m[0]));
      }
    }
  }

  // 3. Last resort: scan the full prompt
  const fullLower = systemPrompt.toLowerCase();
  for (const { role, keywords } of ROLE_TAXONOMY) {
    const matches = [...fullLower.matchAll(new RegExp(keywords.source, "gi"))];
    if (matches.length > 0) {
      const pct = Math.min(60, 40 + (matches.length - 1) * 5);
      return makeClassification(role, pct, matches.map(m => m[0]));
    }
  }

  return makeClassification("General Agent", 10, []);
}

/** Tool name patterns that indicate specific roles. */
const TOOL_ROLE_SIGNALS: { role: string; tools: RegExp }[] = [
  { role: "DevOps / SRE",        tools: /deploy|kubernetes|docker|terraform|ansible|helm|kubectl|aws|gcloud|azure/i },
  { role: "Software Engineering", tools: /code|compile|build|test|lint|git|npm|pip|cargo|debug|exec|write_file|read_file/i },
  { role: "System Admin",        tools: /ssh|systemctl|service|cron|mount|useradd|passwd|iptables/i },
  { role: "Network Engineering",  tools: /ping|traceroute|nslookup|dig|netstat|snmp|bgp|route/i },
  { role: "Data / Analytics",     tools: /query|sql|bigquery|spark|pandas|jupyter|notebook|dataset/i },
  { role: "Customer Support",     tools: /ticket|zendesk|intercom|crm|freshdesk|jira.*service/i },
  { role: "Sales / Outreach",     tools: /salesforce|hubspot|outreach|email.*send|linkedin|prospect/i },
  { role: "Research",             tools: /search|web_fetch|browser|scrape|crawl|arxiv|scholar/i },
  { role: "Writing / Content",    tools: /publish|wordpress|medium|draft|edit.*doc|notion/i },
  { role: "Healthcare / Therapy", tools: /symptom|diagnos|patient|prescri|appointment|medical|health_record/i },
  { role: "Education / Tutoring", tools: /quiz|grade|lesson|flashcard|curriculum|assignment|enroll/i },
  { role: "E-commerce",           tools: /cart|checkout|order|product|catalog|payment|shipping|inventory/i },
  { role: "Gaming",               tools: /game|inventory|combat|quest|character|equip|level|spawn/i },
  { role: "Personal Assistant",   tools: /calendar|schedule|remind|todo|weather|timer/i },
];

/**
 * Enhanced classifier that uses tools + SOUL.md + label.
 * Called when new data (tools or SOUL) becomes available.
 */
export function classifyAgentWithTools(
  label: string, soulExtract: string, tools: string[],
): AgentClassification {
  // Start with base classification
  const base = classifyAgent(label, soulExtract);

  // If already high confidence, keep it
  if (base.confidencePct >= 80) return base;

  // Try to upgrade using tool inventory — but ONLY if base is General Agent
  // or if tools confirm the same role. All OpenClaw agents share base tools
  // (Read, Write, exec, etc.) so generic tools shouldn't override a label match.
  if (tools.length > 0 && (base.role === "General Agent" || base.confidencePct < 50)) {
    const toolStr = tools.join(" ").toLowerCase();
    for (const { role, tools: pattern } of TOOL_ROLE_SIGNALS) {
      const matches = [...toolStr.matchAll(new RegExp(pattern.source, "gi"))];
      if (matches.length >= 2) { // Require 2+ tool matches to classify from tools alone
        const toolPct = Math.min(75, 50 + matches.length * 5);
        const signals = [...base.signals, ...matches.map(m => "tool:" + m[0])];
        return makeClassification(role, toolPct, signals);
      }
    }
  } else if (tools.length > 0 && base.confidencePct >= 50) {
    // Tools confirm existing classification — boost confidence
    const toolStr = tools.join(" ").toLowerCase();
    for (const { role, tools: pattern } of TOOL_ROLE_SIGNALS) {
      if (role === base.role) {
        const matches = [...toolStr.matchAll(new RegExp(pattern.source, "gi"))];
        if (matches.length > 0) {
          const boosted = Math.min(95, base.confidencePct + 10);
          const signals = [...base.signals, ...matches.map(m => "tool:" + m[0])];
          return makeClassification(role, boosted, signals);
        }
      }
    }
  }

  // Try SOUL.md if we have it and base is still weak
  if (soulExtract && base.confidencePct < 50) {
    const soulResult = classifyAgent(label, soulExtract);
    if (soulResult.confidencePct > base.confidencePct) {
      return soulResult;
    }
  }

  return base;
}

// ===================================================================
// Channel detection — extract channel type from prompt metadata
// ===================================================================

/**
 * Detect the channel type from OpenClaw prompt metadata.
 *
 * OpenClaw embeds channel info in JSON metadata blocks, not as plain text
 * like "Slack message in #channel". Detection must match actual metadata:
 * - Slack: has "conversation_label" with "#channel-name"
 * - WhatsApp: has "sender_id" with E.164 phone number, no conversation_label
 * - TUI/terminal: has "tui" or "terminal" in metadata
 * - Cron: has "cron" or "scheduled" context
 * - Heartbeat: has HEARTBEAT.md or HEARTBEAT_OK patterns
 *
 * Also supports plain-text channel markers for backwards compatibility.
 */
export function detectChannel(prompt: string): string | null {
  // Heartbeat — check first, these are special
  if (/HEARTBEAT\.md|HEARTBEAT_OK|heartbeat\s+(?:check|run|turn)/i.test(prompt)) return "heartbeat";

  // Slack — conversation_label with # prefix is the primary signal
  if (/"conversation_label"\s*:\s*"#/i.test(prompt)) return "slack";
  if (/Slack\s+message/i.test(prompt)) return "slack";

  // WhatsApp — E.164 sender_id without conversation_label
  if (/"sender_id"\s*:\s*"\+\d+"/i.test(prompt) && !/"conversation_label"/i.test(prompt)) return "whatsapp";
  if (/WhatsApp\s+message/i.test(prompt)) return "whatsapp";

  // TUI / terminal
  if (/"channel"\s*:\s*"tui"/i.test(prompt)) return "tui";
  if (/TUI\s+(?:session|message)/i.test(prompt) || /openclaw-tui/i.test(prompt)) return "tui";

  // Cron / scheduled
  if (/"channel"\s*:\s*"cron"/i.test(prompt)) return "cron";
  if (/Cron\s+(?:job|task|trigger)/i.test(prompt) || /scheduled\s+task/i.test(prompt)) return "cron";

  // Email
  if (/"channel"\s*:\s*"email"/i.test(prompt)) return "email";
  if (/Email\s+(?:message|from)/i.test(prompt) || /Gmail\s+/i.test(prompt)) return "email";

  // Other platforms
  if (/Discord\s+message/i.test(prompt) || /"channel"\s*:\s*"discord"/i.test(prompt)) return "discord";
  if (/Telegram\s+message/i.test(prompt) || /"channel"\s*:\s*"telegram"/i.test(prompt)) return "telegram";
  if (/Teams\s+message/i.test(prompt) || /"channel"\s*:\s*"teams"/i.test(prompt)) return "teams";

  return null;
}

/** Check if a prompt is a heartbeat prompt. */
export function isHeartbeatPrompt(prompt: string): boolean {
  return /HEARTBEAT\.md|Read\s+HEARTBEAT|heartbeat\s+(?:check|run|turn)|nothing\s+needs\s+attention.*HEARTBEAT_OK/i.test(prompt);
}

/** Check if a response is a heartbeat OK response. */
export function isHeartbeatOk(response: string): boolean {
  return /HEARTBEAT_OK/i.test(response);
}
