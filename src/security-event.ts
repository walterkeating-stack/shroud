/**
 * Security event types and in-memory event bus.
 *
 * Shared by all security tracks: injection detection, canary monitoring,
 * and behavioural profiling. Events are accumulated in memory and
 * queryable during the session.
 */

import { readFileSync } from "node:fs";

/** Threat classes for injection signature detection. */
export enum ThreatClass {
  INSTRUCTION_OVERRIDE = "instruction_override",
  ROLE_SWITCH = "role_switch",
  PROMPT_EXTRACTION = "prompt_extraction",
  CONVERSATION_MOCKUP = "conversation_mockup",
  ENCODING_BYPASS = "encoding_bypass",
  DATA_EXFILTRATION = "data_exfiltration",
  PRIVILEGE_ESCALATION = "privilege_escalation",
  MCP_TOOL_POISONING = "mcp_tool_poisoning",
  SEMANTIC_DRIFT = "semantic_drift",
  SHADOW_EXFIL = "shadow_exfil_detected",
  CAUSAL_INCOHERENCE = "causal_incoherence",
  NOVEL_WORKFLOW = "novel_workflow",
  URL_CORRELATION = "url_correlation",
  DELEGATION_DRIFT = "delegation_drift",
  TOOL_SEQUENCE_ANOMALY = "tool_sequence_anomaly",
}

/** Severity levels for security events. */
export type SecuritySeverity = "low" | "medium" | "high";

/** Actions taken in response to a security event. */
export type SecurityAction = "flagged" | "blocked";

/** A security event emitted by any of the three tracks. */
export interface SecurityEvent {
  timestamp: number;
  eventType: "injection_detected" | "canary_triggered" | "anomaly_detected";
  direction: "request" | "response";
  threatClass: ThreatClass;
  signatureId: string;
  severity: SecuritySeverity;
  matchedText: string;
  matchStart: number;
  matchEnd: number;
  textLength: number;
  action: SecurityAction;
  description: string;
  /** Agent identity — which agent's session produced this event. */
  agentBuildId?: string;
  /** Human-readable agent label. */
  agentLabel?: string;
  /** Agent session ID. */
  agentSessionId?: string;
  /** Channel the event originated from (slack, whatsapp, tui, etc.). */
  channel?: string;
}

/** Aggregate statistics for security events. */
export interface SecurityStats {
  totalEvents: number;
  byThreatClass: Record<string, number>;
  bySeverity: Record<string, number>;
  byDirection: Record<string, number>;
  blockedCount: number;
  flaggedCount: number;
}

/**
 * In-memory accumulator for security events. Bounded by maxEvents
 * to prevent unbounded growth during long sessions.
 */
export class SecurityEventBus {
  private _events: SecurityEvent[] = [];
  private _maxEvents: number;
  private _listeners: Array<(event: SecurityEvent) => void> = [];
  /** Dedup window: signatureId:matchedText:agentLabel → last emit timestamp. */
  private _dedupWindow = new Map<string, number>();
  /** Dedup interval in ms — skip duplicate events within this window. */
  private _dedupIntervalMs: number;
  /** Content-hash dedup: signatureId:matchStart:matchedText:agentBuildId → true.
   *  Permanently suppresses identical matches at the same offset (system prompt FPs). */
  private _contentDedup = new Set<string>();

  constructor(maxEvents = 500, dedupIntervalMs = 0) {
    this._maxEvents = maxEvents;
    this._dedupIntervalMs = dedupIntervalMs;
  }

  emit(event: SecurityEvent): void {
    // Content-hash dedup: if the same signature fires on the same text at the same
    // offset for the same agent, suppress permanently. This catches shared system
    // prompt content (pe_repeat_instructions, eb_token_smuggling) that fires on
    // every request but never changes.
    const contentKey = `${event.signatureId}:${event.matchStart}:${(event.matchedText || "").slice(0, 80)}:${event.agentBuildId || ""}`;
    if (this._contentDedup.has(contentKey)) {
      return; // Already seen this exact match — suppress
    }
    this._contentDedup.add(contentKey);
    // Cap content dedup set
    if (this._contentDedup.size > 5000) {
      // Keep most recent entries by rebuilding (rare — only under sustained novel attacks)
      const entries = [...this._contentDedup];
      this._contentDedup.clear();
      for (const e of entries.slice(-2500)) this._contentDedup.add(e);
    }

    // Time-window dedup: skip events with same signature + matched text + agent within the dedup window.
    const dedupKey = `${event.signatureId}:${(event.matchedText || "").slice(0, 100)}:${event.agentLabel || ""}`;
    const lastEmit = this._dedupWindow.get(dedupKey);
    if (lastEmit && (event.timestamp - lastEmit) < this._dedupIntervalMs) {
      return; // Duplicate within window — suppress
    }
    this._dedupWindow.set(dedupKey, event.timestamp);
    // Prune stale dedup entries periodically
    if (this._dedupWindow.size > 1000) {
      const cutoff = Date.now() - this._dedupIntervalMs;
      for (const [k, ts] of this._dedupWindow) {
        if (ts < cutoff) this._dedupWindow.delete(k);
      }
    }

    this._events.push(event);
    // Evict oldest if over capacity
    if (this._events.length > this._maxEvents) {
      this._events.splice(0, this._events.length - this._maxEvents);
    }
    // Notify listeners (SSE dashboard, SIEM, etc.)
    for (const listener of this._listeners) {
      try { listener(event); } catch { /* listeners must not break emit */ }
    }
  }

  /** Subscribe to real-time events. Returns unsubscribe function. */
  onEvent(listener: (event: SecurityEvent) => void): () => void {
    this._listeners.push(listener);
    return () => {
      const idx = this._listeners.indexOf(listener);
      if (idx >= 0) this._listeners.splice(idx, 1);
    };
  }

  getEvents(): readonly SecurityEvent[] {
    return this._events;
  }

  /** Clear all events. Used by test harness to isolate scenarios. */
  clearEvents(): void {
    this._events.length = 0;
  }

  /**
   * Load events from a JSONL file (e.g. SIEM log) to restore state after restart.
   * Only loads events from the last `maxAgeMs` (default 1 hour).
   * Events loaded this way bypass dedup and listeners (they're historical).
   */
  loadFromJsonl(filePath: string, maxAgeMs = 3_600_000): number {
    try {
      const raw = readFileSync(filePath, "utf-8");
      const cutoff = Date.now() - maxAgeMs;
      let loaded = 0;

      for (const line of raw.split("\n")) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line) as SecurityEvent;
          if (event.timestamp && event.timestamp > cutoff && event.signatureId) {
            this._events.push(event);
            loaded++;
          }
        } catch { /* skip malformed lines */ }
      }

      // Trim to capacity
      if (this._events.length > this._maxEvents) {
        this._events.splice(0, this._events.length - this._maxEvents);
      }

      return loaded;
    } catch {
      return 0; // File may not exist
    }
  }

  getStats(): SecurityStats {
    const stats: SecurityStats = {
      totalEvents: this._events.length,
      byThreatClass: {},
      bySeverity: {},
      byDirection: {},
      blockedCount: 0,
      flaggedCount: 0,
    };

    for (const e of this._events) {
      stats.byThreatClass[e.threatClass] = (stats.byThreatClass[e.threatClass] ?? 0) + 1;
      stats.bySeverity[e.severity] = (stats.bySeverity[e.severity] ?? 0) + 1;
      stats.byDirection[e.direction] = (stats.byDirection[e.direction] ?? 0) + 1;
      if (e.action === "blocked") stats.blockedCount++;
      else stats.flaggedCount++;
    }

    return stats;
  }

  clear(): void {
    this._events = [];
  }
}
