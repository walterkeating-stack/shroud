/**
 * Security event types and in-memory event bus.
 *
 * Shared by all security tracks: injection detection, canary monitoring,
 * and behavioural profiling. Events are accumulated in memory and
 * queryable during the session.
 */

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

  constructor(maxEvents = 500, dedupIntervalMs = 0) {
    this._maxEvents = maxEvents;
    this._dedupIntervalMs = dedupIntervalMs;
  }

  emit(event: SecurityEvent): void {
    // Dedup: skip events with same signature + matched text + agent within the dedup window.
    // This prevents shared system prompt content from generating repeated events per call.
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
