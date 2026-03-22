/**
 * SIEM webhook sink for real-time event streaming.
 *
 * Buffers events and pushes them to configured HTTP endpoints with
 * retry + exponential backoff. Supports JSON and CEF output formats.
 * Zero external dependencies — uses Node.js built-in fetch.
 */

// -------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------

export type SiemEventType =
  | "obfuscation_summary"
  | "leak_detected"
  | "exposure_alert"
  | "key_rotation"
  | "compliance_violation"
  | "deobfuscation"
  | "session_event"
  | "monitor_alert";

export interface SiemWebhookEndpoint {
  url: string;
  /** Bearer token or API key value for Authorization header. */
  authHeader?: string;
  /** Additional custom headers. */
  headers?: Record<string, string>;
  /** Filter: only send these event types (empty/undefined = all). */
  eventTypes?: SiemEventType[];
}

export interface SiemEvent {
  /** ISO-8601 timestamp. */
  timestamp: string;
  /** Monotonically increasing sequence number. */
  seq: number;
  /** Event type discriminator. */
  eventType: SiemEventType;
  /** Source identifier (tenantId or process-level). */
  source: string;
  /** Session identifier. */
  sessionId: string;
  /** Per-request correlation ID. */
  requestId: string;
  /** Severity: 0=info, 3=low, 5=medium, 7=high, 10=critical. */
  severity: number;
  /** Event-specific payload (never contains real PII). */
  data: Record<string, unknown>;
}

export interface SiemSinkConfig {
  endpoints: SiemWebhookEndpoint[];
  batchSize: number;
  flushIntervalMs: number;
  maxRetries: number;
  retryBackoffMs: number;
  eventFormat: "json" | "cef";
}

// -------------------------------------------------------------------------
// Event builder
// -------------------------------------------------------------------------

let _seqCounter = 0;

export class SiemEventBuilder {
  static obfuscationSummary(
    source: string,
    sessionId: string,
    requestId: string,
    data: {
      totalEntities: number;
      byCategory: Record<string, number>;
      byRule: Record<string, number>;
      inputChars: number;
      outputChars: number;
    },
  ): SiemEvent {
    return {
      timestamp: new Date().toISOString(),
      seq: ++_seqCounter,
      eventType: "obfuscation_summary",
      source,
      sessionId,
      requestId,
      severity: 0,
      data,
    };
  }

  static leakDetected(
    source: string,
    sessionId: string,
    requestId: string,
    data: { category: string; count: number; context?: string },
  ): SiemEvent {
    return {
      timestamp: new Date().toISOString(),
      seq: ++_seqCounter,
      eventType: "leak_detected",
      source,
      sessionId,
      requestId,
      severity: 7,
      data,
    };
  }

  static exposureAlert(
    source: string,
    sessionId: string,
    requestId: string,
    data: { category: string; count: number; threshold: number; message: string },
  ): SiemEvent {
    return {
      timestamp: new Date().toISOString(),
      seq: ++_seqCounter,
      eventType: "exposure_alert",
      source,
      sessionId,
      requestId,
      severity: 7,
      data,
    };
  }

  static keyRotation(
    source: string,
    sessionId: string,
    data: { oldVersion: number; newVersion: number; totalKeys: number },
  ): SiemEvent {
    return {
      timestamp: new Date().toISOString(),
      seq: ++_seqCounter,
      eventType: "key_rotation",
      source,
      sessionId,
      requestId: "",
      severity: 5,
      data,
    };
  }

  static complianceViolation(
    source: string,
    sessionId: string,
    requestId: string,
    data: { missingCategories: string[]; foundCategories: string[] },
  ): SiemEvent {
    return {
      timestamp: new Date().toISOString(),
      seq: ++_seqCounter,
      eventType: "compliance_violation",
      source,
      sessionId,
      requestId,
      severity: 7,
      data,
    };
  }

  static deobfuscation(
    source: string,
    sessionId: string,
    requestId: string,
    data: { replacementCount: number },
  ): SiemEvent {
    return {
      timestamp: new Date().toISOString(),
      seq: ++_seqCounter,
      eventType: "deobfuscation",
      source,
      sessionId,
      requestId,
      severity: 0,
      data,
    };
  }

  static monitorAlert(
    source: string,
    sessionId: string,
    data: { alertType: string; message: string; details: Record<string, unknown> },
  ): SiemEvent {
    return {
      timestamp: new Date().toISOString(),
      seq: ++_seqCounter,
      eventType: "monitor_alert",
      source,
      sessionId,
      requestId: "",
      severity: 7,
      data,
    };
  }

  /** Reset sequence counter (for testing). */
  static _resetSeq(): void {
    _seqCounter = 0;
  }
}

// -------------------------------------------------------------------------
// CEF formatter
// -------------------------------------------------------------------------

const SEVERITY_MAP: Record<number, string> = {
  0: "Low",
  3: "Low",
  5: "Medium",
  7: "High",
  10: "Critical",
};

export class CefFormatter {
  static format(event: SiemEvent): string {
    const severityLabel = SEVERITY_MAP[event.severity] ?? "Unknown";
    const extension = Object.entries(event.data)
      .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
      .join(" ");
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    return `CEF:0|Shroud|OpenClaw-Shroud|1.0.0|${event.eventType}|${event.eventType}|${severityLabel}|src=${event.source} sessionId=${event.sessionId} seq=${event.seq} ${extension}`;
  }
}

// -------------------------------------------------------------------------
// Webhook sink
// -------------------------------------------------------------------------

export class WebhookSink {
  private _config: SiemSinkConfig;
  private _buffer: SiemEvent[] = [];
  private _flushTimer: ReturnType<typeof setInterval> | null = null;
  private _flushing = false;
  /** Counts of events sent (for stats). */
  private _sentCount = 0;
  private _failedCount = 0;

  constructor(config: SiemSinkConfig) {
    this._config = config;
    if (config.flushIntervalMs > 0) {
      this._flushTimer = setInterval(() => {
        this.flush().catch(() => {});
      }, config.flushIntervalMs);
      // Don't block process exit
      if (this._flushTimer && typeof this._flushTimer === "object" && "unref" in this._flushTimer) {
        this._flushTimer.unref();
      }
    }
  }

  /** Add an event to the buffer. Auto-flushes at batch threshold. */
  emit(event: SiemEvent): void {
    this._buffer.push(event);
    if (this._buffer.length >= this._config.batchSize) {
      this.flush().catch(() => {});
    }
  }

  /** Flush all buffered events to all endpoints. */
  async flush(): Promise<void> {
    if (this._buffer.length === 0 || this._flushing) return;
    this._flushing = true;

    const batch = this._buffer.splice(0);

    try {
      const promises = this._config.endpoints.map((endpoint) => {
        // Filter events by endpoint's eventTypes filter
        const filtered = endpoint.eventTypes && endpoint.eventTypes.length > 0
          ? batch.filter((e) => endpoint.eventTypes!.includes(e.eventType))
          : batch;
        if (filtered.length === 0) return Promise.resolve();
        return this._sendBatch(endpoint, filtered);
      });
      await Promise.allSettled(promises);
    } finally {
      this._flushing = false;
    }
  }

  /** Stop the flush timer and drain remaining events. */
  async destroy(): Promise<void> {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    await this.flush();
  }

  /** Stats for diagnostics. */
  getStats(): { buffered: number; sent: number; failed: number } {
    return {
      buffered: this._buffer.length,
      sent: this._sentCount,
      failed: this._failedCount,
    };
  }

  private async _sendBatch(endpoint: SiemWebhookEndpoint, events: SiemEvent[]): Promise<void> {
    const format = this._config.eventFormat;
    const body = format === "cef"
      ? events.map((e) => CefFormatter.format(e)).join("\n")
      : JSON.stringify(events);

    const headers: Record<string, string> = {
      "Content-Type": format === "cef" ? "text/plain" : "application/json",
      "User-Agent": "Shroud-SIEM/1.0",
      ...(endpoint.headers ?? {}),
    };
    if (endpoint.authHeader) {
      headers["Authorization"] = endpoint.authHeader;
    }

    await this._retryWithBackoff(async () => {
      const res = await fetch(endpoint.url, {
        method: "POST",
        headers,
        body,
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        throw new Error(`SIEM webhook ${endpoint.url} returned ${res.status}`);
      }
      this._sentCount += events.length;
    });
  }

  private async _retryWithBackoff(fn: () => Promise<void>): Promise<void> {
    let backoff = this._config.retryBackoffMs;
    for (let attempt = 0; attempt <= this._config.maxRetries; attempt++) {
      try {
        await fn();
        return;
      } catch (err) {
        if (attempt === this._config.maxRetries) {
          this._failedCount++;
          // Best-effort: log but don't throw
          console.warn(`[shroud][siem] Failed after ${this._config.maxRetries + 1} attempts: ${err}`);
          return;
        }
        await new Promise((r) => setTimeout(r, backoff));
        backoff *= 2;
      }
    }
  }
}
