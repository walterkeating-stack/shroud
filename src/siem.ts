/**
 * SIEM integration — ships security events to external systems.
 *
 * Two output modes:
 * 1. Webhook POST: sends events as JSON to a configured URL (Splunk HEC, Grafana Loki, custom)
 * 2. JSONL file: appends events as newline-delimited JSON to a local file
 *
 * Both are async fire-and-forget — never blocks the request pipeline.
 * Zero runtime dependencies.
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { SecurityEvent } from "./security-event.js";

/** SIEM output configuration. */
export interface SiemConfig {
  /** Webhook URL to POST events to. Null = disabled. */
  webhookUrl: string | null;
  /** Optional auth header value (e.g. "Bearer xxx" or "Splunk xxx"). */
  webhookAuth: string | null;
  /** JSONL file path to append events. Null = disabled. */
  jsonlPath: string | null;
  /** Batch size — buffer events and flush at this count. 1 = immediate. */
  batchSize: number;
  /** Max flush interval in ms. Events flushed even if batch not full. */
  flushIntervalMs: number;
}

/**
 * SIEM event shipper. Subscribes to SecurityEventBus and ships events
 * to configured destinations.
 */
export class SiemShipper {
  private _config: SiemConfig;
  private _buffer: SecurityEvent[] = [];
  private _flushTimer: ReturnType<typeof setInterval> | null = null;
  private _stats = { shipped: 0, webhookErrors: 0, fileErrors: 0 };

  constructor(config: SiemConfig) {
    this._config = config;

    // Start flush timer if batching
    if (config.batchSize > 1 && config.flushIntervalMs > 0) {
      this._flushTimer = setInterval(() => this.flush(), config.flushIntervalMs);
    }

    // Ensure JSONL directory exists
    if (config.jsonlPath) {
      try { mkdirSync(dirname(config.jsonlPath), { recursive: true }); } catch {}
    }
  }

  /** Called for each security event. Buffers and flushes. */
  onEvent(event: SecurityEvent): void {
    this._buffer.push(event);
    if (this._buffer.length >= this._config.batchSize) {
      this.flush();
    }
  }

  /** Flush buffered events to all configured destinations. */
  flush(): void {
    if (this._buffer.length === 0) return;
    const events = this._buffer.splice(0);

    // JSONL file output
    if (this._config.jsonlPath) {
      try {
        const lines = events.map(e => JSON.stringify(e)).join("\n") + "\n";
        appendFileSync(this._config.jsonlPath, lines);
        this._stats.shipped += events.length;
      } catch {
        this._stats.fileErrors++;
      }
    }

    // Webhook POST
    if (this._config.webhookUrl) {
      this._postWebhook(events);
    }
  }

  /** Stop the flush timer and flush remaining events. */
  stop(): void {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    this.flush();
  }

  /** Get shipping stats. */
  getStats() {
    return { ...this._stats, buffered: this._buffer.length };
  }

  private _postWebhook(events: SecurityEvent[]): void {
    try {
      const url = new URL(this._config.webhookUrl!);
      const isHttps = url.protocol === "https:";
      const reqFn = isHttps ? httpsRequest : httpRequest;

      const body = JSON.stringify({ events, count: events.length, timestamp: new Date().toISOString() });

      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          ...(this._config.webhookAuth ? { Authorization: this._config.webhookAuth } : {}),
        },
      };

      const req = reqFn(options, (res) => {
        // Drain response
        res.resume();
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          this._stats.shipped += events.length;
        } else {
          this._stats.webhookErrors++;
        }
      });

      req.on("error", () => { this._stats.webhookErrors++; });
      req.write(body);
      req.end();
    } catch {
      this._stats.webhookErrors++;
    }
  }
}
