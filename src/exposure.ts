/**
 * Rate-of-exposure tracker with sliding window alerting.
 *
 * Tracks per-category detection counts within a configurable time window.
 * When any category exceeds its threshold, an alert is generated.
 */

import { Category } from "./types.js";

export interface ExposureAlert {
  category: string;
  count: number;
  threshold: number;
  windowMs: number;
  message: string;
}

export class ExposureTracker {
  private _windowMs: number;
  private _thresholds: Map<string, number>;
  private _events: Map<string, number[]> = new Map();
  private _globalThreshold: number;

  constructor(
    windowMs = 60_000,
    thresholds: Record<string, number> = {},
    globalThreshold = 100,
  ) {
    this._windowMs = windowMs;
    this._thresholds = new Map(Object.entries(thresholds));
    this._globalThreshold = globalThreshold;
  }

  /** Record detection events for a category. */
  record(category: string, count: number): void {
    const now = Date.now();
    let events = this._events.get(category);
    if (!events) {
      events = [];
      this._events.set(category, events);
    }
    for (let i = 0; i < count; i++) {
      events.push(now);
    }
  }

  /** Check all categories and return alerts for any that exceed thresholds. */
  check(): ExposureAlert[] {
    const now = Date.now();
    const cutoff = now - this._windowMs;
    const alerts: ExposureAlert[] = [];

    let globalCount = 0;

    for (const [category, events] of this._events) {
      // Prune old events
      const recent = events.filter((t) => t > cutoff);
      this._events.set(category, recent);

      globalCount += recent.length;

      const threshold =
        this._thresholds.get(category) ?? this._thresholds.get("*") ?? Infinity;

      if (recent.length > threshold) {
        alerts.push({
          category,
          count: recent.length,
          threshold,
          windowMs: this._windowMs,
          message: `Category '${category}' exposure spike: ${recent.length} detections in ${this._windowMs / 1000}s window (threshold: ${threshold})`,
        });
      }
    }

    // Global threshold check
    if (globalCount > this._globalThreshold) {
      alerts.push({
        category: "__global__",
        count: globalCount,
        threshold: this._globalThreshold,
        windowMs: this._windowMs,
        message: `Global exposure spike: ${globalCount} total detections in ${this._windowMs / 1000}s window (threshold: ${this._globalThreshold})`,
      });
    }

    return alerts;
  }

  /** Reset all tracked events. */
  reset(): void {
    this._events.clear();
  }
}
