/**
 * Active monitoring and alerting pipeline.
 *
 * Watches for anomalies in real-time:
 * - Sudden detection rate spikes (compared to rolling baseline)
 * - New categories appearing that weren't seen before
 * - Canary token leaks detected in outputs
 * - Repeated exposure threshold breaches
 *
 * Integrates with the SIEM WebhookSink for alert delivery and
 * maintains an in-memory alert log for API access.
 */

export type MonitorAlertType =
  | "rate_spike"
  | "new_category"
  | "canary_leak"
  | "exposure_breach"
  | "deobfuscation_failure"
  | "key_expiry_warning";

export interface MonitorAlert {
  id: number;
  timestamp: string;
  alertType: MonitorAlertType;
  severity: "info" | "warning" | "critical";
  message: string;
  details: Record<string, unknown>;
  acknowledged: boolean;
}

export interface MonitorConfig {
  /** Enable active monitoring. */
  enabled: boolean;
  /** Rolling window size in ms for rate baseline (default 60s). */
  rateWindowMs: number;
  /** Spike threshold multiplier: alert if rate > baseline * multiplier (default 3.0). */
  spikeMultiplier: number;
  /** Max alerts to keep in memory (default 500). */
  maxAlerts: number;
  /** Alert callback for integration with SIEM sink. */
  onAlert?: (alert: MonitorAlert) => void;
}

interface RateWindow {
  counts: number[];
  timestamps: number[];
  baseline: number;
}

let _alertIdCounter = 0;

export class AlertPipeline {
  private _config: MonitorConfig;
  private _alerts: MonitorAlert[] = [];
  private _rateWindow: RateWindow;
  private _seenCategories: Set<string> = new Set();
  private _breachCounts: Map<string, number> = new Map();
  private _enabled: boolean;

  constructor(config: Partial<MonitorConfig> = {}) {
    this._config = {
      enabled: config.enabled ?? true,
      rateWindowMs: config.rateWindowMs ?? 60_000,
      spikeMultiplier: config.spikeMultiplier ?? 3.0,
      maxAlerts: config.maxAlerts ?? 500,
      onAlert: config.onAlert,
    };
    this._enabled = this._config.enabled;
    this._rateWindow = { counts: [], timestamps: [], baseline: 0 };
  }

  /** Record a detection event and check for anomalies. */
  recordDetection(entityCount: number, categories: string[]): MonitorAlert[] {
    if (!this._enabled) return [];

    const now = Date.now();
    const alerts: MonitorAlert[] = [];

    // Track rate
    this._rateWindow.counts.push(entityCount);
    this._rateWindow.timestamps.push(now);

    // Prune old entries outside the window
    const cutoff = now - this._config.rateWindowMs;
    while (
      this._rateWindow.timestamps.length > 0 &&
      this._rateWindow.timestamps[0] < cutoff
    ) {
      this._rateWindow.timestamps.shift();
      this._rateWindow.counts.shift();
    }

    // Compute current rate (entities per window)
    const currentRate = this._rateWindow.counts.reduce((a, b) => a + b, 0);

    // Update baseline (exponential moving average)
    if (this._rateWindow.baseline === 0) {
      this._rateWindow.baseline = currentRate;
    } else {
      this._rateWindow.baseline =
        this._rateWindow.baseline * 0.9 + currentRate * 0.1;
    }

    // Check for rate spike
    if (
      this._rateWindow.baseline > 0 &&
      currentRate > this._rateWindow.baseline * this._config.spikeMultiplier &&
      currentRate > 10 // Minimum absolute threshold to avoid false positives
    ) {
      const alert = this._createAlert(
        "rate_spike",
        "warning",
        `Detection rate spike: ${currentRate} entities in window vs baseline ${Math.round(this._rateWindow.baseline)}`,
        { currentRate, baseline: Math.round(this._rateWindow.baseline), multiplier: this._config.spikeMultiplier },
      );
      alerts.push(alert);
    }

    // Check for new categories
    for (const cat of categories) {
      if (!this._seenCategories.has(cat)) {
        this._seenCategories.add(cat);
        // Only alert after the initial learning period (first 5 events)
        if (this._rateWindow.counts.length > 5) {
          const alert = this._createAlert(
            "new_category",
            "info",
            `New entity category detected: ${cat}`,
            { category: cat },
          );
          alerts.push(alert);
        }
      }
    }

    return alerts;
  }

  /** Record a canary leak detection. */
  recordCanaryLeak(context: string): MonitorAlert {
    const alert = this._createAlert(
      "canary_leak",
      "critical",
      `Canary token detected in LLM output — possible data leak`,
      { context: context.slice(0, 200) },
    );
    return alert;
  }

  /** Record an exposure threshold breach. */
  recordExposureBreach(category: string, count: number, threshold: number): MonitorAlert {
    const breachKey = category;
    const prevCount = this._breachCounts.get(breachKey) ?? 0;
    this._breachCounts.set(breachKey, prevCount + 1);

    const severity = prevCount >= 3 ? "critical" : "warning";
    const alert = this._createAlert(
      "exposure_breach",
      severity,
      `Exposure threshold breached for ${category}: ${count}/${threshold} (breach #${prevCount + 1})`,
      { category, count, threshold, consecutiveBreaches: prevCount + 1 },
    );
    return alert;
  }

  /** Record a key expiry warning. */
  recordKeyExpiryWarning(version: number, expiresAt: string, hoursRemaining: number): MonitorAlert {
    const alert = this._createAlert(
      "key_expiry_warning",
      hoursRemaining < 1 ? "critical" : "warning",
      `Key version ${version} expires in ${hoursRemaining.toFixed(1)} hours`,
      { keyVersion: version, expiresAt, hoursRemaining },
    );
    return alert;
  }

  /** Acknowledge an alert by ID. */
  acknowledge(alertId: number): boolean {
    const alert = this._alerts.find((a) => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
      return true;
    }
    return false;
  }

  /** Get all alerts, optionally filtered. */
  getAlerts(opts?: {
    unacknowledgedOnly?: boolean;
    alertType?: MonitorAlertType;
    since?: string;
  }): MonitorAlert[] {
    let result = this._alerts;
    if (opts?.unacknowledgedOnly) {
      result = result.filter((a) => !a.acknowledged);
    }
    if (opts?.alertType) {
      result = result.filter((a) => a.alertType === opts.alertType);
    }
    if (opts?.since) {
      const sinceTs = new Date(opts.since).getTime();
      result = result.filter((a) => new Date(a.timestamp).getTime() >= sinceTs);
    }
    return result;
  }

  /** Get summary stats. */
  getStats(): {
    totalAlerts: number;
    unacknowledged: number;
    byType: Record<string, number>;
    currentRate: number;
    baseline: number;
    categoriesSeen: string[];
  } {
    const byType: Record<string, number> = {};
    let unack = 0;
    for (const a of this._alerts) {
      byType[a.alertType] = (byType[a.alertType] ?? 0) + 1;
      if (!a.acknowledged) unack++;
    }

    return {
      totalAlerts: this._alerts.length,
      unacknowledged: unack,
      byType,
      currentRate: this._rateWindow.counts.reduce((a, b) => a + b, 0),
      baseline: Math.round(this._rateWindow.baseline),
      categoriesSeen: [...this._seenCategories],
    };
  }

  /** Clear all alerts and reset state. */
  reset(): void {
    this._alerts = [];
    this._rateWindow = { counts: [], timestamps: [], baseline: 0 };
    this._seenCategories.clear();
    this._breachCounts.clear();
  }

  /** Enable or disable monitoring. */
  setEnabled(enabled: boolean): void {
    this._enabled = enabled;
  }

  get enabled(): boolean {
    return this._enabled;
  }

  private _createAlert(
    alertType: MonitorAlertType,
    severity: "info" | "warning" | "critical",
    message: string,
    details: Record<string, unknown>,
  ): MonitorAlert {
    const alert: MonitorAlert = {
      id: ++_alertIdCounter,
      timestamp: new Date().toISOString(),
      alertType,
      severity,
      message,
      details,
      acknowledged: false,
    };

    // Add to ring buffer
    if (this._alerts.length >= this._config.maxAlerts) {
      this._alerts.shift();
    }
    this._alerts.push(alert);

    // Notify callback (SIEM integration)
    if (this._config.onAlert) {
      try {
        this._config.onAlert(alert);
      } catch {
        // best-effort
      }
    }

    return alert;
  }
}
