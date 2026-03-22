import { describe, it, expect, beforeEach } from "vitest";
import { AlertPipeline, MonitorAlert } from "../src/monitor.js";

describe("AlertPipeline", () => {
  let pipeline: AlertPipeline;

  beforeEach(() => {
    pipeline = new AlertPipeline({
      enabled: true,
      rateWindowMs: 60_000,
      spikeMultiplier: 3.0,
      maxAlerts: 100,
    });
  });

  it("records detections without alerts in normal conditions", () => {
    const alerts = pipeline.recordDetection(5, ["email", "ip_address"]);
    // First events don't trigger spikes (learning period + low absolute count)
    expect(alerts.filter((a) => a.alertType === "rate_spike")).toHaveLength(0);
  });

  it("detects rate spikes when threshold exceeded", () => {
    // Build up a baseline
    for (let i = 0; i < 10; i++) {
      pipeline.recordDetection(2, ["email"]);
    }

    // Massive spike
    const alerts = pipeline.recordDetection(100, ["email"]);
    const spikes = alerts.filter((a) => a.alertType === "rate_spike");
    expect(spikes.length).toBeGreaterThanOrEqual(1);
    expect(spikes[0].severity).toBe("warning");
  });

  it("detects new categories after learning period", () => {
    // Fill learning period (6+ events)
    for (let i = 0; i < 7; i++) {
      pipeline.recordDetection(1, ["email"]);
    }

    // New category appears
    const alerts = pipeline.recordDetection(1, ["credit_card"]);
    const newCats = alerts.filter((a) => a.alertType === "new_category");
    expect(newCats.length).toBe(1);
    expect(newCats[0].details.category).toBe("credit_card");
  });

  it("does not alert on new categories during learning period", () => {
    const alerts = pipeline.recordDetection(1, ["email"]);
    const newCats = alerts.filter((a) => a.alertType === "new_category");
    expect(newCats).toHaveLength(0);
  });

  it("records canary leak as critical", () => {
    const alert = pipeline.recordCanaryLeak("found token in output: SHROUD-CANARY-abc123");
    expect(alert.alertType).toBe("canary_leak");
    expect(alert.severity).toBe("critical");
    expect(alert.details.context).toContain("SHROUD-CANARY");
  });

  it("records exposure breach with escalating severity", () => {
    const a1 = pipeline.recordExposureBreach("email", 20, 10);
    expect(a1.severity).toBe("warning");

    // Repeated breaches escalate
    pipeline.recordExposureBreach("email", 25, 10);
    pipeline.recordExposureBreach("email", 30, 10);
    const a4 = pipeline.recordExposureBreach("email", 35, 10);
    expect(a4.severity).toBe("critical");
    expect(a4.details.consecutiveBreaches).toBe(4);
  });

  it("records key expiry warnings", () => {
    const a1 = pipeline.recordKeyExpiryWarning(2, "2025-01-01T12:00:00Z", 12);
    expect(a1.alertType).toBe("key_expiry_warning");
    expect(a1.severity).toBe("warning");

    const a2 = pipeline.recordKeyExpiryWarning(2, "2025-01-01T00:30:00Z", 0.5);
    expect(a2.severity).toBe("critical");
  });

  it("acknowledges alerts", () => {
    pipeline.recordCanaryLeak("test");
    const alerts = pipeline.getAlerts();
    expect(alerts[0].acknowledged).toBe(false);

    const result = pipeline.acknowledge(alerts[0].id);
    expect(result).toBe(true);
    expect(pipeline.getAlerts({ unacknowledgedOnly: true })).toHaveLength(0);
  });

  it("filters alerts by type", () => {
    pipeline.recordCanaryLeak("test1");
    pipeline.recordExposureBreach("email", 10, 5);

    const canaries = pipeline.getAlerts({ alertType: "canary_leak" });
    expect(canaries.length).toBe(1);
    expect(canaries[0].alertType).toBe("canary_leak");
  });

  it("respects maxAlerts limit", () => {
    const smallPipeline = new AlertPipeline({ maxAlerts: 3 });
    for (let i = 0; i < 5; i++) {
      smallPipeline.recordCanaryLeak(`test${i}`);
    }
    expect(smallPipeline.getAlerts().length).toBe(3);
  });

  it("provides accurate stats", () => {
    pipeline.recordDetection(5, ["email", "ip_address"]);
    pipeline.recordCanaryLeak("test");

    const stats = pipeline.getStats();
    expect(stats.totalAlerts).toBeGreaterThanOrEqual(1); // canary leak
    expect(stats.categoriesSeen).toContain("email");
    expect(stats.categoriesSeen).toContain("ip_address");
  });

  it("can be disabled and re-enabled", () => {
    pipeline.setEnabled(false);
    const alerts = pipeline.recordDetection(100, ["email"]);
    expect(alerts).toHaveLength(0);

    pipeline.setEnabled(true);
    expect(pipeline.enabled).toBe(true);
  });

  it("reset clears all state", () => {
    pipeline.recordCanaryLeak("test");
    pipeline.recordDetection(5, ["email"]);
    pipeline.reset();

    const stats = pipeline.getStats();
    expect(stats.totalAlerts).toBe(0);
    expect(stats.categoriesSeen).toHaveLength(0);
    expect(stats.currentRate).toBe(0);
  });

  it("calls onAlert callback", () => {
    const received: MonitorAlert[] = [];
    const withCallback = new AlertPipeline({
      onAlert: (alert) => received.push(alert),
    });
    withCallback.recordCanaryLeak("test");
    expect(received.length).toBe(1);
    expect(received[0].alertType).toBe("canary_leak");
  });
});
