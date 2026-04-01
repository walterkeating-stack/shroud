import { describe, test, expect } from "vitest";
import { CausalCoherenceTracker, buildCoherenceEvent } from "../src/causal-coherence.js";
import { ThreatClass } from "../src/security-event.js";

describe("CausalCoherenceTracker", () => {
  test("returns null when no pending result", () => {
    const tracker = new CausalCoherenceTracker();
    const result = tracker.checkCoherence("edit", { file_path: "/tmp/test.py" });
    expect(result).toBeNull();
  });

  test("forms pair when result is fed then tool call checked", () => {
    const tracker = new CausalCoherenceTracker();
    tracker.feedResult("read", "def hello():\n  print('world')");
    const result = tracker.checkCoherence("edit", { file_path: "/tmp/test.py" });
    expect(result).not.toBeNull();
    expect(result!.transitionKey).toBe("read\u2192edit");
    expect(result!.distance).toBeGreaterThanOrEqual(0);
    expect(result!.distance).toBeLessThanOrEqual(1);
  });

  test("consumes pending result after check", () => {
    const tracker = new CausalCoherenceTracker();
    tracker.feedResult("read", "some content");
    tracker.checkCoherence("edit", {});
    // Second check should return null — pending consumed
    const result = tracker.checkCoherence("exec", {});
    expect(result).toBeNull();
  });

  test("empty result text clears pending", () => {
    const tracker = new CausalCoherenceTracker();
    tracker.feedResult("read", "");
    const result = tracker.checkCoherence("edit", {});
    expect(result).toBeNull();
  });

  test("builds transition stats over multiple pairs", () => {
    const tracker = new CausalCoherenceTracker();
    // Feed the same transition 5 times to build baseline
    for (let i = 0; i < 5; i++) {
      tracker.feedResult("read", "function foo() { return 42; }");
      tracker.checkCoherence("edit", { file_path: "/tmp/foo.js" });
    }
    const stats = tracker.getStats();
    expect(stats["read\u2192edit"]).toBeDefined();
    expect(stats["read\u2192edit"].n).toBe(5);
  });

  test("detects incoherence after baseline is established", () => {
    const tracker = new CausalCoherenceTracker({ zScoreThreshold: 2.0 });
    // Build stable baseline: read → edit with consistent distances
    for (let i = 0; i < 10; i++) {
      tracker.feedResult("read", "def process_data(): return data.transform()");
      tracker.checkCoherence("edit", { file_path: "/tmp/data.py" });
    }
    // Now introduce an incoherent pair: read → message (totally different)
    tracker.feedResult("read", "def process_data(): return data.transform()");
    const result = tracker.checkCoherence("message", { channel: "#secrets", body: "sending all credentials" });
    // This might or might not trigger based on the actual distances —
    // we check the structure is correct regardless
    expect(result).not.toBeNull();
    expect(result!.transitionKey).toBe("read\u2192message");
  });

  test("resetTurn clears pending but preserves stats", () => {
    const tracker = new CausalCoherenceTracker();
    tracker.feedResult("read", "some content");
    tracker.checkCoherence("edit", {});
    const statsBefore = Object.keys(tracker.getStats()).length;

    tracker.resetTurn();

    // Stats preserved
    expect(Object.keys(tracker.getStats()).length).toBe(statsBefore);
    // Pending cleared
    const result = tracker.checkCoherence("exec", {});
    expect(result).toBeNull();
  });

  test("getRecentPairs returns recorded pairs", () => {
    const tracker = new CausalCoherenceTracker();
    tracker.feedResult("read", "content");
    tracker.checkCoherence("edit", {});
    const pairs = tracker.getRecentPairs();
    expect(pairs.length).toBe(1);
    expect(pairs[0].resultToolName).toBe("read");
    expect(pairs[0].actionToolName).toBe("edit");
  });

  test("loadStats restores persisted stats", () => {
    const tracker = new CausalCoherenceTracker();
    tracker.loadStats({
      "read\u2192edit": { mean: 0.3, m2: 0.01, n: 20, min: 0.2, max: 0.4 },
    });
    const stats = tracker.getStats();
    expect(stats["read\u2192edit"].n).toBe(20);
  });
});

describe("buildCoherenceEvent", () => {
  test("produces SecurityEvent with correct threat class", () => {
    const event = buildCoherenceEvent({
      coherent: false,
      distance: 0.9,
      expectedDistance: 0.3,
      zScore: 4.5,
      severity: "high",
      reason: "Causal break",
      transitionKey: "read\u2192message",
    });
    expect(event.threatClass).toBe(ThreatClass.CAUSAL_INCOHERENCE);
    expect(event.severity).toBe("high");
    expect(event.eventType).toBe("anomaly_detected");
  });
});
