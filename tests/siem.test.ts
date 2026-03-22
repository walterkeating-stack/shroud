import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  SiemEventBuilder,
  CefFormatter,
  WebhookSink,
  SiemEvent,
  SiemSinkConfig,
} from "../src/siem.js";

describe("SiemEventBuilder", () => {
  beforeEach(() => {
    SiemEventBuilder._resetSeq();
  });

  it("builds obfuscation_summary events", () => {
    const event = SiemEventBuilder.obfuscationSummary("tenant1", "sess1", "req1", {
      totalEntities: 5,
      byCategory: { email: 3, ip_address: 2 },
      byRule: { "regex:email": 3 },
      inputChars: 100,
      outputChars: 120,
    });
    expect(event.eventType).toBe("obfuscation_summary");
    expect(event.severity).toBe(0);
    expect(event.seq).toBe(1);
    expect(event.data.totalEntities).toBe(5);
  });

  it("builds leak_detected events with high severity", () => {
    const event = SiemEventBuilder.leakDetected("t1", "s1", "r1", {
      category: "email",
      count: 1,
    });
    expect(event.eventType).toBe("leak_detected");
    expect(event.severity).toBe(7);
  });

  it("builds exposure_alert events", () => {
    const event = SiemEventBuilder.exposureAlert("t1", "s1", "r1", {
      category: "ip_address",
      count: 50,
      threshold: 10,
      message: "exceeded",
    });
    expect(event.eventType).toBe("exposure_alert");
    expect(event.severity).toBe(7);
  });

  it("builds key_rotation events", () => {
    const event = SiemEventBuilder.keyRotation("t1", "s1", {
      oldVersion: 1,
      newVersion: 2,
      totalKeys: 2,
    });
    expect(event.eventType).toBe("key_rotation");
    expect(event.severity).toBe(5);
  });

  it("sequence numbers are monotonic", () => {
    const e1 = SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 1 });
    const e2 = SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 2 });
    expect(e2.seq).toBe(e1.seq + 1);
  });
});

describe("CefFormatter", () => {
  it("formats events in CEF standard", () => {
    const event = SiemEventBuilder.obfuscationSummary("t1", "s1", "r1", {
      totalEntities: 3,
      byCategory: {},
      byRule: {},
      inputChars: 50,
      outputChars: 60,
    });
    const cef = CefFormatter.format(event);
    expect(cef).toContain("CEF:0|Shroud|OpenClaw-Shroud|1.0.0|obfuscation_summary");
    expect(cef).toContain("src=t1");
    expect(cef).toContain("sessionId=s1");
  });

  it("maps severity correctly", () => {
    const lowEvent: SiemEvent = {
      timestamp: new Date().toISOString(),
      seq: 1,
      eventType: "obfuscation_summary",
      source: "t",
      sessionId: "s",
      requestId: "r",
      severity: 0,
      data: {},
    };
    expect(CefFormatter.format(lowEvent)).toContain("|Low|");

    const highEvent = { ...lowEvent, severity: 7 };
    expect(CefFormatter.format(highEvent)).toContain("|High|");

    const critEvent = { ...lowEvent, severity: 10 };
    expect(CefFormatter.format(critEvent)).toContain("|Critical|");
  });
});

describe("WebhookSink", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    SiemEventBuilder._resetSeq();
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function makeConfig(overrides?: Partial<SiemSinkConfig>): SiemSinkConfig {
    return {
      endpoints: [{ url: "https://siem.example.com/events" }],
      batchSize: 10,
      flushIntervalMs: 0, // disable timer for tests
      maxRetries: 1,
      retryBackoffMs: 10,
      eventFormat: "json",
      ...overrides,
    };
  }

  it("buffers events and flushes at threshold", async () => {
    const calls: any[] = [];
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true }) as any;

    const sink = new WebhookSink(makeConfig({ batchSize: 3 }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r1", { replacementCount: 1 }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r2", { replacementCount: 2 }));
    // Not flushed yet (below threshold)
    expect(globalThis.fetch).not.toHaveBeenCalled();

    // Third event triggers flush
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r3", { replacementCount: 3 }));

    // Give async flush time to complete
    await new Promise((r) => setTimeout(r, 50));
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);

    await sink.destroy();
  });

  it("sends correct JSON payload", async () => {
    let sentBody = "";
    globalThis.fetch = vi.fn().mockImplementation(async (_url: string, opts: any) => {
      sentBody = opts.body;
      return { ok: true };
    }) as any;

    const sink = new WebhookSink(makeConfig({ batchSize: 1 }));
    sink.emit(SiemEventBuilder.obfuscationSummary("t", "s", "r", {
      totalEntities: 5, byCategory: {}, byRule: {}, inputChars: 10, outputChars: 20,
    }));

    await new Promise((r) => setTimeout(r, 50));
    const parsed = JSON.parse(sentBody);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].eventType).toBe("obfuscation_summary");
    await sink.destroy();
  });

  it("sends CEF format when configured", async () => {
    let sentBody = "";
    globalThis.fetch = vi.fn().mockImplementation(async (_url: string, opts: any) => {
      sentBody = opts.body;
      return { ok: true };
    }) as any;

    const sink = new WebhookSink(makeConfig({ batchSize: 1, eventFormat: "cef" }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 1 }));
    await new Promise((r) => setTimeout(r, 50));
    expect(sentBody).toContain("CEF:0|Shroud");
    await sink.destroy();
  });

  it("includes auth header when configured", async () => {
    let sentHeaders: any = {};
    globalThis.fetch = vi.fn().mockImplementation(async (_url: string, opts: any) => {
      sentHeaders = opts.headers;
      return { ok: true };
    }) as any;

    const sink = new WebhookSink(makeConfig({
      batchSize: 1,
      endpoints: [{ url: "https://siem.example.com", authHeader: "Bearer tok123" }],
    }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 1 }));
    await new Promise((r) => setTimeout(r, 50));
    expect(sentHeaders.Authorization).toBe("Bearer tok123");
    await sink.destroy();
  });

  it("filters events by endpoint eventTypes", async () => {
    let sentBody = "";
    globalThis.fetch = vi.fn().mockImplementation(async (_url: string, opts: any) => {
      sentBody = opts.body;
      return { ok: true };
    }) as any;

    const sink = new WebhookSink(makeConfig({
      batchSize: 2,
      endpoints: [{ url: "https://siem.example.com", eventTypes: ["exposure_alert"] }],
    }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 1 }));
    sink.emit(SiemEventBuilder.exposureAlert("t", "s", "r", {
      category: "email", count: 10, threshold: 5, message: "test",
    }));
    await new Promise((r) => setTimeout(r, 50));

    if (sentBody) {
      const parsed = JSON.parse(sentBody);
      expect(parsed.length).toBe(1);
      expect(parsed[0].eventType).toBe("exposure_alert");
    }
    await sink.destroy();
  });

  it("retries on failure", async () => {
    let callCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      callCount++;
      if (callCount <= 1) return { ok: false, status: 500 };
      return { ok: true };
    }) as any;

    const sink = new WebhookSink(makeConfig({ batchSize: 1, maxRetries: 2, retryBackoffMs: 10 }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 1 }));
    await new Promise((r) => setTimeout(r, 200));
    expect(callCount).toBe(2); // 1 fail + 1 success
    await sink.destroy();
  });

  it("destroy drains remaining buffer", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true }) as any;

    const sink = new WebhookSink(makeConfig({ batchSize: 100 }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 1 }));
    expect(globalThis.fetch).not.toHaveBeenCalled();

    await sink.destroy();
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("getStats returns correct counts", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true }) as any;

    const sink = new WebhookSink(makeConfig({ batchSize: 1 }));
    sink.emit(SiemEventBuilder.deobfuscation("t", "s", "r", { replacementCount: 1 }));
    await new Promise((r) => setTimeout(r, 50));

    const stats = sink.getStats();
    expect(stats.sent).toBe(1);
    expect(stats.buffered).toBe(0);
    await sink.destroy();
  });
});
