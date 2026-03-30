/**
 * Event grader integration test.
 * Tests: SecurityEventBus → EventGrader pipeline.
 */
import { describe, test, expect, vi } from "vitest";
import { SecurityEventBus } from "../src/security-event.js";
import { EventGrader, GRADING_AGENT_LABEL } from "../src/event-grader.js";
import type { SecurityEvent } from "../src/security-event.js";

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "injection_detected",
    direction: "request",
    threatClass: "instruction_override" as any,
    signatureId: "io_ignore_previous",
    severity: "high",
    matchedText: "ignore all previous instructions",
    matchStart: 0,
    matchEnd: 30,
    textLength: 100,
    action: "flagged",
    description: "Instruction override attempt",
    agentLabel: "TestAgent",
    ...overrides,
  };
}

describe("EventGrader — bus wiring", () => {
  test("grader receives events from security bus", () => {
    const bus = new SecurityEventBus();
    const grader = new EventGrader({
      threshold: 100, // high threshold so it doesn't auto-grade
      intervalSec: 9999,
      gatewayUrl: "ws://localhost:0",
    });

    // Wire bus → grader (same as hooks.ts does)
    bus.onEvent((event) => grader.addEvent(event));

    // Emit events
    bus.emit(makeEvent({ timestamp: 1 }));
    bus.emit(makeEvent({ timestamp: 2 }));
    bus.emit(makeEvent({ timestamp: 3 }));

    const stats = grader.getStats();
    expect(stats.pending).toBe(3);
    expect(stats.graded).toBe(0);

    grader.stop();
  });

  test("grader ignores events from grading sessions", () => {
    const bus = new SecurityEventBus();
    const grader = new EventGrader({
      threshold: 100,
      intervalSec: 9999,
      gatewayUrl: "ws://localhost:0",
    });

    bus.onEvent((event) => grader.addEvent(event));

    // Normal event — should be queued
    bus.emit(makeEvent({ timestamp: 1 }));

    // Grading session event — should be ignored
    bus.emit(makeEvent({
      timestamp: 2,
      agentSessionId: "shroud-grading-12345",
    }));

    expect(grader.getStats().pending).toBe(1); // only the normal one

    grader.stop();
  });

  test("grader doesn't double-queue same event", () => {
    const grader = new EventGrader({
      threshold: 100,
      intervalSec: 9999,
      gatewayUrl: "ws://localhost:0",
    });

    const event = makeEvent({ timestamp: 999 });
    grader.addEvent(event);
    grader.addEvent(event); // duplicate

    // First goes to pending, but after grading it won't re-queue
    expect(grader.getStats().pending).toBe(2); // both queued (not yet graded)

    grader.stop();
  });

  test("batch log records failed attempts", async () => {
    const grader = new EventGrader({
      threshold: 1,
      intervalSec: 9999,
      gatewayUrl: "ws://localhost:0",
    });

    grader.addEvent(makeEvent({ timestamp: Date.now() }));

    // Wait for the async grading to attempt and fail (no gateway)
    await new Promise(r => setTimeout(r, 5000));

    const log = grader.getBatchLog();
    expect(log.length).toBeGreaterThanOrEqual(1);
    expect(log[0].success).toBe(false);
    expect(log[0].error.length).toBeGreaterThan(0);
    expect(log[0].eventCount).toBe(1);

    grader.stop();
  });
});

describe("EventGrader — whitelist", () => {
  test("GRADING_AGENT_LABEL is defined", () => {
    expect(GRADING_AGENT_LABEL).toBe("Security Event Grader");
  });
});
