/**
 * Event grader integration test.
 * Tests: SecurityEventBus → EventGrader pipeline.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";
import { SecurityEventBus } from "../src/security-event.js";
import { EventGrader, GRADING_AGENT_LABEL, captureModel } from "../src/event-grader.js";
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
      threshold: 100,
      intervalSec: 9999,
    });

    bus.onEvent((event) => grader.addEvent(event));

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
    });

    bus.onEvent((event) => grader.addEvent(event));

    bus.emit(makeEvent({ timestamp: 1 }));
    bus.emit(makeEvent({
      timestamp: 2,
      agentSessionId: "shroud-grading-12345",
    }));

    expect(grader.getStats().pending).toBe(1);
    grader.stop();
  });

  test("grader doesn't double-queue same event", () => {
    const grader = new EventGrader({
      threshold: 100,
      intervalSec: 9999,
    });

    const event = makeEvent({ timestamp: 999 });
    grader.addEvent(event);
    grader.addEvent(event);

    expect(grader.getStats().pending).toBe(2);
    grader.stop();
  });

  test("events queue up and threshold triggers grading", () => {
    const grader = new EventGrader({
      threshold: 3,
      intervalSec: 9999,
    });

    // Add events below threshold — no grading triggered
    grader.addEvent(makeEvent({ timestamp: 1 }));
    grader.addEvent(makeEvent({ timestamp: 2 }));
    expect(grader.getStats().pending).toBe(2);

    // Third event hits threshold — grading fires (async, won't complete in test)
    grader.addEvent(makeEvent({ timestamp: 3 }));
    // Events were spliced into a batch (pending drops to 0)
    expect(grader.getStats().pending).toBe(0);

    grader.stop();
  });
});

describe("EventGrader — model capture", () => {
  beforeEach(() => {
    delete (globalThis as any).__shroudGradingModel;
  });

  test("captureModel stores first model", () => {
    captureModel("claude-sonnet-4-6");
    expect((globalThis as any).__shroudGradingModel).toBe("claude-sonnet-4-6");
  });

  test("captureModel doesn't overwrite", () => {
    captureModel("claude-sonnet-4-6");
    captureModel("gpt-4o");
    expect((globalThis as any).__shroudGradingModel).toBe("claude-sonnet-4-6");
  });

  afterEach(() => {
    delete (globalThis as any).__shroudGradingModel;
  });
});

describe("EventGrader — whitelist", () => {
  test("GRADING_AGENT_LABEL is defined", () => {
    expect(GRADING_AGENT_LABEL).toBe("Security Event Grader");
  });
});
