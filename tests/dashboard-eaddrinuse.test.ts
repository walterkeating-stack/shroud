/**
 * Regression test: startDashboard must not crash on EADDRINUSE.
 * Before the fix, server.listen had no error handler — EADDRINUSE fired
 * asynchronously as an uncaught exception and crashed the process.
 */

import { createServer } from "node:http";
import { test, expect } from "vitest";
import { startDashboard } from "../src/dashboard.js";

const STUB_DEPS = {
  securityBus: null,
  agentTracker: { getAllSessions: () => [], getSession: () => null } as any,
  baselineStore: null,
  obfuscator: null as any,
  profiler: null,
  config: {} as any,
  policyEngine: null as any,
  agentSessionFile: "",
  driftDetector: null,
  appEventsFile: "",
  appSessionsFile: "",
};

test("startDashboard does not crash when port is already in use (EADDRINUSE)", async () => {
  // Occupy the port first
  const blocker = createServer();
  await new Promise<void>((resolve) => blocker.listen(0, "127.0.0.1", resolve));
  const port = (blocker.address() as any).port;

  // This must not throw or emit an uncaught exception
  let uncaughtFired = false;
  const onUncaught = () => { uncaughtFired = true; };
  process.once("uncaughtException", onUncaught);

  const dashboard = startDashboard(port, STUB_DEPS);

  // Give the async error event time to fire
  await new Promise((resolve) => setTimeout(resolve, 100));

  process.removeListener("uncaughtException", onUncaught);
  expect(uncaughtFired).toBe(false);

  // Cleanup
  await new Promise<void>((resolve) => dashboard.close(() => resolve()));
  await new Promise<void>((resolve) => blocker.close(() => resolve()));
});
