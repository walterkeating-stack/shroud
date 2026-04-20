import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { loadAppSessions, resolveAppSessionOutputPath, resolveRuntimePaths } from "../src/runtime.js";

describe("runtime helpers", () => {
  test("resolveRuntimePaths prefers SHROUD_RUNTIME_DIR", () => {
    const runtime = resolveRuntimePaths(undefined, {
      HOME: "/tmp/home",
      SHROUD_RUNTIME_DIR: "/tmp/shroud-runtime",
    });

    expect(runtime.stateDir).toBe("/tmp/shroud-runtime");
    expect(runtime.configPath).toBe("/tmp/shroud-runtime/shroud.config.json");
    expect(runtime.appSessionsDir).toBe("/tmp/shroud-runtime/app-sessions");
  });

  test("loadAppSessions merges multiple app session files by latest update", () => {
    const base = mkdtempSync(join(tmpdir(), "shroud-runtime-test-"));
    const appSessionsDir = join(base, "app-sessions");
    mkdirSync(appSessionsDir, { recursive: true });

    writeFileSync(join(appSessionsDir, "alpha-old.json"), JSON.stringify({
      agentLabel: "Alpha",
      agentBuildId: "build-alpha",
      requestCount: 1,
      updatedAt: "2026-04-20T10:00:00.000Z",
    }));
    writeFileSync(join(appSessionsDir, "alpha-new.json"), JSON.stringify({
      agentLabel: "Alpha",
      agentBuildId: "build-alpha",
      requestCount: 5,
      updatedAt: "2026-04-20T11:00:00.000Z",
    }));
    writeFileSync(join(appSessionsDir, "beta.json"), JSON.stringify({
      agentLabel: "Beta",
      requestCount: 2,
      updatedAt: "2026-04-20T09:30:00.000Z",
    }));

    const sessions = loadAppSessions({
      appSessionsDir,
      appSessionsFile: null,
    });

    expect(sessions).toHaveLength(2);
    expect(sessions.find((session) => session.agentBuildId === "build-alpha")?.requestCount).toBe(5);
    expect(sessions.find((session) => session.agentLabel === "Beta")?.requestCount).toBe(2);
  });

  test("resolveAppSessionOutputPath prefers build id over label", () => {
    const outputPath = resolveAppSessionOutputPath(
      { appSessionsDir: "/tmp/app-sessions", appSessionsFile: null },
      { agentLabel: "My Agent", agentBuildId: "build-1234", pid: 99 },
    );

    expect(outputPath).toBe("/tmp/app-sessions/build-1234.json");
  });
});
