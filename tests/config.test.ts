import { describe, test, expect } from "vitest";

import { resolveConfig, validateConfig } from "../src/config.js";

describe("Config validation (QW7)", () => {
  test("valid default config has no errors", () => {
    const config = resolveConfig({});
    const issues = validateConfig(config);
    const errors = issues.filter((i) => i.severity === "error");
    expect(errors).toHaveLength(0);
  });

  test("short secretKey produces error", () => {
    const config = resolveConfig({ secretKey: "abc" });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "secretKey" && i.severity === "error")).toBe(true);
  });

  test("minConfidence out of range produces error", () => {
    const config = resolveConfig({ minConfidence: 2.0 });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "minConfidence" && i.severity === "error")).toBe(true);
  });

  test("negative maxStoreMappings produces error", () => {
    const config = resolveConfig({ maxStoreMappings: -1 });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "maxStoreMappings" && i.severity === "error")).toBe(true);
  });

  test("invalid custom pattern regex produces error", () => {
    const config = resolveConfig({
      customPatterns: [{ name: "bad", pattern: "[invalid((" }],
    });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "customPatterns" && i.severity === "error")).toBe(true);
  });

  test("dryRun produces info", () => {
    const config = resolveConfig({ dryRun: true });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "dryRun" && i.severity === "info")).toBe(true);
  });

  test("dashboard alias and bind are respected", () => {
    const config = resolveConfig({ dashboard: true, dashboardBind: "127.0.0.2" });
    expect(config.dashboardEnabled).toBe(true);
    expect(config.dashboardBind).toBe("127.0.0.2");
  });

  test("profilingMode enforcing alias maps to active", () => {
    const config = resolveConfig({ profilingMode: "enforcing" });
    expect(config.profilingMode).toBe("active");
  });

});
