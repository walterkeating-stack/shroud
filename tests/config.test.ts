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

  test("sharedStorePath + tenantId conflict produces warning", () => {
    const config = resolveConfig({ sharedStorePath: "/tmp/shared.json", tenantId: "t1" });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "sharedStorePath" && i.severity === "warning")).toBe(true);
  });

  test("missing policy file produces warning", () => {
    const config = resolveConfig({ policyFile: "/nonexistent/policy.json" });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "policyFile" && i.severity === "warning")).toBe(true);
  });

  test("very short exposure window produces warning", () => {
    const config = resolveConfig({
      exposureWindow: 100,
      exposureThresholds: { email: 5 },
    });
    const issues = validateConfig(config);
    expect(issues.some((i) => i.field === "exposureWindow" && i.severity === "warning")).toBe(true);
  });
});
