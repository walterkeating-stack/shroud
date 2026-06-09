/**
 * findResidualFakes — the write-path leak guard. Detects fake tokens/components
 * that survive in a payload the agent is about to write to a backend (a value
 * the model invented or recombined from fakes, which deobfuscate() can't reverse).
 */
import { describe, test, expect } from "vitest";

import { ShroudConfig } from "../src/types.js";
import { Obfuscator } from "../src/obfuscator.js";

const base: ShroudConfig = {
  secretKey: "test-secret-key-1234567890abcdef",
  persistentSalt: "fixed-test-salt",
  minConfidence: 0,
  allowlist: [],
  denylist: [],
  canaryEnabled: false,
  canaryPrefix: "SHROUD-CANARY",
  auditEnabled: false,
  logMappings: false,
  customPatterns: [],
  verboseLogging: false,
  auditLogFormat: "human" as const,
  auditIncludeProofHashes: false,
  auditHashSalt: "",
  auditHashTruncate: 12,
  auditMaxFakesSample: 0,
  detectorOverrides: {},
  tenantId: "",
  maxToolDepth: 10,
  lockedCategories: [],
  exposureWindow: 60000,
  exposureThresholds: {},
  exposureGlobalThreshold: 100,
  policyFile: "",
  redactionLevel: "full" as const,
  sharedStorePath: "",
  sharedStoreTtlMs: 5000,
  provenanceTagging: false,
  sessionHandoff: false,
  dryRun: false,
  maxStoreMappings: 0,
};

describe("findResidualFakes (write-path leak guard)", () => {
  test("flags leftover and composed fakes; passes real + clean text", () => {
    const obf = new Obfuscator({ ...base, denylist: ["vvoondi1asr01"] });
    const r = obf.obfuscate("device vvoondi1asr01 online");
    const fake = r.mappingsUsed["vvoondi1asr01"];
    expect(fake).toBeTruthy();
    expect(fake).not.toBe("vvoondi1asr01");

    // model echoed the fake verbatim (deob would have reversed it; here it slipped through)
    expect(obf.findResidualFakes(`name=${fake}`).length).toBeGreaterThan(0);
    // model COMPOSED a new value reusing the fake's obfuscated component
    expect(obf.findResidualFakes(`${fake}_new`).length).toBeGreaterThan(0);

    // the REAL value (what a correct deob yields) is clean
    expect(obf.findResidualFakes("device vvoondi1asr01 online")).toEqual([]);
    // unrelated clean text is clean
    expect(obf.findResidualFakes("just some words 42")).toEqual([]);
  });

  test("empty store / empty text -> clean", () => {
    const obf = new Obfuscator(base);
    expect(obf.findResidualFakes("")).toEqual([]);
    expect(obf.findResidualFakes("anything at all here")).toEqual([]);
  });

  test("residual fake CGNAT / ULA IPs are flagged, real IPs are not", () => {
    const obf = new Obfuscator(base);
    expect(obf.findResidualFakes("mgmt 100.64.3.7 up").length).toBeGreaterThan(0);
    expect(obf.findResidualFakes("v6 fd00:1234::5 up").length).toBeGreaterThan(0);
    expect(obf.findResidualFakes("real 10.0.0.1 and 8.8.8.8")).toEqual([]);
  });
});
