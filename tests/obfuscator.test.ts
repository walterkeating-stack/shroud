import { describe, test, expect } from "vitest";

import { ShroudConfig, Category, DetectedEntity } from "../src/types.js";
import { Obfuscator, resolveOverlaps } from "../src/obfuscator.js";

const testConfig: ShroudConfig = {
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

function makeObfuscator(overrides?: Partial<ShroudConfig>): Obfuscator {
  return new Obfuscator({ ...testConfig, ...overrides });
}

describe("Obfuscator", () => {
  test("obfuscate email: real email not in output", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("Contact john@acme.com for info");
    expect(result.obfuscated).not.toContain("john@acme.com");
    expect(result.obfuscated).toContain("@"); // Replaced with fake email
    expect(result.mappingsUsed).toHaveProperty("john@acme.com");
  });

  test("obfuscate IP: real IP not in output, fake in CGNAT range", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("Server at 192.168.1.100");
    expect(result.obfuscated).not.toContain("192.168.1.100");
    expect(result.obfuscated).toContain("100."); // CGNAT range
  });

  test("obfuscate API key: real key not in output", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate(
      "Use key sk-abc123def456ghi789jkl012mno345",
    );
    expect(result.obfuscated).not.toContain(
      "sk-abc123def456ghi789jkl012mno345",
    );
  });

  test("deobfuscate roundtrip: obfuscate then deobfuscate returns original", () => {
    const obf = makeObfuscator();
    const original = "Send to john@acme.com from 192.168.1.100";
    const result = obf.obfuscate(original);
    const restored = obf.deobfuscate(result.obfuscated);
    expect(restored).toBe(original);
  });

  test("deterministic: same text + same config produces same output", () => {
    const obf = makeObfuscator();
    const r1 = obf.obfuscate("Contact john@acme.com");
    const r2 = obf.obfuscate("Also reach john@acme.com here");
    // Same email should map to same fake
    expect(r1.mappingsUsed["john@acme.com"]).toBe(
      r2.mappingsUsed["john@acme.com"],
    );
  });

  test("allowlist: listed values not obfuscated", () => {
    const obf = makeObfuscator({ allowlist: ["10.0.0.1"] });
    const result = obf.obfuscate("Server at 10.0.0.1");
    expect(result.obfuscated).toContain("10.0.0.1");
  });

  test("denylist: listed values always obfuscated", () => {
    const obf = makeObfuscator({ denylist: ["SecretProject"] });
    const result = obf.obfuscate("Working on SecretProject today");
    expect(result.obfuscated).not.toContain("SecretProject");
  });

  test("confidence filtering works", () => {
    // Set a high minConfidence that should filter out lower confidence detections
    const obf = makeObfuscator({ minConfidence: 0.99 });
    // Phone detection has confidence 0.8, should be filtered
    const result = obf.obfuscate("Call (555) 123-4567");
    // The phone might still be there since confidence is below threshold
    // At 0.99 threshold, only confidence >= 0.99 entities pass
    expect(result.entities.every((e) => e.confidence >= 0.99)).toBe(true);
  });

  test("empty text returns empty", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("");
    expect(result.obfuscated).toBe("");
    expect(Object.keys(result.mappingsUsed).length).toBe(0);
  });

  test("text with no PII returns unchanged", () => {
    const obf = makeObfuscator();
    const text = "The quick brown fox jumps over the lazy dog";
    const result = obf.obfuscate(text);
    expect(result.obfuscated).toBe(text);
    expect(Object.keys(result.mappingsUsed).length).toBe(0);
  });

  test("multiple entities in one text all obfuscated", () => {
    const obf = makeObfuscator();
    const text =
      "Email john@acme.com, server 10.20.30.40, key sk-abcdefghijklmnopqrstuv";
    const result = obf.obfuscate(text);
    expect(result.obfuscated).not.toContain("john@acme.com");
    expect(result.obfuscated).not.toContain("10.20.30.40");
    expect(Object.keys(result.mappingsUsed).length).toBeGreaterThanOrEqual(2);
  });

  test("complex text roundtrip", () => {
    const obf = makeObfuscator();
    const text =
      "Hi, this is John from Acme Corp. " +
      "Please email me at john.doe@acme-corp.com or call (555) 123-4567. " +
      "Our server is at 172.16.0.50 and the docs are at " +
      "https://internal.acme-corp.com/docs. " +
      "My SSN is 123-45-6789.";
    const result = obf.obfuscate(text);
    expect(result.obfuscated).not.toContain("john.doe@acme-corp.com");
    expect(result.obfuscated).not.toContain("172.16.0.50");
    expect(result.obfuscated).not.toContain("123-45-6789");
    const restored = obf.deobfuscate(result.obfuscated);
    expect(restored).toContain("john.doe@acme-corp.com");
    expect(restored).toContain("172.16.0.50");
  });
});

describe("resolveOverlaps", () => {
  test("keeps higher confidence, removes overlapping", () => {
    const entities: DetectedEntity[] = [
      {
        value: "123-45-6789",
        start: 0,
        end: 11,
        category: Category.SSN,
        confidence: 0.9,
        detector: "regex",
      },
      {
        value: "123-45",
        start: 0,
        end: 6,
        category: Category.PHONE,
        confidence: 0.5,
        detector: "regex",
      },
    ];
    // Sort as the obfuscator would: by start, then higher confidence first
    entities.sort(
      (a, b) => a.start - b.start || b.confidence - a.confidence,
    );
    const resolved = resolveOverlaps(entities);
    expect(resolved.length).toBe(1);
    expect(resolved[0].category).toBe(Category.SSN);
  });

  test("non-overlapping entities are all kept", () => {
    const entities: DetectedEntity[] = [
      {
        value: "john@test.com",
        start: 0,
        end: 13,
        category: Category.EMAIL,
        confidence: 0.95,
        detector: "regex",
      },
      {
        value: "10.0.0.1",
        start: 20,
        end: 28,
        category: Category.IP_ADDRESS,
        confidence: 0.95,
        detector: "regex",
      },
    ];
    const resolved = resolveOverlaps(entities);
    expect(resolved.length).toBe(2);
  });

  test("empty input returns empty", () => {
    expect(resolveOverlaps([])).toEqual([]);
  });
});

describe("Obfuscator - rule hit counters", () => {
  test("getStats includes ruleHits after obfuscation", () => {
    const obf = makeObfuscator();
    obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    const stats = obf.getStats() as any;
    expect(stats.ruleHits).toBeDefined();
    expect(stats.ruleHits["regex:email"]).toBe(1);
    expect(stats.ruleHits["regex:ipv4"]).toBe(1);
  });

  test("ruleHits accumulate across calls", () => {
    const obf = makeObfuscator();
    obf.obfuscate("Email john@acme.com");
    obf.obfuscate("Email bob@test.com");
    const stats = obf.getStats() as any;
    expect(stats.ruleHits["regex:email"]).toBe(2);
  });

  test("reset clears ruleHits", () => {
    const obf = makeObfuscator();
    obf.obfuscate("Email john@acme.com");
    obf.reset();
    const stats = obf.getStats() as any;
    expect(Object.keys(stats.ruleHits).length).toBe(0);
  });

  test("detectorOverrides disables rule in obfuscation", () => {
    const obf = makeObfuscator({ detectorOverrides: { email: { enabled: false } } });
    const result = obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    expect(result.obfuscated).toContain("john@acme.com");
    expect(result.obfuscated).not.toContain("10.0.0.1");
  });
});

// ---------------------------------------------------------------------------
// Enterprise features
// ---------------------------------------------------------------------------

describe("Feature 1: Multi-tenant isolation", () => {
  test("same value produces different fakes for different tenants", () => {
    const obf1 = makeObfuscator({ tenantId: "tenant-a" });
    const obf2 = makeObfuscator({ tenantId: "tenant-b" });
    const r1 = obf1.obfuscate("john@acme.com");
    const r2 = obf2.obfuscate("john@acme.com");
    // Both obfuscate, but produce different fakes
    expect(r1.obfuscated).not.toContain("john@acme.com");
    expect(r2.obfuscated).not.toContain("john@acme.com");
    expect(r1.obfuscated).not.toBe(r2.obfuscated);
  });

  test("switchTenant changes mapping context", () => {
    const obf = makeObfuscator({ tenantId: "t1" });
    obf.obfuscate("john@acme.com");
    obf.switchTenant("t2");
    // New tenant has no mappings yet
    const stats = obf.getStats() as any;
    expect(stats.storeMappings).toBe(0);
  });
});

describe("Feature 2: Session handoff", () => {
  test("export and import preserves mappings", () => {
    const obf1 = makeObfuscator({ sessionHandoff: true });
    const r1 = obf1.obfuscate("Contact john@acme.com");
    const blob = obf1.exportSession();

    const obf2 = makeObfuscator({ sessionHandoff: true });
    obf2.importSession(blob);
    // Should deobfuscate using imported mappings
    const deobfuscated = obf2.deobfuscate(r1.obfuscated);
    expect(deobfuscated).toContain("john@acme.com");
  });

  test("encrypted blob is not plaintext", () => {
    const obf = makeObfuscator({ sessionHandoff: true });
    obf.obfuscate("john@acme.com");
    const blob = obf.exportSession();
    expect(blob).not.toContain("john@acme.com");
    expect(blob).not.toContain("acme");
  });
});

describe("Feature 3: Tool chain depth", () => {
  test("enterToolCall increments depth", () => {
    const obf = makeObfuscator();
    expect(obf.toolDepth).toBe(0);
    expect(obf.enterToolCall()).toBe(1);
    expect(obf.enterToolCall()).toBe(2);
    expect(obf.exitToolCall()).toBe(1);
    expect(obf.exitToolCall()).toBe(0);
  });

  test("exitToolCall does not go below 0", () => {
    const obf = makeObfuscator();
    expect(obf.exitToolCall()).toBe(0);
    expect(obf.exitToolCall()).toBe(0);
  });

  test("reset clears tool depth", () => {
    const obf = makeObfuscator();
    obf.enterToolCall();
    obf.enterToolCall();
    obf.reset();
    expect(obf.toolDepth).toBe(0);
  });
});

describe("Feature 4: Compliance-mode entity locking", () => {
  test("reports found and missing locked categories", () => {
    const obf = makeObfuscator({
      lockedCategories: [Category.EMAIL, Category.CREDIT_CARD],
    });
    const result = obf.obfuscate("Contact john@acme.com for info");
    expect(result.complianceReport).toBeDefined();
    expect(result.complianceReport!.found).toContain(Category.EMAIL);
    expect(result.complianceReport!.missing).toContain(Category.CREDIT_CARD);
    expect(result.complianceReport!.passed).toBe(false);
  });

  test("passed=true when all locked categories found", () => {
    const obf = makeObfuscator({
      lockedCategories: [Category.EMAIL],
    });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.complianceReport!.passed).toBe(true);
    expect(result.complianceReport!.missing).toHaveLength(0);
  });

  test("no complianceReport when lockedCategories empty", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.complianceReport).toBeUndefined();
  });
});

describe("Feature 5: Rate-of-exposure tracking", () => {
  test("detects exposure spike", () => {
    const obf = makeObfuscator({
      exposureThresholds: { email: 1 },
      exposureGlobalThreshold: 1000,
    });
    obf.obfuscate("a@b.com c@d.com");
    const alerts = obf.getExposureAlerts();
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0].category).toBe("email");
  });

  test("no alerts when under threshold", () => {
    const obf = makeObfuscator({
      exposureThresholds: { email: 100 },
      exposureGlobalThreshold: 1000,
    });
    obf.obfuscate("a@b.com");
    expect(obf.getExposureAlerts()).toHaveLength(0);
  });
});

describe("Feature 6: Corpus pre-scanning", () => {
  test("batch obfuscate documents", () => {
    const obf = makeObfuscator();
    const docs = [
      { id: "1", text: "Email john@acme.com" },
      { id: "2", text: "IP 10.0.0.1" },
    ];
    const result = obf.preScanCorpus(docs);
    expect(result.documents).toHaveLength(2);
    expect(result.documents[0].obfuscated).not.toContain("john@acme.com");
    expect(result.documents[1].obfuscated).not.toContain("10.0.0.1");
    expect(result.mappingRef).toBeTruthy();
    expect(typeof result.mappingRef).toBe("string");
  });
});

describe("Feature 8: Redaction levels", () => {
  test("masked mode partially masks values", () => {
    const obf = makeObfuscator({ redactionLevel: "masked" });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.obfuscated).not.toContain("john@acme.com");
    expect(result.obfuscated).toContain("***");
  });

  test("stats mode uses category placeholders", () => {
    const obf = makeObfuscator({ redactionLevel: "stats" });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.obfuscated).toContain("[EMAIL-");
  });

  test("full mode uses fake values (default)", () => {
    const obf = makeObfuscator({ redactionLevel: "full" });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.obfuscated).toContain("@");
    expect(result.obfuscated).not.toContain("[EMAIL");
    expect(result.obfuscated).not.toContain("***");
  });
});

describe("Feature 10: Provenance tagging", () => {
  test("adds provenance markers when enabled", () => {
    const obf = makeObfuscator({ provenanceTagging: true });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.obfuscated).toContain("\u00abshroud:");
    expect(result.obfuscated).toContain("\u00bb");
  });

  test("deobfuscate strips provenance markers", () => {
    const obf = makeObfuscator({ provenanceTagging: true });
    const result = obf.obfuscate("Contact john@acme.com");
    const deob = obf.deobfuscate(result.obfuscated);
    expect(deob).toContain("john@acme.com");
    expect(deob).not.toContain("\u00abshroud:");
  });

  test("no markers when disabled", () => {
    const obf = makeObfuscator({ provenanceTagging: false });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.obfuscated).not.toContain("\u00abshroud:");
  });
});

// ---------------------------------------------------------------------------
// Subnet-aware deobfuscation (LLM-derived network addresses)
// ---------------------------------------------------------------------------

describe("Subnet-aware deobfuscation", () => {
  test("deobfuscates LLM-derived network address from host IP + mask", () => {
    const obf = makeObfuscator();

    // Obfuscate a config block with IP + mask so SubnetMapper learns the subnet
    const configText = "ip address 10.1.2.1 255.255.255.0";
    const result = obf.obfuscate(configText);

    // Extract the fake IP (should be 100.64.X.1)
    const fakeMatch = result.obfuscated.match(/(\d+\.\d+\.\d+)\.1/);
    expect(fakeMatch).toBeTruthy();
    const fakePrefix = fakeMatch![1]; // e.g. "100.64.0"

    // Simulate the LLM computing the network address from the fake
    const llmText = `Subnet: ${fakePrefix}.0/24 (gateway: ${fakePrefix}.1)`;
    const deobfuscated = obf.deobfuscate(llmText);

    // The gateway .1 should be deobfuscated via normal store lookup
    expect(deobfuscated).toContain("10.1.2.1");
    // The network .0 should be deobfuscated via subnet-aware reverse mapping
    expect(deobfuscated).toContain("10.1.2.0");
    // No CGNAT IPs should remain
    expect(deobfuscated).not.toMatch(/100\.6[4-9]\.|100\.[7-9]\d\.|100\.1[01]\d\.|100\.12[0-7]\./);
  });

  test("deobfuscates broadcast address derived by LLM", () => {
    const obf = makeObfuscator();

    const configText = "ip address 172.16.5.1 255.255.255.128";
    const result = obf.obfuscate(configText);

    // Extract the fake host IP
    const fakeMatch = result.obfuscated.match(/(100\.\d+\.\d+)\.1/);
    expect(fakeMatch).toBeTruthy();
    const fakePrefix = fakeMatch![1];

    // LLM computes network (.0) and broadcast (.127) from /25
    const llmText = `Network: ${fakePrefix}.0/25, Broadcast: ${fakePrefix}.127`;
    const deobfuscated = obf.deobfuscate(llmText);

    expect(deobfuscated).toContain("172.16.5.0");
    expect(deobfuscated).toContain("172.16.5.127");
  });

  test("deobfuscateWithStats includes subnet-aware replacements in count", () => {
    const obf = makeObfuscator();

    const configText = "ip address 10.99.1.1 255.255.255.0";
    const result = obf.obfuscate(configText);

    const fakeMatch = result.obfuscated.match(/(\d+\.\d+\.\d+)\.1/);
    expect(fakeMatch).toBeTruthy();
    const fakePrefix = fakeMatch![1];

    const llmText = `Network: ${fakePrefix}.0/24`;
    const { text, replacementCount } = obf.deobfuscateWithStats(llmText);

    expect(text).toContain("10.99.1.0");
    expect(replacementCount).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// QW6: Dry-run mode
// ---------------------------------------------------------------------------

describe("Dry-run mode (QW6)", () => {
  test("dryRun returns original text unchanged", () => {
    const obf = makeObfuscator({ dryRun: true });
    const result = obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    expect(result.obfuscated).toBe(result.original);
    expect(result.obfuscated).toContain("john@acme.com");
    expect(result.obfuscated).toContain("10.0.0.1");
  });

  test("dryRun still detects entities", () => {
    const obf = makeObfuscator({ dryRun: true });
    const result = obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    expect(result.entities.length).toBeGreaterThan(0);
    const categories = result.entities.map((e) => e.category);
    expect(categories).toContain(Category.EMAIL);
    expect(categories).toContain(Category.IP_ADDRESS);
  });

  test("dryRun does not populate store mappings", () => {
    const obf = makeObfuscator({ dryRun: true });
    obf.obfuscate("Contact john@acme.com");
    expect(Object.keys(obf.obfuscate("x").mappingsUsed)).toHaveLength(0);
  });

  test("dryRun returns empty mappingsUsed", () => {
    const obf = makeObfuscator({ dryRun: true });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(Object.keys(result.mappingsUsed)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// QW2: Per-category stats
// ---------------------------------------------------------------------------

describe("Per-category stats (QW2)", () => {
  test("getStats includes detectionsByCategory", () => {
    const obf = makeObfuscator();
    obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    const stats = obf.getStats() as any;
    expect(stats.detectionsByCategory).toBeDefined();
    expect(stats.detectionsByCategory[Category.EMAIL]).toBeGreaterThanOrEqual(1);
    expect(stats.detectionsByCategory[Category.IP_ADDRESS]).toBeGreaterThanOrEqual(1);
  });

  test("getStats includes replacementsByCategory", () => {
    const obf = makeObfuscator();
    obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    const stats = obf.getStats() as any;
    expect(stats.replacementsByCategory).toBeDefined();
    expect(stats.replacementsByCategory[Category.EMAIL]).toBeGreaterThanOrEqual(1);
    expect(stats.replacementsByCategory[Category.IP_ADDRESS]).toBeGreaterThanOrEqual(1);
  });

  test("category stats accumulate across calls", () => {
    const obf = makeObfuscator();
    obf.obfuscate("a@b.com");
    obf.obfuscate("c@d.com");
    const stats = obf.getStats() as any;
    expect(stats.detectionsByCategory[Category.EMAIL]).toBeGreaterThanOrEqual(2);
  });

  test("reset clears category stats", () => {
    const obf = makeObfuscator();
    obf.obfuscate("a@b.com");
    obf.reset();
    const stats = obf.getStats() as any;
    expect(stats.detectionsByCategory[Category.EMAIL]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// QW8: Filter stats
// ---------------------------------------------------------------------------

describe("Filter stats (QW8)", () => {
  test("filterStats present in result", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.filterStats).toBeDefined();
    expect(result.filterStats!.totalDetected).toBeGreaterThan(0);
    expect(result.filterStats!.replaced).toBeGreaterThan(0);
  });

  test("belowThreshold counted when minConfidence filters", () => {
    const obf = makeObfuscator({ minConfidence: 0.99 });
    const result = obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    expect(result.filterStats!.belowThreshold).toBeGreaterThan(0);
  });

  test("allowlisted counted when allowlist matches", () => {
    const obf = makeObfuscator({ allowlist: ["john@acme.com"] });
    const result = obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    expect(result.filterStats!.allowlisted).toBeGreaterThanOrEqual(1);
  });

  test("alreadyObfuscated counted for known fakes", () => {
    const obf = makeObfuscator();
    // First call: creates mapping john@acme.com -> fake
    const r1 = obf.obfuscate("Contact john@acme.com");
    const fake = Object.values(r1.mappingsUsed)[0];
    // Second call: the fake email is detected but should be skipped
    const r2 = obf.obfuscate(`Contact ${fake}`);
    expect(r2.filterStats!.alreadyObfuscated).toBeGreaterThanOrEqual(1);
  });

  test("totalDetected >= replaced + belowThreshold + allowlisted + alreadyObfuscated", () => {
    const obf = makeObfuscator({ allowlist: ["john@acme.com"], minConfidence: 0.5 });
    const result = obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    const fs = result.filterStats!;
    expect(fs.totalDetected).toBeGreaterThanOrEqual(
      fs.replaced + fs.belowThreshold + fs.allowlisted + fs.alreadyObfuscated
    );
  });
});

// ---------------------------------------------------------------------------
// QW1: Wildcard allowlist
// ---------------------------------------------------------------------------

describe("Wildcard allowlist (QW1)", () => {
  test("glob * matches domain suffix", () => {
    const obf = makeObfuscator({ allowlist: ["*@acme.com"] });
    const result = obf.obfuscate("Contact john@acme.com and jane@acme.com");
    // Both emails should be preserved (allowlisted by wildcard)
    expect(result.obfuscated).toContain("john@acme.com");
    expect(result.obfuscated).toContain("jane@acme.com");
  });

  test("glob * matches IP prefix", () => {
    const obf = makeObfuscator({ allowlist: ["10.0.0.*"] });
    const result = obf.obfuscate("Server at 10.0.0.1 and 10.0.0.2");
    expect(result.obfuscated).toContain("10.0.0.1");
    expect(result.obfuscated).toContain("10.0.0.2");
  });

  test("wildcard does not match non-matching values", () => {
    const obf = makeObfuscator({ allowlist: ["*@acme.com"] });
    const result = obf.obfuscate("Contact john@other.com");
    expect(result.obfuscated).not.toContain("john@other.com");
  });

  test("? matches single character", () => {
    const obf = makeObfuscator({ allowlist: ["10.0.0.?"] });
    const result = obf.obfuscate("Server at 10.0.0.1");
    expect(result.obfuscated).toContain("10.0.0.1");
  });

  test("exact allowlist entries still work", () => {
    const obf = makeObfuscator({ allowlist: ["john@acme.com"] });
    const result = obf.obfuscate("Contact john@acme.com from 10.0.0.1");
    expect(result.obfuscated).toContain("john@acme.com");
    expect(result.obfuscated).not.toContain("10.0.0.1");
  });

  test("wildcard allowlisted entities counted in filterStats", () => {
    const obf = makeObfuscator({ allowlist: ["*@acme.com"] });
    const result = obf.obfuscate("Contact john@acme.com");
    expect(result.filterStats!.allowlisted).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// QW10: LRU eviction via obfuscator
// ---------------------------------------------------------------------------

describe("LRU eviction via obfuscator (QW10)", () => {
  test("maxStoreMappings limits store size", () => {
    const obf = makeObfuscator({ maxStoreMappings: 2 });
    obf.obfuscate("john@acme.com");
    obf.obfuscate("jane@corp.com");
    obf.obfuscate("bob@test.org");
    const stats = obf.getStats() as any;
    expect(stats.storeMappings).toBeLessThanOrEqual(2);
  });
});
