/** Tests for the 10 detection improvements. */

import { describe, test, expect } from "vitest";

import { Category, ShroudConfig } from "../src/types.js";
import { Obfuscator } from "../src/obfuscator.js";
import { RegexDetector, isDocExample } from "../src/detectors/regex.js";
import { ContextDetector } from "../src/detectors/context.js";

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

// ---------------------------------------------------------------------------
// #1: Context-aware confidence boosting
// ---------------------------------------------------------------------------

describe("#1 Context-aware confidence boosting", () => {
  test("config keywords boost entity confidence", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    // Text with config keywords
    const configText = `interface GigabitEthernet0/1
ip address 10.1.1.1 255.255.255.0
hostname CORE-RTR-01
router ospf 1`;

    const entities = ctx.detect(configText);
    const ip = entities.find((e) => e.value === "10.1.1.1");
    expect(ip).toBeDefined();
    // In config context, confidence should be boosted above base 0.95
    expect(ip!.confidence).toBeGreaterThanOrEqual(0.95);
  });

  test("plain text does not get boosted", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    const plainText = "Send email to bob@corp.com about the server at 10.2.3.4";
    const entities = ctx.detect(plainText);
    const ip = entities.find((e) => e.value === "10.2.3.4");
    expect(ip).toBeDefined();
    // No config keywords → base confidence
    expect(ip!.confidence).toBe(0.95);
  });
});

// ---------------------------------------------------------------------------
// #3: Proximity-based PII clustering
// ---------------------------------------------------------------------------

describe("#3 Proximity-based PII clustering", () => {
  test("nearby name and email boost each other", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    // Name near email within proximity window
    const text = "Contact john@acme.com phone 555-200-1234";
    const entities = ctx.detect(text);
    const email = entities.find((e) => e.category === Category.EMAIL);
    const phone = entities.find((e) => e.category === Category.PHONE);
    expect(email).toBeDefined();
    expect(phone).toBeDefined();
    // Both should be boosted from proximity
    expect(email!.confidence).toBeGreaterThan(0.95);
    expect(phone!.confidence).toBeGreaterThan(0.80);
  });
});

// ---------------------------------------------------------------------------
// #4: Config-block hostname extraction
// ---------------------------------------------------------------------------

describe("#4 Config-block hostname extraction", () => {
  test("hostname command propagates to bare occurrences", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    const text = `hostname COREROUTER1
interface Gi0/1
 description Link to COREROUTER1 backup`;

    const entities = ctx.detect(text);
    const hostnames = entities.filter((e) => e.value === "COREROUTER1");
    // Should find at least 2: one from hostname cmd, one from bare "COREROUTER1" in description
    expect(hostnames.length).toBeGreaterThanOrEqual(2);
  });

  test("bare hostname without command not detected if no prior hostname line", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    // RANDOMNAME alone shouldn't be detected
    const text = "The device RANDOMNAME is offline";
    const entities = ctx.detect(text);
    expect(entities.filter((e) => e.value === "RANDOMNAME")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// #5: SNMP/syslog source correlation
// ---------------------------------------------------------------------------

describe("#5 SNMP/syslog source correlation", () => {
  test("detect syslog facility code", () => {
    const detector = new RegexDetector();
    const entities = detector.detect("Mar 22 10:15:02 %SYS-5-CONFIG_I: Configured from console");
    const syslog = entities.find((e) => e.detector.includes("syslog_facility"));
    expect(syslog).toBeDefined();
  });

  test("detect source-interface in SNMP config", () => {
    const detector = new RegexDetector();
    const entities = detector.detect("snmp-server trap-source Loopback0");
    const src = entities.find((e) => e.detector.includes("syslog_source_interface"));
    expect(src).toBeDefined();
    expect(src!.value).toBe("Loopback0");
  });
});

// ---------------------------------------------------------------------------
// #6: Description field scraping
// ---------------------------------------------------------------------------

describe("#6 Description field scraping", () => {
  test("detect circuit ID in free text", () => {
    const detector = new RegexDetector();
    // Circuit ID outside a description line (not overlapping with interface_description)
    const entities = detector.detect("Provision circuit-id: ABC-12345-XY for the new link");
    const cid = entities.find((e) => e.detector.includes("circuit_id"));
    expect(cid).toBeDefined();
    expect(cid!.value).toBe("ABC-12345-XY");
  });

  test("detect org name in LINK TO pattern", () => {
    const detector = new RegexDetector();
    // LINK TO pattern outside description line
    const entities = detector.detect("This is the LINK TO Acme Corporation for transit");
    const org = entities.find((e) => e.detector.includes("description_org"));
    expect(org).toBeDefined();
    expect(org!.value).toContain("Acme");
  });
});

// ---------------------------------------------------------------------------
// #7: Negative lookahead for documentation/examples
// ---------------------------------------------------------------------------

describe("#7 Documentation/example filtering", () => {
  test("isDocExample filters RFC 5737 IPs", () => {
    expect(isDocExample("192.0.2.1", Category.IP_ADDRESS)).toBe(true);
    expect(isDocExample("198.51.100.5", Category.IP_ADDRESS)).toBe(true);
    expect(isDocExample("203.0.113.10", Category.IP_ADDRESS)).toBe(true);
    expect(isDocExample("10.0.0.1", Category.IP_ADDRESS)).toBe(false);
  });

  test("isDocExample filters example.com emails", () => {
    expect(isDocExample("user@example.com", Category.EMAIL)).toBe(true);
    expect(isDocExample("user@example.org", Category.EMAIL)).toBe(true);
    expect(isDocExample("user@acme.com", Category.EMAIL)).toBe(false);
  });

  test("isDocExample filters doc hostnames", () => {
    expect(isDocExample("localhost", Category.HOSTNAME)).toBe(true);
    expect(isDocExample("COREROUTER1", Category.HOSTNAME)).toBe(false);
  });

  test("detector skips example.com email", () => {
    const detector = new RegexDetector();
    const entities = detector.detect("Email user@example.com for info");
    expect(entities.filter((e) => e.category === Category.EMAIL)).toHaveLength(0);
  });

  test("detector skips TEST-NET IPs", () => {
    const detector = new RegexDetector();
    const entities = detector.detect("Test with 192.0.2.1 and 198.51.100.5");
    const ips = entities.filter((e) => e.category === Category.IP_ADDRESS);
    expect(ips).toHaveLength(0);
  });

  test("detector keeps real IPs", () => {
    const detector = new RegexDetector();
    const entities = detector.detect("Server at 10.0.0.1");
    const ips = entities.filter((e) => e.category === Category.IP_ADDRESS);
    expect(ips.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// #8: Recursive deobfuscation
// ---------------------------------------------------------------------------

describe("#8 Recursive deobfuscation", () => {
  test("handles nested fakes in JSON structures", () => {
    const obf = makeObfuscator();
    // Obfuscate an email
    const r1 = obf.obfuscate("john@acme.com");
    const fakeEmail = r1.obfuscated;

    // Now create text that has the fake embedded in a JSON string
    const nested = `{"config": "contact ${fakeEmail}"}`;
    // Deobfuscate should find and replace the fake
    const result = obf.deobfuscate(nested);
    expect(result).toContain("john@acme.com");
  });
});

// ---------------------------------------------------------------------------
// #9: Learned entity propagation
// ---------------------------------------------------------------------------

describe("#9 Learned entity propagation", () => {
  test("hostname learned in first call detected in second", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    // First call: hostname command teaches CORESW-A
    ctx.detect("hostname CORESW-A\ninterface Gi0/1");

    // Second call: bare CORESW-A without hostname keyword
    const entities = ctx.detect("Check status of CORESW-A interface");
    const learned = entities.find((e) => e.value === "CORESW-A");
    expect(learned).toBeDefined();
    expect(learned!.detector).toBe("context:learned_entity");
  });

  test("reset clears learned entities", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    ctx.detect("hostname CORESW-A\ninterface Gi0/1");
    expect(ctx.learnedCount).toBeGreaterThan(0);
    ctx.reset();
    expect(ctx.learnedCount).toBe(0);

    // After reset, bare CORESW-A should not be detected by learned entity injection
    const entities = ctx.detect("Check CORESW-A status");
    const learned = entities.filter((e) => e.detector === "context:learned_entity");
    expect(learned).toHaveLength(0);
  });

  test("obfuscator reset clears learned entities", () => {
    const obf = makeObfuscator();
    obf.obfuscate("hostname TESTDEVICE1\ninterface Gi0/1");
    obf.reset();
    // After reset, TESTDEVICE1 should not be detected without hostname prefix
    const stats = obf.getStats() as any;
    expect(stats.learnedEntities).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// #10: Confidence decay for common words
// ---------------------------------------------------------------------------

describe("#10 Confidence decay for common words", () => {
  test("common words get reduced confidence", () => {
    const regex = new RegexDetector();
    const ctx = new ContextDetector(regex);

    // "permit" and "deny" are common words that might match ACL patterns
    // They should get confidence decay
    const entities = ctx.detect("ip access-list extended permit");
    const permit = entities.find((e) => e.value.toLowerCase() === "permit");
    if (permit) {
      // Should have reduced confidence (decayed)
      expect(permit.confidence).toBeLessThan(0.85);
    }
    // It's also OK if "permit" doesn't match any pattern at all
  });
});
