import { describe, test, expect } from "vitest";

import { Category } from "../src/types.js";
import { RegexDetector, isMask } from "../src/detectors/regex.js";
import { CustomPatternDetector } from "../src/detectors/patterns.js";

describe("RegexDetector", () => {
  const detector = new RegexDetector();

  test("detect email", () => {
    const entities = detector.detect("Contact john.doe@acme.com for details");
    expect(entities.length).toBe(1);
    expect(entities[0].value).toBe("john.doe@acme.com");
    expect(entities[0].category).toBe(Category.EMAIL);
  });

  test("detect IPv4", () => {
    const entities = detector.detect("Server is at 192.168.1.100");
    expect(
      entities.some(
        (e) => e.category === Category.IP_ADDRESS && e.value === "192.168.1.100",
      ),
    ).toBe(true);
  });

  test("detect phone", () => {
    const entities = detector.detect("Call me at (555) 123-4567");
    expect(entities.some((e) => e.category === Category.PHONE)).toBe(true);
  });

  test("detect API key", () => {
    const entities = detector.detect(
      "Use key SHROUD_TEST_API_KEY",
    );
    expect(entities.some((e) => e.category === Category.API_KEY)).toBe(true);
  });

  test("detect URL", () => {
    const entities = detector.detect(
      "Visit https://secret.internal.corp.com/dashboard",
    );
    expect(entities.some((e) => e.category === Category.URL)).toBe(true);
  });

  test("detect SSN", () => {
    const entities = detector.detect("SSN: 123-45-6789");
    expect(entities.some((e) => e.category === Category.SSN)).toBe(true);
  });

  test("detect credit card", () => {
    const entities = detector.detect("Card: 4111-1111-1111-1111");
    expect(entities.some((e) => e.category === Category.CREDIT_CARD)).toBe(true);
  });

  test("detect file path", () => {
    const entities = detector.detect("Config at /etc/app/config.yaml");
    expect(entities.some((e) => e.category === Category.FILE_PATH)).toBe(true);
  });

  test("detect multiple entity types", () => {
    const text =
      "Email john@acme.com from 10.0.0.1 about https://internal.dev/api";
    const entities = detector.detect(text);
    const categories = new Set(entities.map((e) => e.category));
    expect(categories.has(Category.EMAIL)).toBe(true);
    expect(categories.has(Category.IP_ADDRESS)).toBe(true);
    expect(categories.has(Category.URL)).toBe(true);
  });

  test("no false positives on plain text", () => {
    const text = "The quick brown fox jumps over the lazy dog";
    const entities = detector.detect(text);
    expect(entities.length).toBe(0);
  });

  test("entities sorted by position", () => {
    const text = "From 10.0.0.1 to john@test.com via https://test.dev";
    const entities = detector.detect(text);
    const positions = entities.map((e) => e.start);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });
});

describe("Network infrastructure detection", () => {
  const detector = new RegexDetector();

  test("detect MAC address colon format", () => {
    const entities = detector.detect("MAC: aa:bb:cc:dd:ee:ff");
    expect(entities.some((e) => e.category === Category.MAC_ADDRESS)).toBe(true);
  });

  test("detect MAC address dash format", () => {
    const entities = detector.detect("MAC: AA-BB-CC-DD-EE-FF");
    expect(entities.some((e) => e.category === Category.MAC_ADDRESS)).toBe(true);
  });

  test("detect MAC address Cisco dot format", () => {
    const entities = detector.detect("MAC: aabb.ccdd.eeff");
    expect(entities.some((e) => e.category === Category.MAC_ADDRESS)).toBe(true);
  });

  test("detect SNMP community string", () => {
    const entities = detector.detect("snmp-server community S3cretStr1ng RO");
    expect(
      entities.some(
        (e) =>
          e.category === Category.SNMP_COMMUNITY && e.value === "S3cretStr1ng",
      ),
    ).toBe(true);
  });

  test("detect BGP ASN", () => {
    const entities = detector.detect("router bgp 65110");
    expect(
      entities.some(
        (e) => e.category === Category.BGP_ASN && e.value === "65110",
      ),
    ).toBe(true);
  });

  test("detect Cisco enable secret (type 5 hash)", () => {
    const entities = detector.detect(
      "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
    );
    expect(
      entities.some((e) => e.category === Category.NETWORK_CREDENTIAL),
    ).toBe(true);
  });

  test("detect Cisco type 9 hash", () => {
    const entities = detector.detect("password $9$salt$hashvalue+more");
    expect(
      entities.some((e) => e.category === Category.NETWORK_CREDENTIAL),
    ).toBe(true);
  });

  test("skip subnet mask", () => {
    const entities = detector.detect("mask 255.255.255.0");
    expect(entities.some((e) => e.category === Category.IP_ADDRESS)).toBe(false);
  });

  test("skip wildcard mask", () => {
    const entities = detector.detect("wildcard 0.0.0.255");
    expect(entities.some((e) => e.category === Category.IP_ADDRESS)).toBe(false);
  });

  test("skip all-zeros mask", () => {
    const entities = detector.detect("mask 0.0.0.0");
    expect(entities.some((e) => e.category === Category.IP_ADDRESS)).toBe(false);
  });

  test("real IP still detected", () => {
    const entities = detector.detect("host 10.130.25.1");
    expect(
      entities.some(
        (e) => e.category === Category.IP_ADDRESS && e.value === "10.130.25.1",
      ),
    ).toBe(true);
  });
});

describe("isMask", () => {
  test("returns true for subnet mask 255.255.255.0", () => {
    expect(isMask("255.255.255.0")).toBe(true);
  });

  test("returns true for wildcard mask 0.0.0.255", () => {
    expect(isMask("0.0.0.255")).toBe(true);
  });

  test("returns true for 255.255.0.0", () => {
    expect(isMask("255.255.0.0")).toBe(true);
  });

  test("returns true for 0.0.0.0", () => {
    expect(isMask("0.0.0.0")).toBe(true);
  });

  test("returns false for regular IP 192.168.1.1", () => {
    expect(isMask("192.168.1.1")).toBe(false);
  });

  test("returns false for regular IP 10.130.25.1", () => {
    expect(isMask("10.130.25.1")).toBe(false);
  });
});

describe("Overlap resolution", () => {
  test("overlapping spans keep first (higher confidence)", () => {
    // Two detectors might both match "10.0.0.1" -- the regex detector
    // internally resolves via seenSpans. Here we verify that the detector
    // does not produce duplicate spans for the same IP.
    const detector = new RegexDetector();
    const entities = detector.detect("host 10.0.0.1");
    const ipEntities = entities.filter(
      (e) => e.category === Category.IP_ADDRESS && e.value === "10.0.0.1",
    );
    expect(ipEntities.length).toBe(1);
  });
});

describe("CustomPatternDetector", () => {
  test("custom pattern matches", () => {
    const detector = new CustomPatternDetector([
      { name: "employee_id", pattern: "EMP-\\d{6}", category: "custom" },
    ]);
    const entities = detector.detect("Employee EMP-123456 reported the issue");
    expect(entities.length).toBe(1);
    expect(entities[0].value).toBe("EMP-123456");
    expect(entities[0].category).toBe(Category.CUSTOM);
  });

  test("multiple custom patterns", () => {
    const detector = new CustomPatternDetector([
      {
        name: "project_code",
        pattern: "PRJ-[A-Z]{3}-\\d{4}",
        category: "custom",
      },
      {
        name: "internal_ip",
        pattern: "172\\.16\\.\\d+\\.\\d+",
        category: "ip_address",
      },
    ]);
    const text = "Project PRJ-ABC-1234 runs on 172.16.0.50";
    const entities = detector.detect(text);
    expect(entities.length).toBe(2);
  });
});

describe("RegexDetector - base64 secrets", () => {
  const detector = new RegexDetector();

  test("detect SECRET= base64 value", () => {
    const entities = detector.detect("SECRET=dGhpc2lzYXZlcnlsb25nc2VjcmV0a2V5");
    // env_var_secret pattern matches first (higher priority), categorizing as credential
    expect(entities.some((e) =>
      e.category === Category.API_KEY || e.category === Category.NETWORK_CREDENTIAL
    )).toBe(true);
  });

  test("detect base64: prefixed value", () => {
    const entities = detector.detect("password is base64:c2VjcmV0cGFzcw==");
    expect(entities.some((e) => e.category === Category.API_KEY)).toBe(true);
  });

  test("ignore short base64", () => {
    const entities = detector.detect("base64:abc");
    expect(entities.some((e) => e.detector === "regex:base64_prefixed")).toBe(false);
  });
});

describe("RegexDetector - URL/connection-string credentials", () => {
  const detector = new RegexDetector();

  test("detect password in query param", () => {
    const entities = detector.detect("https://app.corp.internal/api?password=SHROUD_TEST_PASSWORD=admin");
    expect(entities.some((e) => e.category === Category.NETWORK_CREDENTIAL
      && e.value === "s3cr3tValue")).toBe(true);
  });

  test("detect token in query param", () => {
    const entities = detector.detect("url: https://api.corp.internal/v1?api_key=abcdef123456xyz");
    expect(entities.some((e) => e.category === Category.NETWORK_CREDENTIAL
      && e.value === "abcdef123456xyz")).toBe(true);
  });

  test("detect postgres connection string", () => {
    const entities = detector.detect("postgres://admin:MyP4ssw0rd@db.internal:5432/production");
    expect(entities.some((e) => e.category === Category.NETWORK_CREDENTIAL)).toBe(true);
  });

  test("detect mongodb connection string", () => {
    const entities = detector.detect("mongodb://root:hunter2@mongo.cluster:27017/app");
    expect(entities.some((e) => e.category === Category.NETWORK_CREDENTIAL)).toBe(true);
  });
});

describe("RegexDetector - overrides", () => {
  test("disabled rule produces no matches", () => {
    const detector = new RegexDetector(undefined, { email: { enabled: false } });
    const entities = detector.detect("Contact john@acme.com");
    expect(entities.some((e) => e.category === Category.EMAIL)).toBe(false);
  });

  test("confidence override changes entity confidence", () => {
    const detector = new RegexDetector(undefined, { ipv4: { confidence: 0.5 } });
    const entities = detector.detect("Server is at 192.168.1.100");
    const ip = entities.find((e) => e.category === Category.IP_ADDRESS);
    expect(ip).toBeDefined();
    expect(ip!.confidence).toBe(0.5);
  });

  test("unknown override name is ignored", () => {
    const detector = new RegexDetector(undefined, { nonexistent_rule: { enabled: false } });
    const entities = detector.detect("Contact john@acme.com from 10.0.0.1");
    expect(entities.length).toBeGreaterThan(0);
  });

  test("detector field includes rule name", () => {
    const detector = new RegexDetector();
    const entities = detector.detect("Contact john@acme.com");
    const email = entities.find((e) => e.category === Category.EMAIL);
    expect(email).toBeDefined();
    expect(email!.detector).toBe("regex:email");
  });

  // ── Config rules as code ──────────────────────────────

  test("configRules: disable a built-in rule", () => {
    const detector = new RegexDetector(undefined, undefined, {
      email: { enabled: false },
    });
    const entities = detector.detect("Contact john@acme.com");
    expect(entities.find(e => e.category === Category.EMAIL)).toBeUndefined();
  });

  test("configRules: override a built-in rule pattern", () => {
    const detector = new RegexDetector(undefined, undefined, {
      email: { pattern: "\\b[A-Z]+@[A-Z]+\\.[A-Z]+\\b" },
    });
    // Lowercase email should no longer match
    expect(detector.detect("Contact john@acme.com").find(e => e.category === Category.EMAIL)).toBeUndefined();
    // Uppercase email should match
    expect(detector.detect("Contact JOHN@ACME.COM").find(e => e.category === Category.EMAIL)).toBeDefined();
  });

  test("configRules: override confidence", () => {
    const detector = new RegexDetector(undefined, undefined, {
      email: { confidence: 0.1 },
    });
    const entities = detector.detect("Contact john@acme.com");
    const email = entities.find(e => e.category === Category.EMAIL);
    expect(email).toBeDefined();
    expect(email!.confidence).toBe(0.1);
  });

  test("configRules: override category", () => {
    const detector = new RegexDetector(undefined, undefined, {
      email: { category: "custom" },
    });
    const entities = detector.detect("Contact john@acme.com");
    const email = entities.find(e => e.detector === "regex:email");
    expect(email).toBeDefined();
    expect(email!.category).toBe(Category.CUSTOM);
  });

  test("configRules: add a new custom rule", () => {
    const detector = new RegexDetector(undefined, undefined, {
      ticket_id: { pattern: "\\bTICK-\\d{6}\\b", category: "custom", confidence: 0.9 },
    });
    const entities = detector.detect("See TICK-123456 for details");
    const ticket = entities.find(e => e.detector === "regex:ticket_id");
    expect(ticket).toBeDefined();
    expect(ticket!.value).toBe("TICK-123456");
    expect(ticket!.category).toBe(Category.CUSTOM);
    expect(ticket!.confidence).toBe(0.9);
  });

  test("configRules: invalid regex is silently skipped", () => {
    const detector = new RegexDetector(undefined, undefined, {
      bad_rule: { pattern: "[invalid", category: "custom" },
    });
    // Should not throw, built-in rules still work
    const entities = detector.detect("Contact john@acme.com");
    expect(entities.find(e => e.category === Category.EMAIL)).toBeDefined();
  });

  test("configRules: new rule without pattern is ignored", () => {
    const detector = new RegexDetector(undefined, undefined, {
      no_pattern: { category: "custom", confidence: 0.5 },
    });
    // Should not throw
    const entities = detector.detect("anything");
    expect(entities.find(e => e.detector === "regex:no_pattern")).toBeUndefined();
  });

  test("configRules: legacy detectorOverrides still apply after configRules", () => {
    const detector = new RegexDetector(
      undefined,
      { ipv4: { enabled: false } },
      { email: { confidence: 0.1 } },
    );
    // email should have overridden confidence
    const entities = detector.detect("Contact john@acme.com from 10.1.1.1");
    expect(entities.find(e => e.category === Category.EMAIL)?.confidence).toBe(0.1);
    // ipv4 should be disabled by legacy override
    expect(entities.find(e => e.category === Category.IP_ADDRESS)).toBeUndefined();
  });
});
