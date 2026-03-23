import { describe, test, expect } from "vitest";

import { Category } from "../src/types.js";
import { MappingEngine } from "../src/mapping.js";
import { SubnetMapper, ipToInt, intToIp } from "../src/generators/network.js";

describe("Name generation", () => {
  test("person name has first and last (space-separated)", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("John Smith", Category.PERSON_NAME);
    expect(fake).toContain(" ");
    const parts = fake.split(" ");
    expect(parts.length).toBeGreaterThanOrEqual(2);
  });

  test("org name is multi-word", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("Acme Corp", Category.ORG_NAME);
    expect(fake).toContain(" ");
  });
});

describe("Email generation", () => {
  test("contains @", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("real@company.com", Category.EMAIL);
    expect(fake).toContain("@");
  });
});

describe("IP generation", () => {
  test("fake IP is in CGNAT range (starts with 100.)", () => {
    const sm = new SubnetMapper();
    const engine = new MappingEngine("test-secret", "fixed-salt", sm);
    const fake = engine.mapValue("192.168.1.1", Category.IP_ADDRESS);
    expect(fake.startsWith("100.")).toBe(true);
  });

  test("host bits preserved in default /24", () => {
    const sm = new SubnetMapper();
    const engine = new MappingEngine("test-secret", "fixed-salt", sm);
    const fake = engine.mapValue("192.168.1.42", Category.IP_ADDRESS);
    expect(fake.split(".")[3]).toBe("42");
  });

  test("same /24 maps to same fake /24", () => {
    const sm = new SubnetMapper();
    const engine = new MappingEngine("test-secret", "fixed-salt", sm);
    const fake1 = engine.mapValue("10.130.25.1", Category.IP_ADDRESS);
    const fake2 = engine.mapValue("10.130.25.100", Category.IP_ADDRESS);
    const prefix1 = fake1.split(".").slice(0, 3).join(".");
    const prefix2 = fake2.split(".").slice(0, 3).join(".");
    expect(prefix1).toBe(prefix2);
    expect(fake1.split(".")[3]).toBe("1");
    expect(fake2.split(".")[3]).toBe("100");
  });

  test("different /24 subnets map to different fake /24", () => {
    const sm = new SubnetMapper();
    const engine = new MappingEngine("test-secret", "fixed-salt", sm);
    const fake1 = engine.mapValue("10.130.25.1", Category.IP_ADDRESS);
    const fake2 = engine.mapValue("10.130.26.1", Category.IP_ADDRESS);
    const prefix1 = fake1.split(".").slice(0, 3).join(".");
    const prefix2 = fake2.split(".").slice(0, 3).join(".");
    expect(prefix1).not.toBe(prefix2);
    // Same host octet
    expect(fake1.split(".")[3]).toBe("1");
    expect(fake2.split(".")[3]).toBe("1");
  });

  test("learnSubnetsFromText with CIDR /22", () => {
    const sm = new SubnetMapper();
    sm.learnSubnetsFromText("network 10.130.24.0/22");
    const engine = new MappingEngine("test-secret", "fixed-salt", sm);
    // These two IPs are in different /24s but the SAME /22
    const fake1 = engine.mapValue("10.130.24.5", Category.IP_ADDRESS);
    const fake2 = engine.mapValue("10.130.25.5", Category.IP_ADDRESS);
    const f1 = ipToInt(fake1);
    const f2 = ipToInt(fake2);
    const mask22 = (0xffffffff << 10) >>> 0;
    expect((f1 & mask22) >>> 0).toBe((f2 & mask22) >>> 0);
    // Host bits (lower 10 bits) should differ
    expect(f1 & ~mask22).not.toBe(f2 & ~mask22);
  });

  test("learnSubnetsFromText with subnet mask", () => {
    const sm = new SubnetMapper();
    sm.learnSubnetsFromText("ip address 172.16.0.1 mask 255.255.240.0");
    const engine = new MappingEngine("test-secret", "fixed-salt", sm);
    // /20 subnet: 172.16.0.0 - 172.16.15.255
    const fake1 = engine.mapValue("172.16.0.10", Category.IP_ADDRESS);
    const fake2 = engine.mapValue("172.16.15.10", Category.IP_ADDRESS);
    const f1 = ipToInt(fake1);
    const f2 = ipToInt(fake2);
    const mask20 = (0xffffffff << 12) >>> 0;
    expect((f1 & mask20) >>> 0).toBe((f2 & mask20) >>> 0);
  });
});

describe("MAC generation", () => {
  test("produces 6 colon-separated octets", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("aa:bb:cc:dd:ee:ff", Category.MAC_ADDRESS);
    const parts = fake.split(":");
    expect(parts.length).toBe(6);
    for (const part of parts) {
      expect(part).toMatch(/^[0-9a-f]{2}$/);
    }
  });
});

describe("BGP ASN generation", () => {
  test("in private range 64512-65534", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("65110", Category.BGP_ASN);
    const asn = parseInt(fake, 10);
    expect(asn).toBeGreaterThanOrEqual(64512);
    expect(asn).toBeLessThanOrEqual(65534);
  });
});

describe("API key generation", () => {
  test("starts with prefix like sk-shroud- when original has sk- prefix", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue(
      "sk-real-key-12345678901234567890",
      Category.API_KEY,
    );
    expect(fake.startsWith("sk-")).toBe(true);
    // Prefix "sk-real-" is preserved from the original
    expect(fake.startsWith("sk-real-")).toBe(true);
  });
});

describe("File path generation", () => {
  test("preserves depth and extension", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("/etc/app/config.yaml", Category.FILE_PATH);
    // Original has 3 segments after root: etc, app, config.yaml
    const origDepth = "/etc/app/config.yaml".split("/").filter((s) => s).length;
    const fakeDepth = fake.split("/").filter((s) => s).length;
    expect(fakeDepth).toBe(origDepth);
    expect(fake).toMatch(/\.yaml$/);
  });
});

describe("Credit card generation", () => {
  test("produces 16 digits with separators", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("4111-1111-1111-1111", Category.CREDIT_CARD);
    // Should have dashes since original does
    const digits = fake.replace(/[-\s]/g, "");
    expect(digits.length).toBe(16);
    expect(digits).toMatch(/^\d{16}$/);
  });
});

describe("SSN generation", () => {
  test("XXX-XX-XXXX format", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("123-45-6789", Category.SSN);
    expect(fake).toMatch(/^\d{3}-\d{2}-\d{4}$/);
  });
});

describe("Phone generation", () => {
  test("area code + number format", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("(555) 123-4567", Category.PHONE);
    // Should contain parens since original does
    expect(fake).toMatch(/\(\d{3}\)/);
    expect(fake.replace(/[^0-9]/g, "").length).toBe(10);
  });

  test("international no-separator preserves compact format", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("+15551234567", Category.PHONE);
    // Must NOT contain spaces — LLMs strip spaces in tool calls, breaking deobfuscation
    expect(fake).not.toContain(" ");
    expect(fake).toMatch(/^\+1\d+$/);
  });

  test("international with dashes preserves dashes", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("+1-555-886-4315", Category.PHONE);
    expect(fake).toContain("-");
    expect(fake).toMatch(/^\+1-/);
  });

  test("international with spaces preserves spaces", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("+1 555 886 4315", Category.PHONE);
    expect(fake).toContain(" ");
    expect(fake).toMatch(/^\+1 /);
  });
});
