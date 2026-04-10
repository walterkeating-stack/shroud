/**
 * Phase 2 detection tests: legal + identity document categories.
 *
 * Tests PASSPORT_NUMBER, DRIVERS_LICENSE, CASE_NUMBER detection,
 * generation, and round-trip deobfuscation.
 */

import { describe, test, expect } from "vitest";

import { Obfuscator } from "../src/obfuscator.js";
import { Category } from "../src/types.js";
import { resolveConfig } from "../src/config.js";

function makeObfuscator() {
  return new Obfuscator(resolveConfig({
    secretKey: "test-secret-key-phase2-legal-identity-1234",
    persistentSalt: "phase2-salt",
    minConfidence: 0,
  }));
}

// ── Passport Number ──

describe("PASSPORT_NUMBER detection", () => {
  test("passport with keyword and alphanumeric ID", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Passport number: P12345678");
    expect(result.obfuscated).not.toContain("P12345678");
    expect(result.entities.some(e => e.category === Category.PASSPORT_NUMBER)).toBe(true);
  });

  test("passport with numeric-only ID", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Passport no: 123456789");
    expect(result.obfuscated).not.toContain("123456789");
    expect(result.entities.some(e => e.category === Category.PASSPORT_NUMBER)).toBe(true);
  });

  test("German Reisepass", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Reisepass Nr.: C01X00T47");
    expect(result.obfuscated).not.toContain("C01X00T47");
    expect(result.entities.some(e => e.category === Category.PASSPORT_NUMBER)).toBe(true);
  });

  test("travel document", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Travel document: AB1234567");
    expect(result.obfuscated).not.toContain("AB1234567");
    expect(result.entities.some(e => e.category === Category.PASSPORT_NUMBER)).toBe(true);
  });

  test("passport round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Passport: P12345678");
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain("P12345678");
  });

  test("passport fake preserves format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Passport number: P12345678");
    const fake = result.mappingsUsed["P12345678"];
    if (fake) {
      // Should be letter + digits, same length
      expect(fake.length).toBe(9);
      expect(fake).toMatch(/^[A-Z]\d{7}[A-Z0-9]$/);
    }
  });

  test("no false positive without context keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("The code P12345678 was entered.");
    const ppEntities = result.entities.filter(e => e.category === Category.PASSPORT_NUMBER);
    expect(ppEntities.length).toBe(0);
  });
});

// ── Driver's License ──

describe("DRIVERS_LICENSE detection", () => {
  test("driver's license with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Driver's license: A1234567");
    expect(result.obfuscated).not.toContain("A1234567");
    expect(result.entities.some(e => e.category === Category.DRIVERS_LICENSE)).toBe(true);
  });

  test("DL abbreviation", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("DL: B9876543");
    expect(result.obfuscated).not.toContain("B9876543");
    expect(result.entities.some(e => e.category === Category.DRIVERS_LICENSE)).toBe(true);
  });

  test("driving licence (UK spelling)", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Driving licence number: SMITH890123AB4CD");
    expect(result.obfuscated).not.toContain("SMITH890123AB4CD");
    expect(result.entities.some(e => e.category === Category.DRIVERS_LICENSE)).toBe(true);
  });

  test("German Führerschein", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Führerschein Nr. B072RRE2I55");
    expect(result.obfuscated).not.toContain("B072RRE2I55");
    expect(result.entities.some(e => e.category === Category.DRIVERS_LICENSE)).toBe(true);
  });

  test("license plate with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("License plate: W-12345X");
    expect(result.obfuscated).not.toContain("W-12345X");
    expect(result.entities.some(e => e.category === Category.DRIVERS_LICENSE)).toBe(true);
  });

  test("vehicle registration", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Vehicle registration: ABC-1234");
    expect(result.obfuscated).not.toContain("ABC-1234");
    expect(result.entities.some(e => e.category === Category.DRIVERS_LICENSE)).toBe(true);
  });

  test("DL round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("DL: A1234567");
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain("A1234567");
  });

  test("DL fake preserves format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("DL: A1234567");
    const fake = result.mappingsUsed["A1234567"];
    if (fake) {
      expect(fake.length).toBe(8);
      expect(fake).toMatch(/^[A-Z]\d{7}$/);
    }
  });

  test("no false positive without keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("The value A1234567 was returned.");
    const dlEntities = result.entities.filter(e => e.category === Category.DRIVERS_LICENSE);
    expect(dlEntities.length).toBe(0);
  });
});

// ── Case / Docket Number ──

describe("CASE_NUMBER detection", () => {
  test("US federal court case number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Filed as 1:23-cv-01234 in the Southern District");
    expect(result.obfuscated).not.toContain("1:23-cv-01234");
    expect(result.entities.some(e => e.category === Category.CASE_NUMBER)).toBe(true);
  });

  test("US criminal case number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Case 2:24-cr-00567");
    expect(result.obfuscated).not.toContain("2:24-cr-00567");
    expect(result.entities.some(e => e.category === Category.CASE_NUMBER)).toBe(true);
  });

  test("case number with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Case number: CV-2026-78901");
    expect(result.obfuscated).not.toContain("CV-2026-78901");
    expect(result.entities.some(e => e.category === Category.CASE_NUMBER)).toBe(true);
  });

  test("docket number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Docket no: D-2024-12345");
    expect(result.obfuscated).not.toContain("D-2024-12345");
    expect(result.entities.some(e => e.category === Category.CASE_NUMBER)).toBe(true);
  });

  test("US patent number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("US Patent US12345678");
    expect(result.obfuscated).not.toContain("US12345678");
    expect(result.entities.some(e => e.category === Category.CASE_NUMBER)).toBe(true);
  });

  test("European patent", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("EP1234567A1");
    expect(result.obfuscated).not.toContain("EP1234567");
    expect(result.entities.some(e => e.category === Category.CASE_NUMBER)).toBe(true);
  });

  test("German Aktenzeichen", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Az.: 1 BvR 123/45");
    expect(result.obfuscated).not.toContain("1 BvR 123/45");
    expect(result.entities.some(e => e.category === Category.CASE_NUMBER)).toBe(true);
  });

  test("federal case round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Case 1:23-cv-01234");
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain("1:23-cv-01234");
  });

  test("federal case fake preserves format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Filed in 1:23-cv-01234");
    const fake = result.mappingsUsed["1:23-cv-01234"];
    if (fake) {
      // Should preserve X:XX-xx-XXXXX structure
      expect(fake).toMatch(/\d:\d{2}-cv-\d{5}/);
    }
  });

  test("patent fake preserves country prefix", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Patent US12345678");
    const fake = result.mappingsUsed["US12345678"];
    if (fake) {
      expect(fake).toMatch(/^US\d{8}$/);
    }
  });
});
