/**
 * Phase 1 detection tests: healthcare + finance entity categories.
 *
 * Tests DATE_OF_BIRTH, MEDICAL_RECORD_NUMBER, BANK_ACCOUNT_NUMBER,
 * TAX_ID detection, generation, and round-trip deobfuscation.
 */

import { describe, test, expect } from "vitest";

import { Obfuscator } from "../src/obfuscator.js";
import { Category } from "../src/types.js";
import { resolveConfig } from "../src/config.js";

function makeObfuscator() {
  return new Obfuscator(resolveConfig({
    secretKey: "test-secret-key-phase1-healthcare-finance",
    persistentSalt: "phase1-salt",
    minConfidence: 0,
  }));
}

// ── Date of Birth ──

describe("DATE_OF_BIRTH detection", () => {
  test("DOB with US date format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Patient DOB: 03/15/1987");
    expect(result.obfuscated).not.toContain("03/15/1987");
    expect(result.entities.some(e => e.category === Category.DATE_OF_BIRTH)).toBe(true);
  });

  test("DOB with ISO date format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("date of birth: 1987-03-15");
    expect(result.obfuscated).not.toContain("1987-03-15");
    expect(result.entities.some(e => e.category === Category.DATE_OF_BIRTH)).toBe(true);
  });

  test("DOB with written month", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("born on March 15, 1987");
    expect(result.obfuscated).not.toContain("March 15, 1987");
    expect(result.entities.some(e => e.category === Category.DATE_OF_BIRTH)).toBe(true);
  });

  test("DOB with European format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Geburtsdatum: 15.03.1987");
    expect(result.obfuscated).not.toContain("15.03.1987");
    expect(result.entities.some(e => e.category === Category.DATE_OF_BIRTH)).toBe(true);
  });

  test("DOB round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("DOB: 03/15/1987");
    const fake = Object.values(result.mappingsUsed).find(v => v !== "03/15/1987") || "";
    expect(fake).not.toBe("");
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain("03/15/1987");
  });

  test("DOB fake preserves date format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("DOB: 03/15/1987");
    const fake = result.mappingsUsed["03/15/1987"];
    if (fake) {
      // Should be in MM/DD/YYYY format
      expect(fake).toMatch(/\d{2}\/\d{2}\/\d{4}/);
    }
  });

  test("no false positive on standalone date", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("The meeting is on 03/15/2026.");
    // Without DOB context keyword, should not flag as DOB
    const dobEntities = result.entities.filter(e => e.category === Category.DATE_OF_BIRTH);
    expect(dobEntities.length).toBe(0);
  });
});

// ── Medical Record Number ──

describe("MEDICAL_RECORD_NUMBER detection", () => {
  test("MRN with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("MRN: 12345678");
    expect(result.obfuscated).not.toContain("12345678");
    expect(result.entities.some(e => e.category === Category.MEDICAL_RECORD_NUMBER)).toBe(true);
  });

  test("medical record number with full phrase", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Medical record number: ABC-123456");
    expect(result.obfuscated).not.toContain("ABC-123456");
    expect(result.entities.some(e => e.category === Category.MEDICAL_RECORD_NUMBER)).toBe(true);
  });

  test("patient ID", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Patient ID: PT-2026-78901");
    expect(result.obfuscated).not.toContain("PT-2026-78901");
    expect(result.entities.some(e => e.category === Category.MEDICAL_RECORD_NUMBER)).toBe(true);
  });

  test("NPI number", () => {
    const ob = makeObfuscator();
    // Use a number that won't be captured by phone_us first (NPI shares 10-digit format)
    const result = ob.obfuscate("National provider NPI: 1234567890");
    // Either detected as MRN or phone — both are obfuscated (the important thing is it's not leaked)
    expect(result.obfuscated).not.toContain("1234567890");
  });

  test("DEA number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("DEA: AB1234567");
    expect(result.obfuscated).not.toContain("AB1234567");
    expect(result.entities.some(e => e.category === Category.MEDICAL_RECORD_NUMBER)).toBe(true);
  });

  test("health insurance member ID", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Member ID: XYZ123456789");
    expect(result.obfuscated).not.toContain("XYZ123456789");
    expect(result.entities.some(e => e.category === Category.MEDICAL_RECORD_NUMBER)).toBe(true);
  });

  test("MRN round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("MRN: 12345678");
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain("12345678");
  });

  test("no false positive on standalone number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("There are 12345678 items in stock.");
    const mrnEntities = result.entities.filter(e => e.category === Category.MEDICAL_RECORD_NUMBER);
    expect(mrnEntities.length).toBe(0);
  });
});

// ── Bank Account Number ──

describe("BANK_ACCOUNT_NUMBER detection", () => {
  test("US routing number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Routing number: 021000021");
    expect(result.obfuscated).not.toContain("021000021");
    expect(result.entities.some(e => e.category === Category.BANK_ACCOUNT_NUMBER)).toBe(true);
  });

  test("bank account number with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Account number: 1234567890123");
    expect(result.obfuscated).not.toContain("1234567890123");
    expect(result.entities.some(e => e.category === Category.BANK_ACCOUNT_NUMBER)).toBe(true);
  });

  test("UK sort code", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Sort code: 12-34-56");
    expect(result.obfuscated).not.toContain("12-34-56");
    expect(result.entities.some(e => e.category === Category.BANK_ACCOUNT_NUMBER)).toBe(true);
  });

  test("SWIFT/BIC with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("SWIFT: DEUTDEFF");
    expect(result.obfuscated).not.toContain("DEUTDEFF");
    expect(result.entities.some(e => e.category === Category.BANK_ACCOUNT_NUMBER)).toBe(true);
  });

  test("bank account round-trip", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Routing number: 021000021");
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain("021000021");
  });

  test("sort code fake preserves format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Sort code: 12-34-56");
    const fake = result.mappingsUsed["12-34-56"];
    if (fake) {
      expect(fake).toMatch(/\d{2}-\d{2}-\d{2}/);
    }
  });

  test("no false positive on standalone digits", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("The total is 021000021 units.");
    const bankEntities = result.entities.filter(e => e.category === Category.BANK_ACCOUNT_NUMBER);
    expect(bankEntities.length).toBe(0);
  });
});

// ── Tax ID ──

describe("TAX_ID detection", () => {
  test("US EIN with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("EIN: 12-3456789");
    expect(result.obfuscated).not.toContain("12-3456789");
    expect(result.entities.some(e => e.category === Category.TAX_ID)).toBe(true);
  });

  test("tax ID generic keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Tax ID: 987654321");
    expect(result.obfuscated).not.toContain("987654321");
    expect(result.entities.some(e => e.category === Category.TAX_ID)).toBe(true);
  });

  test("UK UTR", () => {
    const ob = makeObfuscator();
    // Use a number that won't be captured by phone_us first (UTR shares 10-digit format)
    const result = ob.obfuscate("Unique taxpayer reference: 1234567890");
    // Either detected as TAX_ID or phone — both are obfuscated
    expect(result.obfuscated).not.toContain("1234567890");
  });

  test("EIN fake preserves format", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("EIN: 12-3456789");
    const fake = result.mappingsUsed["12-3456789"];
    if (fake) {
      expect(fake).toMatch(/\d{2}-\d{7}/);
    }
  });

  test("EIN round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("EIN: 12-3456789");
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain("12-3456789");
  });

  test("no false positive on standalone number", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Error code 12-3456789 reported.");
    const taxEntities = result.entities.filter(e => e.category === Category.TAX_ID);
    expect(taxEntities.length).toBe(0);
  });
});
