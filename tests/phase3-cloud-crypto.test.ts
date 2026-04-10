/**
 * Phase 3 detection tests: cloud + crypto entity categories.
 *
 * Tests CRYPTOCURRENCY_ADDRESS, AWS_ARN detection,
 * generation, and round-trip deobfuscation.
 */

import { describe, test, expect } from "vitest";

import { Obfuscator } from "../src/obfuscator.js";
import { Category } from "../src/types.js";
import { resolveConfig } from "../src/config.js";

function makeObfuscator() {
  return new Obfuscator(resolveConfig({
    secretKey: "test-secret-key-phase3-cloud-crypto-12345",
    persistentSalt: "phase3-salt",
    minConfidence: 0,
  }));
}

// ── Cryptocurrency Address ──

describe("CRYPTOCURRENCY_ADDRESS detection", () => {
  test("Ethereum address", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38");
    expect(result.obfuscated).not.toContain("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38");
    expect(result.entities.some(e => e.category === Category.CRYPTOCURRENCY_ADDRESS)).toBe(true);
  });

  test("Ethereum fake preserves 0x prefix + 40 hex", () => {
    const ob = makeObfuscator();
    const addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38";
    const result = ob.obfuscate(`Wallet: ${addr}`);
    const fake = result.mappingsUsed[addr];
    if (fake) {
      expect(fake).toMatch(/^0x[0-9a-f]{40}$/);
      expect(fake.length).toBe(42);
    }
  });

  test("Bitcoin P2PKH address (starts with 1)", () => {
    const ob = makeObfuscator();
    const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const result = ob.obfuscate(`BTC: ${addr}`);
    expect(result.obfuscated).not.toContain(addr);
    expect(result.entities.some(e => e.category === Category.CRYPTOCURRENCY_ADDRESS)).toBe(true);
  });

  test("Bitcoin P2PKH fake preserves prefix 1 + base58", () => {
    const ob = makeObfuscator();
    const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const result = ob.obfuscate(`Send to ${addr}`);
    const fake = result.mappingsUsed[addr];
    if (fake) {
      expect(fake[0]).toBe("1");
      expect(fake.length).toBe(addr.length);
    }
  });

  test("Bitcoin P2SH address (starts with 3)", () => {
    const ob = makeObfuscator();
    const addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    const result = ob.obfuscate(`P2SH: ${addr}`);
    expect(result.obfuscated).not.toContain(addr);
    expect(result.entities.some(e => e.category === Category.CRYPTOCURRENCY_ADDRESS)).toBe(true);
  });

  test("Bitcoin Bech32 address", () => {
    const ob = makeObfuscator();
    const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const result = ob.obfuscate(`Bech32: ${addr}`);
    expect(result.obfuscated).not.toContain(addr);
    expect(result.entities.some(e => e.category === Category.CRYPTOCURRENCY_ADDRESS)).toBe(true);
  });

  test("Bitcoin Bech32 fake preserves bc1 prefix", () => {
    const ob = makeObfuscator();
    const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const result = ob.obfuscate(`Address: ${addr}`);
    const fake = result.mappingsUsed[addr];
    if (fake) {
      expect(fake.startsWith("bc1")).toBe(true);
      expect(fake.length).toBe(addr.length);
    }
  });

  test("crypto wallet with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Wallet address: AbCdEf1234567890AbCdEf1234567890AbCd");
    expect(result.obfuscated).not.toContain("AbCdEf1234567890AbCdEf1234567890AbCd");
    expect(result.entities.some(e => e.category === Category.CRYPTOCURRENCY_ADDRESS)).toBe(true);
  });

  test("Ethereum round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38";
    const result = ob.obfuscate(`ETH: ${addr}`);
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain(addr);
  });

  test("no false positive on short hex strings", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("Color code: 0xFF5733");
    const cryptoEntities = result.entities.filter(e => e.category === Category.CRYPTOCURRENCY_ADDRESS);
    expect(cryptoEntities.length).toBe(0);
  });
});

// ── AWS ARN ──

describe("AWS_ARN detection", () => {
  test("S3 bucket ARN", () => {
    const ob = makeObfuscator();
    const arn = "arn:aws:s3:::my-secret-bucket";
    const result = ob.obfuscate(`Resource: ${arn}`);
    expect(result.obfuscated).not.toContain("my-secret-bucket");
    expect(result.entities.some(e => e.category === Category.AWS_ARN)).toBe(true);
  });

  test("IAM role ARN with account ID", () => {
    const ob = makeObfuscator();
    const arn = "arn:aws:iam::123456789012:role/AdminRole";
    const result = ob.obfuscate(`Role: ${arn}`);
    expect(result.obfuscated).not.toContain("123456789012");
    expect(result.entities.some(e => e.category === Category.AWS_ARN)).toBe(true);
  });

  test("Lambda function ARN", () => {
    const ob = makeObfuscator();
    const arn = "arn:aws:lambda:eu-west-1:123456789012:function:my-processor";
    const result = ob.obfuscate(`Function: ${arn}`);
    expect(result.obfuscated).not.toContain("123456789012");
    expect(result.obfuscated).not.toContain("my-processor");
    expect(result.entities.some(e => e.category === Category.AWS_ARN)).toBe(true);
  });

  test("ARN fake preserves partition and service", () => {
    const ob = makeObfuscator();
    const arn = "arn:aws:lambda:eu-west-1:123456789012:function/my-func";
    const result = ob.obfuscate(`ARN: ${arn}`);
    const fake = result.mappingsUsed[arn];
    if (fake) {
      expect(fake.startsWith("arn:aws:lambda:eu-west-1:")).toBe(true);
      expect(fake).not.toContain("123456789012");
    }
  });

  test("AWS account ID with keyword", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("AWS Account ID: 123456789012");
    expect(result.obfuscated).not.toContain("123456789012");
    expect(result.entities.some(e => e.category === Category.AWS_ARN)).toBe(true);
  });

  test("ARN round-trip deobfuscation", () => {
    const ob = makeObfuscator();
    const arn = "arn:aws:iam::123456789012:role/AdminRole";
    const result = ob.obfuscate(`Role: ${arn}`);
    const deob = ob.deobfuscate(result.obfuscated);
    expect(deob).toContain(arn);
  });

  test("no false positive on non-ARN strings", () => {
    const ob = makeObfuscator();
    const result = ob.obfuscate("The arn of the ship was damaged.");
    const arnEntities = result.entities.filter(e => e.category === Category.AWS_ARN);
    expect(arnEntities.length).toBe(0);
  });
});
