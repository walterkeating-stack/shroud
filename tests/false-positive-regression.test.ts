/**
 * False positive regression tests.
 *
 * These test real-world agent conversation patterns that caused
 * production issues. Each test represents a bug that was found in
 * production and should never recur.
 *
 * v2.2.8: file_path_unix obfuscating workspace paths (broke tool calls)
 * v2.2.8: gps_coordinate matching financial data (18k false positives)
 * v2.2.8: file_path_unix matching inside public URLs
 */

import { describe, test, expect, beforeEach, afterEach } from "vitest";
import { Obfuscator } from "../src/obfuscator.js";
import { resolveConfig } from "../src/config.js";
import { DnsCache } from "../src/dns-cache.js";
import { isDocExample } from "../src/detectors/regex.js";

function makeObfuscator(overrides: Record<string, unknown> = {}) {
  return new Obfuscator(
    resolveConfig({ secretKey: "regression-test-key-32-chars-xxx!", ...overrides })
  );
}

// ── Workspace / operational file paths ──

describe("file_path_unix: operational paths must NOT be obfuscated", () => {
  let ob: Obfuscator;

  beforeEach(() => {
    ob = makeObfuscator();
  });

  test("OpenClaw workspace paths pass through", () => {
    const input = "Upload the file from /home/user/.openclaw/media/report.pdf to Slack";
    const result = ob.obfuscate(input);
    expect(result.obfuscated).toContain("/home/user/.openclaw/media/report.pdf");
  });

  test("OpenClaw extension paths pass through", () => {
    const input = "Plugin installed at /home/user/.openclaw/extensions/shroud-privacy/dist/index.js";
    const result = ob.obfuscate(input);
    expect(result.obfuscated).toContain("/home/user/.openclaw/extensions/shroud-privacy/dist/index.js");
  });

  test("Script paths in exec commands pass through", () => {
    const input = "python3 /home/user/.openclaw/workspace/scripts/searxng_search.py \"semiconductor\"";
    const result = ob.obfuscate(input);
    expect(result.obfuscated).toContain("/home/user/.openclaw/workspace/scripts/searxng_search.py");
  });

  test("/tmp paths pass through", () => {
    const input = "Extracting /tmp/openclaw-npm-pack-CGhrdL/shroud-privacy-2.2.8.tgz";
    const result = ob.obfuscate(input);
    expect(result.obfuscated).toContain("/tmp/openclaw-npm-pack-CGhrdL/shroud-privacy-2.2.8.tgz");
  });

  test("node_modules paths under /home pass through", () => {
    const input = "Module at /home/user/.npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js";
    const result = ob.obfuscate(input);
    expect(result.obfuscated).toContain("event-stream.js");
  });

  test("infrastructure paths under /opt ARE obfuscated", () => {
    const input = "Config backup at /opt/network-configs/core-router/running-config.cfg";
    const result = ob.obfuscate(input);
    // /opt is NOT in the operational list — could be infra
    expect(result.entities.length).toBeGreaterThan(0);
  });
});

// ── File paths inside public URLs ──

describe("file_path_unix: must NOT match inside public URLs", () => {
  let ob: Obfuscator;

  beforeEach(() => {
    ob = makeObfuscator();
    (globalThis as any).__shroudDnsCache = new DnsCache();
  });

  afterEach(() => {
    delete (globalThis as any).__shroudDnsCache;
  });

  test("GitHub URL path not detected as file_path", () => {
    const result = ob.obfuscate("Check https://github.com/wkeything/shroud");
    expect(result.obfuscated).toContain("github.com");
    const fpEntities = result.entities.filter(e => e.category === "file_path");
    expect(fpEntities).toHaveLength(0);
  });

  test("npmjs URL path not detected as file_path", () => {
    const result = ob.obfuscate("See https://www.npmjs.com/package/shroud-privacy");
    expect(result.obfuscated).toContain("npmjs.com");
    const fpEntities = result.entities.filter(e => e.category === "file_path");
    expect(fpEntities).toHaveLength(0);
  });

  test("Wikipedia URL path not detected as file_path", () => {
    const result = ob.obfuscate("Read https://en.wikipedia.org/wiki/Network_security");
    expect(result.obfuscated).toContain("wikipedia.org");
    const fpEntities = result.entities.filter(e => e.category === "file_path");
    expect(fpEntities).toHaveLength(0);
  });

  test("Stack Overflow URL path not detected as file_path", () => {
    const result = ob.obfuscate("Answer at https://stackoverflow.com/questions/12345/some-question");
    expect(result.obfuscated).toContain("stackoverflow.com");
    const fpEntities = result.entities.filter(e => e.category === "file_path");
    expect(fpEntities).toHaveLength(0);
  });

  test("DNS-verified public URL path not detected as file_path", () => {
    const cache: DnsCache = (globalThis as any).__shroudDnsCache;
    cache.seed("docs.stripe.com", "52.1.2.3", true);
    const result = ob.obfuscate("Read https://docs.stripe.com/api/charges/create");
    expect(result.obfuscated).toContain("docs.stripe.com");
  });
});

// ── GPS coordinate false positives ──

describe("gps_coordinate: must NOT match financial/research data", () => {
  let ob: Obfuscator;

  beforeEach(() => {
    ob = makeObfuscator();
  });

  test("stock prices are not GPS coordinates", () => {
    const input = "ASML traded at 654.3200, volume 1234567. Previous close 648.9100.";
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(0);
  });

  test("space-separated decimals are not GPS coordinates", () => {
    const input = "returns: 1.23456789 -0.98765432 over the period";
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(0);
  });

  test("PE ratios without commas are not GPS coordinates", () => {
    const input = "P/E 34.5678 vs sector average 28.1234";
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(0);
  });

  test("out-of-range lat/lon values are not GPS coordinates", () => {
    const input = "stock price 654.3200, market cap 267.8901 billion";
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(0);
  });

  test("real GPS coordinates ARE still detected", () => {
    const input = "Location: 48.2082, 16.3738 (Vienna)";
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(1);
    expect(gpsEntities[0].value).toContain("48.2082");
  });

  test("negative GPS coordinates detected (Sydney)", () => {
    const input = "Office at -33.8688, 151.2093";
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(1);
  });

  test("NYC GPS coordinates detected", () => {
    const input = "HQ location: 40.7128, -74.0060";
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(1);
  });
});

// ── High-volume agent conversation simulation ──

describe("real-world agent conversation: no excessive false positives", () => {
  let ob: Obfuscator;

  beforeEach(() => {
    ob = makeObfuscator();
  });

  test("financial research text does not trigger mass detections", () => {
    const input = `ASML Holding NV (ASML) Q4 2025 Earnings Call Transcript
Revenue: EUR 7.3856 billion, up 12.4% YoY.
Gross margin: 51.7234% vs consensus 50.8765%.
EPS: EUR 5.12340 vs estimate EUR 4.98760.
Bookings: EUR 3.6123 billion, below guidance of EUR 4.0000 billion.
Free cash flow: EUR 2.12345 billion.
P/E ratio: 34.5678, forward P/E: 28.9012.
Stock price: 654.3200, market cap: EUR 267.8901 billion.
Segment breakdown:
  Logic: 65.1234% of revenue
  Memory: 28.8765% of revenue
  Other: 6.0001% of revenue`;
    const result = ob.obfuscate(input);
    const gpsEntities = result.entities.filter(e => e.category === "gps_coordinate");
    expect(gpsEntities).toHaveLength(0);
    // Total entities should be modest, not hundreds
    expect(result.entities.length).toBeLessThan(20);
  });

  test("OpenClaw agent exec output does not trigger mass file_path detections", () => {
    const input = `Running: python3 /home/user/.openclaw/workspace/scripts/searxng_search.py "ASML earnings"
Output saved to /tmp/search-results-abc123.json
Reading /home/user/.openclaw/workspace/memory/2026-03-28.md
Writing /home/user/.openclaw/semiconalpha-workspace/drafts/asml-q4.md
Converting: python3 /home/user/.openclaw/semiconalpha-workspace/scripts/md_to_pdf.py drafts/asml-q4.md drafts/asml-q4.pdf
Copying to /home/user/.openclaw/media/asml-q4.pdf
Uploading via: openclaw message send --channel slack --target C0AN09SPT29 --message "ASML Q4 draft" --media /home/user/.openclaw/media/asml-q4.pdf`;
    const result = ob.obfuscate(input);
    const fpEntities = result.entities.filter(e => e.category === "file_path");
    expect(fpEntities).toHaveLength(0);
  });

  test("mixed conversation with PII + workspace paths: only PII obfuscated", () => {
    const input = `User asked me to check admin@acme.com's access to 10.1.0.1.
Script: /home/user/.openclaw/workspace/scripts/audit_access.py
Results saved to /tmp/audit-output.json
Found 3 login attempts from 192.168.1.100.`;
    const result = ob.obfuscate(input);
    // Email and IPs should be obfuscated
    expect(result.obfuscated).not.toContain("admin@acme.com");
    expect(result.obfuscated).not.toContain("10.1.0.1");
    expect(result.obfuscated).not.toContain("192.168.1.100");
    // Workspace paths should pass through
    expect(result.obfuscated).toContain("/home/user/.openclaw/workspace/scripts/audit_access.py");
    expect(result.obfuscated).toContain("/tmp/audit-output.json");
  });
});

// ── isDocExample direct tests for file_path ──

describe("isDocExample: file_path category", () => {
  test("home directory paths are skipped", () => {
    expect(isDocExample("/home/user/.openclaw/media/file.pdf", "file_path")).toBe(true);
  });

  test("/tmp paths are skipped", () => {
    expect(isDocExample("/tmp/shroud-stats.json", "file_path")).toBe(true);
  });

  test("/usr paths are NOT skipped (could be infra)", () => {
    expect(isDocExample("/usr/local/etc/haproxy/haproxy.cfg", "file_path")).toBe(false);
  });

  test("/etc paths are NOT skipped (could be infra)", () => {
    expect(isDocExample("/etc/nginx/sites-enabled/default.conf", "file_path")).toBe(false);
  });

  test("/var paths are NOT skipped (could be infra)", () => {
    expect(isDocExample("/var/lib/docker/volumes/data", "file_path")).toBe(false);
  });

  test("/opt paths are NOT skipped (could be infra)", () => {
    expect(isDocExample("/opt/network-configs/router.cfg", "file_path")).toBe(false);
  });

  test("public domain URL paths are skipped", () => {
    expect(isDocExample("/www.npmjs.com/package/shroud-privacy", "file_path")).toBe(true);
    expect(isDocExample("/github.com/wkeything/shroud", "file_path")).toBe(true);
  });

  test("unknown paths are NOT skipped", () => {
    expect(isDocExample("/data/backups/core-router-config.tar.gz", "file_path")).toBe(false);
  });
});
