import { describe, test, expect } from "vitest";

import { ShroudConfig, Category } from "../src/types.js";
import { Obfuscator } from "../src/obfuscator.js";
import { IdentifierGenerator } from "../src/generators/identifier.js";

// Anchor: NCG /netbox runs 2026-06-08. Device hostnames hit the opaque
// [REDACTED-...] fallback, which destroyed the structure the agent needs to
// suffix-match / group, so it rejected a correct 101-device `name__iew=_new`
// result. Format-preserving obfuscation keeps the shape so the agent can still
// reason, while the real identity stays hidden and round-trips.

const shape = (s: string): string =>
  [...s]
    .map((c) => (/[a-z]/.test(c) ? "a" : /[A-Z]/.test(c) ? "A" : /[0-9]/.test(c) ? "9" : c))
    .join("");

describe("IdentifierGenerator (format-preserving)", () => {
  const gen = new IdentifierGenerator();
  const fake = (s: string) => gen.generate(Category.HOSTNAME, 0, s);

  test("claims hostname / interface_desc / custom / location", () => {
    expect(gen.categories).toContain(Category.HOSTNAME);
    expect(gen.categories).toContain(Category.CUSTOM);
    expect(gen.categories).toContain(Category.INTERFACE_DESC);
    expect(gen.categories).toContain(Category.LOCATION);
  });

  test("preserves site/rack code structure (LOCATION), consistently", () => {
    const f = (s: string) => gen.generate(Category.LOCATION, 0, s);
    for (const site of ["++ATVIE+F", "++LOWG+TWR", "++ATVIE+F.02-262-030"]) {
      expect(shape(f(site))).toBe(shape(site)); // separators (+ . -) preserved
      expect(f(site)).not.toBe(site);
    }
    // same site prefix -> same fake prefix, so the agent can group by site
    const a = f("++ATVIE+F.02-262");
    const b = f("++ATVIE+F.02-401");
    const prefix = (s: string) => s.slice(0, s.indexOf(".")); // "++ATVIE+F" part
    expect(prefix(a)).toBe(prefix(b));
  });

  test("preserves shape: char classes, lengths, separators", () => {
    for (const real of ["vvoondi01sw_01_new", "wgoormt1aro_new", "++ATVIE+F", "C8200L-1N-4T"]) {
      const f = fake(real);
      expect(f).toHaveLength(real.length);
      expect(shape(f)).toBe(shape(real));
      // separators preserved verbatim
      expect(f.replace(/[a-zA-Z0-9]/g, "")).toBe(real.replace(/[a-zA-Z0-9]/g, ""));
    }
  });

  test("token-consistent: identical tokens map identically (enables matching)", () => {
    const a = fake("vvoondi01sw_01_new");
    const b = fake("xzoormt1aro_new");
    const suffix = (s: string) => s.slice(s.lastIndexOf("_"));
    // every "_new" shares one fake suffix -> agent can group/suffix-match
    expect(suffix(a)).toBe(suffix(b));
    // a different suffix maps differently
    expect(suffix(fake("vvoondi01sw_02_old"))).not.toBe(suffix(a));
  });

  test("hides the real identity (no real token survives)", () => {
    const f = fake("vvoondi01sw_01_new");
    expect(f).not.toContain("vvoondi");
    expect(f).not.toContain("new");
    expect(f).not.toBe("vvoondi01sw_01_new");
  });

  test("deterministic across calls", () => {
    expect(fake("vvoondi01sw_01_new")).toBe(fake("vvoondi01sw_01_new"));
  });
});

describe("end-to-end obfuscate/deobfuscate over a NetBox result", () => {
  const cfg: ShroudConfig = {
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
    auditLogFormat: "human",
    auditIncludeProofHashes: false,
    auditHashSalt: "",
    auditHashTruncate: 12,
    auditMaxFakesSample: 0,
    detectorOverrides: {},
    tenantId: "ncg",
    maxToolDepth: 10,
    lockedCategories: [],
    exposureWindow: 60000,
    exposureThresholds: {},
    exposureGlobalThreshold: 100,
    policyFile: "",
    redactionLevel: "full",
    sharedStorePath: "",
    sharedStoreTtlMs: 5000,
    provenanceTagging: false,
    sessionHandoff: false,
    dryRun: false,
    maxStoreMappings: 0,
  };

  test("device names are format-preserved, hidden, and round-trip", () => {
    const ob = new Obfuscator(cfg);
    const names = [
      "vvoondi01sw_01_new",
      "vvoondi1asr_03_new",
      "wgoormt1aro_new",
      "xzoondi02sw_new",
    ];
    const payload = JSON.stringify({
      count: names.length,
      results: names.map((n, i) => ({
        id: 49766 + i,
        url: `https://10.28.5.3/api/dcim/devices/${49766 + i}/`,
        name: n,
        device_type: { manufacturer: { slug: "cisco-systems" } },
      })),
    });

    const res = ob.obfuscate(payload);
    const fakeText: string = (res as any).obfuscated;
    const fakeNames: string[] = JSON.parse(fakeText).results.map((r: any) => r.name);

    // 1) real names are hidden from the LLM view
    expect(fakeText).not.toContain("_new");
    for (const n of names) expect(fakeText).not.toContain(n);

    // 2) shape preserved + all "_new" share a fake suffix (matchable)
    fakeNames.forEach((f, i) => expect(shape(f)).toBe(shape(names[i])));
    const suffix = (s: string) => s.slice(s.lastIndexOf("_"));
    expect(new Set(fakeNames.map(suffix)).size).toBe(1);

    // 3) round-trips back to the real names for the user-facing output
    const back = ob.deobfuscate(fakeText);
    const backText = (back as any).text ?? (back as any);
    expect(JSON.parse(backText).results.map((r: any) => r.name)).toEqual(names);
  });
});

describe("deobfuscation survives the LLM restoring an inferable token", () => {
  const cfg: any = {
    secretKey: "test-secret-key-1234567890abcdef", persistentSalt: "fixed-test-salt",
    minConfidence: 0, allowlist: [], denylist: [], canaryEnabled: false,
    canaryPrefix: "C", auditEnabled: false, logMappings: false, customPatterns: [],
    verboseLogging: false, auditLogFormat: "human", auditIncludeProofHashes: false,
    auditHashSalt: "", auditHashTruncate: 12, auditMaxFakesSample: 0, detectorOverrides: {},
    tenantId: "ncg", maxToolDepth: 10, lockedCategories: [], exposureWindow: 60000,
    exposureThresholds: {}, exposureGlobalThreshold: 100, policyFile: "", redactionLevel: "full",
    sharedStorePath: "", sharedStoreTtlMs: 5000, provenanceTagging: false, sessionHandoff: false,
    dryRun: false, maxStoreMappings: 0,
  };

  test("agent rewriting the obfuscated suffix back to '_new' still reverses", () => {
    const ob = new Obfuscator(cfg);
    const reals = ["vvoondi1asr_01_new", "vvoonsa4asw_new", "wgoormt1aro_new"];
    const payload = JSON.stringify({
      results: reals.map((n, i) => ({ url: `https://10.28.5.3/api/dcim/devices/${i}/`, name: n })),
    });
    const fakes: string[] = JSON.parse((ob.obfuscate(payload) as any).obfuscated).results.map((r: any) => r.name);
    // none of the fakes leak the real names
    for (const r of reals) expect(fakes.join(",")).not.toContain(r);
    // simulate the LLM restoring the inferable suffix it knows from the query
    const rewritten = fakes.map((f) => f.replace(/[a-z0-9]+$/i, "new"));
    const out = (ob.deobfuscate("Devices: " + rewritten.join(", ")) as any);
    const text = typeof out === "string" ? out : out.text;
    for (const r of reals) expect(text).toContain(r);
  });

  test("does not reverse innocent text that was never obfuscated", () => {
    const ob = new Obfuscator(cfg);
    ob.obfuscate(JSON.stringify({ results: [{ url: "https://10.28.5.3/api/dcim/devices/1/", name: "vvoondi1asr_01_new" }] }));
    const innocent = "The new router is online and the network is stable.";
    const out = (ob.deobfuscate(innocent) as any);
    expect(typeof out === "string" ? out : out.text).toBe(innocent);
  });
});
