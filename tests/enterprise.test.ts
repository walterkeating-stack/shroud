/** Tests for enterprise modules: exposure, policy, redaction, tenant, shared-store. */

import { describe, test, expect } from "vitest";

import { ExposureTracker } from "../src/exposure.js";
import { PolicyLoader } from "../src/policy.js";
import { RedactionFormatter } from "../src/redaction.js";
import { TenantStoreManager } from "../src/tenant.js";
import { MemoryStore } from "../src/store.js";
import { Category } from "../src/types.js";

// ---------------------------------------------------------------------------
// ExposureTracker
// ---------------------------------------------------------------------------

describe("ExposureTracker", () => {
  test("no alerts under threshold", () => {
    const tracker = new ExposureTracker(60000, { email: 10 }, 100);
    tracker.record("email", 3);
    expect(tracker.check()).toHaveLength(0);
  });

  test("alerts when category exceeds threshold", () => {
    const tracker = new ExposureTracker(60000, { email: 2 }, 100);
    tracker.record("email", 5);
    const alerts = tracker.check();
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts[0].category).toBe("email");
    expect(alerts[0].count).toBe(5);
  });

  test("global threshold triggers alert", () => {
    const tracker = new ExposureTracker(60000, {}, 3);
    tracker.record("email", 2);
    tracker.record("ip_address", 2);
    const alerts = tracker.check();
    const global = alerts.find((a) => a.category === "__global__");
    expect(global).toBeDefined();
    expect(global!.count).toBe(4);
  });

  test("reset clears events", () => {
    const tracker = new ExposureTracker(60000, { email: 1 }, 100);
    tracker.record("email", 5);
    tracker.reset();
    expect(tracker.check()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// PolicyLoader
// ---------------------------------------------------------------------------

describe("PolicyLoader", () => {
  test("literal allowlist matches exact value", () => {
    const rules = PolicyLoader.parseInline({
      allowlist: ["10.0.0.1", "example.com"],
    });
    expect(PolicyLoader.isAllowed("10.0.0.1", rules.allowlist)).toBe(true);
    expect(PolicyLoader.isAllowed("10.0.0.2", rules.allowlist)).toBe(false);
  });

  test("glob allowlist matches patterns", () => {
    const rules = PolicyLoader.parseInline({
      allowlist: [{ pattern: "192.168.*.*", type: "glob" }],
    });
    expect(PolicyLoader.isAllowed("192.168.1.1", rules.allowlist)).toBe(true);
    expect(PolicyLoader.isAllowed("10.0.0.1", rules.allowlist)).toBe(false);
  });

  test("regex denylist matches", () => {
    const rules = PolicyLoader.parseInline({
      denylist: [
        { pattern: "\\b(SECRET|CONFIDENTIAL)\\b", type: "regex", category: "custom" },
      ],
    });
    const result = PolicyLoader.isDenied("SECRET", rules.denylist);
    expect(result.denied).toBe(true);
  });

  test("scanDenylist finds matches in text", () => {
    const rules = PolicyLoader.parseInline({
      denylist: ["CLASSIFIED"],
    });
    const matches = PolicyLoader.scanDenylist(
      "This is CLASSIFIED info, CLASSIFIED twice",
      rules.denylist,
    );
    expect(matches).toHaveLength(2);
    expect(matches[0].value).toBe("CLASSIFIED");
  });

  test("merge combines rule sets", () => {
    const a = PolicyLoader.parseInline({ allowlist: ["a"], denylist: [] });
    const b = PolicyLoader.parseInline({ allowlist: ["b"], denylist: ["x"] });
    const merged = PolicyLoader.merge(a, b);
    expect(merged.allowlist).toHaveLength(2);
    expect(merged.denylist).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// RedactionFormatter
// ---------------------------------------------------------------------------

describe("RedactionFormatter", () => {
  const fmt = new RedactionFormatter();

  test("full mode returns fake value", () => {
    expect(fmt.format("real", "fake", Category.EMAIL, "full")).toBe("fake");
  });

  test("masked mode masks email", () => {
    const result = fmt.format("john@acme.com", "fake", Category.EMAIL, "masked");
    expect(result).toContain("***");
    expect(result).not.toContain("john");
  });

  test("masked mode masks credit card last 4", () => {
    const result = fmt.format("4111-1111-1111-1234", "fake", Category.CREDIT_CARD, "masked");
    expect(result).toContain("1234");
    expect(result).toContain("****");
  });

  test("stats mode returns placeholder", () => {
    fmt.resetCounters();
    const r1 = fmt.format("val1", "fake1", Category.EMAIL, "stats");
    const r2 = fmt.format("val2", "fake2", Category.EMAIL, "stats");
    expect(r1).toBe("[EMAIL-1]");
    expect(r2).toBe("[EMAIL-2]");
  });

  test("stats counters reset", () => {
    fmt.resetCounters();
    const r = fmt.format("val", "fake", Category.IP_ADDRESS, "stats");
    expect(r).toBe("[IP_ADDRESS-1]");
  });
});

// ---------------------------------------------------------------------------
// TenantStoreManager
// ---------------------------------------------------------------------------

describe("TenantStoreManager", () => {
  test("isolates stores per tenant", () => {
    const mgr = new TenantStoreManager();
    const s1 = mgr.getStore("t1");
    const s2 = mgr.getStore("t2");
    s1.put("real", "fake1", Category.EMAIL);
    s2.put("real", "fake2", Category.EMAIL);
    expect(s1.getFake("real")).toBe("fake1");
    expect(s2.getFake("real")).toBe("fake2");
  });

  test("totalSize sums across tenants", () => {
    const mgr = new TenantStoreManager();
    mgr.getStore("t1").put("a", "b", Category.EMAIL);
    mgr.getStore("t2").put("c", "d", Category.EMAIL);
    expect(mgr.totalSize()).toBe(2);
  });

  test("clearAll removes everything", () => {
    const mgr = new TenantStoreManager();
    mgr.getStore("t1").put("a", "b", Category.EMAIL);
    mgr.clearAll();
    expect(mgr.tenantIds()).toHaveLength(0);
    expect(mgr.totalSize()).toBe(0);
  });

  test("clearTenant removes one tenant", () => {
    const mgr = new TenantStoreManager();
    mgr.getStore("t1").put("a", "b", Category.EMAIL);
    mgr.getStore("t2").put("c", "d", Category.EMAIL);
    mgr.clearTenant("t1");
    expect(mgr.tenantIds()).toEqual(["t2"]);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore export/import
// ---------------------------------------------------------------------------

describe("MemoryStore export/import", () => {
  test("export and import round-trips", () => {
    const store1 = new MemoryStore();
    store1.put("real1", "fake1", Category.EMAIL);
    store1.put("real2", "fake2", Category.IP_ADDRESS);
    const exported = store1.export("test-salt");

    const store2 = new MemoryStore();
    store2.import(exported);
    expect(store2.getFake("real1")).toBe("fake1");
    expect(store2.getReal("fake2")).toBe("real2");
    expect(store2.size()).toBe(2);
  });

  test("export includes metadata", () => {
    const store = new MemoryStore();
    store.put("real", "fake", Category.EMAIL);
    const exported = store.export("my-salt", "tenant-1");
    expect(exported.salt).toBe("my-salt");
    expect(exported.tenantId).toBe("tenant-1");
    expect(exported.exportedAt).toBeTruthy();
    expect(exported.mappings).toHaveLength(1);
  });
});
