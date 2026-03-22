import { describe, it, expect } from "vitest";
import { SessionManager } from "../src/session.js";

describe("SessionManager", () => {
  const key = "test-key-long-enough-for-validation-32chars";

  it("creates sessions with unique IDs", () => {
    const mgr = new SessionManager({ secretKey: key });
    const id1 = mgr.createSession();
    const id2 = mgr.createSession();
    expect(id1).not.toBe(id2);
    expect(mgr.sessionCount).toBe(2);
  });

  it("creates session with explicit ID", () => {
    const mgr = new SessionManager({ secretKey: key });
    const id = mgr.createSession("my-session");
    expect(id).toBe("my-session");
  });

  it("switches between sessions", () => {
    const mgr = new SessionManager({ secretKey: key });
    const id1 = mgr.createSession("s1");
    const id2 = mgr.createSession("s2");

    expect(mgr.activeSessionId).toBe("s2");
    mgr.switchSession("s1");
    expect(mgr.activeSessionId).toBe("s1");
  });

  it("throws on switching to non-existent session", () => {
    const mgr = new SessionManager({ secretKey: key });
    expect(() => mgr.switchSession("nope")).toThrow("does not exist");
  });

  it("provides isolated stores per session", () => {
    const mgr = new SessionManager({ secretKey: key });
    mgr.createSession("s1");
    const session1 = mgr.getActiveSession()!;
    session1.store.put("real1", "fake1", "email" as any);

    mgr.createSession("s2");
    const session2 = mgr.getActiveSession()!;
    expect(session2.store.size()).toBe(0); // Isolated
    expect(session1.store.size()).toBe(1);
  });

  it("destroys sessions and clears data", () => {
    const mgr = new SessionManager({ secretKey: key });
    const id = mgr.createSession("s1");
    mgr.getActiveSession()!.store.put("r", "f", "email" as any);

    mgr.destroySession(id);
    expect(mgr.sessionCount).toBe(0);
    expect(mgr.activeSessionId).toBeNull();
  });

  it("lists sessions with metadata", () => {
    const mgr = new SessionManager({ secretKey: key });
    mgr.createSession("s1");
    mgr.getActiveSession()!.store.put("r", "f", "email" as any);
    mgr.createSession("s2");

    const sessions = mgr.listSessions();
    expect(sessions.length).toBe(2);
    const s1 = sessions.find((s) => s.id === "s1")!;
    expect(s1.storeSize).toBe(1);
    expect(s1.active).toBe(false);

    const s2 = sessions.find((s) => s.id === "s2")!;
    expect(s2.active).toBe(true);
  });

  it("clearAll removes everything", () => {
    const mgr = new SessionManager({ secretKey: key });
    mgr.createSession("s1");
    mgr.createSession("s2");
    mgr.clearAll();
    expect(mgr.sessionCount).toBe(0);
    expect(mgr.activeSessionId).toBeNull();
  });

  it("creates canary injectors when enabled", () => {
    const mgr = new SessionManager({ secretKey: key, canaryEnabled: true });
    mgr.createSession();
    const session = mgr.getActiveSession()!;
    expect(session.canary).not.toBeNull();
  });

  it("no canary when disabled", () => {
    const mgr = new SessionManager({ secretKey: key, canaryEnabled: false });
    mgr.createSession();
    const session = mgr.getActiveSession()!;
    expect(session.canary).toBeNull();
  });
});

describe("Per-session isolation in Obfuscator", () => {
  it("isolates obfuscation across sessions", async () => {
    const { resolveConfig } = await import("../src/config.js");
    const { Obfuscator } = await import("../src/obfuscator.js");

    const config = resolveConfig({
      secretKey: "test-key-long-enough-for-validation-32chars",
      sessionIsolation: true,
      persistentSalt: "test-salt",
    });
    const obfuscator = new Obfuscator(config);

    // Get the initial session ID created by constructor
    const s1Id = obfuscator.sessionManager!.activeSessionId!;

    // Session 1: obfuscate email
    const r1 = obfuscator.obfuscate("Contact john@acme.com for details");
    expect(r1.entities.length).toBeGreaterThan(0);

    // Create new session — mappings should be isolated
    obfuscator.createSession("s2");
    const r2 = obfuscator.deobfuscate(r1.obfuscated);
    // In the new session, old fakes are NOT in the store, so deobfuscation won't work
    expect(r2).toBe(r1.obfuscated);

    // Switch back to original session
    obfuscator.switchSession(s1Id);

    // Now deobfuscation works
    const r3 = obfuscator.deobfuscate(r1.obfuscated);
    expect(r3).toContain("john@acme.com");
  });
});
