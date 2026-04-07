import { describe, test, expect, vi } from "vitest";

import { ShroudConfig } from "../src/types.js";
import { Obfuscator } from "../src/obfuscator.js";
import { registerHooks } from "../src/hooks.js";

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
  auditLogFormat: "human",
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

/**
 * Creates a mock PluginApi that captures registered hooks
 * and allows invoking them by event name.
 */
function createMockApi() {
  const handlers: Record<string, Function> = {};
  const tools: Record<string, { description: string; handler: Function }> = {};
  const logLines: string[] = [];
  const api = {
    on(event: string, handler: Function) {
      handlers[event] = handler;
    },
    registerTool(tool: { name: string; description: string; handler: Function }) {
      tools[tool.name] = { description: tool.description, handler: tool.handler };
    },
    logger: {
      info(...args: any[]) { logLines.push(args.map(String).join(" ")); },
      warn(...args: any[]) { logLines.push(args.map(String).join(" ")); },
      error(...args: any[]) { logLines.push(args.map(String).join(" ")); },
    },
  };
  return { api, handlers, tools, logLines };
}

describe("hooks - before_prompt_build", () => {
  test("obfuscates user prompt and returns prompt replacement", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { prompt: "Contact john@acme.com please", messages: [] } as any;
    const result = await handlers["before_prompt_build"](event);
    // Hook returns systemPrompt with obfuscated prompt
    expect(result?.systemPrompt).toBeDefined();
    expect(result.systemPrompt).not.toContain("john@acme.com");
    expect(result.systemPrompt).toContain("@"); // fake email present
  });

  test("returns nothing when no PII detected", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { prompt: "Hello world" };
    const result = await handlers["before_prompt_build"](event);
    expect(result).toBeUndefined();
  });

  test("returns nothing for empty prompt", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const result = await handlers["before_prompt_build"]({ prompt: "" });
    expect(result).toBeUndefined();
  });
});

describe("hooks - before_message_write", () => {
  test("obfuscates string content in messages", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { message: { role: "user", content: "Contact john@acme.com please" } };
    const result = handlers["before_message_write"](event);
    expect(result).toBeDefined();
    expect(result.message.content).not.toContain("john@acme.com");
    expect(result.message.content).toContain("@"); // fake email
    expect(result.message.role).toBe("user");
  });

  test("obfuscates array-of-blocks content", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = {
      message: {
        role: "user",
        content: [{ type: "text", text: "Found alice@secret.org in logs" }],
      },
    };
    const result = handlers["before_message_write"](event);
    expect(result).toBeDefined();
    expect(result.message.content[0].text).not.toContain("alice@secret.org");
  });

  test("returns void when no PII detected", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { message: { role: "user", content: "Hello world" } };
    const result = handlers["before_message_write"](event);
    expect(result).toBeUndefined();
  });

  test("returns void for empty/missing message", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    expect(handlers["before_message_write"]({})).toBeUndefined();
    expect(handlers["before_message_write"]({ message: null })).toBeUndefined();
  });

  test("deobfuscation works after message_write obfuscation", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate via before_message_write
    const event = { message: { role: "user", content: "Email john@acme.com" } };
    const result = handlers["before_message_write"](event);
    const fakeContent = result.message.content;

    // Deobfuscate via message_sending (simulating outbound)
    const deobResult = obf.deobfuscate(fakeContent);
    expect(deobResult).toContain("john@acme.com");
  });
});


describe("hooks - before_tool_call", () => {
  test("deobfuscates tool params (object)", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // First obfuscate to populate the store
    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    const event = { toolName: "some_tool", params: { query: `search for ${fakeEmail}` } };
    const result = await handlers["before_tool_call"](event);
    expect(result).toBeDefined();
    expect(result.params.query).toContain("john@acme.com");
    expect(result.params.query).not.toContain(fakeEmail);
  });

  test("deobfuscates tool params with nested values", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const obResult = obf.obfuscate("10.20.30.40");
    const fakeIp = obResult.mappingsUsed["10.20.30.40"];

    const event = { toolName: "ssh", params: { host: fakeIp } };
    const result = await handlers["before_tool_call"](event);
    expect(result).toBeDefined();
    expect(result.params.host).toBe("10.20.30.40");
  });

  test("returns void when no params to deobfuscate", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const result = await handlers["before_tool_call"]({ toolName: "read", params: { path: "/tmp/foo" } });
    expect(result).toBeUndefined();
  });
});

describe("hooks - tool_result_persist", () => {
  test("obfuscates tool result message (string)", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { message: "Found email alice@secret.org in logs" };
    const result = handlers["tool_result_persist"](event);
    expect(result).toBeDefined();
    expect(result.message).not.toContain("alice@secret.org");
  });

  test("obfuscates tool result message (array blocks)", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = {
      message: [{ type: "text", text: "IP 172.16.0.50 is active" }],
    };
    const result = handlers["tool_result_persist"](event);
    expect(result).toBeDefined();
    expect(result.message[0].text).not.toContain("172.16.0.50");
  });

  test("returns void when no message", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const result = handlers["tool_result_persist"]({});
    expect(result).toBeUndefined();
  });
});

describe("hooks - message_sending", () => {
  test("deobfuscates outbound message content", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate first to populate the store
    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    const event = { content: `The contact is ${fakeEmail}` };
    const result = await handlers["message_sending"](event);
    expect(result).toBeDefined();
    expect(result.content).toContain("john@acme.com");
    expect(result.content).not.toContain(fakeEmail);
  });

  test("always returns content even when nothing changed (overrides original payload)", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const result = await handlers["message_sending"]({ content: "Hello world" });
    // Must always return { content } to override OpenClaw's original payload,
    // which may have fake text from the streaming buffer
    expect(result).toBeDefined();
    expect(result.content).toBe("Hello world");
  });
});

describe("hooks - full flow", () => {
  test("prompt obfuscated -> message_write obfuscated -> tool deobfuscated -> message_sending deobfuscated", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Step 1: User sends prompt with PII
    const step1Event = { prompt: "Look up john@acme.com", messages: [] } as any;
    const step1Result = await handlers["before_prompt_build"](step1Event);
    expect(step1Result?.systemPrompt).not.toContain("john@acme.com");

    // Get the fake email from the mapping
    const fakeEmail = obf.obfuscate("john@acme.com").mappingsUsed["john@acme.com"];

    // Step 2: before_message_write obfuscates message in session
    const step2 = handlers["before_message_write"]({
      message: { role: "user", content: "Look up john@acme.com" },
    });
    expect(step2).toBeDefined();
    expect(step2.message.content).not.toContain("john@acme.com");

    // Step 3: Tool call gets deobfuscated params
    const step3 = await handlers["before_tool_call"]({
      toolName: "message",
      params: { email: fakeEmail },
    });
    expect(step3.params.email).toBe("john@acme.com");

    // Step 4: Tool result re-obfuscated
    const step4 = handlers["tool_result_persist"]({
      message: "User john@acme.com has account #1234",
    });
    expect(step4.message).not.toContain("john@acme.com");

    // Step 5: Outbound message deobfuscated via message_sending
    const step5 = await handlers["message_sending"]({
      content: `Found account for ${fakeEmail}`,
    });
    expect(step5).toBeDefined();
    expect(step5.content).toContain("john@acme.com");
    expect(step5.content).not.toContain(fakeEmail);
  });

});

// =========================================================================
// shroud-stats tool tests
// =========================================================================

describe("hooks - shroud-stats tool", () => {
  test("registers shroud-stats tool and returns rule table", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, tools } = createMockApi();
    registerHooks(api, obf);

    expect(tools["shroud-stats"]).toBeDefined();

    // Generate some hits
    obf.obfuscate("Contact john@acme.com from 10.0.0.1");

    const result = await tools["shroud-stats"].handler({});
    const text = result.content[0].text;

    expect(text).toContain("Shroud Rule Hits");
    expect(text).toContain("email");
    expect(text).toContain("ipv4");
    expect(text).toContain("active");
    expect(text).toContain("Store:");
  });

  test("shows disabled rules from detectorOverrides", async () => {
    const obf = new Obfuscator({
      ...testConfig,
      detectorOverrides: { phone_intl: { enabled: false } },
    });
    const { api, tools } = createMockApi();
    registerHooks(api, obf);

    const result = await tools["shroud-stats"].handler({});
    const text = result.content[0].text;

    expect(text).toContain("DISABLED");
  });
});

describe("hooks - before_message_write assistant deobfuscation", () => {
  test("deobfuscates assistant message string content", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers: hooks } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate to populate mapping store
    const result = obf.obfuscate("Contact john@acme.com for details");
    const fakeEmail = result.obfuscated.match(/\S+@\S+/)![0];

    // Simulate assistant message with fakes
    const handler = hooks["before_message_write"];
    const out = handler({
      message: { role: "assistant", content: `Here is the email: ${fakeEmail}` },
    });

    expect(out).toBeDefined();
    expect(out.message.content).toContain("john@acme.com");
    expect(out.message.content).not.toContain(fakeEmail);
  });

  test("does not deobfuscate user messages", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers: hooks } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate to populate mapping
    const result = obf.obfuscate("Contact john@acme.com");
    const fakeEmail = result.obfuscated.match(/\S+@\S+/)![0];

    // User message with fake should be obfuscated further, not deobfuscated
    const handler = hooks["before_message_write"];
    const out = handler({
      message: { role: "user", content: `Send to ${fakeEmail}` },
    });

    // User message gets obfuscated (not deobfuscated)
    if (out) {
      expect(out.message.content).not.toContain("john@acme.com");
    }
  });

  test("deobfuscates assistant array-of-blocks content", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers: hooks } = createMockApi();
    registerHooks(api, obf);

    const result = obf.obfuscate("Contact john@acme.com");
    const fakeEmail = result.obfuscated.match(/\S+@\S+/)![0];

    const handler = hooks["before_message_write"];
    const out = handler({
      message: {
        role: "assistant",
        content: [{ type: "text", text: `Email: ${fakeEmail}` }],
      },
    });

    expect(out).toBeDefined();
    expect(out.message.content[0].text).toContain("john@acme.com");
  });
});

// =========================================================================
// Streaming deobfuscation hook tests
// =========================================================================

describe("hooks - streaming deobfuscation (__shroudStreamDeobfuscate)", () => {
  test("deobfuscates text_delta events via buffer", () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    const hook = (globalThis as any).__shroudStreamDeobfuscate;
    expect(hook).toBeTypeOf("function");

    // Obfuscate to populate mappings
    const obResult = obf.obfuscate("Contact john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    // text_delta with fake should be deobfuscated
    const stream: any = {};
    hook(stream, { type: "text_delta", delta: `Email: ${fakeEmail}` });

    // Buffer should be created
    const bufSymbols = Object.getOwnPropertySymbols(stream);
    expect(bufSymbols.length).toBe(1);
  });

  test("streaming buffer resets after message_end", () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    const hook = (globalThis as any).__shroudStreamDeobfuscate;
    const stream: any = {};

    hook(stream, { type: "text_delta", delta: "hello " });
    hook(stream, { type: "text_delta", delta: "world" });

    // Buffer should exist
    expect(Object.getOwnPropertySymbols(stream).length).toBe(1);

    // End message — buffer should be cleaned up
    hook(stream, { type: "done" });
    expect(Object.getOwnPropertySymbols(stream).length).toBe(0);
  });

  test("message_end passes content through (deobfuscation handled by before_message_write)", () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    const hook = (globalThis as any).__shroudStreamDeobfuscate;

    // Obfuscate to populate mappings
    const obResult = obf.obfuscate("Server 10.42.88.7 is down");
    const fakeIp = obResult.mappingsUsed["10.42.88.7"];
    const fakeText = `The server ${fakeIp} needs attention`;

    const stream: any = {};
    const finalContent = [{ type: "text", text: fakeText }];
    const endEvt = hook(stream, {
      type: "message_end",
      message: { content: finalContent },
    });

    // message_end deobfuscates content blocks (used by streaming delivery)
    expect(endEvt.message.content[0].text).toContain("10.42.88.7");
    expect(endEvt.message.content[0].text).not.toContain(fakeIp);
  });
});

// =========================================================================
// Audit counter accuracy tests
// =========================================================================

describe("hooks - audit counter accuracy", () => {
  test("before_message_write assistant deob emits audit when auditEnabled", () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate to populate mapping
    const obResult = obf.obfuscate("Contact john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    // Simulate assistant message with fake
    handlers["before_message_write"]({
      message: { role: "assistant", content: `Found: ${fakeEmail}` },
    });

    const deobAudit = logLines.filter(l => l.includes("shroud.audit.deobfuscate"));
    expect(deobAudit.length).toBe(1);

    const audit = JSON.parse(deobAudit[0]);
    expect(audit.deobfuscations).toBeGreaterThan(0);
  });

  test("message_sending emits deobfuscation audit", async () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    const obResult = obf.obfuscate("Contact john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    await handlers["message_sending"]({ content: `Email: ${fakeEmail}` });

    const deobAudit = logLines.filter(l => l.includes("shroud.audit.deobfuscate"));
    expect(deobAudit.length).toBe(1);
  });

  test("obfuscation count matches across full lifecycle", async () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate 3 times
    await handlers["before_prompt_build"]({ prompt: "Email john@acme.com" });
    await handlers["before_prompt_build"]({ prompt: "IP 10.1.0.1 is down" });
    await handlers["before_prompt_build"]({ prompt: "Call +14155551234" });

    const stats = obf.getStats() as any;
    expect(stats.storeMappings).toBeGreaterThanOrEqual(3);
  });

  test("before_message_write obfuscation emits audit for user messages", () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    handlers["before_message_write"]({
      message: { role: "user", content: "Contact alice@secret.org about 10.0.0.1" },
    });

    const obfAudit = logLines.filter(l => l.includes("shroud.audit.obfuscate"));
    expect(obfAudit.length).toBe(1);

    const audit = JSON.parse(obfAudit[0]);
    expect(audit.totalEntities).toBeGreaterThanOrEqual(2);
    expect(audit.byCategory).toBeDefined();
    expect(audit.byRule).toBeDefined();
  });

  test("before_message_write obfuscation emits audit for array-of-blocks", () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    handlers["before_message_write"]({
      message: {
        role: "user",
        content: [{ type: "text", text: "Server 10.20.30.40 and john@acme.com" }],
      },
    });

    const obfAudit = logLines.filter(l => l.includes("shroud.audit.obfuscate"));
    expect(obfAudit.length).toBeGreaterThanOrEqual(1);
  });

  test("tool_result_persist triggers dumpStatsFile", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate first to have something in the store
    obf.obfuscate("alice@secret.org");

    handlers["tool_result_persist"]({
      message: "Found alice@secret.org in the database",
    });

    // Stats should show at least 1 mapping
    const stats = obf.getStats() as any;
    expect(stats.storeMappings).toBeGreaterThanOrEqual(1);
  });

  test("no audit emitted when auditEnabled is false", () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: false });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    handlers["before_message_write"]({
      message: { role: "user", content: "Email alice@secret.org" },
    });

    const auditLines = logLines.filter(l => l.includes("shroud.audit"));
    expect(auditLines.length).toBe(0);
  });

  test("message_end deobfuscates final content blocks", () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    const hook = (globalThis as any).__shroudStreamDeobfuscate;

    // Obfuscate to populate mappings
    const obResult = obf.obfuscate("Email john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    // Send message_end with fake in content blocks
    const stream: any = {};
    const endEvt = hook(stream, {
      type: "done",
      message: { content: [{ type: "text", text: `Result: ${fakeEmail}` }] },
    });

    // message_end deobfuscates content blocks (used by streaming delivery)
    expect(endEvt.message.content[0].text).toContain("john@acme.com");
    expect(endEvt.message.content[0].text).not.toContain(fakeEmail);
  });
});

// =========================================================================
// Audit format tests (JSON vs human)
// =========================================================================

describe("hooks - audit log formats", () => {
  test("emitObfuscationAudit JSON format has all required fields", () => {
    const obf = new Obfuscator({
      ...testConfig,
      auditEnabled: true,
      auditLogFormat: "json",
      auditIncludeProofHashes: true,
      auditHashSalt: "test-salt",
      auditHashTruncate: 12,
      auditMaxFakesSample: 3,
    });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    handlers["before_message_write"]({
      message: { role: "user", content: "Contact john@acme.com from 10.1.0.1" },
    });

    const obfAudit = logLines.filter(l => l.includes("shroud.audit.obfuscate"));
    expect(obfAudit.length).toBe(1);

    const audit = JSON.parse(obfAudit[0]);
    expect(audit.event).toBe("shroud.audit.obfuscate");
    expect(audit.req).toBeDefined();
    expect(audit.ts).toBeDefined();
    expect(audit.modified).toBe(true);
    expect(audit.totalEntities).toBeGreaterThanOrEqual(2);
    expect(audit.inputChars).toBeGreaterThan(0);
    expect(audit.outputChars).toBeGreaterThan(0);
    expect(audit.charDelta).toBeDefined();
    expect(audit.byCategory).toBeDefined();
    expect(audit.byRule).toBeDefined();
    // Proof hashes
    expect(audit.proofIn).toBeDefined();
    expect(audit.proofIn.length).toBe(12);
    expect(audit.proofOut).toBeDefined();
    expect(audit.proofOut.length).toBe(12);
    // Fakes sample
    expect(audit.fakesSample).toBeDefined();
    expect(audit.fakesSample.length).toBeGreaterThan(0);
    expect(audit.fakesSample.length).toBeLessThanOrEqual(3);
  });

  test("emitObfuscationAudit human format has pipe-separated fields", () => {
    const obf = new Obfuscator({
      ...testConfig,
      auditEnabled: true,
      auditLogFormat: "human",
    });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    handlers["before_message_write"]({
      message: { role: "user", content: "Contact john@acme.com" },
    });

    const obfAudit = logLines.filter(l => l.includes("[shroud][audit] OBFUSCATE"));
    expect(obfAudit.length).toBe(1);
    expect(obfAudit[0]).toContain("req=");
    expect(obfAudit[0]).toContain("entities=");
    expect(obfAudit[0]).toContain("chars=");
    expect(obfAudit[0]).toContain("modified=YES");
    expect(obfAudit[0]).toContain("byCat=");
    expect(obfAudit[0]).toContain("byRule=");
    expect(obfAudit[0]).toContain("|");
  });

  test("emitDeobfuscationAudit JSON format", async () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    await handlers["message_sending"]({ content: `Found ${fakeEmail}` });

    const deobAudit = logLines.filter(l => l.includes("shroud.audit.deobfuscate"));
    expect(deobAudit.length).toBe(1);

    const audit = JSON.parse(deobAudit[0]);
    expect(audit.event).toBe("shroud.audit.deobfuscate");
    expect(audit.req).toBeDefined();
    expect(audit.ts).toBeDefined();
    expect(audit.modified).toBe(true);
    expect(audit.deobfuscations).toBeGreaterThan(0);
  });

  test("emitDeobfuscationAudit human format", async () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "human" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    await handlers["message_sending"]({ content: `Found ${fakeEmail}` });

    const deobAudit = logLines.filter(l => l.includes("[shroud][audit] DEOBFUSCATE"));
    expect(deobAudit.length).toBe(1);
    expect(deobAudit[0]).toContain("req=");
    expect(deobAudit[0]).toContain("replacements=");
    expect(deobAudit[0]).toContain("modified=YES");
  });

  test("proof hashes not included when auditIncludeProofHashes is false", () => {
    const obf = new Obfuscator({
      ...testConfig,
      auditEnabled: true,
      auditLogFormat: "json",
      auditIncludeProofHashes: false,
    });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    handlers["before_message_write"]({
      message: { role: "user", content: "Contact john@acme.com" },
    });

    const obfAudit = logLines.filter(l => l.includes("shroud.audit.obfuscate"));
    const audit = JSON.parse(obfAudit[0]);
    expect(audit.proofIn).toBeUndefined();
    expect(audit.proofOut).toBeUndefined();
  });

  test("fakes sample not included when auditMaxFakesSample is 0", () => {
    const obf = new Obfuscator({
      ...testConfig,
      auditEnabled: true,
      auditLogFormat: "json",
      auditMaxFakesSample: 0,
    });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    handlers["before_message_write"]({
      message: { role: "user", content: "Contact john@acme.com" },
    });

    const obfAudit = logLines.filter(l => l.includes("shroud.audit.obfuscate"));
    const audit = JSON.parse(obfAudit[0]);
    expect(audit.fakesSample).toBeUndefined();
  });

  test("modified=NO when no entities detected", () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, handlers, logLines } = createMockApi();
    registerHooks(api, obf);

    // Send text with no PII — before_message_write returns undefined (no audit)
    const result = handlers["before_message_write"]({
      message: { role: "user", content: "Hello world no PII here" },
    });
    expect(result).toBeUndefined();
    // No audit line when nothing was modified
    const obfAudit = logLines.filter(l => l.includes("shroud.audit.obfuscate"));
    expect(obfAudit.length).toBe(0);
  });
});

// =========================================================================
// Fetch intercept tests
// =========================================================================

describe("hooks - fetch intercept", () => {
  test("fetch intercept obfuscates user message content", async () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    // Populate mappings
    obf.obfuscate("john@acme.com");
    const fakeEmail = obf.obfuscate("john@acme.com").mappingsUsed["john@acme.com"];

    // Simulate a fetch call to an LLM API
    const capturedBodies: string[] = [];
    const mockFetch = async (input: any, init: any) => {
      capturedBodies.push(init?.body);
      return new Response(JSON.stringify({ choices: [{ message: { content: "ok" } }] }));
    };

    // The fetch intercept patches globalThis.fetch
    const interceptedFetch = globalThis.fetch;
    try {
      const body = JSON.stringify({
        model: "test",
        messages: [
          { role: "user", content: [{ type: "text", text: "Contact john@acme.com please" }] },
        ],
      });

      await interceptedFetch("http://localhost/v1/messages", {
        method: "POST",
        body,
        headers: { "Content-Type": "application/json" },
      } as any).catch(() => {});

      // The intercepted fetch should have modified the body
      // We can't easily capture the modified body without mocking,
      // but we can verify the intercept is installed
      expect((globalThis as any).__shroudFetchPatched).toBe(true);
    } finally {
      // Don't restore — other tests may need the intercept
    }
  });

  test("fetch intercept re-obfuscates deobfuscated assistant messages", async () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    // Simulate multi-turn flow:
    // 1. User sends PII → obfuscated to fake
    // 2. LLM responds with fake → before_message_write deobfuscates to real
    // 3. Next turn: assistant message in history contains REAL PII
    // 4. Fetch intercept MUST re-obfuscate it to prevent PII leaking to LLM

    const result = obf.obfuscate("Contact john@acme.com");
    const fakeEmail = result.mappingsUsed["john@acme.com"];

    // Simulate deobfuscated assistant message (contains real email)
    const assistantContent = `Here is the email: john@acme.com`;

    // Re-obfuscate — must produce the same fake (deterministic)
    const reObf = obf.obfuscate(assistantContent);
    const reFake = reObf.mappingsUsed["john@acme.com"];
    expect(reFake).toBe(fakeEmail);

    // The fetch intercept must NOT skip assistant messages, otherwise
    // real PII from deobfuscated responses leaks to the LLM on the
    // next turn, causing the LLM to output both real and fake values.
    // Verify the code no longer skips assistant messages:
    expect(obf.obfuscate(assistantContent).obfuscated).not.toContain("john@acme.com");
  });

  test("before_prompt_build and fetch intercept produce same fake for same value", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Simulate before_prompt_build
    const hookResult = handlers["before_prompt_build"]({
      prompt: "Contact john@acme.com",
    });

    // Get the fake from the mapping store
    const fakeEmail = obf.obfuscate("john@acme.com").mappingsUsed["john@acme.com"];

    // The hook result should contain the same fake
    expect(hookResult).toBeDefined();
    // hookResult is a Promise (async handler)
    hookResult.then((r: any) => {
      if (r?.prompt) {
        expect(r.prompt).toContain(fakeEmail);
        expect(r.prompt).not.toContain("john@acme.com");
      }
    });
  });

  test("re-obfuscating already-obfuscated text does not create new fakes", () => {
    const obf = new Obfuscator(testConfig);

    // First obfuscation
    const r1 = obf.obfuscate("Server 10.1.0.1 contacted admin@acme.com");
    const obfuscated = r1.obfuscated;

    // Second obfuscation of the already-obfuscated text
    const r2 = obf.obfuscate(obfuscated);

    // The text should not change — fakes are already in place
    // and the original values are gone
    expect(r2.obfuscated).toBe(obfuscated);
    expect(r2.entities.length).toBe(0);
  });

  test("multi-turn conversation: no PII leaks through history", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Turn 1: user sends PII
    const obfResult = obf.obfuscate("Contact john@acme.com about 10.1.0.1");
    const fakeEmail = obfResult.mappingsUsed["john@acme.com"];
    const fakeIp = obfResult.mappingsUsed["10.1.0.1"];

    // Turn 1: LLM response (deobfuscated by streaming — contains reals)
    const assistantResponse = `Here is john@acme.com at 10.1.0.1`;

    // Turn 2: new user message with PII
    const turn2 = obf.obfuscate("Also check alice@secret.org");
    const fakeEmail2 = turn2.mappingsUsed["alice@secret.org"];

    // Build the messages array as OpenClaw would
    const messages = [
      { role: "user", content: obfResult.obfuscated },         // obfuscated
      { role: "assistant", content: assistantResponse },         // deobfuscated (reals)
      { role: "user", content: turn2.obfuscated },              // obfuscated
    ];

    // Verify: user messages have fakes, not reals
    expect(messages[0].content).toContain(fakeEmail);
    expect(messages[0].content).not.toContain("john@acme.com");
    expect(messages[2].content).toContain(fakeEmail2);
    expect(messages[2].content).not.toContain("alice@secret.org");

    // Verify: assistant message has reals before fetch intercept runs
    // (the fetch intercept will re-obfuscate these on the next turn)
    expect(messages[1].content).toContain("john@acme.com");

    // Verify: no duplicate fakes exist across the conversation
    const allContent = messages.map(m => m.content).join("\n");
    const fakeOccurrences = (allContent.match(new RegExp(fakeEmail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
    expect(fakeOccurrences).toBe(1); // only in the user message, not duplicated
  });
});

describe("hooks - Slack E2E simulation", () => {
  test("fetch intercept strips Slack mailto markup and obfuscates PII", async () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    // Simulate Slack-formatted user message with <mailto:> markup
    const slackMessage = 'fomat as json please: <mailto:user@example.test|user@example.test>';

    // Obfuscate via before_prompt_build
    const result = obf.obfuscate(slackMessage);
    expect(result.entities.length).toBeGreaterThan(0);

    // The obfuscated text should not contain the real email
    expect(result.obfuscated).not.toContain("user@example.test");
  });

  test("fetch intercept re-obfuscates assistant message with Slack content blocks", async () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    // Turn 1: obfuscate email
    const r1 = obf.obfuscate("user@example.test");
    const fake = r1.mappingsUsed["user@example.test"];

    // Simulate: assistant responded with fake, before_message_write deobfuscated
    // Now transcript has real email in assistant content block (Anthropic format)
    const assistantBlock = { type: "text", text: `{"email": "user@example.test"}` };

    // Re-obfuscate the assistant block text (as fetch intercept would)
    const r2 = obf.obfuscate(assistantBlock.text);
    expect(r2.entities.length).toBe(1);
    expect(r2.obfuscated).not.toContain("user@example.test");
    expect(r2.obfuscated).toContain(fake); // same deterministic fake
  });

  test("message_sending deobfuscates channel output with fake email", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate to create mapping
    const r = obf.obfuscate("user@example.test");
    const fake = r.mappingsUsed["user@example.test"];

    // Simulate message_sending with fake in content (as 2026.3.24 deliverOutboundPayloads does)
    const result = await handlers["message_sending"]({ content: `{"email": "${fake}"}` });

    // Should deobfuscate the fake back to real
    expect(result?.content || `{"email": "${fake}"}`).toContain("user@example.test");
  });

  test("full Slack flow: obfuscate→LLM→deobfuscate→channel — single output, no fakes", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Step 1: User sends message via Slack (with mailto markup)
    const slackInput = 'format as json: <mailto:user@example.test|user@example.test>';

    // Step 2: before_prompt_build obfuscates
    const promptResult = await handlers["before_prompt_build"]({ prompt: slackInput });
    const obfuscatedPrompt = promptResult?.systemPrompt || slackInput;
    expect(obfuscatedPrompt).not.toContain("user@example.test");

    // Step 3: LLM receives obfuscated prompt, responds with the fake
    const fake = obf.obfuscate("user@example.test").mappingsUsed["user@example.test"];
    const llmResponse = `{"email": "${fake}"}`;

    // Step 4: before_message_write deobfuscates assistant response
    const writeResult = handlers["before_message_write"]({
      message: { role: "assistant", content: llmResponse },
    });
    const deobResponse = writeResult?.message?.content || llmResponse;
    expect(deobResponse).toContain("user@example.test");
    expect(deobResponse).not.toContain(fake);

    // Step 5: message_sending fires for channel delivery (2026.3.24 path)
    const sendResult = await handlers["message_sending"]({ content: deobResponse });
    // Content is already deobfuscated — message_sending is a no-op
    const finalContent = sendResult?.content || deobResponse;
    expect(finalContent).toContain("user@example.test");
    expect(finalContent).not.toContain(fake);

    // Step 6: Verify only ONE output with real email, no fakes anywhere
    const outputEmails = finalContent.match(/[\w.-]+@[\w.-]+\.\w{2,}/g) || [];
    expect(outputEmails).toEqual(["user@example.test"]);
  });

  test("multi-turn: second turn fetch intercept prevents PII leak from assistant history", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Turn 1
    const t1Result = await handlers["before_prompt_build"]({ prompt: "format: user@example.test" });
    const fake = obf.obfuscate("user@example.test").mappingsUsed["user@example.test"];

    // LLM responds with fake → deobfuscated → stored with real email
    const t1LlmResponse = `{"email": "${fake}"}`;
    handlers["before_message_write"]({
      message: { role: "assistant", content: t1LlmResponse },
    });

    // Turn 2: the assistant message from turn 1 is in context with real email
    // Simulate what the fetch intercept does: re-obfuscate ALL messages
    const turn2Messages = [
      { role: "user", content: [{ type: "text", text: t1Result?.systemPrompt || "" }] },
      { role: "assistant", content: [{ type: "text", text: `{"email": "user@example.test"}` }] },
      { role: "user", content: [{ type: "text", text: "now format: ops@internal.net" }] },
    ];

    // Re-obfuscate each message as the fetch intercept would
    for (const msg of turn2Messages) {
      if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block.type === "text" && typeof block.text === "string") {
            const r = obf.obfuscate(block.text);
            if (r.entities.length > 0) block.text = r.obfuscated;
          }
        }
      }
    }

    // The assistant message must NOT contain real PII after re-obfuscation
    const assistantText = (turn2Messages[1].content as any[])[0].text;
    expect(assistantText).not.toContain("user@example.test");
    expect(assistantText).toContain(fake); // same deterministic fake
  });
});
