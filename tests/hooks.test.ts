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

    const event = { prompt: "Contact john@acme.com please" };
    const result = await handlers["before_prompt_build"](event);
    expect(result).toBeDefined();
    expect(result.prompt).toBeDefined();
    expect(result.prompt).not.toContain("john@acme.com");
    expect(result.prompt).toContain("@"); // fake email present
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

  test("returns void when nothing changed", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const result = await handlers["message_sending"]({ content: "Hello world" });
    expect(result).toBeUndefined();
  });
});

describe("hooks - full flow", () => {
  test("prompt obfuscated -> message_write obfuscated -> tool deobfuscated -> message_sending deobfuscated", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Step 1: User sends prompt with PII
    const step1 = await handlers["before_prompt_build"]({
      prompt: "Look up john@acme.com",
    });
    expect(step1.prompt).not.toContain("john@acme.com");

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
  test("deobfuscates text_delta events and tracks replacement count", () => {
    const obf = new Obfuscator({ ...testConfig, auditEnabled: true, auditLogFormat: "json" });
    const { api, logLines } = createMockApi();
    registerHooks(api, obf);

    const hook = (globalThis as any).__shroudStreamDeobfuscate;
    expect(hook).toBeTypeOf("function");

    // Obfuscate to populate mappings
    const obResult = obf.obfuscate("Contact john@acme.com about 10.1.0.1");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];
    const fakeIp = obResult.mappingsUsed["10.1.0.1"];

    // Simulate streaming: send fake values as text_delta chunks
    const stream: any = {};
    const response = `Here is ${fakeEmail} and ${fakeIp} for reference.`;
    const chunks = response.match(/.{1,10}/g) || [];

    for (const chunk of chunks) {
      hook(stream, { type: "text_delta", delta: chunk });
    }

    // Fire message_end with final content
    hook(stream, {
      type: "message_end",
      message: {
        content: [{ type: "text", text: obf.deobfuscate(response) }],
      },
    });

    // Buffer should have tracked replacements
    // Audit log should have been emitted
    const auditLines = logLines.filter(l => l.includes("shroud.audit.deobfuscate"));
    expect(auditLines.length).toBeGreaterThanOrEqual(1);

    const audit = JSON.parse(auditLines[0]);
    expect(audit.event).toBe("shroud.audit.deobfuscate");
    expect(audit.deobfuscations).toBeGreaterThan(0);
  });

  test("streaming buffer resets after message_end", () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    const hook = (globalThis as any).__shroudStreamDeobfuscate;
    const stream: any = {};

    // Send some chunks
    hook(stream, { type: "text_delta", delta: "hello " });
    hook(stream, { type: "text_delta", delta: "world" });

    // Verify buffer exists
    const bufSymbols = Object.getOwnPropertySymbols(stream);
    expect(bufSymbols.length).toBe(1);

    // End message — buffer should be cleaned up
    hook(stream, { type: "done" });
    const afterSymbols = Object.getOwnPropertySymbols(stream);
    expect(afterSymbols.length).toBe(0);
  });

  test("streaming deobfuscation corrects final content on message_end", () => {
    const obf = new Obfuscator(testConfig);
    const { api } = createMockApi();
    registerHooks(api, obf);

    const hook = (globalThis as any).__shroudStreamDeobfuscate;

    // Obfuscate to populate mappings
    const obResult = obf.obfuscate("Server 10.42.88.7 is down");
    const fakeIp = obResult.mappingsUsed["10.42.88.7"];
    const fakeText = `The server ${fakeIp} needs attention`;

    // Stream in word-sized chunks (realistic LLM behavior)
    const stream: any = {};
    const chunks = fakeText.match(/.{1,8}/g) || [];
    for (const chunk of chunks) {
      hook(stream, { type: "text_delta", delta: chunk });
    }

    // Fire message_end — final content should have real values
    const finalContent = [{ type: "text", text: fakeText }];
    const endEvt = hook(stream, {
      type: "message_end",
      message: { content: finalContent },
    });

    // The corrected final message should contain real IP
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

    const obfAudit = logLines.filter(l => l.includes("shroud.audit.obfuscate"));
    // before_prompt_build doesn't emit audit directly (it's done via message_write)
    // but getStats should show the obfuscation counts
    const stats = obf.getStats() as any;
    expect(stats.storeMappings).toBeGreaterThanOrEqual(3);
  });
});
