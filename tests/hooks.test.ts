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
  test("obfuscates user prompt and returns prependContext", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { prompt: "Contact john@acme.com please" };
    const result = await handlers["before_prompt_build"](event);
    expect(result).toBeDefined();
    expect(result.prependContext).toBeDefined();
    expect(result.prependContext).not.toContain("john@acme.com");
    expect(result.prependContext).toContain("@"); // fake email present
    expect(result.prependContext).toContain("SHROUD");
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
        role: "assistant",
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
    expect(step1.prependContext).not.toContain("john@acme.com");

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
