import { describe, test, expect } from "vitest";

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
};

/**
 * Creates a mock PluginApi that captures registered hooks
 * and allows invoking them by event name.
 */
function createMockApi() {
  const handlers: Record<string, Function> = {};
  const api = {
    on(event: string, handler: Function) {
      handlers[event] = handler;
    },
    registerTool() {},
    logger: {
      info() {},
      warn() {},
      error() {},
    },
  };
  return { api, handlers };
}

describe("hooks - before_agent_start", () => {
  test("obfuscates user prompt and returns prependContext", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { prompt: "Contact john@acme.com please" };
    const result = await handlers["before_agent_start"](event);
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
    const result = await handlers["before_agent_start"](event);
    expect(result).toBeUndefined();
  });

  test("returns nothing for empty prompt", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const result = await handlers["before_agent_start"]({ prompt: "" });
    expect(result).toBeUndefined();
  });
});

describe("hooks - before_tool_call", () => {
  test("deobfuscates tool arguments (string)", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // First obfuscate to populate the store
    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    const event = { arguments: `query for ${fakeEmail}` };
    const result = await handlers["before_tool_call"](event);
    expect(result.arguments).toContain("john@acme.com");
    expect(result.arguments).not.toContain(fakeEmail);
  });

  test("deobfuscates tool arguments (object)", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const obResult = obf.obfuscate("10.20.30.40");
    const fakeIp = obResult.mappingsUsed["10.20.30.40"];

    const event = { arguments: { host: fakeIp } };
    const result = await handlers["before_tool_call"](event);
    expect(result.arguments.host).toBe("10.20.30.40");
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
  test("prompt obfuscated -> tool call deobfuscated -> tool result re-obfuscated -> reply deobfuscated", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Step 1: User sends prompt with PII
    const step1 = await handlers["before_agent_start"]({
      prompt: "Look up john@acme.com",
    });
    expect(step1.prependContext).not.toContain("john@acme.com");

    // Get the fake email from the mapping
    const fakeEmail = obf.obfuscate("john@acme.com").mappingsUsed["john@acme.com"];

    // Step 2: Agent makes tool call with fake email
    const step2 = await handlers["before_tool_call"]({
      arguments: { email: fakeEmail },
    });
    expect(step2.arguments.email).toBe("john@acme.com"); // deobfuscated for API

    // Step 3: Tool returns result with real PII
    const step3 = handlers["tool_result_persist"]({
      message: "User john@acme.com has account #1234",
    });
    expect(step3.message).not.toContain("john@acme.com"); // re-obfuscated

    // Step 4: Agent reply contains fake value, deobfuscated for user
    const step4 = await handlers["message_sending"]({
      content: `Found account for ${fakeEmail}`,
    });
    expect(step4.content).toContain("john@acme.com");
    expect(step4.content).not.toContain(fakeEmail);
  });
});
