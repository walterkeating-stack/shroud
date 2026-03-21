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

describe("hooks - before_llm_send", () => {
  test("obfuscates messages and returns transformResponse", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const messages = [
      { role: "user", content: "Look up john@acme.com" },
    ];
    const result = await handlers["before_llm_send"]({ messages });
    expect(result).toBeDefined();
    expect(result.messages).toBeDefined();
    expect(result.messages[0].content).not.toContain("john@acme.com");
    expect(typeof result.transformResponse).toBe("function");
  });

  test("transformResponse deobfuscates LLM output", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate to populate the store and get fake email
    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    const messages = [{ role: "user", content: "test" }];
    const result = await handlers["before_llm_send"]({ messages });

    // Simulate LLM responding with fake value
    const deobfuscated = result.transformResponse(`The email is ${fakeEmail}`);
    expect(deobfuscated).toContain("john@acme.com");
    expect(deobfuscated).not.toContain(fakeEmail);
  });

  test("obfuscates content block arrays", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const messages = [
      {
        role: "user",
        content: [{ type: "text", text: "Contact alice@secret.org" }],
      },
    ];
    const result = await handlers["before_llm_send"]({ messages });
    expect(result.messages[0].content[0].text).not.toContain("alice@secret.org");
  });

  test("returns void when no messages", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const result = await handlers["before_llm_send"]({});
    expect(result).toBeUndefined();
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

describe("hooks - full flow with before_llm_send", () => {
  test("prompt obfuscated -> LLM sees fakes -> transformResponse deobfuscates output", async () => {
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

    // Step 2: before_llm_send obfuscates messages and provides transformResponse
    const step2 = await handlers["before_llm_send"]({
      messages: [
        { role: "user", content: `Look up ${fakeEmail}` },
      ],
    });
    expect(step2.messages[0].content).not.toContain("john@acme.com");
    expect(typeof step2.transformResponse).toBe("function");

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

    // Step 5: LLM output deobfuscated via transformResponse (auto-reply path)
    const llmOutput = `Found account for ${fakeEmail}`;
    const deobfuscated = step2.transformResponse(llmOutput);
    expect(deobfuscated).toContain("john@acme.com");
    expect(deobfuscated).not.toContain(fakeEmail);
  });
});
