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
  test("obfuscates user message content (string)", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = {
      messages: [
        { role: "user", content: "Contact john@acme.com please" },
      ],
    };
    const result = await handlers["before_agent_start"](event);
    expect(result.messages[0].content).not.toContain("john@acme.com");
    expect(result.messages[0].content).toContain("@"); // fake email
  });

  test("obfuscates user message content (array blocks)", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = {
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "IP is 10.20.30.40" },
          ],
        },
      ],
    };
    const result = await handlers["before_agent_start"](event);
    expect(result.messages[0].content[0].text).not.toContain("10.20.30.40");
  });

  test("ignores non-user messages", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = {
      messages: [
        { role: "assistant", content: "john@acme.com" },
      ],
    };
    const result = await handlers["before_agent_start"](event);
    expect(result.messages[0].content).toBe("john@acme.com");
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
  test("obfuscates tool result (string content)", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = { content: "Found email alice@secret.org in logs" };
    const result = handlers["tool_result_persist"](event);
    expect(result.content).not.toContain("alice@secret.org");
  });

  test("obfuscates tool result (array blocks)", () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = {
      content: [{ type: "text", text: "IP 172.16.0.50 is active" }],
    };
    const result = handlers["tool_result_persist"](event);
    expect(result.content[0].text).not.toContain("172.16.0.50");
  });
});

describe("hooks - message_sending", () => {
  test("deobfuscates assistant reply", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate first to populate the store
    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    const event = {
      message: { content: `The contact is ${fakeEmail}` },
    };
    const result = await handlers["message_sending"](event);
    expect(result.message.content).toContain("john@acme.com");
    expect(result.message.content).not.toContain(fakeEmail);
  });

  test("deobfuscates array block content", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const obResult = obf.obfuscate("10.0.0.1");
    const fakeIp = obResult.mappingsUsed["10.0.0.1"];

    const event = {
      message: {
        content: [{ type: "text", text: `Server: ${fakeIp}` }],
      },
    };
    const result = await handlers["message_sending"](event);
    expect(result.message.content[0].text).toContain("10.0.0.1");
  });
});

describe("hooks - full flow", () => {
  test("user PII -> obfuscated for agent -> tool deobfuscated -> result re-obfuscated -> reply deobfuscated", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Step 1: User sends message with PII
    const userEvent = {
      messages: [
        { role: "user", content: "Look up john@acme.com" },
      ],
    };
    const step1 = await handlers["before_agent_start"](userEvent);
    const obfuscatedMessage = step1.messages[0].content;
    expect(obfuscatedMessage).not.toContain("john@acme.com");

    // Extract the fake email from the obfuscated message
    const fakeEmail = obf.obfuscate("john@acme.com").mappingsUsed["john@acme.com"];

    // Step 2: Agent makes tool call with fake email in args
    const toolCallEvent = { arguments: { email: fakeEmail } };
    const step2 = await handlers["before_tool_call"](toolCallEvent);
    expect(step2.arguments.email).toBe("john@acme.com"); // Deobfuscated

    // Step 3: Tool returns result with real PII
    const toolResultEvent = {
      content: "User john@acme.com has account #1234",
    };
    const step3 = handlers["tool_result_persist"](toolResultEvent);
    expect(step3.content).not.toContain("john@acme.com"); // Re-obfuscated

    // Step 4: Assistant sends reply with fake value
    const replyEvent = {
      message: { content: `Found account for ${fakeEmail}` },
    };
    const step4 = await handlers["message_sending"](replyEvent);
    expect(step4.message.content).toContain("john@acme.com"); // Deobfuscated
    expect(step4.message.content).not.toContain(fakeEmail);
  });
});
