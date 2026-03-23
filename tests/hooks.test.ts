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

describe("hooks - before_llm_send", () => {
  test("obfuscates messages and returns transformResponse", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    const event = {
      messages: [
        { role: "user", content: "Contact john@acme.com" },
        { role: "assistant", content: "OK" },
      ],
    };
    const result = await handlers["before_llm_send"](event);
    expect(result).toBeDefined();
    expect(result.transformResponse).toBeTypeOf("function");
    // Messages should be obfuscated
    expect(result.messages).toBeDefined();
    expect(result.messages[0].content).not.toContain("john@acme.com");
    expect(result.messages[1].content).toBe("OK"); // no PII, unchanged
  });

  test("transformResponse deobfuscates LLM output", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Obfuscate to populate store
    const obResult = obf.obfuscate("john@acme.com");
    const fakeEmail = obResult.mappingsUsed["john@acme.com"];

    const event = { messages: [{ role: "user", content: "Hi" }] };
    const result = await handlers["before_llm_send"](event);
    expect(result.transformResponse).toBeTypeOf("function");

    // Simulate LLM response containing fake value
    const transformed = result.transformResponse(`The email is ${fakeEmail}`);
    expect(transformed).toContain("john@acme.com");
    expect(transformed).not.toContain(fakeEmail);
  });

  test("returns transformResponse even when no messages obfuscated", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Pre-populate store so transformResponse has something to work with
    obf.obfuscate("john@acme.com");

    const event = { messages: [{ role: "user", content: "Hello world" }] };
    const result = await handlers["before_llm_send"](event);
    expect(result).toBeDefined();
    expect(result.transformResponse).toBeTypeOf("function");
    // messages should be undefined since nothing changed
    expect(result.messages).toBeUndefined();
  });

  test("returns void for non-array messages", async () => {
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

  test("before_llm_send transformResponse deobfuscates LLM output (>=2026.3.14 path)", async () => {
    const obf = new Obfuscator(testConfig);
    const { api, handlers } = createMockApi();
    registerHooks(api, obf);

    // Step 1: Obfuscate via prompt build
    await handlers["before_prompt_build"]({ prompt: "Look up john@acme.com" });
    const fakeEmail = obf.obfuscate("john@acme.com").mappingsUsed["john@acme.com"];

    // Step 2: before_llm_send installs transformResponse
    const llmResult = await handlers["before_llm_send"]({
      messages: [{ role: "user", content: `Find ${fakeEmail}` }],
    });
    expect(llmResult.transformResponse).toBeTypeOf("function");

    // Step 3: LLM responds with fake value — transformResponse deobfuscates
    const deobfuscated = llmResult.transformResponse(`The contact is ${fakeEmail}`);
    expect(deobfuscated).toContain("john@acme.com");
    expect(deobfuscated).not.toContain(fakeEmail);
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

describe("hooks - transport interceptor", () => {
  test("wraps WebClient.prototype.apiCall when found in require.cache", () => {
    // Simulate @slack/web-api being loaded in require.cache
    const { createRequire } = require("node:module");
    const esmRequire = createRequire(import.meta.url);

    // Create a fake WebClient class
    class FakeWebClient {
      async apiCall(method: string, options?: any) {
        return { ok: true, method, options };
      }
    }

    // Inject into require.cache under a @slack/web-api key
    const fakeModulePath = "/fake/node_modules/@slack/web-api/dist/index.js";
    esmRequire.cache[fakeModulePath] = {
      id: fakeModulePath,
      filename: fakeModulePath,
      loaded: true,
      exports: { WebClient: FakeWebClient },
    } as any;

    try {
      const obf = new Obfuscator(testConfig);
      const { api, logLines } = createMockApi();
      registerHooks(api, obf);

      expect(logLines.some((l) => l.includes("Installed Slack transport interceptor"))).toBe(true);
      expect((FakeWebClient.prototype as any).__shroudPatched).toBe(true);
    } finally {
      delete esmRequire.cache[fakeModulePath];
    }
  });

  test("deobfuscates text in chat.postMessage calls", async () => {
    const { createRequire } = require("node:module");
    const esmRequire = createRequire(import.meta.url);

    const callLog: any[] = [];
    class FakeWebClient {
      async apiCall(method: string, options?: any) {
        callLog.push({ method, text: options?.text });
        return { ok: true };
      }
    }

    const fakeModulePath = "/fake2/node_modules/@slack/web-api/dist/index.js";
    esmRequire.cache[fakeModulePath] = {
      id: fakeModulePath,
      filename: fakeModulePath,
      loaded: true,
      exports: { WebClient: FakeWebClient },
    } as any;

    try {
      const obf = new Obfuscator(testConfig);
      // First obfuscate to populate the mapping store
      const result = obf.obfuscate("Contact john@acme.com");
      const fakeEmail = result.obfuscated.match(/\S+@\S+/)![0];

      const { api } = createMockApi();
      registerHooks(api, obf);

      // Simulate a Slack API call with the fake email
      const client = new FakeWebClient();
      await client.apiCall("chat.postMessage", { channel: "C123", text: `Here is the email: ${fakeEmail}` });

      // The interceptor should have deobfuscated the text
      expect(callLog[0].text).toContain("john@acme.com");
      expect(callLog[0].text).not.toContain(fakeEmail);
    } finally {
      delete esmRequire.cache[fakeModulePath];
      delete (FakeWebClient.prototype as any).__shroudPatched;
    }
  });

  test("does not modify non-chat API calls", async () => {
    const { createRequire } = require("node:module");
    const esmRequire = createRequire(import.meta.url);

    const callLog: any[] = [];
    class FakeWebClient {
      async apiCall(method: string, options?: any) {
        callLog.push({ method, text: options?.text });
        return { ok: true };
      }
    }

    const fakeModulePath = "/fake3/node_modules/@slack/web-api/dist/index.js";
    esmRequire.cache[fakeModulePath] = {
      id: fakeModulePath,
      filename: fakeModulePath,
      loaded: true,
      exports: { WebClient: FakeWebClient },
    } as any;

    try {
      const obf = new Obfuscator(testConfig);
      const result = obf.obfuscate("Contact john@acme.com");
      const fakeEmail = result.obfuscated.match(/\S+@\S+/)![0];

      const { api } = createMockApi();
      registerHooks(api, obf);

      // Non-chat API call should pass through unchanged
      const client = new FakeWebClient();
      await client.apiCall("conversations.list", { text: fakeEmail });

      expect(callLog[0].text).toBe(fakeEmail);
    } finally {
      delete esmRequire.cache[fakeModulePath];
      delete (FakeWebClient.prototype as any).__shroudPatched;
    }
  });
});
