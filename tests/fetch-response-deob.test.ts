/**
 * Fetch response deobfuscation tests.
 *
 * Tests the per-block flushing TransformStream that deobfuscates
 * LLM SSE responses before OpenClaw processes them.
 *
 * Architecture:
 *   1. Mock LLM server sends SSE stream with fake PII
 *   2. Shroud's fetch intercept obfuscates the request (verified)
 *   3. Shroud's fetch intercept deobfuscates the response via TransformStream
 *   4. The test reads the transformed response and verifies:
 *      - No fake values in the output
 *      - Real values present
 *      - JSON structure intact
 *      - Tool use blocks preserved
 *      - Non-PII text unchanged
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { createServer, IncomingMessage, ServerResponse, Server } from "node:http";
import { Obfuscator } from "../src/obfuscator.js";
import { registerHooks } from "../src/hooks.js";
import { ShroudConfig } from "../src/types.js";

const testConfig: ShroudConfig = {
  secretKey: "fetch-response-test-key-123456",
  persistentSalt: "fetch-response-salt",
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

// ── Helpers ──────────────────────────────────────────────────

function collectBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
    req.on("end", () => resolve(body));
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface SSEEvent {
  event?: string;
  data: Record<string, unknown>;
}

function sseMessage(evt: SSEEvent): string {
  return (evt.event ? `event: ${evt.event}\n` : "") +
    `data: ${JSON.stringify(evt.data)}\n\n`;
}

function anthropicTextDelta(index: number, text: string): string {
  return sseMessage({
    event: "content_block_delta",
    data: { type: "content_block_delta", index, delta: { type: "text_delta", text } },
  });
}

function anthropicBlockStart(index: number, type: string): string {
  return sseMessage({
    event: "content_block_start",
    data: { type: "content_block_start", index, content_block: { type, text: "" } },
  });
}

function anthropicBlockStop(index: number): string {
  return sseMessage({
    event: "content_block_stop",
    data: { type: "content_block_stop", index },
  });
}

function anthropicToolDelta(index: number, json: string): string {
  return sseMessage({
    event: "content_block_delta",
    data: { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: json } },
  });
}

function anthropicMessageStart(): string {
  return sseMessage({
    event: "message_start",
    data: { type: "message_start", message: { id: "msg_test", role: "assistant", content: [] } },
  });
}

function anthropicMessageStop(): string {
  return sseMessage({ event: "message_delta", data: { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 10 } } }) +
    sseMessage({ event: "message_stop", data: { type: "message_stop" } });
}

/** Extract text_delta text values from SSE body */
function extractTextDeltas(body: string): string[] {
  const results: string[] = [];
  for (const line of body.split("\n")) {
    if (!line.startsWith("data: ")) continue;
    try {
      const json = JSON.parse(line.slice(6));
      if (json.type === "content_block_delta" && json.delta?.type === "text_delta" && json.delta.text) {
        results.push(json.delta.text);
      }
    } catch {}
  }
  return results;
}

/** Count JSON parse errors in SSE body */
function countParseErrors(body: string): number {
  let errors = 0;
  for (const line of body.split("\n")) {
    if (line.startsWith("data: ")) {
      try { JSON.parse(line.slice(6)); } catch { errors++; }
    }
  }
  return errors;
}

// ── Fresh install helper ────────────────────────────────────

function freshInstall(savedFetch: typeof globalThis.fetch) {
  globalThis.fetch = savedFetch;
  delete (globalThis as any).__shroudFetchPatched;
  delete (globalThis as any).__shroudObfuscator;
  delete (globalThis as any).__shroudDeobfuscate;
  delete (globalThis as any).__shroudStreamDeobfuscate;

  const obf = new Obfuscator(testConfig);
  const { api, handlers } = createMockApi();
  registerHooks(api, obf);
  return { obf, handlers };
}

function createMockApi() {
  const handlers: Record<string, Function> = {};
  const api = {
    on(event: string, handler: Function) { handlers[event] = handler; },
    registerTool() {},
    logger: {
      info() {},
      warn() {},
      error() {},
    },
  };
  return { api, handlers };
}

// ── Tests ───────────────────────────────────────────────────

describe("Fetch response deobfuscation — per-block flushing", () => {
  let server: Server;
  let port: number;
  let savedFetch: typeof globalThis.fetch;
  let sseBody: string;

  beforeAll(async () => {
    savedFetch = globalThis.fetch;

    const s = createServer(async (req, res) => {
      await collectBody(req);
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      res.end(sseBody);
    });
    await new Promise<void>((resolve) => {
      s.listen(0, "127.0.0.1", () => {
        port = (s.address() as any).port;
        server = s;
        resolve();
      });
    });
  });

  afterAll(async () => {
    globalThis.fetch = savedFetch;
    delete (globalThis as any).__shroudFetchPatched;
    delete (globalThis as any).__shroudObfuscator;
    delete (globalThis as any).__shroudDeobfuscate;
    await new Promise((r) => server.close(r));
  });

  beforeEach(() => {
    sseBody = "";
  });

  async function fetchLLM(obf: Obfuscator, handlers: Record<string, Function>) {
    await handlers["before_prompt_build"]({ prompt: "test", messages: [] });
    return fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: "test", max_tokens: 1024, messages: [{ role: "user", content: "test" }] }),
    });
  }

  // ═══════════════════════════════════════════════════════════
  //  BASIC DEOBFUSCATION
  // ═══════════════════════════════════════════════════════════

  test("single email: deobfuscated in response", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    const fakeEmail = "notify42@beacon.com";
    obf["_store"].put("user@example.test", fakeEmail, "email");

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, "Contact: ") +
      anthropicTextDelta(0, "noti") +
      anthropicTextDelta(0, "fy42") +
      anthropicTextDelta(0, "@bea") +
      anthropicTextDelta(0, "con.") +
      anthropicTextDelta(0, "com") +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain(fakeEmail);
    expect(body).toContain("user@example.test");
    expect(countParseErrors(body)).toBe(0);
  });

  test("multiple PII types: email + IP", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "admin1@test.com", "email");
    obf["_store"].put("10.0.1.5", "100.64.0.5", "ip_address");

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, "Email: admin1@test.com and IP: 100.64.0.5") +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("admin1@test.com");
    expect(body).not.toContain("100.64.0.5");
    expect(body).toContain("user@example.test");
    expect(body).toContain("10.0.1.5");
  });

  test("no PII: response passes through unchanged", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, "Hello! ") +
      anthropicTextDelta(0, "How can I help?") +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).toContain("Hello! ");
    expect(body).toContain("How can I help?");
    expect(countParseErrors(body)).toBe(0);
  });

  // ═══════════════════════════════════════════════════════════
  //  MULTI-BLOCK
  // ═══════════════════════════════════════════════════════════

  test("multiple text blocks: each deobfuscated independently", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("alice@corp.com", "user1@fake.com", "email");
    obf["_store"].put("bob@corp.com", "user2@fake.com", "email");

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, "First: user1@fake.com") +
      anthropicBlockStop(0) +
      anthropicBlockStart(1, "text") +
      anthropicTextDelta(1, "Second: user2@fake.com") +
      anthropicBlockStop(1) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("user1@fake.com");
    expect(body).not.toContain("user2@fake.com");
    expect(body).toContain("alice@corp.com");
    expect(body).toContain("bob@corp.com");
  });

  test("text block + tool_use block: tool use untouched", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "fake1@x.com", "email");

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, "Result: fake1@x.com") +
      anthropicBlockStop(0) +
      anthropicBlockStart(1, "tool_use") +
      anthropicToolDelta(1, '{"path":"/etc/hosts"}') +
      anthropicBlockStop(1) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("fake1@x.com");
    expect(body).toContain("user@example.test");
    expect(body).toContain("input_json_delta");
    expect(body).toContain("/etc/hosts");
  });

  // ═══════════════════════════════════════════════════════════
  //  PII SPLIT ACROSS DELTAS
  // ═══════════════════════════════════════════════════════════

  test("PII split across many small deltas (1-2 chars each)", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    const fake = "ops99@grid.net";
    obf["_store"].put("real@domain.com", fake, "email");

    // Split into 1-char chunks
    const deltas = fake.split("").map((ch) => anthropicTextDelta(0, ch));

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      deltas.join("") +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain(fake);
    expect(body).toContain("real@domain.com");
    expect(countParseErrors(body)).toBe(0);
  });

  test("PII in single large delta", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("ceo@bigcorp.com", "bot1@x.com", "email");

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, "The CEO email is bot1@x.com and they need it ASAP.") +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("bot1@x.com");
    expect(body).toContain("ceo@bigcorp.com");
  });

  // ═══════════════════════════════════════════════════════════
  //  LARGE RESPONSES
  // ═══════════════════════════════════════════════════════════

  test("large response: 500 deltas with scattered PII", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    const fake = "scan1@hub.io";
    obf["_store"].put("admin@internal.net", fake, "email");

    let events = anthropicMessageStart() + anthropicBlockStart(0, "text");
    for (let i = 0; i < 500; i++) {
      if (i % 100 === 50) {
        events += anthropicTextDelta(0, `Contact ${fake} for help. `);
      } else {
        events += anthropicTextDelta(0, "Lorem ipsum dolor sit amet. ");
      }
    }
    events += anthropicBlockStop(0) + anthropicMessageStop();
    sseBody = events;

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain(fake);
    expect(body).toContain("admin@internal.net");
    expect(countParseErrors(body)).toBe(0);

    // Count real email occurrences (should be 5: at indices 50, 150, 250, 350, 450)
    const matches = body.match(/admin@internal\.net/g) || [];
    expect(matches.length).toBe(5);
  });

  // ═══════════════════════════════════════════════════════════
  //  JSON (NON-STREAMING) RESPONSE
  // ═══════════════════════════════════════════════════════════

  test("JSON response (non-streaming): deobfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "json1@x.com", "email");

    // Use a separate server for JSON
    const jsonServer = createServer(async (req, res) => {
      await collectBody(req);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        id: "msg_1", type: "message", role: "assistant",
        content: [{ type: "text", text: "Email: json1@x.com" }],
        stop_reason: "end_turn", usage: { output_tokens: 5 },
      }));
    });
    const jsonPort = await new Promise<number>((r) => {
      jsonServer.listen(0, "127.0.0.1", () => r((jsonServer.address() as any).port));
    });

    try {
      const resp = await fetch(`http://127.0.0.1:${jsonPort}/v1/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: "test", max_tokens: 100, messages: [{ role: "user", content: "test" }] }),
      });
      const body = await resp.text();
      const json = JSON.parse(body);

      expect(json.content[0].text).toContain("user@example.test");
      expect(json.content[0].text).not.toContain("json1@x.com");
    } finally {
      await new Promise((r) => jsonServer.close(r));
    }
  });

  // ═══════════════════════════════════════════════════════════
  //  EMPTY / EDGE CASES
  // ═══════════════════════════════════════════════════════════

  test("empty text block: no crash", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();
    expect(countParseErrors(body)).toBe(0);
  });

  test("response with only tool use blocks: passes through", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "tool_use") +
      anthropicToolDelta(0, '{"query":"test"}') +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp = await fetchLLM(obf, handlers);
    const body = await resp.text();
    expect(body).toContain("input_json_delta");
    expect(body).toContain("test");
    expect(countParseErrors(body)).toBe(0);
  });

  // ═══════════════════════════════════════════════════════════
  //  MULTI-TURN: LLM generates email, user echoes it
  // ═══════════════════════════════════════════════════════════

  test("multi-turn: LLM-generated email echoed by user is obfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    // Turn 1: LLM generates a random email (no PII in store yet)
    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, "Here is a random email: sparkle99@nova.com") +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp1 = await fetchLLM(obf, handlers);
    const body1 = await resp1.text();
    // No deob needed — sparkle99@nova.com is LLM-generated, not in store
    expect(body1).toContain("sparkle99@nova.com");

    // Turn 2: User echoes it back. before_prompt_build creates a mapping.
    await handlers["before_prompt_build"]({
      prompt: "echo: sparkle99@nova.com",
      messages: [
        { role: "user", content: "give me a random email" },
        { role: "assistant", content: "Here is a random email: sparkle99@nova.com" },
      ],
    });

    // The store now has sparkle99@nova.com → some fake
    const fake = obf["_store"].allMappings().get("sparkle99@nova.com");
    expect(fake).toBeDefined();
    expect(fake).not.toBe("sparkle99@nova.com");

    // LLM responds with the fake
    sseBody = anthropicMessageStart() +
      anthropicBlockStart(0, "text") +
      anthropicTextDelta(0, fake!) +
      anthropicBlockStop(0) +
      anthropicMessageStop();

    const resp2 = await fetchLLM(obf, handlers);
    const body2 = await resp2.text();

    // The fetch response should deobfuscate the fake back to the real
    expect(body2).not.toContain(fake);
    expect(body2).toContain("sparkle99@nova.com");
  });
});

// ═══════════════════════════════════════════════════════════════
//  OPENAI FORMAT — SSE STREAMING + JSON + TOOL_CALLS
// ═══════════════════════════════════════════════════════════════

function openaiTextDelta(index: number, content: string): string {
  return sseMessage({
    data: { choices: [{ index, delta: { content }, finish_reason: null }] },
  });
}

function openaiFinish(index: number): string {
  return sseMessage({
    data: { choices: [{ index, delta: {}, finish_reason: "stop" }] },
  });
}

function openaiToolCallDelta(choiceIndex: number, toolIndex: number, args: string): string {
  return sseMessage({
    data: {
      choices: [{
        index: choiceIndex,
        delta: {
          tool_calls: [{ index: toolIndex, function: { arguments: args } }],
        },
        finish_reason: null,
      }],
    },
  });
}

function openaiToolCallStart(choiceIndex: number, toolIndex: number, id: string, name: string): string {
  return sseMessage({
    data: {
      choices: [{
        index: choiceIndex,
        delta: {
          tool_calls: [{ index: toolIndex, id, type: "function", function: { name, arguments: "" } }],
        },
        finish_reason: null,
      }],
    },
  });
}

function openaiDone(): string {
  return "data: [DONE]\n\n";
}

describe("Fetch response deobfuscation — OpenAI format", () => {
  let server: Server;
  let port: number;
  let savedFetch: typeof globalThis.fetch;
  let sseBody: string;
  let jsonMode: boolean;
  let jsonBody: string;

  beforeAll(async () => {
    savedFetch = globalThis.fetch;

    const s = createServer(async (req, res) => {
      await collectBody(req);
      if (jsonMode) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(jsonBody);
      } else {
        res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
        res.end(sseBody);
      }
    });
    await new Promise<void>((resolve) => {
      s.listen(0, "127.0.0.1", () => {
        port = (s.address() as any).port;
        server = s;
        resolve();
      });
    });
  });

  afterAll(async () => {
    globalThis.fetch = savedFetch;
    delete (globalThis as any).__shroudFetchPatched;
    delete (globalThis as any).__shroudObfuscator;
    delete (globalThis as any).__shroudDeobfuscate;
    await new Promise((r) => server.close(r));
  });

  beforeEach(() => {
    sseBody = "";
    jsonMode = false;
    jsonBody = "";
  });

  async function fetchOpenAI(obf: Obfuscator, handlers: Record<string, Function>) {
    await handlers["before_prompt_build"]({ prompt: "test", messages: [] });
    return fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "test" }] }),
    });
  }

  // ── SSE Streaming ────────────────────────────────────────

  test("OpenAI SSE: single email deobfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "proxy99@fake.com", "email");

    sseBody =
      openaiTextDelta(0, "Contact: ") +
      openaiTextDelta(0, "proxy") +
      openaiTextDelta(0, "99@fa") +
      openaiTextDelta(0, "ke.com") +
      openaiFinish(0) +
      openaiDone();

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("proxy99@fake.com");
    expect(body).toContain("user@example.test");
  });

  test("OpenAI SSE: multiple PII types", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "admin1@test.com", "email");
    obf["_store"].put("10.0.1.5", "100.64.0.5", "ip_address");

    sseBody =
      openaiTextDelta(0, "Email: admin1@test.com and IP: 100.64.0.5") +
      openaiFinish(0) +
      openaiDone();

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("admin1@test.com");
    expect(body).not.toContain("100.64.0.5");
    expect(body).toContain("user@example.test");
    expect(body).toContain("10.0.1.5");
  });

  test("OpenAI SSE: no PII passes through unchanged", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    sseBody =
      openaiTextDelta(0, "Hello, this has no PII at all.") +
      openaiFinish(0) +
      openaiDone();

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();
    expect(body).toContain("Hello, this has no PII at all.");
  });

  test("OpenAI SSE: finish_reason in separate event from content", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "split99@test.com", "email");

    sseBody =
      openaiTextDelta(0, "Email: split99@test.com") +
      openaiFinish(0) +
      openaiDone();

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("split99@test.com");
    expect(body).toContain("user@example.test");
  });

  // ── Tool Calls ──────────────────────────────────────────

  test("OpenAI SSE: tool_calls arguments deobfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "tool1@fake.com", "email");

    sseBody =
      openaiToolCallStart(0, 0, "call_abc", "send_email") +
      openaiToolCallDelta(0, 0, '{"to":"tool') +
      openaiToolCallDelta(0, 0, '1@fake.com"}') +
      openaiFinish(0) +
      openaiDone();

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("tool1@fake.com");
    expect(body).toContain("user@example.test");
  });

  test("OpenAI SSE: tool_calls with multiple tools deobfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "multi1@fake.com", "email");
    obf["_store"].put("10.0.1.5", "100.64.0.5", "ip_address");

    sseBody =
      openaiToolCallStart(0, 0, "call_1", "send_email") +
      openaiToolCallDelta(0, 0, '{"to":"multi1@fake.com"}') +
      openaiToolCallStart(0, 1, "call_2", "ping_host") +
      openaiToolCallDelta(0, 1, '{"host":"100.64.0.5"}') +
      openaiFinish(0) +
      openaiDone();

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();

    expect(body).not.toContain("multi1@fake.com");
    expect(body).not.toContain("100.64.0.5");
    expect(body).toContain("user@example.test");
    expect(body).toContain("10.0.1.5");
  });

  // ── JSON (Non-Streaming) ────────────────────────────────

  test("OpenAI JSON: content deobfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "json1@fake.com", "email");

    jsonMode = true;
    jsonBody = JSON.stringify({
      id: "chatcmpl-1",
      choices: [{
        index: 0,
        message: { role: "assistant", content: "Email: json1@fake.com" },
        finish_reason: "stop",
      }],
      usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
    });

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();
    const json = JSON.parse(body);

    expect(json.choices[0].message.content).toContain("user@example.test");
    expect(json.choices[0].message.content).not.toContain("json1@fake.com");
  });

  test("OpenAI JSON: tool_calls arguments deobfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);
    obf["_store"].put("user@example.test", "jsontc@fake.com", "email");

    jsonMode = true;
    jsonBody = JSON.stringify({
      id: "chatcmpl-2",
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content: null,
          tool_calls: [{
            id: "call_xyz",
            type: "function",
            function: { name: "send_email", arguments: '{"to":"jsontc@fake.com"}' },
          }],
        },
        finish_reason: "tool_calls",
      }],
      usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
    });

    const resp = await fetchOpenAI(obf, handlers);
    const body = await resp.text();
    const json = JSON.parse(body);

    const args = json.choices[0].message.tool_calls[0].function.arguments;
    expect(args).toContain("user@example.test");
    expect(args).not.toContain("jsontc@fake.com");
  });

  // ── Outbound Obfuscation ────────────────────────────────

  test("OpenAI outbound: tool_calls arguments obfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    // Pre-populate store with a mapping
    const result = obf.obfuscate("Contact user@example.test please");
    const fake = obf["_store"].allMappings().get("user@example.test")!;
    expect(fake).toBeDefined();

    // Set up a server that captures the request body
    let capturedBody = "";
    const captureServer = createServer(async (req, res) => {
      capturedBody = await collectBody(req);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        id: "chatcmpl-3",
        choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 },
      }));
    });
    const capturePort = await new Promise<number>((r) => {
      captureServer.listen(0, "127.0.0.1", () => r((captureServer.address() as any).port));
    });

    try {
      await handlers["before_prompt_build"]({ prompt: "test", messages: [] });
      await fetch(`http://127.0.0.1:${capturePort}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [
            { role: "user", content: "send email" },
            {
              role: "assistant",
              content: null,
              tool_calls: [{
                id: "call_abc",
                type: "function",
                function: { name: "send_email", arguments: `{"to":"user@example.test"}` },
              }],
            },
            { role: "tool", tool_call_id: "call_abc", content: "Email sent to user@example.test" },
          ],
        }),
      });

      const parsed = JSON.parse(capturedBody);
      const toolCallArgs = parsed.messages[1].tool_calls[0].function.arguments;
      const toolContent = parsed.messages[2].content;

      // tool_calls arguments should be obfuscated
      expect(toolCallArgs).not.toContain("user@example.test");
      expect(toolCallArgs).toContain(fake);

      // tool result content should also be obfuscated
      expect(toolContent).not.toContain("user@example.test");
    } finally {
      await new Promise((r) => captureServer.close(r));
    }
  });

  test("OpenAI Responses outbound: input_text blocks are obfuscated", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    const fakeIp = obf.obfuscate("192.168.1.101").mappingsUsed["192.168.1.101"];
    expect(fakeIp).toBeDefined();

    let capturedBody = "";
    const captureServer = createServer(async (req, res) => {
      capturedBody = await collectBody(req);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        id: "resp_123",
        output: [{
          id: "msg_123",
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: "ok" }],
        }],
      }));
    });
    const capturePort = await new Promise<number>((r) => {
      captureServer.listen(0, "127.0.0.1", () => r((captureServer.address() as any).port));
    });

    try {
      await handlers["before_prompt_build"]({ prompt: "test", messages: [] });
      await fetch(`http://127.0.0.1:${capturePort}/responses`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-5",
          input: [{
            type: "message",
            role: "user",
            content: [{ type: "input_text", text: "sorry my ip address is actuall 192.168.1.101" }],
          }],
        }),
      });

      const parsed = JSON.parse(capturedBody);
      const inputText = parsed.input[0].content[0].text;

      expect(inputText).not.toContain("192.168.1.101");
      expect(inputText).toContain(fakeIp);
    } finally {
      await new Promise((r) => captureServer.close(r));
    }
  });
});
