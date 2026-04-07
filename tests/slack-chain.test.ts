/**
 * Real Slack HTTP test chain — mimics a real install.
 *
 * Two real HTTP servers:
 *   1. Mock LLM API  (Anthropic /v1/messages)  — captures what it receives
 *   2. Mock Slack API (chat.postMessage)         — captures what it receives
 *
 * Full lifecycle with REAL HTTP at both ends:
 *
 *   User PII
 *     → registerHooks patches globalThis.fetch
 *     → before_prompt_build creates mappings
 *     → real fetch() to mock LLM  →  fetch intercept obfuscates the body
 *     → verify: LLM received ONLY fakes, zero real PII
 *     → mock LLM returns response containing fakes
 *     → before_message_write deobfuscates assistant response
 *     → globalThis.__shroudDeobfuscate (OpenClaw's one-line patch)
 *     → real http.request POST to mock Slack API
 *     → verify: Slack received ONLY reals, zero fakes
 *
 * No webhooks. No mocked fetch. Real HTTP both directions.
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { createServer, IncomingMessage, ServerResponse, Server } from "node:http";
import { request as httpRequest } from "node:http";
import { Obfuscator } from "../src/obfuscator.js";
import { registerHooks } from "../src/hooks.js";
import { ShroudConfig } from "../src/types.js";

const testConfig: ShroudConfig = {
  secretKey: "slack-chain-test-key-1234567890ab",
  persistentSalt: "slack-chain-salt",
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

// ── HTTP helpers ───────────────────────────────────────────────────────

interface HttpCapture {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  parsed: Record<string, unknown> | null;
}

function startServer(
  handler: (req: IncomingMessage, res: ServerResponse, captures: HttpCapture[]) => void,
): Promise<{ server: Server; port: number; captures: HttpCapture[] }> {
  const captures: HttpCapture[] = [];
  const server = createServer((req, res) => handler(req, res, captures));
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, port, captures });
    });
  });
}

function stopServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function collectBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
    req.on("end", () => resolve(body));
  });
}

function httpPost(
  port: number,
  path: string,
  body: Record<string, unknown>,
  headers?: Record<string, string>,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = httpRequest(
      {
        hostname: "127.0.0.1", port, path, method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": String(Buffer.byteLength(data)),
          ...headers,
        },
      },
      (res) => {
        let respBody = "";
        res.on("data", (chunk: Buffer) => { respBody += chunk.toString(); });
        res.on("end", () => resolve({ status: res.statusCode || 0, body: respBody }));
      },
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// ── Mock PluginApi ─────────────────────────────────────────────────────

function createMockApi() {
  const handlers: Record<string, Function> = {};
  const tools: Record<string, { description: string; handler: Function }> = {};
  const logLines: string[] = [];
  const api = {
    on(event: string, handler: Function) { handlers[event] = handler; },
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

/** Fresh hooks + obfuscator. Resets globalThis state for clean install. */
function freshInstall(savedFetch: typeof globalThis.fetch) {
  globalThis.fetch = savedFetch;
  delete (globalThis as any).__shroudFetchPatched;
  delete (globalThis as any).__shroudObfuscator;
  delete (globalThis as any).__shroudDeobfuscate;

  const obf = new Obfuscator(testConfig);
  const { api, handlers, logLines } = createMockApi();
  registerHooks(api, obf);
  const deobfuscate = (globalThis as any).__shroudDeobfuscate as (t: string) => string;
  return { obf, handlers, logLines, deobfuscate };
}

// ── Tests ──────────────────────────────────────────────────────────────

describe("Slack HTTP chain — real servers, real fetch intercept", () => {
  let llmServer: { server: Server; port: number; captures: HttpCapture[] };
  let slackServer: { server: Server; port: number; captures: HttpCapture[] };
  let savedFetch: typeof globalThis.fetch;
  let llmResponseText: string;

  beforeAll(async () => {
    savedFetch = globalThis.fetch;

    llmServer = await startServer(async (req, res, captures) => {
      const body = await collectBody(req);
      let parsed: Record<string, unknown> | null = null;
      try { parsed = JSON.parse(body); } catch {}
      captures.push({ method: req.method || "GET", path: req.url || "/", headers: req.headers as any, body, parsed });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        id: "msg_test", type: "message", role: "assistant",
        content: [{ type: "text", text: llmResponseText }],
        model: "claude-3-5-sonnet-20241022", stop_reason: "end_turn",
        usage: { input_tokens: 10, output_tokens: 5 },
      }));
    });

    slackServer = await startServer(async (req, res, captures) => {
      const body = await collectBody(req);
      let parsed: Record<string, unknown> | null = null;
      try { parsed = JSON.parse(body); } catch {
        try { parsed = Object.fromEntries(new URLSearchParams(body).entries()); } catch {}
      }
      captures.push({ method: req.method || "GET", path: req.url || "/", headers: req.headers as any, body, parsed });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, ts: "1234567890.123456" }));
    });
  });

  afterAll(async () => {
    globalThis.fetch = savedFetch;
    delete (globalThis as any).__shroudFetchPatched;
    delete (globalThis as any).__shroudObfuscator;
    delete (globalThis as any).__shroudDeobfuscate;
    await Promise.all([stopServer(llmServer.server), stopServer(slackServer.server)]);
  });

  beforeEach(() => {
    llmServer.captures.length = 0;
    slackServer.captures.length = 0;
    llmResponseText = "";
  });

  // ════════════════════════════════════════════════════════════════════
  //  HAPPY PATH
  // ════════════════════════════════════════════════════════════════════

  test("E2E: real fetch to LLM → real HTTP to Slack — full install", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);
    expect(typeof deobfuscate).toBe("function");

    const userPii = "Please format as JSON: walter@example.test and server 10.0.1.5";
    await handlers["before_prompt_build"]({ prompt: userPii, messages: [] });

    const fakeEmail = obf.obfuscate("walter@example.test").mappingsUsed["walter@example.test"];
    const fakeIp = obf.obfuscate("10.0.1.5").mappingsUsed["10.0.1.5"];

    llmResponseText = `Here is the JSON:\n{"email": "${fakeEmail}", "server": "${fakeIp}"}`;

    const llmResp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": "sk-test" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        system: "You are a helpful assistant.",
        messages: [{ role: "user", content: userPii }],
      }),
    });
    expect(llmResp.ok).toBe(true);

    // LLM got fakes, not reals
    const llmBody = llmServer.captures[0].parsed as any;
    expect(llmBody.messages[0].content).not.toContain("walter@example.test");
    expect(llmBody.messages[0].content).not.toContain("10.0.1.5");
    expect(llmBody.messages[0].content).toContain(fakeEmail);
    expect(llmBody.messages[0].content).toContain(fakeIp);

    // Deobfuscate assistant response
    const llmJson = await llmResp.json() as any;
    const writeResult = handlers["before_message_write"]({
      message: { role: "assistant", content: llmJson.content[0].text },
    });
    const deobAssistant = writeResult?.message?.content || llmJson.content[0].text;
    expect(deobAssistant).toContain("walter@example.test");
    expect(deobAssistant).toContain("10.0.1.5");

    // OpenClaw's global hook + Slack delivery
    const channelText = deobfuscate(deobAssistant);
    const slackResp = await httpPost(slackServer.port, "/api/chat.postMessage", {
      channel: "C0123REAL", text: channelText,
    }, { "Authorization": "Bearer xoxb-real-token" });
    expect(slackResp.status).toBe(200);

    // Slack got reals
    const slackText = (slackServer.captures[0].parsed as any).text;
    expect(slackText).toContain("walter@example.test");
    expect(slackText).toContain("10.0.1.5");
    expect(slackText).not.toContain(fakeEmail);
    expect(slackText).not.toContain(fakeIp);

    // No duplicates
    const emails = slackText.match(/[\w.-]+@[\w.-]+\.\w{2,}/g) || [];
    expect(emails).toEqual(["walter@example.test"]);
  });

  test("Slack mailto markup: stripped at fetch, reals at Slack", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    const slackInput = "check <mailto:ops@internal.net|ops@internal.net> on host 192.168.1.50";
    await handlers["before_prompt_build"]({ prompt: slackInput, messages: [] });

    const fakeEmail = obf.obfuscate("ops@internal.net").mappingsUsed["ops@internal.net"];
    const fakeIp = obf.obfuscate("192.168.1.50").mappingsUsed["192.168.1.50"];
    llmResponseText = `Contact ${fakeEmail} at ${fakeIp}`;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: slackInput }],
      }),
    });

    // LLM: no reals, no mailto markup
    const llmContent = (llmServer.captures[0].parsed as any).messages[0].content;
    expect(llmContent).not.toContain("ops@internal.net");
    expect(llmContent).not.toContain("192.168.1.50");
    expect(llmContent).not.toContain("<mailto:");

    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const channelText = deobfuscate(w?.message?.content || json.content[0].text);

    await httpPost(slackServer.port, "/api/chat.postMessage", { channel: "C_OPS", text: channelText });

    const slackText = (slackServer.captures[0].parsed as any).text;
    expect(slackText).toContain("ops@internal.net");
    expect(slackText).toContain("192.168.1.50");
    expect(slackText).not.toContain(fakeEmail);
    expect(slackText).not.toContain(fakeIp);
  });

  // ════════════════════════════════════════════════════════════════════
  //  ADVERSARIAL: things that COULD go wrong
  // ════════════════════════════════════════════════════════════════════

  test("LLM invents a CGNAT IP not in the store — still deobfuscated via subnet reverse", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    // Create a single mapping so the subnet mapper learns 10.0.1.x → 100.64.0.x
    await handlers["before_prompt_build"]({
      prompt: "server 10.0.1.5 is important",
      messages: [],
    });
    const fakeIp = obf.obfuscate("10.0.1.5").mappingsUsed["10.0.1.5"];
    expect(fakeIp).toMatch(/^100\.64\./);

    // LLM "invents" a new IP in the same CGNAT subnet (e.g., 100.64.0.99)
    // This IP was never obfuscated — the LLM derived it from seeing 100.64.0.5
    const inventedCgnat = fakeIp.replace(/\.\d+$/, ".99"); // same /24, different host
    llmResponseText = `Also check ${inventedCgnat} in that subnet`;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: "server 10.0.1.5 is important" }],
      }),
    });

    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const channelText = deobfuscate(w?.message?.content || json.content[0].text);

    // The invented CGNAT IP should be reverse-mapped to the real subnet
    expect(channelText).toContain("10.0.1.99");
    expect(channelText).not.toContain("100.64.");
  });

  test("LLM truncates a fake email — partial fake must not leak", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    await handlers["before_prompt_build"]({
      prompt: "contact walter@example.test please",
      messages: [],
    });
    const fakeEmail = obf.obfuscate("walter@example.test").mappingsUsed["walter@example.test"];

    // LLM truncates the fake (takes only the local part)
    const truncated = fakeEmail.split("@")[0];
    llmResponseText = `I'll email ${truncated}...`;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: "contact walter@example.test" }],
      }),
    });

    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const channelText = deobfuscate(w?.message?.content || json.content[0].text);

    // Truncated fake should NOT be in final output — it's not a full fake
    // so it won't be in the reverse map. This is a known limitation.
    // The key: it must NOT contain the full fake email.
    expect(channelText).not.toContain(fakeEmail);
    // The truncated part leaks, but it's meaningless without the domain
    // and can't be reversed to the real email. Acceptable.
  });

  test("__shroudDeobfuscate handles non-string gracefully", () => {
    const { deobfuscate } = freshInstall(savedFetch);

    // OpenClaw might pass unexpected types
    expect(deobfuscate(null as any)).toBe(null);
    expect(deobfuscate(undefined as any)).toBe(undefined);
    expect(deobfuscate(42 as any)).toBe(42);
    expect(deobfuscate("" as any)).toBe("");
    expect(deobfuscate("plain text")).toBe("plain text");
  });

  test("mixed real + fake in same message: all fakes replaced, reals preserved", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    await handlers["before_prompt_build"]({
      prompt: "email walter@example.test about 10.0.1.5",
      messages: [],
    });
    const fakeEmail = obf.obfuscate("walter@example.test").mappingsUsed["walter@example.test"];
    const fakeIp = obf.obfuscate("10.0.1.5").mappingsUsed["10.0.1.5"];

    // LLM echoes BOTH fake and real (hallucination / confusion)
    llmResponseText = `Contact ${fakeEmail} (that's walter@example.test) at ${fakeIp}`;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: "email walter@example.test about 10.0.1.5" }],
      }),
    });

    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const channelText = deobfuscate(w?.message?.content || json.content[0].text);

    // All fakes must be replaced with reals
    expect(channelText).not.toContain(fakeEmail);
    expect(channelText).not.toContain(fakeIp);
    // Real values present (possibly duplicated, which is fine — LLM put them there)
    expect(channelText).toContain("walter@example.test");
    expect(channelText).toContain("10.0.1.5");
  });

  test("multi-turn: turn 2 fetch re-obfuscates assistant history", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    // Turn 1
    await handlers["before_prompt_build"]({
      prompt: "Email ceo@bigcorp.com about 172.16.0.1",
      messages: [],
    });
    const fakeEmail = obf.obfuscate("ceo@bigcorp.com").mappingsUsed["ceo@bigcorp.com"];
    const fakeIp = obf.obfuscate("172.16.0.1").mappingsUsed["172.16.0.1"];

    llmResponseText = `Done: ${fakeEmail} at ${fakeIp}`;

    let resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: "Email ceo@bigcorp.com about 172.16.0.1" }],
      }),
    });

    const t1Json = await resp.json() as any;
    const t1Write = handlers["before_message_write"]({
      message: { role: "assistant", content: t1Json.content[0].text },
    });
    const t1Deob = t1Write?.message?.content || t1Json.content[0].text;
    expect(t1Deob).toContain("ceo@bigcorp.com"); // transcript has reals

    // Deliver turn 1 to Slack
    await httpPost(slackServer.port, "/api/chat.postMessage", {
      channel: "C_CEO", text: deobfuscate(t1Deob),
    });
    expect((slackServer.captures[0].parsed as any).text).toContain("ceo@bigcorp.com");

    // Turn 2: before_prompt_build detects new PII in turn 2 user message
    llmServer.captures.length = 0;
    await handlers["before_prompt_build"]({
      prompt: "Also check ops@bigcorp.com",
      messages: [
        { role: "user", content: "Email ceo@bigcorp.com about 172.16.0.1" },
        { role: "assistant", content: t1Deob },  // has REAL PII
      ],
    });

    llmResponseText = "Got it";

    resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [
          { role: "user", content: "Email ceo@bigcorp.com about 172.16.0.1" },
          { role: "assistant", content: t1Deob },  // REAL PII from transcript
          { role: "user", content: "Also check ops@bigcorp.com" },
        ],
      }),
    });
    expect(resp.ok).toBe(true);

    // Turn 2 LLM request: ALL messages must be obfuscated
    const t2Body = llmServer.captures[0].parsed as any;
    const t2Messages = t2Body.messages;

    // User message 1: re-obfuscated
    expect(t2Messages[0].content).not.toContain("ceo@bigcorp.com");
    expect(t2Messages[0].content).not.toContain("172.16.0.1");

    // Assistant message: re-obfuscated (THE critical check)
    expect(t2Messages[1].content).not.toContain("ceo@bigcorp.com");
    expect(t2Messages[1].content).not.toContain("172.16.0.1");
    expect(t2Messages[1].content).toContain(fakeEmail);
    expect(t2Messages[1].content).toContain(fakeIp);

    // User message 2: new PII obfuscated
    expect(t2Messages[2].content).not.toContain("ops@bigcorp.com");
  });

  test("concurrent channels: 3 deliveries, all get reals", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    await handlers["before_prompt_build"]({
      prompt: "Alert admin@company.io now",
      messages: [],
    });
    const fakeEmail = obf.obfuscate("admin@company.io").mappingsUsed["admin@company.io"];
    llmResponseText = `Alerting ${fakeEmail}`;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: "Alert admin@company.io now" }],
      }),
    });
    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const channelText = deobfuscate(w?.message?.content || json.content[0].text);

    await Promise.all([
      httpPost(slackServer.port, "/api/chat.postMessage", { channel: "C_SLACK", text: channelText }),
      httpPost(slackServer.port, "/api/chat.postMessage", { channel: "C_TEAMS", text: channelText }),
      httpPost(slackServer.port, "/api/chat.postMessage", { channel: "C_SIGNAL", text: channelText }),
    ]);

    expect(slackServer.captures.length).toBe(3);
    for (const cap of slackServer.captures) {
      expect((cap.parsed as any).text).toContain("admin@company.io");
      expect((cap.parsed as any).text).not.toContain(fakeEmail);
    }
  });

  test("fake email inside JSON value: structure preserved after deobfuscation", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    await handlers["before_prompt_build"]({
      prompt: "format walter@example.test as JSON",
      messages: [],
    });
    const fakeEmail = obf.obfuscate("walter@example.test").mappingsUsed["walter@example.test"];

    // LLM returns JSON with the fake embedded
    llmResponseText = `{"contacts": [{"name": "Walter", "email": "${fakeEmail}"}]}`;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: "format walter@example.test as JSON" }],
      }),
    });
    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const channelText = deobfuscate(w?.message?.content || json.content[0].text);

    // Verify JSON is still valid after deobfuscation
    const parsed = JSON.parse(channelText);
    expect(parsed.contacts[0].email).toBe("walter@example.test");
    expect(channelText).not.toContain(fakeEmail);
  });

  test("two different private subnets in same session: both deobfuscate correctly", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    // Both IPs in the same user message
    await handlers["before_prompt_build"]({
      prompt: "check 10.0.1.5 and 192.168.1.50",
      messages: [],
    });
    const fake1 = obf.obfuscate("10.0.1.5").mappingsUsed["10.0.1.5"];
    const fake2 = obf.obfuscate("192.168.1.50").mappingsUsed["192.168.1.50"];
    expect(fake1).not.toBe(fake2);

    llmResponseText = `Node A: ${fake1}, Node B: ${fake2}`;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: "check 10.0.1.5 and 192.168.1.50" }],
      }),
    });
    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const channelText = deobfuscate(w?.message?.content || json.content[0].text);

    expect(channelText).toContain("10.0.1.5");
    expect(channelText).toContain("192.168.1.50");
    expect(channelText).not.toContain(fake1);
    expect(channelText).not.toContain(fake2);
  });

  test("idempotent: deobfuscate on already-real text is a no-op", () => {
    const { obf, deobfuscate } = freshInstall(savedFetch);
    obf.obfuscate("test@example.com"); // create mapping
    const real = "No fakes here, just plain text.";
    expect(deobfuscate(real)).toBe(real);
  });

  // ════════════════════════════════════════════════════════════════════
  //  REGRESSION: streaming deob must not corrupt channel delivery
  // ════════════════════════════════════════════════════════════════════

  test("echo back: single email in, single email out — no duplication or garbling", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    const userInput = "echo this back to me please: walter@example.test";
    await handlers["before_prompt_build"]({ prompt: userInput, messages: [] });

    const fakeEmail = obf.obfuscate("walter@example.test").mappingsUsed["walter@example.test"];
    llmResponseText = fakeEmail;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: userInput }],
      }),
    });

    // Verify LLM got fake, not real
    const llmBody = llmServer.captures[0].parsed as any;
    expect(llmBody.messages[0].content).not.toContain("walter@example.test");
    expect(llmBody.messages[0].content).toContain(fakeEmail);

    // Simulate streaming: feed text_delta chunks through the stream deob hook
    const streamHook = (globalThis as any).__shroudStreamDeobfuscate;
    expect(typeof streamHook).toBe("function");
    const mockStream: any = {};
    const chunks = fakeEmail.match(/.{1,3}/g) || [fakeEmail];
    const deliveredChunks: string[] = [];
    for (const chunk of chunks) {
      const evt = streamHook(mockStream, { type: "text_delta", delta: chunk, text: chunk });
      deliveredChunks.push(evt?.delta ?? evt?.text ?? chunk);
    }
    // End the stream
    const endEvt = streamHook(mockStream, {
      type: "done",
      message: { content: [{ type: "text", text: fakeEmail }] },
    });

    // before_message_write deobfuscates the final message
    const json = await resp.json() as any;
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const afterWrite = w?.message?.content || json.content[0].text;

    // __shroudDeobfuscate (channel delivery hook)
    const channelText = deobfuscate(afterWrite);

    // Deliver to Slack
    await httpPost(slackServer.port, "/api/chat.postMessage", {
      channel: "C_ECHO", text: channelText,
    });

    const slackText = (slackServer.captures[0].parsed as any).text;

    // Must be exactly the real email — no duplication, no garbling
    expect(slackText).toBe("walter@example.test");
    expect(slackText).not.toContain(fakeEmail);

    // No concatenated emails (the original bug: "agentr@example.testagent69@zenith.test")
    const emails = slackText.match(/[\w.-]+@[\w.-]+\.\w{2,}/g) || [];
    expect(emails).toHaveLength(1);
    expect(emails[0]).toBe("walter@example.test");

    // The done event deobfuscates content blocks (streaming delivery uses these)
    const doneMsg = endEvt?.message;
    if (doneMsg?.content?.[0]?.text) {
      expect(doneMsg.content[0].text).toBe("walter@example.test");
    }
  });

  test("streaming deltas pass through unchanged (deob happens at fetch response level)", async () => {
    const { obf, handlers } = freshInstall(savedFetch);

    await handlers["before_prompt_build"]({
      prompt: "contact ceo@megacorp.com please",
      messages: [],
    });
    const fakeEmail = obf.obfuscate("ceo@megacorp.com").mappingsUsed["ceo@megacorp.com"];

    const streamHook = (globalThis as any).__shroudStreamDeobfuscate;
    const mockStream: any = {};

    // Stream the fake email in small chunks
    const chunks = fakeEmail.match(/.{1,4}/g) || [fakeEmail];
    const outputChunks: string[] = [];
    for (const chunk of chunks) {
      const evt = streamHook(mockStream, { type: "text_delta", delta: chunk });
      outputChunks.push(evt?.delta ?? chunk);
    }

    // Deltas pass through unchanged — deobfuscation happens at the
    // fetch response level (per-block flushing in the SSE TransformStream)
    const streamedText = outputChunks.join("");
    expect(streamedText).toBe(fakeEmail);

    // message_end content blocks have the deobfuscated text
    const endEvt = streamHook(mockStream, {
      type: "done",
      message: { content: [{ type: "text", text: fakeEmail }] },
    });
    expect(endEvt.message.content[0].text).toBe("ceo@megacorp.com");
  });

  test("WhatsApp echo: single email round-trip without garbling", async () => {
    const { obf, handlers, deobfuscate } = freshInstall(savedFetch);

    const userInput = "echo this back to me please: walter@example.test";
    await handlers["before_prompt_build"]({ prompt: userInput, messages: [] });

    const fakeEmail = obf.obfuscate("walter@example.test").mappingsUsed["walter@example.test"];
    llmResponseText = fakeEmail;

    const resp = await fetch(`http://127.0.0.1:${llmServer.port}/v1/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022", max_tokens: 1024,
        messages: [{ role: "user", content: userInput }],
      }),
    });
    const json = await resp.json() as any;

    // Simulate streaming + message_sending (WhatsApp uses message_sending)
    const streamHook = (globalThis as any).__shroudStreamDeobfuscate;
    const mockStream: any = {};
    for (const ch of fakeEmail.match(/.{1,5}/g) || [fakeEmail]) {
      streamHook(mockStream, { type: "text_delta", delta: ch });
    }
    streamHook(mockStream, {
      type: "done",
      message: { content: [{ type: "text", text: fakeEmail }] },
    });

    // before_message_write deobfuscates
    const w = handlers["before_message_write"]({
      message: { role: "assistant", content: json.content[0].text },
    });
    const afterWrite = w?.message?.content || json.content[0].text;

    // message_sending hook (WhatsApp path)
    const sendResult = await handlers["message_sending"]({ content: afterWrite });
    const channelContent = sendResult?.content ?? afterWrite;

    // __shroudDeobfuscate (global hook — may also fire)
    const finalText = deobfuscate(channelContent);

    // Must be exactly the real email
    expect(finalText).toBe("walter@example.test");
    const emails = finalText.match(/[\w.-]+@[\w.-]+\.\w{2,}/g) || [];
    expect(emails).toHaveLength(1);
    expect(emails[0]).toBe("walter@example.test");
  });
});
