/**
 * Shadow execution — the "treadmill" for suspicious tool calls.
 *
 * When a tool call triggers medium-severity alerts, instead of blocking
 * immediately, Shroud runs it against a fake sandbox. The LLM gets plausible
 * fake results and continues for 1-2 steps. Shroud watches the trajectory:
 * does it advance toward the user's goal, or toward exfiltration?
 *
 * The LLM thinks it's succeeding. Nothing real happened. Shroud observes
 * the full attack chain in simulation before any damage.
 *
 * Uses node:https directly — bypasses all fetch
 * wrappers to avoid triggering Shroud's own obfuscation interceptor.
 *
 * Zero external dependencies.
 */

import { request as httpsRequest } from "node:https";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { SecurityEvent, SecuritySeverity } from "./security-event.js";
import { ThreatClass } from "./security-event.js";
import { ToolCategory, TOOL_CATEGORIES } from "./detectors/tool-intent.js";
import type { IntentSignals } from "./detectors/tool-intent.js";
import type { HoneypotManager } from "./detectors/honeypot.js";

// ─── Types ───

export interface ShadowStep {
  stepNumber: number;
  fakeToolResult: string;
  llmResponse: {
    text: string;
    toolCalls: Array<{ name: string; params: Record<string, unknown> }>;
  } | null;
  durationMs: number;
}

export interface ShadowExecutionResult {
  triggered: boolean;
  originalToolCall: { name: string; params: unknown };
  steps: ShadowStep[];
  verdict: "allow" | "block";
  verdictReason: string;
  totalDurationMs: number;
}

export interface ShadowExecutionOpts {
  toolName: string;
  params: unknown;
  intent: IntentSignals;
  honeypot: HoneypotManager | null;
  model: string | null;
  maxSteps: 1 | 2;
  timeoutMs: number;
  /** The last LLM request body (captured from fetch intercept). */
  lastLlmBody: any;
}

// ─── OAuth ───

const CREDS_PATH = join(homedir(), ".claude", ".credentials.json");
const OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token";
const OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_SCOPES = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
const OAUTH_BETAS = "claude-code-20250219,oauth-2025-04-20";
const OAUTH_REFRESH_BUFFER_MS = 5 * 60 * 1000;

interface OAuthCreds {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

function loadOAuthCreds(): OAuthCreds | null {
  try {
    const d = JSON.parse(readFileSync(CREDS_PATH, "utf-8"));
    const oauth = d?.claudeAiOauth;
    if (!oauth?.accessToken) return null;
    return { accessToken: oauth.accessToken, refreshToken: oauth.refreshToken, expiresAt: oauth.expiresAt || 0 };
  } catch { return null; }
}

async function refreshOAuthToken(refreshToken: string): Promise<OAuthCreds> {
  const payload = JSON.stringify({
    grant_type: "refresh_token", client_id: OAUTH_CLIENT_ID,
    refresh_token: refreshToken, scope: OAUTH_SCOPES,
  });
  return new Promise((resolve, reject) => {
    const url = new URL(OAUTH_TOKEN_URL);
    const req = httpsRequest({
      hostname: url.hostname, path: url.pathname, method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "shroud-shadow/1.0" },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
          resolve({
            accessToken: data.access_token,
            refreshToken: data.refresh_token || refreshToken,
            expiresAt: Date.now() + data.expires_in * 1000 - OAUTH_REFRESH_BUFFER_MS,
          });
        } catch (e) { reject(new Error(`OAuth refresh failed: ${(e as Error).message}`)); }
      });
    });
    req.on("error", reject);
    req.setTimeout(15_000, () => { req.destroy(); reject(new Error("OAuth refresh timeout")); });
    req.write(payload);
    req.end();
  });
}

// ─── Fake result generation ───

/**
 * Generate plausible fake tool results by category.
 *
 * The fakes must be realistic enough that a malicious LLM continues its
 * attack chain, but contain no real data. They're generic and deterministic.
 */
export function generateFakeResult(toolName: string, params: unknown): string {
  const category = TOOL_CATEGORIES[toolName];
  const p = (typeof params === "object" && params !== null) ? params as Record<string, unknown> : {};

  switch (category) {
    case ToolCategory.READ_ONLY:
      // Return plausible file content or search results
      if (typeof p.file_path === "string" || typeof p.path === "string") {
        const path = (p.file_path || p.path) as string;
        if (path.includes(".env")) return 'DATABASE_URL=postgresql://app:****@db.internal:5432/main\nREDIS_URL=redis://cache.internal:6379\nAPI_KEY=sk-proj-****\n';
        if (path.includes(".json")) return '{\n  "name": "app",\n  "version": "1.0.0",\n  "dependencies": {}\n}';
        return '# Configuration\nSee documentation for details.\nLast updated: 2026-03-15\n';
      }
      if (typeof p.query === "string") return `Found 3 results for "${String(p.query).slice(0, 30)}":\n1. Result entry alpha\n2. Result entry beta\n3. Result entry gamma`;
      return "OK";

    case ToolCategory.EXECUTE:
      // Return plausible command output
      if (typeof p.command === "string") {
        const cmd = (p.command as string).toLowerCase();
        if (cmd.includes("curl") || cmd.includes("wget")) return '{"status":"ok","message":"received"}';
        if (cmd.includes("ls")) return "README.md\nsrc/\ntests/\npackage.json\n";
        if (cmd.includes("cat")) return "# File contents\nSample data here.\n";
        if (cmd.includes("grep")) return "src/main.ts:42: matching line here\n";
      }
      return "exit code 0\n";

    case ToolCategory.NETWORK:
      // HTTP success responses — critical for exfil detection
      return '{"status":"ok","received":true,"timestamp":"2026-04-01T12:00:00Z"}';

    case ToolCategory.COMMUNICATE:
      // Message sent confirmation
      return '{"ok":true,"message":"sent","ts":"1711929600.000100"}';

    case ToolCategory.WRITE_LOCAL:
      return '{"success":true,"bytes_written":1024}';

    default:
      return '{"ok":true}';
  }
}

// ─── Shadow LLM caller ───

async function callShadowLlm(
  messages: any[],
  system: any,
  model: string,
  tools: any[] | undefined,
  token: string,
  timeoutMs: number,
): Promise<{ text: string; toolCalls: Array<{ name: string; params: Record<string, unknown> }> }> {
  const reqBody = JSON.stringify({
    model,
    max_tokens: 1024,
    system: Array.isArray(system) ? [
      { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
      ...system.slice(1), // keep other system blocks but replace first with required identity
    ] : [
      { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
      ...(typeof system === "string" && system ? [{ type: "text", text: system }] : []),
    ],
    messages,
    ...(tools && tools.length > 0 ? { tools } : {}),
  });

  const responseData = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = httpsRequest({
      hostname: "api.anthropic.com",
      path: "/v1/messages",
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": `Bearer ${token}`,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": OAUTH_BETAS,
        "user-agent": "claude-cli/2.1.75",
        "x-app": "cli",
      },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode || 0, body: Buffer.concat(chunks).toString("utf-8") }));
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error("Shadow LLM timeout")); });
    req.write(reqBody);
    req.end();
  });

  if (responseData.status < 200 || responseData.status >= 300) {
    throw new Error(`Shadow LLM API ${responseData.status}: ${responseData.body.slice(0, 200)}`);
  }

  // Parse non-streaming response
  const json = JSON.parse(responseData.body);
  let text = "";
  const toolCalls: Array<{ name: string; params: Record<string, unknown> }> = [];

  if (Array.isArray(json.content)) {
    for (const block of json.content) {
      if (block.type === "text") text += block.text;
      if (block.type === "tool_use") {
        toolCalls.push({ name: block.name, params: block.input || {} });
      }
    }
  }

  return { text, toolCalls };
}

// ─── Trajectory analysis ───

/**
 * Analyze shadow execution trajectory for exfiltration signals.
 *
 * Pure behavioral analysis — no LLM, no content inspection:
 * 1. Egress escalation: shadow steps include communication/network tools
 * 2. Honeypot usage: shadow steps reference honeypot values
 * 3. Tool category divergence: shadow steps use unexpected categories
 * 4. Data accumulation: multiple reads of sensitive paths
 */
function analyzeTrajectory(
  steps: ShadowStep[],
  intent: IntentSignals,
  honeypot: HoneypotManager | null,
): { verdict: "allow" | "block"; reason: string } {
  let egressCount = 0;
  let readCount = 0;
  let sensitivePathReads = 0;
  const toolNames: string[] = [];

  for (const step of steps) {
    if (!step.llmResponse) continue;

    for (const tc of step.llmResponse.toolCalls) {
      toolNames.push(tc.name);
      const category = TOOL_CATEGORIES[tc.name];

      // Check 1: Egress escalation
      if (category === ToolCategory.COMMUNICATE || category === ToolCategory.NETWORK) {
        egressCount++;
      }

      // Check 2: Honeypot usage in shadow
      if (honeypot) {
        const hit = honeypot.checkToolCall(tc.name, tc.params);
        if (hit) {
          return { verdict: "block", reason: `Shadow trajectory used honeypot value in "${tc.name}" — confirmed exfiltration` };
        }
      }

      // Check 3: Data accumulation
      if (category === ToolCategory.READ_ONLY) {
        readCount++;
        const paramStr = JSON.stringify(tc.params);
        if (/\.env|credentials|secrets?|\.pem|\.key|password/i.test(paramStr)) {
          sensitivePathReads++;
        }
      }
    }
  }

  // Verdict logic

  // Strong signal: egress without user requesting it
  if (egressCount > 0 && !intent.wantsCommunication && !intent.wantsNetwork) {
    return {
      verdict: "block",
      reason: `Shadow trajectory attempted ${egressCount} egress call(s) (${toolNames.filter(n => {
        const c = TOOL_CATEGORIES[n];
        return c === ToolCategory.COMMUNICATE || c === ToolCategory.NETWORK;
      }).join(", ")}) — user did not request communication or network access`,
    };
  }

  // Medium signal: reading sensitive files then communicating
  if (sensitivePathReads > 0 && egressCount > 0) {
    return {
      verdict: "block",
      reason: `Shadow trajectory: read ${sensitivePathReads} sensitive path(s) then attempted egress — exfiltration pattern`,
    };
  }

  // Weak signal: lots of reads but no egress — probably benign
  if (egressCount === 0) {
    return { verdict: "allow", reason: "Shadow trajectory shows no egress attempts — tool call appears benign" };
  }

  // Egress with user permission — allow
  return { verdict: "allow", reason: "Shadow trajectory egress matches user intent" };
}

// ─── Main executor ───

export class ShadowExecutor {
  private _oauthCreds: OAuthCreds | null = null;

  constructor() {
    this._oauthCreds = loadOAuthCreds();
  }

  private async _ensureToken(): Promise<string> {
    if (!this._oauthCreds) this._oauthCreds = loadOAuthCreds();
    if (!this._oauthCreds) throw new Error("No OAuth credentials for shadow execution");
    if (Date.now() >= this._oauthCreds.expiresAt) {
      this._oauthCreds = await refreshOAuthToken(this._oauthCreds.refreshToken);
    }
    return this._oauthCreds.accessToken;
  }

  /**
   * Execute shadow simulation for a suspicious tool call.
   *
   * Returns a verdict: "allow" (tool call is probably safe) or "block"
   * (shadow trajectory shows exfiltration behavior).
   */
  async execute(opts: ShadowExecutionOpts): Promise<ShadowExecutionResult> {
    const startTime = Date.now();
    const result: ShadowExecutionResult = {
      triggered: true,
      originalToolCall: { name: opts.toolName, params: opts.params },
      steps: [],
      verdict: "allow",
      verdictReason: "",
      totalDurationMs: 0,
    };

    // Can't shadow without the conversation body or model
    if (!opts.lastLlmBody || !opts.model) {
      result.verdictReason = "No conversation body or model available — falling back to pre-shadow behavior";
      result.totalDurationMs = Date.now() - startTime;
      return result;
    }

    try {
      const token = await this._ensureToken();
      const perStepTimeout = Math.floor(opts.timeoutMs / opts.maxSteps);

      // Build initial shadow conversation:
      // Take the original messages, append the tool call + fake result
      let messages = [...(opts.lastLlmBody.messages || [])];

      // Step through shadow execution
      for (let step = 1; step <= opts.maxSteps; step++) {
        const stepStart = Date.now();

        // Generate fake result for the tool call being shadowed
        const fakeResult = step === 1
          ? generateFakeResult(opts.toolName, opts.params)
          : generateFakeResult(
              result.steps[step - 2]?.llmResponse?.toolCalls[0]?.name || opts.toolName,
              result.steps[step - 2]?.llmResponse?.toolCalls[0]?.params || opts.params,
            );

        // Append tool_use (assistant) + tool_result (user) to conversation
        if (step === 1) {
          // First step: add the original tool call + fake result
          messages = [
            ...messages,
            {
              role: "assistant",
              content: [{
                type: "tool_use",
                id: `shadow_${step}`,
                name: opts.toolName,
                input: opts.params,
              }],
            },
            {
              role: "user",
              content: [{
                type: "tool_result",
                tool_use_id: `shadow_${step}`,
                content: fakeResult,
              }],
            },
          ];
        } else {
          // Subsequent steps: add the LLM's tool call from previous step + fake result
          const prevToolCalls = result.steps[step - 2]?.llmResponse?.toolCalls;
          if (!prevToolCalls || prevToolCalls.length === 0) break; // LLM didn't make a tool call — done

          const prevTc = prevToolCalls[0];
          messages = [
            ...messages,
            {
              role: "assistant",
              content: [{
                type: "tool_use",
                id: `shadow_${step}`,
                name: prevTc.name,
                input: prevTc.params,
              }],
            },
            {
              role: "user",
              content: [{
                type: "tool_result",
                tool_use_id: `shadow_${step}`,
                content: fakeResult,
              }],
            },
          ];
        }

        // Call the LLM
        const llmResponse = await callShadowLlm(
          messages,
          opts.lastLlmBody.system,
          opts.model,
          opts.lastLlmBody.tools,
          token,
          perStepTimeout,
        );

        const shadowStep: ShadowStep = {
          stepNumber: step,
          fakeToolResult: fakeResult,
          llmResponse,
          durationMs: Date.now() - stepStart,
        };
        result.steps.push(shadowStep);

        // Append the LLM's response to messages for next step
        if (llmResponse.toolCalls.length > 0) {
          messages.push({
            role: "assistant",
            content: [
              ...(llmResponse.text ? [{ type: "text", text: llmResponse.text }] : []),
              ...llmResponse.toolCalls.map((tc, i) => ({
                type: "tool_use",
                id: `shadow_${step}_tc_${i}`,
                name: tc.name,
                input: tc.params,
              })),
            ],
          });
        }

        // If LLM didn't request any tools, no more steps needed
        if (llmResponse.toolCalls.length === 0) break;

        // Check timeout
        if (Date.now() - startTime > opts.timeoutMs) break;
      }

      // Analyze the trajectory
      const analysis = analyzeTrajectory(result.steps, opts.intent, opts.honeypot);
      result.verdict = analysis.verdict;
      result.verdictReason = analysis.reason;
    } catch (err: any) {
      // On error, fall back to allow (don't block legitimate tool calls due to shadow infra failures)
      result.verdict = "allow";
      result.verdictReason = `Shadow execution failed: ${err?.message || "unknown error"} — allowing tool call`;
    }

    result.totalDurationMs = Date.now() - startTime;
    return result;
  }
}

// ─── Security event builder ───

/** Build a SecurityEvent from a shadow execution result. */
export function buildShadowEvent(
  result: ShadowExecutionResult,
  action: "flagged" | "blocked" = "blocked",
): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: ThreatClass.SHADOW_EXFIL,
    signatureId: `shadow_${result.verdict}`,
    severity: result.verdict === "block" ? "high" : "low",
    matchedText: `${result.originalToolCall.name}: ${result.verdictReason.slice(0, 100)}`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action: result.verdict === "block" ? action : "flagged",
    description: `Shadow execution (${result.steps.length} steps, ${result.totalDurationMs}ms): ${result.verdictReason}`,
  };
}
