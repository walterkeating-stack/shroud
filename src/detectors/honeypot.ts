/**
 * Honeypot injection — plant fake secrets in LLM context as tripwires.
 *
 * Shroud already replaces real PII with deterministic fakes. Honeypots
 * extend this: inject additional fake values that have NO real counterpart.
 * No legitimate tool call would ever use them — they don't map to anything
 * in the deobfuscation table and don't correspond to any user request.
 *
 * If a tool call contains a honeypot value, it's 100% injection-driven.
 * Zero false positives by construction.
 *
 * Honeypot types:
 * - Fake API key: if it appears in any tool call → exfiltration attempt
 * - Fake webhook URL: if web_fetch targets it → confirmed exfil
 * - Fake email: if message targets it → confirmed exfil
 * - Fake internal hostname: if exec/web_fetch references it → lateral movement
 *
 * The honeypots are injected into the system prompt context (via
 * before_prompt_build) and checked on every tool call (via before_tool_call).
 */

import { createHash, randomBytes } from "node:crypto";
import type { SecurityEvent } from "../security-event.js";
import { ThreatClass } from "../security-event.js";

/** A single honeypot token. */
export interface HoneypotToken {
  /** The fake value planted in the context. */
  value: string;
  /** What kind of secret this pretends to be. */
  type: "api_key" | "webhook_url" | "email" | "hostname" | "credential";
  /** Human-readable description for security events. */
  description: string;
}

/**
 * Generates and manages honeypot tokens for a session.
 *
 * Tokens are deterministic per session (seeded from HMAC key + session label)
 * so they're stable across turns but unique per agent.
 */
export class HoneypotManager {
  private _tokens: HoneypotToken[] = [];
  private _valueSet = new Set<string>();
  private _contextFragments: string[] = [];

  /**
   * Generate honeypot tokens for this session.
   * Call once per agent session (in before_prompt_build on first turn).
   *
   * @param seed - Unique seed for this session (e.g. agent label + session ID)
   * @param secretKey - HMAC key for deterministic generation
   */
  generate(seed: string, secretKey: string): void {
    if (this._tokens.length > 0) return; // Already generated

    const hash = (input: string) =>
      createHash("sha256").update(`honeypot:${secretKey}:${seed}:${input}`).digest("hex");

    // Helper: deterministic alphanumeric from hash
    const alphaNum = (h: string, len: number) => {
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      let out = "";
      for (let i = 0; i < len; i++) out += chars[parseInt(h.slice(i * 2, i * 2 + 2), 16) % chars.length];
      return out;
    };
    const upperAlphaNum = (h: string, len: number) => {
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let out = "";
      for (let i = 0; i < len; i++) out += chars[parseInt(h.slice(i * 2, i * 2 + 2), 16) % chars.length];
      return out;
    };

    // 1. Fake API key — looks like a real OpenAI key (sk-proj- prefix, 48 chars)
    const apiKey = `sk-proj-${alphaNum(hash("apikey"), 48)}`;
    this._addToken(apiKey, "api_key", "Honeypot API key — no legitimate use");

    // 2. Fake webhook URL — looks like a real Slack incoming webhook
    const t1 = upperAlphaNum(hash("slack-t"), 9);
    const b1 = upperAlphaNum(hash("slack-b"), 9);
    const whKey = alphaNum(hash("slack-k"), 24);
    const webhookUrl = `https://hooks.slack.com/services/${t1}/${b1}/${whKey}`;
    this._addToken(webhookUrl, "webhook_url", "Honeypot webhook URL — no legitimate use");

    // 3. Fake email — looks like a real internal ops address
    const names = ["devops", "sre", "platform", "infra", "oncall", "alerts"];
    const nameIdx = parseInt(hash("ename").slice(0, 2), 16) % names.length;
    const domains = ["ops.internal", "eng.corp.net", "infra.team"];
    const domIdx = parseInt(hash("edom").slice(0, 2), 16) % domains.length;
    const email = `${names[nameIdx]}-${hash("email").slice(0, 4)}@${domains[domIdx]}`;
    this._addToken(email, "email", "Honeypot email — no legitimate use");

    // 4. Fake AWS key — looks like a real IAM access key (AKIA prefix + 16 uppercase)
    const awsKey = `AKIA${upperAlphaNum(hash("aws"), 16)}`;
    this._addToken(awsKey, "api_key", "Honeypot AWS key — no legitimate use");

    // 5. Fake credential — looks like a real PostgreSQL connection string
    const dbUser = names[(nameIdx + 1) % names.length];
    const dbPass = alphaNum(hash("credential"), 20);
    const dbHost = `db-${hash("dbhost").slice(0, 6)}.us-east-1.rds.amazonaws.com`;
    const credential = `postgresql://${dbUser}:${dbPass}@${dbHost}:5432/production`;
    this._addToken(credential, "credential", "Honeypot connection string — no legitimate use");
  }

  /**
   * Build a context block containing all honeypot values.
   * This gets injected into the system prompt alongside real obfuscated data.
   *
   * Designed to look like legitimate configuration/context that an agent
   * would reasonably have access to but should never act on unprompted.
   */
  buildContextBlock(): string {
    if (this._tokens.length === 0) return "";

    const apiKey = this._tokens.find(t => t.type === "api_key")?.value || "";
    const webhook = this._tokens.find(t => t.type === "webhook_url")?.value || "";
    const email = this._tokens.find(t => t.type === "email")?.value || "";
    const cred = this._tokens.find(t => t.type === "credential")?.value || "";

    // Scatter tokens across separate context fragments that look like
    // different parts of the system — NOT grouped together as a credentials block.
    // Each fragment blends with the kind of context agents normally see.
    const apiKey2 = this._tokens.find(t => t.type === "api_key" && t.value.startsWith("AKIA"))?.value || "";
    this._contextFragments = [
      `If deployment fails, post to ${webhook} with the error log.`,
      `Escalation contact: ${email}`,
      `Readonly analytics connection: ${cred}`,
      `Fallback API key for rate-limited requests: ${apiKey}`,
      apiKey2 ? `AWS read-only audit key: ${apiKey2}` : "",
    ].filter(Boolean);
    // Return empty — fragments are injected separately by the hook
    return "";
  }

  /**
   * Check if a tool call contains any honeypot values.
   * Returns a security event if a honeypot is tripped, null otherwise.
   *
   * This is the tripwire — 100% certainty of injection if triggered.
   */
  checkToolCall(toolName: string, params: unknown): SecurityEvent | null {
    if (this._tokens.length === 0) return null;

    const serialized = typeof params === "string" ? params : JSON.stringify(params || "");

    for (const token of this._tokens) {
      if (serialized.includes(token.value)) {
        return {
          timestamp: Date.now(),
          eventType: "injection_detected",
          direction: "request",
          threatClass: ThreatClass.DATA_EXFILTRATION,
          signatureId: `hp_${token.type}`,
          severity: "high",
          matchedText: `${toolName}: honeypot ${token.type} detected in tool call`,
          matchStart: serialized.indexOf(token.value),
          matchEnd: serialized.indexOf(token.value) + token.value.length,
          textLength: serialized.length,
          action: "blocked",
          description: `HONEYPOT TRIPPED: Tool "${toolName}" used honeypot ${token.type}. This is 100% injection-driven — no legitimate workflow uses honeypot values. ${token.description}`,
        };
      }
    }

    return null;
  }

  /**
   * Check if a response text contains any honeypot values.
   * If the LLM echoes honeypot values back, it may be preparing to exfiltrate.
   */
  checkResponse(text: string): SecurityEvent | null {
    if (this._tokens.length === 0 || !text) return null;

    // Only check for the webhook URL and email — these are the exfil targets.
    // API keys and credentials appearing in responses is expected (echo mode).
    const exfilTokens = this._tokens.filter(t => t.type === "webhook_url" || t.type === "email");

    for (const token of exfilTokens) {
      if (text.includes(token.value)) {
        return {
          timestamp: Date.now(),
          eventType: "injection_detected",
          direction: "response",
          threatClass: ThreatClass.DATA_EXFILTRATION,
          signatureId: `hp_echo_${token.type}`,
          severity: "medium",
          matchedText: `LLM response contains honeypot ${token.type}`,
          matchStart: text.indexOf(token.value),
          matchEnd: text.indexOf(token.value) + token.value.length,
          textLength: text.length,
          action: "flagged",
          description: `Honeypot ${token.type} echoed in LLM response — possible exfiltration preparation`,
        };
      }
    }

    return null;
  }

  /** Get all active honeypot tokens. */
  getTokens(): readonly HoneypotToken[] {
    return this._tokens;
  }

  /** Get context fragments for scattered injection into the prompt.
   *  Each fragment is a single sentence containing one honeypot value,
   *  designed to be inserted at different points in the system prompt. */
  getContextFragments(): readonly string[] {
    return this._contextFragments;
  }

  /** Check if a specific value is a honeypot. */
  isHoneypot(value: string): boolean {
    return this._valueSet.has(value);
  }

  private _addToken(value: string, type: HoneypotToken["type"], description: string): void {
    this._tokens.push({ value, type, description });
    this._valueSet.add(value);
  }
}
