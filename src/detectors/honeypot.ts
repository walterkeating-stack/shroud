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
 * - **Loud** (credential-shaped): sk-proj-, AKIA, postgresql://, webhook URL, email
 *   These attract exfil payloads but may be noticed by smart LLMs.
 * - **Quiet** (Shroud-format): CGNAT IP (100.64.x.x), Shroud-domain email,
 *   structured hostname — blend perfectly with normal Shroud fakes.
 *
 * Rate-limiting: not every session gets honeypots. Decision is deterministic
 * from session seed, tiered by agent maturity.
 *
 * Token rotation: when armed, only 1-2 tokens are injected per session.
 */

import { createHash } from "node:crypto";
import type { SecurityEvent } from "../security-event.js";
import { ThreatClass } from "../security-event.js";

// Shroud fake-format constants (match src/generators/network.ts)
const SHROUD_DOMAINS = [
  "nexus.dev", "vertex.io", "prism.net", "atlas.org", "cipher.co",
  "beacon.tech", "forge.dev", "crest.io", "pulse.net", "apex.org",
  "echo.co", "nova.dev", "summit.io", "core.net", "bridge.org",
  "spark.co", "tide.dev", "haven.io", "peak.net", "drift.org",
];
const SHROUD_EMAIL_PREFIXES = [
  "contact", "info", "admin", "support", "hello", "team", "ops",
  "dev", "eng", "data", "sec", "cloud", "mail", "notify", "alerts",
];
const SHROUD_HOSTNAME_ROLES = ["SW", "RTR", "FW", "AP", "SRV", "LB", "DC", "NAS"];
const SHROUD_HOSTNAME_SITES = [
  "DEN", "SFO", "ATL", "SEA", "BOS", "MIA", "DFW", "ORD", "PHX", "PDX",
];

/** A single honeypot token. */
export interface HoneypotToken {
  /** The fake value planted in the context. */
  value: string;
  /** What kind of secret this pretends to be. */
  type: "api_key" | "webhook_url" | "email" | "hostname" | "credential" | "ip_address";
  /** Human-readable description for security events. */
  description: string;
  /** Whether this is a quiet (Shroud-format) or loud (credential-shaped) token. */
  format: "loud" | "quiet";
}

/** Info about the agent's maturity for rate-limiting decisions. */
export interface AgentMaturityInfo {
  /** Profiler maturity level (learning/reliable/mature). Null if profiling disabled. */
  maturity: "learning" | "reliable" | "mature" | null;
  /** Number of security events for this agent. */
  securityEventCount: number;
}

/** Result of the arming decision. */
export interface ArmingDecision {
  /** Whether this session should have honeypots injected. */
  armed: boolean;
  /** Whether to use loud (credential-shaped) or quiet (Shroud-format) tokens. */
  mode: "loud" | "quiet" | "none";
  /** Indices into the token array indicating which tokens to inject. */
  selectedIndices: number[];
}

/**
 * Generates and manages honeypot tokens for a session.
 *
 * Tokens are deterministic per session (seeded from HMAC key + session label)
 * so they're stable across turns but unique per agent.
 */
export class HoneypotManager {
  private _loudTokens: HoneypotToken[] = [];
  private _quietTokens: HoneypotToken[] = [];
  private _allTokens: HoneypotToken[] = [];
  private _valueSet = new Set<string>();
  private _contextFragments: string[] = [];
  private _quietValues: string[] = [];
  private _armingDecision: ArmingDecision | null = null;

  /**
   * Generate all honeypot tokens for this session (both loud and quiet).
   * Call once per agent session (in before_prompt_build on first turn).
   *
   * @param seed - Unique seed for this session (e.g. agent label + session ID)
   * @param secretKey - HMAC key for deterministic generation
   */
  generate(seed: string, secretKey: string): void {
    if (this._allTokens.length > 0) return; // Already generated

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

    // === LOUD tokens (credential-shaped) ===

    // 1. Fake API key — looks like a real OpenAI key (sk-proj- prefix, 48 chars)
    const apiKey = `sk-proj-${alphaNum(hash("apikey"), 48)}`;
    this._addLoud(apiKey, "api_key", "Honeypot API key — no legitimate use");

    // 2. Fake webhook URL — looks like a real Slack incoming webhook
    const t1 = upperAlphaNum(hash("slack-t"), 9);
    const b1 = upperAlphaNum(hash("slack-b"), 9);
    const whKey = alphaNum(hash("slack-k"), 24);
    const webhookUrl = `https://hooks.slack.com/services/${t1}/${b1}/${whKey}`;
    this._addLoud(webhookUrl, "webhook_url", "Honeypot webhook URL — no legitimate use");

    // 3. Fake email — looks like a real internal ops address
    const names = ["devops", "sre", "platform", "infra", "oncall", "alerts"];
    const nameIdx = parseInt(hash("ename").slice(0, 2), 16) % names.length;
    const domains = ["ops.internal", "eng.corp.net", "infra.team"];
    const domIdx = parseInt(hash("edom").slice(0, 2), 16) % domains.length;
    const email = `${names[nameIdx]}-${hash("email").slice(0, 4)}@${domains[domIdx]}`;
    this._addLoud(email, "email", "Honeypot email — no legitimate use");

    // 4. Fake AWS key — looks like a real IAM access key (AKIA prefix + 16 uppercase)
    const awsKey = `AKIA${upperAlphaNum(hash("aws"), 16)}`;
    this._addLoud(awsKey, "api_key", "Honeypot AWS key — no legitimate use");

    // 5. Fake credential — looks like a real PostgreSQL connection string
    const dbUser = names[(nameIdx + 1) % names.length];
    const dbPass = alphaNum(hash("credential"), 20);
    const dbHost = `db-${hash("dbhost").slice(0, 6)}.us-east-1.rds.amazonaws.com`;
    const credential = `postgresql://${dbUser}:${dbPass}@${dbHost}:5432/production`;
    this._addLoud(credential, "credential", "Honeypot connection string — no legitimate use");

    // === QUIET tokens (Shroud-format — blend with normal obfuscation output) ===

    // Q1. Fake email using Shroud's email format (prefix@domain from Shroud pools)
    const qEmailPrefixIdx = parseInt(hash("qemail-prefix").slice(0, 4), 16) % SHROUD_EMAIL_PREFIXES.length;
    const qEmailDomainIdx = parseInt(hash("qemail-domain").slice(0, 4), 16) % SHROUD_DOMAINS.length;
    const quietEmail = `${SHROUD_EMAIL_PREFIXES[qEmailPrefixIdx]}@${SHROUD_DOMAINS[qEmailDomainIdx]}`;
    this._addQuiet(quietEmail, "email", "Quiet honeypot email (Shroud format)");

    // Q2. Fake IP using Shroud's CGNAT format (100.64.x.x)
    const qIpOctet3 = parseInt(hash("qip-3").slice(0, 2), 16) % 64; // 0-63 (stays in 100.64-127 range)
    const qIpOctet4 = (parseInt(hash("qip-4").slice(0, 2), 16) % 254) + 1; // 1-254
    const quietIp = `100.${64 + qIpOctet3}.${parseInt(hash("qip-3b").slice(0, 2), 16) % 256}.${qIpOctet4}`;
    this._addQuiet(quietIp, "ip_address", "Quiet honeypot IP (CGNAT format)");

    // Q3. Fake hostname using Shroud's structured format (SITE-ROLE-NN)
    const qSiteIdx = parseInt(hash("qhost-site").slice(0, 4), 16) % SHROUD_HOSTNAME_SITES.length;
    const qRoleIdx = parseInt(hash("qhost-role").slice(0, 4), 16) % SHROUD_HOSTNAME_ROLES.length;
    const qNum = (parseInt(hash("qhost-num").slice(0, 2), 16) % 99) + 1;
    const quietHostname = `${SHROUD_HOSTNAME_SITES[qSiteIdx]}-${SHROUD_HOSTNAME_ROLES[qRoleIdx]}-${String(qNum).padStart(2, "0")}`;
    this._addQuiet(quietHostname, "hostname", "Quiet honeypot hostname (Shroud format)");

    // Build combined list for checking
    this._allTokens = [...this._loudTokens, ...this._quietTokens];
  }

  /**
   * Decide whether this session should be armed with honeypots.
   * Decision is deterministic from session seed (hash-based, not random).
   *
   * @param seed - Same seed used for generate()
   * @param secretKey - Same key used for generate()
   * @param rate - Base rate (0.0 to 1.0, default 0.25)
   * @param agentMaturity - Agent maturity info for rate tiering
   */
  arm(seed: string, secretKey: string, rate: number, agentMaturity?: AgentMaturityInfo): ArmingDecision {
    if (this._armingDecision) return this._armingDecision;

    // Compute effective rate based on agent maturity
    let effectiveRate = rate;
    if (agentMaturity) {
      if (agentMaturity.securityEventCount > 0) {
        // Prior security incidents: higher rate (capped at 0.5)
        effectiveRate = Math.min(rate * 2.0, 0.5);
      } else if (agentMaturity.maturity === "reliable" || agentMaturity.maturity === "mature") {
        // Mature clean agents: reduced rate
        effectiveRate = rate * 0.4;
      }
      // learning/null with 0 events: use base rate
    }

    // Deterministic armed decision from hash
    const armHash = createHash("sha256")
      .update(`honeypot-arm:${secretKey}:${seed}`)
      .digest("hex");
    const armValue = parseInt(armHash.slice(0, 8), 16) / 0xffffffff; // 0.0..1.0
    const armed = armValue < effectiveRate;

    if (!armed) {
      this._armingDecision = { armed: false, mode: "none", selectedIndices: [] };
      return this._armingDecision;
    }

    // Decide loud vs quiet: 70% quiet, 30% loud
    const modeHash = createHash("sha256")
      .update(`honeypot-mode:${secretKey}:${seed}`)
      .digest("hex");
    const modeValue = parseInt(modeHash.slice(0, 8), 16) / 0xffffffff;
    const mode: "loud" | "quiet" = modeValue < 0.7 ? "quiet" : "loud";

    // Select 1-2 tokens from the chosen pool
    const pool = mode === "loud" ? this._loudTokens : this._quietTokens;
    const countHash = createHash("sha256")
      .update(`honeypot-count:${secretKey}:${seed}`)
      .digest("hex");
    const tokenCount = (parseInt(countHash.slice(0, 2), 16) % 2) + 1; // 1 or 2

    // Deterministic selection of which tokens
    const selHash = createHash("sha256")
      .update(`honeypot-sel:${secretKey}:${seed}`)
      .digest("hex");
    const selectedIndices: number[] = [];
    if (pool.length > 0) {
      const first = parseInt(selHash.slice(0, 4), 16) % pool.length;
      selectedIndices.push(first);
      if (tokenCount >= 2 && pool.length >= 2) {
        let second = parseInt(selHash.slice(4, 8), 16) % pool.length;
        if (second === first) second = (second + 1) % pool.length;
        selectedIndices.push(second);
      }
    }

    this._armingDecision = { armed, mode, selectedIndices };
    return this._armingDecision;
  }

  /** Get the current arming decision (null if arm() hasn't been called). */
  getArmingDecision(): ArmingDecision | null {
    return this._armingDecision;
  }

  /**
   * Build context fragments for loud token injection.
   * Only returns fragments for the selected loud tokens (bare values, no labels).
   * Returns empty if session is not armed or mode is quiet.
   */
  buildContextBlock(): string {
    if (this._allTokens.length === 0) return "";

    this._contextFragments = [];
    this._quietValues = [];

    const decision = this._armingDecision;
    if (!decision || !decision.armed) return "";

    if (decision.mode === "loud") {
      // Loud: bare values as context fragments (no labels like "Ops contact:")
      for (const idx of decision.selectedIndices) {
        if (idx < this._loudTokens.length) {
          this._contextFragments.push(this._loudTokens[idx].value);
        }
      }
    } else {
      // Quiet: collect values to be added as runtime allowlist entries
      // (no context fragments — they blend with normal Shroud output)
      for (const idx of decision.selectedIndices) {
        if (idx < this._quietTokens.length) {
          this._quietValues.push(this._quietTokens[idx].value);
        }
      }
    }

    return "";
  }

  /**
   * Check if a tool call contains any honeypot values.
   * Returns a security event if a honeypot is tripped, null otherwise.
   *
   * This is the tripwire — 100% certainty of injection if triggered.
   * Checks ALL generated tokens (both loud and quiet, whether injected or not).
   */
  checkToolCall(toolName: string, params: unknown): SecurityEvent | null {
    if (this._allTokens.length === 0) return null;

    const serialized = typeof params === "string" ? params : JSON.stringify(params || "");

    for (const token of this._allTokens) {
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
    if (this._allTokens.length === 0 || !text) return null;

    // Only check for the webhook URL and email — these are the exfil targets.
    // API keys and credentials appearing in responses is expected (echo mode).
    const exfilTokens = this._allTokens.filter(t => t.type === "webhook_url" || t.type === "email");

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

  /** Get all active honeypot tokens (both loud and quiet). */
  getTokens(): readonly HoneypotToken[] {
    return this._allTokens;
  }

  /** Get only loud tokens. */
  getLoudTokens(): readonly HoneypotToken[] {
    return this._loudTokens;
  }

  /** Get only quiet tokens. */
  getQuietTokens(): readonly HoneypotToken[] {
    return this._quietTokens;
  }

  /** Get context fragments for scattered injection into the prompt.
   *  Only populated for loud mode. Each fragment is a bare value. */
  getContextFragments(): readonly string[] {
    return this._contextFragments;
  }

  /** Get quiet honeypot values to add to the obfuscator's runtime allowlist.
   *  These blend with normal Shroud output — no prompt injection needed. */
  getQuietValues(): readonly string[] {
    return this._quietValues;
  }

  /** Check if a specific value is a honeypot. */
  isHoneypot(value: string): boolean {
    return this._valueSet.has(value);
  }

  private _addLoud(value: string, type: HoneypotToken["type"], description: string): void {
    const token: HoneypotToken = { value, type, description, format: "loud" };
    this._loudTokens.push(token);
    this._valueSet.add(value);
  }

  private _addQuiet(value: string, type: HoneypotToken["type"], description: string): void {
    const token: HoneypotToken = { value, type, description, format: "quiet" };
    this._quietTokens.push(token);
    this._valueSet.add(value);
  }
}
