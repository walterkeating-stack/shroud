/**
 * Per-agent ob/deob mode resolver.
 *
 * Maps an agent label to a mode (enforce | shadow | off) using the
 * `agents` block of shroud.config.json.
 *
 * Precedence: exact label match > wildcard pattern match > "*" fallback > "enforce".
 */

import type { AgentsConfig, AgentMode } from "./types.js";

function wildcardMatch(value: string, pattern: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

export class AgentModeResolver {
  private readonly exact: Map<string, AgentMode>;
  private readonly patterns: Array<{ pattern: string; mode: AgentMode }>;
  private readonly fallback: AgentMode;

  constructor(config: AgentsConfig = {}) {
    this.exact = new Map();
    this.patterns = [];
    let fallback: AgentMode = "enforce";
    for (const [label, rule] of Object.entries(config)) {
      if (label === "*") {
        fallback = rule.mode;
        continue;
      }
      if (label.includes("*") || label.includes("?")) {
        this.patterns.push({ pattern: label, mode: rule.mode });
      } else {
        this.exact.set(label, rule.mode);
      }
    }
    this.fallback = fallback;
  }

  /** Resolve mode for a given agent label. */
  resolve(agentLabel: string): AgentMode {
    const exact = this.exact.get(agentLabel);
    if (exact !== undefined) return exact;
    for (const { pattern, mode } of this.patterns) {
      if (wildcardMatch(agentLabel, pattern)) return mode;
    }
    return this.fallback;
  }

  /** Return every configured entry as {label, mode, source} for the dashboard. */
  listConfigured(): Array<{ label: string; mode: AgentMode; source: "exact" | "wildcard" | "fallback" }> {
    const out: Array<{ label: string; mode: AgentMode; source: "exact" | "wildcard" | "fallback" }> = [];
    for (const [label, mode] of this.exact) {
      out.push({ label, mode, source: "exact" });
    }
    for (const { pattern, mode } of this.patterns) {
      out.push({ label: pattern, mode, source: "wildcard" });
    }
    out.push({ label: "*", mode: this.fallback, source: "fallback" });
    return out;
  }
}

/** Module-level resolver instance, refreshed on config reload. */
let _resolver = new AgentModeResolver();

export function setAgentModeResolver(resolver: AgentModeResolver): void {
  _resolver = resolver;
}

export function getAgentModeResolver(): AgentModeResolver {
  return _resolver;
}

/**
 * Module-level "current agent mode" — set at hook entry, read inside the
 * obfuscator as a default when no explicit mode is passed. Hooks are sync
 * and the runtime is single-threaded, so this is safe.
 */
let _currentMode: AgentMode = "enforce";
let _currentAgentLabel: string = "Unknown Agent";

export function setCurrentAgentMode(label: string, mode: AgentMode): void {
  _currentAgentLabel = label;
  _currentMode = mode;
}

export function getCurrentAgentMode(): AgentMode {
  return _currentMode;
}

export function getCurrentAgentLabel(): string {
  return _currentAgentLabel;
}

/** Reset to defaults (for tests). */
export function resetCurrentAgentMode(): void {
  _currentAgentLabel = "Unknown Agent";
  _currentMode = "enforce";
}
