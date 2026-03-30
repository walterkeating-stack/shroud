/**
 * Per-agent firewall policy engine.
 *
 * Maps agent build IDs to security policy overrides.
 * Supports hot-reload from a JSON policy file.
 * Enables per-agent WAF rules — different agents get different
 * injection detection thresholds, disabled signatures, and action modes.
 *
 * Policy file format (~/.shroud/policy.json):
 * {
 *   "default": {
 *     "injectionDetection": "flag",
 *     "injectionMinSeverity": "low",
 *     "injectionDisabledSignatures": []
 *   },
 *   "agents": {
 *     "a1b2c3d4e5f6g7h8": {
 *       "label": "research-agent",
 *       "injectionDetection": "flag",
 *       "injectionMinSeverity": "medium",
 *       "injectionDisabledSignatures": ["rs_jailbreak"],
 *       "notes": "Research agent legitimately discusses injection patterns"
 *     }
 *   }
 * }
 */

import { readFileSync, writeFileSync, existsSync, watchFile, unwatchFile, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

/** Per-agent policy overrides. */
export interface AgentPolicy {
  label?: string;
  injectionDetection?: "flag" | "block" | "off";
  injectionMinSeverity?: "low" | "medium" | "high";
  injectionDisabledSignatures?: string[];
  injectionScanResponses?: boolean;
  profilingMode?: "learning" | "active" | "strict";
  notes?: string;
}

/** Full policy file structure. */
export interface PolicyFile {
  default: AgentPolicy;
  agents: Record<string, AgentPolicy>;
}

/** A versioned policy commit. */
export interface PolicyCommit {
  version: number;
  timestamp: string;
  description: string;
  policy: PolicyFile;
}

/** Policy history — stored alongside the policy file. */
export interface PolicyHistory {
  current: number;
  commits: PolicyCommit[];
}

/**
 * Policy engine with hot-reload support.
 */
export class PolicyEngine {
  private _policyPath: string;
  private _historyPath: string;
  private _policy: PolicyFile;
  private _history: PolicyHistory;
  private _watching = false;
  private _onReload: Array<() => void> = [];

  constructor(policyPath: string) {
    this._policyPath = policyPath;
    this._historyPath = policyPath.replace(/\.json$/, ".history.json");
    this._policy = this._loadOrDefault();
    this._history = this._loadHistory();
  }

  /** Get the effective policy for an agent (merged with defaults). */
  getPolicy(agentBuildId: string): AgentPolicy {
    const agentOverride = this._policy.agents[agentBuildId];
    if (!agentOverride) return { ...this._policy.default };

    return {
      ...this._policy.default,
      ...agentOverride,
      // Merge disabled signatures (union of default + agent-specific)
      injectionDisabledSignatures: [
        ...(this._policy.default.injectionDisabledSignatures || []),
        ...(agentOverride.injectionDisabledSignatures || []),
      ],
    };
  }

  /** Get the full policy file. */
  getFullPolicy(): PolicyFile {
    return this._policy;
  }

  /** Update policy for a specific agent. Saves to disk. */
  setAgentPolicy(agentBuildId: string, policy: AgentPolicy): void {
    this._policy.agents[agentBuildId] = {
      ...this._policy.agents[agentBuildId],
      ...policy,
    };
    this._save();
  }

  /** Update the default policy. Saves to disk. */
  setDefaultPolicy(policy: AgentPolicy): void {
    this._policy.default = { ...this._policy.default, ...policy };
    this._save();
  }

  /** Remove agent-specific policy (falls back to default). */
  removeAgentPolicy(agentBuildId: string): void {
    delete this._policy.agents[agentBuildId];
    this._save();
  }

  /**
   * Commit the current policy state with a description.
   * Creates a versioned snapshot that can be rolled back to.
   */
  commit(description: string): PolicyCommit {
    const version = (this._history.commits.length > 0
      ? this._history.commits[this._history.commits.length - 1].version
      : 0) + 1;

    const commit: PolicyCommit = {
      version,
      timestamp: new Date().toISOString(),
      description,
      policy: JSON.parse(JSON.stringify(this._policy)), // deep clone
    };

    this._history.commits.push(commit);
    this._history.current = version;

    // Keep last 50 commits max
    if (this._history.commits.length > 50) {
      this._history.commits = this._history.commits.slice(-50);
    }

    this._saveHistory();
    this._save();
    return commit;
  }

  /**
   * Rollback to a specific version number.
   * Returns the restored commit or null if version not found.
   */
  rollback(version: number): PolicyCommit | null {
    const commit = this._history.commits.find(c => c.version === version);
    if (!commit) return null;

    this._policy = JSON.parse(JSON.stringify(commit.policy)); // deep clone
    this._history.current = version;

    this._saveHistory();
    this._save();
    for (const cb of this._onReload) cb();
    return commit;
  }

  /** Get the commit history. */
  getHistory(): PolicyHistory {
    return this._history;
  }

  /** Get the current version number. */
  getCurrentVersion(): number {
    return this._history.current;
  }

  /** Start watching the policy file for external changes (hot-reload). */
  startWatching(): void {
    if (this._watching) return;
    this._watching = true;

    watchFile(this._policyPath, { interval: 2000 }, () => {
      try {
        this._policy = this._loadOrDefault();
        for (const cb of this._onReload) cb();
      } catch {
        // Corrupt file — keep current policy
      }
    });
  }

  /** Stop watching. */
  stopWatching(): void {
    if (!this._watching) return;
    this._watching = false;
    unwatchFile(this._policyPath);
  }

  /** Register a callback for policy reload events. */
  onReload(callback: () => void): void {
    this._onReload.push(callback);
  }

  private _loadOrDefault(): PolicyFile {
    if (existsSync(this._policyPath)) {
      try {
        const raw = readFileSync(this._policyPath, "utf-8");
        const parsed = JSON.parse(raw);
        return {
          default: parsed.default || {},
          agents: parsed.agents || {},
        };
      } catch {
        // Corrupt file
      }
    }

    return {
      default: {
        injectionDetection: "flag",
        injectionMinSeverity: "low",
        injectionDisabledSignatures: [],
      },
      agents: {},
    };
  }

  private _save(): void {
    try {
      mkdirSync(dirname(this._policyPath), { recursive: true });
      writeFileSync(this._policyPath, JSON.stringify(this._policy, null, 2) + "\n", "utf-8");
    } catch {
      // Best-effort — don't crash if path is unwritable
    }
  }

  private _loadHistory(): PolicyHistory {
    if (existsSync(this._historyPath)) {
      try {
        const raw = readFileSync(this._historyPath, "utf-8");
        const parsed = JSON.parse(raw);
        return {
          current: parsed.current || 0,
          commits: parsed.commits || [],
        };
      } catch { /* corrupt file */ }
    }
    return { current: 0, commits: [] };
  }

  private _saveHistory(): void {
    try {
      mkdirSync(dirname(this._historyPath), { recursive: true });
      writeFileSync(this._historyPath, JSON.stringify(this._history, null, 2) + "\n", "utf-8");
    } catch {
      // Best-effort
    }
  }
}
