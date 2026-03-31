/**
 * File-based persistence for behavioural profiling baselines.
 *
 * Stores per-agent-build baselines as JSON files.
 * Uses Welford's online algorithm — only running statistics are persisted,
 * not raw data. Zero runtime dependencies.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

import {
  AgentBaseline,
  BaselineMaturity,
  SessionProfile,
} from "./profiler-types.js";
import { updateBaseline } from "./profiler-analysis.js";

/**
 * File-based store for agent behavioural baselines.
 */
export class BaselineStore {
  private readonly _profileDir: string;

  constructor(profileDir: string) {
    // Expand ~ to actual home directory (Node.js doesn't do this automatically)
    this._profileDir = profileDir.startsWith("~")
      ? join(process.env.HOME || "/tmp", profileDir.slice(1))
      : profileDir;
  }

  /** Load a baseline for the given agent build ID. Returns null if not found. */
  load(agentBuildId: string): AgentBaseline | null {
    const filePath = this._filePath(agentBuildId);
    if (!existsSync(filePath)) return null;

    try {
      const raw = readFileSync(filePath, "utf-8");
      return JSON.parse(raw) as AgentBaseline;
    } catch {
      // Corrupt file — start fresh
      return null;
    }
  }

  /** Save a baseline to disk. */
  save(agentBuildId: string, baseline: AgentBaseline): void {
    try {
      mkdirSync(this._profileDir, { recursive: true });
      const filePath = this._filePath(agentBuildId);
      writeFileSync(filePath, JSON.stringify(baseline, null, 2), "utf-8");
    } catch {
      // Best-effort — don't crash the plugin if profile dir is unwritable
    }
  }

  /**
   * Update the baseline with a completed session's feature data.
   * Uses Welford's algorithm for incremental statistics.
   *
   * @param agentBuildId Stable agent identity hash (derived from label)
   * @param session Session profile with per-turn feature vectors
   * @param toolInventory Full tool inventory from the agent session (body.tools)
   */
  updateFromSession(agentBuildId: string, session: SessionProfile, toolInventory?: string[]): void {
    let baseline = this.load(agentBuildId);

    if (!baseline) {
      baseline = {
        agentBuildId,
        sessionCount: 0,
        maturity: "learning",
        features: {},
        toolProfile: [],
        categoryProfile: [],
        lastUpdated: Date.now(),
      };
    }

    // Update running stats for each turn's features
    for (const turn of session.turns) {
      baseline.features = updateBaseline(baseline.features, turn);
    }

    // Update tool and category profiles
    const toolSet = new Set(baseline.toolProfile);
    const catSet = new Set(baseline.categoryProfile);

    // Add tools from individual turns (tools actually called)
    for (const turn of session.turns) {
      for (const tool of turn.toolNames) toolSet.add(tool);
      for (const cat of Object.keys(turn.entityCategoryCounts)) {
        if (turn.entityCategoryCounts[cat] > 0) catSet.add(cat);
      }
    }

    // Add full tool inventory (tools available to the agent, from body.tools)
    if (toolInventory) {
      for (const tool of toolInventory) toolSet.add(tool);
    }

    baseline.toolProfile = [...toolSet];
    baseline.categoryProfile = [...catSet];
    baseline.sessionCount += 1;
    baseline.maturity = this._computeMaturity(baseline.sessionCount);
    baseline.lastUpdated = Date.now();

    this.save(agentBuildId, baseline);
  }

  /** Check if a baseline exists for the given build ID. */
  exists(agentBuildId: string): boolean {
    return existsSync(this._filePath(agentBuildId));
  }

  /**
   * Remove baseline files that don't match any known agent.
   * Call on startup after agent sessions are loaded from disk.
   * Cleans up orphaned files from the old unstable build ID scheme.
   */
  purgeStaleBaselines(knownBuildIds: Set<string>): number {
    let removed = 0;
    try {
      if (!existsSync(this._profileDir)) return 0;
      const files = readdirSync(this._profileDir);
      for (const file of files) {
        // Only touch baseline JSON files (16-char hex name), skip agent-sessions.json etc
        const match = file.match(/^([a-f0-9]{16})\.json$/);
        if (!match) continue;
        const buildId = match[1];
        if (!knownBuildIds.has(buildId)) {
          try {
            unlinkSync(join(this._profileDir, file));
            removed++;
          } catch {}
        }
      }
    } catch {}
    return removed;
  }

  private _filePath(agentBuildId: string): string {
    // Sanitize build ID for filesystem safety
    const safe = agentBuildId.replace(/[^a-zA-Z0-9_-]/g, "");
    return join(this._profileDir, `${safe}.json`);
  }

  private _computeMaturity(sessionCount: number): BaselineMaturity {
    if (sessionCount >= 50) return "mature";
    if (sessionCount >= 5) return "reliable";
    return "learning";
  }
}

/**
 * Compute agent build ID from system prompt, plugin list, and model.
 * Excludes dynamic files (MEMORY.md) to avoid constant invalidation.
 */
export function computeAgentBuildId(
  systemPrompt: string,
  pluginList: string[],
  modelId: string,
): string {
  const components = [
    systemPrompt,
    pluginList.sort().join(","),
    modelId,
  ];
  return createHash("sha256")
    .update(components.join("\n"))
    .digest("hex")
    .slice(0, 16);
}
