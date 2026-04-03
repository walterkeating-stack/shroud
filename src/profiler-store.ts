/**
 * File-based persistence for behavioural profiling baselines.
 *
 * Stores per-agent-build baselines as JSON files.
 * Uses Welford's online algorithm — only running statistics are persisted,
 * not raw data. Zero runtime dependencies.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, unlinkSync } from "node:fs";
import { writeFile, mkdir } from "node:fs/promises";
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
  /** In-memory cache — authoritative after first load, avoids sync I/O on hot path. */
  private _cache = new Map<string, AgentBaseline>();
  /** Build IDs with pending async writes. */
  private _dirty = new Set<string>();
  /** Whether an async flush is already scheduled. */
  private _flushScheduled = false;
  /** Whether the profile dir has been created (avoids repeated mkdir). */
  private _dirCreated = false;

  constructor(profileDir: string) {
    // Expand ~ to actual home directory (Node.js doesn't do this automatically)
    this._profileDir = profileDir.startsWith("~")
      ? join(process.env.HOME || "/tmp", profileDir.slice(1))
      : profileDir;
  }

  /** Load a baseline for the given agent build ID. Returns null if not found. */
  load(agentBuildId: string): AgentBaseline | null {
    // Cache hit — no I/O
    const cached = this._cache.get(agentBuildId);
    if (cached) return cached;

    // Cold start — sync read, then cache
    const filePath = this._filePath(agentBuildId);
    if (!existsSync(filePath)) return null;

    try {
      const raw = readFileSync(filePath, "utf-8");
      const baseline = JSON.parse(raw) as AgentBaseline;
      this._cache.set(agentBuildId, baseline);
      return baseline;
    } catch {
      // Corrupt file — start fresh
      return null;
    }
  }

  /** Save a baseline — writes to cache immediately, flushes to disk async. */
  save(agentBuildId: string, baseline: AgentBaseline): void {
    this._cache.set(agentBuildId, baseline);
    this._dirty.add(agentBuildId);
    this._scheduleFlush();
  }

  /** Flush all dirty baselines to disk synchronously. For SIGTERM/SIGINT only. */
  flushSync(): void {
    if (this._dirty.size === 0) return;
    try {
      mkdirSync(this._profileDir, { recursive: true });
    } catch { /* best-effort */ }
    for (const id of this._dirty) {
      const baseline = this._cache.get(id);
      if (baseline) {
        try {
          writeFileSync(this._filePath(id), JSON.stringify(baseline), "utf-8");
        } catch { /* best-effort */ }
      }
    }
    this._dirty.clear();
  }

  private _scheduleFlush(): void {
    if (this._flushScheduled) return;
    this._flushScheduled = true;
    setImmediate(() => this._flushAsync());
  }

  private async _flushAsync(): Promise<void> {
    this._flushScheduled = false;
    const ids = [...this._dirty];
    this._dirty.clear();
    try {
      if (!this._dirCreated) {
        await mkdir(this._profileDir, { recursive: true });
        this._dirCreated = true;
      }
      for (const id of ids) {
        const baseline = this._cache.get(id);
        if (baseline) {
          await writeFile(this._filePath(id), JSON.stringify(baseline), "utf-8");
        }
      }
    } catch { /* best-effort */ }
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
    return this._cache.has(agentBuildId) || existsSync(this._filePath(agentBuildId));
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
