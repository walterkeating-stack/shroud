/**
 * Shroud -- OpenClaw privacy plugin.
 *
 * Automatically obfuscates sensitive data before it reaches the LLM
 * and deobfuscates responses before they reach the user.
 */

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { resolveConfig } from "./config.js";
import { Obfuscator } from "./obfuscator.js";
import { registerHooks } from "./hooks.js";
import { BaselineStore } from "./profiler-store.js";
import type { BehaviouralProfiler } from "./profiler.js";
import { startDashboard } from "./dashboard.js";
import type { AgentSessionTracker } from "./agent-session.js";
import { PolicyEngine } from "./policy.js";
import { SiemShipper } from "./siem.js";
import { ConfigManager } from "./config-manager.js";

// ---------------------------------------------------------------------------
// Runtime prototype patch: wrap EventStream.prototype.push() with the
// Shroud deobfuscation hook. No file reads, no file writes, no cache
// clearing, no restarts needed. Works across OpenClaw versions because
// it patches the live prototype at import time.
// ---------------------------------------------------------------------------
const PATCH_MARKER = "__shroudEventStreamPatched";

function patchEventStreamPrototype(logger: any): void {
  // Already patched by another plugin instance — skip
  if ((globalThis as any)[PATCH_MARKER]) return;

  let EventStream: any = null;

  // Strategy 1: direct ESM import via createRequire
  try {
    const esmRequire = createRequire(import.meta.url);
    const mod = esmRequire("@mariozechner/pi-ai/dist/utils/event-stream.js");
    EventStream = mod?.EventStream ?? mod?.default?.EventStream;
  } catch {
    // Not resolvable from Shroud's own location — try from OpenClaw
  }

  // Strategy 2: walk require.cache to find OpenClaw's install root
  if (!EventStream) {
    try {
      const esmRequire = createRequire(import.meta.url);
      const cache = esmRequire.cache;
      if (cache) {
        for (const key of Object.keys(cache)) {
          const idx = key.indexOf("/openclaw/");
          if (idx === -1) continue;
          const root = key.slice(0, idx + "/openclaw/".length);
          try {
            const req2 = createRequire(root + "package.json");
            const mod = req2("@mariozechner/pi-ai/dist/utils/event-stream.js");
            EventStream = mod?.EventStream ?? mod?.default?.EventStream;
            if (EventStream) break;
          } catch { /* try next */ }
        }
      }
    } catch { /* no cache access */ }
  }

  // Strategy 3: resolve from process.argv[1] (the OpenClaw binary)
  if (!EventStream && process.argv[1]) {
    try {
      const binRequire = createRequire(process.argv[1]);
      const mod = binRequire("@mariozechner/pi-ai/dist/utils/event-stream.js");
      EventStream = mod?.EventStream ?? mod?.default?.EventStream;
    } catch { /* not found from binary location */ }
  }

  // Strategy 4: find the file on disk via known paths (bypasses exports restriction)
  if (!EventStream) {
    const candidates = [
      // From OpenClaw's npm global install
      process.argv[1] && join(dirname(dirname(process.argv[1])), "lib", "node_modules", "openclaw", "node_modules", "@mariozechner", "pi-ai", "dist", "utils", "event-stream.js"),
      // From npm global prefix
      join(process.env.HOME || "/root", ".npm-global", "lib", "node_modules", "openclaw", "node_modules", "@mariozechner", "pi-ai", "dist", "utils", "event-stream.js"),
      // Common global locations
      "/usr/local/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js",
      "/usr/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js",
    ].filter(Boolean) as string[];

    for (const candidate of candidates) {
      if (!existsSync(candidate)) continue;
      try {
        // Use dynamic import to load the ESM module directly by file path
        const fileUrl = "file://" + candidate;
        // We can't use top-level await, so use createRequire with the file's own dir
        // to bypass the parent package.json exports
        const localRequire = createRequire(candidate);
        // Try requiring from the file's own directory (no exports restriction from parent)
        const mod = localRequire("./event-stream.js");
        EventStream = mod?.EventStream ?? mod?.default?.EventStream;
        if (EventStream) break;
      } catch { /* try next */ }
    }
  }

  if (!EventStream?.prototype?.push) return;

  // Wrap prototype.push with the deobfuscation hook
  const originalPush = EventStream.prototype.push;
  EventStream.prototype.push = function shroudPatchedPush(event: any) {
    const deob = (globalThis as any).__shroudStreamDeobfuscate;
    if (deob && event && typeof event === "object") {
      event = deob(this, event);
    }
    return originalPush.call(this, event);
  };

  // Mark as patched to prevent double-wrapping
  (globalThis as any)[PATCH_MARKER] = true;

}

export default {
  id: "shroud-privacy",
  name: "Shroud",
  register(api: any) {
    // Patch EventStream prototype for streaming deobfuscation (no file I/O)
    patchEventStreamPrototype(api.logger);

    const config = resolveConfig(api.pluginConfig);
    const obfuscator = new Obfuscator(config);

    // Config-as-code: watch ~/.shroud/shroud.config.json for hot-reload.
    // Defer startWatching so watchFile doesn't block plugin install (which
    // loads the plugin to verify it, then expects the process to exit).
    // Resolve config path: prefer OPENCLAW_STATE_DIR, then HOME/.shroud
    const configDir = process.env.OPENCLAW_STATE_DIR
      ? join(process.env.OPENCLAW_STATE_DIR, ".shroud")
      : join(process.env.HOME || "/root", ".shroud");
    const configPath = join(configDir, "shroud.config.json");
    const configManager = new ConfigManager(configPath, config);
    configManager.onReload((newConfig) => {
      obfuscator.updateConfig(newConfig);
      api.logger?.info("[shroud] Config hot-reloaded from " + configPath);
    });
    const watchTimer = setTimeout(() => configManager.startWatching(), 5000);
    watchTimer.unref();

    registerHooks(api, obfuscator);

    // Register shroud_status tool
    api.registerTool({
      name: "shroud_status",
      description:
        "Show plugin diagnostics: entity counts, session info, status",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      handler: async () => ({
        content: [
          {
            type: "text",
            text: JSON.stringify(obfuscator.getStats(), null, 2),
          },
        ],
      }),
    });

    // Register shroud_security tool — security extension stats
    api.registerTool({
      name: "shroud_security",
      description:
        "Show injection detection events, agent sessions, and security statistics",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      handler: async () => {
        const bus = (globalThis as any).__shroudSecurityBus;
        const tracker = (globalThis as any).__shroudAgentTracker;
        const result: Record<string, unknown> = {
          injectionDetection: config.injectionDetection,
        };

        if (bus) {
          result.securityStats = bus.getStats();
          result.recentEvents = bus.getEvents().slice(-10);
        }

        if (tracker) {
          result.agentSessions = tracker.getAllSessions();
        }

        // Per-agent profiling status — shows learning phase progress
        const profiler = (globalThis as any).__shroudProfiler as BehaviouralProfiler | undefined;
        if (config.profilingEnabled) {
          const profileDir = config.profilingProfileDir.replace("~", process.env.HOME || "/root");
          const store = new BaselineStore(profileDir);
          const agentProfiles: Record<string, unknown>[] = [];

          // Get baselines for all tracked agents
          const sessions = tracker?.getAllSessions() || [];
          for (const session of sessions) {
            const baseline = store.load(session.agentBuildId);
            if (baseline) {
              const sessionsNeeded = Math.max(0, config.profilingMinBaseline - baseline.sessionCount);
              agentProfiles.push({
                agentBuildId: baseline.agentBuildId,
                agentLabel: session.agentLabel,
                maturity: baseline.maturity,
                sessionCount: baseline.sessionCount,
                sessionsUntilActive: sessionsNeeded,
                learningProgress: Math.min(100, Math.round((baseline.sessionCount / config.profilingMinBaseline) * 100)),
                lastUpdated: new Date(baseline.lastUpdated).toISOString(),
                trackedFeatures: Object.keys(baseline.features).length,
                knownTools: baseline.toolProfile,
                knownCategories: baseline.categoryProfile,
                anomalyThreshold: `${config.profilingSigma}σ`,
                mode: config.profilingMode,
                status: baseline.sessionCount >= config.profilingMinBaseline
                  ? `✓ Active — ${baseline.maturity} baseline (${baseline.sessionCount} sessions)`
                  : `◐ Learning — ${sessionsNeeded} more session${sessionsNeeded === 1 ? "" : "s"} needed`,
              });
            } else {
              agentProfiles.push({
                agentBuildId: session.agentBuildId,
                agentLabel: session.agentLabel,
                maturity: "none",
                sessionCount: 0,
                sessionsUntilActive: config.profilingMinBaseline,
                learningProgress: 0,
                mode: config.profilingMode,
                status: `○ No baseline — first session in progress`,
              });
            }
          }

          result.profiling = {
            enabled: true,
            mode: config.profilingMode,
            sigma: config.profilingSigma,
            minBaseline: config.profilingMinBaseline,
            agents: agentProfiles,
          };

          // Current session alerts
          if (profiler) {
            const alerts = profiler.getAlerts();
            if (alerts.length > 0) {
              result.anomalyAlerts = alerts.slice(-10);
            }
          }
        }

        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
          }],
        };
      },
    });

    // Register shroud_reset tool
    api.registerTool({
      name: "shroud_reset",
      description:
        "Clear all plugin mappings and start a fresh session",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      handler: async () => {
        obfuscator.reset();
        return {
          content: [
            {
              type: "text",
              text: "Shroud session reset. All mappings cleared.",
            },
          ],
        };
      },
    });

    // --- SIEM startup ---
    if ((config.siemWebhookUrl || config.siemJsonlPath) && !(globalThis as any).__shroudSiemStarted) {
      (globalThis as any).__shroudSiemStarted = true;
      const siemShipper = new SiemShipper({
        webhookUrl: config.siemWebhookUrl,
        webhookAuth: config.siemWebhookAuth,
        jsonlPath: config.siemJsonlPath,
        batchSize: config.siemBatchSize,
        flushIntervalMs: 5000,
      });
      // Subscribe to security events
      const secBus = (globalThis as any).__shroudSecurityBus;
      if (secBus) {
        secBus.onEvent((event: any) => siemShipper.onEvent(event));
      }
      (globalThis as any).__shroudSiemShipper = siemShipper;
      api.logger?.info(`[shroud] SIEM shipper started${config.siemWebhookUrl ? ` (webhook: ${config.siemWebhookUrl})` : ""}${config.siemJsonlPath ? ` (jsonl: ${config.siemJsonlPath})` : ""}`);
    }

    // --- Dashboard startup ---
    // Only start dashboard in the main gateway process, not in subprocesses
    // (e.g. openclaw message send). Subprocess env markers: OPENCLAW_SUBPROCESS,
    // OPENCLAW_SEND_MEDIA, or the presence of an already-bound port.
    const isSubprocess = !!(process.env.OPENCLAW_SUBPROCESS || process.env.OPENCLAW_SEND_MEDIA || process.env.OPENCLAW_AGENT_EXEC);
    if (config.dashboardEnabled && !isSubprocess && !(globalThis as any).__shroudDashboardStarted) {
      (globalThis as any).__shroudDashboardStarted = true;
      try {
        const profileDir = config.profilingProfileDir.replace("~", process.env.HOME || "/root");
        const policyPath = profileDir.replace(/\/profiles\/?$/, "/policy.json");
        const policyEngine = new PolicyEngine(policyPath.includes("policy.json") ? policyPath : `${profileDir}/../policy.json`);
        policyEngine.startWatching();
        (globalThis as any).__shroudPolicyEngine = policyEngine;

        startDashboard(config.dashboardPort, {
          securityBus: (globalThis as any).__shroudSecurityBus ?? null,
          agentTracker: (globalThis as any).__shroudAgentTracker ?? { getAllSessions: () => [], getSession: () => null },
          baselineStore: config.profilingEnabled ? new BaselineStore(profileDir) : null,
          obfuscator,
          profiler: (globalThis as any).__shroudProfiler ?? null,
          config,
          policyEngine,
          agentSessionFile: `${profileDir}/agent-sessions.json`,
          driftDetector: (globalThis as any).__shroudDriftDetector ?? null,
          appEventsFile: process.env.SHROUD_APP_EVENTS_FILE || "/tmp/shroud-app-events.jsonl",
          appSessionsFile: process.env.SHROUD_APP_SESSIONS_FILE
            || (existsSync(`${process.env.HOME}/shroud-app-sessions.json`) ? `${process.env.HOME}/shroud-app-sessions.json` : "/tmp/shroud-app-sessions.json"),
        });
        api.logger?.info(`[shroud] Security dashboard started on http://127.0.0.1:${config.dashboardPort}`);
      } catch (err: any) {
        api.logger?.info(`[shroud] Dashboard failed to start: ${err.message}`);
      }
    }

    // Single load confirmation — used by test harness to verify plugin loaded.
    // Only logs once per process (suppressed on subsequent agent loads).
    if (!(globalThis as any).__shroudLoadLogged) {
      (globalThis as any).__shroudLoadLogged = true;
      api.logger?.info("[shroud] Plugin loaded.");
    }
  },
};
