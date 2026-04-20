import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { ShroudConfig } from "./types.js";

type EnvSource = NodeJS.ProcessEnv | Record<string, string | undefined>;

export interface AppSessionRecord extends Record<string, unknown> {
  agentLabel?: string;
  agentBuildId?: string;
  updatedAt?: string;
}

export interface ShroudRuntimePaths {
  homeDir: string;
  stateDir: string;
  configPath: string;
  statsFile: string;
  appEventsFile: string;
  appSessionsDir: string | null;
  appSessionsFile: string | null;
  dashboardBind: string;
}

function envValue(env: EnvSource, key: string): string | undefined {
  const value = env[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function defaultStateDir(homeDir: string, env: EnvSource): string {
  const explicit = envValue(env, "SHROUD_RUNTIME_DIR");
  if (explicit) return explicit;

  const openclawState = envValue(env, "OPENCLAW_STATE_DIR");
  if (openclawState) return join(openclawState, ".shroud");

  const sharedOpenClawDir = join(homeDir, ".openclaw", ".shroud");
  if (existsSync(sharedOpenClawDir)) return sharedOpenClawDir;

  return join(homeDir, ".shroud");
}

function legacyAppSessionFile(homeDir: string): string | null {
  const homeFile = join(homeDir, "shroud-app-sessions.json");
  if (existsSync(homeFile)) return homeFile;
  if (existsSync("/tmp/shroud-app-sessions.json")) return "/tmp/shroud-app-sessions.json";
  return null;
}

function normalizeLabel(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function identitySuffix(identity: { agentLabel?: string | null; agentBuildId?: string | null; pid?: number }): string {
  const buildId = identity.agentBuildId?.trim();
  if (buildId) return buildId;

  const label = normalizeLabel(identity.agentLabel).replace(/[^a-z0-9._-]+/g, "-");
  if (label) return label;

  return `pid-${identity.pid || process.pid}`;
}

function sessionKey(session: AppSessionRecord): string {
  const buildId = typeof session.agentBuildId === "string" ? session.agentBuildId.trim() : "";
  if (buildId) return `build:${buildId}`;

  const label = normalizeLabel(session.agentLabel);
  if (label) return `label:${label}`;

  return "";
}

function sessionTimestamp(session: AppSessionRecord): number {
  const updatedAt = typeof session.updatedAt === "string" ? Date.parse(session.updatedAt) : NaN;
  return Number.isFinite(updatedAt) ? updatedAt : 0;
}

function readSessionCandidates(filePath: string): AppSessionRecord[] {
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf-8"));
    if (Array.isArray(parsed)) {
      return parsed.filter(
        (entry): entry is AppSessionRecord =>
          !!entry && typeof entry === "object" && typeof (entry as AppSessionRecord).agentLabel === "string",
      );
    }
    if (parsed && typeof parsed === "object" && typeof (parsed as AppSessionRecord).agentLabel === "string") {
      return [parsed as AppSessionRecord];
    }
  } catch {
    // best-effort
  }
  return [];
}

export function resolveRuntimePaths(
  config?: Partial<Pick<ShroudConfig, "dashboardBind">>,
  env: EnvSource = process.env,
): ShroudRuntimePaths {
  const homeDir = envValue(env, "HOME") || "/root";
  const stateDir = defaultStateDir(homeDir, env);
  const appSessionsFile = envValue(env, "SHROUD_APP_SESSIONS_FILE") || legacyAppSessionFile(homeDir);

  return {
    homeDir,
    stateDir,
    configPath: join(stateDir, "shroud.config.json"),
    statsFile: envValue(env, "SHROUD_STATS_FILE") || join(stateDir, "stats.json"),
    appEventsFile: envValue(env, "SHROUD_APP_EVENTS_FILE") || join(stateDir, "app-events.jsonl"),
    appSessionsDir: envValue(env, "SHROUD_APP_SESSIONS_DIR") || join(stateDir, "app-sessions"),
    appSessionsFile,
    dashboardBind: envValue(env, "SHROUD_DASHBOARD_BIND")
      || config?.dashboardBind
      || "0.0.0.0",
  };
}

export function resolveAppSessionOutputPath(
  runtime: Pick<ShroudRuntimePaths, "appSessionsDir" | "appSessionsFile">,
  identity: { agentLabel?: string | null; agentBuildId?: string | null; pid?: number },
): string {
  if (runtime.appSessionsDir) {
    return join(runtime.appSessionsDir, `${identitySuffix(identity)}.json`);
  }

  if (runtime.appSessionsFile) return runtime.appSessionsFile;

  return join("/tmp", `shroud-app-session-${identity.pid || process.pid}.json`);
}

export function resolveAppStatsOutputPath(
  runtime: Pick<ShroudRuntimePaths, "stateDir">,
  identity: { agentLabel?: string | null; agentBuildId?: string | null; pid?: number },
): string {
  return join(runtime.stateDir, "app-stats", `${identitySuffix(identity)}.json`);
}

export function loadAppSessions(
  runtime: Pick<ShroudRuntimePaths, "appSessionsDir" | "appSessionsFile">,
): AppSessionRecord[] {
  const merged = new Map<string, AppSessionRecord>();
  const files: string[] = [];

  if (runtime.appSessionsFile && existsSync(runtime.appSessionsFile)) {
    files.push(runtime.appSessionsFile);
  }

  if (runtime.appSessionsDir && existsSync(runtime.appSessionsDir)) {
    const dirFiles = readdirSync(runtime.appSessionsDir)
      .filter((name) => name.endsWith(".json"))
      .sort()
      .map((name) => join(runtime.appSessionsDir as string, name));
    files.push(...dirFiles);
  }

  for (const filePath of files) {
    for (const session of readSessionCandidates(filePath)) {
      const key = sessionKey(session);
      if (!key) continue;

      const existing = merged.get(key);
      if (!existing || sessionTimestamp(session) >= sessionTimestamp(existing)) {
        merged.set(key, session);
      }
    }
  }

  return [...merged.values()];
}
