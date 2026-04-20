/**
 * Config-as-code manager with hot-reload.
 *
 * Watches a JSONC config file (`~/.shroud/shroud.config.json` by default)
 * and merges it with the base config from `resolveConfig(pluginConfig)`.
 *
 * Priority: env vars > config file > plugin config > defaults.
 *
 * Supports:
 * - JSONC (JSON with // and /* comments)
 * - Keyed field-change callbacks (only fires when watched fields change)
 * - Generic reload callbacks
 * - Commit/rollback with 50-version history
 * - Dashboard read/write via setFields()
 */

import { readFileSync, writeFileSync, existsSync, watchFile, unwatchFile, mkdirSync, statSync } from "node:fs";
import { dirname } from "node:path";
import type { ShroudConfig } from "./types.js";
import { resolveConfig, validateConfig, type ConfigIssue } from "./config.js";
import { BUILTIN_PATTERNS } from "./detectors/regex.js";

/** Fields that cannot be hot-reloaded — require gateway restart. */
const RESTART_ONLY = new Set([
  "secretKey",
  "persistentSalt",
  "dashboardEnabled",
  "dashboardPort",
  "dashboardBind",
  "maxStoreMappings",
]);

/** A versioned config snapshot. */
export interface ConfigCommit {
  version: number;
  timestamp: string;
  description: string;
  config: Partial<ShroudConfig>;
}

type FieldListener = {
  fields: Set<string>;
  callback: () => void;
};

export class ConfigManager {
  private _configPath: string;
  private _historyPath: string;
  private _base: ShroudConfig;
  private _fileOverrides: Partial<ShroudConfig>;
  private _effective: ShroudConfig;
  private _fieldListeners: FieldListener[] = [];
  private _reloadListeners: Array<(config: ShroudConfig) => void> = [];
  private _history: ConfigCommit[] = [];
  private _version = 0;
  private _watching = false;

  constructor(configPath: string, baseConfig: ShroudConfig) {
    this._configPath = configPath;
    this._historyPath = configPath + ".history.json";
    this._base = baseConfig;
    // Auto-create config file with built-in rules if it doesn't exist
    if (!existsSync(configPath)) {
      this._writeDefaultConfig();
    }
    this._fileOverrides = this._loadFile();
    this._effective = this._merge(this._base, this._fileOverrides);
    this._loadHistory();
  }

  /** Current effective config (merged). */
  getEffective(): ShroudConfig {
    return this._effective;
  }

  /** Raw overrides from the config file. */
  getFileOverrides(): Partial<ShroudConfig> {
    return { ...this._fileOverrides };
  }

  /** Path to the config file. */
  getConfigPath(): string {
    return this._configPath;
  }

  /** Current version number (increments on each commit). */
  getCurrentVersion(): number {
    return this._version;
  }

  // ── Subscriptions ──────────────────────────────────────

  /**
   * Register a callback that fires when any of the specified fields change.
   * The callback is deduplicated: even if multiple watched fields change in
   * one reload, the callback fires exactly once.
   */
  onFieldChange(fields: string[], callback: () => void): void {
    this._fieldListeners.push({ fields: new Set(fields), callback });
  }

  /** Register a callback that fires on every successful reload. */
  onReload(callback: (config: ShroudConfig) => void): void {
    this._reloadListeners.push(callback);
  }

  // ── File watching ──────────────────────────────────────

  startWatching(): void {
    if (this._watching) return;
    this._watching = true;
    // Ensure parent directory exists so watchFile can stat the path
    mkdirSync(dirname(this._configPath), { recursive: true });
    watchFile(this._configPath, { interval: 2000 }, () => {
      this._reload();
    });
  }

  stopWatching(): void {
    if (!this._watching) return;
    this._watching = false;
    unwatchFile(this._configPath);
  }

  // ── Programmatic writes (dashboard) ────────────────────

  /** Merge partial config into the file and trigger reload. */
  setFields(partial: Partial<ShroudConfig>): { changedFields: string[]; warnings: string[] } {
    const warnings: string[] = [];
    const cleaned: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(partial)) {
      if (RESTART_ONLY.has(key)) {
        warnings.push(`"${key}" requires gateway restart — skipped`);
        continue;
      }
      cleaned[key] = value;
    }
    // Merge with existing file overrides
    const merged = { ...this._fileOverrides, ...cleaned };
    this._saveFile(merged as Partial<ShroudConfig>);
    const changedFields = this._reload();
    return { changedFields, warnings };
  }

  /** Validate a partial config without applying it. */
  validate(partial: Partial<ShroudConfig>): ConfigIssue[] {
    const testConfig = this._merge(this._base, { ...this._fileOverrides, ...partial });
    return validateConfig(testConfig);
  }

  // ── Commit / rollback ──────────────────────────────────

  commit(description: string): ConfigCommit {
    this._version++;
    const entry: ConfigCommit = {
      version: this._version,
      timestamp: new Date().toISOString(),
      description,
      config: { ...this._fileOverrides },
    };
    this._history.push(entry);
    // Cap at 50
    if (this._history.length > 50) {
      this._history = this._history.slice(-50);
    }
    this._saveHistory();
    return entry;
  }

  rollback(version: number): ConfigCommit | null {
    const entry = this._history.find(h => h.version === version);
    if (!entry) return null;
    this._saveFile(entry.config);
    this._reload();
    return entry;
  }

  getHistory(): ConfigCommit[] {
    return [...this._history];
  }

  // ── Internal ───────────────────────────────────────────

  /** Generate default config file with all built-in detection rules. */
  private _writeDefaultConfig(): void {
    const lines: string[] = [
      "{",
      "  // Shroud config-as-code — auto-generated with built-in detection rules.",
      "  // Edit rules here. Changes hot-reload within 2 seconds (no restart needed).",
      "  // Priority: env vars > this file > plugin config > defaults.",
      "  //",
      "  // Per-tool field scoping — controls which fields get scanned for PII.",
      "  // Reduces false positives from structural fields (IDs, hashes, timestamps).",
      '  "fieldScoping": {',
      '    "toolFields": {',
      '      "Read":     { "scanFields": ["content", "text"] },',
      '      "read":     { "scanFields": ["content", "text"] },',
      '      "Bash":     { "scanFields": ["output", "stdout", "stderr"] },',
      '      "exec":     { "scanFields": ["output", "stdout", "stderr"] }',
      "    },",
      '    "neverScanFields": ["id", "created_at", "updated_at", "sha", "hash", "ref", "type", "status", "state", "mode"],',
      '    "defaultScanFields": []',
      "  },",
      "  //",
      "  // Rule format:",
      '  //   "rule_name": {',
      '  //     "pattern": "regex string",     // override or define the detection regex',
      '  //     "category": "email",            // entity category (email, ip_address, phone, etc.)',
      '  //     "confidence": 0.95,             // detection confidence (0.0-1.0)',
      '  //     "enabled": false                // set to false to disable a rule',
      "  //   }",
      "  //",
      '  "rules": {',
    ];
    for (let i = 0; i < BUILTIN_PATTERNS.length; i++) {
      const p = BUILTIN_PATTERNS[i];
      const comma = i < BUILTIN_PATTERNS.length - 1 ? "," : "";
      // Convert RegExp to source string + flags
      const flags = p.pattern.flags.replace("g", "") || undefined; // "g" is always added; only store extra flags (i, m, etc.)
      const flagsPart = flags ? `, "flags": "${flags}"` : "";
      lines.push(`    "${p.name}": { "pattern": ${JSON.stringify(p.pattern.source)}, "category": "${p.category}", "confidence": ${p.confidence}${flagsPart} }${comma}`);
    }
    lines.push("  }");
    lines.push("}");
    lines.push("");

    try {
      mkdirSync(dirname(this._configPath), { recursive: true });
      writeFileSync(this._configPath, lines.join("\n"), "utf-8");
    } catch { /* non-fatal — config file is optional */ }
  }

  private _reload(): string[] {
    const oldEffective = this._effective;
    try {
      this._fileOverrides = this._loadFile();
      this._effective = this._merge(this._base, this._fileOverrides);
    } catch {
      // Corrupt file — keep previous config
      return [];
    }
    const changed = this._diff(oldEffective, this._effective);

    // Filter out restart-only fields — log warning but don't apply
    const restartChanged = changed.filter(f => RESTART_ONLY.has(f));
    if (restartChanged.length > 0) {
      console.warn(`[shroud][config] Fields require restart (not applied): ${restartChanged.join(", ")}`);
      // Revert restart-only fields to base values
      for (const field of restartChanged) {
        (this._effective as unknown as Record<string, unknown>)[field] =
          (oldEffective as unknown as Record<string, unknown>)[field];
      }
    }

    const effectiveChanged = changed.filter(f => !RESTART_ONLY.has(f));

    if (effectiveChanged.length > 0) {
      // Fire field-specific listeners
      const firedCallbacks = new Set<() => void>();
      for (const listener of this._fieldListeners) {
        if (effectiveChanged.some(f => listener.fields.has(f)) && !firedCallbacks.has(listener.callback)) {
          firedCallbacks.add(listener.callback);
          try { listener.callback(); } catch { /* non-fatal */ }
        }
      }
      // Fire generic reload listeners
      for (const cb of this._reloadListeners) {
        try { cb(this._effective); } catch { /* non-fatal */ }
      }
    }

    return effectiveChanged;
  }

  private _loadFile(): Partial<ShroudConfig> {
    if (!existsSync(this._configPath)) return {};
    try {
      const raw = readFileSync(this._configPath, "utf-8");
      const stripped = stripComments(raw);
      return JSON.parse(stripped) as Partial<ShroudConfig>;
    } catch {
      return {};
    }
  }

  private _saveFile(config: Partial<ShroudConfig>): void {
    try {
      mkdirSync(dirname(this._configPath), { recursive: true });
      writeFileSync(this._configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
    } catch (err) {
      console.warn(`[shroud][config] Failed to write config file: ${err}`);
    }
  }

  private _merge(base: ShroudConfig, overlay: Partial<ShroudConfig>): ShroudConfig {
    const result = { ...base };
    for (const [key, value] of Object.entries(overlay)) {
      if (value !== undefined) {
        (result as unknown as Record<string, unknown>)[key] = value;
      }
    }
    // Re-apply env var overrides (env always wins)
    return applyEnvOverrides(result);
  }

  private _diff(oldConfig: ShroudConfig, newConfig: ShroudConfig): string[] {
    const changed: string[] = [];
    const allKeys = Array.from(new Set([
      ...Object.keys(oldConfig),
      ...Object.keys(newConfig),
    ]));
    for (const key of allKeys) {
      const oldVal = (oldConfig as unknown as Record<string, unknown>)[key];
      const newVal = (newConfig as unknown as Record<string, unknown>)[key];
      if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
        changed.push(key);
      }
    }
    return changed;
  }

  private _loadHistory(): void {
    if (!existsSync(this._historyPath)) return;
    try {
      const raw = readFileSync(this._historyPath, "utf-8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        this._history = parsed;
        const maxVersion = this._history.reduce((max, h) => Math.max(max, h.version), 0);
        this._version = maxVersion;
      }
    } catch { /* start fresh */ }
  }

  private _saveHistory(): void {
    try {
      mkdirSync(dirname(this._historyPath), { recursive: true });
      writeFileSync(this._historyPath, JSON.stringify(this._history, null, 2) + "\n", "utf-8");
    } catch { /* non-fatal */ }
  }
}

/**
 * Strip // and /* comments from JSONC text.
 * Handles strings correctly (doesn't strip inside quoted values).
 */
export function stripComments(jsonc: string): string {
  let result = "";
  let i = 0;
  const len = jsonc.length;
  while (i < len) {
    // String literal — copy verbatim
    if (jsonc[i] === '"') {
      const start = i;
      i++; // opening quote
      while (i < len && jsonc[i] !== '"') {
        if (jsonc[i] === "\\") i++; // skip escaped char
        i++;
      }
      i++; // closing quote
      result += jsonc.slice(start, i);
      continue;
    }
    // Line comment
    if (jsonc[i] === "/" && jsonc[i + 1] === "/") {
      while (i < len && jsonc[i] !== "\n") i++;
      continue;
    }
    // Block comment
    if (jsonc[i] === "/" && jsonc[i + 1] === "*") {
      i += 2;
      while (i < len && !(jsonc[i] === "*" && jsonc[i + 1] === "/")) i++;
      i += 2; // skip */
      continue;
    }
    result += jsonc[i];
    i++;
  }
  return result;
}

/**
 * Re-apply environment variable overrides to a config.
 * Env vars always win over file and plugin config.
 */
function applyEnvOverrides(config: ShroudConfig): ShroudConfig {
  const result = { ...config } as Record<string, unknown>;
  const env = process.env;

  // Boolean env overrides
  const boolOverrides: Array<[string, string]> = [
    ["SHROUD_CANARY_ENABLED", "canaryEnabled"],
    ["SHROUD_HONEYPOT_ENABLED", "honeypotEnabled"],
    ["SHROUD_PROFILING_ENABLED", "profilingEnabled"],
    ["SHROUD_CANARY_SYSTEM", "canarySystemInjection"],
    ["SHROUD_CANARY_BEHAVIOURAL", "canaryBehavioural"],
    ["SHROUD_INJECTION_SCAN_RESPONSES", "injectionScanResponses"],
    ["SHROUD_DRIFT_ENABLED", "driftEnabled"],
    ["SHROUD_SHADOW_EXECUTION", "shadowExecutionEnabled"],
    ["SHROUD_DASHBOARD", "dashboardEnabled"],
    ["SHROUD_COHERENCE_ENABLED", "coherenceEnabled"],
    ["SHROUD_VECTOR_STORE_ENABLED", "vectorStoreEnabled"],
    ["SHROUD_CLUSTERING_ENABLED", "clusteringEnabled"],
    ["SHROUD_URL_CORRELATION_ENABLED", "urlCorrelationEnabled"],
    ["SHROUD_INTENT_CHAIN_ENABLED", "intentChainEnabled"],
    ["SHROUD_TRANSFORMER_ENABLED", "transformerEnabled"],
  ];
  for (const [envKey, field] of boolOverrides) {
    if (env[envKey] === "true") result[field] = true;
    else if (env[envKey] === "false") result[field] = false;
  }

  // Enum env overrides
  if (env.SHROUD_INJECTION_DETECTION === "flag" || env.SHROUD_INJECTION_DETECTION === "block" || env.SHROUD_INJECTION_DETECTION === "off") {
    result.injectionDetection = env.SHROUD_INJECTION_DETECTION;
  }
  if (env.SHROUD_INJECTION_MIN_SEVERITY === "low" || env.SHROUD_INJECTION_MIN_SEVERITY === "medium" || env.SHROUD_INJECTION_MIN_SEVERITY === "high") {
    result.injectionMinSeverity = env.SHROUD_INJECTION_MIN_SEVERITY;
  }
  if (env.SHROUD_PROFILING_MODE === "learning" || env.SHROUD_PROFILING_MODE === "active" || env.SHROUD_PROFILING_MODE === "strict") {
    result.profilingMode = env.SHROUD_PROFILING_MODE;
  } else if (env.SHROUD_PROFILING_MODE === "enforcing") {
    result.profilingMode = "active";
  }

  // String env overrides
  const stringOverrides: Array<[string, string]> = [
    ["SHROUD_SECRET_KEY", "secretKey"],
    ["SHROUD_PERSISTENT_SALT", "persistentSalt"],
    ["SHROUD_PROFILING_DIR", "profilingProfileDir"],
    ["SHROUD_DASHBOARD_BIND", "dashboardBind"],
    ["SHROUD_SIGNATURES_URL", "signaturesUrl"],
    ["SHROUD_SIGNATURES_FILE", "signaturesFile"],
    ["SHROUD_SIEM_WEBHOOK_URL", "siemWebhookUrl"],
    ["SHROUD_SIEM_WEBHOOK_AUTH", "siemWebhookAuth"],
    ["SHROUD_SIEM_JSONL_PATH", "siemJsonlPath"],
  ];
  for (const [envKey, field] of stringOverrides) {
    if (env[envKey]) result[field] = env[envKey];
  }

  // Numeric env overrides
  const numOverrides: Array<[string, string]> = [
    ["SHROUD_DRIFT_THRESHOLD", "driftThreshold"],
    ["SHROUD_DRIFT_SUDDEN_TURN", "driftSuddenTurnDelta"],
    ["SHROUD_COHERENCE_ZSCORE", "coherenceZScore"],
    ["SHROUD_COHERENCE_RESULT_LIMIT", "coherenceResultLimit"],
    ["SHROUD_TRANSFORMER_THRESHOLD", "transformerThreshold"],
    ["SHROUD_TRANSFORMER_WINDOW", "transformerWindowSize"],
    ["SHROUD_TRANSFORMER_MIN_SESSIONS", "transformerMinSessions"],
    ["SHROUD_TRANSFORMER_TRAIN_INTERVAL", "transformerTrainInterval"],
    ["SHROUD_TRANSFORMER_INTENT_ATTENTION_THRESHOLD", "transformerIntentAttentionThreshold"],
    ["SHROUD_SIGNATURES_REFRESH", "signaturesRefreshSec"],
    ["SHROUD_DASHBOARD_PORT", "dashboardPort"],
    ["SHROUD_VECTOR_STORE_MAX", "vectorStoreMax"],
    ["SHROUD_DELEGATION_DRIFT_THRESHOLD", "delegationDriftThreshold"],
    ["SHROUD_SHADOW_TIMEOUT", "shadowExecutionTimeoutMs"],
    ["SHROUD_HONEYPOT_RATE", "honeypotRate"],
  ];
  for (const [envKey, field] of numOverrides) {
    if (env[envKey]) {
      const parsed = parseFloat(env[envKey]!);
      if (!isNaN(parsed)) result[field] = parsed;
    }
  }

  return result as unknown as ShroudConfig;
}
