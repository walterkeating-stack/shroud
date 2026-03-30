/**
 * Configuration resolver for the Shroud plugin.
 *
 * Merges plugin config with environment variables and provides defaults.
 */

import { randomBytes } from "node:crypto";

import { Category, ShroudConfig } from "./types.js";
import type { RedactionLevel } from "./redaction.js";

/**
 * Resolve a fully populated ShroudConfig from optional plugin config
 * and environment variables.
 *
 * Priority: env vars > pluginConfig > defaults.
 */
export const STATS_FILE = process.env.SHROUD_STATS_FILE || "/tmp/shroud-stats.json";
export const IS_TEST = process.env.NODE_ENV === "test";

export function resolveConfig(pluginConfig?: unknown): ShroudConfig {
  const raw: Record<string, unknown> =
    pluginConfig != null && typeof pluginConfig === "object"
      ? (pluginConfig as Record<string, unknown>)
      : {};

  // Env var overrides
  const envSecretKey = process.env.SHROUD_SECRET_KEY;
  const envSalt = process.env.SHROUD_PERSISTENT_SALT;

  let secretKey =
    envSecretKey ??
    (typeof raw.secretKey === "string" ? raw.secretKey : "");

  // Auto-generate if missing
  if (!secretKey) {
    secretKey = randomBytes(32).toString("hex");
  }

  // Warn if too short (but don't throw -- let the plugin still load)
  if (secretKey.length < 16) {
    console.warn(
      "[shroud] WARNING: secretKey is shorter than 16 characters. " +
        "This weakens mapping security. Set SHROUD_SECRET_KEY or pass a longer key.",
    );
  }

  const persistentSalt =
    envSalt ??
    (typeof raw.persistentSalt === "string" ? raw.persistentSalt : "");

  // Validate redactionLevel
  const redactionRaw = raw.redactionLevel;
  const validLevels: RedactionLevel[] = ["full", "masked", "stats"];
  const redactionLevel: RedactionLevel =
    typeof redactionRaw === "string" && validLevels.includes(redactionRaw as RedactionLevel)
      ? (redactionRaw as RedactionLevel)
      : "full";

  const config: ShroudConfig = {
    secretKey,
    persistentSalt,
    minConfidence:
      typeof raw.minConfidence === "number" ? raw.minConfidence : 0.0,
    allowlist: Array.isArray(raw.allowlist)
      ? (raw.allowlist as string[])
      : [],
    denylist: Array.isArray(raw.denylist)
      ? (raw.denylist as string[])
      : [],
    canaryEnabled:
      typeof raw.canaryEnabled === "boolean" ? raw.canaryEnabled : false,
    canaryPrefix:
      typeof raw.canaryPrefix === "string"
        ? raw.canaryPrefix
        : "SHROUD-CANARY",
    auditEnabled:
      typeof raw.auditEnabled === "boolean" ? raw.auditEnabled : false,
    logMappings:
      typeof raw.logMappings === "boolean" ? raw.logMappings : false,
    customPatterns: Array.isArray(raw.customPatterns)
      ? (raw.customPatterns as ShroudConfig["customPatterns"])
      : [],
    // Verbose audit logging
    verboseLogging:
      typeof raw.verboseLogging === "boolean" ? raw.verboseLogging : false,
    auditLogFormat:
      raw.auditLogFormat === "json" ? "json" : "human",
    auditIncludeProofHashes:
      typeof raw.auditIncludeProofHashes === "boolean"
        ? raw.auditIncludeProofHashes
        : false,
    auditHashSalt:
      typeof raw.auditHashSalt === "string" ? raw.auditHashSalt : "",
    auditHashTruncate:
      typeof raw.auditHashTruncate === "number" ? raw.auditHashTruncate : 12,
    auditMaxFakesSample:
      typeof raw.auditMaxFakesSample === "number"
        ? raw.auditMaxFakesSample
        : 0,
    detectorOverrides:
      raw.detectorOverrides != null && typeof raw.detectorOverrides === "object"
        ? (raw.detectorOverrides as Record<string, { enabled?: boolean; confidence?: number }>)
        : {},

    // Tool chain depth
    maxToolDepth:
      typeof raw.maxToolDepth === "number" ? raw.maxToolDepth : 10,

    // Redaction level
    redactionLevel,

    // Dry-run mode
    dryRun:
      typeof raw.dryRun === "boolean" ? raw.dryRun : false,

    // LRU store eviction (0 = unlimited)
    maxStoreMappings:
      typeof raw.maxStoreMappings === "number" ? raw.maxStoreMappings : 0,

    // --- Injection detection ---
    injectionDetection: (() => {
      const env = process.env.SHROUD_INJECTION_DETECTION;
      if (env === "flag" || env === "block" || env === "off") return env;
      const val = raw.injectionDetection;
      if (val === "flag" || val === "block" || val === "off") return val as "flag" | "block" | "off";
      return "off";
    })(),
    injectionDisabledSignatures: Array.isArray(raw.injectionDisabledSignatures)
      ? (raw.injectionDisabledSignatures as string[])
      : [],
    injectionMinSeverity: (() => {
      const env = process.env.SHROUD_INJECTION_MIN_SEVERITY;
      if (env === "low" || env === "medium" || env === "high") return env;
      const val = raw.injectionMinSeverity;
      if (val === "low" || val === "medium" || val === "high") return val as "low" | "medium" | "high";
      return "low";
    })(),
    injectionScanResponses: (() => {
      const env = process.env.SHROUD_INJECTION_SCAN_RESPONSES;
      if (env === "true") return true;
      if (env === "false") return false;
      return typeof raw.injectionScanResponses === "boolean" ? raw.injectionScanResponses : true;
    })(),

    // --- Behavioural profiling ---
    profilingEnabled: (() => {
      const env = process.env.SHROUD_PROFILING_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      return typeof raw.profilingEnabled === "boolean" ? raw.profilingEnabled : false;
    })(),
    profilingMode: (() => {
      const env = process.env.SHROUD_PROFILING_MODE;
      if (env === "learning" || env === "active" || env === "strict") return env;
      const val = raw.profilingMode;
      if (val === "learning" || val === "active" || val === "strict") return val as "learning" | "active" | "strict";
      return "learning";
    })(),
    profilingSigma:
      typeof raw.profilingSigma === "number" ? raw.profilingSigma : 3.0,
    profilingMinBaseline:
      typeof raw.profilingMinBaseline === "number" ? raw.profilingMinBaseline : 5,
    profilingProfileDir: (() => {
      const env = process.env.SHROUD_PROFILING_DIR;
      if (env) return env;
      return typeof raw.profilingProfileDir === "string"
        ? raw.profilingProfileDir
        : "~/.shroud/profiles";
    })(),

    // --- Canary security extensions ---
    canarySystemInjection:
      typeof raw.canarySystemInjection === "boolean" ? raw.canarySystemInjection : false,
    canaryBehavioural:
      typeof raw.canaryBehavioural === "boolean" ? raw.canaryBehavioural : false,
    canaryNearMatchDistance:
      typeof raw.canaryNearMatchDistance === "number" ? raw.canaryNearMatchDistance : 2,
  };

  return config;
}

/** Validation issue severity. */
export type ConfigSeverity = "error" | "warning" | "info";

/** A single config validation issue. */
export interface ConfigIssue {
  severity: ConfigSeverity;
  field: string;
  message: string;
}

/**
 * Validate a resolved ShroudConfig and return actionable issues.
 *
 * Does NOT throw — callers decide how to handle warnings vs errors.
 */
export function validateConfig(config: ShroudConfig): ConfigIssue[] {
  const issues: ConfigIssue[] = [];

  // Secret key checks
  if (config.secretKey.length < 16) {
    issues.push({ severity: "error", field: "secretKey", message: "secretKey is shorter than 16 chars — mappings are weak. Set SHROUD_SECRET_KEY." });
  } else if (config.secretKey.length < 32) {
    issues.push({ severity: "warning", field: "secretKey", message: "secretKey is shorter than 32 chars — consider a longer key for production." });
  }

  // minConfidence range
  if (config.minConfidence < 0 || config.minConfidence > 1) {
    issues.push({ severity: "error", field: "minConfidence", message: `minConfidence=${config.minConfidence} is outside [0,1]. Set to a value between 0 and 1.` });
  }

  // maxStoreMappings negative
  if (config.maxStoreMappings < 0) {
    issues.push({ severity: "error", field: "maxStoreMappings", message: "maxStoreMappings must be >= 0 (0 = unlimited)." });
  }

  // dryRun informational
  if (config.dryRun) {
    issues.push({ severity: "info", field: "dryRun", message: "Dry-run mode is active — entities are detected but text is NOT obfuscated." });
  }

  // Custom patterns with invalid regex
  for (const cp of config.customPatterns) {
    try {
      new RegExp(cp.pattern);
    } catch {
      issues.push({ severity: "error", field: "customPatterns", message: `Custom pattern "${cp.name}" has invalid regex: ${cp.pattern}` });
    }
  }

  // Detector overrides referencing unknown rules (info-level since we can't check at config time)
  if (Object.keys(config.detectorOverrides).length > 0) {
    issues.push({ severity: "info", field: "detectorOverrides", message: `${Object.keys(config.detectorOverrides).length} detector override(s) configured.` });
  }

  // Injection detection
  if (config.injectionDetection !== "flag" && config.injectionDetection !== "block" && config.injectionDetection !== "off") {
    issues.push({ severity: "error", field: "injectionDetection", message: `injectionDetection="${config.injectionDetection}" is invalid. Must be "flag", "block", or "off".` });
  }
  if (config.injectionDetection !== "off") {
    issues.push({ severity: "info", field: "injectionDetection", message: `Injection detection is active in "${config.injectionDetection}" mode.` });
  }

  return issues;
}
