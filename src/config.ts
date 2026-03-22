/**
 * Configuration resolver for the Shroud plugin.
 *
 * Merges plugin config with environment variables and provides defaults.
 */

import { randomBytes } from "node:crypto";

import { ShroudConfig } from "./types.js";

/**
 * Resolve a fully populated ShroudConfig from optional plugin config
 * and environment variables.
 *
 * Priority: env vars > pluginConfig > defaults.
 */
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
    // Use console.warn since we may not have a logger yet
    console.warn(
      "[shroud] WARNING: secretKey is shorter than 16 characters. " +
        "This weakens mapping security. Set SHROUD_SECRET_KEY or pass a longer key.",
    );
  }

  const persistentSalt =
    envSalt ??
    (typeof raw.persistentSalt === "string" ? raw.persistentSalt : "");

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
  };

  return config;
}
