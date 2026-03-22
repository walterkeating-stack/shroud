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
export function resolveConfig(pluginConfig?: unknown): ShroudConfig {
  const raw: Record<string, unknown> =
    pluginConfig != null && typeof pluginConfig === "object"
      ? (pluginConfig as Record<string, unknown>)
      : {};

  // Env var overrides
  const envSecretKey = process.env.SHROUD_SECRET_KEY;
  const envSalt = process.env.SHROUD_PERSISTENT_SALT;
  const envTenantId = process.env.SHROUD_TENANT_ID;
  const envSharedStore = process.env.SHROUD_SHARED_STORE;

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

  // Validate lockedCategories against Category enum
  const categoryValues = new Set(Object.values(Category));
  const lockedRaw = Array.isArray(raw.lockedCategories)
    ? (raw.lockedCategories as string[])
    : [];
  const lockedCategories = lockedRaw.filter((c) =>
    categoryValues.has(c as Category),
  ) as Category[];

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

    // --- Enterprise features ---

    // Feature 1: Multi-tenant
    tenantId:
      envTenantId ??
      (typeof raw.tenantId === "string" ? raw.tenantId : ""),

    // Feature 3: Tool chain depth
    maxToolDepth:
      typeof raw.maxToolDepth === "number" ? raw.maxToolDepth : 10,

    // Feature 4: Compliance-mode
    lockedCategories,

    // Feature 5: Exposure tracking
    exposureWindow:
      typeof raw.exposureWindow === "number" ? raw.exposureWindow : 60_000,
    exposureThresholds:
      raw.exposureThresholds != null && typeof raw.exposureThresholds === "object"
        ? (raw.exposureThresholds as Record<string, number>)
        : {},
    exposureGlobalThreshold:
      typeof raw.exposureGlobalThreshold === "number"
        ? raw.exposureGlobalThreshold
        : 100,

    // Feature 7: Policy file
    policyFile:
      typeof raw.policyFile === "string" ? raw.policyFile : "",

    // Feature 8: Redaction level
    redactionLevel,

    // Feature 9: Shared store
    sharedStorePath:
      envSharedStore ??
      (typeof raw.sharedStorePath === "string" ? raw.sharedStorePath : ""),
    sharedStoreTtlMs:
      typeof raw.sharedStoreTtlMs === "number" ? raw.sharedStoreTtlMs : 5000,

    // Feature 10: Provenance tagging
    provenanceTagging:
      typeof raw.provenanceTagging === "boolean" ? raw.provenanceTagging : false,

    // Feature 2: Session handoff
    sessionHandoff:
      typeof raw.sessionHandoff === "boolean" ? raw.sessionHandoff : false,

    // Dry-run mode
    dryRun:
      typeof raw.dryRun === "boolean" ? raw.dryRun : false,

    // LRU store eviction (0 = unlimited)
    maxStoreMappings:
      typeof raw.maxStoreMappings === "number" ? raw.maxStoreMappings : 0,

    // --- Key rotation ---
    keys: Array.isArray(raw.keys) ? (raw.keys as ShroudConfig["keys"]) : [],
    activeKeyVersion:
      typeof raw.activeKeyVersion === "number" ? raw.activeKeyVersion : 0,

    // --- SIEM integration ---
    siemWebhooks: Array.isArray(raw.siemWebhooks)
      ? (raw.siemWebhooks as ShroudConfig["siemWebhooks"])
      : [],
    siemBatchSize:
      typeof raw.siemBatchSize === "number" ? raw.siemBatchSize : 100,
    siemFlushIntervalMs:
      typeof raw.siemFlushIntervalMs === "number" ? raw.siemFlushIntervalMs : 30_000,
    siemMaxRetries:
      typeof raw.siemMaxRetries === "number" ? raw.siemMaxRetries : 3,
    siemRetryBackoffMs:
      typeof raw.siemRetryBackoffMs === "number" ? raw.siemRetryBackoffMs : 1000,
    siemEventFormat:
      raw.siemEventFormat === "cef" ? "cef" : "json",

    // --- Hot-reload ---
    hotReload:
      typeof raw.hotReload === "boolean" ? raw.hotReload : false,
    customPatternsFile:
      typeof raw.customPatternsFile === "string" ? raw.customPatternsFile : "",
    hotReloadDebounceMs:
      typeof raw.hotReloadDebounceMs === "number" ? raw.hotReloadDebounceMs : 1000,

    // --- Per-session isolation ---
    sessionIsolation:
      typeof raw.sessionIsolation === "boolean" ? raw.sessionIsolation : false,

    // --- Active monitoring ---
    monitorEnabled:
      typeof raw.monitorEnabled === "boolean" ? raw.monitorEnabled : false,
    monitorRateWindowMs:
      typeof raw.monitorRateWindowMs === "number" ? raw.monitorRateWindowMs : 60_000,
    monitorSpikeMultiplier:
      typeof raw.monitorSpikeMultiplier === "number" ? raw.monitorSpikeMultiplier : 3.0,
    monitorMaxAlerts:
      typeof raw.monitorMaxAlerts === "number" ? raw.monitorMaxAlerts : 500,
  };

  // Env var support: SHROUD_SIEM_WEBHOOK_URL for single-endpoint quick setup
  const envSiemUrl = process.env.SHROUD_SIEM_WEBHOOK_URL;
  if (envSiemUrl && config.siemWebhooks.length === 0) {
    config.siemWebhooks.push({
      url: envSiemUrl,
      authHeader: process.env.SHROUD_SIEM_WEBHOOK_AUTH,
    });
  }

  // Env var support: SHROUD_KEYS for JSON-encoded key array
  const envKeys = process.env.SHROUD_KEYS;
  if (envKeys && config.keys.length === 0) {
    try {
      config.keys = JSON.parse(envKeys);
    } catch {
      console.warn("[shroud] WARNING: SHROUD_KEYS env var is not valid JSON — ignored.");
    }
  }

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

  // exposureWindow sanity
  if (config.exposureWindow < 1000 && Object.keys(config.exposureThresholds).length > 0) {
    issues.push({ severity: "warning", field: "exposureWindow", message: `exposureWindow=${config.exposureWindow}ms is very short — exposure alerts may fire constantly.` });
  }

  // lockedCategories with invalid values already stripped, but warn if input had unknowns
  const categoryValues = new Set(Object.values(Category));
  for (const cat of config.lockedCategories) {
    if (!categoryValues.has(cat)) {
      issues.push({ severity: "warning", field: "lockedCategories", message: `Unknown locked category "${cat}" — ignored. Valid: ${[...categoryValues].join(", ")}` });
    }
  }

  // Policy file check (only warn — may not be accessible at validation time)
  if (config.policyFile) {
    try {
      const { existsSync } = require("node:fs");
      if (!existsSync(config.policyFile)) {
        issues.push({ severity: "warning", field: "policyFile", message: `Policy file "${config.policyFile}" not found.` });
      }
    } catch {
      // skip if fs not available
    }
  }

  // sharedStorePath + tenantId conflict
  if (config.sharedStorePath && config.tenantId) {
    issues.push({ severity: "warning", field: "sharedStorePath", message: "Both sharedStorePath and tenantId are set — sharedStorePath takes precedence, tenantId is ignored." });
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

  // --- Key rotation validation ---
  if (config.keys.length > 0) {
    const versions = config.keys.map((k) => k.version);
    if (new Set(versions).size !== versions.length) {
      issues.push({ severity: "error", field: "keys", message: "Key versions must be unique." });
    }
    for (const k of config.keys) {
      if (!k.key || k.key.length < 16) {
        issues.push({ severity: "error", field: "keys", message: `Key version ${k.version} is shorter than 16 chars.` });
      }
    }
    const nonExpired = config.keys.filter((k) => {
      if (!k.expiresAt) return true;
      return new Date(k.expiresAt).getTime() > Date.now();
    });
    if (nonExpired.length === 0) {
      issues.push({ severity: "error", field: "keys", message: "All keys are expired — no valid key available." });
    }
    const expired = config.keys.filter((k) => k.expiresAt && new Date(k.expiresAt).getTime() <= Date.now());
    if (expired.length > 0) {
      issues.push({ severity: "warning", field: "keys", message: `${expired.length} key(s) are expired.` });
    }
    if (config.activeKeyVersion > 0) {
      const active = config.keys.find((k) => k.version === config.activeKeyVersion);
      if (!active) {
        issues.push({ severity: "error", field: "activeKeyVersion", message: `Active key version ${config.activeKeyVersion} not found in keys array.` });
      } else if (active.retired) {
        issues.push({ severity: "warning", field: "activeKeyVersion", message: `Active key version ${config.activeKeyVersion} is retired.` });
      }
    }
    issues.push({ severity: "info", field: "keys", message: `Key rotation active: ${config.keys.length} key(s), ${nonExpired.length} valid.` });
  }

  // --- SIEM validation ---
  if (config.siemWebhooks.length > 0) {
    for (const wh of config.siemWebhooks) {
      if (!wh.url.startsWith("https://") && !wh.url.startsWith("http://localhost")) {
        issues.push({ severity: "warning", field: "siemWebhooks", message: `Webhook URL "${wh.url}" is not HTTPS — credentials may be exposed in transit.` });
      }
    }
    if (config.siemBatchSize < 1) {
      issues.push({ severity: "error", field: "siemBatchSize", message: "siemBatchSize must be >= 1." });
    }
    if (config.siemFlushIntervalMs < 5000 && config.siemFlushIntervalMs > 0) {
      issues.push({ severity: "warning", field: "siemFlushIntervalMs", message: `siemFlushIntervalMs=${config.siemFlushIntervalMs}ms is very short — may overload endpoints.` });
    }
    issues.push({ severity: "info", field: "siemWebhooks", message: `SIEM push active: ${config.siemWebhooks.length} endpoint(s).` });
  }

  // --- Hot-reload validation ---
  if (config.hotReload) {
    issues.push({ severity: "info", field: "hotReload", message: "Hot-reload enabled — detection rules will auto-update on file changes." });
  }

  // --- Session isolation ---
  if (config.sessionIsolation) {
    issues.push({ severity: "info", field: "sessionIsolation", message: "Per-session isolation enabled." });
  }

  // --- Monitor validation ---
  if (config.monitorEnabled) {
    if (config.monitorSpikeMultiplier < 1) {
      issues.push({ severity: "warning", field: "monitorSpikeMultiplier", message: "monitorSpikeMultiplier < 1 will trigger on any detection — likely too sensitive." });
    }
    issues.push({ severity: "info", field: "monitorEnabled", message: "Active monitoring pipeline enabled." });
  }

  return issues;
}
