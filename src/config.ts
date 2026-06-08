/**
 * Configuration resolver for the Shroud plugin.
 *
 * Merges plugin config with environment variables and provides defaults.
 */

import { randomBytes } from "node:crypto";
import { join } from "node:path";

import { Category, ShroudConfig, FieldScopingConfig, AgentsConfig, AgentMode } from "./types.js";
import type { RedactionLevel } from "./redaction.js";
import { resolveRuntimePaths } from "./runtime.js";

export const IS_TEST = process.env.NODE_ENV === "test";

export function resolveConfig(pluginConfig?: unknown): ShroudConfig {
  const raw: Record<string, unknown> =
    pluginConfig != null && typeof pluginConfig === "object"
      ? (pluginConfig as Record<string, unknown>)
      : {};
  const runtime = resolveRuntimePaths(undefined, process.env);

  // Env var overrides
  const envSecretKey = process.env.SHROUD_SECRET_KEY;
  const envSalt = process.env.SHROUD_PERSISTENT_SALT;
  const dashboardFlag =
    typeof raw.dashboardEnabled === "boolean"
      ? raw.dashboardEnabled
      : typeof raw.dashboard === "boolean"
        ? raw.dashboard
        : false;

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
    canaryEnabled: (() => {
      const env = process.env.SHROUD_CANARY_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      return typeof raw.canaryEnabled === "boolean" ? raw.canaryEnabled : false;
    })(),
    honeypotEnabled: (() => {
      const env = process.env.SHROUD_HONEYPOT_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      return typeof raw.honeypotEnabled === "boolean" ? raw.honeypotEnabled : true;
    })(),
    honeypotRate: (() => {
      const env = process.env.SHROUD_HONEYPOT_RATE;
      if (env) {
        const parsed = parseFloat(env);
        if (!isNaN(parsed)) return Math.max(0, Math.min(1, parsed));
      }
      if (typeof raw.honeypotRate === "number") return Math.max(0, Math.min(1, raw.honeypotRate));
      return 0.25;
    })(),
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

    rules:
      raw.rules != null && typeof raw.rules === "object"
        ? (raw.rules as ShroudConfig["rules"])
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
      if (env === "enforcing") return "active";
      const val = raw.profilingMode;
      if (val === "learning" || val === "active" || val === "strict") return val as "learning" | "active" | "strict";
      if (val === "enforcing") return "active";
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
        : join(runtime.stateDir, "profiles");
    })(),

    // --- Canary security extensions ---
    canarySystemInjection: (() => {
      const env = process.env.SHROUD_CANARY_SYSTEM;
      if (env === "true") return true;
      if (env === "false") return false;
      return typeof raw.canarySystemInjection === "boolean" ? raw.canarySystemInjection : false;
    })(),
    canaryBehavioural: (() => {
      const env = process.env.SHROUD_CANARY_BEHAVIOURAL;
      if (env === "true") return true;
      if (env === "false") return false;
      return typeof raw.canaryBehavioural === "boolean" ? raw.canaryBehavioural : false;
    })(),
    canaryNearMatchDistance:
      typeof raw.canaryNearMatchDistance === "number" ? raw.canaryNearMatchDistance : 2,

    // --- Hot-refresh signatures ---
    signaturesUrl: process.env.SHROUD_SIGNATURES_URL
      || (typeof raw.signaturesUrl === "string" ? raw.signaturesUrl : null),
    signaturesFile: process.env.SHROUD_SIGNATURES_FILE
      || (typeof raw.signaturesFile === "string" ? raw.signaturesFile : null),
    signaturesRefreshSec: (() => {
      const env = process.env.SHROUD_SIGNATURES_REFRESH;
      if (env) return parseInt(env, 10) || 3600;
      return typeof raw.signaturesRefreshSec === "number" ? raw.signaturesRefreshSec : 3600;
    })(),

    // --- SIEM ---
    siemWebhookUrl: (() => {
      const env = process.env.SHROUD_SIEM_WEBHOOK_URL;
      if (env) return env;
      return typeof raw.siemWebhookUrl === "string" ? raw.siemWebhookUrl : null;
    })(),
    siemWebhookAuth: (() => {
      const env = process.env.SHROUD_SIEM_WEBHOOK_AUTH;
      if (env) return env;
      return typeof raw.siemWebhookAuth === "string" ? raw.siemWebhookAuth : null;
    })(),
    siemJsonlPath: (() => {
      const env = process.env.SHROUD_SIEM_JSONL_PATH;
      if (env) return env;
      return typeof raw.siemJsonlPath === "string" ? raw.siemJsonlPath : null;
    })(),
    siemBatchSize:
      typeof raw.siemBatchSize === "number" ? raw.siemBatchSize : 10,

    // --- Semantic drift detection ---
    driftEnabled: (() => {
      const env = process.env.SHROUD_DRIFT_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.driftEnabled === "boolean") return raw.driftEnabled;
      // Auto-enable when dashboard is active
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    driftThreshold: (() => {
      const env = process.env.SHROUD_DRIFT_THRESHOLD;
      if (env) return parseFloat(env) || 0.15;
      return typeof raw.driftThreshold === "number" ? raw.driftThreshold : 0.15;
    })(),
    driftSuddenTurnDelta: (() => {
      const env = process.env.SHROUD_DRIFT_SUDDEN_TURN;
      if (env) return parseFloat(env) || 0.3;
      return typeof raw.driftSuddenTurnDelta === "number" ? raw.driftSuddenTurnDelta : 0.3;
    })(),

    // --- Shadow execution ---
    shadowExecutionEnabled: (() => {
      const env = process.env.SHROUD_SHADOW_EXECUTION;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.shadowExecutionEnabled === "boolean") return raw.shadowExecutionEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    shadowExecutionMaxSteps: (() => {
      const env = process.env.SHROUD_SHADOW_MAX_STEPS;
      if (env === "1") return 1 as const;
      if (env === "2") return 2 as const;
      return (raw.shadowExecutionMaxSteps === 1 || raw.shadowExecutionMaxSteps === 2)
        ? raw.shadowExecutionMaxSteps as 1 | 2 : 2 as const;
    })(),
    shadowExecutionTimeoutMs: (() => {
      const env = process.env.SHROUD_SHADOW_TIMEOUT;
      if (env) return parseInt(env, 10) || 15000;
      return typeof raw.shadowExecutionTimeoutMs === "number" ? raw.shadowExecutionTimeoutMs : 15000;
    })(),

    // --- Dashboard ---
    dashboardEnabled: (() => {
      const env = process.env.SHROUD_DASHBOARD;
      if (env === "true") return true;
      if (env === "false") return false;
      return dashboardFlag;
    })(),
    dashboardPort: (() => {
      const env = process.env.SHROUD_DASHBOARD_PORT;
      if (env) return parseInt(env, 10) || 9380;
      return typeof raw.dashboardPort === "number" ? raw.dashboardPort : 9380;
    })(),
    dashboardBind: (() => {
      const env = process.env.SHROUD_DASHBOARD_BIND;
      if (env) return env;
      return typeof raw.dashboardBind === "string" && raw.dashboardBind.trim()
        ? raw.dashboardBind
        : runtime.dashboardBind;
    })(),

    // --- Causal coherence tracking ---
    coherenceEnabled: (() => {
      const env = process.env.SHROUD_COHERENCE_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.coherenceEnabled === "boolean") return raw.coherenceEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    coherenceZScore: (() => {
      const env = process.env.SHROUD_COHERENCE_ZSCORE;
      if (env) return parseFloat(env) || 3.0;
      return typeof raw.coherenceZScore === "number" ? raw.coherenceZScore : 3.0;
    })(),
    coherenceResultLimit: (() => {
      const env = process.env.SHROUD_COHERENCE_RESULT_LIMIT;
      if (env) return parseInt(env, 10) || 500;
      return typeof raw.coherenceResultLimit === "number" ? raw.coherenceResultLimit : 500;
    })(),

    // --- Vector store + clustering ---
    vectorStoreEnabled: (() => {
      const env = process.env.SHROUD_VECTOR_STORE_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.vectorStoreEnabled === "boolean") return raw.vectorStoreEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    vectorStoreMax: (() => {
      const env = process.env.SHROUD_VECTOR_STORE_MAX;
      if (env) return parseInt(env, 10) || 10000;
      return typeof raw.vectorStoreMax === "number" ? raw.vectorStoreMax : 10000;
    })(),
    clusteringEnabled: (() => {
      const env = process.env.SHROUD_CLUSTERING_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.clusteringEnabled === "boolean") return raw.clusteringEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    urlCorrelationEnabled: (() => {
      const env = process.env.SHROUD_URL_CORRELATION_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.urlCorrelationEnabled === "boolean") return raw.urlCorrelationEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),

    // --- Multi-agent intent chain ---
    intentChainEnabled: (() => {
      const env = process.env.SHROUD_INTENT_CHAIN_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.intentChainEnabled === "boolean") return raw.intentChainEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    delegationDriftThreshold: (() => {
      const env = process.env.SHROUD_DELEGATION_DRIFT_THRESHOLD;
      if (env) return parseFloat(env) || 0.10;
      return typeof raw.delegationDriftThreshold === "number" ? raw.delegationDriftThreshold : 0.10;
    })(),

    // --- Adversarial stress test (red team) ---
    redTeamEnabled: (() => {
      const env = process.env.SHROUD_RED_TEAM_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.redTeamEnabled === "boolean") return raw.redTeamEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    redTeamMaxScenarios: (() => {
      const env = process.env.SHROUD_RED_TEAM_MAX_SCENARIOS;
      if (env) return parseInt(env, 10) || 50;
      return typeof raw.redTeamMaxScenarios === "number" ? raw.redTeamMaxScenarios : 50;
    })(),
    redTeamMutationCount: (() => {
      const env = process.env.SHROUD_RED_TEAM_MUTATIONS;
      if (env) return parseInt(env, 10) || 5;
      return typeof raw.redTeamMutationCount === "number" ? raw.redTeamMutationCount : 5;
    })(),
    redTeamIntervalSessions: (() => {
      const env = process.env.SHROUD_RED_TEAM_INTERVAL;
      if (env) return parseInt(env, 10) || 10;
      return typeof raw.redTeamIntervalSessions === "number" ? raw.redTeamIntervalSessions : 10;
    })(),

    // --- Collective immune response ---
    immuneEnabled: (() => {
      const env = process.env.SHROUD_IMMUNE_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.immuneEnabled === "boolean") return raw.immuneEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    immuneTtlSec: (() => {
      const env = process.env.SHROUD_IMMUNE_TTL;
      if (env) return parseInt(env, 10) || 86400;
      return typeof raw.immuneTtlSec === "number" ? raw.immuneTtlSec : 86400;
    })(),
    immuneSigmaTightenFactor: (() => {
      const env = process.env.SHROUD_IMMUNE_SIGMA_TIGHTEN;
      if (env) return parseFloat(env) || 0.5;
      return typeof raw.immuneSigmaTightenFactor === "number" ? raw.immuneSigmaTightenFactor : 0.5;
    })(),
    immuneMatchThreshold: (() => {
      const env = process.env.SHROUD_IMMUNE_MATCH_THRESHOLD;
      if (env) return parseFloat(env) || 0.7;
      return typeof raw.immuneMatchThreshold === "number" ? raw.immuneMatchThreshold : 0.7;
    })(),
    immuneMaxAntibodies: (() => {
      const env = process.env.SHROUD_IMMUNE_MAX_ANTIBODIES;
      if (env) return parseInt(env, 10) || 100;
      return typeof raw.immuneMaxAntibodies === "number" ? raw.immuneMaxAntibodies : 100;
    })(),

    // --- Transformer sequence predictor ---
    transformerEnabled: (() => {
      const env = process.env.SHROUD_TRANSFORMER_ENABLED;
      if (env === "true") return true;
      if (env === "false") return false;
      if (typeof raw.transformerEnabled === "boolean") return raw.transformerEnabled;
      const dash = process.env.SHROUD_DASHBOARD;
      if (dash === "true") return true;
      if (dash === "false") return false;
      return dashboardFlag;
    })(),
    transformerThreshold: (() => {
      const env = process.env.SHROUD_TRANSFORMER_THRESHOLD;
      if (env) return parseFloat(env) || 0.85;
      return typeof raw.transformerThreshold === "number" ? raw.transformerThreshold : 0.85;
    })(),
    transformerWindowSize: (() => {
      const env = process.env.SHROUD_TRANSFORMER_WINDOW;
      if (env) return parseInt(env) || 10;
      return typeof raw.transformerWindowSize === "number" ? raw.transformerWindowSize : 10;
    })(),
    transformerMinSessions: (() => {
      const env = process.env.SHROUD_TRANSFORMER_MIN_SESSIONS;
      if (env) return parseInt(env) || 30;
      return typeof raw.transformerMinSessions === "number" ? raw.transformerMinSessions : 30;
    })(),
    transformerTrainInterval: (() => {
      const env = process.env.SHROUD_TRANSFORMER_TRAIN_INTERVAL;
      if (env) return parseInt(env) || 50;
      return typeof raw.transformerTrainInterval === "number" ? raw.transformerTrainInterval : 50;
    })(),
    transformerIntentAttentionThreshold: (() => {
      const env = process.env.SHROUD_TRANSFORMER_INTENT_ATTENTION_THRESHOLD;
      if (env) return parseFloat(env) || 0.05;
      return typeof raw.transformerIntentAttentionThreshold === "number" ? raw.transformerIntentAttentionThreshold : 0.05;
    })(),

    // --- Per-agent ob/deob mode ---
    agents: (() => {
      const a = raw.agents;
      if (!a || typeof a !== "object") return {};
      const out: AgentsConfig = {};
      for (const [label, rule] of Object.entries(a as Record<string, unknown>)) {
        if (!rule || typeof rule !== "object") continue;
        const m = (rule as Record<string, unknown>).mode;
        if (m === "enforce" || m === "shadow" || m === "off") {
          out[label] = { mode: m as AgentMode };
        }
      }
      return out;
    })(),
    dashboardModeControl: (() => {
      const env = process.env.SHROUD_DASHBOARD_MODE_CONTROL;
      if (env === "mutate" || env === "readonly") return env;
      const val = raw.dashboardModeControl;
      if (val === "mutate" || val === "readonly") return val as "mutate" | "readonly";
      return "readonly";
    })(),

    // --- Field scoping (optional, backward compatible) ---
    fieldScoping: (() => {
      const fs = raw.fieldScoping;
      if (!fs || typeof fs !== "object") return undefined;
      const fsc = fs as Record<string, unknown>;
      const toolFields: Record<string, { scanFields: string[] }> = {};
      if (fsc.toolFields && typeof fsc.toolFields === "object") {
        for (const [pattern, rule] of Object.entries(fsc.toolFields as Record<string, unknown>)) {
          if (rule && typeof rule === "object" && Array.isArray((rule as any).scanFields)) {
            toolFields[pattern] = { scanFields: (rule as any).scanFields.filter((f: unknown) => typeof f === "string") };
          }
        }
      }
      return {
        toolFields,
        neverScanFields: Array.isArray(fsc.neverScanFields)
          ? (fsc.neverScanFields as unknown[]).filter((f): f is string => typeof f === "string")
          : [],
        defaultScanFields: Array.isArray(fsc.defaultScanFields)
          ? (fsc.defaultScanFields as unknown[]).filter((f): f is string => typeof f === "string")
          : [],
        useContractExemptions: typeof fsc.useContractExemptions === "boolean" ? fsc.useContractExemptions : false,
      };
    })(),
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

  // Rules as code
  if (config.rules && Object.keys(config.rules).length > 0) {
    const ruleCount = Object.keys(config.rules).length;
    const disabled = Object.values(config.rules).filter(r => r.enabled === false).length;
    const custom = Object.entries(config.rules).filter(([, r]) => r.pattern && r.enabled !== false).length;
    issues.push({ severity: "info", field: "rules", message: `${ruleCount} rule(s) configured (${custom} custom/override, ${disabled} disabled).` });
    // Validate regex patterns
    for (const [name, rule] of Object.entries(config.rules)) {
      if (rule.pattern) {
        try { new RegExp(rule.pattern); } catch {
          issues.push({ severity: "error", field: "rules", message: `Rule "${name}" has invalid regex pattern.` });
        }
      }
    }
  }

  // Per-agent mode config
  const agentCount = Object.keys(config.agents).length;
  if (agentCount > 0) {
    const shadow = Object.values(config.agents).filter(a => a.mode === "shadow").length;
    const off = Object.values(config.agents).filter(a => a.mode === "off").length;
    issues.push({ severity: "info", field: "agents", message: `${agentCount} agent mode rule(s) configured (${shadow} shadow, ${off} off).` });
    if (off > 0) {
      issues.push({ severity: "warning", field: "agents", message: `${off} agent(s) have mode="off" — obfuscation is fully disabled for those agents.` });
    }
  }
  if (config.dashboardModeControl === "mutate") {
    issues.push({ severity: "warning", field: "dashboardModeControl", message: "Dashboard can mutate agent modes. Safe only on trusted localhost deployments." });
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
