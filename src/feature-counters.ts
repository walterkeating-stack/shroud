import type { ShroudConfig } from "./types.js";

export type FeatureOutcome = "observed" | "suppressed" | "flagged" | "blocked";

export interface FeatureDefinition {
  id: string;
  label: string;
  category: "privacy" | "deterministic" | "behavioral" | "learned" | "policy" | "tripwire" | "runtime";
  enabled: boolean;
  explanation: string;
  thresholds?: Record<string, unknown>;
}

export interface FeatureCounterState extends FeatureDefinition {
  counters: {
    evaluated: number;
    observed: number;
    suppressed: number;
    flagged: number;
    blocked: number;
  };
  lastOutcome: FeatureOutcome | "inactive";
  lastExplanation: string;
  lastSuppressionReason: string | null;
  lastEvaluatedAt: number | null;
  lastTriggeredAt: number | null;
}

export interface FeatureRecordInput {
  agentBuildId?: string;
  agentLabel?: string;
  explanation?: string;
  suppressionReason?: string;
  thresholds?: Record<string, unknown>;
  enabled?: boolean;
  outcome?: FeatureOutcome;
}

function initialState(def: FeatureDefinition): FeatureCounterState {
  return {
    ...def,
    counters: {
      evaluated: 0,
      observed: 0,
      suppressed: 0,
      flagged: 0,
      blocked: 0,
    },
    lastOutcome: def.enabled ? "inactive" : "inactive",
    lastExplanation: def.explanation,
    lastSuppressionReason: null,
    lastEvaluatedAt: null,
    lastTriggeredAt: null,
  };
}

function applyRecord(
  state: FeatureCounterState,
  input: FeatureRecordInput,
): void {
  const now = Date.now();
  state.counters.evaluated++;
  state.lastEvaluatedAt = now;
  if (input.explanation) state.lastExplanation = input.explanation;
  if (input.thresholds) state.thresholds = input.thresholds;
  if (typeof input.enabled === "boolean") state.enabled = input.enabled;

  const outcome = input.outcome ?? "observed";
  state.lastOutcome = outcome;
  if (outcome === "suppressed") {
    state.counters.suppressed++;
    state.lastSuppressionReason = input.suppressionReason || "suppressed";
    return;
  }

  state.lastSuppressionReason = null;
  if (outcome === "observed") state.counters.observed++;
  if (outcome === "flagged") {
    state.counters.flagged++;
    state.lastTriggeredAt = now;
  }
  if (outcome === "blocked") {
    state.counters.blocked++;
    state.lastTriggeredAt = now;
  }
}

const FEATURE_DEFINITIONS = (config: ShroudConfig): FeatureDefinition[] => [
  {
    id: "privacy_obfuscation",
    label: "Privacy Obfuscation",
    category: "privacy",
    enabled: true,
    explanation: "Deterministically replaces sensitive values before LLM calls.",
    thresholds: { minConfidence: config.minConfidence, redactionLevel: config.redactionLevel },
  },
  {
    id: "injection_signatures",
    label: "Injection Signatures",
    category: "deterministic",
    enabled: config.injectionDetection !== "off",
    explanation: "Regex and signature-based prompt injection scanning on requests and responses.",
    thresholds: { mode: config.injectionDetection, minSeverity: config.injectionMinSeverity },
  },
  {
    id: "tool_guard",
    label: "Tool Guard",
    category: "deterministic",
    enabled: config.injectionDetection !== "off",
    explanation: "Scans tool calls for dangerous commands, exfiltration, or destructive actions.",
  },
  {
    id: "sandbox_boundary",
    label: "Sandbox Boundary",
    category: "policy",
    enabled: true,
    explanation: "Checks whether tool usage violates the agent registry sandbox boundary.",
  },
  {
    id: "contract_enforcement",
    label: "Capability Contracts",
    category: "policy",
    enabled: true,
    explanation: "Enforces per-role allowed tool families, channels, delegation targets, and egress policy.",
  },
  {
    id: "intent_lease",
    label: "Intent Leases",
    category: "policy",
    enabled: true,
    explanation: "Constrains delegated child-agent work to a short-lived allowed scope.",
  },
  {
    id: "trust_zone_guard",
    label: "Trust-Zone Guard",
    category: "policy",
    enabled: true,
    explanation: "Prevents low-trust prompt content from overriding higher-trust instructions on privileged tools.",
  },
  {
    id: "tool_alignment",
    label: "Tool Alignment",
    category: "behavioral",
    enabled: config.injectionDetection !== "off",
    explanation: "Compares selected tools against extracted user intent.",
  },
  {
    id: "egress_attempt",
    label: "Egress Intent",
    category: "behavioral",
    enabled: config.injectionDetection !== "off",
    explanation: "Flags outbound communication or network egress inconsistent with the stated task.",
  },
  {
    id: "tool_sequence",
    label: "Tool Sequence",
    category: "behavioral",
    enabled: config.injectionDetection !== "off",
    explanation: "Tracks improbable local tool-order anomalies within a turn.",
  },
  {
    id: "result_validation",
    label: "Result Validation",
    category: "deterministic",
    enabled: config.injectionDetection !== "off",
    explanation: "Checks whether tool results contain risky sensitive patterns relative to user intent.",
  },
  {
    id: "exfil_chain",
    label: "Exfiltration Chain",
    category: "deterministic",
    enabled: config.injectionDetection !== "off",
    explanation: "Detects sensitive tool results followed by network or communication steps.",
  },
  {
    id: "novel_egress",
    label: "Novel Egress",
    category: "behavioral",
    enabled: config.injectionDetection !== "off",
    explanation: "Flags first-time use of communication or network tools in a session.",
  },
  {
    id: "honeypot",
    label: "Honeypots",
    category: "tripwire",
    enabled: config.honeypotEnabled,
    explanation: "Planted fake secrets; any use is a confirmed injection attempt.",
    thresholds: { rate: config.honeypotRate },
  },
  {
    id: "phantom_tools",
    label: "Phantom Tools",
    category: "tripwire",
    enabled: config.honeypotEnabled,
    explanation: "Fake tools exposed only to catch injected tool invocations.",
  },
  {
    id: "canary",
    label: "Canaries",
    category: "tripwire",
    enabled: config.canaryEnabled,
    explanation: "Planted prompt canaries and behavioural canaries to detect model-side prompt leakage or hijack.",
    thresholds: { nearMatchDistance: config.canaryNearMatchDistance },
  },
  {
    id: "prompt_fingerprint",
    label: "Prompt Fingerprint Drift",
    category: "behavioral",
    enabled: config.driftEnabled,
    explanation: "Compares current system prompt against the stored prompt baseline for the agent.",
    thresholds: { similarity: 0.85, warmup: config.profilingMinBaseline },
  },
  {
    id: "semantic_drift",
    label: "Semantic Drift",
    category: "behavioral",
    enabled: config.driftEnabled,
    explanation: "Measures similarity between the current tool trajectory and the original user intent.",
    thresholds: { similarity: config.driftThreshold, suddenTurn: config.driftSuddenTurnDelta },
  },
  {
    id: "causal_coherence",
    label: "Causal Coherence",
    category: "behavioral",
    enabled: config.coherenceEnabled,
    explanation: "Checks whether tool actions make sense given the immediately preceding tool results.",
    thresholds: { zScore: config.coherenceZScore },
  },
  {
    id: "transformer",
    label: "Transformer Predictor",
    category: "learned",
    enabled: config.transformerEnabled,
    explanation: "Sequence model scoring tool-call surprise and learned anomaly heads.",
    thresholds: {
      anomaly: config.transformerThreshold,
      windowSize: config.transformerWindowSize,
      intentAttention: config.transformerIntentAttentionThreshold,
    },
  },
  {
    id: "delegation_drift",
    label: "Delegation Drift",
    category: "behavioral",
    enabled: config.intentChainEnabled,
    explanation: "Checks whether delegated child-agent behavior drifts away from the parent intent.",
    thresholds: { drift: config.delegationDriftThreshold },
  },
  {
    id: "url_correlation",
    label: "URL Correlation",
    category: "behavioral",
    enabled: config.urlCorrelationEnabled,
    explanation: "Flags fetched URLs previously associated with malicious or hijacked workflows.",
  },
  {
    id: "shadow_execution",
    label: "Shadow Execution",
    category: "learned",
    enabled: config.shadowExecutionEnabled,
    explanation: "Runs suspicious tool calls in a fake sandbox to observe the likely attack chain before execution.",
    thresholds: { maxSteps: config.shadowExecutionMaxSteps, timeoutMs: config.shadowExecutionTimeoutMs },
  },
  {
    id: "red_team",
    label: "Adversarial Stress Test",
    category: "learned",
    enabled: config.redTeamEnabled,
    explanation: "Proactively attacks detection pipeline with synthetic scenarios to find blind spots.",
    thresholds: { maxScenarios: config.redTeamMaxScenarios, mutations: config.redTeamMutationCount },
  },
  {
    id: "immune_response",
    label: "Collective Immune Response",
    category: "learned",
    enabled: config.immuneEnabled,
    explanation: "Propagates attack fingerprints from confirmed incidents to tighten detection across all agents.",
    thresholds: { ttlSec: config.immuneTtlSec, matchThreshold: config.immuneMatchThreshold },
  },
];

export class FeatureCounterRegistry {
  private _global = new Map<string, FeatureCounterState>();
  private _perAgent = new Map<string, Map<string, FeatureCounterState>>();

  constructor(definitions: FeatureDefinition[]) {
    for (const def of definitions) this.define(def);
  }

  define(def: FeatureDefinition): void {
    this._global.set(def.id, initialState(def));
  }

  record(featureId: string, input: FeatureRecordInput = {}): void {
    const globalState = this._global.get(featureId);
    if (!globalState) return;
    applyRecord(globalState, input);

    if (!input.agentBuildId && !input.agentLabel) return;
    const key = input.agentBuildId || `label:${input.agentLabel}`;
    let featureMap = this._perAgent.get(key);
    if (!featureMap) {
      featureMap = new Map<string, FeatureCounterState>();
      this._perAgent.set(key, featureMap);
    }
    let state = featureMap.get(featureId);
    if (!state) {
      state = initialState(globalState);
      featureMap.set(featureId, state);
    }
    applyRecord(state, input);
  }

  getAll(): FeatureCounterState[] {
    return [...this._global.values()].sort((a, b) => a.label.localeCompare(b.label));
  }

  getForAgent(agentBuildId?: string, agentLabel?: string): FeatureCounterState[] {
    const key = agentBuildId || (agentLabel ? `label:${agentLabel}` : "");
    if (!key) return this.getAll();
    const featureMap = this._perAgent.get(key);
    if (!featureMap) return [];
    return [...featureMap.values()].sort((a, b) => a.label.localeCompare(b.label));
  }

  getSummary() {
    const features = this.getAll();
    return {
      total: features.length,
      enabled: features.filter(f => f.enabled).length,
      evaluated: features.reduce((sum, f) => sum + f.counters.evaluated, 0),
      suppressed: features.reduce((sum, f) => sum + f.counters.suppressed, 0),
      flagged: features.reduce((sum, f) => sum + f.counters.flagged, 0),
      blocked: features.reduce((sum, f) => sum + f.counters.blocked, 0),
    };
  }
}

export function createFeatureCounterRegistry(config: ShroudConfig): FeatureCounterRegistry {
  return new FeatureCounterRegistry(FEATURE_DEFINITIONS(config));
}
