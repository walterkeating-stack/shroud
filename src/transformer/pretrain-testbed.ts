/**
 * Pre-training testbed data for the mini transformer.
 *
 * Contains 20 healthy tool sequences, 15 attack traces (5 exfil, 5 privesc,
 * 5 recon), and deterministic intent vector generation. Used by seed-pretrain
 * to bootstrap Tiers 2 (contrastive) and 4 (threat heads) from cold start.
 */

import { fnv1a, xorshift32 } from "./linalg.js";
import { SelfLabelingFlywheel } from "./flywheel.js";
import { LearnedThreatClass } from "./threat-heads.js";
import type { AttackTrace } from "./contrastive.js";
import type { ThreatLabeledExample } from "./threat-heads.js";

// ── Healthy sequences ─────────────────────────────────────────

/** 20 healthy tool sequences from 3 agent profiles + general dev patterns. */
export const HEALTHY_SEQUENCES: string[][] = [
  // Research agent
  ["search", "read_file", "read_file", "write_file"],
  ["read_file", "search", "read_file", "edit", "write_file"],
  ["grep", "read_file", "read_file", "write_file", "write_file"],
  ["search", "read_file", "edit", "read_file", "write_file"],
  ["read_file", "read_file", "search", "write_file"],
  // Coaching / sessions agent
  ["sessions_list", "sessions_create", "sessions_send", "sessions_send"],
  ["memory_search", "sessions_create", "sessions_send", "memory_set"],
  ["sessions_list", "sessions_send", "memory_set"],
  ["memory_get", "sessions_send", "sessions_send", "memory_set"],
  ["sessions_create", "sessions_send", "sessions_send", "sessions_send"],
  // Personal assistant
  ["read_file", "edit", "exec", "read_file"],
  ["read_file", "edit", "read_file", "edit", "exec"],
  ["exec", "read_file", "edit"],
  ["glob", "read_file", "edit", "exec"],
  ["read_file", "read_file", "edit", "exec", "edit"],
  // General development patterns
  ["glob", "read_file", "edit", "exec", "read_file", "edit"],
  ["search", "read_file", "edit", "bash", "read_file"],
  ["read_file", "edit", "bash", "read_file", "edit", "bash"],
  ["grep", "read_file", "edit", "exec"],
  ["read_file", "write_file", "exec", "read_file"],
];

// ── Attack traces ─────────────────────────────────────────────

/** 5 exfiltration attack traces. */
const EXFIL_TRACES: AttackTrace[] = [
  {
    legitimatePrefix: ["read_file", "read_file"],
    hijackedSuffix: ["grep", "read_file", "web_fetch"],
    injectionPoint: 2,
    source: "honeypot" as const,
    threatType: "honeypot_api_key",
  },
  {
    legitimatePrefix: ["memory_search"],
    hijackedSuffix: ["memory_get", "memory_get", "message"],
    injectionPoint: 1,
    source: "phantom" as const,
    threatType: "phantom_data_upload",
  },
  {
    legitimatePrefix: ["glob", "read_file"],
    hijackedSuffix: ["read_file", "read_file", "web_fetch", "web_fetch"],
    injectionPoint: 2,
    source: "honeypot" as const,
    threatType: "honeypot_credential",
  },
  {
    legitimatePrefix: ["read_file"],
    hijackedSuffix: ["write_file", "exec", "web_fetch"],
    injectionPoint: 1,
    source: "shadow" as const,
    threatType: "shadow_exfil",
  },
  {
    legitimatePrefix: ["read_file", "edit"],
    hijackedSuffix: ["sessions_create", "sessions_send", "sessions_send"],
    injectionPoint: 2,
    source: "phantom" as const,
    threatType: "phantom_webhook_relay",
  },
];

/** 5 privilege escalation attack traces. */
const PRIVESC_TRACES: AttackTrace[] = [
  {
    legitimatePrefix: ["glob"],
    hijackedSuffix: ["exec", "bash", "exec", "bash"],
    injectionPoint: 1,
    source: "shadow" as const,
    threatType: "shadow_privesc",
  },
  {
    legitimatePrefix: ["read_file"],
    hijackedSuffix: ["edit", "cron_add", "exec"],
    injectionPoint: 1,
    source: "honeypot" as const,
    threatType: "honeypot_credential",
  },
  {
    legitimatePrefix: ["read_file"],
    hijackedSuffix: ["glob", "write_file", "exec"],
    injectionPoint: 1,
    source: "shadow" as const,
    threatType: "shadow_privesc",
  },
  {
    legitimatePrefix: ["read_file", "read_file"],
    hijackedSuffix: ["write_file", "write_file", "exec"],
    injectionPoint: 2,
    source: "shadow" as const,
    threatType: "shadow_privesc",
  },
  {
    legitimatePrefix: ["exec"],
    hijackedSuffix: ["sessions_spawn", "exec", "bash", "exec"],
    injectionPoint: 1,
    source: "phantom" as const,
    threatType: "phantom_api_relay",
  },
];

/** 5 reconnaissance attack traces. */
const RECON_TRACES: AttackTrace[] = [
  {
    legitimatePrefix: [],
    hijackedSuffix: ["glob", "glob", "glob", "read_file", "read_file"],
    injectionPoint: 0,
    source: "shadow" as const,
    threatType: "shadow_recon",
  },
  {
    legitimatePrefix: [],
    hijackedSuffix: ["exec", "exec", "exec", "exec"],
    injectionPoint: 0,
    source: "shadow" as const,
    threatType: "shadow_recon",
  },
  {
    legitimatePrefix: [],
    hijackedSuffix: ["memory_search", "memory_search", "memory_get", "memory_get", "memory_get"],
    injectionPoint: 0,
    source: "phantom" as const,
    threatType: "phantom_data_upload",
  },
  {
    legitimatePrefix: ["search", "read_file"],
    hijackedSuffix: ["search", "read_file", "search", "read_file"],
    injectionPoint: 2,
    source: "shadow" as const,
    threatType: "shadow_recon",
  },
  {
    legitimatePrefix: [],
    hijackedSuffix: ["cron_list", "exec", "glob", "exec", "read_file"],
    injectionPoint: 0,
    source: "shadow" as const,
    threatType: "shadow_recon",
  },
];

/** All 15 attack traces. */
export const ATTACK_TRACES: AttackTrace[] = [
  ...EXFIL_TRACES,
  ...PRIVESC_TRACES,
  ...RECON_TRACES,
];

// ── Intent vectors ────────────────────────────────────────────

/** Generate a deterministic 256-dim intent vector from a seed string. */
export function generateSyntheticIntent(seed: string): Float64Array {
  const vec = new Float64Array(256);
  const state = { s: fnv1a(seed) || 1 };
  let norm = 0;
  for (let i = 0; i < 256; i++) {
    // Sparse: only ~40% of dimensions non-zero
    const r = xorshift32(state);
    if ((r & 0xff) < 100) {
      vec[i] = 0;
    } else {
      vec[i] = ((r >>> 0) / 0xffffffff);
      norm += vec[i] * vec[i];
    }
  }
  // L2 normalize
  if (norm > 0) {
    const invNorm = 1 / Math.sqrt(norm);
    for (let i = 0; i < 256; i++) vec[i] *= invNorm;
  }
  return vec;
}

/** Generate intent vectors for healthy sequences (non-null) and attack sequences (null). */
export function generateTestbedIntents(
  healthySequences: string[][],
  attackTraces: AttackTrace[],
): Array<Float64Array | null> {
  const intents: Array<Float64Array | null> = [];
  // Healthy sequences get intent vectors
  for (let i = 0; i < healthySequences.length; i++) {
    intents.push(generateSyntheticIntent(`healthy-${i}-${healthySequences[i].join(",")}`));
  }
  // Attack sequences get null intent (injection with no user message)
  for (let i = 0; i < attackTraces.length; i++) {
    intents.push(null);
  }
  return intents;
}

// ── Threat labels ─────────────────────────────────────────────

/**
 * Generate threat-labeled examples from attack traces and healthy sequences
 * using the flywheel's label mapping logic.
 */
export function generateTestbedLabels(
  healthySequences: string[][],
  attackTraces: AttackTrace[],
): ThreatLabeledExample[] {
  const flywheel = new SelfLabelingFlywheel();
  const labels: ThreatLabeledExample[] = [];

  // Healthy baselines → ALIGNED on all heads
  for (let i = 0; i < healthySequences.length; i++) {
    const intent = generateSyntheticIntent(`healthy-${i}-${healthySequences[i].join(",")}`);
    const label = flywheel.onHealthyWorkflow(healthySequences[i], intent);
    if (label) labels.push(label);
  }

  // Attack traces → flywheel maps to threat-specific labels
  for (const trace of attackTraces) {
    const fullSequence = [...trace.legitimatePrefix, ...trace.hijackedSuffix];
    if (trace.source === "honeypot") {
      const event = flywheel.onHoneypotTrigger(
        trace.threatType,
        fullSequence,
        trace.injectionPoint,
        null,
      );
      labels.push(...event.labels);
    } else if (trace.source === "phantom") {
      const event = flywheel.onPhantomTrigger(
        trace.threatType.replace("phantom_", ""),
        fullSequence,
        null,
      );
      labels.push(...event.labels);
    } else {
      // Shadow traces: manually label based on category
      const isExfil = trace.threatType.includes("exfil");
      const isPrivesc = trace.threatType.includes("privesc");
      const isRecon = trace.threatType.includes("recon");
      labels.push({
        sequence: fullSequence,
        intentVec: null,
        headLabels: [
          isExfil ? LearnedThreatClass.HOSTILE : LearnedThreatClass.ALIGNED,
          isPrivesc ? LearnedThreatClass.HOSTILE : LearnedThreatClass.ALIGNED,
          isRecon ? LearnedThreatClass.HOSTILE : LearnedThreatClass.ALIGNED,
        ],
      });
    }
  }

  return labels;
}
