/**
 * Firewall rule suggestion engine.
 *
 * Analyzes security events, profiler baselines, and agent behaviour
 * to generate actionable rule suggestions. Each suggestion can be
 * accepted (applied via PolicyEngine) or dismissed.
 *
 * Zero runtime dependencies.
 */

import type { SecurityEvent, SecurityEventBus } from "./security-event.js";
import type { AgentBaseline } from "./profiler-types.js";
import type { BaselineStore } from "./profiler-store.js";
import type { PolicyEngine, AgentPolicy } from "./policy.js";
import type { ShroudConfig } from "./types.js";

/** A single firewall rule suggestion. */
export interface RuleSuggestion {
  id: string;
  agentBuildId: string;
  agentLabel: string;
  type: "suppress" | "widen_threshold" | "add_allowlist";
  signatureId?: string;
  reason: string;
  confidence: number;  // 0-1
  impact: string;      // e.g. "Would suppress 23 events/day for this agent"
}

/** Dismissed suggestion tracking. */
interface DismissedEntry {
  id: string;
  timestamp: number;
}

/**
 * Rule suggestion engine. Stateless computation — call generateSuggestions()
 * to get current recommendations based on event data.
 */
export class RuleSuggestionEngine {
  private _dismissed: Map<string, DismissedEntry> = new Map();

  /**
   * Generate rule suggestions from current event data and baselines.
   */
  generateSuggestions(
    events: readonly SecurityEvent[],
    baselineStore: BaselineStore | null,
    config: ShroudConfig,
  ): RuleSuggestion[] {
    const suggestions: RuleSuggestion[] = [];
    if (events.length === 0) return suggestions;

    // Group events by agent
    const byAgent = new Map<string, SecurityEvent[]>();
    for (const e of events) {
      const key = e.agentBuildId || "unknown";
      if (!byAgent.has(key)) byAgent.set(key, []);
      byAgent.get(key)!.push(e);
    }

    // Group events by signature
    const bySig = new Map<string, SecurityEvent[]>();
    for (const e of events) {
      if (!bySig.has(e.signatureId)) bySig.set(e.signatureId, []);
      bySig.get(e.signatureId)!.push(e);
    }

    // Analyze each agent
    for (const [agentId, agentEvents] of byAgent) {
      if (agentId === "unknown") continue;
      const label = agentEvents[0]?.agentLabel || agentId.slice(0, 12);
      const baseline = baselineStore?.load(agentId) ?? null;

      // 1. Mature agent with high event rate on specific signatures → suppress
      if (baseline && (baseline.maturity === "mature" || baseline.maturity === "reliable")) {
        const sigCounts = new Map<string, number>();
        for (const e of agentEvents) {
          sigCounts.set(e.signatureId, (sigCounts.get(e.signatureId) || 0) + 1);
        }

        for (const [sig, count] of sigCounts) {
          if (count >= 5) {
            const id = `suppress:${agentId}:${sig}`;
            if (!this._dismissed.has(id)) {
              const eventsPerDay = estimateRate(agentEvents.filter(e => e.signatureId === sig));
              suggestions.push({
                id,
                agentBuildId: agentId,
                agentLabel: label,
                type: "suppress",
                signatureId: sig,
                reason: `${label} triggers ${sig} ${count} times with a ${baseline.maturity} baseline (${baseline.sessionCount} sessions). This is likely normal behaviour.`,
                confidence: Math.min(0.95, 0.5 + (baseline.sessionCount / 100) + (count / 50)),
                impact: `Would suppress ~${eventsPerDay} events/day for this agent`,
              });
            }
          }
        }
      }

      // 2. >50% of events are drift/coherence → suggest widening thresholds
      const driftCoherenceCount = agentEvents.filter(e =>
        e.signatureId.startsWith("drift_") ||
        e.signatureId.startsWith("coherence_") ||
        e.signatureId === "semantic_drift" ||
        e.signatureId === "causal_incoherence"
      ).length;
      if (agentEvents.length >= 5 && driftCoherenceCount / agentEvents.length > 0.5) {
        const id = `widen:${agentId}:drift_coherence`;
        if (!this._dismissed.has(id)) {
          suggestions.push({
            id,
            agentBuildId: agentId,
            agentLabel: label,
            type: "widen_threshold",
            reason: `${Math.round(driftCoherenceCount / agentEvents.length * 100)}% of ${label}'s events are drift/coherence alerts. The agent may have naturally varied behaviour.`,
            confidence: Math.min(0.9, driftCoherenceCount / agentEvents.length),
            impact: `Would reduce ~${driftCoherenceCount} drift/coherence events for this agent`,
          });
        }
      }

      // 3. Tools flagged as "unexpected" that appear in baseline → add to allowlist
      if (baseline) {
        const toolEvents = agentEvents.filter(e =>
          e.signatureId === "tool_outside_profile" ||
          e.signatureId === "sb_tool_boundary"
        );
        const flaggedTools = new Set<string>();
        for (const e of toolEvents) {
          // Extract tool name from matchedText (format: "toolName: reason")
          const toolName = e.matchedText.split(":")[0]?.trim();
          if (toolName && baseline.toolProfile.includes(toolName)) {
            flaggedTools.add(toolName);
          }
        }

        for (const tool of flaggedTools) {
          const id = `allowlist:${agentId}:${tool}`;
          if (!this._dismissed.has(id)) {
            suggestions.push({
              id,
              agentBuildId: agentId,
              agentLabel: label,
              type: "add_allowlist",
              signatureId: "tool_outside_profile",
              reason: `Tool "${tool}" is in ${label}'s baseline profile but still triggers alerts. Adding it to the allowlist would eliminate these false positives.`,
              confidence: 0.85,
              impact: `Would suppress tool boundary alerts for "${tool}" on this agent`,
            });
          }
        }
      }
    }

    // 4. Signatures triggered by a single agent → suggest per-agent override
    for (const [sig, sigEvents] of bySig) {
      const agents = new Set(sigEvents.map(e => e.agentBuildId).filter(Boolean));
      if (agents.size === 1 && sigEvents.length >= 3) {
        const agentId = [...agents][0]!;
        const label = sigEvents[0]?.agentLabel || agentId.slice(0, 12);
        const id = `single_agent:${agentId}:${sig}`;
        if (!this._dismissed.has(id)) {
          // Don't duplicate if we already suggested suppress for this combo
          const alreadySuggested = suggestions.some(s =>
            s.agentBuildId === agentId && s.signatureId === sig
          );
          if (!alreadySuggested) {
            suggestions.push({
              id,
              agentBuildId: agentId,
              agentLabel: label,
              type: "suppress",
              signatureId: sig,
              reason: `Signature ${sig} is only triggered by ${label} (${sigEvents.length} times). This suggests agent-specific behaviour rather than a real threat.`,
              confidence: Math.min(0.8, 0.4 + (sigEvents.length / 20)),
              impact: `Would suppress ${sigEvents.length} events from ${sig} for this agent only`,
            });
          }
        }
      }
    }

    // Sort by confidence descending
    suggestions.sort((a, b) => b.confidence - a.confidence);
    return suggestions;
  }

  /**
   * Accept a suggestion — apply it via PolicyEngine.
   * Returns true if applied, false if suggestion not found.
   */
  acceptSuggestion(
    suggestion: RuleSuggestion,
    policyEngine: PolicyEngine,
  ): boolean {
    if (!suggestion) return false;

    switch (suggestion.type) {
      case "suppress": {
        if (suggestion.signatureId) {
          const existing = policyEngine.getPolicy(suggestion.agentBuildId);
          const disabled = new Set(existing.injectionDisabledSignatures || []);
          disabled.add(suggestion.signatureId);
          policyEngine.setAgentPolicy(suggestion.agentBuildId, {
            label: suggestion.agentLabel,
            injectionDisabledSignatures: [...disabled],
          });
          policyEngine.commit(`Auto: suppress ${suggestion.signatureId} for ${suggestion.agentLabel}`);
        }
        break;
      }
      case "widen_threshold": {
        // Widen thresholds by adding a note — actual threshold adjustment
        // happens via the adaptive threshold engine based on baselines
        policyEngine.setAgentPolicy(suggestion.agentBuildId, {
          label: suggestion.agentLabel,
          notes: `Auto-widened: ${suggestion.reason}`,
        });
        policyEngine.commit(`Auto: widen thresholds for ${suggestion.agentLabel}`);
        break;
      }
      case "add_allowlist": {
        if (suggestion.signatureId) {
          const existing = policyEngine.getPolicy(suggestion.agentBuildId);
          const disabled = new Set(existing.injectionDisabledSignatures || []);
          disabled.add(suggestion.signatureId);
          policyEngine.setAgentPolicy(suggestion.agentBuildId, {
            label: suggestion.agentLabel,
            injectionDisabledSignatures: [...disabled],
          });
          policyEngine.commit(`Auto: allowlist ${suggestion.signatureId} for ${suggestion.agentLabel}`);
        }
        break;
      }
    }

    return true;
  }

  /** Dismiss a suggestion so it won't be shown again. */
  dismissSuggestion(id: string): void {
    this._dismissed.set(id, { id, timestamp: Date.now() });
  }

  /** Check if a suggestion has been dismissed. */
  isDismissed(id: string): boolean {
    return this._dismissed.has(id);
  }

  /** Get all dismissed IDs. */
  getDismissed(): string[] {
    return [...this._dismissed.keys()];
  }

  /** Clear old dismissed entries (older than 7 days). */
  pruneStale(): number {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    let pruned = 0;
    for (const [id, entry] of this._dismissed) {
      if (entry.timestamp < cutoff) {
        this._dismissed.delete(id);
        pruned++;
      }
    }
    return pruned;
  }
}

/** Estimate events per day from a set of events. */
function estimateRate(events: SecurityEvent[]): number {
  if (events.length < 2) return events.length;
  const span = events[events.length - 1].timestamp - events[0].timestamp;
  if (span <= 0) return events.length;
  const msPerDay = 86400000;
  return Math.round((events.length / span) * msPerDay);
}
