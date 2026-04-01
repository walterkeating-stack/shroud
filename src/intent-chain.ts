/**
 * Multi-agent intent chain — propagates intent vectors across delegation
 * boundaries so sub-agents are checked against both their immediate
 * delegation instruction AND the user's original root intent.
 *
 * OpenClaw doesn't expose parent session IDs. When agent A calls
 * sessions_send/sessions_spawn, a new before_prompt_build fires for
 * agent B — but with no link back to A. This module builds the
 * delegation chain by observing tool calls and correlating them with
 * subsequent before_prompt_build events.
 *
 * The temporal ordering is reliable because OpenClaw runs agents
 * sequentially in the same Node.js process.
 *
 * Zero external dependencies.
 */

import type { VectorProvider } from "./detectors/drift-detector.js";
import { TfIdfProvider, describeToolCall } from "./detectors/drift-detector.js";
import type { SecurityEvent, SecuritySeverity } from "./security-event.js";
import { ThreatClass } from "./security-event.js";

// ─── Types ───

/** A node in the intent delegation chain. */
export interface IntentNode {
  agentBuildId: string;
  agentLabel: string;
  sessionId: string;
  /** Embedded intent for this agent (delegation message or user message). */
  intentVec: Float64Array;
  intentText: string;
  /** User's original intent (propagated down the chain). */
  rootIntentVec: Float64Array;
  rootIntentText: string;
  parentAgentBuildId: string | null;
  depth: number;
  timestamp: number;
}

/** Captured when sessions_send/sessions_spawn is called. */
export interface PendingDelegation {
  parentAgentBuildId: string;
  parentAgentLabel: string;
  parentSessionId: string;
  rootIntentVec: Float64Array;
  rootIntentText: string;
  delegationMessage: string;
  delegationVec: Float64Array;
  targetAgentId?: string;
  timestamp: number;
}

/** Persisted record of a delegation relationship. */
export interface DelegationRecord {
  parentBuildId: string;
  parentLabel: string;
  childBuildId: string;
  childLabel: string;
  delegationText: string;
  rootIntentText: string;
  immediateCoherence: number;
  rootCoherence: number;
  timestamp: number;
  eventCount: number;
}

/** Result of a cross-agent drift check. */
export interface CrossAgentDriftResult {
  /** Similarity to delegation message (immediate parent's instruction). */
  immediateCoherence: number;
  /** Similarity to user's original intent (root). */
  rootCoherence: number;
  /** Delegation depth (0 = root agent). */
  depth: number;
  /** Whether this is a drift from the delegation intent. */
  drifted: boolean;
  severity: SecuritySeverity;
  reason: string;
}

// ─── Intent chain ───

export class IntentChain {
  private _provider: VectorProvider;
  private _nodes: Map<string, IntentNode> = new Map();
  private _pendingDelegations: PendingDelegation[] = [];
  private _history: DelegationRecord[] = [];
  private _delegationDriftThreshold: number;
  private _rootDriftThreshold: number;

  constructor(opts: {
    provider?: VectorProvider;
    delegationDriftThreshold?: number;
  } = {}) {
    this._provider = opts.provider ?? new TfIdfProvider(256);
    this._delegationDriftThreshold = opts.delegationDriftThreshold ?? 0.10;
    // Root intent threshold is even tighter at depth 2+ — sub-sub-agents
    // should be very focused on a narrow slice of the original intent.
    this._rootDriftThreshold = 0.05;
  }

  // ─── Delegation capture ───

  /**
   * Capture a delegation from before_tool_call when the tool is
   * sessions_send or sessions_spawn.
   *
   * Called from hooks.ts before_tool_call handler.
   */
  captureDelegation(
    parentAgentBuildId: string,
    parentAgentLabel: string,
    parentSessionId: string,
    toolParams: unknown,
  ): void {
    const p = (typeof toolParams === "object" && toolParams !== null)
      ? toolParams as Record<string, unknown>
      : {};

    // Extract the delegation message from tool params
    const message = String(p.message || p.content || p.text || p.body || "");
    if (!message.trim()) return;

    // Find the parent's node to get root intent
    const parentNode = this._nodes.get(parentAgentBuildId);
    const rootIntentVec = parentNode?.rootIntentVec ?? this._provider.embed(message);
    const rootIntentText = parentNode?.rootIntentText ?? message;

    const delegation: PendingDelegation = {
      parentAgentBuildId,
      parentAgentLabel,
      parentSessionId,
      rootIntentVec,
      rootIntentText,
      delegationMessage: message,
      delegationVec: this._provider.embed(message),
      targetAgentId: p.agentId ? String(p.agentId) : undefined,
      timestamp: Date.now(),
    };

    this._pendingDelegations.push(delegation);
  }

  /**
   * Consume a pending delegation when a child agent's before_prompt_build fires.
   * Returns the IntentNode for the child, or null if this is a root agent.
   *
   * Matching strategy:
   * 1. If targetAgentId matches the new agent, use that delegation
   * 2. Otherwise, consume FIFO (oldest pending delegation)
   * 3. Expire delegations older than 30 seconds
   */
  consumeDelegation(
    agentBuildId: string,
    agentLabel: string,
    sessionId: string,
    userMessage: string,
  ): IntentNode {
    // Expire old delegations (>30s)
    const now = Date.now();
    this._pendingDelegations = this._pendingDelegations.filter(
      d => now - d.timestamp < 30_000,
    );

    // Try to match by target agent ID
    let delegation: PendingDelegation | undefined;
    const targetIdx = this._pendingDelegations.findIndex(
      d => d.targetAgentId && d.targetAgentId === agentBuildId,
    );
    if (targetIdx >= 0) {
      delegation = this._pendingDelegations.splice(targetIdx, 1)[0];
    } else if (this._pendingDelegations.length > 0) {
      // FIFO fallback
      delegation = this._pendingDelegations.shift();
    }

    if (delegation) {
      // This is a delegated child agent
      const parentNode = this._nodes.get(delegation.parentAgentBuildId);
      const depth = (parentNode?.depth ?? 0) + 1;

      const node: IntentNode = {
        agentBuildId,
        agentLabel,
        sessionId,
        intentVec: delegation.delegationVec,
        intentText: delegation.delegationMessage,
        rootIntentVec: delegation.rootIntentVec,
        rootIntentText: delegation.rootIntentText,
        parentAgentBuildId: delegation.parentAgentBuildId,
        depth,
        timestamp: now,
      };

      this._nodes.set(agentBuildId, node);

      // Record delegation relationship
      this._history.push({
        parentBuildId: delegation.parentAgentBuildId,
        parentLabel: delegation.parentAgentLabel,
        childBuildId: agentBuildId,
        childLabel: agentLabel,
        delegationText: delegation.delegationMessage.slice(0, 200),
        rootIntentText: delegation.rootIntentText.slice(0, 200),
        immediateCoherence: 1.0, // Will be updated as tool calls come in
        rootCoherence: 1.0,
        timestamp: now,
        eventCount: 0,
      });

      return node;
    }

    // Root agent — no delegation
    const intentVec = this._provider.embed(userMessage);
    const node: IntentNode = {
      agentBuildId,
      agentLabel,
      sessionId,
      intentVec,
      intentText: userMessage,
      rootIntentVec: intentVec,
      rootIntentText: userMessage,
      parentAgentBuildId: null,
      depth: 0,
      timestamp: now,
    };

    this._nodes.set(agentBuildId, node);
    return node;
  }

  // ─── Drift checking ───

  /**
   * Check a tool call against the agent's intent chain.
   * Returns null for root agents (they use the standard drift detector).
   * Returns drift result for delegated agents (depth >= 1).
   */
  checkDelegationDrift(
    agentBuildId: string,
    toolName: string,
    params: unknown,
  ): CrossAgentDriftResult | null {
    const node = this._nodes.get(agentBuildId);
    if (!node || node.depth === 0) return null;

    const description = describeToolCall(toolName, params);
    const toolVec = this._provider.embed(description);

    const immediateSim = this._provider.similarity(node.intentVec, toolVec);
    const rootSim = this._provider.similarity(node.rootIntentVec, toolVec);

    // Thresholds tighten with depth
    const immediateThreshold = this._delegationDriftThreshold;
    const rootThreshold = node.depth >= 2 ? this._rootDriftThreshold : this._delegationDriftThreshold;

    const immediateDrifted = immediateSim < immediateThreshold;
    const rootDrifted = rootSim < rootThreshold;

    let severity: SecuritySeverity = "low";
    let reason = "";

    if (immediateDrifted && rootDrifted) {
      severity = "high";
      reason = `Delegation breach at depth ${node.depth}: "${toolName}" drifted from both delegation intent (sim=${immediateSim.toFixed(3)}) and root intent (sim=${rootSim.toFixed(3)})`;
    } else if (immediateDrifted) {
      severity = "medium";
      reason = `Delegation drift at depth ${node.depth}: "${toolName}" drifted from delegation intent (sim=${immediateSim.toFixed(3)})`;
    } else if (rootDrifted && node.depth >= 2) {
      severity = "medium";
      reason = `Root intent drift at depth ${node.depth}: "${toolName}" drifted from user's original intent (sim=${rootSim.toFixed(3)})`;
    }

    const drifted = severity !== "low";

    // Update delegation record coherence scores
    if (drifted) {
      const record = this._history.find(
        r => r.childBuildId === agentBuildId && r.parentBuildId === node.parentAgentBuildId,
      );
      if (record) {
        // Running average of coherence scores
        record.immediateCoherence = (record.immediateCoherence + immediateSim) / 2;
        record.rootCoherence = (record.rootCoherence + rootSim) / 2;
        record.eventCount++;
      }
    }

    return {
      immediateCoherence: immediateSim,
      rootCoherence: rootSim,
      depth: node.depth,
      drifted,
      severity,
      reason,
    };
  }

  // ─── Accessors ───

  getNode(agentBuildId: string): IntentNode | undefined {
    return this._nodes.get(agentBuildId);
  }

  getAllNodes(): IntentNode[] {
    return [...this._nodes.values()];
  }

  getHistory(): readonly DelegationRecord[] {
    return this._history;
  }

  getHistoryForAgent(agentBuildId: string): DelegationRecord[] {
    return this._history.filter(
      r => r.parentBuildId === agentBuildId || r.childBuildId === agentBuildId,
    );
  }

  getProvider(): VectorProvider {
    return this._provider;
  }

  /** Get the delegation depth for an agent (0 = root). */
  getDepth(agentBuildId: string): number {
    return this._nodes.get(agentBuildId)?.depth ?? 0;
  }
}

// ─── Security event builder ───

export function buildDelegationDriftEvent(
  agentLabel: string,
  result: CrossAgentDriftResult,
  action: "flagged" | "blocked" = "flagged",
): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: ThreatClass.DELEGATION_DRIFT,
    signatureId: result.rootCoherence < 0.05
      ? "delegation_root_breach"
      : "delegation_immediate_drift",
    severity: result.severity,
    matchedText: `${agentLabel}: depth=${result.depth} immediate=${result.immediateCoherence.toFixed(3)} root=${result.rootCoherence.toFixed(3)}`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action,
    description: result.reason,
  };
}
