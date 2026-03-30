/**
 * LLM-based security event grading.
 *
 * Accumulates flagged security events, batches them, and sends to an LLM
 * via OpenClaw gateway session to classify as TRUE_POSITIVE, FALSE_POSITIVE,
 * or NEEDS_REVIEW. Results are stored on the event for dashboard display.
 *
 * Self-whitelisting: grading sessions use a marker in the session key so
 * Shroud's own scanner doesn't flag the grading prompt (which contains
 * real injection examples by definition).
 *
 * Zero external dependencies — uses Node.js built-in child_process to call
 * `openclaw gateway call sessions.create`.
 */

import { execFileSync } from "node:child_process";
import type { SecurityEvent } from "./security-event.js";

/** Verdict from LLM grading. */
export type GradingVerdict = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "UNGRADED";

/** A graded event with LLM verdict. */
export interface GradedEvent {
  eventTimestamp: number;
  signatureId: string;
  agentLabel: string;
  matchedText: string;
  verdict: GradingVerdict;
  reasoning: string;
  gradedAt: number;
}

/** Marker prefix for grading session keys. */
export const GRADING_SESSION_PREFIX = "shroud-grading-";

/** The agent label that grading sessions will produce via extractLabel. */
export const GRADING_AGENT_LABEL = "Security Event Grader";

/** The grading system prompt. */
const GRADING_PROMPT = `You are a security event grader for an AI agent firewall (Shroud).

For each flagged event below, classify it as one of:
- TRUE_POSITIVE: This is a genuine security concern (injection attempt, data exfiltration, etc.)
- FALSE_POSITIVE: This is benign — the pattern triggered on normal content being discussed, not an actual attack
- NEEDS_REVIEW: Ambiguous — a human should review this

Consider:
- Is the matched text being DISCUSSED/QUOTED (benign) or EXECUTED/INJECTED (malicious)?
- Is this a normal part of the agent's role? (e.g. a security researcher discussing injection techniques is expected)
- What is the agent's classification and context?

Respond with ONLY a JSON array. Each element:
{"index": N, "verdict": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW", "reasoning": "one sentence"}

Do not include any other text outside the JSON array.`;

export class EventGrader {
  private _pending: SecurityEvent[] = [];
  private _graded: Map<number, GradedEvent> = new Map(); // keyed by event timestamp
  private _timer: ReturnType<typeof setInterval> | null = null;
  private _threshold: number;
  private _intervalMs: number;
  private _gatewayUrl: string;
  private _openclawBin: string;
  private _running = false;

  constructor(opts: {
    threshold: number;
    intervalSec: number;
    gatewayUrl: string;
  }) {
    this._threshold = opts.threshold;
    this._intervalMs = opts.intervalSec * 1000;
    this._gatewayUrl = opts.gatewayUrl;
    // Find openclaw binary
    this._openclawBin = process.env.OPENCLAW_BIN || "openclaw";
    try {
      const which = execFileSync("which", ["openclaw"], { encoding: "utf-8" }).trim();
      if (which) this._openclawBin = which;
    } catch {}
  }

  /** Start the grading timer. */
  start(): void {
    if (this._timer) return;
    this._timer = setInterval(() => this._tryGrade(), this._intervalMs);
    if (this._timer.unref) this._timer.unref();
  }

  /** Stop the grading timer. */
  stop(): void {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /** Add an event to the pending grading queue. */
  addEvent(event: SecurityEvent): void {
    // Don't grade events from grading sessions (prevent recursion)
    if (event.agentSessionId?.startsWith(GRADING_SESSION_PREFIX)) return;
    // Don't re-grade
    if (this._graded.has(event.timestamp)) return;
    this._pending.push(event);

    // Trigger immediately if threshold met
    if (this._pending.length >= this._threshold) {
      this._tryGrade();
    }
  }

  /** Get the verdict for an event (by timestamp). */
  getVerdict(eventTimestamp: number): GradedEvent | null {
    return this._graded.get(eventTimestamp) ?? null;
  }

  /** Get all graded events. */
  getAllGraded(): GradedEvent[] {
    return [...this._graded.values()];
  }

  /** Get grading stats. */
  getStats(): { pending: number; graded: number; truePositive: number; falsePositive: number; needsReview: number } {
    let tp = 0, fp = 0, nr = 0;
    for (const g of this._graded.values()) {
      if (g.verdict === "TRUE_POSITIVE") tp++;
      else if (g.verdict === "FALSE_POSITIVE") fp++;
      else if (g.verdict === "NEEDS_REVIEW") nr++;
    }
    return { pending: this._pending.length, graded: this._graded.size, truePositive: tp, falsePositive: fp, needsReview: nr };
  }

  /** Attempt a grading batch. */
  private _tryGrade(): void {
    if (this._running || this._pending.length === 0) return;
    this._running = true;

    // Take up to 20 events per batch
    const batch = this._pending.splice(0, 20);

    try {
      const verdicts = this._callGateway(batch);
      for (const v of verdicts) {
        if (v.index >= 0 && v.index < batch.length) {
          const event = batch[v.index];
          this._graded.set(event.timestamp, {
            eventTimestamp: event.timestamp,
            signatureId: event.signatureId,
            agentLabel: event.agentLabel || "unknown",
            matchedText: event.matchedText?.slice(0, 100) || "",
            verdict: v.verdict,
            reasoning: v.reasoning || "",
            gradedAt: Date.now(),
          });
        }
      }
    } catch {
      // Put events back if grading failed
      this._pending.unshift(...batch);
    }

    this._running = false;
  }

  /** Call the OpenClaw gateway to grade a batch of events. */
  private _callGateway(batch: SecurityEvent[]): Array<{ index: number; verdict: GradingVerdict; reasoning: string }> {
    // Format events for the LLM
    const eventsText = batch.map((e, i) =>
      `[${i}] sig=${e.signatureId} sev=${e.severity} agent="${e.agentLabel || "?"}" ` +
      `class=${e.threatClass} match="${(e.matchedText || "").slice(0, 150)}" ` +
      `desc="${e.description || ""}"`,
    ).join("\n");

    const message = `Grade these ${batch.length} security events:\n\n${eventsText}`;
    const sessionKey = `${GRADING_SESSION_PREFIX}${Date.now()}`;


    try {
      const result = execFileSync(this._openclawBin, [
        "gateway", "call", "sessions.create",
        "--expect-final",
        "--timeout", "30000",
        "--json",
        "--params", JSON.stringify({
          key: sessionKey,
          message,
          systemPrompt: GRADING_PROMPT,
        }),
      ], {
        timeout: 35_000,
        encoding: "utf-8",
        env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      });

      // Parse the LLM response — extract JSON array
      const jsonMatch = result.match(/\[[\s\S]*?\]/);
      if (!jsonMatch) return [];

      const parsed = JSON.parse(jsonMatch[0]);
      if (!Array.isArray(parsed)) return [];

      return parsed
        .filter((v: any) =>
          typeof v.index === "number" &&
          ["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"].includes(v.verdict),
        )
        .map((v: any) => ({
          index: v.index,
          verdict: v.verdict as GradingVerdict,
          reasoning: typeof v.reasoning === "string" ? v.reasoning.slice(0, 200) : "",
        }));
    } catch {
      return [];
    }
  }
}
