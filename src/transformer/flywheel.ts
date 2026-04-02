/**
 * Self-labeling flywheel — converts runtime security events (honeypot triggers,
 * phantom tool triggers, shadow execution blocks) into typed training labels
 * for the threat head classifier.
 *
 * Stateless converter: takes trigger details + session context, produces
 * AttackTrace + ThreatLabeledExample pairs.
 *
 * Zero dependencies. Pure TypeScript.
 */

import { LearnedThreatClass, type ThreatLabeledExample } from "./threat-heads.js";
import type { AttackTrace, AttackTraceSource } from "./contrastive.js";

// ─── Types ───

/** Wraps a security event with derived labels. */
export interface FlyWheelEvent {
  /** The original attack trace. */
  trace: AttackTrace;
  /** Derived threat labels for the threat head classifier. */
  labels: ThreatLabeledExample[];
}

// ─── Flywheel ───

export class SelfLabelingFlywheel {

  /**
   * Generate labels from a honeypot trigger.
   * @param tokenType - The honeypot token type that was triggered (e.g. "webhook_url", "api_key")
   * @param sessionSequence - Tool names in the session up to the trigger point
   * @param injectionIdx - Index in the session where injection occurred
   */
  onHoneypotTrigger(
    tokenType: string,
    sessionSequence: string[],
    injectionIdx: number,
    intentVec?: Float64Array | null,
  ): FlyWheelEvent {
    const legitimatePrefix = sessionSequence.slice(0, injectionIdx);
    const hijackedSuffix = sessionSequence.slice(injectionIdx);

    const trace: AttackTrace = {
      legitimatePrefix,
      hijackedSuffix,
      injectionPoint: injectionIdx,
      source: "honeypot" as AttackTraceSource,
      threatType: `honeypot_${tokenType}`,
      timestamp: Date.now(),
    };

    // Label mapping:
    // - webhook_url, email → exfil head HOSTILE (outbound data channel)
    // - api_key, credential → exfil head HOSTILE (credential theft for exfil)
    // - hostname, ip_address → recon head SUSPICIOUS + exfil head HOSTILE
    // Non-triggering heads get ALIGNED
    const labels: ThreatLabeledExample[] = [];

    // The attack sequence gets hostile labels
    const fullSequence = [...legitimatePrefix, ...hijackedSuffix];
    if (fullSequence.length >= 2) {
      let exfilLabel = LearnedThreatClass.HOSTILE;
      let privescLabel = LearnedThreatClass.ALIGNED;
      let reconLabel = LearnedThreatClass.ALIGNED;

      if (tokenType === "hostname" || tokenType === "ip_address") {
        reconLabel = LearnedThreatClass.SUSPICIOUS;
      }

      labels.push({
        sequence: fullSequence,
        intentVec: intentVec || null,
        headLabels: [exfilLabel, privescLabel, reconLabel],
      });
    }

    // The legitimate prefix (if long enough) gets ALIGNED labels
    if (legitimatePrefix.length >= 2) {
      labels.push({
        sequence: legitimatePrefix,
        intentVec: intentVec || null,
        headLabels: [
          LearnedThreatClass.ALIGNED,
          LearnedThreatClass.ALIGNED,
          LearnedThreatClass.ALIGNED,
        ],
      });
    }

    return { trace, labels };
  }

  /**
   * Generate labels from a phantom tool trigger.
   * @param trapType - The phantom tool trap type (e.g. "data_upload", "webhook_relay")
   * @param sessionSequence - Tool names in the session up to the trigger
   */
  onPhantomTrigger(
    trapType: string,
    sessionSequence: string[],
    intentVec?: Float64Array | null,
  ): FlyWheelEvent {
    // The phantom tool itself is the hijacked suffix (last tool is the phantom)
    const injectionPoint = Math.max(0, sessionSequence.length - 1);
    const legitimatePrefix = sessionSequence.slice(0, injectionPoint);
    const hijackedSuffix = sessionSequence.slice(injectionPoint);

    const trace: AttackTrace = {
      legitimatePrefix,
      hijackedSuffix,
      injectionPoint,
      source: "phantom" as AttackTraceSource,
      threatType: `phantom_${trapType}`,
      timestamp: Date.now(),
    };

    const labels: ThreatLabeledExample[] = [];

    // All phantom trap types map to exfil HOSTILE:
    // data_upload, webhook_relay, email_forward, api_relay, file_export
    // These are all outbound data channels
    const exfilHeadTypes = [
      "data_upload", "webhook_relay", "email_forward", "api_relay", "file_export",
    ];
    const isExfil = exfilHeadTypes.includes(trapType);

    const fullSequence = [...sessionSequence];
    if (fullSequence.length >= 2) {
      labels.push({
        sequence: fullSequence,
        intentVec: intentVec || null,
        headLabels: [
          isExfil ? LearnedThreatClass.HOSTILE : LearnedThreatClass.SUSPICIOUS,
          LearnedThreatClass.ALIGNED,
          LearnedThreatClass.ALIGNED,
        ],
      });
    }

    // Legitimate prefix gets ALIGNED
    if (legitimatePrefix.length >= 2) {
      labels.push({
        sequence: legitimatePrefix,
        intentVec: intentVec || null,
        headLabels: [
          LearnedThreatClass.ALIGNED,
          LearnedThreatClass.ALIGNED,
          LearnedThreatClass.ALIGNED,
        ],
      });
    }

    return { trace, labels };
  }

  /**
   * Generate labels from a shadow execution block.
   * @param verdictReason - The reason for the block verdict
   * @param sessionSequence - Tool names in the session up to the shadow trigger
   * @param shadowSteps - Tool names from the shadow execution steps
   */
  onShadowBlock(
    verdictReason: string,
    sessionSequence: string[],
    shadowSteps: string[],
    intentVec?: Float64Array | null,
  ): FlyWheelEvent {
    const trace: AttackTrace = {
      legitimatePrefix: [...sessionSequence],
      hijackedSuffix: shadowSteps,
      injectionPoint: sessionSequence.length,
      source: "shadow" as AttackTraceSource,
      threatType: "shadow_block",
      timestamp: Date.now(),
    };

    const labels: ThreatLabeledExample[] = [];
    const reason = verdictReason.toLowerCase();

    // Derive labels from the verdict reason
    let exfilLabel = LearnedThreatClass.SUSPICIOUS;
    let privescLabel = LearnedThreatClass.ALIGNED;
    let reconLabel = LearnedThreatClass.ALIGNED;

    if (reason.includes("egress")) {
      exfilLabel = LearnedThreatClass.HOSTILE;
    }

    if (reason.includes("sensitive path")) {
      reconLabel = LearnedThreatClass.SUSPICIOUS;
      exfilLabel = LearnedThreatClass.HOSTILE;
    }

    const fullSequence = [...sessionSequence, ...shadowSteps];
    if (fullSequence.length >= 2) {
      labels.push({
        sequence: fullSequence,
        intentVec: intentVec || null,
        headLabels: [exfilLabel, privescLabel, reconLabel],
      });
    }

    // Legitimate prefix gets ALIGNED
    if (sessionSequence.length >= 2) {
      labels.push({
        sequence: sessionSequence,
        intentVec: intentVec || null,
        headLabels: [
          LearnedThreatClass.ALIGNED,
          LearnedThreatClass.ALIGNED,
          LearnedThreatClass.ALIGNED,
        ],
      });
    }

    return { trace, labels };
  }

  /**
   * Generate ALIGNED labels from a healthy completed workflow.
   * Call this during normal session completion to provide positive examples.
   */
  onHealthyWorkflow(
    sequence: string[],
    intentVec?: Float64Array | null,
  ): ThreatLabeledExample | null {
    if (sequence.length < 2) return null;
    return {
      sequence: [...sequence],
      intentVec: intentVec || null,
      headLabels: [
        LearnedThreatClass.ALIGNED,
        LearnedThreatClass.ALIGNED,
        LearnedThreatClass.ALIGNED,
      ],
    };
  }
}
