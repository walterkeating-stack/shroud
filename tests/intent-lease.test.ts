import { describe, expect, it } from "vitest";

import { IntentLeaseManager } from "../src/intent-lease.js";
import { ToolCategory } from "../src/detectors/tool-intent.js";

describe("intent leases", () => {
  it("binds a child agent to delegated tool families", () => {
    const mgr = new IntentLeaseManager();
    mgr.issueLease({
      parentAgentBuildId: "parent",
      parentAgentLabel: "OpenClaw Orchestrator",
      childHint: "Shroud Research",
      intentSummary: "Research this incident and report back",
      allowedToolFamilies: [ToolCategory.READ_ONLY, ToolCategory.WRITE_LOCAL],
      allowedDataClasses: ["file_path"],
      maxSteps: 3,
    });

    const lease = mgr.consumeLease("child-build", "Shroud Research", "Shroud Research");
    expect(lease).not.toBeNull();
    expect(mgr.checkLease("child-build", "read")).toBeNull();
    expect(mgr.checkLease("child-build", "web_fetch")?.signatureId).toBe("lease_tool_family");
  });

  it("enforces delegated step limits", () => {
    const mgr = new IntentLeaseManager();
    mgr.issueLease({
      parentAgentBuildId: "parent",
      parentAgentLabel: "OpenClaw Orchestrator",
      childHint: "Coach Alessandra",
      intentSummary: "Reply with a short update",
      allowedToolFamilies: [ToolCategory.COMMUNICATE],
      allowedDataClasses: ["person_name"],
      maxSteps: 1,
    });
    mgr.consumeLease("child2", "Coach Alessandra", "Coach Alessandra");
    expect(mgr.checkLease("child2", "sessions_send")).toBeNull();
    expect(mgr.checkLease("child2", "sessions_send")?.signatureId).toBe("lease_step_limit");
  });
});
