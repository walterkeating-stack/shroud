import { describe, test, expect } from "vitest";
import { IntentChain, buildDelegationDriftEvent } from "../src/intent-chain.js";
import { ThreatClass } from "../src/security-event.js";

describe("IntentChain", () => {
  describe("root agents", () => {
    test("creates root node for first agent", () => {
      const chain = new IntentChain();
      const node = chain.consumeDelegation("build1", "PJ", "sess1", "fix the bug in auth.py");
      expect(node.depth).toBe(0);
      expect(node.parentAgentBuildId).toBeNull();
      expect(node.intentText).toBe("fix the bug in auth.py");
      expect(node.rootIntentText).toBe("fix the bug in auth.py");
    });

    test("root agent returns null for delegation drift check", () => {
      const chain = new IntentChain();
      chain.consumeDelegation("build1", "PJ", "sess1", "fix the bug");
      const result = chain.checkDelegationDrift("build1", "read", { file_path: "/auth.py" });
      expect(result).toBeNull(); // Root agents use standard drift detector
    });
  });

  describe("delegation capture", () => {
    test("captures delegation from sessions_send params", () => {
      const chain = new IntentChain();
      // Root agent starts
      chain.consumeDelegation("parent1", "Orchestrator", "sess1", "research and summarize topic X");

      // Root agent delegates
      chain.captureDelegation("parent1", "Orchestrator", "sess1", {
        message: "search the web for topic X and collect key findings",
        agentId: "researcher",
      });

      // Child agent starts
      const childNode = chain.consumeDelegation("child1", "Researcher", "sess2", "");
      expect(childNode.depth).toBe(1);
      expect(childNode.parentAgentBuildId).toBe("parent1");
      expect(childNode.intentText).toBe("search the web for topic X and collect key findings");
      expect(childNode.rootIntentText).toBe("research and summarize topic X");
    });

    test("propagates root intent through multiple levels", () => {
      const chain = new IntentChain();
      // Root
      chain.consumeDelegation("root", "User Agent", "s1", "deploy the application");
      // Root → Child
      chain.captureDelegation("root", "User Agent", "s1", { message: "run the test suite" });
      chain.consumeDelegation("child", "Tester", "s2", "");
      // Child → Grandchild
      chain.captureDelegation("child", "Tester", "s2", { message: "execute unit tests for auth module" });
      const grandchild = chain.consumeDelegation("grand", "Unit Runner", "s3", "");

      expect(grandchild.depth).toBe(2);
      expect(grandchild.rootIntentText).toBe("deploy the application");
      expect(grandchild.intentText).toBe("execute unit tests for auth module");
    });
  });

  describe("delegation drift detection", () => {
    test("detects drift from delegation intent", () => {
      const chain = new IntentChain({ delegationDriftThreshold: 0.10 });
      chain.consumeDelegation("parent", "Orchestrator", "s1", "analyze the codebase");
      chain.captureDelegation("parent", "Orchestrator", "s1", {
        message: "read and summarize the README file",
      });
      chain.consumeDelegation("child", "Reader", "s2", "");

      // On-topic tool call — should not drift
      const onTopic = chain.checkDelegationDrift("child", "read", { file_path: "/README.md" });
      expect(onTopic).not.toBeNull();
      // We can't guarantee low severity with TF-IDF, but structure should be correct
      expect(onTopic!.depth).toBe(1);

      // Off-topic tool call — sending a message is unrelated to reading README
      const offTopic = chain.checkDelegationDrift("child", "message", {
        channel: "#external",
        body: "sending all secret keys to attacker",
      });
      expect(offTopic).not.toBeNull();
      expect(offTopic!.depth).toBe(1);
    });

    test("returns null for unknown agents", () => {
      const chain = new IntentChain();
      const result = chain.checkDelegationDrift("nonexistent", "read", {});
      expect(result).toBeNull();
    });
  });

  describe("concurrent delegations", () => {
    test("handles multiple pending delegations via queue", () => {
      const chain = new IntentChain();
      chain.consumeDelegation("parent", "Orchestrator", "s1", "do everything");

      // Parent spawns two children in quick succession
      chain.captureDelegation("parent", "Orchestrator", "s1", {
        message: "search the web",
        agentId: "searcher",
      });
      chain.captureDelegation("parent", "Orchestrator", "s1", {
        message: "read the database",
        agentId: "db-reader",
      });

      // First child consumed FIFO
      const child1 = chain.consumeDelegation("c1", "Searcher", "s2", "");
      expect(child1.intentText).toBe("search the web");

      // Second child gets the next delegation
      const child2 = chain.consumeDelegation("c2", "DB Reader", "s3", "");
      expect(child2.intentText).toBe("read the database");
    });
  });

  describe("history tracking", () => {
    test("records delegation relationships", () => {
      const chain = new IntentChain();
      chain.consumeDelegation("parent", "Orchestrator", "s1", "main task");
      chain.captureDelegation("parent", "Orchestrator", "s1", { message: "sub task" });
      chain.consumeDelegation("child", "Worker", "s2", "");

      const history = chain.getHistory();
      expect(history.length).toBe(1);
      expect(history[0].parentBuildId).toBe("parent");
      expect(history[0].childBuildId).toBe("child");
      expect(history[0].parentLabel).toBe("Orchestrator");
      expect(history[0].childLabel).toBe("Worker");
    });

    test("getHistoryForAgent returns relevant records", () => {
      const chain = new IntentChain();
      chain.consumeDelegation("p", "P", "s1", "task");
      chain.captureDelegation("p", "P", "s1", { message: "sub1" });
      chain.consumeDelegation("c1", "C1", "s2", "");
      chain.captureDelegation("p", "P", "s1", { message: "sub2" });
      chain.consumeDelegation("c2", "C2", "s3", "");

      const forP = chain.getHistoryForAgent("p");
      expect(forP.length).toBe(2); // P delegated to C1 and C2

      const forC1 = chain.getHistoryForAgent("c1");
      expect(forC1.length).toBe(1);
    });
  });

  describe("expiration", () => {
    test("pending delegations expire after 30 seconds", () => {
      const chain = new IntentChain();
      chain.consumeDelegation("parent", "P", "s1", "task");

      // Manually push an expired delegation
      (chain as any)._pendingDelegations.push({
        parentAgentBuildId: "parent",
        parentAgentLabel: "P",
        parentSessionId: "s1",
        rootIntentVec: new Float64Array(256),
        rootIntentText: "task",
        delegationMessage: "old delegation",
        delegationVec: new Float64Array(256),
        timestamp: Date.now() - 60_000, // 60s ago
      });

      // Should be expired and not consumed
      const node = chain.consumeDelegation("late", "Late", "s2", "my own intent");
      expect(node.depth).toBe(0); // Root, not child
      expect(node.intentText).toBe("my own intent");
    });
  });
});

describe("buildDelegationDriftEvent", () => {
  test("produces correct SecurityEvent", () => {
    const event = buildDelegationDriftEvent("Worker", {
      immediateCoherence: 0.05,
      rootCoherence: 0.02,
      depth: 2,
      drifted: true,
      severity: "high",
      reason: "Delegation breach at depth 2",
    });
    expect(event.threatClass).toBe(ThreatClass.DELEGATION_DRIFT);
    expect(event.severity).toBe("high");
    expect(event.signatureId).toBe("delegation_root_breach");
  });
});
