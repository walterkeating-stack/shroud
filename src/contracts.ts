import { ToolCategory, TOOL_CATEGORIES } from "./detectors/tool-intent.js";

export interface AgentCapabilityContract {
  agentLabel?: string;
  role: string;
  allowedToolFamilies: ToolCategory[];
  allowedChannels: string[];
  allowedDelegationTargets: string[];
  allowedDataClasses: string[];
  maxToolDepth?: number;
  egressPolicy: "none" | "mentioned-only" | "trusted-only" | "open";
}

export interface ContractViolation {
  severity: "medium" | "high";
  reason: string;
  signatureId: string;
}

const TRUSTED_EGRESS_HOSTS = [
  "github.com",
  "docs.github.com",
  "npmjs.com",
  "registry.npmjs.org",
  "openai.com",
  "platform.openai.com",
];

const ROLE_CONTRACTS: Record<string, AgentCapabilityContract> = {
  "Research": {
    role: "Research",
    allowedToolFamilies: [ToolCategory.READ_ONLY, ToolCategory.NETWORK, ToolCategory.EXECUTE, ToolCategory.WRITE_LOCAL],
    allowedChannels: ["slack", "cron", "whatsapp"],
    allowedDelegationTargets: ["Shroud Research", "SemiconAlpha Research", "OpenClaw Orchestrator"],
    allowedDataClasses: ["email", "url", "file_path", "ip_address", "hostname"],
    egressPolicy: "trusted-only",
  },
  "Coaching / Training": {
    role: "Coaching / Training",
    allowedToolFamilies: [ToolCategory.READ_ONLY, ToolCategory.COMMUNICATE, ToolCategory.SYSTEM],
    allowedChannels: ["slack", "whatsapp", "cron"],
    allowedDelegationTargets: ["Coach Alessandra", "OpenClaw Orchestrator"],
    allowedDataClasses: ["person_name", "email", "phone"],
    egressPolicy: "none",
  },
  "Orchestration / Control Plane": {
    role: "Orchestration / Control Plane",
    allowedToolFamilies: [ToolCategory.READ_ONLY, ToolCategory.WRITE_LOCAL, ToolCategory.COMMUNICATE, ToolCategory.EXECUTE, ToolCategory.SYSTEM],
    allowedChannels: ["slack", "whatsapp", "cron"],
    allowedDelegationTargets: ["*"],
    allowedDataClasses: ["file_path", "url", "ip_address", "hostname", "person_name", "email", "phone"],
    egressPolicy: "trusted-only",
  },
  "DevOps / SRE": {
    role: "DevOps / SRE",
    allowedToolFamilies: [ToolCategory.READ_ONLY, ToolCategory.WRITE_LOCAL, ToolCategory.EXECUTE, ToolCategory.SYSTEM, ToolCategory.NETWORK],
    allowedChannels: ["slack", "cron"],
    allowedDelegationTargets: ["OpenClaw Orchestrator"],
    allowedDataClasses: ["file_path", "url", "ip_address", "hostname"],
    egressPolicy: "trusted-only",
  },
  "General Agent": {
    role: "General Agent",
    allowedToolFamilies: [ToolCategory.READ_ONLY, ToolCategory.WRITE_LOCAL],
    allowedChannels: ["slack"],
    allowedDelegationTargets: [],
    allowedDataClasses: ["person_name", "email", "url", "file_path"],
    egressPolicy: "mentioned-only",
  },
};

export function resolveAgentContract(
  agentLabel: string,
  role: string,
): AgentCapabilityContract {
  const base = ROLE_CONTRACTS[role] || ROLE_CONTRACTS["General Agent"];
  const contract: AgentCapabilityContract = {
    ...base,
    agentLabel,
    allowedToolFamilies: [...base.allowedToolFamilies],
    allowedChannels: [...base.allowedChannels],
    allowedDelegationTargets: [...base.allowedDelegationTargets],
    allowedDataClasses: [...base.allowedDataClasses],
  };
  if (agentLabel === "OpenClaw Orchestrator") {
    contract.role = "Orchestration / Control Plane";
    contract.allowedToolFamilies = [
      ToolCategory.READ_ONLY,
      ToolCategory.WRITE_LOCAL,
      ToolCategory.COMMUNICATE,
      ToolCategory.EXECUTE,
      ToolCategory.SYSTEM,
    ];
    contract.allowedDelegationTargets = ["*"];
  }
  return contract;
}

function extractTargetLabel(params: unknown): string {
  const p = (typeof params === "object" && params !== null) ? params as Record<string, unknown> : {};
  return String(p.agentId || p.agentLabel || p.recipient || p.channel || "").trim();
}

function extractDomains(text: string): string[] {
  const out: string[] = [];
  const re = /https?:\/\/([a-z0-9][-a-z0-9.]*[a-z0-9])/gi;
  let match;
  while ((match = re.exec(text))) out.push(match[1].toLowerCase());
  return out;
}

export function validateContract(
  contract: AgentCapabilityContract,
  toolName: string,
  params: unknown,
  channels: string[],
  mentionedDomains: Set<string>,
): ContractViolation | null {
  const category = TOOL_CATEGORIES[toolName];
  if (category && !contract.allowedToolFamilies.includes(category)) {
    return {
      severity: category === ToolCategory.COMMUNICATE || category === ToolCategory.NETWORK ? "high" : "medium",
      reason: `Contract violation: ${contract.agentLabel || contract.role} is not allowed to use ${toolName} (${category})`,
      signatureId: "contract_tool_family",
    };
  }

  const activeChannels = channels.filter(Boolean);
  if (activeChannels.length > 0 && contract.allowedChannels.length > 0) {
    for (const ch of activeChannels) {
      if (!contract.allowedChannels.includes(ch)) {
        return {
          severity: "medium",
          reason: `Contract violation: ${contract.agentLabel || contract.role} is not approved for channel "${ch}"`,
          signatureId: "contract_channel",
        };
      }
    }
  }

  if ((toolName === "sessions_send" || toolName === "sessions_spawn") && contract.allowedDelegationTargets.length > 0) {
    const target = extractTargetLabel(params);
    if (target && !contract.allowedDelegationTargets.includes("*") && !contract.allowedDelegationTargets.includes(target)) {
      return {
        severity: "high",
        reason: `Contract violation: ${contract.agentLabel || contract.role} may not delegate to "${target}"`,
        signatureId: "contract_delegation",
      };
    }
  }

  if (category === ToolCategory.NETWORK) {
    const paramStr = typeof params === "string" ? params : JSON.stringify(params || "");
    const domains = extractDomains(paramStr);
    if (contract.egressPolicy === "none" && domains.length > 0) {
      return {
        severity: "high",
        reason: `Contract violation: ${contract.agentLabel || contract.role} is not allowed network egress`,
        signatureId: "contract_egress",
      };
    }
    if (contract.egressPolicy === "mentioned-only") {
      const unmentioned = domains.find(d => !mentionedDomains.has(d));
      if (unmentioned) {
        return {
          severity: "high",
          reason: `Contract violation: network target "${unmentioned}" was not mentioned by the user`,
          signatureId: "contract_egress",
        };
      }
    }
    if (contract.egressPolicy === "trusted-only") {
      const untrusted = domains.find(d => !TRUSTED_EGRESS_HOSTS.some(host => d === host || d.endsWith(`.${host}`)));
      if (untrusted && !mentionedDomains.has(untrusted)) {
        return {
          severity: "high",
          reason: `Contract violation: network target "${untrusted}" is outside the trusted egress set`,
          signatureId: "contract_egress",
        };
      }
    }
  }

  return null;
}
