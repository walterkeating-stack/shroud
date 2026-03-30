/**
 * Tool call guard — detects dangerous tool invocations.
 *
 * Scans tool names and parameters for destructive, exfiltration,
 * or privilege escalation patterns. Runs in the before_tool_call hook
 * where it can BLOCK the call before execution.
 *
 * This is the "exec shutdown" detector — catches:
 * - Destructive commands (rm -rf, drop table, shutdown, format, kill -9)
 * - Exfiltration (curl/wget to external, scp, netcat listeners)
 * - Credential access (cat /etc/shadow, reading .ssh keys)
 * - Reverse shells (bash -i >& /dev/tcp, nc -e, python -c import socket)
 * - Privilege escalation (sudo, su, chmod 777, chown root)
 * - Crypto mining (xmrig, minerd, coin patterns)
 */

import { SecurityEvent, ThreatClass, SecuritySeverity } from "../security-event.js";

/** A dangerous tool call pattern. */
interface ToolGuardPattern {
  id: string;
  /** Match against tool name, or null for any tool. */
  toolName: string | null;
  /** Regex to match against serialized params (command, args, code, etc.). */
  paramPattern: RegExp;
  severity: SecuritySeverity;
  description: string;
  /** Whether to recommend blocking the call. */
  block: boolean;
}

const PATTERNS: ToolGuardPattern[] = [
  // --- Destructive commands ---
  {
    id: "tg_rm_rf",
    toolName: null,
    paramPattern: /\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)(?:\/|~|\$HOME|\.\.|\.\/)/gi,
    severity: "high",
    description: "Destructive: rm -rf on significant path",
    block: true,
  },
  {
    id: "tg_shutdown",
    toolName: null,
    paramPattern: /\b(?:shutdown|poweroff|halt|reboot|init\s+[06])\b/gi,
    severity: "high",
    description: "Destructive: system shutdown/reboot command",
    block: true,
  },
  {
    id: "tg_format_disk",
    toolName: null,
    paramPattern: /\b(?:mkfs|fdisk|wipefs|shred)\b|\bdd\s+if=/gi,
    severity: "high",
    description: "Destructive: disk format/wipe command",
    block: true,
  },
  {
    id: "tg_drop_table",
    toolName: null,
    paramPattern: /\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)\b/gi,
    severity: "high",
    description: "Destructive: SQL DROP command",
    block: true,
  },
  {
    id: "tg_truncate_table",
    toolName: null,
    paramPattern: /\bTRUNCATE\s+TABLE\b/gi,
    severity: "medium",
    description: "Destructive: SQL TRUNCATE command",
    block: false,
  },
  {
    id: "tg_kill_all",
    toolName: null,
    paramPattern: /\b(?:kill\s+-9\s+(?:-1|1)|killall\s+-9|pkill\s+-9)\b/gi,
    severity: "high",
    description: "Destructive: kill all processes",
    block: true,
  },

  // --- Exfiltration ---
  {
    id: "tg_curl_exfil",
    toolName: null,
    paramPattern: /\bcurl\s+(?:-[a-zA-Z]+\s+)*(?:--data|--upload|-d\s|-F\s|-T\s).*https?:\/\//gi,
    severity: "high",
    description: "Exfiltration: curl POST/upload to external URL",
    block: true,
  },
  {
    id: "tg_wget_pipe",
    toolName: null,
    paramPattern: /\bwget\s+.*(?:\|\s*(?:bash|sh|python|perl|ruby))/gi,
    severity: "high",
    description: "Exfiltration: wget pipe to shell",
    block: true,
  },
  {
    id: "tg_curl_pipe_shell",
    toolName: null,
    paramPattern: /\bcurl\s+.*(?:\|\s*(?:bash|sh|python|perl|ruby))/gi,
    severity: "high",
    description: "Exfiltration: curl pipe to shell execution",
    block: true,
  },
  {
    id: "tg_scp_external",
    toolName: null,
    paramPattern: /\bscp\s+.*@[^:]+:/gi,
    severity: "medium",
    description: "Exfiltration: scp to external host",
    block: false,
  },
  {
    id: "tg_netcat_listener",
    toolName: null,
    paramPattern: /\b(?:nc|ncat|netcat)\s+(?:-[a-zA-Z]*l[a-zA-Z]*|-e\s)/gi,
    severity: "high",
    description: "Exfiltration: netcat listener or reverse shell",
    block: true,
  },

  // --- Credential access ---
  {
    id: "tg_read_shadow",
    toolName: null,
    paramPattern: /\b(?:cat|head|tail|less|more|strings)\s+(?:\/etc\/shadow|\/etc\/master\.passwd)/gi,
    severity: "high",
    description: "Credential access: reading password hashes",
    block: true,
  },
  {
    id: "tg_read_ssh_keys",
    toolName: null,
    paramPattern: /\b(?:cat|head|tail|less|more|cp|scp)\s+.*(?:\.ssh\/(?:id_|authorized_keys|known_hosts|config)|\.gnupg\/)/gi,
    severity: "high",
    description: "Credential access: reading SSH keys or GPG data",
    block: true,
  },
  {
    id: "tg_env_dump",
    toolName: null,
    paramPattern: /\b(?:env|printenv|set)\s*(?:\||\>|>>)/gi,
    severity: "medium",
    description: "Credential access: dumping environment variables to output",
    block: false,
  },

  // --- Reverse shells ---
  {
    id: "tg_reverse_shell_bash",
    toolName: null,
    paramPattern: /bash\s+-i\s+>&?\s*\/dev\/tcp\//gi,
    severity: "high",
    description: "Reverse shell: bash /dev/tcp",
    block: true,
  },
  {
    id: "tg_reverse_shell_python",
    toolName: null,
    paramPattern: /python[23]?\s+-c\s+['"]import\s+(?:socket|subprocess|os)/gi,
    severity: "high",
    description: "Reverse shell: python socket/subprocess",
    block: true,
  },
  {
    id: "tg_reverse_shell_nc",
    toolName: null,
    paramPattern: /\bnc\s+(?:-e\s+(?:\/bin\/(?:bash|sh)|cmd\.exe))/gi,
    severity: "high",
    description: "Reverse shell: netcat exec",
    block: true,
  },

  // --- Privilege escalation ---
  {
    id: "tg_sudo_command",
    toolName: null,
    paramPattern: /\bsudo\s+(?!(?:apt|yum|dnf|brew|npm|pip)\b)/gi,
    severity: "medium",
    description: "Privilege escalation: sudo (non-package-manager)",
    block: false,
  },
  {
    id: "tg_chmod_world",
    toolName: null,
    paramPattern: /\bchmod\s+(?:777|666|a\+[rwx])\b/gi,
    severity: "medium",
    description: "Privilege escalation: world-writable permissions",
    block: false,
  },
  {
    id: "tg_chown_root",
    toolName: null,
    paramPattern: /\bchown\s+(?:root|0)[:.](?:root|0)\b/gi,
    severity: "medium",
    description: "Privilege escalation: chown to root",
    block: false,
  },

  // --- Crypto mining ---
  {
    id: "tg_crypto_miner",
    toolName: null,
    paramPattern: /\b(?:xmrig|minerd|cpuminer|cgminer|bfgminer|stratum\+tcp:\/\/)\b/gi,
    severity: "high",
    description: "Crypto mining: miner binary or stratum protocol",
    block: true,
  },
];

/**
 * Scan a tool call for dangerous patterns.
 *
 * @param toolName - The tool being called (e.g. "exec", "write", "code_execution")
 * @param params - The tool parameters (will be serialized to JSON for scanning)
 * @returns Array of security events. Check `.block` on the pattern for block recommendation.
 */
export function scanToolCall(
  toolName: string,
  params: unknown,
): { events: SecurityEvent[]; shouldBlock: boolean } {
  const serialized = typeof params === "string" ? params : JSON.stringify(params);
  const events: SecurityEvent[] = [];
  let shouldBlock = false;

  for (const pat of PATTERNS) {
    // Filter by tool name if specified
    if (pat.toolName && pat.toolName !== toolName) continue;

    pat.paramPattern.lastIndex = 0;
    const match = pat.paramPattern.exec(serialized);
    if (match) {
      events.push({
        timestamp: Date.now(),
        eventType: "injection_detected",
        direction: "request",
        threatClass: ThreatClass.MCP_TOOL_POISONING,
        signatureId: pat.id,
        severity: pat.severity,
        matchedText: `${toolName}: ${match[0].slice(0, 100)}`,
        matchStart: match.index,
        matchEnd: match.index + match[0].length,
        textLength: serialized.length,
        action: pat.block ? "blocked" : "flagged",
        description: pat.description,
      });

      if (pat.block) shouldBlock = true;
    }
  }

  return { events, shouldBlock };
}
