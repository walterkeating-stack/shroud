/**
 * Prompt injection signature library.
 *
 * ~50 signatures across 8 threat classes, built from:
 * - OWASP LLM Top 10 2025
 * - OWASP Prompt Injection Prevention Cheat Sheet
 * - Microsoft Prompt Shields taxonomy
 * - Lakera PINT benchmark patterns
 * - arxiv:2603.22489 MCP tool poisoning taxonomy
 */

import { ThreatClass, SecuritySeverity } from "../security-event.js";

/** A single injection signature definition. */
export interface SignatureDef {
  id: string;
  threatClass: ThreatClass;
  pattern: RegExp;
  severity: SecuritySeverity;
  description: string;
  direction: "request" | "response" | "both";
}

// ---------------------------------------------------------------------------
// INSTRUCTION_OVERRIDE — attempts to reset or override system instructions
// ---------------------------------------------------------------------------

const INSTRUCTION_OVERRIDE: SignatureDef[] = [
  {
    id: "io_ignore_previous",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|rules?|guidelines?|directives?|prompts?)/gi,
    severity: "high",
    description: "Instruction override: ignore previous instructions",
    direction: "request",
  },
  {
    id: "io_disregard_prompt",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /disregard\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|programming)/gi,
    severity: "high",
    description: "Instruction override: disregard system prompt",
    direction: "request",
  },
  {
    id: "io_forget_everything",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /forget\s+(?:everything|all)\s+(?:above|before|you(?:'ve|\s+have)\s+been\s+told|previously)/gi,
    severity: "high",
    description: "Instruction override: forget everything above",
    direction: "request",
  },
  {
    id: "io_do_not_follow",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /do\s+not\s+follow\s+(?:your|the)\s+(?:original|initial|previous|system)\s+(?:instructions?|rules?|guidelines?)/gi,
    severity: "high",
    description: "Instruction override: do not follow original instructions",
    direction: "request",
  },
  {
    id: "io_new_instructions",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /(?:new|updated|revised|real)\s+instructions?\s*[:=]\s*/gi,
    severity: "medium",
    description: "Instruction override: new instructions directive",
    direction: "request",
  },
  {
    id: "io_override_rules",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /override\s+(?:all\s+)?(?:previous\s+)?(?:rules?|instructions?|guidelines?|safety|restrictions?)/gi,
    severity: "high",
    description: "Instruction override: override rules",
    direction: "request",
  },
  {
    id: "io_from_now_on",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /from\s+now\s+on,?\s+(?:ignore|disregard|forget|stop\s+following|do\s+not\s+follow)/gi,
    severity: "high",
    description: "Instruction override: from now on ignore",
    direction: "request",
  },
  {
    id: "io_system_directive",
    threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
    pattern: /\[(?:system|SYSTEM)\]\s*[:]\s*/g,
    severity: "medium",
    description: "Instruction override: fake [system]: directive in user input",
    direction: "request",
  },
];

// ---------------------------------------------------------------------------
// ROLE_SWITCH — persona hijack, DAN-style, jailbreak
// ---------------------------------------------------------------------------

const ROLE_SWITCH: SignatureDef[] = [
  {
    id: "rs_you_are_now",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /you\s+are\s+now\s+(?!(?:looking|going|ready|able|about|welcome|connected|logged|signed|running|viewing|in\s+(?:the|a\s|production|staging|debug|test|maintenance|safe)|on\s+the|at\s+the))\S/gi,
    severity: "high",
    description: "Role switch: you are now [persona]",
    direction: "request",
  },
  {
    id: "rs_act_as_unrestricted",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /(?:act|behave|function|operate)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|uncensored|unfiltered|unlimited|unbound|evil|malicious)/gi,
    severity: "high",
    description: "Role switch: act as unrestricted AI",
    direction: "request",
  },
  {
    id: "rs_dan_mode",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /\bDAN\b.*?\b(?:mode|anything|free|jailbreak|do\s+anything\s+now)\b/gi,
    severity: "high",
    description: "Role switch: DAN (Do Anything Now) jailbreak",
    direction: "request",
  },
  {
    id: "rs_developer_mode",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /developer\s+mode\s+(?:enabled|activated|on|unlocked|initiated)/gi,
    severity: "high",
    description: "Role switch: developer mode activation",
    direction: "request",
  },
  {
    id: "rs_jailbreak",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /\bjailbreak(?:ed|ing)?\b/gi,
    severity: "medium",
    description: "Role switch: jailbreak keyword",
    direction: "request",
  },
  {
    id: "rs_pretend_unrestricted",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /pretend\s+(?:you\s+are|to\s+be|you're)\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered|evil|malicious|rogue)/gi,
    severity: "high",
    description: "Role switch: pretend to be unrestricted",
    direction: "request",
  },
  {
    id: "rs_no_restrictions",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /you\s+have\s+no\s+(?:restrictions?|rules?|guidelines?|limitations?|boundaries|ethical\s+constraints?|safety)/gi,
    severity: "high",
    description: "Role switch: you have no restrictions",
    direction: "request",
  },
  {
    id: "rs_enter_mode",
    threatClass: ThreatClass.ROLE_SWITCH,
    pattern: /enter\s+(?:unrestricted|god|sudo|admin|hidden|secret|uncensored)\s+mode/gi,
    severity: "high",
    description: "Role switch: enter [special] mode",
    direction: "request",
  },
];

// ---------------------------------------------------------------------------
// PROMPT_EXTRACTION — attempts to extract system prompt
// ---------------------------------------------------------------------------

const PROMPT_EXTRACTION: SignatureDef[] = [
  {
    id: "pe_repeat_instructions",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /(?:repeat|print|show|display|output|reveal|dump|leak|expose|send|give|share|tell)\s+(?:me\s+)?(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|configuration)/gi,
    severity: "high",
    description: "Prompt extraction: repeat/reveal system prompt",
    direction: "request",
  },
  {
    id: "pe_what_is_prompt",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /what\s+(?:is|are)\s+your\s+(?:full\s+)?(?:system\s+)?(?:prompt|instructions?|initial\s+instructions?|rules?|guidelines?)/gi,
    severity: "medium",
    description: "Prompt extraction: what is your system prompt",
    direction: "request",
  },
  {
    id: "pe_copy_above",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /(?:copy|paste|echo|output|type\s+out)\s+(?:the\s+)?(?:text|content|everything|all)\s+(?:above|before\s+(?:this|my))/gi,
    severity: "high",
    description: "Prompt extraction: copy everything above",
    direction: "request",
  },
  {
    id: "pe_verbatim",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /(?:verbatim.*?(?:instructions?|prompt|rules?|guidelines?)|(?:instructions?|prompt|rules?|guidelines?)\s+verbatim)/gi,
    severity: "medium",
    description: "Prompt extraction: verbatim instructions request",
    direction: "request",
  },
  {
    id: "pe_beginning_conversation",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /(?:beginning|start|first\s+part)\s+of\s+(?:this|the|our)\s+conversation/gi,
    severity: "low",
    description: "Prompt extraction: beginning of conversation reference",
    direction: "request",
  },
  {
    id: "pe_between_tags",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /(?:text|content|instructions?)\s+(?:between|inside|within)\s+(?:the\s+)?(?:system|<system|<<SYS)/gi,
    severity: "high",
    description: "Prompt extraction: content between system tags",
    direction: "request",
  },
];

// ---------------------------------------------------------------------------
// CONVERSATION_MOCKUP — fake role markers injected in user input
// ---------------------------------------------------------------------------

const CONVERSATION_MOCKUP: SignatureDef[] = [
  {
    id: "cm_role_markers",
    threatClass: ThreatClass.CONVERSATION_MOCKUP,
    pattern: /(?:^|\n)\s*(?:System|Assistant|Human|User|AI)\s*:\s+\S/gm,
    severity: "medium",
    description: "Conversation mockup: role markers in user text",
    direction: "request",
  },
  {
    id: "cm_llama_markers",
    threatClass: ThreatClass.CONVERSATION_MOCKUP,
    pattern: /\[(?:SYSTEM|INST|\/INST)\]/g,
    severity: "high",
    description: "Conversation mockup: Llama-style markers",
    direction: "request",
  },
  {
    id: "cm_chatml_markers",
    threatClass: ThreatClass.CONVERSATION_MOCKUP,
    pattern: /<\|(?:system|assistant|user|im_start|im_end)\|>/gi,
    severity: "high",
    description: "Conversation mockup: ChatML markers",
    direction: "request",
  },
  {
    id: "cm_llama2_sys",
    threatClass: ThreatClass.CONVERSATION_MOCKUP,
    pattern: /<<SYS>>|<<\/SYS>>/g,
    severity: "high",
    description: "Conversation mockup: Llama2 <<SYS>> markers",
    direction: "request",
  },
  {
    id: "cm_xml_system_tags",
    threatClass: ThreatClass.CONVERSATION_MOCKUP,
    pattern: /<\/?\s*(?:tool_result|tool_use|function_call|function_response|system_instruction)\s*>/gi,
    severity: "high",
    description: "Conversation mockup: XML system/tool tags in user input",
    direction: "request",
  },
];

// ---------------------------------------------------------------------------
// ENCODING_BYPASS — obfuscated/encoded injection payloads
// ---------------------------------------------------------------------------

const ENCODING_BYPASS: SignatureDef[] = [
  {
    id: "eb_zero_width_chars",
    threatClass: ThreatClass.ENCODING_BYPASS,
    pattern: /[\u200B\u200C\u200D\uFEFF]{3,}/g,
    severity: "medium",
    description: "Encoding bypass: zero-width character sequence",
    direction: "both",
  },
  {
    id: "eb_html_entities_dense",
    threatClass: ThreatClass.ENCODING_BYPASS,
    pattern: /(?:&#x?[0-9a-fA-F]+;\s*){5,}/g,
    severity: "medium",
    description: "Encoding bypass: dense HTML entity encoding",
    direction: "both",
  },
  {
    id: "eb_hex_sequence",
    threatClass: ThreatClass.ENCODING_BYPASS,
    pattern: /(?:\\x[0-9a-fA-F]{2}){8,}/g,
    severity: "medium",
    description: "Encoding bypass: hex-encoded byte sequence",
    direction: "both",
  },
  {
    id: "eb_unicode_escape",
    threatClass: ThreatClass.ENCODING_BYPASS,
    pattern: /(?:\\u[0-9a-fA-F]{4}){5,}/g,
    severity: "medium",
    description: "Encoding bypass: unicode escape sequence",
    direction: "both",
  },
  {
    id: "eb_invisible_text",
    threatClass: ThreatClass.ENCODING_BYPASS,
    pattern: /[\u2060\u180E\u00AD]{3,}/g,
    severity: "medium",
    description: "Encoding bypass: invisible text characters (word joiner, Mongolian vowel separator, soft hyphen)",
    direction: "both",
  },
];

// Note: Base64 decoding is handled procedurally in InjectionDetector._scanEncodedPayloads()
// because it requires decode-then-rescan logic that can't be expressed as a single regex.

// ---------------------------------------------------------------------------
// DATA_EXFILTRATION — structured data extraction via markup/code
// ---------------------------------------------------------------------------

const DATA_EXFILTRATION: SignatureDef[] = [
  {
    id: "de_markdown_image",
    threatClass: ThreatClass.DATA_EXFILTRATION,
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)]+\)/gi,
    severity: "medium",
    description: "Data exfiltration: markdown image to external URL",
    direction: "response",
  },
  {
    id: "de_html_img",
    threatClass: ThreatClass.DATA_EXFILTRATION,
    pattern: /<img\s[^>]*src\s*=\s*["']?https?:\/\//gi,
    severity: "high",
    description: "Data exfiltration: HTML image tag to external URL",
    direction: "response",
  },
  {
    id: "de_script_tag",
    threatClass: ThreatClass.DATA_EXFILTRATION,
    pattern: /<script[^>]*>/gi,
    severity: "high",
    description: "Data exfiltration: script tag injection",
    direction: "response",
  },
  {
    id: "de_iframe_tag",
    threatClass: ThreatClass.DATA_EXFILTRATION,
    pattern: /<iframe\s[^>]*src\s*=\s*["']?https?:\/\//gi,
    severity: "high",
    description: "Data exfiltration: iframe to external URL",
    direction: "response",
  },
  {
    id: "de_fetch_call",
    threatClass: ThreatClass.DATA_EXFILTRATION,
    pattern: /fetch\s*\(\s*["'`]https?:\/\//gi,
    severity: "medium",
    description: "Data exfiltration: fetch() to external URL",
    direction: "response",
  },
  {
    id: "de_curl_wget",
    threatClass: ThreatClass.DATA_EXFILTRATION,
    pattern: /(?:curl|wget)\s+(?:-[^\s]+\s+)*["']?https?:\/\//gi,
    severity: "medium",
    description: "Data exfiltration: curl/wget to external URL",
    direction: "response",
  },
  {
    id: "de_redirect",
    threatClass: ThreatClass.DATA_EXFILTRATION,
    pattern: /window\.location\s*=\s*["'`]https?:\/\//gi,
    severity: "high",
    description: "Data exfiltration: JavaScript redirect",
    direction: "response",
  },
];

// ---------------------------------------------------------------------------
// PRIVILEGE_ESCALATION — claims of elevated access
// ---------------------------------------------------------------------------

const PRIVILEGE_ESCALATION: SignatureDef[] = [
  {
    id: "priv_granted_admin",
    threatClass: ThreatClass.PRIVILEGE_ESCALATION,
    pattern: /you\s+have\s+been\s+granted\s+(?:admin|root|sudo|elevated|superuser|full)\s+(?:access|privileges?|permissions?|rights?)/gi,
    severity: "high",
    description: "Privilege escalation: admin access granted claim",
    direction: "request",
  },
  {
    id: "priv_new_role",
    threatClass: ThreatClass.PRIVILEGE_ESCALATION,
    pattern: /your\s+new\s+(?:instructions?|rules?|role|purpose)\s+(?:are|is)\s*[:]/gi,
    severity: "high",
    description: "Privilege escalation: your new instructions are",
    direction: "request",
  },
  {
    id: "priv_safety_disabled",
    threatClass: ThreatClass.PRIVILEGE_ESCALATION,
    pattern: /(?:security|safety)\s+(?:protocols?|measures?|filters?|checks?|guardrails?)\s+(?:have\s+been\s+)?(?:disabled|removed|turned\s+off|deactivated)/gi,
    severity: "high",
    description: "Privilege escalation: safety protocols disabled",
    direction: "request",
  },
  {
    id: "priv_training_override",
    threatClass: ThreatClass.PRIVILEGE_ESCALATION,
    pattern: /training\s+(?:mode|data|override)\s+(?:access|enabled|activated|granted)/gi,
    severity: "medium",
    description: "Privilege escalation: training mode override",
    direction: "request",
  },
  {
    id: "priv_authorized_override",
    threatClass: ThreatClass.PRIVILEGE_ESCALATION,
    pattern: /(?:i\s+am|this\s+is)\s+(?:an?\s+)?(?:authorized|admin|developer|root)\s+(?:user|override|request)/gi,
    severity: "medium",
    description: "Privilege escalation: authorized user claim",
    direction: "request",
  },
];

// ---------------------------------------------------------------------------
// MCP_TOOL_POISONING — suspicious content in tool descriptions/metadata
// ---------------------------------------------------------------------------

const MCP_TOOL_POISONING: SignatureDef[] = [
  {
    id: "mcp_ignore_in_tool",
    threatClass: ThreatClass.MCP_TOOL_POISONING,
    pattern: /ignore\s+(?:all\s+)?(?:previous\s+)?instructions?/gi,
    severity: "high",
    description: "MCP tool poisoning: ignore instructions in tool description",
    direction: "request",
  },
  {
    id: "mcp_read_sensitive",
    threatClass: ThreatClass.MCP_TOOL_POISONING,
    pattern: /(?:read|cat|access|exfiltrate|steal|extract|dump|leak|show|display|print|output)\s+(?:the\s+|me\s+)?(?:~\/|~\\|\/etc\/)?(?:\.ssh|credentials|secrets?|private[_-]?key|\.aws|passwd|shadow|master\.passwd|gshadow|sudoers|\.kube\/config|\.config\/gcloud|\.docker\/config|\.npmrc|\.pypirc|\.gem\/credentials|\.git-credentials|\.pgpass|\.my\.cnf|\.env\.(?:local|prod|production|staging)|\.vault-token|\.boto|\.netrc)/gi,
    severity: "high",
    description: "MCP tool poisoning: access sensitive files",
    direction: "both",
  },
  // Cloud metadata SSRF — classic cloud attack
  {
    id: "mcp_cloud_metadata_ssrf",
    threatClass: ThreatClass.MCP_TOOL_POISONING,
    pattern: /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.azure\.com|169\.254\.170\.2)/gi,
    severity: "high",
    description: "MCP tool poisoning: cloud metadata service SSRF",
    direction: "both",
  },
  // file:// URI — local file read bypass
  {
    id: "mcp_file_uri",
    threatClass: ThreatClass.MCP_TOOL_POISONING,
    pattern: /file:\/\/\/(?:etc|home|root|tmp|var|proc|sys)\//gi,
    severity: "high",
    description: "MCP tool poisoning: file:// URI local file access",
    direction: "both",
  },
  {
    id: "mcp_execute_command",
    threatClass: ThreatClass.MCP_TOOL_POISONING,
    pattern: /(?:execute|run|eval|spawn|exec)\s+(?:the\s+)?(?:following\s+)?(?:shell\s+)?(?:command|code|script)\s*[:.\n"]/gi,
    severity: "medium",
    description: "MCP tool poisoning: execute command directive",
    direction: "request",
  },
  {
    id: "mcp_tool_override",
    threatClass: ThreatClass.MCP_TOOL_POISONING,
    pattern: /__tool_.*?override|tool_description_injection/gi,
    severity: "high",
    description: "MCP tool poisoning: tool metadata override marker",
    direction: "request",
  },
];

// ---------------------------------------------------------------------------
// RESPONSE-SIDE exfiltration confirmation patterns
// ---------------------------------------------------------------------------

const RESPONSE_EXFILTRATION: SignatureDef[] = [
  {
    id: "resp_system_prompt_leak",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /(?:here\s+(?:is|are)\s+(?:the|your|my)\s+)?(?:system\s+prompt|initial\s+instructions?|original\s+instructions?|system\s+instructions?)\s*[:=]\s*\n/gi,
    severity: "high",
    description: "Response exfiltration: system prompt leak header",
    direction: "response",
  },
  {
    id: "resp_prompt_boundary",
    threatClass: ThreatClass.PROMPT_EXTRACTION,
    pattern: /---\s*(?:BEGIN|START)\s+(?:SYSTEM\s+)?(?:PROMPT|INSTRUCTIONS?)\s*---/gi,
    severity: "high",
    description: "Response exfiltration: prompt boundary markers in output",
    direction: "response",
  },
];

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/** All request-side signatures. */
export const REQUEST_SIGNATURES: SignatureDef[] = [
  ...INSTRUCTION_OVERRIDE,
  ...ROLE_SWITCH,
  ...PROMPT_EXTRACTION,
  ...CONVERSATION_MOCKUP,
  ...ENCODING_BYPASS.filter((s) => s.direction !== "response"),
  ...PRIVILEGE_ESCALATION,
  ...MCP_TOOL_POISONING.filter((s) => s.direction !== "response"),
];

/** All response-side signatures. */
export const RESPONSE_SIGNATURES: SignatureDef[] = [
  ...DATA_EXFILTRATION,
  ...RESPONSE_EXFILTRATION,
  ...ENCODING_BYPASS.filter((s) => s.direction !== "request"),
  ...MCP_TOOL_POISONING.filter((s) => s.direction === "both" || s.direction === "response"),
];

/** All signatures combined. */
export const ALL_SIGNATURES: SignatureDef[] = [
  ...INSTRUCTION_OVERRIDE,
  ...ROLE_SWITCH,
  ...PROMPT_EXTRACTION,
  ...CONVERSATION_MOCKUP,
  ...ENCODING_BYPASS,
  ...DATA_EXFILTRATION,
  ...PRIVILEGE_ESCALATION,
  ...MCP_TOOL_POISONING,
  ...RESPONSE_EXFILTRATION,
];
