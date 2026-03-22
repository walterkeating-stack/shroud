/** Regex-based detectors for structured sensitive data. */

import { Category, DetectedEntity } from "../types.js";
import { BaseDetector } from "./base.js";

/**
 * Subnet masks and wildcard masks should never be obfuscated.
 * Common mask prefixes used to avoid false-positive IP obfuscation.
 */
const MASK_PREFIXES: ReadonlySet<string> = new Set([
  "255.", "0.0.0.", "0.0.255.", "0.0.15.", "0.0.3.", "0.0.1.",
  "0.255.", "0.128.", "0.192.", "0.224.", "0.240.", "0.248.",
  "0.252.", "128.0.", "192.0.0.", "224.0.", "240.0.", "248.0.",
  "252.0.", "254.0.", "127.0.",
]);

/** Heuristic: return true for subnet masks and wildcard masks. */
export function isMask(ip: string): boolean {
  for (const pfx of MASK_PREFIXES) {
    if (ip.startsWith(pfx)) {
      return true;
    }
  }
  const octets = ip.split(".");
  if (octets.length === 4) {
    // Common masks: all octets are 0 or 255
    if (octets.every((o) => o === "0" || o === "255")) {
      return true;
    }
    // Wildcard masks like 0.0.0.X
    if (octets[0] === "0" && octets[1] === "0" && octets[2] === "0") {
      return true;
    }
  }
  return false;
}

/** A named regex pattern with its category. */
export interface PatternDef {
  name: string;
  pattern: RegExp;
  category: Category;
  confidence: number;
}

/** All built-in patterns. */
export const BUILTIN_PATTERNS: PatternDef[] = [
  // --- Core PII ---
  {
    name: "email",
    // Stricter: local part must start/end with alnum, no consecutive dots
    pattern: /\b[a-zA-Z0-9](?:[a-zA-Z0-9._%+\-]*[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b/g,
    category: Category.EMAIL,
    confidence: 0.95,
  },
  {
    name: "ipv4",
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    category: Category.IP_ADDRESS,
    confidence: 0.95,
  },
  {
    name: "ipv6",
    // Full, compressed (::), and IPv4-mapped forms
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4})?(?::\b[0-9a-fA-F]{1,4})*\b|\b::(?:ffff:)?(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g,
    category: Category.IP_ADDRESS,
    confidence: 0.9,
  },
  {
    name: "phone_us",
    pattern: /\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b/g,
    category: Category.PHONE,
    confidence: 0.8,
  },
  {
    name: "phone_intl",
    pattern: /(?<!\w)\+\d{1,3}[\s\-]?\d{4,14}\b/g,
    category: Category.PHONE,
    confidence: 0.75,
  },
  {
    name: "credit_card",
    pattern: /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g,
    category: Category.CREDIT_CARD,
    confidence: 0.85,
  },
  {
    name: "ssn",
    pattern: /\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b/g,
    category: Category.SSN,
    confidence: 0.9,
  },
  // --- API keys and tokens ---
  {
    name: "api_key_generic",
    pattern: /\b(?:sk|pk|api|key|token|secret|access)[-_][a-zA-Z0-9\-_]{20,}\b/gi,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "api_key_aws",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "bearer_token",
    pattern: /(?:Bearer\s+)([A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*\.?[A-Za-z0-9\-_=]*)/g,
    category: Category.API_KEY,
    confidence: 0.9,
  },
  // --- URLs and paths ---
  {
    name: "url",
    pattern: /https?:\/\/[^\s<>"')\]]+/g,
    category: Category.URL,
    confidence: 0.9,
  },
  {
    name: "file_path_unix",
    // Require at least 3 segments to avoid matching git diff /a/ /b/ paths
    pattern: /(?<!\w)(?:\/[\w.\-]+){3,}(?:\.\w+)?/g,
    category: Category.FILE_PATH,
    confidence: 0.7,
  },
  {
    name: "file_path_windows",
    pattern: /\b[A-Z]:\\(?:[\w.\-]+\\)*[\w.\-]+\b/g,
    category: Category.FILE_PATH,
    confidence: 0.8,
  },
  // --- Network infrastructure ---
  {
    name: "mac_address",
    pattern: /\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b|\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b/g,
    category: Category.MAC_ADDRESS,
    confidence: 0.95,
  },
  {
    name: "snmp_community",
    pattern: /(?:snmp-server\s+community\s+)(\S+)/gi,
    category: Category.SNMP_COMMUNITY,
    confidence: 1.0,
  },
  {
    name: "snmp_auth_priv",
    pattern: /(?:auth\s+\S+\s+)(\S+)(?:\s+priv\s+\S+\s+\d*\s*)(\S+)/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  // --- Cisco secrets and hashes ---
  {
    name: "cisco_enable_secret",
    pattern: /(?:enable\s+secret\s+\d+\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "cisco_password_line",
    // "password 7 XXXX" or "password 0 XXXX"
    pattern: /(?:password\s+(?:[057]\s+))(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "cisco_username_secret",
    // "username admin secret 5 $1$..." or "username admin password 7 ..."
    pattern: /(?:username\s+\S+\s+(?:secret|password)\s+\d+\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "cisco_password_hash_type5",
    pattern: /\$1\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "cisco_password_hash_type8",
    pattern: /\$8\$[A-Za-z0-9./]+\$[A-Za-z0-9./+]+/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "cisco_password_hash_type9",
    pattern: /\$9\$[A-Za-z0-9./]+\$[A-Za-z0-9./+]+/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "cisco_type7",
    // Cisco type 7 obfuscated passwords: even-length hex starting with known salts
    pattern: /(?:password\s+7\s+)([0-9A-Fa-f]{4,})/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "key_string",
    pattern: /(?:key-string\s+(?:\d+\s+)?)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "tacacs_key",
    pattern: /(?:tacacs-server\s+(?:host\s+\S+\s+)?key\s+(?:\d+\s+)?)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "radius_key",
    pattern: /(?:radius-server\s+(?:host\s+\S+\s+)?key\s+(?:\d+\s+)?)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "ntp_auth_key",
    pattern: /(?:ntp\s+authentication-key\s+\d+\s+md5\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  // --- BGP / OSPF / routing ---
  {
    name: "bgp_asn",
    pattern: /\b(?:router\s+bgp|remote-as|local-as|peer-as)\s+(\d{4,6})\b/gi,
    category: Category.BGP_ASN,
    confidence: 0.95,
  },
  {
    name: "bgp_neighbor_password",
    pattern: /(?:neighbor\s+\S+\s+password\s+(?:\d+\s+)?)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "ospf_router_id",
    pattern: /(?:router-id\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g,
    category: Category.OSPF_ID,
    confidence: 0.95,
  },
  {
    name: "ospf_area",
    // "area 0.0.0.1" or "area 1" style
    pattern: /(?:area\s+)(\d{1,3}(?:\.\d{1,3}){3})\b/g,
    category: Category.OSPF_ID,
    confidence: 0.85,
  },
  {
    name: "ospf_auth_key",
    pattern: /(?:(?:ip\s+ospf\s+)?(?:authentication-key|message-digest-key\s+\d+\s+md5)\s+(?:\d+\s+)?)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  // --- VLAN ---
  {
    name: "vlan_name",
    // "name VLAN_NAME" inside a vlan context, or "vlan 100" with a name
    pattern: /(?:vlan\s+\d+\s*\n\s*name\s+)(\S+)/gm,
    category: Category.VLAN_ID,
    confidence: 0.9,
  },
  {
    name: "vlan_range",
    // "switchport trunk allowed vlan 100,200,300-400"
    pattern: /(?:allowed\s+vlan\s+(?:add\s+)?)(\d[\d,\-]+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },
  // --- Interface descriptions ---
  {
    name: "interface_description",
    // "description LINK TO CUSTOMER-X" on an interface
    pattern: /(?:^\s*description\s+)(.+)$/gm,
    category: Category.INTERFACE_DESC,
    confidence: 0.9,
  },
  // --- Route maps / ACLs ---
  {
    name: "route_map_name",
    pattern: /(?:route-map\s+)(\S+)(?:\s+(?:permit|deny))?/g,
    category: Category.ROUTE_MAP,
    confidence: 0.85,
  },
  {
    name: "prefix_list_name",
    pattern: /(?:ip\s+prefix-list\s+)(\S+)/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },
  {
    name: "acl_name",
    pattern: /(?:ip\s+access-list\s+(?:standard|extended)\s+)(\S+)/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },
];

/** Check if two spans overlap. */
function spansOverlap(
  spanStart: number,
  spanEnd: number,
  seenSpans: Array<[number, number]>,
): boolean {
  for (const [s, e] of seenSpans) {
    if ((s <= spanStart && spanStart < e) || (s < spanEnd && spanEnd <= e)) {
      return true;
    }
  }
  return false;
}

/** Detects sensitive entities using regex patterns. */
export class RegexDetector implements BaseDetector {
  readonly name = "regex";
  private patterns: PatternDef[];

  constructor(extraPatterns?: PatternDef[]) {
    this.patterns = [...BUILTIN_PATTERNS];
    if (extraPatterns) {
      this.patterns.push(...extraPatterns);
    }
  }

  detect(text: string): DetectedEntity[] {
    const entities: DetectedEntity[] = [];
    const seenSpans: Array<[number, number]> = [];

    for (const pdef of this.patterns) {
      // Reset lastIndex for the global regex
      pdef.pattern.lastIndex = 0;

      for (const match of text.matchAll(pdef.pattern)) {
        // If the pattern has capture groups, emit each group as a
        // separate entity. Otherwise use the full match.
        const groups = match.slice(1);
        const hasGroups = groups.some((g) => g !== undefined);

        if (hasGroups) {
          for (let i = 1; i < match.length; i++) {
            const grp = match[i];
            if (grp === undefined) {
              continue;
            }
            // Get the start of this capture group from the match indices
            // We need to find the position of the group within the full match
            const fullMatchStart = match.index!;
            const fullMatch = match[0];
            // Find the group's position within the full match string
            const grpStart = findGroupStart(fullMatch, fullMatchStart, grp, match, i);
            const grpEnd = grpStart + grp.length;
            const span: [number, number] = [grpStart, grpEnd];

            if (spansOverlap(span[0], span[1], seenSpans)) {
              continue;
            }
            // Skip subnet/wildcard masks for IP-like values
            if (pdef.category === Category.IP_ADDRESS && isMask(grp)) {
              continue;
            }
            seenSpans.push(span);
            entities.push({
              value: grp,
              start: grpStart,
              end: grpEnd,
              category: pdef.category,
              confidence: pdef.confidence,
              detector: this.name,
            });
          }
        } else {
          const start = match.index!;
          const end = start + match[0].length;
          const span: [number, number] = [start, end];

          if (spansOverlap(span[0], span[1], seenSpans)) {
            continue;
          }
          const value = match[0];
          // Skip subnet/wildcard masks
          if (pdef.category === Category.IP_ADDRESS && isMask(value)) {
            continue;
          }
          seenSpans.push(span);
          entities.push({
            value,
            start: span[0],
            end: span[1],
            category: pdef.category,
            confidence: pdef.confidence,
            detector: this.name,
          });
        }
      }
    }

    entities.sort((a, b) => a.start - b.start);
    return entities;
  }
}

/**
 * Find the absolute start position of a capture group within text.
 * Uses the full match string and searches for the group value
 * starting from after previous groups.
 */
function findGroupStart(
  fullMatch: string,
  fullMatchStart: number,
  groupValue: string,
  match: RegExpMatchArray,
  groupIndex: number,
): number {
  // Search for the group value within the full match, accounting for
  // previous groups that may contain the same text.
  let searchFrom = 0;
  for (let prev = 1; prev < groupIndex; prev++) {
    if (match[prev] !== undefined) {
      const prevPos = fullMatch.indexOf(match[prev], searchFrom);
      if (prevPos !== -1) {
        searchFrom = prevPos + match[prev].length;
      }
    }
  }
  const posInMatch = fullMatch.indexOf(groupValue, searchFrom);
  return fullMatchStart + posInMatch;
}
