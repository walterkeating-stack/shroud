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

/**
 * RFC 5737 documentation/example ranges and well-known placeholders.
 * These should never be obfuscated — they're teaching/testing values.
 */
const DOC_IP_PREFIXES = [
  // RFC 5737 TEST-NETs removed: these appear in real configs as stand-in
  // addresses and must be obfuscated when users paste their infrastructure.
  "233.252.0.",   // MCAST-TEST-NET (RFC 6676)
  "100.51.16.",   // Benchmarking (RFC 5180)
];

const DOC_DOMAINS = new Set([
  "example.com", "example.net", "example.org",  // RFC 2606
  "localhost", "invalid",
]);

const DOC_HOSTNAMES = new Set([
  "localhost", "HOSTNAME", "EXAMPLE", "CHANGEME",
  "YOUR_HOST", "YOURHOST", "hostname", "example",
]);

/** Hostname prefixes that are documentation/example labels, not real devices. */
const DOC_HOSTNAME_PREFIXES = [
  "TEST-NET-", "TEST-", "RFC-", "EXAMPLE-", "SAMPLE-", "DEMO-", "DUMMY-",
  "PLACEHOLDER-", "CHANGEME-", "TODO-",
];

/** IPv6 documentation/reserved prefixes that should not be obfuscated. */
const DOC_IPV6_PREFIXES = [
  "2001:db8:",    // RFC 3849 documentation prefix
  "2001:0db8:",   // Same, zero-padded
];
const DOC_IPV6_EXACT = new Set([
  "::1",          // Loopback
  "::0",          // Unspecified
  "::",           // Unspecified
]);

/** Check if a value is a well-known documentation/example/placeholder. */
export function isDocExample(value: string, category: Category): boolean {
  switch (category) {
    case Category.IP_ADDRESS: {
      // IPv6 check
      if (value.includes(":")) {
        const lower = value.toLowerCase();
        if (DOC_IPV6_EXACT.has(lower)) return true;
        for (const pfx of DOC_IPV6_PREFIXES) {
          if (lower.startsWith(pfx)) return true;
        }
        return false;
      }
      // IPv4 check
      for (const pfx of DOC_IP_PREFIXES) {
        if (value.startsWith(pfx)) return true;
      }
      return false;
    }

    case Category.EMAIL:
    case Category.URL: {
      const lower = value.toLowerCase();
      for (const d of DOC_DOMAINS) {
        if (lower.includes(`@${d}`) || lower.includes(`//${d}`) || lower.endsWith(`.${d}`)) {
          return true;
        }
      }
      return false;
    }

    case Category.BGP_ASN:
      // Private ASNs are real infra identifiers — don't skip them
      return false;

    case Category.HOSTNAME:
      if (DOC_HOSTNAMES.has(value) || DOC_HOSTNAMES.has(value.toUpperCase())) return true;
      for (const pfx of DOC_HOSTNAME_PREFIXES) {
        if (value.toUpperCase().startsWith(pfx)) return true;
      }
      return false;

    default:
      return false;
  }
}

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
    // Full 8-group, compressed ::, loopback ::1, link-local, IPv4-mapped
    // Uses \b where possible; :: forms use lookaround for proper boundary
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,6}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,7}\b|(?:^|(?<=[\s,;=(]))::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?(?=$|[\s,;)\]\/])|(?:^|(?<=[\s,;=(]))::(?:ffff:)?(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?=$|[\s,;)\]\/])/g,
    category: Category.IP_ADDRESS,
    confidence: 0.9,
  },
  {
    name: "phone_us",
    // Supports dash, space, and dot separators: 555-123-4567, 555.123.4567, (408) 555-9182
    pattern: /\b(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b/g,
    category: Category.PHONE,
    confidence: 0.8,
  },
  {
    name: "phone_intl",
    // International: +CC followed by 7-14 digits in groups separated by spaces/dashes
    // Matches: +44 20 7946 0958, +61 2 8765 4321, +33 1 42 68 53 00, +14085559182
    pattern: /(?<!\w)\+\d{1,3}[\s\-]?\d(?:[\s\-]?\d){6,13}(?!\d)/g,
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
  // --- URL/connection-string embedded credentials (before URL pattern to claim spans first) ---
  {
    name: "url_query_password",
    pattern: /[?&](?:password|passwd|secret|token|api_key|apikey|auth_token|access_token)=([^&\s]{3,})/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },
  {
    name: "connection_string_password",
    pattern: /(?:postgres|mysql|mongodb|redis|amqp|mssql|mariadb|oracle):\/\/[^:]+:([^@]{3,})@/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },
  // --- URLs and paths ---
  {
    name: "url",
    // Exclude trailing punctuation (.,:;!?) that is likely sentence-ending, not part of URL
    pattern: /https?:\/\/[^\s<>"')\]]+[^\s<>"')\].,;:!?]/g,
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
    // "snmp-server host 10.10.5.30 version 2c COMMUNITY_STRING"
    name: "snmp_host_community",
    pattern: /(?:snmp-server\s+host\s+\S+\s+(?:version\s+\d+[a-z]?\s+)?)(\S+)$/gm,
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
    // "enable secret 5 HASH" or "enable password Cisc0123!" (with or without type number)
    pattern: /(?:enable\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    name: "cisco_password_line",
    // "password 7 XXXX" or "password 0 XXXX" (with explicit type number)
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
    // AAA server-private key: "server-private 10.10.5.50 key 7 045E0A0B0E3A2D44"
    name: "aaa_server_private_key",
    pattern: /(?:server-private\s+\S+\s+key\s+(?:\d+\s+)?)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.0,
  },
  {
    // New-style TACACS/RADIUS standalone key line: " key 0 T@c@csK3y!"
    name: "standalone_key",
    pattern: /(?:^\s*key\s+(?:\d+\s+)?)(\S+)/gm,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },
  {
    // Junos/PAN-OS tacplus/radius secret: "server X secret VALUE" or "tacplus-server X secret VALUE"
    name: "junos_tacplus_secret",
    pattern: /(?:(?:tacplus-server|radius-server|server)\s+\S+\s+secret\s+)"([^"]+)"/g,
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
  // --- VRF ---
  {
    // "ip vrf VRF-NAME" (IOS classic) — exclude "forwarding" and "context"
    name: "vrf_name_classic",
    pattern: /(?:ip\s+vrf\s+)(?!forwarding\b|context\b)(\S+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.95,
  },
  {
    // "vrf definition VRF-NAME" (IOS-XE / IOS-XR)
    name: "vrf_definition",
    pattern: /(?:vrf\s+definition\s+)(\S+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.95,
  },
  {
    // "vrf forwarding VRF-NAME" or "ip vrf forwarding VRF-NAME" (interface binding)
    name: "vrf_forwarding",
    pattern: /(?:(?:ip\s+)?vrf\s+forwarding\s+)(\S+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.95,
  },
  {
    // "vrf VRF-NAME" in Junos / NX-OS (standalone)
    name: "vrf_junos",
    pattern: /(?:^|\n)\s*vrf\s+(\S+)\s*$/gm,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },
  {
    // Route distinguisher: "rd 65001:100"
    name: "route_distinguisher",
    pattern: /(?:rd\s+)(\d+:\d+)/g,
    category: Category.VLAN_ID,
    confidence: 0.90,
  },
  {
    // Route target: "route-target export 65001:100"
    name: "route_target",
    pattern: /(?:route-target\s+(?:export|import|both)\s+)(\d+:\d+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.90,
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
    // Matches both definition ("ip prefix-list PL-X") and reference ("match ip address prefix-list PL-X")
    pattern: /(?:(?:ip\s+)?prefix-list\s+)(\S+)/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },
  {
    name: "acl_name",
    pattern: /(?:ip\s+access-list\s+(?:standard|extended)\s+)(\S+)/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },

  // --- Network device hostnames ---
  {
    // Cisco/IOS "hostname <name>" config line
    name: "cisco_hostname",
    pattern: /(?:^|\n)\s*hostname\s+(\S+)/g,
    category: Category.HOSTNAME,
    confidence: 0.95,
  },
  {
    // Dotted hierarchical device names: 24.rou.acn.atccv.care, 1a.sw.atm.atvie.ops
    name: "device_name_dotted",
    pattern: /\b(\w{1,4}\.(?:rou|sw|rtr|fw)\.(?:[a-z]{2,8}\.){1,3}(?:care|ops|mgmt|cnet|prod|lab|dev))\b/gi,
    category: Category.HOSTNAME,
    confidence: 0.90,
  },
  {
    // Short device codes: FCNETR1, WCNETR2, LCNETR3 — uppercase letter(s) + "CNET" or role + digit(s)
    name: "device_name_short",
    pattern: /\b([A-Z]{1,4}(?:CNET|ONET|MNET|ANET)[A-Z]?\d{1,2})\b/g,
    category: Category.HOSTNAME,
    confidence: 0.85,
  },
  {
    // Hyphenated device names with site/zone/role pattern: f-o-w-cnetr1, l-care-acn-rou24
    name: "device_name_hyphenated",
    pattern: /\b([a-z]{1,6}(?:-[a-z]{1,8}){2,5}[a-z]?\d{1,3})\b/gi,
    category: Category.HOSTNAME,
    confidence: 0.70,
  },
  {
    // Uppercase infrastructure hostnames: PROD-DB-01, AMS-CORE-SW-01, FRA-EDGE-FW-01
    // Pattern: 2-5 uppercase segments separated by hyphens, ending with digits
    name: "device_name_infra",
    pattern: /\b([A-Z][A-Z0-9]{1,10}(?:-[A-Z][A-Z0-9]{0,10}){1,5}-\d{1,3})\b/g,
    category: Category.HOSTNAME,
    confidence: 0.80,
  },

  // --- Syslog / monitoring (#5) ---
  {
    // Cisco syslog facility: %SYS-5-CONFIG_I, %LINK-3-UPDOWN
    name: "syslog_facility",
    pattern: /%([A-Z][A-Z_]+-\d+-[A-Z_]+)/g,
    category: Category.HOSTNAME,
    confidence: 0.80,
  },
  {
    // Source interface in logging/SNMP: trap-source Loopback0, logging source-interface Vlan1
    name: "syslog_source_interface",
    pattern: /(?:trap-source|source-interface|logging\s+source-interface)\s+(\S+)/gi,
    category: Category.HOSTNAME,
    confidence: 0.85,
  },

  // --- Description field sub-entities (#6) ---
  {
    // Circuit ID in description: CID: ABC-123, circuit-id XYZ/456
    name: "circuit_id",
    pattern: /(?:CID|circuit[- ]?id|circuit)\s*[:# ]\s*([A-Za-z0-9\-/]{3,30})/gi,
    category: Category.CUSTOM,
    confidence: 0.85,
  },
  {
    // Org/customer name in description: LINK TO Acme Corp, CONNECTION FROM BigCo
    name: "description_org",
    pattern: /(?:(?:LINK|CONN(?:ECTION)?|CIRCUIT|PEER|UPLINK)\s+(?:TO|FROM|WITH)\s+)([A-Z][A-Za-z0-9\s&,.\-]{2,30})/g,
    category: Category.ORG_NAME,
    confidence: 0.75,
  },

  // ==========================================================================
  // Wave 1: Regulated / Critical Infrastructure
  // ==========================================================================

  // --- Austrian / EU identifiers ---
  {
    name: "iban",
    pattern: /\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,4}\b/g,
    category: Category.IBAN,
    confidence: 0.90,
  },
  {
    name: "austrian_svnr",
    pattern: /\b\d{4}[0-3]\d[01]\d\d{2}\b/g,
    category: Category.NATIONAL_ID,
    confidence: 0.80,
  },
  {
    name: "german_personalausweis",
    pattern: /\b[LMNTPRV][A-Z0-9]{8}\d\b/g,
    category: Category.NATIONAL_ID,
    confidence: 0.85,
  },
  {
    name: "eu_vat_number",
    pattern: /\b(?:AT|DE|FR|IT|NL|ES|BE|PL|CZ|SE|DK|FI|IE|PT|GR|HU|RO|BG|HR|SI|SK|LT|LV|EE|LU|MT|CY)U?\d{8,12}\b/g,
    category: Category.NATIONAL_ID,
    confidence: 0.85,
  },
  {
    name: "gps_coordinate",
    pattern: /(?<!\w)-?\d{1,3}\.\d{4,8}[,\s]+-?\d{1,3}\.\d{4,8}(?!\w)/g,
    category: Category.GPS_COORDINATE,
    confidence: 0.85,
  },

  // --- JWT and OAuth ---
  {
    name: "jwt_token",
    pattern: /\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/g,
    category: Category.JWT,
    confidence: 0.95,
  },
  {
    name: "oauth_refresh_token",
    pattern: /(?:refresh_token["':\s]+)([A-Za-z0-9\-_]{20,})/g,
    category: Category.API_KEY,
    confidence: 0.90,
  },

  // --- Cloud provider tokens ---
  {
    name: "aws_secret_key",
    pattern: /(?:SecretAccessKey|aws_secret_access_key)["':\s=]+([A-Za-z0-9/+=]{40})/gi,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "gcp_api_key",
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "azure_connection_string",
    pattern: /DefaultEndpointsProtocol=[^;\s]+;AccountName=[^;\s]+;AccountKey=[^;\s]+/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "slack_token",
    pattern: /\bxox[bpsar]-[A-Za-z0-9\-]{10,}/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "github_pat",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "gitlab_token",
    pattern: /\bglpat-[A-Za-z0-9\-]{20,}\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "stripe_key",
    pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "sendgrid_key",
    pattern: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "hashicorp_vault_token",
    pattern: /\b(?:hvs\.[A-Za-z0-9]{24,}|s\.[A-Za-z0-9]{24})\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },

  // --- Database connection strings ---
  {
    name: "db_connection_string",
    pattern: /(?:postgres|mysql|mongodb|mongodb\+srv|redis|amqp)s?:\/\/[^\s<>"']+/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "jdbc_url",
    pattern: /jdbc:(?:oracle|sqlserver|mysql|postgresql|mariadb):[^\s<>"']+/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },

  // --- Certificates and keys ---
  {
    name: "pem_private_key",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    category: Category.CERTIFICATE,
    confidence: 1.00,
  },
  {
    name: "pem_certificate",
    pattern: /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    category: Category.CERTIFICATE,
    confidence: 0.85,
  },

  // --- LDAP / Active Directory ---
  {
    name: "ldap_bind_dn",
    pattern: /\bCN=[^,]+(?:,(?:OU|DC|O|C)=[^,]+){2,}/gi,
    category: Category.PERSON_NAME,
    confidence: 0.90,
  },
  {
    name: "ldap_bind_password",
    pattern: /(?:bindPassword|LDAP_BIND_PW|ldap_password)["':\s=]+(\S+)/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "ad_domain_login",
    pattern: /\b[A-Z][A-Z0-9]{1,15}\\[a-zA-Z][a-zA-Z0-9._\-]{0,30}\b/g,
    category: Category.PERSON_NAME,
    confidence: 0.85,
  },
  {
    name: "windows_sid",
    pattern: /\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b/g,
    category: Category.NATIONAL_ID,
    confidence: 0.90,
  },

  // --- Juniper ---
  {
    name: "junos_secret",
    pattern: /"\$9\$[A-Za-z0-9./]+"/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "junos_preshared_key",
    pattern: /(?:pre-shared-key\s+(?:ascii-text|hexadecimal)\s+)"([^"]+)"/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "junos_root_auth",
    pattern: /(?:encrypted-password\s+)"([^"]+)"/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "junos_community",
    pattern: /(?:community\s+)(\S+)(?:\s+(?:authorization|clients))/g,
    category: Category.SNMP_COMMUNITY,
    confidence: 1.00,
  },
  {
    name: "junos_description",
    pattern: /(?:description\s+)"([^"]+)"/g,
    category: Category.INTERFACE_DESC,
    confidence: 0.90,
  },

  // --- Palo Alto ---
  {
    name: "panos_api_key",
    pattern: /\bLUFRPT[A-Za-z0-9=+/]{20,}\b/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "panos_password_hash",
    pattern: /(?:phash\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "panos_master_key",
    pattern: /(?:master-key\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "panos_address_object",
    pattern: /(?:set\s+address\s+)(\S+)(?:\s+ip-netmask)/g,
    category: Category.HOSTNAME,
    confidence: 0.80,
  },
  {
    name: "panos_zone_name",
    pattern: /(?:set\s+zone\s+)(\S+)(?:\s+network)/g,
    category: Category.ACL_NAME,
    confidence: 0.80,
  },
  {
    name: "panos_rule_name",
    pattern: /(?:set\s+rulebase\s+security\s+rules\s+)"?([^"\s]+)"?/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },

  // --- Check Point ---
  {
    name: "checkpoint_password_hash",
    pattern: /(?:set\s+password-hash\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "checkpoint_sic_key",
    pattern: /(?:sic\s+(?:init|key)\s+)(\S+)/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "checkpoint_api_key",
    pattern: /(?:api-key\s+)"?([A-Za-z0-9+/=]{20,})"?/g,
    category: Category.API_KEY,
    confidence: 0.95,
  },
  {
    name: "checkpoint_object_name",
    pattern: /(?:add\s+(?:host|network|group|service-tcp|service-udp)\s+name\s+)"?([^"\s]+)"?/g,
    category: Category.HOSTNAME,
    confidence: 0.80,
  },
  {
    name: "checkpoint_rule_name",
    pattern: /(?:add\s+access-rule\s+.*name\s+)"?([^"\s]+)"?/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },
  {
    name: "checkpoint_vpn_community",
    pattern: /(?:set\s+vpn-community\s+)"?([^"\s]+)"?/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },

  // --- Arista ---
  {
    name: "arista_secret",
    pattern: /(?:secret\s+sha512\s+)(\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./+]+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },

  // --- F5 BIG-IP ---
  {
    name: "f5_password",
    pattern: /(?:auth\s+password\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "f5_ssl_passphrase",
    pattern: /(?:passphrase\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.90,
  },

  // --- Fortinet ---
  {
    name: "fortinet_password",
    pattern: /(?:set\s+password\s+ENC\s+)(\S+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "fortinet_private_key",
    pattern: /(?:set\s+private-key\s+)"(-----BEGIN[\s\S]*?-----END[^"]+)"/g,
    category: Category.CERTIFICATE,
    confidence: 1.00,
  },

  // --- VPN / IPSec / RADIUS ---
  {
    name: "vpn_preshared_key",
    pattern: /(?:pre-shared-key|preshared-key|crypto\s+isakmp\s+key|(?:with\s+)?PSK)\s+(?:\d+\s+)?(\S+)/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "ipsec_transform_set",
    pattern: /(?:crypto\s+ipsec\s+transform-set\s+)(\S+)/g,
    category: Category.ACL_NAME,
    confidence: 0.80,
  },

  // --- ICS / SCADA ---
  {
    name: "opc_ua_endpoint",
    pattern: /opc\.tcp:\/\/[^\s<>"']+/g,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.90,
  },
  {
    name: "modbus_address",
    pattern: /(?:modbus|slave|unit[\-_]?id)[\s:=]+(\d{1,3})/gi,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.80,
  },
  {
    name: "scada_credential",
    pattern: /(?:scada|hmi|plc|rtu|ied)[\-_\s]?(?:password|pass|pwd|credential|auth)[\s:="']+(\S+)/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 1.00,
  },
  {
    name: "iec61850_ied_name",
    pattern: /(?:iedName\s*=\s*)"([^"]+)"/g,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.90,
  },
  {
    name: "dnp3_address",
    pattern: /(?:dnp3|outstation|master)[\-_\s]?(?:address|addr)[\s:=]+(\d{1,5})/gi,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.85,
  },
  {
    name: "bacnet_device_id",
    pattern: /(?:bacnet|device[\-_]?instance)[\s:=]+(\d{1,7})/gi,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.80,
  },
  {
    name: "historian_tag",
    pattern: /\\\\[A-Za-z0-9\-_.]+\\[A-Za-z0-9\-_.]+(?:\\[A-Za-z0-9\-_.]+)*/g,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.85,
  },

  // --- Aviation / ATC ---
  {
    name: "atc_sector_id",
    pattern: /\b(?:TWR|APP|ACC|CTR|GND|DEL|ATIS)[\-_][A-Z0-9]{2,10}\b/g,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.90,
  },
  {
    name: "nav_frequency",
    pattern: /\b1[01]\d\.\d{1,3}\s?MHz\b/g,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.85,
  },
  {
    name: "icao_designator",
    pattern: /\b[A-Z]{4}\b(?=[\s\-](?:TWR|APP|GND|CTR|ATIS|RWY|SID|STAR))/g,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.85,
  },

  // --- Telecom ---
  {
    name: "imsi",
    pattern: /(?:IMSI|imsi)[\s:=]+(\d{15})/g,
    category: Category.NATIONAL_ID,
    confidence: 0.95,
  },
  {
    name: "imei",
    pattern: /(?:IMEI|imei)[\s:=]+(\d{15})/g,
    category: Category.NATIONAL_ID,
    confidence: 0.90,
  },
  {
    name: "clli_code",
    pattern: /\b[A-Z]{6}\d{2}[A-Z0-9]{3}\b/g,
    category: Category.ICS_IDENTIFIER,
    confidence: 0.85,
  },

  // --- Prose/instruction credential patterns ---
  {
    // "with password VALUE", "using password VALUE" — in natural language instructions
    name: "prose_password",
    pattern: /(?:(?:with|using)\s+password\s+)(\S+)/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },
  {
    // "SNMP community: VALUE" or "community string: VALUE" — in prose/reports
    name: "prose_snmp_community",
    pattern: /(?:(?:SNMP\s+)?community(?:\s+string)?[:=]\s*)(\S+)/gi,
    category: Category.SNMP_COMMUNITY,
    confidence: 0.95,
  },

  // --- Environment variable secrets ---
  {
    // DB_PASSWORD=value, SMTP_PASSWORD=value, etc. (shell .env format)
    name: "env_var_secret",
    pattern: /(?:^|[\n;])\s*\w*(?:PASSWORD|PASSWD|SECRET|_KEY|_TOKEN)\w*\s*=\s*(\S+)/gmi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },

  // --- XML/HCL attribute passwords ---
  {
    // password="value", secret="value", token="value" in XML/HCL/config attributes
    name: "attribute_password",
    pattern: /(?:password|passwd|secret|auth)\s*=\s*"([^"]+)"/gi,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },

  // --- Base64-encoded secrets ---
  {
    name: "base64_secret_assignment",
    pattern: /(?:SECRET|PRIVATE_KEY|PASSWORD|TOKEN|API_KEY|APIKEY|AUTH)[\s]*[=:]\s*[A-Za-z0-9+/]{20,}={0,2}/gi,
    category: Category.API_KEY,
    confidence: 0.90,
  },
  {
    name: "base64_prefixed",
    pattern: /\bbase64:[A-Za-z0-9+/]{8,}={0,2}/g,
    category: Category.API_KEY,
    confidence: 0.85,
  },

  // --- VXLAN / VNI ---
  {
    // "vni 10100", "member vni 50000", "vxlan vni 10100"
    name: "vxlan_vni",
    pattern: /(?:(?:member\s+)?vni\s+|vxlan\s+vni\s+)(\d+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.90,
  },

  // --- Juniper VLAN ---
  {
    // "set vlans SERVERVLAN vlan-id 100"
    name: "juniper_vlan_name",
    pattern: /(?:set\s+vlans\s+)(\S+)/g,
    category: Category.VLAN_ID,
    confidence: 0.90,
  },
  {
    // "vlan-id 100" (Juniper style)
    name: "juniper_vlan_id",
    pattern: /(?:vlan-id\s+)(\d+)/g,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },
  {
    // "vlan members SERVERVLAN" (Juniper interface vlan member reference)
    name: "juniper_vlan_members",
    pattern: /(?:vlan\s+members\s+)(\S+)/g,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },

  // --- Standalone VLAN ID ---
  {
    // "switchport access vlan 100", "switchport trunk native vlan 100"
    // Only match switchport context to avoid false positives on prose like "move to VLAN 100"
    name: "switchport_vlan_id",
    pattern: /(?:switchport\s+(?:access|trunk\s+native)\s+vlan\s+)(\d+)\b/gi,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },
  {
    // "vlan 100" at start of line (config context, not prose)
    name: "vlan_config_id",
    pattern: /(?:^|\n)\s*vlan\s+(\d+)\s*$/gm,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },

  // --- L2VPN VPN ID ---
  {
    // "vpn id 200"
    name: "l2vpn_vpn_id",
    pattern: /(?:vpn\s+id\s+)(\d+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },

  // --- Cisco EIGRP AS ---
  {
    // "router eigrp 100"
    name: "eigrp_as",
    pattern: /(?:router\s+eigrp\s+)(\d+)/gi,
    category: Category.BGP_ASN,
    confidence: 0.90,
  },

  // --- MPLS label range ---
  {
    // "mpls label range 100 199"
    name: "mpls_label_range",
    pattern: /(?:mpls\s+label\s+range\s+)(\d+\s+\d+)/gi,
    category: Category.VLAN_ID,
    confidence: 0.85,
  },

  // --- Cisco banner ---
  {
    // "banner motd ^C ... ^C" or "banner login ^C ... ^C"
    // Captures content between delimiter characters
    name: "cisco_banner",
    pattern: /(?:banner\s+(?:motd|login|exec)\s+(\S))\s*([\s\S]*?)\1/gm,
    category: Category.ORG_NAME,
    confidence: 0.85,
  },

  // --- NTP trusted key ---
  {
    // "ntp trusted-key 1" — the key ID reveals NTP infra
    name: "ntp_trusted_key",
    pattern: /(?:ntp\s+trusted-key\s+)(\d+)/g,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.80,
  },

  // --- Cisco line password (console/aux/vty without type number) ---
  {
    // "password VALUE" (without a type number prefix, i.e. not "password 7 XXX")
    // Appears under "line con 0", "line aux 0", "line vty 0 15"
    name: "cisco_line_password",
    pattern: /(?:^\s*password\s+)(?![057]\s)(\S+)/gm,
    category: Category.NETWORK_CREDENTIAL,
    confidence: 0.95,
  },

  // --- RADIUS/TACACS server name ---
  {
    // "tacacs server TAC-PRI", "radius server RAD-01"
    name: "tacacs_server_name",
    pattern: /(?:tacacs\s+server\s+)(\S+)/gi,
    category: Category.HOSTNAME,
    confidence: 0.85,
  },
  {
    name: "radius_server_name",
    pattern: /(?:radius\s+server\s+)(\S+)/gi,
    category: Category.HOSTNAME,
    confidence: 0.85,
  },

  // --- Juniper firewall filter name ---
  {
    // "set firewall family inet filter FILTER-NAME"
    name: "juniper_firewall_filter",
    pattern: /(?:set\s+firewall\s+family\s+\S+\s+filter\s+)(\S+)/g,
    category: Category.ACL_NAME,
    confidence: 0.85,
  },

  // --- Palo Alto service group ---
  {
    // "set service-group SG-NAME"
    name: "panos_service_group",
    pattern: /(?:set\s+service-group\s+)(\S+)/g,
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

/** Override config for individual rules: disable or change confidence. */
export type DetectorOverrides = Record<string, { enabled?: boolean; confidence?: number }>;

/** Detects sensitive entities using regex patterns. */
export class RegexDetector implements BaseDetector {
  readonly name = "regex";
  private patterns: PatternDef[];

  constructor(extraPatterns?: PatternDef[], overrides?: DetectorOverrides) {
    let patterns = [...BUILTIN_PATTERNS];
    if (extraPatterns) {
      patterns.push(...extraPatterns);
    }
    if (overrides) {
      patterns = patterns.filter((p) => {
        const ov = overrides[p.name];
        return ov?.enabled !== false;
      });
      patterns = patterns.map((p) => {
        const ov = overrides[p.name];
        if (ov?.confidence !== undefined) {
          return { ...p, confidence: ov.confidence };
        }
        return p;
      });
    }
    this.patterns = patterns;
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
            // Skip documentation/example values (#7)
            if (isDocExample(grp, pdef.category)) {
              continue;
            }
            seenSpans.push(span);
            entities.push({
              value: grp,
              start: grpStart,
              end: grpEnd,
              category: pdef.category,
              confidence: pdef.confidence,
              detector: `${this.name}:${pdef.name}`,
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
          // Skip documentation/example values (#7)
          if (isDocExample(value, pdef.category)) {
            continue;
          }
          seenSpans.push(span);
          entities.push({
            value,
            start: span[0],
            end: span[1],
            category: pdef.category,
            confidence: pdef.confidence,
            detector: `${this.name}:${pdef.name}`,
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
