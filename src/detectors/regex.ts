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
  "192.0.2.",     // TEST-NET-1 (RFC 5737)
  "198.51.100.",  // TEST-NET-2 (RFC 5737)
  "203.0.113.",   // TEST-NET-3 (RFC 5737)
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
      return DOC_HOSTNAMES.has(value) || DOC_HOSTNAMES.has(value.toUpperCase());

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
  // Wave 1: Enterprise / Regulated / Critical Infrastructure
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
    pattern: /(?:pre-shared-key|preshared-key|crypto\s+isakmp\s+key)\s+(?:\d+\s+)?(\S+)/gi,
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
