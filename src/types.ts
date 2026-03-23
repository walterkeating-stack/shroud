/** Core types for the Shroud OpenClaw plugin. */

import type { RedactionLevel } from "./redaction.js";

/** Categories of sensitive information. */
export enum Category {
  PERSON_NAME = "person_name",
  EMAIL = "email",
  PHONE = "phone",
  IP_ADDRESS = "ip_address",
  API_KEY = "api_key",
  URL = "url",
  ORG_NAME = "org_name",
  LOCATION = "location",
  FILE_PATH = "file_path",
  CREDIT_CARD = "credit_card",
  SSN = "ssn",
  MAC_ADDRESS = "mac_address",
  HOSTNAME = "hostname",
  SNMP_COMMUNITY = "snmp_community",
  BGP_ASN = "bgp_asn",
  NETWORK_CREDENTIAL = "network_credential",
  // Network infrastructure identifiers
  VLAN_ID = "vlan_id",
  INTERFACE_DESC = "interface_desc",
  ROUTE_MAP = "route_map",
  OSPF_ID = "ospf_id",
  ACL_NAME = "acl_name",
  // Regulated / extended categories
  IBAN = "iban",
  NATIONAL_ID = "national_id",
  JWT = "jwt",
  ICS_IDENTIFIER = "ics_identifier",
  GPS_COORDINATE = "gps_coordinate",
  CERTIFICATE = "certificate",
  CUSTOM = "custom",
}

/** A detected sensitive entity in text. */
export interface DetectedEntity {
  value: string;
  start: number;
  end: number;
  category: Category;
  confidence: number;
  detector: string;
}

/** Result of obfuscating text. */
export interface ObfuscationResult {
  original: string;
  obfuscated: string;
  entities: DetectedEntity[];
  mappingsUsed: Record<string, string>;
  /** Filtering stats — how many entities were skipped and why. */
  filterStats?: FilterStats;
}

/** Breakdown of skipped/filtered entities during obfuscation. */
export interface FilterStats {
  /** Total entities detected before filtering. */
  totalDetected: number;
  /** Entities that passed filtering and were replaced (or would be in dryRun). */
  replaced: number;
  /** Entities skipped because confidence < minConfidence. */
  belowThreshold: number;
  /** Entities skipped by allowlist. */
  allowlisted: number;
  /** Entities skipped because they are doc/example values. */
  docExamples: number;
  /** Entities skipped because they are already-known fakes. */
  alreadyObfuscated: number;
}

/** Configuration for the Shroud plugin. */
export interface ShroudConfig {
  secretKey: string;
  persistentSalt: string;
  minConfidence: number;
  allowlist: string[];
  denylist: string[];
  canaryEnabled: boolean;
  canaryPrefix: string;
  auditEnabled: boolean;
  logMappings: boolean;
  customPatterns: Array<{ name: string; pattern: string; category?: string }>;
  // Verbose audit logging
  verboseLogging: boolean;
  auditLogFormat: "human" | "json";
  auditIncludeProofHashes: boolean;
  auditHashSalt: string;
  auditHashTruncate: number;
  auditMaxFakesSample: number;
  detectorOverrides: Record<string, { enabled?: boolean; confidence?: number }>;

  /** Tool chain depth awareness — max depth before warning. */
  maxToolDepth: number;

  /** Redaction levels — 'full' | 'masked' | 'stats'. */
  redactionLevel: RedactionLevel;

  /** Dry-run mode: detect entities but don't replace them. */
  dryRun: boolean;

  /** Max mapping store size; oldest entries evicted when exceeded. 0 = unlimited. */
  maxStoreMappings: number;
}
