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
  // Regulated / enterprise categories
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
  /** Compliance report — present when lockedCategories is configured. */
  complianceReport?: ComplianceReport;
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
  /** Entities skipped by allowlist or policy allowlist. */
  allowlisted: number;
  /** Entities skipped because they are doc/example values. */
  docExamples: number;
  /** Entities skipped because they are already-known fakes. */
  alreadyObfuscated: number;
}

/** Compliance check result for locked categories. */
export interface ComplianceReport {
  found: Category[];
  missing: Category[];
  passed: boolean;
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

  // --- Enterprise features ---

  /** Feature 1: Multi-tenant isolation — tenant ID for HMAC keying. */
  tenantId: string;

  /** Feature 3: Tool chain depth awareness — max depth before warning. */
  maxToolDepth: number;

  /** Feature 4: Compliance-mode entity locking — categories that MUST be detected. */
  lockedCategories: Category[];

  /** Feature 5: Rate-of-exposure tracking — sliding window in ms. */
  exposureWindow: number;
  /** Feature 5: Per-category thresholds (category -> max detections per window). */
  exposureThresholds: Record<string, number>;
  /** Feature 5: Global threshold across all categories. */
  exposureGlobalThreshold: number;

  /** Feature 7: Policy-as-code — path to external policy JSON file. */
  policyFile: string;

  /** Feature 8: Redaction levels — 'full' | 'masked' | 'stats'. */
  redactionLevel: RedactionLevel;

  /** Feature 9: Cross-agent shared store — file path for shared mappings. */
  sharedStorePath: string;
  /** Feature 9: Cache TTL for shared store reads (ms). */
  sharedStoreTtlMs: number;

  /** Feature 10: Provenance tagging — embed origin markers in output. */
  provenanceTagging: boolean;

  /** Feature 2: Session handoff — enable export/import of mapping tables. */
  sessionHandoff: boolean;

  /** Dry-run mode: detect entities but don't replace them. */
  dryRun: boolean;

  /** Max mapping store size; oldest entries evicted when exceeded. 0 = unlimited. */
  maxStoreMappings: number;

  // --- Key rotation ---

  /** Array of versioned keys for key rotation. When set, secretKey is used as fallback only. */
  keys: Array<{
    version: number;
    key: string;
    createdAt?: string;
    expiresAt?: string;
    retired?: boolean;
  }>;

  /** Which key version to use for new obfuscations. Defaults to highest non-expired. */
  activeKeyVersion: number;

  // --- SIEM integration ---

  /** SIEM webhook endpoints for real-time event streaming. */
  siemWebhooks: Array<{
    url: string;
    authHeader?: string;
    headers?: Record<string, string>;
    eventTypes?: string[];
  }>;
  /** Max events before auto-flush (default 100). */
  siemBatchSize: number;
  /** Flush interval in ms (default 30000). */
  siemFlushIntervalMs: number;
  /** Max retry attempts per flush (default 3). */
  siemMaxRetries: number;
  /** Initial retry backoff in ms, doubles each retry (default 1000). */
  siemRetryBackoffMs: number;
  /** Event format: 'json' or 'cef' (default 'json'). */
  siemEventFormat: "json" | "cef";

  // --- Hot-reload ---

  /** Enable hot-reload of detection rules when config files change. */
  hotReload: boolean;
  /** Path to a custom patterns JSON file to watch for hot-reload. */
  customPatternsFile: string;
  /** Debounce interval for hot-reload in ms (default 1000). */
  hotReloadDebounceMs: number;

  // --- Per-session isolation ---

  /** Enable per-session isolation (separate stores per session). */
  sessionIsolation: boolean;

  // --- Active monitoring ---

  /** Enable active monitoring and alerting pipeline. */
  monitorEnabled: boolean;
  /** Rolling window for rate baseline in ms (default 60000). */
  monitorRateWindowMs: number;
  /** Rate spike multiplier threshold (default 3.0). */
  monitorSpikeMultiplier: number;
  /** Max alerts to keep in memory (default 500). */
  monitorMaxAlerts: number;
}
