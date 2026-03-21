/** Core types for the Shroud OpenClaw plugin. */

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
}
