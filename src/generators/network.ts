/**
 * Fake network entity generators: IPs, emails, URLs, domains, MACs, BGP ASNs.
 *
 * Design principle: "obfuscate identity, preserve structure — change WHO and
 * WHERE, keep WHAT and HOW."
 */

import { createHash } from "node:crypto";

import { Category } from "../types.js";
import type { BaseGenerator } from "./base.js";

// ---------------------------------------------------------------------------
// Domain pools
// ---------------------------------------------------------------------------

export const DOMAINS = [
  "nexus.dev", "vertex.io", "prism.net", "atlas.org", "cipher.co",
  "beacon.tech", "forge.dev", "crest.io", "pulse.net", "apex.org",
  "echo.co", "nova.dev", "summit.io", "core.net", "bridge.org",
  "spark.co", "tide.dev", "haven.io", "peak.net", "drift.org",
  "flux.co", "orbit.dev", "zenith.io", "pine.net", "reef.org",
  "slate.co", "wave.dev", "terra.io", "lunar.net", "solar.org",
];

// TLD-grouped domains for format-preserving generation
export const DOMAINS_BY_TLD: Record<string, string[]> = {};
for (const d of DOMAINS) {
  const tld = d.split(".").pop()!;
  if (!DOMAINS_BY_TLD[tld]) DOMAINS_BY_TLD[tld] = [];
  DOMAINS_BY_TLD[tld].push(d);
}

export const EMAIL_PREFIXES = [
  "contact", "info", "admin", "support", "hello", "team", "ops",
  "dev", "eng", "data", "sec", "cloud", "mail", "notify", "alerts",
  "user", "agent", "bot", "service", "api",
];

// Short/medium/long prefixes for length matching
export const EMAIL_PREFIXES_SHORT = EMAIL_PREFIXES.filter(
  (p) => p.length <= 4,
);
export const EMAIL_PREFIXES_MEDIUM = EMAIL_PREFIXES.filter(
  (p) => p.length > 4 && p.length <= 7,
);
export const EMAIL_PREFIXES_LONG = EMAIL_PREFIXES.filter(
  (p) => p.length > 7,
);

export const SNMP_COMMUNITIES = [
  "COMMUNITY_RO", "COMMUNITY_RW", "SNMP_STR_001", "SNMP_STR_002",
  "MGMT_READ", "MGMT_WRITE", "MON_STRING", "NET_COMMUNITY",
];

export const HOSTNAME_ROLES = [
  "SW", "RTR", "FW", "AP", "SRV", "LB", "DC", "NAS",
];

// ---------------------------------------------------------------------------
// Geographic site codes — realistic 3-letter airport/city codes
// ---------------------------------------------------------------------------

export const FAKE_SITES = [
  "DEN", "SFO", "ATL", "SEA", "BOS", "MIA", "DFW", "ORD", "PHX", "PDX",
  "IAD", "LAX", "JFK", "MSP", "DTW", "CLT", "TPA", "SAN", "SLC", "PIT",
];

// Legacy pool kept for backward compat in non-structured hostnames
export const HOSTNAME_SITES = FAKE_SITES;

// ---------------------------------------------------------------------------
// Role-preserving hostname constants
// ---------------------------------------------------------------------------

/** Roles that should be preserved verbatim in structured hostnames. */
const HOSTNAME_ROLE_KEYWORDS = new Set([
  "RTR", "SW", "FW", "AP", "SRV", "LB", "DC", "NAS",
  "PE", "CE", "P", "RR", "GW", "WLC", "MX", "QFX", "EX",
]);

/** Tier/function keywords preserved verbatim. */
const HOSTNAME_TIER_KEYWORDS = new Set([
  "CORE", "DIST", "ACC", "EDGE", "MGMT", "DMZ", "WAN", "LAN",
  "SPINE", "LEAF", "BORDER", "TRANSIT",
]);

/** Detect 2-4 uppercase letter site codes (e.g. CHI, NYC, FRA). */
const SITE_CODE_RE = /^[A-Z]{2,4}$/;

export const PATH_SEGMENTS = [
  "app", "api", "docs", "dashboard", "portal", "v2", "status", "health",
];

// ---------------------------------------------------------------------------
// Topology keywords for description preservation
// ---------------------------------------------------------------------------

const TOPOLOGY_KEYWORDS = new Set([
  "UPLINK", "DOWNLINK", "PEER", "TRANSIT", "LINK", "CONN",
  "WAN", "LAN", "MGMT", "OOB", "BACKUP", "PRIMARY",
  "TO", "FROM", "VIA", "SECONDARY", "TERTIARY",
]);

// ---------------------------------------------------------------------------
// Provider names for route-map semantic generation
// ---------------------------------------------------------------------------

const FAKE_PROVIDERS = [
  "LUMEN", "ZAYO", "TELIA", "GTT", "NTT", "PCCW", "COLT",
  "CENTURYLINK", "ARELION", "SEABORN", "RETN", "SPARKLE",
];

// ---------------------------------------------------------------------------
// CGNAT constants
// ---------------------------------------------------------------------------

/** 100.64.0.0 as unsigned 32-bit int */
export const CGNAT_BASE = ((100 << 24) | (64 << 16)) >>> 0;

/** Mask for CGNAT /10 range */
export const CGNAT_MASK_10 = 0xffc00000;

const CGNAT_SIZE = 1 << 22; // 100.64.0.0 - 100.127.255.255

// ---------------------------------------------------------------------------
// IP / int helpers
// ---------------------------------------------------------------------------

export function ipToInt(ip: string): number {
  const parts = ip.split(".");
  return (
    (((parseInt(parts[0], 10) << 24) |
      (parseInt(parts[1], 10) << 16) |
      (parseInt(parts[2], 10) << 8) |
      parseInt(parts[3], 10)) >>>
      0)
  );
}

export function intToIp(n: number): string {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join(".");
}

// ---------------------------------------------------------------------------
// SubnetMapper class
// ---------------------------------------------------------------------------

export class SubnetMapper {
  /** Forward mapping: serialized key "netInt,prefixLen" -> fake network int */
  subnetFwd: Map<string, number> = new Map();
  /** Reverse mapping: fake network int -> serialized key */
  subnetRev: Map<number, string> = new Map();
  /** Next CGNAT slot to allocate */
  subnetNextSlot = 0;
  /** Learned subnets from text context */
  knownSubnets: Array<{ networkInt: number; prefixLen: number }> = [];

  /**
   * Scan text for CIDR notation and subnet masks to learn subnet boundaries.
   * Call this before obfuscating IPs so the generator knows the correct
   * prefix length for each address.
   */
  learnSubnetsFromText(text: string): void {
    // CIDR notation: 10.0.0.0/22
    const cidrRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})\b/g;
    let m: RegExpExecArray | null;
    while ((m = cidrRe.exec(text)) !== null) {
      try {
        const prefixLen = parseInt(m[2], 10);
        // Skip default routes (/0-/7) and host routes (/31-/32) — they are
        // not real subnet boundaries.  /0 is especially dangerous: it matches
        // every IP, so all 32 host bits leak through the fake mapping.
        if (prefixLen < 8 || prefixLen > 30) continue;
        const ipInt = ipToInt(m[1]);
        const mask = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);
        const netInt = (ipInt & mask) >>> 0;
        this.knownSubnets.push({ networkInt: netInt, prefixLen });
      } catch {
        // skip invalid
      }
    }

    // Subnet masks near IPs: "10.130.24.0 mask 255.255.252.0" etc.
    const maskPat =
      /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?:mask\s+|netmask\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    while ((m = maskPat.exec(text)) !== null) {
      try {
        const ipStr = m[1];
        const maskStr = m[2];
        let maskInt = ipToInt(maskStr);

        // Determine if it's a subnet mask or wildcard mask
        if (maskStr.startsWith("0.") && !maskStr.startsWith("0.0.0.0")) {
          // Wildcard mask -> invert to get subnet mask
          maskInt = (maskInt ^ 0xffffffff) >>> 0;
        }

        // Validate it's a valid mask (contiguous 1s then 0s)
        const inverted = (maskInt ^ 0xffffffff) >>> 0;
        if ((inverted & ((inverted + 1) >>> 0)) === 0) {
          let prefixLen = 0;
          let tmp = maskInt;
          while (tmp) {
            prefixLen += tmp & 1;
            tmp >>>= 1;
          }
          if (prefixLen >= 8 && prefixLen <= 30) {
            const ipInt = ipToInt(ipStr);
            const netMask = (0xffffffff << (32 - prefixLen)) >>> 0;
            const netInt = (ipInt & netMask) >>> 0;
            this.knownSubnets.push({ networkInt: netInt, prefixLen });
          }
        }
      } catch {
        // skip invalid
      }
    }
  }

  /** Find the best matching prefix length for an IP from learned subnets. */
  findPrefixLen(ipInt: number): number {
    // Try most specific (longest prefix) first
    const sorted = [...this.knownSubnets].sort(
      (a, b) => b.prefixLen - a.prefixLen,
    );
    for (const { networkInt, prefixLen } of sorted) {
      const mask = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);
      const net = (ipInt & mask) >>> 0;
      if (net === networkInt) {
        return prefixLen;
      }
    }
    return 24; // Default
  }

  /** Map a real network address to a fake CGNAT network address. */
  mapSubnet(netInt: number, prefixLen: number): number {
    const key = `${netInt},${prefixLen}`;
    const existing = this.subnetFwd.get(key);
    if (existing !== undefined) return existing;

    // Allocate in CGNAT space using a byte offset (not a slot counter).
    // Each allocation advances the offset by the actual subnet size,
    // aligned to the subnet boundary, to prevent overlapping subnets.
    const hostBits = 32 - prefixLen;
    const subnetSize = 1 << hostBits;

    // Align the current offset up to the subnet boundary
    const alignedOffset = (this.subnetNextSlot + subnetSize - 1) & ~(subnetSize - 1);
    let fakeNet = (CGNAT_BASE + alignedOffset) >>> 0;

    // Advance offset past this allocation
    this.subnetNextSlot = alignedOffset + subnetSize;

    // Wrap around if we exceed CGNAT space
    if ((fakeNet + subnetSize) >>> 0 > (CGNAT_BASE + CGNAT_SIZE) >>> 0) {
      this.subnetNextSlot = subnetSize;
      fakeNet = CGNAT_BASE;
    }

    this.subnetFwd.set(key, fakeNet);
    this.subnetRev.set(fakeNet, key);
    return fakeNet;
  }

  /** Reset all subnet mapping state. */
  reset(): void {
    this.subnetFwd.clear();
    this.subnetRev.clear();
    this.subnetNextSlot = 0;
    this.knownSubnets = [];
  }
}

// ---------------------------------------------------------------------------
// NetworkGenerator
// ---------------------------------------------------------------------------

export const VLAN_NAMES = [
  "MGMT", "USERS", "SERVERS", "PRINTERS", "VOIP", "GUEST",
  "DMZ", "BACKUP", "IOT", "SECURITY", "WIRELESS", "STORAGE",
];

export const VRF_NAMES = [
  "VRF-TRANSIT", "VRF-SERVICES", "VRF-INTERNAL", "VRF-EXTERNAL",
  "VRF-MGMT", "VRF-BACKUP", "VRF-GUEST", "VRF-DMZ",
  "VRF-CORE", "VRF-EDGE", "VRF-INFRA", "VRF-MONITOR",
  "VRF-VOICE", "VRF-DATA", "VRF-IOT", "VRF-SECURE",
];

export const INTERFACE_DESCS = [
  "Uplink to Core", "Server Farm Link", "WAN Circuit", "Management VLAN",
  "User Access Port", "Trunk to Distribution", "Backup Link", "DMZ Segment",
  "VoIP VLAN", "Guest Network", "Storage Network", "Monitoring Port",
];

export const ROUTE_MAP_NAMES = [
  "RM-PEER-IN", "RM-PEER-OUT", "RM-TRANSIT", "RM-LOCAL",
  "RM-DEFAULT", "RM-EXPORT", "RM-IMPORT", "RM-BACKUP",
  "RM-PRIMARY", "RM-SECONDARY", "RM-FILTER", "RM-REDISTRIBUTE",
];

export const ACL_NAMES = [
  "ACL-MGMT", "ACL-USERS", "ACL-VPN", "ACL-OUTSIDE",
  "ACL-INSIDE", "ACL-DMZ", "ACL-SERVERS", "ACL-MONITOR",
  "ACL-DENY-ALL", "ACL-PERMIT-RFC1918", "ACL-EDGE", "ACL-CORE",
];

export class NetworkGenerator implements BaseGenerator {
  readonly categories = [
    Category.IP_ADDRESS,
    Category.EMAIL,
    Category.URL,
    Category.MAC_ADDRESS,
    Category.BGP_ASN,
    Category.SNMP_COMMUNITY,
    Category.NETWORK_CREDENTIAL,
    Category.HOSTNAME,
    Category.VLAN_ID,
    Category.INTERFACE_DESC,
    Category.ROUTE_MAP,
    Category.OSPF_ID,
    Category.ACL_NAME,
  ];

  private readonly subnetMapper: SubnetMapper;

  /**
   * Session-level domain mapping for cross-entity consistency.
   * Maps the core org part of a domain (e.g. "acme-corp") to a fake
   * replacement so that emails and hostnames sharing a domain get the
   * same fake domain.
   */
  private _domainMap: Map<string, string> = new Map();

  /**
   * Session-level site code mapping for deterministic site replacement.
   * Maps real site codes (e.g. "CHI") to fake ones (e.g. "DEN").
   */
  private _siteMap: Map<string, string> = new Map();
  private _nextSiteIdx = 0;

  /**
   * Session-level ASN mapping for relationship-preserving replacement.
   * Maps real ASN numbers to fake ones.
   */
  private _asnMap: Map<number, number> = new Map();
  private _nextPrivateAsn = 64512;
  private _nextPublicAsn = 10000;

  constructor(subnetMapper: SubnetMapper) {
    this.subnetMapper = subnetMapper;
  }

  generate(category: Category, seed: number, original = ""): string {
    if (category === Category.IP_ADDRESS) {
      return this._fakeIp(seed, original, this.subnetMapper);
    } else if (category === Category.EMAIL) {
      return this._fakeEmail(seed, original);
    } else if (category === Category.URL) {
      return this._fakeUrl(seed, original);
    } else if (category === Category.MAC_ADDRESS) {
      return this._fakeMac(seed, original);
    } else if (category === Category.BGP_ASN) {
      return this._fakeAsn(seed, original);
    } else if (category === Category.SNMP_COMMUNITY) {
      return this._fakeSnmpCommunity(seed);
    } else if (category === Category.NETWORK_CREDENTIAL) {
      return this._fakeNetworkCredential(seed, original);
    } else if (category === Category.HOSTNAME) {
      return this._fakeHostname(seed, original);
    } else if (category === Category.VLAN_ID) {
      return this._fakeVlanId(seed, original);
    } else if (category === Category.INTERFACE_DESC) {
      return this._fakeInterfaceDesc(seed, original);
    } else if (category === Category.ROUTE_MAP) {
      return this._fakeRouteMap(seed, original);
    } else if (category === Category.OSPF_ID) {
      return this._fakeOspfId(seed, original);
    } else if (category === Category.ACL_NAME) {
      return this._fakeAclName(seed, original);
    }
    return `net-${String(seed % 10000).padStart(4, "0")}`;
  }

  // -------------------------------------------------------------------------
  // Domain consistency helpers
  // -------------------------------------------------------------------------

  /**
   * Extract the "org" portion of a domain. Given "acme-corp.com" returns
   * "acme-corp".  Given "mail.acme-corp.co.uk" returns "acme-corp".
   */
  private _extractOrgDomain(domain: string): string {
    // Strip known compound TLDs first
    let d = domain.toLowerCase();
    const compoundTlds = [".co.uk", ".co.jp", ".co.nz", ".com.au", ".com.br"];
    for (const ct of compoundTlds) {
      if (d.endsWith(ct)) {
        d = d.slice(0, -ct.length);
        break;
      }
    }
    // Strip single TLD
    const dotIdx = d.lastIndexOf(".");
    if (dotIdx > 0) d = d.slice(0, dotIdx);
    // Take the last label (the org name)
    const lastDot = d.lastIndexOf(".");
    if (lastDot >= 0) d = d.slice(lastDot + 1);
    return d;
  }

  /** Get or create a consistent fake domain name for an org domain key. */
  private _mapOrgDomain(orgKey: string, seed: number): string {
    const existing = this._domainMap.get(orgKey);
    if (existing) return existing;
    // Pick a fake domain base name from DOMAINS pool
    const base = DOMAINS[seed % DOMAINS.length].split(".")[0];
    this._domainMap.set(orgKey, base);
    return base;
  }

  /** Map a real site code to a fake one deterministically. */
  private _mapSite(realSite: string): string {
    const key = realSite.toUpperCase();
    const existing = this._siteMap.get(key);
    if (existing) return existing;
    const fake = FAKE_SITES[this._nextSiteIdx % FAKE_SITES.length];
    this._nextSiteIdx++;
    this._siteMap.set(key, fake);
    return fake;
  }

  // -------------------------------------------------------------------------
  // IP
  // -------------------------------------------------------------------------

  /**
   * Subnet-preserving IP obfuscation for any prefix length.
   *
   * Network bits are mapped to the CGNAT range (100.64.0.0/10),
   * host bits are preserved exactly. Defaults to /24 when no
   * subnet context is available.
   */
  _fakeIp(seed: number, original: string, subnetMapper: SubnetMapper): string {
    // IPv6: use fd00::/8 (unique local)
    if (original && original.includes(":")) {
      const buf = Buffer.alloc(8);
      buf.writeUInt32BE((seed >>> 0), 0);
      buf.writeUInt32BE(((seed >>> 16) ^ 0xa5a5a5a5) >>> 0, 4);
      const h = createHash("sha256").update(buf).digest("hex");
      const groups: string[] = [];
      for (let i = 0; i < 32; i += 4) {
        groups.push(h.slice(i, i + 4));
      }
      groups[0] = "fd00";
      return groups.join(":");
    }

    // IPv4: bit-level subnet-preserving mapping
    if (original) {
      try {
        const ipInt = ipToInt(original);
        const prefixLen = subnetMapper.findPrefixLen(ipInt);
        const mask = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);
        const netInt = (ipInt & mask) >>> 0;
        const hostInt = (ipInt & (~mask >>> 0)) >>> 0;

        const fakeNet = subnetMapper.mapSubnet(netInt, prefixLen);
        return intToIp((fakeNet | hostInt) >>> 0);
      } catch {
        // fall through
      }
    }

    // Fallback for non-standard input
    return intToIp((CGNAT_BASE + (seed & 0x3fffff)) >>> 0);
  }

  // -------------------------------------------------------------------------
  // Email — with cross-entity domain consistency
  // -------------------------------------------------------------------------

  _fakeEmail(seed: number, original: string): string {
    // Analyze original structure
    let origLocal = "";
    let origTld = "";
    let origOrgDomain = "";

    if (original && original.includes("@")) {
      const atIdx = original.lastIndexOf("@");
      origLocal = original.slice(0, atIdx);
      const origDomainFull = original.slice(atIdx + 1);
      if (origDomainFull.includes(".")) {
        const dotIdx = origDomainFull.lastIndexOf(".");
        origTld = origDomainFull.slice(dotIdx + 1);
        origOrgDomain = this._extractOrgDomain(origDomainFull);
      }
    }

    // Match local part length
    let pool: string[];
    if (origLocal && origLocal.length <= 4) {
      pool = EMAIL_PREFIXES_SHORT.length > 0 ? EMAIL_PREFIXES_SHORT : EMAIL_PREFIXES;
    } else if (origLocal && origLocal.length > 7) {
      pool = EMAIL_PREFIXES_LONG.length > 0 ? EMAIL_PREFIXES_LONG : EMAIL_PREFIXES;
    } else {
      pool = EMAIL_PREFIXES_MEDIUM.length > 0 ? EMAIL_PREFIXES_MEDIUM : EMAIL_PREFIXES;
    }

    let prefix = pool[seed % pool.length];

    // Use consistent domain mapping if we have an org domain
    let domain: string;
    if (origOrgDomain) {
      const fakeOrg = this._mapOrgDomain(origOrgDomain, seed);
      // Preserve TLD if possible
      const tld = origTld || "com";
      domain = `${fakeOrg}.${tld}`;
    } else {
      // Try to match TLD
      let domainPool: string[];
      if (origTld && DOMAINS_BY_TLD[origTld]) {
        domainPool = DOMAINS_BY_TLD[origTld];
      } else {
        domainPool = DOMAINS;
      }
      domain =
        domainPool[Math.floor(seed / pool.length) % domainPool.length];
    }

    // Preserve dots in local part (e.g., "john.doe" -> "dev.ops")
    if (origLocal && origLocal.includes(".")) {
      const extra =
        EMAIL_PREFIXES[Math.floor(seed / 7) % EMAIL_PREFIXES.length];
      prefix = `${prefix}.${extra}`;
    }

    const num =
      Math.floor(seed / (pool.length * DOMAINS.length)) % 100;
    if (num > 0) {
      return `${prefix}${num}@${domain}`;
    }
    return `${prefix}@${domain}`;
  }

  // -------------------------------------------------------------------------
  // URL — with cross-entity domain consistency
  // -------------------------------------------------------------------------

  _fakeUrl(seed: number, original: string): string {
    let domain: string;

    // Try to extract org domain for consistency
    if (original) {
      const hostMatch = original.match(/https?:\/\/([^/:]+)/);
      if (hostMatch) {
        const origHost = hostMatch[1];
        const orgKey = this._extractOrgDomain(origHost);
        if (orgKey && orgKey.length > 2) {
          const fakeOrg = this._mapOrgDomain(orgKey, seed);
          // Preserve TLD
          const tldMatch = origHost.match(/\.([a-z]{2,})$/i);
          const tld = tldMatch ? tldMatch[1] : "com";
          domain = `${fakeOrg}.${tld}`;
        } else {
          domain = DOMAINS[seed % DOMAINS.length];
        }
      } else {
        domain = DOMAINS[seed % DOMAINS.length];
      }
    } else {
      domain = DOMAINS[seed % DOMAINS.length];
    }

    // Preserve URL path depth
    if (original) {
      const pathMatch = original.match(/https?:\/\/[^/]+(.*)/);
      if (pathMatch) {
        const origPath = pathMatch[1];
        const segments = origPath.split("/").filter((s) => s);
        const fakeSegments: string[] = [];
        for (let i = 0; i < segments.length; i++) {
          fakeSegments.push(
            PATH_SEGMENTS[(seed + i) % PATH_SEGMENTS.length],
          );
        }
        if (fakeSegments.length > 0) {
          return `https://${domain}/${fakeSegments.join("/")}`;
        }
      }
    }

    const path =
      PATH_SEGMENTS[
        Math.floor(seed / DOMAINS.length) % PATH_SEGMENTS.length
      ];
    return `https://${domain}/${path}`;
  }

  /** Generate a fake MAC address preserving format (colon, dash, or Cisco dot). */
  _fakeMac(seed: number, original: string): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(seed >>> 0, 0);
    buf.writeUInt32BE(((seed >>> 16) ^ 0x5a5a5a5a) >>> 0, 4);
    const h = createHash("sha256").update(buf).digest("hex");

    // Use locally-administered bit (second nibble of first octet is even+2)
    const octets: string[] = [];
    for (let i = 0; i < 12; i += 2) {
      octets.push(
        ((i === 0
          ? (parseInt(h.slice(i, i + 2), 16) | 0x02) & 0xfe
          : parseInt(h.slice(i, i + 2), 16)) & 0xff)
          .toString(16)
          .padStart(2, "0"),
      );
    }

    if (original && original.includes(".")) {
      // Cisco format: aabb.ccdd.eeff
      const flat = octets.join("");
      return `${flat.slice(0, 4)}.${flat.slice(4, 8)}.${flat.slice(8, 12)}`;
    } else if (original && original.includes("-")) {
      return octets.join("-");
    }
    return octets.join(":");
  }

  // -------------------------------------------------------------------------
  // BGP ASN — relationship-preserving
  // -------------------------------------------------------------------------

  /**
   * Map BGP AS numbers preserving private/public ranges and sequential
   * relationships. If AS X and AS X+1 both appear, their fakes are also
   * sequential.
   */
  _fakeAsn(seed: number, original = ""): string {
    const realAsn = parseInt(original, 10);
    if (!isNaN(realAsn) && realAsn > 0) {
      const existing = this._asnMap.get(realAsn);
      if (existing !== undefined) return String(existing);

      const isPrivate = realAsn >= 64512 && realAsn <= 65534;

      // Check if realAsn-1 is already mapped (sequential relationship)
      const prevMapping = this._asnMap.get(realAsn - 1);
      if (prevMapping !== undefined) {
        const fakeAsn = prevMapping + 1;
        this._asnMap.set(realAsn, fakeAsn);
        return String(fakeAsn);
      }
      // Check if realAsn+1 is already mapped
      const nextMapping = this._asnMap.get(realAsn + 1);
      if (nextMapping !== undefined) {
        const fakeAsn = nextMapping - 1;
        this._asnMap.set(realAsn, fakeAsn);
        return String(fakeAsn);
      }

      let fakeAsn: number;
      if (isPrivate) {
        fakeAsn = this._nextPrivateAsn;
        this._nextPrivateAsn++;
        if (this._nextPrivateAsn > 65534) this._nextPrivateAsn = 64512;
      } else {
        // Public ASN range: map to plausible public ASNs
        fakeAsn = this._nextPublicAsn;
        this._nextPublicAsn += 7; // spread them out
        if (this._nextPublicAsn > 63999) this._nextPublicAsn = 10000;
      }
      this._asnMap.set(realAsn, fakeAsn);
      return String(fakeAsn);
    }

    // Fallback: no original or non-numeric
    const base = 64512;
    return String(base + (seed % 1023));
  }

  /** Replace SNMP community strings with generic names. */
  _fakeSnmpCommunity(seed: number): string {
    return SNMP_COMMUNITIES[seed % SNMP_COMMUNITIES.length];
  }

  // -------------------------------------------------------------------------
  // Network credentials — type-preserving
  // -------------------------------------------------------------------------

  /** Replace network credentials preserving hash/encoding format. */
  _fakeNetworkCredential(seed: number, original: string): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(seed >>> 0, 0);
    buf.writeUInt32BE(((seed >>> 16) ^ 0xdeadbeef) >>> 0, 4);
    const h = createHash("sha256").update(buf).digest("hex");

    // Cisco type-5 ($1$salt$hash) — generate proper format
    if (/^\$1\$/.test(original)) {
      const fakeSalt = h.slice(0, 4);
      // Type-5 hash body is 22 chars of base64-like chars
      const hashBody = this._toBase64ish(h.slice(4, 26), 22);
      return `$1$${fakeSalt}$${hashBody}`;
    }

    // Cisco type-8 ($8$salt$hash)
    if (/^\$8\$/.test(original)) {
      const fakeSalt = h.slice(0, 14);
      const fakeHash = h.slice(14, 57);
      return `$8$${fakeSalt}$${fakeHash}`;
    }

    // Cisco type-9 ($9$salt$hash)
    if (/^\$9\$/.test(original)) {
      const fakeSalt = h.slice(0, 14);
      const fakeHash = h.slice(14, 57);
      return `$9$${fakeSalt}$${fakeHash}`;
    }

    // Junos $9$ encoded strings
    if (/^\$9\$/.test(original)) {
      const fakeBody = h.slice(0, Math.max(8, original.length - 3));
      return `$9$${fakeBody}`;
    }

    // Generic $N$ hash prefix
    const hashPrefixMatch = original.match(/^(\$\d+\$)/);
    if (hashPrefixMatch) {
      return `${hashPrefixMatch[1]}${h.slice(0, 8)}$${h.slice(8, 30)}`;
    }

    // Cisco type-7 hex strings: even-length hex, first two chars are salt
    // byte 00-15 (i.e., "00" through "15" in decimal representation, but
    // actually hex 00-0F). Type-7 salt is a two-digit decimal 00-15.
    if (/^[0-9A-Fa-f]{4,}$/.test(original) && original.length % 2 === 0) {
      // Generate valid-looking type-7: start with salt byte (00-15 decimal)
      const salt = String(seed % 16).padStart(2, "0");
      // Rest is hex pairs
      const bodyLen = original.length - 2;
      const body = h.slice(0, bodyLen).toUpperCase();
      return salt + body;
    }

    // Generic credential: preserve length and complexity pattern
    if (original.length > 0) {
      return this._similarComplexity(original, h);
    }

    return `REDACTED_${h.slice(0, 16)}`;
  }

  /** Generate a base64-ish string of given length from hex source. */
  private _toBase64ish(hex: string, len: number): string {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
    let result = "";
    for (let i = 0; i < len; i++) {
      const idx = parseInt(hex.slice((i * 2) % hex.length, (i * 2) % hex.length + 2) || "00", 16);
      result += chars[idx % chars.length];
    }
    return result;
  }

  /** Generate a string with similar complexity patterns (length, has-digit, has-special). */
  private _similarComplexity(original: string, hex: string): string {
    const hasDigit = /\d/.test(original);
    const hasSpecial = /[^a-zA-Z0-9]/.test(original);
    const hasUpper = /[A-Z]/.test(original);
    const hasLower = /[a-z]/.test(original);
    const len = original.length;

    // Build from hex, then inject complexity markers
    let result = hex.slice(0, len);

    if (hasUpper && hasLower) {
      // Mix case
      result = result.split("").map((c, i) =>
        i % 3 === 0 ? c.toUpperCase() : c.toLowerCase()
      ).join("");
    } else if (hasUpper) {
      result = result.toUpperCase();
    }

    if (hasSpecial) {
      // Replace a couple chars with special chars matching original's specials
      const specials = original.replace(/[a-zA-Z0-9]/g, "");
      if (specials.length > 0 && result.length > 2) {
        const chars = result.split("");
        for (let i = 0; i < Math.min(specials.length, 3); i++) {
          const pos = Math.min(2 + i * 3, chars.length - 1);
          chars[pos] = specials[i % specials.length];
        }
        result = chars.join("");
      }
    }

    if (hasDigit && !/\d/.test(result)) {
      // Ensure at least one digit
      const chars = result.split("");
      chars[chars.length - 1] = "7";
      result = chars.join("");
    }

    // Ensure exact length
    if (result.length > len) result = result.slice(0, len);
    while (result.length < len) result += "x";

    return result;
  }

  // -------------------------------------------------------------------------
  // Hostname — role-preserving with geographic site codes
  // -------------------------------------------------------------------------

  /**
   * Generate a fake hostname preserving role, tier, and structure.
   *
   * Structured hostnames like CHI-CORE-RTR-01 are parsed into components:
   * site code is swapped from the geographic pool, role and tier are kept,
   * and the ID number is randomized.
   *
   * DNS-style hostnames like web-01.prod.acme.net preserve hierarchy:
   * env labels (prod/staging/dev) and TLD are kept, org is replaced.
   */
  _fakeHostname(seed: number, original = ""): string {
    if (!original) {
      // No original: generate simple structured hostname
      const role = HOSTNAME_ROLES[seed % HOSTNAME_ROLES.length];
      const site = FAKE_SITES[Math.floor(seed / HOSTNAME_ROLES.length) % FAKE_SITES.length];
      const num = (seed % 99) + 1;
      return `${site}-${role}-${String(num).padStart(2, "0")}`;
    }

    // Try DNS-style parsing: role-id.env.org.tld
    if (original.includes(".")) {
      return this._fakeDnsHostname(seed, original);
    }

    // Try structured hostname parsing: SITE-TIER-ROLE-NUM
    const parts = original.split("-");
    if (parts.length >= 2) {
      return this._fakeStructuredHostname(seed, original, parts);
    }

    // Fallback: simple replacement
    const role = HOSTNAME_ROLES[seed % HOSTNAME_ROLES.length];
    const site = FAKE_SITES[Math.floor(seed / HOSTNAME_ROLES.length) % FAKE_SITES.length];
    const num = (seed % 99) + 1;
    return `${site}-${role}-${String(num).padStart(2, "0")}`;
  }

  /** Parse and rebuild a structured hostname like CHI-CORE-RTR-01. */
  private _fakeStructuredHostname(seed: number, _original: string, parts: string[]): string {
    const result: string[] = [];
    let foundRole = false;
    let foundTier = false;
    let foundSite = false;

    for (const part of parts) {
      const upper = part.toUpperCase();

      // Check if it's a role keyword
      if (HOSTNAME_ROLE_KEYWORDS.has(upper)) {
        result.push(upper);
        foundRole = true;
        continue;
      }

      // Check if it's a tier keyword
      if (HOSTNAME_TIER_KEYWORDS.has(upper)) {
        result.push(upper);
        foundTier = true;
        continue;
      }

      // Check if it's a numeric ID (with or without leading zeros)
      if (/^\d+$/.test(part)) {
        // Randomize but preserve format (e.g., "01" stays 2-digit zero-padded)
        const newNum = (seed % 99) + 1;
        result.push(String(newNum).padStart(part.length, "0"));
        continue;
      }

      // Check if it's a site code (2-4 uppercase letters)
      if (SITE_CODE_RE.test(upper) && !foundSite) {
        result.push(this._mapSite(upper));
        foundSite = true;
        continue;
      }

      // Unknown component — replace with a fake site or generic label
      if (!foundSite && upper.length >= 2 && upper.length <= 6) {
        result.push(this._mapSite(upper));
        foundSite = true;
      } else {
        // Keep as-is if it looks structural, otherwise replace
        result.push(FAKE_SITES[(seed + result.length) % FAKE_SITES.length]);
      }
    }

    // If we found no role, inject one for structural validity
    if (!foundRole && !foundTier) {
      // This didn't match the structured pattern well — use fallback
      const role = HOSTNAME_ROLES[seed % HOSTNAME_ROLES.length];
      const site = FAKE_SITES[Math.floor(seed / HOSTNAME_ROLES.length) % FAKE_SITES.length];
      const num = (seed % 99) + 1;
      return `${site}-${role}-${String(num).padStart(2, "0")}`;
    }

    return result.join("-");
  }

  /**
   * Parse and rebuild a DNS-style hostname like web-01.prod.acme.net.
   * Preserves: env labels (prod/staging/dev), TLD, segment count.
   * Replaces: role name, org name.
   */
  private _fakeDnsHostname(seed: number, original: string): string {
    const segments = original.split(".");
    if (segments.length < 2) {
      // Not really DNS — fallback
      const role = HOSTNAME_ROLES[seed % HOSTNAME_ROLES.length];
      const site = FAKE_SITES[seed % FAKE_SITES.length];
      return `${site}-${role}`;
    }

    const ENV_LABELS = new Set(["prod", "staging", "dev", "test", "qa", "uat", "preprod", "stg", "prd"]);
    const KNOWN_TLDS = new Set(["com", "net", "org", "io", "dev", "co", "tech", "edu", "gov"]);

    const result: string[] = [];
    const tld = segments[segments.length - 1].toLowerCase();
    const hasTld = KNOWN_TLDS.has(tld);

    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      const lower = seg.toLowerCase();

      if (i === segments.length - 1 && hasTld) {
        // Preserve TLD
        result.push(seg);
      } else if (ENV_LABELS.has(lower)) {
        // Preserve environment label
        result.push(seg);
      } else if (i === 0) {
        // First segment is typically role-id (e.g., "web-01", "core-rtr-01")
        // Try to preserve role within it
        const subParts = seg.split("-");
        const fakeSubParts: string[] = [];
        for (const sp of subParts) {
          const upper = sp.toUpperCase();
          if (HOSTNAME_ROLE_KEYWORDS.has(upper) || HOSTNAME_TIER_KEYWORDS.has(upper)) {
            fakeSubParts.push(sp); // preserve role/tier
          } else if (/^\d+$/.test(sp)) {
            const newNum = (seed % 99) + 1;
            fakeSubParts.push(String(newNum).padStart(sp.length, "0"));
          } else {
            // Replace non-role part
            fakeSubParts.push(HOSTNAME_ROLES[seed % HOSTNAME_ROLES.length].toLowerCase());
          }
        }
        result.push(fakeSubParts.join("-"));
      } else if (i === segments.length - 2 && hasTld) {
        // Second-to-last before TLD is the org domain — use consistent mapping
        const orgKey = this._extractOrgDomain(original);
        const fakeOrg = this._mapOrgDomain(orgKey, seed);
        result.push(fakeOrg);
      } else {
        // Middle segments — check if env label, otherwise replace
        if (lower.startsWith("dc-") || lower.startsWith("dc")) {
          result.push(seg); // data center label
        } else {
          const fakeOrg = this._mapOrgDomain(lower, seed);
          result.push(fakeOrg);
        }
      }
    }

    return result.join(".");
  }

  /** Fake VLAN ID/name or VRF name. Preserves the keyword structure. */
  _fakeVlanId(seed: number, original: string): string {
    // VRF names: VRF-VOICE, VRF-EUROCAT_E, VRF_OPS_DATA, etc.
    if (/^VRF[-_]/i.test(original) || /^[A-Z][A-Z_]{2,}$/i.test(original)) {
      return VRF_NAMES[seed % VRF_NAMES.length];
    }
    // Route distinguisher / route target: 65001:100
    if (/^\d+:\d+$/.test(original)) {
      const asn = 64512 + (seed % 1023);
      const id = 100 + (seed % 900);
      return `${asn}:${id}`;
    }
    // If the original is a "vlan <id>" or just a number in a vlan context,
    // the detector captures the full match. Preserve surrounding keywords.
    const nameMatch = original.match(/name\s+(.+)/i);
    if (nameMatch) {
      const fakeName = VLAN_NAMES[seed % VLAN_NAMES.length];
      return `name ${fakeName}`;
    }
    // VLAN range like "100-200" or "100,200,300"
    if (original.includes("-") || original.includes(",")) {
      const fakeBase = 100 + (seed % 900);
      if (original.includes("-")) {
        return `${fakeBase}-${fakeBase + 99}`;
      }
      const parts = original.split(",");
      return parts.map((_, i) => fakeBase + i * 10).join(",");
    }
    // Single VLAN number
    return String(100 + (seed % 3900));
  }

  // -------------------------------------------------------------------------
  // Interface description — topology-aware
  // -------------------------------------------------------------------------

  /**
   * Fake interface description preserving topology keywords.
   *
   * UPLINK, DOWNLINK, PEER, TRANSIT, TO, FROM, etc. survive obfuscation.
   * Device names, site codes, circuit IDs, and customer names are replaced.
   */
  _fakeInterfaceDesc(seed: number, original: string): string {
    if (!original) {
      return INTERFACE_DESCS[seed % INTERFACE_DESCS.length];
    }

    // Split by whitespace and underscores (descriptions use both)
    const sep = original.includes("_") ? "_" : " ";
    const tokens = original.split(/[\s_]+/);

    if (tokens.length < 2) {
      return INTERFACE_DESCS[seed % INTERFACE_DESCS.length];
    }

    const result: string[] = [];
    let replacementIdx = 0;

    for (const token of tokens) {
      const upper = token.toUpperCase();
      // Preserve topology keywords
      if (TOPOLOGY_KEYWORDS.has(upper)) {
        result.push(token);
        continue;
      }
      // Preserve if it looks like a known structural keyword (interface type etc.)
      if (/^(Gi|Te|Ge|Eth|Fa|Po|Lo)\d/.test(token)) {
        result.push(token);
        continue;
      }
      // If it looks like a hostname (has dashes and letters), replace it
      if (/[A-Z].*-.*[A-Z0-9]/i.test(token) || SITE_CODE_RE.test(upper)) {
        // Try to parse as structured hostname
        const subParts = token.split("-");
        const fakeSubParts: string[] = [];
        for (const sp of subParts) {
          const spUpper = sp.toUpperCase();
          if (HOSTNAME_ROLE_KEYWORDS.has(spUpper) || HOSTNAME_TIER_KEYWORDS.has(spUpper)) {
            fakeSubParts.push(sp);
          } else if (/^\d+$/.test(sp)) {
            fakeSubParts.push(String((seed % 99) + 1).padStart(sp.length, "0"));
          } else if (SITE_CODE_RE.test(spUpper)) {
            fakeSubParts.push(this._mapSite(spUpper));
          } else {
            fakeSubParts.push(FAKE_SITES[(seed + replacementIdx) % FAKE_SITES.length]);
            replacementIdx++;
          }
        }
        result.push(fakeSubParts.join("-"));
        continue;
      }
      // Circuit IDs, customer names — replace
      if (/^[A-Z]{2,}$/i.test(token) && token.length <= 4) {
        result.push(this._mapSite(token.toUpperCase()));
      } else {
        result.push(INTERFACE_DESCS[seed % INTERFACE_DESCS.length].split(" ")[replacementIdx % 3] || "Link");
        replacementIdx++;
      }
    }

    return result.join(sep);
  }

  // -------------------------------------------------------------------------
  // Route-map — semantic-preserving
  // -------------------------------------------------------------------------

  /**
   * Fake route-map or prefix-list name preserving policy semantics.
   *
   * Pattern: RM-<POLICY>-<PROVIDER>-<DIRECTION>
   * Preserves: RM/PL prefix, policy type (TRANSIT/PEER/CUSTOMER/DEFAULT),
   *            IN/OUT direction. Replaces: provider/customer name.
   */
  _fakeRouteMap(seed: number, original: string): string {
    if (!original) {
      return ROUTE_MAP_NAMES[seed % ROUTE_MAP_NAMES.length];
    }

    const upper = original.toUpperCase();
    const parts = upper.split("-");

    if (parts.length < 2) {
      return ROUTE_MAP_NAMES[seed % ROUTE_MAP_NAMES.length];
    }

    // Known prefixes
    const KNOWN_PREFIXES = new Set(["RM", "PL", "RMAP", "RPL"]);
    // Known policy types
    const POLICY_TYPES = new Set(["TRANSIT", "PEER", "CUSTOMER", "CUST", "DEFAULT", "LOCAL", "EXPORT", "IMPORT", "REDISTRIBUTE", "FILTER", "PRIMARY", "SECONDARY", "BACKUP"]);
    // Known directions
    const DIRECTIONS = new Set(["IN", "OUT", "INBOUND", "OUTBOUND"]);

    const result: string[] = [];
    const toReplace: number[] = [];

    for (let i = 0; i < parts.length; i++) {
      const p = parts[i];
      if (KNOWN_PREFIXES.has(p)) {
        result.push(p);
      } else if (POLICY_TYPES.has(p)) {
        result.push(p);
      } else if (DIRECTIONS.has(p)) {
        result.push(p);
      } else {
        // This is a provider/customer name — mark for replacement
        result.push(p); // placeholder
        toReplace.push(i);
      }
    }

    // Replace provider/customer names with fake providers
    for (const idx of toReplace) {
      result[idx] = FAKE_PROVIDERS[(seed + idx) % FAKE_PROVIDERS.length];
    }

    // If nothing was replaced, just use the fallback
    if (toReplace.length === 0 && parts.length > 2) {
      return ROUTE_MAP_NAMES[seed % ROUTE_MAP_NAMES.length];
    }

    return result.join("-");
  }

  /** Fake OSPF identifiers (router-id or area). */
  _fakeOspfId(seed: number, original: string): string {
    // OSPF area can be a number or dotted-quad
    const areaNumMatch = original.match(/area\s+(\d+)/i);
    if (areaNumMatch) {
      return `area ${seed % 100}`;
    }
    // Router-id is typically an IP-like dotted quad
    const fakeId = `10.${(seed % 256)}.${(Math.floor(seed / 256) % 256)}.${(Math.floor(seed / 65536) % 256)}`;
    return fakeId;
  }

  /** Fake ACL name. */
  _fakeAclName(seed: number, _original: string): string {
    return ACL_NAMES[seed % ACL_NAMES.length];
  }
}
