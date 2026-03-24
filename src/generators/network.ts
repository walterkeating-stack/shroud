/**
 * Fake network entity generators: IPs, emails, URLs, domains, MACs, BGP ASNs.
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

export const HOSTNAME_SITES = [
  "SITE-A", "SITE-B", "SITE-C", "SITE-D", "SITE-E",
];

export const PATH_SEGMENTS = [
  "app", "api", "docs", "dashboard", "portal", "v2", "status", "health",
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
        if (prefixLen < 0 || prefixLen > 32) continue;
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

    // Allocate a slot in CGNAT space, aligned to the subnet size
    const hostBits = 32 - prefixLen;
    const subnetSize = 1 << hostBits;

    // Place fake networks sequentially in CGNAT space
    let fakeNet = (CGNAT_BASE + this.subnetNextSlot * subnetSize) >>> 0;
    this.subnetNextSlot += 1;

    // Wrap around if we exceed CGNAT space
    if ((fakeNet + subnetSize) >>> 0 > (CGNAT_BASE + CGNAT_SIZE) >>> 0) {
      this.subnetNextSlot = 0;
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
      return this._fakeAsn(seed);
    } else if (category === Category.SNMP_COMMUNITY) {
      return this._fakeSnmpCommunity(seed);
    } else if (category === Category.NETWORK_CREDENTIAL) {
      return this._fakeNetworkCredential(seed, original);
    } else if (category === Category.HOSTNAME) {
      return this._fakeHostname(seed);
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

  _fakeEmail(seed: number, original: string): string {
    // Analyze original structure
    let origLocal = "";
    let origTld = "";

    if (original && original.includes("@")) {
      const atIdx = original.lastIndexOf("@");
      origLocal = original.slice(0, atIdx);
      const origDomainFull = original.slice(atIdx + 1);
      if (origDomainFull.includes(".")) {
        const dotIdx = origDomainFull.lastIndexOf(".");
        origTld = origDomainFull.slice(dotIdx + 1);
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

    // Try to match TLD
    let domainPool: string[];
    if (origTld && DOMAINS_BY_TLD[origTld]) {
      domainPool = DOMAINS_BY_TLD[origTld];
    } else {
      domainPool = DOMAINS;
    }
    const domain =
      domainPool[Math.floor(seed / pool.length) % domainPool.length];

    // Preserve dots in local part (e.g., "john.doe" -> "dev.ops")
    if (origLocal && origLocal.includes(".")) {
      const extra =
        EMAIL_PREFIXES[Math.floor(seed / 7) % EMAIL_PREFIXES.length];
      prefix = `${prefix}.${extra}`;
    }

    const num =
      Math.floor(seed / (pool.length * domainPool.length)) % 100;
    if (num > 0) {
      return `${prefix}${num}@${domain}`;
    }
    return `${prefix}@${domain}`;
  }

  _fakeUrl(seed: number, original: string): string {
    const domain = DOMAINS[seed % DOMAINS.length];

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

  /** Map BGP AS numbers to the private AS range (64512-65534). */
  _fakeAsn(seed: number): string {
    const base = 64512;
    return String(base + (seed % 1023));
  }

  /** Replace SNMP community strings with generic names. */
  _fakeSnmpCommunity(seed: number): string {
    return SNMP_COMMUNITIES[seed % SNMP_COMMUNITIES.length];
  }

  /** Replace network credentials with seed-derived unique fake values. */
  _fakeNetworkCredential(seed: number, original: string): string {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(seed >>> 0, 0);
    buf.writeUInt32BE(((seed >>> 16) ^ 0xdeadbeef) >>> 0, 4);
    const h = createHash("sha256").update(buf).digest("hex");

    // Preserve hash type prefix for structure hints
    const hashPrefixMatch = original.match(/^(\$\d\$)/);
    if (hashPrefixMatch) {
      // e.g. $1$salt$hash → $1$fakesalt$fakehash
      return `${hashPrefixMatch[1]}${h.slice(0, 8)}$${h.slice(8, 30)}`;
    }
    // Cisco type 7 hex strings
    if (/^[0-9A-Fa-f]{4,}$/.test(original)) {
      return h.slice(0, original.length).toUpperCase();
    }
    // Generic credential
    return `REDACTED_${h.slice(0, 16)}`;
  }

  /** Generate a fake hostname preserving structure. */
  _fakeHostname(seed: number): string {
    const role = HOSTNAME_ROLES[seed % HOSTNAME_ROLES.length];
    const site =
      HOSTNAME_SITES[
        Math.floor(seed / HOSTNAME_ROLES.length) % HOSTNAME_SITES.length
      ];
    const num = (seed % 99) + 1;
    return `${site}-${role}-${String(num).padStart(2, "0")}`;
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

  /** Fake interface description. */
  _fakeInterfaceDesc(seed: number, _original: string): string {
    return INTERFACE_DESCS[seed % INTERFACE_DESCS.length];
  }

  /** Fake route-map or prefix-list name. */
  _fakeRouteMap(seed: number, _original: string): string {
    return ROUTE_MAP_NAMES[seed % ROUTE_MAP_NAMES.length];
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
