/**
 * DNS resolution cache for URL classification.
 *
 * Resolves FQDNs to determine whether they point to public (external) or
 * private (internal/RFC 1918) addresses. Public URLs are passed through
 * without obfuscation — the LLM needs to see real URLs to make tool call
 * decisions (e.g., "fetch this page").
 *
 * Design:
 *   - warmCache() is async — called in the before_prompt_build hook
 *   - isPublic() is sync — checked in the obfuscation pipeline's isDocExample()
 *   - Cache miss = null (unknown) → obfuscate (safe default, privacy-first)
 *   - Uses only Node.js builtins (dns, net). Zero runtime dependencies.
 */

import { lookup } from "node:dns";
import { isIPv4, isIPv6 } from "node:net";

/** Cache entry for a resolved FQDN. */
interface DnsCacheEntry {
  address: string | null; // resolved IP, or null if NXDOMAIN/error
  isPublic: boolean;
  resolvedAt: number; // Date.now()
}

/** Default cache TTL: 1 hour. */
const DEFAULT_TTL_MS = 60 * 60 * 1000;

/**
 * RFC 1918 + other private/reserved IPv4 ranges.
 * Returns true if the IP should be treated as internal.
 */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p))) return true; // malformed → treat as private

  const [a, b] = parts;

  // 10.0.0.0/8 — RFC 1918
  if (a === 10) return true;

  // 172.16.0.0/12 — RFC 1918 (172.16.0.0 – 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.168.0.0/16 — RFC 1918
  if (a === 192 && b === 168) return true;

  // 127.0.0.0/8 — loopback
  if (a === 127) return true;

  // 169.254.0.0/16 — link-local
  if (a === 169 && b === 254) return true;

  // 100.64.0.0/10 — CGNAT (Shroud's fake range — definitely private)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 0.0.0.0/8 — "this" network
  if (a === 0) return true;

  // 224.0.0.0/4 — multicast
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 — reserved
  if (a >= 240) return true;

  return false;
}

/**
 * Check if an IPv6 address is private/reserved.
 */
export function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();

  // ::1 — loopback
  if (lower === "::1") return true;

  // fc00::/7 — unique local (ULA)
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;

  // fe80::/10 — link-local
  if (lower.startsWith("fe80")) return true;

  // :: — unspecified
  if (lower === "::") return true;

  return false;
}

/**
 * Extract FQDN from a URL string.
 * Returns null if the URL is malformed or the host is an IP literal.
 */
export function extractFqdn(url: string): string | null {
  // Match protocol://host[:port][/path]
  const match = url.match(/^https?:\/\/([^/:]+)/i);
  if (!match) return null;

  const host = match[1].toLowerCase();

  // Skip IP literals — they're handled by the IP detector, not the URL detector
  if (isIPv4(host) || isIPv6(host) || host.startsWith("[")) return null;

  // Skip localhost
  if (host === "localhost") return null;

  // Must have at least one dot (skip bare hostnames)
  if (!host.includes(".")) return null;

  return host;
}

export class DnsCache {
  private _cache = new Map<string, DnsCacheEntry>();
  private _ttlMs: number;
  private _pending = new Map<string, Promise<DnsCacheEntry>>();

  constructor(ttlMs: number = DEFAULT_TTL_MS) {
    this._ttlMs = ttlMs;
  }

  /**
   * Resolve an array of URLs and warm the cache.
   * Called from the async before_prompt_build hook.
   * Resolves all FQDNs in parallel for speed.
   */
  async warmCache(urls: string[]): Promise<void> {
    const fqdns = new Set<string>();
    for (const url of urls) {
      const fqdn = extractFqdn(url);
      if (fqdn && !this._isCached(fqdn)) {
        fqdns.add(fqdn);
      }
    }

    if (fqdns.size === 0) return;

    const promises = [...fqdns].map((fqdn) => this._resolve(fqdn));
    await Promise.allSettled(promises);
  }

  /**
   * Check if a URL points to a public (external) host.
   *
   * Returns:
   *   true  — resolved to a public IP, safe to pass through
   *   false — resolved to a private IP, should be obfuscated
   *   null  — not in cache (DNS not yet resolved), obfuscate as safe default
   */
  isPublic(url: string): boolean | null {
    const fqdn = extractFqdn(url);
    if (!fqdn) return null;

    const entry = this._cache.get(fqdn);
    if (!entry) return null;

    // Check TTL
    if (Date.now() - entry.resolvedAt > this._ttlMs) {
      this._cache.delete(fqdn);
      return null;
    }

    return entry.isPublic;
  }

  /**
   * Get the resolved address for a URL (for logging/audit).
   */
  getAddress(url: string): string | null {
    const fqdn = extractFqdn(url);
    if (!fqdn) return null;
    return this._cache.get(fqdn)?.address ?? null;
  }

  /** Number of cached entries. */
  get size(): number {
    return this._cache.size;
  }

  /** Clear the cache. */
  clear(): void {
    this._cache.clear();
    this._pending.clear();
  }

  /** Pre-seed the cache (for testing with /etc/hosts or mocks). */
  seed(fqdn: string, address: string | null, isPublic: boolean): void {
    this._cache.set(fqdn.toLowerCase(), {
      address,
      isPublic,
      resolvedAt: Date.now(),
    });
  }

  private _isCached(fqdn: string): boolean {
    const entry = this._cache.get(fqdn);
    if (!entry) return false;
    return Date.now() - entry.resolvedAt <= this._ttlMs;
  }

  private _resolve(fqdn: string): Promise<DnsCacheEntry> {
    // Deduplicate concurrent lookups for the same FQDN
    const existing = this._pending.get(fqdn);
    if (existing) return existing;

    const promise = new Promise<DnsCacheEntry>((resolve) => {
      // 3-second timeout to avoid blocking the hook
      const timer = setTimeout(() => {
        const entry: DnsCacheEntry = {
          address: null,
          isPublic: false, // timeout → treat as private (safe default)
          resolvedAt: Date.now(),
        };
        this._cache.set(fqdn, entry);
        this._pending.delete(fqdn);
        resolve(entry);
      }, 3000);

      lookup(fqdn, { all: false }, (err, address, family) => {
        clearTimeout(timer);

        let entry: DnsCacheEntry;
        if (err || !address) {
          // NXDOMAIN, ENOTFOUND, etc. → treat as private
          entry = {
            address: null,
            isPublic: false,
            resolvedAt: Date.now(),
          };
        } else {
          const isPrivate =
            family === 4
              ? isPrivateIPv4(address)
              : family === 6
                ? isPrivateIPv6(address)
                : true; // unknown family → private

          entry = {
            address,
            isPublic: !isPrivate,
            resolvedAt: Date.now(),
          };
        }

        this._cache.set(fqdn, entry);
        this._pending.delete(fqdn);
        resolve(entry);
      });
    });

    this._pending.set(fqdn, promise);
    return promise;
  }
}
