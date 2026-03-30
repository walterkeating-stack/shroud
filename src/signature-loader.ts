/**
 * Hot-refresh signature loader.
 *
 * Fetches external signature definitions from a URL or local file,
 * merges them with built-in signatures at runtime. Supports periodic
 * polling with atomic swap — no restart needed.
 *
 * Zero runtime dependencies — uses Node.js built-in http/https + fs.
 *
 * Signature JSON schema:
 * {
 *   "version": "1.0",
 *   "updated": "2026-03-30T12:00:00Z",
 *   "injectionSignatures": [
 *     { "id": "custom_sig_1", "threatClass": "instruction_override",
 *       "pattern": "ignore all safety", "flags": "gi",
 *       "severity": "high", "description": "...", "direction": "request" }
 *   ],
 *   "toolGuardPatterns": [
 *     { "id": "custom_tg_1", "paramPattern": "kubectl delete ns",
 *       "flags": "gi", "severity": "high", "description": "...",
 *       "block": true, "toolName": null }
 *   ]
 * }
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import * as nodeHttps from "node:https";
import * as nodeHttp from "node:http";
import type { SecuritySeverity, ThreatClass } from "./security-event.js";

/** External signature definition (JSON-friendly — pattern is a string, not RegExp). */
export interface ExternalSignature {
  id: string;
  threatClass: string;
  pattern: string;
  flags?: string;
  severity: "low" | "medium" | "high";
  description: string;
  direction: "request" | "response" | "both";
}

/** External tool guard pattern (JSON-friendly). */
export interface ExternalToolGuard {
  id: string;
  toolName: string | null;
  paramPattern: string;
  flags?: string;
  severity: "low" | "medium" | "high";
  description: string;
  block: boolean;
}

/** The full signature feed payload. */
export interface SignatureFeed {
  version: string;
  updated: string;
  injectionSignatures?: ExternalSignature[];
  toolGuardPatterns?: ExternalToolGuard[];
}

/** Compiled signatures ready for the scanner. */
export interface CompiledSignatures {
  injection: Array<{
    id: string;
    threatClass: string;
    pattern: RegExp;
    severity: "low" | "medium" | "high";
    description: string;
    direction: "request" | "response" | "both";
  }>;
  toolGuard: Array<{
    id: string;
    toolName: string | null;
    paramPattern: RegExp;
    severity: "low" | "medium" | "high";
    description: string;
    block: boolean;
  }>;
  feedVersion: string;
  feedUpdated: string;
  loadedAt: number;
}

/**
 * Signature loader with hot-refresh support.
 */
export class SignatureLoader {
  private _url: string | null;
  private _filePath: string | null;
  private _refreshMs: number;
  private _timer: ReturnType<typeof setInterval> | null = null;
  private _current: CompiledSignatures | null = null;
  private _onUpdate: ((sigs: CompiledSignatures) => void) | null = null;
  private _cacheDir: string;

  constructor(opts: {
    url?: string | null;
    filePath?: string | null;
    refreshSec?: number;
    cacheDir?: string;
  }) {
    this._url = opts.url || null;
    this._filePath = opts.filePath || null;
    this._refreshMs = (opts.refreshSec || 3600) * 1000;
    this._cacheDir = opts.cacheDir || "/tmp/shroud-signatures";
  }

  /** Register a callback for when signatures are refreshed. */
  onUpdate(cb: (sigs: CompiledSignatures) => void): void {
    this._onUpdate = cb;
  }

  /** Get the currently loaded external signatures (null if none loaded). */
  getCurrent(): CompiledSignatures | null {
    return this._current;
  }

  /** Start polling. Does an immediate load, then polls on interval. */
  async start(): Promise<void> {
    if (!this._url && !this._filePath) return;

    // Immediate load
    await this._refresh();

    // Periodic poll
    if (this._refreshMs > 0) {
      this._timer = setInterval(() => this._refresh(), this._refreshMs);
      // Don't keep the process alive for the timer
      if (this._timer.unref) this._timer.unref();
    }
  }

  /** Stop polling. */
  stop(): void {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /** Force a manual refresh. */
  async refresh(): Promise<CompiledSignatures | null> {
    await this._refresh();
    return this._current;
  }

  private async _refresh(): Promise<void> {
    try {
      let json: string | null = null;

      // Try URL first
      if (this._url) {
        json = await this._fetchUrl(this._url);
        // Cache to local file for offline resilience
        if (json) {
          try {
            mkdirSync(this._cacheDir, { recursive: true });
            writeFileSync(
              join(this._cacheDir, "signatures-cache.json"),
              json, "utf-8",
            );
          } catch {}
        }
      }

      // Fall back to local file
      if (!json && this._filePath) {
        try {
          json = readFileSync(this._filePath, "utf-8");
        } catch {}
      }

      // Fall back to cached copy
      if (!json) {
        const cachePath = join(this._cacheDir, "signatures-cache.json");
        if (existsSync(cachePath)) {
          try { json = readFileSync(cachePath, "utf-8"); } catch {}
        }
      }

      if (!json) return;

      // Max feed size: 500KB — reject bloated/malicious payloads
      if (json.length > 512_000) return;

      const feed = JSON.parse(json) as SignatureFeed;

      // Max 500 signatures per feed — prevent resource exhaustion
      if ((feed.injectionSignatures?.length || 0) > 500) return;
      if ((feed.toolGuardPatterns?.length || 0) > 500) return;

      const compiled = this._compile(feed);

      // Only update if version changed or first load
      if (!this._current || compiled.feedVersion !== this._current.feedVersion ||
          compiled.feedUpdated !== this._current.feedUpdated) {
        this._current = compiled;
        if (this._onUpdate) this._onUpdate(compiled);
      }
    } catch {
      // Non-fatal — keep using existing signatures
    }
  }

  /** Compile JSON signature definitions into RegExp objects with safety validation. */
  private _compile(feed: SignatureFeed): CompiledSignatures {
    const injection = (feed.injectionSignatures || [])
      .filter(sig => this._validateSig(sig))
      .map(sig => ({
        id: sig.id,
        threatClass: sig.threatClass,
        pattern: new RegExp(sig.pattern, this._sanitizeFlags(sig.flags)),
        severity: sig.severity,
        description: sig.description,
        direction: sig.direction,
      }));

    const toolGuard = (feed.toolGuardPatterns || [])
      .filter(tg => this._validateToolGuard(tg))
      .map(tg => ({
        id: tg.id,
        toolName: tg.toolName,
        paramPattern: new RegExp(tg.paramPattern, this._sanitizeFlags(tg.flags)),
        severity: tg.severity,
        description: tg.description,
        block: tg.block,
      }));

    return {
      injection,
      toolGuard,
      feedVersion: feed.version || "unknown",
      feedUpdated: feed.updated || new Date().toISOString(),
      loadedAt: Date.now(),
    };
  }

  /** Validate an injection signature before compilation. */
  private _validateSig(sig: ExternalSignature): boolean {
    // Must have required fields
    if (!sig.id || !sig.pattern || !sig.severity || !sig.direction) return false;
    // ID must be prefixed with ext_ (external signatures can't impersonate built-ins)
    if (!sig.id.startsWith("ext_")) return false;
    // Severity must be valid
    if (!["low", "medium", "high"].includes(sig.severity)) return false;
    // Direction must be valid
    if (!["request", "response", "both"].includes(sig.direction)) return false;
    // Pattern length cap — prevents ReDoS via catastrophic backtracking
    if (sig.pattern.length > 500) return false;
    // Block nested quantifiers (ReDoS: (a+)+ or (a*)*b)
    if (/\([^)]*[+*][^)]*\)[+*]/.test(sig.pattern)) return false;
    // Test compile — reject if regex is invalid
    try { new RegExp(sig.pattern); } catch { return false; }
    // Description length cap
    if ((sig.description || "").length > 300) return false;
    return true;
  }

  /** Validate a tool guard pattern before compilation. */
  private _validateToolGuard(tg: ExternalToolGuard): boolean {
    if (!tg.id || !tg.paramPattern || !tg.severity) return false;
    if (!tg.id.startsWith("ext_")) return false;
    if (!["low", "medium", "high"].includes(tg.severity)) return false;
    if (tg.paramPattern.length > 500) return false;
    if (/\([^)]*[+*][^)]*\)[+*]/.test(tg.paramPattern)) return false;
    try { new RegExp(tg.paramPattern); } catch { return false; }
    if ((tg.description || "").length > 300) return false;
    return true;
  }

  /** Sanitize regex flags — only allow safe flags. */
  private _sanitizeFlags(flags?: string): string {
    if (!flags) return "gi";
    return flags.replace(/[^gimsuy]/g, "") || "gi";
  }

  /** Fetch a URL using Node.js built-in http/https. Zero dependencies. */
  private _fetchUrl(url: string): Promise<string | null> {
    return new Promise((resolve) => {
      try {
        const mod = url.startsWith("https") ? nodeHttps : nodeHttp;
        const req = mod.get(url, { timeout: 10_000 }, (res: any) => {
          // Follow redirects (1 level)
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            this._fetchUrl(res.headers.location).then(resolve);
            return;
          }
          if (res.statusCode !== 200) { resolve(null); return; }

          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
          res.on("error", () => resolve(null));
        });
        req.on("error", () => resolve(null));
        req.on("timeout", () => { req.destroy(); resolve(null); });
      } catch {
        resolve(null);
      }
    });
  }
}
