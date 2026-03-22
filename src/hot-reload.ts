/**
 * Hot-reload support for detection rules.
 *
 * Watches the policy file and custom patterns config for changes,
 * and re-initializes detectors without restarting the plugin.
 * Uses Node.js fs.watch for file-system notifications.
 */

import { watchFile, unwatchFile, existsSync, readFileSync } from "node:fs";

export interface HotReloadConfig {
  /** Path to the policy file to watch. */
  policyFile?: string;
  /** Path to a custom patterns JSON file to watch. */
  customPatternsFile?: string;
  /** Debounce interval in ms (prevents rapid reloads). */
  debounceMs?: number;
}

export type ReloadCallback = (what: "policy" | "customPatterns" | "detectorOverrides", data?: unknown) => void;

export class DetectorReloader {
  private _config: HotReloadConfig;
  private _callback: ReloadCallback;
  private _watching = false;
  private _debounceTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();
  private _debounceMs: number;
  private _reloadCount = 0;

  constructor(config: HotReloadConfig, callback: ReloadCallback) {
    this._config = config;
    this._callback = callback;
    this._debounceMs = config.debounceMs ?? 1000;
  }

  /** Start watching configured files. */
  start(): void {
    if (this._watching) return;
    this._watching = true;

    if (this._config.policyFile && existsSync(this._config.policyFile)) {
      this._watchFile(this._config.policyFile, "policy");
    }

    if (this._config.customPatternsFile && existsSync(this._config.customPatternsFile)) {
      this._watchFile(this._config.customPatternsFile, "customPatterns");
    }
  }

  /** Stop watching all files. */
  stop(): void {
    if (!this._watching) return;
    this._watching = false;

    if (this._config.policyFile) {
      unwatchFile(this._config.policyFile);
    }
    if (this._config.customPatternsFile) {
      unwatchFile(this._config.customPatternsFile);
    }

    for (const timer of this._debounceTimers.values()) {
      clearTimeout(timer);
    }
    this._debounceTimers.clear();
  }

  /** Number of successful reloads since start. */
  get reloadCount(): number {
    return this._reloadCount;
  }

  /** Whether the reloader is actively watching. */
  get isWatching(): boolean {
    return this._watching;
  }

  /** Force a reload of a specific config type (for testing / manual trigger). */
  triggerReload(what: "policy" | "customPatterns" | "detectorOverrides", data?: unknown): void {
    this._reloadCount++;
    this._callback(what, data);
  }

  private _watchFile(path: string, type: "policy" | "customPatterns"): void {
    watchFile(path, { interval: 2000 }, () => {
      if (!this._watching) return;

      // Debounce rapid changes
      const existing = this._debounceTimers.get(path);
      if (existing) clearTimeout(existing);

      this._debounceTimers.set(
        path,
        setTimeout(() => {
          this._debounceTimers.delete(path);
          this._onFileChanged(path, type);
        }, this._debounceMs),
      );
    });
  }

  private _onFileChanged(path: string, type: "policy" | "customPatterns"): void {
    try {
      if (!existsSync(path)) return;
      const content = readFileSync(path, "utf-8");
      const parsed = JSON.parse(content);
      this._reloadCount++;
      this._callback(type, parsed);
    } catch (err) {
      console.warn(`[shroud][hot-reload] Failed to reload ${type} from ${path}: ${err}`);
    }
  }
}
