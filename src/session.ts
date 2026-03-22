/**
 * Per-session isolation manager.
 *
 * Maintains separate mapping stores, mapping engines, and canary injectors
 * per session, ensuring that obfuscation state never leaks across sessions.
 * Each session gets its own random salt and store.
 */

import { randomBytes } from "node:crypto";

import { MemoryStore, MappingStore } from "./store.js";
import { MappingEngine } from "./mapping.js";
import { SubnetMapper } from "./generators/network.js";
import { CanaryInjector } from "./canary.js";

export interface SessionInfo {
  id: string;
  createdAt: string;
  salt: string;
  storeSize: number;
  active: boolean;
}

interface SessionState {
  id: string;
  createdAt: string;
  store: MemoryStore;
  mapping: MappingEngine;
  subnetMapper: SubnetMapper;
  canary: CanaryInjector | null;
}

export class SessionManager {
  private _sessions: Map<string, SessionState> = new Map();
  private _activeSessionId: string | null = null;
  private _secretKey: string;
  private _canaryEnabled: boolean;
  private _canaryPrefix: string;
  private _maxStoreMappings: number;
  private _tenantId: string;

  constructor(opts: {
    secretKey: string;
    canaryEnabled?: boolean;
    canaryPrefix?: string;
    maxStoreMappings?: number;
    tenantId?: string;
  }) {
    this._secretKey = opts.secretKey;
    this._canaryEnabled = opts.canaryEnabled ?? false;
    this._canaryPrefix = opts.canaryPrefix ?? "SHROUD-CANARY";
    this._maxStoreMappings = opts.maxStoreMappings ?? 0;
    this._tenantId = opts.tenantId ?? "";
  }

  /** Create a new session and make it active. Returns session ID. */
  createSession(sessionId?: string): string {
    const id = sessionId ?? randomBytes(12).toString("hex");
    const subnetMapper = new SubnetMapper();
    const salt = randomBytes(16).toString("hex");
    const mapping = new MappingEngine(
      this._secretKey,
      salt,
      subnetMapper,
      this._tenantId || undefined,
    );
    const store = new MemoryStore(this._maxStoreMappings);
    const canary = this._canaryEnabled
      ? new CanaryInjector(this._canaryPrefix, this._secretKey)
      : null;

    this._sessions.set(id, {
      id,
      createdAt: new Date().toISOString(),
      store,
      mapping,
      subnetMapper,
      canary,
    });

    this._activeSessionId = id;
    return id;
  }

  /** Switch to an existing session. */
  switchSession(sessionId: string): void {
    if (!this._sessions.has(sessionId)) {
      throw new Error(`Session "${sessionId}" does not exist`);
    }
    this._activeSessionId = sessionId;
  }

  /** Get the active session's components, or null if no active session. */
  getActiveSession(): {
    id: string;
    store: MappingStore;
    mapping: MappingEngine;
    subnetMapper: SubnetMapper;
    canary: CanaryInjector | null;
  } | null {
    if (!this._activeSessionId) return null;
    const s = this._sessions.get(this._activeSessionId);
    if (!s) return null;
    return {
      id: s.id,
      store: s.store,
      mapping: s.mapping,
      subnetMapper: s.subnetMapper,
      canary: s.canary,
    };
  }

  /** Destroy a session and clear its data. */
  destroySession(sessionId: string): void {
    const s = this._sessions.get(sessionId);
    if (s) {
      s.store.clear();
      this._sessions.delete(sessionId);
      if (this._activeSessionId === sessionId) {
        this._activeSessionId = null;
      }
    }
  }

  /** List all sessions with metadata. */
  listSessions(): SessionInfo[] {
    return [...this._sessions.entries()].map(([id, s]) => ({
      id,
      createdAt: s.createdAt,
      salt: s.mapping.salt,
      storeSize: s.store.size(),
      active: id === this._activeSessionId,
    }));
  }

  /** Get the active session ID. */
  get activeSessionId(): string | null {
    return this._activeSessionId;
  }

  /** Total sessions. */
  get sessionCount(): number {
    return this._sessions.size;
  }

  /** Clear all sessions. */
  clearAll(): void {
    for (const s of this._sessions.values()) {
      s.store.clear();
    }
    this._sessions.clear();
    this._activeSessionId = null;
  }
}
