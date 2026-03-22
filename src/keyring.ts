/**
 * Key rotation and versioned key management.
 *
 * Holds multiple versioned secret keys in a ring. The active key is used for
 * new obfuscations; all non-expired keys are available for deobfuscation
 * and session import decryption.
 */

export interface VersionedKey {
  /** Monotonically increasing version number. */
  version: number;
  /** The raw secret key string. */
  key: string;
  /** ISO-8601 creation timestamp. */
  createdAt: string;
  /** Optional ISO-8601 expiration timestamp. */
  expiresAt?: string;
  /** Soft-disable: won't be used for new obfuscation. */
  retired?: boolean;
}

export class KeyRing {
  private _keys: VersionedKey[];
  private _activeVersion: number | undefined;

  constructor(keys: VersionedKey[], activeVersion?: number) {
    if (keys.length === 0) {
      throw new Error("KeyRing requires at least one key");
    }
    // Validate unique versions
    const versions = new Set(keys.map((k) => k.version));
    if (versions.size !== keys.length) {
      throw new Error("All key versions must be unique");
    }
    this._keys = [...keys].sort((a, b) => a.version - b.version);
    this._activeVersion = activeVersion;
  }

  /** Create a KeyRing from a single secret key (backward compat). */
  static fromSingleKey(key: string): KeyRing {
    return new KeyRing([
      {
        version: 1,
        key,
        createdAt: new Date().toISOString(),
      },
    ]);
  }

  /** The key used for new obfuscations: explicitly set active, or highest non-expired non-retired. */
  activeKey(): VersionedKey {
    if (this._activeVersion !== undefined) {
      const k = this._keys.find((k) => k.version === this._activeVersion);
      if (k && !this._isExpired(k)) return k;
    }
    // Fall back to highest non-expired, non-retired
    for (let i = this._keys.length - 1; i >= 0; i--) {
      const k = this._keys[i];
      if (!this._isExpired(k) && !k.retired) return k;
    }
    // Last resort: highest non-expired (even if retired)
    for (let i = this._keys.length - 1; i >= 0; i--) {
      const k = this._keys[i];
      if (!this._isExpired(k)) return k;
    }
    throw new Error("No valid (non-expired) keys in KeyRing");
  }

  /** All non-expired keys (for deobfuscation / session decrypt attempts). */
  allKeys(): VersionedKey[] {
    return this._keys.filter((k) => !this._isExpired(k));
  }

  /** All keys including expired (for diagnostics). */
  allKeysRaw(): VersionedKey[] {
    return [...this._keys];
  }

  /** Get a specific key by version. */
  getKey(version: number): VersionedKey | undefined {
    return this._keys.find((k) => k.version === version);
  }

  /** Add a new key with the next version number. Returns the new VersionedKey. */
  addKey(key: string, expiresAt?: string): VersionedKey {
    const maxVersion = this._keys.length > 0
      ? Math.max(...this._keys.map((k) => k.version))
      : 0;
    const vk: VersionedKey = {
      version: maxVersion + 1,
      key,
      createdAt: new Date().toISOString(),
      expiresAt,
    };
    this._keys.push(vk);
    // New key becomes active by default
    this._activeVersion = vk.version;
    return vk;
  }

  /** Retire a key (soft-disable for new obfuscation, still usable for deobfuscation). */
  retireKey(version: number): void {
    const k = this._keys.find((k) => k.version === version);
    if (k) k.retired = true;
  }

  /** Remove and return expired keys. */
  pruneExpired(): VersionedKey[] {
    const expired = this._keys.filter((k) => this._isExpired(k));
    this._keys = this._keys.filter((k) => !this._isExpired(k));
    return expired;
  }

  /** Number of keys in the ring. */
  get size(): number {
    return this._keys.length;
  }

  /** Current active version number. */
  get activeVersion(): number {
    return this.activeKey().version;
  }

  /** Serialize for config/export. */
  toJSON(): { keys: VersionedKey[]; activeVersion: number } {
    return {
      keys: this._keys.map((k) => ({ ...k })),
      activeVersion: this.activeKey().version,
    };
  }

  private _isExpired(key: VersionedKey): boolean {
    if (!key.expiresAt) return false;
    return new Date(key.expiresAt).getTime() <= Date.now();
  }
}
