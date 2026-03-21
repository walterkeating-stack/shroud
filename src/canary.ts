/**
 * Canary token injection for detecting LLM data leakage.
 *
 * Injects unique, trackable tokens into obfuscated prompts. These tokens
 * serve no semantic purpose but can be monitored for leakage -- if a canary
 * appears in another user's output or in a training data audit, it proves
 * your data was exposed.
 */

import { createHash } from "node:crypto";

export interface CanaryToken {
  token: string;
  sessionId: string;
  timestamp: number;
  messageIndex: number;
}

export class CanaryInjector {
  private readonly _prefix: string;
  private readonly _secret: string;
  private _sessionId: string;
  private _messageCounter: number;
  private _tokens: CanaryToken[];

  constructor(prefix: string, secretKey: string) {
    this._prefix = prefix;
    this._secret = secretKey;
    this._sessionId = createHash("sha256")
      .update(`${secretKey}:${Date.now()}`)
      .digest("hex")
      .slice(0, 12);
    this._messageCounter = 0;
    this._tokens = [];
  }

  get sessionId(): string {
    return this._sessionId;
  }

  /** Inject a canary token into text. Returns modified text. */
  inject(text: string): string {
    this._messageCounter += 1;
    const ts = Date.now();

    // Generate unique token
    const raw = `${this._sessionId}:${this._messageCounter}:${ts}`;
    const tokenHash = createHash("sha256")
      .update(this._secret + raw)
      .digest("hex")
      .slice(0, 16);
    const token = `${this._prefix}-${tokenHash}`;

    const canary: CanaryToken = {
      token,
      sessionId: this._sessionId,
      timestamp: ts,
      messageIndex: this._messageCounter,
    };
    this._tokens.push(canary);

    // Inject as a non-semantic comment at the end of the text
    return `${text}\n<!-- ${token} -->`;
  }

  /** Return all canary tokens injected in this session. */
  getTokens(): CanaryToken[] {
    return [...this._tokens];
  }

  /** Check if any known canary tokens appear in given text. */
  checkLeak(text: string): CanaryToken[] {
    const leaked: CanaryToken[] = [];
    for (const canary of this._tokens) {
      if (text.includes(canary.token)) {
        leaked.push(canary);
      }
    }
    return leaked;
  }

  /** Reset for a new session. */
  reset(): void {
    this._sessionId = createHash("sha256")
      .update(`${this._secret}:${Date.now()}`)
      .digest("hex")
      .slice(0, 12);
    this._messageCounter = 0;
    this._tokens = [];
  }
}
