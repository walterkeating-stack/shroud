/**
 * APP Client — spawns the Shroud app-server and communicates via JSON-RPC
 * over newline-delimited JSON on stdin/stdout of the subprocess.
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import path from "node:path";

class APPClientError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "APPClientError";
    this.code = code;
  }
}

export class APPClient {
  #proc = null;
  #rl = null;
  #pending = new Map();
  #nextId = 1;
  #ready = false;
  #serverInfo = null;

  /**
   * Spawn the APP server and wait for the handshake.
   *
   * @param {...string|string[]} cmd — command and args to spawn the server.
   *   If no arguments given, resolves the server path automatically.
   * @returns {Promise<APPClient>}
   */
  static async spawn(...cmd) {
    if (cmd.length === 0) {
      const serverPath = APPClient.resolveServerPath();
      cmd = ["node", serverPath];
    }

    const client = new APPClient();
    await client.#start(cmd);
    return client;
  }

  /**
   * Resolve the app-server.mjs path from env or conventional locations.
   */
  static resolveServerPath() {
    if (process.env.APP_SERVER_PATH) return process.env.APP_SERVER_PATH;

    const dist = process.env.SHROUD_DIST || path.resolve("../shroud");
    return path.join(dist, "app-server.mjs");
  }

  async #start(cmd) {
    const [command, ...args] = cmd.flat();
    this.#proc = spawn(command, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env },
    });

    this.#proc.on("error", (err) => {
      // Reject all pending requests
      for (const [, { reject }] of this.#pending) {
        reject(new APPClientError(`Process error: ${err.message}`));
      }
      this.#pending.clear();
    });

    this.#proc.on("exit", (code) => {
      for (const [, { reject }] of this.#pending) {
        reject(new APPClientError(`Process exited with code ${code}`));
      }
      this.#pending.clear();
    });

    // Collect stderr for debugging
    let stderrBuf = "";
    this.#proc.stderr.on("data", (chunk) => {
      stderrBuf += chunk.toString();
    });

    this.#rl = createInterface({ input: this.#proc.stdout });
    this.#rl.on("line", (line) => this.#handleLine(line));

    // Wait for the handshake message
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new APPClientError("Timeout waiting for APP handshake (5s)"));
      }, 5000);

      const checkLine = (line) => {
        try {
          const msg = JSON.parse(line);
          // APP handshake: { app: "1.0", engine: "...", version: "...", capabilities: [...] }
          if (msg.app && msg.engine) {
            this.#serverInfo = msg;
            this.#ready = true;
            clearTimeout(timeout);
            this.#rl.removeListener("line", checkLine);
            // Re-attach normal handler
            this.#rl.on("line", (l) => this.#handleLine(l));
            resolve();
          }
        } catch {
          // Not JSON or not the handshake — ignore during startup
        }
      };

      // Remove the default handler temporarily
      this.#rl.removeAllListeners("line");
      this.#rl.on("line", checkLine);
    });
  }

  #handleLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return; // Ignore non-JSON lines
    }

    if (msg.id != null && this.#pending.has(msg.id)) {
      const { resolve, reject } = this.#pending.get(msg.id);
      this.#pending.delete(msg.id);
      if (msg.error) {
        reject(new APPClientError(msg.error.message, msg.error.code));
      } else {
        resolve(msg.result);
      }
    }
  }

  #send(method, params) {
    return new Promise((resolve, reject) => {
      if (!this.#proc || this.#proc.killed) {
        reject(new APPClientError("APP server not running"));
        return;
      }

      const id = this.#nextId++;
      const msg = { jsonrpc: "2.0", id, method, params };
      this.#pending.set(id, { resolve, reject });

      const timeout = setTimeout(() => {
        if (this.#pending.has(id)) {
          this.#pending.delete(id);
          reject(new APPClientError(`Timeout waiting for ${method} response (10s)`));
        }
      }, 10000);

      // Wrap original resolve/reject to clear timeout
      const origResolve = resolve;
      const origReject = reject;
      this.#pending.set(id, {
        resolve: (val) => { clearTimeout(timeout); origResolve(val); },
        reject: (err) => { clearTimeout(timeout); origReject(err); },
      });

      this.#proc.stdin.write(JSON.stringify(msg) + "\n");
    });
  }

  /**
   * Obfuscate text — replace real PII with fake surrogates.
   * @param {string} text
   * @param {object} [context]
   * @returns {Promise<{text: string, entityCount: number, categories: object, modified: boolean}>}
   */
  async obfuscate(text, context) {
    return this.#send("obfuscate", { text, ...(context ? { context } : {}) });
  }

  /**
   * Deobfuscate text — restore real values from fake surrogates.
   * @param {string} text
   * @param {object} [context]
   * @returns {Promise<{text: string, replacementCount: number, modified: boolean}>}
   */
  async deobfuscate(text, context) {
    return this.#send("deobfuscate", { text, ...(context ? { context } : {}) });
  }

  /** Clear all entity mappings. */
  async reset() {
    return this.#send("reset", {});
  }

  /** Get engine statistics. */
  async stats() {
    return this.#send("stats", {});
  }

  /** Liveness check. */
  async health() {
    return this.#send("health", {});
  }

  /** Graceful shutdown. */
  async shutdown() {
    try {
      await this.#send("shutdown", {});
    } catch {
      // Server may close before responding — that's fine
    }
    if (this.#proc && !this.#proc.killed) {
      this.#proc.kill("SIGTERM");
    }
    this.#rl?.close();
  }

  /** Whether the server is ready. */
  get ready() {
    return this.#ready;
  }

  /** Server info from handshake. */
  get serverInfo() {
    return this.#serverInfo;
  }
}
