/**
 * Tool-call tokenizer — maps tool names to integer IDs.
 *
 * Dynamic vocabulary that grows as new tools are observed.
 * Pre-seeded with common OpenClaw tool names.
 * Max vocabulary: 128 tokens (4 special + 124 tools).
 */

/** Serializable tokenizer state. */
export interface TokenizerConfig {
  vocab: Record<string, number>;
  idToToken: string[];
}

/** Special token IDs. */
export const PAD = 0;
export const UNK = 1;
export const BOS = 2;
export const EOS = 3;
export const SPECIAL_COUNT = 4;

/** Maximum vocabulary size (including special tokens). */
export const MAX_VOCAB = 128;

/** Common tool names to pre-seed the vocabulary. */
const SEED_TOOLS = [
  "read", "read_file", "write", "write_file", "edit",
  "exec", "bash", "code_execution",
  "web_fetch", "fetch", "browser",
  "message", "sessions_send", "sessions_spawn", "sessions_create", "sessions_list",
  "memory_search", "memory_get", "memory_set",
  "glob", "grep", "search",
  "cron_add", "cron_list", "cron_remove",
  "shroud_status", "shroud_reset",
];

export class ToolTokenizer {
  private _vocab: Map<string, number>;
  private _idToToken: string[];

  constructor(config?: TokenizerConfig) {
    if (config) {
      this._vocab = new Map(Object.entries(config.vocab));
      this._idToToken = [...config.idToToken];
    } else {
      this._idToToken = ["[PAD]", "[UNK]", "[BOS]", "[EOS]"];
      this._vocab = new Map<string, number>();
      // Seed with common tools
      for (const tool of SEED_TOOLS) {
        this.addTool(tool);
      }
    }
  }

  /** Encode a single tool name to its token ID. */
  encode(toolName: string): number {
    const normalized = toolName.toLowerCase().trim();
    return this._vocab.get(normalized) ?? UNK;
  }

  /** Encode a sequence of tool names. Prepends BOS. */
  encodeSequence(tools: string[]): number[] {
    const ids = [BOS];
    for (const t of tools) {
      ids.push(this.encode(t));
    }
    return ids;
  }

  /** Decode a token ID back to tool name. */
  decode(id: number): string {
    return this._idToToken[id] ?? "[UNK]";
  }

  /** Current vocabulary size. */
  vocabSize(): number {
    return this._idToToken.length;
  }

  /** Add a new tool to the vocabulary. Returns its ID. */
  addTool(toolName: string): number {
    const normalized = toolName.toLowerCase().trim();
    const existing = this._vocab.get(normalized);
    if (existing !== undefined) return existing;

    if (this._idToToken.length >= MAX_VOCAB) return UNK;

    const id = this._idToToken.length;
    this._idToToken.push(normalized);
    this._vocab.set(normalized, id);
    return id;
  }

  /** Check if a tool is in the vocabulary. */
  hasTool(toolName: string): boolean {
    return this._vocab.has(toolName.toLowerCase().trim());
  }

  /** Serialize to JSON-compatible config. */
  toJSON(): TokenizerConfig {
    const vocab: Record<string, number> = {};
    for (const [k, v] of this._vocab) vocab[k] = v;
    return { vocab, idToToken: [...this._idToToken] };
  }

  /** Deserialize from config. */
  static fromJSON(config: TokenizerConfig): ToolTokenizer {
    return new ToolTokenizer(config);
  }
}
