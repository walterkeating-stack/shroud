/**
 * Code-aware detector that finds sensitive data inside string literals and comments.
 *
 * Scans source code for string literals and comments across common languages,
 * then runs the standard regex detector on the extracted text to find PII
 * that would otherwise be missed by scanning raw code.
 */

import { DetectedEntity } from "../types.js";
import { BaseDetector } from "./base.js";
import { RegexDetector } from "./regex.js";

interface CodeSpan {
  text: string;
  start: number;
  end: number;
  kind: "string" | "comment";
}

/** Language-agnostic patterns for extracting strings and comments. */
const SPAN_PATTERNS: RegExp[] = [
  // Triple-quoted strings (Python, etc.)
  /"""[\s\S]*?"""/g,
  /'''[\s\S]*?'''/g,
  // Double-quoted strings
  /"(?:[^"\\]|\\.)*"/g,
  // Single-quoted strings
  /'(?:[^'\\]|\\.)*'/g,
  // Backtick strings (JS/Go/etc.)
  /`(?:[^`\\]|\\.)*`/g,
  // Line comments (C-style, Python, Ruby, Shell)
  /\/\/[^\n]*/g,
  /#[^\n]*/g,
  // Block comments
  /\/\*[\s\S]*?\*\//g,
];

/** Patterns that are purely code constructs with no data (skip these). */
const CODE_NOISE = new RegExp(
  "^[\\s\"'`#/\\*]*" +
  "(?:import |from |require\\(|use |include |" +
  "package |module |class |def |func |fn |" +
  "return |const |let |var |type |interface )" +
  "[^@]*$",
);

const CODE_INDICATORS = [
  "def ", "class ", "function ", "import ", "from ", "require(",
  "const ", "let ", "var ", "func ", "fn ", "pub ", "private ",
  "return ", "if (", "for (", "while (", "package ", "module ",
  "#!/", "# -*- coding", "use strict", "pragma ",
  "SELECT ", "INSERT ", "CREATE TABLE",
];

/** Heuristic: does this text look like source code? */
function looksLikeCode(text: string): boolean {
  const lines = text.split("\n");
  if (lines.length < 3) {
    return false;
  }
  let score = 0;
  for (const indicator of CODE_INDICATORS) {
    if (text.includes(indicator)) {
      score++;
    }
  }
  // Also check for common syntax patterns
  if (/[{};]\s*$/m.test(text)) {
    score++;
  }
  if (/^\s*(def|class|func|fn)\s+\w+/m.test(text)) {
    score++;
  }
  return score >= 2;
}

/**
 * Detects sensitive data embedded in source code strings and comments.
 *
 * Extracts string literals and comments from code, then runs PII detection
 * on the extracted text. Entity positions are mapped back to the original
 * source positions.
 */
export class CodeDetector implements BaseDetector {
  readonly name = "code";
  private _inner: RegexDetector;

  constructor(inner?: RegexDetector) {
    this._inner = inner ?? new RegexDetector();
  }

  detect(text: string): DetectedEntity[] {
    // Only run if the text looks like code
    if (!looksLikeCode(text)) {
      return [];
    }

    const spans = this._extractSpans(text);
    const entities: DetectedEntity[] = [];
    const seenSpans = new Set<string>();

    for (const span of spans) {
      const innerText = span.text;
      const innerOffset = span.start;

      // Skip spans that look like pure code constructs
      if (CODE_NOISE.test(innerText)) {
        continue;
      }

      // Run PII detection on the inner text
      const innerEntities = this._inner.detect(innerText);
      for (const entity of innerEntities) {
        // Map positions back to original text
        const absStart = innerOffset + entity.start;
        const absEnd = innerOffset + entity.end;
        const spanKey = `${absStart}:${absEnd}`;
        if (seenSpans.has(spanKey)) {
          continue;
        }
        seenSpans.add(spanKey);
        entities.push({
          value: entity.value,
          start: absStart,
          end: absEnd,
          category: entity.category,
          confidence: entity.confidence * 0.9, // Slightly lower since it's inside code
          detector: `code:${entity.detector}`,
        });
      }
    }

    entities.sort((a, b) => a.start - b.start);
    return entities;
  }

  /** Extract string literals and comments from code. */
  private _extractSpans(text: string): CodeSpan[] {
    const spans: CodeSpan[] = [];
    // Sorted non-overlapping intervals for O(log n) overlap checks
    const covered: Array<[number, number]> = [];

    for (const pattern of SPAN_PATTERNS) {
      pattern.lastIndex = 0;
      for (const match of text.matchAll(pattern)) {
        const start = match.index!;
        const end = start + match[0].length;

        // Binary search overlap check
        if (this._coveredOverlaps(covered, start, end)) {
          continue;
        }

        // Insert sorted
        let lo = 0, hi = covered.length;
        while (lo < hi) {
          const mid = (lo + hi) >>> 1;
          if (covered[mid][0] < start) lo = mid + 1;
          else hi = mid;
        }
        covered.splice(lo, 0, [start, end]);

        const kind = match[0].startsWith("/") || match[0].startsWith("#")
          ? "comment" as const
          : "string" as const;
        spans.push({ text: match[0], start, end, kind });
      }
    }

    spans.sort((a, b) => a.start - b.start);
    return spans;
  }

  private _coveredOverlaps(spans: Array<[number, number]>, start: number, end: number): boolean {
    const len = spans.length;
    if (len === 0) return false;
    let lo = 0, hi = len - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (spans[mid][0] <= start) lo = mid + 1;
      else hi = mid - 1;
    }
    if (hi >= 0 && start < spans[hi][1]) return true;
    for (let i = lo; i < len && spans[i][0] < end; i++) {
      if (end <= spans[i][1]) return true;
    }
    return false;
  }
}
