/** User-defined custom pattern detector. */

import { Category, DetectedEntity } from "../types.js";
import { BaseDetector } from "./base.js";

export interface CustomPatternDef {
  name: string;
  pattern: string;
  category?: string;
}

/** Detector that uses user-defined regex patterns from config. */
export class CustomPatternDetector implements BaseDetector {
  readonly name = "patterns";
  private _patterns: Array<{ name: string; regex: RegExp; category: Category }>;

  constructor(patterns: CustomPatternDef[]) {
    this._patterns = patterns.map((p) => {
      let cat: Category;
      const catStr = p.category ?? "custom";
      if (Object.values(Category).includes(catStr as Category)) {
        cat = catStr as Category;
      } else {
        cat = Category.CUSTOM;
      }
      return {
        name: p.name,
        regex: new RegExp(p.pattern, "g"),
        category: cat,
      };
    });
  }

  detect(text: string): DetectedEntity[] {
    const entities: DetectedEntity[] = [];
    // Sorted non-overlapping intervals for O(log n) overlap checks
    const spans: Array<[number, number]> = [];

    for (const { name, regex, category } of this._patterns) {
      regex.lastIndex = 0;
      for (const match of text.matchAll(regex)) {
        const start = match.index!;
        const end = start + match[0].length;

        // Binary search overlap check
        if (_spansOverlap(spans, start, end)) {
          continue;
        }

        // Insert sorted
        let lo = 0, hi = spans.length;
        while (lo < hi) {
          const mid = (lo + hi) >>> 1;
          if (spans[mid][0] < start) lo = mid + 1;
          else hi = mid;
        }
        spans.splice(lo, 0, [start, end]);

        entities.push({
          value: match[0],
          start,
          end,
          category,
          confidence: 0.9,
          detector: `custom:${name}`,
        });
      }
    }

    entities.sort((a, b) => a.start - b.start);
    return entities;
  }
}

/** Binary-search overlap check matching original semantics. */
function _spansOverlap(spans: Array<[number, number]>, start: number, end: number): boolean {
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
