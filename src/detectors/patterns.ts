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
    const seenSpans: Array<[number, number]> = [];

    for (const { name, regex, category } of this._patterns) {
      regex.lastIndex = 0;
      for (const match of text.matchAll(regex)) {
        const start = match.index!;
        const end = start + match[0].length;
        const span: [number, number] = [start, end];

        // Check for overlap with existing spans
        let overlaps = false;
        for (const [s, e] of seenSpans) {
          if ((s <= span[0] && span[0] < e) || (s < span[1] && span[1] <= e)) {
            overlaps = true;
            break;
          }
        }
        if (overlaps) {
          continue;
        }

        seenSpans.push(span);
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
