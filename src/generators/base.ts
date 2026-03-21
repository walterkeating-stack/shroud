/** Base generator interface. */

import { Category } from "../types.js";

export interface BaseGenerator {
  readonly categories: Category[];
  generate(category: Category, seed: number, original?: string): string;
}
