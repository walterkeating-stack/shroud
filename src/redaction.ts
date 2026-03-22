/**
 * Redaction level formatter.
 *
 * Three modes:
 * - full:   fake values (current behavior, default)
 * - masked: partial masking (first 2 + *** + last 2)
 * - stats:  category placeholders like [HOSTNAME-1]
 */

import { Category } from "./types.js";

export type RedactionLevel = "full" | "masked" | "stats";

export class RedactionFormatter {
  private _counters: Map<string, number> = new Map();

  /**
   * Format a replacement value according to the redaction level.
   *
   * @param real     The real sensitive value
   * @param fake     The generated fake value (used in 'full' mode)
   * @param category The entity category
   * @param level    The redaction level
   */
  format(
    real: string,
    fake: string,
    category: Category,
    level: RedactionLevel,
  ): string {
    switch (level) {
      case "full":
        return fake;

      case "masked":
        return this._mask(real, category);

      case "stats":
        return this._placeholder(category);
    }
  }

  /** Reset counters (call between requests if needed). */
  resetCounters(): void {
    this._counters.clear();
  }

  private _mask(value: string, category: Category): string {
    const len = value.length;

    // Short values get fully masked
    if (len <= 4) {
      return "***";
    }

    // Category-aware masking
    switch (category) {
      case Category.EMAIL: {
        const at = value.indexOf("@");
        if (at > 0) {
          return value[0] + "***@***" + value.slice(value.lastIndexOf("."));
        }
        break;
      }
      case Category.PHONE:
        // Show last 4 digits
        return "***" + value.slice(-4);
      case Category.CREDIT_CARD:
        // Show last 4 digits
        return "****-****-****-" + value.slice(-4);
      case Category.SSN:
        return "***-**-" + value.slice(-4);
      case Category.IP_ADDRESS:
        // Mask last two octets
        if (value.includes(".")) {
          const parts = value.split(".");
          return parts[0] + "." + parts[1] + ".*.*";
        }
        break;
    }

    // Default: show first 2 and last 2
    if (len <= 6) {
      return value[0] + "***" + value[len - 1];
    }
    return value.slice(0, 2) + "***" + value.slice(-2);
  }

  private _placeholder(category: Category): string {
    const count = (this._counters.get(category) ?? 0) + 1;
    this._counters.set(category, count);
    return `[${category.toUpperCase()}-${count}]`;
  }
}
