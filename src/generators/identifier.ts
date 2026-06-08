/**
 * Format-preserving generator for structured infrastructure identifiers:
 * device hostnames, interface descriptions, and custom inventory fields.
 *
 * The default mapping for these categories was an opaque `[REDACTED-...]`
 * token, which destroys the structure a network-automation agent needs: it can
 * no longer suffix-match (`..._new`), group by an embedded site code, or dedup.
 * That blinds the agent even when a server-side filter returned exactly the
 * right objects (observed on the NCG agent, 2026-06-08: it rejected a correct
 * 101-device `name__iew=_new` result as "filter ignored" because the obfuscated
 * names no longer ended in `_new`).
 *
 * This generator instead preserves the SHAPE of the original:
 *   - character classes are preserved (letter -> letter, digit -> digit),
 *   - lengths are preserved,
 *   - separators / punctuation (`_ - . + / : @` etc.) are kept verbatim,
 *   - each sub-token maps CONSISTENTLY: the same real token always yields the
 *     same fake token, so every `..._new` shares one fake suffix and the agent
 *     can still group / dedup / suffix-match on the obfuscated values.
 *
 * The real identity is still hidden (fake characters are pseudo-random) and
 * reversal is handled by the mapping store (real<->fake pairs), exactly as for
 * every other category. Token-level determinism is intentional: it is what
 * keeps obfuscated values usable for structural reasoning. It implies identical
 * tokens are linkable across values, which is the desired property for
 * infrastructure identifiers (and is strictly less revealing than the real
 * name).
 */

import { Category } from "../types.js";
import type { BaseGenerator } from "./base.js";

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT = "0123456789";

// Fixed pepper so fakes are not a trivial identity transform. NOT a secret —
// the mapping store holds the real secret; this only de-correlates the fake
// character stream from the input while staying fully deterministic.
const PEPPER = "shroud-fpe-v1";

/** FNV-1a 32-bit hash. Deterministic across runs and platforms. */
function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** xorshift32 PRNG seeded deterministically. */
function makeRng(seed: number): () => number {
  let x = (seed >>> 0) || 0x9e3779b9;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5;
    x >>>= 0;
    return x >>> 0;
  };
}

/**
 * Map one same-class token to a deterministic, same-length fake of that class.
 * Seeded by the token itself so identical tokens always produce identical
 * fakes (consistency), independent of the surrounding value.
 */
function mapToken(token: string, alphabet: string, category: string): string {
  const rng = makeRng(fnv1a(`${category}:${PEPPER}:${token}`));
  let out = "";
  for (let i = 0; i < token.length; i++) {
    out += alphabet[rng() % alphabet.length];
  }
  return out;
}

function classOf(ch: string): string | null {
  if (ch >= "a" && ch <= "z") return LOWER;
  if (ch >= "A" && ch <= "Z") return UPPER;
  if (ch >= "0" && ch <= "9") return DIGIT;
  return null;
}

export class IdentifierGenerator implements BaseGenerator {
  readonly categories = [
    Category.HOSTNAME,
    Category.INTERFACE_DESC,
    Category.CUSTOM,
    // Site / region / location / rack names (the netbox detector's LOCATION
    // category). In this dataset these are structured codes — `++ATVIE+F`,
    // `++LOWG+TWR`, racks like `++ATVIE+F.02-262-030` — encoding ICAO/airport
    // codes + building/floor/rack hierarchy the agent reasons on. Semantic
    // place-name fakes ("Cedar Falls") destroy that structure. Format-preserving
    // keeps it (and round-trips). NOTE: this also covers physical_address /
    // address values; format-preserving an address keeps its shape and is a
    // better fit than substituting a fake place name, so there is no separate
    // address carve-out.
    Category.LOCATION,
  ];

  generate(category: Category, seed: number, original = ""): string {
    if (!original) {
      return `id-${String(seed % 10000).padStart(4, "0")}`;
    }
    let out = "";
    let i = 0;
    const n = original.length;
    while (i < n) {
      const cls = classOf(original[i]);
      if (cls === null) {
        // separator / punctuation: preserve verbatim (structure stays visible)
        out += original[i];
        i++;
        continue;
      }
      // consume the maximal run of this character class
      let j = i + 1;
      while (j < n && classOf(original[j]) === cls) j++;
      out += mapToken(original.slice(i, j), cls, category);
      i = j;
    }
    return out;
  }
}
