/**
 * Vitest global teardown — clean up temp dirs left by tests.
 *
 * Some tests create mkdtemp dirs in /tmp/shroud-* and don't always
 * clean up on failure. This sweeps them after the entire suite finishes.
 */

import { readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PREFIXES = [
  "shroud-load-test-",
  "shroud-mem-test-",
  "shroud-pretrain-test",
  "shroud-profiler-test-",
  "shroud-profiler-training-",
  "shroud-profile-test-",
  "shroud-rule-sort-",
  "shroud-rule-sug-",
  "shroud-vs-",
];

export function teardown() {
  const tmp = tmpdir();
  try {
    for (const entry of readdirSync(tmp)) {
      if (PREFIXES.some(p => entry.startsWith(p))) {
        try { rmSync(join(tmp, entry), { recursive: true, force: true }); } catch {}
      }
    }
  } catch {}
}
