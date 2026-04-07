# Security Policy

## Scope

Shroud is a privacy obfuscation plugin. Its security properties are central to its purpose.

## What Shroud guarantees

- **No raw values in logs.** Audit logs never contain original sensitive text, real entity values, or real→fake mapping pairs. Only counts, categories, truncated salted hashes, and fake replacement values are logged.
- **Deterministic but irreversible fakes.** Fake values are generated via HMAC-SHA256 seeded mapping. Without the secret key, you cannot derive the original value from the fake.
- **Best-effort logging.** If audit logging throws, obfuscation still proceeds. Logging failures never break the privacy pipeline.

## What Shroud does NOT guarantee

- **Complete PII detection.** Regex-based detection will miss novel formats, obfuscated PII, or context-dependent sensitive data. Shroud reduces exposure — it does not eliminate it.
- **LLM behavior.** Shroud cannot prevent an LLM from hallucinating values that resemble real data, or from ignoring the privacy context.
- **URL transparency to the LLM.** The LLM sees obfuscated (fake) URLs in its conversation context. Tool calls are deobfuscated automatically before execution, but the LLM cannot reason about URL content (domain, path, site identity) for obfuscated internal URLs. Public URLs are passed through via DNS-based classification, but DNS cache misses default to obfuscate. Add agent prompt guidance (see README) to prevent the LLM from questioning obfuscated URLs.
- **Secret key security.** If `secretKey` is leaked, an attacker can reproduce the mapping. Protect it like any HMAC secret.

## Reporting vulnerabilities

If you discover a security issue such as raw values leaking into logs, bypass of obfuscation, or mapping reversal without the key, report it privately through GitHub Security Advisories:

- Open a [GitHub Security Advisory](https://github.com/wkeything/shroud/security/advisories/new)

Include:

- affected Shroud version
- how to reproduce the issue
- whether the issue leaks real values to logs, prompts, tool calls, or responses

Please do **not** open a public issue for security vulnerabilities.

## Configuration hardening

For production use:

1. **Set a strong `secretKey`** (32+ random bytes hex). Do not rely on auto-generation if you need cross-session consistency.
2. **Prefer environment variables for key material.** `SHROUD_SECRET_KEY` and `SHROUD_PERSISTENT_SALT` override config-file values.
3. **Set `persistentSalt`** if you need the same fake values across restarts.
4. **Enable `auditEnabled`** to verify Shroud is active. `verboseLogging` is an alias, but `auditEnabled` is clearer.
5. **Rotate the key if exposure is suspected.** If `secretKey` may have leaked, replace it and treat old mappings as compromised.
6. **Leave `auditMaxFakesSample: 0`** unless you need to verify fake quality. Fake samples are synthetic, but minimizing log surface is still preferable.
