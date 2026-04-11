## Shroud installed

Privacy obfuscation is now active. All LLM traffic will be scanned for
sensitive data (emails, IPs, credentials, SSNs, hostnames, etc.) and
replaced with deterministic fakes before leaving the process.

**Requirements:** Node.js 18+ on PATH (for the obfuscation engine).

The plugin auto-builds on first session start. No manual setup needed.

**Restart Hermes to activate:**

```
hermes
```

**Verify it's working:**

Check `~/.hermes/shroud-stats.json` after a conversation — `obfuscationEvents`
should be > 0.

**Config-as-code (optional):**

Edit `~/.shroud/shroud.config.json` to customize detection rules, field
scoping, and confidence thresholds. Changes hot-reload within 2 seconds —
no restart needed. The file is JSONC (comments allowed).

The config file is shared with OpenClaw — edits apply to both platforms.
If the file doesn't exist, Shroud uses built-in defaults.

See https://github.com/wkeything/shroud for all config options.
