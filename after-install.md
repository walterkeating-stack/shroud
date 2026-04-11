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

**Configuration (optional):**

Set `SHROUD_PLUGIN_CONFIG` in `~/.hermes/.env` with JSON overrides:

```
SHROUD_PLUGIN_CONFIG={"minConfidence": 0.5, "dryRun": false}
```

See https://github.com/wkeything/shroud for all config options.
