# Hot-Reload

> Status: Config keys exist, not implemented

## Concept

Watch config files and custom pattern files for changes, automatically reload detection rules without restarting the agent. Enables ops teams to tune detection rules in production without downtime.

## Config Keys

```json
{
  "hotReload": true,
  "customPatternsFile": "/etc/shroud/patterns.json",
  "hotReloadDebounceMs": 1000
}
```

## Intended Behavior

- Watch `customPatternsFile` and the main config file for changes
- Debounce file change events by `hotReloadDebounceMs`
- On change: re-read file, validate, update detection rules
- Existing mappings preserved — only detection rules change
- Log reload events for audit trail

## Implementation Notes

- The NCG adapter already implements `update_config()` and `reload_from_file()` — this brings it to the core engine
- `fs.watch()` or `fs.watchFile()` for file monitoring
- Consider: validation before applying (reject bad config, keep current)
- Consider: notification mechanism (tool output, log line) confirming reload
