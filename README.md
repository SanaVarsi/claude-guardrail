# claude-guardrail

A Claude Code plugin that blocks likely secrets — API keys, passwords, private keys, tokens — before they reach a prompt or a Bash/Write/Edit tool call.

## What it does

Claude Code can type messages, run commands, and write/edit files on your behalf. If a real secret ever ends up in any of that, it could get exposed — saved into a file, pushed to a public repo, logged somewhere. This plugin checks the relevant text right before it happens and blocks it if something looks like a real secret, explaining why.

## How it works

Two hooks fire on every message and every Bash/Write/Edit tool call:

1. **`UserPromptSubmit`** — checks every message you type, before it's processed
2. **`PreToolUse`** (matched to `Bash|Write|Edit`) — checks the command/file content before it runs

The text is checked against known secret formats (cloud provider keys, common API tokens, private key files, password-style assignments), plus a randomness check that catches secrets in no known format. A configurable allowlist prevents known-safe values from triggering false alarms.

If anything looks like a real secret, the action is blocked with a reason. If nothing does, it happens normally — the plugin stays silent.

## Install

For local testing, point Claude Code at this folder directly:

```bash
claude --plugin-dir /path/to/claude-guardrail
```

Not yet published to a plugin marketplace.

## Try it yourself

```bash
echo '{"hook_event_name":"UserPromptSubmit","user_input":"here is my key AKIAABCDEFGHIJKLMNOP"}' | python3 hooks/scan-secrets.py
```

Should print a blocked response. A normal message should print nothing:

```bash
echo '{"hook_event_name":"UserPromptSubmit","user_input":"hey can you help me write a function"}' | python3 hooks/scan-secrets.py
```

Run the full automated test suite:

```bash
python3 -m pytest tests/ -v
```

## Project structure

```
claude-guardrail/
├── .claude-plugin/
│   └── plugin.json        # plugin manifest
├── hooks/
│   ├── hooks.json         # registers the two hook events
│   └── scan-secrets.py    # the detection logic
├── config/
│   └── allowlist.json     # known-safe patterns
└── tests/
    └── test_scan_secrets.py
```

## Limitations

- Requires `python3` on the machine running it
- Only checks typed messages and Bash/Write/Edit tool input — doesn't scan file contents already on disk, or output from other tools (Read, WebFetch, subagents)
- Coverage isn't exhaustive — a new or unusual secret format could slip through
- The randomness check is a heuristic, not a guarantee — can occasionally miss real secrets or (rarely) flag harmless random-looking text
- Matching mostly works line-by-line — a secret split across multiple lines may not be caught
- An overly broad allowlist entry could accidentally suppress real detections

## License

MIT
