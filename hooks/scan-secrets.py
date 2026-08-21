#!/usr/bin/env python3
"""
claude-guardrail: secret-leak blocker.

Reads the hook data Claude Code sends on stdin, checks the relevant
text for patterns that look like secrets (API keys, passwords, private
keys), and blocks the action if something matches.
"""

import json
import re
import sys

# Each entry: (label shown when blocked, pattern to search for)
PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Temp/Session Key", re.compile(r"ASIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Stripe Live Key", re.compile(r"(sk|rk)_live_[0-9a-zA-Z]{24,}")),
    ("OpenAI/Anthropic API Key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("Private Key Block", re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Password/Secret Assignment", re.compile(
        r"(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|token|auth)"
        r"\s*[:=]\s*[^\s'\"]{6,}",
        re.IGNORECASE,
    )),
]


def mask(value: str) -> str:
    """Hide most of a matched secret so we never print the real value."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def text_to_scan(payload: dict) -> str:
    """Pick out the right text depending on which hook fired."""
    if payload.get("hook_event_name") == "UserPromptSubmit":
        return payload.get("user_input") or payload.get("prompt") or ""
    return json.dumps(payload.get("tool_input") or "")


def find_secrets(text: str) -> list:
    """Check text against every known secret shape, return what matched."""
    findings = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            findings.append(f"{label}: {mask(match.group())}")
    return findings


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return  # nothing readable, let it through

    event = payload.get("hook_event_name", "PreToolUse")
    text = text_to_scan(payload)
    findings = find_secrets(text)

    if not findings:
        return  # nothing suspicious, say nothing, let it through

    reason = (
        "claude-guardrail blocked this: possible secret(s) detected:\n"
        + "\n".join(findings)
        + "\n\nIf this is a false positive, add a safe pattern to config/allowlist.json."
    )
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason,
    }))


if __name__ == "__main__":
    main()
