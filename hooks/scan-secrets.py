#!/usr/bin/env python3
"""
claude-guardrail: secret-leak blocker.

Reads the hook data Claude Code sends on stdin, checks the relevant
text for patterns that look like secrets (API keys, passwords, private
keys), and blocks the action if something matches.
"""

import json
import math
import os
import re
import sys
from collections import Counter

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

CANDIDATE_CHUNK = re.compile(r"[A-Za-z0-9+/_-]{20,}")
HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
UUID_SHAPE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
ENTROPY_THRESHOLD = 4.3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWLIST_PATH = os.path.join(SCRIPT_DIR, "..", "config", "allowlist.json")


def load_allowlist():
    """Read config/allowlist.json. If it's missing or broken, use no patterns."""
    try:
        with open(ALLOWLIST_PATH) as f:
            data = json.load(f)
        return [re.compile(p, re.IGNORECASE) for p in data.get("patterns", [])]
    except (FileNotFoundError, json.JSONDecodeError):
        return []


ALLOWLIST_PATTERNS = load_allowlist()


def is_allowlisted(value: str) -> bool:
    """Is this value on the known-safe list?"""
    return any(p.search(value) for p in ALLOWLIST_PATTERNS)


def mask(value: str) -> str:
    """Hide most of a matched secret so we never print the real value."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def shannon_entropy(text: str) -> float:
    """How random a chunk of text looks. Higher = more random/scrambled."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def text_to_scan(payload: dict) -> str:
    """Pick out the right text depending on which hook fired."""
    if payload.get("hook_event_name") == "UserPromptSubmit":
        return payload.get("user_input") or payload.get("prompt") or ""
    return json.dumps(payload.get("tool_input") or "")


def find_named_secrets(text: str):
    """Check text against every known secret shape, return what matched."""
    findings = []
    matched_values = set()
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group()
            matched_values.add(value)
            if is_allowlisted(value):
                continue
            findings.append(f"{label}: {mask(value)}")
    return findings, matched_values


def find_high_entropy_strings(text: str, already_matched: set) -> list:
    """Catch random-looking text that didn't match any known shape."""
    findings = []
    for chunk in CANDIDATE_CHUNK.findall(text):
        if chunk in already_matched:
            continue
        if HEX_ONLY.match(chunk):
            continue
        if UUID_SHAPE.search(chunk):
            continue
        if is_allowlisted(chunk):
            continue
        if shannon_entropy(chunk) >= ENTROPY_THRESHOLD:
            findings.append(f"High-entropy string (possible secret): {mask(chunk)}")
    return findings


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return

    event = payload.get("hook_event_name", "PreToolUse")
    text = text_to_scan(payload)

    named_findings, matched_values = find_named_secrets(text)
    entropy_findings = find_high_entropy_strings(text, matched_values)
    findings = named_findings + entropy_findings

    if not findings:
        return

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
