"""
Automated tests for hooks/scan-secrets.py.

Each test fakes a hook payload (the same JSON Claude Code would send),
runs it through the script, and checks whether it got blocked or not.
"""

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "hooks" / "scan-secrets.py"


def run_scanner(user_input=None, tool_input=None, event="UserPromptSubmit"):
    """Send a fake payload to the script, return its raw output."""
    payload = {"hook_event_name": event}
    if user_input is not None:
        payload["user_input"] = user_input
    if tool_input is not None:
        payload["tool_input"] = tool_input

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def was_blocked(output):
    return '"permissionDecision": "deny"' in output


# --- secrets that SHOULD get blocked ---

def test_aws_key_blocked():
    output = run_scanner(user_input="key is AKIAABCDEFGHIJKLMNOP")
    assert was_blocked(output)


def test_github_token_blocked():
    output = run_scanner(user_input="token: ghp_" + "a" * 36)
    assert was_blocked(output)


def test_private_key_blocked():
    output = run_scanner(user_input="-----BEGIN RSA PRIVATE KEY-----\nMIIExyz")
    assert was_blocked(output)


def test_password_assignment_blocked():
    output = run_scanner(user_input="password=SuperSecret123!")
    assert was_blocked(output)


def test_random_looking_secret_blocked():
    output = run_scanner(user_input="db pass is xQ2mK9pR7zL4wN8vB3cT6y")
    assert was_blocked(output)


def test_secret_in_bash_command_blocked():
    output = run_scanner(
        event="PreToolUse",
        tool_input={"command": "curl -H 'Authorization: Bearer AKIAABCDEFGHIJKLMNOP'"},
    )
    assert was_blocked(output)


# --- harmless things that should NOT get blocked ---

def test_normal_sentence_passes():
    output = run_scanner(user_input="hey can you help me write a function")
    assert output == ""


def test_uuid_passes():
    output = run_scanner(user_input="record id is 550e8400-e29b-41d4-a716-446655440000")
    assert output == ""


def test_hash_passes():
    output = run_scanner(user_input="commit abc123def456abc123def456abc123def456ab")
    assert output == ""


def test_allowlisted_example_key_passes():
    output = run_scanner(user_input="example: AKIAIOSFODNN7EXAMPLE")
    assert output == ""
