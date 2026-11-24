"""no-detached-launch: run as a process with real hook payloads."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).parent / "no-detached-launch.py"


def decide(tool, tool_input):
    payload = json.dumps({"tool_name": tool, "tool_input": tool_input}).encode()
    r = subprocess.run([sys.executable, "-B", str(HOOK)], input=payload, capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr
    out = r.stdout.decode().strip()
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else "allow"


INCIDENT = ("    p = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,\n"
            "                         creationflags=NO_WINDOW | 0x00000200 | 0x00000008)  # no window, new group, detached\n")

DENY = {
    "incident-write": ("Write", {"file_path": "drive.py", "content": INCIDENT}),
    "named-constant": ("Write", {"file_path": "x.py", "content": "subprocess.Popen(c, creationflags=subprocess.DETACHED_PROCESS)\n"}),
    "named-or": ("Edit", {"file_path": "x.py", "old_string": "a", "new_string": "flags = CREATE_NO_WINDOW | DETACHED_PROCESS\n"}),
    "short-hex": ("Edit", {"file_path": "x.py", "old_string": "a", "new_string": "Popen(c, creationflags=0x8)"}),
    "decimal": ("Write", {"file_path": "x.py", "content": "Popen(c, creationflags=8)"}),
    "combined-literal": ("Write", {"file_path": "x.py", "content": "Popen(c, creationflags=0x08000208)"}),
    "multiedit": ("MultiEdit", {"file_path": "x.py", "edits": [{"old_string": "a", "new_string": "ok = 1"},
                                                           {"old_string": "b", "new_string": "Popen(c, creationflags=0x00000008)"}]}),
    "bash-inline": ("Bash", {"command": "python -c \"import subprocess;subprocess.Popen(['x'],creationflags=0x00000008)\""}),
    "powershell-inline": ("PowerShell", {"command": "python -c \"import subprocess as s; s.Popen(['x'], creationflags=s.DETACHED_PROCESS)\""}),
    "notebook": ("NotebookEdit", {"notebook_path": "n.ipynb", "new_source": "Popen(c, creationflags=DETACHED_PROCESS)"}),
    "named-or-spaced": ("Write", {"file_path": "x.py", "content": "base = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP\n"}),
    "same-name-elsewhere": ("Write", {"file_path": "C:/x/other/test_no_detached_launch.py", "content": INCIDENT}),
}

ALLOW = {
    "prose-mention": ("Write", {"file_path": "x.py", "content": '"""Windows: a hidden console, never DETACHED_PROCESS."""\n'}),
    "token-compare": ("Write", {"file_path": "x.py", "content": 'if tok.string == "DETACHED_PROCESS":\n    bad = True\n'}),
    "grep-search": ("Bash", {"command": r'grep -rn "0x00000008\|DETACHED_PROCESS" tools --include=*.py'}),
    "markdown-note": ("Write", {"file_path": "notes.md", "content": INCIDENT}),
    "own-test-file": ("Write", {"file_path": "C:/x/no_detached_launch/test_no_detached_launch.py", "content": INCIDENT}),
    "hidden-only": ("Write", {"file_path": "x.py", "content": "Popen(c, creationflags=0x08000000)\n"}),
    "hidden-group": ("Write", {"file_path": "x.py", "content": "Popen(c, creationflags=NO_WINDOW | 0x00000200)\n"}),
    "the-fix-comment": ("Write", {"file_path": "x.py", "content":
                        "    creationflags=NO_WINDOW | 0x00000200)  # hidden console, new group. NEVER detached (0x8):\n"}),
    "comment-holds-old-flags": ("Write", {"file_path": "x.py", "content":
                                "x = Popen(c, creationflags=NO_WINDOW)  # was creationflags=NO_WINDOW | 0x00000008\n"}),
    "comment-names-it":("Write", {"file_path": "x.py", "content": "# never use DETACHED_PROCESS here\nx = 1\n"}),
    "unrelated-0x8": ("Write", {"file_path": "x.py", "content": "caps = 0x1000 | 0x400000 | 0x8\n"}),
    "plain-bash": ("Bash", {"command": "git status"}),
    "read-tool": ("Read", {"file_path": "x.py"}),
    "named-no-window": ("Write", {"file_path": "x.py", "content": "Popen(c, creationflags=subprocess.CREATE_NO_WINDOW)\n"}),
}


@pytest.mark.parametrize("name", sorted(DENY))
def test_denies_detached(name):
    assert decide(*DENY[name]) == "deny", name


@pytest.mark.parametrize("name", sorted(ALLOW))
def test_allows_the_rest(name):
    assert decide(*ALLOW[name]) == "allow", name


def test_garbage_fails_open():
    r = subprocess.run([sys.executable, "-B", str(HOOK)], input=b"{not json", capture_output=True, timeout=30)
    assert r.returncode == 0 and r.stdout.strip() == b""


def test_reason_names_the_fix():
    payload = json.dumps({"tool_name": "Write", "tool_input": {"content": INCIDENT}}).encode()
    out = json.loads(subprocess.run([sys.executable, "-B", str(HOOK)], input=payload, capture_output=True).stdout)
    assert "CREATE_NO_WINDOW" in out["hookSpecificOutput"]["permissionDecisionReason"]
