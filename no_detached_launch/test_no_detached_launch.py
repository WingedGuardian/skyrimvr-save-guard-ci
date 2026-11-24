"""no-detached-launch: run as a process with real hook payloads."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).parent / "no-detached-launch.py"


def run(tool, tool_input, env=None):
    payload = json.dumps({"tool_name": tool, "tool_input": tool_input}).encode()
    e = dict(os.environ, NO_DETACHED_LAUNCH_HEARTBEAT="0")
    e.update(env or {})
    r = subprocess.run([sys.executable, "-B", str(HOOK)], input=payload, capture_output=True, timeout=30, env=e)
    assert r.returncode == 0, r.stderr
    return r


def decide(tool, tool_input):
    out = run(tool, tool_input).stdout.decode().strip()
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else "allow"


INCIDENT = ("    p = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,\n"
            "                         creationflags=NO_WINDOW | 0x00000200 | 0x00000008)  # no window, new group, detached\n")


def W(content, path="x.py"):
    return ("Write", {"file_path": path, "content": content})


DENY = {
    "incident-write": W(INCIDENT),
    "named-constant": W("subprocess.Popen(c, creationflags=subprocess.DETACHED_PROCESS)\n"),
    "named-or": ("Edit", {"file_path": "missing.py", "old_string": "a", "new_string": "flags = CREATE_NO_WINDOW | DETACHED_PROCESS\n"}),
    "named-or-spaced": W("base = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP\n"),
    "or-assign": W("flags |= subprocess.DETACHED_PROCESS\n"),
    "plain-assign": W("flags = subprocess.DETACHED_PROCESS\nPopen(c, creationflags=flags)\n"),
    "create-process": W("win32process.CreateProcess(None, cmd, None, None, 0, win32process.DETACHED_PROCESS, None, None, si)\n"),
    "c-multiline": W("ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE,\n    DETACHED_PROCESS,\n    NULL, NULL, &si, &pi);\n", "x.cpp"),
    "cpp-scope": W("BOOL ok = ::CreateProcessW(NULL, cmd, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi);\n", "x.cpp"),
    "multiline-paren": W("p = Popen(c, creationflags=(\n    NO_WINDOW |\n    0x8))\n"),
    "trailing-or": W("p = Popen(c, creationflags=NO_WINDOW |\n    subprocess.DETACHED_PROCESS,\n    cwd=x)\n"),
    "csharp-trailing-or": W("uint flags = CREATE_NO_WINDOW |\n    DETACHED_PROCESS;\n", "x.cs"),
    "dict-key":W('kw = {"creationflags": 0x8}\n'),
    "kw-index": W('kw["creationflags"] = 8\n'),
    "rust": W("Command::new(x).creation_flags(0x8).spawn()?;\n", "x.rs"),
    "new-console": W("Popen(c, creationflags=subprocess.CREATE_NEW_CONSOLE)\n"),
    "new-console-literal": W("Popen(c, creationflags=0x10)\n"),
    "detached-with-startupinfo": W("Popen(c, creationflags=0x8 | 0x10, startupinfo=si)\n"),
    "node-detached": W("spawn(cmd, args, { detached: true, stdio: 'ignore' })\n", "x.js"),
    "short-hex": ("Edit", {"file_path": "missing.py", "old_string": "a", "new_string": "Popen(c, creationflags=0x8)"}),
    "decimal": W("Popen(c, creationflags=8)"),
    "leading-zero": W("Popen(c, creationflags=0008)"),
    "combined-literal": W("Popen(c, creationflags=0x08000208)"),
    "hash-in-string": W('Popen(["echo", " #1"], creationflags=8)\n'),
    "uppercase-ext": W("Popen(c, creationflags=0x8)\n", "X.PY"),
    "backslash-path": W("Popen(c, creationflags=0x8)\n", "C:\\work\\x.py"),
    "multiedit": ("MultiEdit", {"file_path": "missing.py", "edits": [{"old_string": "a", "new_string": "ok = 1"},
                                                                     {"old_string": "b", "new_string": "Popen(c, creationflags=0x00000008)"}]}),
    "bash-inline": ("Bash", {"command": "python -c \"import subprocess;subprocess.Popen(['x'],creationflags=0x00000008)\""}),
    "bash-heredoc-python": ("Bash", {"command": "python - <<'EOF'\nimport subprocess\nsubprocess.Popen(['x'], creationflags=0x8)\nEOF"}),
    "bash-heredoc-to-file": ("Bash", {"command": "cat > drive.py <<'EOF'\np = Popen(c, creationflags=NO_WINDOW | 0x8)\nEOF"}),
    "bash-list-command": ("Bash", {"command": ["python", "-c", "Popen(c, creationflags=0x8)"]}),
    "powershell-inline": ("PowerShell", {"command": "python -c \"import subprocess as s; s.Popen(['x'], creationflags=s.DETACHED_PROCESS)\""}),
    "monitor": ("Monitor", {"command": "python -c \"from subprocess import *; Popen(['x'], creationflags=8)\""}),
    "notebook": ("NotebookEdit", {"notebook_path": "n.ipynb", "new_source": "Popen(c, creationflags=DETACHED_PROCESS)"}),
    "same-name-elsewhere": W(INCIDENT, "C:/x/other/test_no_detached_launch.py"),
}

ALLOW = {
    "prose-docstring": W('"""Windows: a hidden console, never CREATE_NO_WINDOW | DETACHED_PROCESS."""\nx = 1\n'),
    "string-mention": W('msg = "never use DETACHED_PROCESS"\n'),
    "hidden-new-console": W("p = subprocess.run(c, creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=si)\n"),
    "hidden-new-console-literal": W("p = subprocess.run(c, creationflags=0x10, startupinfo=si)\n"),
    "flag-then-other-kwargs":W("p = subprocess.run(cmd, capture_output=True, creationflags=0x08000000, timeout=120)\n"),
    "value-ends-at-line": W('options = dict(\n    x=1)\nif nt:\n    options["creationflags"] = NO_WINDOW\nelse:\n    tail = 64 * 1024 + 8\n'),
    "code-in-long-string": W("patch('''\nif nt:\n    options[\"creationflags\"] = NO_WINDOW\ntail = 64 * 1024 + 8\n''')\n"),
    "bracket-in-string": W('opener = "("\nprint(subprocess.DETACHED_PROCESS)\nx = 1\n'),
    "name-read-not-used":W("print(subprocess.DETACHED_PROCESS)\n"),
    "token-compare":W('if tok.string == "DETACHED_PROCESS":\n    bad = True\n'),
    "removes-flag-name": W("Popen(c, creationflags=flags & ~subprocess.DETACHED_PROCESS)\n"),
    "removes-flag-literal": W("Popen(c, creationflags=flags & ~0x8)\n"),
    "grep-search": ("Bash", {"command": r'grep -rn "0x00000008\|DETACHED_PROCESS" tools --include=*.py'}),
    "rg-search": ("Bash", {"command": 'rg -n "DETACHED_PROCESS|creationflags" tools'}),
    "select-string": ("PowerShell", {"command": "Select-String -Pattern 'DETACHED_PROCESS|CREATE_NO_WINDOW' *.py"}),
    "git-commit": ("Bash", {"command": 'git commit -m "drop DETACHED_PROCESS: was creationflags=0x8"'}),
    "docstring-flags": W('def f():\n    """Was creationflags=0x8 once; now hidden."""\n    return 1\n'),
    "heredoc-to-notes": ("Bash", {"command": "cat > notes.md <<'EOF'\ncreationflags=NO_WINDOW | DETACHED_PROCESS\nEOF"}),
    "markdown-note": W(INCIDENT, "notes.md"),
    "own-test-file": W(INCIDENT, "C:\\x\\no_detached_launch\\test_no_detached_launch.py"),
    "hidden-only": W("Popen(c, creationflags=0x08000000)\n"),
    "hidden-group": W("Popen(c, creationflags=NO_WINDOW | 0x00000200)\n"),
    "named-no-window": W("Popen(c, creationflags=subprocess.CREATE_NO_WINDOW)\n"),
    "the-fix-comment": W("    creationflags=NO_WINDOW | 0x00000200)  # hidden console, new group. NEVER detached (0x8):\n"),
    "comment-holds-old-flags": W("x = Popen(c, creationflags=NO_WINDOW)  # was creationflags=NO_WINDOW | 0x00000008\n"),
    "comment-slash": W("x = spawn(c, {windowsHide: true}); // was detached: true\n", "x.js"),
    "comment-names-it": W("# never use DETACHED_PROCESS here\nx = 1\n"),
    "batch-rem": W("REM creationflags=8 DETACHED_PROCESS = bad\r\n:: Popen(c, creationflags=8)\r\necho ok\r\n", "x.bat"),
    "unrelated-0x8": W("caps = 0x1000 | 0x400000 | 0x8\n"),
    "huge-literal": W("Popen(c, creationflags=0x100000008)\n"),
    "plain-bash": ("Bash", {"command": "git status"}),
    "read-tool": ("Read", {"file_path": "x.py"}),
}


@pytest.mark.parametrize("name", sorted(DENY))
def test_denies(name):
    assert decide(*DENY[name]) == "deny", name


@pytest.mark.parametrize("name", sorted(ALLOW))
def test_allows(name):
    assert decide(*ALLOW[name]) == "allow", name


def test_small_edit_judged_in_context(tmp_path):
    f = tmp_path / "drive.py"
    f.write_text("p = subprocess.Popen(cmd,\n    creationflags=NO_WINDOW | 0x00000200)\n", encoding="utf-8")
    edit = {"file_path": str(f), "old_string": "NO_WINDOW | 0x00000200)", "new_string": "NO_WINDOW | 0x00000200 | 0x00000008)"}
    assert decide("Edit", edit) == "deny"
    harmless = {"file_path": str(f), "old_string": "cmd,", "new_string": "cmd2,"}
    assert decide("Edit", harmless) == "allow"


def test_edit_elsewhere_in_a_file_with_an_old_bad_line_is_allowed(tmp_path):
    f = tmp_path / "old.py"
    f.write_text("a = Popen(c, creationflags=0x8)\n\n\n\ndef other():\n    return 1\n", encoding="utf-8")
    assert decide("Edit", {"file_path": str(f), "old_string": "return 1", "new_string": "return 2"}) == "allow"


def test_bom_payload_is_read():
    payload = b"\xef\xbb\xbf" + json.dumps({"tool_name": "Write", "tool_input": {"file_path": "x.py", "content":
                                                                                "Popen(c, creationflags=8)"}}).encode()
    r = subprocess.run([sys.executable, "-B", str(HOOK)], input=payload, capture_output=True, timeout=30,
                       env=dict(os.environ, NO_DETACHED_LAUNCH_HEARTBEAT="0"))
    assert r.returncode == 0 and b'"deny"' in r.stdout


def test_garbage_fails_open():
    r = subprocess.run([sys.executable, "-B", str(HOOK)], input=b"{not json", capture_output=True, timeout=30,
                       env=dict(os.environ, NO_DETACHED_LAUNCH_HEARTBEAT="0"))
    assert r.returncode == 0 and r.stdout.strip() == b""


def test_heartbeat_written(tmp_path):
    (tmp_path / ".claude" / "backups").mkdir(parents=True)
    run("Bash", {"command": "git status"}, env={"CLAUDE_PROJECT_DIR": str(tmp_path), "NO_DETACHED_LAUNCH_HEARTBEAT": "1"})
    beat = (tmp_path / ".claude" / "backups" / ".hook-heartbeat" / "no-detached-launch").read_text()
    assert beat.split()[1].startswith("payload_bytes=") and int(beat.split("=")[1]) > 10


def test_reason_names_the_fix():
    r = run("Write", {"file_path": "x.py", "content": INCIDENT})
    assert r.returncode == 0
    assert "CREATE_NO_WINDOW" in json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
