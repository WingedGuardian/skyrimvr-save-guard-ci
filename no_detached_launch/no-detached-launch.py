"""PreToolUse guard: refuse launching helpers DETACHED (Windows DETACHED_PROCESS, 0x00000008).

User rule (2026-11-14, CLAUDE.md "No visible helper consoles"). MEASURED 2026-11-24: an agent's driver started
tools/vr-headless.py with creationflags NO_WINDOW | NEW_PROCESS_GROUP | DETACHED_PROCESS. A detached process has no
console, so every console program it starts without CREATE_NO_WINDOW gets a NEW VISIBLE window; vr-headless read
processes through powershell.exe once a second, and the user got a console pop-up every second for a whole run.
CREATE_NO_WINDOW alone gives the child a hidden console its own children inherit, and the child still outlives the
caller (measured), so detaching is never needed for that.

Checked: text an agent writes (Write content, Edit/MultiEdit new_string, NotebookEdit new_source) and shell commands
(Bash, PowerShell, Monitor). Refused when code (not a comment) names DETACHED_PROCESS, or a `creationflags` expression
holds an integer literal with the 0x8 bit set (0x8, 0x00000008, 8, or an OR of literals containing it).
Unreadable input fails OPEN; the refusal is a JSON deny, honoured by Claude Code and Codex.
"""
import json
import re
import sys

NAMED = re.compile(r"\bDETACHED_PROCESS\b")
# The name counts only where it is USED as a launch flag, not where prose or a search mentions it.
NAMED_USE = re.compile(r"creation_?flags|Popen|CreateProcess|DETACHED_PROCESS\s*(?<!\\)\||(?<!\\)\|\s*[\w.]*DETACHED_PROCESS")
CODE_FILES = (".py", ".pyw", ".ps1", ".psm1", ".js", ".mjs", ".cjs", ".ts", ".cs", ".cpp", ".c", ".h", ".hpp",
              ".ahk", ".bat", ".cmd", ".sh", ".vbs", ".rs", ".go", ".java", ".ipynb")
SELF = ("no-detached-launch.py", "test_no_detached_launch.py", "mutate.py", "replay_history.py")
FLAGS = re.compile(r"creation_?flags\s*[=:]\s*([^,)\n]*)", re.I)
LITERAL = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)(?![\w.])")
COMMENT = re.compile(r"(^|\s)(#|//|REM\s|::)")


def code_part(line):
    """The line up to a comment marker (a crude cut that is good enough for flag spellings)."""
    m = COMMENT.search(line)
    return line[:m.start()] if m else line


def detached(text):
    """The offending line, or None."""
    for line in text.splitlines():
        code = code_part(line)
        if NAMED.search(code) and NAMED_USE.search(code):
            return line.strip()
        for expr in FLAGS.findall(code):
            for lit in LITERAL.findall(expr):
                try:
                    value = int(lit, 0) if not re.fullmatch(r"0\d+", lit) else int(lit, 10)
                except ValueError:
                    continue
                if value & 0x8 and value < 0x100000000:
                    return line.strip()
    return None


def texts(tool, inp):
    path = str(inp.get("file_path") or inp.get("notebook_path") or "").replace("\\", "/")
    if path and (not path.lower().endswith(CODE_FILES) or
                 (path.rsplit("/", 1)[-1] in SELF and "/no_detached_launch/" in path)):
        return  # notes and docs may describe the flag; the hook's own packet must stay editable
    if tool in ("Bash", "PowerShell", "Monitor"):
        yield inp.get("command") or ""
    elif tool == "Write":
        yield inp.get("content") or ""
    elif tool == "Edit":
        yield inp.get("new_string") or ""
    elif tool == "MultiEdit":
        for e in inp.get("edits") or []:
            yield (e or {}).get("new_string") or ""
    elif tool == "NotebookEdit":
        yield inp.get("new_source") or ""


def main():
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"))
        tool, inp = payload.get("tool_name"), payload.get("tool_input") or {}
        hit = None
        for text in texts(tool, inp):
            if isinstance(text, str):
                hit = detached(text)
                if hit:
                    break
    except Exception as error:  # fail open: a parser bug must not block every edit
        print("no-detached-launch: could not read the call ({}); allowed".format(type(error).__name__), file=sys.stderr)
        return 0
    if not hit:
        return 0
    reason = ("no-detached-launch: this launches a process DETACHED ({!r}). A detached process has no console, so every "
              "console program it starts gets a visible window on the user's desktop (2026-11-24: a pop-up every "
              "second for a whole headless run; banned by CLAUDE.md 'No visible helper consoles'). Use "
              "creationflags=CREATE_NO_WINDOW (0x08000000), optionally | CREATE_NEW_PROCESS_GROUP (0x200): the child "
              "gets a hidden console and still outlives the caller.").format(hit[:140])
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
