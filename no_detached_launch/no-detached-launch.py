"""PreToolUse guard: refuse launching helpers DETACHED (Windows DETACHED_PROCESS) or into a NEW visible console.

User rule (2026-11-14, CLAUDE.md "No visible helper consoles"). MEASURED 2026-11-24: an agent's driver started
tools/vr-headless.py with creationflags NO_WINDOW | NEW_PROCESS_GROUP | DETACHED_PROCESS. A detached process has no
console, so every console program it starts without CREATE_NO_WINDOW gets a NEW VISIBLE window; vr-headless read
processes through powershell.exe once a second, and the user got a console pop-up every second for a whole run.
CREATE_NO_WINDOW alone gives the child a hidden console its own children inherit, and the child still outlives the
caller (measured), so detaching is never needed for that.

What is checked:
- Write / Edit / MultiEdit / NotebookEdit on CODE files. An Edit is judged on the file AFTER the edit, statement by
  statement around the changed text, so a small edit that appends `| 0x8` to an existing creationflags line is seen.
- Bash / PowerShell / Monitor: only text that runs as code: `-c`/`-e`/`-Command` scripts, heredoc bodies fed to an
  interpreter or written to a code file, and the unquoted command itself. Commit messages and search patterns are
  quoted arguments and are not judged.
Refused (outside comments and docstrings), per logical statement (bracketed and `|`-continued lines joined):
- DETACHED_PROCESS or CREATE_NEW_CONSOLE used as a flag (creationflags / Popen / CreateProcess / `|` / `|=` /
  assignment), not negated with `~`;
- a creationflags value holding an integer literal with bit 0x8 (detached) or 0x10 (new console), not under `~`;
- Node `detached: true` (libuv sets DETACHED_PROCESS on Windows).
Unreadable input fails OPEN; the refusal is a JSON deny (Claude Code and Codex). Every parsed payload writes a
heartbeat for tools/hook-canary.sh.
"""
import json
import os
import re
import sys
import time

NAMES = r"(?:DETACHED_PROCESS|CREATE_NEW_CONSOLE)"
NAMED = re.compile(r"(?<![\w.])(?:[A-Za-z_]\w*\.)*" + NAMES + r"\b")
NAMED_USE = re.compile(r"creation_?flags|Popen|CreateProcess|spawn|(?<!\\)\||\|=|(?<![=!<>])=(?!=)")
FLAGS = re.compile(r"creation_?flags[\"'\]]*\s*(?:[=:(]|\|=)\s*", re.I)
QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")


def flag_values(code):
    """Each creationflags value: from after `creationflags=` to the next top-level `,` `;` or closing bracket."""
    out = []
    for m in FLAGS.finditer(code):
        depth, i = 0, m.end()
        while i < len(code):
            ch = code[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch in ",;" and depth == 0:
                break
            elif ch == "\n" and depth == 0 and not (code[m.end():i].rstrip().endswith("|") or
                                                     code[i + 1:].lstrip().startswith("|")):
                break  # a value continues past a line end only inside brackets or around `|`
            i += 1
        out.append(code[m.end():i])
    return out
LITERAL = re.compile(r"(~\s*\(?\s*)?(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)(?![\w.])")
NODE_DETACHED = re.compile(r"\bdetached\s*:\s*true\b")
CODE_FILES = (".py", ".pyw", ".pyi", ".ps1", ".psm1", ".psd1", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".cs",
              ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".ahk", ".bat", ".cmd", ".sh", ".bash", ".zsh", ".vbs",
              ".rs", ".go", ".java", ".ipynb")
SELF = ("no-detached-launch.py", "test_no_detached_launch.py", "mutate.py", "replay_history.py")
INTERP = re.compile(r"(?i)(?<![\w.-])(python[\d.]*w?|py|pythonw|node|deno|bun|pwsh|powershell)(\.exe)?(?![\w-])")
CODE_TARGET = re.compile(r">\s*[\"']?[^\s\"'|;&]+(" + "|".join(re.escape(e) for e in CODE_FILES) + r")\b", re.I)
HEREDOC = re.compile(r"(?<!<)<<(?!<)-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
INLINE = re.compile(r"(?i)(?:^|\s)(?:-c|-e|--eval|-Command|-EncodedCommand_never)\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*')")


# ---- text shaping -------------------------------------------------------------------------------------------------

def strip_comments(line, batch=False):
    """Cut a trailing comment (# or //) that is outside quotes; REM/:: only at line start of batch files."""
    if batch and re.match(r"\s*(?i:rem\s|::)", line):
        return ""
    q = None
    i = 0
    while i < len(line):
        ch = line[i]
        if q:
            if ch == "\\":
                i += 2
                continue
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif (ch == "#" or line.startswith("//", i)) and (i == 0 or line[i - 1] in " \t;(,"):
            return line[:i]
        i += 1
    return line


def drop_docstrings(text):
    """Blank triple-quoted blocks that start a line (docstrings / prose), keeping line count."""
    return re.sub(r'(?m)^([ \t]*[rRuUbB]?)("""|\'\'\')(.*?)\2',
                  lambda m: m.group(1) + "\n" * m.group(0).count("\n"), text, flags=re.S)


def statements(text, batch=False):
    """Logical statements: (start_offset, end_offset, joined_code). Lines join while brackets are open or a line
    ends with `|`, or the next line starts with `|`. Comments are cut per line first."""
    lines = text.split("\n")
    out, buf, start, depth, pos = [], [], 0, 0, 0
    for idx, raw in enumerate(lines):
        code = strip_comments(raw, batch)
        if not buf:
            start = pos
        buf.append(code)
        unquoted = QUOTED.sub("''", code)
        depth += sum(unquoted.count(c) for c in "([{") - sum(unquoted.count(c) for c in ")]}")
        depth = max(depth, 0)
        pos += len(raw) + 1
        nxt = lines[idx + 1].lstrip() if idx + 1 < len(lines) else ""
        if depth > 0 or code.rstrip().endswith(("|", "\\")) or nxt.startswith("|") and not nxt.startswith("||"):
            if idx + 1 < len(lines):
                continue
        out.append((start, pos, "\n".join(buf)))
        buf, depth = [], 0
    return out


# ---- the rule -----------------------------------------------------------------------------------------------------

def bad_statement(code):
    """True when one logical statement launches detached / into a new console."""
    bare = QUOTED.sub("''", code)  # a name inside a string is prose
    hidden_console = "startupinfo" in bare.lower()  # a NEW console with a STARTUPINFO (SW_HIDE) can be hidden
    for m in NAMED.finditer(bare):
        if re.search(r"~\s*\(?\s*$", bare[:m.start()]):
            continue  # flags & ~DETACHED_PROCESS removes it
        if hidden_console and m.group(0).endswith("CREATE_NEW_CONSOLE"):
            continue
        if NAMED_USE.search(bare):
            return True
    for expr in flag_values(code):
        for neg, lit in LITERAL.findall(expr):
            if neg:
                continue
            try:
                value = int(lit, 10) if re.fullmatch(r"0\d+", lit) else int(lit, 0)
            except ValueError:
                continue
            if value >= 0x100000000:
                continue
            if value & 0x8 or value & 0x10 and not hidden_console:
                return True
    return bool(NODE_DETACHED.search(code))


def first_bad(text, span=None, batch=False, python=False):
    """The first offending statement text, or None. SPAN (start, end) limits to statements overlapping it."""
    if python:
        text = drop_docstrings(text)
    for s, e, code in statements(text, batch):
        if span and (e <= span[0] or s > span[1]):
            continue
        if bad_statement(code):
            return " ".join(code.split())
    return None


def shell_payloads(command):
    """The parts of a shell command that run as code: heredoc bodies fed to an interpreter or written to a code file,
    inline -c/-e/-Command scripts, and the command text with quotes and other heredoc bodies blanked."""
    out, rest, pos = [], [], 0
    for m in HEREDOC.finditer(command):
        if m.start() < pos:
            continue
        nl = command.find("\n", m.end())
        if nl < 0:
            break
        header = command[command.rfind("\n", 0, m.start()) + 1:nl]
        end = re.compile(r"(?m)^[ \t]*" + re.escape(m.group(2)) + r"[ \t]*$").search(command, nl + 1)
        body_end = end.start() if end else len(command)
        if INTERP.search(header) or CODE_TARGET.search(header):
            out.append(command[nl + 1:body_end])
        rest.append(command[pos:nl + 1])
        pos = end.end() if end else len(command)
    rest.append(command[pos:])
    plain = "".join(rest)
    for m in INLINE.finditer(plain):
        if INTERP.search(plain[:m.start()].split("\n")[-1]):
            body = m.group(1)[1:-1]
            out.append(body.replace('\\"', '"') if m.group(1)[0] == '"' else body)
    blanked = re.sub(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'", "''", plain)
    out.append(blanked)
    return out


def after_edit(path, old, new, replace_all):
    """(text_after, span_of_new) for an Edit, or None when the file cannot be read / old is absent."""
    try:
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            text = f.read()
    except OSError:
        return None
    i = text.find(old) if old else -1
    if i < 0:
        return None
    result = text.replace(old, new) if replace_all else text[:i] + new + text[i + len(old):]
    return result.replace("\r\n", "\n"), (text[:i].replace("\r\n", "\n").__len__(),
                                          text[:i].replace("\r\n", "\n").__len__() + len(new.replace("\r\n", "\n")))


def judge(tool, inp):
    """The offending statement for this call, or None."""
    path = str(inp.get("file_path") or inp.get("notebook_path") or "").replace("\\", "/")
    if tool in ("Bash", "PowerShell", "Monitor"):
        command = inp.get("command")
        if isinstance(command, list):
            command = " ".join(map(str, command))
        if not isinstance(command, str):
            return None
        for payload in shell_payloads(command):
            hit = first_bad(payload)
            if hit:
                return hit
        return None
    if tool not in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return None
    low = path.lower()
    if not low.endswith(CODE_FILES) or (path.rsplit("/", 1)[-1] in SELF and "no_detached_launch/" in path):
        return None  # notes and docs may describe the flag; the hook's own packet must stay editable
    batch, python = low.endswith((".bat", ".cmd")), low.endswith((".py", ".pyw", ".pyi"))
    if tool == "Write":
        return first_bad(str(inp.get("content") or ""), batch=batch, python=python)
    if tool == "NotebookEdit":
        return first_bad(str(inp.get("new_source") or ""), python=True)
    edits = [inp] if tool == "Edit" else [e for e in (inp.get("edits") or []) if isinstance(e, dict)]
    for e in edits:
        new = str(e.get("new_string") or "")
        done = after_edit(path, str(e.get("old_string") or ""), new, bool(e.get("replace_all")))
        hit = (first_bad(done[0], span=done[1], batch=batch, python=python) if done
               else first_bad(new, batch=batch, python=python))
        if hit:
            return hit
    return None


def heartbeat(payload_bytes):
    """hook-canary.sh contract: <root>/.claude/backups/.hook-heartbeat/<name> = 'YYYYMMDD_HHMMSS payload_bytes=N'."""
    try:
        root = os.environ.get("CLAUDE_PROJECT_DIR") or os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        d = os.path.join(root, ".claude", "backups", ".hook-heartbeat")
        if os.path.isdir(os.path.dirname(d)):
            os.makedirs(d, exist_ok=True)
            name = "no-detached-launch" + ("" if payload_bytes else ".blind")
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write("{} payload_bytes={}\n".format(time.strftime("%Y%m%d_%H%M%S"), payload_bytes))
    except OSError:
        pass


def main():
    try:
        raw = sys.stdin.buffer.read()
        if os.environ.get("NO_DETACHED_LAUNCH_HEARTBEAT", "1") == "1":
            heartbeat(len(raw))
        payload = json.loads(raw.decode("utf-8-sig", "replace"))
        hit = judge(payload.get("tool_name"), payload.get("tool_input") or {})
    except Exception as error:  # fail open: a parser bug must not block every edit
        print("no-detached-launch: could not read the call ({}); allowed".format(type(error).__name__), file=sys.stderr)
        return 0
    if not hit:
        return 0
    reason = ("no-detached-launch: this launches a process DETACHED or into a NEW console ({!r}). A detached process "
              "has no console, so every console program it starts gets a visible window on the user's desktop "
              "(2026-11-24: a pop-up every second for a whole headless run; banned by CLAUDE.md 'No visible helper "
              "consoles'). Use creationflags=CREATE_NO_WINDOW (0x08000000), optionally | CREATE_NEW_PROCESS_GROUP "
              "(0x200): the child gets a hidden console and still outlives the caller.").format(hit[:140])
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
