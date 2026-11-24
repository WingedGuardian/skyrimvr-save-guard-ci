"""PreToolUse guard: refuse launching helpers DETACHED (Windows DETACHED_PROCESS) or into a NEW visible console.

User rule (2026-11-14, CLAUDE.md "No visible helper consoles"). MEASURED 2026-11-24: an agent's driver started
tools/vr-headless.py with creationflags NO_WINDOW | NEW_PROCESS_GROUP | DETACHED_PROCESS. A detached process has no
console, so every console program it starts without CREATE_NO_WINDOW gets a NEW VISIBLE window; vr-headless read
processes through powershell.exe once a second, and the user got a console pop-up every second for a whole run.
CREATE_NO_WINDOW alone gives the child a hidden console its own children inherit, and the child still outlives the
caller (measured), so detaching is never needed for that.

What is checked:
- Write / Edit / MultiEdit / NotebookEdit on CODE files. An Edit is judged on the file AFTER the edit (edits applied
  in order), statement by statement around each changed span, so a small edit that appends `| 0x8` to an existing
  creationflags line is seen.
- Bash / PowerShell / Monitor: text that runs or is written as code: -c/-e/-Command and /c bodies after an
  interpreter or shell (nested up to 3 levels), heredoc and PowerShell here-string bodies fed to an interpreter or
  written to a code file, quoted arguments of a command that writes a code file, and the unquoted command itself.
  Commit messages and search patterns are quoted arguments of other commands and are not judged.
Refused, per logical statement (bracketed and `|`-continued lines joined, at most 50 lines; comments, docstrings and
string contents blanked to the same length):
- DETACHED_PROCESS, or CREATE_NEW_CONSOLE without a hiding STARTUPINFO (SW_HIDE in the same text), used as a flag
  (creationflags / Popen / CreateProcess / spawn / `|` / `|=` / assignment) and not negated with `~`;
- a creationflags value holding an integer literal with bit 0x8, or 0x10 without a hiding STARTUPINFO;
- Node `detached: true` / `.detached = true` (libuv sets DETACHED_PROCESS on Windows).
Unreadable input fails OPEN; the refusal is a JSON deny (Claude Code and Codex). Each parsed payload writes a
heartbeat for tools/hook-canary.sh; an unparseable one writes the .blind marker.
"""
import io
import json
import os
import re
import sys
import time
import tokenize

NAMES = r"(?:DETACHED_PROCESS|CREATE_NEW_CONSOLE)"
NAMED = re.compile(r"(?<![\w.])(?:[A-Za-z_]\w*\.)*" + NAMES + r"\b")
NAMED_USE = re.compile(r"creation_?flags|Popen|CreateProcess|spawn|(?<!\\)\||\|=|(?<![=!<>])=(?!=)")
FLAGS = re.compile(r"creation_?flags[\"'\]]*\s*(?:[=:(]|\|=)\s*", re.I)
QUOTED = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'")
QUOTED_ML = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'")  # shell quoting: may span lines; '...' has no escapes
LITERAL = re.compile(r"(~\s*\(?\s*)?(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)(?![\w.])")
NODE_DETACHED = re.compile(r"""(?:\bdetached["']?\s*:|\.detached\s*=)\s*true\b""")
HIDING = re.compile(r"SW_HIDE|wShowWindow\s*=\s*0\b")
CODE_FILES = (".py", ".pyw", ".pyi", ".ps1", ".psm1", ".psd1", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".cs",
              ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".ahk", ".bat", ".cmd", ".sh", ".bash", ".zsh", ".vbs",
              ".rs", ".go", ".java", ".ipynb")
SELF = ("no-detached-launch.py", "test_no_detached_launch.py", "mutate.py", "replay_history.py")
INTERP = re.compile(r"(?i)(?<![\w.-])(python[\d.]*w?|py|pythonw|node|deno|bun|pwsh|powershell|bash|sh|cmd)(\.exe)?(?![\w-])")
CODE_PATH = r"[\"']?[^\s\"'|;&<>]+(?:" + "|".join(re.escape(e) for e in CODE_FILES) + r")\b"
WRITES_CODE = re.compile(r"(?i)(?:>>?\s*" + CODE_PATH + r"|\b(?:Set-Content|Add-Content|Out-File|tee)\b[^|;\n]*?" +
                         CODE_PATH + ")")
HEREDOC = re.compile(r"(?<!<)<<(?!<)-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
HERESTRING = re.compile(r"@(['\"])\r?\n(.*?)\r?\n\1@", re.S)
INLINE = re.compile(r"(?i)(?:^|\s)(?:-c|-e|--eval|-Command|/c|/k)\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*')")
WINDOW = 200          # lines judged on each side of an edit
MAX_FILE = 4_000_000  # bytes; a bigger file is judged on the new text only
MAX_JOIN = 50         # physical lines one statement may span


# ---- same-length blanking ------------------------------------------------------------------------------------------

def blank(s):
    return re.sub(r"[^\n]", " ", s)


KEY = re.compile(r"(?i)creation_?flags|detached")  # keys kept visible: kw["creationflags"], {"detached": true}


def blank_strings(text, rx=QUOTED):
    """String contents to spaces, quotes kept, same length (so offsets survive). A string that IS the key
    `creationflags` (kw["creationflags"] = 8) is kept, so the flag value is still found."""
    def one(m):
        s = m.group(0)
        return s if KEY.fullmatch(s[1:-1]) else s[0] + blank(s[1:-1]) + s[-1]
    return rx.sub(one, text)


def strip_comments(text, batch=False):
    """Same-length: # and // line comments outside quotes, /* */ blocks, REM/:: lines in batch files."""
    out, lines = [], text.split("\n")
    for line in lines:
        if batch and re.match(r"\s*(?i:rem\s|::)", line):
            out.append(blank(line))
            continue
        q, i, cut = None, 0, None
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
                cut = i
                break
            i += 1
        out.append(line if cut is None else line[:cut] + blank(line[cut:]))
    text = "\n".join(out)
    return re.sub(r"/\*.*?\*/", lambda m: blank(m.group(0)), text, flags=re.S)


def python_strings(text):
    """Same-length, by Python's own tokenizer: blank the contents of every string token (docstrings and multi-line
    prose included; prefix and quotes kept), except a string that is the key `creationflags`. Untokenizable text
    (a partial window, a syntax error) is returned unchanged."""
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return text
    starts = [0]
    for line in text.split("\n"):
        starts.append(starts[-1] + len(line) + 1)
    chars = list(text)
    for t in toks:
        if t.type != tokenize.STRING:
            continue
        s = t.string
        q = min(i for i in (s.find('"'), s.find("'")) if i >= 0)
        ql = 3 if s[q:q + 3] in ('"""', "'''") else 1
        if KEY.fullmatch(s[q + ql:len(s) - ql]):
            continue
        a = starts[t.start[0] - 1] + t.start[1] + q + ql
        b = starts[t.end[0] - 1] + t.end[1] - ql
        for k in range(a, min(b, len(chars))):
            if chars[k] != "\n":
                chars[k] = " "
    return "".join(chars)


def statements(code):
    """Logical statements of blanked CODE: [(start, end, text)], text being the original slice (same offsets)."""
    lines = code.split("\n")
    out, start, depth, pos, n = [], 0, 0, 0, 0
    for idx, line in enumerate(lines):
        if n == 0:
            start = pos
        n += 1
        bare = blank_strings(line)
        depth = max(depth + sum(bare.count(c) for c in "([{") - sum(bare.count(c) for c in ")]}"), 0)
        pos += len(line) + 1
        nxt = lines[idx + 1].lstrip() if idx + 1 < len(lines) else ""
        joins = depth > 0 or bare.rstrip().endswith(("|", "\\")) or nxt.startswith("|") and not nxt.startswith("||")
        if joins and idx + 1 < len(lines) and n < MAX_JOIN:
            continue
        out.append((start, pos, code[start:pos]))
        n, depth = 0, 0
    return out


# ---- the rule -----------------------------------------------------------------------------------------------------

def flag_values(bare):
    """Each creationflags value in string-blanked BARE: up to the next top-level `,` `;`, closing bracket, or a line
    end outside brackets that is not continued with `|`."""
    out = []
    for m in FLAGS.finditer(bare):
        depth, i = 0, m.end()
        while i < len(bare):
            ch = bare[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch in ",;" and depth == 0:
                break
            elif ch == "\n" and depth == 0 and not (bare[m.end():i].rstrip().endswith(("|", "\\")) or
                                                     bare[i + 1:].lstrip().startswith("|")):
                break  # a value continues past a line end only inside brackets or around `|`
            i += 1
        out.append(bare[m.end():i])
    return out


def bad_statement(code, hiding):
    """True when one logical statement (comments/docstrings already blanked) launches detached / new console."""
    bare = blank_strings(code)
    hidden_console = hiding and "startupinfo" in bare.lower()
    for m in NAMED.finditer(bare):
        if re.search(r"~\s*\(?\s*$", bare[:m.start()]):
            continue  # flags & ~DETACHED_PROCESS removes it
        if hidden_console and m.group(0).endswith("CREATE_NEW_CONSOLE"):
            continue
        if NAMED_USE.search(bare):
            return True
    for expr in flag_values(bare):
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
    return bool(NODE_DETACHED.search(bare))


def first_bad(text, spans=None, batch=False, python=False):
    """The first offending statement, or None. SPANS [(start, end)] limit to statements overlapping any span."""
    code = python_strings(text) if python else text
    code = strip_comments(code, batch)
    hiding = bool(HIDING.search(code))
    for s, e, stmt in statements(code):
        if spans and not any(s < b + 1 and e > a for a, b in spans):
            continue
        if bad_statement(stmt, hiding):
            return " ".join(stmt.split())
    return None


def shell_payloads(command, depth=0):
    """Parts of a shell command that run as code or are written into a code file (see module docstring)."""
    out, rest, pos = [], [], 0
    writes = bool(WRITES_CODE.search(command))
    for m in HEREDOC.finditer(command):
        if m.start() < pos:
            continue
        nl = command.find("\n", m.end())
        if nl < 0:
            break
        header = command[command.rfind("\n", 0, m.start()) + 1:nl]
        end = re.compile(r"(?m)^[ \t]*" + re.escape(m.group(2)) + r"[ \t]*$").search(command, nl + 1)
        body_end = end.start() if end else len(command)
        if INTERP.search(header) or WRITES_CODE.search(header):
            out.append(command[nl + 1:body_end])
        rest.append(command[pos:nl + 1])
        pos = end.end() if end else len(command)
    rest.append(command[pos:])
    plain = "".join(rest)
    for m in HERESTRING.finditer(plain):  # PowerShell @' ... '@ | python - / | Set-Content x.py
        tail = plain[m.end():m.end() + 200].split("\n")[0]
        if INTERP.search(tail) or WRITES_CODE.search(tail):
            out.append(m.group(2))
    plain = HERESTRING.sub(lambda m: blank(m.group(0)), plain)
    for m in INLINE.finditer(plain):
        if INTERP.search(plain[:m.start()].split("\n")[-1]):
            body = m.group(1)[1:-1]
            body = body.replace('\\"', '"') if m.group(1)[0] == '"' else body
            out.append(body)
            if depth < 3:
                out.extend(shell_payloads(body, depth + 1))
    if writes:  # echo "..." > x.py / printf '...' >> x.py / '...' | Set-Content x.py
        out.extend(m.group(0)[1:-1].replace("\\n", "\n") for m in QUOTED_ML.finditer(plain))
    out.append(QUOTED_ML.sub("''", plain))
    return out


def after_edits(path, edits):
    """(text_after, spans) applying EDITS in order to the file, LF-normalised; None when not applicable."""
    try:
        if os.path.getsize(path) > MAX_FILE:
            return None
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            text = f.read().replace("\r\n", "\n")
    except OSError:
        return None
    spans = []
    for e in edits:
        old = str(e.get("old_string") or "").replace("\r\n", "\n")
        new = str(e.get("new_string") or "").replace("\r\n", "\n")
        if not old or old not in text:
            return None
        hits, i = [], text.find(old)
        while i >= 0:
            hits.append(i)
            if not e.get("replace_all"):
                break
            i = text.find(old, i + len(old))
        shift, delta = 0, len(new) - len(old)
        spans = [(a + (delta if a > hits[0] else 0), b + (delta if a > hits[0] else 0)) for a, b in spans]
        for h in hits:
            spans.append((h + shift, h + shift + len(new)))
            shift += delta
        text = text.replace(old, new) if e.get("replace_all") else text[:hits[0]] + new + text[hits[0] + len(old):]
    return text, spans


def window(text, spans):
    """Cut TEXT to WINDOW lines around SPANS (same offsets: outside lines are blanked)."""
    lo = max(0, min(a for a, _ in spans))
    hi = max(b for _, b in spans)
    a = text.rfind("\n", 0, lo)
    for _ in range(WINDOW):
        a = text.rfind("\n", 0, a) if a > 0 else -1
    b = hi
    for _ in range(WINDOW):
        b = text.find("\n", b + 1)
        if b < 0:
            b = len(text)
            break
    a = max(a, 0)
    return blank(text[:a]) + text[a:b] + blank(text[b:])


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
        content = str(inp.get("content") or "")
        if low.endswith(".ipynb"):
            try:
                content = "\n".join("".join(c.get("source") or []) for c in json.loads(content).get("cells", []))
                python = True
            except (ValueError, AttributeError, TypeError):
                pass
        return first_bad(content, batch=batch, python=python)
    if tool == "NotebookEdit":
        return first_bad(str(inp.get("new_source") or ""), python=True)
    edits = [inp] if tool == "Edit" else [e for e in (inp.get("edits") or []) if isinstance(e, dict)]
    done = after_edits(path, edits)
    if done and done[1]:
        return first_bad(window(*done), spans=done[1], batch=batch, python=python)
    for e in edits:  # file unreadable / old text absent: judge the new text alone
        hit = first_bad(str(e.get("new_string") or ""), batch=batch, python=python)
        if hit:
            return hit
    return None


def heartbeat(name, payload_bytes):
    """hook-canary.sh contract: <root>/.claude/backups/.hook-heartbeat/<name> = 'YYYYMMDD_HHMMSS payload_bytes=N'."""
    try:
        root = os.environ.get("CLAUDE_PROJECT_DIR") or os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        d = os.path.join(root, ".claude", "backups", ".hook-heartbeat")
        if os.path.isdir(os.path.dirname(d)):
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write("{} payload_bytes={}\n".format(time.strftime("%Y%m%d_%H%M%S"), payload_bytes))
    except Exception:
        pass


def main():
    beat = os.environ.get("NO_DETACHED_LAUNCH_HEARTBEAT", "1") == "1"
    try:
        raw = sys.stdin.buffer.read()
        try:
            payload = json.loads(raw.decode("utf-8-sig", "replace"))
        except ValueError:
            if beat:
                heartbeat("no-detached-launch.blind", len(raw))
            raise
        if beat:
            heartbeat("no-detached-launch" if isinstance(payload, dict) else "no-detached-launch.blind", len(raw))
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
