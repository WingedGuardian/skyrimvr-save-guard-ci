"""protect-bash's delete rule: a SIMPLE, best-effort check by resolved operand (user rulings 2026-11-10).

The old rule refused any command that both named a delete program and mentioned the install or the config folder
anywhere in its text. MEASURED over 1,602 transcripts: 101 refusals, essentially all false positives. Saves and the
config INIs are now kept by the save vault (every version), Data can be redeployed by the mod manager and rebuilt from
the manual-install manifests, and mod work is in git. So this rule guards only against the catastrophic, plainly
spelled delete:

    deleting the game root, its Data folder, the config folder (Documents/My Games/<edition>), a Saves folder, the
    backup stores (.claude/backups, its save-backups and kb), or any ANCESTOR of these; or anything INSIDE the save
    vault (%LOCALAPPDATA%/modding-agent-harness/save-vault).

A delete is judged by what it is handed: the operands of rm / rmdir / rd / del / erase / Remove-Item / ri / unlink,
and the start folder of `find ... -delete` or `find ... -exec rm` when no name/type filter narrows it. Each operand is
resolved against the payload's cwd, any literal `cd` earlier in the command, any literal `X=...` assignment earlier in
the command, and the well-known folders ($HOME, $USERPROFILE, $LOCALAPPDATA and their PowerShell/cmd spellings). A
wildcard that takes a folder's whole contents (`*`, `*.*`, `.*`, `**`) counts as that folder. `bash -c`, `sh -c`,
`eval`, `powershell -Command` and `cmd /c` strings are judged as commands. A PowerShell here-string (@' ... '@) is
data. `Remove-Item X\\* -Include P` / `-Filter P` is narrowed by P, so it empties nothing.

KNOWN GAPS, by design (the user chose a simple rule over hardening rounds; every one is plainly a deliberate spelling):
an operand from a variable set OUTSIDE the command, a substitution, or stdin (`... | xargs rm`, `gci X | Remove-Item`);
code inside an interpreter (python -c "shutil.rmtree(...)", node -e, [IO.Directory]::Delete); 8.3 short names, UNC,
\\\\?\\ prefixes; robocopy /MIR or /PURGE (empties, does not delete); git clean; an ANSI-C quote ($'it\\'s') or
a `<<WORD` inside a quoted string can hide the LATER LINES of the same command from this check; `sudo -u USER rm`
(USER is read as the program); PowerShell `Remove-Item ("X")`, `@("X")`, `$null = Remove-Item X`, an unquoted path with backtick-escaped spaces,
a comma list continued on the next line, a here-string whose last line ends in a backtick; `cmd /c` text is read by the PowerShell rules, so a `#` or `'` in it (literal
characters in cmd) can hide the rest of that string. Nothing here reads a command's text for words: a command that only MENTIONS a protected folder is never refused.

    stdin: the PreToolUse payload. env: INSTALL_ROOT[_WIN], SKYRIM_CONFIG_DIR, SKYRIM_GAME_ROOT (from the paths file).
    stdout: one line, the refusal reason, or nothing. Exit 0 either way; a crash exits 1 (the caller then refuses).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys

DESTROYERS = {"rm", "rmdir", "rd", "del", "erase", "remove-item", "ri", "unlink"}
WRAPPERS = {"sudo", "env", "command", "exec", "nohup", "time", "nice", "builtin", "timeout", "xargs",
            "then", "do", "else", "elif", "!", "if", "while", "until"}
SHELLS = {"bash", "sh", "zsh", "dash"}
POWERSHELLS = {"powershell", "pwsh"}
CHDIR = {"cd", "pushd", "set-location", "sl", "chdir", "push-location"}
EDITIONS = ("Skyrim VR", "Skyrim Special Edition", "Skyrim Special Edition GOG", "Skyrim Special Edition EPIC", "Skyrim")
SEPARATORS = {";", "&&", "||", "|", "&", "\n", "(", ")", "{", "}"}
ALL_OF = {"*", "*.*", ".*", "**"}
FIND_FILTERS = {"-name", "-iname", "-path", "-ipath", "-type", "-regex", "-iregex", "-newer", "-mtime", "-mmin",
                "-size", "-wholename", "-empty", "-user", "-perm"}
HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][\w-]*)\1")    # not a <<< here-string
DEPTH = 3


def norm(path):
    path = path.strip().strip("'\"")
    m = re.match(r"^/([a-zA-Z])(/|$)", path)                     # MSYS /c/... -> C:/...
    if m:
        path = m.group(1).upper() + ":/" + path[3:]
    path = os.path.expanduser(path) if path.startswith("~") else path
    return os.path.normcase(os.path.normpath(path.replace("\\", "/")))


def documents():
    found = [os.path.join(os.path.expanduser("~"), "Documents")]
    if os.name == "nt":
        try:
            import ctypes
            import uuid
            guid = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID("FDD39AD0-238F-46AF-ADB4-6C85480369C7").bytes_le)
            out = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) == 0:
                found.append(out.value)
                ctypes.windll.ole32.CoTaskMemFree(out)
        except (OSError, AttributeError, ValueError):
            pass
    return found


def local_appdata(env):
    return env.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")


def protected_roots(env):
    """({normalised path: what}, {normalised path: what}) -- the first protects the path and its ancestors, the
    second also everything inside it."""
    roots, inside = {}, {}
    for key in ("INSTALL_ROOT", "INSTALL_ROOT_WIN", "SKYRIM_GAME_ROOT"):
        for value in filter(None, env.get(key, "").split(os.pathsep if key == "SKYRIM_GAME_ROOT" else "\0")):
            roots[norm(value)] = "the game install"
            roots[norm(os.path.join(value, "Data"))] = "the game's Data folder"
            for sub, what in (("backups", "the install's backup store"),
                              (os.path.join("backups", "save-backups"), "the old save-backup store"),
                              (os.path.join("backups", "kb"), "the knowledge-base backups")):
                roots[norm(os.path.join(value, ".claude", sub))] = what
    configs = [os.path.join(d, "My Games", e) for d in documents() for e in EDITIONS]
    configs += [v for v in env.get("SKYRIM_CONFIG_DIR", "").split(os.pathsep) if v]
    for value in configs:
        roots[norm(value)] = "the game's config folder (INIs, controlmap)"
        roots[norm(os.path.join(value, "Saves"))] = "a Saves folder"
    inside[norm(os.path.join(local_appdata(env), "modding-agent-harness", "save-vault"))] = "the save vault"
    return roots, inside


def hit(target, protected):
    """The protected thing this target IS, CONTAINS (an ancestor deletes its descendants), or lies inside."""
    roots, inside = protected
    for root, what in list(roots.items()) + list(inside.items()):
        if target == root:
            return what
        try:
            if os.path.commonpath([target, root]) == target:
                return "a folder holding " + what
        except ValueError:
            continue
    for root, what in inside.items():
        try:
            if os.path.commonpath([target, root]) == root:
                return "something inside " + what
        except ValueError:
            continue
    return None


def strip_heredocs(text):
    """Heredoc bodies are data unless a shell reads them; drop the bodies, keep the command lines."""
    out, term = [], None
    for line in text.split("\n"):
        if term is not None:
            if line.strip() == term:
                term = None
            continue
        out.append(line)
        m = HEREDOC.search(line)
        if m and not re.search(r"(^|[\s;&|(])(ba|z)?sh\b[^|]*<<|\|\s*(ba|z)?sh\b", line):
            term = m.group(2)
    return "\n".join(out)


PS_TOKEN = re.compile(r"""(?:"(?:[^"`]|`[\s\S])*"|'[^']*'|[^\s"';|&(){}])+|[;|&(){}]+""")   # `" inside "..." is escaped
PS_HERE = re.compile(r"[ \t]*\r?\n")


def requote(word):
    if not re.search(r"\s", word):
        return word
    return "'" + word + "'" if '"' in word else '"' + word + '"'


def words_of(text, powershell):
    if powershell:
        # PowerShell and cmd keep quotes inside a word (-LiteralPath:"C:\a b", "x","y"): one token each, quotes kept
        return PS_TOKEN.findall(ps_unquoted_lines(text))
    text = unquoted_lines(text)
    lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()")
    lex.whitespace_split = True
    lex.commenters = ""                                        # comments were removed by unquoted_lines
    try:
        return list(lex)
    except ValueError:
        # unparseable quoting: parse each separator-delimited piece on its own, so one bad piece cannot hide the
        # others; only the bad piece falls back to whitespace splitting
        words = []
        for piece in re.split(r"(;|&&|\|\||\||&)", text):
            if piece in (";", "&&", "||", "|", "&"):
                words.append(piece)
                continue
            part = shlex.shlex(piece, posix=True, punctuation_chars="()")
            part.whitespace_split = True
            part.commenters = ""
            try:
                words += list(part)
            except ValueError:
                words += piece.split()
        return words


def ps_unquoted_lines(text):
    """PowerShell text with unquoted newlines made `;`, `# ...` line comments and `<# ... #>` blocks removed.
    '...' has no escapes; inside "..." the backtick escapes; `#` starts a comment only at the start of a word."""
    out, quote, i, n = [], None, 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "`" and quote == '"' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch == "<" and text.startswith("<#", i):
            end = text.find("#>", i + 2)
            i = n if end < 0 else end + 2
            continue
        elif ch == "`" and i + 1 < n:
            out.append(ch + text[i + 1])
            i += 2
            continue
        elif ch == "@" and text[i + 1:i + 2] in ("'", '"') and PS_HERE.match(text, i + 2):
            end = text.find("\n" + text[i + 1] + "@", i + 2)   # a here-string is data up to its closing '@ line
            out.append("HERESTRING")
            i = n if end < 0 else end + 3
            continue
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "\n":
            out.append(" ;\t")                                 # (spelt apart from the Bash scanner on purpose)
        elif ch == "#" and (not out or out[-1][-1:] in " \t;&|("):
            nl = text.find("\n", i)                            # a PowerShell line comment ends at its newline
            i = n if nl < 0 else nl
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def unquoted_lines(text):
    """Bash text with each unquoted newline made a `;` and each unquoted `#` comment removed up to its newline.
    Quotes may span lines (python -c "...multi-line..."): inside them nothing changes."""
    out, quote, i, n = [], None, 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch == "\\" and i + 1 < n:
            out.append(ch + text[i + 1])
            i += 2
            continue
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "\n":
            out.append(" ; ")
        elif ch == "#" and (not out or out[-1][-1:] in " \t;&|("):
            while i < n and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


KNOWN_VARS = re.compile(r"\$\{?(HOME|USERPROFILE|LOCALAPPDATA)\}?|\$env:(USERPROFILE|LOCALAPPDATA|HOME)|%(USERPROFILE|LOCALAPPDATA|HOME)%",
                        re.I)


def expand(word, env, assigned):
    """Literal assignments from earlier in the command, then the well-known folders; None if anything else is left."""
    def known(m):
        name = (m.group(1) or m.group(2) or m.group(3)).upper()
        if name == "LOCALAPPDATA":
            return local_appdata(env)
        return env.get(name) or env.get("USERPROFILE") or os.path.expanduser("~")

    for name, value in assigned.items():
        word = re.sub(r"\$\{%s\}|\$%s(?![\w])" % (name, name), lambda m: value, word)
    word = KNOWN_VARS.sub(known, word)
    if any(c in word for c in "$`%"):
        return None
    return word


def resolve(word, cwd, env, assigned, windows_root=False):
    w = expand(word.strip("'\""), env, assigned)
    if not w:
        return None
    if windows_root and w[:1] in ("\\", "/") and w[1:2] not in ("\\", "/") and cwd and re.match(r"^[a-zA-Z]:", cwd):
        w = cwd[:2] + w                                         # PowerShell/cmd: \X is X on the current drive
    if re.match(r"^[a-zA-Z]:([/\\]|$)", w) or w.startswith(("/", "\\", "~")):
        return norm(w)
    if cwd is None:
        return None
    return norm(os.path.join(cwd, w))


def judge_operand(word, cwd, protected, env, assigned, windows_root=False, narrowed=False):
    """The refusal text for one delete operand, or None. narrowed: an -Include/-Filter pattern limits a wildcard."""
    raw = word.strip("'\"").rstrip("/\\") or word.strip("'\"")
    if re.fullmatch(r"[a-zA-Z]:", raw):
        raw += "/"                                              # a bare drive is its root
    cut = re.split(r"[*?\[]", raw, maxsplit=1)
    if len(cut) > 1:                                            # a wildcard: judged by the folder it empties
        folder, pattern = os.path.split(raw)
        if pattern not in ALL_OF or narrowed or any(c in folder for c in "*?["):
            return None
        target = resolve(folder or ".", cwd, env, assigned, windows_root)
    else:
        target = resolve(raw, cwd, env, assigned, windows_root)
    if target is None:
        return None
    what = hit(target, protected)
    return None if what is None else "{} ({})".format(what, target)


def check(payload, env, _depth=0):
    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command") or ""
    powershell = payload.get("tool_name") == "PowerShell"
    cwd = payload.get("cwd") or None
    cwd = norm(cwd) if cwd else None
    return check_text(command, powershell, cwd, env, _depth)


def check_text(command, powershell, cwd, env, depth=0):
    if depth > DEPTH:
        return None
    command = re.sub(r"`\r?\n" if powershell else r"\\\r?\n", " ", command)      # line continuations
    protected = protected_roots(env)
    words = words_of(strip_heredocs(command), powershell)
    segment, assigned = [], {}
    for w in words + [";"]:
        if w in SEPARATORS or (w and set(w) <= set(";&|(){}")):
            if segment:
                cwd, found = judge_segment(segment, cwd, protected, powershell, env, assigned, depth)
                if found:
                    return found
            segment = []
        else:
            segment.append(w)
    return None


def judge_segment(seg, cwd, protected, powershell, env, assigned, depth):
    i = 0
    while i < len(seg):
        word = seg[i]
        m = re.match(r"^([A-Za-z_]\w*)=(.*)$", word)
        if m:
            value = expand(m.group(2), env, assigned)
            if value is not None and len(seg) == 1 + i:
                assigned[m.group(1)] = value                    # `X=...` alone: later words may use $X
            i += 1
            continue
        low = word.lower()
        if low in WRAPPERS:
            i += 1
            while i < len(seg) and (seg[i].startswith("-") or re.match(r"^\d+(\.\d+)?[smhd]?$", seg[i])):
                i += 1                                          # timeout 10, nice -n 19, xargs -0
            continue
        break
    if i >= len(seg):
        return cwd, None
    prog = re.split(r"[/\\]", seg[i].strip("'\""))[-1].lower().lstrip("\\")
    prog = re.sub(r"\.(exe|cmd|bat)$", "", prog)
    args = seg[i + 1:]
    if prog in CHDIR:
        dest = next((a for a in args if not a.startswith("-")), None)
        return (resolve(dest, cwd, env, assigned) if dest else None), None
    if prog in SHELLS or prog in POWERSHELLS or prog == "eval" or prog == "cmd":
        inner = None
        if prog == "eval":
            inner = " ".join(requote(a) for a in args) if len(args) > 1 else (args[0] if args else None)
        else:
            for j, a in enumerate(args):
                low = a.lower()
                takes = (re.fullmatch(r"-[a-z]*c", low) if prog in SHELLS else
                         low in ("-c", "-command", "-commandwithargs") if prog in POWERSHELLS else
                         low in ("/c", "/k", "//c", "//k"))
                if takes and j + 1 < len(args):
                    rest = args[j + 1:]
                    inner = rest[0] if len(rest) == 1 else " ".join(requote(x) for x in rest)
                    if len(rest) == 1 and rest[0][:1] in "\"'" and rest[0][-1:] == rest[0][:1]:
                        inner = rest[0][1:-1]                   # cmd /c "rd /s /q X": the quoted string is the command
                    break
        if inner:
            ps_inner = prog == "cmd" or prog in POWERSHELLS or (powershell and prog == "eval")
            return cwd, check_text(inner, ps_inner, cwd, env, depth + 1)
        return cwd, None
    if prog == "find":
        start = next((a for a in args if not a.startswith("-")), None)
        lows = [a.lower() for a in args]
        deletes = "-delete" in lows or any(x in ("-exec", "-execdir") and j + 1 < len(lows) and
                                           re.split(r"[/\\]", lows[j + 1])[-1] in DESTROYERS
                                           for j, x in enumerate(lows))
        if start and deletes and not FIND_FILTERS & set(lows):
            return cwd, judge_operand(start, cwd, protected, env, assigned)
        return cwd, None
    if prog not in DESTROYERS:
        return cwd, None
    value_flags = {"-path", "-literalpath", "-lp", "-filter", "-include", "-exclude", "-credential"}
    narrowed = False                                            # Remove-Item X\* -Include *.tmp / -Filter *.tmp
    for j, a in enumerate(args):
        flag, _, value = a.lower().partition(":")
        if flag in ("-include", "-filter"):
            parts = [p.strip("'\"") for p in split_list(value or (args[j + 1] if j + 1 < len(args) else ""), True)]
            # every pattern must be a real filter: `*` takes everything, a plain name could be a protected child
            narrowed = narrowed or bool(parts) and all(p not in ALL_OF and any(c in p for c in "*?[") for p in parts)
    skip_next, prev = False, ""
    for a in args:
        if skip_next:
            skip_next = False
            if prev in ("-path", "-literalpath", "-lp"):
                for part in split_list(a, powershell):
                    found = judge_operand(part, cwd, protected, env, assigned, powershell, narrowed)
                    if found:
                        return cwd, found
            continue
        if a == "--":
            continue
        if a.startswith("-") and len(a) > 1 or (a.startswith("/") and len(a) == 2 and prog in ("rd", "rmdir", "del", "erase")):
            flag, _, value = a.partition(":")
            prev = flag.lower()
            if value and prev in ("-path", "-literalpath", "-lp"):        # -LiteralPath:"X"
                for part in split_list(value, powershell):
                    found = judge_operand(part, cwd, protected, env, assigned, powershell, narrowed)
                    if found:
                        return cwd, found
                continue
            skip_next = prev in value_flags and not value
            continue
        for part in split_list(a, powershell):
            found = judge_operand(part, cwd, protected, env, assigned, powershell, narrowed)
            if found:
                return cwd, found
    return cwd, None


def split_list(word, powershell):
    """A PowerShell comma list (`"a","b"`, `a,b`) is several operands; anything else is one."""
    if not powershell:
        return [word]
    parts = re.findall(r'"[^"]*"|\'[^\']*\'|[^,]+', word)
    return [p for p in (x.strip() for x in parts) if p] or [word]


def main():
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace") or "{}")
        reason = check(payload, os.environ)
    except Exception as exc:  # the caller turns a crash into a refusal
        print("delete check failed: {}: {}".format(type(exc).__name__, exc))
        return 1
    if reason:
        print("BLOCKED: this command deletes {}. Nothing can restore that: delete a narrower path instead.".format(reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
