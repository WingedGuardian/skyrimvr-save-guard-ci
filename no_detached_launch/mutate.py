"""One mutant per clause of no-detached-launch.py; each must turn test_no_detached_launch.py red.
The unmutated hook must pass first, and a kill counts only when pytest reports a FAILED test (not a crash)."""
import os, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).parent
SRC = (HERE / "no-detached-launch.py").read_text(encoding="utf-8")
BS = "\\"
M = [
    # names
    ("named-check", "    for m in NAMED.finditer(bare):", "    for m in []:"),
    ("named-needs-use", "        if NAMED_USE.search(bare):", "        if True:"),
    ("named-tilde-skip", "            continue  # flags & ~DETACHED_PROCESS removes it", "            pass"),
    # strings / comments / docstrings
    ("strings-are-prose", "    bare = blank_strings(code)", "    bare = code"),
    ("key-kept", "        return s if KEY.fullmatch(s[1:-1]) else s[0] + blank(s[1:-1]) + s[-1]",
     "        return s[0] + blank(s[1:-1]) + s[-1]"),
    ("python-strings", "    code = python_strings(text) if python else text", "    code = text"),
    # statements
    ("py-key-kept", "        if KEY.fullmatch(s[q + ql:len(s) - ql]):", "        if False:"),
    ("fstring-middles", "        if t.type in MIDDLE_TOKENS:", "        if False:"),
    ("line-comment", "            for k in range(i, j):\n                chars[k] = \" \"", "            for k in []:\n                chars[k] = \" \""),
    ("quote-tracking", "        elif ch in quotes:\n            q = ch", "        elif False:\n            q = ch"),
    ("block-comments", "            block = True\n", "            block = False\n"),
    ("hash-only-hash-langs", 'ch == "#" and style == "hash"', 'ch == "#"'),
    ("batch-rem", r'blank(l) if re.match(r"\s*(?i:rem\s|::)", l) else l', "l"),
    ("comment-style-slash", '    if low_path.endswith(SLASH_FILES):\n        return "slash"', '    if False:\n        return "slash"'),
    ("inline-script", "    for m in INLINE.finditer(plain):", "    for m in []:"),
    ("inline-bound-to-interp", r"""|/[a-z]))*?\s+"
                    r"(?:-\w*c""", r"""|/[a-z]))*?.*?\s+"
                    r"(?:-\w*c"""),
    ("quoted-newline-not-a-cut", '    bare = QUOTED_ML.sub(lambda m: "x" * len(m.group(0)), command)',
     '    bare = QUOTED_ML.sub(lambda m: blank(m.group(0)), command)'),
    ("option-values", r"""(?:\s+(?![-/\"'])[^\s\"';|&]+)?""", ""),
    ("combined-c-flags", r"(?:-\w*c|-e|", r"(?:-c|-e|"),
    ("nested-shells","        if depth < 3:", "        if False:"),
    ("quoted-written-to-code", "    for seg in segments(plain):", "    for seg in []:"),
    ("writes-per-segment", "    for seg in segments(plain):", "    for seg in [plain]:"),
    ("shell-files", "    shell_file = low.endswith(SHELL_FILES)", "    shell_file = False"),
    ("replace-all-shift-count", "a + delta * sum(h < a for h in hits), b + delta * sum(h < a for h in hits)", "a + (delta if a > hits[0] else 0), b + (delta if a > hits[0] else 0)"),
    ("window-after-tokenize", "    code = python_strings(text) if python else text\n    code = strip_comments(code, style)\n    if spans:\n        code = window(code, spans)",
     "    code = window(text, spans) if spans else text\n    code = python_strings(code) if python else code\n    code = strip_comments(code, style)"),
    ("depth-ignores-strings", "        bare = blank_strings(line)", "        bare = line"),
    ("join-brackets", "        joins = depth > 0 or bare.rstrip()", "        joins = False or bare.rstrip()"),
    ("join-trailing", '        joins = depth > 0 or bare.rstrip().endswith(("|", "' + BS + BS + '")) or nxt',
     "        joins = depth > 0 or nxt"),
    ("join-leading-or", 'or nxt.startswith("|") and not nxt.startswith("||")', "or False"),
    ("max-join", "        if joins and idx + 1 < len(lines) and n < MAX_JOIN:", "        if joins and idx + 1 < len(lines):"),
    # flag values
    ("flags-expression", "    for expr in flag_values(bare):", "    for expr in []:"),
    ("flags-dict-key", 'flags[' + BS + '"\'' + BS + ']]*' + BS + 's*(?:', 'flags' + BS + 's*(?:'),
    ("flag-value-stops-at-comma", '            elif ch in ",;" and depth == 0:', "            elif False:"),
    ("flag-value-stops-at-line", '            elif ch == "' + BS + 'n" and depth == 0 and not (', "            elif False and not ("),
    ("flag-value-backslash", 'bare[m.end():i].rstrip().endswith(("|", "' + BS + BS + '"))', 'bare[m.end():i].rstrip().endswith(("|",))'),
    ("literal-tilde-skip", "            if neg:\n                continue", "            if False:\n                continue"),
    ("leading-zero", '                value = int(lit, 10) if re.fullmatch(r"0' + BS + 'd+", lit) else int(lit, 0)',
     "                value = int(lit, 0)"),
    ("upper-bound", "            if value >= 0x100000000:\n                continue", "            if False:\n                continue"),
    ("node-detached", "    return bool(NODE_DETACHED.search(bare))", "    return False"),
    # shell
    ("heredoc-interp", "        if INTERP.search(header) or WRITES_CODE.search(header):", "        if WRITES_CODE.search(header):"),
    ("heredoc-code-file", "        if INTERP.search(header) or WRITES_CODE.search(header):", "        if INTERP.search(header):"),
    ("heredoc-body-not-plain", "        pos = end.end() if end else len(command)", "        pos = nl + 1"),
    ("herestring-judged", "        if INTERP.search(tail) or WRITES_CODE.search(tail):", "        if False:"),
    ("quotes-blanked", "    out.append(QUOTED_ML.sub(\"''\", plain))", "    out.append(plain)"),
    ("quotes-span-lines", "    out.append(QUOTED_ML.sub(\"''\", plain))", "    out.append(QUOTED.sub(\"''\", plain))"),
    ("list-command", '            command = " ".join(map(str, command))', "            command = None"),
    # edits
    ("edit-in-context", "    done = after_edits(path, edits)", "    done = None"),
    ("span-limit", "        if spans and not any(s < b + 1 and e > a for a, b in spans):", "        if False:"),
    ("replace-all-sites", '            if not e.get("replace_all"):\n                break', "            break"),
    ("crlf-normalised", 'text = f.read().replace("' + BS + 'r' + BS + 'n", "' + BS + 'n")', "text = f.read()"),
    ("edits-in-order", '        text = text.replace(old, new) if e.get("replace_all") else text[:hits[0]] + new + text[hits[0] + len(old):]',
     "        text = text"),
    # tools and paths
    ("bash-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("PowerShell", "Monitor"):'),
    ("powershell-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("Bash", "Monitor"):'),
    ("monitor-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("Bash", "PowerShell"):'),
    ("write-covered", '    if tool == "Write":', '    if tool == "WriteX":'),
    ("notebook-covered", '    if tool == "NotebookEdit":', '    if tool == "NotebookEditX":'),
    ("multiedit-covered", '    edits = [inp] if tool == "Edit" else [e for e in (inp.get("edits") or []) if isinstance(e, dict)]',
     '    edits = [inp] if tool == "Edit" else []'),
    ("code-files-only", "    if not low.endswith(CODE_FILES) or", "    if False or"),
    ("self-needs-packet-dir", '(path.rsplit("/", 1)[-1] in SELF and "no_detached_launch/" in path)', '(path.rsplit("/", 1)[-1] in SELF)'),
    ("backslash-paths", 'or "").replace("' + BS + BS + '", "/")', 'or "")'),
    ("lowercase-ext", "    low = path.lower()", "    low = path"),
    # protocol
    ("bom-read", 'raw.decode("utf-8-sig", "replace")', 'raw.decode("utf-8", "replace")'),
    ("heartbeat", '            heartbeat("no-detached-launch" if isinstance(payload, dict) else "no-detached-launch.blind", len(raw))',
     "            pass"),
    ("blind-marker", '                heartbeat("no-detached-launch.blind", len(raw))', '                heartbeat("no-detached-launch", len(raw))'),
    ("deny-printed", '    print(json.dumps({"hookSpecificOutput"', '    0 and print(json.dumps({"hookSpecificOutput"'),
    ("fix-named", "creationflags=CREATE_NO_WINDOW (0x08000000)", "creationflags=hidden"),
]


def pytest_in(d):
    # cwd=d + the file by name: on the Windows runner `pytest <tempdir>` collected nothing ("no tests ran")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_no_detached_launch.py"],
                          capture_output=True, text=True, cwd=d)


with tempfile.TemporaryDirectory() as d:
    shutil.copy(HERE / "test_no_detached_launch.py", d)
    shutil.copy(HERE / "no-detached-launch.py", d)
    base = pytest_in(d)
    if base.returncode != 0:
        print(base.stdout[-2000:])
        sys.exit("baseline is not green: no mutant result means anything")
# f-string literal tokens exist only on Python 3.12+: that mutant is equivalent (unkillable) on an older hook Python.
HOOK_PY = os.environ.get("HOOK_PYTHON", "").split() or [sys.executable]
has_fstring_tokens = subprocess.run(HOOK_PY + ["-c", "import tokenize,sys; sys.exit(0 if hasattr(tokenize, 'FSTRING_MIDDLE') else 1)"],
                                    capture_output=True).returncode == 0
if not has_fstring_tokens:
    M = [m for m in M if m[0] != "fstring-middles"]
    print("hook Python has no f-string tokens: fstring-middles skipped")
bad = [name for name, a, b in M if SRC.count(a) != 1]
if bad:
    sys.exit("mutant targets not found exactly once: " + ", ".join(bad))
survivors = []
for name, a, b in M:
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(HERE / "test_no_detached_launch.py", d)
        (Path(d) / "no-detached-launch.py").write_text(SRC.replace(a, b), encoding="utf-8")
        r = pytest_in(d)
        killed = r.returncode == 1 and " failed" in r.stdout
        print(("killed   " if killed else "SURVIVED ") + name)
        if not killed:
            survivors.append(name)
print("{} mutants, {} survived".format(len(M), len(survivors)))
sys.exit(1 if survivors else 0)
