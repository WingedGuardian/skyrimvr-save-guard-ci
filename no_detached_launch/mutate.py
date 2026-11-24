"""One mutant per clause of no-detached-launch.py; each must turn test_no_detached_launch.py red.
The unmutated hook must pass first, and a kill counts only when pytest reports a FAILED test (not a crash)."""
import shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).parent
SRC = (HERE / "no-detached-launch.py").read_text(encoding="utf-8")
M = [
    ("named-check", "    for m in NAMED.finditer(bare):", "    for m in []:"),
    ("named-needs-use", "        if NAMED_USE.search(bare):", "        if True:"),
    ("named-tilde-skip", "            continue  # flags & ~DETACHED_PROCESS removes it", "            pass"),
    ("strings-are-prose", """    bare = QUOTED.sub("''", code)""", "    bare = code"),
    ("flag-value-stops-at-comma", '            elif ch in ",;" and depth == 0:', '            elif False:'),
    ("flag-value-stops-at-line", '            elif ch == "\\n" and depth == 0 and not (', '            elif False and not ('),
    ("depth-ignores-strings", """        unquoted = QUOTED.sub("''", code)""", "        unquoted = code"),
    ("flags-expression", "    for expr in flag_values(code):", "    for expr in []:"),
    ("hidden-console-name", '        if hidden_console and m.group(0).endswith("CREATE_NEW_CONSOLE"):', "        if False:"),
    ("upper-bound", "            if value >= 0x100000000:\n                continue", "            if False:\n                continue"),
    ("new-console-bit", "            if value & 0x8 or value & 0x10 and not hidden_console:", "            if value & 0x8:"),
    ("hidden-console-literal", "            if value & 0x8 or value & 0x10 and not hidden_console:", "            if value & 0x8 or value & 0x10:"),
    ("hidden-console-not-detached", "            if value & 0x8 or value & 0x10 and not hidden_console:", "            if value & 0x10 and not hidden_console:"),
    ("flags-dict-key", 'flags[\\"\'\\]]*\\s*(?:', 'flags\\s*(?:'),
    ("literal-tilde-skip", "            if neg:\n                continue", "            if False:\n                continue"),
    ("leading-zero", '                value = int(lit, 10) if re.fullmatch(r"0\\d+", lit) else int(lit, 0)',
     "                value = int(lit, 0)"),
    ("node-detached", "    return bool(NODE_DETACHED.search(code))", "    return False"),
    ("comment-cut", "            return line[:i]", "            pass"),
    ("batch-rem", "    if batch and re.match(", "    if False and re.match("),
    ("quote-tracking", "        elif ch in \"'\\\"\":\n            q = ch", "        elif False:\n            q = ch"),
    ("docstrings", "        text = drop_docstrings(text)", "        pass"),
    ("join-brackets", "        if depth > 0 or code.rstrip()", "        if False or code.rstrip()"),
    ("join-trailing-or", 'code.rstrip().endswith(("|", "\\\\"))', 'code.rstrip().endswith(("\\\\",))'),
    ("span-limit", "        if span and (e <= span[0] or s > span[1]):", "        if False:"),
    ("edit-in-context", "        done = after_edit(", "        done = None and after_edit("),
    ("heredoc-interp", "        if INTERP.search(header) or CODE_TARGET.search(header):", "        if CODE_TARGET.search(header):"),
    ("heredoc-code-file", "        if INTERP.search(header) or CODE_TARGET.search(header):", "        if INTERP.search(header):"),
    ("heredoc-body-not-plain", "        pos = end.end() if end else len(command)", "        pos = nl + 1"),
    ("inline-script", '        if INTERP.search(plain[:m.start()].split("\\n")[-1]):', "        if False:"),
    ("quotes-blanked", "    out.append(blanked)", "    out.append(plain)"),
    ("list-command", '            command = " ".join(map(str, command))', "            command = None"),
    ("bash-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("PowerShell", "Monitor"):'),
    ("powershell-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("Bash", "Monitor"):'),
    ("monitor-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("Bash", "PowerShell"):'),
    ("write-covered", '    if tool == "Write":', '    if tool == "WriteX":'),
    ("notebook-covered", '    if tool == "NotebookEdit":', '    if tool == "NotebookEditX":'),
    ("multiedit-covered", '    edits = [inp] if tool == "Edit" else [e for e in (inp.get("edits") or []) if isinstance(e, dict)]',
     '    edits = [inp] if tool == "Edit" else []'),
    ("code-files-only", "    if not low.endswith(CODE_FILES) or", "    if False or"),
    ("self-needs-packet-dir", '(path.rsplit("/", 1)[-1] in SELF and "no_detached_launch/" in path)', '(path.rsplit("/", 1)[-1] in SELF)'),
    ("backslash-paths", 'or "").replace("\\\\", "/")', 'or "")'),
    ("lowercase-ext", "    low = path.lower()", "    low = path"),
    ("bom-read", 'raw.decode("utf-8-sig", "replace")', 'raw.decode("utf-8", "replace")'),
    ("heartbeat", "            heartbeat(len(raw))", "            pass"),
    ("deny-printed", '    print(json.dumps({"hookSpecificOutput"', '    0 and print(json.dumps({"hookSpecificOutput"'),
    ("fix-named", "creationflags=CREATE_NO_WINDOW (0x08000000)", "creationflags=hidden"),
]


def pytest_in(d):
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", d],
                          capture_output=True, text=True)


with tempfile.TemporaryDirectory() as d:
    shutil.copy(HERE / "test_no_detached_launch.py", d)
    shutil.copy(HERE / "no-detached-launch.py", d)
    base = pytest_in(d)
    if base.returncode != 0:
        print(base.stdout[-2000:])
        sys.exit("baseline is not green: no mutant result means anything")
survivors = []
for name, a, b in M:
    assert SRC.count(a) == 1, (name, SRC.count(a))
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
