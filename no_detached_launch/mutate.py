"""One mutant per clause of no-detached-launch.py; each must turn test_no_detached_launch.py red."""
import shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).parent
SRC = (HERE / "no-detached-launch.py").read_text(encoding="utf-8")
M = [
    ("named-constant", "        if NAMED.search(code) and NAMED_USE.search(code):", "        if False:"),
    ("flags-expression", "        for expr in FLAGS.findall(code):", "        for expr in []:"),
    ("bit-test", "                if value & 0x8 and value < 0x100000000:", "                if value == 8:"),
    ("comment-cut", "    return line[:m.start()] if m else line", "    return line"),
    ("bash-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("PowerShell", "Monitor"):'),
    ("powershell-covered", '    if tool in ("Bash", "PowerShell", "Monitor"):', '    if tool in ("Bash", "Monitor"):'),
    ("write-covered", '    elif tool == "Write":', '    elif tool == "WriteX":'),
    ("edit-covered", '    elif tool == "Edit":', '    elif tool == "EditX":'),
    ("multiedit-covered", '    elif tool == "MultiEdit":', '    elif tool == "MultiEditX":'),
    ("notebook-covered", '    elif tool == "NotebookEdit":', '    elif tool == "NotebookEditX":'),
    ("decimal-literal", r'LITERAL = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)(?![\w.])")',
     r'LITERAL = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+)(?![\w.])")'),
    ("deny-printed", '    print(json.dumps({"hookSpecificOutput"', '    0 and print(json.dumps({"hookSpecificOutput"'),
    ("named-needs-use", "        if NAMED.search(code) and NAMED_USE.search(code):", "        if NAMED.search(code):"),
    ("named-use-or", r'DETACHED_PROCESS\s*(?<!\\)\||(?<!\\)\|\s*[\w.]*DETACHED_PROCESS")', r'XX")'),
    ("code-files-only", "    if path and (not path.lower().endswith(CODE_FILES) or", "    if path and (False or"),
    ("code-files-checked", "        return  # notes and docs", "        pass  # notes and docs"),
    ("self-needs-packet-dir", '(path.rsplit("/", 1)[-1] in SELF and "/no_detached_launch/" in path)', '(path.rsplit("/", 1)[-1] in SELF)'),
    ("fix-named", 'creationflags=CREATE_NO_WINDOW (0x08000000)', 'creationflags=hidden'),
]
survivors = []
for name, a, b in M:
    assert SRC.count(a) == 1, (name, SRC.count(a))
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(HERE / "test_no_detached_launch.py", d)
        (Path(d) / "no-detached-launch.py").write_text(SRC.replace(a, b), encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", d],
                           capture_output=True, text=True)
        killed = r.returncode != 0
        print(("killed   " if killed else "SURVIVED ") + name)
        if not killed:
            survivors.append(name)
sys.exit(1 if survivors else 0)
