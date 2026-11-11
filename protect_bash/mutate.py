"""One mutant per guarded clause of protect-bash-deletes.py; each must turn test_protect_bash_deletes.py red."""
import shutil, subprocess, sys, tempfile
from pathlib import Path
HERE = Path(__file__).parent
SRC = (HERE / 'protect-bash-deletes.py').read_text(encoding='utf-8')
M = [
    ('ancestor', '            if os.path.commonpath([target, root]) == target:', '            if False:'),
    ('exact-root', '        if target == root:\n            return what', '        if False:\n            return what'),
    ('inside-vault', '            if os.path.commonpath([target, root]) == root:', '            if False:'),
    ('wildcard-empties', '        if pattern not in ALL_OF or', '        if True or'),
    ('cd-tracked', '        return (resolve(dest, cwd, env, assigned) if dest else None), None', '        return cwd, None'),
    ('find-delete', '        if start and deletes and not FIND_FILTERS & set(lows):', '        if False:'),
    ('find-filter-allows', '        if start and deletes and not FIND_FILTERS & set(lows):', '        if start and deletes:'),
    ('find-exec-rm', '        deletes = "-delete" in lows or any(', '        deletes = "-delete" in lows or False and any('),
    ('heredoc-strip', '    words = words_of(strip_heredocs(command), powershell)', '    words = words_of(command, powershell)'),
    ('unknown-not-guessed', '    if cwd is None:\n        return None', '    if cwd is None:\n        cwd = "C:/GOG Games/The Elder Scrolls V Skyrim VR"'),
    ('wrappers-skipped', '        if low in WRAPPERS:', '        if False:'),
    ('wrapper-args-skipped', "            while i < len(seg) and (seg[i].startswith(\"-\") or re.match(r\"^\\d+(\\.\\d+)?[smhd]?$\", seg[i])):",
     '            while False:'),
    ('continuations-joined', '    command = re.sub(r"`\\r?\\n" if powershell else r"\\\\\\r?\\n", " ", command)      # line continuations',
     '    pass'),
    ('ps-path-value', '            if prev in ("-path", "-literalpath", "-lp"):', '            if False:'),
    ('ps-colon-value', '            if value and prev in ("-path", "-literalpath", "-lp"):        # -LiteralPath:"X"', '            if False:'),
    ('ps-comma-list', '    parts = re.findall(r\'"[^"]*"|\\\'[^\\\']*\\\'|[^,]+\', word)', '    parts = [word]'),
    ('ps-tokens-keep-quotes', '        return PS_TOKEN.findall(ps_unquoted_lines(text))', '        return ps_unquoted_lines(text).split()'),
    ('shell-c-judged', '            return cwd, check_text(inner, ps_inner, cwd, env, depth + 1)', '            return cwd, None'),
    ('assignment-remembered', '                assigned[m.group(1)] = value                    # `X=...` alone: later words may use $X', '                pass'),
    ('known-vars', '    word = KNOWN_VARS.sub(known, word)', '    pass'),
    ('saves-protected', '        roots[norm(os.path.join(value, "Saves"))] = "a Saves folder"', '        pass'),
    ('save-backups-protected', '                              (os.path.join("backups", "save-backups"), "the old save-backup store"),', ''),
    ('comment-ends-at-newline', '            while i < n and text[i] != "\\n":', '            while i < n:'),
    ('newline-separates', '            out.append(" ; ")', '            out.append(" ")'),
    ('quote-spans-lines', '            i += 2\n            continue\n        elif ch in "\'\\"":\n            quote = ch\n            out.append(ch)\n        elif ch == "\\n":\n            out.append(" ; ")',
     '            i += 2\n            continue\n        elif False:\n            quote = ch\n            out.append(ch)\n        elif ch == "\\n":\n            out.append(" ; ")'),
    ('ps-quote-tracked', '        elif ch in "\'\\"":\n            quote = ch\n            out.append(ch)\n        elif ch == "\\n":\n            out.append(" ;\\t")',
     '        elif False:\n            quote = ch\n            out.append(ch)\n        elif ch == "\\n":\n            out.append(" ;\\t")'),
    ('fallback-per-piece', '            try:\n                words += list(part)\n            except ValueError:\n                words += piece.split()',
     '            words += piece.split()'),
    ('cmd-double-slash', 'low in ("/c", "/k", "//c", "//k"))', 'low in ("/c", "/k"))'),
    ('powershell-command', '                         low in ("-c", "-command", "-commandwithargs") if prog in POWERSHELLS else',
     '                         False if prog in POWERSHELLS else'),
    ('shell-flag-cluster', '                takes = (re.fullmatch(r"-[a-z]*c", low) if prog in SHELLS else',
     '                takes = (low == "-c" if prog in SHELLS else'),
    ('trailing-slash', '    raw = word.strip("\'\\"").rstrip("/\\\\") or word.strip("\'\\"")', '    raw = word.strip("\'\\"")'),
    ('bare-drive-root', '        raw += "/"                                              # a bare drive is its root', '        pass'),
    ('drive-less-path', '        w = cwd[:2] + w                                         # PowerShell/cmd: \\X is X on the current drive', '        pass'),
    ('ps-comments-stripped', '        return PS_TOKEN.findall(ps_unquoted_lines(text))', '        return PS_TOKEN.findall(text.replace("\\n", " ; "))'),
    ('ps-block-comment', '        elif ch == "<" and text.startswith("<#", i):', '        elif False:'),
    ('here-string-not-heredoc', 'HEREDOC = re.compile(r"(?<!<)<<(?!<)-?', 'HEREDOC = re.compile(r"<<-?'),
    ('ps-here-string', '        elif ch == "@" and text[i + 1:i + 2] in ("\'", \'"\') and PS_HERE.match(text, i + 2):', '        elif False:'),
    ('ps-here-string-ends', '            i = n if end < 0 else end + 3\n', '            i = n\n'),
    ('ps-backtick-in-string', '(?:"(?:[^"`]|`[\\s\\S])*"|', '(?:"[^"]*"|'),
    ('ps-hash-word-start', '        elif ch == "#" and (not out or out[-1][-1:] in " \\t;&|("):\n            nl = text.find',
     '        elif ch == "#":\n            nl = text.find'),
    ('include-narrows', '            narrowed = narrowed or bool(parts) and all(', '            narrowed = narrowed or False and all('),
    ('include-star-is-all', 'all(p not in ALL_OF and any(c in p for c in "*?[") for p in parts)', 'all(any(c in p for c in "*?[") for p in parts)'),
    ('include-plain-name', 'all(p not in ALL_OF and any(c in p for c in "*?[") for p in parts)', 'all(p not in ALL_OF for p in parts)'),
    ('include-every-part', 'all(p not in ALL_OF and any(c in p for c in "*?[") for p in parts)', 'any(p not in ALL_OF and any(c in p for c in "*?[") for p in parts)'),
    ('exclude-never-narrows', '        if flag in ("-include", "-filter"):', '        if flag in ("-include", "-filter", "-exclude"):'),
    ('codex-shell-override', ' or env.get("PROTECT_BASH_SHELL") == "powershell"', ''),
    ('vault-protected', '    inside[norm(os.path.join(local_appdata(env), "modding-agent-harness", "save-vault"))] = "the save vault"', '    pass'),
]
surv = []
for name, a, r in M:
    assert SRC.count(a) == 1, (name, SRC.count(a))
    d = Path(tempfile.mkdtemp(prefix='pbmut-', dir=HERE))
    (d / 'protect-bash-deletes.py').write_text(SRC.replace(a, r), encoding='utf-8')
    shutil.copy(HERE / 'test_protect_bash_deletes.py', d)
    res = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '-x', str(d / 'test_protect_bash_deletes.py')],
                         capture_output=True, text=True, cwd=d)
    print('%-24s %s' % (name, 'killed' if res.returncode == 1 else 'SURVIVED (rc %d)' % res.returncode))
    if res.returncode != 1:
        surv.append(name)
    shutil.rmtree(d, ignore_errors=True)
print('survivors:', surv)
sys.exit(1 if surv else 0)
