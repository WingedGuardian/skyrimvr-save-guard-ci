"""protect-bash-deletes.py: what must still be refused, and what the old word rule refused that must now pass.
Decision only: no command here is run."""
import importlib.util
import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pbd", HERE / "protect-bash-deletes.py")
pbd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pbd)

G = "C:/GOG Games/The Elder Scrolls V Skyrim VR"
GW = G.replace("/", "\\")
HOME = os.path.expanduser("~").replace("\\", "/")
CFG = HOME + "/Documents/My Games/Skyrim VR"
ENV = {"INSTALL_ROOT": "/c/GOG Games/The Elder Scrolls V Skyrim VR", "INSTALL_ROOT_WIN": G,
       "LOCALAPPDATA": HOME + "/AppData/Local"}


def windows_spelling(cmd, tool):
    """A PowerShell command with backslash paths is a Windows spelling: os.path on another OS does not split it.
    The hook is deployed on Windows; elsewhere these cases are skipped, not judged."""
    if os.name != "nt" and tool == "PowerShell" and "\\" in cmd:
        pytest.skip("Windows path spelling")


def judge(cmd, tool="Bash", cwd="C:/Temp"):
    return pbd.check({"tool_name": tool, "tool_input": {"command": cmd}, "cwd": cwd}, ENV)


REFUSE = [
    ('rm -rf "%s"' % G, "Bash", None),
    ("rm -rf /c/GOG\\ Games/The\\ Elder\\ Scrolls\\ V\\ Skyrim\\ VR", "Bash", None),
    ('rm -r -f "%s"' % G, "Bash", None),
    ('rm --recursive --force -- "%s/Data"' % G, "Bash", None),
    ('cd "%s" && rm -rf .' % G, "Bash", None),
    ('cd "%s" && rm -rf *' % G, "Bash", None),
    ('cd "%s"; rm -rf Data' % G, "Bash", None),
    ('rm -rf "%s/Data/"*' % G, "Bash", None),
    ('rmdir /s /q "%s"' % GW, "Bash", None),
    ('del /f /s /q "%s\\Data"' % GW, "Bash", None),
    ('Remove-Item -Recurse -Force "%s\\Data"' % GW, "PowerShell", None),
    ("Remove-Item -LiteralPath '%s\\Saves' -Recurse" % CFG.replace("/", "\\"), "PowerShell", None),
    ('rm -rf "%s"' % CFG, "Bash", None),
    ('rm -rf "%s/Saves"' % CFG, "Bash", None),
    ('rm -rf "C:/GOG Games"', "Bash", None),
    ("rm -rf C:/", "Bash", None),
    ("rm -rf ~/Documents", "Bash", None),
    ('rm -rf "%s/.claude/backups"' % G, "Bash", None),
    ('rm -rf "%s/AppData/Local/modding-agent-harness/save-vault"' % HOME, "Bash", None),
    ("rm -rf Data", "Bash", G),                               # relative, resolved against the payload's cwd
    ("sudo rm -rf Data", "Bash", G),
]
ALLOW = [
    'rm -rf "$T"',
    'rm -rf "$S/pex" 2>/dev/null',
    "git rm -q --cached .claude/install-profile.md",
    "python - <<'EOF'\ndel data['openrouter']['endpoint']\nEOF",
    'echo "rm -rf %s"' % G,
    'grep -n "rm -rf" "%s/CLAUDE.md"' % G,
    'rm -f "%s/Data/foo.esp.bak"' % G,
    'rm -rf "%s/Data/Meshes/temp-export"' % G,
    'rm -f "%s/Saves/Save1.ess"' % CFG,                     # one save: the vault keeps it
    "rm -rf C:/Temp/hc212/root",
    'rm -rf "%s/_CLAUDE_OUTPUT/x/__pycache__"' % G,
    'cd "%s" && rm -f tools/.vr-headless-state/x.sha256' % G,
    'rm -rf "%s/Data/"*.tmp' % G,                           # a narrow wildcard empties nothing
    "rm -rf $(cygpath -w \"$S\")",
    "cat > x.sh <<'E'\nrm -rf \"%s\"\nE" % G,               # heredoc body handed to cat is data
]


@pytest.mark.parametrize("cmd,tool,cwd", REFUSE)
def test_still_refused(cmd, tool, cwd):
    windows_spelling(cmd, tool)
    assert judge(cmd, tool, cwd or "C:/Temp"), cmd


@pytest.mark.parametrize("cmd", ALLOW)
def test_no_longer_refused(cmd):
    assert judge(cmd) is None, cmd


def test_an_unknown_cwd_never_guesses():
    assert pbd.check({"tool_name": "Bash", "tool_input": {"command": "rm -rf Data"}}, ENV) is None


def test_the_reason_names_what_would_be_lost():
    assert judge('rm -rf "%s"' % G).startswith("the game install (")
    assert judge('rm -rf "C:/GOG Games"').startswith("a folder holding the game install")


def test_a_heredoc_fed_to_a_shell_is_judged():
    assert judge("bash <<'E'\nrm -rf \"%s\"\nE" % G)


# ---- review 2026-11-10 (BLOCK): the cheap, no-false-positive shapes the simple rule now covers

GW_DATA = GW + "\\Data"
MORE_REFUSE = [
    ('rm -rf \\\n  "%s"' % G, "Bash", None),                                  # line continuation
    ('if true; then rm -rf "%s"; fi' % G, "Bash", None),
    ('while false; do rm -rf "%s"; done' % G, "Bash", None),
    ('! rm -rf "%s"' % G, "Bash", None),
    ('timeout 10 rm -rf "%s"' % G, "Bash", None),
    ('nice -n 19 rm -rf "%s"' % G, "Bash", None),
    ('find "%s" -maxdepth 0 -exec rm -rf {} +' % G, "Bash", None),
    ('find "%s/Data" -mindepth 1 -exec rm -rf {} +' % G, "Bash", None),
    ('Remove-Item -LiteralPath:"%s" -Recurse' % GW, "PowerShell", None),
    ('Remove-Item -Path:"%s" -Recurse' % GW, "PowerShell", None),
    ('Remove-Item "C:\\Temp\\x","%s" -Recurse' % GW, "PowerShell", None),
    ('cmd /c rd /s /q "%s"' % GW, "Bash", None),
    ('cmd /c rd /s /q "%s"' % GW_DATA, "PowerShell", None),
    ('cmd.exe /c rd /s /q "%s"' % GW, "Bash", None),
    ('bash -c "rm -rf \'%s\'"' % G, "Bash", None),
    ("sh -c 'rm -rf \"%s\"'" % G, "Bash", None),
    ('eval "rm -rf \'%s\'"' % G, "Bash", None),
    ('rm -rf "%s/.claude/backups/save-backups"' % G, "Bash", None),
    ('rm -rf "%s/.claude/backups/kb"' % G, "Bash", None),
    ('rm -rf "%s/AppData/Local/modding-agent-harness/save-vault/skyrim/store"' % HOME, "Bash", None),
    ('rm -rf "$HOME/Documents/My Games/Skyrim VR"', "Bash", None),
    ('Remove-Item "$env:USERPROFILE\\Documents\\My Games\\Skyrim VR" -Recurse', "PowerShell", None),
    ('G="%s"; rm -rf "$G"' % G, "Bash", None),
    ('G="%s"; rm -rf "${G}/Data"' % G, "Bash", None),
]
MORE_ALLOW = [
    "grep -n \"shutil.rmtree('%s')\" notes.md" % G,                          # mentions are never refused
    "git commit -m \"guard: refuse shutil.rmtree('%s')\"" % G,
    "cat > t.py <<'E'\nimport shutil\nshutil.rmtree('%s/Data')\nE" % G,
    'find "%s" -name "*.tmp" -delete' % G,                                   # a filter narrows it
    'find "%s/Data" -name "*.bak" -type f -delete' % G,
    'rm -rf "%s/.claude/backups/snap-123"' % G,                              # disposable per-task snapshot
    'X="C:/Temp/scratch"; rm -rf "$X"',
    'rm -rf "$SOMETHING_ELSE/Data"',                                         # unknown variable: never guessed
]


@pytest.mark.parametrize("cmd,tool,cwd", MORE_REFUSE)
def test_review_shapes_are_refused(cmd, tool, cwd):
    windows_spelling(cmd, tool)
    assert judge(cmd, tool, cwd or "C:/Temp"), cmd


@pytest.mark.parametrize("cmd", MORE_ALLOW)
def test_review_shapes_still_allowed(cmd):
    assert judge(cmd) is None, cmd


# ---- re-review round 2 (BLOCK): comments, more shells, unquoted ${X}, trailing slash, drive-less paths

ROUND2_REFUSE = [
    ('# cleanup\nrm -rf "%s"' % G, "Bash", None),
    ('echo hi # note\nrm -rf "%s/Data"' % G, "Bash", None),
    ('set -e\n# step 2: remove\nrm -rf "%s/Data"' % G, "Bash", None),
    ('cmd //c rd //s //q "%s"' % GW, "Bash", None),
    ('powershell -Command "Remove-Item -Recurse \'%s\'"' % GW, "Bash", None),
    ('pwsh -c "Remove-Item -Recurse \'%s\'"' % GW, "PowerShell", None),
    ('bash -lc "rm -rf \'%s\'"' % G, "Bash", None),
    ('bash -ec "rm -rf \'%s\'"' % G, "Bash", None),
    ('X="%s"; rm -rf ${X}' % G, "Bash", None),
    ("rm -rf ${HOME}/Documents/My\\ Games/Skyrim\\ VR", "Bash", None),
    ('rm -rf "%s/Data/"*/' % G, "Bash", None),
    ('Remove-Item "%s\\Data\\*\\" -Recurse' % GW, "PowerShell", None),
    ("Remove-Item \\ -Recurse -Force", "PowerShell", None),
    ('Remove-Item "\\GOG Games\\The Elder Scrolls V Skyrim VR" -Recurse', "PowerShell", None),
    ("echo $'it\\'s'; rm -rf \"%s\"" % G, "Bash", None),
]
ROUND2_ALLOW = [
    "# rm -rf \"%s\"\necho just a note" % G,                    # a comment is never a command
    "rm -f /c/Temp/x.txt; echo $'a\\'b'; ls \"$LOCALAPPDATA/modding-agent-harness/save-vault\"",
    "pwsh -c \"Remove-Item -Recurse $env:TEMP\\build\"",
    "cmd //c del //q C:\\Temp\\x.txt",
    "bash -lc 'rm -rf /tmp/scratch'",
]


@pytest.mark.parametrize("cmd,tool,cwd", ROUND2_REFUSE)
def test_round2_shapes_are_refused(cmd, tool, cwd):
    windows_spelling(cmd, tool)
    assert judge(cmd, tool, cwd or "C:/Temp"), cmd


@pytest.mark.parametrize("cmd", ROUND2_ALLOW)
def test_round2_shapes_still_allowed(cmd):
    assert judge(cmd) is None, cmd


def test_a_quoted_string_spanning_lines_is_data():
    """2026-11-10 replay: a multi-line python -c "..." whose code held test strings naming a delete."""
    cmd = 'python -c "\nfor c in [\\"Remove-Item C:/GOG\\"]:\n    print(c)\nrm -rf C:/\n"'
    assert judge(cmd) is None


def test_a_hash_inside_quotes_is_not_a_comment():
    assert judge('echo "step # 2"; rm -rf "%s"' % G)


# ---- confirmation review round 3: PowerShell comments, here-strings

def test_a_powershell_comment_is_never_an_operand():
    assert judge('Remove-Item C:\\Temp\\x  # not "%s"' % GW, "PowerShell") is None
    assert judge('<#\nRemove-Item -Recurse "%s"\n#>\nGet-Date' % GW, "PowerShell") is None


def test_a_powershell_comment_does_not_hide_the_next_line():
    assert judge("Get-Date # it's\nRemove-Item -Recurse '%s'" % GW, "PowerShell")


def test_a_hash_inside_powershell_quotes_is_not_a_comment():
    assert judge('Write-Host "step # 2"; Remove-Item -Recurse "%s"' % GW, "PowerShell")


def test_a_here_string_is_not_a_heredoc():
    assert judge('grep -q foo <<< bar\nrm -rf "%s"' % G)


# ---- confirmation review round 4 (APPROVE, LOW findings): here-strings, `" in a string, -Include/-Filter

def test_a_powershell_here_string_is_data():
    body = "$s = @'\nDon't run this:\nRemove-Item -Recurse '%s'\n'@\nSet-Content C:\\Temp\\n.txt $s" % GW
    assert judge(body, "PowerShell") is None


def test_a_powershell_here_string_does_not_hide_what_follows():
    assert judge("@'\nit's\n'@ | Set-Content C:\\Temp\\x; Remove-Item -Recurse '%s'" % GW, "PowerShell")
    assert judge('$s = @"\nsay "hi\n"@\nRemove-Item -Recurse "%s"' % GW, "PowerShell")


def test_a_backtick_quote_inside_a_powershell_string_does_not_end_it():
    assert judge('Write-Host "12`" screen"; Remove-Item -Recurse "%s"' % GW, "PowerShell")


def test_a_hash_inside_a_powershell_word_is_not_a_comment():
    assert judge("Remove-Item C:\\Temp\\a#b; Remove-Item -Recurse '%s'" % GW, "PowerShell")


def test_include_or_filter_narrows_a_wildcard():
    assert judge('Remove-Item "%s\\Data\\*" -Include *.tmp' % GW, "PowerShell") is None
    assert judge('Remove-Item "%s\\Data\\*" -Recurse -Filter:*.bak' % GW, "PowerShell") is None
    assert judge('Remove-Item -Path "%s\\Data\\*" -Include "*.tmp"' % GW, "PowerShell") is None


@pytest.mark.skipif(os.name != "nt", reason="Windows path spelling")
def test_include_star_or_exclude_does_not_narrow():
    assert judge('Remove-Item "%s\\Data\\*" -Recurse -Include *' % GW, "PowerShell")
    assert judge('Remove-Item "%s\\Data\\*" -Recurse -Exclude *.txt' % GW, "PowerShell")
    assert judge('Remove-Item "%s\\Data" -Recurse -Include *.tmp' % GW, "PowerShell")   # the folder itself is named
    assert judge('Remove-Item "%s\\Data\\*" -Include *.tmp,* -Recurse' % GW, "PowerShell")
    assert judge('Remove-Item "%s\\*" -Include Data -Recurse' % GW, "PowerShell")        # a plain name is no filter


@pytest.mark.skipif(os.name != "nt", reason="Windows path spelling")
def test_codex_powershell_under_the_name_bash_is_read_as_powershell():
    """MEASURED codex-cli 0.167.1: tool_name is "Bash" and the command is PowerShell text."""
    cmd = 'Remove-Item -Path "C:\\Temp\\x","%s" -Recurse' % GW          # a comma list is PowerShell only
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": "C:/Temp"}
    assert pbd.check(payload, ENV) is None
    assert pbd.check(payload, dict(ENV, PROTECT_BASH_SHELL="powershell"))


def test_a_crlf_here_string_is_data():
    body = "$s = @'\r\nDon't\r\nRemove-Item -Recurse '%s'\r\n'@\r\nWrite-Host $s" % GW
    assert judge(body, "PowerShell") is None
