"""The staged protect-bash.sh, run as a real process the way Claude Code runs it (payload on stdin), against a fake
game root, so its own location gives INSTALL_ROOT. Decision only: no command in a payload is ever executed."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")
BASH = str(GIT_BASH) if GIT_BASH.exists() else shutil.which("bash")


@pytest.fixture(scope="module")
def root(tmp_path_factory):
    r = tmp_path_factory.mktemp("pb") / "Fake Skyrim VR"
    hooks = r / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (r / "Data").mkdir()
    for name in ("protect-bash.sh", "protect-bash-deletes.py"):
        shutil.copy(HERE / name, hooks / name)
    return r


def decide(root, command, cwd=None, tool="Bash"):
    payload = {"tool_name": tool, "tool_input": {"command": command}, "cwd": cwd or str(root.parent),
               "hook_event_name": "PreToolUse"}
    r = subprocess.run([BASH, str(root / ".claude" / "hooks" / "protect-bash.sh")], input=json.dumps(payload),
                       capture_output=True, text=True, timeout=60)
    out = r.stdout.strip()
    if not out:
        return "allow", ""
    o = json.loads(out).get("hookSpecificOutput", {})                 # jq pretty-prints one object
    return o.get("permissionDecision", "allow"), o.get("permissionDecisionReason", "") or o.get("additionalContext", "")


def p(root, *parts):
    return "/".join([str(root).replace("\\", "/")] + list(parts))


def test_deleting_the_root_is_refused(root):
    d, why = decide(root, 'rm -rf "%s"' % p(root))
    assert d == "deny" and "game install" in why


def test_deleting_data_by_relative_path_from_the_root_is_refused(root):
    assert decide(root, "rm -rf Data", cwd=str(root))[0] == "deny"


@pytest.mark.parametrize("spelling", ["/usr/bin/rm", '"rm"', "'rm'", "\\rm", "rm.exe", "command rm"])
def test_every_spelling_of_rm_reaches_the_delete_check(root, spelling):
    assert decide(root, '%s -rf "%s"' % (spelling, p(root)))[0] == "deny"


def test_a_scratch_delete_beside_an_install_path_is_allowed(root):
    d, _ = decide(root, 'ls "%s"; rm -rf "$T"' % p(root, "Data"))
    assert d == "allow"


def test_a_file_inside_data_may_be_deleted(root):
    assert decide(root, 'rm -f "%s"' % p(root, "Data", "old.esp.bak"))[0] == "allow"


def test_git_rm_and_python_del_are_allowed(root):
    assert decide(root, "git rm -q --cached .claude/x.md")[0] == "allow"
    assert decide(root, "python - <<'EOF'\ndel data['x']\nEOF")[0] == "allow"


def test_sed_in_place_without_b_is_still_refused(root):
    assert decide(root, "sed -i 's/a/b/' file.txt")[0] == "deny"


def test_registry_delete_is_still_refused(root):
    assert decide(root, r'reg delete "HKLM\SOFTWARE\WOW6432Node\Bethesda Softworks\Skyrim VR" /f')[0] == "deny"


def test_decoded_text_into_a_shell_is_still_refused(root):
    assert decide(root, "echo cm0gLXJmIC8= | base64 -d | bash")[0] == "deny"


def test_resaver_apply_is_no_longer_asked(root):
    assert decide(root, "bash tools/resaver-cli.sh clean Save1.ess --apply")[0] == "allow"


def test_a_broken_delete_helper_refuses_rather_than_allows(root, tmp_path):
    broken = tmp_path / "broken" / "Fake Skyrim VR"
    hooks = broken / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    shutil.copy(HERE / "protect-bash.sh", hooks / "protect-bash.sh")
    (hooks / "protect-bash-deletes.py").write_text("raise SystemExit(3)\n")
    d, why = decide(broken, "rm -rf /c/Temp/x")
    assert d == "deny" and "could not run" in why
