"""Build the packet candidate from the deployed baseline: one READ_ONLY_SCRIPT_VERBS entry and the cd rule."""
import difflib
import json
import pathlib
import sys

packet = pathlib.Path(sys.argv[1])
baseline = pathlib.Path(sys.argv[2])
pins = json.loads((packet / 'project-pins.json').read_text(encoding='utf-8'))
SCRIPT = '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/addon-migration-2026-11-09/engine_parent/controller.py'
s = baseline.read_text(encoding='utf-8')

anchor = " 'tools/housekeep.py': {'sha256': {'388db95fcfff7aec90d88bf0045c85244bb18906f590e81c774083ea501ad556'},"
assert s.count(anchor) == 1
deps = ''.join("                      %r: %r,\n" % (k, v) for k, v in pins.items() if k != SCRIPT)
entry = """ # Gateway loaded-engine parent (user ruling 2026-11-10, option A): `controller.py freeze` writes run METADATA only
 # (frozen source hashes, publication/profile PLANS with application disabled, a pair REQUEST for the separately guarded
 # qualified binding). It spells the save folder because it hashes the source pair and checks the destination pair is
 # absent, which are reads. Every other verb (prepare, publish, profile, preflight, run, menu-ready, loaded, stop,
 # restore) stays under ordinary inspection. Pinned: the script, the four modules its freeze path calls into, and the
 # six support modules that do its writes, preservation reads and cold-state check (review 2026-11-10). A change to any
 # of them revokes this entry (fail closed), as happened to the native_batch_run.py entry above.
 %r: {
     'sha256': {%r},
     'verbs': {'freeze'},
     'dependencies': {
%s                      }},
""" % (SCRIPT, pins[SCRIPT], deps)
s = s.replace(anchor, entry + anchor)

anchor2 = "    starts = [m.end() for m in re.finditer(re.escape(raw), text)]\n    if not starts:\n        return False\n"
assert s.count(anchor2) == 1
rule = anchor2 + """    # A relative script token runs where the SHELL is when it executes, which a directory change earlier in the
    # command moves, while the hook resolves it against the session cwd first (review 2026-11-10: `cd <scratch>;
    # python _CLAUDE_OUTPUT/.../controller.py freeze` would be judged by the pinned install copy and run an unpinned
    # one). The exemption survives only when every directory change the hook can parse resolves to the session cwd
    # itself (the routine `cd "<root>" && ...` prefix from the root); a change it cannot parse (inside a quoted inner
    # command, `chdir`/`sl`/`Push-Location`, GNU env -C/--chdir, -WorkingDirectory) or one that resolves elsewhere
    # revokes it, and ordinary inspection still runs on the command.
    if not Path(raw).is_absolute() and re.search(
            r'(?<![\\w.-])(?:cd|chdir|set-location|sl|pushd|push-location)(?![\\w-])'
            r'|\\benv\\b[^;&|\\n]*\\s(?:-C|--chdir)\\b|-workingdirectory\\b', text, re.I):
        words = re.findall(r'(?<![\\w.-])(?:cd|chdir|set-location|sl|pushd|push-location|env|-workingdirectory)(?![\\w-])',
                           text, re.I)
        targets = _cd_targets(text)
        try:
            here = Path(cwd).resolve()
            same = bool(targets) and len(targets) == len(words) and all(
                (Path(t) if Path(t).is_absolute() else Path(cwd) / t).resolve() == here for t in targets)
        except OSError:
            same = False
        if not same:
            return False
"""
s = s.replace(anchor2, rule)

(packet / 'candidate.py').write_text(s, encoding='utf-8', newline='')
old = baseline.read_text(encoding='utf-8')
patch = ''.join(difflib.unified_diff(old.splitlines(keepends=True), s.splitlines(keepends=True),
                                     'a/protect-save-access.py', 'b/protect-save-access.py'))
(packet / 'candidate.patch').write_text(patch, encoding='utf-8', newline='')
print('candidate written', len(patch.splitlines()), 'patch lines')
