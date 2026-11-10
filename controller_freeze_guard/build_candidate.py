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
rule = anchor2 + """    # A relative script token runs where the SHELL is when it executes, which a `cd` earlier in the command changes,
    # while the hook resolves it against the session cwd first. No exemption for a relative token in a command that
    # changes directory (review 2026-11-10: `cd <scratch>; python _CLAUDE_OUTPUT/.../controller.py freeze` would be
    # judged by the pinned install copy and run an unpinned one); ordinary inspection still runs on it. The word may
    # sit inside a quoted inner command (`bash -c 'cd x; ...'`, `pwsh -Command "cd x; ..."`, `& {cd x; ...}`), so any
    # non-word neighbour counts, and GNU env -C/--chdir and -WorkingDirectory change directory without the word.
    if not Path(raw).is_absolute() and re.search(
            r'(?<![\\w.-])(?:cd|chdir|set-location|sl|pushd|push-location)(?![\\w-])'
            r'|\\benv\\b[^;&|\\n]*\\s(?:-C|--chdir)\\b|-workingdirectory\\b', text, re.I):
        return False
"""
s = s.replace(anchor2, rule)

(packet / 'candidate.py').write_text(s, encoding='utf-8', newline='')
old = baseline.read_text(encoding='utf-8')
patch = ''.join(difflib.unified_diff(old.splitlines(keepends=True), s.splitlines(keepends=True),
                                     'a/protect-save-access.py', 'b/protect-save-access.py'))
(packet / 'candidate.patch').write_text(patch, encoding='utf-8', newline='')
print('candidate written', len(patch.splitlines()), 'patch lines')
