"""Build the packet candidate from the deployed baseline: one READ_ONLY_SCRIPT_VERBS entry, _bare_single_call, the rule."""
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

life_anchor = "REVIEWED_NON_SAVE_LIFECYCLE = {"
assert s.count(life_anchor) == 1
lifecycle = json.loads((packet / 'lifecycle-pins.json').read_text(encoding='utf-8'))
life_deps = ''.join("                      %r: %r,\n" % (k, v) for k, v in {**{k: v for k, v in pins.items() if k != SCRIPT}, **lifecycle}.items())
life_entry = life_anchor + """
 # Gateway loaded-engine parent lifecycle (user ruling 2026-11-10 14:25: same category as the 2026-10-29
 # native_batch_run approval). Configuration and owned-session operations, NOT save operations: run metadata,
 # native07/profile publication and rollback with permanent backups, the owned launch/stop, the protected-file
 # restore. Pair creation and loading stay separate direct calls to tools/resaver-native-runtime.py.
 %r: {
     'sha256': {%r},
     'verbs': {'prepare', 'publish', 'profile', 'preflight', 'run', 'menu-ready', 'loaded', 'stop', 'restore'},
     'dependencies': {
%s                      }},
""" % (SCRIPT, pins[SCRIPT], life_deps)
s = s.replace(life_anchor, life_entry, 1)

helper_anchor = "def read_only_script_call(script, raw, text, cwd='.', tool=None):\n"
assert s.count(helper_anchor) == 1
helper = '''def _bare_single_call(raw, text):
    """True only when the whole command is ONE bare interpreter call of this script token: optional PowerShell `&`,
    the interpreter (optionally path-qualified or quoted), flags, the token (optionally quoted), plain word arguments,
    nothing else. No `;`, `&&`, `|`, newline, substitution, redirection, grouping or quoting in the tail: a relative
    token runs wherever the shell is by then, and everything that can move the shell is excluded by shape, not by a
    list of directory-change words (review 2026-11-10: `cd "<cwd>"/../x`, `cd` + newline, `c\\'\\'d`, env -C,
    SetLocation() all beat a word list)."""
    quoted = "(?:'" + re.escape(raw) + "'|\\"" + re.escape(raw) + "\\"|" + re.escape(raw) + ")"
    interpreter = r'(?:"[^"\\n]*[/\\\\]|\\'[^\\'\\n]*[/\\\\]|[^\\s"\\';|&]*[/\\\\])?(?:python\\w*(?:\\.\\d+)?|py)(?:\\.exe)?["\\']?'
    # Only value-less single-letter options: `-X`, `-W`, `-c`, `-m` and long options take the NEXT word as their
    # value, so `python -X <token> freeze` would run ./freeze from the cwd under the token's exemption. `-O`
    # strips assert statements and `-P` (3.11+) changes the import path, so neither is admitted either.
    flags = r'(?:[ \\t]+-[BEIRSbdiqsuv]+)*'
    tail = r'(?:[ \\t]+[^\\s;&|`$(){}<>"\\'\\\\]+)*'
    return re.fullmatch(r'[ \\t]*(?:&[ \\t]*)?' + interpreter + flags + r'[ \\t]+' + quoted + tail + r'[ \\t]*',
                        text, re.I) is not None


'''
s = s.replace(helper_anchor, helper + helper_anchor)

anchor2 = "    starts = [m.end() for m in re.finditer(re.escape(raw), text)]\n    if not starts:\n        return False\n"
assert s.count(anchor2) == 1
rule = anchor2 + """    # A RELATIVE script token runs where the SHELL is when it executes, and anything else in the command may have
    # moved it, while the hook resolves the token against the session cwd first (review 2026-11-10: `cd <scratch>;
    # python _CLAUDE_OUTPUT/.../controller.py freeze` would be judged by the pinned install copy and run an unpinned
    # one). A relative token is exempt only as one bare call; everything composed must name the script by ABSOLUTE
    # path, which no directory change can redirect. Ordinary inspection still runs on a composed relative call.
    if not Path(raw).is_absolute() and not _bare_single_call(raw, text):
        return False
"""
s = s.replace(anchor2, rule)

(packet / 'candidate.py').write_text(s, encoding='utf-8', newline='')
old = baseline.read_text(encoding='utf-8')
patch = ''.join(difflib.unified_diff(old.splitlines(keepends=True), s.splitlines(keepends=True),
                                     'a/protect-save-access.py', 'b/protect-save-access.py'))
(packet / 'candidate.patch').write_text(patch, encoding='utf-8', newline='')
print('candidate written', len(patch.splitlines()), 'patch lines')
