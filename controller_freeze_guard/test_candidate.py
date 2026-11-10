"""Frozen contrasts for the reviewed `controller.py freeze` read-only exemption. Payload strings are NEVER executed.

Only authored temporary files are created by test setup: a stand-in controller that, like the real one, spells the
save folder and writes metadata files (the combination the hook cannot count from the command), authored stand-ins
for the pinned dependencies, and a modeled protected save folder. The registry under test is the guard's OWN entry
with its hashes replaced by the authored stand-ins' hashes; a guard without the entry (the baseline) has nothing to
admit. decide() must not run any backup, process or game operation; those entry points are instrumented to fail if
reached. The installed guard is not imported or modified.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
guard = None  # The reviewed qualifier selects baseline or isolated candidate.

TASK = '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/addon-migration-2026-11-09'
BASE = '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28'
SCRIPT = TASK + '/engine_parent/controller.py'
DEPENDENCIES = (BASE + '/native_run.py',
                TASK + '/engine_parent/controlled_profile.py',
                TASK + '/goal_launch_authority.py',
                BASE + '/stage/tools/skyrimnet-output-guard/install-native.py',
                BASE + '/gateway_test_support/io.py',
                BASE + '/reference_adapter.py',
                BASE + '/gateway_test_support/reference_preservation.py',
                BASE + '/gateway_test_support/context.py',
                BASE + '/gateway_test_support/session.py',
                'tools/vr-headless.py')
# Authored, never executed. Spells the save folder (hashing the source pair, checking the destination is absent) and
# writes metadata: the shape that made the hook ask for an uncountable save set on 2026-11-10 (hash 6dbc55f8d488a55d).
CONTROLLER = b"""import json, sys
from pathlib import Path
SOURCE_NAME = 'Save3_authored_source.ess'
TEST_NAME = 'Authored_Test_Pair.ess'
def freeze():
    profile = Path.home() / 'Documents/My Games/Skyrim VR/Saves'
    source = profile / SOURCE_NAME
    assert source.read_bytes()
    assert not (profile / TEST_NAME).exists()
    Path('run/pair-request.json').write_text(json.dumps({'source': str(source)}))
globals()[sys.argv[1].replace('-', '_')]()
"""
# The exact refused exec_command (HANDOFF-GUARD-METADATA-FREEZE.md), byte for byte: a here-string piped to
# `python -`, then the controller's freeze verb.
REFUSED = """@'
from pathlib import Path
import sys,json
k=Path('_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/addon-migration-2026-11-09/native-acceptance-campaign').resolve()
sys.path.insert(0,str(k))
import sampling_entry as s
from gateway_test_support.io import write_new
s.validate(json.loads(s.PLAN.read_bytes()))
v={'schema':1,'files':sorted(p.relative_to(s.ROOT).as_posix() for p in s.input_paths()|{s.PLAN})}
out=k.parent/'engine_parent/extra-inputs.json'
write_new(out,v)
print({'extra_inputs':len(v['files']),'sampling_plan_sha256':s.campaign.sha(s.PLAN),'installed_writes':0})
'@ | python -
python -B '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/addon-migration-2026-11-09/engine_parent/controller.py' freeze"""
FREEZE = "python -B '" + SCRIPT + "' freeze"
# The sanctioned real invocation is two commands: the here-string alone (no script token; allowed by both guards
# because it spells no save location), then the controller by ABSOLUTE path (v5: a relative token is exempt only as
# one bare call; the original compound form with a relative token is refused by shape).
HERESTRING = REFUSED.split("'@ | python -")[0] + "'@ | python -"


def digest(data):
    return hashlib.sha256(data if isinstance(data, bytes) else Path(data).read_bytes()).hexdigest()


class Pins(unittest.TestCase):
    """The candidate's live entry pins the exact bytes recorded for review (project-pins.json), nothing wider."""

    def test_registry_pins_the_real_controller_and_its_reviewed_dependencies(self):
        pins = json.loads((HERE / 'project-pins.json').read_bytes())
        entry = guard.READ_ONLY_SCRIPT_VERBS.get(SCRIPT)
        self.assertIsNotNone(entry, 'controller.py freeze is not a reviewed read-only script in this guard')
        self.assertEqual(entry['sha256'], {pins.pop(SCRIPT)})
        self.assertEqual(entry['verbs'], {'freeze'})
        self.assertEqual(entry['dependencies'], pins)
        self.assertEqual(set(pins), set(DEPENDENCIES))
        self.assertNotIn('frozen_inputs', entry)
        self.assertNotIn('plan_verbs', entry)
        self.assertNotIn('exact_desktop_args', entry)
        self.assertNotIn(SCRIPT, guard.REVIEWED_NON_SAVE_LIFECYCLE)


class FreezeExemption(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'authored-root'
        self.root.mkdir()
        self.protected = self.root / 'modeled-protected-location'
        self.protected.mkdir()
        self.home = self.root / 'home'
        self.home.mkdir()
        for index in range(3):
            for suffix in ('.ess', '.skse'):
                (self.protected / ('case-' + str(index) + suffix)).write_bytes(b'authored classifier bytes')
        self.script = self.root / SCRIPT
        self.script.parent.mkdir(parents=True)
        self.script.write_bytes(CONTROLLER)
        # The guard's OWN entry, re-pinned to the authored stand-ins. The baseline has no entry: nothing is admitted.
        real = guard.READ_ONLY_SCRIPT_VERBS.get(SCRIPT)
        self.table = {}
        if real is not None:
            dependencies = {}
            for name in real['dependencies']:
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('# authored nonexecuted dependency ' + name + '\n').encode())
                dependencies[name] = digest(path)
            self.table[SCRIPT] = dict(real, sha256={digest(self.script)}, dependencies=dependencies)
        self.patches = [patch.object(guard, 'ROOT', self.root),
            patch.object(guard, 'READ_ONLY_SCRIPT_VERBS', self.table),
            patch.object(guard, 'REVIEWED_NON_SAVE_LIFECYCLE', {}),
            patch.object(guard, 'REVIEWED_INERT_FIXTURES', {}),
            patch.object(guard, 'BACKUP_ROOT', self.root / 'permanent-backup-store'),
            patch.object(guard, 'ADVICE_LOG', self.root / 'ordinary-advice.jsonl'),
            patch.object(guard, 'KNOWN_SAVE_DIRS', [self.protected]),
            patch.object(guard, 'SAVE_DIR_KEYS', [guard._key(self.protected)]),
            patch.object(guard, 'SAVE_DIR_SPELLINGS', list(guard._spellings(self.protected))),
            patch.object(guard.Path, 'home', return_value=self.home),
            patch.object(guard, 'backup_pairs', side_effect=AssertionError('No backup execution in classifier tests')),
            patch.object(subprocess, 'run', side_effect=AssertionError('No process execution in classifier tests')),
            patch.object(subprocess, 'Popen', side_effect=AssertionError('No process execution in classifier tests'))]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def entry(self):
        self.assertIn(SCRIPT, self.table, 'this contrast needs the candidate entry')
        return self.table[SCRIPT]

    def classify(self, command, tool='Bash'):
        return guard.decide({'tool_name': tool, 'cwd': str(self.root), 'tool_input': {'command': command}})

    def assert_protected(self, command, tool='Bash'):
        value = self.classify(command, tool)
        self.assertNotEqual(value['kind'], 'allow', (command, value))
        return value

    def assert_allowed(self, command, tool='Bash'):
        value = self.classify(command, tool)
        self.assertEqual(value['kind'], 'allow', (command, value))

    def absolute(self, verb='freeze'):
        return 'python -B "' + str(self.script) + '" ' + verb

    # --- the admitted operation (baseline red: the baseline has no entry) ---

    def test_sanctioned_freeze_calls_are_admitted(self):
        self.assert_allowed(HERESTRING, 'PowerShell')   # no script token; both guards allow it
        for name, command, tool in (('bare relative, Bash', FREEZE, 'Bash'), ('bare relative, PowerShell', FREEZE, 'PowerShell'),
                                    ('absolute', self.absolute(), 'PowerShell'),
                                    ('absolute after a cd elsewhere', 'cd ../scratch; ' + self.absolute(), 'PowerShell')):
            with self.subTest(name=name):
                self.assert_allowed(command, tool)

    def test_original_compound_relative_command_is_refused_by_shape(self):
        # The 2026-11-10 refused command composed a here-string with a RELATIVE controller call; v5 admits a relative
        # token only as one bare call, so the compound form stays refused and the real run uses the absolute path.
        for tool in ('Bash', 'PowerShell'):
            with self.subTest(tool=tool):
                self.assert_protected(REFUSED, tool)
        self.assert_protected(HERESTRING + '\n' + self.absolute() + '; true', 'PowerShell')   # composed tail
        self.assert_allowed(HERESTRING + '\n' + self.absolute(), 'PowerShell')               # absolute: composition is fine

    # --- what the exemption must not cover (protected under both guards) ---

    def test_only_the_freeze_verb_is_admitted(self):
        for verb in ('prepare', 'publish', 'profile', 'preflight', 'run', 'menu-ready', 'loaded', 'stop', 'restore', ''):
            with self.subTest(verb=verb):
                self.assert_protected(("python -B '" + SCRIPT + "' " + verb).rstrip())

    def test_freeze_composed_with_another_verb_is_judged_by_that_verb(self):
        for composed in (FREEZE + "; python -B '" + SCRIPT + "' prepare",
                         FREEZE + " && python '" + SCRIPT + "' loaded",
                         "python '" + SCRIPT + "' run | " + FREEZE):
            with self.subTest(command=composed):
                self.assert_protected(composed)

    def test_freeze_handed_a_save_or_save_folder_argument_stays_protected(self):
        for tail in (' modeled-protected-location/case-0.ess', ' Saves/x.ess', ' --out Saves', ' freeze.skse'):
            with self.subTest(tail=tail):
                self.assert_protected(FREEZE + tail)

    def test_relative_script_after_a_directory_change_is_never_exempt(self):
        # Review 2026-11-10: the shell runs the relative path from the cd target, the hook resolved it from the
        # session cwd first; an unpinned copy at the target would run under the pinned copy's exemption.
        other = self.root.parent / 'scratch' / SCRIPT
        other.parent.mkdir(parents=True)
        other.write_bytes(CONTROLLER + b'# unpinned copy\n')
        for prefix in ('cd ../scratch; ', 'cd "../scratch" && ', 'Set-Location ../scratch; ', 'sl ../scratch; ',
                       'pushd ../scratch; ', 'Push-Location ../scratch; ', 'chdir ../scratch; '):
            with self.subTest(prefix=prefix):
                self.assert_protected(prefix + FREEZE)
                self.assert_protected(prefix + REFUSED, 'PowerShell')
        # the directory change written inside a quoted inner command, or without the word (review 2026-11-10 v2);
        # the bash -c form is double-quoted so the inner single-quoted path stays one token (v3 had nested quotes)
        for composed in ('bash -c "cd ../scratch; ' + FREEZE + '; true"',
                         'pwsh -Command "cd ../scratch; ' + FREEZE + '"',
                         '& {cd ../scratch; ' + FREEZE + '}',
                         'env -C ../scratch ' + FREEZE,
                         'env --chdir=../scratch ' + FREEZE,
                         'cd "' + str(self.root) + '"; cd ../scratch; ' + FREEZE):
            with self.subTest(command=composed):
                self.assert_protected(composed, 'PowerShell')

    def test_root_itself_prefix_needs_the_absolute_path(self):
        # The routine `cd "<root>" &&` prefix (side agent 2026-11-10): with a relative token it is composed and
        # refused by shape (a word list cannot tell `cd "<root>"/../x` from `cd "<root>"`); with the absolute path
        # it keeps the exemption. Protect-bash's own advice: name the file by absolute path when composing.
        for prefix in ('cd "' + str(self.root) + '" && ', 'cd ' + self.root.as_posix() + '; ',
                       'Set-Location "' + str(self.root) + '"; ', 'cd . && ', 'pushd "' + str(self.root) + '"; ',
                       'cd "' + str(self.root) + '"/../scratch; ', 'cd\n.\n'):
            with self.subTest(prefix=prefix):
                self.assert_protected(prefix + FREEZE)
                self.assert_allowed(prefix + self.absolute())

    def test_changed_controller_bytes_revoke_the_exemption(self):
        self.script.write_bytes(CONTROLLER + b'\n# one more line\n')
        self.assert_protected(FREEZE)
        self.assert_protected(REFUSED)

    def test_changed_or_missing_dependency_revokes_the_exemption(self):
        for name in self.entry()['dependencies']:
            path = self.root / name
            original = path.read_bytes()
            with self.subTest(name=name, change='edited'):
                path.write_bytes(original + b'# edited\n')
                self.assert_protected(FREEZE)
            with self.subTest(name=name, change='missing'):
                path.unlink()
                self.assert_protected(FREEZE)
            path.write_bytes(original)
        self.assert_allowed(FREEZE)   # restored bytes admit again: the contrast was the dependency, not the command

    def test_dependency_outside_the_root_never_qualifies(self):
        outside = self.root.parent / 'outside.py'
        outside.write_bytes(b'# authored\n')
        self.entry()['dependencies']['../outside.py'] = digest(outside)
        self.assert_protected(FREEZE)

    def test_same_named_script_elsewhere_is_not_exempt(self):
        other = self.root / 'elsewhere/controller.py'
        other.parent.mkdir()
        other.write_bytes(CONTROLLER)
        self.assert_protected("python -B 'elsewhere/controller.py' freeze")

    def test_direct_save_changes_in_the_same_command_stay_protected(self):
        for command in (FREEZE + "; Remove-Item 'modeled-protected-location/case-1.ess'",
                        "rm modeled-protected-location/case-0.ess modeled-protected-location/case-0.skse && " + FREEZE,
                        FREEZE + " && Copy-Item x.ess modeled-protected-location/case-2.ess"):
            with self.subTest(command=command):
                self.assert_protected(command)

    def test_one_pair_and_bulk_changes_keep_the_preservation_decisions(self):
        one = self.classify("Remove-Item 'modeled-protected-location/case-0.ess'")
        self.assertNotEqual(one['kind'], 'allow', one)
        bulk = self.classify("Remove-Item 'modeled-protected-location/*.ess'")
        self.assertNotEqual(bulk['kind'], 'allow', bulk)
        self.assert_allowed("Get-FileHash 'modeled-protected-location/case-0.ess'")


def load(file, name):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == '__main__':
    import sys
    mode = sys.argv.pop(1) if len(sys.argv) > 1 and sys.argv[1] in ('--baseline', '--candidate') else '--candidate'
    file = HERE.parent / 'readonly_classifier_guard/candidate.py' if mode == '--baseline' else HERE / 'candidate.py'
    guard = load(file, 'isolated_controller_freeze_subject')
    unittest.main(verbosity=2)
