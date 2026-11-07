"""Classifier-only authored files. No real save, native backend or game execution."""
import ast
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
BASELINE = HERE.parent / 'inert_fixture_guard/candidate.py'


def digest(file):
    return hashlib.sha256(Path(file).read_bytes()).hexdigest()


def load(file, name):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load(HERE / 'candidate.py', 'native_flag_candidate')
baseline = load(BASELINE, 'native_flag_baseline')


class NativeFlag(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / 'root with spaces'
        self.root.mkdir()
        self.home = self.root.parent / 'home'
        self.home.mkdir()
        self.helper = self.root / 'tools/resaver-native.py'
        self.helper.parent.mkdir()
        self.helper.write_bytes((HERE / 'adapter-source.txt').read_bytes())
        self.assertEqual(digest(self.helper), guard.NATIVE_ADAPTER_SHA256)
        self.binary = self.root / 'tools/resaver-plus/33-82a7d31-native1/resaverpp-cli.exe'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b'authored nonexecutable binary hash fixture\n')
        self.manifest = self.root / 'tools/resaver-native.json'
        self.manifest.write_text(json.dumps({'executable': self.binary.relative_to(self.root).as_posix(),
                                            'sha256': digest(self.binary)}))
        self.runner = self.home / '.claude/tools/resource-budget/rb.py'
        self.runner.parent.mkdir(parents=True)
        self.runner.write_text('from pathlib import Path\nPath("ordinary-output").write_text("model")\n')
        self.source = self.root / 'authored-input.ess'
        self.source.write_bytes(b'authored parser-path fixture, never parsed as a save\n')
        self.output = self.root / 'authored-output.ess'
        self.patches = [patch.object(guard, 'ROOT', self.root), patch.object(baseline, 'ROOT', self.root),
                        patch.object(guard.Path, 'home', return_value=self.home),
                        patch.object(subprocess, 'run', side_effect=AssertionError('No backend/process execution'))]
        # Model a configured protected location; no real protection marker/folder.
        for module in (guard, baseline):
            self.patches.extend([patch.object(module, 'KNOWN_SAVE_DIRS', [self.root]),
                patch.object(module, 'SAVE_DIR_KEYS', [module._key(self.root)]),
                patch.object(module, 'SAVE_DIR_SPELLINGS', list(module._spellings(self.root)))])
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def command(self, *, outer='', inner='', wrapped=True, arguments=None, interpreter='python'):
        args = arguments if arguments is not None else 'writer-scan "' + self.source.as_posix() + '"'
        child = interpreter + (' ' + inner if inner else '') + ' tools/resaver-native.py ' + args
        if not wrapped:
            return child
        return (interpreter + (' ' + outer if outer else '') + ' "' + self.runner.as_posix()
                + '" run --name delirium-readonly-writer-audit --cpu 4 --ram 0.3 -- ' + child)

    def classify(self, command=None, module=guard):
        return module.decide({'tool_name': 'Bash', 'cwd': str(self.root),
                              'tool_input': {'command': command or self.command(outer='-B', inner='-B')}})

    def native(self, command=None):
        text = command or self.command(outer='-B', inner='-B')
        return guard.native_adapter_call(text, str(self.root), {'tool': 'Bash', 'command': text})

    def test_reproduces_refusal_and_repairs_observed_flag_envelope(self):
        text = self.command(outer='-B', inner='-B')
        self.assertEqual(self.classify(text, baseline)['kind'], 'needs_set')
        self.assertEqual(self.classify(text)['kind'], 'allow')
        self.assertEqual(self.native(text)['kind'], 'allow')

    def test_all_outer_inner_flag_combinations_and_direct(self):
        for outer in ('', '-B'):
            for inner in ('', '-B'):
                with self.subTest(outer=outer, inner=inner):
                    self.assertEqual(self.classify(self.command(outer=outer, inner=inner))['kind'], 'allow')
        for flag in ('', '-B'):
            self.assertEqual(self.classify(self.command(wrapped=False, inner=flag))['kind'], 'allow')

    def test_quoted_absolute_python_and_helper_paths(self):
        # The parser does not execute this authored interpreter pathname.
        python = '"' + (self.root / 'runtime/python.exe').as_posix() + '"'
        text = self.command(outer='-B', inner='-B', interpreter=python)
        text = text.replace('tools/resaver-native.py', '"' + self.helper.as_posix() + '"')
        self.assertEqual(self.classify(text)['kind'], 'allow')

    def test_only_one_exact_flag_is_recognized_at_each_boundary(self):
        for flag in ('-B -B', '-b', '-BB', '-I', '-E', '-s', '-S', '-u', '-c', '-m', '--', '-X dev'):
            for role in ('outer', 'inner'):
                with self.subTest(flag=flag, role=role):
                    self.assertIsNone(self.native(self.command(**{role: flag})))
        self.assertIsNone(self.native('python -B'))
        self.assertIsNone(self.native('python -B -B'))
        self.assertIsNone(self.native('& ' + self.command(outer='-B', inner='-B')))

    def test_flag_after_script_or_separator_does_not_gain_admission(self):
        for text in (self.command().replace('rb.py" run', 'rb.py" -B run'),
                     self.command().replace(' -- python', ' -- -B python'),
                     self.command().replace('resaver-native.py ', 'resaver-native.py -B ')):
            result = self.native(text)
            self.assertTrue(result is None or result['kind'] == 'deny')

    def test_wrapper_path_subcommand_and_option_grammar_unchanged(self):
        original = self.command(outer='-B', inner='-B')
        changes = [original.replace(self.runner.as_posix(), (self.home / 'other/rb.py').as_posix()),
                   original.replace('" run ', '" status '),
                   original.replace('--ram 0.3', '--unknown 0.3'),
                   original.replace('--ram 0.3', '--ram'),
                   original.replace(' -- python', ' python')]
        for text in changes:
            with self.subTest(text=text):
                self.assertIsNone(self.native(text))

    def test_composition_and_redirection_never_gain_native_admission(self):
        for tail in ('; echo x', ' && echo x', ' | cat', '\npython other.py', ' > output.txt'):
            with self.subTest(tail=tail):
                result = self.native(self.command(outer='-B', inner='-B') + tail)
                self.assertTrue(result is None or result['kind'] == 'deny')

    def test_adapter_hash_and_binary_hash_and_manifest_drift_refuse(self):
        for file in (self.helper, self.binary, self.manifest):
            original = file.read_bytes()
            file.write_bytes(original + b'changed')
            self.assertEqual(self.classify()['kind'], 'deny')
            file.write_bytes(original)
        self.assertEqual(self.classify()['kind'], 'allow')

    def test_same_name_wrong_helper_path_refuses(self):
        elsewhere = self.root / 'resaver-native.py'
        elsewhere.write_bytes(self.helper.read_bytes())
        text = self.command(outer='-B', inner='-B').replace('tools/resaver-native.py', 'resaver-native.py')
        self.assertEqual(self.classify(text)['kind'], 'deny')

    def test_preview_remains_allow_and_apply_calls_existing_pair_gate(self):
        source, output = self.source.as_posix(), self.output.as_posix()
        for operation, args in (('set-var', '0x1 1 BOOLEAN:false'), ('set-global', '0x1 0'), ('clean', '')):
            arguments = operation + ' "' + source + '" ' + args
            preview = self.command(outer='-B', inner='-B', arguments=arguments)
            self.assertEqual(self.classify(preview)['kind'], 'allow')
            applied = self.command(outer='-B', inner='-B', arguments=arguments + ' "' + output + '" --apply')
            with patch.object(guard, 'in_save_location', return_value=True):
                decision = self.classify(applied)
            self.assertEqual(decision['kind'], 'backup')
            self.assertEqual(decision['count'], 1)
            self.assertEqual(decision['op'], 'native-controlled-edit')
            self.assertEqual(decision['affected'], [str(self.output)])
        self.assertFalse(self.output.exists())  # Classification never applies anything.

    def test_existing_output_and_cosave_member_collision_refuse(self):
        args = 'clean "' + self.source.as_posix() + '" "' + self.output.as_posix() + '" --apply'
        for file in (self.output, self.output.with_suffix('.skse')):
            file.write_bytes(b'authored collision')
            self.assertEqual(self.classify(self.command(outer='-B', inner='-B', arguments=args))['kind'], 'deny')
            file.unlink()

    def test_relative_write_paths_unknown_arguments_and_backup_store_refuse(self):
        source, output = self.source.as_posix(), self.output.as_posix()
        backup = self.root / '.claude/backups/save-backups'
        backup.mkdir(parents=True)
        args = ['clean "' + source + '" "' + output + '" --apply --not-a-flag',
                'clean "' + source + '" "' + (backup / 'new.ess').as_posix() + '" --apply',
                'clean "' + source + '" "' + source + '" --apply',
                'clean "' + source + '" "' + output + '" --apply --apply',
                'writer-scan "' + source + '" --apply']
        for arguments in args:
            with self.subTest(arguments=arguments):
                self.assertEqual(self.classify(self.command(outer='-B', inner='-B', arguments=arguments))['kind'], 'deny')
        # Adapter resolves these; guard must retain literal absolute-write checking.
        with patch('os.getcwd', return_value=str(self.root)):
            for arguments in ('clean authored-input.ess "' + output + '" --apply',
                              'clean "' + source + '" authored-output.ess --apply'):
                self.assertEqual(self.classify(self.command(outer='-B', inner='-B', arguments=arguments))['kind'], 'deny')


class Scope(unittest.TestCase):
    def test_restore_helper_loads_this_candidate(self):
        helper = load(HERE / 'restore-save-backup.py', 'restore_native_flag_binding_test')
        self.assertEqual(Path(helper.guard.__file__).resolve(), (HERE / 'candidate.py').resolve())
        self.assertEqual(digest(helper.guard.__file__), digest(HERE / 'candidate.py'))

    def test_only_native_adapter_definition_changes(self):
        def declarations(file):
            return {getattr(n, 'name', ast.dump(n)): ast.dump(n) for n in ast.parse(file.read_bytes()).body}
        old, new = declarations(BASELINE), declarations(HERE / 'candidate.py')
        self.assertEqual({key for key in old.keys() | new.keys() if old.get(key) != new.get(key)},
                         {'native_adapter_call'})

    def test_patch_and_actual_adapter_source_pin(self):
        expected = ''.join(difflib.unified_diff(BASELINE.read_text().splitlines(keepends=True),
            (HERE / 'candidate.py').read_text().splitlines(keepends=True),
            'a/protect-save-access.py', 'b/protect-save-access.py'))
        self.assertEqual((HERE / 'candidate.patch').read_text(), expected)
        self.assertEqual(digest(HERE / 'adapter-source.txt'), guard.NATIVE_ADAPTER_SHA256)


if __name__ == '__main__':
    unittest.main(verbosity=2)
