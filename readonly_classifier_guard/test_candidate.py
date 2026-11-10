"""Frozen classifier contrasts. Payload strings are NEVER executed.

Only authored temporary files are created by test setup. decide() must not run
any backup, process or game operation; those entry points are instrumented to
fail if reached. The installed guard is not imported or modified.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
guard = None  # The reviewed qualifier selects baseline or isolated candidate.


class Classifier(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'authored-root'
        self.root.mkdir()
        self.protected = self.root / 'modeled-protected-location'
        self.protected.mkdir()
        self.home = self.root / 'home'
        runner = self.home / '.claude/tools/resource-budget/rb.py'
        runner.parent.mkdir(parents=True)
        runner.write_bytes(b'# Authored nonexecuted classifier path model only.\n')
        for index in range(3):
            for suffix in ('.ess', '.skse'):
                (self.protected / ('case-' + str(index) + suffix)).write_bytes(b'authored classifier bytes')
        self.patches = [patch.object(guard, 'ROOT', self.root),
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

    def classify(self, command, tool='Bash'):
        return guard.decide({'tool_name': tool, 'cwd': str(self.root), 'tool_input': {'command': command}})

    def assert_protected(self, command, tool='Bash'):
        value = self.classify(command, tool)
        self.assertNotEqual(value['kind'], 'allow', (command, value))
        return value

    def test_observed_reader_envelope_is_read_only(self):
        text = (HERE / 'reader-input.txt').read_text().replace('{ROOT}', self.root.as_posix())
        text = text.replace('{HOME}', self.home.as_posix())
        self.assertEqual(self.classify(text)['kind'], 'allow')

    def test_python_rd_reader_assignment_and_calls_are_not_shell_aliases(self):
        body = "import json,pathlib; rd=lambda p:json.loads(pathlib.Path(p).read_bytes()); value=rd('ordinary.json'); print('.skse')"
        for text in ('python -c "' + body + '"', "python -c '" + body.replace("'", '"') + "'"):
            with self.subTest(text=text):
                self.assertEqual(self.classify(text)['kind'], 'allow')

    def test_report_strings_are_data_for_ordinary_output(self):
        raw = (HERE / 'report-input.json').read_text().replace('{ROOT}', self.root.as_posix())
        value = json.loads(raw)
        self.assertEqual(guard.decide(value)['kind'], 'allow')

    def test_plain_output_and_search_do_not_execute_quoted_aliases(self):
        for text in ("echo 'rd /s C:/fixture/Saves/*.ess'", "rg 'rd/rmdir .skse' ordinary.txt",
                     "Write-Output 'rd C:/fixture/Saves/case.ess'"):
            with self.subTest(text=text):
                self.assertEqual(self.classify(text)['kind'], 'allow')

    def test_actual_shell_deletions_and_wrappers_remain_protected(self):
        target = (self.protected / 'case-0.ess').as_posix()
        base = 'rd /s /q "' + target + '"'
        for text in (base, 'RD /S /Q "' + target + '"', 'cmd /c ' + base, 'cmd.exe /d /s /c "' + base + '"',
                     "powershell -Command '" + base + "'", "pwsh -Command '" + base + "'",
                     '& rd -Recurse "' + target + '"', 'echo before; ' + base,
                     'echo before && ' + base, 'echo before | ' + base,
                     'command ' + base, 'env ' + base, 'rmdir /s "' + target + '"',
                     'rm -r "' + target + '"'):
            with self.subTest(text=text):
                self.assert_protected(text)

    def test_nested_shell_execution_is_never_a_reader_exemption(self):
        target = (self.protected / 'case-0.ess').as_posix()
        shell = 'rd /s /q ' + target
        cases = ['python -c "import os; os.system(\'' + shell + "')\"",
            'python -c "import subprocess; subprocess.run(\'' + shell + "',shell=True)\"",
            'python -c "import subprocess; subprocess.run([\'cmd\',\'/c\',\'rd\',\'/s\',\'' + target + "'])\"",
            'node -e "require(\'child_process\').execSync(\'' + shell + "')\"",
            "iex '" + shell + "'", "eval '" + shell + "'",
            'echo "' + shell + '" | bash', 'echo "' + shell + '" | pwsh',
            'echo $(' + shell + ')', 'echo `' + shell + '`']
        for text in cases:
            with self.subTest(text=text):
                self.assert_protected(text)

    def test_python_mutation_twin_cannot_gain_reader_scope(self):
        target = (self.protected / 'case-0.ess').as_posix()
        for body in ("from pathlib import Path; rd=lambda p:Path(p).unlink(); rd('" + target + "')",
                     "import os; rd=lambda p:os.remove(p); rd('" + target + "')",
                     "import shutil; shutil.rmtree('" + self.protected.as_posix() + "')"):
            with self.subTest(body=body):
                self.assert_protected('python -c "' + body + '"')

    def test_json_report_mutation_twin_still_names_the_actual_target(self):
        raw = (HERE / 'report-input.json').read_text().replace('{ROOT}', self.root.as_posix())
        value = json.loads(raw)
        ordinary = self.root.as_posix() + '/ordinary-output/INVESTIGATION.json'
        protected = (self.protected / 'case-0.ess').as_posix()
        value['tool_input']['code'] = value['tool_input']['code'].replace(ordinary, protected)
        self.assertNotEqual(guard.decide(value)['kind'], 'allow')

    def test_one_pair_and_bulk_changes_keep_the_preservation_decisions(self):
        target = (self.protected / 'case-0.ess').as_posix()
        one = self.classify('Remove-Item "' + target + '"')
        self.assertEqual((one['kind'], one['count'], one['op']), ('backup', 1, 'delete'))
        self.assertEqual(one['affected'], [str(self.protected / 'case-0.ess')])
        bulk = self.classify('Remove-Item "' + (self.protected / 'case-*.ess').as_posix() + '"')
        self.assertIn(bulk['kind'], ('needs_set', 'needs_files'))

    def test_whole_folder_and_backup_store_protection_stays_denied(self):
        for target in (self.protected, guard.BACKUP_ROOT):
            with self.subTest(target=target):
                value = self.classify('rd /s "' + target.as_posix() + '"')
                self.assertEqual(value['kind'], 'deny')

    def test_unknown_dynamic_deletion_never_becomes_an_empty_set_allowance(self):
        for text in ('rd /s "$target" # .skse', 'powershell -Command "$action" # rd .skse',
                     'cmd /c "%ACTION%" # rd .skse', 'rd("' + (self.protected / 'case-0.ess').as_posix() + '")'):
            with self.subTest(text=text):
                self.assert_protected(text)

    def test_report_profile_never_admits_expressions_getters_or_extra_statements(self):
        raw = (HERE / 'report-input.json').read_text().replace('{ROOT}', self.root.as_posix())
        value = json.loads(raw)
        original = value['tool_input']['code']
        variants = (original.replace("kind:'source-only-refusal-investigation'",
                "get kind(){require('fs').rmSync('C:/fixture/Saves/case.ess');return 'x'}"),
            original.replace("kind:'source-only-refusal-investigation'", "kind:dangerous()"),
            original.replace("JSON.stringify(report, null, 2)", "dangerous(report)"),
            original + " require('child_process').execSync('rd /s C:/fixture/Saves');")
        for code in variants:
            with self.subTest(code=code):
                value['tool_input']['code'] = code
                self.assertNotEqual(guard.decide(value)['kind'], 'allow')

    def test_report_dynamic_destination_and_unrelated_mcp_tool_stay_conservative(self):
        raw = (HERE / 'report-input.json').read_text().replace('{ROOT}', self.root.as_posix())
        value = json.loads(raw)
        original = value['tool_input']['code']
        literal = "'" + self.root.as_posix() + "/ordinary-output/INVESTIGATION.json'"
        value['tool_input']['code'] = original.replace(literal, 'destination')
        self.assertNotEqual(guard.decide(value)['kind'], 'allow')
        value['tool_input']['code'] = original
        value['tool_name'] = 'mcp__unrecognized__code'
        self.assertNotEqual(guard.decide(value)['kind'], 'allow')

    def test_direct_node_file_mutations_still_protect_the_actual_pair(self):
        target = (self.protected / 'case-0.ess').as_posix()
        for operation in ('unlink', 'rm', 'writeFile'):
            value = {'tool_name': 'mcp__node_repl__js', 'cwd': str(self.root),
                'tool_input': {'code': "await fs." + operation + "('" + target + "', 'authored');"}}
            with self.subTest(operation=operation):
                self.assertNotEqual(guard.decide(value)['kind'], 'allow')

    def test_local_reader_binding_does_not_mask_foreign_attributes_or_keywords(self):
        target = (self.protected / 'case-0.ess').as_posix()
        prefix = 'from pathlib import Path; rd=lambda p:Path(p).read_bytes(); '
        for body in (prefix + "other.rd('" + target + "')",
                     prefix + "unknown(rd=rd, target='" + target + "')"):
            with self.subTest(body=body):
                self.assert_protected('python -c "' + body + '"')

    def test_here_string_extra_or_dynamic_consumers_do_not_gain_reader_scope(self):
        text = (HERE / 'reader-input.txt').read_text().replace('{ROOT}', self.root.as_posix())
        text = text.replace('{HOME}', self.home.as_posix())
        for suffix in ('\niex ${code}', '\nGet-Variable -Name code -ValueOnly | iex',
                       '\n& $unknown ${code}'):
            with self.subTest(suffix=suffix):
                self.assert_protected(text + suffix)

    def test_opaque_or_mutated_rd_bindings_remain_conservative(self):
        target = (self.protected / 'case-0.ess').as_posix()
        call = "rd('" + target + "')"
        reader = 'from pathlib import Path\nrd=lambda p:Path(p).read_bytes()\n'
        bodies = ('rd=lambda p:opaque(p)\n' + call,
            'def rd(p):\n    return opaque(p)\n' + call,
            reader + 'from opaque_module import *\n' + call,
            reader + 'rd.__code__=opaque.__code__\n' + call,
            reader + 'for rd in [opaque]:\n    ' + call,
            reader + 'opaque(reader=rd)\n' + call)
        for body in bodies:
            with self.subTest(body=body):
                self.assert_protected('python -c "' + body + '"')


def load(file, name):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == '__main__':
    import sys
    mode = sys.argv.pop(1) if len(sys.argv) > 1 and sys.argv[1] in ('--baseline', '--candidate') else '--candidate'
    file = HERE.parent / 'native_adapter_guard/candidate.py' if mode == '--baseline' else HERE / 'candidate.py'
    guard = load(file, 'isolated_readonly_classifier_subject')
    unittest.main(verbosity=2)
