"""Review-gated isolated qualification; inert inputs are classified, never run."""
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import unittest

HERE = Path(__file__).resolve().parent
BASELINE = HERE.parent / 'native_adapter_guard/candidate.py'
PINNED = {}


def sha(file):
    return hashlib.sha256(Path(file).read_bytes()).hexdigest()


def load(file, name):
    file = Path(file).resolve()
    raw = file.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINNED.get(str(file)):
        raise RuntimeError('Unpinned actual source load: ' + str(file))
    if name in sys.modules:
        raise RuntimeError('Fresh module name required: ' + name)
    module = types.ModuleType(name)
    module.__file__ = str(file)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(file), 'exec', dont_inherit=True), module.__dict__)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def verify():
    packet = json.loads((HERE / 'payload-manifest.json').read_bytes())
    if packet['kind'] != 'readonly-classifier-scope-v1' or packet['native_acceptance'] is not False:
        raise RuntimeError('Wrong isolated packet kind')
    if sha(BASELINE) != packet['baseline_sha256']:
        raise RuntimeError('Exact qualified deployed-source baseline changed')
    PINNED[str(BASELINE.resolve())] = packet['baseline_sha256']
    for name, wanted in packet['files'].items():
        file = (HERE / name).resolve()
        if not file.is_relative_to(HERE) or sha(file) != wanted:
            raise RuntimeError('Isolated packet drift: ' + name)
        PINNED[str(file)] = wanted
    for name, wanted in packet['supporting_inputs'].items():
        file = (HERE.parent / name).resolve()
        if not file.is_relative_to(HERE.parent) or sha(file) != wanted:
            raise RuntimeError('Supporting input drift: ' + name)
        PINNED[str(file)] = wanted
    for name, wanted in packet['referenced_manifests'].items():
        file = (HERE.parent / name).resolve()
        if not file.is_relative_to(HERE.parent) or sha(file) != wanted:
            raise RuntimeError('Referenced packet drift: ' + name)
        PINNED[str(file)] = wanted
        value = json.loads(file.read_bytes())
        entries = value['files']
        pairs = entries.items() if isinstance(entries, dict) else ((row['path'], row['sha256']) for row in entries)
        for relative, expected in pairs:
            item = (file.parent / relative).resolve()
            if not item.is_relative_to(file.parent) or sha(item) != expected:
                raise RuntimeError('Referenced actual input drift: ' + relative)
            PINNED[str(item)] = expected
    return packet


class Scope(unittest.TestCase):
    def test_exact_reviewed_declarations_and_patch_only(self):
        packet = verify()
        def declarations(file):
            result = {}
            for node in ast.parse(file.read_bytes()).body:
                key = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else node.targets[0].id \
                    if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name) else ast.dump(node)
                result[key] = ast.dump(node)
            return result
        old, new = declarations(BASELINE), declarations(HERE / 'candidate.py')
        changed = {name for name in old.keys() | new.keys() if old.get(name) != new.get(name)}
        self.assertEqual(changed, set(packet['reviewed_changed_declarations']))
        expected = ''.join(difflib.unified_diff(BASELINE.read_text().splitlines(keepends=True),
            (HERE / 'candidate.py').read_text().splitlines(keepends=True),
            'a/protect-save-access.py', 'b/protect-save-access.py'))
        self.assertEqual((HERE / 'candidate.patch').read_text(), expected)


def run(suite):
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return {'methods': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'successful': result.wasSuccessful()}


def main():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 10) \
            or sys.flags.ignore_environment != 1 or sys.flags.no_user_site != 1:
        raise RuntimeError('Reviewed CPython3.10 invocation requires -E and -s')
    prefix = HERE / 'no-pyc'
    if not sys.dont_write_bytecode or sys.pycache_prefix is None \
            or Path(sys.pycache_prefix).resolve() != prefix or os.path.lexists(prefix):
        raise RuntimeError('Fresh absent private bytecode namespace and -B required')
    packet = verify()
    tests = load(HERE / 'test_candidate.py', 'readonly_frozen_tests')
    tests.guard = load(BASELINE, 'readonly_exact_baseline')
    positive = ('test_observed_reader_envelope_is_read_only',
        'test_python_rd_reader_assignment_and_calls_are_not_shell_aliases',
        'test_report_strings_are_data_for_ordinary_output')
    red = run(unittest.TestSuite(tests.Classifier(name) for name in positive))
    if (red['methods'], red['failures'], red['errors']) != (3, 4, 0):
        raise RuntimeError('Baseline did not reproduce three methods/four frozen failing assertions: ' + str(red))
    tests.guard = load(HERE / 'candidate.py', 'readonly_reviewed_candidate')
    fresh = unittest.defaultTestLoader.loadTestsFromTestCase(tests.Classifier)
    if fresh.countTestCases() != packet['expected_new_methods']:
        raise RuntimeError('Frozen new suite shape changed')
    new_result = run(fresh)
    if not new_result['successful']:
        return 1
    prior = load(HERE.parent / 'inert_fixture_guard/test_candidate.py', 'readonly_retained_inert')
    prior.guard = tests.guard
    inert_suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        for cls in (prior.ReviewedCommand, prior.CanonicalEnvelope))
    if inert_suite.countTestCases() != 16:
        raise RuntimeError('Retained inert16 shape changed')
    inert = run(inert_suite)
    adapter = load(HERE.parent / 'native_adapter_guard/test_candidate.py', 'readonly_retained_adapter')
    adapter.guard = tests.guard
    native_suite = unittest.defaultTestLoader.loadTestsFromTestCase(adapter.NativeFlag)
    if native_suite.countTestCases() != 12:
        raise RuntimeError('Retained native-adapter12 shape changed')
    native_adapter = run(native_suite)
    if not inert['successful'] or not native_adapter['successful']:
        return 1
    # Keep the prior policy/wrapper/sentinel/preservation checks against THIS
    # candidate. Replace only superseded AST-diff assertions with our exact diff.
    q = load(HERE.parent / 'gateway_guard/qualify.py', 'readonly_retained_gateway')
    q.GUARD = HERE / 'candidate.py'
    obsolete = {'test_decide_gains_only_the_new_pass', 'test_only_the_declared_definitions_changed',
                'test_candidate_patch_is_the_exact_diff'}
    retained = {name: value for name, value in vars(q.PinTests).items()
        if name.startswith('test_') and name not in obsolete}
    q.PinTests = type('ReadonlyCandidateAndRetainedChecks', (Scope,), retained)
    original_load = q.load
    def candidate_load(file, name):
        module = original_load(file, name)
        if hasattr(module, 'guard'):
            module.guard.ROOT = q.INPUTS
            module.guard.RESTORE_HELPER = HERE / 'restore-save-backup.py'
        return module
    q.load = candidate_load
    prior_code = q.main()
    verify()
    if os.path.lexists(prefix):
        raise RuntimeError('Private bytecode namespace unexpectedly appeared')
    print(json.dumps({'kind': packet['kind'], 'candidate_sha256': sha(HERE / 'candidate.py'),
        'baseline_red': red, 'new': new_result, 'retained_inert': inert,
        'retained_native_adapter': native_adapter, 'retained_policy_exit': prior_code,
        'source_stable': True, 'actual_host_hook_acceptance': False, 'native_acceptance': False,
        'payload_strings_executed': False, 'actual_game_or_save_operation': False}))
    return prior_code


if __name__ == '__main__':
    sys.exit(main())
