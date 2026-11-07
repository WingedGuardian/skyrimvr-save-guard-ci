"""Exact candidate plus retained regressions; no real save or native execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent


def load(file, name):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify():
    manifest = json.loads((HERE / 'payload-manifest.json').read_bytes())
    for relative, expected in manifest['files'].items():
        file = (HERE / relative).resolve()
        if not file.is_relative_to(HERE) or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Native adapter packet drift: ' + relative)
    for relative, expected in manifest['referenced_manifests'].items():
        file = (HERE.parent / relative).resolve()
        if not file.is_relative_to(HERE.parent) or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Referenced manifest drift: ' + relative)
        packet = json.loads(file.read_bytes())
        files = packet['files']
        rows = files.items() if isinstance(files, dict) else ((row['path'], row['sha256']) for row in files)
        for name, wanted in rows:
            entry = (file.parent / name).resolve()
            if not entry.is_relative_to(file.parent) or hashlib.sha256(entry.read_bytes()).hexdigest() != wanted:
                raise RuntimeError('Referenced source drift: ' + name)


def main():
    verify()
    tests = load(HERE / 'test_candidate.py', 'native_adapter_flag_tests')
    suite = unittest.defaultTestLoader.loadTestsFromModule(tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    prior = load(HERE.parent / 'inert_fixture_guard/test_candidate.py', 'retained_inert_tests')
    prior.guard = tests.guard
    retained_suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        for cls in (prior.ReviewedCommand, prior.CanonicalEnvelope))
    retained_result = unittest.TextTestRunner(verbosity=2).run(retained_suite)
    if not retained_result.wasSuccessful():
        return 1
    q = load(HERE.parent / 'gateway_guard/qualify.py', 'retained_gateway_qualification')
    q.GUARD = HERE / 'candidate.py'
    obsolete = {'test_decide_gains_only_the_new_pass', 'test_only_the_declared_definitions_changed',
                'test_candidate_patch_is_the_exact_diff'}
    retained = {name: value for name, value in vars(q.PinTests).items()
                if name.startswith('test_') and name not in obsolete}
    # Frozen packet invariants remain in addition to new candidate AST-only scope.
    q.PinTests = type('CandidateAndRetainedChecks', (prior.ScopeInvariant,), retained)
    original = q.load
    def candidate_load(file, name):
        module = original(file, name)
        if hasattr(module, 'guard'):
            module.guard.ROOT = q.INPUTS
            module.guard.RESTORE_HELPER = HERE / 'restore-save-backup.py'
        return module
    q.load = candidate_load
    code = q.main()
    verify()
    print(json.dumps({'candidate_sha256': hashlib.sha256((HERE / 'candidate.py').read_bytes()).hexdigest(),
        'new_classifier_methods': suite.countTestCases(), 'retained_inert_methods': retained_suite.countTestCases(),
        'candidate_packet_unchanged': True, 'source_fixture_only': True,
        'actual_host_acceptance': False, 'native_or_save_execution': False, 'result': code}))
    return code


if __name__ == '__main__':
    sys.exit(main())
