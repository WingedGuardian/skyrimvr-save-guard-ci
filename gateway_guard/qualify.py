"""Targeted private CI for a project-local guard; no deploy or runtime interface."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
INPUTS = HERE/'inputs'
PREFIX = '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28'
BASE = INPUTS/PREFIX
GUARD = INPUTS/'.claude/hooks/protect-save-access.py'
RUNNER = PREFIX+'/native_batch_run.py'
ADAPTER = PREFIX+'/reference_adapter.py'


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def tables(path):
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    names = ('READ_ONLY_SCRIPT_VERBS', 'REVIEWED_NON_SAVE_LIFECYCLE')
    values = {n.targets[0].id:ast.literal_eval(n.value) for n in tree.body
              if isinstance(n, ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0], ast.Name)
              and n.targets[0].id in names}
    other = ast.dump(ast.Module(body=[n for n in tree.body if not (
        isinstance(n, ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id in names)], type_ignores=[]))
    return values, other


# This packet (2026-11-01) changes classifier ALGORITHMS, so unlike the earlier pins-only packets the guard body is
# expected to differ from the baseline (the deployed 4c11cc98... guard). What may differ is declared here, by name,
# and enforced in both directions: nothing outside the list changed, and everything on the list really did.
DECLARED_CHANGES = {
    'HELPER', 'RUNTIME_CALL', 'helper_execution_text',           # removed (user ruling 2026-11-01: names, not code)
    'RUNTIME_PAIR', 'RUNTIME_QUERY', 'RUNTIME_FUNCTIONS', 'RUNTIME_ACTIONS', 'RUNTIME_CONSOLE', 'RUNTIME_CONTEXT',
    '_TOOLS', 'RUNTIME_TOOL', 'RUNTIME_TOKEN', 'runtime_request',  # added: the structural runtime classifier
    'RUNTIME_TOOL_KEYS', 'RUNTIME_CALL_TOOL', 'RUNTIME_FILE_BODY', 'RUNTIME_SENDER', 'TEXT_TOOLS', 'only_text_tools', 'TEXT_TOOL_EXECUTES',
    'TEXT_TOOL_SUBCOMMANDS',
    'SHELL_TOOLS',                                                 # added: which tools carry a shell command line
    'invoked_scripts',                                             # changed: source handed to an interpreter
    'decide',                                                      # changed: the three call sites
}


def top_level(path):
    """{name: ast dump} for every top-level def/class/assignment. Any other statement is keyed by its own content, not
    its position (adding a definition above an unchanged `if` must not make that `if` look changed), so an edited one
    appears as one key removed and one added -- both undeclared, so the test still fails on it."""
    out = {}
    for node in ast.parse(Path(path).read_text(encoding='utf-8')).body:
        dump = ast.dump(node)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            key = node.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            key = node.targets[0].id
        else:
            key = '#%s:%s' % (type(node).__name__, hashlib.sha256(dump.encode()).hexdigest()[:16])
        out[key] = dump
    return out


BASELINE_SHA256 = '4c11cc98ffa28f4e01e1e5f52b43c3739e515e92046726a01f6a59ffb1202293'  # deployed 2026-11-01 02:10Z


def body(source, name):
    """(ast dumps, unparsed text) of the top-level statements of function `name`."""
    fn = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return [ast.dump(s) for s in fn.body], [ast.unparse(s) for s in fn.body]


def changes(before, after):
    import difflib
    matcher = difflib.SequenceMatcher(a=before[0], b=after[0], autojunk=False)
    return [(tag, before[1][i1:i2], after[1][j1:j2]) for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != 'equal']


class PinTests(unittest.TestCase):
    def test_the_baseline_is_the_deployed_guard(self):
        self.assertEqual(BASELINE_SHA256, sha(HERE/'baseline-guard.py'))

    def test_decide_changes_only_the_runtime_block_and_the_helper_name_rule(self):
        """Any other edit inside decide() -- the canary, encoded commands, folder rules, approvals -- fails here."""
        base = (HERE/'baseline-guard.py').read_text(encoding='utf-8')
        # the one declared in-place rename (inside the invoked-script loop)
        base = base.replace('RUNTIME_CALL.search(code)', 'runtime_request(code, need_target=False)')
        got = changes(body(base, 'decide'), body(GUARD.read_text(encoding='utf-8'), 'decide'))
        self.assertEqual(2, len(got), got)
        (tag1, old1, new1), (tag2, old2, new2) = got
        self.assertEqual('replace', tag1)
        self.assertEqual(2, len(old1)); self.assertTrue(old1[0].startswith('runtime_save = '))
        self.assertTrue(old1[1].startswith('if runtime_save and '))
        self.assertEqual(2, len(new1)); self.assertTrue(new1[0].startswith('structured = '))
        self.assertTrue(new1[1].startswith('if runtime_request(text) or '))
        old_if = ast.parse(old1[1]).body[0]; new_if = ast.parse(new1[1]).body[0]
        self.assertEqual([ast.dump(s) for s in old_if.body], [ast.dump(s) for s in new_if.body])  # same deny, same reason
        self.assertEqual(('delete', []), (tag2, new2))
        self.assertEqual(1, len(old2)); self.assertTrue(old2[0].startswith('if HELPER.search('))

    def test_invoked_scripts_only_gains_forms(self):
        base, cand = (HERE/'baseline-guard.py').read_text(encoding='utf-8'), GUARD.read_text(encoding='utf-8')
        got = changes(body(base, 'invoked_scripts'), body(cand, 'invoked_scripts'))
        self.assertTrue(got and all(tag == 'insert' for tag, _, _ in got), got)
        # what is inserted may only ADD forms: `invoked = []` before the return would pass a shape-only check and
        # remove every script inspection (second review 2026-11-01)
        # The one inserted `if` is pinned exactly: a prefix check let `if _depth < 1: invoked = []` through (third review).
        depth_block = ("if _depth < 1:\n    for token in list(invoked):\n        inner = next((v for v in token if v), '')\n"
                       "        if re.search('\\\\s', inner):\n            invoked += invoked_scripts(inner, _depth + 1)")
        for _, _, added in got:
            for statement in added:
                if statement.startswith('if '):
                    self.assertEqual(depth_block, statement)
                else:
                    self.assertTrue(statement.startswith(('invoked += ', 'source = ')), statement)

    def test_pin_tables_are_exactly_the_deployed_ones(self):
        old, _ = tables(HERE/'baseline-guard.py'); new, _ = tables(GUARD)
        self.assertEqual(old, new)

    def test_only_the_declared_definitions_changed(self):
        old, new = top_level(HERE/'baseline-guard.py'), top_level(GUARD)
        changed = {k for k in set(old) | set(new) if old.get(k) != new.get(k)}
        self.assertEqual(DECLARED_CHANGES, changed)

    def test_candidate_patch_is_the_exact_diff(self):
        import difflib
        before = (HERE/'baseline-guard.py').read_text(encoding='utf-8').splitlines(keepends=True)
        after = GUARD.read_text(encoding='utf-8').splitlines(keepends=True)
        diff = ''.join(difflib.unified_diff(before, after, 'a/protect-save-access.py', 'b/protect-save-access.py'))
        self.assertEqual(diff, (HERE/'candidate.patch').read_text(encoding='utf-8'))

    def test_exact_lifecycle_and_offline_freeze_admit(self):
        for tail in ['freeze --desktop pending']+[
                verb+' --desktop '+desktop for verb in ('prepare','publish','preflight','run','ready','stop','restore')
                for desktop in ('pending','current','background')]:
            self.assertTrue(guard.read_only_script_call(INPUTS/RUNNER, RUNNER, 'python '+RUNNER+' '+tail, str(INPUTS)), tail)

    def test_edited_sources_and_manifest_revoke_scope(self):
        original = guard.sha256
        spec = guard.REVIEWED_NON_SAVE_LIFECYCLE[RUNNER]
        frozen = json.loads((BASE/'engine-completion-15/inputs.json').read_bytes())
        paths = sorted({RUNNER, ADAPTER, PREFIX+'/native_run.py',
                        PREFIX+'/engine-completion-15/inputs.json',
                        *spec['dependencies'], *frozen})
        for relative in paths:
            changed = canonical(INPUTS/relative)
            with self.subTest(path=relative), patch.object(guard, 'sha256',
                    side_effect=lambda p: '0'*64 if canonical(p)==changed else original(p)):
                self.assertFalse(guard.read_only_script_call(INPUTS/RUNNER, RUNNER,
                    'python '+RUNNER+' prepare --desktop current', str(INPUTS)))

    def test_extra_chained_duplicate_and_load_arguments_are_not_exempt(self):
        for tail in ('prepare', 'prepare --desktop current --extra', 'load --desktop current',
                     'prepare --desktop unknown', 'prepare --desktop current; whoami',
                     'prepare --desktop current\nwhoami', 'prepare --desktop current && python '+RUNNER+' run --desktop current',
                     'prepare --desktop current C:/profile/Saves/a.ess'):
            self.assertFalse(guard.read_only_script_call(INPUTS/RUNNER, RUNNER, 'python '+RUNNER+' '+tail, str(INPUTS)), tail)

    def test_runtime_bytes_are_not_claimed_as_remote_acceptance(self):
        # Deliberate negative: without the documented missing-native-input shim,
        # this partial source packet cannot qualify the real installed runtime.
        with patch.object(guard, 'sha256', side_effect=real_sha):
            self.assertFalse(guard._pinned(INPUTS/RUNNER, guard.REVIEWED_NON_SAVE_LIFECYCLE[RUNNER]))


def canonical(path): return str(Path(str(path).replace('\\', '/')).resolve()).replace('\\', '/').casefold()


def main():
    manifest = json.loads((HERE/'payload-manifest.json').read_bytes())
    for row in manifest['files']:
        path = HERE/row['path']
        if not path.resolve().is_relative_to(HERE) or sha(path) != row['sha256']:
            raise ValueError('private_source_packet_changed:'+row['path'])
    os.environ['GUARD_SCRIPT'] = str(GUARD)
    global guard, real_sha
    policy = load(INPUTS/'.claude/hooks/test_protect_save_access.py', 'captured_guard_policy_tests')
    guard = policy.guard; real_sha = guard.sha256
    frozen = json.loads((BASE/'engine-completion-15/inputs.json').read_bytes())
    declared = {canonical(INPUTS/k):v for k,v in frozen.items()}
    for table in (guard.READ_ONLY_SCRIPT_VERBS, guard.REVIEWED_NON_SAVE_LIFECYCLE):
        for spec in table.values():
            for key, digest in spec.get('dependencies', {}).items():
                declared.setdefault(canonical(INPUTS/key), digest)
    simulated = set()
    def source_or_declared_hash(path):
        normalized = Path(str(path).replace('\\', '/'))
        if normalized.is_file(): return real_sha(normalized)
        key = canonical(normalized)
        if key in declared:
            simulated.add(key)
            return declared[key]
        return real_sha(normalized)
    guard.sha256 = source_or_declared_hash
    # Restore-helper tests load a second module; keep its diagnostic output in
    # the same disposable test directory, never the immutable source packet.
    original_load = policy.load
    def test_load(path, name):
        module = original_load(path, name)
        if hasattr(module, 'guard'): module.guard.ADVICE_LOG = guard.ADVICE_LOG
        return module
    policy.load = test_load
    selected = ('AlwaysDenied','BackupThenAllow','BackupFailureDenies','NeedsApproval',
                'RecursiveDeletes','Approvals','FreeOperations','RestoreHelper','HelperBasenames',
                'SaveFolders','LockSwitch','GatewayFreezeReadOnly','GatewayLifecycleNonSave','RuntimeRequests')
    suite = unittest.TestSuite()
    windows_policy = os.name == 'nt' and '--portable-only' not in sys.argv[1:]
    windows_only = {('FreeOperations', 'test_free'),
                    ('SaveFolders', 'test_code_and_prose_are_not_whole_folder_targets'),
                    ('GatewayLifecycleNonSave', 'test_frozen_manifest_and_dependency_drift_refuse')}
    excluded = []
    for name in selected:
        for test in unittest.defaultTestLoader.loadTestsFromTestCase(getattr(policy, name)):
            if not windows_policy and (name, test._testMethodName) in windows_only:
                excluded.append(name+'.'+test._testMethodName)
            else:
                suite.addTest(test)
    suite.addTest(policy.Wiring('test_subprocess_contract_and_safe_canary'))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PinTests))
    (BASE/'build').mkdir(exist_ok=True)
    sys.path.insert(0, str(BASE))
    adapter = load(BASE/'test_reference_adapter.py', 'captured_reference_adapter_tests')
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(adapter.ReferenceAdapterTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    unchanged = all(sha(HERE/row['path'])==row['sha256'] for row in manifest['files'])
    print(json.dumps(dict(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), exact_packet_unchanged=unchanged,
        scope='windows_full_policy_and_portable' if windows_policy else 'portable_policy_adapter_and_packet_pins',
        windows_only_fixture_methods_excluded=excluded, full_windows_policy_exercised=windows_policy,
        missing_native_inputs_simulated=len(simulated), native_acceptance=False,
        actual_host_hook_acceptance=False, game_calls=0, provider_calls=0)))
    return 0 if result.wasSuccessful() and unchanged else 1


if __name__ == '__main__': raise SystemExit(main())
