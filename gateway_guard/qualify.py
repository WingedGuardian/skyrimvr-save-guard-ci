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


# This packet (2026-11-02) adds a per-command pass, file_tool_change, so the guard body differs from the baseline (the deployed
# 70d76e6b guard). What may differ is declared here, by name, and enforced in both directions.
DECLARED_CHANGES = {
    'ARCHIVERS',
    'BLOCK_WORDS',
    'CHDIR_BACK',
    'CHDIR_WORDS',
    'CODE_CHANGES_FILES',
    'COMPRESSORS',
    'COMPRESS_READS',
    'DELETE_TOOLS',
    'DOWNLOADERS',
    'EVAL_WORDS',
    'GIT_WRITES',
    'INLINE_CODE',
    'PAREN_METHOD',
    'PIPE_ACTIONS',
    'PIPE_FILTERS',
    'PIPE_LISTERS',
    'PIPE_METHOD',
    'PS_CARRIERS',
    'PS_WRITE_ALIASES',
    'QUOTED_MARK',
    'RCLONE_READS',
    'RELATIVE_DELETE',
    'RELATIVE_WRITE',
    'RSYNC_VALUE_FLAGS',
    'RSYNC_WRITTEN_VALUES',
    'SCP_VALUE_FLAGS',
    'SHELL_CARRIERS',
    'START_WORDS',
    'TAR_VALUE_LETTERS',
    'TRANSFER_ALIASES',
    'WRAPPER_VALUE_FLAGS',
    'WRAPPER_WORDS',
    '_FILE_PROGRAMS',
    '_NODE_FS',
    '_NODE_WRITES',
    '_REDIRECT',
    '_REMOTE',
    '_archiver_writes',
    '_braced',
    '_comma_lists_as_one_word',
    '_command_of',
    '_download_target',
    '_heredoc_body',
    '_inner_command',
    '_is_location',
    '_joined',
    '_judge_written',
    '_masked',
    '_piped_change',
    '_powershell_target',
    '_rclone_writes',
    '_resolved',
    '_rsync_scp_writes',
    '_shell_words',
    '_split_on_ampersand',
    '_substitutions',
    '_tar_writes',
    '_transfer_alias',
    '_without_heredoc_bodies',
    '_without_redirects',
    '_written_paths',
    'changes_files',
    'decide',
    'file_tool_change',
    'operation',
    'outward_copy',
    'transfer_form',
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


BASELINE_SHA256 = '70d76e6bba509f0c3aa3c0ba5da7a3c91e5ae9322908b34dc0cd17cce35febc3'  # deployed, the runtime classifier repair


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

    def test_decide_gains_only_the_new_pass(self):
        """Any other edit inside decide() -- the canary, encoded commands, folder rules, approvals -- fails here."""
        base = (HERE/'baseline-guard.py').read_text(encoding='utf-8')
        # the two declared in-place edits
        one = 'if MUTATE.search(code) and (mentions_save_location(code)'
        two = 'if FOLDER.search(acting) and MUTATE.search(acting):'
        self.assertEqual(1, base.count(one)); self.assertEqual(1, base.count(two))
        base = base.replace(one, 'if changes_files(code) and (mentions_save_location(code)')
        base = base.replace(two, "if (FOLDER.search(acting) and changes_files(acting)) or (form and _named_folders(acting, cwd, lambda p, wild: in_save_location(p))):")
        got = changes(body(base, 'decide'), body(GUARD.read_text(encoding='utf-8'), 'decide'))
        self.assertEqual(1, len(got), got)
        tag, old, new = got[0]
        self.assertEqual(('insert', []), (tag, old))
        self.assertEqual(1, len(new))
        self.assertTrue(new[0].startswith("if isinstance(args, str) or (not tool.startswith('mcp__') and"), new[0])
        self.assertIn('written = file_tool_change(text, cwd, tool, base)', new[0])

    def test_invoked_scripts_is_untouched(self):
        base, cand = (HERE/'baseline-guard.py').read_text(encoding='utf-8'), GUARD.read_text(encoding='utf-8')
        self.assertEqual(body(base, 'invoked_scripts')[0], body(cand, 'invoked_scripts')[0])

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
                'SaveFolders','LockSwitch','GatewayFreezeReadOnly','GatewayLifecycleNonSave','RuntimeRequests',
                'FileToolsThatChangeSaves')
    suite = unittest.TestSuite()
    windows_policy = os.name == 'nt' and '--portable-only' not in sys.argv[1:]
    windows_only = {('FreeOperations', 'test_free'),
                    ('SaveFolders', 'test_code_and_prose_are_not_whole_folder_targets'),
                    ('GatewayLifecycleNonSave', 'test_frozen_manifest_and_dependency_drift_refuse'),
                    ('FileToolsThatChangeSaves', 'test_each_tool_that_changes_saves_is_guarded')}   # Windows path forms; the hook runs on Windows
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
