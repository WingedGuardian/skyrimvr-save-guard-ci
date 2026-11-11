"""Save sentinel checks. Fake saves only, in a fresh temporary folder; the state, log and manifest are redirected
there. No real save is listed or touched. Run with:  python -m unittest test_save_sentinel  (from this folder)
"""
import datetime
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import patch


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# SENTINEL_SCRIPT points the suite at a candidate copy (stage/CI packet); default is the sentinel beside this file.
sentinel = load(Path(os.environ.get('SENTINEL_SCRIPT') or Path(__file__).with_name('save-sentinel.py')), 'save_sentinel')


class SentinelCase(unittest.TestCase):
    """Shared fixture: fake saves in a temp folder, every module path redirected there."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        t = Path(self._tmp.name)
        self.saves = t / 'Saves'
        self.saves.mkdir()
        self.out = t / '_CLAUDE_OUTPUT'
        self.kept = self.out / 'task' / 'baseline'
        self.kept.mkdir(parents=True)
        self.manifest = t / 'manifest.jsonl'
        fake_guard = types.SimpleNamespace(KNOWN_SAVE_DIRS=[self.saves])
        for name, value in (('STATE', t / 'state.json'), ('LOG', t / 'sentinel.log'), ('DIAG', t),
                            ('MANIFEST', self.manifest), ('ROOT', t), ('LOCK_CONFIG', t / 'save-lock.json')):
            p = patch.object(sentinel, name, value)
            p.start()
            self.addCleanup(p.stop)
        for target, value in (('guard_module', lambda: fake_guard), ('game_running', lambda: False)):
            p = patch.object(sentinel, target, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    def save(self, folder, stem, data=b'e'):
        for ext in ('.ess', '.skse'):
            (folder / (stem + ext)).write_bytes(data)
        return folder / (stem + '.ess')

    def step(self):
        return sentinel.check({'tool_name': 'Bash'})

    def bump(self, path, data):
        path.write_bytes(data)
        st = os.stat(path)
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))

    def record(self, *originals):
        row = {'time': (datetime.datetime.now() + datetime.timedelta(seconds=1)).isoformat(timespec='seconds'),
               'originals': [str(o) for o in originals]}
        with self.manifest.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(row) + '\n')


class Sentinel(SentinelCase):
    def test_first_look_is_silent_and_new_saves_are_not_reported(self):
        self.save(self.saves, 'a')
        self.assertEqual((None, False), self.step())
        self.save(self.saves, 'b')
        self.assertEqual((None, False), self.step())

    def test_an_unbacked_change_or_removal_is_reported_loudly(self):
        a = self.save(self.saves, 'a')
        self.save(self.saves, 'b')
        self.step()
        self.bump(a, b'changed')
        (self.saves / 'b.skse').unlink()
        message, loud = self.step()
        self.assertTrue(loud)
        self.assertIn('modified: ' + str(a), message)
        self.assertIn('removed: ' + str(self.saves / 'b.skse'), message)
        self.assertEqual((None, False), self.step())          # reported once, then the new state is the baseline

    def test_a_change_with_a_backup_record_is_not_reported(self):
        a = self.save(self.saves, 'a')
        self.step()
        self.record(a, a.with_suffix('.skse'))
        self.bump(a, b'changed')
        self.assertEqual((None, False), self.step())

    def test_a_marked_folder_is_watched_recursively(self):
        (self.kept / 'deep').mkdir()
        b = self.save(self.kept / 'deep', 'b')
        (self.kept / sentinel.MARKER).write_text('kept', encoding='utf-8')
        self.step()
        b.unlink()
        message, loud = self.step()
        self.assertIn('removed: ' + str(b), message)

    def test_while_the_game_runs_it_is_noted_not_raised(self):
        a = self.save(self.saves, 'a')
        self.step()
        self.bump(a, b'changed')
        with patch.object(sentinel, 'game_running', lambda: True):
            message, loud = self.step()
        self.assertFalse(loud)
        self.assertIn('may be the game itself', message)

    def fake_locks(self, elevated=False):
        calls = []
        fake = types.SimpleNamespace(
            is_elevated=lambda: elevated,
            ROTATING=__import__('re').compile(r'^(?:autosave|quicksave)', __import__('re').I), SETTLE_S=180,
            user_sid=lambda: 'S-1-5-21-x', status_map=lambda folder: {}, is_locked=lambda p: True,
            lock_folder=lambda p, sid: calls.append(('folder', p)),
            lock_file=lambda p, sid: calls.append(('file', os.path.basename(p))))
        return fake, calls

    def test_auto_lock_is_off_unless_enabled(self):
        fake, calls = self.fake_locks()
        old = time.time() - 3600
        a = self.save(self.saves, 'A')
        os.utime(a, (old, old))
        with patch.object(sentinel, 'save_lock_module', lambda: fake), patch.object(sentinel, 'lock_config', lambda: {}):
            self.step(); self.step()
        self.assertEqual([], calls)

    def test_auto_lock_locks_settled_saves_once_and_skips_rotating_and_fresh(self):
        fake, calls = self.fake_locks()
        old = time.time() - 3600
        for stem in ('A', 'Autosave1_x'):
            for ext in ('.ess', '.skse'):
                p = self.saves / (stem + ext); p.write_bytes(b'e'); os.utime(p, (old, old))
        self.save(self.saves, 'Fresh')                     # written just now: may still be in use
        with patch.object(sentinel, 'save_lock_module', lambda: fake), \
                patch.object(sentinel, 'lock_config', lambda: {'enabled': True}):
            self.step()
            self.assertEqual({'A.ess', 'A.skse'}, {n for k, n in calls if k == 'file'})
            calls.clear()
            self.step()                                     # already locked and unchanged: nothing again
            self.assertEqual([], [c for c in calls if c[0] == 'file'])
            self.bump(self.saves / 'A.ess', b'changed after a user unlock')
            self.step()                                     # changed: locked again once settled (mtime bumped +5 s)
        self.assertNotIn(('file', 'Autosave1_x.ess'), calls)

    def test_agent_test_saves_are_never_auto_locked(self):
        """User ruling 2026-11-10: ShinsoObserver_Headless_* test copies stay unlocked; every other settled save locks."""
        fake, calls = self.fake_locks()
        old = time.time() - 3600
        for stem in ('ShinsoObserver_Headless_Run7_20261110', 'shinsoobserver_headless_lower', 'Play_ShinsoObserver_Headless_'):
            for ext in ('.ess', '.skse'):
                p = self.saves / (stem + ext); p.write_bytes(b'e'); os.utime(p, (old, old))
        with patch.object(sentinel, 'save_lock_module', lambda: fake), \
                patch.object(sentinel, 'lock_config', lambda: {'enabled': True}):
            self.step(); self.step()
        self.assertEqual({'Play_ShinsoObserver_Headless_.ess', 'Play_ShinsoObserver_Headless_.skse'},
                         {n for k, n in calls if k == 'file'})

    def test_an_elevated_session_is_raised_once_while_locking_is_on(self):
        for enabled, elevated, expect in ((True, True, True), (True, False, False), (False, True, False)):
            STATE_FILE = sentinel.STATE
            if STATE_FILE.exists():
                STATE_FILE.unlink()                         # same-run test state
            fake, _ = self.fake_locks(elevated=elevated)
            with patch.object(sentinel, 'save_lock_module', lambda: fake), \
                    patch.object(sentinel, 'lock_config', lambda: {'enabled': enabled}), \
                    patch.object(sentinel.os, 'name', 'nt'):
                message, loud = self.step()
                self.assertEqual(expect, loud, (enabled, elevated))
                self.assertEqual(expect, 'runs as administrator' in (message or ''), (enabled, elevated))
                message, loud = self.step()                 # within 12 hours: not repeated
                self.assertFalse('runs as administrator' in (message or ''))

    def test_switching_locking_off_is_raised_to_the_user(self):
        fake, _ = self.fake_locks()
        with patch.object(sentinel, 'save_lock_module', lambda: fake):
            with patch.object(sentinel, 'lock_config', lambda: {'enabled': True}):
                self.step()
                message, loud = self.step()
                self.assertFalse('switched OFF' in (message or ''))
            with patch.object(sentinel, 'lock_config', lambda: {}):
                message, loud = self.step()
                self.assertTrue(loud)
                self.assertIn('switched OFF', message)
                message, loud = self.step()                 # said once, not on every call after
                self.assertFalse('switched OFF' in (message or ''))

    def test_a_crash_never_breaks_the_tool_call(self):
        with patch.object(sentinel, 'check', side_effect=RuntimeError('boom')), \
                patch('sys.stdin', types.SimpleNamespace(read=lambda: '{}')):
            self.assertEqual(0, sentinel.main())


class StateFileRace(SentinelCase):
    """Several sessions run the sentinel at once. On Windows a replace or read of the shared state file fails with
    PermissionError while another sentinel holds it open; before 2026-11-03 the write raised (abandoning a 2.5 MB
    .tmp-<pid> beside the state) and the read fell to `state = {}`, which forgot the previous look, so a save changed
    in that same window went unreported."""

    def failing_then_real(self, real, failures, calls):
        def side_effect(*a, **k):
            calls.append(1)
            if len(calls) <= failures:
                raise PermissionError(5, 'Access is denied')
            return real(*a, **k)
        return side_effect

    def tmp_files(self):
        return sorted(p.name for p in sentinel.DIAG.glob('*.tmp-*'))

    def test_replace_retries_then_succeeds_and_leaves_no_tmp(self):
        calls = []
        with patch.object(sentinel.os, 'replace', side_effect=self.failing_then_real(os.replace, 3, calls)), \
                patch.object(sentinel.time, 'sleep'):
            sentinel.save_state({'files': {}, 'time': 1.0})
        self.assertEqual(4, len(calls))
        self.assertEqual({'files': {}, 'time': 1.0}, json.loads(sentinel.STATE.read_text(encoding='utf-8')))
        self.assertEqual([], self.tmp_files())

    def test_permanent_replace_failure_removes_tmp_and_logs_once(self):
        calls = []
        with patch.object(sentinel.os, 'replace', side_effect=self.failing_then_real(os.replace, 10 ** 6, calls)), \
                patch.object(sentinel.time, 'sleep'):
            sentinel.save_state({'files': {}, 'time': 1.0})          # must not raise
        self.assertLessEqual(len(calls), 10)
        self.assertEqual([], self.tmp_files(), 'an abandoned .tmp-<pid> is the 2026-11-01/02 defect')
        lines = sentinel.LOG.read_text(encoding='utf-8').splitlines()
        self.assertEqual(1, len(lines))
        self.assertIn('PermissionError', lines[0])

    def test_transient_read_failure_keeps_the_previous_look(self):
        a = self.save(self.saves, 'a')
        self.step()                                                   # first look recorded
        self.bump(a, b'changed')
        real = Path.read_text
        calls = []
        state_path = str(sentinel.STATE)

        def read_text(self_path, *args, **kwargs):
            if str(self_path) == state_path:
                calls.append(1)
                if len(calls) == 1:
                    raise PermissionError(5, 'Access is denied')
            return real(self_path, *args, **kwargs)
        with patch.object(Path, 'read_text', read_text), patch.object(sentinel.time, 'sleep'):
            message, loud = self.step()
        self.assertTrue(loud, 'a locked state read must not forget the previous look: the change went unreported')
        self.assertIn('a.ess', message or '')
        self.assertEqual(2, len(calls))

    def test_read_locked_past_retries_keeps_the_look_on_disk_and_reports_next_round(self):
        """A lock that outlasts the retries costs one silent round, never the previous look: the state file is left
        exactly as it was, and the NEXT round reports the change made during the lock."""
        a = self.save(self.saves, 'a')
        self.step()
        before = sentinel.STATE.read_bytes()
        self.bump(a, b'changed')
        state_path = str(sentinel.STATE)
        real = Path.read_text

        def always_locked(self_path, *args, **kwargs):
            if str(self_path) == state_path:
                raise PermissionError(5, 'Access is denied')
            return real(self_path, *args, **kwargs)
        # the whole round is skipped: nothing below the read may run on a blank state (false lock notes, repeat warnings)
        ran = AssertionError('the round ran on a blank state')
        with patch.object(Path, 'read_text', always_locked), patch.object(sentinel.time, 'sleep'), \
                patch.object(sentinel, 'look', side_effect=ran), patch.object(sentinel, 'elevated_note', side_effect=ran):
            message, loud = self.step()
        self.assertEqual((None, False), (message, loud))
        self.assertEqual(before, sentinel.STATE.read_bytes(), 'an unreadable look must not be overwritten')
        message, loud = self.step()                                   # lock gone: the change is still reportable
        self.assertTrue(loud)
        self.assertIn('a.ess', message or '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
