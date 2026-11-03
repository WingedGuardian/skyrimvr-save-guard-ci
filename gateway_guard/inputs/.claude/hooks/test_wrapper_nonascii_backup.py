"""CI ONLY. The real backup and restore path with a non-ASCII save location, end to end through the rendered wrapper.

Commands naming such a path used to crash into a "malformed input" deny before reaching the backup code; with the guard
in UTF-8 mode they reach it for the first time, so it needs a real run. Fake saves in a temp folder, with temp copies of
the guard and restore helper, so the backup store is in the temp folder too. Not run on the install: a script that writes
to a folder of this name is, correctly, refused there, and the hosted runner has no saves to protect.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import render_wrapper  # noqa: E402

PS = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File']
PROFILE = 'fake-ü断”-profile'          # the close-quote's last byte is one cp1252 leaves undefined


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


@unittest.skipUnless(os.name == 'nt', 'the wrapper is Windows PowerShell')
class NonAsciiBackup(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name).resolve()
        self.d = d
        self.box = d / 'install' / '.claude' / 'hooks'
        self.box.mkdir(parents=True)
        for name in ('protect-save-access.py', 'restore-save-backup.py'):
            shutil.copy(HERE / name, self.box / name)
        saves = d / PROFILE / 'Saves'
        saves.mkdir(parents=True)
        self.ess, self.cosave = saves / 'Fake1.ess', saves / 'Fake1.skse'
        self.ess.write_bytes(b'fake-ess-original')
        self.cosave.write_bytes(b'fake-skse-original')
        self.manifest = d / 'install' / '.claude' / 'backups' / 'save-backups' / 'manifest.jsonl'

    def wrapper(self, template):
        path = self.box / 'save-access-entry.ps1'
        path.write_text(render_wrapper.render(template, sys.executable), encoding='utf-8', newline='\n')
        payload = {'tool_name': 'Bash', 'tool_input': {'command': 'rm "' + self.ess.as_posix() + '"'},
                   'hook_event_name': 'PreToolUse', 'cwd': str(self.d)}
        r = subprocess.run(PS + [str(path)], input=json.dumps(payload, ensure_ascii=False).encode('utf-8'), capture_output=True)
        return r.returncode, r.stdout.decode('utf-8', 'replace').strip()

    def template(self):
        return (HERE / 'save-access-entry.template.ps1').read_text(encoding='utf-8')

    def test_backup_then_allow_and_hash_verified_restore(self):
        before = sha(self.ess), sha(self.cosave)
        rc, out = self.wrapper(self.template())
        self.assertEqual((0, ''), (rc, out), 'a 1-save change must be allowed after its backup: ' + out[:300])
        self.assertTrue(self.ess.is_file(), 'the hook must not have changed the save itself')
        rows = [json.loads(x) for x in self.manifest.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(1, len(rows))
        rec = rows[0]
        norm = lambda p: str(p).replace('\\', '/').casefold()
        self.assertIn(norm(self.ess), [norm(o) for o in rec['originals']], 'the record must hold the true path, not mojibake')
        self.assertEqual(before, (rec['ess']['sha256'], rec['skse']['sha256']))
        self.assertEqual(before, (sha(rec['ess']['backup']), sha(rec['skse']['backup'])))
        self.ess.write_bytes(b'fake-ess-CHANGED')
        r = subprocess.run([sys.executable, '-B', str(self.box / 'restore-save-backup.py'), 'restore', rec['id']], capture_output=True)
        self.assertEqual(0, r.returncode, 'restore failed: ' + ascii(r.stdout[-300:]) + ascii(r.stderr[-400:]))
        self.assertEqual(before, (sha(self.ess), sha(self.cosave)), 'restore must return the original bytes')

    def test_twin_without_utf8_mode_this_command_never_reaches_the_backup(self):
        old = "'-B -X utf8 \"'"
        self.assertEqual(1, self.template().count(old))
        _, out = self.wrapper(self.template().replace(old, "'-B \"'"))
        self.assertIn('malformed input', out, 'mutant survived: the path reached the guard without UTF-8 mode')
        self.assertFalse(self.manifest.exists(), 'no backup should have been taken on the crash path')


if __name__ == '__main__':
    unittest.main(verbosity=2)
