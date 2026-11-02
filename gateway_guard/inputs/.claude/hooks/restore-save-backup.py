"""Restore one save pair (.ess + .skse) from the save-guard backup store, hash-verified.

  python restore-save-backup.py list [text]          records, newest last (filter on text)
  python restore-save-backup.py show <record-id>     one record in full
  python restore-save-backup.py restore <record-id> [--dry-run] [--recycle-extra]

A restore puts BOTH files of the recorded pair back where they were. Before writing, the
current pair is itself backed up through the guard (so a restore can be undone). Each
backup copy is checked against its recorded SHA-256 before use, written beside the
original under a temporary name, verified, then swapped in with os.replace and verified
again.

If the record has no co-save (or no .ess) but one exists now, the stale file would
not match the restored partner: the restore refuses unless --recycle-extra is given, which
sends that file to the Recycle Bin after it has been backed up.

Run it through an agent session or by hand; either way the pre-restore backup happens.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
_loader = importlib.machinery.SourceFileLoader('save_guard', str(HERE / 'protect-save-access.py'))
_spec = importlib.util.spec_from_loader('save_guard', _loader)
guard = importlib.util.module_from_spec(_spec)
_loader.exec_module(guard)


def recycle(path):
    script = ("Add-Type -AssemblyName Microsoft.VisualBasic; "
              "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($args[0], 'OnlyErrorDialogs', 'SendToRecycleBin')")
    subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script, path], check=True)
    if os.path.lexists(path):
        raise RuntimeError(f'{path} is still present after the Recycle Bin call')


def restore(record, dry_run, recycle_extra):
    plan, extra = [], []
    for kind in ('ess', 'skse'):
        entry = record.get(kind)
        original = record['originals'][0 if kind == 'ess' else 1] if record.get('originals') else None
        if entry:
            if not os.path.isfile(entry['backup']):
                raise RuntimeError(f"backup file missing: {entry['backup']}")
            if guard.sha256(entry['backup']) != entry['sha256']:
                raise RuntimeError(f"backup file does not match its recorded hash: {entry['backup']}")
            plan.append((entry['original'], entry['backup'], entry['sha256']))
        elif original and os.path.lexists(original):
            extra.append(original)
    if not plan:
        raise RuntimeError('this record holds no backed-up file (nothing existed when it was taken)')
    if extra and not recycle_extra:
        raise RuntimeError('the record has no copy of ' + ', '.join(extra) + ', which exists now and would not '
                           'match the restored partner. Re-run with --recycle-extra to send it to the Recycle Bin '
                           '(after it is backed up).')
    if dry_run:
        return {'dry_run': True, 'restore': [{'original': o, 'from': b, 'sha256': h} for o, b, h in plan],
                'recycle': extra}
    current = [p for p in record.get('originals', []) if p]
    rows = guard.backup_pairs(current, 'restore-pre', 'restore-save-backup.py', 'restore ' + record['id'], 'none',
                              deadline=float('inf'))
    for original, backup, digest in plan:
        temp = original + '.restore-tmp'
        guard.shutil.copy2(backup, temp)
        if guard.sha256(temp) != digest:
            raise RuntimeError(f'copy of {backup} did not verify; {original} was not touched')
        os.replace(temp, original)
        if guard.sha256(original) != digest:
            raise RuntimeError(f'{original} does not match the backup after the swap')
    for path in extra:
        recycle(path)
    return {'restored': [{'original': o, 'sha256': h} for o, _, h in plan], 'recycled': extra,
            'pre_restore_backup': [r['id'] for r in rows]}


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    records = guard.manifest_records()
    if argv[0] == 'list':
        needle = ' '.join(argv[1:]).lower()
        for r in records:
            line = f"{r.get('id')}  {r.get('time')}  {r.get('operation')}  {(r.get('originals') or ['?'])[0]}  {r.get('note', '')}"
            if needle in line.lower():
                print(line)
        return 0
    if len(argv) < 2:
        print(__doc__)
        return 2
    record = next((r for r in records if r.get('id') == argv[1]), None)
    if record is None:
        print(f'no record {argv[1]}', file=sys.stderr)
        return 2
    if argv[0] == 'show':
        print(json.dumps(record, indent=2, ensure_ascii=False))
        return 0
    if argv[0] == 'restore':
        try:
            result = restore(record, '--dry-run' in argv, '--recycle-extra' in argv)
        except Exception as exc:
            print(json.dumps({'ok': False, 'error': str(exc)}))
            return 1
        print(json.dumps(dict(ok=True, **result), indent=2, ensure_ascii=False))
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
