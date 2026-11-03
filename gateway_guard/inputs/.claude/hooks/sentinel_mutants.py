"""Mutation twins for the sentinel state-file race fix: each twin breaks one guard in a TEMP copy of the sentinel
and requires the NAMED test to go red; the unmutated copy must be green first or nothing here means anything.
Never edits the real sentinel.

    python sentinel_mutants.py <sentinel.py> <test_save_sentinel.py>      exit 0 = every twin killed
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

TWINS = [
    ('no-retry', 'for attempt in range(REPLACE_ATTEMPTS):', 'for attempt in range(1):',
     'test_save_sentinel.StateFileRace.test_replace_retries_then_succeeds_and_leaves_no_tmp'),
    ('no-cleanup', '            tmp.unlink()\n', '            pass\n',
     'test_save_sentinel.StateFileRace.test_permanent_replace_failure_removes_tmp_and_logs_once'),
    ('no-read-retry', 'for attempt in range(READ_ATTEMPTS):', 'for attempt in range(1):',
     'test_save_sentinel.StateFileRace.test_transient_read_failure_keeps_the_previous_look'),
]


def run_named(sentinel_path, test_file, name):
    env = dict(os.environ, SENTINEL_SCRIPT=str(sentinel_path), PYTHONDONTWRITEBYTECODE='1')
    r = subprocess.run([sys.executable, '-B', '-m', 'unittest', name], cwd=str(Path(test_file).parent),
                       env=env, capture_output=True, text=True)
    return r.returncode == 0


def main(argv):
    sentinel, test_file = Path(argv[1]).resolve(), Path(argv[2]).resolve()
    source = sentinel.read_text(encoding='utf-8')
    killed = 0
    with tempfile.TemporaryDirectory() as d:
        clean = Path(d) / 'save-sentinel.py'
        clean.write_text(source, encoding='utf-8')
        for _, _, _, name in TWINS:
            if not run_named(clean, test_file, name):
                print('BASELINE RED on the unmutated copy:', name)
                return 2
        for label, old, new, name in TWINS:
            if source.count(old) != 1:
                print('ANCHOR MISSING for twin', label, repr(old))
                return 2
            mutant = Path(d) / ('save-sentinel-' + label + '.py')
            mutant.write_text(source.replace(old, new), encoding='utf-8')
            survived = run_named(mutant, test_file, name)
            print(('SURVIVED ' if survived else 'killed   ') + label + ' <- ' + name.rsplit('.', 1)[1])
            killed += not survived
    print(f'SENTINEL TWINS: {killed}/{len(TWINS)} killed')
    return 0 if killed == len(TWINS) else 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
