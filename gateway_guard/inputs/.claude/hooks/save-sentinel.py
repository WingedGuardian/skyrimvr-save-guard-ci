"""PostToolUse save sentinel: notices a save that changed WITHOUT a backup first, whatever changed it.

The PreToolUse save guard (protect-save-access.py) judges a command before it runs. It cannot see inside every
script, so a save changed by code that never spells a save folder slips past it (user ruling 2026-10-30: guard the
save folders, not the words -- this sentinel is what makes that loosening safe). After each tool call this compares
the save folders against the previous look and reports every .ess/.skse that was MODIFIED or REMOVED without a
backup record taken since then. It never blocks (PostToolUse cannot) and never touches a save: it lists and stats.

Watched: the guard's discovered save folders (top level, as the game keeps them) and every folder marked with
.protect-saves under _CLAUDE_OUTPUT (recursive, bounded). New saves are not reported: creating a save changes none.
While the game runs it may be the writer, so the note says so and is not raised to the user.

State: .claude/diag/save-sentinel.json (any session's view; a change made by another session is reported here
too, as "since the last look"). Log: .claude/diag/save-sentinel.log.
"""
import datetime
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HOOKS = Path(__file__).resolve().parent
ROOT = HOOKS.parents[1]
DIAG = ROOT / '.claude' / 'diag'
STATE = DIAG / 'save-sentinel.json'
LOG = DIAG / 'save-sentinel.log'
MANIFEST = ROOT / '.claude' / 'backups' / 'save-backups' / 'manifest.jsonl'
EXTS = ('.ess', '.skse')
MARKER = '.protect-saves'
MARKED_REFRESH = 3600          # seconds between searches for marked folders
MARKED_DEPTH = 4               # _CLAUDE_OUTPUT/<task>/<sub>/<sub>/.protect-saves at most
WALK_LIMIT = 20000             # entries per marked folder; a bigger one is reported as truncated
GAMES = ('SkyrimVR.exe', 'SkyrimSE.exe', 'Skyrim.exe')


def guard_module():
    path = HOOKS / 'protect-save-access.py'
    loader = importlib.machinery.SourceFileLoader('save_guard_for_sentinel', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def find_marked(base, depth=MARKED_DEPTH):
    found = []
    stack = [(str(base), 0)]
    while stack:
        folder, level = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        if any(e.name == MARKER and e.is_file() for e in entries):
            found.append(folder)
            continue                      # everything below is covered by the walk
        if level < depth:
            stack.extend((e.path, level + 1) for e in entries if e.is_dir(follow_symlinks=False))
    return sorted(found)


def look(save_dirs, marked):
    files, truncated = {}, []
    for d in save_dirs:
        try:
            for e in os.scandir(d):
                if e.name.lower().endswith(EXTS) and e.is_file():
                    st = e.stat()
                    files[os.path.normcase(e.path)] = [st.st_size, st.st_mtime_ns, e.path]
        except OSError:
            continue
    for m in marked:
        n = 0
        for folder, _, names in os.walk(m):
            for name in names:
                n += 1
                if name.lower().endswith(EXTS):
                    p = os.path.join(folder, name)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    files[os.path.normcase(p)] = [st.st_size, st.st_mtime_ns, p]
            if n > WALK_LIMIT:
                truncated.append(m)
                break
    return files, truncated


def backed_up_since(since):
    """Original paths (normcased) of every backup record written at or after `since` (epoch seconds)."""
    covered = set()
    try:
        lines = MANIFEST.read_text(encoding='utf-8').splitlines()
    except OSError:
        return covered
    for line in reversed(lines):
        try:
            row = json.loads(line)
            when = datetime.datetime.fromisoformat(row['time']).timestamp()
        except (ValueError, KeyError, TypeError):
            continue
        if when < since - 5:
            break                          # the manifest is append-only, newest last
        for key in ('ess', 'skse'):
            if isinstance(row.get(key), dict) and row[key].get('original'):
                covered.add(os.path.normcase(row[key]['original']))
        covered.update(os.path.normcase(o) for o in row.get('originals', []) if isinstance(o, str))
    return covered


def game_running():
    try:
        out = subprocess.run(['tasklist', '/NH', '/FO', 'CSV'], capture_output=True, text=True, timeout=5,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False
    return any('"' + g.lower() + '"' in out for g in GAMES)


REPLACE_ATTEMPTS = 10          # x 50 ms: another session's sentinel holds the state file for milliseconds, not seconds
READ_ATTEMPTS = 3


def log_line(**fields):
    try:
        DIAG.mkdir(parents=True, exist_ok=True)
        with LOG.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(dict(time=datetime.datetime.now().isoformat(timespec='seconds'), **fields)) + '\n')
    except OSError:
        pass


def read_state():
    """The previous look. A PermissionError here is another session's sentinel mid-replace (Windows holds the
    file for the duration): retry briefly rather than forget the previous look, because `state = {}` would also
    drop any save change made in that window from the report. Returns None when the file is still locked after
    the retries: the caller then compares against nothing this round but MUST NOT overwrite the look on disk, so the
    next round still compares against it. A missing or corrupt file is a genuine empty state ({})."""
    for attempt in range(READ_ATTEMPTS):
        try:
            return json.loads(STATE.read_text(encoding='utf-8'))
        except PermissionError:
            if attempt + 1 == READ_ATTEMPTS:
                return None
            time.sleep(0.05)
        except (OSError, ValueError):
            return {}


def save_state(state):
    """Atomic replace with a short retry; the temp file never outlives this call (two abandoned 2.5 MB
    .tmp-<pid> files, 2026-11-01 and 2026-11-02, were PermissionError on the replace with no cleanup)."""
    DIAG.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix('.tmp-' + str(os.getpid()))
    try:
        tmp.write_text(json.dumps(state), encoding='utf-8')
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(tmp, STATE)
                return
            except PermissionError as exc:
                if attempt + 1 == REPLACE_ATTEMPTS:
                    log_line(error=type(exc).__name__ + ': ' + str(exc)[:300], state_update='dropped after retries')
                    return
                time.sleep(0.05)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log_line(error='tmp cleanup: ' + type(exc).__name__ + ': ' + str(exc)[:200])


def check(payload):
    now = time.time()
    state = read_state()
    unreadable = state is None                   # locked past the retries: look, but keep the look on disk intact
    if unreadable:
        state = {}
    guard = guard_module()
    save_dirs = [str(d) for d in guard.KNOWN_SAVE_DIRS if os.path.isdir(d)]
    marked = state.get('marked')
    if marked is None or now - state.get('marked_time', 0) > MARKED_REFRESH:
        marked = find_marked(ROOT / '_CLAUDE_OUTPUT')
        state['marked_time'] = now
    files, truncated = look(save_dirs, marked)
    previous = state.get('files')
    since = state.get('time', now)
    message, loud = None, False
    if isinstance(previous, dict):
        changed = []
        for key, (size, mtime, path) in previous.items():
            now_row = files.get(key)
            if now_row is None:
                changed.append(('removed', path))
            elif now_row[0] != size or now_row[1] != mtime:
                changed.append(('modified', path))
        if changed:
            covered = backed_up_since(since)
            unbacked = [(how, p) for how, p in changed if os.path.normcase(p) not in covered]
            if unbacked:
                running = game_running()
                lines = ['  ' + how + ': ' + p for how, p in unbacked[:15]]
                if len(unbacked) > 15:
                    lines.append('  ... and %d more' % (len(unbacked) - 15))
                message = ('SAVE SENTINEL: %d save file(s) changed since the last look with no backup taken first '
                           '(tool: %s).\n' % (len(unbacked), payload.get('tool_name', '?')) + '\n'.join(lines)
                           + ('\nThe game is running, so it may be the game itself saving.' if running else
                              '\nThe save guard did not back these up. If a command or script you ran did this, '
                              'tell the user now; check the Recycle Bin for removed files.'))
                with LOG.open('a', encoding='utf-8') as fh:
                    fh.write(json.dumps({'time': datetime.datetime.now().isoformat(timespec='seconds'),
                                         'tool': payload.get('tool_name', ''), 'game_running': running,
                                         'changes': unbacked[:50]}, ensure_ascii=False) + '\n')
                loud = not running
    if truncated:
        note = 'SAVE SENTINEL: marked folder(s) too large to watch fully: ' + ', '.join(truncated)
        message = (message + '\n' + note) if message else note
    folders = list(dict.fromkeys(save_dirs + [os.path.dirname(p) for _, _, p in files.values()]))
    lock_note = auto_lock(state, files, folders, now)
    enabled = bool(lock_config().get('enabled'))
    if state.get('lock_enabled') and not enabled:
        note = ('SAVE LOCK: save locking was switched OFF (.claude/save-lock.json changed or removed). '
                'If you did not do this, an agent or script did; switch it back on with `python tools/save_lock.py on`.')
        message = (message + '\n' + note) if message else note
        loud = True
    state['lock_enabled'] = enabled
    if lock_note:
        message = (message + '\n' + lock_note) if message else lock_note
    elevated = elevated_note(state, now)
    if elevated:
        message = (message + '\n' + elevated) if message else elevated
        loud = True
    state.update({'time': now, 'files': files, 'marked': marked})
    if unreadable:
        log_line(note='state file locked past retries; this round not saved so the previous look survives')
    else:
        save_state(state)
    return message, loud


LOCK_CONFIG = ROOT / '.claude' / 'save-lock.json'
LOCK_VERIFY_S = 3600


def lock_config():
    """{'enabled': bool, 'include_rotating': bool} -- locking is OFF unless the user turned it on."""
    try:
        data = json.loads(LOCK_CONFIG.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {'enabled': False}
    return data if isinstance(data, dict) else {'enabled': False}


def save_lock_module():
    path = ROOT / 'tools' / 'save_lock.py'
    loader = importlib.machinery.SourceFileLoader('save_lock_for_sentinel', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def auto_lock(state, files, folders, now):
    """Lock every settled save the sentinel has not locked yet (tools/save_lock.py: the OS then refuses to delete or
    change it until the user unlocks it elevated). Tracks its own locks in `state`, so a call locks only new or
    changed saves; a full re-check from one icacls listing per folder runs at most hourly."""
    cfg = lock_config()
    if not cfg.get('enabled') or os.name != 'nt':
        return ''
    sl = save_lock_module()
    sid = sl.user_sid()
    locked = state.setdefault('locked', {})
    if now - state.get('lock_verified', 0) > LOCK_VERIFY_S:
        locked.clear()
        for folder in folders:
            try:
                locked.update({os.path.normcase(p): True for p, ok in sl.status_map(folder).items() if ok})
                if not sl.is_locked(folder):
                    sl.lock_folder(folder, sid)
            except OSError:
                continue
        state['lock_verified'] = now
    previous = state.get('files') or {}
    done, failed = 0, []
    for key, (size, mtime, path) in files.items():
        changed = key in previous and previous[key][:2] != [size, mtime]
        if key in locked and not changed:
            continue                       # locked, and not changed since the last look: nothing to do
        name = os.path.basename(path)
        if (not cfg.get('include_rotating') and sl.ROTATING.match(name)) or now - mtime / 1e9 < sl.SETTLE_S:
            locked.pop(key, None)
            continue
        try:
            sl.lock_file(path, sid)
            locked[key] = True
            done += 1
        except OSError as exc:
            failed.append(path)
    for key in [k for k in locked if k not in files]:
        del locked[key]
    if failed:
        return 'SAVE LOCK: could not lock %d save file(s): %s' % (len(failed), ', '.join(failed[:5]))
    return ''


ELEVATED_REPEAT_S = 12 * 3600


def elevated_note(state, now):
    """Save locks stop only non-admin processes; a hook inherits the agent's rights, so an elevated hook means an
    elevated agent that can lift any lock unprompted. Raised to the user at most every 12 hours while locking is on."""
    if not lock_config().get('enabled') or os.name != 'nt':
        return ''
    if not save_lock_module().is_elevated():
        state.pop('elevated_warned', None)
        return ''
    if 'elevated_warned' in state and now - state['elevated_warned'] < ELEVATED_REPEAT_S:
        return ''
    state['elevated_warned'] = now
    return ('SAVE LOCK: this agent session runs as administrator, so the save locks do NOT protect your saves from '
            'it. Restart the agent from a normal (non-admin) terminal.')


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    try:
        message, loud = check(payload)
    except Exception as exc:            # a sentinel that crashes must not break the tool call
        try:
            DIAG.mkdir(parents=True, exist_ok=True)
            with LOG.open('a', encoding='utf-8') as fh:
                fh.write(json.dumps({'time': datetime.datetime.now().isoformat(timespec='seconds'),
                                     'error': type(exc).__name__ + ': ' + str(exc)[:300]}) + '\n')
        except OSError:
            pass
        return 0
    if message:
        out = {'hookSpecificOutput': {'hookEventName': 'PostToolUse', 'additionalContext': message}}
        if loud:
            out['systemMessage'] = message
        print(json.dumps(out))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
