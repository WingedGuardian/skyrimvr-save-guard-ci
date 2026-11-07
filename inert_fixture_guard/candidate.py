"""PreToolUse save guard for Claude and Codex: back up first, then allow.

Policy (user ruling 2026-10-13, "Save policy: back up first" in CLAUDE.md / AGENTS.md;
supersedes the 2026-10-11 individual-approval rule):

- A save is the PAIR: the .ess and its .skse co-save (same stem), whichever one is named.
- A tool call that CHANGES 1 or 2 saves (write, copy onto, move, rename, delete, clean,
  replace, restore, ReSaver write ops): this hook copies BOTH files of every affected pair
  into the backup store, verifies each copy by SHA-256, appends a manifest record and
  only then allows the call. No approval is needed. A missing co-save is recorded.
- More than 2 saves, any wildcard write, and anything the hook cannot count exactly
  (variables, relative or runtime-assembled paths, loops, listings fed into actions,
  helpers): needs a SAVE_ACCESS_APPROVAL line typed by the user in a genuine user turn.
  Once approved the saves are STILL backed up first.
- Reading, hashing, parsing, listing and copying saves OUT of their folder: always free.
- A failed backup (disk full, unreadable, hash mismatch, unresolvable path, time limit)
  DENIES the call: fail closed.
- Deleting, moving or renaming a whole Saves folder, a parent of one, or the backup
  store stays DENIED, approval or not. Backups are kept forever; nothing here prunes.
- Generic automated runtime save/load stays denied. Only the qualified pinned
  protected controller has a named-load exception; it independently verifies
  both pair backups, disabled known writers and an owned startup before dispatch.

Approval formats (one line, typed by the user, valid for the rest of the session):
  SAVE_ACCESS_APPROVAL {"files":[{"path":"<abs path>","operation":"delete"}, ...]}
  SAVE_ACCESS_APPROVAL {"set":{"command_sha256":"<16 hex>","operation":"delete","count":6}}
  SAVE_ACCESS_APPROVAL {"set":{"command_sha256":"<16 hex>","operation":"delete",
                               "folder":"<abs folder>","pattern":"Autosave*","count":6}}
The set form binds ONE exact command (its hash, printed by the deny message). "folder" and
"pattern" are required only when the hook cannot work out the saves itself; they name
what is backed up first, and the live count must equal "count".

Classification errs toward the stricter operation: any write indicator makes the command
a write, and a write the hook cannot pin down needs approval instead of passing.
"""
import datetime
from fnmatch import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
# Not named ".../saves/": a path component "saves" would make the store look like a Saves folder.
BACKUP_ROOT = ROOT / '.claude' / 'backups' / 'save-backups'
RESTORE_HELPER = Path(__file__).resolve().with_name('restore-save-backup.py')
TIME_BUDGET = 18.0            # seconds; hooks are killed (and FAIL OPEN) at 30
FREE_SPACE_MARGIN = 256 * 1024 * 1024
_DOCS = Path(os.path.expanduser('~')) / 'Documents' / 'My Games'
# The per-game folders under My Games, VR first. The GOG and Epic builds of SE/AE write under their own names
# (SKSE64's SAVE_FOLDER_NAME); same list as the toolkit's paths.GAME_FOLDERS.
GAME_FOLDERS = ('Skyrim VR', 'Skyrim Special Edition', 'Skyrim Special Edition GOG', 'Skyrim Special Edition EPIC',
                'Skyrim')
SAVE_PATH_KEY = re.compile(r'^\s*sLocalSavePath\s*=\s*(.*?)\s*$', re.I | re.M)


def _documents_folders():
    """Where Documents really is (a OneDrive-redirected one included), then the profile default."""
    found = []
    if os.name == 'nt':
        try:
            import ctypes
            import uuid
            guid = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID('FDD39AD0-238F-46AF-ADB4-6C85480369C7').bytes_le)
            out = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) == 0:
                found.append(Path(out.value))
                ctypes.windll.ole32.CoTaskMemFree(out)
        except Exception:
            pass                  # fall back to the profile default below
    found.append(Path(os.path.expanduser('~')) / 'Documents')
    return found


def _paths_env_values(key):
    try:
        text = (ROOT / '.claude' / 'skyrim-paths.env').read_text(encoding='utf-8-sig')
    except OSError:
        return []
    return [m.strip().strip('"\'') for m in re.findall(r'^\s*' + key + r'\s*=\s*(.+?)\s*$', text, re.M)]


def discover_save_dirs():
    """Every folder the game may read saves from. The VR default stays first (the protected load controller pins
    it). Sources: Documents (as Windows reports it) / My Games / each game folder / Saves; each game folder's
    sLocalSavePath override in its INIs; SKYRIM_CONFIG_DIR and SKYRIM_SAVE_DIRS from skyrim-paths.env or the
    environment. Missing folders are kept: a save folder created later is still protected."""
    dirs = [_DOCS / GAME_FOLDERS[0] / 'Saves']
    games = [docs / 'My Games' / name for docs in _documents_folders() for name in GAME_FOLDERS]
    games += [Path(v) for v in _paths_env_values('SKYRIM_CONFIG_DIR') + os.environ.get('SKYRIM_CONFIG_DIR', '').split(os.pathsep) if v]
    for game in games:
        dirs.append(game / 'Saves')
        for ini in ('Skyrim.ini', 'SkyrimCustom.ini', 'SkyrimVR.ini', 'SkyrimPrefs.ini'):
            try:
                text = (game / ini).read_bytes().decode('latin-1')
            except OSError:
                continue
            for value in SAVE_PATH_KEY.findall(text):
                value = value.strip('"\'').rstrip('\\/')
                if value:
                    dirs.append(Path(value) if os.path.isabs(value) else game / value)
    extra = _paths_env_values('SKYRIM_SAVE_DIRS') + os.environ.get('SKYRIM_SAVE_DIRS', '').split(os.pathsep)
    dirs += [Path(v) for v in extra if v.strip()]
    unique = {}
    for d in dirs:
        unique.setdefault(os.path.normcase(os.path.normpath(str(d))), d)
    return list(unique.values())


KNOWN_SAVE_DIRS = discover_save_dirs()

SAVE = re.compile(r'[^/\\\s\"\'(){};]+\.(?:ess|skse)(?:\.[\w.-]+)?(?:\:[\w:$]+)?$', re.I)
PAIR = re.compile(r'^(.*)\.(ess|skse)((?:\.[\w.-]+)?)(?::[\w:$]+)?$', re.I)
# A Saves directory as a PATH component (/Saves, \saves) or the bare capitalised shell word
# `Saves`. Prose such as "co-saves are gone" or "two saves" is not a folder reference.
FOLDER = re.compile(r'(?:[/\\](?:__mo_)?saves|(?<![\w-])(?-i:Saves))(?=[/\\\s\"\';|)&,]|$)', re.I)
MUTATE = re.compile(r'\b(?:move-item|copy-item|remove-item|rename-item|set-content|add-content|clear-content|out-file|mv|cp|rm|del|erase|robocopy|xcopy|touch|tee|truncate|dd|set-itemproperty|rmdir|rd|expand-archive|unzip)\b|shutil\.(?:move|copy\w*|rmtree)|\.(?:unlink|rename|replace|write_\w+|utime|open|delete|moveto|copyto)\s*\(|::(?:write|create|append|delete|move|copy|replace)\w*', re.I)
READ = re.compile(r'get-content|get-item\b|get-filehash|read_bytes|read_text|\.stat\s*\(|\bopen\s*\(|\b(?:cat|type|sha256sum|stat)\s', re.I)
EXTENSION = re.compile(r'\.(?:ess|skse)(?![\w])', re.I)
_NODE_FS = r'\bfs(?:\.promises)?\.'
_NODE_WRITES = r'(?:rename|unlink|rm|rmdir|copyfile|cp|writefile|appendfile|truncate|symlink|link|createwritestream|opensync|utimes)'
_FILE_PROGRAMS = r'(?:rsync|rclone|scp|shred|sdelete\d*|ln|mklink|gzip|gunzip|bzip2|xz|7z|7za|tar|bsdtar)'
# In code, not in a command line: a command is parsed by file_tool_change. A quoted program name is a subprocess call, a line
# that starts with one is a shell script, and the others are API names.
CODE_CHANGES_FILES = re.compile(r'[\'"]' + _FILE_PROGRAMS + r'[\'"]\s*,|(?m:^[ \t]*(?:sudo\s+)?' + _FILE_PROGRAMS + r'\s+(?!=))'
                                r'|\bos\.(?:sym)?link\s*\(|\bos\.remove\s*\(|\.(?:hardlink_to|symlink_to)\s*\(|\bunpack_archive\s*\('
                                r'|\.extractall\s*\(|' + _NODE_FS + _NODE_WRITES + r'|\b' + _NODE_WRITES + r'sync\s*\('
                                r'|\|\s*(?:%|foreach(?:-object)?)\s+(?:-membername\s+)?(?:delete|moveto|encrypt)\b|\|\s*(?:ri|remove-item)\b', re.I)


def changes_files(code):
    return bool(MUTATE.search(code) or CODE_CHANGES_FILES.search(code))
# A save LOCATION spelled in code: a Saves path component, the quoted component 'Saves' (os.path.join(..., 'Saves')),
# or the INI key that moves the folder. Not the bare word: "Saves your session stats" in a help string made every
# run of a 37k-line plugin script a counted save change (false positive, user 2026-10-30).
LOCATION = re.compile(r'[/\\](?:__mo_)?saves(?=[/\\\s\"\';|)&,]|$)'
                      # the quoted component keeps the folder's own capital: "saves" is a module or key name
                      # (assign_lanes.py lists skyguard modules; replay 2026-10-30)
                      r'|(?<![\w-])[\"\'](?-i:(?:__MO_)?Saves)[\"\']'
                      r'|\bslocalsavepath\b'
                      # the bare shell word as an ARGUMENT (`ls Saves)`, `cd Saves`, `Saves/a.ess`), never followed
                      # by a space: "Saves your session stats" stays prose
                      r'|(?<![\w-])(?-i:Saves)(?=[/\\\"\';|)&,]|$)', re.I | re.M)
# A DevBench request that saves or loads the game: policy keeps generic runtime save/load denied (CLAUDE.md), the
# pinned protected controller excepted. Judged by the request's STRUCTURE -- a key/value pair in any quoting, layout or
# language (JSON, Python dict or keywords, PowerShell @{}) -- never by word proximity. 2026-11-01 audit
# (rewrite-audit-2026-11-01): the old one-line 100-character word window refused `?name=game` followed by `json.load(`
# and missed every multiline, single-quoted and here-string request.
RUNTIME_PAIR = re.compile(r'(?<![\w$-])[\"\']?(action|function|command|tool|tool_?name|endpoint|name)[\"\']?\s*'
                          r'(?::|=>|=)\s*[\"\']([^\"\'\r\n]{0,200})[\"\']', re.I)
RUNTIME_QUERY = re.compile(r'[?&](action|tool)=([\w-]+)', re.I)
RUNTIME_FUNCTIONS = {'savegame', 'loadgame', 'requestsave', 'requestautosave', 'quittomainmenu'}
RUNTIME_ACTIONS = {'save', 'load', 'loadlast'}
RUNTIME_TOOL_KEYS = {'tool', 'tool_name', 'toolname', 'endpoint', 'name'}
RUNTIME_CONSOLE = re.compile(r'(?:^|;)\s*(?:save|load|savegame|loadgame|qsave|qload)\b', re.I)
RUNTIME_CONTEXT = re.compile(r'devbench|8921|/api/tool/|mcp__|localhost|127\.0\.0\.1', re.I)
# Where a request names its DevBench tool: a URL path, a variable-built URL ($B/game, ${env:X}/game, $($c.Base)/game),
# a URL template ('{}/game'.format(...), '%s/game' % ..., f'{BASE}/game'), a call whose first argument is the tool
# (api('tool/game', ...) or the gateway helpers' call('game', ...)), a concatenated path, or an MCP tool name.
# A bare tuple fixture -- [('tool/game', {...})] in a test that checks the request is REFUSED -- names no tool: the
# 2026-11-01 replay found the gateway's own tests run that way (test_single_owner_exit.py). User decision 2026-11-01
# (precise over conservative): a loop that SENDS such tuples stays a known gap.
_TOOLS = r'(game|console|papyrus|scenario)'
RUNTIME_CALL_TOOL = (r'\b(?!(?:get|pop|setdefault|startswith|endswith|count|index|find|replace|split)\b)\w+\s*\(\s*'
                     r'[rRfFbB]{0,2}[\"\'](?:[^\"\'\r\n]*/)?' + _TOOLS + r'[\"\']\s*,')
RUNTIME_TOOL = re.compile(r'/api/tool/' + _TOOLS + r'\b'
                          r'|\$(?:\{[^}\s]{1,80}\}|\([^)\r\n]{1,80}\)|\w+(?::\w+)?)/' + _TOOLS + r'\b'
                          r'|[\"\'][^\"\'\r\n]{0,200}?(?:\{[^}\"\'\r\n]{0,80}\}|%s|%\(\w+\)s)/(?:tool/)?' + _TOOLS + r'[\"\']'
                          # the tool, then its body: call('game', {...}); never a lookup such as consent.get('game')
                          r'|' + RUNTIME_CALL_TOOL +
                          r'|\+\s*[rRfFbB]{0,2}[\"\']/?(?:tool/)?' + _TOOLS + r'[\"\']'
                          r'|mcp__[\w-]*?__' + _TOOLS + r'\b', re.I)
RUNTIME_TOKEN = re.compile(r'[\"\'](?:save|load|loadlast)[\"\']', re.I)
# A body the hook cannot read (curl -d @file, Invoke-RestMethod -InFile) aimed at the game tool may save or load.
RUNTIME_FILE_BODY = re.compile(r'(?:^|\s)(?:-d|--data[\w-]*|--json)\s+[\"\']?@|(?:^|\s)-InFile\s', re.I)
# A COMMAND made only of text tools (a commit message, an echo, an rg) that QUOTES a request sends nothing (review
# 2026-11-01) -- unless a sender appears anywhere in it. Fail-safe: any other program, including an unknown client
# (`client.send({'tool': 'game', ...})`), counts as a possible sender. Script sources are judged without this
# (need_target=False): a script that holds a request is assumed to send it, as before.
TEXT_TOOLS = {'git', 'gh', 'rg', 'grep', 'egrep', 'fgrep', 'echo', 'printf', 'write-output', 'write-host',
              'select-string', 'sls', 'findstr', 'get-content', 'gc', 'cat', 'head', 'tail', 'wc', 'uniq', 'cut', 'tr'}
# Second review 2026-11-01: text a shell still EXECUTES inside a text tool -- command substitution (backticks, $(...)),
# process substitution, a /dev/tcp|udp redirect -- and the subcommands of git/gh/rg that run programs.
TEXT_TOOL_EXECUTES = re.compile(r'`|\$\(|[<>]\(|/dev/(?:tcp|udp)/', re.I)
TEXT_TOOL_SUBCOMMANDS = {'git': {'commit', 'log', 'show', 'diff', 'status', 'add', 'blame', 'grep'}, 'gh': {'pr', 'issue'}}
RUNTIME_SENDER = re.compile(r'\b(?:curl|wget|invoke-restmethod|invoke-webrequest|irm|iwr|urlopen|urllib|httpx|aiohttp|'
                            r'http\.client|httpconnection|webclient|httpclient|uploadstring|socket|requests\.\w+|'
                            r'webrequest|tcpclient|http\.request|net\.http)\b|/dev/(?:tcp|udp)/'
                            r'|\bfetch\s*\(|mcp__|' + RUNTIME_CALL_TOOL +
                            # any client called with the tool as a keyword: invoke(tool_name='game', ...)
                            r'|\b\w+\s*\([^()\r\n]{0,200}?\b(?:tool_?name|endpoint|tool)\s*=\s*[\"\']', re.I)


def _spellings(path):
    s = os.path.normpath(str(path)).lower()
    out = {s, s.replace('\\', '/')}
    drive = re.match(r'^([a-z]):[\\/](.*)$', s)
    if drive:                                       # the MSYS spelling Git Bash uses: /c/users/...
        out.add('/' + drive.group(1) + '/' + drive.group(2).replace('\\', '/'))
    return out


SAVE_DIR_SPELLINGS = sorted({s for d in KNOWN_SAVE_DIRS for s in _spellings(d)}, key=len, reverse=True)
# Environment variables that point into a save folder: `rm "$SAVEDIR/x.ess"` names one without spelling it.
SAVE_ENV_VARS = sorted(k for k, v in os.environ.items()
                       if v and any(s in v.lower().replace('\\', '/') for s in SAVE_DIR_SPELLINGS))


def mentions_save_location(text):
    """True when code or a command spells a save location (never prose, never a bare .ess name)."""
    if LOCATION.search(text):
        return True
    low = text.lower()
    if any(s in low for s in SAVE_DIR_SPELLINGS):
        return True
    return any(re.search(r'\$\{?' + re.escape(k) + r'\b|%' + re.escape(k) + r'%|\$env:' + re.escape(k) + r'\b',
                         text, re.I) for k in SAVE_ENV_VARS)


SAVE_DIR_KEYS = [os.path.normcase(os.path.normpath(str(d))).rstrip('\\/') for d in KNOWN_SAVE_DIRS]


def _key(path):
    return os.path.normcase(os.path.normpath(os.path.abspath(str(path)))).rstrip('\\/')


PROTECT_MARKER = '.protect-saves'
_marked = {}


def _marker_above(k):
    """The nearest folder at or above k holding a .protect-saves marker (kept save copies the user wants guarded
    like a Saves folder: the Save90012 play-boundary baseline, user 2026-10-30), else ''."""
    folder = k
    for _ in range(12):
        if folder not in _marked:
            try:
                _marked[folder] = os.path.isfile(os.path.join(folder, PROTECT_MARKER))
            except (OSError, ValueError):
                _marked[folder] = False
        if _marked[folder]:
            return folder
        parent = os.path.dirname(folder)
        if parent == folder:
            break
        folder = parent
    return ''


def in_save_location(path):
    """A path inside a save folder: a discovered one, any folder named Saves / __MO_Saves, or a folder marked
    with .protect-saves (or below one)."""
    if not path:
        return False
    try:
        k = _key(path)
    except (TypeError, ValueError):
        return False
    return (any(k == r or k.startswith(r + os.sep) for r in SAVE_DIR_KEYS)
            or bool(LOCATION.search(str(path).replace('\\', '/') + '/'))
            or bool(_marker_above(k if os.path.isdir(k) else os.path.dirname(k))))


def holds_save_location(path):
    """A folder at or above a save folder (deleting or wildcarding it reaches saves)."""
    try:
        k = _key(path)
    except (TypeError, ValueError):
        return False
    return any(r == k or r.startswith(k + os.sep) for r in SAVE_DIR_KEYS)


ADVICE_LOG = ROOT / '.claude' / 'diag' / 'save-guard-advice.jsonl'


def advise(paths, op, base):
    """Saves outside every save folder: allowed, recorded here (they are copies the game does not read)."""
    try:
        ADVICE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with ADVICE_LOG.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps({'time': datetime.datetime.now().isoformat(timespec='seconds'), 'op': op,
                                 'paths': sorted(map(str, paths))[:20], 'tool': base.get('tool', ''),
                                 'command': str(base.get('command', ''))[:300]}, ensure_ascii=False) + '\n')
    except OSError:
        pass                 # advice is a record, never a gate
# A shell output statement's literal text is shown to a person, not run: setup.sh's help lines ("ReSaver CLI --
# headless .ess parse/clean") made every run of it a counted save change (false positive, user 2026-10-30).
# Discard only plain literal output; retain shell control, expansion, capture options and continuations.
# Comments and Python print() stay: they can describe or compute actual paths.
# This conservative source heuristic is not a shell parser or a filesystem security boundary.
_OUTPUT_LINE = re.compile(r'^\s*(?:echo|printf|Write-Host|Write-Output)\b(?!\s*\()', re.I)
_QUOTED_TEXT = re.compile(r'"(?:[^"\\]|\\.)*"' + r"|'[^']*'")


def without_output_text(source):
    # Only discard plain literal output. Keep executable suffixes, expansion,
    # variable-capture options, incomplete quotes and continuation/pipeline input.
    # This is deliberately conservative, not a general shell parser.
    kept = []
    following = ''
    for line in reversed(source.splitlines()):
        remainder = _QUOTED_TEXT.sub('', line)
        literal = (_OUTPUT_LINE.match(line) and not re.search(r'[$`]', line)
                   and not re.search(r'''[<>&;|\\'"(){}^]''', remainder)
                   and not re.search(r'(?:^|\s)-', remainder)
                   and not following.startswith(('|', '&', ';', '<', '>')))
        if not literal:
            kept.append(line)
        stripped = line.lstrip()
        if stripped and not stripped.startswith('#'):
            following = stripped
    return '\n'.join(reversed(kept))
# Toolkit scripts whose READ-ONLY verbs are exempt from the "invoked script mentions saves and moves files" check
# (user request 2026-10-25: housekeep.py lists .ess/.skse only to refuse them, and its report/plan change nothing).
# Pinned by content: an edited or updated copy is judged like any other script until its hash is added here. The
# exemption covers only that one script token; every other check still runs on the whole command, and an argument
# naming a save or a Saves folder (plan -o writes a file) keeps the normal check.
READ_ONLY_SCRIPT_VERBS = {'_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/native_batch_run.py': {'sha256': {'f23292ab096f77152ba44c3a69ae747b31851d2d81c806079644546e1a7d678d'},
                                                                                      'verbs': {'freeze'},
                                                                                      'dependencies': {'_CLAUDE_OUTPUT/skyrim-souls-vr-2026-10-24/shutdown-repair-20261029/single_owner_exit.py': 'f8f8418bb28498484ce83b937413131b2c55394f2e2e56ffc9096b93a9c4b6da',
                                                                                                       '_CLAUDE_OUTPUT/skyrim-souls-vr-2026-10-24/shutdown-repair-20261029/managed_owner.py': '20070c9dcd0b9c2a4881b35ebed067c12581f122ccec6ef17d93f566b92bc1b8',
                                                                                                       '_CLAUDE_OUTPUT/skyrim-souls-vr-2026-10-24/shutdown-repair-20261029/process_identity.py': '09ede27b72c2302a2f8bda4878367fe0dfcdc43e83e20c262d46812526c54325',
                                                                                                       '_CLAUDE_OUTPUT/skyrim-souls-vr-2026-10-24/shutdown-repair-20261029/session_publication.py': '4680e935c2563863bccc7a0aee4096e84086a68a1ac740513d1fa2974f8171e3',
                                                                                                       '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/native_lifecycle.py': '9c198c44007e75fe9e424301d8c6727d93114310b5ef2aba0b23e50c781c47be',
                                                                                                       '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/native_run.py': '62176cb11bb2aa6218d18cbdec52ab5ea41d85c122451d33ed5f474ca0ab5fd0',
                                                                                                       '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/stage/tools/skyrimnet-output-guard/install-native.py': '5fc0c451135ac8cf69bf98c33845cef77eb3b0a3686ab9479062feda8ad27e69',
                                                                                                       'tools/skyrim-souls-vr/diagnostic/build.py': 'c1ca29052873a43248fb32568120bc088370e18b4d34b833d08708143fd6b57e',
                                                                                                       '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/reference_adapter.py': '9bb7f88bc380d6b416bfeab26f357e53c38eaea7b0836c960b5594e1db310201'}},
 'tools/housekeep.py': {'sha256': {'388db95fcfff7aec90d88bf0045c85244bb18906f590e81c774083ea501ad556'},
                        'verbs': {'', '--help', 'version', '-h', 'plan', 'report'},
                        'plan_verbs': {'apply'}}}


# User-approved 2026-10-29: configuration/owned-session operations, NOT save
# operations. Pair creation/loading remains a separate protected CLI invocation.
# This is not a launch approval; the lifecycle still checks its one-run consent.
REVIEWED_NON_SAVE_LIFECYCLE = {'_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/native_batch_run.py': {'sha256': {'f23292ab096f77152ba44c3a69ae747b31851d2d81c806079644546e1a7d678d'},
                                                                                      'verbs': {'preflight',
                                                                                                'prepare',
                                                                                                'publish',
                                                                                                'ready',
                                                                                                'restore',
                                                                                                'run',
                                                                                                'stop'},
                                                                                      'exact_desktop_args': True,
                                                                                      'frozen_inputs': {'path': '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/engine-completion-15/inputs.json',
                                                                                                        'sha256': '73900a5595193d42ef439d7cab0a3b5de32f2106928c86d15379746e39c3ac33'},
                                                                                      'dependencies': {'_CLAUDE_OUTPUT/skyrimnet-beta28-install-2026-10-22/deploy.py': '58ff4af55fa20c1f2e917bca3b0bd119cc807e2a272ee2c70d30b09a84a6632d',
                                                                                                       '_CLAUDE_OUTPUT/output-guard/guardian/native-feasibility-2026-10-26/isolation.py': '545c7ce0fd7b650d5c166dc6c0e2a8708b76749146969c3fab8b29e0d5e569b4',
                                                                                                       'tools/vr-headless.py': 'c00fda353828460b09b177adc924d4bc7995562d81d34856abfdb169f036618a',
                                                                                                       'tools/vr_background_desktop.py': 'b18838010e4ba655ce53ca061884bcf77de0777be2166aecdfa7cb2e3eea1738',
                                                                                                       '_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/reference_adapter.py': '9bb7f88bc380d6b416bfeab26f357e53c38eaea7b0836c960b5594e1db310201'}}}


# Exact reviewed inert commands only. Populated after dependency qualification.
REVIEWED_INERT_FIXTURES = {
    '_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/test_owner_quit.py': {   'cache_tag': 'cpython-310',
        'commands': {   'Bash': '"{HOME}/AppData/Local/Programs/Python/Python310/python.exe" -E -s -S -B '
                                '"{HOME}/.claude/tools/resource-budget/rb.py" run --policy headroom --name '
                                'delirium-owner-quit --cpu 5 --ram 0.5 --disk C=0.01 --priority '
                                'below_normal --wait-until-fits 2 -- '
                                '"{HOME}/AppData/Local/Programs/Python/Python310/python.exe" -E -s -S -B '
                                '"{ROOT}/_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/test_owner_quit.py"',
                        'PowerShell': '& "{HOME}/AppData/Local/Programs/Python/Python310/python.exe" -E -s '
                                      '-S -B "{HOME}/.claude/tools/resource-budget/rb.py" run --policy '
                                      'headroom --name delirium-owner-quit --cpu 5 --ram 0.5 --disk C=0.01 '
                                      '--priority below_normal --wait-until-fits 2 -- '
                                      '"{HOME}/AppData/Local/Programs/Python/Python310/python.exe" -E -s -S '
                                      '-B '
                                      '"{ROOT}/_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/test_owner_quit.py"',
                        'exec_command': '& "{HOME}/AppData/Local/Programs/Python/Python310/python.exe" -E '
                                        '-s -S -B "{HOME}/.claude/tools/resource-budget/rb.py" run --policy '
                                        'headroom --name delirium-owner-quit --cpu 5 --ram 0.5 --disk '
                                        'C=0.01 --priority below_normal --wait-until-fits 2 -- '
                                        '"{HOME}/AppData/Local/Programs/Python/Python310/python.exe" -E -s '
                                        '-S -B '
                                        '"{ROOT}/_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/test_owner_quit.py"',
                        'functions.exec_command': '& '
                                                  '"{HOME}/AppData/Local/Programs/Python/Python310/python.exe" '
                                                  '-E -s -S -B "{HOME}/.claude/tools/resource-budget/rb.py" '
                                                  'run --policy headroom --name delirium-owner-quit --cpu 5 '
                                                  '--ram 0.5 --disk C=0.01 --priority below_normal '
                                                  '--wait-until-fits 2 -- '
                                                  '"{HOME}/AppData/Local/Programs/Python/Python310/python.exe" '
                                                  '-E -s -S -B '
                                                  '"{ROOT}/_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/test_owner_quit.py"'},
        'dependencies': {   '_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/binding.py': 'b325e3cb1921357426aacba4b021cf0f421365b353cf97be8da298602e59a517',
                            '_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/owner_quit.py': 'bdccf71f505830e48797b61a99df07ff4574a6d2557f44208ecbae4568f9aefd',
                            '_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/shutdown_recovery.py': 'be6dd42d22c9c934c50afbf34d707b22f461d3db38c9aea69050baa0f11e4abd',
                            '_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/startup_handoff.py': 'b274e8d3f5e713ce54e54d2a0083b51c453884c5d845b49f1275193b2bdd0a25',
                            '_CLAUDE_OUTPUT/delirium-vr-assessment-20261104/native-test-preparation-20261106/windows_identity.py': '9ca82e5170a64cd5d10d709d4635464cf4544dad0bfbd8b1fb5036b8c574092a',
                            'tools/__pycache__/vr-headless.cpython-310.pyc': '1b4863ef8c7dfee55338126d8a29cd033055b323220e4120447c80af3bbcbcfe',
                            'tools/vr-headless.py': 'c00fda353828460b09b177adc924d4bc7995562d81d34856abfdb169f036618a'},
        'dependency_closure_complete': True,
        'home_dependencies': {   '.claude/tools/resource-budget/rb.py': '00ffd3c56aa4a810fe5b26ed0d17aaa06aa8724ec229799c795ec8baa72c8030',
                                 '.claude/tools/resource-budget/rblib/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                                 '.claude/tools/resource-budget/rblib/__pycache__/__init__.cpython-310.pyc': '65f3bdca9f566475d6695c07bd13f0ce48594a7d141e3181e3af0c5a2b59bd57',
                                 '.claude/tools/resource-budget/rblib/__pycache__/budget.cpython-310.pyc': '86fa382995e63563c4f97508e8dfa2fd4e67e3f5d9f6e5303042e591af9221b7',
                                 '.claude/tools/resource-budget/rblib/__pycache__/config.cpython-310.pyc': 'cab81ff0a7fd18ecb6605511e1fffabdb5aab99750358673c3d70530128bbea4',
                                 '.claude/tools/resource-budget/rblib/__pycache__/costs.cpython-310.pyc': 'ff26109c6739b546fa105fb4f835aebbbfa15ff2a0411111202879b97dbf0517',
                                 '.claude/tools/resource-budget/rblib/__pycache__/diskio.cpython-310.pyc': '5564737463a3f548aed2bcd164bc28aa0213397aa14b3b3f483b8b8507fa1347',
                                 '.claude/tools/resource-budget/rblib/__pycache__/filelock.cpython-310.pyc': '799d0303f4b2fafe321ebd9728c4b6949c098b0d07d7dc2652316bf45872b820',
                                 '.claude/tools/resource-budget/rblib/__pycache__/guard.cpython-310.pyc': '609baa1cfd51b12f25110ea794a9df925700813779c9b533fc576cae5d5458f2',
                                 '.claude/tools/resource-budget/rblib/__pycache__/launcher.cpython-310.pyc': '4c34e1866ebeadd2920b69feafb629172a823e9ca066a4216ea93176aae92070',
                                 '.claude/tools/resource-budget/rblib/__pycache__/ledger.cpython-310.pyc': '58f73d676bcc8ed312c810ad06c8ef0e0b3170a127557b7b5f58e9a8ee24d7cb',
                                 '.claude/tools/resource-budget/rblib/__pycache__/policy.cpython-310.pyc': 'c15c455a7992190952b4828506473e855ec596b15b8224047e32f4c7947b26bc',
                                 '.claude/tools/resource-budget/rblib/__pycache__/probes.cpython-310.pyc': 'f265d2e0f197ece997c0c58e247786e07df5705fba083f553af254e4d72ba247',
                                 '.claude/tools/resource-budget/rblib/__pycache__/procs.cpython-310.pyc': '35cab5bb423d30795043314db2ea16750a8f552730eeaeb48b9e2b8bdf988afd',
                                 '.claude/tools/resource-budget/rblib/__pycache__/watchdog.cpython-310.pyc': '8e62723f6d13f091a9e459056ad0e846772fca2e7c548cf2acba1ecfeae04ce3',
                                 '.claude/tools/resource-budget/rblib/__pycache__/winjob.cpython-310.pyc': 'dd280c546c774fb9214069d95d6116f193ec81b551d149f3c72bcc73e448f35a',
                                 '.claude/tools/resource-budget/rblib/budget.py': 'efdf6a287cd39a67c5f25945ef09ef2a93b8390c0194d870ce4e2cea14c9aeb5',
                                 '.claude/tools/resource-budget/rblib/config.py': '6cd2f7c2746c452e26f1f94e3d96fe473fd75801bb8584fee4939d38c964d4bb',
                                 '.claude/tools/resource-budget/rblib/costs.py': '6aa1175f10d425bdf98ae0ab9244fe9934f432e27ac074ce38a95785d473d097',
                                 '.claude/tools/resource-budget/rblib/diskio.py': '3ae6b62cc0864a9d5af9153a41b6402d6249311f650bff66935f300ee7c13842',
                                 '.claude/tools/resource-budget/rblib/filelock.py': 'b69b2ad7f312b295540845222965a882bc0c53cef65b12c63101b73923d7e69c',
                                 '.claude/tools/resource-budget/rblib/guard.py': '9100588c7f2c203d00c40ab74511999e8c6bcf1f328945b5bc1e3f6eab5420ea',
                                 '.claude/tools/resource-budget/rblib/launcher.py': '45f069b85203ec2d5c6b9c2dcb2542116543c2d0a07b50fc42355c2547f93a15',
                                 '.claude/tools/resource-budget/rblib/ledger.py': 'cd964f93a966680601a86a378f75506515d421158166a46c9de8688df8e69a09',
                                 '.claude/tools/resource-budget/rblib/policy.py': 'c99b7c533af4819dd573d2fd7a5068c5f667ef93ede61c03514ed6f0074422ff',
                                 '.claude/tools/resource-budget/rblib/posixjob.py': 'ab89b6ad44d0057f1addd77c737587adbb4d17a82c85f4bb5417cba0737c0e56',
                                 '.claude/tools/resource-budget/rblib/probes.py': '95713764f458f6e9ea2a9379c2a7607d255bf600e41a81d41825ab83fc15cd5c',
                                 '.claude/tools/resource-budget/rblib/procs.py': '69d1db04c004a75eddd3dbc3d49605845177d529ea31198b1a5d185695a498b8',
                                 '.claude/tools/resource-budget/rblib/watchdog.py': '7e73809e3a627fdaa17335cede086c74d4293c0ff4452e4cc5fe02be0e7fbfd7',
                                 '.claude/tools/resource-budget/rblib/winjob.py': '6d1b86c01013ec70815a5a25811754cb5c665928735bff367613965bae51096a',
                                 'AppData/Local/Programs/Python/Python310/python.exe': '47942e1f899c5b0ccd23ba0730adbbc979b1488e0f2e5274abf398360877b7ec',
                                 'AppData/Local/Programs/Python/Python310/python3.dll': '73b0f3952be222ce676672603ae3848ee6e8e479782bd06745116712a4834c53',
                                 'AppData/Local/Programs/Python/Python310/python310.dll': '2bf761bae584ba67d9a41507b45ebd41ab6ae51755b1782496d0bc60cc1d41d5',
                                 'AppData/Local/Programs/Python/Python310/vcruntime140.dll': '9d2b40f0395cc5d1b4d5ea17b84970c29971d448c37104676db577586d4ad1b1',
                                 'AppData/Local/Programs/Python/Python310/vcruntime140_1.dll': '34048abaa070ecc13b318cea31425f4ca3edd133d350318ac65259e6058c8b32'},
        'sha256': '9d273caf375793ed2c2c9a4eec96d26e72757d5251bf0140610f60f9d62f71a9',
        'tools': ['Bash', 'PowerShell', 'exec_command', 'functions.exec_command']}
}


def reviewed_inert_fixture_call(script, raw, text, cwd, tool):
    """One source-qualified command envelope; never a generic test exemption."""
    if type(REVIEWED_INERT_FIXTURES) is not dict or not REVIEWED_INERT_FIXTURES:
        return False
    try:
        if script.absolute().relative_to(ROOT.absolute()).as_posix() not in REVIEWED_INERT_FIXTURES:
            return False
    except (OSError, ValueError):
        return False
    started = time.monotonic()
    def plain(path):
        for part in (path, *path.parents):
            if time.monotonic() - started > 2.0:
                return False
            if '..' in part.parts:
                return False
            info = os.lstat(part)
            if os.path.islink(part) or (getattr(info, 'st_file_attributes', 0) or 0) & 0x400:
                return False
        return True
    def digest(value):
        return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
    try:
        if os.environ.get('RB_HOME') or (Path.home() / '.claude/tools/resource-budget/config.json').exists():
            return False
        originals = (ROOT.absolute(), Path(cwd).absolute(), script.absolute(), Path.home().absolute())
        if any(any(character in str(path) for character in ('$', '`', '"', '\r', '\n')) for path in originals):
            return False
        if not all(plain(path) for path in originals):
            return False
        root, current, resolved, home_root = (path.resolve(strict=True) for path in originals)
        if current != root:
            return False
        relative = resolved.relative_to(root).as_posix()
        spec = REVIEWED_INERT_FIXTURES.get(relative)
        keys = {'sha256', 'commands', 'tools', 'dependencies', 'home_dependencies', 'dependency_closure_complete', 'cache_tag'}
        if type(spec) is not dict or set(spec) != keys or spec['dependency_closure_complete'] is not True:
            return False
        if spec['cache_tag'] != sys.implementation.cache_tag:
            return False
        if type(spec['tools']) is not list or not spec['tools'] or not all(type(t) is str for t in spec['tools']) or tool not in spec['tools']:
            return False
        if not digest(spec['sha256']) or type(spec['commands']) is not dict or set(spec['commands']) != set(spec['tools']) or not all(type(c) is str for c in spec['commands'].values()):
            return False
        if text != spec['commands'][tool].replace('{ROOT}', root.as_posix()).replace('{HOME}', home_root.as_posix()):
            return False
        paths = [(resolved, spec['sha256'])]
        for base, entries, maximum in ((root, spec['dependencies'], 16), (home_root, spec['home_dependencies'], 64)):
            if type(entries) is not dict or not entries or len(entries) > maximum:
                return False
            for name, expected in entries.items():
                if time.monotonic() - started > 2.0:
                    return False
                if type(name) is not str or not digest(expected) or Path(name).is_absolute():
                    return False
                path = (base / name).absolute()
                if not plain(path) or path.resolve(strict=True) != path or not path.is_relative_to(base):
                    return False
                paths.append((path, expected))
        expected_paths = {path for path, expected in paths}
        for source, expected in paths:
            if source.suffix != '.py':
                continue
            for suffix in ('.pyc', '.opt-1.pyc', '.opt-2.pyc'):
                cache = source.parent / '__pycache__' / (source.stem + '.' + spec['cache_tag'] + suffix)
                if os.path.lexists(cache) and cache not in expected_paths:
                    return False
        total = 0
        for path, expected in paths:
            if time.monotonic() - started > 2.0:
                return False
            info = path.stat()
            remaining = 8388608 - total
            total += info.st_size
            if info.st_mode & 0o170000 != 0o100000 or info.st_nlink != 1 or total > 8388608:
                return False
            with path.open('rb') as stream:
                data = stream.read(remaining + 1)
            if len(data) != info.st_size or hashlib.sha256(data).hexdigest() != expected:
                return False
        return time.monotonic() - started <= 2.0
    except (OSError, ValueError, KeyError, TypeError):
        return False


def read_only_script_call(script, raw, text, cwd='.', tool=None):
    """Recognize pinned read-only calls, verified non-save plans, or the exact
    user-approved non-save lifecycle. This never grants launch/load consent."""
    if reviewed_inert_fixture_call(script, raw, text, cwd, tool):
        return True
    try:
        rel = script.resolve().relative_to(ROOT).as_posix()
    except (OSError, ValueError):
        return False
    specs = [table[rel] for table in (READ_ONLY_SCRIPT_VERBS, REVIEWED_NON_SAVE_LIFECYCLE) if rel in table]
    if not specs:
        return False
    # EVERY occurrence of the script in the command must be a read-only call: `plan && apply` is an apply.
    starts = [m.end() for m in re.finditer(re.escape(raw), text)]
    if not starts:
        return False
    return any(
        (not spec.get('exact_desktop_args') or (len(starts) == 1 and not re.search(r'[;&|\r\n`]', text)))
        and all(_read_only_tail(spec, text[at:], cwd) for at in starts)
        and _pinned(script, spec)
        for spec in specs)


def _cd_targets(text):
    """Directories the command `cd`s / `Set-Location`s into, Git Bash /c/... spelling turned into C:/..."""
    out = []
    for m in re.finditer(r'(?:^|[\s;&|(])(?:cd|set-location|pushd)\s+(?:-\w+\s+)?("[^"\n]+"|\'[^\'\n]+\'|[^\s;&|)]+)',
                         text, re.I):
        d = m.group(1).strip('\'"')
        drive = re.match(r'^/([a-zA-Z])(/.*)?$', d)
        if drive:
            d = drive.group(1).upper() + ':' + (drive.group(2) or '/')
        out.append(d)
    return out


def plan_without_saves(plan_path):
    """True only when the plan parses and no action names a save, a Saves folder, or a folder that holds a save."""
    try:
        actions = json.loads(Path(plan_path).read_text(encoding='utf-8'))['actions']
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if not isinstance(actions, list):
        return False
    save_dirs = [d.as_posix().lower() + '/' for d in KNOWN_SAVE_DIRS]
    for a in actions:
        if not isinstance(a, dict) or not isinstance(a.get('path'), str):
            return False
        for key in ('path', 'live', 'canonical', 'task'):
            v = a.get(key)
            if v is None:
                continue
            if not isinstance(v, str):
                return False
            low = v.replace('\\', '/').lower() + '/'
            if EXTENSION.search(v) or FOLDER.search(v) or any(low.startswith(d) for d in save_dirs):
                return False
        if os.path.isdir(a['path']):
            for _, _, files in os.walk(a['path']):
                if any(EXTENSION.search(f) for f in files):
                    return False
    return True


def _read_only_tail(spec, rest, cwd='.'):
    tail = re.split(r'[;&|\n]', rest.lstrip('\'"'), maxsplit=1)[0]
    words = tail.split()
    if spec.get('exact_desktop_args'):
        return (len(words) == 3 and words[0] in spec['verbs']
                and words[1] == '--desktop' and words[2] in ('pending', 'current', 'background'))
    if any(w in ('-h', '--help') for w in words):
        verb = '--help'
    else:
        # The verb is the first word that is neither an option nor an option's value (--config FILE, -o FILE,
        # --only CLASSES): `--config x apply plan.json` is an apply.
        verb, skip = '', False
        for w in words:
            if skip:
                skip = False
            elif w in ('--config', '-o', '--out', '--only'):
                skip = True
            elif w.startswith('-'):
                continue
            else:
                verb = w
                break
    if FOLDER.search(tail) or EXTENSION.search(tail):
        return False
    if verb in spec.get('plan_verbs', ()):
        # Exactly `apply PLAN.json [--only CLASSES]`: the verb first, no --config/-o, one positional.
        if not words or words[0] != verb:
            return False
        pos, skip = [], False
        for w in words[1:]:
            if skip:
                skip = False
            elif w == '--only':
                skip = True
            elif w.startswith('-'):
                return False
            else:
                pos.append(w.strip('\'"'))
        if len(pos) != 1:
            return False
        plan = Path(pos[0]) if Path(pos[0]).is_absolute() else Path(cwd) / pos[0]
        return plan_without_saves(plan)
    return verb in spec['verbs']


def _pinned(script, spec):
    try:
        if sha256(script) not in spec['sha256']:
            return False
        # Imported code must remain reviewed too; a changed dependency revokes
        # only this exception and falls back to ordinary script inspection.
        for relative, expected in spec.get('dependencies', {}).items():
            dependency = (ROOT / relative).resolve()
            if not dependency.is_relative_to(ROOT.resolve()) or sha256(dependency) != expected:
                return False
        frozen = spec.get('frozen_inputs')
        if frozen is not None:
            manifest = (ROOT / frozen['path']).resolve()
            if not manifest.is_relative_to(ROOT.resolve()) or sha256(manifest) != frozen['sha256']:
                return False
            inputs = json.loads(manifest.read_bytes())
            if not isinstance(inputs, dict) or not inputs:
                return False
            for relative, expected in inputs.items():
                dependency = (ROOT / relative).resolve()
                if (not dependency.is_relative_to(ROOT.resolve())
                        or not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected)
                        or sha256(dependency) != expected):
                    return False
        return True
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return False


ENUMERATE = re.compile(r'\b(?:glob|iglob|rglob|listdir|scandir|walk|iterdir|get-childitem|gci|ls|dir|find|fd)\b', re.I)
RECURSIVE = re.compile(r'-recurse\b|--recursive\b|\brmtree\b|(?<!\S)-[fvirFVIR]*[rR][fvirFVIR]*(?=\s|$)|(?<!\S)/s\b|\brmdir\b|\brd\b|removedirs', re.I)
WRITE_OPS = ('delete', 'move', 'rename', 'copy', 'write', 'restore')
# Mirrors the read-only op list in tools/resaver-cli.sh; everything else there can write.
RESAVER_READ_OPS = {'info', 'dump', 'changeform', 'find-refs', 'find', 'worries', 'extradata-scan', 'recon',
                    'changeform-diff', 'freeze-report', 'writer-scan', 'globaldata', 'globaldata-diff'}
LISTERS = {'ls', 'dir', 'find', 'get-childitem', 'gci', 'fd'}
FILTERS = {'grep', 'egrep', 'fgrep', 'awk', 'gawk', 'sed', 'sort', 'uniq', 'wc', 'head', 'tail', 'cut', 'tr',
           'echo', 'printf', 'column', 'nl', 'select-string', 'select-object', 'sort-object', 'measure-object',
           'where-object', 'format-table', 'out-string', 'cat'}
# Commands that only read what a listing hands them (xargs X / -exec X / pipeline stage).
READERS = {'cat', 'head', 'tail', 'sha256sum', 'sha1sum', 'md5sum', 'file', 'stat', 'wc', 'xxd', 'od', 'hexdump',
           'strings', 'get-filehash', 'get-content', 'get-item', 'grep', 'ls', 'du', 'foreach-object', '%'}
EXECUTORS = re.compile(r'^(?:xargs|sh|bash|zsh|python\w*|py|node|perl|ruby|pwsh|powershell|iex|invoke-expression|'
                       r'foreach-object|%|eval|source|\.|parallel|cmd|start-process)$', re.I)
RUNNERS = re.compile(r'^(?:sh|bash|zsh|python\w*|py|node|perl|ruby|pwsh|powershell|iex|invoke-expression|'
                     r'eval|source|\.|parallel|cmd|start-process)$', re.I)
# Text-only tools: their arguments are prose for a person or another agent, not file operations.
# A subagent's own tool calls still pass through this guard.
COMMUNICATION = ('request_user_input', 'send_message', 'web_search', 'Agent', 'Task', 'SendMessage',
                 'AskUserQuestion', 'WebSearch', 'TodoWrite', 'ScheduleWakeup', 'PushNotification',
                 'ExitPlanMode', 'EnterPlanMode')
# Tools whose `command` is a shell command line (Codex's shell arrives as "Bash" too). Any other tool's input is also
# judged as structured data, keys included (runtime_request in decide).
SHELL_TOOLS = ('Bash', 'PowerShell', 'Monitor')
NOT_ACTIONS = {'cd', 'pushd', 'popd', 'set-location', 'sl', 'chdir', 'git', 'echo', 'printf', 'write-output',
               'write-host', 'grep', 'rg', 'select-string', 'gh'}


class BackupError(Exception):
    pass


def operation(text, tool):
    text = tool + '\n' + text
    for label, pattern in [
            ('delete', r'remove-item|\bunlink\b|\brmtree\b|\brm\b|\bdel\b|\berase\b|\brmdir\b|\brd\b|os\.remove'
                       r'|send2trash|deletefile|::delete|\.delete\s*\(|\s-delete\b'
                       r'|' + _NODE_FS + r'(?:unlink|rm|rmdir)\b|\b(?:unlink|rm|rmdir)sync\s*\('),
            ('move', r'move-item|shutil\.move|\bmv\b|::move|movefile|\.moveto\s*\('),
            ('rename', r'rename-item|\.rename\s*\(|os\.replace|\.replace\s*\(\s*(?![\'"])'
                       r'|' + _NODE_FS + r'rename\b|\brenamesync\s*\('),
            ('copy', r'copy-item|copy_?file|shutil\.copy|\bcp\b|robocopy|xcopy|::copy|\.copyto\s*\('
                     r'|' + _NODE_FS + r'cp\b|\bcpsync\s*\('),
            ('write', r'set-content|add-content|clear-content|out-file|new-item\b|set-itemproperty|write_bytes|write_text'
                      r'|\.write\s*\(|::(?:write|create|append|open|replace)|\btee\b|\btruncate\b|\btouch\b|\bdd\b'
                      r'|\bsed\s+(?:-\w+\s+)*-\w*i|\butime\b|--apply|\b(?:clean|set-global|set-var|reset-havok'
                      r'|cleanse-formlists|remove-created|verify-roundtrip)\b|expand-archive|\bunzip\b'
                      r'|\bopen\s*\([^)]*?,\s*(?:mode\s*=\s*)?[\'"][rbt]*[wax+]'
                      r'|\.open\s*\(\s*(?:mode\s*=\s*)?[\'"][rbt]*[wax+]'
                      r'|>{1,2}\|?\s*(?:\'[^\']*\.(?:ess|skse)[^\']*\'|"[^"]*\.(?:ess|skse)[^"]*"|[^\s\'";|&]*\.(?:ess|skse)\b)'
                      r'|\bos\.(?:sym)?link\s*\(|\.(?:hardlink_to|symlink_to)\s*\(|\bunpack_archive\s*\(|\.extractall\s*\('
                      r'|[\'"]' + _FILE_PROGRAMS + r'[\'"]\s*,'
                      r'|' + _NODE_FS + r'(?:writefile|appendfile|truncate|symlink|link|createwritestream)\b'
                      r'|\b(?:writefile|appendfile|truncate|symlink|link|open)sync\s*\('),
            ('hash', r'get-filehash|sha\d*sum|md5sum|hashlib|certutil')]:
        if re.search(pattern, text, re.I):
            return label
    return 'write' if tool in ('Write', 'Edit', 'NotebookEdit', 'apply_patch') else 'read'


def values_of(text, literal=False):
    """Candidate path strings in text as (value, dollar_is_literal)."""
    if literal:
        return [(v, True) for v in text.split('\n') if v.strip()]
    # Top-level single quotes are literal in bash and PowerShell, so a '$' there is a
    # real character ($Recycle.Bin, $R23V3O6.skse). Everywhere else it may expand.
    tokens = re.findall(r"'([^'\n]+)'|\"([^\"\n]+)\"", text)
    values = [(a, True) if a else (b, False) for a, b in tokens]
    # Code inside quotes (python -c "open('x.ess')") carries its own quoted strings.
    for value, _ in list(values):
        values += [(a or b, False) for a, b in re.findall(r"'([^'\n]+)'|\"([^\"\n]+)\"", value)]
    bare = re.sub(r"'[^'\n]+'|\"[^\"\n]+\"", ' ', text)
    values += [(v, False) for v in re.findall(r'[^\s\"\'`;|<>(){},]+', bare)]
    return values


def msys_fix(value):
    msys = re.match(r'^/([a-z])/(.*)$', value, re.I)
    return msys[1].upper() + ':/' + msys[2] if msys else value  # Git Bash /c/x == C:/x


def is_abs(value):
    return Path(value).is_absolute() or bool(re.match(r'^[a-z]:[/\\]', value, re.I))


def norm(value):
    return os.path.normpath(os.path.abspath(value))  # lexical only


def paths_in(text, cwd, literal=False):
    """Exact save paths named in text. Returns (paths, problem) where problem names why a
    save token could not be pinned to one file. Never stats or opens a save."""
    found = set()
    problem = None
    for value, dollar_is_literal in values_of(text, literal):
        value = value.strip()
        if not SAVE.search(value) or value.lower() in ('.ess', '.skse'):
            continue
        value = msys_fix(value)
        if any(c in value for c in '*?%{}[]') or ('$' in value and not dollar_is_literal) or value.startswith('-'):
            problem = problem or 'Save target contains a wildcard or variable.'
            continue
        if '\n' in value or '=' in value or value.startswith(('http:', 'https:')):
            problem = problem or 'Save target is embedded in code or an assignment.'
            continue
        if not is_abs(value):
            # A bare name may be joined to a directory at runtime (D + 'x.ess'); resolving it
            # against cwd would describe a different file than the one actually opened.
            problem = problem or 'Save path is relative or assembled at runtime.'
            continue
        found.add(norm(value))
    return sorted(found, key=str.casefold), problem


def split_segments(text):
    """Split a shell command into simple commands outside quotes. Heredoc bodies stay with
    the command that reads them. Yields (segment, starts_new_pipeline)."""
    out, cur, quote, i, new_pipe = [], '', None, 0, True
    heredoc = None
    while i < len(text):
        c = text[i]
        if heredoc is not None:
            end = re.match(r'[^\n]*\n?', text[i:])[0]
            cur += end
            i += len(end)
            if end.strip() == heredoc:
                heredoc = None
            continue
        if quote:
            cur += c
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ('"', "'", '`'):
            quote = c
            cur += c
            i += 1
            continue
        m = re.match(r"<<-?\s*['\"]?(\w+)['\"]?", text[i:])
        if m:
            cur += m[0]
            i += len(m[0])
            rest = re.match(r'[^\n]*\n?', text[i:])[0]
            cur += rest
            i += len(rest)
            heredoc = m[1]
            continue
        two = text[i:i + 2]
        if two in ('&&', '||', '$('):
            out.append((cur, new_pipe))
            cur, new_pipe = '', two != '$('
            i += 2
            continue
        if c in ';\n':
            out.append((cur, new_pipe))
            cur, new_pipe = '', True
        elif c == '|':
            out.append((cur, new_pipe))
            cur, new_pipe = '', False
        elif c in '()':
            out.append((cur, new_pipe))
            cur, new_pipe = '', True
        else:
            cur += c
        i += 1
    out.append((cur, new_pipe))
    return [(s.strip(), p) for s, p in out if s.strip()]


def first_word(segment):
    words = re.findall(r"'[^']*'|\"[^\"]*\"|\S+", segment)
    while words and re.match(r'^\w+=', words[0]):
        words.pop(0)
    return (words[0].strip('\'"').lower() if words else ''), words[1:]


def unquoted_words(segment):
    """Shell words with their quotes removed; 'dir/'*.ess is ONE word, as the shell sees it."""
    words = re.findall(r"(?:'[^']*'|\"[^\"]*\"|[^\s'\"])+", segment)
    return [re.sub(r"'([^']*)'|\"([^\"]*)\"", lambda m: m[1] if m[1] is not None else m[2], w) for w in words]


def acting_text(text):
    """The segments that can act on files: prose carriers (git -m, echo, grep) removed."""
    return '\n'.join(s for s, _ in split_segments(text) if first_word(s)[0] not in NOT_ACTIONS)


def listing_ok(word, args, segment):
    """Listings may show names, sizes and times. Only listings that ACT on what they find
    are refused here."""
    if word in ('find', 'fd'):
        return not re.search(r'\s-(?:exec|execdir|ok|okdir|delete|fprintf|fprint|fprint0|fls)\b|\s--exec\b|\s-[xX]\b', segment)
    return word in LISTERS


def listing_violation(text):
    """Reason a listing of save locations goes beyond names, or None."""
    listing_in_pipe = False
    segments = split_segments(text)
    for index, (segment, new_pipe) in enumerate(segments):
        if new_pipe:
            listing_in_pipe = False
        word, args = first_word(segment)
        touches = bool(FOLDER.search(segment) or EXTENSION.search(segment))
        if word in LISTERS and touches:
            following = segments[index + 1] if index + 1 < len(segments) else ('', True)
            names_next = not following[1] and re.match(r'select-object\s+-expandproperty\s+name\s*$', following[0], re.I)
            if not names_next and not listing_ok(word, args, segment):
                return 'A save listing that acts on what it finds (-exec, -delete, -fprint) is bulk access.'
            listing_in_pipe = True
        elif listing_in_pipe and (EXECUTORS.match(word) or word not in FILTERS):
            return 'A save listing may only feed text filters (grep, awk, sort...), never a command runner.'
        elif listing_in_pipe and word in ('awk', 'gawk') and re.search(r'\bsystem\s*\(|\|\s*"|\|&|getline\s*<', segment):
            return 'A save listing piped into awk that runs commands is blocked.'
    acting = acting_text(text)  # prose carried by git -m / heredocs, echo, grep is not an action
    if (FOLDER.search(acting) or EXTENSION.search(acting)) and re.search(r'\bxargs\b|\s-exec(?:dir)?\b|\s-ok\b|\s-delete\b', acting):
        return 'Turning a save listing into actions (xargs, -exec, -delete) is bulk access.'
    return None


def reader_only(text, op):
    """A listing that hands its names only to pure readers (xargs sha256sum, -exec cat,
    | Get-FileHash). Reads are free in any number; anything else is an uncountable action."""
    if op in WRITE_OPS or MUTATE.search(text):
        return False
    if re.search(r'\s-(?:delete|fprint\w*|fls|ok|okdir)\b|\|\s*&|\bsystem\s*\(', text, re.I):
        return False
    for m in re.finditer(r'\bxargs\b((?:\s+-\S+)*)\s+([^\s|;&]+)', text):
        if m[2].lower() not in READERS:
            return False
    for m in re.finditer(r'\s-exec(?:dir)?\s+([^\s|;&]+)', text):
        if m[1].lower() not in READERS:
            return False
    for segment, _ in split_segments(text):
        word, _ = first_word(segment)
        if RUNNERS.match(word):
            return False
    return True


def names_only(text):
    """True when every touch of a save location is a filename-only listing whose output
    reaches nothing but text filters."""
    if listing_violation(text) or re.search(r'\bxargs\b|-exec\b|\bsystem\s*\(|\|\s*&|\binvoke-expression\b|\biex\b', text, re.I):
        return False
    listing_in_pipe = False
    for segment, new_pipe in split_segments(text):
        if new_pipe:
            listing_in_pipe = False
        word, args = first_word(segment)
        touches = bool(FOLDER.search(segment) or EXTENSION.search(segment))
        if word in LISTERS:
            if touches and not listing_ok(word, args, segment):
                return False
            listing_in_pipe = listing_in_pipe or touches
            continue
        if listing_in_pipe and (EXECUTORS.match(word) or word not in FILTERS):
            return False
        if not touches:
            continue
        if word in FILTERS and not FOLDER.search(segment):
            paths, problem = paths_in(segment, '.')
            if not paths and not problem:
                continue
        if save_free_code(segment):
            continue
        return False
    return True


def save_free_code(segment):
    """Code that only mentions save extensions as text (a '.ess' filter, a report label)
    while reading literal non-save files: no save folder, no enumeration, no write, no path."""
    if FOLDER.search(segment) or ENUMERATE.search(segment):
        return False
    if operation(segment, 'Bash') in WRITE_OPS or MUTATE.search(segment):
        return False
    paths, problem = paths_in(segment, '.')
    return not paths and not problem


# ----------------------------------------------------------------- folder protection

def under(path, root):
    p, r = os.path.normcase(norm(path)), os.path.normcase(norm(str(root)))
    return p == r or p.startswith(r.rstrip('\\/') + os.sep)


def protected_dirs():
    return [str(d) for d in KNOWN_SAVE_DIRS] + [str(BACKUP_ROOT)]


def folder_violation(text, cwd):
    """A delete/move/rename whose target is a whole Saves folder, a parent of one, or the
    backup store (or anything inside the store). Never approvable."""
    vcwd = cwd
    for segment, _ in split_segments(text):
        word, args = first_word(segment)
        words = unquoted_words(segment)
        if word in ('cd', 'pushd', 'set-location', 'sl', 'chdir') and len(words) > 1:
            target = msys_fix(words[-1])
            if not any(c in target for c in '$*?%'):
                vcwd = norm(target if is_abs(target) else os.path.join(vcwd, target))
            continue
        if word in NOT_ACTIONS or operation(segment, 'Bash') not in ('delete', 'move', 'rename'):
            continue
        if re.search(r'save-backups', segment, re.I):
            return 'Save backups are kept forever: deleting, moving or renaming the backup store or anything in it is blocked.'
        if word == 'find':
            starts, patterns, _ = find_parts(segment)
            if patterns:
                if not any(matches_saves(p) for p in patterns):
                    continue  # a filtered find -delete that cannot match a save name
                for start in starts:
                    target = norm(msys_fix(start) if is_abs(msys_fix(start)) else os.path.join(vcwd, start))
                    if under(target, BACKUP_ROOT) or under(str(BACKUP_ROOT), target):
                        return 'Save backups are kept forever: this find -delete would reach the backup store.'
                continue  # filtered: the start folder survives; counted by recursive_delete_set
        for value in segment_candidates(segment):
            value = msys_fix(value.strip())
            if not value or value.startswith('-') or any(c in value for c in '*?%{}[]$`'):
                continue
            if '\n' in value or '=' in value or re.match(r'^[a-z]+:(?![/\\])', value, re.I):
                continue
            if re.fullmatch(r'[/\\]+', value):
                continue      # Python's `a / b`, a regex delimiter: resolved, it read as the drive root (2026-10-30)
            target = norm(value if is_abs(value) else os.path.join(vcwd, value))
            # A folder NAMED Saves only when the token is a path: it has a separator, is the shell word `Saves`, or
            # names a folder that exists. The lower-case word in a message string ("saves intact") is prose.
            pathlike = bool(re.search(r'[/\\]', value)) or value == 'Saves' or os.path.isdir(target)
            if pathlike and Path(target).name.lower() in ('saves', '__mo_saves'):
                return 'Deleting or moving a whole Saves folder is blocked, approval or not. Name the save files instead.'
            if os.path.isdir(target) and _marker_above(os.path.normcase(target).rstrip('\\/')):
                return ('This folder is marked ' + PROTECT_MARKER + ' (kept save copies): deleting or moving it whole '
                        'is blocked, approval or not. Name the save files instead.')
            if under(target, BACKUP_ROOT):
                return 'Save backups are kept forever: deleting, moving or renaming them is blocked.'
            for d in protected_dirs():
                if os.path.normcase(d).startswith(os.path.normcase(target).rstrip('\\/') + os.sep):
                    return 'This removes or moves a folder that contains saves or save backups; blocked, approval or not.'
        if RECURSIVE.search(segment) and FOLDER.search(segment) and operation(segment, 'Bash') != 'delete':
            return 'A recursive move inside a Saves folder is blocked. Name the save files instead.'
        if re.search(r'My Games(?:[/\\]Skyrim[^/\\\'"]*)?[/\\]?[\"\']', segment, re.I):
            return 'A parent of the save directory is a mutation target; blocked.'
        if re.search(r'(?:npc-controlled|npc-matched|headed-combat|headed-neutral-combat)-2026-10-\d\d[/\\](?:originals|after)(?:[\"\']|[/\\])', segment, re.I):
            return 'A recorded save-isolation archive folder is a mutation target; blocked.'
    return None


def segment_candidates(segment):
    """Whole shell words (so 'Saves'/a* is the word Saves/a*, not the folder), plus the
    strings quoted inside code (python -c "shutil.rmtree('...')")."""
    candidates = unquoted_words(segment)
    for quoted in re.findall(r'"([^"\n]+)"', segment):
        candidates += [a or b for a, b in re.findall(r"'([^'\n]+)'|\"([^\"\n]+)\"", quoted)]
    return candidates


def find_parts(segment):
    """(start folders, -name/-iname patterns, countable) for a `find` command. Countable
    only with predicates the hook can reproduce: -name -iname -type f -maxdepth -mindepth,
    and the actions -delete / -print / -exec rm [-f] {} + or ;."""
    words = unquoted_words(segment)[1:]
    starts, patterns, countable, i = [], [], True, 0
    depth = {'max': None, 'min': 0}
    while i < len(words) and not words[i].startswith(('-', '(', '!')):
        starts.append(words[i]); i += 1
    while i < len(words):
        w = words[i].lower()
        if w in ('-name', '-iname') and i + 1 < len(words):
            patterns.append(words[i + 1]); i += 2
        elif w == '-type' and i + 1 < len(words) and words[i + 1] == 'f':
            i += 2
        elif w in ('-maxdepth', '-mindepth') and i + 1 < len(words) and words[i + 1].isdigit():
            depth['max' if w == '-maxdepth' else 'min'] = int(words[i + 1]); i += 2
        elif w in ('-delete', '-print'):
            i += 1
        elif w == '-exec':
            rest = words[i + 1:]
            end = next((k for k, x in enumerate(rest) if x in ('+', ';', '\\;')), None)
            body = rest[:end] if end is not None else rest
            if end is None or not body or body[0] != 'rm' or any(x not in ('rm', '-f', '{}') for x in body):
                countable = False
            i += 2 + (end if end is not None else len(rest))
        else:
            countable = False
            i += 1
    return starts, patterns, (countable and len(patterns) <= 1 and bool(starts), depth)


def matches_saves(pattern):
    return any(fnmatch(name, pattern.lower()) for name in ('a.ess', 'a.skse', 'a.ess.bak', 'a.skse.bak'))


def walk_saves(top, deadline, maxdepth=None, mindepth=0, pattern=None):
    """Save files under top (or top itself). Raises TimeoutError when it cannot finish in time."""
    if os.path.isfile(top):
        return [norm(top)] if is_save(top) and (pattern is None or fnmatch(os.path.basename(top).lower(), pattern)) else []
    found, seen = [], 0
    base = top.rstrip('\\/').count(os.sep)
    for root, dirs, files in os.walk(top):
        level = root.rstrip('\\/').count(os.sep) - base
        if maxdepth is not None and level + 1 > maxdepth:
            dirs[:] = []
            if level + 1 > maxdepth:
                continue
        for name in files:
            seen += 1
            if seen > 50000 or time.monotonic() > deadline:
                raise TimeoutError
            if level + 1 >= mindepth and is_save(name) and (pattern is None or fnmatch(name.lower(), pattern)):
                found.append(norm(os.path.join(root, name)))
    return found


def recursive_delete_set(text, cwd):
    """For find -delete / find -exec rm and recursive deletes that reach saves:
    ('set', files) when the hook can count the matches now, ('uncountable', why), or None
    when the command is not such a delete. Whole-folder targets were refused before this."""
    vcwd, applies, files = cwd, False, set()
    deadline = time.monotonic() + 5.0
    for segment, _ in split_segments(text):
        word, _ = first_word(segment)
        words = unquoted_words(segment)
        if word in ('cd', 'pushd', 'set-location', 'sl', 'chdir') and len(words) > 1:
            target = msys_fix(words[-1])
            if not any(c in target for c in '$*?%'):
                vcwd = norm(target if is_abs(target) else os.path.join(vcwd, target))
            continue
        if word in NOT_ACTIONS or operation(segment, 'Bash') != 'delete':
            continue
        try:
            if word == 'find':
                starts, patterns, (countable, depth) = find_parts(segment)
                if not patterns or not any(matches_saves(p) for p in patterns):
                    continue
                applies = True
                if not countable or any(c in s for s in starts for c in '$`%*?{}[]'):
                    return ('uncountable', 'the find expression uses something the hook cannot reproduce')
                for start in starts:
                    top = norm(msys_fix(start) if is_abs(msys_fix(start)) else os.path.join(vcwd, start))
                    files.update(walk_saves(top, deadline, depth['max'], depth['min'], patterns[0].lower()))
            elif RECURSIVE.search(segment) and (FOLDER.search(segment) or EXTENSION.search(segment)):
                applies = True
                for value in segment_candidates(segment)[1:]:
                    value = msys_fix(value.strip())
                    if not value or value.startswith(('-', '/')) and not is_abs(value) or any(c in value for c in '();=\n'):
                        continue
                    if any(c in value for c in '$`%{}[]'):
                        return ('uncountable', 'a target is a variable or expression')
                    path = value if is_abs(value) else os.path.join(vcwd, value)
                    if any(c in os.path.dirname(path) for c in '*?'):
                        return ('uncountable', 'a wildcard in a folder name')
                    folder, leaf = os.path.split(path)
                    if any(c in leaf for c in '*?'):
                        hits = [os.path.join(folder, n) for n in os.listdir(folder) if fnmatch(n.lower(), leaf.lower())] \
                            if os.path.isdir(folder) else []
                    else:
                        hits = [path] if os.path.exists(path) else []
                    for hit in hits:
                        files.update(walk_saves(hit, deadline))
        except (TimeoutError, OSError):
            return ('uncountable', 'too many files to count inside the hook time limit')
    return ('set', sorted(files, key=str.casefold)) if applies else None


# ----------------------------------------------------------------- what a change touches

def pair_of(path):
    """(ess, skse, key) for a save file path; the partner swaps only the extension."""
    m = PAIR.match(path)
    if not m:
        return None
    base, _, suffix = m.groups()
    ess, skse = base + '.ess' + suffix, base + '.skse' + suffix
    return ess, skse, os.path.normcase(base + '|' + suffix)


def pair_exists(path):
    p = pair_of(path)
    return bool(p) and (os.path.lexists(p[0]) or os.path.lexists(p[1]))


def stems(paths):
    seen = {}
    for p in paths:
        pair = pair_of(p)
        if pair and pair[2] not in seen:
            seen[pair[2]] = pair
    return seen


def _comma_lists_as_one_word(words):
    """PowerShell's `a, b ,c` is one list of three, however it is spaced."""
    out = []
    for w in words:
        if out and (out[-1].endswith(',') or w.startswith(',')):
            out[-1] += w
        else:
            out.append(w)
    return out


def transfer_form(text, args):
    """Sources and destination of ONE plain copy/move/rename, or None. Sources may hold
    wildcards; anything else that is not a literal absolute path gives None."""
    if isinstance(args, dict) and not args.get('command') and not args.get('cmd'):
        src = args.get('source', args.get('src', args.get('from', args.get('sourcePath'))))
        dst = args.get('destination', args.get('dest', args.get('to', args.get('target', args.get('destinationPath')))))
        if isinstance(src, str) and isinstance(dst, str):
            return {'sources': [src], 'dest': dst, 'dir': dst.endswith(('/', '\\'))}
        return None
    segments = split_segments(text)
    if len(segments) != 1:
        return None
    segment = segments[0][0]
    py = re.findall(r'(?:shutil\.(copy2?|copyfile|move)|os\.(rename|replace))\(\s*r?([\'"])([^\'"]+)\3\s*,\s*r?([\'"])([^\'"]+)\5\s*\)', segment)
    if py:
        if len(py) != 1:
            return None
        _, _, _, src, _, dst = py[0]
        return {'sources': [src], 'dest': dst, 'dir': dst.endswith(('/', '\\'))}
    words = unquoted_words(segment)
    if not words:
        return None
    cmd, rest = words[0].lower(), words[1:]
    if cmd in ('cp', 'mv'):
        if any(w.startswith('-') and not re.fullmatch(r'-[pfvnriuRa]+|--recursive|--archive|--force|--verbose', w) for w in rest):
            return None  # -t/--target-directory, --backup ...: not a plain transfer
        plain = [w for w in rest if not w.startswith('-')]
        if len(plain) < 2:
            return None
        return {'sources': plain[:-1], 'dest': plain[-1], 'dir': plain[-1].endswith(('/', '\\')) or len(plain) > 2}
    if cmd in ('copy-item', 'cpi', 'copy', 'move-item', 'mi', 'move', 'rename-item', 'rni', 'ren'):
        sources, dest, i = [], None, 0
        dest_flags = ('-destination',) if not cmd.startswith(('rename', 'rni', 'ren')) else ('-newname',)
        rest = _comma_lists_as_one_word(rest)
        while i < len(rest):
            w, low = rest[i], rest[i].lower()
            if low in ('-path', '-literalpath') and i + 1 < len(rest):
                sources.extend(p for p in rest[i + 1].split(',') if p); i += 2; continue
            if low in dest_flags and i + 1 < len(rest):
                if dest is not None:
                    return None
                dest = rest[i + 1]; i += 2; continue
            if low in ('-force', '-recurse', '-verbose', '-passthru', '-container'):
                i += 1; continue
            if w.startswith('-'):
                return None  # -Filter, -Include, -Exclude, -Destination twice...: not plain
            if sources and dest is None:
                dest = w
            else:
                sources.extend(p for p in w.split(',') if p)
            i += 1
        if not sources or dest is None:
            return None
        if cmd.startswith(('rename', 'rni', 'ren')):
            if len(sources) != 1 or re.search(r'[/\\]', dest):
                return None
            return {'sources': sources, 'dest': os.path.join(os.path.dirname(msys_fix(sources[0])), dest), 'dir': False,
                    'newname': True}
        return {'sources': sources, 'dest': dest, 'dir': dest.endswith(('/', '\\')) or len(sources) > 1}
    return None


def literal_abs(value):
    value = msys_fix(value.strip())
    if not value or any(c in value for c in '$`%{}[]') or not is_abs(value):
        return None
    return value


def expand(value):
    """Files a literal-folder wildcard names right now (case-insensitive), or [value]."""
    if not any(c in value for c in '*?'):
        return [norm(value)]
    folder, pattern = os.path.split(value)
    if any(c in folder for c in '*?') or not os.path.isdir(folder):
        return []
    with os.scandir(folder) as entries:
        return sorted(norm(os.path.join(folder, e.name)) for e in entries
                      if fnmatch(e.name.lower(), pattern.lower()) and not e.is_dir())


def resolve_transfer(form):
    """(sources, dests) as absolute paths with wildcards expanded, or None."""
    if form is None:
        return None
    raw_sources = [literal_abs(s) for s in form['sources']]
    dest = literal_abs(form['dest'])
    if dest is None or any(s is None for s in raw_sources) or any(c in dest for c in '*?'):
        return None
    sources = [p for s in raw_sources for p in expand(s)]
    if form['dir'] or os.path.isdir(dest) or any(any(c in s for c in '*?') for s in raw_sources):
        dests = [norm(os.path.join(dest, os.path.basename(s))) for s in sources]
    else:
        dests = [norm(dest)] * len(sources)
    return sources, dests


def is_save(path):
    return bool(SAVE.search(os.path.basename(path)))


def change_sets(op, form_paths, named):
    """(affected, counted) save file paths for a change.
    affected = files whose pairs are backed up; counted = pairs that count toward the limit."""
    if form_paths is None or op in ('delete', 'write'):
        return named, named
    sources, dests = form_paths
    save_dests = [d for d in dests if is_save(d)]
    save_sources = [s for s in sources if is_save(s)]
    if op == 'copy':
        return save_dests, save_dests
    return save_sources + save_dests, save_sources + [d for d in save_dests if pair_exists(d)]


def wildcard_set(text, op, form):
    """Save files a wildcard write would change right now, or None when uncountable."""
    resolved = resolve_transfer(form)
    if resolved is not None and op in ('copy', 'move', 'rename'):
        affected, _ = change_sets(op, resolved, [])
        return sorted(set(affected), key=str.casefold)
    found = set()
    for value, dollar_literal in values_of(text):
        value = msys_fix(value.strip())
        if not (SAVE.search(value) or FOLDER.search(value + '/') or any(c in value for c in '*?')):
            continue
        if not (EXTENSION.search(value) or FOLDER.search(value)):
            continue
        if ('$' in value and not dollar_literal) or any(c in value for c in '%{}[]`=\n') or not is_abs(value):
            return None
        folder = os.path.dirname(value)
        if any(c in folder for c in '*?'):
            return None
        if any(c in value for c in '*?'):
            found.update(p for p in expand(value) if is_save(p))
        elif is_save(value):
            found.add(norm(value))
        else:
            return None  # a bare folder or non-save path inside a Saves folder: not countable
    return sorted(found, key=str.casefold)


# ----------------------------------------------------------------- decision

def decision(kind, **extra):
    extra['kind'] = kind
    return extra


def command_hash(text):
    return hashlib.sha256(text.strip().encode('utf-8')).hexdigest()[:16]


def change(affected, counted, op, base):
    for p in affected:
        if under(p, BACKUP_ROOT):
            return decision('deny', reason='Save backups are kept forever: writing over or removing a backup is blocked.')
    # Only saves in a save folder are guarded (user ruling 2026-10-30): a .ess elsewhere is a copy the game never
    # reads -- test fixtures, evidence, archives. Those are allowed and recorded, not backed up or counted.
    outside = [p for p in affected if not in_save_location(p)]
    if outside:
        advise(outside, op, base)
        affected = [p for p in affected if in_save_location(p)]
        counted = [p for p in counted if in_save_location(p)]
    pairs = stems(affected)
    if not pairs:
        return decision('allow')
    n = len(stems(counted))
    return decision('backup' if n <= 2 else 'needs_files', op=op, affected=sorted(affected, key=str.casefold),
                    count=n, **base)


def restore_helper_call(text, cwd):
    """('restore', record_id) / ('read', None) for an invocation of the restore helper,
    or None when the command is something else."""
    segments = split_segments(text)
    if len(segments) != 1:
        return None
    words = unquoted_words(segments[0][0])
    if len(words) < 2 or not re.match(r'^(?:&\s*)?(?:.*[/\\])?(?:python\w*|py)(?:\.exe)?$', words[0], re.I):
        return None
    i = 1
    while i < len(words) and re.fullmatch(r'-[BIu]+', words[i]):
        i += 1
    if i >= len(words):
        return None
    script = msys_fix(words[i])
    script = norm(script if is_abs(script) else os.path.join(cwd, script))
    if os.path.normcase(script) != os.path.normcase(str(RESTORE_HELPER)):
        return None
    rest = words[i + 1:]
    if not rest or rest[0] in ('list', 'show', '-h', '--help') or '--dry-run' in rest:
        return ('read', None)
    if rest[0] == 'restore' and len(rest) >= 2 and all(w in ('--recycle-extra',) for w in rest[2:]):
        return ('restore', rest[1])
    return ('bad', None)


CONTROLLED_LOAD_SHA256 = '22e0b8b1c004bc4ee79946836a6ce0abb60c4ca9b06ded20b8e659e61dc8102b'
NATIVE_CONTROLLED_RUNTIME_SHA256 = 'e84e88888568fdda2e39ed2b761fd50679c87e10ecdfe9332e77b8ca82e7f155'


def controlled_load_call(text, cwd, base):
    """Only the pinned self-protecting controller may prepare/load a test pair.

    This does not allow generic REST/Papyrus/console loads or any save request.
    The controller independently verifies backups and writer/session prerequisites
    before dispatch; a hosting hook failure never removes that local gate.
    """
    segments = split_segments(text)
    if len(segments) != 1:
        return None
    words = unquoted_words(segments[0][0])
    if len(words) < 2 or not re.fullmatch(r'(?:.*[/\\])?(?:python(?:\d+(?:\.\d+)*)?|py)(?:\.exe)?', words[0], re.I):
        return None
    name = Path(words[1]).name.lower()
    if name not in ('guarded-runtime-load.py', 'resaver-native-runtime.py'):
        return None
    native = name == 'resaver-native-runtime.py'
    helper = ROOT / ('tools/resaver-native-runtime.py' if native else '.claude/scripts/guarded-runtime-load.py')
    candidate = norm(msys_fix(words[1]) if is_abs(msys_fix(words[1])) else os.path.join(cwd, words[1]))
    if os.path.normcase(candidate) != os.path.normcase(str(helper)):
        return decision('deny', reason='Controlled loader must be the exact installed controller.')
    actions = ('inspect', 'prepare', 'load') if native else ('prepare', 'load')
    if len(words) != 5 or words[2] not in actions or words[3] != '--request':
        return decision('deny', reason='Controlled loader requires one explicit action and request; no extra arguments.')
    try:
        expected = NATIVE_CONTROLLED_RUNTIME_SHA256 if native else CONTROLLED_LOAD_SHA256
        if sha256(helper) != expected:
            raise ValueError('controller code differs from the qualified version')
        request = Path(msys_fix(words[4]))
        if not request.is_absolute() or not request.is_file() or request.stat().st_size > 65536:
            raise ValueError('exact bounded request file required')
        data = json.loads(request.read_text(encoding='utf-8-sig'))
        if data.get('schema') != 1:
            raise ValueError('unsupported request schema')
        paths = []
        for key in ('source', 'test'):
            path = Path(data[key])
            if not path.is_absolute() or path.resolve().parent != KNOWN_SAVE_DIRS[0].resolve():
                raise ValueError('only the qualified default VR profile is supported')
            if not re.fullmatch(r'[A-Za-z0-9_-]+\.ess', path.name, re.I):
                raise ValueError('literal ESS names only')
            paths.append(str(path.resolve()))
        prefix = 'ShinsoObserver_Headless_ReSaverPlus_' if native else 'ShinsoObserver_Headless_'
        if os.path.normcase(paths[0]) == os.path.normcase(paths[1]) or not Path(paths[1]).stem.startswith(prefix):
            raise ValueError('separate explicitly named test copy required')
        if not Path(paths[0]).is_file() or (words[2] == 'load' and not Path(paths[1]).is_file()):
            raise ValueError('required source/test file is absent')
        if words[2] == 'prepare' and (os.path.lexists(paths[1]) or os.path.lexists(Path(paths[1]).with_suffix('.skse'))):
            raise ValueError('refuse overwrite of any existing test pair')
    except Exception as exc:
        return decision('deny', reason='Controlled loader refused: ' + str(exc))
    if native and words[2] == 'inspect':
        return decision('allow')  # pinned native settings/diagnostic reads only
    selected = paths if words[2] == 'prepare' else paths[1:]
    return change(selected, selected, 'controlled-' + words[2], base)


# This bounded route is inserted into the existing guard after controlled_load_call.
# It is kept separately to make the preservation change independently reviewable.
NATIVE_PROBE_HELPER_SHA256 = '36d14880f508b7afbaa5b66ce55c1cc24e35b2692679b394a68e2e47fffa6500'


def native_probe_call(text, cwd, base):
    """Recognize one pinned write probe, with one new private output pair.

    This is not a general native save-tool exemption. Other commands continue
    through normal classification, counts, permanent backups and approval rules.
    """
    segments = split_segments(text)
    if len(segments) != 1:
        return None
    words = unquoted_words(segments[0][0])
    python = r'(?:.*[/\\])?(?:python(?:\d+(?:\.\d+)*)?|py)(?:\.exe)?'
    if len(words) < 2 or not re.fullmatch(python, words[0], re.I):
        return None
    # Unwrap only the installed resource runner's ordinary run command.
    runner = Path.home() / '.claude/tools/resource-budget/rb.py'
    if Path(words[1]).name.lower() == 'rb.py':
        if Path(msys_fix(words[1])).resolve() != runner.resolve() or words[2:3] != ['run']:
            return None
        try:
            divider = words.index('--', 3)
        except ValueError:
            return None
        flags = words[3:divider]
        if len(flags) % 2 or any(flags[i] not in ('--name', '--cpu', '--ram', '--disk', '--cpu-cap', '--mem-cap', '--priority', '--wait-until-fits')
                               for i in range(0, len(flags), 2)):
            return None
        words = words[divider + 1:]
        if len(words) < 2 or not re.fullmatch(python, words[0], re.I):
            return None
    if len(words) < 2 or Path(words[1]).name.lower() != 'resaver-port-write-check.py':
        return None
    try:
        helper = ROOT / 'tools/resaver-port-write-check.py'
        candidate = Path(msys_fix(words[1]))
        if not candidate.is_absolute():
            candidate = Path(cwd) / candidate
        if candidate.resolve() != helper.resolve() or sha256(helper) != NATIVE_PROBE_HELPER_SHA256:
            raise ValueError('helper differs from the reviewed, binary-pinned qualification driver')
        if len(words) not in (4, 6) or (len(words) == 6 and (words[4] != '--case' or words[5] not in (
                'noop', 'synthetic-fixture', 'staged-ess', 'staged-cosave', 'destination-collision', 'cosave-publication-collision'))):
            raise ValueError('one source/output and an optional named qualification case are required')
        source, output = (Path(msys_fix(value)) for value in words[2:4])
        for path in (source, output):
            if not path.is_absolute() or path.suffix.lower() != '.ess' or any(c in str(path) for c in '*?$%{}[]`\n'):
                raise ValueError('literal absolute ESS pair paths required')
        source, output = source.resolve(), output.resolve()
        allowed = (ROOT / '_CLAUDE_OUTPUT/resaver-upgrade-33-20261028/private-fixtures').resolve()
        if output.parent != allowed or not re.fullmatch(r'[A-Za-z0-9_-]+\.ess', output.name, re.I):
            raise ValueError('output must be one named pair in the private qualification directory')
        if not source.is_file() or source == output:
            raise ValueError('an existing source and a separate output are required')
        if output.exists() or output.with_suffix('.skse').exists():
            raise ValueError('refuse either existing output member')
        if under(str(source), BACKUP_ROOT):
            raise ValueError('use an explicit read-only copy outside the permanent backup store')
    except Exception as exc:
        return decision('deny', reason='Native write probe refused: ' + str(exc))
    return change([str(output)], [str(output)], 'native-write-qualification', base)


NATIVE_ADAPTER_SHA256 = '38d3781c8fbe906dc35b1491d01e95127653d4f101d69e0539b150c7f1830af0'


def native_adapter_call(text, cwd, base):
    """Count one pinned native operation; writes require one new output pair."""
    segments = split_segments(text)
    if len(segments) != 1:
        return None
    words = unquoted_words(segments[0][0])
    python = r'(?:.*[/\\])?(?:python(?:\d+(?:\.\d+)*)?|py)(?:\.exe)?'
    if len(words) < 2 or not re.fullmatch(python, words[0], re.I):
        return None
    if Path(words[1]).name.lower() == 'rb.py':
        runner = Path.home() / '.claude/tools/resource-budget/rb.py'
        if Path(msys_fix(words[1])).resolve() != runner.resolve() or words[2:3] != ['run']:
            return None
        try:
            divider = words.index('--', 3)
        except ValueError:
            return None
        flags = words[3:divider]
        if len(flags) % 2 or any(flags[i] not in ('--name', '--cpu', '--ram', '--disk', '--cpu-cap', '--mem-cap', '--priority', '--wait-until-fits')
                               for i in range(0, len(flags), 2)):
            return None
        words = words[divider + 1:]
        if len(words) < 2 or not re.fullmatch(python, words[0], re.I):
            return None
    if len(words) < 2 or Path(words[1]).name.lower() != 'resaver-native.py':
        return None
    try:
        helper = ROOT / 'tools/resaver-native.py'
        candidate = Path(msys_fix(words[1]))
        if not candidate.is_absolute():
            candidate = Path(cwd) / candidate
        if candidate.resolve() != helper.resolve() or sha256(helper) != NATIVE_ADAPTER_SHA256:
            raise ValueError('adapter differs from the reviewed candidate')
        import importlib.util
        spec = importlib.util.spec_from_file_location('qualified_native_adapter', helper)
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        operation, source, output, native = adapter.invocation(words[2:])
        adapter.executable()  # verify the installed candidate pin before authorizing it
        if output is None:
            return decision('allow')  # reads and in-memory previews never write a save
        if any(not is_abs(msys_fix(w)) for w in (words[3], native[1])):
            raise ValueError('literal absolute input required for a write')
        raw_positions = []
        i = 4
        while i < len(words):
            if words[i].startswith('--'):
                i += 2 if words[i] in adapter.VALUE_FLAGS else 1
            else:
                raw_positions.append(words[i])
                i += 1
        output_index = 3 if operation == 'set-var' else 2 if operation == 'set-global' else 0
        if not is_abs(msys_fix(raw_positions[output_index])):
            raise ValueError('literal absolute output required for a write')
        if any(c in str(output) for c in '*?$%{}[]`\n'):
            raise ValueError('literal output required')
        return change([str(output)], [str(output)], 'native-controlled-edit', base)
    except Exception as exc:
        return decision('deny', reason='Native candidate refused: ' + str(exc))


def invoked_scripts(text, _depth=0):
    """Script files this command RUNS (not files it merely names, such as `git add x.py`), as regex tuples.
    The interpreter may be named by full path, quoted or not (C:/.../python.exe script.py). Two passes so the
    PowerShell call operator (& 'x.ps1') cannot swallow `&& python x.py` or `& "C:/.../python.exe" x.py`."""
    script_arg = r"(?:\s+-(?!File\b)[-\w]+)*\s+(?:-File\s+)?(?:'([^'\n]+)'|\"([^\"\n]+)\"|([^\s\"';|&]+))"
    invoked = re.findall(r"(?:^|[\s;&|(])(?:\"[^\"\n]*[/\\]|'[^'\n]*[/\\]|[^\s\"';|&]*[/\\])?"
                         r"(?:python\w*(?:\.\d+)?|py|bash|sh|pwsh|powershell|node)(?:\.exe)?[\"']?" + script_arg, text, re.I)
    invoked += re.findall(r"(?:^|[\s;|(])(?<!&)&(?!&)" + script_arg, text, re.I)
    invoked += re.findall(r"(?:^|[\s;&|(])()()(\.{0,2}/[^\s\"';|&]+\.(?:sh|py))\b", text)
    # A script's SOURCE handed to an interpreter runs that script just the same: piped (`Get-Content x.ps1 | pwsh -`,
    # `cat x.py | python -`), exec'd (`exec(open('x.py').read())`), evaluated (`iex (Get-Content x.ps1 -Raw)`) or
    # dot-sourced (`. ./x.ps1`). Until 2026-11-01 only the helper-NAME rule caught these, and only for six names.
    # a bare source never starts with '-', so flags and the path cannot trade characters (quadratic backtracking on
    # `cat -a -a -a ...`, review 2026-11-01)
    source = r"(?:'([^'\n]+)'|\"([^\"\n]+)\"|((?!-)[^\s\"';|&()]+))"
    invoked += re.findall(r"(?:^|[\s;&|(])(?:get-content|gc|cat|type)(?:\s+-\w+)*\s+" + source +
                          # within ONE command (no ; & or newline before the pipe), into a command-word interpreter;
                          # replay 2026-11-01: `rg -n 'a|durable_python'` after `; Get-Content x.py` is not a pipe
                          r"[^|;&\n]*\|\s*(?:&\s*)?(?:[^\s|;'\"]*[/\\])?(?:python\w*|py|bash|sh|pwsh|powershell|node)(?:\.exe)?(?![\w.-])",
                          text, re.I)
    invoked += re.findall(r"exec\s*\(\s*open\s*\(\s*" + source, text, re.I)
    invoked += re.findall(r"(?:iex|invoke-expression)\s*\(?\s*(?:get-content|gc|cat|type)(?:\s+-\w+)*\s+" + source, text, re.I)
    invoked += re.findall(r"(?:^|[;&|\n]\s*)\.\s+" + source, text, re.I)
    # ripgrep's --pre runs its argument on every file it searches.
    invoked += re.findall(r"(?:^|\s)--pre(?:=|\s+)" + source, text)
    # An inline command (`pwsh -Command "& './x.ps1'"`, `bash -c '. ./x.sh'`) is captured whole above; the scripts it
    # runs are found one level down.
    if _depth < 1:
        for token in list(invoked):
            inner = next((v for v in token if v), '')
            if re.search(r'\s', inner):
                invoked += invoked_scripts(inner, _depth + 1)
    return invoked


def only_text_tools(text):
    """True only for ONE bare text-tool command (TEXT_TOOLS) that runs nothing: no shell composition at all outside
    quotes (no & | ; < > or newline -- each review round found a new way a composed line hid a second program from the
    segment splitter, so composition simply ends the exemption), no substitution anywhere, no leading VAR=..., git/gh
    only as a plain listed subcommand without options that start programs, and no rg --pre."""
    if TEXT_TOOL_EXECUTES.search(text):
        return False
    unquoted = re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", '', text)
    if re.search(r'[&|;<>\r\n]', unquoted.strip()):
        return False
    words = re.findall(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"|\S+", text.strip())
    if not words or re.match(r'^[\w.-]+=', words[0]):
        return False
    name = re.sub(r'\.exe$', '', re.split(r'[/\\]', words[0].strip('\'"').lower())[-1])
    args = [w.strip('\'"') for w in words[1:]]
    if name not in TEXT_TOOLS:
        return False
    if name in TEXT_TOOL_SUBCOMMANDS:
        if not args or args[0] not in TEXT_TOOL_SUBCOMMANDS[name]:
            return False
        if any(re.match(r'-(?:c\b|O|-open-files-in-pager|-ext-diff|-textconv|-exec|-config|-paginate|p\b)', a) for a in args):
            return False
    if name == 'rg' and any(a.startswith('--pre') for a in args):
        return False
    return True


def runtime_request(text, need_target=True):
    """True when `text` asks DevBench to save or load the game (see RUNTIME_PAIR). A command (need_target) made only of
    text tools with no sender in it never counts (TEXT_TOOLS), and a function or console request counts only beside
    DevBench context; an invoked
    script's source counts without either, as the pre-2026-11-01 script check did. A game action counts only where a
    request names the game tool (RUNTIME_TOOL or a tool/tool_name/endpoint/name pair), so a test fixture that lists a
    request in order to check it is refused does not."""
    # escaped quotes: JSON in a shell string (\") and PowerShell's backtick (`")
    t = text.replace('\\"', '"').replace("\\'", "'").replace('`"', '"').replace("`'", "'")
    if need_target and only_text_tools(text) and not RUNTIME_SENDER.search(t):
        return False
    pairs = [(m[1].lower(), m[2].strip().lower()) for m in RUNTIME_PAIR.finditer(t)]
    pairs += [(m[1].lower(), m[2].strip().lower()) for m in RUNTIME_QUERY.finditer(t)]
    named = {next(g for g in m.groups() if g).lower() for m in RUNTIME_TOOL.finditer(t)}
    reach = not need_target or bool(named) or bool(RUNTIME_CONTEXT.search(t))
    if reach and any(k == 'function' and v in RUNTIME_FUNCTIONS for k, v in pairs):
        return True
    if reach and any(k == 'command' and RUNTIME_CONSOLE.search(v) for k, v in pairs):
        return True
    aimed = 'game' in named or any(k in RUNTIME_TOOL_KEYS and v.rsplit('/', 1)[-1] == 'game' for k, v in pairs)
    acted = (any(k == 'action' and v in RUNTIME_ACTIONS for k, v in pairs) or bool(RUNTIME_TOKEN.search(t))
             or bool(RUNTIME_FILE_BODY.search(t)))
    return aimed and acted


def touches_save_location(text, cwd):
    """Does this command reach a save folder at all? The shell sits in or above one, the text spells one, or a
    path it names (relative ones resolved against cwd; a wildcard judged by the folder before it) is a save folder
    or holds one. When this is False nothing the command can name is a save the game reads."""
    if cwd and (in_save_location(cwd) or holds_save_location(norm(cwd))):
        return True
    # The never-approvable folder rules (folder_violation: `My Games` parents, the store, the isolation archives)
    # and recursive_delete_set's disk walk run BEFORE this is asked, so neither needs to be repeated here.
    if FOLDER.search(text) or mentions_save_location(text):
        return True
    # Inside the store counts; ABOVE it does not (the install root is above it, so every `cd` into the install
    # counted -- replay 2026-10-30). Deleting a parent of the store is folder_violation's refusal.
    return bool(_named_folders(text, cwd, lambda p, wild: in_save_location(p) or holds_save_location(p)
                               or under(p, BACKUP_ROOT)))


def hands_save_location(text, cwd):
    """For a script: does the command hand it a path INSIDE a save location (or run it from one)? Folders ABOVE
    one do not count here -- crash-triage.py handed `My Games/Skyrim VR/SKSE/crash.log` reads a log (replay
    2026-10-30); a direct delete of such a folder is still folder_violation's and the wildcard rule's."""
    if cwd and in_save_location(cwd):
        return True
    if FOLDER.search(text) or mentions_save_location(text):
        return True
    return bool(_named_folders(text, cwd, lambda p, wild: in_save_location(p) or under(p, BACKUP_ROOT)))


def _named_folders(text, cwd, test):
    """Paths the text names (relative ones resolved against cwd; a wildcard judged by the folder before it)
    for which test(path, had_wildcard) holds. `My\\ Games` (an escaped space) stays one word."""
    found = []
    escaped = text.replace('\\ ', '\x01')
    for value in {v.replace('\x01', ' ') for v, _ in values_of(escaped)}:
        v = msys_fix(value.strip())
        if len(v) < 2 or v.startswith('-'):
            continue
        cut = re.split(r'[*?\[]', v, maxsplit=1)[0]
        wild = cut != v
        if wild and not cut.endswith(('/', '\\')):
            cut = os.path.dirname(cut)
        if not cut or any(c in cut for c in '$%`\n\0'):
            continue      # variables: only the save-pointing environment variables matter (mentions_save_location)
        if wild and re.fullmatch(r'[/\\]+|[a-z]:[/\\]*', cut, re.I):
            continue      # `/[0-9]+/`, `/*.json`: a regex or glob fragment, not the drive root (replay 2026-10-30)
        try:
            p = norm(cut if is_abs(cut) else os.path.join(cwd or str(ROOT), cut))
        except (ValueError, OSError):
            continue
        if test(p, wild):
            found.append(p)
    return found


def recursive_wildcard_above_saves(text, cwd):
    """`rm -rf "<My Games>/*"`: a recursive wildcard delete in a folder ABOVE a save folder takes the whole Saves
    folder with it. Deleting that folder by name is already refused (folder_violation); its contents by wildcard
    were not (both guards allowed it, found 2026-10-30)."""
    if not RECURSIVE.search(text) or operation(text, 'Bash') != 'delete':
        return []
    # Strictly ABOVE: `Saves/*` itself stays the approvable bulk change the rest of the guard counts.
    return _named_folders(text, cwd, lambda p, wild: wild and holds_save_location(p) and not in_save_location(p))


def outside_save_folders(text, op, base):
    """Nothing here reaches a save folder: allow, recording any save-named change for the record."""
    if op in WRITE_OPS:
        named = re.findall(r'[^\s\"\'`;|<>(){},]+\.(?:ess|skse)\b', text, re.I)
        if named:
            advise(named, op, base)
    return decision('allow')


LOCK_SWITCH = 'save-lock.json'
# This install's switch: .claude/save-lock.json. A file of the same name elsewhere (a toolkit checkout's) is not it.
LOCK_SWITCH_PATH = re.compile(r'(?<![\w-])\.claude[/\\]+save-lock\.json', re.I)
LOCK_OFF = re.compile(r'save_lock\.py[\"\']?\s+(?:\S+\s+)*?off\b', re.I)
LOCK_SWITCH_DENY = ('SAVE LOCK SWITCH: only the user turns save locking off (run `python tools/save_lock.py off` '
                    'from an elevated prompt). Agents may read .claude/save-lock.json but never change or remove it.')


def lock_switch_violation(tool, text):
    """Turning save locking off is the user's call: no agent edit, removal or `off` (user ruling 2026-10-31)."""
    if tool in ('apply_patch', 'Edit', 'Write', 'NotebookEdit'):
        return any(LOCK_SWITCH_PATH.search(p.strip().strip('"\'')) or
                   (os.path.basename(p.strip().strip('"\'')).lower() == LOCK_SWITCH
                    and os.path.normcase(os.path.abspath(p.strip().strip('"\''))) ==
                    os.path.normcase(str(ROOT / '.claude' / LOCK_SWITCH)))
                   for p in text.splitlines() if p.strip())
    if re.search(r'>\s*[\'"]?\S*\.claude[/\\]+' + re.escape(LOCK_SWITCH), text, re.I):
        return True                        # a redirect writes it, whatever command (echo, printf) carries it
    acting = acting_text(text)             # prose carriers (git -m, echo, printf) mention it without acting
    if LOCK_OFF.search(acting):
        return True
    if not LOCK_SWITCH_PATH.search(acting):
        return False
    return bool(MUTATE.search(acting) or operation(acting, tool) not in ('read', 'hash'))


# ------------------------------------------------- what each command writes to (2026-11-02)
# A peer's probe found rsync, tar, shred, ln, `gci | % Delete` and others changed saves with no backup, because
# operation() called them reads; an independent review found `cd Saves && rm *` allowed too. A word search on the raw text
# is the wrong tool for this: it refuses `rg 'a|ln b'` and misses /usr/bin/rsync. So each simple command is parsed: which
# tool, in which folder (following cd), and which of its words it WRITES. Reading and copying out write nothing there.
WRAPPER_WORDS = {'env', 'nohup', 'time', 'nice', 'ionice', 'command', 'exec', 'stdbuf', 'busybox', 'wsl', 'then', 'do', 'else',
                 'if', 'while', 'until', '!', '{', '&', 'call', 'start', 'sudo', 'timeout'}
WRAPPER_VALUE_FLAGS = {'sudo': {'-u', '-g', '-h', '-p', '-c', '-t', '-r'}, 'nice': {'-n'}, 'ionice': {'-c', '-n'},
                       'env': {'-u', '-C', '-S'}, 'stdbuf': {'-i', '-o', '-e'}, 'wsl': {'-d', '-u', '-e'}, 'timeout': {'-k', '-s'}}
SHELL_CARRIERS = {'bash', 'sh', 'zsh', 'dash', 'ksh'}
PS_CARRIERS = {'pwsh', 'powershell'}
CHDIR_WORDS = {'cd', 'pushd', 'chdir', 'set-location', 'sl', 'push-location'}
CHDIR_BACK = {'popd', 'pop-location'}
EVAL_WORDS = {'iex', 'invoke-expression', 'eval'}
BLOCK_WORDS = {'try', 'catch', 'finally', 'function', 'measure-command', 'invoke-command', 'icm', 'start-job', 'sajb', 'foreach',
               'for', 'while', 'if', 'else', 'elseif'}
START_WORDS = {'start-process', 'saps'}
PIPE_FILTERS = {'?', 'where', 'where-object', 'select', 'select-object', 'sort', 'sort-object', 'group', 'group-object'}
INLINE_CODE = {'python': '-c', 'python3': '-c', 'py': '-c', 'node': '-e', 'perl': '-e', 'ruby': '-e'}
DELETE_TOOLS = {'shred', 'sdelete', 'sdelete64', 'ri'}
COMPRESSORS = {'gzip', 'gunzip', 'bzip2', 'bunzip2', 'xz', 'unxz', 'lzma', 'unlzma', 'zstd', 'unzstd'}
COMPRESS_READS = {'-c', '-l', '-t', '--stdout', '--to-stdout', '--list', '--test', '-h', '--help', '-V', '--version'}
PS_WRITE_ALIASES = {'sc', 'ac', 'clc', 'cli', 'si', 'ni', 'clear-item', 'set-item', 'tee-object'}
TRANSFER_ALIASES = {'copy', 'cpi', 'move', 'mi', 'ren', 'rename', 'rni'}
ARCHIVERS = {'7z', '7za', '7zr', '7zz', 'unrar', 'rar'}
DOWNLOADERS = {'curl': ('-o', '--output'), 'wget': ('-O', '--output-document'), 'iwr': ('-outfile',),
               'invoke-webrequest': ('-outfile',), 'irm': ('-outfile',), 'invoke-restmethod': ('-outfile',), 'sort': ('-o', '--output')}
# Only under a cd into a save folder: the guard's later rules judge these on literal paths, but a relative one was never seen.
RELATIVE_DELETE = {'rm', 'del', 'erase', 'rmdir', 'rd', 'remove-item', 'unlink'}
RELATIVE_WRITE = {'touch', 'truncate', 'tee', 'set-content', 'add-content', 'clear-content', 'out-file', 'new-item'}
GIT_WRITES = {'clean', 'checkout', 'restore', 'reset', 'switch', 'stash', 'apply', 'merge', 'rebase', 'pull', 'revert', 'cherry-pick'}
RSYNC_VALUE_FLAGS = {'--exclude', '--include', '--exclude-from', '--include-from', '--files-from', '--link-dest', '--compare-dest',
                     '--copy-dest', '--backup-dir', '--temp-dir', '-T', '--partial-dir', '--log-file', '--filter', '-f', '--rsh', '-e',
                     '--chmod', '--chown', '--timeout', '--bwlimit', '--max-size', '--min-size', '--suffix', '--port', '--password-file',
                     '--rsync-path', '--out-format', '--info', '--debug'}
SCP_VALUE_FLAGS = {'-P', '-i', '-o', '-F', '-l', '-c', '-S', '-J', '-D'}
RSYNC_WRITTEN_VALUES = {'--backup-dir', '--temp-dir', '-T', '--partial-dir', '--log-file'}
RCLONE_READS = {'ls', 'lsf', 'lsd', 'lsl', 'lsjson', 'check', 'md5sum', 'sha1sum', 'hashsum', 'size', 'cat', 'tree', 'version',
                'listremotes', 'config', 'about', 'help'}
TAR_VALUE_LETTERS = 'fCXTbHLKNgV'
PAREN_METHOD = re.compile(r'\)\s*\.(?:delete|moveto|encrypt|decrypt)\s*\(|\$\w+\.(?:delete|moveto|encrypt|decrypt)\s*\(', re.I)
PIPE_METHOD = re.compile(r'^[\'"]?(delete|moveto|copyto|encrypt|decrypt)[\'"]?$', re.I)
PIPE_LISTERS = {'get-childitem', 'gci', 'ls', 'dir', 'get-item', 'gi'}
PIPE_ACTIONS = {'ri': 'delete', 'remove-item': 'delete', 'del': 'delete', 'rm': 'delete', 'mi': 'move', 'move-item': 'move',
                'rni': 'rename', 'rename-item': 'rename', 'cpi': 'copy', 'copy-item': 'copy'}
_REMOTE = re.compile(r'^(?:[^/\\:\s]{2,}):(?![/\\]{2})')


def _shell_words(segment):
    """Words with quotes removed, keeping `\\ ` and `\\"`: the real save path has a space, and `bash -c "x \\"a b\\""` is everyday.
    Any other backslash is a Windows path separator."""
    words, cur, started, quote, i = [], '', False, None, 0
    quoted = False
    while i < len(segment):
        c = segment[i]
        if c == '\\' and i + 1 < len(segment) and segment[i + 1] in ' "' and quote != "'":
            cur += segment[i + 1]
            started = True
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
            else:
                cur += c
        elif c in '"\'':
            quote = c
            quoted = quoted or not cur
            started = True
        elif c.isspace():
            if started:
                words.append(QUOTED_MARK + cur if quoted else cur)
            cur, started, quoted = '', False, False
        else:
            cur += c
            started = True
        i += 1
    if started:
        words.append(QUOTED_MARK + cur if quoted else cur)
    return words


QUOTED_MARK = '\0'
_REDIRECT = re.compile(r'^(?:\d*|&)(>>?\|?|<<?<?)(&?)(.*)$')


def _without_redirects(words):
    """(the command's own words, files it redirects output into). `2>&1` and a trailing `&` are not arguments."""
    out, targets, i = [], [], 0
    while i < len(words):
        w = words[i]
        i += 1
        if w.startswith(QUOTED_MARK):
            out.append(w[1:])
            continue
        if w == '&':
            continue
        m = _REDIRECT.match(w)
        if not m:
            out.append(w)
            continue
        value = m[3]
        if not value and not m[2] and i < len(words):
            value = words[i].lstrip(QUOTED_MARK)
            i += 1
        # A variable target is left to the later rules: `ls Saves > "$LOG"` is an everyday read.
        if m[1].startswith('>') and not m[2] and value and '$' not in value and value.lower() not in ('/dev/null', 'nul'):
            targets.append(value)
    return out, targets


def _split_on_ampersand(segment):
    """split_segments keeps a lone `&`. In bash it starts a background job; in PowerShell it calls what follows."""
    parts, cur, quote, i = [], '', None, 0
    while i < len(segment):
        c = segment[i]
        if quote:
            quote = None if c == quote else quote
        elif c in '"\'':
            quote = c
        elif c == '&' and segment[i - 1:i] not in ('>', '<') and segment[i + 1:i + 2] != '>':
            parts.append(cur)
            cur, i = '', i + 1
            continue
        cur += c
        i += 1
    parts.append(cur)
    return [x.strip() for x in parts if x.strip()]


def _without_heredoc_bodies(text):
    """Keep each heredoc's first line. Its body is data unless a shell reads it, which the driver handles separately."""
    return re.sub(r"(<<-?\s*['\"]?(\w+)['\"]?[^\n]*)\n.*?(?:\n[ \t]*\2[ \t]*(?=\n|\)|$)|\Z)", r'\1', text, flags=re.S)


def _masked(text):
    """text with every quoted span blanked (same length), so structure can be searched without reading text."""
    out, quote = [], None
    for c in text:
        if quote:
            out.append(' ')
            if c == quote:
                quote = None
        elif c in '"\'':
            quote = c
            out.append(' ')
        else:
            out.append(c)
    return ''.join(out)


def _substitutions(text):
    """The commands in backticks and $(...), which run even inside double quotes. Single quotes hide them; an inner
    single-quoted path stays part of the command."""
    found, i, quote = [], 0, None
    while i < len(text):
        c = text[i]
        if c == "'" and quote != '"':
            quote = None if quote == "'" else "'"
        elif quote == "'":
            pass
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == '`' and (end := text.find('`', i + 1)) > i:
            found.append(text[i + 1:end])
            i = end
        elif text.startswith('$(', i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {'(': 1, ')': -1}.get(text[j], 0)
                j += 1
            found.append(text[i + 2:j - 1])
            i = j - 1
        i += 1
    return found


def _braced(segment):
    """The code in a segment's outermost { }, which split_segments leaves in one piece."""
    masked = _masked(segment)
    a, b = masked.find('{'), masked.rfind('}')
    return segment[a + 1:b] if 0 <= a < b else None


def _heredoc_body(segment):
    m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)(?:\n\s*\1\s*$|\Z)", segment, re.S)
    return m[2] if m else None


def _command_of(words):
    """(tool name, its arguments) with wrappers, assignments, a path and .exe removed."""
    words = list(words)
    while words:
        w = words[0]
        if re.match(r'^[A-Za-z_]\w*=', w):
            words.pop(0)
            continue
        if re.fullmatch(r'\$[\w:]+', w) and words[1:2] == ['=']:     # PowerShell: $r = rsync ...
            del words[:2]
            continue
        base = re.split(r'[/\\]', w)[-1].lower()
        base = re.sub(r'\.(?:exe|cmd|bat)$', '', base)
        if base not in WRAPPER_WORDS:
            return base, words[1:]
        words.pop(0)
        values = WRAPPER_VALUE_FLAGS.get(base, ())
        while words and (words[0].startswith('-') or re.match(r'^[A-Za-z_]\w*=', words[0])):
            flag = words.pop(0)
            if flag in values and words:
                words.pop(0)
        if base == 'timeout' and words:
            words.pop(0)                                   # the duration
    return '', []


def _joined(words):
    """Words back into command text; each one that holds a space keeps its quotes."""
    return words[0] if len(words) == 1 else ' '.join('"' + w + '"' if ' ' in w else w for w in words)


def _inner_command(name, args):
    """The command text a shell is told to run, or None. One quoted argument is the whole command; several are its words."""
    if name in SHELL_CARRIERS:
        for i, w in enumerate(args):
            if re.fullmatch(r'-[a-zA-Z]*c[a-zA-Z]*', w):
                return _joined(args[i + 1:])
        return None
    if name == 'cmd':
        for i, w in enumerate(args):
            if w.lower() in ('/c', '/k'):
                return _joined(args[i + 1:])
        return None
    if name in PS_CARRIERS:
        for i, w in enumerate(args):
            if re.fullmatch(r'-c(?:ommand)?', w, re.I):
                return _joined(args[i + 1:])
    return None


def _tar_writes(args):
    """Paths tar writes, or None when it writes nothing. Case matters: -x extracts, -X names an exclude file."""
    extract = writes_archive = removes = to_stdout = False
    folders, archives, operands = [], [], []
    i, first = 0, True
    while i < len(args):
        w = args[i]
        i += 1
        if w.startswith('--'):
            flag, eq, value = w.partition('=')
            if flag.startswith('--ext') or flag == '--get':
                extract = True
            elif flag in ('--create', '--append', '--update', '--delete', '--catenate', '--concatenate'):
                writes_archive = True
            elif flag.startswith('--rem'):
                removes = True
            elif flag.startswith('--to-std'):
                to_stdout = True
            elif flag.startswith(('--di', '--one')):
                if not eq and i < len(args) and flag.startswith('--di'):
                    value = args[i]
                    i += 1
                if value:
                    folders.append(value)
            elif flag.startswith('--file'):
                if not eq and i < len(args):
                    value = args[i]
                    i += 1
                archives.append(value)
            first = False
            continue
        dashed = w.startswith('-') and len(w) > 1
        if dashed or (first and re.fullmatch(r'[a-zA-Z]{1,8}', w)):
            letters = w[1:] if dashed else w
            for j, c in enumerate(letters):
                if c == 'x':
                    extract = True
                elif c == 'O':
                    to_stdout = True
                elif c in 'cruA':
                    writes_archive = True
                if c in TAR_VALUE_LETTERS:
                    attached = letters[j + 1:] if dashed else ''
                    if attached:
                        value = attached
                    elif i < len(args):
                        value = args[i]
                        i += 1
                    else:
                        value = ''
                    if c == 'C':
                        folders.append(value)
                    elif c == 'f':
                        archives.append(value)
                    if attached:
                        break
            first = False
            continue
        first = False
        operands.append(w)
    written = []
    if extract and not to_stdout:
        written += folders or ['.']
    if writes_archive:
        written += [a for a in archives if a != '-']
    if removes:
        written += [folders[-1].rstrip('/\\') + '/' + o for o in operands] if folders else operands
    return written


def _archiver_writes(name, args):
    plain = [a for a in args if not a.startswith('-')]
    if not plain:
        return []
    verb = plain[0].lower()
    if verb in ('x', 'e'):
        outs = [a[2:] for a in args if a.startswith('-o') and len(a) > 2]
        if name in ('unrar', 'rar') and len(plain) > 2:
            outs += [plain[-1]]
        return outs or ['.']
    if verb in ('a', 'u', 'd', 'rn', 'f'):
        written = plain[1:2]
        if any(a.lower() == '-sdel' for a in args):
            written += plain[2:]
        return written
    return []


def _rsync_scp_writes(name, args):
    """(destination-side writes, operands). A flag's value is never an operand."""
    values = RSYNC_VALUE_FLAGS if name == 'rsync' else SCP_VALUE_FLAGS
    operands, written, remove_source, i = [], [], False, 0
    while i < len(args):
        w = args[i]
        i += 1
        if w.startswith('-') and len(w) > 1:
            flag, eq, value = w.partition('=')
            if flag.startswith(('--remove-source', '--remove-sent')):
                remove_source = True
            if flag in values and not eq:
                value = args[i] if i < len(args) else ''
                i += 1
            if flag in RSYNC_WRITTEN_VALUES and value:
                written.append(value)
            continue
        operands.append(w)
    if len(operands) >= 2:
        written.append(operands[-1])
        if remove_source:
            written += operands[:-1]
    return written


def _rclone_writes(args):
    plain = [a for a in args if not a.startswith('-')]
    if not plain or plain[0].lower() in RCLONE_READS:
        return 'write', []
    verb, rest = plain[0].lower(), plain[1:]
    if verb in ('delete', 'deletefile', 'purge', 'rmdir', 'rmdirs', 'cleanup'):
        return 'delete', rest
    if verb in ('move', 'moveto'):
        return 'move', rest
    return 'write', rest[-1:]


def _powershell_target(args):
    """The file a *-Content style command writes: -Path's value, else the first plain word. The others are its value."""
    for i, a in enumerate(args):
        if a.lower() in ('-path', '-literalpath', '-filepath', '-pspath'):
            return args[i + 1:i + 2]
    i = 0
    while i < len(args):
        if args[i].startswith('-'):
            i += 2
            continue
        return [args[i]]
    return []


def _download_target(name, args):
    if name in ('iwr', 'invoke-webrequest', 'irm', 'invoke-restmethod'):
        for i, a in enumerate(args):
            if len(a) > 2 and '-outfile'.startswith(a.lower()):
                return args[i + 1:i + 2]
        return []
    short = {'curl': 'o', 'wget': 'O', 'sort': 'o'}[name]
    long_flag = {'curl': '--output', 'wget': '--output-document', 'sort': '--output'}[name]
    for i, a in enumerate(args):
        if a.startswith(long_flag + '='):
            return [a.split('=', 1)[1]]
        if a == long_flag:
            return args[i + 1:i + 2]
        m = re.fullmatch(r'-[a-zA-Z]*?' + short + r'(.*)', a)
        if m and not a.startswith('--'):
            return [m[1]] if m[1] else args[i + 1:i + 2]
    return []


def _written_paths(name, args, tool, under_cd):
    """(op, words this command writes), or None when it isn't a tool this pass judges."""
    plain = [a for a in args if not a.startswith('-')]
    low = [a.lower() for a in args]
    if name == 'tar' or name == 'bsdtar':
        return 'write', _tar_writes(args)
    if name in ARCHIVERS:
        return 'write', _archiver_writes(name, args)
    if name in ('rsync', 'scp'):
        return 'copy', _rsync_scp_writes(name, args)
    if name == 'rclone':
        return _rclone_writes(args)
    if name in DELETE_TOOLS:
        return 'delete', plain
    if name in COMPRESSORS:
        return ('write', []) if any(a in COMPRESS_READS or re.fullmatch(r'-[a-zA-Z]*[clt][a-zA-Z]*', a) for a in args) else ('write', plain)
    if name == 'ln':
        for i, a in enumerate(args):
            if a.startswith('--target-directory='):
                return 'write', [a.split('=', 1)[1]]
            if a == '--target-directory' or re.fullmatch(r'-[a-zA-Z]*t', a):
                return 'write', args[i + 1:i + 2]
        return 'write', [plain[-1] if len(plain) >= 2 else '.'] if plain else []
    if name == 'mklink':
        return 'write', [a for a in args if not a.startswith('/')][:1]
    if name == 'fsutil' and len(plain) >= 3 and plain[0].lower() == 'hardlink':
        return 'write', plain[2:3]
    if name == 'zip':
        written = plain[:1]
        if any(re.fullmatch(r'-[a-zA-Z]*T[a-zA-Z]*|--test', a) for a in args):
            return 'write', []
        if any(re.fullmatch(r'-[a-zA-Z]*m[a-zA-Z]*|--move', a) for a in args):
            written += plain[1:]
        return 'write', written
    if name in PS_WRITE_ALIASES and tool == 'PowerShell':
        return 'write', _powershell_target(args)
    if name == 'perl' and any(re.fullmatch(r'-[a-zA-Z]*i\S*', a) for a in args):
        code = next((i for i, a in enumerate(args) if re.search(r'e', a) and a.startswith('-')), None)
        return 'write', [a for a in args[(code + 2 if code is not None else 0):] if not a.startswith('-')]
    if name == 'sed' and '--in-place' in low:
        return 'write', plain[1:]
    if name == 'install' and len(plain) >= 2:
        return 'copy', plain[-1:]
    if name in DOWNLOADERS:
        return 'write', _download_target(name, args)
    if name == 'dd':
        return 'write', [a[3:] for a in args if a.startswith('of=')]
    if under_cd:
        if name in RELATIVE_DELETE:
            return 'delete', plain or ['.']
        if name in RELATIVE_WRITE:
            return 'write', _powershell_target(args) if '-' in name else plain or ['.']
        if name in ('cp', 'copy-item'):
            return 'copy', plain[-1:]
        if name in ('mv', 'move-item', 'rename-item'):
            return 'move', plain
        if name == 'git' and plain and plain[0].lower() in GIT_WRITES:
            return 'write', ['.']
    return None


def _resolved(word, vcwd):
    """(absolute path, certain). A wildcard is judged by its folder; a variable can't be known."""
    value = msys_fix(word.strip())
    if any(c in value for c in '$`%{}'):
        return None, False
    cut = re.split(r'[*?\[]', value, maxsplit=1)[0]
    if cut != value:
        cut = cut if cut.endswith(('/', '\\')) or not cut else os.path.dirname(cut)
    try:
        return norm(cut if cut and is_abs(cut) else os.path.join(vcwd, cut)), cut == value
    except (ValueError, OSError):
        return None, False


def _is_location(path):
    return bool(FOLDER.search(path.replace('\\', '/') + '/')) or in_save_location(path)


def _judge_written(op, words, vcwd, base, text):
    saves, reached, wild, unknown = [], [], [], False
    for word in words:
        if not word or word == '-' or _REMOTE.match(word):
            continue
        path, certain = _resolved(word, vcwd)
        if path is None:
            unknown = True
            continue
        if under(path, BACKUP_ROOT):
            return decision('deny', reason='Save backups are kept forever: writing over or removing a backup is blocked.')
        if not certain:
            if _is_location(path) or holds_save_location(path) or os.path.isdir(os.path.join(path, 'Saves')):
                wild.append(path)
        elif _is_location(path):
            if is_save(path):
                saves.append(path)
            else:
                reached.append(path)
        elif holds_save_location(path) or os.path.isdir(os.path.join(path, 'Saves')):
            reached.append(path)
    # A variable or loop anywhere in the command can carry a save folder named elsewhere in it.
    if unknown and (FOLDER.search(text) or mentions_save_location(text) or _is_location(vcwd)):
        return decision('needs_set', op=op, set=None, why='A file tool writes to a path the hook cannot read.', **base)
    if wild:
        return decision('needs_set', op=op, set=None, why='A file tool changes saves through a wildcard.', **base)
    if reached:
        if op in ('delete', 'move') and any(Path(p).name.lower() in ('saves', '__mo_saves') or holds_save_location(p)
                                            or (os.path.isdir(p) and _marker_above(os.path.normcase(p).rstrip('\\/')) and p != vcwd)
                                            for p in reached):
            return decision('deny', reason='Deleting or moving a whole Saves folder is blocked, approval or not. Name the save files instead.')
        return decision('needs_set', op=op, set=None, why='A file tool writes into a save folder without naming each save.', **base)
    if saves:
        return change(saves, saves, op, base)
    return None


def _piped_change(name, args, previous, vcwd, base, segment='', whole=''):
    """`gci Saves | % Delete` and `gci Saves | ri`: what the lister before the pipe found is what gets changed."""
    if previous is None or previous[0] not in PIPE_LISTERS:
        return None
    op = PIPE_ACTIONS.get(name)
    if op is None and name in ('%', 'foreach', 'foreach-object'):
        text = re.sub(r'"[^"]*"|\'[^\']*\'', ' ', segment)
        method = next((a for a in args if PIPE_METHOD.match(a)), None)
        if method is not None:
            op = {'delete': 'delete', 'moveto': 'move', 'copyto': 'copy'}.get(method.strip('\'"').lower(), 'write')
        elif re.search(r'\b(?:ri|remove-item|rm|del|mi|move-item|rni|rename-item|cpi|copy-item)\b|\.(?:delete|moveto)\s*\(', text, re.I):
            op = 'delete'
    if op is None:
        return None
    if op == 'copy' and any(a.startswith('-dest') for a in (x.lower() for x in args)):
        return None
    for word in [a for a in previous[1] if not a.startswith('-')] or ['.']:
        path, _ = _resolved(word, vcwd)
        unknown_near_saves = path is None and (FOLDER.search(whole) or mentions_save_location(whole) or _is_location(vcwd))
        if unknown_near_saves or (path is not None and (_is_location(path) or holds_save_location(path))):
            return decision('needs_set', op=op, set=None, why='A pipeline changes what it lists from a save folder.', **base)
    return None


def _transfer_alias(name, segment, vcwd, tool, base):
    """cmd's and PowerShell's short names for copy, move and rename: the same reading as their long forms."""
    words = _without_redirects(_shell_words(segment))[0]
    long_name = {'copy': 'copy-item', 'cpi': 'copy-item', 'move': 'move-item', 'mi': 'move-item', 'ren': 'rename-item',
                 'rename': 'rename-item', 'rni': 'rename-item', 'cp': 'copy-item', 'mv': 'move-item'}[name]
    op = {'copy-item': 'copy', 'move-item': 'move', 'rename-item': 'rename'}[long_name]
    at = next((i for i, w in enumerate(words) if re.split(r'[/\\]', w)[-1].lower().removesuffix('.exe') == name), None)
    if at is None:
        return None
    # a cmd builtin writes /y style flags, which aren't sources
    rest = [w for w in words[at + 1:] if not re.fullmatch(r'/[a-zA-Z-]+', w)]
    form = transfer_form(' '.join(['"' + w + '"' if ' ' in w else w for w in [long_name] + rest]), None)
    try:
        resolved = resolve_transfer(form) if form else None
    except OSError:
        return decision('needs_set', op=op, set=None, why='A short copy or move name reaches a folder the hook cannot read.', **base)
    if resolved is None:
        for w in rest:
            path, _ = _resolved(w, vcwd)
            if not w.startswith('-') and (path is None or _is_location(path)):
                return decision('needs_set', op=op, set=None, why='A short copy or move name reaches a save folder uncounted.', **base)
        return None
    affected, counted = change_sets(op, resolved, [])
    if not [p for p in resolved[1] + (resolved[0] if op != 'copy' else []) if _is_location(p)]:
        return None
    if affected:
        return change(affected, counted, op, base)
    return decision('needs_set', op=op, set=None, why='A short copy or move name writes into a save folder.', **base)


def file_tool_change(text, cwd, tool, base, _depth=0, whole=None):
    """A decision for the first command that writes into a save folder, the backup store, or a parent of one; else None.
    Nothing here reads a save or stats one: every judgement is on paths the command names."""
    whole = text if whole is None else whole
    start = vcwd = cwd or str(ROOT)
    previous, stack, assigned = None, [], {}

    def inner(code, next_tool=tool):
        return file_tool_change(code, vcwd, next_tool, base, _depth + 1, whole) if code and _depth < 3 else None

    for code in _substitutions(_without_heredoc_bodies(text)):
        found = inner(code)
        if found:
            return found
    for whole_segment, new_pipeline in split_segments(text):
        parts = _split_on_ampersand(whole_segment.split('\n', 1)[0]) if '<<' in whole_segment else _split_on_ampersand(whole_segment)
        fed_body = _heredoc_body(whole_segment)
        for part_index, segment in enumerate(parts):
            starts_pipeline = new_pipeline or part_index > 0
            words, redirected = _without_redirects(_shell_words(segment))
            name, args = _command_of(words)
            if fed_body and re.search(r'\|\s*(?:\S*[/\\])?(?:bash|sh|zsh|dash|pwsh|powershell)\b', _masked(segment), re.I):
                found = inner(fed_body, 'Bash')                  # cat <<EOF | bash: the pipe stays on the heredoc's first line
                if found:
                    return found
            if redirected:
                found = _judge_written('write', redirected, vcwd, base, whole)
                if found:
                    return found
            if not name:
                continue
            if name in CHDIR_BACK or (name == 'cd' and args[:1] == ['-']):
                vcwd = stack.pop() if stack else vcwd
                previous = None
                continue
            if name in CHDIR_WORDS:
                target = next((a for a in args if not a.startswith('-') and not re.fullmatch(r'/[a-zA-Z]', a)), None)
                if target:
                    path, certain = _resolved(target, vcwd)
                    if path is not None and certain:
                        stack.append(vcwd)
                        vcwd = path
                previous = None
                continue
            carried = _inner_command(name, args)
            if carried:
                found = inner(carried, 'PowerShell' if name in PS_CARRIERS else 'Bash' if name in SHELL_CARRIERS else tool)
                if found:
                    return found
                continue
            if name in SHELL_CARRIERS | PS_CARRIERS:             # code fed in by a heredoc or a pipe
                fed = fed_body
                if fed is None and previous is not None and not starts_pipeline:
                    fed = previous[2]
                found = inner(fed, 'PowerShell' if name in PS_CARRIERS else 'Bash')
                if found:
                    return found
                continue
            if name in EVAL_WORDS:
                found = inner(' '.join(args))
                if found:
                    return found
                continue
            if name in START_WORDS and args:
                listed = next((args[i + 1] for i, a in enumerate(args) if a.lower().startswith('-arg') and i + 1 < len(args)), '')
                found = inner(_joined(args[:1]) + ' ' + listed)
                if found:
                    return found
                continue
            if name in INLINE_CODE and start != vcwd and _is_location(vcwd):
                flag = INLINE_CODE[name]
                body = next((args[i + 1] for i, a in enumerate(args) if a == flag and i + 1 < len(args)), None)
                if body and changes_files(body):
                    return decision('needs_set', op='write', set=None, why='Code that changes files runs from inside a save folder.', **base)
            if name == 'xargs':
                tool_words = [a for a in args if not a.startswith('-')]
                listed_there = previous is not None and any(
                    (_resolved(a, vcwd)[0] is None) or _is_location(_resolved(a, vcwd)[0]) for a in [x for x in previous[1] if not x.startswith('-')] or ['.'])
                if vcwd != start and tool_words and listed_there and _written_paths(_command_of(tool_words)[0], [], tool, True) is not None:
                    return decision('needs_set', op='write', set=None, why='xargs hands a file tool what was listed from a save folder.', **base)
                continue
            if not starts_pipeline:
                if name in PIPE_FILTERS:
                    continue                                     # it passes along what the lister found
                if name.startswith('$') and name in assigned:
                    previous = assigned[name]
                    continue
                found = _piped_change(name, args, previous, vcwd, base, segment, whole)
                if found:
                    return found
            if name.startswith('$') and name in assigned:
                previous = assigned[name]
                continue
            assign = re.match(r'^(\$[\w:]+)\s*=', segment)
            previous = (name, args, fed_body or (' '.join(args) if name in ('echo', 'printf', 'write-output') else None))
            if assign:
                assigned[assign[1].lower()] = previous
            if name in BLOCK_WORDS or '{' in _masked(segment):
                body = _braced(segment)
                found = inner(body) if body and body.strip() != segment.strip() else None
                if found:
                    return found
                if name in BLOCK_WORDS:
                    continue
            comma_list = tool == 'PowerShell' and name in ('cp', 'mv') and any(',' in w for w in args)
            if name in TRANSFER_ALIASES or comma_list:
                found = _transfer_alias(name, segment, vcwd, tool, base)
                if found:
                    return found
                continue
            written = _written_paths(name, args, tool, under_cd=vcwd != start and _is_location(vcwd))
            if written is not None:
                found = _judge_written(written[0], written[1], vcwd, base, whole)
                if found:
                    return found
    # split_segments takes the parentheses out of `(gci x).Delete()`, so a method call is looked for across the whole command.
    masked = _masked(_without_heredoc_bodies(text))
    for statement in re.split(r'[;\n]|&&|\|\|', masked):
        if PAREN_METHOD.search(statement) and first_word(statement.lstrip('( '))[0] not in NOT_ACTIONS \
                and (FOLDER.search(whole) or mentions_save_location(whole) or _is_location(vcwd)):
            return decision('needs_set', op='delete', set=None, why='A method call changes what it lists from a save folder.', **base)
    return None


def decide(payload):
    """What to do with a tool call: allow / deny / backup / needs_files / needs_set."""
    tool = payload.get('tool_name', '')
    args = payload.get('tool_input')
    cwd = payload.get('cwd') or str(ROOT)
    if not isinstance(tool, str) or not isinstance(args, (dict, str)) or not isinstance(cwd, str):
        return decision('deny', reason='Malformed tool input; save policy could not be evaluated.')
    if tool in COMMUNICATION or any(x in tool for x in ('request_user_input', 'send_message', 'web_search')):
        return decision('allow')
    if tool in ('Glob', 'Grep', 'Read'):
        return decision('allow')  # names, searches and reads are free in any number
    base = {'tool': tool}
    if tool in ('apply_patch', 'Edit', 'Write', 'NotebookEdit'):
        if tool == 'apply_patch':
            patch = args.get('command', args.get('patch', '')) if isinstance(args, dict) else args
            targets = re.findall(r'^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$', patch, re.M)
            text = '\n'.join(a or b for a, b in targets)
            op = 'delete' if re.search(r'^\*\*\* Delete File: .*\.(?:ess|skse)', patch, re.M | re.I) else 'write'
        else:
            text = str(args.get('file_path', args.get('notebook_path', args.get('path', ''))))
            op = 'write'
        if lock_switch_violation(tool, text):
            return decision('deny', reason=LOCK_SWITCH_DENY)
        paths, problem = paths_in(text, cwd, literal=True)
        if problem:
            return decision('deny', reason='SAVE CHANGE BLOCKED: ' + problem + ' Name the save with a literal absolute path.')
        base['command'] = tool + ' ' + text
        return change(paths, paths, op, base)
    text = args if isinstance(args, str) else str(args.get('command', args.get('cmd', '')))
    if not text:
        # Walk structured inputs without JSON escaping Windows paths. Tool labels
        # do not matter: MCP copy/read operations are subject to the same policy.
        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for item in value.values():
                    yield from strings(item)
            elif isinstance(value, list):
                for item in value:
                    yield from strings(item)
        text = '\n'.join('"' + item + '"' for item in strings(args))
        text = tool + '\n' + text
    base['command'] = text
    base['hash'] = command_hash(text)
    if 'SAVE_GUARD_DENY_CANARY' in text:
        return decision('deny', reason='Save guard canary: intentionally blocked; no save file is involved.')
    if lock_switch_violation(tool, text):
        return decision('deny', reason=LOCK_SWITCH_DENY)
    if re.search(r'-(?:encodedcommand|enc)\b|base64\s+-d.*\|\s*(?:bash|sh|python)', text, re.I):
        return decision('deny', reason='Encoded executable commands cannot be checked for save access and are blocked.')
    native_adapter = native_adapter_call(text, cwd, base)
    if native_adapter is not None:
        return native_adapter
    if re.search(r"resaverpp-cli(?:\.exe)?[\"\']?\s+.*(?:--apply|(?:^|\s)-o\b)", text, re.I):
        return decision('deny', reason='Native save writes require the pinned preservation adapter.')
    native_probe = native_probe_call(text, cwd, base)
    if native_probe is not None:
        return native_probe
    protected = controlled_load_call(text, cwd, base)
    if protected is not None:
        return protected
    # A structured (MCP) call is judged with its keys: flattening above keeps only the values, which lost
    # {action: save} on mcp__devbench-vr__game, and `command` on the console tool is a game command, not a shell one.
    structured = None if isinstance(args, str) or tool in SHELL_TOOLS else tool + '\n' + json.dumps(args, default=str)
    if runtime_request(text) or (structured is not None and runtime_request(structured)):
        return decision('deny', reason='Automated in-game save/load stays a one-interaction-at-a-time manual matter; blocked.')
    violation = folder_violation(text, cwd)
    if violation:
        return decision('deny', reason=violation)
    above = recursive_wildcard_above_saves(text, cwd)
    if above:
        return decision('deny', reason='A recursive wildcard delete in ' + above[0] + ' would remove a whole Saves '
                        'folder with it. Never approvable; name the files to delete instead.')
    recursive = recursive_delete_set(text, cwd)
    if recursive:
        if recursive[0] == 'uncountable':
            return decision('deny', reason='A recursive or find-based delete that reaches saves is blocked when the hook '
                            'cannot count its matches (' + recursive[1] + '). Name the files, or use a plain '
                            'find -name/-iname [-type f] [-maxdepth N] -delete on a literal folder.')
        return decision('needs_set', op='delete', set=recursive[1],
                        why='A recursive or find-based delete reaches saves.', **base)
    # Only command text is a command: an MCP tool's flattened strings are documents, and its `command` may be a game console's.
    if isinstance(args, str) or (not tool.startswith('mcp__') and (args.get('command') or args.get('cmd'))):
        written = file_tool_change(text, cwd, tool, base)
        if written:
            return written
    # The never-approvable folder rules above always run. Past them, a command that reaches no save folder and
    # runs no script is not a save change (user ruling 2026-10-30: guard the save folders, not the words).
    if not invoked_scripts(text) and not touches_save_location(text, cwd):
        return outside_save_folders(text, operation(text, tool), base)
    op = operation(text, tool)
    helper = restore_helper_call(text, cwd)
    if helper:
        if helper[0] == 'read':
            return decision('allow')
        if helper[0] == 'bad':
            return decision('deny', reason='Restore helper: use `restore <record-id> [--recycle-extra]`, `show <id>`, `list` or `--dry-run`.')
        record = find_record(helper[1])
        if record is None:
            return decision('deny', reason='Restore helper: no backup record with id ' + helper[1] + ' in the manifest.')
        originals = [record[k]['original'] for k in ('ess', 'skse') if record.get(k)]
        originals += [o for o in record.get('originals', []) if o not in originals]
        return change(originals, originals, 'restore', base)
    paths, problem = paths_in(text, cwd)
    # Known save tools on literally named files: judged by their own documented op list.
    tool_call = re.search(r'(resaver-cli|cosave-cli)\.sh\b\s+(\S+)?', text, re.I)
    if tool_call:
        if tool_call[1].lower() == 'resaver-cli' and (tool_call[2] or '').strip('\'"').lower() not in RESAVER_READ_OPS:
            op = 'write' if op not in WRITE_OPS else op
    # Inspect the source of scripts this command RUNS (not files it merely names, such as
    # `git add x.py`), to catch save changes hidden inside ordinary helpers.
    # The interpreter may be named by full path, quoted or not (C:/.../python.exe script.py).
    # Two passes so the PowerShell call operator (& 'x.ps1') cannot swallow `&& python x.py`
    # or `& "C:/.../python.exe" x.py`.
    invoked = invoked_scripts(text)
    for token in ([] if tool_call else invoked):  # the known save tools are judged by their op list
        raw = next((v for v in token if v), '')
        if Path(raw).name.lower() == 'resaver-native.py':
            return decision('deny', reason='Native candidate requires one exact unchained invocation.')
        if Path(raw).suffix.lower() not in ('.py', '.ps1', '.sh', '.js'):
            continue
        # A relative script is judged where it actually resolves. The hook only sees the session cwd, so a command
        # that does `cd X; python rel/script.py` used to find nothing there and skip the inspection (fail open,
        # found 2026-10-28). Try the session cwd, then every `cd` target in the command, then the install root.
        script_dir = cwd
        script = Path(raw)
        if not script.is_absolute():
            for b in [cwd] + _cd_targets(text) + [str(ROOT)]:
                if (Path(b) / raw).is_file():
                    script_dir = b
                    break
            script = Path(script_dir) / raw
        if script.absolute() == Path(__file__).absolute() and text.rstrip().endswith('--self-test'):
            continue
        if read_only_script_call(script, raw, text, script_dir, tool=tool):
            continue
        if script.name.lower() == RESTORE_HELPER.name.lower():
            # Only its exact unchained form is judged by its record (restore_helper_call); any other use of the
            # restore helper writes into a Saves folder uncounted.
            return decision('needs_set', op='restore', set=None,
                            why='The restore helper writes saves; only its exact `restore <id>` form is counted.', **base)
        try:
            source = script.read_text(encoding='utf-8-sig')
        except (OSError, UnicodeError):
            continue
        code = without_output_text(source)
        if runtime_request(code, need_target=False):
            return decision('needs_set', op='write', set=None,
                            why='An invoked script drives in-game save/load through DevBench.', **base)
        # A script that can write counts when its code spells a save LOCATION, or when this command hands it one.
        # A bare .ess mention in its code does not: native_batch_run.py names `.ess` only to REFUSE touching saves.
        if changes_files(code) and (mentions_save_location(code) or hands_save_location(text, cwd)):
            return decision('needs_set', op=op if op in WRITE_OPS else 'write', set=None,
                            why='An invoked script changes saves the hook cannot count from the command.', **base)
    if not touches_save_location(text, cwd):
        return outside_save_folders(text, op, base)
    violation = listing_violation(text)
    if violation:
        if reader_only(text, op):
            return decision('allow')  # names handed to pure readers: reads are free
        return decision('needs_set', op=op if op in WRITE_OPS else 'write', set=None, why=violation, **base)
    if op not in WRITE_OPS:
        return decision('allow')  # reading, hashing, parsing, listing: free in any number
    # ---- a write-class command from here on
    if op == 'copy' and outward_copy(text, cwd):
        return decision('allow')  # copying saves OUT of their folder: free
    if re.search(r'\b(?:robocopy|xcopy)\b', text, re.I) and (FOLDER.search(text) or EXTENSION.search(text)):
        return decision('needs_set', op=op, set=None, why='robocopy/xcopy into or within a Saves folder changes saves in bulk.', **base)
    form = transfer_form(text, args)
    if form and form.get('newname') and problem:
        # Rename-Item's -NewName is a bare file name in the source's own folder by definition;
        # once the source is a literal absolute path, the target is exact.
        resolved = resolve_transfer(form)
        if resolved is not None and not any(c in s for s in form['sources'] for c in '*?'):
            paths, problem = sorted({p for p in resolved[0] + resolved[1] if is_save(p)}, key=str.casefold), None
    in_saves_cwd = bool(FOLDER.search(cwd.replace('\\', '/') + '/'))
    if problem or (in_saves_cwd and not paths):
        wild = None if (in_saves_cwd and not paths) else wildcard_set(text, op, form)
        return decision('needs_set', op=op, set=wild,
                        why=(problem or 'The shell is inside a Saves folder and the targets are relative.'), **base)
    if form and any(c in s for s in form['sources'] for c in '*?'):
        return decision('needs_set', op=op, set=wildcard_set(text, op, form),
                        why='The command changes saves through a wildcard.', **base)
    if not paths:
        resolved = resolve_transfer(form)
        if resolved is not None and op in ('copy', 'move', 'rename'):
            affected, counted = change_sets(op, resolved, [])
            if affected:
                return change(affected, counted, op, base)
        acting = acting_text(text)
        # A folder known only by its marker or INI has no telltale word: a plain transfer naming it counts, but a script's
        # own string literals do not (a broader test fired on 54 harmless heredocs in the replay).
        if (FOLDER.search(acting) and changes_files(acting)) or (form and _named_folders(acting, cwd, lambda p, wild: in_save_location(p))):
            return decision('needs_set', op=op, set=wildcard_set(text, op, form),
                            why='The command changes a Saves folder without naming each save.', **base)
        if EXTENSION.search(acting) and (READ.search(acting) or MUTATE.search(acting)) \
                and not names_only(text) and not all(save_free_code(s) for s, _ in split_segments(acting)):
            return decision('needs_set', op=op, set=None, why='Save access does not identify every exact file.', **base)
        return decision('allow')
    resolved = resolve_transfer(form)
    if resolved is None and op in ('copy', 'move', 'rename'):
        if form is not None:
            # A plain transfer whose destination is relative or a variable: where it lands
            # (possibly onto a save) cannot be known, so neither can what to back up.
            return decision('needs_set', op=op, set=None,
                            why='The destination is not a literal absolute path.', **base)
        # An unparsed transfer may write into a folder it names without a file name.
        for value, _ in values_of(acting_text(text)):
            value = msys_fix(value.strip())
            if not value or value.startswith('-') or is_save(value) or any(c in value for c in '();=\n'):
                continue  # a save, a flag, or code text (its own quoted strings are separate values)
            absolute = literal_abs(value)
            if FOLDER.search(value.replace('\\', '/') + '/') or (absolute and os.path.isdir(absolute)):
                return decision('needs_set', op=op, set=None,
                                why='The destination is a folder the hook cannot pair with a file name.', **base)
    affected, counted = change_sets(op, resolved, paths)
    return change(sorted(set(affected) | (set(paths) if resolved is None else set())), counted, op, base)


def outward_copy(text, cwd):
    """True only for ONE plain `cp` / `Copy-Item` / `robocopy` whose single literal
    destination lies outside every Saves folder and outside the backup store. Sources may be
    literal, wildcards or whole folders: reading and copying saves out is free."""
    segments = split_segments(text)
    if len(segments) != 1 or re.search(r'[`$%{}<>]', segments[0][0]):
        return False
    words = unquoted_words(segments[0][0])
    if not words:
        return False
    cmd, rest = words[0].lower(), words[1:]
    if cmd == 'cp':
        if any(w.startswith('-') and not re.fullmatch(r'-[pfvrRa]+|--recursive|--archive', w) for w in rest):
            return False  # -t/--target-directory/-u/--remove-destination...: not a plain copy
        args = [w for w in rest if not w.startswith('-')]
        sources, dest = args[:-1], args[-1] if args else None
    elif cmd == 'copy-item':
        sources, dest, i = [], None, 0
        rest = _comma_lists_as_one_word(rest)
        while i < len(rest):
            w, low = rest[i], rest[i].lower()
            if low in ('-path', '-literalpath') and i + 1 < len(rest):
                sources.append(rest[i + 1]); i += 2; continue
            if low == '-destination' and i + 1 < len(rest):
                if dest is not None:
                    return False
                dest = rest[i + 1]; i += 2; continue
            if low in ('-force', '-recurse', '-container', '-verbose'):
                i += 1; continue
            if w.startswith('-'):
                return False  # -Filter, -Include, -PassThru ...: not a plain copy
            if sources and dest is None:
                dest = w
            else:
                sources.append(w)
            i += 1
    elif cmd == 'robocopy':
        plain = [w for w in rest if not w.startswith('/')]
        flags = [w.lower() for w in rest if w.startswith('/')]
        if len(plain) < 2 or any(re.match(r'/(?:mov|move|mir|purge|create|a-|a\+|it|im|is|xx)(?::|$)', f) for f in flags):
            return False
        sources, dest = [plain[0]], plain[1]
    else:
        return False
    if not dest or not sources:
        return False
    dest = msys_fix(dest)
    if not is_abs(dest):
        return False  # a relative destination is resolved against a cwd we cannot trust
    normed = norm(dest)
    if FOLDER.search(normed.replace('\\', '/') + '/') or in_save_location(normed) or under(normed, BACKUP_ROOT):
        return False  # into a save folder (creates/overwrites a save) or onto backups
    for s in sources:
        s = msys_fix(s)
        if not is_abs(s) or any(c in s for c in '[]'):
            return False
    return True


# ----------------------------------------------------------------- approvals

def user_messages(transcript):
    """Text the user actually typed this session. Skill text, hook output, injected
    instruction files and tool results are excluded: an agent can influence those."""
    with open(transcript, encoding='utf-8') as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get('type') == 'response_item':  # Codex
                msg = row.get('payload', {})
                if msg.get('role') != 'user':
                    continue
                content = msg.get('content', '')
                text = content if isinstance(content, str) else '\n'.join(
                    x.get('text', '') for x in content if isinstance(x, dict))
                if text.lstrip().startswith(('<', '# AGENTS.md')):
                    continue  # environment, instruction-file and queue envelopes
                yield text
                continue
            attachment = row.get('attachment')
            if row.get('type') == 'attachment' and isinstance(attachment, dict):
                if attachment.get('type') == 'queued_command' and (attachment.get('origin') or {}).get('kind') == 'human' \
                        and attachment.get('commandMode', 'prompt') == 'prompt' and isinstance(attachment.get('prompt'), str):
                    yield attachment['prompt']
                continue
            msg = row.get('message') or {}
            if msg.get('role') != 'user' or row.get('isMeta'):
                continue
            # Typed prompts carry origin.kind == 'human'; tool-result rows carry no origin at all.
            if (row.get('origin') or {}).get('kind') != 'human':
                continue
            content = msg.get('content', '')
            if isinstance(content, str):
                yield content
            else:
                yield '\n'.join(x.get('text', '') for x in content if isinstance(x, dict) and x.get('type', 'text') == 'text')


def approvals(payload):
    """Every approval object the user typed this session ([] when unreadable)."""
    transcript = payload.get('transcript_path')
    if not isinstance(transcript, str) or not transcript or EXTENSION.search(transcript):
        return []
    found = []
    try:
        for message in user_messages(transcript):
            for match in re.finditer(r'^SAVE_ACCESS_APPROVAL\s+(\{[^\n]+\})\s*$', message, re.M):
                try:
                    obj = json.loads(match[1])
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    found.append(obj)
    except (OSError, ValueError):
        return []
    return found


def files_granted(payload, paths, op):
    grants = set()
    for obj in approvals(payload):
        try:
            for item in obj.get('files', []):
                grants.add((os.path.normcase(os.path.normpath(item['path'])), item['operation']))
        except (KeyError, TypeError, AttributeError):
            continue
    return all((os.path.normcase(p), op) in grants for p in paths)


def set_grants(payload, digest, op):
    out = []
    for obj in approvals(payload):
        sets = obj.get('set')
        for item in (sets if isinstance(sets, list) else [sets]):
            if isinstance(item, dict) and str(item.get('command_sha256', '')).lower() == digest \
                    and item.get('operation') == op and isinstance(item.get('count'), int):
                out.append(item)
    return out


def declared_set(item):
    """Save files in a user-declared folder/pattern set, or None when it is not usable."""
    folder, pattern = item.get('folder'), item.get('pattern')
    if not isinstance(folder, str) or not isinstance(pattern, str) or not pattern:
        return None
    folder = msys_fix(folder)
    if not is_abs(folder) or not os.path.isdir(folder) or re.search(r'[/\\]', pattern):
        return None
    with os.scandir(folder) as entries:
        return sorted(norm(os.path.join(folder, e.name)) for e in entries
                      if not e.is_dir() and is_save(e.name) and fnmatch(e.name.lower(), pattern.lower()))


# ----------------------------------------------------------------- backup store

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def manifest_records(root=None):
    path = Path(root or BACKUP_ROOT) / 'manifest.jsonl'
    if not path.is_file():
        return []
    out = []
    with open(path, encoding='utf-8') as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                out.append(row)
    return out


def find_record(record_id):
    for row in manifest_records():
        if row.get('id') == record_id:
            return row
    return None


def append_manifest(root, rows):
    lines = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows)
    lock = open(root / 'manifest.lock', 'a+b')
    try:
        try:
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)  # retries ~10 s, then raises
            locked = True
        except ImportError:
            locked = False
        with open(root / 'manifest.jsonl', 'a', encoding='utf-8') as stream:
            stream.write(lines)
            stream.flush()
            os.fsync(stream.fileno())
        if locked:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    finally:
        lock.close()


def backup_pairs(paths, op, tool, command, approval, deadline=None):
    """Copy both files of every save pair among paths into the store, verify each copy by
    SHA-256 and append one manifest record per pair. Raises BackupError on any failure."""
    deadline = deadline or (time.monotonic() + TIME_BUDGET)
    root = Path(BACKUP_ROOT)
    pairs = list(stems(paths).values())
    if not pairs:
        return []
    try:
        root.mkdir(parents=True, exist_ok=True)
        if not root.is_dir():
            raise BackupError(f'backup store {root} is not a folder')
        files = []
        for ess, skse, _ in pairs:
            for p in (ess, skse):
                if os.path.lexists(p):
                    if not os.path.isfile(p):
                        raise BackupError(f'{p} exists but is not a regular file')
                    files.append(p)
        # Metadata narrows the candidates; it never establishes byte identity.
        index = {}
        for row in manifest_records(root):
            for k in ('ess', 'skse'):
                e = row.get(k)
                if isinstance(e, dict) and 'original' in e:
                    index[(os.path.normcase(e['original']), e.get('size'), e.get('mtime_ns'))] = e
        need = sum(os.path.getsize(p) for p in files)
        if shutil.disk_usage(root).free < need + FREE_SPACE_MARGIN:
            raise BackupError(f'not enough free space for {need} bytes of save backups')
        now = datetime.datetime.now()
        op_id = now.strftime('%Y%m%d-%H%M%S-') + secrets.token_hex(3)
        op_dir = root / now.strftime('%Y-%m-%d') / op_id
        rows = []
        for i, (ess, skse, key) in enumerate(pairs):
            row = {'id': f'{op_id}-{i}', 'time': now.isoformat(timespec='seconds'), 'tool': tool,
                   'operation': op, 'approval': approval, 'command': command[:4000],
                   'originals': [ess, skse], 'ess': None, 'skse': None}
            for kind, src in (('ess', ess), ('skse', skse)):
                if time.monotonic() > deadline:
                    raise BackupError('backup did not finish inside the hook time limit; completed copies are '
                                      'reused, so re-running the same command continues the backup')
                if not os.path.lexists(src):
                    continue
                st = os.stat(src)
                prior = index.get((os.path.normcase(src), st.st_size, st.st_mtime_ns))
                before = sha256(src)
                if (prior and os.path.isfile(prior.get('backup', ''))
                        and os.path.getsize(prior['backup']) == st.st_size
                        and prior.get('sha256') == before and sha256(prior['backup']) == before):
                    row[kind] = dict(prior, reused=True)
                    continue
                dest = op_dir / str(i) / os.path.basename(src)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                after = sha256(dest)
                st2 = os.stat(src)
                if before != after or (st2.st_size, st2.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                    raise BackupError(f'verification failed for {src} (hash mismatch or the file changed during the copy)')
                row[kind] = {'original': src, 'backup': str(dest), 'sha256': before, 'size': st.st_size,
                             'mtime_ns': st.st_mtime_ns}
            if row['ess'] and not row['skse']:
                row['note'] = 'co-save missing'
            elif row['skse'] and not row['ess']:
                row['note'] = '.ess missing'
            elif not row['ess'] and not row['skse']:
                row['note'] = 'no file existed (nothing to back up)'
            rows.append(row)
        # Verify the complete pair after both copies, including reused copies.
        # Also reject a counterpart that appeared while the pair was copied.
        for row in rows:
            for kind, src in zip(('ess', 'skse'), row['originals']):
                if time.monotonic() > deadline:
                    raise BackupError('backup verification exceeded the hook time limit')
                item = row[kind]
                if item is None:
                    if os.path.lexists(src):
                        raise BackupError('previously missing pair member appeared during backup: ' + src)
                    continue
                if sha256(src) != item['sha256'] or sha256(item['backup']) != item['sha256']:
                    raise BackupError('final pair hash verification failed for ' + src)
        append_manifest(root, rows)
        return rows
    except BackupError:
        raise
    except Exception as exc:  # disk full, permissions, unreadable save ...
        raise BackupError(f'{type(exc).__name__}: {exc}') from exc


# ----------------------------------------------------------------- run

def run(payload):
    d = decide(payload)
    kind = d['kind']
    if kind == 'deny':
        return d['reason']
    if kind == 'allow':
        return None
    approval = 'none'
    targets = d.get('affected', [])
    if kind == 'needs_files':
        if not files_granted(payload, d['affected'], d['op']):
            grant = {'files': [{'path': p, 'operation': d['op']} for p in d['affected']]}
            return ('SAVE CHANGE NEEDS APPROVAL: ' + d['op'] + f' changes {d["count"]} saves (more than 2). '
                    'Each save pair is backed up first once approved. The agent must not create an approval '
                    'itself. If the user agrees, they type this line (valid for these files and this operation '
                    'for the rest of the session):\nSAVE_ACCESS_APPROVAL ' + json.dumps(grant, ensure_ascii=False))
        approval = 'files'
    elif kind == 'needs_set':
        grants = set_grants(payload, d['hash'], d['op'])
        computed = d.get('set')
        if computed is not None:
            n = len(stems(computed))
            if not any(g['count'] == n for g in grants):
                listing = '\n'.join('  ' + p for p in computed[:12]) + ('\n  ...' if len(computed) > 12 else '')
                line = {'set': {'command_sha256': d['hash'], 'operation': d['op'], 'count': n}}
                return ('SAVE CHANGE NEEDS APPROVAL: ' + d['why'] + f' This command would {d["op"]} {n} save(s) '
                        'right now' + (':\n' + listing if computed else '.') + '\nThey are backed up first once '
                        'approved. The agent must not create an approval itself. If the user agrees, they type '
                        'this line (it covers this exact command and count only):\nSAVE_ACCESS_APPROVAL '
                        + json.dumps(line, ensure_ascii=False))
            targets = computed
        else:
            usable = []
            for g in grants:
                files = declared_set(g)
                if files is not None and len(stems(files)) == g['count']:
                    usable.append(files)
            if not usable:
                line = {'set': {'command_sha256': d['hash'], 'operation': d['op'], 'folder': '<absolute folder>',
                                'pattern': '<file pattern, e.g. Autosave*>', 'count': '<number of saves matching now>'}}
                return ('SAVE CHANGE NEEDS APPROVAL: ' + d['why'] + ' The hook cannot tell exactly which saves this '
                        'command changes. Prefer naming each save with a literal absolute path (1-2 saves need no '
                        'approval, only a backup). Otherwise the user approves THIS exact command and names the set '
                        'that is backed up first; the count must match the folder at run time. The agent must not '
                        'create an approval itself. Line for the user to complete and type:\nSAVE_ACCESS_APPROVAL '
                        + json.dumps(line, ensure_ascii=False))
            targets = sorted({p for files in usable for p in files}, key=str.casefold)
        approval = 'set'
    try:
        backup_pairs(targets, d['op'], d.get('tool', ''), d.get('command', ''), approval)
    except BackupError as exc:
        return ('SAVE CHANGE BLOCKED: the pre-change backup failed, so nothing may change: ' + str(exc)
                + '. Backups go to ' + str(BACKUP_ROOT) + '. Fix the cause and retry; do not bypass the guard.')
    return None


def main():
    if sys.argv[1:] == ['--self-test']:
        import unittest
        class GuardChecks(unittest.TestCase):
            def test_blocked_operations(self):
                for command in ["Move-Item 'C:/profile/Saves' 'C:/archive'", "Remove-Item 'C:/profile/Saves' -Recurse",
                                "python -c \"import shutil; shutil.move('C:/profile/Saves','C:/archive')\"",
                                "Remove-Item 'C:/profile/Saves/*.ess'", "powershell -File isolate.ps1 -Action restore"]:
                    with self.subTest(command=command):
                        self.assertIsNotNone(run({'tool_name': 'Bash', 'tool_input': {'command': command}}))
            def test_ordinary_files_and_documentation_patch(self):
                self.assertIsNone(run({'tool_name':'Bash','tool_input':{'command':"Get-Content CLAUDE.md"}}))
                self.assertIsNone(run({'tool_name':'apply_patch','tool_input':{'command':'*** Begin Patch\n*** Update File: AGENTS.md\n+Do not touch .ess or .skse\n*** End Patch'}}))
            def test_missing_payload(self):
                self.assertIsNotNone(run({}))
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(GuardChecks))
        return 0 if result.wasSuccessful() else 1
    try:
        payload = json.load(sys.stdin)
        reason = run(payload)
    except Exception:
        reason = 'SAVE ACCESS BLOCKED: malformed input or guard evaluation failure.'
    if reason:
        print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': reason}}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
