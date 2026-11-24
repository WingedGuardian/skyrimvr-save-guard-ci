# no-detached-launch (PreToolUse guard, new 2026-11-24)

Refuses an agent tool call that would launch a process with Windows `DETACHED_PROCESS` (`0x00000008`): the pattern
that produces console pop-up SPAM. Deliberately visible terminal work (`CREATE_NEW_CONSOLE`, `Start-Process`, a
terminal the user opens) is not refused (user, 2026-11-24: "im not trying to prohibit visible terminal work
altogether. just whatever you do that specifically causes that spam").

## Why

The install's standing rule: helpers never pop up console windows. MEASURED 2026-11-24 on the install machine with a
passive window logger (EnumWindows, no child processes):

| parent launched with | child runs `powershell.exe` without flags | window on the user's desktop |
|---|---|---|
| `CREATE_NO_WINDOW` | yes | none |
| `CREATE_NO_WINDOW \| NEW_PROCESS_GROUP \| DETACHED_PROCESS` | yes | **Windows Terminal window** |
| same, child powershell with `CREATE_NO_WINDOW` | yes | none |

A detached process has no console, so each console program it starts without `CREATE_NO_WINDOW` gets a new visible
one. An agent's test driver launched the headless game tool detached; that tool reads processes through PowerShell
once a second, and the user got a pop-up every second for a whole run. `CREATE_NO_WINDOW` alone gives a hidden
console that children inherit, and the launched process still outlives the caller (measured), so detaching is never
needed. The install-side tool fix (every PowerShell read started hidden) ships separately; this guard stops the next
launcher from reintroducing the detached form.

## Rule

- **Code files** (`CODE_FILES`) written with `Write`, `Edit`, `MultiEdit`, `NotebookEdit`. An Edit is judged on the
  file AFTER the edit, statement by statement around the changed text, so appending `| 0x8` to an existing
  `creationflags` line is seen; an unreadable file falls back to the new text. Notes and docs (`.md`, `.txt`,
  `.json`, ...) may describe the flag; the packet's own files under `no_detached_launch/` stay editable.
- **Shell commands** (`Bash`, `PowerShell`, `Monitor`) and shell script files (`.sh`, `.ps1`, `.bat`, ...): only
  text that runs or is written as code: `-c`/`-e`/`-Command` and `/c` bodies that belong to the interpreter or shell
  directly before them (its own options only in between; nested up to 3 levels), heredoc and PowerShell here-string bodies
  fed to an interpreter or written to a code file, quoted arguments within the `;`/`&&`/`||`-separated part of the command that
  writes a code file, and the unquoted command.
  Commit messages and search patterns are quoted arguments and are not judged.
- Per logical statement (bracketed, `|`- and `\`-continued lines joined, at most 50 lines; comments, block comments,
  docstrings and string contents blanked to the same length, Python via its own tokenizer on the whole file before
  the edit window is cut; `#` comments for Python/shell/PowerShell, `//` and quote-aware `/* */` for C-family/JS):
  `DETACHED_PROCESS` used as a flag (`creationflags`, `Popen`, `CreateProcess`, `spawn`, `|`, `|=`, assignment) and
  not negated with `~`; a `creationflags` value holding an integer literal with bit 0x8; Node `detached: true` (libuv sets `DETACHED_PROCESS` on Windows).
- Unreadable input fails open. The refusal is a JSON deny. Every parsed payload writes a heartbeat
  (`.claude/backups/.hook-heartbeat/no-detached-launch`) for `tools/hook-canary.sh`, so a hook that stops firing is
  visible.

Out of scope (documented, not caught): a flag constant renamed through data flow; code generated inside Python
string literals (string contents are blanked to avoid prose false positives); helpers started via `pythonw` or a
`.pyw` (also console-less); PowerShell `Start-Process` without `-WindowStyle Hidden`. Codex is registered for its
`Bash` tool only; edits Codex makes through `apply_patch` are not checked.

## Evidence of price (local, transcripts not in this repo)

`replay_history.py` over every recorded Claude Code tool call on the install machine (172,128 calls): 7 refused,
all genuine (the 7th is the 2026-11-24 deploy probe) detached launches (the incident, its edit, an earlier BELOW_NORMAL | GROUP | 0x8 launcher, and two named
`DETACHED_PROCESS` flag builds). No false positive remains. Four rounds of independent review (91f784c, 9922f7d, 86d482f, 2f2d16c) found: a minimal Edit adding the flag unseen, the
docstring offset shift breaking that fix, multi-line / `|=` / dict-key / Node spellings, code written through quoted
shell text or PowerShell here-strings, nested `bash -c` / `cmd /c`, `replace_all`, CRLF files, MultiEdit order, and
false positives on commit messages, searches, docstrings and strings; then (round 3) tokenizing after the edit
window is cut, `-c`/`-e` of a later command taken as a script, 3.12 f-string tokens, whole-command write scope,
quote-blind `/* */`, and MultiEdit span shifts after a multi-site `replace_all`; (round 4) quoted code with a
line break written to a file, and interpreter options with a value (`-X utf8`, `-ExecutionPolicy Bypass`) or
combined flags (`bash -lc`). Known, not fixed (LOW): an Edit to a shell script judges its whole 400-line window,
so a script that already holds a bad launch can refuse an unrelated edit nearby. All are now cases in the tests.
CI on the Windows runner also showed `pytest <tempdir>` collecting nothing, which the earlier mutant gate had
counted as kills; the gate now requires a green baseline and runs pytest inside the temp folder.

## Files

- `no-detached-launch.py`: the hook. `test_no_detached_launch.py`: 124 cases through the hook as a process
  (`HOOK_PYTHON="py -3.12"` runs the hook under another interpreter than pytest).
- `mutate.py`: 66 mutants, one per clause (the f-string one only where the hook Python has f-string tokens, 3.12+);
  the unmodified hook must pass first, and a kill must be a failing test. CI runs Python 3.10, 3.12 and 3.13 on
  Ubuntu and Windows, because the registration's `py -3` picks the newest installed 3.x (3.12 on the install).
- `claude-pretooluse-hook.json`, `codex-pretooluse-hook.json`: the registration entries added on deploy (`py -3`,
  standard library only).
- `replay_history.py`: the price check above. `MANIFEST.sha256` + `verify_manifest.py`: every packet file pinned;
  an unlisted file fails the check.
