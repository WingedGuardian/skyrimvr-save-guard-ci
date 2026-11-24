# no-detached-launch (PreToolUse guard, new 2026-11-24)

Refuses an agent tool call that would launch a process with Windows `DETACHED_PROCESS` (`0x00000008`), or into a
new VISIBLE console (`CREATE_NEW_CONSOLE`, `0x10`, without a `startupinfo`).

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
- **Shell commands** (`Bash`, `PowerShell`, `Monitor`): only text that runs as code: `-c`/`-e`/`-Command` scripts
  after an interpreter, heredoc bodies fed to an interpreter or written to a code file, and the unquoted command.
  Commit messages and search patterns are quoted arguments and are not judged.
- Per logical statement (bracketed and `|`-continued lines joined; comments, docstrings and quoted prose dropped):
  `DETACHED_PROCESS` / `CREATE_NEW_CONSOLE` used as a flag (`creationflags`, `Popen`, `CreateProcess`, `spawn`, `|`,
  `|=`, assignment) and not negated with `~`; a `creationflags` value holding an integer literal with bit 0x8, or
  0x10 without `startupinfo`; Node `detached: true` (libuv sets `DETACHED_PROCESS` on Windows).
- Unreadable input fails open. The refusal is a JSON deny. Every parsed payload writes a heartbeat
  (`.claude/backups/.hook-heartbeat/no-detached-launch`) for `tools/hook-canary.sh`, so a hook that stops firing is
  visible.

Out of scope (documented, not caught): a flag constant renamed through data flow; helpers started via `pythonw` or a
`.pyw` (also console-less); PowerShell `Start-Process` without `-WindowStyle Hidden`. Codex is registered for its
`Bash` tool only; edits Codex makes through `apply_patch` are not checked.

## Evidence of price (local, transcripts not in this repo)

`replay_history.py` over every recorded Claude Code tool call on the install machine (171,788 calls): 7 refused,
all genuine: 5 detached launches (including the incident and its edit), 2 named `DETACHED_PROCESS` flag builds.
No false positive remains. An independent review of the first draft found that a minimal Edit could add the flag
unseen, that multi-line and `|=` spellings were missed, and that commit messages and searches would be refused; all
are now cases in the tests.

## Files

- `no-detached-launch.py`: the hook. `test_no_detached_launch.py`: 73 cases through the hook as a process.
- `mutate.py`: 45 mutants, one per clause; the unmodified hook must pass first, and a kill must be a failing test.
- `claude-pretooluse-hook.json`, `codex-pretooluse-hook.json`: the registration entries added on deploy (`py -3`,
  standard library only).
- `replay_history.py`: the price check above. `MANIFEST.sha256` + `verify_manifest.py`: every packet file pinned;
  an unlisted file fails the check.
