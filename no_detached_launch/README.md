# no-detached-launch (PreToolUse guard, new 2026-11-24)

Refuses an agent tool call that would launch a process with Windows `DETACHED_PROCESS` (`0x00000008`).

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

Checked: shell commands (`Bash`, `PowerShell`, `Monitor`) and text written to CODE files (`Write` content,
`Edit`/`MultiEdit` new_string, `NotebookEdit` new_source; extensions in `CODE_FILES`). Refused when, outside a
comment, a line uses `DETACHED_PROCESS` as a launch flag (with `creationflags`, `Popen`, `CreateProcess`, or OR-ed
with `|`), or a `creationflags` expression holds an integer literal with the 0x8 bit set. Notes and docs (`.md`,
`.txt`, `.json`, ...) may describe the flag; the packet's own files under `no_detached_launch/` stay editable.
Unreadable input fails open. The refusal is a JSON deny (Claude Code and Codex both honour it).

## Evidence of price (local, transcripts not in this repo)

`replay_history.py` over every recorded Claude Code tool call on the install machine (161,294 calls): 9 refused.
7 are genuine detached launches (including the incident), 2 are false positives: a `grep` whose pattern lists
`creationflags\|DETACHED_PROCESS`, and a shell edit of this hook's own source. An earlier, broader draft refused 22
(prose and docstrings); `CODE_FILES` and the use-context rule removed those.

## Files

- `no-detached-launch.py`: the hook. `test_no_detached_launch.py`: 28 cases through the hook as a process.
- `mutate.py`: 18 mutants, one per clause; CI fails unless every one is killed.
- `claude-pretooluse-hook.json`, `codex-pretooluse-hook.json`: the registration entries added on deploy.
- `MANIFEST.sha256` + `verify_manifest.py`: packet bytes pinned.
