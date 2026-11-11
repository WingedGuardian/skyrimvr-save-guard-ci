# protect-bash packet (2026-11-11)

The install's `protect-bash.sh` PreToolUse hook with its delete rule replaced. The old rule refused any command
that named a delete program and mentioned the install anywhere in its text. The new rule
(`protect-bash-deletes.py`) judges a delete by the operands it is handed, resolved: it refuses a delete of the
game root, its Data folder, the config folder, a Saves folder, a backup store, any folder holding one of these,
or anything inside the save vault. It is a simple best-effort rule; its docstring lists the known gaps.

- `protect-bash.sh`, `protect-bash-deletes.py`: the two files that are deployed, byte for byte.
- `test_protect_bash_deletes.py`: the rule's decisions. `test_protect_bash_shell.py`: the hook run as a process
  against a fake game root. No command in any payload is executed.
- `mutate.py`: one mutant per clause; each must turn the decision tests red. Runs on Windows, the OS the hook is
  deployed on: PowerShell commands with backslash paths are Windows spellings and are skipped on other systems.
- `MANIFEST.sha256` / `verify_manifest.py`: the packet bytes CI ran on.

## Codex (added 2026-11-11)

`codex-hooks.json` is the install's `.codex/hooks.json`. Measured on codex-cli 0.167.1 (Windows): a Codex payload has
tool_name "Bash" and PowerShell text, so the registration passes the word `codex` and the delete check reads the
command as PowerShell. Known limits: a hook that fails to start is an ALLOW in Codex (so Git Bash is named by absolute
path and the deploy is proven with a real Codex canary); if Codex is ever set to run Git Bash, commands are still read
as PowerShell; `apply_patch` is not checked (patch text is not a command), so a `*** Delete File:` inside the save
vault is not refused by this hook; Codex must be told to trust the hook once (`/hooks`).

## Save-vault watcher alert (added 2026-11-11)

`claude-sessionstart-hook.json` (one entry added to the install's `.claude/settings.json` SessionStart list) and the
SessionStart group in `codex-hooks.json` run the pinned save vault's own `status` command at session start. It reads
one small heartbeat file per vault and prints `save vault: running (...)` or `save vault: NOT RUNNING (...)`. `status`
exits 1 when the watcher is down and a failed SessionStart hook's output is dropped, so each command ends by exiting
0 in its host's shell. Measured with an empty vault folder: a Claude session and a codex-cli 0.167.1 session both
received the NOT RUNNING line. No hook code is added.
