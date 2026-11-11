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
