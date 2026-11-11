# save-sentinel packet (2026-11-11)

The install's PostToolUse save sentinel with one change: agent test saves named `ShinsoObserver_Headless_*` are never
auto-locked (user ruling 2026-11-10). A locked test copy needed an elevated unlock before every next test run. The
sentinel still reports changes to them, and the save vault keeps every version. The exemption is a constant in the
hook file, not a key in the locked `save-lock.json`, so widening it is a reviewed hook change.

Not changed: saves that are already locked stay locked until the user unlocks them, and a manual
`save_lock.py lock` / `on` still locks test saves.

Save locks are Windows/NTFS only, so CI runs this packet on the Windows leg.
