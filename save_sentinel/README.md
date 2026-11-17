# save-sentinel packet (2026-11-11)

The install's PostToolUse save sentinel with one change: agent test saves named `ShinsoObserver_Headless_*` are never
auto-locked (user ruling 2026-11-10). A locked test copy needed an elevated unlock before every next test run. The
sentinel still reports changes to them, and the save vault keeps every version. The exemption is a constant in the
hook file, not a key in the locked `save-lock.json`, so widening it is a reviewed hook change.

Not changed: saves that are already locked stay locked until the user unlocks them, and a manual
`save_lock.py lock` / `on` still locks test saves.

Save locks are Windows/NTFS only, so CI runs this packet on the Windows leg.

## 2026-11-17: SSSO rotating autosave slots

Skyrim Save System Overhaul's timed autosaves overwrite ten slots named `SaveN_<id>_<n>_<hexname>_AutoRotate_<slot>_...` in place, like Autosave/Quicksave. A locked slot made every new autosave fail silently and leave only an `.ess.tmp`. The sentinel no longer auto-locks those slots (`SSSO_ROTATION`); look-alike names still lock. Already-locked slots need the user's elevated unlock.
