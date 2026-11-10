Reviewed read-only exemption for the gateway engine parent's `controller.py freeze` -- ISOLATED, UNQUALIFIED SOURCE

The qualified deployed baseline is readonly_classifier_guard/candidate.py, SHA256
1f8dc45eab46fc99f3b90ee34b9e3570266f3e38003ec449781ace17141ea00e, deployed to the
game root 2026-11-10 09:29 -05:00 (DEPLOY.json, from 4d56a70). No game-root hook or
registration is edited by this packet.

Observed refusal (gateway handoff HANDOFF-GUARD-METADATA-FREEZE.md, hash 6dbc55f8d488a55d)
PreToolUse refused the gateway's source-freeze command with "An invoked script changes
saves the hook cannot count from the command." Diagnosis from the deployed source: the
invoked script (engine_parent/controller.py) is not in READ_ONLY_SCRIPT_VERBS or
REVIEWED_NON_SAVE_LIFECYCLE, it writes files (run metadata) and its code spells the save
folder (it hashes the source pair and checks the destination pair is absent), so the
"invoked script changes_files + mentions_save_location" branch asked for an uncountable
set. The freeze branch itself changes zero saves: it writes frozen hashes, a publication
plan with application disabled, a controlled-profile plan and a pair REQUEST under the
task folder. Pair creation and loading are separate direct calls to the qualified
tools/resaver-native-runtime.py, which stay fully guarded. The classifier worked as
designed; the operation needed the existing reviewed-script route, not a new rule.

Scope (user ruling 2026-11-10: option A, small pin)
One READ_ONLY_SCRIPT_VERBS entry: the controller by exact SHA256 with verbs {freeze} and
four dependencies by exact SHA256: native_run.py, controlled_profile.py,
goal_launch_authority.py and the staged install-native.py (the code the freeze path calls
into). The full measured import closure is 34 modules at import time and more through
lazy imports; pinning all of it would revoke the exemption on every product edit, so the
pin follows the native_batch_run.py precedent (script + direct helpers). project-pins.json
records the five hashes; the Scope test proves each appears exactly once in the candidate.
Every other controller verb (prepare, publish, profile, preflight, run, menu-ready,
loaded, stop, restore), a composed command with another verb, an argument naming a save
or Saves folder, a changed script or dependency, a dependency outside the root, and a
same-named script elsewhere all stay under ordinary inspection (test_candidate.py).

What this is not
Not a general read-only Python exemption, not a launch/load consent, not an unpin of any
other rule. The native_batch_run.py entries above it are already dead (their pinned
native_run.py changed from 62176cb1... to 9f269bdb...); they are left untouched, which
is the fail-closed behaviour this entry will show too when any of its five files changes.
A later freeze after product edits needs a new reviewed pin.

Tests and review gates
Expected outcomes are frozen in test_candidate.py before candidate execution. The baseline
must reproduce two methods / three failing assertions (the Pins check and the exact refused
command on the Bash and PowerShell tool labels); the candidate must pass all 11 methods and
the retained read-only 20, inert 16, native-adapter 12 and gateway policy/wrapper/sentinel
checks. The five real pinned files are NOT in this public repository: CI proves the
mechanism on authored stand-ins and that the entry carries exactly the reviewed hashes; the
deploy step proves the real bytes with a live decision-only probe of the exact refused
command (expected: allow) and of `controller.py prepare` (expected: needs approval), plus
the SAVE_GUARD_DENY_CANARY and hook-canary.

Local run
Running test_candidate.py on the install is expected to be refused by the installed guard
(its source spells save locations and deletes, by design of the controls). Results come
from CI on the exact head; no alternative local runner is used.

Limits
A freeze argument naming a configured save folder whose path lacks the word Saves passes
_read_only_tail's spelling check; that is pre-existing behaviour of every exempt script
and every real save folder on this install contains the word. The entry trusts the five
pinned files' bytes; it does not analyse what they do, which is why it is small and
explicit. No native, package or save-operation acceptance follows from this packet.

Workflow pin
readonly_classifier_guard/payload-manifest.json pins .github/workflows/qualify.yml; adding this
packet's CI step changes that file, so that one supporting-input hash is updated to the new
workflow bytes (nothing else in that packet changes; its candidate stays 1f8dc45e).

Deployment gate
Independent review and green CI on the exact commit, then deploy with a backup folder and
DEPLOY.json under .claude/backups/hook-deploys/, as on 2026-11-10 09:29. The game-root
guard stays unchanged until then.
