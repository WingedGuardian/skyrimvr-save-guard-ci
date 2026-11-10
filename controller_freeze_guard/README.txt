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
set. The freeze branch changes zero saves: it writes seven JSON files with exclusive create
under the task folder (frozen hashes, a publication plan with application disabled, a
controlled-profile plan, a pair REQUEST). Pair creation and loading are separate direct
calls to the qualified tools/resaver-native-runtime.py, which stay fully guarded. The
classifier worked as designed; the operation needed the existing reviewed-script route.
Decision-only probe of the deployed guard against the real install reproduces the refusal
on the exact command; the candidate admits it and refuses prepare/loaded/run and the
composed freeze+prepare (7 cases, 0 mismatches).

Scope (user ruling 2026-11-10: option A, small pin; widened once by review)
One READ_ONLY_SCRIPT_VERBS entry: the controller by exact SHA256 with verbs {freeze} and
ten dependencies by exact SHA256: the four modules the freeze path calls into (native_run,
controlled_profile, goal_launch_authority, the staged install-native) and, after the
independent review, the six support modules that do its writes (gateway_test_support/io),
its preservation reads (reference_adapter, reference_preservation, context) and its
cold-state check (session, tools/vr-headless.py). The full import closure is 34 modules at
import time and more through lazy imports; pinning all of it would revoke the exemption on
every product edit, so the pin follows the native_batch_run.py precedent (script + the
helpers that can act). project-pins.json records the eleven hashes; the Scope test proves
each appears exactly once in the candidate.

One rule change in read_only_script_call (review finding, HIGH): a RELATIVE script token in
a command that changes directory (cd, chdir, Set-Location, sl, pushd, Push-Location) is
never exempt. The hook resolved the token against the session cwd first, the shell runs it
from the cd target, so an unpinned copy at the target would have run under the pinned
copy's exemption. The pre-existing gap applied to every exempt script; this entry would
have widened it. Ordinary inspection still runs on such a command.

Every other controller verb (prepare, publish, profile, preflight, run, menu-ready,
loaded, stop, restore), a composed command with another verb, an argument naming a save
or Saves folder, a changed script or dependency, a dependency outside the root, a
same-named script elsewhere and the cd shapes all stay under ordinary inspection
(test_candidate.py).

What this is not
Not a general read-only Python exemption, not a launch/load consent, not an unpin of any
other rule. The native_batch_run.py entries above it are already dead (their pinned
native_run.py changed from 62176cb1... to 9f269bdb...); they are left untouched, which is
the fail-closed behaviour this entry will show too when any of its eleven files changes.
A later freeze after product edits needs a new reviewed pin.

Tests and review gates
Expected outcomes are frozen in test_candidate.py before candidate execution. The test
registry is the guard's OWN entry re-pinned to authored stand-ins; the baseline has no entry
and admits nothing (the first draft patched an authored entry into both guards, which the
review caught: the baseline could not go red for the right reason, and Ubuntu CI 42842426652
failed at that gate). The baseline must reproduce two methods / three failing assertions
(the Pins check and the exact refused command on the Bash and PowerShell tool labels); the
candidate must pass all 12 methods and the retained read-only 20, inert 16, native-adapter
12 and gateway policy/wrapper/sentinel checks. The eleven real pinned files are NOT in this
public repository: CI proves the mechanism on authored stand-ins and that the entry carries
exactly the reviewed hashes; the deploy step proves the real bytes with a live decision-only
probe (expected: the refused command allowed; prepare, loaded, run and freeze+prepare
refused), plus SAVE_GUARD_DENY_CANARY and hook-canary.

Independent review 2026-11-10 (read-only agent; Read/Grep/Glob only)
Six findings. 1 BLOCKING test design (fixed as above). 2 HIGH cd/relative bypass (rule
added, contrast test added). 3 MEDIUM pins missed the write-path modules and the README
overstated them (six pins added, text corrected). 4 MEDIUM-LOW cached bytecode not pinned
(recorded as a limit, below). 5 LOW tool label/payload shape (Bash and PowerShell are both
SHELL_TOOLS; Codex reports canonical Bash; recorded). 6 INFO: the here-string half of the
refused command is admitted only because it spells no save location; its code
(sampling_entry, write_new) is the gateway's own reviewed source, not guard-admitted.

Follow-up review of v2 (same reviewer): v2 fixes confirmed; the Scope pin-count check tripped
on tools/vr-headless.py, whose hash already sits in two older entries (now: exactly one NEW
occurrence per pin, counted against the baseline); the cd rule missed a directory change
written inside a quoted inner command (`bash -c 'cd ..'`, `pwsh -Command "cd .."`, `& {cd ..}`)
and the wordless forms `env -C/--chdir` (rule widened to any non-word neighbour plus those
forms; contrasts added). `Start-Process -WorkingDirectory` is not modeled: the hook does not
recognise a script token inside -ArgumentList, so that shape is judged by the ordinary rules
only. v3 also re-pins controller.py after a gateway-owned change to its launch-approval
validation (a recorded per-launch user answer for Claude-owned runs; freeze() untouched).

Local run
Running test_candidate.py on the install is expected to be refused by the installed guard
(its source spells save locations and deletes, by design of the controls). Results come
from CI on the exact head; no alternative local runner is used.

Limits
Cached bytecode of pinned modules (__pycache__/*.cpython-310.pyc) is not pinned; -B stops
writing, not reading. Pre-existing for every exempt script; the inert fixture packet pins
caches for its own entry. gateway_test_support/qualification.py (consumed-host pins,
read-only by construction) is deliberately not pinned: it must change to admit the newly
deployed guard, and pinning it here would be circular. The non-sampling campaign branch
modules are not pinned: the sampling extra-inputs select the sampling branch. A freeze
argument naming a configured save folder whose path lacks the word Saves passes
_read_only_tail's spelling check (pre-existing; every real save folder here contains it;
argparse also rejects extra positionals). The entry trusts the eleven pinned files' bytes;
it does not analyse what they do. No native, package or save-operation acceptance follows.

Workflow pin
readonly_classifier_guard/payload-manifest.json pins .github/workflows/qualify.yml; adding
this packet's CI step changes that file, so that one supporting-input hash is updated to the
new workflow bytes (nothing else in that packet changes; its candidate stays 1f8dc45e).

Deployment gate
Independent review and green CI on the exact commit, then deploy with a backup folder and
DEPLOY.json under .claude/backups/hook-deploys/, as on 2026-11-10 09:29. The game-root
guard stays unchanged until then. After the deploy the gateway's own consumed-host pin
(gateway_test_support/qualification.py) and its support qualification record must be
refreshed for the new guard hash before freeze can run; that is gateway-owned work.
