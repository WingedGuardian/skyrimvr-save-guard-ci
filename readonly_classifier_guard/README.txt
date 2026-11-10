Read-only classifier repair -- ISOLATED, UNQUALIFIED SOURCE

The qualified deployed baseline is native_adapter_guard/candidate.py at
commit 1e2bf07b59228e2a75dbd5c2aeeb02c37874e54c (SHA25619a5a52d...).
No game-root hook or registration is edited by this packet.

Observed problem
A read/hash Python payload defines rd as a JSON reader. Raw shell-verb regexes
misread that identifier as directory deletion when .skse is present. An ordinary
Node report is separately mistaken for deletion because its data discusses
rd/rmdir and a save path. The observed response requests deletion approval for
zero files. reader-input.txt and report-input.json are sanitized classifier
INPUT DATA ONLY. Never execute either payload.

Scope
Recognize the demonstrated explicitly imported stdlib reader lambda without
mistaking its rd identifier for a shell command, while retaining actual mutation,
preservation, runtime-load, never-delete-folder, backup retention or approval
rules. A constrained static Node JSON writer may expose its exact literal write
target to the existing target judge; unmatched code remains conservative.
This is not a general JavaScript interpreter, read-only Python exemption,
zero-match allowance, sandbox or permission to execute a diagnostic via exec.

Tests and review gates
Expected outcomes are frozen in test_candidate.py before candidate execution.
The baseline must reproduce three methods/four failing assertions (the inline
Python method has two quotation subcases); the candidate must pass all
20 methods and retained inert, native-adapter, policy, wrapper and sentinel
checks. Existing packet inputs remain referenced and unchanged. Source review
precedes execution; raw result and actual CI jobs must bind the exact final head.
This folder's .gitattributes preserves exact pinned bytes on checkout, including
Windows; whitespace in unified-patch context lines is intentional.

First CI outcome and correction
Run42729306928 tested6241ddba on Windows and Linux. Each prior three-packet step
passed; the new candidate's18 methods had four assertion failures: two harmless
literal-output cases were overblocked and two whole-configured-folder controls
were allowed. Source comparison identifies preexisting baseline behavior, not an
invalid fixture. The correction retains those oracles, protects exact configured
roots as well as their ancestors, and recognizes only a bounded literal-output
grammar. An extra actual composition/redirection/expression method is added.
The next CI also runs the three legacy baseline methods expecting four failed
assertions, separately from the original baseline3/four assertion phase. No
passing result for the corrected candidate exists at this source checkpoint.
No game, native backend, actual user saves or paid inference is invoked.

The local baseline run was REFUSED BEFORE EXECUTION (identifier01cb543087836403)
because the test source contains deletion controls. There is no red result or
local test log. The operation was stopped; do not repackage it in a new runner
to evade that refusal. The user's separate supported-route choice is pending.
The user chose separate investigation of this test-run refusal. Source inspection
identifies its invoked-script changes_files + mentions_save_location branch:
temporary fixture setup writes and inert deletion-control strings are combined.
That heuristic does not track whether each location belongs to an executed write.
No wrapper or alternative local runner is approved. Local syntax inspection is
not a passing test. CI preparation is not publication.

The qualifier raw-compiles immediately hash-verified packet modules. Its CI
invocation uses -B and a fresh absent private pycache_prefix for retained loaders;
the namespace must remain absent afterward. Merely using -B would still permit
reading an earlier compiled module and would not prove consumed source bytes.

Second CI outcome and correction (toolkit session, 2026-11-09)
Run42748857513 tested223e2b43 on Windows and Linux. Both baseline contrasts
reproduced as frozen; the candidate failed two composition assertions: a
whole protected-folder delete behind a lone `&` and inside backticks was
allowed. Decision-only probes show the deployed baseline 19a5a52d allows the
same shapes (also rm -rf and PowerShell 7 Remove-Item -Recurse behind `&`), so
this is a preexisting gap, not one 223e introduced. folder_violation now also
splits each command on a lone `&` (_command_units; a heredoc body stays with
its command) and judges every backtick/$() substitution as its own command.
Method 20 pins the rm/Remove-Item spellings plus composed commands that stay
allowed. Decision-only probe of this head: 10 composed deletes refused, 7
ordinary controls allowed. No passing CI result exists for this head yet.

Deployment gate
The user approved preparing an isolated fix with independent review and green
CI on the exact commit before deployment. The existing game-root guard stays
unchanged until those gates and any remaining publication authority are met.
Do not land on shared toolkit master or reuse another mutable candidate.

Limits
The original multi-statement Node report may remain outside the constrained
writer profile; do not claim that exact form is repaired without classification.
The separate parser diagnostic remains unexecuted after its own refusal. No
classifier fixture result qualifies native Delirium or Skyrim behavior.
