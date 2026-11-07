# Exact reviewed inert-fixture exception

## Host-envelope correction

The earlier `4024afc` candidate passed offline/CI but failed actual-host
qualification and was withdrawn. Unified exec reports canonical `Bash` to hooks
even when the configured shell is PowerShell. The original tests paired tool
labels with assumed shell syntax and missed that real combination. The correction
changes only the literal registry, retaining its predicates, ordinary policy and
all43source/runtime/cache pins. New regressions reproduce the observed envelope
and reject unobserved aliases/no-call-operator forms, including a mutation twin.
Official contract: https://learn.chatgpt.com/docs/hooks . Fresh local observation
uses the unchanged guard advisory path and an ordinary text artifact; no save
file, hook mutation or blocked fixture execution. See `ENVELOPE-RESULTS.json`;
`RESULTS.json` records the earlier candidate and does not qualify this revision.

This isolated change adds one source-qualified non-save fixture exception. Its
baseline references the unchanged existing gateway packet guard, SHA256
`fe1005c4bab628ec5c35f93e9d180a635bf12a6cd99187284fde2b56564a7ed4`.
The installed guard has not been changed. The fixture is never executed by this
qualification packet: these are guard-decision and preservation regressions.

## Eligibility

Only the observed canonical hook tool `Bash` with the exact configured PowerShell
command (including its leading `&`) is eligible. A hook tool name does not select
the execution shell. Unobserved labels and the old no-`&` spelling are rejected.
The cwd, source contents and all dependencies must match. Both interpreters
use `-E -s -S -B`; resource admission remains fixed to headroom, explicit limits,
below-normal priority and a bounded wait. Extra flags, commands, a different
resource home or a resource config file revoke the exception. This is no general
test-name, assertion or string-literal exemption.

The registry pins 43 real local files: seven project source files, one existing
project cache, wrapper/all15 local helper sources, Python executable/four runtime
DLLs and14 eligible helper caches. The measured aggregate is approximately5.1MB,
below an8MiB bounded-read cap. Compatible unreviewed caches revoke eligibility.
The recorded cached CodeType values were independently compared with freshly
compiled pinned source without executing the cached code. Other Python cache
tags are ineligible for the pinned CPython3.10 runtime. OS/standard-library trust
is not a sandbox;2s checks are cooperative, not a hard bound on individual I/O.

The packet fixture changes only its inert child interpreter startup flags; the
negative save control remains. The old live fixture is intentionally rejected
until the reviewed hardened fixture is published together with the qualified
guard. No blocked local fixture has been executed by another route.

## Qualification

`python -B inert_fixture_guard/qualify.py` runs new decision tests, then the
existing authored save-policy, backup/restore, wrapper, preservation and sentinel
regressions against THIS candidate. Applicable legacy functional pin tests are
retained. Only obsolete baseline-specific change/patch assertions are replaced
by new exact baseline/patch/AST invariants. Existing gateway qualification also
runs unchanged as a separate CI step. The restore-helper shim references its
unchanged source and binds it to the candidate rather than copying that helper.
The first broad run had3 missing-helper harness errors; that failed result is
retained in local reporting and does not count as successful qualification.

Public portability positives author external files and replace their hashes in
fixture-only registry copies; project source hashes remain real. A separate local
readback checks all real private dependencies and the staged paired command.
No private wrapper/bytecode bytes, user-specific absolute paths, game assets,
saves or credentials are published. The local ignored project cache used for
readback is excluded from the manifest and publication.

The manifest binds all packet source/data bytes before and after execution.
Guard deployment requires independent review and green public CI on the exact
commit. No push, deployment, game run, native/save acceptance or host-hook
acceptance follows from a local test result.
