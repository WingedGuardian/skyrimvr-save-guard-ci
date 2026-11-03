# Private project-local gateway runner qualification

## Current packet: 2026-11-03 wrapper hardening + sentinel race (additive; the guard itself is unchanged here)

Two hook files that had NO CI until now join the gate. Neither changes a guard decision.

- `save-access-entry.template.ps1` is the PowerShell wrapper that hosts register, with the pinned interpreter path
  replaced by `__GUARD_PYTHON__` (`render_wrapper.py` renders it; the deployed file is the template rendered with the
  private absolute pin, so the pin never enters this repo). Fixes: the child's stdout is drained asynchronously (a
  decision above the ~4 KB pipe buffer used to deadlock the child into a 20 s timeout and a generic deny); every
  failure path names its stage (`start`, `stdin`, `exit`, `exitcode`, `output-json`) and appends the child's stderr,
  so a deny under machine load reads as load, not as a broken hook (2026-11-02: two such denies, 4.9 s and 7.6 s wall,
  while the machine had under 1 GiB RAM free); one 24 s deadline with an 8 s stdin handoff, inside both hosts' 30 s
  hook timeout, which fails OPEN. `test_save_access_entry.py`: nine twin cases against fake guards, four mutation twins
  (each names the case it must turn red), render contract. The PowerShell cases run on the Windows runner only;
  `qualify.py` fails the Windows job if fewer than nine wrapper HARNESS RUNS happened (`wrapper_cases_run` counts
  wrapper invocations, not test methods), and the Linux job prints a SKIP line, runs the portable `RenderContract`, and
  records `wrapper_cases_run: 0`. The 24 s budget is counted from the wrapper process's own start time with the last
  3 s reserved for post-timeout cleanup, so the hard ceiling including Kill stays under the hosts' 30 s; the child
  may spend the whole remaining ~21 s on start plus answer (there is no separate stdin allowance: once the payload is
  written as bytes, a write only blocks for payloads above the pipe buffer, so a second budget would be incoherent); the
  `output-json` deny names only the exception type and output length, never the output (ConvertFrom-Json's message
  embeds its whole input, which could be the hook payload). The payload is written to the guard as explicit BOM-less
  UTF-8 bytes: .NET Framework's `StandardInput` uses `Console.InputEncoding`, which on a UTF-8 (65001) console emits
  a BOM, and the guard's `json.load()` then refuses every call as malformed. This was invisible on the install's OEM
  console and surfaced on this runner (run 41595187331: the first fake guard that parsed its stdin crashed). Case 10
  (`strict_json`) and its BOM twin pin it.
- `save-sentinel.py` (PostToolUse): `os.replace` and the state read retry on `PermissionError` (another session's
  sentinel holding the shared state file); the `.tmp-<pid>` never outlives the call. Before, the write raised and
  abandoned a 2.5 MB temp file, and the read fell to an empty state, forgetting the previous look, so a save changed in
  that window went unreported. `test_save_sentinel.StateFileRace` (3 tests, both runners) and `sentinel_mutants.py`
  (3 twins on temp copies; the run fails unless all are killed).

`PinTests`, `DECLARED_CHANGES`, `baseline-guard.py` and the guard inputs are exactly the 2026-11-02 packet's.

## Previous packet: 2026-11-01 classifier repair (supersedes the pins-only scope described below)

The candidate CHANGES ALGORITHMS, unlike the earlier pins-only packets. It repairs the runtime save/load rule after the
Codex gateway session's read-only audit (42 frozen cases: 13 false allows, 6 false refusals). Requests are now judged
by structure (a key/value pair in any quoting or layout, MCP keys included, plus the position that names the DevBench
tool) instead of a one-line 100-character word window. Per the user's 2026-11-01 ruling, helper file NAMES no longer
count; a script's source handed to an interpreter (piped, exec'd, iex'd, dot-sourced, inline -Command, rg --pre) is
judged as a run of that script. `baseline-guard.py` is the deployed guard (4c11cc98…).

`PinTests` is re-scoped for an algorithm change, and the change is bounded three ways:
- `test_pin_tables_are_exactly_the_deployed_ones`: `READ_ONLY_SCRIPT_VERBS` and `REVIEWED_NON_SAVE_LIFECYCLE` equal
  the baseline exactly.
- `test_only_the_declared_definitions_changed`: the set of changed top-level definitions (by AST) equals
  `DECLARED_CHANGES`, in both directions.
- `test_candidate_patch_is_the_exact_diff`: `candidate.patch` is the exact unified diff from baseline to candidate.

`RuntimeRequests` (the frozen audit manifests, copied under `inputs/` with their sha256 asserted, plus replay-derived
rows and one mutation twin per clause) joins the selected classes. The pins-only `test_old_hash_does_not_authorize_current_runner`
is retired: with the deployed guard as baseline, the runner's current pin is the expected one. Local evidence for this
packet, including a replay of every historical Claude and Codex tool call, lives in the install under
`_CLAUDE_OUTPUT/output-guard/guardian/mvp-closeout-2026-10-28/follower-context-2026-10-31/rewrite-repair-2026-11-01/`.

## Earlier packets

This directory is internal qualification material, not a toolkit feature or a runtime dependency of the SkyrimNet gateway mod. Do not copy it into a public release or deploy it with the toolkit generator. No game assets, saves, databases, provider credentials, prompts or budget ledgers are included.

The exact guard candidate changes only the runner's reviewed hash/dependency/frozen-input data in two existing tables. Its algorithms, registered commands, exact desktop argument restriction, backup/count rules and both real host registrations stay unchanged. The previously proposed MO2/canary exception is absent. `candidate.patch` and `payload-manifest.json` bind exact copied source bytes.

The CI entry point is `python private_qualification/gateway_guard/qualify.py`. It exercises captured existing synthetic save-policy regressions, actual candidate subprocess deny/allow output, exact lifecycle argument and drift refusals, AST/pin invariance, and the actual legacy preservation controller's authored-file/SQLite roundtrip through the new metadata-reference adapter. No payload links are created, and unchanged originals are not copied. Tests use disposable authored fixtures only.

CI is deliberately a partial source environment: it includes the exact runner, adapter, guard, shared preservation implementation and legacy controller, with small frozen metadata. Missing native binaries and runtime inputs are represented by their frozen hashes **only for classifier fixture tests**. A negative test proves the candidate fails without that simulation. This is not installed-input or native acceptance; all295 inputs must pass the real local preflight before use. Unchanged PowerShell/host registration integration and unrelated housekeep-exemption tests are outside this targeted CI suite. The real Codex hook is checked separately after any qualified cutover; no Claude-host acceptance is inferred.

The targeted dispatch mode skips unrelated toolkit jobs explicitly; its green result qualifies this packet only. Normal CI behavior remains the default when that mode is not selected. No tag, release, public push or game launch is authorized by this packet.

Platform scope: Windows runs the full captured Windows save-policy suite plus portable adapter/pin tests (94 tests). Linux runs91, excluding only3 Windows-specific fixture methods: `FreeOperations.test_free`, `SaveFolders.test_code_and_prose_are_not_whole_folder_targets`, and `GatewayLifecycleNonSave.test_frozen_manifest_and_dependency_drift_refuse`. All other captured policy tests, the actual candidate subprocess, the adapter and portable pin tests remain on both platforms. Exclusions are printed explicitly, never counted as passing.

The first hosted run's three Linux failures are retained: Robocopy mistook POSIX absolute fixture paths for Windows flags; a `C:/` parent assertion is not a POSIX root; an old exact-Path mutation fixture did not match backslash-separated frozen keys while the explicit missing-native shim normalized them. Windows passed all94. The portable canonical drift test now checks every frozen input/dependency on both platforms. Guard/runtime source bytes and policy are unchanged; this is not Linux guard support or native acceptance. `--portable-only` locally exercises Linux's supplemental scope. The earlier94/19 local trial is retained; final94/91 checks supersede it.
