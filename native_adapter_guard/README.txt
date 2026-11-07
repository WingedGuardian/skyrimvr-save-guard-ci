Native adapter literal -B recognition -- isolated candidate, 2026-11-07

Problem: native_adapter_call expects the script in words[1] at both Python
interpreter boundaries. A read-only writer-scan invoked through the installed
resource runner with python -B at both levels misses the reviewed adapter route
and falls into generic source inspection, which sees the wrapper's file writes.

Change: normalize one exact, case-sensitive -B immediately after the outer and
wrapped Python command names. No other Python option or leading shell operator
is added. All existing wrapper grammar, adapter source hash, binary hash,
invocation validation, absolute write paths/output collision checks and existing
change()/verified pair-backup policy remain. Only native_adapter_call changes;
AST and exact patch tests enforce that scope against the committed baseline.

Qualification uses a byte-for-byte retained copy of the actual pinned adapter
because hosted CI cannot read the private installation. Authored binary and ESS
pathname marker files are never executed/parsed. Configured protection roots
are modeled; no real protected location, save, game or native backend is used.
Classifier tests cannot establish installed hook activation or runtime safety.
Full existing policy/backup/runtime-refusal regressions run against the candidate.
All old packets remain byte-identical and are referenced by verified manifests.

Before deployment: independent review and Windows/Linux CI green on the exact
commit. The source stays on fix/native-adapter-bytecode-flag-20261107; no main,
toolkit release or shared publishing state changes. Public branch push requires
the user's explicit approval under the standing committing rule.
Then verify installed activation with deliberate canary plus actual original
read-only scan, checking the source pair is unchanged. No game launch authorized.

Python -B semantics are documented by CPython:
https://docs.python.org/3.10/using/cmdline.html#cmdoption-B
