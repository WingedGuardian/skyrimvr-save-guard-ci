# Skyrim VR save-guard qualification

Public CI for changes to a personal Skyrim VR install's agent save guard (a Claude Code / Codex PreToolUse hook
that backs up ESS/SKSE save pairs before changes and refuses unapproved bulk or runtime save/load operations).

`gateway_guard/` is a frozen qualification packet: the deployed baseline guard, the candidate, the exact patch,
its tests and the captured inputs they need, each pinned by SHA-256 in `payload-manifest.json`. CI runs
`python gateway_guard/qualify.py` on Ubuntu and Windows. A packet's README describes its own scope; where it says
`private_qualification/gateway_guard/qualify.py`, read `gateway_guard/qualify.py` (the packet bytes are kept
exactly as qualified).

This is not a toolkit or a release. The public toolkit is
[skyrimvr-claude-toolkit](https://github.com/WingedGuardian/skyrimvr-claude-toolkit).
