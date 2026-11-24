"""Replay every Write/Edit/MultiEdit/NotebookEdit/Bash/PowerShell/Monitor call from Claude Code transcripts through
the hook's detection. Local evidence only (transcripts never enter the repo). Usage: python replay_history.py DIR [...]"""
import importlib.util, json, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("h", Path(__file__).parent / "no-detached-launch.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
total = hits = 0
seen = set()
for d in sys.argv[1:]:
    for f in Path(d).rglob("*.jsonl"):
        for line in open(f, encoding="utf-8", errors="replace"):
            if '"tool_use"' not in line:
                continue
            try:
                msg = json.loads(line)["message"]["content"]
            except Exception:
                continue
            for c in msg if isinstance(msg, list) else []:
                if c.get("type") != "tool_use" or c.get("id") in seen:
                    continue
                seen.add(c.get("id"))
                tool, inp = c.get("name"), c.get("input") or {}
                found = [t for t in h.texts(tool, inp) if isinstance(t, str)]
                if not found:
                    continue
                total += 1
                for t in found:
                    hit = h.detached(t)
                    if hit:
                        hits += 1
                        print("HIT", tool, f.name[:8], hit[:150])
                        break
print("calls", total, "refused", hits)
