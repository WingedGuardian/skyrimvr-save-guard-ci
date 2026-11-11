"""Every packet file must have the SHA-256 the manifest records."""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
bad = []
for line in (HERE / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
    digest, name = line.split("  ", 1)
    got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
    print(("ok   " if got == digest else "DIFF ") + name)
    if got != digest:
        bad.append(name)
sys.exit(1 if bad else 0)
