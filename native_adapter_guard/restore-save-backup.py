"""CI-only reference loader for the frozen helper, bound to this candidate."""
from pathlib import Path
import hashlib
import importlib.util

_packet = Path(__file__).resolve().parent
_original = _packet.parent / 'gateway_guard/inputs/.claude/hooks/restore-save-backup.py'
_raw = _original.read_bytes()
if hashlib.sha256(_raw).hexdigest() != '6118fe35ba773cd520727b59821d93ce3fb9746c7f0e6a3295a1921ff4fdc9e6':
    raise RuntimeError('Frozen restore helper drift')
__file__ = str(_original)
exec(compile(_raw, str(_original), 'exec'), globals())
_candidate_spec = importlib.util.spec_from_file_location('restore_native_flag_guard', _packet / 'candidate.py')
guard = importlib.util.module_from_spec(_candidate_spec)
_candidate_spec.loader.exec_module(guard)
