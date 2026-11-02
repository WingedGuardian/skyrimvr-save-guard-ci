"""Task-local metadata references for the existing pinned preservation controller.

No payload staging or links. Reuse ReferenceStore's validation, parking and
exclusive checked restoration; adapt the legacy controller's logical hash/copy
calls only for exact recorded PRIVATE members. No game or save interface.
"""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import build
from reference_preservation import ReferenceStore


def bind_manifest(source, target, digest):
    """One small independent metadata file, never a linked staging view."""
    source, target = Path(source), Path(target)
    raw = source.read_bytes()
    import hashlib
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('reference_manifest_drift')
    with target.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    if target.samefile(source) or target.stat().st_nlink != 1 or build.sha(target) != digest:
        raise ValueError('independent_manifest_verification_failed')


class ReferenceAdapter(ReferenceStore):
    def __init__(self, context, manifest, objects, expected_hash, verify_objects=True):
        super().__init__(context, manifest, objects, expected_hash, verify_objects=verify_objects)
        self.expected_manifest_sha256 = expected_hash

    def bind(self):
        if getattr(self.context, '_gateway_reference_bound', False):
            raise ValueError('preservation_context_already_bound')
        self.real_sha = self.context.sha
        self.context._gateway_reference_bound = True
        self.context.sha = self.hash_path
        self.context.copy_verified = self.capture
        self.context.shutil = SimpleNamespace(copy2=self.restore_file)

    def require_empty_controller_sources(self):
        # These exact small files have a separate preservation path in the
        # gateway runner. The legacy copy delegate must never handle them.
        for name in ('prepared-pair.json', 'owned-session.json', 'load-dispatch.json', 'load-lifecycle.json'):
            for base in (self.context.HERE/'private/controller-before', self.context.WORK):
                if os.path.lexists(base/name):
                    raise ValueError('legacy_controller_metadata_requires_separate_preservation')

    def _absent_payloads(self):
        private = self.context.PRIVATE
        if private.is_symlink():
            raise ValueError('unexpected_private_link')
        if private.exists():
            for path in private.rglob('*'):
                if path.is_symlink() or not path.is_dir():
                    raise ValueError('unexpected_private_payload')

    def _logical_member(self, path):
        path = Path(path)
        try:
            relative = path.relative_to(self.context.PRIVATE).as_posix()
        except ValueError:
            return None
        if relative not in self.rows or path != self.context.PRIVATE/relative:
            return None
        if os.path.lexists(path):
            raise ValueError('unexpected_logical_payload')
        return relative

    def capture(self, source, destination):
        if Path(destination) != self.context.PRIVATE:
            return super().capture(source, destination)
        source = self.live(source)
        relative = source.relative_to(self.context.ROOT).as_posix()
        self._absent_payloads()
        reference = self.object_path(relative)
        stat = source.stat()
        digest = build.sha(source)
        if (digest != self.rows[relative]['sha256'] or source.samefile(reference)
                or stat.st_nlink != 1):
            raise ValueError('reference_drift_or_shared_live_input')
        return dict(path=relative, sha256=digest, reference=str(reference), stage='immutable-reference',
                    mtime_ns=stat.st_mtime_ns, atime_ns=stat.st_atime_ns)

    def prepared_rows(self):
        self._absent_payloads()
        path = self.context.HERE/'runtime-preservation.json'
        value = json.loads(path.read_text(encoding='utf-8'))
        rows = value['files']
        if value.get('controller_files', []) != []:
            raise ValueError('unexpected_legacy_controller_payload')
        indexed = {row['path']: row for row in rows}
        if len(indexed) != len(rows) or set(indexed) != set(self.rows):
            raise ValueError('preservation_references_omit_or_add_inputs')
        for relative, row in indexed.items():
            reference = self.object_path(relative)
            if (row.get('sha256') != self.rows[relative]['sha256']
                    or row.get('stage') != 'immutable-reference'
                    or Path(row.get('reference', '')) != reference
                    or type(row.get('mtime_ns')) is not int or type(row.get('atime_ns')) is not int
                    or self._logical_member(self.context.PRIVATE/relative) != relative):
                raise ValueError('preservation_reference_identity_changed')
        self.prepared_manifest_sha256 = build.sha(path)
        return indexed

    def _member_reference(self, relative):
        self._absent_payloads()
        if build.sha(self.manifest) != self.expected_manifest_sha256:
            raise ValueError('permanent_reference_manifest_changed')
        if not hasattr(self, 'restoration_rows'):
            self.prepare_restore()
        if build.sha(self.context.HERE/'runtime-preservation.json') != self.prepared_manifest_sha256:
            raise ValueError('prepared_reference_manifest_changed')
        reference = self.object_path(relative)
        row = self.restoration_rows[relative]
        if Path(row['reference']) != reference or row['sha256'] != self.rows[relative]['sha256']:
            raise ValueError('prepared_reference_member_changed')
        return reference

    def hash_path(self, path):
        relative = self._logical_member(path)
        if relative is None:
            return self.real_sha(path)
        return build.sha(self._member_reference(relative))

    def restore_file(self, source, target):
        target = self.live(target)
        relative = self._logical_member(source)
        if relative is None or target != self.context.ROOT/relative:
            raise ValueError('restoration_source_target_mismatch')
        reference = self._member_reference(relative)
        if not hasattr(self, '_delegate'):
            # Separate context, not a temporary change to the live controller's
            # PRIVATE. Base restore_file now sees an actual exact source object
            # and keeps its hash, parking, exclusive-temp and no-alias checks.
            context = SimpleNamespace(ROOT=self.context.ROOT, HERE=self.context.HERE,
                                      PRIVATE=self.objects, TREES=self.context.TREES)
            self._delegate = ReferenceStore(context, self.manifest, self.objects,
                                            self.expected_manifest_sha256, verify_objects=False)
            self._delegate.restoration_rows = self.restoration_rows
        return self._delegate.restore_file(reference, target)
