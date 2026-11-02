"""Reference adapter for the pinned cold preservation controller, never live backup links."""
import json
import os
from pathlib import Path
import build


class ReferenceStore:
    def __init__(self, context, manifest, objects, expected_hash, verify_objects=True):
        self.context = context
        self.manifest = Path(manifest)
        self.objects = Path(objects)
        if build.sha(self.manifest) != expected_hash:
            raise ValueError('Historical reference manifest changed')
        rows = json.loads(self.manifest.read_text())['files']
        self.rows = {row['path']: row for row in rows}
        if len(self.rows) != len(rows) or not rows:
            raise ValueError('Missing or duplicate historical references')
        for relative in self.rows:
            self.live(context.ROOT / relative)
            if verify_objects:self.object_path(relative)

    def local(self, path, root):
        path = Path(path)
        if not path.resolve().is_relative_to(Path(root).resolve()):
            raise ValueError('Preservation path escapes its exact local root')
        if not path.resolve().is_relative_to(self.context.ROOT.resolve()):
            raise ValueError('Preservation path escapes local installation')
        return path

    def live(self, path):
        path = self.local(path, self.context.ROOT)
        if path.suffix.lower() in ('.ess', '.skse') or not any(
                path.resolve().is_relative_to(tree.resolve()) for tree in self.context.TREES):
            raise ValueError('Only named non-save configuration/data trees are supported')
        return path

    def object_path(self, relative):
        path = self.local(self.objects / relative, self.objects)
        if build.sha(path) != self.rows[relative]['sha256']:
            raise ValueError('Immutable reference object changed')
        return path

    def preflight(self):
        current = {p.relative_to(self.context.ROOT).as_posix(): p for p in self.context.files()}
        if set(current) != set(self.rows):
            raise ValueError('Current input paths differ from verified references')
        for relative, path in current.items():
            self.live(path)
            reference = self.object_path(relative)
            if path.samefile(reference):
                raise ValueError('Live mutable input aliases its immutable reference')
            if path.stat().st_nlink!=1:
                raise ValueError('Shared live input requires alias review before editing')
            if build.sha(path) != self.rows[relative]['sha256']:
                raise ValueError('Current input bytes differ from verified references')
        return len(current)

    def capture(self, source, destination):
        source = self.live(source)
        relative = source.relative_to(self.context.ROOT).as_posix()
        target = self.local(Path(destination) / relative, self.context.HERE)
        target.parent.mkdir(parents=True, exist_ok=True)
        sha = build.sha(source)
        stat = source.stat()
        if Path(destination) == self.context.PRIVATE:
            reference = self.object_path(relative)
            if sha != self.rows[relative]['sha256'] or source.samefile(reference):
                raise ValueError('Reference drift or mutable alias before staging')
            os.link(reference, target)  # Existing immutable object, never live Data.
            if not target.samefile(reference) or target.samefile(source) or build.sha(target) != sha:
                raise ValueError('Invalid immutable staging link')
            return dict(path=relative, sha256=sha, reference=str(reference), stage='immutable-hardlink',
                        mtime_ns=stat.st_mtime_ns, atime_ns=stat.st_atime_ns)
        expected_after = self.context.HERE / 'private/runtime-after'
        if relative not in self.rows:
            raise ValueError('New outputs must be parked before the legacy restoration loop')
        if Path(destination) != expected_after or target.exists():
            raise ValueError('Only fresh parked test outputs are supported')
        return self.park(source, target, sha, stat)

    def park(self, source, target, sha, stat):
        # Journal intent before parking the actual output once. No database copy.
        self.live(source);self.local(target,self.context.HERE)
        if target.exists():raise ValueError('Never overwrite a retained test output')
        if source.stat().st_nlink!=1:raise ValueError('Shared live output requires alias review before parking')
        relative = source.relative_to(self.context.ROOT).as_posix()
        record = dict(path=relative, sha256=sha, parked=str(target), bytes=stat.st_size)
        with (self.context.HERE/'restoration-moves.jsonl').open('a', encoding='utf-8') as log:
            log.write(json.dumps(record)+'\n'); log.flush(); os.fsync(log.fileno())
        os.rename(source, target)  # Windows refuses an existing destination.
        if source.exists() or build.sha(target) != sha:
            raise ValueError('Parked output verification failed')
        return record

    def prepared_rows(self):
        rows = json.loads((self.context.HERE/'runtime-preservation.json').read_text())['files']
        indexed = {row['path']: row for row in rows}
        if len(indexed) != len(rows) or set(indexed) != set(self.rows):
            raise ValueError('Preservation references omit or add input paths')
        for relative, row in indexed.items():
            if row['sha256'] != self.rows[relative]['sha256'] or row.get('stage') != 'immutable-hardlink':
                raise ValueError('Preservation reference identity changed')
            path = self.local(self.context.PRIVATE/relative, self.context.PRIVATE)
            if build.sha(path) != row['sha256']:
                raise ValueError('Staged immutable object changed before restoration')
        return indexed

    def prepare_restore(self):
        self.restoration_rows = self.prepared_rows()

    def park_new_outputs(self):
        result=[]
        for source in self.context.files():
            self.live(source)
            relative=source.relative_to(self.context.ROOT).as_posix()
            if relative in self.rows:continue
            target=self.local(self.context.HERE/'private/runtime-new-outputs'/relative,self.context.HERE)
            if target.exists():raise ValueError('Never overwrite retained new output')
            target.parent.mkdir(parents=True,exist_ok=True)
            result.append(self.park(source,target,build.sha(source),source.stat()))
        return result

    def restore_file(self, source, target):
        target = self.live(target)
        relative = target.relative_to(self.context.ROOT).as_posix()
        source = self.local(source, self.context.PRIVATE)
        if source != self.context.PRIVATE/relative:
            raise ValueError('Restoration source does not match its exact target')
        if not hasattr(self, 'restoration_rows'):
            self.prepare_restore()
        row = self.restoration_rows[relative]
        if build.sha(source) != row['sha256']:
            raise ValueError('Immutable object drifted before its restoration')
        if target.exists() and build.sha(target) != row['sha256']:
            raise ValueError('Changed output must be parked before restoration')
        if target.exists() and target.stat().st_nlink!=1:
            raise ValueError('Shared live target requires alias review before restoration')
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            temp = self.local(target.with_name(target.name+'.souls-restore.tmp'), self.context.ROOT)
            with source.open('rb') as src, temp.open('xb') as dst:
                for chunk in iter(lambda: src.read(1024*1024), b''):
                    dst.write(chunk)
                dst.flush(); os.fsync(dst.fileno())
            if build.sha(temp) != row['sha256']:
                raise ValueError('Restoration bytes failed verification before publication')
            os.rename(temp, target)  # Do not overwrite an unexpected concurrent input.
        if target.samefile(source) or build.sha(target) != row['sha256']:
            raise ValueError('Restored live input aliases or differs from immutable object')
        os.utime(target, ns=(row['atime_ns'], row['mtime_ns']))
