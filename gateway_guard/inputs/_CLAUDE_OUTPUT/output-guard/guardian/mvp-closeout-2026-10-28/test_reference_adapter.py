"""Disposable authored file/SQLite roundtrips; never uses installed payloads."""
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3]/'tools/skyrim-souls-vr/diagnostic'))
import build
import reference_preservation
from reference_adapter import ReferenceAdapter, bind_manifest


class ReferenceAdapterTests(unittest.TestCase):
    def test_reference_only_cleanup_verifies_current_session_without_unlinking(self):
        import native_batch_run as batch
        live, store = self.seed(); self.stage(store); store.prepare_restore()
        metadata = self.here/'reference-manifest.json'
        bind_manifest(self.manifest, metadata, build.sha(self.manifest))
        # The fixture uses a metadata reference root matching the runner's shape.
        ref = self.root/'baseline'; ref.mkdir()
        original = ref/'runtime-preservation.json'; original.write_bytes(self.manifest.read_bytes())
        (self.here/'restoration-verified.json').write_text('{"ok":true}')
        def read(path): return json.loads(Path(path).read_bytes())
        def write(path, value):
            with Path(path).open('x') as stream: json.dump(value, stream)
        with patch.object(batch.n, 'FOLDER', self.here), patch.object(batch.n, 'REFERENCE', ref), \
             patch.object(batch.n, 'REFERENCE_PIN', build.sha(original)), patch.object(batch.n, 'read', side_effect=read), \
             patch.object(batch.n, 'write', side_effect=write), patch.object(batch.n, 'sha', side_effect=build.sha), \
             patch.object(batch.n, 'context', return_value=(self.context, store)), \
             patch.object(Path, 'unlink', side_effect=AssertionError('no reference-only deletion')):
            batch.recycle_reference_view(self.here)
        result = read(self.here/'reference-view-recycled.json')
        self.assertEqual(result['unlinked'], 0)
        self.assertFalse(result['permanent_backups_removed'])
        self.assertTrue(live.exists()); self.assertTrue(original.exists()); self.assertTrue(metadata.exists())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gateway-reference-', dir=HERE/'build')
        self.root = Path(self.temp.name)
        self.tree = self.root/'Data/authored'; self.tree.mkdir(parents=True)
        self.here = self.root/'session'; self.here.mkdir()
        self.objects = self.root/'objects'
        self.private = self.here/'private/runtime-before'
        self.manifest = self.root/'reference.json'
        self.context = SimpleNamespace(ROOT=self.root, HERE=self.here, PRIVATE=self.private,
            WORK=self.root/'loader', TREES=[self.tree], sha=build.sha,
            files=lambda: [p for p in self.tree.rglob('*') if p.is_file()])

    def tearDown(self):
        self.temp.cleanup()

    def seed(self, names=('settings.txt',)):
        rows = []
        for name in names:
            live = self.tree/name; live.write_bytes(('original '+name).encode())
            obj = self.objects/live.relative_to(self.root); obj.parent.mkdir(parents=True, exist_ok=True)
            obj.write_bytes(live.read_bytes())
            rows.append(dict(path=live.relative_to(self.root).as_posix(), sha256=build.sha(live)))
        self.manifest.write_text(json.dumps(dict(files=rows)))
        store = ReferenceAdapter(self.context, self.manifest, self.objects, build.sha(self.manifest))
        store.bind()
        return self.tree/names[0], store

    def stage(self, store):
        store.preflight(); store.require_empty_controller_sources()
        self.private.mkdir(parents=True, exist_ok=False)
        rows = [store.capture(p, self.private) for p in self.context.files()]
        (self.here/'runtime-preservation.json').write_text(json.dumps(dict(files=rows, controller_files=[])))
        return rows

    def test_capture_creates_no_payload_or_link_and_unchanged_restore_copies_nothing(self):
        live, store = self.seed(); inode = live.stat().st_ino
        reference = self.objects/live.relative_to(self.root)
        with patch('os.link', side_effect=AssertionError('no new links')), \
             patch('reference_preservation.os.rename', side_effect=AssertionError('no unchanged publication')):
            rows = self.stage(store); store.prepare_restore()
            logical = self.private/live.relative_to(self.root)
            self.assertFalse(logical.exists()); self.assertEqual(list(self.private.iterdir()), [])
            self.assertEqual(rows[0]['stage'], 'immutable-reference')
            self.assertEqual(self.context.sha(logical), build.sha(reference))
            store.restore_file(logical, live)
        self.assertEqual(live.stat().st_ino, inode)
        self.assertFalse(live.samefile(reference)); self.assertEqual(reference.stat().st_nlink, 1)

    def test_changed_and_new_outputs_are_parked_and_restore_uses_independent_object(self):
        live, store = self.seed(); self.stage(store); store.prepare_restore()
        original = live.read_bytes(); live.write_bytes(b'changed authored output')
        after = self.here/'private/runtime-after'; after.mkdir()
        changed = store.capture(live, after)
        new = self.tree/'new.txt'; new.write_bytes(b'new authored output')
        parked = store.park_new_outputs()
        store.restore_file(self.private/live.relative_to(self.root), live)
        self.assertEqual(live.read_bytes(), original)
        self.assertEqual(Path(changed['parked']).read_bytes(), b'changed authored output')
        self.assertEqual(len(parked), 1); self.assertFalse(new.exists())
        self.assertEqual(Path(parked[0]['parked']).read_bytes(), b'new authored output')
        self.assertEqual(self.context.sha(live), build.sha(live))
        self.assertEqual(self.context.sha(Path(changed['parked'])), build.sha(Path(changed['parked'])))

    def test_sqlite_changed_result_is_retained_and_original_restored_without_staging_database(self):
        live = self.tree/'authored.db'
        with sqlite3.connect(live) as database:
            database.execute('create table facts(value text)'); database.execute("insert into facts values ('original')")
        database.close()
        obj = self.objects/live.relative_to(self.root); obj.parent.mkdir(parents=True); obj.write_bytes(live.read_bytes())
        self.manifest.write_text(json.dumps(dict(files=[dict(path=live.relative_to(self.root).as_posix(), sha256=build.sha(live))])))
        store = ReferenceAdapter(self.context, self.manifest, self.objects, build.sha(self.manifest)); store.bind()
        self.stage(store)
        with sqlite3.connect(live) as database: database.execute("insert into facts values ('test result')")
        database.close()
        after = self.here/'private/runtime-after'; after.mkdir(); store.prepare_restore()
        changed = store.capture(live, after)
        store.restore_file(self.private/live.relative_to(self.root), live)
        with sqlite3.connect(live) as database:
            self.assertEqual(database.execute('select * from facts').fetchall(), [('original',)])
        database.close()
        with sqlite3.connect(changed['parked']) as database:
            self.assertEqual(database.execute('select count(*) from facts').fetchone()[0], 2)
        database.close()
        self.assertFalse((self.private/live.relative_to(self.root)).exists())

    def test_bad_or_changed_reference_rows_are_refused_before_restoration(self):
        _, store = self.seed(); rows = self.stage(store)
        for mutate in ('duplicate', 'missing', 'extra', 'reference', 'hash', 'stage', 'time'):
            value = copy.deepcopy(rows)
            if mutate == 'duplicate': value += value
            elif mutate == 'missing': value = []
            elif mutate == 'extra': value.append(dict(value[0], path='Data/authored/extra.txt'))
            elif mutate == 'reference': value[0]['reference'] = str(self.root/'foreign.txt')
            elif mutate == 'hash': value[0]['sha256'] = '0'*64
            elif mutate == 'stage': value[0]['stage'] = 'immutable-hardlink'
            else: value[0]['mtime_ns'] = None
            (self.here/'runtime-preservation.json').write_text(json.dumps(dict(files=value)))
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): store.prepare_restore()

    def test_unexpected_real_logical_file_cannot_be_hidden_by_virtual_hash(self):
        live, store = self.seed(); self.stage(store)
        logical = self.private/live.relative_to(self.root); logical.parent.mkdir(parents=True)
        logical.write_bytes(b'foreign real payload')
        with self.assertRaisesRegex(ValueError, 'unexpected'): self.context.sha(logical)
        with self.assertRaisesRegex(ValueError, 'unexpected'): store.prepare_restore()
        self.assertEqual(logical.read_bytes(), b'foreign real payload')

    def test_foreign_private_payload_and_controller_source_refuse(self):
        _, store = self.seed(); self.private.mkdir(parents=True); (self.private/'foreign.txt').write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError, 'unexpected'): store.capture(self.tree/'settings.txt', self.private)
        self.context.WORK.mkdir(); (self.context.WORK/'prepared-pair.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'separate_preservation'): store.require_empty_controller_sources()

    def test_drift_after_prepare_and_wrong_restore_pair_are_refused(self):
        live, store = self.seed(); self.stage(store); store.prepare_restore()
        logical = self.private/live.relative_to(self.root)
        with self.assertRaises(ValueError): store.restore_file(logical, self.tree/'wrong.txt')
        with self.assertRaises(ValueError): store.restore_file(self.root/'foreign.txt', live)
        obj = self.objects/live.relative_to(self.root); obj.write_bytes(b'corrupted retained object')
        with self.assertRaises(ValueError): self.context.sha(logical)
        self.assertEqual(live.read_bytes(), b'original settings.txt')

    def test_failed_publication_keeps_changed_output_and_reference(self):
        live, store = self.seed(); self.stage(store); store.prepare_restore()
        live.write_bytes(b'changed output')
        after = self.here/'private/runtime-after'; after.mkdir()
        parked = store.capture(live, after)
        with patch('reference_preservation.os.rename', side_effect=OSError('fixture publication failure')):
            with self.assertRaises(OSError):
                store.restore_file(self.private/live.relative_to(self.root), live)
        self.assertFalse(live.exists())
        self.assertEqual(Path(parked['parked']).read_bytes(), b'changed output')
        self.assertEqual((self.objects/live.relative_to(self.root)).read_bytes(), b'original settings.txt')

    def test_broken_link_presence_is_not_treated_as_absent(self):
        live, store = self.seed(); self.stage(store); store.prepare_restore()
        logical = self.private/live.relative_to(self.root)
        actual = __import__('os').path.lexists
        with patch('reference_adapter.os.path.lexists', side_effect=lambda p: True if Path(p)==logical else actual(p)):
            with self.assertRaisesRegex(ValueError, 'unexpected_logical_payload'): self.context.sha(logical)

    def test_prepared_manifest_drift_is_refused(self):
        live, store = self.seed(); self.stage(store); store.prepare_restore()
        (self.here/'runtime-preservation.json').write_text('{"files":[]}')
        with self.assertRaisesRegex(ValueError, 'prepared_reference_manifest_changed'):
            self.context.sha(self.private/live.relative_to(self.root))

    def test_independent_metadata_binding_has_no_links_or_overwrite(self):
        _, _store = self.seed(); target = self.here/'reference-manifest.json'
        with patch('os.link', side_effect=AssertionError('no links')):
            bind_manifest(self.manifest, target, build.sha(self.manifest))
        self.assertEqual(target.read_bytes(), self.manifest.read_bytes())
        self.assertFalse(target.samefile(self.manifest))
        with self.assertRaises(FileExistsError): bind_manifest(self.manifest, target, build.sha(self.manifest))
        with self.assertRaises(ValueError): bind_manifest(self.manifest, self.here/'wrong.json', '0'*64)

    def test_full_pinned_legacy_controller_roundtrip_and_unchanged_payload(self):
        import native_run
        spec = importlib.util.spec_from_file_location('authored_reference_legacy', native_run.PRESERVER)
        controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)
        self.assertEqual(build.sha(native_run.PRESERVER), native_run.PRESERVER_PIN)
        controller.ROOT = self.root; controller.LIVE = self.root/'Data/native'
        controller.HERE = self.here; controller.PRIVATE = self.private; controller.WORK = self.root/'loader'
        controller.OWNER = 'authored-gateway-reference'; controller.TREES = [controller.LIVE/'config', controller.LIVE/'data']
        inputs = {'SkyrimNet.yaml':'gamemaster: {enabled: true, agentEnabled: true}\n',
                  'Agents.yaml':'agents: {enable: true}\n', 'NpcThoughts.yaml':'enabled: true\n',
                  'OmniSight.yaml':'omnisight: {enabled: true}\n',
                  'plugins/IntelEngine/settings.yaml':'politics: {enabled: true}\n'}
        for name, text in inputs.items():
            path = controller.LIVE/'config'/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
        unchanged = controller.LIVE/'data/unchanged.txt'; unchanged.parent.mkdir()
        unchanged.write_bytes(b'unchanged authored sentinel'*10000); inode = unchanged.stat().st_ino
        owner = self.root/'_CLAUDE_OUTPUT/skyrimnet-work-status.json'; owner.parent.mkdir()
        owner.write_text(json.dumps(dict(active_shared_config_owner=None, active_live_test_owner=None)))
        rows = []
        for path in controller.files():
            obj = self.objects/path.relative_to(self.root); obj.parent.mkdir(parents=True, exist_ok=True)
            obj.write_bytes(path.read_bytes()); rows.append(dict(path=path.relative_to(self.root).as_posix(), sha256=build.sha(path)))
        self.manifest.write_text(json.dumps(dict(files=rows)))
        store = ReferenceAdapter(controller, self.manifest, self.objects, build.sha(self.manifest))
        store.bind(); store.preflight(); store.require_empty_controller_sources()
        with patch.dict(sys.modules, {'deploy':SimpleNamespace(no_game=lambda:None)}), \
             patch('os.link', side_effect=AssertionError('no new hardlinks')):
            controller.prepare()
            self.assertEqual(json.loads(owner.read_text())['active_live_test_owner'], controller.OWNER)
            new = controller.LIVE/'data/new.txt'; new.write_bytes(b'authored new output')
            store.prepare_restore(); parked = store.park_new_outputs(); controller.restore()
        self.assertTrue(all(build.sha(self.root/row['path']) == row['sha256'] for row in rows))
        self.assertEqual(unchanged.stat().st_ino, inode)
        self.assertIsNone(json.loads(owner.read_text())['active_live_test_owner'])
        self.assertEqual(len(parked), 1)
        self.assertFalse(any(path.is_file() for path in self.private.rglob('*')))


if __name__ == '__main__': unittest.main()
