"""Explicit completion15 preparation/lifecycle; never launches during preparation.

Reuse the qualified preservation, named-load and one-launch controllers. Native
publication is paired with its installer receipt; no production Python overlay.
"""
import argparse
import json
from pathlib import Path
import socket
import native_run as n

HERE=n.HERE
RUN=HERE/'engine-completion-15'
OWNER='gateway-native-migration'
OUTPUTS=('control-private.json','combat-active.txt','combat-command.json',
         'combat-result.txt','combat-registration.txt','combat-start-registration.txt',
         'combat-dispatch.txt','guardian/native-plugin-health.json')


def configure(desktop):
    if desktop not in ('pending','current','background'):raise ValueError('fresh_desktop_choice_required')
    n.RUN=RUN;n.FOLDER=RUN/'sessions/baseline';n.OWNER=OWNER;n.DESKTOP=desktop;n.build.RUNS=RUN


def installer():
    value=n.module(HERE/'stage/tools/skyrimnet-output-guard/install-native.py','batch_native_installer')
    value.ROOT=n.ROOT
    return value


def ports_closed():
    for port in (8922,18922):
        with socket.socket() as connection:
            connection.settimeout(.2)
            if connection.connect_ex(('127.0.0.1',port))==0:raise ValueError('stop_gateway_before_preparation')


def freeze():
    n.freeze()
    path=RUN/'inputs.json';pins=n.read(path)
    source=HERE/'stage/tools/skyrimnet-output-guard'
    paths=[Path(__file__),HERE/'native_follow_probe.py',HERE/'native_qualification_run.py',
           HERE/'build/native/Release/GuardianNative.dll',
           HERE.parent/'beta28-qualification-2026-10-23/native-probe.py']
    paths += list(source.glob('*.py'))
    for directory in ('native','native-combat'):
        paths += [p for p in (source/directory).iterdir() if p.is_file()]
    paths += list((RUN/'qualification/requests').glob('*.json'))
    manifest = n.read(RUN/'batch-manifest.json')
    from completion_segments import BASELINE, CONTRASTS, qualification_directory
    for segment in CONTRASTS:
        if manifest.get('qualification_segments') == [BASELINE, segment]:
            folder = qualification_directory(RUN, segment)
            paths += list((folder/'requests').glob('*.json'))
            paths += [folder/'frozen-native-expectations.json']
    paths += [HERE/'completion_segments.py', HERE/'completion_startup.py']
    paths += [HERE/'beta29-readiness-2026-10-31'/name for name in
              ('semantic_variants.py','semantic-development-manifest.json','audit.py','audit.json')]
    paths += [RUN/'qualification/frozen-native-expectations.json',RUN/'batch-manifest.json',
              HERE/'completion-native-cases.json', HERE/'completion-campaign-approval.json',
              HERE/'completion_probe_scope.py', HERE/'completion_probe_service.py',
              HERE/'completion_stream_fixture.py', HERE/'completion_packet.py',
              HERE/'completion_boundary.py', HERE/'completion_procedures.py',
              HERE/'completion_case_driver.py', HERE/'completion_runtime_ops.py', HERE/'completion_duplicate.py',
              HERE/'offline-readiness-2026-10-30/info-parent-topics.json',
              HERE/'offline-readiness-2026-10-30/PROCEDURES.md', HERE/'offline-readiness-2026-10-30/audit.json',
              HERE/'completion-engineering-evidence.json', HERE/'completion-campaign-evidence.json',
              HERE/'completion-final-offline-evidence.json', HERE/'completion-final-campaign.md',
              HERE.parent/'fleet-scope-2026-10-28/native_probe_service.py',
              HERE.parent/'fleet-scope-2026-10-28/probe_scope.py']
    paths += [HERE/'semantic_continuation.py', RUN/'PROCEDURES.md', RUN/'prepare_metadata.py', RUN/'audit_prepared.py']
    paths += list(RUN.glob('*.py'))
    if manifest.get('comparison_manifest') == '../follower-context-2026-10-31/cases.json':
        paths += [HERE/name for name in ('reference_adapter.py', 'follower_context_scope.py',
            'follower_context_driver.py', 'follower_context_comparison.py')]
        paths += [HERE/'follower-context-2026-10-31/cases.json',
            n.ROOT/'.skyguard/housecarl/artifacts/gateway-follower-context-info-parents-20261031.jsonl',
            n.REFERENCE/'runtime-preservation.json']
    if manifest.get('qualification_segments') == ['baseline', 'ttft-floor-5000']:
        paths += [HERE/'repair-clock-verification.json', HERE/'repair-clock-review-2026-10-31.md']
    paths += [HERE/'certainty-2026-10-30'/name for name in ('run_semantics.py',
              'prepare_semantics.py','semantic-cases.json','semantic-packet-manifest.json','semantic-packet-manifest-v2.json','semantic-packet-manifest-v3.json','semantic-packet-manifest-v4.json',
              'semantic-freeze.json','verification.json')]
    pins.update({p.relative_to(n.ROOT).as_posix():n.sha(p) for p in paths})
    path.write_text(json.dumps(pins,indent=2)+'\n')
    mapping=installer().publish(HERE/'build/native/Release/GuardianNative.dll')['changes']
    n.write(RUN/'publication-plan.json',dict(changes=mapping,production_acceptance=False))


def preserve_outputs():
    base=n.ROOT/'_CLAUDE_OUTPUT/output-guard';rows=[]
    for name in OUTPUTS:
        path=base/name
        rows.append(dict(name=name,sha256=n.sha(path) if path.is_file() else None))
    n.write(RUN/'private/output-preservation.json',rows)
    for row in rows:
        path=base/row['name']
        if row['sha256'] is None:continue
        target=RUN/'private/output-before'/row['name'];target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists() or n.sha(path)!=row['sha256']:raise ValueError('output_preservation_drift')
        path.rename(target)
        if n.sha(target)!=row['sha256']:raise ValueError('output_preservation_hash')


def prepare():
    n.checked();ports_closed();n.prepare();preserve_outputs()


def identity_paths():
    source=HERE/'stage/tools/skyrimnet-output-guard/native-combat/0095_gateway_combat.prompt'
    target=n.ROOT/'Data/SKSE/Plugins/SkyrimNet/external/wingedguardian.personal-rules/prompts/submodules/system_head/0095_gateway_combat.prompt'
    if target.is_symlink() or not target.resolve().is_relative_to(n.ROOT.resolve()):
        raise ValueError('identity_template_target_scope')
    return source,target


def publish_identity():
    # Controlled test only. Production shadow intentionally has no marker.
    source,target=identity_paths()
    if target.exists():raise ValueError('existing_identity_template_requires_preservation_review')
    digest=n.sha(source)
    n.write(RUN/'identity-publication-intent.json',dict(before=None,sha256=digest))
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('xb') as stream:stream.write(source.read_bytes())
    if n.sha(target)!=digest:raise ValueError('identity_template_publication_hash')
    n.write(RUN/'identity-publication.json',dict(sha256=digest,production_acceptance=False))


def restore_identity():
    intent=RUN/'identity-publication-intent.json'
    if not intent.exists():return  # Publication did not reach this step.
    value=n.read(intent)
    if value.get('before','unknown') is not None:raise ValueError('identity_template_prior_state')
    _,target=identity_paths()
    existed=target.exists()
    if existed:
        if n.sha(target)!=value['sha256']:raise ValueError('identity_template_changed; preserve for review')
        # Only our exact newly created file; never a directory or previous file.
        target.unlink()
    n.write(RUN/'identity-restoration.json',dict(restored_absence=not target.exists(),removed=existed))


def publish():
    n.checked();n.cold(OWNER);ports_closed()
    previous=n.read(RUN/'publication-plan.json')
    current=installer().publish(HERE/'build/native/Release/GuardianNative.dll')
    if current['changes']!=previous['changes']:raise ValueError('publication_plan_drift')
    if (RUN/'publication.json').exists():raise ValueError('publication_already_recorded')
    # Installer permanently records verified backups before changing any target.
    # If it fails, its preserved-status receipt supports partial rollback.
    result=installer().publish(HERE/'build/native/Release/GuardianNative.dll',apply=True)
    n.write(RUN/'publication.json',result)
    publish_identity()


def check_publication():
    n.checked();ports_closed()
    source,target=identity_paths()
    if not target.is_file() or n.sha(target)!=n.sha(source):raise ValueError('identity_template_missing_or_changed')
    rows=n.read(RUN/'publication.json')['changes']
    for row in rows:
        if n.sha(n.ROOT/row['target'])!=row['source_sha256']:raise ValueError('published_artifact_drift')
    for name in ('control-private.json','combat-active.txt','combat-command.json'):
        if (n.ROOT/'_CLAUDE_OUTPUT/output-guard'/name).exists():raise ValueError('unexpected_native_authority')


def preflight():
    check_publication();n.preflight()


def run():
    check_publication();n.run()


def restore_outputs():
    base=n.ROOT/'_CLAUDE_OUTPUT/output-guard'
    for row in n.read(RUN/'private/output-preservation.json'):
        path=base/row['name'];before=RUN/'private/output-before'/row['name']
        if row['sha256'] is not None and n.sha(before)!=row['sha256']:
            raise ValueError('preserved_output_changed')
        if path.exists():
            after=RUN/'private/output-after'/row['name'];after.parent.mkdir(parents=True,exist_ok=True)
            if after.exists():raise ValueError('retained_output_exists')
            path.rename(after)
        if row['sha256'] is not None:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(before.read_bytes())
            if n.sha(path)!=row['sha256']:raise ValueError('output_restore_hash')


def recycle_reference_view(folder):
    """Unlink this run's immutable scratch view only after verified restoration."""
    folder=Path(folder).resolve()
    if n.read(folder/'restoration-verified.json').get('ok') is not True:
        raise ValueError('restoration_required_before_view_cleanup')
    view=folder/'private/runtime-before'
    rows=n.read(folder/'runtime-preservation.json')['files']
    if rows and all(row.get('stage') == 'immutable-reference' for row in rows):
        # The new adapter never creates payload stage files. Keep the small
        # independent metadata receipt and verify every permanent object; there
        # is no staging tree to unlink and no backup retirement.
        if folder != n.FOLDER.resolve():
            raise ValueError('current_reference_session_required')
        _, store = n.context(restoring=True)
        store.prepared_rows()
        manifest = folder/'reference-manifest.json'
        original = n.REFERENCE/'runtime-preservation.json'
        if (manifest.is_symlink() or manifest.samefile(original) or manifest.stat().st_nlink != 1
                or n.sha(manifest) != n.REFERENCE_PIN or n.sha(original) != n.REFERENCE_PIN):
            raise ValueError('independent_manifest_identity_mismatch')
        n.write(folder/'reference-view-recycled.json',dict(unlinked=0,
            stage='immutable-reference',cleanup='no_payload_staging',
            original_objects_verified=True,permanent_backups_removed=False))
        return
    paths=[]
    for row in rows:
        target=view/row['path'];reference=Path(row['reference'])
        if (row.get('stage')!='immutable-hardlink' or target.is_symlink()
                or not target.resolve().is_relative_to(view.resolve())
                or target.suffix.lower() in ('.ess','.skse')
                or not reference.resolve().is_relative_to(n.REFERENCE/'private/runtime-before')
                or not target.samefile(reference) or target.stat().st_nlink<2
                or n.sha(reference)!=row['sha256']):
            raise ValueError('scratch_view_identity_mismatch')
        paths.append((target,reference,row['sha256']))
    manifest=folder/'reference-manifest.json'
    if manifest.exists():
        original=n.REFERENCE/'runtime-preservation.json'
        if (manifest.is_symlink() or not manifest.samefile(original)
                or n.sha(original)!=n.REFERENCE_PIN):
            raise ValueError('scratch_manifest_identity_mismatch')
        paths.append((manifest,original,n.REFERENCE_PIN))
    # Validate the entire set before unlinking a single scratch name.
    for target,reference,digest in paths:
        target.unlink()
        if n.sha(reference)!=digest:raise ValueError('immutable_reference_changed')
    n.write(folder/'reference-view-recycled.json',dict(unlinked=len(paths),
        original_objects_verified=True,permanent_backups_removed=False))


def restore():
    n.cold(OWNER);ports_closed()
    receipt=n.read(RUN/'publication.json')['receipt']
    result=installer().rollback(receipt,apply=True)
    n.write(RUN/'publication-rollback.json',result)
    restore_identity()
    restore_outputs()
    n.restore()
    recycle_reference_view(n.FOLDER)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('freeze','prepare','publish','preflight','run','ready','stop','restore'))
    parser.add_argument('--desktop',required=True,choices=('pending','current','background'))
    args=parser.parse_args()
    if Path.cwd().resolve()!=n.ROOT.resolve():raise ValueError('installation_workdir_required')
    configure(args.desktop)
    actions=dict(freeze=freeze,prepare=prepare,publish=publish,preflight=preflight,
                 run=run,ready=n.adopt_and_ready,stop=n.stop,restore=restore)
    actions[args.action]()
