"""One approved read-only engine run using existing preservation/load/lifecycle helpers."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RUN = HERE/'engine-readonly-01'
FOLDER = RUN/'sessions/baseline'
OWNER = 'gateway-native-contracts-20261029'
DESKTOP = 'current'
HELPERS = ROOT/'tools/skyrim-souls-vr/diagnostic'
REFERENCE = HERE/'beta29-readiness-2026-10-31/reference-current'
REFERENCE_PIN = 'deedb430b20df0f7ab8ed5d7441532d256fca3c30d0e94564b64f5da3fb6c808'
PRESERVER = ROOT/'_CLAUDE_OUTPUT/output-guard/guardian/beta28-lifecycle-2026-10-23/config-context.py'
PRESERVER_PIN = '1a5537e9abf6841a20419b17173493043826439190f47c0f1ce9d3f8245c9502'
BINDING = ROOT/'tools/resaver-native-runtime.py'
BINDING_PIN = 'e84e88888568fdda2e39ed2b761fd50679c87e10ecdfe9332e77b8ca82e7f155'
CONTROL = ROOT/'_CLAUDE_OUTPUT/resaver-upgrade-33-20261028/runtime'
CONTROL_NAMES = ('prepared-pair.json','owned-session.json','load-dispatch.json','load-lifecycle.json')
sys.path.insert(0, str(HELPERS))
import build
build.RUNS = RUN


def sha(path):
    return build.sha(Path(path))


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    path = Path(path);path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, indent=2);out.write('\n')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def sources():
    qualification = read(HELPERS/'OFFLINE-QUALIFICATION.json')
    if not qualification.get('offline_passed') or not qualification.get('full_review_complete'):
        raise ValueError('Existing helpers lack offline qualification')
    for name, digest in qualification['reviewed_sha256'].items():
        if sha(HELPERS/name) != digest:raise ValueError('Qualified helper changed:'+name)
    for path, digest in ((PRESERVER, PRESERVER_PIN), (BINDING, BINDING_PIN)):
        if sha(path) != digest:raise ValueError('Pinned native/preservation helper changed')
    pins = {str((HELPERS/name).relative_to(ROOT)):digest
            for name, digest in qualification['reviewed_sha256'].items()}
    import native_lifecycle
    native_lifecycle.bindings()
    pins[str((HERE/'native_lifecycle.py').relative_to(ROOT))] = sha(HERE/'native_lifecycle.py')
    pins.update({str((native_lifecycle.REPAIR/name).relative_to(ROOT)):digest
                 for name,digest in native_lifecycle.PINS.items()})
    return pins


def owner(expected):
    state = read(ROOT/'_CLAUDE_OUTPUT/skyrimnet-work-status.json')
    if any(state.get(key) != expected for key in ('active_shared_config_owner','active_live_test_owner')):
        raise ValueError('Shared runtime is missing or owned by another session')


def cold(expected):
    owner(expected)
    from session_driver import headless
    status = headless().status()
    if status['active'] or not status['normal_vr']['ready']:
        raise ValueError('Restored VR required')
    from recovery import VR_NAMES_LOWER
    if any(p['ProcessName'].casefold() in VR_NAMES_LOWER for p in status['processes']):
        raise ValueError('Another game/VR process is present')
    return status


def context(restoring=False):
    c = module(PRESERVER, 'gateway_preservation')
    c.HERE = FOLDER;c.PRIVATE = FOLDER/'private/runtime-before'
    c.WORK = RUN/'loader/baseline';c.OWNER = OWNER
    c.TREES = [*c.TREES, ROOT/'Data/SSSOConf']
    from reference_adapter import ReferenceAdapter
    ref = FOLDER/'reference-manifest.json' if restoring else REFERENCE/'runtime-preservation.json'
    store = ReferenceAdapter(c, ref, REFERENCE/'private/runtime-before', REFERENCE_PIN,
                             verify_objects=not restoring)
    store.bind()
    return c, store


def freeze():
    pins = sources()
    pins.update({str(path.relative_to(ROOT)):sha(path) for path in
                 (PRESERVER, BINDING, Path(__file__), HERE/'reference_adapter.py', HERE/'native_contract_probe.py',
                  ROOT/'_CLAUDE_OUTPUT/skyrim-souls-vr-2026-10-24/baseline_readiness.py',
                  HERE/'stage/tools/skyrimnet-output-guard/native/start-check.hpp')})
    for path in (RUN/'pair-request.json',RUN/'literal-pair.json'):
        pins[str(path.relative_to(ROOT))]=sha(path)
    write(RUN/'inputs.json', pins)


def checked():
    for name, digest in read(RUN/'inputs.json').items():
        if sha(ROOT/name) != digest:raise ValueError('Frozen input changed:'+name)


def prepare():
    checked();status = cold(None)
    c, store = context();store.preflight()
    store.require_empty_controller_sources()
    if FOLDER.exists():raise ValueError('Fresh engine evidence directory required')
    FOLDER.mkdir(parents=True)
    from reference_adapter import bind_manifest
    bind_manifest(REFERENCE/'runtime-preservation.json', FOLDER/'reference-manifest.json', REFERENCE_PIN)
    # The original controller claims before publishing and retains its manifest.
    c.prepare()
    from importlib import import_module
    sys.path.insert(0, str(ROOT/'_CLAUDE_OUTPUT/output-guard/guardian/native-feasibility-2026-10-26'))
    isolation = import_module('isolation')
    names=('SkyrimNet.yaml','Agents.yaml','NpcThoughts.yaml','OmniSight.yaml',
           'plugins/IntelEngine/settings.yaml','Memory.yaml','Events.yaml')
    current={n:(c.LIVE/'config'/n).read_bytes() for n in names}
    for name, raw in isolation.prepare(current).items():
        target=c.LIVE/'config'/name
        if target.read_bytes()!=current[name]:raise ValueError('Concurrent profile change')
        temp=target.with_suffix(target.suffix+'.gateway.tmp');temp.write_bytes(raw);temp.replace(target)
    request=read(RUN/'pair-request.json')
    source=Path(request['source'])
    from metadata_report import inventory
    before=inventory(source.parent)
    external=[*source.parent.parent.glob('*.ini'),*(Path.home()/'AppData/Local/Skyrim VR').glob('*.txt')]
    rows=[dict(path=str(p),sha256=sha(p),bytes_base64=base64.b64encode(p.read_bytes()).decode('ascii'))
          for p in external if p.is_file()]
    write(FOLDER/'before-pair.json',dict(inventory=before,external=rows,normal_vr=status))
    controllers={name:base64.b64encode((CONTROL/name).read_bytes()).decode('ascii')
                 if (CONTROL/name).exists() else None for name in CONTROL_NAMES}
    write(FOLDER/'controller-before.json',controllers)


def same_pair(value, request):
    return all(isinstance(value.get(k), str) and
               Path(value[k]).resolve() == Path(request[k]).resolve()
               for k in ('source', 'test'))


def preflight():
    checked();cold(OWNER)
    c,store=context();request=read(RUN/'pair-request.json');literal=read(RUN/'literal-pair.json')
    prepared=read(CONTROL/'prepared-pair.json')
    if not same_pair(prepared, request):raise ValueError('Wrong prepared pair')
    write(RUN/'loader/preparation/prepared-pair.json',prepared)
    source=Path(request['source']);before=read(FOLDER/'before-pair.json')
    from metadata_report import inventory
    preserved=inventory(source.parent,tuple(Path(literal[k]).name for k in ('test','test_companion')))
    if any(preserved[key]!=before['inventory'][key] for key in ('count','metadata_sha256')):
        raise ValueError('Original entries changed during pair preparation')
    names=('SkyrimNet.yaml','Agents.yaml','NpcThoughts.yaml','OmniSight.yaml',
           'plugins/IntelEngine/settings.yaml','Memory.yaml','Events.yaml')
    if DESKTOP not in ('current','background'):raise ValueError('Explicit desktop required')
    write(FOLDER/'preflight.json',dict(prelaunch_no_game=True,desktop=DESKTOP,
          save_inventory=inventory(source.parent),external=before['external'],
          profile_sha256={n:sha(c.LIVE/'config'/n) for n in names},
          preservation_sha256=sha(FOLDER/'runtime-preservation.json')))


def run():
    checked();cold(OWNER)
    if type(read(RUN/'launch-approval.json').get('launches')) is not int:
        raise ValueError('Exact one-launch approval required')
    approval=read(RUN/'launch-approval.json')
    if (approval.get('source')!='user chat' or approval.get('launches')!=1
            or DESKTOP not in ('current','background')
            or approval.get('desktop')!=DESKTOP or approval.get('game')!='Skyrim VR'):
        raise ValueError('Exact one-launch approval required')
    preflight=read(FOLDER/'preflight.json')
    for name,digest in preflight['profile_sha256'].items():
        if sha(ROOT/'Data/SKSE/Plugins/SkyrimNet/config'/name)!=digest:raise ValueError('Profile drift')
    write(RUN/'launch-consumed.json',dict(at=datetime.now(timezone.utc).isoformat(),approval_sha256=sha(RUN/'launch-approval.json')))
    from session_driver import headless
    import native_lifecycle
    native_lifecycle.run(headless(),FOLDER,DESKTOP,OWNER)


def adopt_and_ready():
    checked();owner(OWNER)
    from session_driver import adopt, Session
    readiness=module(ROOT/'_CLAUDE_OUTPUT/skyrim-souls-vr-2026-10-24/baseline_readiness.py','gateway_readiness')
    adopt('baseline')
    session=Session('baseline');session.negotiate();rows=[]
    proof=readiness.wait_ready(session, rows.append)
    proof.update(owned_identity=session.owned,ready_wall_time=time.time(),observations=rows)
    write(FOLDER/'readiness.json',proof)
    readiness.require_ready(proof,session.owned)
    # Only publish exact-process JSON. The caller invokes the pinned loader
    # directly; this wrapper never prepares or dispatches a named load.
    prepared=read(CONTROL/'prepared-pair.json');request=read(RUN/'pair-request.json')
    if not same_pair(prepared, request):raise ValueError('Wrong controller pair')
    temp=CONTROL/'owned-session.gateway.tmp'
    temp.write_text(json.dumps(session.owned),encoding='utf-8');temp.replace(CONTROL/'owned-session.json')
    write(FOLDER/'load-ready.json',dict(owned_identity=session.owned,ready_wall_time=time.time()))


def stop():
    from session_driver import headless
    import native_lifecycle
    print(json.dumps(native_lifecycle.stop(headless(),FOLDER,OWNER)))


def restore_controller_metadata():
    original=read(FOLDER/'controller-before.json')
    request=read(RUN/'pair-request.json')
    owned_path=RUN/'loader/baseline/owned-session.json'
    pid=read(owned_path)['Id'] if owned_path.exists() else None
    changes=[]
    for name in CONTROL_NAMES:
        target=CONTROL/name
        current=target.read_bytes() if target.exists() else None
        previous=base64.b64decode(original[name]) if original[name] is not None else None
        if current==previous:continue
        if current is not None:
            value=json.loads(current)
            if name=='prepared-pair.json':valid=same_pair(value, request)
            elif name=='owned-session.json':valid=pid is not None and value.get('Id')==pid
            elif name=='load-dispatch.json':valid=pid is not None and value.get('pid')==pid
            else:valid=pid is not None and value.get('health',{}).get('pid')==pid
            if not valid:raise ValueError('Foreign controller metadata:'+name)
        changes.append((target,current,previous))
    for target,current,previous in changes:
        if current is not None:
            archive=FOLDER/'controller-after'/target.name
            archive.parent.mkdir(parents=True,exist_ok=True)
            with archive.open('xb') as out:out.write(current)
            if archive.read_bytes()!=current:raise ValueError('Controller archive mismatch')
        if previous is None:
            if target.exists():target.unlink()  # Exact controller JSON only; retained above.
        else:
            temp=target.with_suffix('.gateway.tmp');temp.write_bytes(previous);temp.replace(target)
        if (target.read_bytes() if target.exists() else None)!=previous:raise ValueError('Controller restoration mismatch')


def restore():
    cold(OWNER)
    c,store=context(restoring=True);store.prepare_restore()
    new=store.park_new_outputs()
    restore_controller_metadata()
    c.restore()
    write(FOLDER/'new-outputs-retained.json',new)
    from metadata_report import inventory
    before=read(FOLDER/'preflight.json');pair=read(RUN/'loader/preparation/prepared-pair.json')
    assert inventory(Path(pair['source']).parent)==before['save_inventory'],'Save metadata changed'
    for row in before['external']:assert sha(row['path'])==row['sha256'],'External settings changed'
    for row in read(FOLDER/'runtime-preservation.json')['files']:assert sha(ROOT/row['path'])==row['sha256']
    literal=read(RUN/'literal-pair.json')
    for path,digest in ((literal['source'],pair['original_hashes'][0]),
                        (literal['source_companion'],pair['original_hashes'][1]),
                        (literal['test'],pair['test_sha256']),
                        (literal['test_companion'],pair['test_skse_sha256'])):
        assert sha(path)==digest,'Pair changed'
    write(FOLDER/'restoration-verified.json',dict(ok=True,normal_vr=cold(None),
          protected_files=len(read(FOLDER/'runtime-preservation.json')['files']),save_inventory=before['save_inventory']))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('freeze','prepare','preflight','run','ready','stop','restore'))
    args=parser.parse_args()
    dict(freeze=freeze,prepare=prepare,preflight=preflight,run=run,ready=adopt_and_ready,stop=stop,restore=restore)[args.action]()
