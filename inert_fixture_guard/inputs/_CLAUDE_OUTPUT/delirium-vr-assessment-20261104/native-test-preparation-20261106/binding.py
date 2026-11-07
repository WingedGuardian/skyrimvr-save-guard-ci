"""Offline composition primitives, not a launcher or a live replacement adapter."""
from pathlib import Path
import hashlib,re
from functools import wraps
from windows_identity import ProcessLease,Refused,canonical,filetime_from_iso,strict_json

READER_SHA='685bccf154b03c33ce6ca802a4f91ae4af5d3ca6b856ed65f149b17a9fd8d72c'
SOURCE='4469617e865a7b2f8c44e3aa82d44371bf0dd3783161ce5f4e920e25d4578e82'
DLL='e39acb180ff364a93963efe1615f37751b8c5b9ec520317fe8442e84b6f8abe9'

def require(value,message):
    if not value:raise Refused(message)

def refuse_malformed(fn):
    @wraps(fn)
    def checked(*args,**kwargs):
        try:return fn(*args,**kwargs)
        except (KeyError,TypeError,AttributeError,ValueError,OSError,OverflowError) as error:
            raise Refused('Malformed/unavailable evidence: '+str(error)) from error
    return checked

def reader():
    path=Path(__file__).resolve().parent.parent/'diagnostic-preparation-20261106/read_capture.py'
    raw=path.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==READER_SHA,'Qualified reader changed')
    module={'__name__':'qualified_capture_reader','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),module)
    return module['analyze']

@refuse_malformed
def startup_identity(event,manifest,*,session,creator_pid,desktop,executable):
    """Validate records from an OWNED runner. Record provenance is caller-owned.

    Does not prove lineage/desktop isolation or that caller owns a real runner.
    Actual process generation is independently checked by CaptureBinding.
    """
    require(isinstance(event,dict) and set(event)=={'managed_session_started'},'Startup event schema')
    row=event['managed_session_started']
    require(row.get('started') is True and row.get('save_loaded') is False,'Not menu startup')
    require(isinstance(session,str) and bool(re.fullmatch(r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z',session)),'Session identity')
    require(type(creator_pid) is int and creator_pid>0,'Runner identity')
    require(row.get('session')==session==manifest.get('id'),'Wrong session')
    require(manifest.get('creator_pid')==creator_pid,'Wrong runner')
    require(desktop in ('current','background') and manifest.get('desktop_mode')==desktop,'Wrong desktop mode')
    require(manifest.get('interaction')==('background-devbench' if desktop=='background' else 'desktop-devbench'),'Wrong interaction')
    require(manifest.get('frontend_started') is False,'Unexpected frontend')
    health=row.get('health',{})
    require(health==manifest.get('startup_health') and health.get('ok') is True,'Health mismatch')
    require(health.get('lastLifecycle')=='dataLoaded' and type(health.get('frame')) is int and health['frame']>100,'Not ready')
    games=[p for p in manifest.get('processes',[]) if p.get('ProcessName')=='SkyrimVR']
    require(len(games)==1,'Ambiguous/missing game process')
    game=games[0]
    require(type(game.get('Id')) is int and game['Id']>0 and game['Id']==health.get('pid'),'Health PID mismatch')
    require(canonical(game['Path'])==canonical(executable),'Wrong executable')
    return {'pid':game['Id'],'birth':filetime_from_iso(game['StartTime']),'path':canonical(executable)}

class CaptureBinding:
    """A held process generation plus one immutable arm request; never writes it.

    Caller owns lease lifetime. Caller must independently establish owned-runner
    provenance and actual arm publication; this class proves neither.
    """
    @refuse_malformed
    def __init__(self,lease,identity,nonce):
        require(type(lease) is ProcessLease,'Actual Windows process lease required')
        require(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'Nonce')
        self.lease=lease;self.identity=dict(lease.verify(identity));self.nonce=nonce
        self._analyze=reader()
        self._prefix=f'{SOURCE} {DLL} {self.identity["pid"]} {self.identity["birth"]} {nonce}'
        self.arm=('ARM '+self._prefix+'\n').encode('ascii')
    @refuse_malformed
    def accept(self,capture,seal):
        self.lease.verify(self.identity)
        require(type(capture) is bytes and type(seal) is bytes,'Raw capture bytes required')
        require(len(capture)<=1048576 and len(seal)<=1024,'Capture bounds')
        text=capture.decode('ascii');completion=seal.decode('ascii')
        header=text.split('\n',1)[0].split(' ')
        require(len(header)==7 and ' '.join(header[:6])=='H '+self._prefix,'Foreign/stale process or arm')
        result=self._analyze(text,SOURCE,DLL,completion)
        self.lease.verify(self.identity)
        result.update(process_generation_independently_bound=True,
                      launch_identity_independently_bound=False,
                      arm_publication_independently_proved=False)
        return result

@refuse_malformed
def context_records(expected,active,marker,manifest_raw,manifest_hash,prepared,slots):
    """Check supplied snapshots only; no lock or mutation authority is granted."""
    owner,run=expected['owner'],expected['run']
    require(isinstance(owner,str) and owner and isinstance(run,str) and re.fullmatch(r'[A-Za-z0-9_-]+',run),'Owner/run')
    paths={k:canonical(expected[k]) for k in ('game','state','store')}
    game=Path(paths['game'])
    require(all(not Path(paths[k]).is_relative_to(game) for k in ('state','store')),'State/store inside game')
    digest=hashlib.sha256(manifest_raw).hexdigest()
    require(manifest_hash==digest.encode('ascii'),'Manifest digest')
    manifest=strict_json(manifest_raw)
    require(manifest.get('schema')==1,'Context schema')
    for record in (active,marker,manifest,prepared):
        require(record.get('owner')==owner and record.get('run')==run,'Context owner/run mismatch')
    require(active.get('phase')=='prepared','Context not prepared')
    for record in (active,manifest):
        require(all(canonical(record[k])==paths[k] for k in ('game','store')),'Context game/store mismatch')
        require(record.get('slots')==expected['slots'],'Slot contract mismatch')
    require(canonical(marker['state'])==paths['state'],'Context state mismatch')
    require(prepared.get('manifest_sha256')==digest,'Prepare receipt mismatch')
    keys=expected['slots']['keys']
    require(bool(keys) and len(set(keys))==len(keys),'Empty/duplicate slot contract')
    require(all(slots.get(k)==owner for k in keys),'Exact context ownership lost')
    return {'records_consistent':True,'manifest_sha256':digest,'mutation_authorized':False}

def restore_order(require_cold,require_owner,restore_dll,verify_dll,restore_context):
    """Ordering seam only. Callback qualification and recovery are separate.

    No finally-release: on any failure ownership remains for explicit recovery.
    """
    require(require_cold() is True,'Cold proof failed')
    require(require_owner() is True,'Ownership proof failed')
    restore_dll()
    require(verify_dll() is True,'DLL restoration not verified')
    require(require_cold() is True,'Cold proof lost before context restoration')
    require(require_owner() is True,'Ownership lost before context restoration')
    return restore_context()
