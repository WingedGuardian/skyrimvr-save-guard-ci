"""Task-owned offline handoff candidate. No manifest reads or launch entry point.

Not a live controller: cold ownership, shutdown, profile and publication approval
are separate gates. Only a caller-owned, source-qualified runner pipe is eligible.
"""
import ctypes,hashlib,io,msvcrt,os,re,subprocess,time
from ctypes import wintypes as wt
from datetime import datetime,timezone
from pathlib import Path
from binding import require,refuse_malformed
from windows_identity import ProcessLease,Refused,canonical,filetime_from_iso,strict_json,api

LAUNCHER_SHA='c00fda353828460b09b177adc924d4bc7995562d81d34856abfdb169f036618a'
peek=api('PeekNamedPipe',[wt.HANDLE,ctypes.c_void_p,wt.DWORD,ctypes.c_void_p,ctypes.POINTER(wt.DWORD),ctypes.c_void_p],wt.BOOL)
# Published handles are deliberately process-lifetime resources. The qualified
# runner must exit after its bounded managed run; Windows closes them at exit.
# No callable clears this collection or closes its target handles.
_PUBLISHED_HANDLES=[]

def load_pinned_launcher(path):
    """Load exact installed source; never invoke its CLI or lifecycle here."""
    raw=Path(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest()==LAUNCHER_SHA,'Launcher source drift')
    scope={'__name__':'qualified_headless_source','__file__':str(Path(path).resolve())}
    exec(compile(raw,str(path),'exec'),scope)
    return scope

@refuse_malformed
def session_time(session):
    require(isinstance(session,str) and re.fullmatch(r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z',session),'Session format')
    stamp=datetime.strptime(session,'%Y%m%dT%H%M%S.%fZ').replace(tzinfo=timezone.utc)
    return filetime_from_iso(stamp.strftime('%Y-%m-%dT%H:%M:%S.%f')+'0Z')

class RetainedInventory:
    """Retain before returning the first target row; never rebind or release early.

    Observation failures latch separately and preserve original inventory behavior.
    Once published, target retention lasts to owner process exit, even after close.
    No explicit handoff ACK is needed; controller refuses a dead publishing owner.
    """
    def __init__(self,reader,target_image):
        self.reader=reader;self.image=canonical(target_image)
        self.owner=ProcessLease(os.getpid())
        try:self.owner_identity=self.owner.inspect()
        except BaseException:self.owner.close();raise
        self.target=None;self.identity=None;self.failure=None;self.closed=False;self.published=False
    def __call__(self):
        try:rows=self.reader()
        except Exception as error:
            self.failure=type(error).__name__+': '+str(error)
            raise  # Preserve original inventory errors, and permanently poison attestation.
        if self.closed or self.failure:return rows
        try:
            games=[p for p in rows if p.get('ProcessName')=='SkyrimVR']
            require(len(games)<=1,'Ambiguous target inventory')
            if not games:return rows  # Cleanup inventories may legitimately omit it.
            row=games[0]
            identity={'pid':row['Id'],'birth':filetime_from_iso(row['StartTime']),'path':canonical(row['Path'])}
            require(identity['path']==self.image,'Foreign target image')
            require(identity['birth']>=self.owner_identity['birth'],'Target predates owned runner')
            if self.target is None:
                lease=ProcessLease(identity['pid'])
                try:lease.verify(identity)
                except BaseException:lease.close();raise
                self.target=lease;self.identity=identity
            else:
                require(identity==self.identity,'Target generation changed; no rebind')
                self.target.verify(self.identity)
        except (Refused,KeyError,TypeError,ValueError,AttributeError,OSError) as error:
            self.failure=type(error).__name__+': '+str(error)
        return rows
    def attest(self,startup,nonce,desktop):
        try:
            require(not self.closed and not self.failure and not self.published,'Inventory retention unavailable/already published')
            require(self.target is not None,'No retained target')
            self.owner.verify(self.owner_identity);self.target.verify(self.identity)
            require(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce),'Nonce')
            require(desktop in ('current','background'),'Desktop request')
            require(startup['started'] is True and startup['save_loaded'] is False,'Not menu startup')
            health=startup['health']
            require(health['ok'] is True and type(health['pid']) is int and health['pid']==self.identity['pid'],'Health identity')
            require(health['lastLifecycle']=='dataLoaded' and type(health['frame']) is int and health['frame']>100,'Startup health')
            require(self.owner_identity['birth']<=session_time(startup['session'])<=self.identity['birth'],'Stale session interval')
            _PUBLISHED_HANDLES.append(self.target);self.published=True
            return {'ok':True,'nonce':nonce,'desktop_requested':desktop,'owner':dict(self.owner_identity),
                    'target':dict(self.identity),'launcher_sha256':LAUNCHER_SHA}
        except (Refused,KeyError,TypeError,ValueError,AttributeError,OSError) as error:
            self.failure=type(error).__name__+': '+str(error)
            return {'ok':False,'reason':self.failure}
    def close(self):
        self.closed=True
        if self.target and not self.published:self.target.close()
        self.owner.close()

def retained_lifecycle(base):
    """Task-local subclass: supported reader injection plus additive startup data."""
    class RetainedLifecycle(base):
        def __init__(self,*args,observer,nonce,**kwargs):
            self.identity_observer=observer;self.identity_nonce=nonce
            super().__init__(*args,process_reader=observer,**kwargs)
        def launch(self,interactive=False,desktop='background'):
            require(interactive is False,'Interactive startup is outside this adapter')
            startup=super().launch(interactive,desktop)
            return dict(startup,retained_identity=self.identity_observer.attest(startup,self.identity_nonce,desktop))
    return RetainedLifecycle

def read_line(pipe,deadline,limit=8192):
    """One bounded line from an exclusive owned pipe; no reader thread to leak."""
    require(type(limit) is int and 0<limit<=8192,'Pipe bound')
    handle=msvcrt.get_osfhandle(pipe.fileno());data=bytearray()
    while time.monotonic()<deadline:
        count=wt.DWORD()
        if not peek(handle,None,0,None,ctypes.byref(count),None):raise Refused('Owned pipe closed/unreadable')
        if count.value:
            byte=os.read(pipe.fileno(),1)
            require(bool(byte),'Owned pipe EOF')
            data.extend(byte)
            require(len(data)<=limit,'Startup line exceeds bound')
            if byte==b'\n':return bytes(data)
        else:time.sleep(.01)
    raise Refused('Startup message deadline expired')

class Handoff:
    """Retains consumer handles. Caller owns runner invocation/pipe provenance.

    This does not establish cold ownership, engine lineage, desktop isolation,
    arm publication or native compatibility. No process is launched or stopped.
    """
    @refuse_malformed
    def __init__(self,process,*,nonce,runner_image,target_image,desktop,timeout=5):
        self.owner=None;self.target=None;self.identity=None;self.event=None
        try:
            require(type(process) is subprocess.Popen and process.stdout is not None,'Owned binary Popen pipe required')
            require(not isinstance(process.stdout,io.TextIOBase),'Binary exclusive pipe required')
            require(type(timeout) in (int,float) and 0<timeout<=30,'Bounded timeout')
            require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'Expected nonce')
            require(process.poll() is None,'Runner already exited')
            self.owner=ProcessLease(process.pid);owner=self.owner.inspect()
            require(owner['path']==canonical(runner_image),'Unexpected runner image')
            raw=read_line(process.stdout,time.monotonic()+timeout)
            event=strict_json(raw);require(set(event)=={'managed_session_started'},'Unexpected event envelope')
            startup=event['managed_session_started'];att=startup['retained_identity']
            require(att['ok'] is True and att['nonce']==nonce,'Unqualified/foreign publication')
            require(att['owner']==owner,'Foreign runner generation')
            require(desktop in ('current','background') and att['desktop_requested']==desktop,'Desktop request mismatch')
            require(att['launcher_sha256']==LAUNCHER_SHA,'Publisher launcher source mismatch')
            identity=att['target'];require(canonical(identity['path'])==canonical(target_image),'Unexpected target image')
            require(type(identity['birth']) is int and type(identity['pid']) is int,'Exact target generation')
            require(owner['birth']<=session_time(startup['session'])<=identity['birth'],'Stale session interval')
            health=startup['health']
            require(startup['started'] is True and startup['save_loaded'] is False,'Not menu startup')
            require(health['ok'] is True and type(health['pid']) is int and health['pid']==identity['pid'],'Target health mismatch')
            require(health['lastLifecycle']=='dataLoaded' and type(health['frame']) is int and health['frame']>100,'Startup health')
            require(identity['pid']!=owner['pid'],'Runner cannot be target')
            self.target=ProcessLease(identity['pid']);self.target.verify(identity)
            self.owner.verify(owner);require(process.poll() is None,'Runner exited during handoff')
            self.identity=dict(identity);self.event=event
        except BaseException:self.close();raise
    def close(self):
        if self.target:self.target.close()
        if self.owner:self.owner.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
