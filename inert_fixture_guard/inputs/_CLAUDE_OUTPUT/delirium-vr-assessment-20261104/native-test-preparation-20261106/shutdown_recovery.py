"""Offline coordinator candidate. No launch, HTTP transport, slots or Data writes.

Callbacks must be independently qualified before native use. A durable intent is
never replayable: submission uncertainty is retained even across a new instance.
"""
from pathlib import Path
import json,os,re,time,uuid
from windows_identity import Refused,wait,strict_json
from binding import require

NATIVE_INTEGRATION_QUALIFIED=False
FIXTURES=Path(__file__).resolve().parent/'handoff-fixtures'

def plain(path):
    for entry in [*reversed(path.parents),path]:
        info=os.lstat(entry)
        require(not (info.st_file_attributes&0x400),'Linked journal path')
    if path.is_file():require(path.stat().st_nlink==1,'Multi-link journal')

def durable_new(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())

class Shutdown:
    """External callback MODEL only: native launcher has a separate quit sender.

    Native wiring is rejected pending one owner-side shared QuitAuthority for
    requested exit and launcher finally/error cleanup. Never use request() as
    the native transport owner.
    """
    def __init__(self,folder,handoff,process):
        self.folder=Path(folder).absolute();self.handoff=handoff;self.process=process
        require('..' not in self.folder.parts and self.folder.resolve()==self.folder,'Canonical task fixture path required')
        require(self.folder.is_relative_to(FIXTURES) and self.folder!=FIXTURES,'Task fixture space only')
        plain(self.folder)
        require(self.folder.is_dir(),'Existing owned journal directory required')
        self.identity=dict(handoff.identity)
        self.owner=handoff.owner.inspect()
        require(self.owner['pid']==process.pid and process.poll() is None,'Owned runner mismatch')
        handoff.target.verify(self.identity)
        self.contract={'schema':1,'target':self.identity,'owner':self.owner,
            'run':str(self.folder),'nonce':handoff.event['managed_session_started']['retained_identity']['nonce'],
            'launcher_source':handoff.event['managed_session_started']['retained_identity']['launcher_sha256']}
    def _event(self,name,**data):
        durable_new(self.folder/name,dict(self.contract,**data))
        self._read(name)
    def _read(self,name):
        path=self.folder/name;plain(path)
        require(path.is_file() and 0<path.stat().st_size<=8192,'Missing/oversized journal record')
        value=strict_json(path.read_bytes())
        require(type(value) is dict and all(value.get(k)==v for k,v in self.contract.items()),'Foreign/corrupt journal contract')
        schemas={'quit-intent.json':{'intent_id':str},'quit-submitted.json':{'accepted':bool},
            'quit-uncertain.json':{'replay_allowed':bool},'processes-settled.json':{'exit_code':int,'normal_vr_verified':bool},
            'restore-intent.json':{},'restore-complete.json':{'callback_contract_passed':bool,'native_acceptance':bool}}
        fields=schemas[name]
        require(set(value)==set(self.contract)|set(fields),'Journal event schema')
        require(all(type(value[k]) is type(v) for k,v in self.contract.items()) and all(type(value[k]) is t for k,t in fields.items()),'Journal scalar types')
        if name=='quit-intent.json':require(re.fullmatch('[0-9a-f]{32}',value['intent_id']),'Intent identifier')
        return value
    def request(self,submit):
        # Exclusive create is the commitment to one attempt, even if it crashes
        # before submit. No retry/deletion path exists in this coordinator.
        self.handoff.owner.verify(self.owner);self.handoff.target.verify(self.identity)
        self._event('quit-intent.json',intent_id=uuid.uuid4().hex)
        try:
            self.handoff.owner.verify(self.owner);self.handoff.target.verify(self.identity)
            response=submit()
            require(response is True,'Submission result is uncertain')
            self._event('quit-submitted.json',accepted=True)
        except BaseException:
            self._event('quit-uncertain.json',replay_allowed=False)
            raise
    def settle(self,timeout=60):
        require(type(timeout) in (int,float) and 0<timeout<=120,'Bounded settlement timeout')
        self._read('quit-intent.json')
        deadline=time.monotonic()+timeout
        while True:
            handles=(self.handoff.target.handle,self.handoff.owner.handle)
            require(all(handles),'Retained process handles required')
            states=[wait(handle,0) for handle in handles]
            require(all(state in (0,0x102) for state in states),'Process settlement unknown')
            if states==[0,0]:break
            if time.monotonic()>=deadline:raise Refused('Target/owner still live; retain recovery state')
            time.sleep(.01)
        require(self.process.wait(timeout=1)==0,'Managed owner failed; recovery review required')
        # This proves process settlement only, not normal VR restoration.
        self._event('processes-settled.json',exit_code=0,normal_vr_verified=False)
    def restore(self,*,cold,owner,normal_vr,restore_dll,verify_dll,restore_context):
        require(self._read('processes-settled.json').get('exit_code')==0,'Unsettled shutdown')
        # Revalidate actual handles; receipts alone are not liveness evidence.
        require(all(h and wait(h,0)==0 for h in (self.handoff.target.handle,self.handoff.owner.handle)),'Process not settled')
        require(self.process.poll()==0,'Owner exit not clean')
        require(not (self.folder/'restore-intent.json').exists(),'Restoration already attempted; explicit recovery required')
        require(cold() is True and owner() is True and normal_vr() is True,'Restoration gates failed')
        self._event('restore-intent.json')
        restore_dll()
        require(verify_dll() is True,'DLL restoration not verified; keep context ownership')
        require(cold() is True and owner() is True and normal_vr() is True,'Restoration gates changed')
        require(restore_context() is True,'Context restoration not verified')
        self._event('restore-complete.json',callback_contract_passed=True,native_acceptance=False)
