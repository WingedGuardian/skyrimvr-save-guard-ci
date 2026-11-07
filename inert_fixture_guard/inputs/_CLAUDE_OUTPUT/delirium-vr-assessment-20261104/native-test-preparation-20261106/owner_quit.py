"""Task-local owner-side submission gate candidate; no default native transport.

The caller must source-qualify its owned runner and supplied opener. Tests use
an inert opener. This does not qualify native cleanup or authorize a game run.
"""
from pathlib import Path
from types import SimpleNamespace
import json,os,re,threading,uuid
from binding import require
from startup_handoff import LAUNCHER_SHA,session_time
from shutdown_recovery import durable_new,plain,FIXTURES
from windows_identity import ProcessLease,strict_json

class RequestedExit(RuntimeError):pass

class QuitAuthority:
    def __init__(self,folder,target,identity,nonce,session):
        self.folder=Path(folder).absolute()
        require('..' not in self.folder.parts and self.folder.resolve()==self.folder and self.folder.is_relative_to(FIXTURES),'Task-owned fixture authority only')
        plain(self.folder)
        require(type(target) is ProcessLease and type(identity) is dict,'Actual retained target required')
        require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'Nonce')
        session_time(session)
        self.owner=ProcessLease(os.getpid())
        try:
            self.owner_identity=self.owner.inspect();target.verify(identity)
            require(self.owner_identity['birth']<=session_time(session)<=identity['birth'],'Stale owner session')
        except BaseException:self.owner.close();raise
        self.thread=threading.get_ident();self.target=target;self.identity=dict(identity)
        self.attempted=False
        self.contract={'owner':self.owner_identity,'target':self.identity,'nonce':nonce,'session':session,'source':LAUNCHER_SHA}
    def attempt(self,submit):
        require(os.getpid()==self.owner_identity['pid'] and threading.get_ident()==self.thread,'Owner thread alone submits quit')
        self.owner.verify(self.owner_identity);self.target.verify(self.identity)
        require(not self.attempted,'Owner quit already attempted')
        self.attempted=True
        # Existing, damaged or incomplete intent all deny another attempt.
        durable_new(self.folder/'owner-quit-intent.json',dict(self.contract,intent_id=uuid.uuid4().hex))
        try:
            self.owner.verify(self.owner_identity);self.target.verify(self.identity)
            response=submit()
            durable_new(self.folder/'owner-quit-returned.json',dict(self.contract,transport_returned=True,native_execution_proved=False))
            return response
        except BaseException:
            # Never undo the pre-submit intent, even if evidence writing fails.
            raise
    def close(self):self.owner.close()

def install_transport_gate(scope,authority,opener):
    """Private module facade; never monkeypatch process-wide urllib.

    Covers the pinned launcher's original cleanup POST as well as repeated stop.
    Opener provenance/no-retry/direct-loopback behavior still needs qualification.
    """
    original=scope['urllib'].request
    require('_owner_quit_gate' not in scope,'Owner transport gate already installed')
    require(scope['Lifecycle']._stop_owned.__globals__ is scope,'Private launcher scope required')
    def urlopen(request,timeout=None):
        url=request if type(request) is str else request.full_url
        require(url in ('http://127.0.0.1:8921/api/health','http://127.0.0.1:8921/api/tool/console'),'Unexpected launcher endpoint')
        if type(request) is str:
            require(url.endswith('/api/health'),'Only health GET is qualified')
            return opener(request,timeout=timeout)
        require(url=='http://127.0.0.1:8921/api/tool/console' and request.get_method()=='POST' and strict_json(request.data)=={'action':'exec','command':'qqq'},'Unexpected launcher write')
        return authority.attempt(lambda:opener(request,timeout=timeout))
    # These functions use their own loaded module globals; shared urllib intact.
    scope['urllib']=SimpleNamespace(request=SimpleNamespace(Request=original.Request,urlopen=urlopen))
    scope['_owner_quit_gate']=authority

class RequestedExitReader:
    """Deliver a controller's request on the owner thread at the next inventory.

    Original Lifecycle.run finally performs stop. A consumed request cannot fire
    again while finally itself reads inventory. Caller owns request authentication.
    """
    def __init__(self,reader,event):self.reader=reader;self.event=event;self.consumed=False
    def __call__(self):
        if self.event.is_set() and not self.consumed:
            self.consumed=True;raise RequestedExit('Owned shutdown requested')
        return self.reader()
