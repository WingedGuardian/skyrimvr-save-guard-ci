"""Real pinned cleanup/finally through an inert transport; no HTTP/game calls."""
from pathlib import Path
from contextlib import contextmanager,redirect_stdout
from io import BytesIO,StringIO
from datetime import datetime,timezone
import json,os,subprocess,sys,threading,unittest,uuid
from owner_quit import QuitAuthority,install_transport_gate,RequestedExitReader
from startup_handoff import load_pinned_launcher
from windows_identity import ProcessLease,iso_from_filetime,Refused,sha

HERE=Path(__file__).resolve().parent;RUN=HERE/'handoff-fixtures'/('owner-'+uuid.uuid4().hex);RUN.mkdir(parents=True)
SETTLED=[]
@contextmanager
def target():
    folder=RUN/uuid.uuid4().hex;folder.mkdir()
    session=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    p=subprocess.Popen([sys.executable,'-B','-c','import sys;sys.stdin.buffer.read()'],cwd=folder,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    lease=None;authority=None
    try:
        lease=ProcessLease(p.pid);identity=lease.inspect()
        authority=QuitAuthority(folder,lease,identity,uuid.uuid4().hex,session)
        yield folder,p,identity,authority
    finally:
        if authority:authority.close()
        if lease:lease.close()
        p.stdin.close();forced=False
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=5);forced=True
        SETTLED.append({'pid':p.pid,'exit':p.returncode,'forced':forced});assert p.returncode==0 and not forced

class Response(BytesIO):pass
class Tests(unittest.TestCase):
    def test_requested_exit_and_finally_cleanup_share_original_post_gate(self):
        with target() as (folder,p,identity,authority):
            scope=load_pinned_launcher(HERE.parents[2]/'tools/vr-headless.py');writes=[];event=threading.Event()
            original_urlopen=scope['urllib'].request.urlopen
            def opener(request,timeout):
                if type(request) is str:return Response(json.dumps({'pid':p.pid}).encode())
                writes.append(request.data);raise TimeoutError('ambiguous native-model delivery')
            install_transport_gate(scope,authority,opener)
            row={'Id':p.pid,'ProcessName':'SkyrimVR','Path':identity['path'],'StartTime':iso_from_filetime(identity['birth'])}
            manifest={'creator_pid':os.getpid(),'interaction':'background-devbench','steam_policy':'keep-running','processes':[row]}
            reader=RequestedExitReader(lambda:[row],event)
            class Inert(scope['Lifecycle']):
                def __init__(self):super().__init__(root=folder,steam=folder,local=folder,process_reader=reader);self.active=False
                def current(self):return folder/'manifest.json',manifest if self.active else None
                def on(self,*args):self.active=True
                def launch(self,**kwargs):event.set();return {'fixture':True}
                def stop(self):return self._stop_owned()  # Actual pinned HTTP cleanup body.
            life=Inert()
            with redirect_stdout(StringIO()),self.assertRaises(TimeoutError):life.run()
            self.assertTrue(reader.consumed)
            with self.assertRaisesRegex(Refused,'already attempted'):life.stop()
            self.assertEqual(len(writes),1)
            import urllib.request
            self.assertIs(urllib.request.urlopen,original_urlopen)
    def test_returned_transport_is_not_execution_and_never_replays(self):
        with target() as (folder,p,identity,authority):
            self.assertEqual(authority.attempt(lambda:'transport response'),'transport response')
            record=json.loads((folder/'owner-quit-returned.json').read_bytes());self.assertFalse(record['native_execution_proved'])
            with self.assertRaisesRegex(Refused,'already attempted'):authority.attempt(lambda:None)
            another=QuitAuthority(folder,authority.target,identity,authority.contract['nonce'],authority.contract['session'])
            try:
                with self.assertRaises(FileExistsError):another.attempt(lambda:None)
            finally:another.close()
    def test_corrupt_preexisting_intent_refuses_before_transport(self):
        with target() as (folder,p,identity,authority):
            (folder/'owner-quit-intent.json').write_bytes(b'{');calls=[]
            with self.assertRaises(FileExistsError):authority.attempt(lambda:calls.append(1))
            self.assertEqual(calls,[])
    def test_other_thread_cannot_submit_and_unknown_writes_refuse(self):
        with target() as (folder,p,identity,authority):
            errors=[]
            def other():
                try:authority.attempt(lambda:True)
                except Refused as error:errors.append(str(error))
            t=threading.Thread(target=other);t.start();t.join(timeout=2);self.assertFalse(t.is_alive());self.assertEqual(len(errors),1)
            scope=load_pinned_launcher(HERE.parents[2]/'tools/vr-headless.py');calls=[]
            install_transport_gate(scope,authority,lambda *args,**kwargs:calls.append(1))
            request=scope['urllib'].request.Request('http://127.0.0.1:8921/api/tool/console',data=b'{"action":"exec","command":"save"}')
            with self.assertRaises(Refused):scope['urllib'].request.urlopen(request,timeout=1)
            with self.assertRaises(Refused):scope['urllib'].request.urlopen('http://127.0.0.1:8921/api/tool/console',timeout=1)
            request=scope['urllib'].request.Request('http://127.0.0.1:8921/api/health',data=b'{"action":"exec","command":"qqq"}')
            with self.assertRaises(Refused):scope['urllib'].request.urlopen(request,timeout=1)
            self.assertEqual(calls,[])

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    receipt={'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'sources':{n:sha(HERE/n) for n in ('owner_quit.py','test_owner_quit.py','shutdown_recovery.py','startup_handoff.py','windows_identity.py')},'settled':SETTLED,'transport':'inert callback; no network','native_acceptance':False,'limit':'Actual pinned run/finally/_stop_owned POST selection, fixture startup/inventory, deliberate timeout before helper cleanup; no real teardown or HTTP qualification.'}
    (RUN/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print('Receipt:',RUN/'receipt.json')
    sys.exit(0 if result.wasSuccessful() else 1)
