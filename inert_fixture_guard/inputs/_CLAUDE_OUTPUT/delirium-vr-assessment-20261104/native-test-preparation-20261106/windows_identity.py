"""Read-only Windows identity/snapshot primitives. No launch, termination or writes."""
from contextlib import contextmanager
from pathlib import Path
import ctypes
from ctypes import wintypes as w
from datetime import datetime,timezone,timedelta
import hashlib,json,os,re

class Refused(RuntimeError): pass
K=ctypes.WinDLL('kernel32',use_last_error=True)
class FileTime(ctypes.Structure):
    _fields_=[('low',w.DWORD),('high',w.DWORD)]
    def integer(self):return (int(self.high)<<32)|int(self.low)
class FileInfo(ctypes.Structure):
    _fields_=[('attributes',w.DWORD),('created',FileTime),('accessed',FileTime),('written',FileTime),
              ('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),('links',w.DWORD),('index_high',w.DWORD),('index_low',w.DWORD)]
def api(name,args,result):
    fn=getattr(K,name);fn.argtypes=args;fn.restype=result;return fn
open_process=api('OpenProcess',[w.DWORD,w.BOOL,w.DWORD],w.HANDLE)
close_handle=api('CloseHandle',[w.HANDLE],w.BOOL)
wait=api('WaitForSingleObject',[w.HANDLE,w.DWORD],w.DWORD)
process_id=api('GetProcessId',[w.HANDLE],w.DWORD)
process_times=api('GetProcessTimes',[w.HANDLE,*([ctypes.POINTER(FileTime)]*4)],w.BOOL)
process_image=api('QueryFullProcessImageNameW',[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)],w.BOOL)
create_file=api('CreateFileW',[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE],w.HANDLE)
file_info=api('GetFileInformationByHandle',[w.HANDLE,ctypes.POINTER(FileInfo)],w.BOOL)
read_file=api('ReadFile',[w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p],w.BOOL)
INVALID=ctypes.c_void_p(-1).value
EPOCH=datetime(1601,1,1,tzinfo=timezone.utc)
def canonical(path):return os.path.normcase(str(Path(path).resolve(strict=True)))
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):h.update(block)
    return h.hexdigest()
def filetime_from_iso(text):
    match=re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d{7})Z',text)
    if not match:raise Refused('Exact UTC round-trip timestamp with seven fractional digits required')
    delta=datetime.strptime(match[1],'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)-EPOCH
    value=(delta.days*86400+delta.seconds)*10000000+int(match[2])
    if not 0<value<2**64:raise Refused('Invalid process birth')
    return value
def iso_from_filetime(value):
    whole,fraction=divmod(value,10000000)
    return (EPOCH+timedelta(seconds=whole)).strftime('%Y-%m-%dT%H:%M:%S')+f'.{fraction:07d}Z'

class ProcessLease:
    """Retains one process object; never reopens a PID during validation."""
    def __init__(self,pid):
        if type(pid) is not int or not 0<pid<2**32:raise Refused('Invalid PID')
        self.pid=pid;self.handle=open_process(0x1000|0x100000,False,pid)
        if not self.handle:raise Refused('Cannot query/synchronize process: '+str(ctypes.get_last_error()))
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def close(self):
        if self.handle:close_handle(self.handle);self.handle=None
    def inspect(self):
        if not self.handle or wait(self.handle,0)!=0x102:raise Refused('Process is not proved alive')
        times=[FileTime() for _ in range(4)]
        if not process_times(self.handle,*[ctypes.byref(x) for x in times]):raise Refused('Process times unavailable')
        buffer=ctypes.create_unicode_buffer(32768);size=w.DWORD(len(buffer))
        if not process_image(self.handle,0,buffer,ctypes.byref(size)) or not size.value:raise Refused('Image path unavailable')
        if process_id(self.handle)!=self.pid or wait(self.handle,0)!=0x102:raise Refused('Process identity/liveness changed')
        return {'pid':self.pid,'birth':times[0].integer(),'path':canonical(buffer.value)}
    def verify(self,expected):
        actual=self.inspect()
        if actual!={'pid':expected['pid'],'birth':expected['birth'],'path':canonical(expected['path'])}:raise Refused('Process generation/path mismatch')
        return actual

def _info(handle):
    value=FileInfo()
    if not file_info(handle,ctypes.byref(value)):raise Refused('File identity unavailable')
    if value.attributes&0x400 or value.links!=1:raise Refused('Reparse/multiple-link snapshot refused')
    return value
def _stable(info):return (info.volume,info.index_high,info.index_low,info.size_high,info.size_low,info.written.integer(),info.attributes)
@contextmanager
def shared_read(path):
    # These share flags do NOT prevent os.replace failures on an open destination.
    # The actual Windows contrast failed; never read an active launcher manifest here.
    handle=create_file(str(Path(path)),0x80000000,7,None,3,0x00200000,None)
    if handle==INVALID or not handle:raise Refused('Snapshot cannot be opened: '+str(ctypes.get_last_error()))
    try:
        _info(handle);yield handle
    finally:close_handle(handle)
def read_handle(handle,limit=1048576):
    before=_info(handle);size=(before.size_high<<32)|before.size_low
    if not 0<size<=limit:raise Refused('Empty/oversized snapshot')
    buffer=ctypes.create_string_buffer(size+1);count=w.DWORD()
    if not read_file(handle,buffer,size+1,ctypes.byref(count),None) or count.value!=size:raise Refused('Incomplete/changing snapshot')
    if _stable(before)!=_stable(_info(handle)):raise Refused('Snapshot changed during read')
    return buffer.raw[:size]
def snapshot(path,limit=1048576):
    with shared_read(path) as handle:return read_handle(handle,limit)
def strict_json(raw):
    def unique(pairs):
        value={}
        for k,v in pairs:
            if k in value:raise Refused('Duplicate JSON field')
            value[k]=v
        return value
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=unique,parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeError,ValueError) as error:raise Refused('Invalid JSON snapshot') from error
