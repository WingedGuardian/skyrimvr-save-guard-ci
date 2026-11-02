"""Offline diagnostic build/check entry point. Never deploys or launches Skyrim."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
WORK=ROOT/'_CLAUDE_OUTPUT/skyrim-souls-vr-2026-10-24/diagnostic-build-ninja'
RUNS=WORK.parent/'timed-revision'
VS=Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools')
CMAKE=VS/'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
NINJA=VS/'Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe'
MSVC=VS/'VC/Tools/MSVC/14.44.35207'
KITS=Path('C:/Program Files (x86)/Windows Kits/10')
SDK='10.0.26100.0'

def environment():
    env=dict(os.environ)
    for name in ('CL','_CL_','LINK','_LINK_'):env.pop(name,None)
    env['PATH']=';'.join(map(str,[MSVC/'bin/Hostx64/x64',KITS/'bin'/SDK/'x64']))+';'+env['PATH']
    env['INCLUDE']=';'.join(map(str,[MSVC/'include',*[KITS/'Include'/SDK/name for name in ('ucrt','shared','um','winrt','cppwinrt')]]))
    env['LIB']=';'.join(map(str,[MSVC/'lib/x64',KITS/'Lib'/SDK/'ucrt/x64',KITS/'Lib'/SDK/'um/x64']))
    return env

def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()

def sources():
    paths=[HERE/'CMakeLists.txt',HERE/'build.py',HERE/'src/context.hpp',HERE/'src/xstate.hpp',HERE/'tests/capture.asm',HERE/'tests/bridge_tests.cpp']
    if (HERE/'src/bridges.asm').is_file():paths.append(HERE/'src/bridges.asm')
    return {p.relative_to(HERE).as_posix():sha(p) for p in paths}

def main():
    phase=sys.argv[1]
    if phase not in ('configure','build','direct','red','negative','test'):
        raise ValueError('Unknown offline phase')
    WORK.mkdir(parents=True,exist_ok=True)
    before=sources()
    exe=WORK/'bridge-tests.exe'
    if phase in ('red','negative','test'):
        builds=[json.loads(p.read_text()) for p in sorted(WORK.glob('*-direct.json'))]
        builds=[x for x in builds if x.get('expected_result_observed') and 'source_sha256' in x]
        if not builds or builds[-1]['source_sha256']!=before or builds[-1]['executable_sha256']!=sha(exe):
            raise ValueError('No matching successful build receipt; refuse stale executable')
    if phase=='configure':
        args=[CMAKE,'-S',HERE,'-B',WORK,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',
              '-DCMAKE_MAKE_PROGRAM='+str(NINJA)]
    elif phase=='build':args=[CMAKE,'--build',WORK,'--parallel','1']
    elif phase=='direct':args=[]
    else:args=[WORK/'bridge-tests.exe',*(['--negative-control'] if phase=='negative' else [])]
    args=list(map(str,args))
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    stem=WORK/(stamp+'-'+phase)
    commands=[args]
    if phase=='direct':
        compiler=MSVC/'bin/Hostx64/x64'
        assembly=['tests/capture.asm']
        if (HERE/'src/bridges.asm').is_file():assembly.append('src/bridges.asm')
        commands=[[str(compiler/'ml64.exe'),'/nologo','/c','/WX','/Fo'+str(WORK/(Path(p).stem+'.obj')),str(HERE/p)] for p in assembly]
        commands.append([str(compiler/'cl.exe'),'/nologo','/c','/std:c++latest','/EHsc','/O2','/W4','/WX','/utf-8','/MD',
                         *(['/DSOULS_HAVE_BRIDGES=1'] if len(assembly)==2 else []),
                         '/Fo'+str(WORK/'bridge-tests.obj'),str(HERE/'tests/bridge_tests.cpp')])
        commands.append([str(compiler/'link.exe'),'/nologo','/OUT:'+str(WORK/'bridge-tests.exe'),
                         str(WORK/'bridge-tests.obj'),*[str(WORK/(Path(p).stem+'.obj')) for p in assembly],
                         'Kernel32.lib','/SUBSYSTEM:CONSOLE','/MACHINE:X64'])
    log='';exit_code=0;steps=[]
    for command in commands:
        try:
            result=subprocess.run(command,cwd=WORK,env=environment(),capture_output=True,text=True,timeout=180)
            output=result.stdout+result.stderr;exit_code=result.returncode
        except subprocess.TimeoutExpired as error:
            output='TIMEOUT after 180s\n'+str(error.stdout or '')+str(error.stderr or '')
            exit_code=124
        log+=output
        steps.append(dict(command=command,exit_code=exit_code))
        if exit_code:break
    stem.with_suffix('.log').write_text(log,encoding='utf-8')
    expected=1 if phase in ('red','negative') else 0
    correct=exit_code==expected
    correct=correct and before==sources()
    if phase=='red':correct=correct and 'production native bridges are missing' in log
    if phase=='negative':correct=correct and 'FAIL ordinary C++ preserves leaf GPR contract' in log
    if phase=='test':correct=correct and bool(re.search(r'checks=\d+ failures=0 game_code_executed=false',log))
    receipt=dict(phase=phase,steps=steps,exit_code=exit_code,expected_exit=expected,
                 expected_result_observed=correct,log=str(stem.with_suffix('.log')),
                 installed=False,game_launched=False,source_sha256=before,
                 executable_sha256=sha(exe) if exe.is_file() else None)
    stem.with_suffix('.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(log[-9000:])
    print(json.dumps(receipt))
    return 0 if correct else 1

if __name__=='__main__':raise SystemExit(main())
