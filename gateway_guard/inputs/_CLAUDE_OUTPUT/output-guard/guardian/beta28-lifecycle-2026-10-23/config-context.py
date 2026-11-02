"""Preserve native configuration/databases for one owned qualification session."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import yaml

HERE = Path(__file__).resolve().parent
ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / '_CLAUDE_OUTPUT/skyrimnet-beta28-install-2026-10-22'))
LIVE = ROOT / 'Data/SKSE/Plugins/SkyrimNet'
WORK = ROOT / '_CLAUDE_OUTPUT/shinso-guarded-headless-20261014'
PRIVATE = HERE / 'private/runtime-before'
TREES = [LIVE / 'config', LIVE / 'data', ROOT / 'Data/SKSE/Plugins/STFU', ROOT / 'Data/SKSE/Plugins/SeverActions']
OWNER = 'gateway-beta28-lifecycle-20261023'

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def files():
    return [p for tree in TREES for p in tree.rglob('*') if p.is_file()]

def copy_verified(p, base):
    target = base / p.relative_to(ROOT)
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = sha(p)
    shutil.copy2(p, target)
    assert sha(target) == sha(p) == digest
    return {'path': p.relative_to(ROOT).as_posix(), 'sha256': digest}

def claim(release=False):
    path = ROOT / '_CLAUDE_OUTPUT/skyrimnet-work-status.json'
    raw = path.read_bytes()
    value = json.loads(raw)
    for key in ['active_shared_config_owner', 'active_live_test_owner']:
        assert value[key] in (None, OWNER), (key, value[key])
        old = json.dumps(value[key])
        new = json.dumps(None if release else OWNER)
        needle = ('"' + key + '": ' + old).encode()
        assert raw.count(needle) == 1
        raw = raw.replace(needle, ('"' + key + '": ' + new).encode(), 1)
    path.write_bytes(raw)

def prepare():
    import deploy
    deploy.no_game()
    claim()
    PRIVATE.mkdir(parents=True, exist_ok=False)
    rows = [copy_verified(p, PRIVATE) for p in files()]
    controller = PRIVATE / 'controller'
    controller.mkdir()
    for name in ['prepared-pair.json', 'owned-session.json', 'load-dispatch.json', 'load-lifecycle.json']:
        source = HERE / 'private/controller-before' / name
        if not source.is_file():
            source = WORK / name
        if source.is_file():
            shutil.copy2(source, controller / name)
    (HERE / 'runtime-preservation.json').write_text(json.dumps({'files': rows, 'desktop': 'private background', 'controller_files': [p.name for p in controller.iterdir()]}, indent=2) + '\n')
    edits = {
        'SkyrimNet.yaml': [(('gamemaster', 'enabled'), False), (('gamemaster', 'agentEnabled'), False)],
        'Agents.yaml': [(('agents', 'enable'), False)],
        'NpcThoughts.yaml': [(('enabled',), False)],
        'OmniSight.yaml': [(('omnisight', 'enabled'), False)],
        'plugins/IntelEngine/settings.yaml': [(('politics', 'enabled'), False)],
    }
    for name, changes in edits.items():
        path = LIVE / 'config' / name
        value = yaml.safe_load(path.read_bytes())
        for keys, new in changes:
            node = value
            for key in keys[:-1]:
                node = node[key]
            assert keys[-1] in node
            node[keys[-1]] = new
        path.write_text(yaml.safe_dump(value, sort_keys=False, allow_unicode=True), encoding='utf-8', newline='\n')
    print(json.dumps({'prepared': True, 'protected_files': len(rows), 'bytes': sum((ROOT / row['path']).stat().st_size for row in rows)}))

def restore():
    import deploy
    deploy.no_game()
    manifest = json.loads((HERE / 'runtime-preservation.json').read_text())
    after = HERE / 'private/runtime-after'
    after.mkdir(parents=True, exist_ok=False)
    changes = []
    originals = {row['path']: row for row in manifest['files']}
    for p in files():
        rel = p.relative_to(ROOT).as_posix()
        if rel not in originals or sha(p) != originals[rel]['sha256']:
            changes.append(copy_verified(p, after))
    for row in manifest['files']:
        original = PRIVATE / row['path']
        assert sha(original) == row['sha256']
        target = ROOT / row['path']
        shutil.copy2(original, target)
        assert sha(target) == row['sha256']
    # New database/config artifacts are preserved permanently before parking them.
    for row in changes:
        if row['path'] not in originals:
            target = ROOT / row['path']
            assert target.resolve().is_relative_to((ROOT / 'Data/SKSE/Plugins').resolve())
            assert sha(after / row['path']) == sha(target)
            __import__('os').replace(target, after / row['path'])
    controller_after = after / 'controller'
    controller_after.mkdir()
    for name in manifest['controller_files']:
        target = WORK / name
        if target.is_file():
            shutil.copy2(target, controller_after / name)
        shutil.copy2(PRIVATE / 'controller' / name, target)
        assert sha(target) == sha(PRIVATE / 'controller' / name)
    claim(release=True)
    (HERE / 'runtime-restoration.json').write_text(json.dumps({'restored': True, 'protected_files': len(originals), 'changed_test_files_preserved': changes, 'controller_restored': True}, indent=2) + '\n')
    print(json.dumps({'restored': True, 'files': len(originals), 'test_changes_preserved': len(changes)}))

if __name__ == '__main__':
    {'prepare': prepare, 'restore': restore}[sys.argv[1]]()
