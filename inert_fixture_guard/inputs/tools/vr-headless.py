"""Official null driver with background DevBench control and isolated startup.

No save operations, plugin activation or gameplay commands are implemented here.
All session backups are permanent. Old tools/.vr-headless-state is read-only.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
STEAM = Path("C:/Program Files (x86)/Steam")
OFFICIAL_SHA = "fc689623914c6643c6e8629dc6bcb130193888b6835d902ed6411ab476121454"
NORMAL_LOADER_SHA = "fd651802468df85475266f1896b33186855bfd8bd5027a956dab22b0664e25e4"
NORMAL_INPUT_SHA = "eded2ab515a459174b3d8dc216d5f40bbf9fabd975aa88fdeb6b4b7b91a0589a"
VR_NAMES = {"SkyrimVR", "sksevr_loader", "vrserver", "vrmonitor", "vrcompositor", "steamvr_room_setup",
            "vrwebhelper", "vrdashboard", "vrstartup"}
STEAM_NAMES = {"steam", "steamwebhelper"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".headless-" + uuid.uuid4().hex)
    try:
        temp.write_bytes(data)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def write_json(path, value):
    atomic(path, (json.dumps(value, indent=2) + "\n").encode())


def processes():
    command = "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in @('steam','SkyrimVR','sksevr_loader','vrserver','vrmonitor','vrcompositor','steamvr_room_setup','steamwebhelper','vrwebhelper','vrdashboard','vrstartup') -or $_.ProcessName -like 'AutoHotkey*' } | Select-Object Id,ProcessName,Path,@{Name='StartTime';Expression={$_.StartTime.ToUniversalTime().ToString('o')}} | ConvertTo-Json -Compress"
    # A failed host query is unknown, never proof that the owned game exited.
    # Retry only the read, with a short bound; persistent failure still restores.
    for attempt in range(3):
        try:
            result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command],
                                    capture_output=True, text=True, check=True, timeout=8)
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            if attempt == 2:
                raise
            print("Process inventory read failed; retrying read only: " +
                  type(exc).__name__ + " code=" + str(getattr(exc, "returncode", None)),
                  file=sys.stderr, flush=True)
            time.sleep(.25 * (attempt + 1))
    value = json.loads(result.stdout) if result.stdout.strip() else []
    return value if isinstance(value, list) else [value]


class Lifecycle:
    def __init__(self, root=ROOT, steam=STEAM, local=None, process_reader=processes):
        self.root, self.steam = Path(root), Path(steam)
        self.local = Path(local or os.environ["LOCALAPPDATA"])
        self.sessions = self.root / "tools/.vr-headless-sessions"
        self.active = self.sessions / "active.json"
        self.loader = self.root / "openvr_api.dll"
        self.settings = self.steam / "config/steamvr.vrsettings"
        self.driver = self.steam / "steamapps/common/SteamVR/drivers/null/bin/win64/driver_null.dll"
        self.valve = self.steam / "steamapps/common/SteamVR/bin/win64/openvr_api.dll"
        self.vrstartup = self.valve.with_name('vrstartup.exe')
        self.legacy = self.root / "tools/vr-emu-driver/bin/driver_null.dll"
        self.plugins = [self.root / "Data/SKSE/Plugins" / n for n in ("OCUnleashedSKSE.dll", "OpenCompositeInput.dll")]
        self.controls = self.local / "SkyrimVR Devkit/Actions/controls.txt"
        self.read_processes = process_reader

    @contextmanager
    def lock(self):
        self.sessions.mkdir(parents=True, exist_ok=True)
        lock = self.sessions / "operation.lock"
        try:
            with lock.open("x") as f:
                f.write(str(os.getpid()))
        except FileExistsError:
            raise RuntimeError("Another lifecycle operation or interrupted lock exists: " + str(lock))
        try:
            yield
        finally:
            lock.unlink()

    def require_idle(self, driver_change=False):
        frontend_runtime = (self.root / "tools/vr-devkit/autohotkey/AutoHotkey64.exe").resolve()
        blocked = [p for p in self.read_processes() if p["ProcessName"] in VR_NAMES or
                   (driver_change and p["ProcessName"] in STEAM_NAMES) or
                   (p["ProcessName"].startswith("AutoHotkey") and p.get("Path") and
                    Path(p["Path"]).resolve() == frontend_runtime)]
        if blocked:
            raise RuntimeError("Close game/VR/frontend" + (" and Steam" if driver_change else "") + " before switching: " + str(blocked))

    def current(self):
        if not self.active.exists():
            return None, None
        path = Path(json.loads(self.active.read_text())["manifest"])
        path.resolve().relative_to(self.sessions.resolve())
        if path.name != "manifest.json":
            raise RuntimeError("Invalid active manifest")
        return path, json.loads(path.read_text())

    def driver_kind(self):
        if not self.driver.is_file():
            return "missing"
        digest = sha(self.driver)
        if digest == OFFICIAL_SHA:
            return "devkit-2.0.1"
        if self.legacy.is_file() and digest == sha(self.legacy):
            return "legacy-independent-poses"
        return "unknown"

    def normal_status(self):
        """Verify the approved play path; file size is not loader identity."""
        failures = []
        loader_hash = sha(self.loader) if self.loader.is_file() else None
        input_plugin = self.plugins[1]
        input_hash = sha(input_plugin) if input_plugin.is_file() else None
        if loader_hash != NORMAL_LOADER_SHA:
            failures.append('Approved OpenComposite loader is not installed')
        if input_hash != NORMAL_INPUT_SHA:
            failures.append('Approved OpenComposite input plugin is not installed')
        settings = json.loads(self.settings.read_text(encoding='utf-8-sig')) if self.settings.is_file() else {}
        if settings.get('driver_null', {}).get('enable') or settings.get('steamvr', {}).get('forcedDriver') == 'null':
            failures.append('SteamVR null driver is still enabled or forced')
        appid = self.root/'steam_appid.txt'
        if not appid.is_file() or appid.read_text(encoding='utf-8-sig').strip() != '611670':
            failures.append('Local Steam app identity is missing or incorrect')
        runtime = None
        if self.root.resolve() == ROOT.resolve():
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Khronos\OpenXR\1') as key:
                    runtime = winreg.QueryValueEx(key, 'ActiveRuntime')[0]
                expected = Path('C:/Program Files/Virtual Desktop Streamer/OpenXR/virtualdesktop-openxr.json')
                if Path(runtime).resolve() != expected.resolve() or not expected.is_file():
                    failures.append('Virtual Desktop is not the active OpenXR runtime')
                override = os.environ.get('XR_RUNTIME_JSON')
                if override and Path(override).resolve() != expected.resolve():
                    failures.append('XR_RUNTIME_JSON overrides the normal OpenXR runtime')
            except OSError as exc:
                failures.append('Cannot verify the OpenXR runtime: '+str(exc))
        return {'ready':not failures,'loader_sha256':loader_hash,'input_sha256':input_hash,
                'openxr_runtime':runtime,'failures':failures}

    def verify_normal(self):
        result = self.normal_status()
        if not result['ready']:
            raise RuntimeError('Normal VR readiness failed: '+'; '.join(result['failures']))
        return result

    def snapshot(self, directory, targets):
        rows = []
        for index, path in enumerate(targets):
            row = {"path": str(path), "existed": path.is_file(), "sha256": None, "backup": None}
            if path.is_file():
                dst = directory / "before" / (str(index) + "-" + path.name)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dst)
                row.update(sha256=sha(path), backup=str(dst))
                if sha(dst) != row["sha256"]:
                    raise RuntimeError("Backup verification failed: " + str(path))
            rows.append(row)
        return rows

    def on(self, mode="devkit", park=False):
        with self.lock():
            _, previous = self.current()
            if previous:
                if previous["state"] == "ready" and previous["driver"] == mode and previous["park"] == park:
                    self.verify_ready(previous)
                    return {"already_active": True, "session": previous["id"]}
                raise RuntimeError("A session is active; restore it before changing mode")
            self.require_idle(driver_change=(mode == "legacy"))
            self.verify_normal()
            for path in (self.loader, self.valve, self.settings, self.driver):
                if not path.is_file():
                    raise RuntimeError("Required file missing: " + str(path))
            if self.loader.stat().st_size <= 2000000:
                raise RuntimeError("Normal OpenComposite baseline required; no old stash will be consumed")
            if self.driver_kind() != "devkit-2.0.1":
                raise RuntimeError("Install/repair the pinned official driver first")
            if mode == "legacy" and not self.legacy.is_file():
                raise RuntimeError("Legacy driver missing")
            settings = json.loads(self.settings.read_text(encoding="utf-8-sig"))
            settings["driver_null"] = {"enable": True, "id": "Null Driver", "windowWidth": 1920,
                "windowHeight": 1080, "renderWidth": 1920, "renderHeight": 1080,
                "secondsFromVsyncToPhotons": 0.01111, "displayFrequency": 90}
            settings.setdefault("steamvr", {}).update(requireHmd=False, forcedDriver="null", activateMultipleDrivers=False)
            for name in ("vrlink", "oculus", "oculus_legacy", "lighthouse", "htc", "prism"):
                settings.setdefault("driver_" + name, {})["enable"] = False
            settings.setdefault("power", {})["pauseCompositorOnStandby"] = False
            ident = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            directory = self.sessions / ident
            directory.mkdir()
            replacements = {str(self.loader): self.valve.read_bytes(),
                            str(self.settings): (json.dumps(settings, indent=2) + "\n").encode()}
            # Background mode has no frontend heartbeat or mouse capture. Also
            # disable mouse-look explicitly, preserving its prior file for off.
            controls = self.controls.read_bytes() if self.controls.is_file() else b"turn_speed 216.0\nmouse_enabled 0\nmouse_sens 0.0500\nmouse_invert_y 0\n"
            lines = controls.splitlines(keepends=True)
            found = False
            for i, line in enumerate(lines):
                if line.strip().startswith(b"mouse_enabled "):
                    ending = b"\r\n" if line.endswith(b"\r\n") else b"\n"
                    lines[i] = b"mouse_enabled 0" + ending
                    found = True
            if not found:
                lines.append(b"\nmouse_enabled 0\n")
            replacements[str(self.controls)] = b"".join(lines)
            if mode == "legacy":
                replacements[str(self.driver)] = self.legacy.read_bytes()
            if park:
                replacements.update({str(p): None for p in self.plugins if p.is_file()})
            targets = [Path(p) for p in replacements]
            if self.driver not in targets:
                targets.append(self.driver)  # verify unchanged driver too; no routine rewrite
            manifest = {"schema": 1, "id": ident, "state": "prepared", "driver": mode, "park": park,
                        "creator_pid": os.getpid(),
                        "files": self.snapshot(directory, targets), "processes": []}
            for row in manifest["files"]:
                row["mutated"] = row["path"] in replacements
                content = replacements[row["path"]] if row["path"] in replacements else Path(row["path"]).read_bytes()
                row["installed_sha256"] = hashlib.sha256(content).hexdigest() if content is not None else None
            path = directory / "manifest.json"
            write_json(path, manifest)
            # Publish recovery information BEFORE the first live change.
            write_json(self.active, {"manifest": str(path)})
            try:
                for row in manifest["files"]:
                    target = Path(row["path"])
                    if (sha(target) if target.is_file() else None) != row["sha256"]:
                        raise RuntimeError("Baseline changed after backup: " + str(target))
                    if not row["mutated"]:
                        continue
                    content = replacements[row["path"]]
                    if content is None:
                        target.unlink()
                    else:
                        atomic(target, content)
                manifest["state"] = "ready"
                write_json(path, manifest)
                self.verify_ready(manifest)
            except Exception:
                manifest["state"] = "interrupted"
                write_json(path, manifest)
                raise
            return {"enabled": True, "driver": mode, "session": ident, "backups_verified": True}

    def verify_ready(self, manifest):
        for row in manifest["files"]:
            path = Path(row["path"])
            if (sha(path) if path.is_file() else None) != row["installed_sha256"]:
                raise RuntimeError("Session files changed: " + str(path))

    def off(self):
        with self.lock():
            path, manifest = self.current()
            if not manifest:
                return {"already_off": True, "old_stashes_untouched": True, "normal_vr":self.verify_normal()}
            self.require_idle(driver_change=(manifest["driver"] == "legacy"))
            allowed = {str(p) for p in [self.loader, self.settings, self.driver, self.controls, *self.plugins]}
            # Validate EVERY backup before restoring ANY file.
            for row in manifest["files"]:
                if row["path"] not in allowed:
                    raise RuntimeError("Unexpected restore target")
                if not row["existed"]:
                    if Path(row["path"]) != self.controls or row["backup"] is not None:
                        raise RuntimeError("Unexpected absent restore target")
                    continue
                backup = Path(row["backup"])
                backup.resolve().relative_to(path.parent.resolve())
                if not backup.is_file() or sha(backup) != row["sha256"]:
                    raise RuntimeError("Missing/corrupt permanent backup: " + str(backup))
            manifest["state"] = "restoring"
            write_json(path, manifest)
            after = path.parent / ("after-" + uuid.uuid4().hex)
            self.snapshot(after, [Path(row["path"]) for row in manifest["files"]])
            for row in reversed(manifest["files"]):
                target = Path(row["path"])
                if not row["existed"]:
                    if target.is_file():
                        target.unlink()  # outgoing copy permanently retained above
                    continue
                if not target.is_file() or sha(target) != row["sha256"]:
                    atomic(target, Path(row["backup"]).read_bytes())
                if sha(row["path"]) != row["sha256"]:
                    raise RuntimeError("Restoration mismatch: " + row["path"])
            normal = self.verify_normal()
            manifest.update(state="restored", restored_at=datetime.now(timezone.utc).isoformat(), normal_vr=normal)
            write_json(path, manifest)
            self.active.unlink()  # pointer only; all backups and manifests remain.
            return {"restored": True, "verified_files": len(manifest["files"]), "session": manifest["id"], "normal_vr":normal}

    def status(self):
        path, manifest = self.current()
        settings = json.loads(self.settings.read_text(encoding="utf-8-sig")) if self.settings.is_file() else {}
        report = self.local / "SkyrimVR Devkit/Actions/driver_status.txt"
        return {"active": manifest["id"] if manifest else None, "session_state": manifest["state"] if manifest else None,
            "selected_driver": manifest["driver"] if manifest else None, "installed_driver": self.driver_kind(),
            "interaction": manifest.get("interaction") if manifest else None,
            "desktop": manifest.get("desktop") if manifest else None,
            "frontend_started": manifest.get("frontend_started", False) if manifest else False,
            "steam_policy": manifest.get('steam_policy') if manifest else None,
            "last_verified_desktop_boundary": manifest.get("desktop_boundary") if manifest else None,
            "loader": "OpenComposite" if self.loader.is_file() and sha(self.loader) == NORMAL_LOADER_SHA else "Valve-or-unknown",
            "normal_vr": self.normal_status(),
            "null_enabled": settings.get("driver_null", {}).get("enable", False),
            "processes": self.read_processes(), "driver_status_age_seconds": round(time.time()-report.stat().st_mtime, 2) if report.is_file() else None,
            "driver_status": report.read_text() if report.is_file() else None,
            "manifest": str(path) if path else None, "legacy_stashes_consumed": False}

    def stop(self):
        """Complete an owned session, including verified normal-VR restoration."""
        self.sessions.mkdir(parents=True, exist_ok=True)
        lock = self.sessions/'finish.lock'
        deadline = time.monotonic()+90
        while True:
            try:
                with lock.open('x') as handle:
                    handle.write(str(os.getpid()))
                break
            except FileExistsError:
                if time.monotonic()>deadline:
                    raise RuntimeError('Session cleanup still owns finish.lock; inspect before retrying')
                time.sleep(0.2)
        try:
            _, manifest = self.current()
            if not manifest:
                return self.off()
            exited = self._stop_owned()
            restored = self.off()
            return {**exited, 'restoration':restored}
        finally:
            lock.unlink()

    def run(self, mode='devkit', park=False, desktop='background'):
        """Managed lifecycle: restoration is part of exit/error, not a caller step."""
        if self.current()[1]:
            raise RuntimeError('Managed run requires a fresh session; finish the existing session first')
        try:
            self.on(mode, park)
            startup = self.launch(desktop=desktop)
            print(json.dumps({'managed_session_started':startup}), flush=True)
            missing_game_reads = 0
            while True:
                _, manifest = self.current()
                if not manifest:
                    break
                owned_games = [p for p in manifest['processes'] if p['ProcessName']=='SkyrimVR']
                if not owned_games:
                    raise RuntimeError('Managed startup did not record its game identity')
                running = self.read_processes()
                if any(all(p.get(k)==g.get(k) for k in ('Id','ProcessName','Path','StartTime'))
                       for g in owned_games for p in running):
                    missing_game_reads = 0
                else:
                    # A single enumeration can omit the still-starting game.
                    # Do not enter stop()/queue qqq until absence persists.
                    missing_game_reads += 1
                    if missing_game_reads >= 3:
                        break
                time.sleep(1)
        finally:
            _, manifest = self.current()
            if manifest and manifest.get('creator_pid') != os.getpid():
                raise RuntimeError('Session owner changed; refuse to clean up another startup')
            if manifest and manifest.get('interaction') not in ('background-devbench','desktop-devbench'):
                self.off()  # Failure before engine process ownership was established.
            elif manifest:
                self.stop()
            else:
                self.verify_normal()
        return {'completed':True,'normal_vr':self.verify_normal()}

    def _stop_owned(self):
        """Exit only a recorded background session, using no shared-desktop input."""
        path, manifest = self.current()
        if not manifest or manifest.get('interaction') not in ('background-devbench', 'desktop-devbench'):
            raise RuntimeError('A recorded engine-controlled session is required for automatic stop')
        keep_steam = manifest.get('steam_policy') == 'keep-running'
        helper_names = VR_NAMES if keep_steam else VR_NAMES | {'steamwebhelper'}
        owned = {p['Id']: p for p in manifest['processes']}
        def adopt_helpers(running):
            # Chromium can fork a final crash-handler child during VR shutdown.
            # Adopt only a verified child of an already-owned process, under Steam.
            candidates = [p for p in running if p['ProcessName'] in helper_names and
                          p['ProcessName'] not in ('SkyrimVR','sksevr_loader') and p['Id'] not in owned]
            for p in candidates:
                try:
                    Path(p['Path']).resolve().relative_to(self.steam.resolve())
                except ValueError:
                    continue
                query = "Get-CimInstance Win32_Process -Filter 'ProcessId = " + str(int(p['Id'])) + "' | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress"
                result = subprocess.run(['powershell.exe','-NoProfile','-Command',query],capture_output=True,text=True,check=True)
                if not result.stdout.strip():
                    continue
                ancestry = json.loads(result.stdout)
                parent = owned.get(ancestry['ParentProcessId'])
                if not parent or p['StartTime'] < parent['StartTime']:
                    continue
                owned[p['Id']] = p
                manifest['processes'].append(p)
                manifest.setdefault('late_helpers',[]).append({'process':p,'owned_parent':parent['Id']})
                write_json(path,manifest)
        def matches(p):
            prior = owned.get(p['Id'])
            return prior and all(p[k] == prior[k] for k in ('ProcessName','Path','StartTime'))
        running = self.read_processes()
        games = [p for p in running if p['ProcessName'] in ('SkyrimVR','sksevr_loader')]
        if any(not matches(p) for p in games):
            raise RuntimeError('An unowned game exists; stop refused')
        if games:
            with urllib.request.urlopen('http://127.0.0.1:8921/api/health', timeout=3) as response:
                health = json.load(response)
            if len(games) != 1 or health.get('pid') != games[0]['Id']:
                raise RuntimeError('DevBench identity does not match the owned game')
            request = urllib.request.Request('http://127.0.0.1:8921/api/tool/console',
                data=json.dumps({'action':'exec','command':'qqq'}).encode(),
                headers={'Content-Type':'application/json'})
            with urllib.request.urlopen(request, timeout=8) as response:
                manifest['exit_response'] = json.load(response)
            write_json(path, manifest)
            deadline = time.monotonic()+30
            while any(p['ProcessName'] in ('SkyrimVR','sksevr_loader') for p in self.read_processes()):
                if time.monotonic()>deadline:
                    raise TimeoutError('Owned game has not exited normally; do not restore live files')
                time.sleep(1)
        from vr_background_desktop import BackgroundDesktop, CurrentDesktop, bindings
        desktop_type = CurrentDesktop if manifest['interaction'] == 'desktop-devbench' else BackgroundDesktop
        desktop = desktop_type(manifest['desktop'])
        try:
            clients = [] if keep_steam else [p for p in self.read_processes() if p['ProcessName']=='steam']
            if any(not matches(p) for p in clients):
                raise RuntimeError('An unowned Steam client exists; leave it untouched')
            if clients:
                handle, _ = desktop.start([self.steam/'steam.exe','-shutdown'],self.steam)
                handle.Close()
            deadline = time.monotonic()+30
            while not keep_steam and any(p['ProcessName']=='steam' and matches(p) for p in self.read_processes()):
                if time.monotonic()>deadline:
                    raise TimeoutError('Owned Steam has not exited normally')
                time.sleep(1)
            api, con, _, process, _ = bindings()
            stopped = []
            deadline = time.monotonic()+15
            while True:
                running = self.read_processes()
                adopt_helpers(running)
                helpers = [p for p in running if p['ProcessName'] in helper_names and matches(p)]
                if not helpers:
                    break
                if time.monotonic()>deadline:
                    raise TimeoutError('Owned VR helpers have not settled; session retained')
                for p in helpers:
                    # Game is gone; only same-PID/path/start-time owned helper processes.
                    handle = api.OpenProcess(con.PROCESS_TERMINATE | con.PROCESS_QUERY_INFORMATION, False, p['Id'])
                    try:
                        stamp = re.sub(r'(\.\d{6})\d+(?=Z$)',r'\1',p['StartTime']).replace('Z','+00:00')
                        expected = datetime.fromisoformat(stamp)
                        created = process.GetProcessTimes(handle)['CreationTime']
                        if abs((created-expected).total_seconds()) > 0.001:
                            raise RuntimeError('Helper PID was reused; refuse termination')
                        process.TerminateProcess(handle,0)
                        stopped.append(p['Id'])
                    finally:
                        handle.Close()
                time.sleep(0.5)
            if manifest.get('background_cleanup'):
                manifest.setdefault('cleanup_history',[]).append(manifest['background_cleanup'])
            manifest['background_cleanup'] = {'game_exited':True,'helpers_stopped':stopped,
                                               'input_desktop_unchanged':True,'steam_left_running':keep_steam}
            write_json(path,manifest)
            return manifest['background_cleanup']
        finally:
            desktop.close()

    def launch(self, interactive=False, desktop='background'):
        if desktop not in ('background', 'current') or (interactive and desktop != 'background'):
            raise ValueError('Choose current engine-only mode OR the separately coordinated interactive frontend')
        path, manifest = self.current()
        if not manifest or manifest["state"] != "ready":
            raise RuntimeError("Enable a headless session first")
        self.verify_ready(manifest)
        keep_steam = not interactive and (desktop == 'current' or manifest['driver'] == 'devkit')
        direct_runtime = keep_steam and desktop == 'background'
        self.require_idle(driver_change=not interactive and not keep_steam)
        prior_steam = [p for p in self.read_processes() if p['ProcessName'] in STEAM_NAMES]
        if direct_runtime:
            # Steam's singleton forwards -applaunch to its existing desktop.
            # Start the VR runtime itself here; never move or own the user's client.
            if not any(p['ProcessName'] == 'steam' for p in prior_steam):
                raise RuntimeError('Open Steam normally before a background session; leave it running')
            if not self.vrstartup.is_file():
                raise RuntimeError('SteamVR runtime launcher missing: ' + str(self.vrstartup))
        if not interactive:
            from vr_background_desktop import BackgroundDesktop, CurrentDesktop
            background = CurrentDesktop() if desktop == 'current' else BackgroundDesktop()
            manifest.update(desktop=background.name, desktop_mode=desktop,
                interaction="desktop-devbench" if desktop == 'current' else "background-devbench",
                frontend_started=False, steam_policy='keep-running' if keep_steam else 'owned-private',
                preexisting_steam=prior_steam)
        else:
            background = None
            manifest.update(desktop="shared-interactive", interaction="interactive", frontend_started=False)
        write_json(path, manifest)
        if interactive and manifest["driver"] == "devkit":
            base = self.root / "tools/vr-devkit"
            ahk, frontend = base / "autohotkey/AutoHotkey64.exe", base / "frontend/AHK Frontend/SkyrimVR Devkit.ahk"
            if not ahk.is_file() or not frontend.is_file():
                raise RuntimeError("Official frontend or AutoHotkey missing")
            # Visible GUI is intentional: interactive headless navigation.
            subprocess.Popen([str(ahk), str(frontend)], cwd=base / "frontend")
            manifest["frontend_started"] = True
        def record_processes():
            running = self.read_processes()
            manifest["processes"] = [p for p in running if p["ProcessName"] in VR_NAMES or
                                     (background and not keep_steam and p['ProcessName'] in STEAM_NAMES) or
                                     p["ProcessName"].startswith("AutoHotkey")]
            if background:
                manifest["desktop_boundary"] = background.boundary([p["Id"] for p in manifest["processes"]])
                if desktop == 'background' and not manifest["desktop_boundary"]["isolated"]:
                    write_json(path, manifest)
                    raise RuntimeError("A test window escaped onto the shared desktop; stop this owned session")
            write_json(path, manifest)
            return running
        try:
            record_processes()
            if background:
                command = [self.vrstartup] if direct_runtime else [self.steam / 'steam.exe', '-silent', '-applaunch', '250820']
                handle, child = background.start(command, self.vrstartup.parent if direct_runtime else self.steam)
                handle.Close()
                manifest['runtime_launch' if direct_runtime else 'steam_launch'] = child
                write_json(path, manifest)
            else:
                subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Start-Process 'steam://rungameid/250820' -WindowStyle Hidden"], check=True)
            deadline = time.monotonic() + 90
            while not any(p["ProcessName"] == "vrserver" for p in record_processes()):
                if time.monotonic() > deadline:
                    raise TimeoutError("SteamVR did not start; session retained for cleanup")
                time.sleep(1)
            # Room setup may exist before its private window is created.
            # Missing proof is pending within the original deadline, never an
            # excuse to terminate an unknown helper or launch around it.
            deadline = time.monotonic() + 25
            room_seen = {}
            while True:
                rooms = [p for p in record_processes() if p["ProcessName"] == "steamvr_room_setup"]
                if rooms:
                    if background:
                        expected = self.steam / "steamapps/common/SteamVR/tools/steamvr_room_setup/win64/steamvr_room_setup.exe"
                        for p in rooms:
                            if not p.get("StartTime") or not p.get("Path") or Path(p["Path"]).resolve() != expected.resolve():
                                raise RuntimeError("Room setup executable/generation is unproved; game not launched")
                            prior = room_seen.get(p["Id"])
                            if prior and any(p[k] != prior[k] for k in ("ProcessName", "Path", "StartTime")):
                                raise RuntimeError("Room setup PID was reused; game not launched")
                            room_seen[p["Id"]] = dict(p)
                        missing = [p["Id"] for p in rooms if p["Id"] not in manifest["desktop_boundary"]["private_window_pids"]]
                        if missing:
                            manifest["room_setup_pending"] = {"pids": missing, "deadline": deadline}
                            write_json(path, manifest)
                            if time.monotonic() >= deadline:
                                raise TimeoutError("Room setup private-window proof timed out; game not launched")
                            time.sleep(0.25)
                            continue
                        from vr_background_desktop import bindings
                        api, con, _, process, _ = bindings()
                        for p in rooms:
                            h = api.OpenProcess(con.PROCESS_TERMINATE | con.PROCESS_QUERY_INFORMATION, False, p["Id"])
                            try:
                                stamp = re.sub(r'(\.\d{6})\d+(?=Z$)', r'\1', p['StartTime']).replace('Z', '+00:00')
                                expected_time = datetime.fromisoformat(stamp)
                                created = process.GetProcessTimes(h)['CreationTime']
                                if abs((created - expected_time).total_seconds()) > 0.001:
                                    raise RuntimeError("Room setup handle generation changed; game not launched")
                                process.TerminateProcess(h, 0)
                            finally:
                                h.Close()
                        manifest["room_setup_cleanup"] = rooms
                        write_json(path, manifest)
                    exit_deadline = time.monotonic() + 120
                    while any(p["ProcessName"] == "steamvr_room_setup" for p in record_processes()):
                        if time.monotonic() > exit_deadline:
                            raise TimeoutError("Room setup still owns scene slot; game not launched")
                        time.sleep(1)
                    break
                if room_seen:
                    manifest["room_setup_natural_exit"] = list(room_seen.values())
                    write_json(path, manifest)
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(1)
            game = self.root / "sksevr_loader.exe"
            if background:
                handle, child = background.start([game], self.root)
                handle.Close()
                manifest["game_launch"] = child
                write_json(path, manifest)
            else:
                subprocess.Popen([str(game)], cwd=self.root)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                running = record_processes()
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8921/api/health", timeout=2) as response:
                        health = json.load(response)
                    owned = [p for p in running if p["ProcessName"] == "SkyrimVR"]
                    if len(owned) == 1 and health.get("ok") and health.get("pid") == owned[0]["Id"] and health.get("lastLifecycle") == "dataLoaded" and health.get("frame", 0) > 100:
                        manifest["startup_health"] = health
                        write_json(path, manifest)
                        return {"started": True, "session": manifest["id"], "health": health, "save_loaded": False}
                except (OSError, ValueError):
                    pass
                time.sleep(2)
            raise TimeoutError("Main-menu health not established; inspect owned session before cleanup")
        finally:
            if background:
                background.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "run", "on", "off", "launch", "stop", "emu"), nargs="?", default="status")
    parser.add_argument("emu_action", nargs="?", choices=("on", "off"))
    parser.add_argument("--driver", choices=("devkit", "legacy"), default="devkit")
    parser.add_argument("--park", action="store_true")
    parser.add_argument("--interactive", action="store_true", help="Opt-in shared-desktop GUI; coordinate desktop ownership first")
    parser.add_argument("--desktop", choices=("background", "current"), default="background",
                        help="Engine-only launch location; current does not start the AHK frontend")
    args = parser.parse_args()
    lifecycle = Lifecycle()
    if args.command == "run":
        if args.interactive:
            parser.error('Managed run uses engine control only')
        result = lifecycle.run(args.driver, args.park, args.desktop)
    elif args.command == "on":
        result = lifecycle.on(args.driver, args.park)
    elif args.command == "off":
        result = lifecycle.off()
    elif args.command == "launch":
        result = lifecycle.launch(args.interactive, args.desktop)
    elif args.command == "stop":
        result = lifecycle.stop()
    elif args.command == "emu":
        if not args.emu_action:
            parser.error("emu requires on or off")
        _, active = lifecycle.current()
        if active and active["driver"] != "legacy":
            raise RuntimeError("emu compatibility commands cannot change an official Devkit session")
        result = lifecycle.on("legacy", args.park) if args.emu_action == "on" else lifecycle.off()
    else:
        result = lifecycle.status()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        raise SystemExit("ERROR: " + str(error))
