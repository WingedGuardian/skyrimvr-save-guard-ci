"""Twin tests for the save-guard PowerShell wrapper (save-access-entry.ps1).

The wrapper under test is the template rendered with THIS interpreter (default), or the file named by the
environment variable WRAPPER (e.g. the deployed wrapper, or the pre-fix one to watch cases 3/4/7/8 go red).
Each case gets its own folder holding the wrapper and a FAKE `protect-save-access.py` beside it; no real guard,
save, backup or hook registration is touched. Windows only (the wrapper is Windows PowerShell 5.1); elsewhere the
class skips and the module prints `WRAPPER CASES RUN: 0` so a packet runner can tell skipped from passed.

Run from this folder:  python -B -m unittest test_save_access_entry -v
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / 'save-access-entry.template.ps1'
sys.path.insert(0, str(HERE))
import render_wrapper  # noqa: E402

PS = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File']
DEADLINE = 24.0
SLACK = 1.5                     # process start/stop overhead allowed on top of a wrapper-internal bound
CASES_RUN = 0

FAKE = {
    'allow': "import sys\nsys.stdin.read()\n",
    'deny': ("import json, os, sys\nsys.stdin.read()\n"
             "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',"
             " 'permissionDecisionReason': 'R' * int(os.environ['FAKE_N'])}}))\n"),
    'slow_start': "import os, sys, time\ntime.sleep(float(os.environ['FAKE_DELAY']))\nsys.stdin.read()\n",
    'never_exit': ("import os, sys, time\nsys.stdin.read()\n"
                   "open(os.environ['FAKE_PIDFILE'], 'w').write(str(os.getpid()))\ntime.sleep(600)\n"),
    'crash': "import sys\nsys.stdin.read()\nraise RuntimeError('boom-traceback-marker')\n",
    'badjson': "import sys\nsys.stdin.read()\nprint('not json {')\n",
}


def wrapper_text():
    override = os.environ.get('WRAPPER')
    if override:
        return Path(override).read_text(encoding='utf-8')
    return render_wrapper.render(TEMPLATE.read_text(encoding='utf-8'), sys.executable)


def pid_alive(pid):
    out = subprocess.run(['tasklist', '/FI', f'PID eq {pid}', '/NH'], capture_output=True, text=True).stdout
    return str(pid) in out


def kill(pid):
    subprocess.run(['taskkill', '/PID', str(pid), '/F'], capture_output=True)


class Harness:
    """One folder per run: the wrapper plus the fake guard it will find beside itself."""

    def __init__(self, text, fake, env=None):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.wrapper = d / 'save-access-entry.ps1'
        self.wrapper.write_text(text, encoding='utf-8', newline='\n')
        (d / 'protect-save-access.py').write_text(FAKE[fake], encoding='utf-8')
        self.env = dict(os.environ, **(env or {}))
        self.pidfile = d / 'pid.txt'
        self.env['FAKE_PIDFILE'] = str(self.pidfile)

    def run(self, payload=b'{"tool_name":"Bash","tool_input":{"command":"echo x"}}'):
        """Returns (wall seconds, exit code, stdout, stderr). A fake guard the wrapper failed to kill inherits the
        wrapper's stdout pipe and would block this read forever, so the read has a deadline; past it the orphan is
        reaped from its pidfile and `self.orphan_killed` records that the wrapper left it alive."""
        global CASES_RUN
        CASES_RUN += 1
        self.orphan_killed = False
        t = time.time()
        p = subprocess.Popen(PS + [str(self.wrapper)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=self.env)
        try:
            out, err = p.communicate(payload, timeout=DEADLINE + 6)
        except subprocess.TimeoutExpired:
            wall = time.time() - t
            pid = int(self.pidfile.read_text() or 0) if self.pidfile.exists() else 0
            if pid and pid_alive(pid):
                kill(pid)
                self.orphan_killed = True
            if p.poll() is None:
                p.kill()
            out, err = p.communicate(timeout=10)
            return wall, p.returncode, out.decode('utf-8', 'replace').strip(), err.decode('utf-8', 'replace')
        return time.time() - t, p.returncode, out.decode('utf-8', 'replace').strip(), err.decode('utf-8', 'replace')

    def close(self):
        if self.pidfile.exists():
            pid = int(self.pidfile.read_text() or 0)
            if pid and pid_alive(pid):
                kill(pid)
        self.dir.cleanup()


def deny_reason(stdout):
    doc = json.loads(stdout)
    h = doc['hookSpecificOutput']
    if h['permissionDecision'] != 'deny':
        raise AssertionError('not a deny: ' + stdout[:200])
    return h['permissionDecisionReason']


@unittest.skipUnless(os.name == 'nt', 'the wrapper is Windows PowerShell')
class WrapperCases(unittest.TestCase):
    text = None

    @classmethod
    def setUpClass(cls):
        cls.text = wrapper_text()

    def harness(self, fake, env=None, text=None):
        h = Harness(text or self.text, fake, env)
        self.addCleanup(h.close)
        return h

    # --- the nine cases from the spec -------------------------------------------------------------------------
    def test_1_allow_is_silent_exit_0(self):
        wall, rc, out, _ = self.harness('allow').run()
        self.assertEqual((0, ''), (rc, out))
        self.assertLess(wall, 5)

    def test_2_short_deny_forwarded_intact(self):
        _, rc, out, _ = self.harness('deny', {'FAKE_N': '1000'}).run()
        self.assertEqual(0, rc)
        self.assertEqual('R' * 1000, deny_reason(out))

    def test_3_long_deny_forwarded_intact_and_fast(self):
        wall, rc, out, _ = self.harness('deny', {'FAKE_N': '70000'}).run()
        self.assertEqual(0, rc)
        self.assertEqual('R' * 70000, deny_reason(out), 'a decision above the pipe buffer must be forwarded whole')
        self.assertLess(wall, 2.0 + SLACK)

    def test_4_slow_start_within_budget_is_allowed(self):
        wall, rc, out, _ = self.harness('slow_start', {'FAKE_DELAY': '3'}).run()
        self.assertEqual((0, ''), (rc, out), 'a 3 s interpreter start must not be refused: ' + out[:200])
        self.assertLess(wall, 8 + SLACK)

    def test_5_slow_start_past_budget_denies_naming_stdin(self):
        wall, rc, out, _ = self.harness('slow_start', {'FAKE_DELAY': '10'}).run()
        self.assertEqual(0, rc)
        self.assertIn('(stdin: ', deny_reason(out))
        self.assertLess(wall, DEADLINE + SLACK)

    def test_6_hung_guard_denies_naming_exit_and_is_killed(self):
        h = self.harness('never_exit')
        wall, rc, out, _ = h.run()
        self.assertEqual(0, rc)
        self.assertIn('(exit: ', deny_reason(out))
        self.assertLess(wall, DEADLINE + SLACK)
        self.assertTrue(h.pidfile.exists(), 'fake guard never started')
        self.assertFalse(h.orphan_killed, 'the wrapper must kill a child that outlives the deadline')
        self.assertFalse(pid_alive(int(h.pidfile.read_text())))

    def test_7_crash_denies_naming_exitcode_with_stderr(self):
        _, rc, out, _ = self.harness('crash').run()
        self.assertEqual(0, rc)
        reason = deny_reason(out)
        self.assertIn('(exitcode: ', reason)
        self.assertIn('boom-traceback-marker', reason, 'the child traceback must reach the reader')

    def test_8_non_json_output_denies_naming_output_json(self):
        _, rc, out, _ = self.harness('badjson').run()
        self.assertEqual(0, rc)
        self.assertIn('(output-json: ', deny_reason(out))

    def test_9_missing_interpreter_denies_naming_start(self):
        broken = render_wrapper.render(TEMPLATE.read_text(encoding='utf-8'), 'C:/no/such/python-3.99.exe')
        _, rc, out, _ = self.harness('allow', text=broken).run()
        self.assertEqual(0, rc)
        self.assertIn('(start: ', deny_reason(out))

    def test_payload_is_never_echoed_in_a_deny(self):
        marker = b'PAYLOAD-SECRET-7f3a'
        _, _, out, _ = self.harness('crash').run(b'{"tool_name":"Bash","tool_input":{"command":"' + marker + b'"}}')
        self.assertNotIn(marker.decode(), out)


def mutate(text, old, new):
    if text.count(old) != 1:
        raise AssertionError(f'mutation anchor not found exactly once: {old!r}')
    return text.replace(old, new)


@unittest.skipUnless(os.name == 'nt', 'the wrapper is Windows PowerShell')
class WrapperMutationTwins(unittest.TestCase):
    """Each twin breaks one guard inside the template and requires the NAMED case to go red (and only that proof
    counts: a suite that merely fails somewhere launders a survivor into a kill). Twins run on the template, not on
    WRAPPER, because they edit the template's text."""

    @classmethod
    def setUpClass(cls):
        cls.template = TEMPLATE.read_text(encoding='utf-8')
        cls.text = render_wrapper.render(cls.template, sys.executable)

    def run_case(self, text, fake, env=None, payload=None):
        h = Harness(text, fake, env)
        self.addCleanup(h.close)
        return h.run() if payload is None else h.run(payload)

    def test_removing_the_async_stdout_read_breaks_case_3(self):
        m = mutate(self.template, "        $outTask = $child.StandardOutput.ReadToEndAsync()\n", "")
        m = mutate(m, "        if (-not $outTask.Wait((Remaining))) { throw 'Save guard output did not drain.' }\n", "")
        m = mutate(m, "        $result = $outTask.Result\n", "        $result = $child.StandardOutput.ReadToEnd()\n")
        wall, _, out, _ = self.run_case(render_wrapper.render(m, sys.executable), 'deny', {'FAKE_N': '70000'})
        forwarded = out.startswith('{') and 'R' * 70000 in out
        self.assertFalse(forwarded and wall < 2.0 + SLACK, 'mutant survived: case 3 still passes without the async read')
        # and the healthy template still passes case 3 right now (baseline green, same machine, same minute)
        wall, _, out, _ = self.run_case(self.text, 'deny', {'FAKE_N': '70000'})
        self.assertEqual('R' * 70000, deny_reason(out)); self.assertLess(wall, 2.0 + SLACK)

    def test_restoring_the_2s_stdin_wait_breaks_case_4(self):
        m = mutate(self.template, "[Math]::Min(8000, (Remaining))", "[Math]::Min(2000, (Remaining))")
        _, _, out, _ = self.run_case(render_wrapper.render(m, sys.executable), 'slow_start', {'FAKE_DELAY': '3'})
        self.assertIn('(stdin: ', deny_reason(out), 'mutant survived: a 2 s stdin wait still allowed a 3 s start')

    def test_dropping_the_kill_breaks_case_6(self):
        m = mutate(self.template, "            $child.Kill()\n", "")
        h = Harness(render_wrapper.render(m, sys.executable), 'never_exit')
        self.addCleanup(h.close)
        _, _, out, _ = h.run()
        self.assertIn('(exit: ', deny_reason(out))
        self.assertTrue(h.orphan_killed, 'mutant survived: the child died without Kill()')

    def test_dropping_json_validation_breaks_case_8(self):
        m = mutate(self.template, '        $null = "$result" | ConvertFrom-Json -ErrorAction Stop\n', "")
        _, _, out, _ = self.run_case(render_wrapper.render(m, sys.executable), 'badjson')
        self.assertEqual('not json {', out, 'mutant survived: bad JSON was not forwarded verbatim, so validation still happens')


class RenderContract(unittest.TestCase):
    def test_placeholder_once_and_no_quotes(self):
        t = TEMPLATE.read_text(encoding='utf-8')
        self.assertEqual(1, t.count(render_wrapper.PLACEHOLDER))
        self.assertNotIn(render_wrapper.PLACEHOLDER, render_wrapper.render(t, 'C:/py/python.exe'))
        with self.assertRaises(ValueError):
            render_wrapper.render(t, 'C:/py/"python.exe')
        with self.assertRaises(ValueError):
            render_wrapper.render(t, 'python.exe')
        # both flavours of absolute render on either runner (the Linux job renders the template too)
        self.assertNotIn(render_wrapper.PLACEHOLDER, render_wrapper.render(t, '/usr/bin/python3'))
        self.assertNotIn(render_wrapper.PLACEHOLDER, render_wrapper.render(t, 'C:\\py\\python.exe'))
        with self.assertRaises(ValueError):
            render_wrapper.render(t.replace(render_wrapper.PLACEHOLDER, 'x'), 'C:/py/python.exe')

    def test_template_has_no_private_path(self):
        self.assertIsNone(re.search(r'(?i)c:[/\\]users[/\\]', TEMPLATE.read_text(encoding='utf-8')))


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        print(f'WRAPPER CASES RUN: {CASES_RUN}')
