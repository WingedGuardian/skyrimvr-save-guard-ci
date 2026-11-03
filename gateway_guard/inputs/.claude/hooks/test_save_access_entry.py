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
CEILING = 27.0                  # end to end from before spawn. Hosts fail OPEN at 30 s; the wrapper normally answers at 21.1 s
                                # (max 21.16 over 32 loaded local runs, stage/probe_deadline.py). 24 s went red once on the
                                # CI runner at 25.46 s with cleanup measured at 0.1 s, so 27 s tolerates a runner stall and
                                # keeps 3 s of margin. The anchor twin separately proves the budget counts from process start.
NOT_DEADLOCKED = 15.0          # a long decision normally takes 0.3 s and a deadlocked one at least 21 s (the child budget).
                                # 3.5 s went red once at 5.9 s on a loaded machine, with the code at 0.31 s over 12 runs.
CASES_RUN = 0

FAKE = {
    'allow': "import sys\nsys.stdin.read()\n",
    'deny': ("import json, os, sys\nsys.stdin.read()\n"
             "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',"
             " 'permissionDecisionReason': 'R' * int(os.environ['FAKE_N'])}}))\n"),
    'slow_start': ("import os, sys, time\nopen(os.environ['FAKE_PIDFILE'], 'w').write(str(os.getpid()))\n"
                   "time.sleep(float(os.environ['FAKE_DELAY']))\nsys.stdin.read()\n"),
    'never_exit': ("import os, sys, time\nsys.stdin.read()\n"
                   "open(os.environ['FAKE_PIDFILE'], 'w').write(str(os.getpid()))\ntime.sleep(600)\n"),
    'crash': "import sys\nsys.stdin.read()\nraise RuntimeError('boom-traceback-marker')\n",
    'badjson': "import sys\nsys.stdin.read()\nprint('not json {')\n",
    # a broken guard that echoes its input as invalid JSON: ConvertFrom-Json's message would carry the payload
    'echo_badjson': "import sys\nd = sys.stdin.read()\nprint('{\"partial\": ' + d)\n",
    # ...and one that puts the payload's command where the parser reports it as an unquoted "primitive": PowerShell
    # 5.1 builds differ in whether the object-parse error embeds the whole input (Windows 11 does, the CI runner's
    # Server build says only "Invalid JSON primitive: ."), but both name a bare token in full
    'echo_primitive': ("import json, sys\nraw = sys.stdin.buffer.read()\n"
                       "try:\n    d = json.loads(raw.decode('utf-8-sig'))\n"
                       "except Exception as exc:\n    sys.stderr.write('STDIN NOT JSON: %r first bytes %r\\n' % (exc, raw[:40])); sys.exit(1)\n"
                       "print('{\"echo\": ' + d['tool_input']['command'] + '}')\n"),
    # the real guard does json.load(sys.stdin): a BOM or any non-JSON prefix in what the wrapper writes makes it deny
    # every call as malformed; this fake fails the same way and reports the first bytes it saw
    'strict_json': ("import json, sys\nraw = sys.stdin.buffer.read()\n"
                    "try:\n    d = json.loads(raw.decode('utf-8'))\n"
                    "except Exception as exc:\n    sys.stderr.write('STDIN NOT JSON: %r first bytes %r\\n' % (exc, raw[:40])); sys.exit(1)\n"
                    "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',"
                    " 'permissionDecisionReason': 'parsed ' + d['tool_name']}}))\n"),
    'badjson_70k': "import sys\nsys.stdin.read()\nprint('{' + 'x' * 70000)\n",
}
FAKE['raw_dump'] = ("import json, sys\nraw = sys.stdin.buffer.read()\n"
                    "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',"
                    " 'permissionDecisionReason': raw.hex()}}))\n")
# decodes as the real guard does (json.load on sys.stdin, whatever encoding the wrapper's launch gives it)
FAKE['as_guard'] = ("import json, sys\nd = json.load(sys.stdin)\n"
                    "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',"
                    " 'permissionDecisionReason': d['tool_input']['command'].encode('utf-8', 'backslashreplace').hex()}}))\n")
# characters whose UTF-8 includes every byte cp1252 leaves undefined, and ones that survive only by accident
NON_ASCII = 'uü d— a→ l“ r” e… k断 pł zź s\U0001F600 ĀāďĐĝ'
NON_ASCII_PAYLOAD = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': NON_ASCII}}, ensure_ascii=False).encode('utf-8')
PAYLOAD_MARKER = b'PAYLOAD-SECRET-7f3a'
# above the anonymous-pipe buffer (4 KB): the wrapper's stdin write cannot complete until the child reads
BIG_PAYLOAD = b'{"tool_name":"apply_patch","tool_input":{"command":"' + b'x' * 12000 + b'"}}'
MARKED_PAYLOAD = b'{"tool_name":"Bash","tool_input":{"command":"' + PAYLOAD_MARKER + b'"}}'


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


def run_in_utf8_console(text, fake, payload, codepage=65001):
    """Run the wrapper under a chosen code page in a hidden NEW console, so the test runner's own console keeps its
    code page and the result does not depend on the machine. Handles cannot be inherited into a new console reliably,
    so the batch file redirects the wrapper's stdin/stdout to files; the deny (or decision) comes back from the output
    file."""
    d = Path(tempfile.mkdtemp())
    (d / 'save-access-entry.ps1').write_text(text, encoding='utf-8', newline='\n')
    (d / 'protect-save-access.py').write_text(FAKE[fake], encoding='utf-8')
    (d / 'payload.json').write_bytes(payload)
    bat = d / 'run.cmd'
    bat.write_text('@echo off\r\nchcp ' + str(codepage) + ' >nul\r\npowershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'
                   + str(d / 'save-access-entry.ps1') + '" < "' + str(d / 'payload.json') + '" > "' + str(d / 'out.txt') + '" 2>&1\r\n',
                   encoding='ascii')
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0                                   # SW_HIDE
    env = dict(os.environ, FAKE_PIDFILE=str(d / 'pid.txt'))
    subprocess.run(['cmd.exe', '/d', '/c', str(bat)], creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=si,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=DEADLINE + 10)
    return (d / 'out.txt').read_text(encoding='utf-8', errors='replace').strip()


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
        self.assertLess(wall, NOT_DEADLOCKED)

    def test_4_slow_start_within_budget_is_allowed(self):
        wall, rc, out, _ = self.harness('slow_start', {'FAKE_DELAY': '3'}).run()
        self.assertEqual((0, ''), (rc, out), 'a 3 s interpreter start must not be refused: ' + out[:200])
        self.assertLess(wall, 8 + SLACK)

    def test_5_slow_start_past_budget_denies_naming_stdin(self):
        """A payload above the pipe buffer blocks the write until the child reads: a child that never starts reading
        in time is reported at the stdin stage, inside the absolute deadline."""
        wall, rc, out, _ = self.harness('slow_start', {'FAKE_DELAY': '40'}).run(BIG_PAYLOAD)
        self.assertEqual(0, rc)
        self.assertIn('(stdin: ', deny_reason(out))
        self.assertLess(wall, CEILING)

    def test_5b_slow_start_small_payload_denies_naming_exit(self):
        """A small payload is in the pipe at once, so the same slow child is caught by the exit wait instead; the
        deadline is the same. A start of 10 s with a small payload is simply allowed (the child answers in time)."""
        wall, rc, out, _ = self.harness('slow_start', {'FAKE_DELAY': '40'}).run()
        self.assertEqual(0, rc)
        self.assertIn('(exit: ', deny_reason(out))
        self.assertLess(wall, CEILING)
        wall, rc, out, _ = self.harness('slow_start', {'FAKE_DELAY': '10'}).run()
        self.assertEqual((0, ''), (rc, out), 'a 10 s start that still answers inside the budget must be allowed')

    def test_6_hung_guard_denies_naming_exit_and_is_killed(self):
        h = self.harness('never_exit')
        wall, rc, out, _ = h.run()
        self.assertEqual(0, rc)
        self.assertIn('(exit: ', deny_reason(out))
        # ABSOLUTE bound, measured from before powershell.exe is spawned and including the kill: the host's 30 s timer
        # also starts at spawn and fails OPEN
        self.assertLess(wall, CEILING)
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

    def test_10_stdin_reaches_the_guard_as_plain_utf8_json(self):
        """The guard must be able to json.load() exactly what the wrapper writes, on every console encoding: no BOM,
        no transcoding. Red on a UTF-8-console machine (the CI runner) before the explicit-bytes write."""
        _, rc, out, _ = self.harness('strict_json').run(MARKED_PAYLOAD)
        self.assertEqual(0, rc)
        self.assertEqual('parsed Bash', deny_reason(out), 'the guard did not receive clean JSON: ' + out[:400])

    def test_11_non_ascii_reaches_the_guard_byte_identical(self):
        _, _, out, _ = self.harness('raw_dump').run(NON_ASCII_PAYLOAD)
        self.assertEqual(NON_ASCII_PAYLOAD.hex(), deny_reason(out), 'the wrapper changed the bytes it was given')

    def test_11b_byte_identical_on_a_utf8_console_too(self):
        out = run_in_utf8_console(self.text, 'raw_dump', NON_ASCII_PAYLOAD)
        self.assertEqual(NON_ASCII_PAYLOAD.hex(), deny_reason(out))

    def test_11c_byte_identical_on_a_legacy_console(self):
        """Code page 437, the install's console: the one where decoding through the console garbles."""
        out = run_in_utf8_console(self.text, 'raw_dump', NON_ASCII_PAYLOAD, codepage=437)
        self.assertEqual(NON_ASCII_PAYLOAD.hex(), deny_reason(out))

    def test_12_guard_decodes_non_ascii_correctly(self):
        """Python's UTF-8 mode: the guard reads the command the host sent, with no surrogates and no mojibake."""
        _, _, out, _ = self.harness('as_guard').run(NON_ASCII_PAYLOAD)
        self.assertEqual(NON_ASCII.encode('utf-8').hex(), deny_reason(out), 'the guard did not decode the payload as sent')

    def test_9_missing_interpreter_denies_naming_start(self):
        broken = render_wrapper.render(TEMPLATE.read_text(encoding='utf-8'), 'C:/no/such/python-3.99.exe')
        _, rc, out, _ = self.harness('allow', text=broken).run()
        self.assertEqual(0, rc)
        self.assertIn('(start: ', deny_reason(out))

    def test_payload_is_never_echoed_in_a_deny(self):
        """Every deny path that could carry the payload: a crash (stderr) and a guard that echoes stdin as bad JSON
        (ConvertFrom-Json's message embeds its whole input). The reason also stays bounded for a huge bad decision."""
        for fake in ('crash', 'echo_badjson', 'echo_primitive'):
            with self.subTest(fake=fake):
                _, _, out, _ = self.harness(fake).run(MARKED_PAYLOAD)
                self.assertNotIn(PAYLOAD_MARKER.decode(), out)
                self.assertIn('permissionDecision":"deny', out)
        _, _, out, _ = self.harness('badjson_70k').run()
        self.assertIn('(output-json: ', deny_reason(out))
        self.assertLess(len(out), 1200, 'a malformed decision must not be copied into the reason')


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
        self.assertFalse(forwarded and wall < NOT_DEADLOCKED, 'mutant survived: case 3 still passes without the async read')
        # and the healthy template still passes case 3 right now (baseline green, same machine, same minute)
        wall, _, out, _ = self.run_case(self.text, 'deny', {'FAKE_N': '70000'})
        self.assertEqual('R' * 70000, deny_reason(out)); self.assertLess(wall, NOT_DEADLOCKED)

    def test_restoring_a_2s_stdin_wait_breaks_case_4(self):
        """The old wrapper's 2 s handoff allowance is what denied a loaded machine's 10 KB payload: with it back, a
        3 s start with a big payload is refused at the stdin stage; case 4's shape must stay allowed."""
        m = mutate(self.template, "if (-not $write.Wait((Remaining)))", "if (-not $write.Wait([Math]::Min(2000, (Remaining))))")
        _, _, out, _ = self.run_case(render_wrapper.render(m, sys.executable), 'slow_start', {'FAKE_DELAY': '3'}, payload=BIG_PAYLOAD)
        self.assertIn('(stdin: ', deny_reason(out), 'mutant survived: a 2 s stdin wait still allowed a 3 s start')
        _, _, out, _ = self.run_case(self.text, 'slow_start', {'FAKE_DELAY': '3'}, payload=BIG_PAYLOAD)
        self.assertEqual('', out, 'healthy template must allow a 3 s start with a big payload')

    def test_unbounded_stdin_wait_breaks_case_5(self):
        """Without the deadline on the write, a child that never reads a big payload holds the wrapper past the host's
        timeout (fail-open). The harness reaps it at DEADLINE + 6 s and reports a wall past the deadline."""
        m = mutate(self.template, "if (-not $write.Wait((Remaining)))", "if (-not $write.Wait())")
        wall, _, out, _ = self.run_case(render_wrapper.render(m, sys.executable), 'slow_start', {'FAKE_DELAY': '40'}, payload=BIG_PAYLOAD)
        self.assertGreaterEqual(wall, DEADLINE, 'mutant survived: the write still gave up inside the deadline')

    def test_dropping_the_kill_breaks_case_6(self):
        m = mutate(self.template, "            $child.Kill()\n", "")
        h = Harness(render_wrapper.render(m, sys.executable), 'never_exit')
        self.addCleanup(h.close)
        _, _, out, _ = h.run()
        self.assertIn('(exit: ', deny_reason(out))
        self.assertTrue(h.orphan_killed, 'mutant survived: the child died without Kill()')

    def test_forwarding_the_json_exception_message_leaks_the_payload(self):
        m = mutate(self.template, "        $message = 'guard output is not JSON (' + $_.Exception.GetType().Name + ', ' + \"$result\".Length + ' chars)'\n", "")
        # echo_primitive, not echo_badjson: only the bare-token error form embeds its text on every PS 5.1 build
        _, _, out, _ = self.run_case(render_wrapper.render(m, sys.executable), 'echo_primitive', payload=MARKED_PAYLOAD)
        self.assertIn(PAYLOAD_MARKER.decode(), out, 'mutant survived: the payload did not leak, so the fixed message is not what hides it')

    def test_anchoring_the_deadline_at_wrapper_time_breaks_case_6(self):
        """The budget must count from process START (the host's timer does). Anchored at 'now' plus the same 24 s, a
        hung guard finishes AFTER 24 s measured from spawn: the twin must see case 6's absolute bound go red."""
        m = mutate(self.template, "[System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().AddSeconds(24)",
                   "[DateTime]::UtcNow.AddSeconds(24)")
        m = mutate(m, "$childStop = $hardStop.AddSeconds(-3)", "$childStop = $hardStop")
        h = Harness(render_wrapper.render(m, sys.executable), 'never_exit')
        self.addCleanup(h.close)
        wall, _, out, _ = h.run()
        self.assertIn('(exit: ', deny_reason(out))
        self.assertGreaterEqual(wall, DEADLINE, 'mutant survived: without the start-time anchor the wall still fit the budget')

    def test_removing_the_input_encoding_line_breaks_case_10_on_a_utf8_console(self):
        """.NET Framework writes Console.InputEncoding's preamble into the child's stdin at Start(). On a UTF-8 console
        that is a BOM. This twin runs the wrapper in a HIDDEN NEW CONSOLE set to code page 65001 (nobody's terminal is
        touched): the healthy template delivers clean JSON there, the template without the InputEncoding line delivers
        a BOM and the strict guard refuses it. This is the shape that was red on the UTF-8 CI runner (run 41596008285)
        while every plain-console test stayed green."""
        healthy = run_in_utf8_console(self.text, 'strict_json', MARKED_PAYLOAD)
        self.assertEqual('parsed Bash', deny_reason(healthy), 'healthy template under a UTF-8 console: ' + healthy[:300])
        m = mutate(self.template, "    [Console]::InputEncoding = New-Object System.Text.UnicodeEncoding($false, $false)\n", "")
        out = run_in_utf8_console(render_wrapper.render(m, sys.executable), 'strict_json', MARKED_PAYLOAD)
        reason = deny_reason(out)
        self.assertIn('(exitcode: ', reason, 'mutant survived: without the InputEncoding line the guard still parsed its stdin')
        self.assertIn('BOM', reason)

    def test_reading_stdin_as_text_breaks_case_11c(self):
        """The regression that passed five review rounds and CI: decode with the console, re-encode as UTF-8. Pinned to
        code page 437, because on a UTF-8 console (the CI runner) the text round trip happens to be lossless."""
        m = mutate(self.template, "    $inputStream.CopyTo($buffer)\n    $payloadBytes = $buffer.ToArray()\n",
                   "    $payloadBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes([Console]::In.ReadToEnd())\n")
        out = run_in_utf8_console(render_wrapper.render(m, sys.executable), 'raw_dump', NON_ASCII_PAYLOAD, codepage=437)
        self.assertNotEqual(NON_ASCII_PAYLOAD.hex(), deny_reason(out), 'mutant survived: text mode kept the bytes intact')

    def test_dropping_utf8_mode_breaks_case_12(self):
        m = mutate(self.template, "'-B -X utf8 \"'", "'-B \"'")
        _, _, out, _ = self.run_case(render_wrapper.render(m, sys.executable), 'as_guard', payload=NON_ASCII_PAYLOAD)
        self.assertNotEqual(NON_ASCII.encode('utf-8').hex(), deny_reason(out), 'mutant survived: the guard decoded correctly without UTF-8 mode')

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

    BUDGET = ('[System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().AddSeconds(24)',
              '$childStop = $hardStop.AddSeconds(-3)')

    def test_budget_is_pinned_static(self):
        """Runtime bounds cannot see this: a 29 s budget measures 26 s when nothing stalls, then crosses the hosts' 30 s
        fail-open limit on a stall like the one CI showed. Changing the budget must be a deliberate edit here."""
        t = TEMPLATE.read_text(encoding='utf-8')
        missing = lambda text: [b for b in self.BUDGET if text.count(b) != 1]
        self.assertEqual([], missing(t))
        self.assertTrue(missing(t.replace('AddSeconds(24)', 'AddSeconds(29)')), 'the check cannot see a raised budget')
        self.assertTrue(missing(t.replace('AddSeconds(-3)', 'AddSeconds(0)')), 'the check cannot see a dropped cleanup reserve')
        self.assertTrue(missing(t.replace('.StartTime.ToUniversalTime()', '.StartTime')), 'the check cannot see a changed anchor')

    def test_template_has_no_private_path(self):
        self.assertIsNone(re.search(r'(?i)c:[/\\]users[/\\]', TEMPLATE.read_text(encoding='utf-8')))


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        print(f'WRAPPER CASES RUN: {CASES_RUN}')
