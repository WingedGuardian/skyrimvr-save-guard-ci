# Wrapper failures produce an explicit deny: hook execution errors can fail open.
# TEMPLATE: rendered by render_wrapper.py, which substitutes the interpreter path only. The deployed copy is
# save-access-entry.ps1 beside protect-save-access.py. Every failure names its stage so a deny under machine load
# (stdin handoff slow) is not mistaken for a broken guard (2026-11-02, two such denies cost an hour).
$stage = 'start'
$childErr = ''
$errTask = $null
try {
    $ErrorActionPreference = 'Stop'
    $inputJson = [Console]::In.ReadToEnd()
    $guardScript = Join-Path $PSScriptRoot 'protect-save-access.py'
    if ($guardScript.Contains('"')) { throw 'Invalid guard script path.' }
    # One budget for everything: 24 s counted from THIS PROCESS's start (the host's 30 s timer started when it spawned
    # powershell.exe, so PowerShell's own startup must count). A host timeout fails OPEN (measured), so the wrapper
    # must always answer first. The last 3 s are reserved for the cleanup that follows a timeout (Kill + 2 s wait,
    # 0.5 s stderr wait, JSON); the child may use the rest.
    $hardStop = [System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().AddSeconds(24)
    $childStop = $hardStop.AddSeconds(-3)
    function Remaining {
        $ms = [int][Math]::Floor(($childStop - [DateTime]::UtcNow).TotalMilliseconds)
        if ($ms -lt 1) { 1 } else { $ms }
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = '__GUARD_PYTHON__'
    $start.Arguments = '-B "' + $guardScript + '"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # .NET Framework builds the child's StandardInput writer from Console.InputEncoding and writes that encoding's
    # PREAMBLE into the pipe at Start(): on a UTF-8 (65001) console that is a BOM, and the guard's json.load() then
    # refuses every call as malformed (measured 2026-11-03 on the CI runner and locally under chcp 65001; this
    # install's OEM console never showed it). A BOM-less Unicode encoding has no preamble, and the Framework skips
    # SetConsoleCP for Unicode encodings, so the shared console is untouched. The payload itself is written below as
    # explicit UTF-8 bytes, so this choice affects only the preamble. Set AFTER the host's stdin was read above.
    [Console]::InputEncoding = New-Object System.Text.UnicodeEncoding($false, $false)
    $child = New-Object System.Diagnostics.Process
    $child.StartInfo = $start
    if (-not $child.Start()) { throw 'Save guard interpreter did not start.' }
    try {
        # Drain both pipes from the start: a decision longer than the pipe buffer (~4 KB) must never block the
        # child, which used to turn a long deny into a 20 s timeout and a generic refusal.
        $outTask = $child.StandardOutput.ReadToEndAsync()
        $errTask = $child.StandardError.ReadToEndAsync()
        $stage = 'stdin'
        # Explicit UTF-8 WITHOUT a byte-order mark. .NET Framework encodes StandardInput with Console.InputEncoding;
        # on a UTF-8 (65001) console that encoding emits a BOM, and the guard's json.load() then refuses every
        # payload as malformed (seen on the CI runner 2026-11-03; this machine's OEM console hid it).
        # A payload under the pipe buffer (~4 KB) lands at once; a larger one (a 10 KB apply_patch) blocks here until
        # the child starts reading, so a slow interpreter start under load shows up at THIS stage. Either way the
        # child has the whole child budget: there is one deadline, not a separate handoff allowance (the old 2 s one
        # produced the 2026-11-02 "repair the hook" denies on a loaded machine).
        $payloadBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($inputJson)
        $write = $child.StandardInput.BaseStream.WriteAsync($payloadBytes, 0, $payloadBytes.Length)
        if (-not $write.Wait((Remaining))) { throw 'Save guard input timed out (interpreter slow to start; machine under load?).' }
        $child.StandardInput.Close()
        $stage = 'exit'
        if (-not $child.WaitForExit((Remaining))) { throw 'Save guard interpreter timed out.' }
        if (-not $outTask.Wait((Remaining))) { throw 'Save guard output did not drain.' }
        $stage = 'exitcode'
        if ($child.ExitCode -ne 0) { throw ('Save guard interpreter failed with exit code ' + $child.ExitCode + '.') }
        $result = $outTask.Result
    } finally {
        if (-not $child.HasExited) {
            $child.Kill()
            $null = $child.WaitForExit(2000)
        }
        $child.Dispose()
    }
    $stage = 'output-json'
    if ($null -ne $result -and "$result".Trim()) {
        $null = "$result" | ConvertFrom-Json -ErrorAction Stop
        Write-Output $result
    }
} catch {
    $message = $_.Exception.Message
    if ($_.Exception -is [System.AggregateException] -and $null -ne $_.Exception.InnerException) { $message = $_.Exception.InnerException.Message }
    if ($stage -eq 'output-json') {
        # ConvertFrom-Json's message embeds the WHOLE input, which may carry the hook payload (the user's command
        # line) when a broken guard echoes it. Never forward it: name the type and the length only.
        $message = 'guard output is not JSON (' + $_.Exception.GetType().Name + ', ' + "$result".Length + ' chars)'
    }
    if ($message.Length -gt 300) { $message = $message.Substring(0, 300) }
    try { if ($null -ne $errTask -and $errTask.Wait(500)) { $childErr = $errTask.Result } } catch { }
    $reason = 'SAVE ACCESS BLOCKED: save guard wrapper failure (' + $stage + ': ' + $message + '). Fail-closed; retry once the machine is responsive, and if it recurs repair the hook, do not bypass it.'
    if ($childErr) { $reason += ' stderr: ' + $childErr.Substring(0, [Math]::Min(300, $childErr.Length)) }
    $deny = @{ hookSpecificOutput = @{ hookEventName = 'PreToolUse'; permissionDecision = 'deny'; permissionDecisionReason = $reason } }
    Write-Output (ConvertTo-Json -InputObject $deny -Compress -Depth 4)
}
exit 0
