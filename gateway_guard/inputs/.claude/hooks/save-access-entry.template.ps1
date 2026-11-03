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
    # One deadline for every stage: 24 s, inside both hosts' 30 s hook timeout. A host timeout fails OPEN
    # (measured), so the wrapper must always answer first.
    $deadline = [DateTime]::UtcNow.AddSeconds(24)
    function Remaining {
        $ms = [int][Math]::Floor(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
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
    $child = New-Object System.Diagnostics.Process
    $child.StartInfo = $start
    if (-not $child.Start()) { throw 'Save guard interpreter did not start.' }
    try {
        # Drain both pipes from the start: a decision longer than the pipe buffer (~4 KB) must never block the
        # child, which used to turn a long deny into a 20 s timeout and a generic refusal.
        $outTask = $child.StandardOutput.ReadToEndAsync()
        $errTask = $child.StandardError.ReadToEndAsync()
        $stage = 'stdin'
        # Up to 8 s for the child to accept its input: interpreter start plus importing the guard, which exceeds
        # 2 s only when the machine is paging.
        $write = $child.StandardInput.WriteAsync($inputJson)
        if (-not $write.Wait([Math]::Min(8000, (Remaining)))) { throw 'Save guard input timed out (interpreter slow to start; machine under load?).' }
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
    try { if ($null -ne $errTask -and $errTask.Wait(500)) { $childErr = $errTask.Result } } catch { }
    $reason = 'SAVE ACCESS BLOCKED: save guard wrapper failure (' + $stage + ': ' + $message + '). Fail-closed; retry once the machine is responsive, and if it recurs repair the hook, do not bypass it.'
    if ($childErr) { $reason += ' stderr: ' + $childErr.Substring(0, [Math]::Min(300, $childErr.Length)) }
    $deny = @{ hookSpecificOutput = @{ hookEventName = 'PreToolUse'; permissionDecision = 'deny'; permissionDecisionReason = $reason } }
    Write-Output (ConvertTo-Json -InputObject $deny -Compress -Depth 4)
}
exit 0
