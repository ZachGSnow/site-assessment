function Write-Step {
    param([string]$Text, [string]$Color = 'Cyan')
    $elapsed = [int]((Get-Date) - $RunStart).TotalSeconds
    Write-Host ('[{0,4}s] {1}' -f $elapsed, $Text) -ForegroundColor $Color
}

function Add-Flag {
    param([string]$Severity, [string]$Category, [string]$Message)
    $script:Flags += [pscustomobject]@{ Severity = $Severity; Category = $Category; Message = $Message }
}

function Invoke-Collector {
    # Runs one collector; any failure is recorded and the run continues.
    param([string]$Name, [scriptblock]$Script, [switch]$AdminOnly)
    if ($AdminOnly -and -not $script:AdminActive) {
        return [ordered]@{ Status = 'skipped (admin tier not active)' }
    }
    Write-Step $Name
    $t0 = Get-Date
    try {
        $out = & $Script
        $script:Timings[$Name] = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
        return $out
    } catch {
        $msg = $_.Exception.Message
        $script:Errors += [pscustomobject]@{ Collector = $Name; Error = $msg }
        $script:Timings[$Name] = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
        Write-Step ("  {0} unavailable: {1}" -f $Name, $msg) 'DarkYellow'
        return [ordered]@{ Status = "unavailable: $msg" }
    }
}

function Save-Json {
    # Writes assessment.json. Called at the checkpoint before active discovery, after the analysis,
    # and after the data check. $Stage records how far the run got, so a run that was cut off is recognizable.
    param([string]$Stage)
    try {
        if ($Stage) { $Result['Meta']['Stage'] = $Stage }
        $Result['Errors'] = $script:Errors
        $json = $Result | ConvertTo-Json -Depth 10
        [IO.File]::WriteAllText((Join-Path $OutDir 'assessment.json'), $json, (New-Object Text.UTF8Encoding $false))
        return $true
    } catch {
        Write-Host "JSON write failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-Val {
    # Safe lookup into a collector result (which may be an error record instead).
    param($Dict, [string]$Key)
    if ($Dict -is [System.Collections.IDictionary] -and $Dict.Contains($Key)) { return $Dict[$Key] }
    return $null
}

function Get-EventsSafe {
    # Get-WinEvent throws when nothing matches; treat that as zero events.
    param([hashtable]$Filter, [int]$Max)
    try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch { if ($_.Exception.Message -match 'No events were found') { return @() } throw }
}

function Format-Date {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') } catch { return "$Value" }
}

function Get-RegValues {
    # Returns a key's values as an ordered hashtable (no PS* noise).
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Path
    $h = [ordered]@{}
    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        if ($p.Name -match 'password|secret|key$|token') { continue }
        $v = $p.Value
        if ($v -is [byte[]]) { $v = '(binary {0} bytes)' -f $v.Length }
        $h[$p.Name] = $v
    }
    return $h
}

function Get-OemEncoding {
    try { return [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage) }
    catch { return [Text.Encoding]::Default }
}

function Invoke-Native {
    # Runs a console exe with a timeout and returns its stdout as a string.
    param([string]$FilePath, [string]$Arguments = '', [int]$TimeoutSec = 60)
    if (-not $script:FullLanguage) {
        $argList = @()
        if ($Arguments) { $argList = $Arguments -split ' ' }
        return (& $FilePath @argList 2>&1 | Out-String)
    }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = Get-OemEncoding
    $p = [Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        throw "$FilePath timed out after $TimeoutSec s"
    }
    $p.WaitForExit()
    return ($outTask.Result + $errTask.Result)
}

function Start-NativeAsync {
    # Starts a console exe in the background; collect with Receive-NativeAsync.
    param([string]$FilePath, [string]$Arguments, [string]$Label)
    if (-not $script:FullLanguage) {
        return [pscustomobject]@{ Label = $Label; FilePath = $FilePath; Arguments = $Arguments; Process = $null; Task = $null }
    }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = Get-OemEncoding
    $p = [Diagnostics.Process]::Start($psi)
    return [pscustomobject]@{ Label = $Label; FilePath = $FilePath; Arguments = $Arguments; Process = $p; Task = $p.StandardOutput.ReadToEndAsync() }
}

function Start-IcmpJob {
    # A ping series or a traceroute with .NET in a background runspace. The output is written the way
    # English ping.exe and tracert.exe print it, so one parser serves every Windows display language.
    # Constrained Language cannot create runspaces, so it falls back to the exes (see ConvertFrom-PingOutput).
    param([ValidateSet('Ping', 'Trace')][string]$Kind, [string]$Target, [int]$Count = 4, [int]$MaxHops = 20, [int]$TimeoutMs = 1000, [string]$Label)
    if (-not $script:FullLanguage) {
        $args0 = if ($Kind -eq 'Ping') { "-n $Count -w $TimeoutMs $Target" } else { "-d -w $TimeoutMs -h $MaxHops $Target" }
        return Start-NativeAsync $(if ($Kind -eq 'Ping') { 'ping.exe' } else { 'tracert.exe' }) $args0 $Label
    }
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        param($kind, $target, $count, $maxHops, $timeout)
        $lines = New-Object Collections.Generic.List[string]
        $addr = $null; $parsed = $null
        if ([Net.IPAddress]::TryParse("$target", [ref]$parsed)) { $addr = $parsed }
        else { try { $addr = @([Net.Dns]::GetHostAddresses("$target") | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0] } catch { } }
        if (-not $addr) { return "Unable to resolve target system name $target." }
        $pinger = New-Object Net.NetworkInformation.Ping
        $buf = New-Object byte[] 32
        # One throwaway loopback ping first: the first send of a session runs a few ms slow.
        try { [void]$pinger.Send([Net.IPAddress]::Loopback, 200) } catch { }
        try {
            if ($kind -eq 'Trace') {
                $lines.Add(''); $lines.Add(('Tracing route to {0} [{1}]' -f $target, $addr)); $lines.Add("over a maximum of $maxHops hops:"); $lines.Add('')
                for ($ttl = 1; $ttl -le $maxHops; $ttl++) {
                    $cells = @(); $hop = $null; $done = $false
                    for ($k = 0; $k -lt 3; $k++) {
                        $sw = [Diagnostics.Stopwatch]::StartNew(); $r = $null
                        try { $r = $pinger.Send($addr, $timeout, $buf, (New-Object Net.NetworkInformation.PingOptions($ttl, $false))) } catch { }
                        # .NET reports 0 ms for a TTL-expired reply, so the stopwatch times every probe.
                        $ms = [int][math]::Round($sw.Elapsed.TotalMilliseconds)
                        if ($r -and ("$($r.Status)" -eq 'TtlExpired' -or "$($r.Status)" -eq 'Success')) {
                            if ("$($r.Status)" -eq 'Success') { $ms = [int]$r.RoundtripTime; $done = $true }
                            $cells += $(if ($ms -lt 1) { '<1 ms' } else { "$ms ms" })
                            if (-not $hop) { $hop = "$($r.Address)" }
                        } else { $cells += '*' }
                    }
                    $lines.Add(('{0,3}  {1,8}  {2,8}  {3,8}  {4}' -f $ttl, $cells[0], $cells[1], $cells[2], $(if ($hop) { $hop } else { 'Request timed out.' })))
                    if ($done) { break }
                }
                $lines.Add(''); $lines.Add('Trace complete.')
            } else {
                $lines.Add(('Pinging {0} with 32 bytes of data:' -f $addr))
                for ($i = 0; $i -lt $count; $i++) {
                    $sw = [Diagnostics.Stopwatch]::StartNew(); $r = $null
                    try { $r = $pinger.Send($addr, $timeout, $buf) } catch { }
                    if ($r -and "$($r.Status)" -eq 'Success') {
                        $tt = if ($r.RoundtripTime -lt 1) { 'time<1ms' } else { "time=$($r.RoundtripTime)ms" }
                        $lines.Add(('Reply from {0}: bytes=32 {1} TTL={2}' -f $r.Address, $tt, $(if ($r.Options) { $r.Options.Ttl } else { 0 })))
                    } else { $lines.Add('Request timed out.') }
                    $rest = 1000 - $sw.ElapsedMilliseconds
                    if ($i -lt $count - 1 -and $rest -gt 0) { Start-Sleep -Milliseconds ([int]$rest) }
                }
            }
        } finally { $pinger.Dispose() }
        return ($lines -join "`r`n")
    }).AddArgument($Kind).AddArgument($Target).AddArgument($Count).AddArgument($MaxHops).AddArgument($TimeoutMs)
    return [pscustomobject]@{ Label = $Label; FilePath = $null; Arguments = $null; Process = $null; Task = $null; PS = $ps; Async = $ps.BeginInvoke() }
}

function Invoke-IcmpText {
    # Start-IcmpJob and wait for it: the text of one ping series or traceroute.
    param([ValidateSet('Ping', 'Trace')][string]$Kind, [string]$Target, [int]$Count = 4, [int]$MaxHops = 20, [int]$TimeoutMs = 1000, [int]$WaitSec = 120)
    return (Receive-NativeAsync (Start-IcmpJob -Kind $Kind -Target $Target -Count $Count -MaxHops $MaxHops -TimeoutMs $TimeoutMs -Label "$Kind $Target") $WaitSec)
}

function Receive-NativeAsync {
    param($Handle, [int]$TimeoutSec = 120)
    if ($Handle.PSObject.Properties['PS'] -and $Handle.PS) {
        if (-not $Handle.Async.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) { try { $Handle.PS.Stop() } catch { } }
        $txt = ''
        try { $txt = (@($Handle.PS.EndInvoke($Handle.Async)) -join "`r`n") } catch { }
        try { $Handle.PS.Dispose() } catch { }
        return $txt
    }
    if ($null -eq $Handle.Process) {
        # Constrained Language fallback: run synchronously now.
        return (Invoke-Native -FilePath $Handle.FilePath -Arguments $Handle.Arguments -TimeoutSec $TimeoutSec)
    }
    if (-not $Handle.Process.WaitForExit($TimeoutSec * 1000)) {
        try { $Handle.Process.Kill() } catch { }
        return ($Handle.Task.Result + "`r`n(timed out)")
    }
    $Handle.Process.WaitForExit()
    return $Handle.Task.Result
}

function Start-TcpSeries {
    # Background TCP connect series (one connect per second). Connect time is one round trip, so this
    # gives loss and jitter to hosts that drop ICMP, such as RDP gateways. FullLanguage only.
    param([string]$Target, [string]$Address, [int]$Port, [int]$Count)
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        param($a, $p, $n)
        $failRun = 0
        for ($i = 0; $i -lt $n; $i++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $c = New-Object Net.Sockets.TcpClient
            $ok = $false
            try { $ok = $c.ConnectAsync($a, $p).Wait(2000) -and $c.Connected } catch { }
            $ms = $sw.Elapsed.TotalMilliseconds
            try { $c.Close() } catch { }
            [pscustomobject]@{ Ok = $ok; Ms = [math]::Round($ms, 1) }
            # A target that stops answering would double the run time; 15 failures in a row ends the series.
            if ($ok) { $failRun = 0 } else { $failRun++; if ($failRun -ge 15) { break } }
            $rest = 1000 - $ms
            if ($rest -gt 0) { Start-Sleep -Milliseconds ([int]$rest) }
        }
    }).AddArgument($Address).AddArgument($Port).AddArgument($Count)
    return [pscustomobject]@{ Target = $Target; Address = $Address; Port = $Port; Count = $Count; PS = $ps; Async = $ps.BeginInvoke() }
}

function Receive-TcpSeries {
    param($Job, [int]$TimeoutSec = 150)
    if (-not $Job.Async.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) { try { $Job.PS.Stop() } catch { } }
    $rows = @()
    try { $rows = @($Job.PS.EndInvoke($Job.Async)) } catch { }
    try { $Job.PS.Dispose() } catch { }
    $times = @($rows | Where-Object { $_.Ok } | ForEach-Object { [double]$_.Ms })
    $sorted = @($times | Sort-Object)
    $jit = $null
    if ($times.Count -gt 1) { $d = 0; for ($k = 1; $k -lt $times.Count; $k++) { $d += [math]::Abs($times[$k] - $times[$k - 1]) }; $jit = [math]::Round($d / ($times.Count - 1), 1) }
    $sent = $rows.Count
    return [ordered]@{
        Target = $Job.Target; Address = $Job.Address; Port = $Job.Port; Method = 'TCP connect'
        Sent = $sent; Received = $times.Count
        LossPct = if ($sent) { [math]::Round(100 * ($sent - $times.Count) / $sent, 1) } else { $null }
        MinMs = if ($sorted.Count) { $sorted[0] } else { $null }
        AvgMs = if ($sorted.Count) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
        P95Ms = if ($sorted.Count) { $sorted[[math]::Min($sorted.Count - 1, [int][math]::Ceiling(0.95 * $sorted.Count) - 1)] } else { $null }
        MaxMs = if ($sorted.Count) { $sorted[-1] } else { $null }
        JitterMs = $jit
    }
}

function ConvertFrom-ColonText {
    # Parses "Key : Value" console output into an ordered hashtable (first value wins).
    param([string]$Text)
    $h = [ordered]@{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*([^:]+?)\s+:\s(.*)$') {
            $k = $matches[1].Trim(); $v = $matches[2].Trim()
            if (-not $h.Contains($k)) { $h[$k] = $v }
        }
    }
    return $h
}
function Get-Prop {
    # Reads $Obj.A.B... from hashtables or objects alike (live results and saved JSON); $null when absent.
    param($Obj, [string[]]$Path)
    foreach ($k in $Path) {
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($k)) { $Obj = $Obj[$k] } else { return $null } }
        else { $pp = $Obj.PSObject.Properties[$k]; if ($pp) { $Obj = $pp.Value } else { return $null } }
    }
    return $Obj
}

function Get-RegString {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

# =====================================================================
# PHASE 6: bandwidth (after the ping, TCP and trace series, so it does not distort them;
# before active discovery, so nothing that might upset security software runs ahead of it)
# Each direction fails over through $BandwidthProviders in order:
#   Cloudflare (download + upload) -> M-Lab NDT7 (download + upload) -> Vultr (download only).
# The helper functions below run inside Measure-Bandwidth and use its $client, $sw,
# $startProbe and $finishProbe through PowerShell's dynamic scoping.
# =====================================================================
function Get-MedianValue { param($Values) $s = @($Values | Where-Object { $null -ne $_ } | Sort-Object); if ($s.Count) { return [math]::Round([double]$s[[int][math]::Floor($s.Count / 2)], 1) } return $null }
