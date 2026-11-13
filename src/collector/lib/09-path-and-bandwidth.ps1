function Get-StunMappings {
    # Asks STUN servers, from one socket, which public address and port they see. The same port from
    # two servers means the NAT keeps one mapping per socket (good for calls); different ports means it does not.
    param($Servers, [int]$TimeoutMs = 1500)
    $out = @()
    $u = New-Object Net.Sockets.UdpClient
    try {
        $u.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)))
        $u.Client.ReceiveTimeout = $TimeoutMs
        try { [void]$u.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null) } catch { }
        foreach ($s in @($Servers)) {
            $row = [ordered]@{ Server = "$($s[0]):$($s[1])"; Answered = $false; MappedIp = $null; MappedPort = $null; LocalPort = $u.Client.LocalEndPoint.Port; Ms = $null }
            try {
                $addr = @([Net.Dns]::GetHostAddresses([string]$s[0]) | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0]
                $req = New-Object byte[] 20; $req[1] = 1; $req[4] = 0x21; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42
                $tx = [Guid]::NewGuid().ToByteArray(); [Array]::Copy($tx, 0, $req, 8, 12)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                [void]$u.Send($req, 20, (New-Object Net.IPEndPoint($addr, [int]$s[1])))
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $r = $u.Receive([ref]$ep)
                $row['Ms'] = [math]::Round($sw.Elapsed.TotalMilliseconds, 1); $row['Answered'] = $true
                $p = 20
                while ($p + 4 -le $r.Length) {
                    $t = ([int]$r[$p] * 256) + [int]$r[$p + 1]; $l = ([int]$r[$p + 2] * 256) + [int]$r[$p + 3]
                    if ($t -eq 0x0020 -and $l -ge 8) { $row['MappedPort'] = ((([int]$r[$p + 6] * 256) + [int]$r[$p + 7]) -bxor 0x2112); $row['MappedIp'] = '{0}.{1}.{2}.{3}' -f ([int]$r[$p + 8] -bxor 0x21), ([int]$r[$p + 9] -bxor 0x12), ([int]$r[$p + 10] -bxor 0xA4), ([int]$r[$p + 11] -bxor 0x42) }
                    elseif ($t -eq 0x0001 -and $l -ge 8 -and -not $row['MappedIp']) { $row['MappedPort'] = ([int]$r[$p + 6] * 256) + [int]$r[$p + 7]; $row['MappedIp'] = ConvertTo-IpText $r ($p + 8) }
                    $p += 4 + $l + ((4 - ($l % 4)) % 4)
                }
            } catch { }
            $out += [pscustomobject]$row
        }
    } catch { } finally { try { $u.Close() } catch { } }
    return $out
}

function Measure-VoicePath {
    # A call sends a packet every 20 ms. This pings at that pace and reports what a call would feel:
    # loss, bursts of loss, jitter and an estimated call-quality score (MOS, 1 to 4.4).
    param([string]$Target, [int]$Seconds = 20, [int]$PerSecond = 50)
    $n = $Seconds * $PerSecond; $interval = 1000.0 / $PerSecond
    $pool = @(); for ($i = 0; $i -lt 40; $i++) { $pool += New-Object Net.NetworkInformation.Ping }
    $tasks = New-Object object[] $n
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $n; $i++) {
        while ($sw.Elapsed.TotalMilliseconds -lt $i * $interval) { [Threading.Thread]::SpinWait(300) }
        try { $tasks[$i] = $pool[$i % 40].SendPingAsync($Target, 400) } catch { $tasks[$i] = $null }
    }
    Start-Sleep -Milliseconds 600
    $rtt = New-Object 'Collections.Generic.List[double]'; $lost = 0; $burst = 0; $maxBurst = 0; $jsum = 0.0; $jn = 0; $prev = $null
    foreach ($t in $tasks) {
        $ok = $false
        try { if ($t -and "$($t.Status)" -eq 'RanToCompletion' -and "$($t.Result.Status)" -eq 'Success') { $ok = $true } } catch { }
        if ($ok) { $v = [double]$t.Result.RoundtripTime; $rtt.Add($v); if ($null -ne $prev) { $jsum += [math]::Abs($v - $prev); $jn++ }; $prev = $v; $burst = 0 }
        else { $lost++; $burst++; if ($burst -gt $maxBurst) { $maxBurst = $burst } }
    }
    foreach ($p in $pool) { try { $p.Dispose() } catch { } }
    $r = [ordered]@{ Target = $Target; Sent = $n; Received = $rtt.Count; LossPct = [math]::Round(100.0 * $lost / $n, 2); LongestLossBurst = $maxBurst; AvgMs = $null; MaxMs = $null; P99Ms = $null; JitterMs = $null; Mos = $null; Rating = $null; PacketsPerSecond = $PerSecond; Seconds = $Seconds }
    if ($rtt.Count) {
        $sorted = @($rtt | Sort-Object)
        $avg = ($rtt | Measure-Object -Average).Average; $jit = if ($jn) { $jsum / $jn } else { 0 }
        $r['AvgMs'] = [math]::Round($avg, 1); $r['MaxMs'] = $sorted[-1]; $r['P99Ms'] = $sorted[[int][math]::Floor(($sorted.Count - 1) * 0.99)]; $r['JitterMs'] = [math]::Round($jit, 2)
        # Simplified E-model: one-way delay is half the round trip, jitter counts double, each 1% loss costs 2.5.
        $eff = ($avg / 2) + (2 * $jit) + 10
        $rf = if ($eff -lt 160) { 93.2 - ($eff / 40) } else { 93.2 - (($eff - 120) / 10) }
        $rf = [math]::Max(0.0, [double]($rf - (2.5 * $r['LossPct'])))
        $mos = 1 + (0.035 * $rf) + (0.000007 * $rf * ($rf - 60) * (100 - $rf))
        $r['Mos'] = [math]::Round([math]::Min(4.4, [math]::Max(1.0, [double]$mos)), 2)
        $r['Rating'] = if ($r['Mos'] -ge 4.0) { 'good' } elseif ($r['Mos'] -ge 3.6) { 'acceptable' } else { 'poor' }
    }
    return $r
}

function Get-PathMtu {
    param([string]$Target)
    $probe = {
        param($size)
        if ($script:FullLanguage) {
            # Don't-fragment ping of $size bytes; PacketTooBig is the "needs to be fragmented" answer in any language.
            try {
                $r = (New-Object Net.NetworkInformation.Ping).Send($Target, 1500, (New-Object byte[] $size), (New-Object Net.NetworkInformation.PingOptions(64, $true)))
                if ("$($r.Status)" -eq 'Success') { return 'ok' }
                if ("$($r.Status)" -eq 'PacketTooBig') { return 'frag' }
            } catch { }
            return 'none'
        }
        $o = Invoke-Native 'ping.exe' "-f -l $size -n 1 -w 1500 $Target" 6
        if ($o -match 'needs to be fragmented|Packet needs') { return 'frag' }
        if ($o -match '[=<]\s*\d+\s*(ms|\u043c\u0441)') { return 'ok' }
        return 'none'
    }
    $first = & $probe 1472
    if ($first -eq 'ok') { return [ordered]@{ Target = $Target; MtuBytes = 1500; Note = 'Full 1500' } }
    if ((& $probe 576) -ne 'ok') { return [ordered]@{ Target = $Target; MtuBytes = $null; Note = 'ICMP blocked or no reply' } }
    $lo = 548; $hi = 1472
    while ($hi - $lo -gt 4) {
        $mid = [int](($lo + $hi) / 2)
        if ((& $probe $mid) -eq 'ok') { $lo = $mid } else { $hi = $mid }
    }
    return [ordered]@{ Target = $Target; MtuBytes = $lo + 28; Note = 'Reduced (tunnel/PPPoE overhead likely)' }
}

function ConvertFrom-Tracert {
    param([string]$Text)
    $hops = @()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*(\d+)\s+(\*|<?\s*\d+\s*(?:ms|\u043c\u0441))\s+(\*|<?\s*\d+\s*(?:ms|\u043c\u0441))\s+(\*|<?\s*\d+\s*(?:ms|\u043c\u0441))\s+(.+?)\s*$') {
            $hopNum = [int]$matches[1]
            $rtts = @($matches[2], $matches[3], $matches[4]) | Where-Object { $_ -ne '*' } | ForEach-Object { [int](($_ -replace '[^\d]', '')) }
            $addr = $matches[5].Trim()
            $ip = if ($addr -match '(\d{1,3}(\.\d{1,3}){3})') { $matches[1] } else { $null }
            $hops += [pscustomobject]@{
                Hop = $hopNum; IP = $ip; Class = if ($ip) { Get-IpClass $ip } else { 'Timeout' }
                AvgMs = if ($rtts.Count) { [math]::Round((($rtts | Measure-Object -Average).Average), 1) } else { $null }
                Ptr = $null
            }
        }
    }
    return $hops
}

function Get-TraceAnalysis {
    param($Hops)
    $firstPublic = $Hops | Where-Object { $_.Class -eq 'Public' } | Select-Object -First 1
    $firstCgnat = $Hops | Where-Object { $_.Class -eq 'CGNAT' } | Select-Object -First 1
    $afterGw = @($Hops | Where-Object { $_.Hop -gt 1 -and (-not $firstPublic -or $_.Hop -lt $firstPublic.Hop) })
    $privateAfterGw = @($afterGw | Where-Object { $_.Class -eq 'Private' })
    # Private hops after a CGNAT hop are inside the carrier's network (Starlink, cellular, some cable ISPs).
    $carrierHops = @($privateAfterGw | Where-Object { $firstCgnat -and $_.Hop -gt $firstCgnat.Hop })
    $customerHops = @($privateAfterGw | Where-Object { -not ($firstCgnat -and $_.Hop -gt $firstCgnat.Hop) })
    # A customer-side private hop with real latency looks like a tunnel/MPLS (or ISP-internal); low latency = double NAT.
    $tunnelHops = @($customerHops | Where-Object { $_.AvgMs -ge 6 })
    [ordered]@{
        HopCount           = $Hops.Count
        FirstPublicHop     = if ($firstPublic) { $firstPublic.Hop } else { $null }
        FirstPublicIP      = if ($firstPublic) { $firstPublic.IP } else { $null }
        FirstPublicMs      = if ($firstPublic) { $firstPublic.AvgMs } else { $null }
        PrivateHopsAfterGw = @($customerHops | ForEach-Object { '{0}@{1}ms' -f $_.IP, $_.AvgMs })
        CarrierPrivateHops = @($carrierHops | ForEach-Object { '{0}@{1}ms' -f $_.IP, $_.AvgMs })
        CgnatHops          = @($Hops | Where-Object { $_.Class -eq 'CGNAT' }).Count
        TunnelIndicator    = ($tunnelHops.Count -gt 0)
        DoubleNatLikely    = ($customerHops.Count -gt 0 -and $tunnelHops.Count -eq 0)
        ReachedTarget      = $false
    }
}

function ConvertFrom-PingOutput {
    param([string]$Text, [string]$Target, [int]$Sent)
    $times = @()
    # 'time=12ms' in English, 'Zeit=12ms', 'temps=12 ms', 'tiempo<1 ms', Cyrillic 'ms'... the number after = or <, followed by ms.
    foreach ($m in [regex]::Matches($Text, '[=<]\s*(\d+)\s*(?:ms|\u043c\u0441)\b')) { $times += [int]$m.Groups[1].Value }
    $recv = $times.Count
    $sorted = @($times | Sort-Object)
    $jit = $null
    if ($times.Count -gt 1) { $d = 0; for ($k = 1; $k -lt $times.Count; $k++) { $d += [math]::Abs($times[$k] - $times[$k - 1]) }; $jit = [math]::Round($d / ($times.Count - 1), 1) }
    [ordered]@{
        Target  = $Target
        Sent    = $Sent
        Received = $recv
        LossPct = if ($Sent) { [math]::Round(100 * ($Sent - $recv) / $Sent, 1) } else { $null }
        MinMs   = if ($recv) { $sorted[0] } else { $null }
        AvgMs   = if ($recv) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
        P95Ms   = if ($recv) { $sorted[[math]::Min($sorted.Count - 1, [int][math]::Ceiling(0.95 * $sorted.Count) - 1)] } else { $null }
        MaxMs   = if ($recv) { $sorted[-1] } else { $null }
        JitterMs = $jit
    }
}

function ConvertTo-TraceResult {
    # Saves the raw tracert text next to the JSON and returns the parsed hops plus analysis.
    param([string]$Target, [string]$Text)
    Set-Content -LiteralPath (Join-Path $OutDir ('traceroute_{0}.txt' -f ($Target -replace '[^A-Za-z0-9\.-]', '_'))) -Value $Text
    $hops = @(ConvertFrom-Tracert $Text)
    $pub = 0
    foreach ($h in $hops) {
        if ($h.Class -eq 'Public' -and $pub -lt 2) { $h.Ptr = Resolve-Ptr $h.IP; $pub++ }
    }
    $an = Get-TraceAnalysis $hops
    $destIp = if ($Text -match '\[(\d{1,3}(\.\d{1,3}){3})\]') { $matches[1] } elseif (Test-IPv4 $Target) { $Target } else { $null }
    $lastHop = $hops | Where-Object { $_.IP } | Select-Object -Last 1
    $an['ReachedTarget'] = [bool]($destIp -and $lastHop -and $lastHop.IP -eq $destIp)
    $an['FirstPublicPtr'] = ($hops | Where-Object { $_.Ptr } | Select-Object -First 1).Ptr
    return [pscustomobject]@{ Target = $Target; Analysis = $an; Hops = $hops }
}

function Get-ThroughputStats {
    # Mbps over the run minus the TCP ramp-up (first 2 s or 20%), plus the best 1-second window.
    param($Samples, [double]$T0)
    if ($Samples.Count -lt 2) { return @(0, 0) }
    $dur = $Samples[$Samples.Count - 1].T - $T0
    $skip = $T0 + [math]::Min(2.0, $dur * 0.2)
    $a = $Samples | Where-Object { $_.T -ge $skip } | Select-Object -First 1
    $b = $Samples[$Samples.Count - 1]
    if (-not $a -or $b.T - $a.T -lt 0.5) { $a = $Samples[0] }
    $mbps = if ($b.T - $a.T -gt 0) { ($b.B - $a.B) * 8 / ($b.T - $a.T) / 1e6 } else { 0 }
    $peak = 0
    for ($x = 0; $x -lt $Samples.Count; $x++) {
        for ($y = $x + 1; $y -lt $Samples.Count; $y++) {
            if ($Samples[$y].T - $Samples[$x].T -ge 1.0) { $v = ($Samples[$y].B - $Samples[$x].B) * 8 / ($Samples[$y].T - $Samples[$x].T) / 1e6; if ($v -gt $peak) { $peak = $v }; break }
        }
    }
    return @([math]::Round($mbps, 1), [math]::Round($peak, 1))
}

function Invoke-HttpDownloadTest {
    # Multi-stream HTTP download for $BandwidthSeconds; $UrlFactory returns the URL for each new request.
    param([scriptblock]$UrlFactory, [int64]$CapBytes)
    $out = @{ Ok = $false; Mbps = $null; PeakMbps = $null; MB = 0; LoadedLatencyMs = $null; HttpStatus = @(); Errors = @(); Had429 = $false; RetryAfterSec = $null }
    $cts = New-Object Threading.CancellationTokenSource
    $streams = @{}
    $total = [int64]0
    $samples = New-Object Collections.Generic.List[object]
    $loaded = @()
    $probeTask = $null; $probeStart = 0; $lastProbe = 0
    $status = @{}; $errors = @(); $faults = 0
    $start = $sw.Elapsed.TotalSeconds
    $deadline = $start + $BandwidthSeconds
    $startStream = {
        param($slot)
        $req = $client.GetAsync((& $UrlFactory), [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token)
        $streams[$slot] = @{ Phase = 'head'; Req = $req; Stream = $null; Read = $null; Buf = (New-Object byte[] 262144) }
    }
    for ($s = 0; $s -lt $BandwidthStreams; $s++) { & $startStream $s }
    while ($sw.Elapsed.TotalSeconds -lt $deadline -and $total -lt $CapBytes) {
        $tasks = @()
        foreach ($k in @($streams.Keys)) {
            $st = $streams[$k]
            if ($st.Phase -eq 'head') { $tasks += $st.Req } elseif ($st.Phase -eq 'body' -and $st.Read) { $tasks += $st.Read }
        }
        if ($tasks.Count -eq 0) { break }   # every stream gave up (errors/non-200)
        [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$tasks, 100)
        foreach ($k in @($streams.Keys)) {
            $st = $streams[$k]
            if ($st.Phase -eq 'head' -and $st.Req.IsCompleted) {
                if ($st.Req.IsFaulted -or $st.Req.IsCanceled) {
                    $faults++
                    if ($st.Req.Exception) { $m = $st.Req.Exception.GetBaseException().Message; if ($errors -notcontains $m -and $errors.Count -lt 3) { $errors += $m } }
                    if ($faults -lt 20) { & $startStream $k } else { $st.Phase = 'dead' }
                    continue
                }
                $resp = $st.Req.Result
                $code = [int]$resp.StatusCode
                $status["$code"] = 1 + [int]$status["$code"]
                if (-not $resp.IsSuccessStatusCode) {
                    if ($code -eq 429) {
                        $out.Had429 = $true
                        try { $dlt = $resp.Headers.RetryAfter.Delta; if ($dlt) { $out.RetryAfterSec = [int]([TimeSpan]$dlt).TotalSeconds } } catch { }
                    }
                    # Stop this stream instead of hammering the endpoint.
                    try { $resp.Dispose() } catch { }
                    $st.Phase = 'dead'
                    continue
                }
                $st.Stream = $resp.Content.ReadAsStreamAsync().Result
                $st.Phase = 'body'
                $st.Read = $st.Stream.ReadAsync($st.Buf, 0, $st.Buf.Length, $cts.Token)
            } elseif ($st.Phase -eq 'body' -and $st.Read.IsCompleted) {
                $n = 0
                if (-not $st.Read.IsFaulted -and -not $st.Read.IsCanceled) { $n = $st.Read.Result }
                if ($n -gt 0) {
                    $total += $n
                    $st.Read = $st.Stream.ReadAsync($st.Buf, 0, $st.Buf.Length, $cts.Token)
                } else {
                    try { $st.Stream.Dispose(); $st.Req.Result.Dispose() } catch { }
                    & $startStream $k
                }
            }
        }
        $now = $sw.Elapsed.TotalSeconds
        if ($samples.Count -eq 0 -or $now - $samples[$samples.Count - 1].T -ge 0.25) { $samples.Add([pscustomobject]@{ T = $now; B = $total }) }
        if ($probeTask -and $probeTask.IsCompleted) {
            $lv = & $finishProbe $probeTask $probeStart
            if ($null -ne $lv) { $loaded += $lv }
            $probeTask = $null
        }
        if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $start -gt 0.3) {
            $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now
            $probeTask = & $startProbe
        }
    }
    $cts.Cancel()
    $samples.Add([pscustomobject]@{ T = $sw.Elapsed.TotalSeconds; B = $total })
    foreach ($k in @($streams.Keys)) { try { if ($streams[$k].Stream) { $streams[$k].Stream.Dispose() } } catch { } }
    if ($probeTask) { try { [void]$probeTask.Wait(2500) } catch { } }
    $stats = Get-ThroughputStats $samples $start
    $out.MB = [math]::Round($total / 1MB, 1)
    $out.HttpStatus = @($status.Keys | Sort-Object | ForEach-Object { '{0} x{1}' -f $_, $status[$_] })
    $out.Errors = $errors
    $out.LoadedLatencyMs = Get-MedianValue $loaded
    if ($total -ge 1MB) { $out.Ok = $true; $out.Mbps = $stats[0]; $out.PeakMbps = $stats[1] }
    return $out
}

function Invoke-CloudflareUpload {
    param([int64]$CapBytes)
    $out = @{ Ok = $false; Mbps = $null; MB = 0; LoadedLatencyMs = $null; HttpStatus = @(); Errors = @(); Had429 = $false; RetryAfterSec = $null }
    $rand = New-Object Random
    $payload = New-Object byte[] (16MB)
    $rand.NextBytes($payload)
    $size = 1MB
    $inflight = @{}
    $ulBytes = [int64]0
    $loaded = @(); $probeTask = $null; $probeStart = 0; $lastProbe = 0
    $status = @{}; $errors = @()
    $ulStart = $sw.Elapsed.TotalSeconds
    $ulDeadline = $ulStart + $BandwidthSeconds
    $lastDone = $ulStart
    $sent = [int64]0
    for ($s = 0; $s -lt $BandwidthStreams; $s++) {
        $inflight[$s] = @{ Task = $client.PostAsync('https://speed.cloudflare.com/__up', [Net.Http.ByteArrayContent]::new($payload, 0, $size)); Size = $size; Started = $sw.Elapsed.TotalSeconds }
        $sent += $size
    }
    while ($true) {
        $now = $sw.Elapsed.TotalSeconds
        $active = @($inflight.Keys | Where-Object { $inflight[$_] })
        if ($active.Count -eq 0) { break }
        if ($now -gt $ulDeadline + 8) { break }
        $tasks = @($active | ForEach-Object { $inflight[$_].Task })
        [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$tasks, 100)
        foreach ($k in $active) {
            $it = $inflight[$k]
            if (-not $it.Task.IsCompleted) { continue }
            $took = $sw.Elapsed.TotalSeconds - $it.Started
            $okPost = $false
            if (-not $it.Task.IsFaulted -and -not $it.Task.IsCanceled) {
                $resp = $it.Task.Result
                $code = [int]$resp.StatusCode
                $status["$code"] = 1 + [int]$status["$code"]
                if ($resp.IsSuccessStatusCode) {
                    $okPost = $true
                    $ulBytes += $it.Size; $lastDone = $sw.Elapsed.TotalSeconds
                    if ($took -lt 0.5 -and $size -lt 16MB) { $size = [int]($size * 2) }
                } elseif ($code -eq 429) {
                    $out.Had429 = $true
                    try { $dlt = $resp.Headers.RetryAfter.Delta; if ($dlt) { $out.RetryAfterSec = [int]([TimeSpan]$dlt).TotalSeconds } } catch { }
                }
                try { $resp.Dispose() } catch { }
            } elseif ($it.Task.Exception) {
                $m = $it.Task.Exception.GetBaseException().Message
                if ($errors -notcontains $m -and $errors.Count -lt 3) { $errors += $m }
            }
            $inflight[$k] = $null
            if ($okPost -and $sw.Elapsed.TotalSeconds -lt $ulDeadline -and $sent -lt $CapBytes) {
                $inflight[$k] = @{ Task = $client.PostAsync('https://speed.cloudflare.com/__up', [Net.Http.ByteArrayContent]::new($payload, 0, $size)); Size = $size; Started = $sw.Elapsed.TotalSeconds }
                $sent += $size
            }
        }
        $now = $sw.Elapsed.TotalSeconds
        if ($probeTask -and $probeTask.IsCompleted) {
            $lv = & $finishProbe $probeTask $probeStart
            if ($null -ne $lv) { $loaded += $lv }
            $probeTask = $null
        }
        if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $ulStart -gt 0.3 -and $now -lt $ulDeadline) {
            $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now
            $probeTask = & $startProbe
        }
    }
    if ($probeTask) { try { [void]$probeTask.Wait(2500) } catch { } }
    $ulDur = $lastDone - $ulStart
    $out.MB = [math]::Round($ulBytes / 1MB, 1)
    $out.HttpStatus = @($status.Keys | Sort-Object | ForEach-Object { '{0} x{1}' -f $_, $status[$_] })
    $out.Errors = $errors
    $out.LoadedLatencyMs = Get-MedianValue $loaded
    if ($ulBytes -ge 1MB -and $ulDur -gt 0) { $out.Ok = $true; $out.Mbps = [math]::Round($ulBytes * 8 / $ulDur / 1e6, 1) }
    return $out
}

function Get-MlabServers {
    # M-Lab's locate API returns the nearest NDT7 servers with short-lived access tokens.
    $l = Invoke-RestMethod -Uri 'https://locate.measurementlab.net/v2/nearest/ndt/ndt7' -UseBasicParsing -TimeoutSec 10
    return @(@($l.results) | ForEach-Object {
        [pscustomobject]@{ Machine = $_.machine; City = $_.location.city; Country = $_.location.country; Download = $_.urls.'wss:///ndt/v7/download'; Upload = $_.urls.'wss:///ndt/v7/upload' }
    } | Where-Object { $_.Download -and $_.Upload })
}

function Invoke-Ndt7Test {
    # One NDT7 test over WebSocket (protocol net.measurementlab.ndt.v7). Download: the server
    # streams for ~10 s. Upload: we send growing binary messages for $BandwidthSeconds.
    param([string]$Url, [string]$Direction, [int64]$CapBytes = [int64]::MaxValue)
    $out = @{ Ok = $false; Mbps = $null; PeakMbps = $null; ClientMbps = $null; ServerMbps = $null; MinRttMs = $null; MB = 0; LoadedLatencyMs = $null; Error = $null }
    $ws = New-Object Net.WebSockets.ClientWebSocket
    $ws.Options.AddSubProtocol('net.measurementlab.ndt.v7')
    $ws.Options.SetBuffer(65536, 65536)
    $cts = New-Object Threading.CancellationTokenSource
    $samples = New-Object Collections.Generic.List[object]
    $loaded = @(); $probeTask = $null; $probeStart = 0; $lastProbe = 0
    $total = [int64]0
    $lastServer = $null
    try {
        $connect = $ws.ConnectAsync([Uri]$Url, $cts.Token)
        if (-not $connect.Wait(10000)) { throw 'WebSocket connect timed out' }
        $buf = New-Object byte[] 1048576
        $seg = [ArraySegment[byte]]::new($buf)
        $text = New-Object Text.StringBuilder
        $start = $sw.Elapsed.TotalSeconds
        $recv = $ws.ReceiveAsync($seg, $cts.Token)
        $closed = $false
        $handleRecv = {
            # Returns $false once the server closes the connection.
            if ($recv.IsFaulted -or $recv.IsCanceled) { return $false }
            $r = $recv.Result
            if ("$($r.MessageType)" -eq 'Close') { return $false }
            if ("$($r.MessageType)" -eq 'Binary') { if ($Direction -eq 'download') { $script:ndtRecvBytes += $r.Count } }
            else {
                [void]$text.Append([Text.Encoding]::UTF8.GetString($buf, 0, $r.Count))
                if ($r.EndOfMessage) { $script:ndtLastServer = $text.ToString(); [void]$text.Clear() }
            }
            return $true
        }
        $script:ndtRecvBytes = [int64]0; $script:ndtLastServer = $null
        if ($Direction -eq 'download') {
            $deadline = $start + 13
            # The server streams for 10 s regardless of speed; stop early at the data cap.
            while (-not $closed -and $sw.Elapsed.TotalSeconds -lt $deadline -and $total -lt $CapBytes) {
                if ($recv.Wait(100)) {
                    if (& $handleRecv) { $recv = $ws.ReceiveAsync($seg, $cts.Token) } else { $closed = $true }
                }
                $total = $script:ndtRecvBytes
                $now = $sw.Elapsed.TotalSeconds
                if ($samples.Count -eq 0 -or $now - $samples[$samples.Count - 1].T -ge 0.25) { $samples.Add([pscustomobject]@{ T = $now; B = $total }) }
                if ($probeTask -and $probeTask.IsCompleted) { $lv = & $finishProbe $probeTask $probeStart; if ($null -ne $lv) { $loaded += $lv }; $probeTask = $null }
                if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $start -gt 0.3) { $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now; $probeTask = & $startProbe }
            }
        } else {
            $payload = New-Object byte[] (1MB)
            (New-Object Random).NextBytes($payload)
            $size = 8192
            $pending = 0
            $send = $null
            $deadline = $start + $BandwidthSeconds
            while (-not $closed -and $sw.Elapsed.TotalSeconds -lt $deadline) {
                if (-not $send -or $send.IsCompleted) {
                    if ($send -and ($send.IsFaulted -or $send.IsCanceled)) { throw "upload send failed: $($send.Exception.GetBaseException().Message)" }
                    if ($send) { $total += $pending }
                    # NDT7 guidance: grow the message while it is under 1/16 of what has been sent.
                    # Capped at 64 KB: larger frames from the .NET Framework client got reset by some servers.
                    if ($size -lt 64KB -and $total -ge 16 * $size) { $size = $size * 2 }
                    $pending = $size
                    $send = $ws.SendAsync([ArraySegment[byte]]::new($payload, 0, $size), [Net.WebSockets.WebSocketMessageType]::Binary, $true, $cts.Token)
                }
                if ($recv.IsCompleted) { if (& $handleRecv) { $recv = $ws.ReceiveAsync($seg, $cts.Token) } else { $closed = $true } }
                [void]$send.Wait(50)
                $now = $sw.Elapsed.TotalSeconds
                if ($samples.Count -eq 0 -or $now - $samples[$samples.Count - 1].T -ge 0.25) { $samples.Add([pscustomobject]@{ T = $now; B = $total }) }
                if ($probeTask -and $probeTask.IsCompleted) { $lv = & $finishProbe $probeTask $probeStart; if ($null -ne $lv) { $loaded += $lv }; $probeTask = $null }
                if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $start -gt 0.3) { $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now; $probeTask = & $startProbe }
            }
            if ($send -and $send.Wait(3000) -and -not $send.IsFaulted) { $total += $pending }
            # Give the server a moment to send its final measurement.
            $until = $sw.Elapsed.TotalSeconds + 1.5
            while (-not $closed -and $sw.Elapsed.TotalSeconds -lt $until) {
                if ($recv.Wait(100)) { if (& $handleRecv) { $recv = $ws.ReceiveAsync($seg, $cts.Token) } else { $closed = $true } }
            }
        }
        $samples.Add([pscustomobject]@{ T = $sw.Elapsed.TotalSeconds; B = $total })
        $lastServer = $script:ndtLastServer
        $stats = Get-ThroughputStats $samples $start
        $out.ClientMbps = $stats[0]; $out.PeakMbps = $stats[1]
        $out.MB = [math]::Round($total / 1MB, 1)
        if ($lastServer) {
            try {
                $m = $lastServer | ConvertFrom-Json
                $ti = $m.TCPInfo
                if ($ti -and $ti.ElapsedTime -gt 0) {
                    $bytes = if ($Direction -eq 'download') { [double]$ti.BytesAcked } else { [double]$ti.BytesReceived }
                    if ($bytes -gt 0) { $out.ServerMbps = [math]::Round($bytes * 8 / ([double]$ti.ElapsedTime / 1e6) / 1e6, 1) }
                    if ($ti.MinRTT) { $out.MinRttMs = [math]::Round([double]$ti.MinRTT / 1000, 1) }
                }
            } catch { }
        }
        # Upload bytes counted on our side include what is still queued in the socket, so prefer the server's figure there.
        $out.Mbps = if ($Direction -eq 'upload' -and $out.ServerMbps) { $out.ServerMbps } else { $out.ClientMbps }
        $out.Ok = ($total -ge 1MB -and $out.Mbps -gt 0)
    } catch {
        $out.Error = $_.Exception.GetBaseException().Message
    } finally {
        try { [void]$ws.CloseOutputAsync([Net.WebSockets.WebSocketCloseStatus]::NormalClosure, '', $cts.Token).Wait(2000) } catch { }
        try { $ws.Abort(); $ws.Dispose() } catch { }
        if ($probeTask) { try { [void]$probeTask.Wait(2500) } catch { } }
    }
    $out.LoadedLatencyMs = Get-MedianValue $loaded
    return $out
}

function Select-VultrUrl {
    # Fastest Vultr test file by time-to-first-response on a HEAD request.
    $best = $null; $bestMs = [double]::MaxValue
    foreach ($u in $VultrTestUrls) {
        $t0 = $sw.Elapsed.TotalMilliseconds
        try {
            $req = New-Object Net.Http.HttpRequestMessage([Net.Http.HttpMethod]::Head, $u)
            $resp = $client.SendAsync($req).Result
            $ms = $sw.Elapsed.TotalMilliseconds - $t0
            if ($resp.IsSuccessStatusCode -and $ms -lt $bestMs) { $best = $u; $bestMs = $ms }
            $resp.Dispose()
        } catch { }
    }
    return $best
}

function Update-Bufferbloat {
    # Bufferbloat = worst loaded latency minus idle latency, graded like common speed tests.
    param($Res)
    $worstLoaded = @($Res['DownloadLoadedLatencyMs'], $Res['UploadLoadedLatencyMs']) | Where-Object { $null -ne $_ } | Sort-Object -Descending | Select-Object -First 1
    $Res['BufferbloatMs'] = if ($null -ne $worstLoaded -and $null -ne $Res['IdleLatencyMs']) { [math]::Round($worstLoaded - $Res['IdleLatencyMs'], 1) } else { $null }
    $Res['BufferbloatGrade'] = if ($null -eq $Res['BufferbloatMs']) { $null } elseif ($Res['BufferbloatMs'] -lt 30) { 'A (good)' } elseif ($Res['BufferbloatMs'] -lt 100) { 'B (fair)' } elseif ($Res['BufferbloatMs'] -lt 250) { 'C (poor)' } else { 'D (bad)' }
}

function Measure-Bandwidth {
    # -Only limits the run to one direction (the retry phase uses it for whichever direction failed).
    param([string[]]$Only = @('Download', 'Upload'))
    # StartedAt/FinishedAt let the merge spot two machines at a site testing at the same time.
    $res = [ordered]@{ Providers = ($BandwidthProviders -join ' > '); Method = $null; StartedAt = Format-Date (Get-Date); FinishedAt = $null }
    $capBytes = [int64]$MaxTestMB * 1MB
    if (-not $script:FullLanguage) {
        # Constrained Language: plain cmdlets only, Cloudflare only, single stream.
        $res.Method = 'Invoke-WebRequest single stream (Constrained Language fallback, lower confidence)'
        try {
            $t0 = Get-Date
            $r = Invoke-WebRequest -Uri ('https://speed.cloudflare.com/__down?bytes={0}' -f [int64]([math]::Min(25MB, $capBytes / 2))) -UseBasicParsing -TimeoutSec 60
            $sec = ((Get-Date) - $t0).TotalSeconds
            $res['DownloadMbps'] = [math]::Round($r.RawContentLength * 8 / $sec / 1e6, 1); $res['DownloadOk'] = $true; $res['DownloadProvider'] = 'Cloudflare'
        } catch { $res['DownloadOk'] = $false; $res['DownloadFailure'] = $_.Exception.Message }
        try {
            $body = New-Object byte[] (5MB)
            $t0 = Get-Date
            Invoke-WebRequest -Uri 'https://speed.cloudflare.com/__up' -Method Post -Body $body -UseBasicParsing -TimeoutSec 60 | Out-Null
            $sec = ((Get-Date) - $t0).TotalSeconds
            $res['UploadMbps'] = [math]::Round($body.Length * 8 / $sec / 1e6, 1); $res['UploadOk'] = $true; $res['UploadProvider'] = 'Cloudflare'
        } catch { $res['UploadOk'] = $false; $res['UploadFailure'] = $_.Exception.Message }
        return $res
    }
    $res.Method = "$BandwidthStreams HTTP streams (Cloudflare/Vultr) or one WebSocket (M-Lab NDT7), $BandwidthSeconds s per direction"
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.UseProxy = $true
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $sw = [Diagnostics.Stopwatch]::StartNew()

    # Latency is measured with ICMP to 1.1.1.1 (comparable to the ping series);
    # HTTP round trips are the fallback when ICMP is blocked.
    $pinger = New-Object Net.NetworkInformation.Ping
    $useIcmp = $false
    try { $useIcmp = ($pinger.Send('1.1.1.1', 1000).Status -eq 'Success') } catch { }
    $res['LatencyMethod'] = if ($useIcmp) { 'ICMP to 1.1.1.1' } else { 'HTTP round trip to speed.cloudflare.com' }
    $startProbe = {
        if ($useIcmp) { return $pinger.SendPingAsync('1.1.1.1', 2000) }
        return $client.GetAsync('https://speed.cloudflare.com/__down?bytes=0', [Net.Http.HttpCompletionOption]::ResponseHeadersRead)
    }
    $finishProbe = {
        param($task, $startedMs)
        if ($task.IsFaulted -or $task.IsCanceled) { return $null }
        if ($useIcmp) { if ($task.Result.Status -eq 'Success') { return [double]$task.Result.RoundtripTime } return $null }
        try { $task.Result.Dispose() } catch { }
        return ($sw.Elapsed.TotalMilliseconds - $startedMs)
    }

    # Idle latency
    $idle = @()
    for ($i = 0; $i -lt 21; $i++) {
        $t = $sw.Elapsed.TotalMilliseconds
        $p = & $startProbe
        try { [void]$p.Wait(2500) } catch { }
        $v = & $finishProbe $p $t
        if ($i -gt 0 -and $null -ne $v) { $idle += $v }   # first probe warms up TLS/ARP and is discarded
        if ($useIcmp) { Start-Sleep -Milliseconds 100 }
    }
    $res['IdleLatencyMs'] = Get-MedianValue $idle
    if ($idle.Count -gt 1) { $d = 0; for ($k = 1; $k -lt $idle.Count; $k++) { $d += [math]::Abs($idle[$k] - $idle[$k - 1]) }; $res['IdleJitterMs'] = [math]::Round($d / ($idle.Count - 1), 1) }

    $attempts = New-Object Collections.Generic.List[object]
    $mlabCache = @{}
    $dlCap = [int64]($capBytes * 0.6)
    $ulCap = [int64]($capBytes * 0.4)

    $runDirection = {
        # Tries each provider in order for one direction; returns the first good result (or $null).
        # M-Lab upload is held back to the second pass: from Windows PowerShell's WebSocket client it
        # reads low, so Cloudflare gets a second chance first.
        param([string]$Dir, [int]$Pass = 1)
        foreach ($prov in $BandwidthProviders) {
            if ($Dir -eq 'Upload' -and $prov -eq 'MLab' -and $Pass -eq 1) { continue }
            $r = $null; $detail = $null; $label = $prov
            if ($prov -eq 'Cloudflare') {
                Write-Step "  $Dir via Cloudflare"
                $r = if ($Dir -eq 'Download') { Invoke-HttpDownloadTest { 'https://speed.cloudflare.com/__down?bytes=26214400' } $dlCap } else { Invoke-CloudflareUpload $ulCap }
                if (-not $r.Ok -and $r.Had429 -and $r.RetryAfterSec -ge 1 -and $r.RetryAfterSec -le 20) {
                    Write-Step ("  Cloudflare asked to wait {0} s; retrying once" -f $r.RetryAfterSec) 'Yellow'
                    Start-Sleep -Seconds $r.RetryAfterSec
                    $r = if ($Dir -eq 'Download') { Invoke-HttpDownloadTest { 'https://speed.cloudflare.com/__down?bytes=26214400' } $dlCap } else { Invoke-CloudflareUpload $ulCap }
                }
                $why = @()
                if ($r.HttpStatus) { $why += 'HTTP ' + ($r.HttpStatus -join ', ') }
                if ($r.Errors) { $why += $r.Errors[0] }
                if ($r.Had429) { $why += 'rate-limited' }
                $detail = $why -join '; '
            } elseif ($prov -eq 'MLab') {
                if (-not $mlabCache.ContainsKey('servers')) {
                    try { $mlabCache['servers'] = @(Get-MlabServers) } catch { $mlabCache['servers'] = @(); $mlabCache['error'] = $_.Exception.Message }
                }
                $servers = @($mlabCache['servers'])
                if ($servers.Count -eq 0) { $detail = "M-Lab locate failed: $($mlabCache['error'])" }
                foreach ($srv in ($servers | Select-Object -First 2)) {
                    # Each locate token is single use, so a server is only tried once per direction.
                    Write-Step ("  {0} via M-Lab ({1}{2})" -f $Dir, $srv.Machine.Split('.')[0], $(if ($srv.City) { ", $($srv.City)" } else { '' }))
                    $url = if ($Dir -eq 'Download') { $srv.Download } else { $srv.Upload }
                    $r = Invoke-Ndt7Test $url $Dir.ToLower() $(if ($Dir -eq 'Download') { $dlCap } else { $ulCap })
                    $label = "M-Lab NDT7 ($($srv.Machine.Split('.')[0]))"
                    $detail = if ($r.Ok) { "server-side $($r.ServerMbps) Mbps, min RTT $($r.MinRttMs) ms" } else { $r.Error }
                    if ($r.Ok -and $Dir -eq 'Upload') { $r['Note'] = 'M-Lab upload from this client reads low; treat as a lower bound' }
                    if ($r.Ok) { break }
                }
                # A fresh locate is needed for any later retry.
                $mlabCache.Remove('servers')
            } elseif ($prov -eq 'Vultr') {
                if ($Dir -ne 'Download') { continue }
                $vu = Select-VultrUrl
                if (-not $vu) { $detail = 'no Vultr test file reachable' }
                else {
                    $label = 'Vultr (' + ([Uri]$vu).Host.Split('.')[0] + ')'
                    Write-Step "  Download via $label"
                    $r = Invoke-HttpDownloadTest ([scriptblock]::Create("'$vu'")) $dlCap
                    $detail = if ($r.Ok) { $null } else { (@(if ($r.HttpStatus) { 'HTTP ' + ($r.HttpStatus -join ', ') }) + @($r.Errors | Select-Object -First 1)) -join '; ' }
                }
            } else { continue }
            $ok = [bool]($r -and $r.Ok)
            $attempts.Add([pscustomobject]@{ Direction = $Dir; Provider = $label; Ok = $ok; Mbps = $(if ($ok) { $r.Mbps }); Detail = $detail })
            if ($ok) { $r['Provider'] = $label; return $r }
            Write-Step ("  {0} via {1} failed: {2}" -f $Dir, $label, $detail) 'Yellow'
        }
        return $null
    }

    $wantDl = ($Only -contains 'Download'); $wantUl = ($Only -contains 'Upload')
    $dl = $null; $ul = $null
    if ($wantDl) { $dl = & $runDirection 'Download' }
    if ($wantUl) { $ul = & $runDirection 'Upload' }
    if (($wantDl -and -not $dl) -or ($wantUl -and -not $ul)) {
        # One more pass for whatever failed, after a pause (rate limits usually clear quickly).
        Write-Step '  Bandwidth incomplete; waiting 30 s and trying every provider once more' 'Yellow'
        Start-Sleep -Seconds 30
        if ($wantDl -and -not $dl) { $dl = & $runDirection 'Download' 2 }
        if ($wantUl -and -not $ul) { $ul = & $runDirection 'Upload' 2 }
    }

    foreach ($pair in @(@('Download', $dl), @('Upload', $ul))) {
        $dir = $pair[0]; $r = $pair[1]
        if ($Only -notcontains $dir) { continue }
        if ($r) {
            $res["${dir}Ok"] = $true
            $res["${dir}Mbps"] = $r.Mbps
            if ($dir -eq 'Download') { $res['DownloadPeakMbps'] = $r.PeakMbps }
            $res["${dir}MB"] = $r.MB
            $res["${dir}LoadedLatencyMs"] = $r.LoadedLatencyMs
            $res["${dir}Provider"] = $r.Provider
            if ($r.ServerMbps) { $res["${dir}ServerMbps"] = $r.ServerMbps }
            if ($r.MinRttMs) { $res["${dir}MinRttMs"] = $r.MinRttMs }
            $failedFirst = @($attempts | Where-Object { $_.Direction -eq $dir -and -not $_.Ok } | ForEach-Object { $_.Provider } | Select-Object -Unique)
            $noteParts = @()
            if ($failedFirst.Count) { $noteParts += "Fallback used after: $($failedFirst -join ', ')" }
            if ($r.Note) { $noteParts += $r.Note }
            if ($noteParts.Count) { $res["${dir}Note"] = $noteParts -join '; ' }
        } else {
            $res["${dir}Ok"] = $false
            $res["${dir}Mbps"] = $null
            $res["${dir}Failure"] = ((@($attempts | Where-Object Direction -eq $dir) | ForEach-Object { '{0}: {1}' -f $_.Provider, $_.Detail }) -join ' | ')
        }
    }
    $res['Attempts'] = $attempts.ToArray()   # @() on a generic List fails when stored in an ordered dictionary
    Update-Bufferbloat $res
    $res['TestedOver'] = '{0} - {1}' -f $Result['Network']['PhysicalClass'], $Result['Network']['PhysicalAdapter']
    $res['FinishedAt'] = Format-Date (Get-Date)
    try { $client.Dispose(); $pinger.Dispose() } catch { }
    return $res
}
function Test-TraceUsable { param($T) return [bool]($T -and @($T.Hops | Where-Object { $_.IP }).Count -ge 2) }
