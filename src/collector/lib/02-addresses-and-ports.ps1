function Test-SameSubnet {
    # True when $Ip is inside the subnet of $LocalIp/$Mask (dotted IPv4 only).
    param([string]$Ip, [string]$LocalIp, [string]$Mask)
    $toInt = { param($s) $o = "$s".Split('.'); if ($o.Count -ne 4) { return $null }; ([int64]$o[0] -shl 24) + ([int64]$o[1] -shl 16) + ([int64]$o[2] -shl 8) + [int64]$o[3] }
    $a = & $toInt $Ip; $b = & $toInt $LocalIp; $m = & $toInt $Mask
    if ($null -eq $a -or $null -eq $b -or $null -eq $m) { return $false }
    return (($a -band $m) -eq ($b -band $m))
}

# ---------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------
function Test-IPv4 { param([string]$Ip) return ($Ip -match '^\d{1,3}(\.\d{1,3}){3}$') }

function Get-IpClass {
    param([string]$Ip)
    if (-not (Test-IPv4 $Ip)) {
        if ($Ip -match '^(fe80|fc|fd)') { return 'Private' }
        if ($Ip -match ':') { return 'Public' }
        return 'Unknown'
    }
    $o = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o[0] -eq 10) { return 'Private' }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return 'Private' }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return 'Private' }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return 'CGNAT' }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return 'LinkLocal' }
    if ($o[0] -eq 127) { return 'Loopback' }
    return 'Public'
}

function Resolve-Ptr {
    param([string]$Ip)
    try {
        $r = Resolve-DnsName -Name $Ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1
        if ($r -and $r.NameHost -notmatch 'localhost|^undefined') { return $r.NameHost }
    } catch { }
    return $null
}

function Test-TcpPort {
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 1000)
    $c = New-Object Net.Sockets.TcpClient
    try { $t = $c.ConnectAsync($Address, $Port); return ($t.Wait($TimeoutMs) -and $c.Connected) }
    catch { return $false }
    finally { $c.Close() }
}

function Test-TcpPortsBulk {
    # TCP connect check of every IP x port pair, 400 at a time. Returns @{ ip = @(open ports) }.
    param([string[]]$Ips, [int[]]$Ports, [int]$TimeoutMs = 800)
    $open = @{}
    $pairs = New-Object Collections.Generic.List[object]
    foreach ($ip in $Ips) { foreach ($p in $Ports) { $pairs.Add(@($ip, $p)) } }
    for ($i = 0; $i -lt $pairs.Count; $i += 400) {
        $batch = @(); $tasks = @()
        for ($j = $i; $j -lt [math]::Min($i + 400, $pairs.Count); $j++) {
            $c = New-Object Net.Sockets.TcpClient
            $t = $null
            try { $t = $c.ConnectAsync([string]$pairs[$j][0], [int]$pairs[$j][1]) } catch { }
            $batch += , @($pairs[$j][0], $pairs[$j][1], $c, $t)
            if ($t) { $tasks += $t }
        }
        if ($tasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, $TimeoutMs) } catch { } }
        foreach ($b in $batch) {
            if ($b[3] -and "$($b[3].Status)" -eq 'RanToCompletion' -and $b[2].Connected) {
                if (-not $open.ContainsKey($b[0])) { $open[$b[0]] = @() }
                $open[$b[0]] += [int]$b[1]
            }
            try { $b[2].Close() } catch { }
        }
    }
    return $open
}

function Invoke-UdpProbe {
    # Sends datagrams from one socket and returns every reply heard within $WaitMs as IP, Port, Data.
    # $Sends is a list of @{ Address; Port; Bytes }. With -ListenPort the socket binds that port on
    # every address, for protocols whose answers are broadcast (MikroTik, Netgear).
    param($Sends, [string]$SourceIp, [int]$ListenPort = 0, [int]$WaitMs = 2500, [int]$MaxReplies = 3000)
    $replies = New-Object Collections.Generic.List[object]
    $udp = New-Object Net.Sockets.UdpClient
    try {
        $udp.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket, [Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $udp.EnableBroadcast = $true
        try { $udp.Client.ReceiveBufferSize = 1048576 } catch { }
        # Without this a refused datagram (ICMP port unreachable) makes the next receive fail on Windows.
        try { [void]$udp.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null) } catch { }
        $bindIp = if ($ListenPort -eq 0 -and $SourceIp -and (Test-IPv4 $SourceIp)) { [Net.IPAddress]::Parse($SourceIp) } else { [Net.IPAddress]::Any }
        $udp.Client.Bind((New-Object Net.IPEndPoint($bindIp, $ListenPort)))
        foreach ($s in @($Sends)) {
            try {
                $bytes = [byte[]]$s.Bytes
                [void]$udp.Send($bytes, $bytes.Length, (New-Object Net.IPEndPoint([Net.IPAddress]::Parse([string]$s.Address), [int]$s.Port)))
            } catch { }
        }
        $until = (Get-Date).AddMilliseconds($WaitMs); $rt = $null
        while ((Get-Date) -lt $until -and $replies.Count -lt $MaxReplies) {
            try {
                if (-not $rt) { $rt = $udp.ReceiveAsync() }
                if (-not $rt.Wait(200)) { continue }
                $res = $rt.Result; $rt = $null
                $ip = $res.RemoteEndPoint.Address.ToString()
                if ($ip -eq $SourceIp) { continue }
                $replies.Add([pscustomobject]@{ IP = $ip; Port = $res.RemoteEndPoint.Port; Data = $res.Buffer })
            } catch { $rt = $null }
        }
    } finally { try { $udp.Close() } catch { } }
    return $replies.ToArray()
}

function Get-BroadcastAddress {
    param([string]$Ip, [string]$Mask)
    try {
        $i = [Net.IPAddress]::Parse($Ip).GetAddressBytes(); $m = [Net.IPAddress]::Parse($Mask).GetAddressBytes()
        return ('{0}.{1}.{2}.{3}' -f ([int]$i[0] -bor (255 - [int]$m[0])), ([int]$i[1] -bor (255 - [int]$m[1])), ([int]$i[2] -bor (255 - [int]$m[2])), ([int]$i[3] -bor (255 - [int]$m[3])))
    } catch { return $null }
}

# ---------------------------------------------------------------------
# Other subnets: which ones this PC knows it can reach, which ones to sweep, and the sweep itself.
# Only subnets listed in CONFIG or chosen at the prompt are swept; inferred ones are only reported.
# ---------------------------------------------------------------------
function ConvertTo-IpNumber { param([string]$Ip) $o = "$Ip".Split('.'); return ([int64]$o[0] -shl 24) + ([int64]$o[1] -shl 16) + ([int64]$o[2] -shl 8) + [int64]$o[3] }
function ConvertFrom-IpNumber { param([int64]$N) return '{0}.{1}.{2}.{3}' -f (($N -shr 24) -band 255), (($N -shr 16) -band 255), (($N -shr 8) -band 255), ($N -band 255) }

function ConvertTo-NetRange {
    # Network number and broadcast number of $Ip/$Prefix (any prefix).
    param([string]$Ip, [int]$Prefix)
    $maskInt = ([int64]4294967295 -shl (32 - $Prefix)) -band [int64]4294967295
    $net = (ConvertTo-IpNumber $Ip) -band $maskInt
    return [pscustomobject]@{ NetInt = $net; End = $net + ([int64]1 -shl (32 - $Prefix)) - 1; Prefix = $Prefix }
}
