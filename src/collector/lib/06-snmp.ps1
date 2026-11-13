# ---------------------------------------------------------------------
# v1.7.0 helpers: SNMP (read only), Windows build from the file-sharing handshake, IPP, RTSP, STUN,
# NTP and the fast ping used for the voice sample.
# ---------------------------------------------------------------------
function ConvertTo-BerLength { param([int]$Len) if ($Len -lt 128) { return , ([byte[]]@($Len)) } elseif ($Len -lt 256) { return , ([byte[]]@(0x81, $Len)) } else { return , ([byte[]]@(0x82, ($Len -shr 8), ($Len -band 255))) } }
function Join-Bytes {
    # Concatenates byte arrays (and single values) into one byte[].
    $l = New-Object Collections.Generic.List[byte]
    foreach ($a in $args) { if ($null -ne $a) { $l.AddRange([byte[]]$a) } }
    return , $l.ToArray()
}
function ConvertTo-BerTlv { param([int]$Tag, [byte[]]$Value) if ($null -eq $Value) { $Value = [byte[]]@() }; return , (Join-Bytes ([byte[]]@($Tag)) (ConvertTo-BerLength $Value.Length) $Value) }
function ConvertTo-BerInt {
    param([int]$N)
    $b = New-Object Collections.Generic.List[byte]; $v = $N
    do { $b.Insert(0, [byte]($v -band 255)); $v = $v -shr 8 } while ($v -gt 0)
    if ($b[0] -band 0x80) { $b.Insert(0, 0) }
    return , (ConvertTo-BerTlv 2 $b.ToArray())
}
function ConvertTo-BerOid {
    param([string]$Oid)
    $p = @($Oid.Trim('.').Split('.') | ForEach-Object { [uint32]$_ })
    $b = New-Object Collections.Generic.List[byte]
    $b.Add([byte](($p[0] * 40) + $p[1]))
    for ($i = 2; $i -lt $p.Count; $i++) {
        $v = $p[$i]; $chunk = New-Object Collections.Generic.List[byte]
        $chunk.Add([byte]($v -band 0x7F)); $v = $v -shr 7
        while ($v -gt 0) { $chunk.Insert(0, [byte](($v -band 0x7F) -bor 0x80)); $v = $v -shr 7 }
        $b.AddRange($chunk)
    }
    return , (ConvertTo-BerTlv 6 $b.ToArray())
}
function New-SnmpRequest {
    # SNMP v2c message. $PduType: 0xA0 get, 0xA1 get-next, 0xA5 get-bulk (then the two numbers are
    # non-repeaters and max-repetitions).
    param([int]$PduType, [string]$Community, [int]$RequestId, [string[]]$Oids, [int]$NonRepeaters = 0, [int]$MaxRepetitions = 0)
    $vb = New-Object Collections.Generic.List[byte]
    foreach ($o in $Oids) { $vb.AddRange([byte[]](ConvertTo-BerTlv 0x30 (Join-Bytes (ConvertTo-BerOid $o) ([byte[]]@(5, 0))))) }
    $pdu = Join-Bytes (ConvertTo-BerInt $RequestId) (ConvertTo-BerInt $NonRepeaters) (ConvertTo-BerInt $MaxRepetitions) (ConvertTo-BerTlv 0x30 $vb.ToArray())
    $msg = Join-Bytes (ConvertTo-BerInt 1) (ConvertTo-BerTlv 4 ([Text.Encoding]::ASCII.GetBytes($Community))) (ConvertTo-BerTlv $PduType $pdu)
    return , (ConvertTo-BerTlv 0x30 $msg)
}
function Read-BerTlv {
    # Returns @(tag, value start, value length, offset after) or $null.
    param([byte[]]$B, [int]$Pos)
    if ($Pos -lt 0 -or $Pos + 2 -gt $B.Length) { return $null }
    $tag = [int]$B[$Pos]; $l = [int]$B[$Pos + 1]; $p = $Pos + 2
    if ($l -band 0x80) {
        $n = $l -band 0x7F
        if ($n -lt 1 -or $n -gt 3 -or $p + $n -gt $B.Length) { return $null }
        $l = 0; for ($i = 0; $i -lt $n; $i++) { $l = ($l * 256) + [int]$B[$p + $i] }
        $p += $n
    }
    if ($p + $l -gt $B.Length) { return $null }
    return @($tag, $p, $l, ($p + $l))
}
function ConvertFrom-BerValue {
    param([byte[]]$B, [int]$Tag, [int]$Start, [int]$Len)
    if ($Tag -eq 6) {
        if ($Len -lt 1) { return '' }
        $parts = New-Object Collections.Generic.List[string]
        $parts.Add([string][math]::Floor([int]$B[$Start] / 40)); $parts.Add([string]([int]$B[$Start] % 40))
        $v = [uint64]0
        for ($i = $Start + 1; $i -lt $Start + $Len; $i++) { $v = ($v * 128) + ([int]$B[$i] -band 0x7F); if (-not ([int]$B[$i] -band 0x80)) { $parts.Add([string]$v); $v = [uint64]0 } }
        return ($parts -join '.')
    }
    if ($Tag -eq 2) { $v = [int64]0; if ($Len -gt 0 -and ([int]$B[$Start] -band 0x80)) { $v = -1 }; for ($i = 0; $i -lt $Len; $i++) { $v = ($v * 256) + [int]$B[$Start + $i] }; return $v }
    if ($Tag -eq 0x41 -or $Tag -eq 0x42 -or $Tag -eq 0x43 -or $Tag -eq 0x46) { $v = [uint64]0; for ($i = 0; $i -lt $Len; $i++) { $v = ($v * 256) + [uint64]$B[$Start + $i] }; return $v }
    if ($Tag -eq 0x40 -and $Len -eq 4) { return ConvertTo-IpText $B $Start }
    if ($Tag -eq 4) {
        if ($Len -eq 0) { return '' }
        $printable = $true
        for ($i = $Start; $i -lt $Start + $Len; $i++) { $ch = [int]$B[$i]; if (($ch -lt 32 -and $ch -ne 9 -and $ch -ne 10 -and $ch -ne 13 -and $ch -ne 0) -or $ch -gt 126) { $printable = $false; break } }
        if ($printable) { return ((([Text.Encoding]::ASCII.GetString($B, $Start, $Len)) -replace '[^\x20-\x7E]', ' ') -replace '\s+', ' ').Trim() }
        return [BitConverter]::ToString($B, $Start, $Len)
    }
    if ($Tag -eq 0x80) { return 'noSuchObject' } if ($Tag -eq 0x81) { return 'noSuchInstance' } if ($Tag -eq 0x82) { return 'endOfMibView' }
    return $null
}
function ConvertFrom-SnmpResponse {
    # The variable bindings of an SNMP message as Oid, Type, Value.
    param([byte[]]$B)
    $out = @()
    if (-not $B) { return $out }
    $m = Read-BerTlv $B 0; if (-not $m -or $m[0] -ne 0x30) { return $out }
    $v = Read-BerTlv $B $m[1]; if (-not $v) { return $out }
    $c = Read-BerTlv $B $v[3]; if (-not $c) { return $out }
    $pdu = Read-BerTlv $B $c[3]; if (-not $pdu) { return $out }
    $rid = Read-BerTlv $B $pdu[1]; if (-not $rid) { return $out }
    $es = Read-BerTlv $B $rid[3]; if (-not $es) { return $out }
    $ei = Read-BerTlv $B $es[3]; if (-not $ei) { return $out }
    $vbl = Read-BerTlv $B $ei[3]; if (-not $vbl) { return $out }
    $p = $vbl[1]; $end = $vbl[3]
    while ($p -lt $end) {
        $vb = Read-BerTlv $B $p; if (-not $vb) { break }
        $o = Read-BerTlv $B $vb[1]; if (-not $o -or $o[0] -ne 6) { break }
        $val = Read-BerTlv $B $o[3]; if (-not $val) { break }
        $out += [pscustomobject]@{ Oid = (ConvertFrom-BerValue $B 6 $o[1] $o[2]); Type = $val[0]; Value = (ConvertFrom-BerValue $B $val[0] $val[1] $val[2]) }
        $p = $vb[3]
    }
    return $out
}
function Get-SnmpValues {
    # One GET for several OIDs. Returns @{ oid = value } for the ones that exist, or $null when nothing answered.
    param([string]$Ip, [string]$Community, [string[]]$Oids, [int]$TimeoutMs = 1500)
    $u = New-Object Net.Sockets.UdpClient
    try {
        $u.Client.ReceiveTimeout = $TimeoutMs; $u.Connect($Ip, 161)
        $pkt = New-SnmpRequest 0xA0 $Community (Get-Random -Minimum 1000 -Maximum 60000) $Oids
        for ($t = 0; $t -lt 2; $t++) {
            try {
                [void]$u.Send($pkt, $pkt.Length)
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $resp = $u.Receive([ref]$ep)
                $h = @{}
                foreach ($vb in @(ConvertFrom-SnmpResponse $resp)) { if ($vb.Type -lt 0x80 -and $null -ne $vb.Value) { $h["$($vb.Oid)"] = $vb.Value } }
                return $h
            } catch { }
        }
    } catch { } finally { try { $u.Close() } catch { } }
    return $null
}
function Invoke-SnmpWalk {
    # Reads one table column (everything under $Base) with get-bulk, falling back to get-next for old agents.
    # Returns rows of Index (the part of the OID after $Base) and Value.
    param([string]$Ip, [string]$Community, [string]$Base, [int]$MaxRows = 300, [int]$TimeoutMs = 1500)
    $rows = New-Object Collections.Generic.List[object]
    $root = $Base.Trim('.'); $cur = $root; $rid = Get-Random -Minimum 1000 -Maximum 50000; $bulk = $true
    $u = New-Object Net.Sockets.UdpClient
    try {
        $u.Client.ReceiveTimeout = $TimeoutMs; $u.Connect($Ip, 161)
        while ($rows.Count -lt $MaxRows) {
            $rid++
            $pkt = if ($bulk) { New-SnmpRequest 0xA5 $Community $rid @($cur) 0 20 } else { New-SnmpRequest 0xA1 $Community $rid @($cur) }
            $resp = $null
            for ($t = 0; $t -lt 2 -and -not $resp; $t++) { try { [void]$u.Send($pkt, $pkt.Length); $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); $resp = $u.Receive([ref]$ep) } catch { } }
            $vbs = @(ConvertFrom-SnmpResponse $resp)
            if (-not $vbs.Count) { if ($bulk -and $rows.Count -eq 0) { $bulk = $false; continue }; break }
            $done = $false
            foreach ($vb in $vbs) {
                $oid = "$($vb.Oid)"
                if ($vb.Type -ge 0x80 -or -not $oid.StartsWith("$root.") -or $oid -eq $cur) { $done = $true; break }
                $rows.Add([pscustomobject]@{ Index = $oid.Substring($root.Length + 1); Value = $vb.Value }); $cur = $oid
                if ($rows.Count -ge $MaxRows) { $done = $true; break }
            }
            if ($done) { break }
        }
    } catch { } finally { try { $u.Close() } catch { } }
    return $rows.ToArray()
}

# ---------------------------------------------------------------------
# Router and UPS tables over SNMP (read only, same community as the rest of the SNMP step).
# The parsers take the rows Invoke-SnmpWalk returns (Index = the OID part after the column).
# ---------------------------------------------------------------------
function ConvertFrom-SnmpMac {
    # A MAC from an SNMP octet string; $null unless it is six bytes that are not all zero.
    param($Value)
    $v = "$Value".Trim().ToUpper() -replace ':', '-'
    if ($v -notmatch '^([0-9A-F]{2}-){5}[0-9A-F]{2}$' -or $v -eq '00-00-00-00-00-00' -or $v -eq 'FF-FF-FF-FF-FF-FF') { return $null }
    return $v
}

function ConvertFrom-ArpRows {
    # ipNetToMediaPhysAddress (1.3.6.1.2.1.4.22.1.2, index ifIndex.a.b.c.d) or ipNetToPhysicalPhysAddress
    # (1.3.6.1.2.1.4.35.1.4, index ifIndex.1.4.a.b.c.d for IPv4) -> IP, Mac, IfIndex.
    param($Rows)
    $out = @()
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $p = @("$($r.Index)" -split '\.')
        $ip = $null
        if ($p.Count -eq 5) { $ip = ($p[1..4]) -join '.' }
        elseif ($p.Count -eq 7 -and $p[1] -eq '1' -and $p[2] -eq '4') { $ip = ($p[3..6]) -join '.' }
        $mac = ConvertFrom-SnmpMac $r.Value
        if ($ip -and $mac) { $out += [pscustomobject]@{ IP = $ip; Mac = $mac; IfIndex = [int]$p[0] } }
    }
    return $out
}

function ConvertFrom-AddrRows {
    # ipAdEntIfIndex (1.3.6.1.2.1.4.20.1.2) and ipAdEntNetMask (1.3.6.1.2.1.4.20.1.3), both indexed by the
    # address -> IP, Mask, Prefix, IfIndex, Class. Loopback addresses are left out.
    param($IfRows, $MaskRows)
    $masks = @{}; foreach ($m in @($MaskRows)) { if ($m) { $masks["$($m.Index)"] = "$($m.Value)" } }
    $out = @()
    foreach ($r in @($IfRows)) {
        if (-not $r -or -not (Test-IPv4 "$($r.Index)") -or "$($r.Index)" -like '127.*') { continue }
        $mk = $masks["$($r.Index)"]; $pre = $null
        if (Test-IPv4 $mk) { $pre = 0; $mi = ConvertTo-IpNumber $mk; for ($bit = 31; $bit -ge 0; $bit--) { if (($mi -shr $bit) -band 1) { $pre++ } else { break } } }
        $out += [pscustomobject]@{ IP = "$($r.Index)"; Mask = $mk; Prefix = $pre; IfIndex = [int]$r.Value; Class = (Get-IpClass "$($r.Index)") }
    }
    return $out
}

function ConvertFrom-RouteRows {
    # ipCidrRouteNextHop (1.3.6.1.2.1.4.24.4.1.4, index dest.mask.tos.nexthop) -> Destination, Prefix, NextHop.
    # Or, with -Legacy, ipRouteNextHop (1.3.6.1.2.1.4.21.1.7, index dest) plus ipRouteMask rows.
    param($Rows, $MaskRows = @(), [switch]$Legacy)
    $toPrefix = { param($mk) if (-not (Test-IPv4 $mk)) { return $null }; $n = 0; $mi = ConvertTo-IpNumber $mk; for ($bit = 31; $bit -ge 0; $bit--) { if (($mi -shr $bit) -band 1) { $n++ } else { break } }; $n }
    $out = @()
    if ($Legacy) {
        $masks = @{}; foreach ($m in @($MaskRows)) { if ($m) { $masks["$($m.Index)"] = "$($m.Value)" } }
        foreach ($r in @($Rows)) { if ($r -and (Test-IPv4 "$($r.Index)")) { $out += [pscustomobject]@{ Destination = "$($r.Index)"; Prefix = (& $toPrefix $masks["$($r.Index)"]); NextHop = "$($r.Value)" } } }
    } else {
        foreach ($r in @($Rows)) {
            $p = @("$($r.Index)" -split '\.')
            if ($p.Count -ne 13) { continue }
            $out += [pscustomobject]@{ Destination = ($p[0..3] -join '.'); Prefix = (& $toPrefix ($p[4..7] -join '.')); NextHop = "$($r.Value)" }
        }
    }
    return @($out | Sort-Object { ConvertTo-IpNumber $_.Destination }, Prefix)
}

function Get-UpsOidMap {
    # The UPS values read over SNMP: RFC 1628 UPS-MIB, or with -Apc the APC PowerNet-MIB for network
    # cards that do not answer UPS-MIB.
    param([switch]$Apc)
    if ($Apc) {
        return [ordered]@{
            Model = '1.3.6.1.4.1.318.1.1.1.1.1.1.0'; BatteryStatus = '1.3.6.1.4.1.318.1.1.1.2.1.1.0'; ChargePct = '1.3.6.1.4.1.318.1.1.1.2.2.1.0'
            RuntimeTicks = '1.3.6.1.4.1.318.1.1.1.2.2.3.0'; ReplaceBattery = '1.3.6.1.4.1.318.1.1.1.2.2.4.0'; OutputStatus = '1.3.6.1.4.1.318.1.1.1.4.1.1.0'; LoadPct = '1.3.6.1.4.1.318.1.1.1.4.2.3.0'
        }
    }
    return [ordered]@{
        Manufacturer = '1.3.6.1.2.1.33.1.1.1.0'; Model = '1.3.6.1.2.1.33.1.1.2.0'; BatteryStatus = '1.3.6.1.2.1.33.1.2.1.0'
        MinutesRemaining = '1.3.6.1.2.1.33.1.2.3.0'; ChargePct = '1.3.6.1.2.1.33.1.2.4.0'; OutputSource = '1.3.6.1.2.1.33.1.4.1.0'; LoadPct = '1.3.6.1.2.1.33.1.4.4.1.5.1'
    }
}

function ConvertTo-UpsStatus {
    # Values read with $UpsOids (-Standard) or $ApcUpsOids (-Apc) -> one plain UPS record, or $null.
    param($Standard, $Apc)
    $UpsOids = Get-UpsOidMap; $ApcUpsOids = Get-UpsOidMap -Apc
    $num = { param($v) if ($null -eq $v -or "$v" -eq '') { return $null }; try { return [double]$v } catch { return $null } }
    if ($Standard -and ($Standard[$UpsOids.Model] -or $Standard[$UpsOids.BatteryStatus])) {
        $bs = & $num $Standard[$UpsOids.BatteryStatus]; $src = & $num $Standard[$UpsOids.OutputSource]
        return [pscustomobject]@{
            Source = 'UPS-MIB'; Manufacturer = "$($Standard[$UpsOids.Manufacturer])".Trim(); Model = "$($Standard[$UpsOids.Model])".Trim()
            Battery = $(switch ($bs) { 2 { 'normal' } 3 { 'low' } 4 { 'depleted' } default { 'unknown' } })
            OnBattery = ($src -eq 5); ChargePct = (& $num $Standard[$UpsOids.ChargePct]); MinutesRemaining = (& $num $Standard[$UpsOids.MinutesRemaining])
            LoadPct = (& $num $Standard[$UpsOids.LoadPct]); ReplaceBattery = $null
        }
    }
    if ($Apc -and ($Apc[$ApcUpsOids.Model] -or $Apc[$ApcUpsOids.BatteryStatus])) {
        $bs = & $num $Apc[$ApcUpsOids.BatteryStatus]; $os = & $num $Apc[$ApcUpsOids.OutputStatus]; $rt = & $num $Apc[$ApcUpsOids.RuntimeTicks]
        return [pscustomobject]@{
            Source = 'APC'; Manufacturer = 'APC'; Model = "$($Apc[$ApcUpsOids.Model])".Trim()
            Battery = $(switch ($bs) { 2 { 'normal' } 3 { 'low' } 4 { 'in fault' } default { 'unknown' } })
            OnBattery = ($os -eq 3); ChargePct = (& $num $Apc[$ApcUpsOids.ChargePct]); MinutesRemaining = $(if ($null -ne $rt) { [math]::Round($rt / 6000, 0) } else { $null })
            LoadPct = (& $num $Apc[$ApcUpsOids.LoadPct]); ReplaceBattery = ((& $num $Apc[$ApcUpsOids.ReplaceBattery]) -eq 2)
        }
    }
    return $null
}

function Get-RouterTables {
    # A router's own addresses, ARP table and routes, read only. Returns $null when it is not a router.
    param([string]$Ip, [string]$Community, [bool]$Force = $false)
    $fw = Get-SnmpValues $Ip $Community @('1.3.6.1.2.1.4.1.0') 1500
    $isRouter = ($fw -and "$($fw['1.3.6.1.2.1.4.1.0'])" -eq '1')
    if (-not $isRouter -and -not $Force) { return $null }
    $addr = @(ConvertFrom-AddrRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.20.1.2' 100 1500) (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.20.1.3' 100 1500))
    $arp = @(ConvertFrom-ArpRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.22.1.2' 2000 1500))
    if (-not $arp.Count) { $arp = @(ConvertFrom-ArpRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.35.1.4' 2000 1500)) }
    $routes = @(ConvertFrom-RouteRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.24.4.1.4' 300 1500))
    if (-not $routes.Count) { $routes = @(ConvertFrom-RouteRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.21.1.7' 300 1500) (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.21.1.11' 300 1500) -Legacy) }
    if (-not $isRouter -and -not $addr.Count -and -not $arp.Count -and -not $routes.Count) { return $null }
    return [ordered]@{
        Forwarding = $isRouter
        Addresses = $addr
        WanAddresses = @($addr | Where-Object { $_.Class -eq 'Public' } | ForEach-Object { $_.IP })
        Arp = $arp
        Routes = $routes
        DefaultRoute = @($routes | Where-Object { $_.Destination -eq '0.0.0.0' -and $_.Prefix -eq 0 } | ForEach-Object { $_.NextHop } | Select-Object -First 1)
    }
}
