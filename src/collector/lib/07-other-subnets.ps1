function ConvertTo-SubnetSpec {
    # 'a.b.c' (taken as a /24) or 'a.b.c.d/nn' with nn from 22 to 30. Anything else returns $null.
    param([string]$Text)
    $t = "$Text".Trim()
    if ($t -match '^\d{1,3}\.\d{1,3}\.\d{1,3}$') { $t = "$t.0/24" }
    if ($t -notmatch '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$') { return $null }
    $ip = $matches[1]; $prefix = [int]$matches[3]
    if (@($ip.Split('.') | Where-Object { [int]$_ -gt 255 }).Count -or $prefix -lt 22 -or $prefix -gt 30) { return $null }
    $r = ConvertTo-NetRange $ip $prefix
    return [pscustomobject]@{ Cidr = '{0}/{1}' -f (ConvertFrom-IpNumber $r.NetInt), $prefix; NetInt = $r.NetInt; End = $r.End; First = $r.NetInt + 1; Last = $r.End - 1; Prefix = $prefix; Reason = $null }
}

function Get-SubnetHosts {
    param($Spec)
    $out = New-Object Collections.Generic.List[string]
    for ($h = [int64]$Spec.First; $h -le [int64]$Spec.Last; $h++) { $out.Add((ConvertFrom-IpNumber $h)) }
    return , $out.ToArray()
}

function Test-RangeOverlap { param($A, $B) return ([int64]$A.NetInt -le [int64]$B.End -and [int64]$B.NetInt -le [int64]$A.End) }

function Get-CandidateSubnets {
    # Private subnets this PC already knows about from data it collected (routes, DNS, DHCP and other
    # servers, printer ports, private traceroute hops, remote desktop lookups). Nothing is sent to build it.
    # $Exclude: ranges to leave out (this PC's own subnets). Hosted = a remote desktop target is in it,
    # so it may be the provider's network rather than the client's.
    param($R, $Exclude = @())
    $found = [ordered]@{}
    $note = {
        param($spec, $why, [bool]$hosted)
        if (-not $spec) { return }
        foreach ($x in @($Exclude)) { if ($x -and (Test-RangeOverlap $spec $x)) { return } }
        if (-not $found.Contains($spec.Cidr)) { $found[$spec.Cidr] = [pscustomobject]@{ Cidr = $spec.Cidr; NetInt = $spec.NetInt; End = $spec.End; Reasons = @(); Hosted = $false } }
        $e = $found[$spec.Cidr]
        if ($e.Reasons -notcontains $why) { $e.Reasons += $why }
        if ($hosted) { $e.Hosted = $true }
    }
    $addIp = {
        param([string]$ip, [string]$why, [bool]$hosted)
        if (-not (Test-IPv4 $ip) -or (Get-IpClass $ip) -ne 'Private') { return }
        $n = ConvertTo-IpNumber $ip
        # An address inside a subnet already found from a route belongs to that subnet.
        foreach ($k in @($found.Keys)) { $f = $found[$k]; if ($n -ge $f.NetInt -and $n -le $f.End) { & $note (ConvertTo-SubnetSpec $k) $why $hosted; return } }
        & $note (ConvertTo-SubnetSpec ((@($ip.Split('.'))[0..2]) -join '.')) $why $hosted
    }
    foreach ($rt in @(Get-Prop $R 'NetworkExtra', 'Routes')) {
        if (-not $rt -or "$(Get-Prop $rt 'Prefix')" -notmatch '^(\d{1,3}(\.\d{1,3}){3})/(\d+)$') { continue }
        $pre = [int]$matches[3]
        if ($pre -lt 22 -or $pre -gt 30 -or (Get-IpClass $matches[1]) -ne 'Private') { continue }
        $hop = "$(Get-Prop $rt 'NextHop')"
        & $note (ConvertTo-SubnetSpec "$($matches[1])/$pre") ("route " + $(if ($hop -and $hop -ne '0.0.0.0') { "via $hop" } else { 'on-link' })) $false
    }
    foreach ($d in @(Get-Prop $R 'NetworkExtra', 'DnsServers')) { if ($d) { & $addIp "$(Get-Prop $d 'Server')" "DNS server $(Get-Prop $d 'Server')" $false } }
    foreach ($a in @(Get-Prop $R 'Network', 'Adapters')) { if ($a -and (Get-Prop $a 'DhcpServer')) { & $addIp "$(Get-Prop $a 'DhcpServer')" "DHCP server $(Get-Prop $a 'DhcpServer')" $false } }
    foreach ($sv in @(Get-Prop $R 'Servers', 'Servers')) { if ($sv) { foreach ($ip in @(Get-Prop $sv 'IPs')) { & $addIp "$ip" "server $(Get-Prop $sv 'Name')" $false } } }
    foreach ($p in @(Get-Prop $R 'Peripherals', 'Printers')) { if ($p -and -not (Get-Prop $p 'IsVirtual') -and (Get-Prop $p 'HostAddress')) { & $addIp "$(Get-Prop $p 'HostAddress')" "printer $(Get-Prop $p 'Name')" $false } }
    foreach ($t in @(Get-Prop $R 'Traceroutes')) {
        if (-not $t) { continue }
        foreach ($hp in @(@(Get-Prop $t 'Hops') | Where-Object { $_ } | Sort-Object { [int](Get-Prop $_ 'Hop') })) {
            $c = "$(Get-Prop $hp 'Class')"
            if ($c -eq 'CGNAT' -or $c -eq 'Public') { break }
            if ([int](Get-Prop $hp 'Hop') -gt 1 -and $c -eq 'Private') { & $addIp "$(Get-Prop $hp 'IP')" "traceroute hop to $(Get-Prop $t 'Target')" $false }
        }
    }
    foreach ($rp in @(Get-Prop $R 'RdpPath')) { if ($rp) { foreach ($ip in @(Get-Prop $rp 'ResolvedIPs')) { & $addIp "$ip" "remote desktop host $(Get-Prop $rp 'Host')" $true } } }
    foreach ($c in @(Get-Prop $R 'Rdp', 'ActiveTcp')) { if ($c) { & $addIp "$(Get-Prop $c 'RemoteAddress')" 'live remote desktop session' $true } }
    foreach ($site in @(Get-Prop $R 'AdSites', 'Sites')) { foreach ($sn in @(Get-Prop $site 'Subnets')) { $sp = ConvertTo-SubnetSpec "$sn"; if ($sp -and (Get-IpClass (("$sn" -split '/')[0])) -eq 'Private') { & $note $sp "Active Directory site $(Get-Prop $site 'Name')" $false } } }
    foreach ($rt in @(Get-Prop $R 'GatewayRouter', 'Routes')) {
        $sp = if ($null -ne (Get-Prop $rt 'Prefix')) { ConvertTo-SubnetSpec ("{0}/{1}" -f (Get-Prop $rt 'Destination'), (Get-Prop $rt 'Prefix')) } else { $null }
        if ($sp -and (Get-IpClass "$(Get-Prop $rt 'Destination')") -eq 'Private') { & $note $sp "route on the gateway via $(Get-Prop $rt 'NextHop') (SNMP)" $false }
    }
    return @($found.Values | Sort-Object NetInt | ForEach-Object { [pscustomobject]@{ Cidr = $_.Cidr; Reasons = @($_.Reasons); Hosted = $_.Hosted } })
}

function Select-ScanSubnets {
    # The subnets to sweep: every valid entry from CONFIG, then the candidates picked at the prompt
    # ('1,3', '2-4', 'A' for all, empty for none). This PC's own subnets and anything past $Max are left out.
    param([string[]]$Explicit = @(), $Candidates = @(), [string]$Answer = '', $Exclude = @(), [int]$Max = 8)
    $sel = New-Object Collections.Generic.List[object]; $rej = New-Object Collections.Generic.List[string]
    $take = {
        param($spec, [string]$reason)
        if (@($sel | Where-Object { Test-RangeOverlap $_ $spec }).Count) { return }
        foreach ($x in @($Exclude)) { if ($x -and (Test-RangeOverlap $spec $x)) { $rej.Add("$($spec.Cidr): this PC's own subnet, covered by the local sweep"); return } }
        if ($sel.Count -ge $Max) { $rej.Add("$($spec.Cidr): over the limit of $Max subnets per run"); return }
        $spec.Reason = $reason
        $sel.Add($spec)
    }
    foreach ($e in @($Explicit | Where-Object { "$_".Trim() })) {
        $s = ConvertTo-SubnetSpec $e
        if ($s) { & $take $s 'listed in CONFIG' } else { $rej.Add("${e}: not a.b.c or a.b.c.d/22 to /30") }
    }
    $cands = @($Candidates | Where-Object { $_ })
    $idx = @()
    if ("$Answer" -match '^\s*(a|all)\s*$') { if ($cands.Count) { $idx = 0..($cands.Count - 1) } }
    else {
        foreach ($part in @("$Answer" -split '[,;\s]+' | Where-Object { $_ })) {
            if ($part -match '^(\d+)-(\d+)$') { $idx += ([int]$matches[1] - 1)..([int]$matches[2] - 1) }
            elseif ($part -match '^\d+$') { $idx += [int]$part - 1 }
        }
    }
    foreach ($i in @($idx | Sort-Object -Unique)) {
        if ($i -lt 0 -or $i -ge $cands.Count) { continue }
        $s = ConvertTo-SubnetSpec $cands[$i].Cidr
        if ($s) { & $take $s ('chosen at the prompt (' + (@($cands[$i].Reasons) | Select-Object -First 1) + ')') }
    }
    return [pscustomobject]@{ Selected = $sel.ToArray(); Rejected = $rej.ToArray() }
}

function Invoke-RemoteSweep {
    # Sweeps subnets on the far side of a router: ping every address, try a few TCP ports on the ones
    # that ignore ping, then a name lookup and the sweep ports on every device that answered. MAC
    # addresses do not cross a router; they come later from NetBIOS or the router's own ARP table.
    param($Specs, [int[]]$Ports = @(), [int[]]$PresencePorts = @(), [int]$TimeoutMs = 1000)
    $devices = @(); $summary = @()
    foreach ($sp in @($Specs)) {
        $t0 = Get-Date
        $hosts = Get-SubnetHosts $sp
        $alive = @{}
        # Smaller batches with a pause than the local sweep: this traffic crosses a router or a tunnel.
        for ($b0 = 0; $b0 -lt $hosts.Count; $b0 += 128) {
            $chunk = @($hosts[$b0..([math]::Min($b0 + 127, $hosts.Count - 1))])
            $pingers = @(); $tasks = @()
            foreach ($t in $chunk) { $p = New-Object Net.NetworkInformation.Ping; $pingers += $p; $tasks += $p.SendPingAsync($t, $TimeoutMs) }
            try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, $TimeoutMs + 4000) | Out-Null } catch { }
            for ($j = 0; $j -lt $tasks.Count; $j++) { if ($tasks[$j].IsCompleted -and -not $tasks[$j].IsFaulted -and $tasks[$j].Result.Status -eq 'Success') { $alive[$chunk[$j]] = $true } }
            foreach ($p in $pingers) { $p.Dispose() }
            Start-Sleep -Milliseconds 150
        }
        $tcpOnly = @{}
        $silent = @($hosts | Where-Object { -not $alive.ContainsKey($_) })
        if (@($PresencePorts).Count -and $silent.Count) { $pm = Test-TcpPortsBulk $silent $PresencePorts $TimeoutMs; foreach ($k in $pm.Keys) { $tcpOnly[$k] = @($pm[$k]) } }
        $live = @(@($alive.Keys) + @($tcpOnly.Keys) | Sort-Object -Unique | Sort-Object { [version]$_ })
        $minW = 0; $minIo = 0
        [Threading.ThreadPool]::GetMinThreads([ref]$minW, [ref]$minIo)
        [void][Threading.ThreadPool]::SetMinThreads([math]::Max($minW, 128), $minIo)
        $nameTasks = @{}
        foreach ($ip in $live) { try { $nameTasks[$ip] = [Net.Dns]::GetHostEntryAsync([string]$ip) } catch { } }
        $open = if (@($Ports).Count -and $live.Count) { Test-TcpPortsBulk $live $Ports $TimeoutMs } else { @{} }
        if ($nameTasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($nameTasks.Values), 8000) } catch { } }
        [void][Threading.ThreadPool]::SetMinThreads($minW, $minIo)
        foreach ($ip in $live) {
            $nt = $nameTasks[$ip]
            $name = if ($nt -and "$($nt.Status)" -eq 'RanToCompletion' -and $nt.Result.HostName -and $nt.Result.HostName -ne $ip) { $nt.Result.HostName } else { $null }
            $ports = @(@($open[$ip]) + @($tcpOnly[$ip]) | Where-Object { $null -ne $_ } | Sort-Object -Unique)
            $devices += [pscustomobject]@{ IP = $ip; Mac = $null; Vendor = $null; RespondedToPing = $alive.ContainsKey($ip); Name = $name; OpenPorts = $ports; Role = (Get-DeviceRole $ports); Subnet = $sp.Cidr; Remote = $true }
        }
        $summary += [pscustomobject]@{ Subnet = $sp.Cidr; Reason = $sp.Reason; AddressesSwept = $hosts.Count; PingResponders = $alive.Count; TcpOnly = $tcpOnly.Count; Devices = $live.Count; Seconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1) }
    }
    return [ordered]@{
        Subnets = $summary
        PortsChecked = @($Ports); PresencePorts = @($PresencePorts)
        RoleSummary = @($devices | Where-Object { $_.Role } | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        Devices = $devices
    }
}
