# =====================================================================
# PHASE 6c: active discovery, deliberately last. Bandwidth, traceroutes and the path tests are
# already done and are saved here first (checkpoint), so if security software or the firewall
# reacts to the gateway probes or the sweep, the core data is already on disk.
# =====================================================================
[void](Save-Json 'checkpoint: core data saved, active discovery not finished')
Write-Step $(if ($EnableDiscovery) { 'Core data saved. Starting active discovery (gateway probes, device discovery, subnet sweep)' } else { 'Core data saved. Discovery is off: finishing the checks of this PC and its internet path' })

# ---- Other subnets: what this PC can reach (no traffic), and which to sweep (-Discovery only) ----
$script:ScanSpecs = @()
try {
    $localRanges = @()
    foreach ($a in @(Get-Val $Result['Network'] 'Adapters')) {
        if (-not $a -or $a.Status -ne 'Up') { continue }
        $ips = @($a.IPv4); $masks = @($a.SubnetMask)
        for ($q = 0; $q -lt $ips.Count; $q++) {
            if (-not (Test-IPv4 "$($ips[$q])") -or "$($ips[$q])" -like '169.254.*') { continue }
            $mk = if ($masks.Count -gt $q -and (Test-IPv4 "$($masks[$q])")) { "$($masks[$q])" } else { '255.255.255.0' }
            $pre = 0; $mi = ConvertTo-IpNumber $mk; for ($bit = 31; $bit -ge 0; $bit--) { if (($mi -shr $bit) -band 1) { $pre++ } else { break } }
            $localRanges += ConvertTo-NetRange "$($ips[$q])" $pre
        }
    }
    if ($EnableDiscovery -and $EnableSnmp -and $script:FullLanguage -and $Gateway -and $SnmpCommunity) {
        $Result['GatewayRouter'] = Invoke-Collector 'Gateway routes over SNMP (for the subnet list)' {
            $gt = Get-RouterTables "$Gateway" $SnmpCommunity $true
            if (-not $gt) { throw 'the gateway did not answer SNMP' }
            $gt
        }
    }
    $cands = @(Get-CandidateSubnets $Result $localRanges)
    $rsOut = [ordered]@{ Candidates = $cands; Answer = $null; Selected = @(); Rejected = @() }
    if ($EnableDiscovery -and $EnableRemoteSweep -and $script:FullLanguage) {
        $explicit = @(@($ScanSubnets) + @($SiteSubnets) | Where-Object { $_ })
        $explicitSpecs = @($explicit | ForEach-Object { ConvertTo-SubnetSpec $_ } | Where-Object { $_ })
        $offer = @($cands | Where-Object { $c = ConvertTo-SubnetSpec $_.Cidr; -not @($explicitSpecs | Where-Object { Test-RangeOverlap $_ $c }).Count })
        $answer = ''
        if ($offer.Count -and -not $NoPrompt) {
            Write-Host ''
            Write-Host 'OTHER SUBNETS this PC can reach. None is swept unless you pick it:' -ForegroundColor White
            for ($k = 0; $k -lt $offer.Count; $k++) {
                $why = (@($offer[$k].Reasons) | Select-Object -First 3) -join '; '
                Write-Host ('  {0,2}) {1,-18} {2}' -f ($k + 1), $offer[$k].Cidr, $why)
                if ($offer[$k].Hosted) { Write-Host '                         a remote desktop target is here: this may be the provider''s network, not the client''s' -ForegroundColor Yellow }
            }
            $answer = Read-Host 'Sweep which? Numbers (1,3 or 2-4), A for all, Enter for none'
        }
        $sel = Select-ScanSubnets -Explicit $explicit -Candidates $offer -Answer $answer -Exclude $localRanges -Max $RemoteSweepMaxSubnets
        $script:ScanSpecs = @($sel.Selected)
        $rsOut['Answer'] = $answer
        $rsOut['Selected'] = @($sel.Selected | ForEach-Object { [pscustomobject]@{ Subnet = $_.Cidr; Reason = $_.Reason } })
        $rsOut['Rejected'] = @($sel.Rejected)
        foreach ($rj in @($sel.Rejected)) { Write-Step "  Not swept: $rj" 'DarkYellow' }
    }
    $Result['RemoteSubnets'] = $rsOut
} catch { $script:Errors += [pscustomobject]@{ Collector = 'Other subnets'; Error = $_.Exception.Message } }

if ($EnableGatewayProbe -and $Gateway) {
    $Result['GatewayProbe'] = Invoke-Collector 'Gateway banner probe' {
        # A 1 s port check first, so a gateway that ignores web requests (guest Wi-Fi) costs seconds, not 10.
        foreach ($pp in @(@('https', 443), @('http', 80))) {
            if (Test-TcpPort $Gateway $pp[1] 1000) { Get-HttpBanner ('{0}://{1}/' -f $pp[0], $Gateway) 5000 }
            else { [pscustomobject]@{ Url = ('{0}://{1}/' -f $pp[0], $Gateway); Status = $null; Server = $null; Title = $null; CertSubject = $null; CertIssuer = $null; Error = "tcp/$($pp[1]) closed or filtered" } }
        }
    }
    $Result['GatewayModel'] = Get-FirewallModelHint @($Result['GatewayProbe'])
}

if ($EnableFirewallPorts -and $Gateway -and (Test-IPv4 $Gateway)) {
    $Result['FirewallPorts'] = Invoke-Collector 'Gateway admin ports + SSH banner' {
        $rows = @()
        # 4443/8443/10443 FortiGate and generic admin, 4433 SonicWall SSL VPN, 4444 Sophos admin,
        # 8080 WatchGuard Web UI, 4118 WatchGuard WSM (not HTTPS; open/closed is the signal).
        foreach ($port in @(4443, 8443, 10443, 4433, 4444, 8080, 4118)) {
            $open = Test-TcpPort $Gateway $port 1200
            $b = $null
            if ($open -and $port -ne 4118) { $b = Get-HttpBanner ("https://{0}:{1}/" -f $Gateway, $port) 4000 }
            $rows += [pscustomobject]@{ Port = $port; Open = $open; Title = $(if ($b) { $b.Title }); Server = $(if ($b) { $b.Server }); CertSubject = $(if ($b) { $b.CertSubject }); CertIssuer = $(if ($b) { $b.CertIssuer }); Banner = $null }
        }
        # SSH announces itself on connect (e.g. "SSH-2.0-...").
        $ssh = [pscustomobject]@{ Port = 22; Open = $false; Title = $null; Server = $null; CertSubject = $null; CertIssuer = $null; Banner = $null }
        $c = New-Object Net.Sockets.TcpClient
        try {
            $t = $c.ConnectAsync($Gateway, 22)
            if ($t.Wait(1200) -and $c.Connected) {
                $ssh.Open = $true
                $ns = $c.GetStream(); $ns.ReadTimeout = 2000
                $buf = New-Object byte[] 256
                try { $n = $ns.Read($buf, 0, $buf.Length); if ($n -gt 0) { $ssh.Banner = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -replace '[^\x20-\x7E]', '').Trim() } } catch { }
            }
        } catch { } finally { $c.Close() }
        $rows += $ssh
        $hints = @()
        foreach ($r in $rows) {
            $hay = "$($r.Title) $($r.Server) $($r.CertSubject) $($r.CertIssuer) $($r.Banner)"
            if ($hay -match 'Forti') { $hints += 'Fortinet' }
            elseif ($hay -match 'SonicWall|SonicOS') { $hints += 'SonicWall' }
            elseif ($hay -match 'Sophos') { $hints += 'Sophos' }
            elseif ($hay -match 'WatchGuard') { $hints += 'WatchGuard' }
            elseif ($hay -match 'Meraki') { $hints += 'Cisco Meraki' }
            elseif ($hay -match 'Palo ?Alto|PAN-OS|GlobalProtect') { $hints += 'Palo Alto Networks' }
            elseif ($hay -match 'ApplianceCertificate') { $hints += 'Sophos' }
            elseif ($hay -match 'pfSense|OPNsense|UniFi|Ubiquiti|EdgeOS|MikroTik|Cisco') { $hints += $matches[0] }
        }
        $openPorts = @($rows | Where-Object { $_.Open } | ForEach-Object { $_.Port })
        if ($openPorts -contains 4444) { $hints += 'Sophos (admin port 4444 open)' }
        if ($openPorts -contains 8080 -and $openPorts -contains 4118) { $hints += 'WatchGuard (ports 8080 + 4118 open)' }
        # A Meraki MX answers DNS for wired.meraki.com with its own LAN address (when clients use it for DNS).
        $meraki = $null
        try {
            $mr = @(Resolve-DnsName -Name 'wired.meraki.com' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' })[0]
            if ($mr -and (Get-IpClass $mr.IPAddress) -eq 'Private') {
                $mb = Get-HttpBanner ('http://{0}/' -f $mr.IPAddress) 4000
                $meraki = [ordered]@{ LocalStatusPageIp = $mr.IPAddress; Title = $mb.Title; Server = $mb.Server; Error = $mb.Error }
                $hints += 'Cisco Meraki (MX local status page)'
            }
        } catch { }
        [ordered]@{ Ports = $rows; VendorHints = @($hints | Sort-Object -Unique); MerakiLocalStatus = $meraki }
    }
}

if ($EnableSsdp -and $script:FullLanguage) {
    $Result['Ssdp'] = Invoke-Collector 'SSDP/UPnP discovery' {
        $src = Get-Val $Result['Network'] 'SourceIp'
        $udp = New-Object Net.Sockets.UdpClient
        $found = @{}
        try {
            $bindIp = if ($src -and (Test-IPv4 $src)) { [Net.IPAddress]::Parse($src) } else { [Net.IPAddress]::Any }
            $udp.Client.Bind((New-Object Net.IPEndPoint($bindIp, 0)))
            $udp.Client.ReceiveTimeout = 400
            $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: ssdp:all`r`n`r`n"
            $bytes = [Text.Encoding]::ASCII.GetBytes($msg)
            $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Parse('239.255.255.250'), 1900)
            [void]$udp.Send($bytes, $bytes.Length, $ep)
            [void]$udp.Send($bytes, $bytes.Length, $ep)
            $until = (Get-Date).AddSeconds(3)
            $rt = $null
            while ((Get-Date) -lt $until) {
                # ReceiveAsync returns the sender with the data ([ref] on Receive did not update in PowerShell).
                # One receive stays pending across loop passes so no reply is dropped.
                if (-not $rt) { $rt = $udp.ReceiveAsync() }
                if (-not $rt.Wait(400)) { continue }
                if ($rt.IsFaulted) { $rt = $null; continue }
                $data = $rt.Result.Buffer
                $ip = $rt.Result.RemoteEndPoint.Address.ToString()
                $rt = $null
                if ($ip -eq $src) { continue }
                $txt = [Text.Encoding]::ASCII.GetString($data)
                $loc = $null; $srv = $null
                if ($txt -match '(?im)^LOCATION:\s*(\S+)') { $loc = $matches[1] }
                if ($txt -match '(?im)^SERVER:\s*(.+)$') { $srv = $matches[1].Trim() }
                if (-not $found.ContainsKey($ip)) { $found[$ip] = [ordered]@{ IP = $ip; Server = $srv; Locations = @(); FriendlyName = $null; Manufacturer = $null; Model = $null; ModelNumber = $null; DeviceType = $null } }
                if ($loc -and $found[$ip].Locations -notcontains $loc) { $found[$ip].Locations += $loc }
                if (-not $found[$ip].Server -and $srv) { $found[$ip].Server = $srv }
            }
        } finally { $udp.Close() }
        # Each device's description XML names the model.
        $fetched = 0
        foreach ($ip in @($found.Keys)) {
            $d = $found[$ip]
            foreach ($loc in ($d.Locations | Select-Object -First 2)) {
                if ($fetched -ge 20 -or $d.Model) { break }
                $fetched++
                try {
                    $resp = Invoke-WebRequest -Uri $loc -UseBasicParsing -TimeoutSec 3
                    [xml]$x = $resp.Content
                    $dev = $x.root.device
                    if ($dev) {
                        $d.FriendlyName = "$($dev.friendlyName)"; $d.Manufacturer = "$($dev.manufacturer)"
                        $d.Model = "$($dev.modelName)"; $d.ModelNumber = "$($dev.modelNumber)"; $d.DeviceType = ("$($dev.deviceType)" -replace '^urn:schemas-upnp-org:device:', '')
                    }
                } catch { }
            }
        }
        $devices = @($found.Values | ForEach-Object { [pscustomobject]@{ IP = $_.IP; FriendlyName = $_.FriendlyName; Manufacturer = $_.Manufacturer; Model = $_.Model; ModelNumber = $_.ModelNumber; DeviceType = $_.DeviceType; Server = $_.Server } } | Sort-Object { try { [version]$_.IP } catch { [version]'0.0' } })
        [ordered]@{ DeviceCount = $devices.Count; Devices = $devices }
    }
}

if ($EnableSubnetSweep) {
    $Result['SubnetSweep'] = Invoke-Collector 'Subnet sweep' {
        $primary = @($Result['Network']['Adapters'] | Where-Object { $_.Name -eq $Result['Network']['PhysicalAdapter'] }) | Select-Object -First 1
        # @() because a one-item array assigned from an if-expression collapses to a plain string.
        $ip = @($primary.IPv4)[0]
        if (-not $ip) { throw 'No IPv4 address on the primary adapter' }
        # Sweep the adapter's real subnet (not an assumed /24), capped at the /22 around this machine.
        $toInt = { param($s) $o = "$s".Split('.'); ([int64]$o[0] -shl 24) + ([int64]$o[1] -shl 16) + ([int64]$o[2] -shl 8) + [int64]$o[3] }
        $toIp = { param([int64]$n) '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255) }
        $mask = @($primary.SubnetMask)[0]
        if (-not (Test-IPv4 $mask)) { $mask = '255.255.255.0' }
        $maskInt = & $toInt $mask
        $prefix = 0
        for ($bit = 31; $bit -ge 0; $bit--) { if (($maskInt -shr $bit) -band 1) { $prefix++ } else { break } }
        $sweepNote = $null
        if ($prefix -lt 22) { $sweepNote = "Subnet is /$prefix; only the /22 around this machine was swept"; $prefix = 22 }
        if ($prefix -gt 30) { throw "Subnet /$prefix is too small to sweep" }
        $netInt = (& $toInt $ip) -band (([int64]4294967295 -shl (32 - $prefix)) -band [int64]4294967295)
        $bcastInt = $netInt + ([int64]1 -shl (32 - $prefix)) - 1
        $targets = New-Object Collections.Generic.List[string]
        for ($h = $netInt + 1; $h -lt $bcastInt; $h++) { $targets.Add((& $toIp $h)) }
        $alive = @()
        # Batches of 256 keep the number of open ping handles reasonable on a /22.
        for ($b0 = 0; $b0 -lt $targets.Count; $b0 += 256) {
            $chunk = @($targets[$b0..([math]::Min($b0 + 255, $targets.Count - 1))])
            $pingers = @(); $tasks = @()
            foreach ($t in $chunk) { $p = New-Object Net.NetworkInformation.Ping; $pingers += $p; $tasks += $p.SendPingAsync($t, 600) }
            try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, 8000) | Out-Null } catch { }
            for ($j = 0; $j -lt $tasks.Count; $j++) {
                if ($tasks[$j].IsCompleted -and -not $tasks[$j].IsFaulted -and $tasks[$j].Result.Status -eq 'Success') { $alive += $chunk[$j] }
            }
            foreach ($p in $pingers) { $p.Dispose() }
        }
        $neigh = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $primary.IfIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-){5}00$|^(FF-){5}FF$' -and "$($_.State)" -ne 'Unreachable' } |
            Where-Object { $n = & $toInt $_.IPAddress; $n -gt $netInt -and $n -lt $bcastInt })
        $devices = @()
        foreach ($n in $neigh) {
            $devices += [pscustomobject]@{ IP = $n.IPAddress; Mac = $n.LinkLayerAddress; Vendor = (Get-MacVendor $n.LinkLayerAddress); RespondedToPing = ($alive -contains $n.IPAddress); Name = $null; OpenPorts = @(); Role = $null }
        }
        # Identify what was found: a name lookup and a few TCP ports per device (first 256 devices).
        $identified = 0
        if ($EnableSweepPorts -and $script:FullLanguage -and $devices.Count) {
            $scan = @($devices | Select-Object -First 256)
            # Name lookups block a thread each until they answer or time out, so allow enough threads for the batch.
            $minW = 0; $minIo = 0
            [Threading.ThreadPool]::GetMinThreads([ref]$minW, [ref]$minIo)
            [void][Threading.ThreadPool]::SetMinThreads([math]::Max($minW, 128), $minIo)
            $nameTasks = @{}
            foreach ($d in $scan) { try { $nameTasks[$d.IP] = [Net.Dns]::GetHostEntryAsync([string]$d.IP) } catch { } }
            $openMap = Test-TcpPortsBulk @($scan | ForEach-Object { $_.IP }) $SweepPorts 800
            if ($nameTasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($nameTasks.Values), 8000) } catch { } }
            [void][Threading.ThreadPool]::SetMinThreads($minW, $minIo)
            foreach ($d in $scan) {
                $t = $nameTasks[$d.IP]
                if ($t -and "$($t.Status)" -eq 'RanToCompletion' -and $t.Result.HostName -and $t.Result.HostName -ne $d.IP) { $d.Name = $t.Result.HostName }
                if ($openMap.ContainsKey($d.IP)) { $d.OpenPorts = @($openMap[$d.IP] | Sort-Object) }
                $d.Role = Get-DeviceRole $d.OpenPorts
                if ($d.Name -or $d.Role) { $identified++ }
            }
        }
        [ordered]@{
            Subnet = '{0}/{1}' -f (& $toIp $netInt), $prefix
            Note = $sweepNote
            PortsChecked = $(if ($EnableSweepPorts -and $script:FullLanguage) { $SweepPorts } else { @() })
            Identified = $identified
            RoleSummary = @($devices | Where-Object { $_.Role } | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            AddressesSwept = $targets.Count
            PingResponders = $alive.Count
            ArpEntries = $devices.Count
            Devices = @($devices | Sort-Object { [version]$_.IP })
            VendorSummary = @($devices | Group-Object Vendor | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        }
    }
}

if ($EnableRemoteSweep -and $script:FullLanguage -and @($script:ScanSpecs).Count) {
    $Result['RemoteSweep'] = Invoke-Collector ("Other subnets ({0}): ping and TCP sweep across routing" -f ((@($script:ScanSpecs) | ForEach-Object { $_.Cidr }) -join ', ')) {
        Invoke-RemoteSweep -Specs $script:ScanSpecs -Ports $(if ($EnableSweepPorts) { $SweepPorts } else { @() }) -PresencePorts $RemoteSweepPresencePorts -TimeoutMs 1000
    }
}

# Runs after the sweep so printers the sweep found are identified too.
if ($EnablePrinterProbe) {
    $Result['PrinterProbe'] = Invoke-Collector 'Network printer web pages' {
        $ips = @()
        foreach ($p in @(Get-Val $Result['Peripherals'] 'Printers')) { if ($p -and $p.HostAddress -and (Test-IPv4 $p.HostAddress)) { $ips += $p.HostAddress } }
        $printVendors = 'Hewlett|HP Inc|Brother|Canon|Epson|Seiko Epson|Xerox|Lexmark|Ricoh|Kyocera|Konica|Sharp|Toshiba|Zebra|Oki|Fuji'
        foreach ($d in @(Get-Val $Result['SubnetSweep'] 'Devices')) { if ($d -and ($d.Vendor -match $printVendors -or $d.Role -eq 'Printer')) { $ips += $d.IP } }
        $rows = @()
        foreach ($ip in ($ips | Select-Object -Unique | Select-Object -First 15)) {
            $row = [ordered]@{ IP = $ip; Reachable = $false; Title = $null; Server = $null; Url = $null }
            foreach ($scheme in @(@('http', 80), @('https', 443))) {
                if (Test-TcpPort $ip $scheme[1] 1000) {
                    $row.Reachable = $true
                    $b = Get-HttpBanner ('{0}://{1}/' -f $scheme[0], $ip) 4000
                    if ($b.Title -or $b.Server) { $row.Title = $b.Title; $row.Server = $b.Server; $row.Url = $b.Url; break }
                }
            }
            $rows += [pscustomobject]$row
        }
        $rows
    }
}
