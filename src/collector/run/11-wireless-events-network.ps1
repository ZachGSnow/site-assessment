# ---------------------------------------------------------------------
# Windows 11 24H2+ only lets netsh read Wi-Fi details when location is allowed for desktop apps.
# These helpers allow it briefly for the running account and put every value back afterwards.
# ---------------------------------------------------------------------
$LocKey = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'

$Result['Wireless'] = Invoke-Collector 'Wireless' {
    $hasWifi = @($Result['Network']['Adapters'] | Where-Object { $_.Class -eq 'Wi-Fi' }).Count -gt 0
    if (-not $hasWifi) { return [ordered]@{ Status = 'No Wi-Fi adapter' } }
    $out = [ordered]@{}
    $isBlocked = { param($t) $t -match 'location permission|Location services|ms-settings:privacy-location' }
    $loc = [ordered]@{ Needed = $false; Attempted = $false; Result = $null; Restored = $null }
    $changes = @()
    $nText = $null
    try {
        $ifText = Invoke-Native 'netsh.exe' 'wlan show interfaces' 20
        if (& $isBlocked $ifText) {
            $loc.Needed = $true
            $pol = Get-LocationPolicy
            $loc['Before'] = $pol
            $deviceOff = ($pol.DeviceValue -eq 'Deny')
            if (-not $TempEnableLocation) { $loc.Result = 'Not attempted ($TempEnableLocation = $false)' }
            elseif ($pol.PolicyBlocked) { $loc.Result = "Blocked by policy ($($pol.PolicyReason)); not overridden" }
            elseif ($deviceOff -and -not $script:AdminActive) { $loc.Result = 'Location services are off device-wide; only admin mode can enable them temporarily' }
            else {
                $loc.Attempted = $true
                $changes = @(Enable-TempLocation -IncludeDevice $deviceOff)
                Start-Sleep -Milliseconds 1500
                $ifText = Invoke-Native 'netsh.exe' 'wlan show interfaces' 20
                $loc.Result = if (& $isBlocked $ifText) { 'Still blocked after temporary enable' } else { 'Temporarily enabled; Wi-Fi read OK' }
            }
        }
        if (-not (& $isBlocked $ifText)) {
            try { $nText = Invoke-Native 'netsh.exe' 'wlan show networks mode=bssid' 25 } catch { }
        }
    } finally {
        if ($changes.Count -gt 0) {
            $failed = @(Restore-TempLocation $changes)
            $loc.Restored = ($failed.Count -eq 0)
            if ($failed.Count) {
                Write-Step ("  WARNING: could not restore location setting(s): {0}" -f ($failed -join ', ')) 'Red'
                $loc['RestoreFailed'] = $failed
            }
        }
    }
    $out['LocationWorkaround'] = $loc
    if (& $isBlocked $ifText) {
        $out['Status'] = 'Blocked by Windows location permission'
        $out['Fix'] = if ("$($loc.Result)" -like 'Blocked by policy*') { "Location is disabled by policy ($($loc['Before'].PolicyReason)); Wi-Fi radio details cannot be read on this machine. SSID comes from the network profile instead." }
                      elseif ("$($loc.Result)" -like 'Location services are off device-wide*') { 'Re-run in an elevated ISE, or turn on Settings > Privacy & security > Location > Location services.' }
                      else { "Workaround: $($loc.Result). Manual fix: Settings > Privacy & security > Location: turn on Location services and 'Let desktop apps access your location', then re-run." }
        Write-Step "  Wi-Fi details blocked by location permission ($($loc.Result))" 'Yellow'
    } elseif ($loc.Attempted) {
        Write-Step '  Location allowed temporarily for the Wi-Fi read, then restored'
    }
    $i = ConvertFrom-ColonText $ifText
    $bssid = if ($i['AP BSSID']) { $i['AP BSSID'] } else { $i['BSSID'] }
    $sig = $null
    if ($i['Signal'] -match '(\d+)%') { $sig = [int]$matches[1] }
    $rssi = $null
    if ($i['Rssi'] -match '(-?\d+)') { $rssi = [int]$matches[1] }
    $ch = $null
    if ($i['Channel'] -match '(\d+)') { $ch = [int]$matches[1] }
    $band = $i['Band']
    if (-not $band -and $ch) { $band = if ($ch -le 14) { '2.4 GHz' } else { '5 GHz (or 6 GHz)' } }
    $out['Current'] = [ordered]@{
        State = $i['State']; SSID = $i['SSID']; BSSID = $bssid; ApVendor = (Get-MacVendor $bssid)
        RadioType = $i['Radio type']; Band = $band; Channel = $ch; Authentication = $i['Authentication']; Cipher = $i['Cipher']
        SignalPct = $sig; ApproxDbm = if ($rssi) { $rssi } elseif ($null -ne $sig) { [int](($sig / 2) - 100) } else { $null }
        ReceiveMbps = $i['Receive rate (Mbps)']; TransmitMbps = $i['Transmit rate (Mbps)']; Profile = $i['Profile']
        Adapter = $i['Description']; ConnectionMode = $i['Connection mode']; SsidSource = 'netsh'
    }
    if (-not $out['Current'].SSID) {
        # netsh blocked: the network profile name is normally the SSID and needs no location permission.
        try {
            $wifiIdx = @($Result['Network']['Adapters'] | Where-Object { $_.Class -eq 'Wi-Fi' -and $_.Status -eq 'Up' } | ForEach-Object { $_.IfIndex })
            $prof = Get-NetConnectionProfile -ErrorAction Stop | Where-Object { $wifiIdx -contains $_.InterfaceIndex } | Select-Object -First 1
            if ($prof) { $out['Current'].SSID = $prof.Name; $out['Current'].SsidSource = 'network profile (netsh blocked)' }
        } catch { }
    }

    # Nearby networks
    $nets = @()
    try {
        $ssid = $null; $auth = $null; $cur = $null
        foreach ($line in ($nText -split "`r?`n")) {
            if ($line -match '^SSID \d+ : (.*)$') { $ssid = $matches[1].Trim(); continue }
            if ($line -match '^\s+Authentication\s+:\s(.*)$') { $auth = $matches[1].Trim(); continue }
            if ($line -match '^\s+BSSID \d+\s+:\s(.*)$') {
                if ($cur) { $nets += [pscustomobject]$cur }
                $cur = [ordered]@{ SSID = $ssid; Auth = $auth; BSSID = $matches[1].Trim(); SignalPct = $null; Radio = $null; Band = $null; Channel = $null }
                continue
            }
            if ($cur) {
                if ($line -match '^\s+Signal\s+:\s(\d+)%') { $cur.SignalPct = [int]$matches[1] }
                elseif ($line -match '^\s+Radio type\s+:\s(.*)$') { $cur.Radio = $matches[1].Trim() }
                elseif ($line -match '^\s+Band\s+:\s(.*)$') { $cur.Band = $matches[1].Trim() }
                elseif ($line -match '^\s+Channel\s+:\s(\d+)') { $cur.Channel = [int]$matches[1] }
            }
        }
        if ($cur) { $nets += [pscustomobject]$cur }
    } catch { }
    foreach ($n in $nets) {
        $vendor = $null
        $clean = ($n.BSSID -replace '[^0-9A-Fa-f]', '').ToUpper()
        if ($clean.Length -ge 6 -and $script:OuiTable.ContainsKey($clean.Substring(0, 6))) { $vendor = $script:OuiTable[$clean.Substring(0, 6)] }
        $n | Add-Member -NotePropertyName Vendor -NotePropertyValue $vendor
    }
    $out['Nearby'] = $nets
    $out['NearbyBssidCount'] = $nets.Count
    $out['NearbySsidCount'] = @($nets | Select-Object -ExpandProperty SSID -Unique).Count
    if ($out['Current'].SSID) {
        $same = @($nets | Where-Object { $_.SSID -eq $out['Current'].SSID })
        $out['SameSsidAps'] = $same.Count
        $out['SameSsidVendors'] = @($same | ForEach-Object { $_.Vendor } | Where-Object { $_ } | Sort-Object -Unique)
    }
    $chanLoad = @($nets | Where-Object { $_.Channel } | Group-Object Channel | Sort-Object Count -Descending | ForEach-Object { 'ch{0}={1}' -f $_.Name, $_.Count })
    $out['ChannelLoad'] = $chanLoad

    # Saved profile names only (never keys)
    try {
        $pText = Invoke-Native 'netsh.exe' 'wlan show profiles' 15
        $out['SavedProfiles'] = @($pText -split "`r?`n" | Where-Object { $_ -match 'Profile\s+:\s(.+)$' } | ForEach-Object { ($_ -split ':\s', 2)[1].Trim() })
    } catch { }

    # Wi-Fi event history
    try {
        $ev = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime = (Get-Date).AddDays(-$LookbackDays) } 3000)
        # A "real drop" is a disconnect followed by a reconnect to the same SSID within 2 minutes.
        # Disconnects without a quick reconnect are mostly the laptop leaving (moving, sleep, shutdown).
        $cd = @($ev | Where-Object { $_.Id -eq 8001 -or $_.Id -eq 8003 } | Sort-Object TimeCreated | ForEach-Object {
            $ssidV = $null; $reason = $null
            if ($_.Message -match 'SSID:\s*(.+)') { $ssidV = $matches[1].Trim() }
            if ($_.Message -match 'Reason:\s*(.+)') { $reason = $matches[1].Trim() }
            [pscustomobject]@{ Id = $_.Id; Time = $_.TimeCreated; SSID = $ssidV; Reason = $reason }
        })
        $drops = @()
        for ($x = 0; $x -lt $cd.Count; $x++) {
            if ($cd[$x].Id -ne 8003) { continue }
            for ($y = $x + 1; $y -lt $cd.Count; $y++) {
                if (($cd[$y].Time - $cd[$x].Time).TotalSeconds -gt 120) { break }
                if ($cd[$y].Id -eq 8001 -and $cd[$y].SSID -eq $cd[$x].SSID) {
                    $drops += [pscustomobject]@{ Time = Format-Date $cd[$x].Time; SSID = $cd[$x].SSID; Reason = $cd[$x].Reason; DownSeconds = [int]($cd[$y].Time - $cd[$x].Time).TotalSeconds }
                    break
                }
            }
        }
        $out['Events'] = [ordered]@{
            Connected     = @($ev | Where-Object Id -eq 8001).Count
            ConnectFailed = @($ev | Where-Object Id -eq 8002).Count
            Disconnected  = @($ev | Where-Object Id -eq 8003).Count
            RealDrops     = $drops.Count
            RealDropsBySsid = @($drops | Group-Object SSID | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })
            RecentRealDrops = @($drops | Select-Object -Last 10)
            DropReasons   = @($drops | Group-Object Reason | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })
        }
    } catch { $out['Events'] = "unavailable: $($_.Exception.Message)" }
    $out
}

$Result['EventLogs'] = Invoke-Collector 'Event logs (RDP client, System)' {
    $out = [ordered]@{}
    $since = (Get-Date).AddDays(-$LookbackDays)

    # RDP client history
    try {
        $ev = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'; StartTime = $since } 1500)
        # Event 1026 primary disconnect reasons (Microsoft IMsTscAxEvents::OnDisconnected and the TechNet
        # "Disconnect Codes and Reasons" table), grouped by what caused them.
        $reasonMap = @{
            '0' = 'No information'; '1' = 'Local disconnect by user'; '2' = 'Remote logoff by user'; '3' = 'Remote disconnect by server (admin, error or network)'
            '260' = 'DNS lookup failed'; '262' = 'Out of memory'; '263' = 'Normal session end'; '264' = 'Connection timed out'; '516' = 'Winsock connect failed (unreachable)'
            '520' = 'Host not found'; '772' = 'Winsock send failed (network error)'; '776' = 'Invalid IP address'; '1028' = 'Winsock receive failed'; '1030' = 'Security data invalid'
            '1032' = 'Internal error'; '1288' = 'DNS lookup failed'; '1540' = 'Host name lookup failed'; '1796' = 'Time-out'; '1800' = 'Console session already in progress'
            '2052' = 'Bad IP address'; '2055' = 'Login failed'; '2056' = 'License negotiation failed'; '2308' = 'Socket closed (connection lost)'; '2310' = 'Internal security error'
            '2311' = 'Unexpected server certificate'; '2312' = 'Licensing time-out'; '2566' = 'Internal security error'; '2567' = 'User has no account'; '2820' = 'Error prevented the connection'
            '2822' = 'Encryption error'; '2823' = 'Account disabled'; '2825' = 'Server requires NLA'; '3078' = 'Decryption error'; '3079' = 'Account restricted'; '3080' = 'Decompression error'
            '3335' = 'Account locked out'; '3591' = 'Account expired'; '3592' = 'Failed to reconnect to session'; '3847' = 'Password expired'; '4359' = 'Logon restricted to other computers'
            '4615' = 'Must change password'; '5639' = 'Credential delegation not allowed'; '5895' = 'Delegation needs mutual auth'; '6151' = 'No authentication authority reachable'
            '6919' = 'Certificate invalid or clock skew'; '7175' = 'Wrong smart card PIN'; '7431' = 'Client/server clock difference'; '8455' = 'Fresh credentials required'; '8711' = 'Smart card blocked'
            '9732' = 'Client/server version mismatch'; '50331649' = 'RD Gateway: bad user name or password'; '50331651' = 'RD Gateway certificate problem'; '50331654' = 'RD Gateway certificate problem'
            '50331657' = 'RD Gateway: send error (network down)'; '50331658' = 'RD Gateway: receive error (network down)'; '50331660' = 'RD Gateway unreachable'; '50331661' = 'RD Gateway temporarily unavailable'
            '50331672' = 'RD Gateway ended the connection'; '50331673' = 'RD Gateway admin ended the connection'; '50331675' = 'Not authorized by RD Gateway policy'; '50331676' = 'Not authorized by RD Gateway policy'
            '50331680' = 'Web proxy requires authentication'; '50331698' = 'Idle time limit'; '50331699' = 'Session time limit'; '50331716' = 'Forward proxy failure'; '50331722' = 'Network does not allow the HTTPS ports'
        }
        $cat = @{}
        foreach ($c in '0', '1', '2', '263') { $cat[$c] = 'User/normal' }
        foreach ($c in '260', '264', '516', '520', '772', '1028', '1288', '1540', '1796', '2308', '3592', '50331657', '50331658', '50331660', '50331661', '50331680', '50331716', '50331722') { $cat[$c] = 'Network' }
        foreach ($c in '2055', '2567', '2823', '3079', '3335', '3591', '3847', '4359', '4615', '5639', '5895', '6151', '7175', '8455', '8711', '50331649', '50331675', '50331676') { $cat[$c] = 'Authentication' }
        foreach ($c in '3', '1800', '50331672', '50331673', '50331698', '50331699') { $cat[$c] = 'Server/policy' }
        foreach ($c in '1030', '2310', '2311', '2566', '2822', '6919', '7431', '50331651', '50331654', '3078', '3080') { $cat[$c] = 'Security/certificate' }
        foreach ($c in '2056', '2312') { $cat[$c] = 'Licensing' }
        $attempts = @(); $disc = @()
        foreach ($e in $ev) {
            if ($e.Id -eq 1024) {
                $srv = $null
                if ($e.Message -match '\(([^)]+)\)') { $srv = $matches[1] }
                $attempts += $srv
            } elseif ($e.Id -eq 1026) {
                $code = $null
                if ($e.Message -match 'Reason=\s*(\d+)') { $code = $matches[1] }
                $category = if ($code -and $cat.ContainsKey("$code")) { $cat["$code"] } else { 'Other' }
                $disc += [pscustomobject]@{ Time = Format-Date $e.TimeCreated; Code = $code; Meaning = $reasonMap["$code"]; Category = $category }
            }
        }
        # UDP side channel: 1102 attempted, 1103 established, 1104 failed (stays on TCP), 1105 closed (also at
        # every normal session end), 226 UDP state-machine error.
        $udp = [ordered]@{
            Attempted = @($ev | Where-Object Id -eq 1102).Count; Established = @($ev | Where-Object Id -eq 1103).Count
            Failed = @($ev | Where-Object Id -eq 1104).Count; Closed = @($ev | Where-Object Id -eq 1105).Count; StateErrors = @($ev | Where-Object Id -eq 226).Count
        }
        $udp['Status'] = if ($udp.Established -gt 0 -and $udp.Failed -eq 0) { 'UDP works' }
                         elseif ($udp.Established -gt 0) { "UDP works sometimes ($($udp.Established) established, $($udp.Failed) failed)" }
                         elseif ($udp.Failed -gt 0) { 'UDP fails: sessions run on TCP only' }
                         elseif ($udp.Attempted -gt 0) { 'UDP attempted, result not logged' }
                         elseif ($attempts.Count -gt 0) { 'No UDP attempts (server or gateway does not offer UDP)' }
                         else { 'No RDP sessions logged' }
        $unexpected = @($disc | Where-Object { $_.Code -and $_.Category -ne 'User/normal' })
        $network = @($disc | Where-Object { $_.Category -eq 'Network' })
        $out['RdpClient'] = [ordered]@{
            EventCount = $ev.Count
            ConnectAttempts = $attempts.Count
            ServersSeen = @($attempts | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
            Disconnects = $disc.Count
            UnexpectedDisconnects = $unexpected.Count
            NetworkDisconnects = $network.Count
            DisconnectsByCategory = @($disc | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })
            DisconnectReasons = @($disc | Group-Object Code | Sort-Object Count -Descending | ForEach-Object { '{0} {1} x{2}' -f $_.Name, $reasonMap["$($_.Name)"], $_.Count })
            RecentDisconnects = @($disc | Select-Object -First 15)
            AllDisconnects = $disc
            Udp = $udp
            UdpTransportEvents = ($udp.Attempted + $udp.Established + $udp.Failed + $udp.Closed)
            FirstEvent = if ($ev.Count) { Format-Date $ev[-1].TimeCreated } else { $null }
        }
    } catch { $out['RdpClient'] = "unavailable: $($_.Exception.Message)" }

    # System log warnings/errors, grouped
    try {
        $sys = @(Get-EventsSafe @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $since } 4000)
        $groups = @($sys | Group-Object ProviderName, Id | Sort-Object Count -Descending)
        $nicRegex = 'e1.express|e1iexpress|e1rexpress|e2f|rt640|rtux|Rtl|Netwtw|Netwbw|Netwaw|b57nd|bnxt|mrvl|Realtek|Intel.*Ethernet|athw|Qualcomm|mtkwl|RTWlan|NDIS|Tcpip'
        $top = @()
        $nic = @()
        $rank = 0
        # The 25 largest groups go in SystemTop; NIC groups are checked at any size so rare link drops still count.
        foreach ($g in $groups) {
            $sample = $g.Group[0]
            $isTop = ($rank -lt 25); $rank++
            $isNic = ($sample.ProviderName -match $nicRegex)
            if (-not $isTop -and -not $isNic) { continue }
            $msg = $null
            try { $msg = ("$($sample.Message)" -split "`r?`n")[0] } catch { }
            if ($msg -and $msg.Length -gt 160) { $msg = $msg.Substring(0, 160) }
            $row = [pscustomobject]@{ Provider = $sample.ProviderName; Id = $sample.Id; Count = $g.Count; Last = Format-Date $sample.TimeCreated; Sample = $msg }
            if ($isTop) { $top += $row }
            if ($isNic -and $msg -match 'disconnect|link.*down|reset|lost') { $nic += $row }
        }
        $out['SystemTop'] = $top
        $out['NicLinkEvents'] = $nic
        $out['NicLinkEventCount'] = ($nic | Measure-Object Count -Sum).Sum
        $out['UnexpectedShutdowns'] = @($sys | Where-Object { ($_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41) -or ($_.ProviderName -eq 'EventLog' -and $_.Id -eq 6008) }).Count
        $out['DnsClientTimeouts'] = @($sys | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-DNS-Client' -and $_.Id -eq 1014 }).Count
    } catch { $out['System'] = "unavailable: $($_.Exception.Message)" }
    $out
}

$Result['NetworkExtra'] = Invoke-Collector 'Gateway, DNS, proxy, routes' {
    $out = [ordered]@{}
    $gw = $Gateway
    $out['Gateway'] = $gw
    if ($gw -and (Test-IPv4 $gw)) {
        try { Invoke-Native 'ping.exe' "-n 1 -w 500 $gw" 5 | Out-Null } catch { }
        $nb = Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-){5}00$' } | Select-Object -First 1
        $out['GatewayMac'] = if ($nb) { $nb.LinkLayerAddress } else { $null }
        $out['GatewayVendor'] = if ($nb) { Get-MacVendor $nb.LinkLayerAddress } else { $null }
        $out['GatewayPtr'] = Resolve-Ptr $gw
    }

    # DNS servers classified
    $known = @{ '1.1.1.1' = 'Cloudflare'; '1.0.0.1' = 'Cloudflare'; '8.8.8.8' = 'Google'; '8.8.4.4' = 'Google'; '9.9.9.9' = 'Quad9'; '149.112.112.112' = 'Quad9'; '208.67.222.222' = 'OpenDNS/Umbrella'; '208.67.220.220' = 'OpenDNS/Umbrella'; '4.2.2.1' = 'Level3'; '4.2.2.2' = 'Level3' }
    $dns = @()
    $primaryIf = @($Result['Network']['Adapters'] | Where-Object { $_.Name -eq $Result['Network']['PrimaryAdapter'] })
    $servers = @()
    foreach ($a in $primaryIf) { $servers += $a.DnsServers }
    try { $servers += @(Get-DnsClientServerAddress -AddressFamily IPv6 -InterfaceAlias $Result['Network']['PrimaryAdapter'] -ErrorAction Stop).ServerAddresses } catch { }
    foreach ($s in ($servers | Where-Object { $_ } | Select-Object -Unique)) {
        $kind = Get-IpClass $s
        $label = if ($s -eq $gw) { 'Gateway (firewall/router)' }
                 elseif ($known.ContainsKey($s)) { "Public resolver ($($known[$s]))" }
                 elseif ($kind -eq 'Private') { 'Private, not the gateway (internal DNS / DC / tunnel)' }
                 elseif ($kind -eq 'Public') { 'Public (likely ISP)' }
                 else { $kind }
        $dns += [pscustomobject]@{ Server = $s; Type = $label }
    }
    $out['DnsServers'] = $dns
    $out['DnsSuffixSearch'] = @(try { (Get-DnsClientGlobalSetting -ErrorAction Stop).SuffixSearchList } catch { })

    # Proxy
    $out['WinHttpProxy'] = try { ((Invoke-Native 'netsh.exe' 'winhttp show proxy' 10) -split "`r?`n" | Where-Object { $_.Trim() }) -join ' | ' } catch { $null }
    $ie = Get-RegValues "$($script:UserHive)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if ($ie) { $out['UserProxy'] = [ordered]@{ ProxyEnable = $ie['ProxyEnable']; ProxyServer = $ie['ProxyServer']; AutoConfigURL = $ie['AutoConfigURL']; ProxyOverride = $ie['ProxyOverride'] } }

    # Error counters on the physical adapter since boot (no admin needed): errors point at a cable or switch port.
    try {
        $phys = $Result['Network']['PhysicalAdapter']
        if ($phys) {
            $st = Get-NetAdapterStatistics -Name $phys -ErrorAction Stop
            $out['AdapterStats'] = [ordered]@{
                Adapter = $phys; ReceivedPackets = $st.ReceivedUnicastPackets + $st.ReceivedMulticastPackets + $st.ReceivedBroadcastPackets
                SentPackets = $st.SentUnicastPackets + $st.SentMulticastPackets + $st.SentBroadcastPackets
                ReceiveErrors = $st.ReceivedPacketErrors; SendErrors = $st.OutboundPacketErrors
                ReceiveDiscards = $st.ReceivedDiscardedPackets; SendDiscards = $st.OutboundDiscardedPackets
            }
        }
    } catch { $out['AdapterStats'] = "unavailable: $($_.Exception.Message)" }

    # Hosts file entries
    try { $out['HostsEntries'] = @(Get-Content "$env:WINDIR\System32\drivers\etc\hosts" -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#\s]' } | ForEach-Object { $_.Trim() }) } catch { }

    # Routes (minus multicast/broadcast noise)
    $out['Routes'] = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -notmatch '^(224\.|255\.255\.255\.255|127\.)' -and $_.DestinationPrefix -notmatch '/32$' } |
        ForEach-Object { [pscustomobject]@{ Prefix = $_.DestinationPrefix; NextHop = $_.NextHop; Interface = $_.InterfaceAlias; Metric = $_.RouteMetric } })
    $out
}

$Result['Servers'] = Invoke-Collector 'Servers this PC depends on' {
    # Names come from what the PC already uses (mapped drives, shared printers, its domain). Each one is
    # resolved and placed: this subnet (on-prem here), another private subnet (another site or a tunnel)
    # or public (cloud). Internal names only resolve on site, so this cannot be done later.
    $cands = @()
    foreach ($d in @(Get-Val $Result['Identity'] 'MappedDrives')) {
        if ($d -and "$($d.RemotePath)" -match '^\\\\([^\\]+)\\') { $cands += [pscustomobject]@{ Name = $matches[1]; Source = "mapped drive $($d.Drive) $($d.RemotePath)" } }
    }
    foreach ($p in @(Get-Val $Result['Peripherals'] 'Printers')) {
        if ($p -and "$($p.Name)" -match '^\\\\([^\\]+)\\') { $cands += [pscustomobject]@{ Name = $matches[1]; Source = "shared printer $($p.Name)" } }
    }
    foreach ($c in @(Get-Val $Result['Peripherals'] 'UserPrinterConnections')) {
        if ("$c" -match '^\\\\([^\\]+)\\') { $cands += [pscustomobject]@{ Name = $matches[1]; Source = "user printer connection $c" } }
    }
    $dc = $null
    if (Get-Val $Result['Machine'] 'PartOfDomain') {
        $dc = [ordered]@{ Domain = Get-Val $Result['Machine'] 'Domain' }
        try {
            $raw = Invoke-Native 'nltest.exe' ('/dsgetdc:{0}' -f $dc['Domain']) 20
            foreach ($line in ($raw -split "`r?`n")) {
                if ($line -match '^\s*DC:\s*\\\\(\S+)') { $dc['Name'] = $matches[1] }
                elseif ($line -match '^\s*Address:\s*\\\\(\S+)') { $dc['Address'] = $matches[1] }
                elseif ($line -match '^\s*Dc Site Name:\s*(.+?)\s*$') { $dc['DcSite'] = $matches[1] }
                elseif ($line -match '^\s*Our Site Name:\s*(.+?)\s*$') { $dc['ClientSite'] = $matches[1] }
            }
            if ($dc['Name']) { $cands += [pscustomobject]@{ Name = $dc['Name']; Source = "domain controller for $($dc['Domain'])" } }
            else { $dc['Error'] = (($raw -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' ') }
        } catch { $dc['Error'] = $_.Exception.Message }
    }
    $localNets = @()
    foreach ($a in @(Get-Val $Result['Network'] 'Adapters' | Where-Object { $_ -and $_.Status -eq 'Up' })) {
        $ipsA = @($a.IPv4); $masks = @($a.SubnetMask)
        for ($q = 0; $q -lt $ipsA.Count; $q++) { if ($ipsA[$q] -and $masks.Count -gt $q) { $localNets += [pscustomobject]@{ Ip = $ipsA[$q]; Mask = $masks[$q] } } }
    }
    $rows = @()
    foreach ($g in @($cands | Group-Object { "$($_.Name)".ToLower() } | Select-Object -First 20)) {
        $name = $g.Group[0].Name
        $ips = @()
        if (Test-IPv4 $name) { $ips = @($name) }
        else {
            try { $ips = @(Resolve-DnsName -Name $name -Type A -QuickTimeout -ErrorAction Stop | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and (Test-IPv4 $_) } | Select-Object -Unique) } catch { }
        }
        $where = 'Does not resolve from this PC'
        $smb = $null
        if ($ips.Count) {
            $cls = Get-IpClass $ips[0]
            $onLink = [bool](@($localNets | Where-Object { Test-SameSubnet $ips[0] $_.Ip $_.Mask }).Count)
            $where = if ($cls -eq 'Private' -and $onLink) { 'On-prem, this subnet' }
                     elseif ($cls -eq 'Private') { 'Private, another subnet (another site, VLAN or tunnel)' }
                     elseif ($cls -eq 'Public') { 'Public (cloud or hosted)' }
                     else { $cls }
            try { $smb = Test-TcpPort $ips[0] 445 1000 } catch { }
        }
        $rows += [pscustomobject]@{ Name = $name; Sources = @($g.Group | ForEach-Object { $_.Source } | Select-Object -Unique); IPs = $ips; Location = $where; FileSharingReachable = $smb }
    }
    [ordered]@{ Servers = $rows; DomainController = $dc }
}

if ($EnableAdSites -and $script:FullLanguage -and (Get-Val $Result['Machine'] 'PartOfDomain')) {
    $Result['AdSites'] = Invoke-Collector 'Active Directory sites and subnets' { Get-AdSites 20 }
}

$Result['Patching'] = Invoke-Collector 'Windows Update, reboot, Microsoft 365' {
    $out = [ordered]@{}
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
    if (Get-RegString 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations') { $reasons += 'Pending file renames' }
    $out['PendingReboot'] = ($reasons.Count -gt 0)
    $out['PendingRebootReasons'] = $reasons

    # Update source: WSUS, Windows Update for Business policy, or plain Windows Update.
    $wu = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $au = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $out['WsusServer'] = Get-Val $wu 'WUServer'
    $out['UseWsus'] = ((Get-Val $au 'UseWUServer') -eq 1)
    $out['WufbDeferQualityDays'] = Get-Val $wu 'DeferQualityUpdatesPeriodInDays'
    $out['WufbDeferFeatureDays'] = Get-Val $wu 'DeferFeatureUpdatesPeriodInDays'
    # Last OS patch. Update history is mostly daily Defender signatures and Store apps, which say nothing
    # about OS patching, so only Windows OS updates count. Get-HotFix also lists installed cumulative
    # updates when history was cleared or another tool (RMM, WSUS) installed them; the newer source wins.
    $candidates = @()
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $srch = $sess.CreateUpdateSearcher()
        $cnt = $srch.GetTotalHistoryCount()
        $hist = @()
        if ($cnt -gt 0) { $hist = @($srch.QueryHistory(0, [math]::Min(1000, $cnt))) }
        $ok = @($hist | Where-Object { $_.ResultCode -eq 2 -and $_.Title } | Sort-Object Date -Descending)
        $osInclude = 'Cumulative Update for Windows|Security Update \(KB|Security Update for Windows|Feature update to Windows|Servicing Stack Update|Update for Windows 1[01]'
        $osExclude = 'Defender|Security Intelligence|KB2267602|KB4052623|KB890830|Malicious Software|\.NET|Driver|Firmware'
        $osOk = @($ok | Where-Object { $_.Title -match $osInclude -and $_.Title -notmatch $osExclude })
        if ($ok.Count) { $out['LastAnyUpdate'] = '{0} {1}' -f (Format-Date $ok[0].Date.ToLocalTime()), $ok[0].Title }
        if ($osOk.Count) { $candidates += [pscustomobject]@{ Date = $osOk[0].Date.ToLocalTime(); Title = $osOk[0].Title; Source = 'update history' } }
        $out['FailedUpdatesRecent'] = @($hist | Where-Object { $_.ResultCode -in @(4, 5) } | Select-Object -First 5 | ForEach-Object { '{0} {1}' -f (Format-Date $_.Date.ToLocalTime()), $_.Title })
    } catch { $out['UpdateHistoryError'] = $_.Exception.Message }
    try {
        $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) { $candidates += [pscustomobject]@{ Date = [datetime]$hf.InstalledOn; Title = '{0} {1}' -f $hf.HotFixID, $hf.Description; Source = 'installed KBs (Get-HotFix)' } }
    } catch { }
    $newest = $candidates | Sort-Object Date -Descending | Select-Object -First 1
    $out['LastUpdateInstalled'] = if ($newest) { Format-Date $newest.Date } else { $null }
    $out['LastUpdateTitle'] = if ($newest) { $newest.Title } else { $null }
    $out['LastUpdateSource'] = if ($newest) { $newest.Source } else { $null }
    $out['DaysSinceLastUpdate'] = if ($newest) { [math]::Round(((Get-Date) - $newest.Date).TotalDays, 0) } else { $null }

    # Microsoft 365 Apps (Click-to-Run)
    $c2r = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    if ($c2r) {
        $channels = @{
            '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current'
            '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current (Preview)'
            '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise'
            '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise'
            'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise (Preview)'
            '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta'
        }
        $chanUrl = "$(Get-Val $c2r 'UpdateChannel') $(Get-Val $c2r 'CDNBaseUrl')"
        $chan = $null
        foreach ($g in $channels.Keys) { if ($chanUrl -match $g) { $chan = $channels[$g]; break } }
        $out['M365'] = [ordered]@{
            Version = Get-Val $c2r 'VersionToReport'; Platform = Get-Val $c2r 'Platform'; Channel = $chan
            Products = Get-Val $c2r 'ProductReleaseIds'; SharedActivation = ((Get-Val $c2r 'SharedComputerLicensing') -eq '1')
        }
    } else { $out['M365'] = $null }
    $out
}
