function Get-AccessType {
    # The kind of internet access, when the carrier's network name says it outright. $null when it does
    # not (most telcos sell fiber, DSL and wireless under one name, so they are not guessed).
    param([string]$Carrier)
    $c = "$Carrier"
    if ($c -match 'Space Exploration|Starlink|SpaceX') { return 'Starlink (low-orbit satellite)' }
    if ($c -match 'Viasat|Hughes|EchoStar|Inmarsat') { return 'geostationary satellite' }
    if ($c -match 'T-Mobile|Cellco|Verizon Wireless|AT&T Mobility|Sprint|UScellular|US Cellular') { return 'cellular or fixed wireless' }
    if ($c -match 'Comcast|Charter|Spectrum|Cox Comm|Altice|Optimum|Mediacom|WideOpenWest|\bWOW\b|Sparklight|Cable One|Rogers|Shaw|Virgin Media|Liberty') { return 'cable' }
    return $null
}

# ---------------------------------------------------------------------
# Network risks, read from what discovery already collected. Nothing extra is sent to any device.
# Returns Severity, Category, Message rows for Add-Flag.
# ---------------------------------------------------------------------
function Get-NetworkRiskFlags {
    param($R, [datetime]$Now = (Get-Date))
    $out = New-Object Collections.Generic.List[object]
    $flag = { param($sev, $msg) $out.Add([pscustomobject]@{ Severity = $sev; Category = 'Network risk'; Message = $msg }) }
    $label = { param($d) $n = "$(Get-Prop $d 'Name')"; if ($n) { '{0} ({1})' -f (Get-Prop $d 'IP'), $n.Split('.')[0] } else { "$(Get-Prop $d 'IP')" } }
    $list = { param($items) $a = @($items); $t = (@($a | Select-Object -First 6 | ForEach-Object { & $label $_ })) -join ', '; if ($a.Count -gt 6) { $t += " and $($a.Count - 6) more" }; $t }
    $devs = @(@(Get-Prop $R 'Identify', 'Devices') | Where-Object { $_ })
    $ports = { param($d) @(@(Get-Prop $d 'OpenPorts') | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ }) }

    $smb1 = @($devs | Where-Object { Get-Prop $_ 'Smb', 'Smb1Enabled' })
    if ($smb1.Count) { & $flag 'High' "$($smb1.Count) device(s) still accept SMBv1, the file-sharing version WannaCry spread over: $(& $list $smb1)" }
    $telnet = @($devs | Where-Object { (& $ports $_) -contains 23 })
    if ($telnet.Count) { & $flag 'Medium' "$($telnet.Count) device(s) accept Telnet, where logins cross the network in clear text: $(& $list $telnet)" }
    $ftp = @($devs | Where-Object { (& $ports $_) -contains 21 })
    if ($ftp.Count) { & $flag 'Low' "$($ftp.Count) device(s) run FTP, where logins cross the network in clear text: $(& $list $ftp)" }

    # A web page only over plain HTTP: whatever is typed into its login crosses the network unencrypted.
    $httpOnly = @($devs | Where-Object {
        $w = @(@(Get-Prop $_ 'Web') | Where-Object { $_ -and (Get-Prop $_ 'Status') })
        @($w | Where-Object { "$(Get-Prop $_ 'Url')" -like 'http://*' }).Count -and -not @($w | Where-Object { "$(Get-Prop $_ 'Url')" -like 'https://*' }).Count
    })
    if ($httpOnly.Count) { & $flag 'Low' "$($httpOnly.Count) device(s) offer their web page only over plain HTTP, so a login there is sent unencrypted: $(& $list $httpOnly)" }

    $expired = @($devs | Where-Object {
        @(@(Get-Prop $_ 'Web') | Where-Object { $na = "$(Get-Prop $_ 'CertNotAfter')"; $na -and ([datetime]$na) -lt $Now }).Count
    })
    if ($expired.Count) { & $flag 'Low' "$($expired.Count) device(s) present an expired HTTPS certificate, which teaches people to click through certificate warnings: $(& $list $expired)" }

    # Remote Desktop and file sharing reachable from an office port across routing
    $remote = @($devs | Where-Object { Get-Prop $_ 'Remote' })
    $rdp = @($remote | Where-Object { (& $ports $_) -contains 3389 })
    if ($rdp.Count) { & $flag 'Medium' "From an ordinary office port, Remote Desktop answers on $($rdp.Count) device(s) on other subnets, with nothing filtering in between: $(& $list $rdp)" }
    $smb = @($remote | Where-Object { (& $ports $_) -contains 445 })
    if ($smb.Count) { & $flag 'Medium' "From an ordinary office port, file sharing answers on $($smb.Count) device(s) on other subnets, the path ransomware spreads along: $(& $list $smb)" }

    $snmpN = Get-Prop $R 'Snmp', 'Answered'
    if ($snmpN -and "$(Get-Prop $R 'Snmp', 'Community')" -eq 'public') {
        & $flag 'Medium' "$snmpN device(s) answer SNMP with the default community 'public': anyone on the network can read their configuration, ARP tables and routes"
    }

    # SSH servers from before 2017 (OpenSSH under 7.4, Dropbear before 2017)
    $oldSsh = @($devs | Where-Object {
        $b = "$(Get-Prop $_ 'SshBanner')"
        ($b -match 'OpenSSH_(\d+)\.(\d+)' -and ([int]$matches[1] -lt 7 -or ([int]$matches[1] -eq 7 -and [int]$matches[2] -lt 4))) -or ($b -match 'dropbear_(\d{4})' -and [int]$matches[1] -lt 2017)
    })
    if ($oldSsh.Count) { & $flag 'Low' "$($oldSsh.Count) device(s) run an SSH server from before 2017, a sign of firmware that has not been updated in years: $(& $list $oldSsh)" }

    # Windows that no longer gets security updates, named by the file-sharing handshake
    $hosts = @(@(Get-Prop $R 'WindowsHosts', 'Hosts') | Where-Object { $_ })
    $dead = @($hosts | Where-Object { "$(Get-Prop $_ 'Os')" -match '^Windows (7|8)\b' })
    if ($dead.Count) { & $flag 'High' "$($dead.Count) machine(s) on the network run Windows that no longer gets security updates (Windows 7 or 8, Server 2008 R2 or 2012): $((@($dead | Select-Object -First 6 | ForEach-Object { '{0} ({1}, {2})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'ComputerName'), (Get-Prop $_ 'Os') })) -join ', ')" }
    $checks = @(@(Get-Prop $R 'LeadChecks', 'Checks') | Where-Object { $_ })
    $oldEsx = @($checks | Where-Object { "$(Get-Prop $_ 'Kind')" -eq 'Hypervisor' -and "$(Get-Prop $_ 'Version')" -match '^(5|6|7)\.' })
    if ($oldEsx.Count) { & $flag 'High' "$($oldEsx.Count) VMware host(s) run a version out of general support (6.x ended 2022, 7.0 in October 2025): $((@($oldEsx | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'What') })) -join ', ')" }
    $bmc = @($checks | Where-Object { "$(Get-Prop $_ 'Kind')" -eq 'ServerManagement' })
    if ($bmc.Count) { & $flag 'Medium' "$($bmc.Count) server management controller(s) (iDRAC, iLO and similar) can be reached from an ordinary office port; they belong on a management network: $((@($bmc | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'What') })) -join ', ')" }
    $w10 = @($hosts | Where-Object { "$(Get-Prop $_ 'Os')" -like 'Windows 10 (*' })
    if ($w10.Count) { & $flag 'Medium' "$($w10.Count) machine(s) on the network run Windows 10, out of support since October 2025 unless they are LTSC or covered by Extended Security Updates: $((@($w10 | Select-Object -First 6 | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'ComputerName') })) -join ', ')" }

    return $out.ToArray()
}

function Get-AssessmentFindings {
    # Turns the collected evidence into plain statements, each with what it rests on and how sure it is:
    # Confirmed (measured directly), Likely (several signs agree), Possible (one sign, or an inference).
    # Reads live results and saved JSON alike, so it can be re-run on old runs.
    param($R)
    $out = New-Object Collections.Generic.List[object]
    $add = { param($area, $conf, $text, $evidence) $out.Add([pscustomobject]@{ Area = $area; Confidence = $conf; Finding = "$text"; Evidence = @(@($evidence) | Where-Object { $_ } | ForEach-Object { "$_" }) }) }
    $net = Get-Prop $R 'Network'; $bw = Get-Prop $R 'Bandwidth'; $cap = Get-Prop $R 'Capture'; $eg = Get-Prop $R 'Egress'
    $class = "$(Get-Prop $net 'PhysicalClass')"; $wired = ($class -like 'Wired*')
    $link = Get-Prop $net 'PhysicalLinkMbps'; $srcIp = "$(Get-Prop $net 'SourceIp')"; $gw = "$(Get-Prop $net 'Gateway')"
    $elev = [bool](Get-Prop $R 'Meta', 'AdminTierActive')
    $ad = @(@(Get-Prop $net 'Adapters') | Where-Object { $_ -and "$(Get-Prop $_ 'Name')" -eq "$(Get-Prop $net 'PhysicalAdapter')" }) | Select-Object -First 1
    $mask = "$(@(Get-Prop $ad 'SubnetMask') | Select-Object -First 1)"
    if ($mask -notmatch '^\d+\.\d+\.\d+\.\d+$') { $mask = '255.255.255.0' }
    $pre = { param($ip) (("$ip" -split '\.')[0..2] -join '.') }

    $machine = ("$(Get-Prop $R 'Machine', 'Manufacturer') $(Get-Prop $R 'Machine', 'Model')").Trim()
    if ((Get-Prop $R 'Preflight', 'LooksLikeHostedDesktop') -or $machine -match 'VMware|Virtual Machine|VirtualBox|KVM|QEMU|Xen') {
        & $add 'This run' 'Confirmed' 'This run was made on a virtual machine or hosted desktop. Everything below describes the data center or cloud it runs in, not an office.' @("Machine: $machine", "Address: $srcIp", "Egress: $(Get-Prop $eg 'Carrier')")
    }

    # ---- What the wire capture heard ----
    $lldp = @(@(Get-Prop $cap 'Lldp') | Where-Object { $_ }); $cdp = @(@(Get-Prop $cap 'Cdp') | Where-Object { $_ }); $stp = @(@(Get-Prop $cap 'SpanningTree') | Where-Object { $_ })
    $haveCap = ($null -ne $cap -and $null -ne (Get-Prop $cap 'Frames'))
    $captureRan = $haveCap -or ($null -ne (Get-Prop $R 'Lldp', 'FramesCaptured'))
    $capSecs = Get-Prop $cap 'Seconds'; if (-not $capSecs) { $capSecs = 65 }
    $switches = @(); $phones = @(); $others = @(); $foreign = @(); $voiceVlan = $null
    foreach ($n in $lldp) {
        $caps = @(Get-Prop $n 'Capabilities'); $cls = "$(Get-Prop $n 'MedDeviceClass')"
        $label = (@("$(Get-Prop $n 'SystemName')", "$(Get-Prop $n 'SystemDescription')", "$(Get-Prop $n 'ChassisVendor')") | Where-Object { $_ }) -join ', '
        if (-not $label) { $label = "MAC $(Get-Prop $n 'SenderMac')" }
        if ($caps -contains 'Telephone' -or $cls -like '*phone*') { $phones += "$label (LLDP)" }
        elseif ($caps -contains 'Bridge' -or $caps -contains 'WLAN access point' -or $cls -like 'Network connectivity*') {
            $port = "$(Get-Prop $n 'PortDescription')"; if (-not $port) { $port = "$(Get-Prop $n 'PortId')" }
            $switches += [pscustomobject]@{ Label = $label; Port = $port; Vlan = Get-Prop $n 'PortVlan'; LinkMode = "$(Get-Prop $n 'LinkMode')"; MgmtIP = "$(Get-Prop $n 'MgmtIP')"; Proto = 'LLDP' }
            if (Get-Prop $n 'VoiceVlan') { $voiceVlan = Get-Prop $n 'VoiceVlan' }
        }
        else { $others += "$label (LLDP)"; $ip = "$(Get-Prop $n 'MgmtIP')"; if ($ip -and $srcIp -and -not (Test-SameSubnet $ip $srcIp $mask)) { $foreign += "$ip ($label)" } }
    }
    foreach ($n in $cdp) {
        $caps = @(Get-Prop $n 'Capabilities')
        $label = (@("$(Get-Prop $n 'DeviceId')", "$(Get-Prop $n 'Platform')", "$(Get-Prop $n 'Software')") | Where-Object { $_ }) -join ', '
        if ($caps -contains 'Telephone') { $phones += "$label (CDP)" }
        elseif ($caps -contains 'Switch' -or $caps -contains 'Bridge') {
            $switches += [pscustomobject]@{ Label = $label; Port = "$(Get-Prop $n 'PortId')"; Vlan = Get-Prop $n 'NativeVlan'; LinkMode = ''; MgmtIP = "$(Get-Prop $n 'Address')"; Proto = 'CDP' }
            if (Get-Prop $n 'VoiceVlan') { $voiceVlan = Get-Prop $n 'VoiceVlan' }
        }
        else { $others += "$label (CDP)"; $ip = "$(Get-Prop $n 'Address')"; if ($ip -and $srcIp -and -not (Test-SameSubnet $ip $srcIp $mask)) { $foreign += "$ip ($label)" } }
    }
    if (-not $haveCap) {
        # Runs made before 1.6.0 only have the older neighbor list, without capabilities.
        foreach ($n in @(@(Get-Prop $R 'Lldp', 'Neighbors') | Where-Object { $_ })) {
            $label = (@("$(Get-Prop $n 'SystemName')", "$(Get-Prop $n 'SystemDescription')") | Where-Object { $_ }) -join ', '
            if ("$(Get-Prop $n 'Protocol')" -eq 'LLDP' -and "$(Get-Prop $n 'Port')" -notmatch '^eth\d') { $switches += [pscustomobject]@{ Label = $label; Port = "$(Get-Prop $n 'Port')"; Vlan = Get-Prop $n 'Vlan'; LinkMode = "$(Get-Prop $n 'LinkMode')"; MgmtIP = "$(Get-Prop $n 'MgmtIP')"; Proto = 'LLDP' } }
            else { $others += "$label ($(Get-Prop $n 'Protocol'))" }
        }
    }

    # ---- Speed test: did the port or the circuit set the limit? ----
    $down = Get-Prop $bw 'DownloadMbps'; $up = Get-Prop $bw 'UploadMbps'; $peak = Get-Prop $bw 'DownloadPeakMbps'
    $capped = $false
    if ($down) {
        $ev = @("Link speed: $link Mbps ($class)", "Download $down Mbps (peak $peak), upload $up Mbps, via $(Get-Prop $bw 'DownloadProvider')")
        $rounds = @(@(Get-Prop $bw 'Rounds') | Where-Object { $_ -and (Get-Prop $_ 'DownloadOk') })
        $spread = $null
        if ($rounds.Count -gt 1) {
            $vals = @($rounds | ForEach-Object { [double](Get-Prop $_ 'DownloadMbps') })
            $mx = ($vals | Measure-Object -Maximum).Maximum; $mn = ($vals | Measure-Object -Minimum).Minimum
            if ($mx -gt 0) { $spread = [int][math]::Round(100 * ($mx - $mn) / $mx) }
            $ev += ('Rounds (down/up Mbps): {0}; spread {1}%' -f (($rounds | ForEach-Object { '{0}/{1}' -f (Get-Prop $_ 'DownloadMbps'), (Get-Prop $_ 'UploadMbps') }) -join ', '), $spread)
        }
        if ($link) { $capped = ([double]$down -ge 0.85 * [double]$link) -or ($peak -and [double]$peak -ge 0.95 * [double]$link) }
        if (-not $wired) {
            & $add 'Speed test' 'Likely' "Tested over $class at a radio rate of $link Mbps: the result ($down down / $up up Mbps) reflects the wireless link as much as the circuit." $ev
        } elseif ($capped -and [double]$link -lt 1000) {
            & $add 'Speed test' 'Confirmed' "The speed test ran into the limit of this port ($link Mbps link), so it measured the port, not the circuit. The circuit delivers at least $down down / $up up Mbps; its real speed is not known from this run." $ev
        } elseif ($capped) {
            & $add 'Speed test' 'Confirmed' "Download reached the limit of the $link Mbps link ($down Mbps, peak $peak): the circuit is at least that fast. Upload measured $up Mbps." $ev
        } elseif ($link) {
            $c = if ($null -ne $spread -and $spread -le 15) { 'Confirmed' } else { 'Likely' }
            & $add 'Speed test' $c "The port linked at $link Mbps and the test stayed well under it, so $down down / $up up Mbps reflects the internet circuit (or its provisioned speed), not this port." $ev
        }
        if ($null -ne $spread -and $spread -gt 25) { & $add 'Speed test' 'Likely' "The rounds differ by $spread%: the circuit was busy or unstable while testing. Treat the best round as the capability and the spread as contention." $ev }
        if ($up -and [double]$down -gt 0 -and $machine -notmatch 'VMware|Virtual Machine|VirtualBox|KVM|QEMU|Xen') {
            $ratio = [double]$up / [double]$down
            if ($capped -and [double]$up -gt 40) { & $add 'Internet service' 'Likely' "Upload reached $up Mbps even through the port limit, which rules out older cable and DSL tiers: a symmetrical service (fiber or a newer cable tier)." @("Download $down, upload $up Mbps") }
            elseif (-not $capped -and $ratio -ge 0.7) { & $add 'Internet service' 'Likely' "Upload is close to download ($up vs $down Mbps): a symmetrical service, typically fiber." @("Upload/download ratio $([math]::Round($ratio, 2))") }
            elseif (-not $capped -and $ratio -le 0.25) {
                $acc = Get-AccessType "$(Get-Prop $eg 'Carrier')"
                & $add 'Internet service' 'Likely' "Upload is a fraction of download ($up vs $down Mbps): an asymmetric service, $(if ($acc) { "as expected on $acc" } else { 'such as cable, DSL, satellite or cellular' })." @("Upload/download ratio $([math]::Round($ratio, 2))")
            }
        }
    }

    # ---- Where this port lands ----
    if ($wired) {
        $heard = @()
        if ($others.Count) { $heard += "Other devices announcing themselves on this port: $((@($others) | Select-Object -First 6) -join '; ')" }
        if (-not $elev -or -not $captureRan) {
            & $add 'Switch port' 'Possible' 'The wire capture did not run (ISE not elevated, or the capture failed), so the switch behind this port could not be identified.' @("Elevated: $elev", "Link speed: $link Mbps")
        } elseif ($phones.Count) {
            $t = "This jack is the pass-through port of a desk phone: $($phones[0])."
            if ($link -and [double]$link -lt 1000) { $t += " That is why the link is $link Mbps." }
            & $add 'Switch port' 'Confirmed' $t (@("Phone announced itself on this port: $($phones -join '; ')", "Link speed: $link Mbps") + $heard)
        } elseif ($switches.Count) {
            $s = $switches[0]
            $t = "This port is on a managed switch: $($s.Label), port $($s.Port)"
            if ($s.Vlan) { $t += ", VLAN $($s.Vlan)" }
            $t += '.'
            if ($s.LinkMode -like '100*' -or $s.LinkMode -like '10BASE*') { $t += " The switch itself reports this port at $($s.LinkMode): a 10/100 port, or cabling that cannot carry gigabit." }
            elseif ($link -and [double]$link -lt 1000) { $t += " The link is only $link Mbps although a managed switch is directly upstream: check the cable and the port speed setting." }
            & $add 'Switch port' 'Confirmed' $t (@("Announced by $($s.Proto): $($s.Label)", "Management address: $($s.MgmtIP)", "Link mode reported by the switch: $($s.LinkMode)", "Link speed seen by this PC: $link Mbps") + $heard)
        } elseif ($stp.Count) {
            $b = $stp[0]
            & $add 'Switch port' 'Likely' "No switch announced itself by LLDP or CDP, but spanning-tree frames from $(Get-Prop $b 'BridgeMac') ($(Get-Prop $b 'SenderVendor')) reached this port: a managed switch is upstream with discovery protocols turned off." (@("Spanning tree: bridge $(Get-Prop $b 'BridgeMac'), root $(Get-Prop $b 'RootMac') ($(Get-Prop $b 'RootVendor')), root path cost $(Get-Prop $b 'RootPathCost')", "Listened for $capSecs s, elevated") + $heard)
        } elseif ($link -and [double]$link -lt 1000) {
            & $add 'Switch port' 'Likely' "No switch announced itself in $capSecs s of listening (no LLDP, no CDP, no spanning tree) and the link is only $link Mbps. Together that points to something unmanaged between this jack and the real switch: a desk phone's pass-through port, a small 10/100 switch, or old two-pair cabling." (@("Run elevated: yes; capture ran for $capSecs s", "Link speed: $link Mbps on an adapter set to auto-negotiate", 'No LLDP or CDP frame from a switch, no spanning-tree frame') + $heard)
        } else {
            & $add 'Switch port' 'Possible' "No switch announced itself in $capSecs s of listening (no LLDP, CDP or spanning tree) although the link is $link Mbps: the switch is unmanaged, or has discovery protocols and spanning tree turned off." (@("Run elevated: yes; capture ran for $capSecs s") + $heard)
        }
        if ($stp.Count) {
            $b = $stp[0]
            $t = if (Get-Prop $b 'ThisSwitchIsRoot') { "The switch this port hangs off is itself the spanning-tree root ($(Get-Prop $b 'RootMac'), $(Get-Prop $b 'RootVendor'))." } else { "The spanning-tree root (the core switch) is $(Get-Prop $b 'RootMac') ($(Get-Prop $b 'RootVendor')), priority $(Get-Prop $b 'RootPriority'), $(Get-Prop $b 'RootPathCost') in path cost away from this port." }
            & $add 'Switching' 'Confirmed' $t @("Protocol: $(Get-Prop $b 'Protocol')", "Sending bridge: $(Get-Prop $b 'BridgeMac') priority $(Get-Prop $b 'BridgePriority')")
        }
    }

    # ---- DNS and DHCP: where they live ----
    $dhcp = "$(Get-Prop $ad 'DhcpServer')"; $dnsList = @(@(Get-Prop $ad 'DnsServers') | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
    $traces = @(@(Get-Prop $R 'Traceroutes') | Where-Object { $_ })
    $pings = @(@(Get-Prop $R 'PingSeries') | Where-Object { $_ })
    $where = {
        param($ip)
        if (-not $ip) { return 'none' }
        if ($ip -eq $gw) { return 'gateway' }
        if ($srcIp -and (Test-SameSubnet $ip $srcIp $mask)) { return 'lan' }
        if ((Get-IpClass $ip) -eq 'Private') { return 'remote' }
        return 'public'
    }
    $pathTo = {
        param($ip)
        $t = $traces | Where-Object { "$(Get-Prop $_ 'Target')" -eq $ip } | Select-Object -First 1
        if (-not $t) { $t = $traces | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (& $pre $tp) -eq (& $pre $ip) } | Select-Object -First 1 }
        if (-not $t) { return $null }
        $hops = @(@(Get-Prop $t 'Hops') | Where-Object { $_ })
        $p = $pings | Where-Object { "$(Get-Prop $_ 'Target')" -eq "$(Get-Prop $t 'Target')" } | Select-Object -First 1
        return [pscustomobject]@{ Target = "$(Get-Prop $t 'Target')"; HopCount = $hops.Count; Path = (@($hops | ForEach-Object { if (Get-Prop $_ 'IP') { "$(Get-Prop $_ 'IP') ($(Get-Prop $_ 'AvgMs') ms)" } else { 'no reply' } }) -join ' > '); AvgMs = Get-Prop $p 'AvgMs'; LossPct = Get-Prop $p 'LossPct'; Jitter = Get-Prop $p 'JitterMs' }
    }
    if ($ad) {
        $dns1 = "$($dnsList | Select-Object -First 1)"
        $wDhcp = & $where $dhcp; $wDns = & $where $dns1
        $ev = @("DHCP server on the lease: $dhcp", "DNS servers: $($dnsList -join ', ')", "This PC: $srcIp mask $mask, gateway $gw")
        $relay = @(@(Get-Prop $cap 'DhcpServers') | Where-Object { $_ -and (Get-Prop $_ 'RelayAgent') }) | Select-Object -First 1
        if ($relay) { $ev += "DHCP answers on the wire came through relay agent $(Get-Prop $relay 'RelayAgent') for server $(Get-Prop $relay 'Server')" }
        $lo = Get-Prop $ad 'DhcpLeaseObtained'; $le = Get-Prop $ad 'DhcpLeaseExpires'
        if ($lo -and $le) { try { $ev += ('Lease length: {0:N1} hours' -f (([datetime]$le) - ([datetime]$lo)).TotalHours) } catch { } }
        if ($wDhcp -eq 'remote' -or $wDns -eq 'remote') {
            $remote = if ($wDns -eq 'remote') { $dns1 } else { $dhcp }
            $p = & $pathTo $remote
            $what = if ($wDhcp -eq 'remote' -and $wDns -eq 'remote') { if ($dhcp -eq $dns1) { "DHCP and DNS for this office both come from $dhcp" } else { "DHCP ($dhcp) and DNS ($dns1) for this office both come from servers" } } elseif ($wDns -eq 'remote') { "DNS for this office comes from $dns1" } else { "DHCP for this office comes from $dhcp" }
            if ($p) {
                $ev += "Path to $($p.Target): $($p.Path)"
                if ($null -ne $p.AvgMs) { $ev += "Round trip $($p.AvgMs) ms, loss $($p.LossPct)%, jitter $($p.Jitter) ms" }
                & $add 'DNS and DHCP' 'Confirmed' "$what, which is not on site: it is $($p.HopCount) hops away over a private path. If that path or the far end is down, PCs here cannot get an address or resolve names, so even local internet stops working." $ev
            } else {
                & $add 'DNS and DHCP' 'Likely' "$what on another private network (not this LAN, not the gateway). No trace to it was run, so the path is not confirmed, but it is not on site unless another local subnet exists." $ev
            }
        } elseif ($wDhcp -eq 'gateway' -and ($wDns -eq 'gateway' -or $wDns -eq 'public')) {
            & $add 'DNS and DHCP' 'Confirmed' "The gateway hands out addresses$(if ($wDns -eq 'gateway') { ' and answers DNS' } else { "; DNS goes to public resolvers ($($dnsList -join ', '))" }): basic connectivity does not depend on any server." $ev
        } elseif ($wDhcp -eq 'lan' -or $wDns -eq 'lan') {
            & $add 'DNS and DHCP' 'Confirmed' "DHCP and/or DNS come from a server on this LAN ($((@($dhcp, $dns1) | Where-Object { $_ -and (& $where $_) -eq 'lan' } | Select-Object -Unique) -join ', ')): an on-site server, usually a domain controller." $ev
        } elseif ($wDhcp -eq 'none' -and $dns1) {
            & $add 'DNS and DHCP' 'Confirmed' "This adapter has a static address (no DHCP); DNS is $($dnsList -join ', ')." $ev
        }
        $servers = @(@(Get-Prop $cap 'DhcpServers') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'Server')" } | Select-Object -Unique)
        if ($servers.Count -gt 1) { & $add 'DNS and DHCP' 'Confirmed' "More than one DHCP server answered on this network during the capture: $($servers -join ', '). One of them may be unintended." @("Servers seen: $($servers -join ', ')") }
        $tftp = @(@(Get-Prop $cap 'DhcpServers') | Where-Object { $_ -and ((Get-Prop $_ 'TftpServer') -or (Get-Prop $_ 'TftpAddresses')) }) | Select-Object -First 1
        if ($tftp) { & $add 'Phones' 'Confirmed' "DHCP hands phones a provisioning server: $(Get-Prop $tftp 'TftpServer') $(Get-Prop $tftp 'TftpAddresses')." @("DHCP option 66/150 from $(Get-Prop $tftp 'Server')") }
    }

    # ---- Traffic design, tunnel, internet ----
    $topo = Get-Prop $R 'Topology'
    if (Get-Prop $topo 'Verdict') {
        $c = switch ("$(Get-Prop $topo 'Confidence')") { 'High' { 'Confirmed' } 'Medium-High' { 'Likely' } 'Medium' { 'Likely' } default { 'Possible' } }
        $sig = @(@(Get-Prop $topo 'Signals') | Where-Object { $_ })
        & $add 'Traffic design' $c "Traffic design: $(Get-Prop $topo 'Verdict')." @($sig | Select-Object -First 6)
    }
    $inet = $pings | Where-Object { "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' } | Select-Object -First 1
    $priv = @($pings | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -ne $gw -and $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (Get-IpClass $tp) -eq 'Private' -and (Get-Prop $_ 'Received') })
    $tcps = @(@(Get-Prop $R 'TcpSeries') | Where-Object { $_ })
    if ($priv.Count) {
        $b = $priv | Sort-Object { [double](Get-Prop $_ 'AvgMs') } | Select-Object -First 1
        $worstLoss = ($priv | ForEach-Object { [double](Get-Prop $_ 'LossPct') } | Measure-Object -Maximum).Maximum
        $ev = @($priv | ForEach-Object { "$(Get-Prop $_ 'Target'): avg $(Get-Prop $_ 'AvgMs') ms, p95 $(Get-Prop $_ 'P95Ms') ms, jitter $(Get-Prop $_ 'JitterMs') ms, loss $(Get-Prop $_ 'LossPct')%" })
        if ($inet) { $ev += "Internet (1.1.1.1): avg $(Get-Prop $inet 'AvgMs') ms, jitter $(Get-Prop $inet 'JitterMs') ms, loss $(Get-Prop $inet 'LossPct')%" }
        $pub = $tcps | Where-Object { "$(Get-Prop $_ 'Address')" -and (Get-IpClass "$(Get-Prop $_ 'Address')") -eq 'Public' } | Select-Object -First 1
        $t = "Servers and desktops across the private tunnel answer in $(Get-Prop $b 'AvgMs') ms with $worstLoss% loss and $(Get-Prop $b 'JitterMs') ms jitter over $(Get-Prop $b 'Sent') samples."
        if ($pub) { $ev += "$(Get-Prop $pub 'Target') tcp/$(Get-Prop $pub 'Port') over the public internet: avg $(Get-Prop $pub 'AvgMs') ms, p95 $(Get-Prop $pub 'P95Ms') ms"; if ([double](Get-Prop $pub 'AvgMs') -gt 1.3 * [double](Get-Prop $b 'AvgMs')) { $t += " The public route to the provider ($(Get-Prop $pub 'AvgMs') ms average, $(Get-Prop $pub 'P95Ms') ms at the 95th percentile) is slower and less steady than the tunnel." } }
        & $add 'Tunnel' 'Confirmed' $t $ev
    }
    $mtu = @(@(Get-Prop $R 'Mtu') | Where-Object { $_ })
    $mtuPriv = $mtu | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (Get-IpClass $tp) -eq 'Private' } | Select-Object -First 1
    $mtuInet = $mtu | Where-Object { "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' } | Select-Object -First 1
    if ($mtuPriv -and (Get-Prop $mtuPriv 'MtuBytes')) {
        $mb = [int](Get-Prop $mtuPriv 'MtuBytes')
        if ($mb -lt 1500) { & $add 'Tunnel' 'Confirmed' "The largest packet that crosses the tunnel unfragmented is $mb bytes ($(1500 - $mb) bytes of tunnel overhead); the internet path carries $(Get-Prop $mtuInet 'MtuBytes')." @("Probe target $(Get-Prop $mtuPriv 'Target')") }
        else { & $add 'Tunnel' 'Confirmed' 'Full 1500-byte packets cross the tunnel path unfragmented (no visible tunnel overhead to this target).' @("Probe target $(Get-Prop $mtuPriv 'Target')") }
    } elseif ($mtuPriv) { & $add 'Tunnel' 'Possible' 'The tunnel packet size limit could not be measured (the far end does not answer large pings).' @("Probe target $(Get-Prop $mtuPriv 'Target'): $(Get-Prop $mtuPriv 'Note')") }

    $pubIp = "$(Get-Prop $eg 'PublicIPv4')"
    if ($pubIp) {
        $own = Get-Prop $eg 'Owner'
        $carrierTxt = @("$(Get-Prop $eg 'Carrier')", "$(Get-Prop $eg 'EgressCity')" | Where-Object { $_ -and $_ -ne ', ' })
        $t = "Internet leaves this office from $pubIp$(if ($carrierTxt.Count -eq 2) { " on $($carrierTxt[0]) ($($carrierTxt[1]))" } elseif ($carrierTxt.Count) { " ($($carrierTxt[0]))" })."
        $ev = @(); if (Get-Prop $eg 'IpInfo', 'Hostname') { $ev += "Reverse name: $(Get-Prop $eg 'IpInfo', 'Hostname')" }
        if (Get-Prop $own 'RegisteredTo') {
            $t += " The address block $(Get-Prop $own 'Range') is registered to $(Get-Prop $own 'RegisteredTo')"
            if (Get-Prop $own 'Address') { $t += " at $(Get-Prop $own 'Address')" }
            if (Get-Prop $own 'Registered') { $t += " since $(Get-Prop $own 'Registered')" }
            $t += '.'
            if ("$(Get-Prop $own 'RegisteredTo')" -match $ProviderAsn) { $t += ' That is the hosted desktop provider, not the client, so the provider is probably the account holder for this circuit.' }
            $ev += "Whois block $(Get-Prop $own 'Block') ($(Get-Prop $own 'Type')); chain: $(@(Get-Prop $own 'Chain') -join ' > ')"
        }
        & $add 'Internet service' 'Confirmed' $t $ev
        $t1 = $traces | Where-Object { "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' } | Select-Object -First 1
        $an = Get-Prop $t1 'Analysis'
        if ($an) {
            if ((Get-Prop $an 'CgnatHops') -gt 0) { & $add 'Internet service' 'Confirmed' 'The carrier puts this circuit behind carrier-grade NAT: there is no public address of its own, so inbound connections and some VPNs will not work.' @("Trace: $((@(Get-Prop $t1 'Hops') | Select-Object -First 5 | ForEach-Object { "$(Get-Prop $_ 'IP') [$(Get-Prop $_ 'Class')]" }) -join ' > ')") }
            elseif (Get-Prop $an 'DoubleNatLikely') { & $add 'Internet service' 'Likely' "There are two layers of NAT (for example an ISP modem in router mode in front of the firewall): $((@(Get-Prop $an 'PrivateHopsAfterGw')) -join ', ')." @() }
            elseif (-not (Get-Prop $an 'TunnelIndicator')) { & $add 'Internet service' 'Confirmed' 'One NAT at the gateway, then straight onto the carrier: no carrier NAT, no second router in the path.' @("First public hop: $(Get-Prop $an 'FirstPublicIP') at $(Get-Prop $an 'FirstPublicMs') ms ($(Get-Prop $an 'FirstPublicPtr'))") }
        }
        # Access type from the latency step into the carrier: an inference, kept at Possible.
        $steps = @()
        foreach ($t in @($traces | Where-Object { @('1.1.1.1', '8.8.8.8') -contains "$(Get-Prop $_ 'Target')" })) {
            $pubHops = @(@(Get-Prop $t 'Hops') | Where-Object { $_ -and "$(Get-Prop $_ 'Class')" -eq 'Public' -and $null -ne (Get-Prop $_ 'AvgMs') } | Select-Object -First 2)
            if ($pubHops.Count -eq 2) { $steps += [double](Get-Prop $pubHops[1] 'AvgMs') }
        }
        if ($steps.Count) {
            $s2 = ($steps | Measure-Object -Minimum).Minimum
            $acc = Get-AccessType "$(Get-Prop $eg 'Carrier')"
            # When the carrier's name already says satellite or cellular, the hop timing guess adds nothing
            if ($acc -and $acc -notlike 'cable') { }
            elseif ($s2 -ge 8) { & $add 'Internet service' 'Possible' "The second carrier hop is $s2 ms away. That latency step is typical of cable (DOCSIS) or fixed wireless access; fiber usually shows 1 to 4 ms there." @("Second public hop latency per trace: $($steps -join ', ') ms") }
            elseif ($s2 -le 4) { & $add 'Internet service' 'Possible' "The second carrier hop is only $s2 ms away, which is typical of a fiber hand-off." @("Second public hop latency per trace: $($steps -join ', ') ms") }
        }
    }
    $accessType = Get-AccessType "$(Get-Prop $eg 'Carrier')"
    if ($accessType) { & $add 'Internet service' 'Likely' "The circuit is $accessType, going by the carrier's network name ($(Get-Prop $eg 'Carrier'))." @() }
    $re = Get-Prop $R 'DnsDiscovery', 'ResolverEgress'
    if ($re -and (Get-Prop $re 'Ip') -and $pubIp -and "$(Get-Prop $re 'Ip')" -ne $pubIp) {
        # Where name lookups leave depends on which DNS servers the PC uses. Public resolvers always look
        # up names from their own servers; only a private DNS server exiting elsewhere means a tunnel.
        $dnsSrv = @(@(Get-Prop $R 'NetworkExtra', 'DnsServers') | ForEach-Object { "$(Get-Prop $_ 'Server')" } | Where-Object { Test-IPv4 $_ })
        $allPublic = $dnsSrv.Count -and -not @($dnsSrv | Where-Object { (Get-IpClass $_) -ne 'Public' }).Count
        if ($allPublic) {
            & $add 'DNS and DHCP' 'Confirmed' "Name lookups go straight to public resolvers ($($dnsSrv -join ', ')), so they reach the internet from the resolver's own servers ($(Get-Prop $re 'Ip'), $(Get-Prop $re 'Org')), not from this office. That is normal for public DNS." @("whoami.akamai.net answered $(Get-Prop $re 'Ip')")
        } else {
            & $add 'DNS and DHCP' 'Confirmed' "Name lookups reach the internet from $(Get-Prop $re 'Ip') ($(Get-Prop $re 'Org'), $(Get-Prop $re 'City')), not from this office's own address ($pubIp): the site's DNS server forwards them from somewhere else (the far end of a tunnel, or a filtering service), so content networks may place these users there." @("whoami.akamai.net answered $(Get-Prop $re 'Ip')", "DNS servers: $($dnsSrv -join ', ')")
        }
    }

    # ---- Gateway ----
    $idDevs = @(@(Get-Prop $R 'Identify', 'Devices') | Where-Object { $_ })
    $gwId = $idDevs | Where-Object { "$(Get-Prop $_ 'IP')" -eq $gw } | Select-Object -First 1
    $gwVendor = "$(Get-Prop $R 'NetworkExtra', 'GatewayVendor')"
    $gwModel = Get-Prop $R 'GatewayModel'
    $fwPorts = @(@(Get-Prop $R 'FirewallPorts', 'Ports') | Where-Object { $_ -and (Get-Prop $_ 'Open') } | ForEach-Object { Get-Prop $_ 'Port' })
    $webOpen = @(@(Get-Prop $R 'GatewayProbe') | Where-Object { $_ -and (Get-Prop $_ 'Status') } | ForEach-Object { "$(Get-Prop $_ 'Url')" })
    if ($gw) {
        $name = $null; $c = 'Possible'; $ev = @("MAC maker: $gwVendor ($(Get-Prop $R 'NetworkExtra', 'GatewayMac'))")
        if ($gwId -and (Get-Prop $gwId 'Model')) { $name = "$(Get-Prop $gwId 'Vendor') $(Get-Prop $gwId 'Model')"; if (Get-Prop $gwId 'Firmware') { $name += ", firmware $(Get-Prop $gwId 'Firmware')" }; $c = "$(Get-Prop $gwId 'Confidence')"; $ev += @(Get-Prop $gwId 'Evidence') }
        elseif (Get-Prop $gwModel 'Vendor') { $name = "$(Get-Prop $gwModel 'Vendor') $(Get-Prop $gwModel 'Model')".Trim(); $c = 'Likely'; $ev += "$(Get-Prop $gwModel 'Source')" }
        elseif ($gwId -and (Get-Prop $gwId 'Vendor')) { $name = "$(Get-Prop $gwId 'Vendor') ($(Get-Prop $gwId 'Kind'))"; $c = 'Likely'; $ev += @(Get-Prop $gwId 'Evidence') }
        elseif ($gwVendor -and $gwVendor -ne 'Unknown') { $name = "made by $gwVendor (model not readable)" }
        if ($name) {
            $t = "The gateway ($gw) is $name."
            if ($webOpen.Count -or $fwPorts.Count) { $t += " Its admin interface answers from the user network ($((@($webOpen) + @($fwPorts | ForEach-Object { "tcp/$_" })) -join ', '))." }
            & $add 'Gateway' $c $t $ev
        }
    }

    # ---- Equipment that named itself ----
    $vd = @(@(Get-Prop $R 'VendorDiscovery', 'Devices') | Where-Object { $_ })
    if ($vd.Count) {
        $groups = @($vd | Group-Object { ('{0} {1}' -f ("$(Get-Prop $_ 'Protocol')" -replace ' discovery$', ''), $(if (Get-Prop $_ 'ModelFull') { Get-Prop $_ 'ModelFull' } else { Get-Prop $_ 'Model' })).Trim() } | Sort-Object Count -Descending)
        & $add 'Network equipment' 'Confirmed' "$($vd.Count) network devices named themselves: $(($groups | ForEach-Object { "$($_.Count) x $($_.Name)" }) -join ', ')." @($vd | Select-Object -First 12 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name') $(Get-Prop $_ 'Model') firmware $(Get-Prop $_ 'Firmware')" })
    } elseif ($null -ne (Get-Prop $R 'VendorDiscovery')) {
        $ubnt = @(@(Get-Prop $R 'SubnetSweep', 'Devices') | Where-Object { $_ -and "$(Get-Prop $_ 'Vendor')" -match 'Ubiquiti|MikroTik|Routerboard|NETGEAR' }).Count
        if ($ubnt) { & $add 'Network equipment' 'Possible' "$ubnt devices from Ubiquiti, MikroTik or Netgear are on the network but none answered its vendor discovery protocol: discovery is turned off on them, or this PC's firewall dropped the answers. Models have to come from the closet walk." @() }
    }

    # ---- Network layout ----
    $sweep = Get-Prop $R 'SubnetSweep'
    $kinds = @{}
    if ($idDevs.Count) { foreach ($d in $idDevs) { $k = "$(Get-Prop $d 'Kind')"; if (-not $k) { $k = 'Unidentified' }; $kinds[$k] = 1 + [int]$kinds[$k] } }
    else { foreach ($d in @(@(Get-Prop $sweep 'Devices') | Where-Object { $_ })) { $k = "$(Get-Prop $d 'Role')"; if (-not $k) { $k = 'Unidentified' }; $kinds[$k] = 1 + [int]$kinds[$k] } }
    $total = ($kinds.Values | Measure-Object -Sum).Sum
    if ($total) {
        $mix = @($kinds.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Value) $($_.Key)" })
        $groupsPresent = @()
        foreach ($g in @(@('phones', 'phone'), @('cameras', 'camera|recorder'), @('printers', 'printer|copier'), @('computers', 'Windows|thin client|computer'), @('door access', 'door access'), @('payment terminals', 'payment'), @('time clocks', 'time clock'))) { if (@($kinds.Keys | Where-Object { $_ -match $g[1] }).Count) { $groupsPresent += $g[0] } }
        $subnet = "$(Get-Prop $sweep 'Subnet')"; $swept = Get-Prop $sweep 'AddressesSwept'
        $ev = @("Devices by kind: $($mix -join ', ')", "No VLAN tag was seen on this port: $(-not (@(Get-Prop $cap 'VlanTagsSeen') | Where-Object { $_ }))")
        if ($groupsPresent.Count -ge 3) { & $add 'Network layout' 'Confirmed' "One flat network: $($groupsPresent -join ', ') all sit in $subnet together, reachable from this user port with nothing separating them." $ev }
        if ($groupsPresent -contains 'payment terminals') { & $add 'Network layout' 'Confirmed' 'A card payment terminal shares the network with every other device: a card-data compliance concern.' @($ev[0]) }
        if ($swept -and ($total / [double]$swept) -ge 0.6) { & $add 'Network layout' 'Confirmed' "The address range is $([int](100 * $total / [double]$swept))% used ($total of $swept addresses live): little room to grow in one DHCP scope." @("Subnet $subnet") }
    }
    $arpSubs = @(@(Get-Prop $cap 'ArpSubnets') | Where-Object { $_ -and $srcIp -and "$(Get-Prop $_ 'Subnet')" -ne ((& $pre $srcIp) + '.0/24') })
    if ($foreign.Count -or $arpSubs.Count) {
        $ev = @()
        if ($foreign.Count) { $ev += "Devices on this wire announcing addresses outside $srcIp/$mask`: $((@($foreign) | Select-Object -First 8) -join '; ')" }
        foreach ($a in $arpSubs) { $ev += "ARP heard from $(Get-Prop $a 'Subnet'): $(Get-Prop $a 'Hosts') hosts, e.g. $(Get-Prop $a 'Sample')" }
        $nets = @(@($foreign | ForEach-Object { (& $pre (($_ -split ' ')[0])) + '.0/24' }) + @($arpSubs | ForEach-Object { "$(Get-Prop $_ 'Subnet')" }) | Select-Object -Unique)
        & $add 'Network layout' 'Confirmed' "More than one IP range shares this wire: devices in $($nets -join ', ') were heard on a port that sits in $((& $pre $srcIp) + '.0/24'). They are separated by addressing only, not by a VLAN." $ev
    }
    $tags = @(@(Get-Prop $cap 'VlanTagsSeen') | Where-Object { $_ })
    if ($tags.Count) { & $add 'Network layout' 'Confirmed' "Tagged frames for VLAN $($tags -join ', ') reached this port: it is a trunk or hybrid port, and those VLANs exist on the switch." @() }
    if ($voiceVlan) {
        $phoneCount = @($kinds.Keys | Where-Object { $_ -match 'phone' } | ForEach-Object { $kinds[$_] } | Measure-Object -Sum).Sum
        $t = "The switch advertises voice VLAN $voiceVlan to phones."
        if ($phoneCount) { $t += " Yet $phoneCount phones answer in the data subnet, so they are not using it." }
        & $add 'Phones' 'Confirmed' $t @()
    }
    if ($haveCap) {
        $bps = Get-Prop $cap 'BroadcastPerSecond'
        if ($null -ne $bps) {
            $lvl = if ([double]$bps -ge 100) { 'heavy' } elseif ([double]$bps -ge 30) { 'busy' } else { 'ordinary' }
            & $add 'Network layout' 'Likely' "Broadcast traffic on this network is $lvl`: about $bps frames per second reach every port." @("Captured $(Get-Prop $cap 'BroadcastFrames') broadcast frames in $capSecs s (approximate)", "Busiest senders: $((@(Get-Prop $cap 'TopBroadcasters') | Where-Object { $_ } | Select-Object -First 4 | ForEach-Object { "$(Get-Prop $_ 'Mac') $(Get-Prop $_ 'Vendor') ($(Get-Prop $_ 'Frames'))" }) -join '; ')")
        }
        $ra = @(@(Get-Prop $cap 'Ipv6RouterAdvertisers') | Where-Object { $_ })
        if ($ra.Count) { & $add 'Network layout' 'Confirmed' "IPv6 router advertisements are being sent on this network by $(($ra | ForEach-Object { "$(Get-Prop $_ 'Mac') $(Get-Prop $_ 'Vendor')" }) -join ', '). If that is not the gateway, something else is offering itself as a router." @() }
    }

    # ---- Phones and Windows machines ----
    $ph = @($idDevs | Where-Object { "$(Get-Prop $_ 'Kind')" -match 'phone' })
    if ($ph.Count) {
        $models = @($ph | Where-Object { Get-Prop $_ 'Model' } | Group-Object { "$(Get-Prop $_ 'Vendor') $(Get-Prop $_ 'Model')" } | Sort-Object Count -Descending | ForEach-Object { "$($_.Count) x $($_.Name)" })
        $slow = @($ph | Where-Object { "$(Get-Prop $_ 'PassThrough')" -eq '10/100' }).Count; $fast = @($ph | Where-Object { "$(Get-Prop $_ 'PassThrough')" -eq 'Gigabit' }).Count
        if ($models.Count) { & $add 'Phones' 'Confirmed' "$($ph.Count) desk phones; models read from the phones themselves: $($models -join ', ')." @() }
        if ($slow) { & $add 'Phones' 'Likely' "$slow of $($ph.Count) phones are models whose PC pass-through port is 10/100 only ($fast are gigabit). Any PC plugged in behind one of those links at 100 Mbps regardless of the switch." @('From the model numbers reported by the phones') }
        elseif ($fast -and $link -and [double]$link -lt 1000 -and $wired) { & $add 'Phones' 'Likely' "The phones that reported a model have gigabit pass-through ports, so a phone is not the reason for the $link Mbps link here: look at the cable or the switch port." @() }
    }
    $smb1 = @($idDevs | Where-Object { Get-Prop $_ 'Smb', 'Smb1Enabled' })
    if ($smb1.Count) { & $add 'Windows machines' 'Confirmed' "The old SMB1 file-sharing protocol is still enabled on $($smb1.Count) machines: $((@($smb1) | Select-Object -First 8 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name')" }) -join ', ')." @() }
    $smbAll = @($idDevs | Where-Object { Get-Prop $_ 'Smb', 'Smb2Dialect' })
    if ($smbAll.Count) {
        $unsigned = @($smbAll | Where-Object { -not (Get-Prop $_ 'Smb', 'SigningRequired') }).Count
        & $add 'Windows machines' 'Confirmed' "$($smbAll.Count) machines answer Windows file sharing; $unsigned of them do not require signed connections." @("Dialects: $((@($smbAll | Group-Object { "$(Get-Prop $_ 'Smb', 'Smb2Dialect')" } | ForEach-Object { "SMB $($_.Name) x $($_.Count)" })) -join ', ')")
    }

    # ---- Other offices and the directory ----
    $sr = @(@(Get-Prop $R 'SiteReach', 'Targets') | Where-Object { $_ })
    $reach = @($sr | Where-Object { (Get-Prop $_ 'PingReplies') -gt 0 -or "$(Get-Prop $_ 'LastHopIp')" -eq "$(Get-Prop $_ 'Target')" })
    if ($sr.Count) {
        if ($reach.Count) {
            $tunnelHops = @($traces | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (Get-IpClass $tp) -eq 'Private' } | ForEach-Object { @(Get-Prop $_ 'Hops') | Where-Object { $_ -and (Get-Prop $_ 'IP') } | Select-Object -First 1 } | ForEach-Object { "$(Get-Prop $_ 'IP')" } | Select-Object -Unique)
            $via = @($reach | Where-Object { $h = @(@(Get-Prop $_ 'Hops') | Where-Object { $_ -and (Get-Prop $_ 'IP') } | ForEach-Object { "$(Get-Prop $_ 'IP')" }); @($h | Where-Object { $tunnelHops -contains $_ }).Count -gt 0 })
            $t = "Other office networks answer from here: $(($reach | ForEach-Object { "$(Get-Prop $_ 'Target') ($(Get-Prop $_ 'AvgMs') ms)" }) -join ', ')."
            if ($via.Count -and $tunnelHops.Count) { $t += " The path to them goes through the same tunnel hop as the hosted desktop or data center ($($tunnelHops -join ', ')): offices talk to each other through the provider, not directly." }
            & $add 'Other offices' 'Confirmed' $t @($sr | ForEach-Object { "$(Get-Prop $_ 'Target'): $(Get-Prop $_ 'PingReplies')/3 pings, path $(Get-Prop $_ 'Path')" })
        } else {
            & $add 'Other offices' 'Likely' 'None of the other office gateways tried answered from here: either the addressing guess is wrong for them, or offices cannot reach each other.' @($sr | ForEach-Object { "$(Get-Prop $_ 'Target'): path $(Get-Prop $_ 'Path')" })
        }
    }
    $ss = @(@(Get-Prop $R 'DnsDiscovery', 'SubnetSummary') | Where-Object { $_ -and (Get-Prop $_ 'Names') -gt 0 })
    if ($ss.Count) { & $add 'Other offices' 'Confirmed' "The site DNS server holds reverse names for these networks: $(($ss | ForEach-Object { "$(Get-Prop $_ 'Subnet') ($(Get-Prop $_ 'Names') names)" }) -join ', '). The names are in the saved data and identify devices at offices not visited." @() }
    $rd = Get-Prop $R 'DnsDiscovery', 'RootDse'
    if ($rd -and (Get-Prop $rd 'DnsHostName')) {
        & $add 'Directory' 'Confirmed' "The DNS server is domain controller $(Get-Prop $rd 'DnsHostName') for $(Get-Prop $rd 'DefaultNamingContext'), domain functional level $(Get-Prop $rd 'DomainLevel'), forest $(Get-Prop $rd 'ForestLevel')." @("Server object: $(Get-Prop $rd 'ServerName')", "Domain controllers in DNS: $((@(Get-Prop $R 'DnsDiscovery', 'DomainControllers') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'Target')" } | Select-Object -Unique) -join ', ')")
    }

    # ================= v1.7.0 evidence =================
    # ---- ISP modem page ----
    foreach ($m in @(@(Get-Prop $R 'IspModem', 'Targets') | Where-Object { $_ -and (Get-Prop $_ 'LooksLike') })) {
        $pg = @(@(Get-Prop $m 'Pages') | Where-Object { $_ }) | Select-Object -First 1
        $c = if ("$(Get-Prop $m 'LooksLike')" -like 'ISP device*') { 'Possible' } else { 'Confirmed' }
        & $add 'Internet service' $c "A device answers at $(Get-Prop $m 'Address') ($(Get-Prop $m 'Role')): $(Get-Prop $m 'LooksLike')." @("Page title: $(Get-Prop $pg 'Title')", "Server: $(Get-Prop $pg 'Server')", "Page text: $(Get-Prop $pg 'BodySample')")
    }
    # ---- No access control on the port ----
    if ($wired -and $srcIp -and (Get-Prop $ad 'DhcpEnabled') -and $haveCap -and -not (Get-Prop $cap 'EapolFrames')) {
        & $add 'Network layout' 'Confirmed' "No network access control on this port: a laptop the network had never seen was given an address ($srcIp) and full reach with no authentication." @('No 802.1X (EAPOL) frame was seen on the port', "Devices reachable from it: $total")
    }
    foreach ($dup in @(@(Get-Prop $cap 'ArpConflicts') | Where-Object { $_ })) { & $add 'Network layout' 'Confirmed' "Address conflict: $(Get-Prop $dup 'IP') is being claimed by two devices ($(Get-Prop $dup 'Macs'))." @() }

    # ---- SNMP ----
    $snmp = Get-Prop $R 'Snmp'
    $sd = @(@(Get-Prop $snmp 'Devices') | Where-Object { $_ })
    if ($snmp -and $sd.Count) {
        & $add 'Network equipment' 'Confirmed' "$($sd.Count) devices answer SNMP with the default community '$(Get-Prop $snmp 'Community')': anyone on this network can read their configuration details. $((@($sd | Select-Object -First 10 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'SysName')" })) -join ', ')." @($sd | Select-Object -First 8 | ForEach-Object { "$(Get-Prop $_ 'IP'): $(Get-Prop $_ 'SysDescr')" })
        $macKind = @{}
        foreach ($d in $idDevs) { $macKind["$(Get-Prop $d 'Mac')"] = "$(Get-Prop $d 'Kind')" }
        $myMacs = @(@(Get-Prop $net 'Adapters') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'MacAddress')" } | Where-Object { $_ })
        foreach ($s in @($sd | Where-Object { @(Get-Prop $_ 'Ports').Count -ge 5 })) {
            $ports = @(@(Get-Prop $s 'Ports') | Where-Object { $_ }); $upPorts = @($ports | Where-Object { Get-Prop $_ 'Up' })
            $slow = @($upPorts | Where-Object { $sp = Get-Prop $_ 'SpeedMbps'; $null -ne $sp -and [double]$sp -gt 0 -and [double]$sp -lt 1000 })
            $label = (@("$(Get-Prop $s 'SysName')", "$(Get-Prop $s 'Model')") | Where-Object { $_ }) -join ', '; if (-not $label) { $label = "$(Get-Prop $s 'IP')" }
            $ev = @("$(Get-Prop $s 'IP'): $(Get-Prop $s 'SysDescr')", "Up for $(Get-Prop $s 'UptimeDays') days; serial $(Get-Prop $s 'Serial'); software $(Get-Prop $s 'Software')")
            if ($null -ne (Get-Prop $s 'PoeWattsUsed')) { $ev += "PoE: $(Get-Prop $s 'PoeWattsUsed') W in use of $(Get-Prop $s 'PoeWattsBudget') W" }
            $t = "Switch $label`: $(Get-Prop $s 'PortSummary')."
            if ($slow.Count) { $t += " $($slow.Count) of its live ports run below 1 Gbps: $((@($slow | Select-Object -First 16 | ForEach-Object { "$(Get-Prop $_ 'Name') ($(Get-Prop $_ 'SpeedMbps'))" })) -join ', ')." }
            & $add 'Switching' 'Confirmed' $t $ev
            $mt = @(@(Get-Prop $s 'MacTable') | Where-Object { $_ })
            if ($mt.Count) {
                $mine = $mt | Where-Object { $myMacs -contains "$(Get-Prop $_ 'Mac')" } | Select-Object -First 1
                if ($mine) {
                    $onPort = @($mt | Where-Object { "$(Get-Prop $_ 'Port')" -eq "$(Get-Prop $mine 'Port')" })
                    $pinfo = $ports | Where-Object { "$(Get-Prop $_ 'Name')" -eq "$(Get-Prop $mine 'Port')" } | Select-Object -First 1
                    if ($onPort.Count -le 3) {
                        $others = @($onPort | Where-Object { $myMacs -notcontains "$(Get-Prop $_ 'Mac')" } | ForEach-Object { $k = $macKind["$(Get-Prop $_ 'Mac')"]; "$(Get-Prop $_ 'Mac')$(if ($k) { " ($k)" })" })
                        $t2 = "This laptop is on $label port $(Get-Prop $mine 'Port'), which the switch reports at $(Get-Prop $pinfo 'SpeedMbps') Mbps."
                        if ($others.Count) { $t2 += " The same port also carries $($others -join ', '): the laptop is plugged in behind that device." }
                        & $add 'Switch port' 'Confirmed' $t2 @("From the switch's own forwarding table ($($mt.Count) addresses)")
                    }
                }
                # Ports that carry a phone and one other device: a PC plugged into the back of a phone.
                $byPort = @($mt | Group-Object { "$(Get-Prop $_ 'Port')" } | Where-Object { $_.Count -ge 2 -and $_.Count -le 3 })
                $behind = @($byPort | Where-Object { @($_.Group | Where-Object { $macKind["$(Get-Prop $_ 'Mac')"] -match 'phone' }).Count -ge 1 })
                if ($behind.Count) {
                    $slowBehind = @($behind | Where-Object { $pn = $_.Name; $pp = $ports | Where-Object { "$(Get-Prop $_ 'Name')" -eq $pn } | Select-Object -First 1; $pp -and $null -ne (Get-Prop $pp 'SpeedMbps') -and [double](Get-Prop $pp 'SpeedMbps') -lt 1000 })
                    & $add 'Phones' 'Confirmed' "On $label, $($behind.Count) ports carry a desk phone plus one more device: PCs or thin clients plugged into the back of a phone. $($slowBehind.Count) of those ports run below 1 Gbps." @("Ports: $((@($behind | Select-Object -First 20 | ForEach-Object { $_.Name })) -join ', ')")
                }
            }
        }
        $pr = @($sd | Where-Object { (Get-Prop $_ 'Printer', 'Serial') -or (Get-Prop $_ 'Printer', 'PageCount') })
        if ($pr.Count) { & $add 'Printers' 'Confirmed' "$($pr.Count) printers gave serial numbers and lifetime page counts over SNMP." @($pr | Select-Object -First 15 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Printer', 'Model'): serial $(Get-Prop $_ 'Printer', 'Serial'), $(Get-Prop $_ 'Printer', 'PageCount') pages" }) }
    } elseif ($snmp -and $null -ne (Get-Prop $snmp 'Asked')) {
        & $add 'Network equipment' 'Confirmed' "No device answered SNMP with the community '$(Get-Prop $snmp 'Community')' ($(Get-Prop $snmp 'Asked') asked): SNMP is off or the community was changed." @()
    }
    # Devices that restarted together (uptime from discovery and SNMP)
    $ups = @(@($vd | ForEach-Object { if (Get-Prop $_ 'UptimeSec') { [pscustomobject]@{ Name = "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name')"; Days = [math]::Round([double](Get-Prop $_ 'UptimeSec') / 86400, 1) } } }) + @($sd | ForEach-Object { if ($null -ne (Get-Prop $_ 'UptimeDays')) { [pscustomobject]@{ Name = "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'SysName')"; Days = [double](Get-Prop $_ 'UptimeDays') } } }) | Where-Object { $_ })
    if ($ups.Count -ge 3) {
        $grp = @($ups | Group-Object { [math]::Round($_.Days) } | Sort-Object Count -Descending | Select-Object -First 1)
        if ($grp.Count -and $grp[0].Count -ge 3 -and [double]$grp[0].Name -lt 60) { & $add 'Network equipment' 'Likely' "$($grp[0].Count) network devices all restarted about $($grp[0].Name) days ago: a power event or maintenance at that time." @($grp[0].Group | Select-Object -First 8 | ForEach-Object { "$($_.Name): up $($_.Days) days" }) }
    }

    # ---- Windows versions ----
    $wh = @(@(Get-Prop $R 'WindowsHosts', 'Hosts') | Where-Object { $_ -and (Get-Prop $_ 'Build') })
    if ($wh.Count) {
        $w10 = @($wh | Where-Object { $b = [int](Get-Prop $_ 'Build'); $b -ge 10240 -and $b -le 19045 }); $old = @($wh | Where-Object { [int](Get-Prop $_ 'Build') -lt 10240 })
        $t = "$($wh.Count) Windows machines on this network reported their version: $((@(Get-Prop $R 'WindowsHosts', 'OsSummary')) -join '; ')."
        if ($w10.Count -or $old.Count) { $t += " $($w10.Count + $old.Count) of them run Windows 10 or older, which is out of support." }
        & $add 'Windows machines' 'Confirmed' $t @($wh | Select-Object -First 20 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'ComputerName') ($(Get-Prop $_ 'DnsDomain')): $(Get-Prop $_ 'OsVersion')" })
    }

    # ---- DNS timing and fallback ----
    $dt = @(@(Get-Prop $R 'DnsTiming', 'Servers') | Where-Object { $_ })
    $site = $dt | Where-Object { "$(Get-Prop $_ 'Role')" -eq 'Site DNS server' -and $null -ne (Get-Prop $_ 'MedianMs') } | Select-Object -First 1
    $pubDns = @($dt | Where-Object { "$(Get-Prop $_ 'Role')" -like 'Public*' })
    $pubOk = $pubDns | Where-Object { (Get-Prop $_ 'Answered') -gt 0 -and $null -ne (Get-Prop $_ 'MedianMs') } | Sort-Object { [double](Get-Prop $_ 'MedianMs') } | Select-Object -First 1
    if ($dt.Count) {
        $ev = @($dt | ForEach-Object { "$(Get-Prop $_ 'Server') ($(Get-Prop $_ 'Role')): answered $(Get-Prop $_ 'Answered') of $(Get-Prop $_ 'Asked'), median $(Get-Prop $_ 'MedianMs') ms" })
        if ($site -and (Get-IpClass "$(Get-Prop $site 'Server')") -eq 'Public') {
            # The site's DNS servers are public resolvers already: no fallback advice to give
            & $add 'DNS and DHCP' 'Confirmed' "DHCP hands out public resolvers as DNS servers; a lookup through $(Get-Prop $site 'Server') takes $(Get-Prop $site 'MedianMs') ms." $ev
        } elseif ($site -and $pubOk) {
            & $add 'DNS and DHCP' 'Confirmed' "A name lookup through the site's DNS server takes $(Get-Prop $site 'MedianMs') ms; the same lookup sent straight to a public resolver takes $(Get-Prop $pubOk 'MedianMs') ms. Public DNS is reachable from this office, so listing a second DNS server in DHCP would keep internet working when the path to $(Get-Prop $site 'Server') is down." $ev
        } elseif ($site -and $pubDns.Count) {
            & $add 'DNS and DHCP' 'Confirmed' "Public DNS resolvers do not answer from this office (outbound DNS is blocked), so the site's DNS server ($(Get-Prop $site 'Server'), $(Get-Prop $site 'MedianMs') ms per lookup) is the only way to resolve names." $ev
        }
        $gwDns = $dt | Where-Object { "$(Get-Prop $_ 'Role')" -eq 'Gateway' -and (Get-Prop $_ 'Answered') -gt 0 } | Select-Object -First 1
        if ($gwDns) { & $add 'DNS and DHCP' 'Confirmed' "The gateway itself answers DNS ($(Get-Prop $gwDns 'MedianMs') ms) although DHCP does not hand it out: it could serve as the local resolver." @() }
    }

    # ---- Cloud services ----
    $cl = Get-Prop $R 'Cloud'
    $m365 = @(@(Get-Prop $cl 'Microsoft365') | Where-Object { $_ -and $null -ne (Get-Prop $_ 'ConnectMs') })
    if ($m365.Count) {
        $worst = ($m365 | ForEach-Object { [double](Get-Prop $_ 'ConnectMs') } | Measure-Object -Maximum).Maximum
        $lvl = if ($worst -le 60) { 'well within' } elseif ($worst -le 120) { 'within' } else { 'outside' }
        & $add 'Cloud services' 'Confirmed' "Microsoft 365 front doors answer in $((@($m365 | ForEach-Object { "$(Get-Prop $_ 'ConnectMs') ms ($("$(Get-Prop $_ 'Host')".Split('.')[0]))" })) -join ', ') from this office, $lvl what Microsoft 365 needs." @("Path to Outlook: $(Get-Prop $cl 'OutlookPath')")
    }
    if ($cl -and $null -ne (Get-Prop $cl 'NatBehaviour')) {
        $t = if (Get-Prop $cl 'TeamsMediaPortOpen') { 'The Teams media relay answers on UDP 3478 from this office.' } else { 'The Teams media relay did not answer on UDP 3478: calls would fall back to TCP, with worse quality.' }
        & $add 'Cloud services' 'Confirmed' "$t NAT behaviour: $(Get-Prop $cl 'NatBehaviour')." @(@(Get-Prop $cl 'Stun') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'Server'): answered $(Get-Prop $_ 'Answered'), public port $(Get-Prop $_ 'MappedPort') for local port $(Get-Prop $_ 'LocalPort'), $(Get-Prop $_ 'Ms') ms" })
    }

    # ---- Voice sample ----
    foreach ($v in @(@(Get-Prop $R 'Voice', 'Samples') | Where-Object { $_ -and (Get-Prop $_ 'Sent') -gt 0 })) {
        $tg = "$(Get-Prop $v 'Target')"
        $what = if ((Get-IpClass $tg) -eq 'Private') { "the phone system path ($tg, across the tunnel)" } else { "the internet path ($tg), which a cloud phone service would use" }
        & $add 'Phones' 'Confirmed' "Call quality over ${what}: estimated score $(Get-Prop $v 'Mos') of 4.4 ($(Get-Prop $v 'Rating')). Loss $(Get-Prop $v 'LossPct')%, jitter $(Get-Prop $v 'JitterMs') ms, longest gap $(Get-Prop $v 'LongestLossBurst') packets." @("$(Get-Prop $v 'Sent') packets at $(Get-Prop $v 'PacketsPerSecond') per second; average $(Get-Prop $v 'AvgMs') ms, 99th percentile $(Get-Prop $v 'P99Ms') ms, worst $(Get-Prop $v 'MaxMs') ms", 'Score is an estimate from ping timing, which is coarser than real call traffic')
    }

    # ---- Printers and cameras that described themselves ----
    $pq = @(@(Get-Prop $R 'PrinterQuery', 'Printers') | Where-Object { $_ -and (Get-Prop $_ 'MakeAndModel') })
    if ($pq.Count) { & $add 'Printers' 'Confirmed' "$($pq.Count) printers described themselves: $((@($pq | Group-Object { "$(Get-Prop $_ 'MakeAndModel')" } | Sort-Object Count -Descending | ForEach-Object { "$($_.Count) x $($_.Name)" })) -join ', ')." @($pq | Select-Object -First 15 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'MakeAndModel'): firmware $(Get-Prop $_ 'Firmware'), pages $(Get-Prop $_ 'PagesPrinted'), state $(Get-Prop $_ 'StateReasons')" }) }
    $cq = @(@(Get-Prop $R 'CameraQuery', 'Cameras') | Where-Object { $_ -and (Get-Prop $_ 'Server') })
    if ($cq.Count) { & $add 'Cameras' 'Confirmed' "$($cq.Count) cameras or recorders named their software over RTSP: $((@(Get-Prop $R 'CameraQuery', 'ServerSummary')) -join '; ')." @($cq | Select-Object -First 12 | ForEach-Object { "$(Get-Prop $_ 'IP'): $(Get-Prop $_ 'Server')" }) }

    # ---- Outbound filtering ----
    $ob = Get-Prop $R 'Outbound'
    if ($ob -and @(Get-Prop $ob 'PortsTried').Count) {
        $blocked = @(@(Get-Prop $ob 'Blocked') | Where-Object { $null -ne $_ }); $open = @(@(Get-Prop $ob 'Open') | Where-Object { $null -ne $_ })
        if (-not (Get-Prop $ob 'Reliable')) { & $add 'Internet service' 'Possible' 'The outbound port test was inconclusive: the public test host did not accept connections, so nothing can be said about outbound filtering from this run.' @("Open: $($open -join ', ')") }
        elseif ($open.Count -and $blocked.Count -le 3) { & $add 'Internet service' 'Confirmed' "The gateway does not filter outbound traffic: $($open.Count) of $($open.Count + $blocked.Count) test ports connect out$(if ($blocked.Count) { " (not $($blocked -join ', '), which carriers commonly block)" })." @("Open: $($open -join ', ')") }
        elseif ($open.Count) { & $add 'Internet service' 'Confirmed' "Outbound traffic is filtered: $($blocked.Count) of $($open.Count + $blocked.Count) test ports are blocked ($($blocked -join ', '))." @("Open: $($open -join ', ')") }
        $dn = @(@(Get-Prop $ob 'DnsTests') | Where-Object { $_ })
        if ($dn.Count) {
            if (Get-Prop $ob 'FilteringSeen') { & $add 'Internet service' 'Confirmed' "A DNS security filter is in place: known test names are blocked ($((@($dn | Where-Object { Get-Prop $_ 'Filtered' } | ForEach-Object { "$(Get-Prop $_ 'Name')" })) -join ', '))." @($dn | ForEach-Object { "$(Get-Prop $_ 'Name'): site answer $(Get-Prop $_ 'SiteAnswer'); public answer $(Get-Prop $_ 'PublicAnswer')" }) }
            else { & $add 'Internet service' 'Likely' 'No DNS security filtering: test names that filters block resolve normally through the site DNS server.' @($dn | ForEach-Object { "$(Get-Prop $_ 'Name'): site answer $(Get-Prop $_ 'SiteAnswer'); public answer $(Get-Prop $_ 'PublicAnswer')" }) }
        }
    }

    # ---- Email domain ----
    foreach ($p in @(@(Get-Prop $R 'Domains', 'Domains') | Where-Object { $_ })) {
        $spf = Get-Prop $p 'Spf'; $dm = Get-Prop $p 'Dmarc'
        $bits = @()
        $bits += $(if (@(Get-Prop $p 'Mx').Count) { "mail goes to $(Get-Prop $p 'Provider') ($((@(Get-Prop $p 'Mx') | Select-Object -First 2) -join ', '))" } else { 'no MX record (it receives no mail)' })
        $bits += $(if (Get-Prop $spf 'Present') { "SPF ends in $(Get-Prop $spf 'All')" } else { 'no SPF' })
        $bits += $(if (Get-Prop $dm 'Present') { "DMARC p=$(Get-Prop $dm 'Policy')$(if (Get-Prop $dm 'Reports') { ' with reports' })" } else { 'no DMARC' })
        $bits += $(if (@(Get-Prop $p 'DkimSelectors').Count) { "DKIM at $((@(Get-Prop $p 'DkimSelectors')) -join ', ')" } else { 'no DKIM at the usual selectors' })
        if (Get-Prop $p 'MtaSts') { $bits += 'MTA-STS on' }
        & $add 'Email and domain' 'Confirmed' "$(Get-Prop $p 'Domain'): $($bits -join '; ')." @(@("SPF: $(Get-Prop $spf 'Record')", "DMARC: $(Get-Prop $dm 'Record')", "Autodiscover: $(@(Get-Prop $p 'Autodiscover') -join ', ')") | Where-Object { $_ -notmatch ': $' })
    }

    # ---- IPv6 ----
    $v6 = Get-Prop $R 'Ipv6'
    $v6s = "$(Get-Prop $v6 'Status')"
    if ($v6s) {
        $pre = @(@(Get-Prop $v6 'GlobalPrefixes') | Where-Object { $_ })
        $ev6 = @($(if ($pre.Count) { "Global prefix(es): $($pre -join ', ')$(if (Get-Prop $v6 'TemporaryAddresses') { ' (privacy addresses in use)' })" }),
                 $(if (Get-Prop $v6 'DefaultRoute') { "IPv6 default route$(if (Get-Prop $v6 'RouterIsLinkLocal') { ' via the router''s link-local address (router advertisements)' })" } else { 'No IPv6 default route' }),
                 $(if (@(Get-Prop $v6 'DnsServers').Count) { "IPv6 DNS servers: $((@(Get-Prop $v6 'DnsServers')) -join ', ')" }),
                 $(if ($null -ne (Get-Prop $v6 'AaaaLookup')) { "IPv6 (AAAA) name lookups: $(if (Get-Prop $v6 'AaaaLookup') { 'answered' } else { 'no answer' })" }))
        if ($v6s -eq 'Working') {
            $ms = Get-Prop $v6 'Ping', 'AvgMs'
            $t = "IPv6 works here: this PC reaches the internet over IPv6$(if ($null -ne $ms) { " in $ms ms (Cloudflare, $(Get-Prop $v6 'Ping', 'LossPct')% loss)" })."
            if (Get-Prop $v6 'Egress', 'SameAsPc') { $t += ' It leaves from its own address, with no NAT: inbound IPv6 is held back only by the firewall''s IPv6 rules, so they need the same care as the IPv4 ones.' }
            $ob = Get-Prop $R 'Outbound'
            if (@(Get-Prop $ob 'DnsTests').Count) { $t += ' The DNS filtering test above ran over IPv4 only.' }
            & $add 'Internet service' 'Confirmed' $t $ev6
        } elseif ($v6s -eq 'Broken') {
            & $add 'Internet service' 'Confirmed' "IPv6 is offered here but does not reach the internet. Apps try IPv6 first and wait for it to fail, which shows up as slow first connections; fix the IPv6 path or stop advertising it." @($ev6 + @("Cloudflare over IPv6: $(if (Get-Prop $v6 'Egress', 'Error') { Get-Prop $v6 'Egress', 'Error' } else { 'no answer' })"))
        } elseif ($v6s -eq 'Local only') {
            & $add 'Internet service' 'Confirmed' 'Only unique-local IPv6 addresses are in use here (no global prefix and no IPv6 route out): IPv6 works inside the network only.' $ev6
        } else {
            & $add 'Internet service' 'Confirmed' 'IPv6 is not offered on this network: everything runs over IPv4.' $ev6
        }
    }

    # ---- Gateway port mapping ----
    $gs = Get-Prop $R 'GatewayServices'
    if ($gs) {
        $np = [bool](Get-Prop $gs 'NatPmp', 'Answered'); $up = [bool](Get-Prop $gs 'Upnp', 'Found')
        $maps = @(@(Get-Prop $gs 'Upnp', 'Mappings') | Where-Object { $_ })
        if ($np -or $up) {
            $t = "The gateway lets any device on the network open inbound ports by itself ($((@($(if ($up) { 'UPnP' }), $(if ($np) { 'NAT-PMP' })) | Where-Object { $_ }) -join ' and ') is on)."
            if ($maps.Count) { $t += " $($maps.Count) port mappings exist now." }
            & $add 'Gateway' 'Confirmed' $t @($maps | Select-Object -First 12 | ForEach-Object { "$(Get-Prop $_ 'Protocol') $(Get-Prop $_ 'ExternalPort') to $(Get-Prop $_ 'InternalClient'):$(Get-Prop $_ 'InternalPort') ($(Get-Prop $_ 'Description'))" })
        } else { & $add 'Gateway' 'Confirmed' 'The gateway does not offer UPnP or NAT-PMP port mapping.' @() }
    }

    # ---- Routers and UPS over SNMP ----
    foreach ($sd in @(@(Get-Prop $R 'Snmp', 'Devices') | Where-Object { $_ -and (Get-Prop $_ 'Router') })) {
        $rt = Get-Prop $sd 'Router'
        $nm = "$(Get-Prop $sd 'SysName')"; if (-not $nm) { $nm = "$(Get-Prop $sd 'IP')" }
        $wan = @(@(Get-Prop $rt 'WanAddresses') | Where-Object { $_ })
        $t = "Router $nm answered SNMP: $(@(Get-Prop $rt 'Addresses').Count) addresses of its own, $(@(Get-Prop $rt 'Arp').Count) entries in its ARP table and $(@(Get-Prop $rt 'Routes').Count) routes."
        if ($wan.Count) { $t += " Its WAN side is $($wan -join ', '): that is the circuit it serves, even where no machine was run." }
        $pub = "$(Get-Prop $R 'Egress', 'PublicIPv4')"
        if ($wan.Count -and $pub -and $wan -notcontains $pub) { $t += " Traffic from this PC leaves from $pub instead, so another device (an ISP modem doing NAT, or another firewall) is in the path or this router is not this office's exit." }
        $privNets = @(@(Get-Prop $rt 'Addresses') | Where-Object { $_ -and (Get-Prop $_ 'Class') -eq 'Private' } | ForEach-Object { '{0}/{1}' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'Prefix') })
        & $add 'Network equipment' 'Confirmed' $t @(@("Interfaces with addresses: $($privNets -join ', ')"), $(if (Get-Prop $rt 'DefaultRoute') { "Default route via $(@(Get-Prop $rt 'DefaultRoute') -join ', ')" }), "System: $(Get-Prop $sd 'SysDescr')")
    }
    foreach ($sd in @(@(Get-Prop $R 'Snmp', 'Devices') | Where-Object { $_ -and (Get-Prop $_ 'Ups') })) {
        $u = Get-Prop $sd 'Ups'
        $bits = @("battery $(Get-Prop $u 'Battery')")
        if ($null -ne (Get-Prop $u 'ChargePct')) { $bits += "$(Get-Prop $u 'ChargePct')% charged" }
        if ($null -ne (Get-Prop $u 'MinutesRemaining')) { $bits += "$(Get-Prop $u 'MinutesRemaining') minutes of runtime" }
        if ($null -ne (Get-Prop $u 'LoadPct')) { $bits += "$(Get-Prop $u 'LoadPct')% load" }
        if (Get-Prop $u 'OnBattery') { $bits += 'RUNNING ON BATTERY' }
        if (Get-Prop $u 'ReplaceBattery') { $bits += 'battery needs replacing' }
        & $add 'Network equipment' 'Confirmed' "UPS $((("$(Get-Prop $u 'Manufacturer') $(Get-Prop $u 'Model')").Trim())) at $(Get-Prop $sd 'IP'): $($bits -join ', ')." @("Read over SNMP ($(Get-Prop $u 'Source'))")
    }

    # ---- Active Directory sites ----
    $sites = @(@(Get-Prop $R 'AdSites', 'Sites') | Where-Object { $_ })
    if ($sites.Count) {
        $t = "Active Directory lists $($sites.Count) site(s) in $(Get-Prop $R 'AdSites', 'Forest'): $((@($sites | Select-Object -First 8 | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'Name'), $(if (@(Get-Prop $_ 'Subnets').Count) { (@(Get-Prop $_ 'Subnets') | Select-Object -First 4) -join ', ' } else { 'no subnets' }) })) -join '; ')."
        if (Get-Prop $R 'AdSites', 'CurrentSite') { $t += " This PC belongs to site $(Get-Prop $R 'AdSites', 'CurrentSite')." }
        $empty = @($sites | Where-Object { -not @(Get-Prop $_ 'Subnets').Count })
        if ($empty.Count) { $t += " $($empty.Count) site(s) have no subnets, so their machines log on to whichever domain controller answers first." }
        $ac = Get-AdSiteCheck $R
        $ev = @('Read from Active Directory Sites and Services as the signed-in user')
        if ($ac) {
            $ev += $(if ($ac.AdSubnet) { "This PC's address $($ac.Ip) is in AD subnet $($ac.AdSubnet) (site $($ac.SiteBySubnet))" } else { "This PC's address $($ac.Ip) is in no AD subnet" })
            if ($ac.LogonServer) { $ev += "Logon server: $($ac.LogonServer)$(if ($ac.LogonServerSite) { " in site $($ac.LogonServerSite)" })" }
        }
        & $add 'Network layout' 'Confirmed' $t $ev
    }

    # ---- Follow-up checks on leads ----
    foreach ($c in @(@(Get-Prop $R 'LeadChecks', 'Checks') | Where-Object { $_ })) {
        $area = switch ("$(Get-Prop $c 'Kind')") { 'Firewall' { 'Gateway' } 'Modem' { 'Internet service' } default { 'Network equipment' } }
        & $add $area 'Confirmed' "$(Get-Prop $c 'What') at $(Get-Prop $c 'IP'): $(Get-Prop $c 'Detail')." @("Checked $(Get-Prop $c 'Url')")
    }

    # ---- Remote desktop transport ----
    $rt = Get-RdpTransportCheck $R
    if ($rt -and $rt.Verdict -ne 'Not known' -and @(Get-Prop $R 'Rdp', 'SelectedTargets').Count) {
        $t = switch -Wildcard ($rt.Verdict) {
            'UDP in use' { 'Remote desktop sessions on this PC have been using UDP, the faster transport.' }
            'UDP possible' { 'Remote desktop sessions here can use UDP: it gets out, and the NAT keeps one public port per connection.' }
            'TCP only: UDP turned off*' { 'Remote desktop sessions on this PC can only use TCP: UDP is turned off for the RDP client.' }
            'TCP only: outbound UDP blocked' { 'Remote desktop sessions here can only use TCP: outbound UDP is blocked, so they stall more on packet loss.' }
            'Relayed UDP only*' { 'The NAT here gives each destination its own public port (symmetric NAT), so Azure Virtual Desktop can only use UDP through its TURN relay.' }
            default { "Remote desktop UDP may fail here: $($rt.Verdict)." }
        }
        if (@($rt.Caveats).Count) { $t += " Microsoft lists these as getting in the way of a direct UDP path: $(@($rt.Caveats) -join '; ')." }
        & $add 'Remote desktop' $(if ($rt.Verdict -in @('UDP in use', 'TCP only: outbound UDP blocked') -or $rt.Verdict -like 'TCP only*') { 'Confirmed' } else { 'Likely' }) $t @($rt.Evidence)
    }

    # ---- Other subnets ----
    $rsSubs = @(@(Get-Prop $R 'RemoteSweep', 'Subnets') | Where-Object { $_ })
    if ($rsSubs.Count) {
        $rsDev = @(@(Get-Prop $R 'RemoteSweep', 'Devices') | Where-Object { $_ })
        $t = "Across routing, $($rsDev.Count) devices answered on $($rsSubs.Count) other subnet(s): $((@($rsSubs | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'Subnet'), (Get-Prop $_ 'Devices') })) -join ', ')."
        $roles = @(Get-Prop $R 'RemoteSweep', 'RoleSummary' | Where-Object { $_ })
        if ($roles.Count) { $t += " By open ports: $(($roles | Select-Object -First 5) -join '; ')." }
        & $add 'Network layout' 'Confirmed' $t @($rsSubs | ForEach-Object { "$(Get-Prop $_ 'Subnet'): $(Get-Prop $_ 'PingResponders') answered ping, $(Get-Prop $_ 'TcpOnly') only on TCP, $(Get-Prop $_ 'Seconds') s ($(Get-Prop $_ 'Reason'))" })
    }
    $swept = @($rsSubs | ForEach-Object { "$(Get-Prop $_ 'Subnet')" })
    $notSwept = @(@(Get-Prop $R 'RemoteSubnets', 'Candidates') | Where-Object { $_ -and $swept -notcontains "$(Get-Prop $_ 'Cidr')" })
    if ($notSwept.Count) {
        & $add 'Network layout' 'Possible' "This PC knows of $($notSwept.Count) other private subnet(s) that were not swept: $((@($notSwept | Select-Object -First 8 | ForEach-Object { Get-Prop $_ 'Cidr' })) -join ', '). Add the client's ones to `$ScanSubnets to sweep them with -Discovery." @($notSwept | ForEach-Object { "$(Get-Prop $_ 'Cidr'): $((@(Get-Prop $_ 'Reasons') | Select-Object -First 3) -join '; ')$(if (Get-Prop $_ 'Hosted') { ' (remote desktop target here)' })" })
    }

    # ---- Reach across the tunnel ----
    $tr = @(@(Get-Prop $R 'TunnelReach', 'Servers') | Where-Object { $_ -and @(Get-Prop $_ 'OpenPorts' | Where-Object { $null -ne $_ }).Count })
    if ($tr.Count) {
        $rdp = @($tr | Where-Object { @(Get-Prop $_ 'OpenPorts') -contains 3389 }); $smbs = @($tr | Where-Object { @(Get-Prop $_ 'OpenPorts') -contains 445 })
        $t = "From an ordinary office port, $($tr.Count) servers across the tunnel accept connections with no filtering in between."
        if ($rdp.Count) { $t += " Remote Desktop is open on $($rdp.Count) of them ($((@($rdp | Select-Object -First 6 | ForEach-Object { $n = "$(Get-Prop $_ 'Name')"; if ($n) { $n.Split('.')[0] } else { "$(Get-Prop $_ 'IP')" } })) -join ', '))." }
        if ($smbs.Count) { $t += " File sharing is open on $($smbs.Count)." }
        & $add 'Tunnel' 'Confirmed' $t @($tr | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name'): ports $((@(Get-Prop $_ 'OpenPorts')) -join ', ')" })
    }
    return $out.ToArray()
}

# =====================================================================
# PHASE 7: analysis, flags, summary
# =====================================================================
function Get-TopologyVerdict {
    # Scores backhaul and split-tunnel signals from one run. Uses $ProviderAsn and $HostedLabel from CONFIG.
    param($Result, [string[]]$RdpHosts = @())
    $signals = @()
    $backhaul = 0; $split = 0
    $eg = $Result['Egress']
    $carrier = Get-Val $eg 'Carrier'
    if ($carrier -match $ProviderAsn) { $backhaul += 3; $signals += "Egress ASN is '$carrier' ($HostedLabel provider): internet exits via the provider" }
    elseif ($carrier) { $signals += "Egress ISP/ASN: $carrier ($(Get-Val $eg 'EgressCity'))" }

    $inet = $Result['Traceroutes'] | Where-Object { $_.Target -eq '1.1.1.1' } | Select-Object -First 1
    if ($inet) {
        $a = $inet.Analysis
        # On its own a private hop is only a hint (some ISPs number their edge privately); it needs a second signal.
        if ($a['TunnelIndicator']) { $backhaul += 1; $signals += "Internet trace crosses private hop(s) with latency before reaching the ISP (tunnel/MPLS or ISP-internal): $($a['PrivateHopsAfterGw'] -join ', ')" }
        elseif ($a['DoubleNatLikely']) { $signals += "Internet trace shows low-latency private hop(s) after gateway (double NAT, e.g. ISP modem + firewall): $($a['PrivateHopsAfterGw'] -join ', ')" }
        elseif ($a['CgnatHops'] -gt 0) { $signals += 'Internet trace goes from the gateway into carrier-grade NAT (ISP-side), i.e. straight out the local circuit' }
        else { $signals += 'Internet trace goes straight from the gateway to a public ISP hop' }
        if (@($a['CarrierPrivateHops']).Count -gt 0) { $signals += "Private hops after the CGNAT hop are carrier-internal, ignored: $($a['CarrierPrivateHops'] -join ', ')" }
        # A distant first public hop only hints at backhaul when it is not just access latency:
        # skip satellite/cellular/CGNAT paths and cases where it roughly equals end-to-end latency.
        $inetPing = @($Result['PingSeries']) | Where-Object { $_ -and $_.Target -eq '1.1.1.1' } | Select-Object -First 1
        $e2e = if ($inetPing) { $inetPing.AvgMs } else { $null }
        $accessLatency = ($a['CgnatHops'] -gt 0) -or ($e2e -and $a['FirstPublicMs'] -ge 0.7 * $e2e)
        if ($a['FirstPublicMs'] -ge 30 -and -not $accessLatency) { $backhaul += 1; $signals += "First public hop is far away ($($a['FirstPublicMs']) ms) compared with end-to-end latency" }
        elseif ($a['FirstPublicMs'] -ge 30) { $signals += "First public hop at $($a['FirstPublicMs']) ms is access-link latency (satellite/cellular/CGNAT or similar), not counted as backhaul" }
        if ($a['FirstPublicPtr']) { $signals += "First public hop rDNS: $($a['FirstPublicPtr'])" }
    }

    $rdpTraces = @($Result['Traceroutes'] | Where-Object { $RdpHosts -contains $_.Target })
    foreach ($t in $rdpTraces) {
        if ($t.Analysis['TunnelIndicator'] -and -not ($inet -and $inet.Analysis['TunnelIndicator'])) { $split += 2; $signals += "RDP trace to $($t.Target) goes through a private tunnel hop that internet traffic does not" }
    }
    foreach ($r in @($Result['RdpPath'])) {
        if ($r -and $r.ResolvesPrivate) { $split += 2; $signals += "RDP host $($r.Host) resolves to a private IP ($($r.ResolvedIPs -join ', ')): reached over a tunnel" }
    }
    $actPriv = @(Get-Val $Result['Rdp'] 'ActiveTcp' | Where-Object { $_.Class -eq 'Private' })
    if ($actPriv.Count -gt 0) { $split += 2; $signals += "Live RDP session is connected to a private IP ($(($actPriv | ForEach-Object { $_.RemoteAddress }) -join ', '))" }

    # DNS on this machine's own subnet is an on-prem server (DC, file server, firewall DNS), not a tunnel.
    # Private DNS on some other subnet hints that DNS is reached over a tunnel; it counts once.
    $localNets = @()
    foreach ($a in @(Get-Val $Result['Network'] 'Adapters' | Where-Object { $_ -and $_.Status -eq 'Up' })) {
        $ips = @($a.IPv4); $masks = @($a.SubnetMask)
        for ($q = 0; $q -lt $ips.Count; $q++) { if ($ips[$q] -and $masks.Count -gt $q) { $localNets += [pscustomobject]@{ Ip = $ips[$q]; Mask = $masks[$q] } } }
    }
    $onPremDns = @(); $remoteDns = @()
    foreach ($d in @(Get-Val $Result['NetworkExtra'] 'DnsServers')) {
        if (-not $d -or $d.Type -notlike 'Private, not the gateway*') { continue }
        if (@($localNets | Where-Object { Test-SameSubnet $d.Server $_.Ip $_.Mask }).Count) { $onPremDns += $d.Server } else { $remoteDns += $d.Server }
    }
    if ($onPremDns.Count) { $signals += "DNS server(s) on this machine's own subnet ($($onPremDns -join ', ')): on-prem server or DC, not a tunnel" }
    if ($remoteDns.Count) { $split += 1; $signals += "DNS server(s) on another private subnet ($($remoteDns -join ', ')): DNS may be reached over a tunnel" }
    $script:OnPremDns = $onPremDns
    $mtu = @($Result['Mtu'])
    $mtuInet = ($mtu | Where-Object { $_.Target -eq '1.1.1.1' } | Select-Object -First 1)
    $mtuRdp = ($mtu | Where-Object { $_.Target -ne '1.1.1.1' } | Select-Object -First 1)
    if ($mtuInet -and $mtuInet.MtuBytes -and $mtuInet.MtuBytes -lt 1500) { $signals += "Internet path MTU is $($mtuInet.MtuBytes) (PPPoE or tunnel overhead)"; if ($mtuInet.MtuBytes -lt 1440) { $backhaul += 1 } }
    if ($mtuRdp -and $mtuRdp.MtuBytes -and $mtuRdp.MtuBytes -lt 1440 -and (-not $mtuInet.MtuBytes -or $mtuInet.MtuBytes -ge 1492)) { $split += 1; $signals += "RDP path MTU is $($mtuRdp.MtuBytes) while internet is $($mtuInet.MtuBytes): tunnel to RDP" }
    if (Get-Val $Result['Network'] 'VpnHoldsDefaultRoute') { $backhaul += 2; $signals += 'A client VPN adapter holds the default route on this PC (full tunnel)' }

    $verdict = 'Local breakout'
    if ($backhaul -ge 2) { $verdict = 'Full backhaul' }
    elseif ($split -ge 2) { $verdict = 'Split tunnel (local internet, RDP over tunnel)' }
    $score = [math]::Max($backhaul, $split)
    $confidence = if ($verdict -eq 'Local breakout') { if ($signals.Count -ge 3) { 'Medium-High' } else { 'Medium' } } elseif ($score -ge 4) { 'High' } elseif ($score -ge 2) { 'Medium' } else { 'Low' }
    [ordered]@{ Verdict = $verdict; Confidence = $confidence; BackhaulScore = $backhaul; SplitScore = $split; Signals = $signals }
}
