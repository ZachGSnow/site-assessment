try { $Result['Leads'] = @(Get-Leads $Result) } catch { $script:Errors += [pscustomobject]@{ Collector = 'Leads'; Error = $_.Exception.Message } }
$Topology = Invoke-Collector 'Topology verdict' { Get-TopologyVerdict $Result $RdpHosts }
$Result['Topology'] = $Topology

# What the evidence adds up to: saved with the data and printed at the end of the run.
$script:Findings = @()
try {
    $areaOrder = @('This run', 'Speed test', 'Switch port', 'Switching', 'Internet service', 'Traffic design', 'Remote desktop', 'Tunnel', 'DNS and DHCP', 'Cloud services', 'Gateway', 'Network equipment', 'Network layout', 'Phones', 'Windows machines', 'Printers', 'Cameras', 'Other offices', 'Directory')
    $fi = 0
    $script:Findings = @(Get-AssessmentFindings $Result | ForEach-Object { $fi++; $ix = [array]::IndexOf($areaOrder, "$($_.Area)"); if ($ix -lt 0) { $ix = 99 }; [pscustomobject]@{ Sort = ($ix * 1000) + $fi; Item = $_ } } | Sort-Object Sort | ForEach-Object { $_.Item })
} catch { $script:Errors += [pscustomobject]@{ Collector = 'Findings'; Error = $_.Exception.Message } }
$Result['Findings'] = $script:Findings

# ---------------- Flags ----------------
try {
    foreach ($dp in @(Get-Val $Result['Domains'] 'Domains')) { foreach ($df in @(Get-DomainFlags $dp)) { Add-Flag $df.Severity $df.Category $df.Message } }
    foreach ($af in @(Get-AdSiteFlags (Get-AdSiteCheck $Result))) { Add-Flag $af.Severity $af.Category $af.Message }
    $Result['RdpTransport'] = Get-RdpTransportCheck $Result
    foreach ($rf in @(Get-RdpTransportFlags $Result['RdpTransport'] ([bool]@($RdpHosts).Count))) { Add-Flag $rf.Severity $rf.Category $rf.Message }
    if ("$(Get-Prop $Result 'Ipv6', 'Status')" -eq 'Broken') { Add-Flag 'Medium' 'Network' 'IPv6 is offered but does not reach the internet (slow first connections)' }
    foreach ($rf in @(Get-NetworkRiskFlags $Result)) { Add-Flag $rf.Severity $rf.Category $rf.Message }
    foreach ($sd in @(Get-Val $Result['Snmp'] 'Devices')) {
        $u = Get-Prop $sd 'Ups'
        if (-not $u) { continue }
        $un = ("UPS {0} at {1}" -f ("$($u.Manufacturer) $($u.Model)").Trim(), $sd.IP)
        if ($u.OnBattery) { Add-Flag 'High' 'Power' "$un is running on battery" }
        if ($u.Battery -in @('low', 'depleted', 'in fault')) { Add-Flag 'High' 'Power' "$un reports its battery as $($u.Battery)" }
        if ($u.ReplaceBattery) { Add-Flag 'High' 'Power' "$un says its battery needs replacing" }
        if ($null -ne $u.MinutesRemaining -and $u.MinutesRemaining -lt 10) { Add-Flag 'Medium' 'Power' "$un has only $($u.MinutesRemaining) minutes of runtime at the current load" }
        if ($null -ne $u.LoadPct -and $u.LoadPct -ge 80) { Add-Flag 'Medium' 'Power' "$un is loaded to $($u.LoadPct)%" }
    }
    $m = $Result['Machine']
    if (Get-Val $m 'IsWindows10') { Add-Flag 'High' 'Lifecycle' 'Windows 10 (out of support since Oct 2025)' }
    if ((Get-Val $m 'RamGB') -and $m['RamGB'] -lt 7.5) { Add-Flag 'Medium' 'Lifecycle' "Only $($m['RamGB']) GB RAM" }
    if (@(Get-Val $m 'Disks' | Where-Object { $_.MediaType -eq 'HDD' }).Count -gt 0) { Add-Flag 'Medium' 'Lifecycle' 'Spinning hard drive (HDD)' }
    if ((Get-Val $m 'ApproxAgeYears') -ge 5) { Add-Flag 'Medium' 'Lifecycle' "About $($m['ApproxAgeYears']) years old (from $(Get-Val $m 'AgeSource'))" }
    $tpmV = Get-Val (Get-Val $m 'Tpm') 'TPM Version'
    $tpmP = "$(Get-Val (Get-Val $m 'Tpm') 'TPM Present')"
    $adminTpm = Get-Val $Result['Admin'] 'Tpm'
    if ($adminTpm -is [System.Collections.IDictionary]) {
        if (-not $adminTpm['Present']) { Add-Flag 'High' 'Lifecycle' 'No TPM (admin check)' }
        elseif (-not $adminTpm['Is20']) { Add-Flag 'High' 'Lifecycle' 'No TPM 2.0 (admin check)' }
    }
    elseif ($tpmP -match '^(False|No)') { Add-Flag 'High' 'Lifecycle' 'No TPM detected (tpmtool)' }
    elseif ($tpmV -and $tpmV -notmatch '^2') { Add-Flag 'High' 'Lifecycle' "TPM version $tpmV" }
    foreach ($b in @(Get-Val $m 'Battery')) { if ($b -and $b.HealthPct -and $b.HealthPct -lt 60) { Add-Flag 'Medium' 'Lifecycle' "Battery health $($b.HealthPct)% of design" } }
    foreach ($v in @(Get-Val $m 'Volumes')) { if ($v -and $v.FreePct -ne $null -and $v.FreePct -lt 10) { Add-Flag 'Low' 'Lifecycle' "Drive $($v.Drive) only $($v.FreePct)% free" } }

    $n = $Result['Network']
    if ("$(Get-Val $n 'PhysicalClass')" -like 'Wired*' -and (Get-Val $n 'PhysicalLinkMbps') -and $n['PhysicalLinkMbps'] -lt 1000) { Add-Flag 'Medium' 'Network' "Wired link negotiated at $($n['PhysicalLinkMbps']) Mbps (cable/switch port)" }
    if (Get-Val $n 'MultipleConnected') { Add-Flag 'Low' 'Network' "Multiple connections up: $($n['ConnectedPhysical'] -join '; ')" }
    if ("$(Get-Val $n 'PhysicalClass')" -eq 'Phone tether (USB)') { Add-Flag 'High' 'Network' 'Internet is via a phone tether' }
    $w = Get-Val $Result['Wireless'] 'Current'
    if ($w -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi') {
        if ($w['SignalPct'] -ne $null -and $w['SignalPct'] -lt 50) { Add-Flag 'Medium' 'Wireless' "Weak Wi-Fi signal ($($w['SignalPct'])%)" }
        if ("$($w['Band'])" -like '2.4*') { Add-Flag 'Medium' 'Wireless' 'Connected on 2.4 GHz' }
        if ("$($w['RadioType'])" -match '802\.11[bgn]$') { Add-Flag 'Low' 'Wireless' "Legacy radio type $($w['RadioType'])" }
    }
    if ((Get-Val $Result['Wireless'] 'Status') -like 'Blocked*') {
        # A policy block applies to every managed PC; a permission block can differ per machine.
        $locWhy = "$(Get-Val (Get-Val $Result['Wireless'] 'LocationWorkaround') 'Result')"
        $flagText = if ($locWhy -like 'Blocked by policy*') { 'Wi-Fi details blocked: location is disabled by policy (likely on every managed PC)' } else { 'Wi-Fi details blocked by location permission' }
        Add-Flag 'Low' 'Wireless' $flagText
    }
    $wev = Get-Val $Result['Wireless'] 'Events'
    # Only drops on the network this run is on count; a laptop's history at other places is not this site.
    $curSsid = if ($w -is [System.Collections.IDictionary]) { $w['SSID'] } else { $null }
    if ("$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi' -and $curSsid -and $wev -is [System.Collections.IDictionary]) {
        $siteDrops = @($wev['RecentRealDrops'] | Where-Object { $_ -and $_.SSID -eq $curSsid }).Count
        $bySsid = @($wev['RealDropsBySsid'] | Where-Object { $_ -like "$curSsid x*" })
        if ($bySsid.Count -and $bySsid[0] -match ' x(\d+)$') { $siteDrops = [int]$matches[1] }
        $wev['SiteSsidDrops'] = $siteDrops
        if ($siteDrops -ge 10) { Add-Flag $(if ($siteDrops -ge 30) { 'High' } else { 'Medium' }) 'Wireless' "$siteDrops Wi-Fi drops with quick reconnect on '$curSsid' in $LookbackDays days" }
    }
    if (@($script:OnPremDns).Count) { Add-Flag 'Medium' 'Infrastructure' "On-prem DNS server(s) on the LAN ($($script:OnPremDns -join ', ')): likely domain controller(s) or servers; confirm what runs on them" }
    $nas = @(@(Get-Val $Result['Ssdp'] 'Devices') | Where-Object { $_ -and "$($_.Manufacturer) $($_.Model)" -match 'Synology|QNAP|Western Digital|WD My|Buffalo|Asustor|TrueNAS|NETGEAR ReadyNAS|Drobo|TerraMaster' })
    foreach ($nd in $nas) { Add-Flag 'Medium' 'Infrastructure' ("On-prem NAS found: {0} {1} '{2}' at {3}" -f $nd.Manufacturer, $nd.Model, $nd.FriendlyName, $nd.IP) }

    foreach ($p in @($Result['PingSeries'])) {
        if (-not $p) { continue }
        if ($p.LossPct -ge 1) { Add-Flag $(if ($p.LossPct -ge 5) { 'High' } else { 'Medium' }) 'Path' "Packet loss $($p.LossPct)% to $($p.Target)" }
        if ($p.JitterMs -ge 30) { Add-Flag 'Medium' 'Path' "Jitter $($p.JitterMs) ms to $($p.Target)" }
    }
    foreach ($ts in @($Result['TcpSeries'])) {
        if (-not $ts -or -not $ts.Sent) { continue }
        if ($ts.LossPct -ge 1) { Add-Flag $(if ($ts.LossPct -ge 5) { 'High' } else { 'Medium' }) 'Path' "TCP connect loss $($ts.LossPct)% to $($ts.Target):$($ts.Port)" }
        if ($ts.JitterMs -ge 30) { Add-Flag 'Medium' 'Path' "Jitter $($ts.JitterMs) ms to $($ts.Target):$($ts.Port) (TCP)" }
    }
    # Microsoft (AVD connection quality): round trip under 150 ms is fine, 150-200 ms is OK for text work, over 200 ms degrades.
    $rdpRtt = @(@($Result['TcpSeries']) + @($Result['PingSeries']) | Where-Object { $_ -and $RdpHosts -contains $_.Target -and $null -ne $_.AvgMs })
    foreach ($rt in $rdpRtt) {
        $how = if ($rt.Method) { 'TCP' } else { 'ping' }
        if ($rt.AvgMs -gt 200) { Add-Flag 'High' 'RDP' "Round trip to $($rt.Target) is $($rt.AvgMs) ms ($how); over 200 ms degrades remote desktop use" }
        elseif ($rt.AvgMs -gt 150) { Add-Flag 'Medium' 'RDP' "Round trip to $($rt.Target) is $($rt.AvgMs) ms ($how); Microsoft recommends under 150 ms" }
    }
    $ast = Get-Val $Result['NetworkExtra'] 'AdapterStats'
    if ($ast -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -like 'Wired*') {
        $errs = [double]$ast['ReceiveErrors'] + [double]$ast['SendErrors']
        $pkts = [double]$ast['ReceivedPackets'] + [double]$ast['SentPackets']
        if ($errs -gt 0 -and $pkts -gt 0 -and ($errs / $pkts) -ge 0.0001) { Add-Flag 'Medium' 'Network' ("{0} adapter errors in {1:N0} packets since boot (cable or switch port)" -f $errs, $pkts) }
    }
    foreach ($mt in @($Result['Mtu'])) { if ($mt -and $mt.MtuBytes -and $mt.MtuBytes -lt 1500) { Add-Flag 'Low' 'Path' "Reduced MTU $($mt.MtuBytes) to $($mt.Target)" } }
    $bw = $Result['Bandwidth']
    if ((Get-Val $bw 'BufferbloatMs') -ge 100) { Add-Flag 'High' 'Path' "Bufferbloat: latency rises $($bw['BufferbloatMs']) ms under load (RDP lag)" }
    if ((Get-Val $bw 'UploadMbps') -ne $null -and $bw['UploadMbps'] -lt 5) { Add-Flag 'Medium' 'Path' "Low upload ($($bw['UploadMbps']) Mbps)" }
    if ($bw -is [System.Collections.IDictionary] -and $bw.Contains('DownloadOk') -and -not $bw['DownloadOk']) { Add-Flag 'High' 'Run' "Download bandwidth NOT measured by any provider ($($bw['DownloadFailure'])); re-run this machine" }
    if ($bw -is [System.Collections.IDictionary] -and $bw.Contains('UploadOk') -and -not $bw['UploadOk']) { Add-Flag 'High' 'Run' "Upload bandwidth NOT measured by any provider ($($bw['UploadFailure'])); re-run this machine" }
    $tlsF = $Result['Tls']
    if ($tlsF -is [System.Collections.IDictionary] -and $tlsF['InspectionSuspected']) {
        $insp = @($tlsF['Checks'] | Where-Object { $_ -and $_.Inspected } | ForEach-Object { '{0} (issuer {1})' -f $_.Host, $_.Issuer })
        Add-Flag 'Medium' 'Security' "HTTPS inspection: $($insp -join '; '). Inspecting the connection to the hosted desktop is a known cause of remote desktop problems"
    }
    $srvF = @(Get-Val $Result['Servers'] 'Servers' | Where-Object { $_ -and $_.Location -like 'On-prem*' })
    if ($srvF.Count) { Add-Flag 'Medium' 'Infrastructure' ("This PC uses on-prem server(s) on its own subnet: {0}" -f (($srvF | ForEach-Object { '{0} ({1})' -f $_.Name, ($_.Sources -join ', ') }) -join '; ')) }
    foreach ($dcDev in @(Get-Val $Result['SubnetSweep'] 'Devices' | Where-Object { $_ -and $_.Role -eq 'Domain controller' })) {
        Add-Flag 'Medium' 'Infrastructure' ("Domain controller on the LAN: {0} {1}" -f $dcDev.IP, $dcDev.Name)
    }
    $ptF = $Result['Patching']
    if ((Get-Val $ptF 'DaysSinceLastUpdate') -ge 45) { Add-Flag 'Medium' 'Patching' "No Windows OS update installed in $($ptF['DaysSinceLastUpdate']) days (last: $($ptF['LastUpdateTitle']))" }
    if (Get-Val $ptF 'PendingReboot') { Add-Flag 'Low' 'Patching' "Reboot pending ($($ptF['PendingRebootReasons'] -join ', '))" }
    $clkF = Get-Val $Result['Egress'] 'ClockOffsetSec'
    if ($null -ne $clkF -and [math]::Abs($clkF) -ge 60) { Add-Flag 'Medium' 'Stability' "Clock is off by $clkF s (breaks MFA/Kerberos)" }
    $admF = $Result['Admin']
    if ($script:AdminActive -and (Get-Val $admF 'SecureBoot') -eq $false) { Add-Flag 'Low' 'Security' 'Secure Boot is off (admin-confirmed)' }
    foreach ($bl in @(Get-Val $admF 'BitLocker')) { if ($bl -and $bl.VolumeType -eq 'OperatingSystem' -and $bl.Protection -ne 'On') { Add-Flag 'Medium' 'Security' "BitLocker protection $($bl.Protection) on $($bl.Mount) (admin-confirmed)" } }
    foreach ($dr in @(Get-Val $admF 'DiskReliability')) { if ($dr -and $dr.WearPct -ge 80) { Add-Flag 'High' 'Lifecycle' "SSD wear $($dr.WearPct)% on $($dr.Disk)" } }

    $rc = Get-Val $Result['EventLogs'] 'RdpClient'
    if ($rc -is [System.Collections.IDictionary]) {
        if ($rc['NetworkDisconnects'] -ge 3) {
            $netReasons = @($rc['AllDisconnects'] | Where-Object { $_ -and $_.Category -eq 'Network' } | Group-Object Code | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
            Add-Flag 'High' 'RDP' "$($rc['NetworkDisconnects']) network-caused RDP disconnects in $LookbackDays days (codes $netReasons)"
        } elseif ($rc['UnexpectedDisconnects'] -ge 5) { Add-Flag 'Medium' 'RDP' "$($rc['UnexpectedDisconnects']) unexpected RDP disconnects in $LookbackDays days ($($rc['DisconnectsByCategory'] -join ', '))" }
        $udpF = $rc['Udp']
        if ($udpF -is [System.Collections.IDictionary] -and $udpF['Failed'] -gt 0 -and $udpF['Established'] -eq 0) { Add-Flag 'Low' 'RDP' 'RDP UDP never established; sessions run on TCP only, which is more sensitive to packet loss' }
    }
    if ((Get-Val $Result['EventLogs'] 'NicLinkEventCount') -ge 10) { Add-Flag 'Medium' 'Network' "Network adapter reset/link-down events: $($Result['EventLogs']['NicLinkEventCount']) in $LookbackDays days" }
    if ((Get-Val $Result['EventLogs'] 'UnexpectedShutdowns') -ge 2) { Add-Flag 'Medium' 'Stability' "$($Result['EventLogs']['UnexpectedShutdowns']) unexpected shutdowns" }
    if ($RdpHosts.Count -eq 0) { Add-Flag 'Medium' 'RDP' 'No remote desktop target resolved on this machine' }
    # Session health (its own try so a problem here cannot skip the flags that follow)
    try {
        $sh = $Result['Session']
        $crashTotal = [int](Get-Val $sh 'ClientCrashes') + [int](Get-Val $sh 'ClientHangs')
        if ($crashTotal -ge 1) { Add-Flag $(if ($crashTotal -ge 3) { 'Medium' } else { 'Low' }) 'RDP' ("Remote desktop client crashed or hung {0} time(s) in {1} days ({2})" -f $crashTotal, $LookbackDays, (@(Get-Val $sh 'ClientCrashByApp') -join ', ')) }
        $udpPol = Get-Val $sh 'UdpPolicy'
        if ($udpPol -is [System.Collections.IDictionary] -and $udpPol['UdpDisabled']) { Add-Flag 'Low' 'RDP' "RDP UDP transport is turned off on this PC ($($udpPol['Source'])); sessions run on TCP only, which is more sensitive to packet loss" }
        $ld = Get-Val $sh 'Load'
        if ($ld -is [System.Collections.IDictionary]) {
            if ($null -ne $ld['MemoryUsedPct'] -and $ld['MemoryUsedPct'] -ge 90) { Add-Flag 'Medium' 'Performance' ("Memory nearly full during the run: {0}% of {1} GB in use (largest: {2})" -f $ld['MemoryUsedPct'], [math]::Round($ld['MemoryTotalMB'] / 1024, 1), ((@($ld['TopByMemory']) | Select-Object -First 3) -join ', ')) }
            if ($null -ne $ld['CpuAvgPct'] -and $ld['CpuAvgPct'] -ge 80) { Add-Flag 'Medium' 'Performance' "CPU busy during the run: $($ld['CpuAvgPct'])% average over $(@($ld['CpuSamplesPct']).Count) samples" }
        }
        $dp = Get-Val $sh 'Displays'
        if ($dp -is [System.Collections.IDictionary] -and $dp['TotalMegapixels'] -ge 8) { Add-Flag 'Low' 'Peripherals' ("Large display area ({0}): a hosted desktop this size needs more bandwidth per user" -f (@($dp['Sizes']) -join ' + ')) }
        $ap = Get-Val $sh 'AdapterPower'
        if ($ap -is [System.Collections.IDictionary] -and "$($ap['AllowTurnOff'])" -match '^(Enabled|Default)' -and "$(Get-Val $Result['Network'] 'PhysicalClass')" -notlike 'Wired*') {
            $dropCount = [int](Get-Val (Get-Val $Result['Wireless'] 'Events') 'SiteSsidDrops') + [int](Get-Val (Get-Val $Result['EventLogs'] 'RdpClient') 'NetworkDisconnects') + [int](Get-Val $Result['EventLogs'] 'NicLinkEventCount')
            if ($dropCount -ge 3) { Add-Flag 'Low' 'Network' "Adapter power saving has not been turned off on $($ap['Adapter']) and this PC has $dropCount recorded connection drops in $LookbackDays days: untick 'Allow the computer to turn off this device'" }
        }
    } catch { $script:Errors += [pscustomobject]@{ Collector = 'Flags (session health)'; Error = $_.Exception.Message } }

    $sw = $Result['Software']
    $blStatus = Get-Val (Get-Val $sw 'BitLocker') 'Status'
    if ($blStatus -in @('Off', 'Suspended')) { Add-Flag 'Medium' 'Security' "BitLocker $blStatus on OS drive" }
    if (@(Get-Val $sw 'AntiVirus' | Where-Object { $_.Enabled }).Count -eq 0 -and (Get-Val $sw 'AntiVirus')) { Add-Flag 'High' 'Security' 'No enabled antivirus reported' }
    if (Get-Val $Result['Identity'] 'UserIsLocalAdmin') { Add-Flag 'Medium' 'Security' 'Signed-in user is a local administrator' }
    if (Get-Val $Result['Identity'] 'LikelyShared') { Add-Flag 'Low' 'Identity' "$($Result['Identity']['ProfilesActiveInLookback']) user profiles active in $LookbackDays days (shared PC?)" }

    foreach ($c in @(Get-Val $Result['Peripherals'] 'RedirectionCheck')) { foreach ($g in @($c.Gaps)) { if ($g) { Add-Flag 'Medium' 'Peripherals' "$g ($([IO.Path]::GetFileName($c.RdpFile)))" } } }
    if ($Result['Meta']['AdminDowngraded']) { Add-Flag 'Low' 'Run' 'Admin tests skipped (ISE not elevated)' }
} catch {
    $script:Errors += [pscustomobject]@{ Collector = 'Flags'; Error = $_.Exception.Message }
}
$Result['Flags'] = $script:Flags
$Result['Errors'] = $script:Errors
$Result['Timings'] = $script:Timings
$Result['Meta']['RunSeconds'] = [int]((Get-Date) - $RunStart).TotalSeconds

# Save again now that the analysis is in, so nothing later (summary, check, zip) can lose it.
[void](Save-Json 'analysis done, data check pending')

# ---------------- Summary text ----------------
$L = New-Object Collections.Generic.List[string]
# Wrapped so a formatting problem in the summary can never stop the data from being written and checked.
try {
$m = $Result['Machine']; $n = $Result['Network']; $eg = $Result['Egress']; $bw = $Result['Bandwidth']; $w = Get-Val $Result['Wireless'] 'Current'

Add-Line ('=' * 72)
Add-Line ("SITE ASSESSMENT  {0}  /  {1}" -f $SiteName, $env:COMPUTERNAME)
Add-Line ("Run {0}  ({1} s)  by {2}  user {3}" -f $Result['Meta']['RunStart'], $Result['Meta']['RunSeconds'], $currentId.Name, $script:UserName)
Add-Line ("Admin tier: {0}" -f $(if ($script:AdminActive) { 'ACTIVE' } else { 'off' }))
if (Get-Prop $Result 'Ipv6', 'Status') { Add-Line ("IPv6: {0}{1}" -f (Get-Prop $Result 'Ipv6', 'Status'), $(if ($null -ne (Get-Prop $Result 'Ipv6', 'Ping', 'AvgMs')) { " ($(Get-Prop $Result 'Ipv6', 'Ping', 'AvgMs') ms to Cloudflare)" })) }
if ($Notes) { Add-Line "Notes: $Notes" }
Add-Line ('=' * 72)
Add-Line ''
Add-Line 'CONNECTION'
$connLine = '  {0} - {1} ({2})' -f (Get-Val $n 'PhysicalClass'), (Get-Val $n 'PhysicalDescription'), $(if (Get-Val $n 'PhysicalLinkMbps') { "$($n['PhysicalLinkMbps']) Mbps link" } else { 'link n/a' })
Add-Line $connLine
if ($w -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi' -and $w['SSID'] -and $w['SsidSource'] -ne 'netsh') {
    Add-Line ('  Wi-Fi: SSID {0} (from {1}; radio details unavailable)' -f $w['SSID'], $w['SsidSource'])
} elseif ($w -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi' -and $w['SSID']) {
    Add-Line ('  Wi-Fi: SSID {0}, {1}, {2}, ch {3}, signal {4}% (~{5} dBm), rx {6} Mbps, AP {7} ({8})' -f $w['SSID'], $w['RadioType'], $w['Band'], $w['Channel'], $w['SignalPct'], $w['ApproxDbm'], $w['ReceiveMbps'], $w['BSSID'], $w['ApVendor'])
}
if (Get-Val $n 'VpnHoldsDefaultRoute') { Add-Line "  Default route held by VPN adapter: $($n['PrimaryAdapter'])" }
$wevS = Get-Val $Result['Wireless'] 'Events'
if ($wevS -is [System.Collections.IDictionary]) {
    $onSsid = if ($null -ne $wevS['SiteSsidDrops']) { "$($wevS['SiteSsidDrops']) on the current network; " } else { '' }
    Add-Line ('  Wi-Fi history, this machine ({0} days): {1}{2} real drops on all networks, {3} disconnects total, {4} failed connects' -f $LookbackDays, $onSsid, $wevS['RealDrops'], $wevS['Disconnected'], $wevS['ConnectFailed'])
}
$locS = Get-Val $Result['Wireless'] 'LocationWorkaround'
if ($locS -is [System.Collections.IDictionary] -and $locS['Needed']) { Add-Line ('  Location workaround: {0}{1}' -f $locS['Result'], $(if ($locS['Attempted']) { "; restored=$($locS['Restored'])" } else { '' })) }
Add-Line ('  IP {0}  gateway {1}  gateway vendor {2}' -f (Get-Val $n 'SourceIp'), (Get-Val $n 'Gateway'), (Get-Val $Result['NetworkExtra'] 'GatewayVendor'))
$gm = $Result['GatewayModel']
if ($gm -is [System.Collections.IDictionary]) { Add-Line ('  Firewall: {0}  (from {1})' -f $(if ($gm['Model']) { "$($gm['Vendor']) $($gm['Model'])" } else { $gm['Vendor'] }), $gm['Source']) }
foreach ($gp in @($Result['GatewayProbe'])) {
    if (-not $gp -or -not $gp.Url) { continue }
    if ($gp.Error -and -not $gp.Status) { Add-Line ('  Gateway probe {0}: {1}' -f $gp.Url, $gp.Error); continue }
    Add-Line ('  Gateway probe {0}: HTTP {1}  title "{2}"  server "{3}"{4}' -f $gp.Url, $gp.Status, $gp.Title, $gp.Server, $(if ($gp.CertSubject) { "  cert $($gp.CertSubject) (issuer $($gp.CertIssuer))" } else { '' }))
}
Add-Line ('  DNS: {0}' -f ((@(Get-Val $Result['NetworkExtra'] 'DnsServers') | ForEach-Object { if (@($script:OnPremDns) -contains $_.Server) { "$($_.Server) [on-prem, this subnet]" } else { "$($_.Server) [$($_.Type)]" } }) -join '; '))
Add-Line ('  Public IP {0}  carrier {1}  egress {2}  CF colo {3}' -f (Get-Val $eg 'PublicIPv4'), (Get-Val $eg 'Carrier'), (Get-Val $eg 'EgressCity'), (Get-Val $eg 'CloudflareColo'))
Add-Line ''
Add-Line 'TOPOLOGY'
Add-Line ('  Verdict: {0}  (confidence {1})' -f (Get-Val $Topology 'Verdict'), (Get-Val $Topology 'Confidence'))
foreach ($s in @(Get-Val $Topology 'Signals')) { Add-Line "   - $s" }
Add-Line ''
Add-Line 'BANDWIDTH'
if ($bw -is [System.Collections.IDictionary] -and $bw.Contains('DownloadOk')) {
    $dlText = if ($bw['DownloadOk']) { '{0} Mbps (peak {1}) via {2}' -f $bw['DownloadMbps'], $bw['DownloadPeakMbps'], $bw['DownloadProvider'] } else { "NOT MEASURED - $($bw['DownloadFailure'])" }
    $ulText = if ($bw['UploadOk']) { '{0} Mbps via {1}' -f $bw['UploadMbps'], $bw['UploadProvider'] } else { "NOT MEASURED - $($bw['UploadFailure'])" }
    Add-Line "  Down $dlText"
    Add-Line "  Up   $ulText"
    if ($bw['DownloadNote']) { Add-Line "  Download note: $($bw['DownloadNote'])" }
    if ($bw['UploadNote']) { Add-Line "  Upload note: $($bw['UploadNote'])" }
    if ($bw['DownloadMinRttMs'] -or $bw['UploadMinRttMs']) { Add-Line ('  M-Lab server view: down {0} Mbps, up {1} Mbps, min RTT {2} ms' -f $bw['DownloadServerMbps'], $bw['UploadServerMbps'], $(if ($bw['DownloadMinRttMs']) { $bw['DownloadMinRttMs'] } else { $bw['UploadMinRttMs'] })) }
    foreach ($at in @($bw['Attempts'] | Where-Object { $_ -and -not $_.Ok })) { Add-Line ('  Failed attempt: {0} via {1}: {2}' -f $at.Direction, $at.Provider, $at.Detail) }
    $na = { param($v) if ($null -eq $v -or "$v" -eq '') { 'n/a' } else { $v } }
    Add-Line ('  Idle latency {0} ms (jitter {1})  loaded down {2} ms / up {3} ms  bufferbloat {4}' -f (& $na (Get-Val $bw 'IdleLatencyMs')), (& $na (Get-Val $bw 'IdleJitterMs')), (& $na (Get-Val $bw 'DownloadLoadedLatencyMs')), (& $na (Get-Val $bw 'UploadLoadedLatencyMs')), (& $na (Get-Val $bw 'BufferbloatGrade')))
} else { Add-Line "  $(Get-Val $bw 'Status')" }
Add-Line ''
Add-Line 'LATENCY / LOSS (ping series, then TCP connect series)'
foreach ($p in @($Result['PingSeries'])) { if ($p) { Add-Line ('  {0,-34} loss {1,5}%  avg {2,6} ms  p95 {3,6} ms  jitter {4,5} ms' -f $p.Target, $p.LossPct, $p.AvgMs, $p.P95Ms, $p.JitterMs) } }
foreach ($p in @($Result['TcpSeries'])) { if ($p) { Add-Line ('  {0,-34} loss {1,5}%  avg {2,6} ms  p95 {3,6} ms  jitter {4,5} ms' -f ('{0} tcp/{1}' -f $p.Target, $p.Port), $p.LossPct, $p.AvgMs, $p.P95Ms, $p.JitterMs) } }
Add-Line ''
Add-Line 'TRACEROUTES'
foreach ($t in @($Result['Traceroutes'])) {
    if (-not $t) { continue }
    Add-Line ('  {0}: {1} hops, first public hop #{2} {3} ({4} ms) {5}' -f $t.Target, $t.Analysis['HopCount'], $t.Analysis['FirstPublicHop'], $t.Analysis['FirstPublicIP'], $t.Analysis['FirstPublicMs'], $t.Analysis['FirstPublicPtr'])
    $path = ($t.Hops | Select-Object -First 6 | ForEach-Object { if ($_.IP) { "$($_.IP)($($_.AvgMs))" } else { '*' } }) -join ' > '
    Add-Line "     $path"
}
Add-Line ''
Add-Line 'RDP'
$rdp = $Result['Rdp']
# Only clients that are installed are listed.
$clientParts = @()
if (Get-Val $rdp 'MstscVersion') { $clientParts += "mstsc $(Get-Val $rdp 'MstscVersion')" }
if (Get-Val $rdp 'MsrdcVersion') { $clientParts += "MSRDC $(Get-Val $rdp 'MsrdcVersion')" }
$clientParts += @(Get-Val $rdp 'AppxClients' | Where-Object { $_ })
Add-Line ('  Clients: {0}' -f $(if ($clientParts.Count) { $clientParts -join '; ' } else { 'none found' }))
Add-Line ('  Targets: {0}' -f $(if ($RdpHosts.Count) { $RdpHosts -join ', ' } else { 'none found' }))
foreach ($r in @($Result['RdpPath'])) { if ($r) { Add-Line ('  {0} -> {1} [{2}]  {3}' -f $r.Host, ($r.ResolvedIPs -join ','), $r.AddressClass, (($r.Tcp | ForEach-Object { if ($_.Open) { "tcp/$($_.Port) $($_.MedianMs) ms" } else { "tcp/$($_.Port) closed" } }) -join ', ')) } }
if (@(Get-Val $rdp 'RunningClients').Count) { Add-Line ('  Live session: {0}; UDP sockets: {1}' -f ((Get-Val $rdp 'RunningClients') -join ', '), (Get-Val $rdp 'UdpLikelyInUse')) }
$rc = Get-Val $Result['EventLogs'] 'RdpClient'
if ($rc -is [System.Collections.IDictionary]) {
    Add-Line ('  Last {0} days: {1} connects, {2} disconnects ({3} unexpected, {4} network): {5}' -f $LookbackDays, $rc['ConnectAttempts'], $rc['Disconnects'], $rc['UnexpectedDisconnects'], $rc['NetworkDisconnects'], ($rc['DisconnectReasons'] -join '; '))
    if ($rc['Udp'] -is [System.Collections.IDictionary]) { Add-Line ('  UDP transport: {0} (attempted {1}, established {2}, failed {3})' -f $rc['Udp']['Status'], $rc['Udp']['Attempted'], $rc['Udp']['Established'], $rc['Udp']['Failed']) }
}
$avc = @(Get-Val $rdp 'HostedConnections')
if ($avc.Count -and $avc[0]) { Add-Line ('  Live hosted desktop connections: {0}' -f (($avc | ForEach-Object { '{0} {1}:{2} ({3})' -f $_.Name, $_.RemoteAddress, $_.RemotePort, $_.Process }) -join '; ')) }
if (@(Get-Val $rdp 'UnresolvedCandidates').Count) { Add-Line ('  Not tested (name does not resolve): {0}' -f ((Get-Val $rdp 'UnresolvedCandidates') -join ', ')) }
$hda = Get-Val $rdp 'HostedDesktopApp'
if ($hda -is [System.Collections.IDictionary]) {
    if ($hda['Found']) {
        Add-Line ('  Hosted-desktop app: {0}' -f ((@($hda['Executables']) | ForEach-Object { '{0} {1}' -f [IO.Path]::GetFileName($_.Path), $_.Version }) -join '; '))
        if (@($hda['Hosts']).Count) { Add-Line ('  Hosts named in its files: {0}' -f (@($hda['Hosts']) -join ', ')) }
    } else { Add-Line '  Hosted-desktop app: not found on this PC (no app matching the hosted desktop profile for this user)' }
}
Add-Line ''
Add-Line 'MACHINE'
Add-Line ('  {0} {1}  S/N {2}  {3}  ~{4} yrs (from {5})' -f (Get-Val $m 'Manufacturer'), (Get-Val $m 'Model'), (Get-Val $m 'SerialNumber'), (Get-Val $m 'FormFactor'), (Get-Val $m 'ApproxAgeYears'), (Get-Val $m 'AgeSource'))
Add-Line ('  {0}  {1} GB RAM  {2}' -f (Get-Val $m 'Cpu'), (Get-Val $m 'RamGB'), ((@(Get-Val $m 'Disks') | ForEach-Object { "$($_.SizeGB)GB $($_.MediaType)" }) -join ', '))
$tpmShow = Get-Val (Get-Val $m 'Tpm') 'TPM Version'
if (-not $tpmShow -and "$(Get-Val (Get-Val $m 'Tpm') 'TPM Present')" -match '^(False|No)') { $tpmShow = 'none' }
Add-Line ('  {0} {1} (build {2}.{3})  TPM {4}  SecureBoot {5}' -f (Get-Val $m 'OsCaption'), (Get-Val $m 'OsDisplayVersion'), (Get-Val $m 'OsBuild'), (Get-Val $m 'OsUbr'), $tpmShow, (Get-Val $m 'SecureBootRegistry'))
$id = $Result['Identity']
Add-Line ('  Join: {0}  tenant {1}  Intune {2}  user local admin {3}' -f (Get-Val $id 'JoinType'), (Get-Val (Get-Val $id 'Dsregcmd') 'TenantName'), (Get-Val $id 'IntuneEnrolled'), (Get-Val $id 'UserIsLocalAdmin'))
$swr = $Result['Software']
Add-Line ('  RMM: {0}' -f ((@(Get-Val (Get-Val $swr 'Tagged') 'RMM')) -join ', '))
$secList = @(Get-Val (Get-Val $swr 'Tagged') 'Security') + @(Get-Val $swr 'AntiVirus' | ForEach-Object { $_.Name })
Add-Line ('  Security: {0}' -f ((@($secList | Where-Object { $_ } | Sort-Object -Unique)) -join ', '))
Add-Line ('  VPN clients: {0}' -f ((@(Get-Val (Get-Val $swr 'Tagged') 'VPN')) -join ', '))
$pt = $Result['Patching']
if ($pt -is [System.Collections.IDictionary]) {
    $src = if ($pt['UseWsus']) { "WSUS $($pt['WsusServer'])" } elseif ($null -ne $pt['WufbDeferQualityDays']) { "WUfB policy (quality defer $($pt['WufbDeferQualityDays']) d)" } else { 'Windows Update' }
    Add-Line ('  Updates: last OS update {0} ({1} days ago, {2}, from {3}) via {4}; pending reboot {5}{6}' -f $pt['LastUpdateInstalled'], $pt['DaysSinceLastUpdate'], $pt['LastUpdateTitle'], $pt['LastUpdateSource'], $src, $pt['PendingReboot'], $(if ($pt['PendingReboot']) { " ($($pt['PendingRebootReasons'] -join ', '))" } else { '' }))
    $o365 = $pt['M365']
    if ($o365) { Add-Line ('  Microsoft 365 Apps: {0} {1}, {2} channel{3}' -f $o365['Version'], $o365['Platform'], $(if ($o365['Channel']) { $o365['Channel'] } else { 'unknown' }), $(if ($o365['SharedActivation']) { ', shared computer activation' } else { '' })) }
    else { Add-Line '  Microsoft 365 Apps: not installed (Click-to-Run)' }
}
$clk = Get-Val $Result['Egress'] 'ClockOffsetSec'
if ($null -ne $clk) { Add-Line ('  Clock offset vs Cloudflare: {0} s' -f $clk) }
$adm = $Result['Admin']
Add-Line ''
Add-Line 'ADMIN CHECKS'
if (-not $script:AdminActive) { Add-Line '  Not run (admin tier off)' }
elseif ($adm -is [System.Collections.IDictionary]) {
    $tp = $adm['Tpm']
    if ($tp -is [System.Collections.IDictionary]) { Add-Line ('  TPM: present {0}, ready {1}, spec {2}, maker {3}' -f $tp['Present'], $tp['Ready'], $tp['SpecVersion'], "$($tp['ManufacturerId'])".Trim()) } else { Add-Line "  TPM: $tp" }
    Add-Line ('  Secure Boot (confirmed): {0}' -f $adm['SecureBoot'])
    foreach ($b in @($adm['BitLocker'])) { if ($b -and $b.Mount) { Add-Line ('  BitLocker {0}: {1}, protection {2}, {3}, protectors {4}' -f $b.Mount, $b.Status, $b.Protection, $b.Method, ($b.Protectors -join '+')) } elseif ($b) { Add-Line "  BitLocker: $b" } }
    foreach ($d in @($adm['DiskReliability'])) {
        if (-not $d -or -not $d.Disk) { continue }
        # NVMe drives often leave some counters empty; only print what the drive reports.
        $parts = @()
        if ($null -ne $d.WearPct) { $parts += "wear $($d.WearPct)%" }
        if ($d.TemperatureC) { $parts += "temp $($d.TemperatureC) C" }
        if ($d.PowerOnHours) { $parts += "power-on $($d.PowerOnHours) h" }
        if ($null -ne $d.ReadErrorsTotal -and "$($d.ReadErrorsTotal)" -ne '') { $parts += "read errors $($d.ReadErrorsTotal)" }
        Add-Line ('  Disk {0}: {1}' -f $d.Disk, $(if ($parts.Count) { $parts -join ', ' } else { 'no health counters reported' }))
    }
    $lg = $adm['InteractiveLogons']
    if ($lg -is [string]) { Add-Line "  Sign-ins: $lg" }
    else { Add-Line ('  Sign-ins ({0} days): {1}' -f $LookbackDays, ((@($lg) | Where-Object { $_ } | ForEach-Object { '{0} x{1} [{2}] last {3}' -f $_.User, $_.Count, $_.Types, $_.Last }) -join '; ')) }
    if ($adm['WlanReport'] -eq 'wlanreport.html') { Add-Line '  Wi-Fi report: wlanreport.html (in the zip)' }
}
$sh = $Result['Session']
if ($sh -is [System.Collections.IDictionary]) {
    Add-Line ''
    Add-Line 'SESSION HEALTH (this PC)'
    if ($null -ne (Get-Val $sh 'ClientCrashes')) { Add-Line ('  Remote desktop client, last {0} days: {1} crash(es), {2} hang(s){3}' -f $LookbackDays, $sh['ClientCrashes'], $sh['ClientHangs'], $(if (@($sh['ClientCrashByApp']).Count) { ': ' + (@($sh['ClientCrashByApp']) -join ', ') } else { '' })) }
    $udpPolS = Get-Val $sh 'UdpPolicy'
    if ($udpPolS -is [System.Collections.IDictionary]) { Add-Line ('  RDP UDP on this client: {0}' -f $(if ($udpPolS['UdpDisabled']) { "turned off ($($udpPolS['Source']))" } else { 'not turned off' })) }
    $dpS = Get-Val $sh 'Displays'
    if ($dpS -is [System.Collections.IDictionary] -and @($dpS['Sizes']).Count) { Add-Line ('  Displays: {0} ({1} megapixels)' -f (@($dpS['Sizes']) -join ' + '), $dpS['TotalMegapixels']) }
    $ldS = Get-Val $sh 'Load'
    if ($ldS -is [System.Collections.IDictionary]) {
        Add-Line ('  CPU {0}% average, memory {1}% of {2} GB in use' -f $ldS['CpuAvgPct'], $ldS['MemoryUsedPct'], [math]::Round($ldS['MemoryTotalMB'] / 1024, 1))
        if (@($ldS['TopByMemory']).Count) { Add-Line ('  Largest programs in memory: {0}' -f (@($ldS['TopByMemory']) -join '; ')) }
    }
    $apS = Get-Val $sh 'AdapterPower'
    if ($apS -is [System.Collections.IDictionary]) { Add-Line ('  Adapter power saving on {0}: {1}' -f $apS['Adapter'], $apS['AllowTurnOff']) }
}
Add-Line ''
Add-Line 'PERIPHERALS'
$pr = $Result['Peripherals']
foreach ($p in @(Get-Val $pr 'Printers' | Where-Object { -not $_.IsVirtual })) { Add-Line ('  Printer: {0} [{1}{2}] driver {3}{4}' -f $p.Name, $p.PortType, $(if ($p.HostAddress) { " $($p.HostAddress)" } else { '' }), $p.Driver, $(if ($p.IsDefault) { ' (default)' } else { '' })) }
Add-Line ('  Monitors: {0}  {1}' -f (Get-Val $pr 'MonitorCount'), ((@(Get-Val $pr 'Monitors') | ForEach-Object { "$($_.Manufacturer) $($_.Model) $($_.DiagonalInches)in" }) -join '; '))
$dbc = Get-Val $pr 'DevicesByClass'
if ($dbc -is [System.Collections.IDictionary]) { foreach ($k in $dbc.Keys) { if (@($dbc[$k]).Count) { Add-Line ('  {0}: {1}' -f $k, (@($dbc[$k]) -join '; ')) } } }
if (@(Get-Val $pr 'NotableDevices').Count) { Add-Line ('  Notable: {0}' -f ((Get-Val $pr 'NotableDevices') -join '; ')) }
if (@(Get-Val $pr 'Docks').Count) { Add-Line ('  Docks: {0}' -f ((Get-Val $pr 'Docks') -join '; ')) }
$sweep = $Result['SubnetSweep']
if ($sweep) {
    Add-Line ''
    Add-Line 'LOCAL NETWORK (subnet sweep)'
    if (Get-Val $sweep 'Subnet') {
        Add-Line ('  {0}: {1} devices seen, {2} answered ping' -f $sweep['Subnet'], $sweep['ArpEntries'], $sweep['PingResponders'])
        if ($sweep['Note']) { Add-Line "  $($sweep['Note'])" }
        if (@($sweep['RoleSummary']).Count) { Add-Line ('  By type: {0}' -f (@($sweep['RoleSummary']) -join '; ')) }
        foreach ($dv in @($sweep['Devices'] | Where-Object { $_ -and ($_.Name -or $_.Role) } | Select-Object -First 60)) {
            Add-Line ('  {0,-15} {1}' -f $dv.IP, ((@($dv.Name, $dv.Role, $(if (@($dv.OpenPorts).Count) { 'ports ' + (@($dv.OpenPorts) -join ',') }), $dv.Vendor) | Where-Object { $_ }) -join ' | '))
        }
        Add-Line ('  Vendors: {0}' -f ((@($sweep['VendorSummary'])) -join '; '))
    } else { Add-Line "  $(Get-Val $sweep 'Status')" }
}
$srvS = $Result['Servers']
if ($srvS -is [System.Collections.IDictionary] -and $srvS.Contains('Servers')) {
    Add-Line ''
    Add-Line 'SERVERS THIS PC USES'
    if (@($srvS['Servers']).Count -eq 0) { Add-Line '  none (no mapped drives, shared printers or domain)' }
    foreach ($sv in @($srvS['Servers'])) { if ($sv) { Add-Line ('  {0} -> {1} [{2}]  {3}' -f $sv.Name, $(if (@($sv.IPs).Count) { @($sv.IPs) -join ',' } else { 'no address' }), $sv.Location, (@($sv.Sources) -join '; ')) } }
    $dcS = $srvS['DomainController']
    if ($dcS -is [System.Collections.IDictionary]) { Add-Line ('  Domain {0}: controller {1} {2}, AD site {3}{4}' -f $dcS['Domain'], $dcS['Name'], $dcS['Address'], $dcS['ClientSite'], $(if ($dcS['Error']) { "  ($($dcS['Error']))" } else { '' })) }
}
$tlsS = $Result['Tls']
if ($tlsS -is [System.Collections.IDictionary] -and $tlsS.Contains('Checks')) {
    Add-Line ''
    Add-Line ('HTTPS CERTIFICATES (inspection suspected: {0})' -f $tlsS['InspectionSuspected'])
    foreach ($tc in @($tlsS['Checks'])) {
        if (-not $tc) { continue }
        if ($tc.Error) { Add-Line ('  {0}:{1}  no TLS answer: {2}' -f $tc.Host, $tc.Port, $tc.Error) }
        else { Add-Line ('  {0}:{1}  issued by {2}  for {3}  ({4}, check: {5})' -f $tc.Host, $tc.Port, $tc.Issuer, $tc.Subject, $tc.Protocol, $tc.PolicyErrors) }
    }
}
$fwp = $Result['FirewallPorts']
if ($fwp -is [System.Collections.IDictionary] -and $fwp.Contains('Ports')) {
    Add-Line ''
    Add-Line 'GATEWAY ADMIN PORTS'
    $openP = @($fwp['Ports'] | Where-Object { $_.Open })
    if ($openP.Count -eq 0) { Add-Line '  4443/8443/10443/22 all closed' }
    foreach ($p in $openP) { Add-Line ('  tcp/{0} open  {1}' -f $p.Port, ((@($p.Title, $p.Server, $p.CertSubject, $p.Banner) | Where-Object { $_ }) -join ' | ')) }
    if (@($fwp['VendorHints']).Count) { Add-Line ('  Vendor hints: {0}' -f ($fwp['VendorHints'] -join ', ')) }
}
$ssdp = $Result['Ssdp']
if ($ssdp -is [System.Collections.IDictionary] -and $ssdp.Contains('Devices')) {
    Add-Line ''
    Add-Line ('UPNP / SSDP DEVICES ({0})' -f $ssdp['DeviceCount'])
    foreach ($d in @($ssdp['Devices'])) { if ($d) { Add-Line ('  {0,-15} {1}' -f $d.IP, ((@($d.Manufacturer, $d.Model, $d.ModelNumber, $d.FriendlyName, $d.DeviceType) | Where-Object { $_ } | Select-Object -Unique) -join ' | ')) } }
}
$pp = @($Result['PrinterProbe'])
if ($pp.Count -and $pp[0] -and $pp[0].IP) {
    Add-Line ''
    Add-Line 'NETWORK PRINTER WEB PAGES'
    foreach ($p in $pp) { if ($p) { Add-Line ('  {0,-15} {1}' -f $p.IP, $(if (-not $p.Reachable) { 'not reachable from here' } else { (@($p.Title, $p.Server) | Where-Object { $_ }) -join ' | ' })) } }
}
$lldp = $Result['Lldp']
if ($lldp) {
    Add-Line ''
    Add-Line 'SWITCH (LLDP/CDP)'
    foreach ($nb in @(Get-Val $lldp 'Neighbors')) {
        if (-not $nb) { continue }
        Add-Line ('  {0}: {1}' -f $nb.Protocol, $(if ($nb.Model) { $nb.Model } else { 'model not advertised' }))
        $bits = @("name $($nb.SystemName)", "this PC on port $($nb.Port)")
        if ($nb.LinkMode) { $bits += "link $($nb.LinkMode)" }
        if ($nb.Vlan) { $bits += "VLAN $($nb.Vlan)" }
        if ($nb.MgmtIP) { $bits += "management $($nb.MgmtIP)" }
        Add-Line ('    ' + ($bits -join ', '))
        if ($nb.SystemDescription -and $nb.SystemDescription -ne $nb.Model) { Add-Line "    $($nb.SystemDescription)" }
    }
    if (Get-Val $lldp 'Note') { Add-Line "  $($lldp['Note'])" }
}
Add-Line ''
Add-Line 'FLAGS'
if ($script:Flags.Count -eq 0) { Add-Line '  none' }
foreach ($f in ($script:Flags | Sort-Object @{ Expression = { @{ High = 0; Medium = 1; Low = 2 }[$_.Severity] } })) { Add-Line ('  [{0}] {1}: {2}' -f $f.Severity, $f.Category, $f.Message) }
if ($script:Errors.Count) {
    Add-Line ''
    Add-Line 'COLLECTOR ERRORS (see errors.log)'
    foreach ($e in $script:Errors) { Add-Line ('  {0}: {1}' -f $e.Collector, $e.Error) }
}
$wifiFix = Get-Val $Result['Wireless'] 'Fix'
if ($wifiFix) { Add-Line ''; Add-Line "WI-FI FIX: $wifiFix" }
} catch {
    Add-Line ''
    Add-Line "SUMMARY INCOMPLETE: $($_.Exception.Message) (the data in assessment.json is not affected)"
}

# Safety net: never leave a packet capture running.
if ($script:PktmonStarted) {
    try { Invoke-Native 'pktmon.exe' 'stop' 60 | Out-Null; Invoke-Native 'pktmon.exe' 'filter remove' 15 | Out-Null } catch { }
}
