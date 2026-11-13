# =====================================================================
# PHASE 2: background traceroutes + ping series
# =====================================================================
$Targets = @('1.1.1.1', '8.8.8.8') + $RdpHosts
$Jobs = @()
Write-Step 'Starting background traceroutes and ping series'
foreach ($t in $Targets) {
    $Jobs += [pscustomobject]@{ Kind = 'Trace'; Target = $t; Handle = (Start-IcmpJob -Kind Trace -Target $t -MaxHops 20 -TimeoutMs 750 -Label "trace $t") }
}
$PingTargets = @()
if ($Gateway) { $PingTargets += $Gateway }
$PingTargets += '1.1.1.1'
$PingTargets += $RdpHosts
$PingTargets = @($PingTargets | Select-Object -Unique)
# Hosts that ignore ICMP would only add timeouts and false 100% loss; precheck with 2 quick pings.
$script:IcmpSilent = @()
if ($script:FullLanguage) {
    foreach ($t in $PingTargets) {
        $ok = $false
        for ($k = 0; $k -lt 2 -and -not $ok; $k++) {
            try { $pr = (New-Object Net.NetworkInformation.Ping).Send($t, 800); if ($pr.Status -eq 'Success') { $ok = $true } } catch { }
        }
        if (-not $ok) { $script:IcmpSilent += $t }
    }
}
foreach ($t in $PingTargets) {
    if ($script:IcmpSilent -contains $t) { continue }
    $Jobs += [pscustomobject]@{ Kind = 'Ping'; Target = $t; Handle = (Start-IcmpJob -Kind Ping -Target $t -Count $PingCount -TimeoutMs 1000 -Label "ping $t") }
}
if ($script:IcmpSilent.Count) { Write-Step ("  No ICMP reply (ping series skipped, TCP series used): {0}" -f ($script:IcmpSilent -join ', ')) }

# TCP connect series to the first 3 remote desktop hosts that answer, each on the first port that answers.
$TcpSeriesJobs = @()
if ($script:FullLanguage) {
    foreach ($h in $RdpHosts) {
        if ($TcpSeriesJobs.Count -ge 3) { break }
        try {
            $addr = $h
            if (-not (Test-IPv4 $h)) { $addr = @(Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' })[0].IPAddress }
            $tryPorts = @(@(Get-Val $portMap $h) + @(443, 3389) | Where-Object { $_ } | Select-Object -Unique)
            $openPort = $tryPorts | Where-Object { Test-TcpPort $addr $_ 1500 } | Select-Object -First 1
            if ($openPort) { $TcpSeriesJobs += Start-TcpSeries $h $addr $openPort $PingCount }
        } catch { $script:Errors += [pscustomobject]@{ Collector = "TCP series $h"; Error = $_.Exception.Message } }
    }
    if ($TcpSeriesJobs.Count) { Write-Step ("  TCP series running: {0}" -f (($TcpSeriesJobs | ForEach-Object { '{0} tcp/{1}' -f $_.Target, $_.Port }) -join ', ')) }
}

# Admin + wired: LLDP/CDP capture with pktmon runs alongside everything else.
$script:PktmonStarted = $false
$PktmonEtl = Join-Path $OutDir 'lldp.etl'
$PktmonStartTime = $null
if ($script:AdminActive -and $Net -and "$($Net['PhysicalClass'])" -like 'Wired*') {
    try {
        Write-Step 'Admin: starting pktmon LLDP/CDP capture (stops automatically)'
        Invoke-Native 'pktmon.exe' 'filter remove' 15 | Out-Null
        Invoke-Native 'pktmon.exe' 'filter add LLDP -d 0x88CC' 15 | Out-Null
        Invoke-Native 'pktmon.exe' 'filter add CDP -m 01-00-0C-CC-CC-CC' 15 | Out-Null
        # Also listen to what every port on the VLAN hears anyway: broadcasts (ARP, DHCP, vendor discovery),
        # spanning tree and IPv6 router advertisements. Nothing is sent. A failed filter only narrows the capture.
        foreach ($flt in @('BCAST -m FF-FF-FF-FF-FF-FF', 'STP -m 01-80-C2-00-00-00', 'PVST -m 01-00-0C-CC-CC-CD', 'IPV6RA -m 33-33-00-00-00-01', 'UBNT -t UDP -p 10001', 'MNDP -t UDP -p 5678', 'NSDP -t UDP -p 63321', 'DHCP -t UDP -p 67', 'EAPOL -d 0x888E')) {
            try { Invoke-Native 'pktmon.exe' "filter add $flt" 15 | Out-Null } catch { }
        }
        Invoke-Native 'pktmon.exe' ('start --capture --comp nics --pkt-size 0 --file-name "{0}"' -f $PktmonEtl) 20 | Out-Null
        $script:PktmonStarted = $true
        $PktmonStartTime = Get-Date
    } catch {
        $script:Errors += [pscustomobject]@{ Collector = 'pktmon start'; Error = $_.Exception.Message }
    }
    # Vendor discovery questions go out once while the capture is listening: MikroTik and Netgear answer
    # by broadcast, which Windows Firewall would drop before a socket sees it, but the capture records it.
    if ($script:PktmonStarted -and $EnableVendorDiscovery -and $script:FullLanguage) {
        try { [void](Send-VendorDiscovery (Get-Val $Net 'SourceIp') 400) } catch { $script:Errors += [pscustomobject]@{ Collector = 'Vendor discovery (during capture)'; Error = $_.Exception.Message } }
    }
    # A lease renewal (the address is kept, nothing drops) makes the DHCP server answer while the capture
    # listens, so its address and the options it hands out are on record.
    if ($script:PktmonStarted -and $EnableDhcpRenew) {
        try {
            $rnAd = @($Net['Adapters'] | Where-Object { $_.Name -eq $Net['PhysicalAdapter'] }) | Select-Object -First 1
            if ($rnAd -and $rnAd.DhcpEnabled) { Invoke-Native 'ipconfig.exe' ('/renew "{0}"' -f $rnAd.Name) 25 | Out-Null }
        } catch { $script:Errors += [pscustomobject]@{ Collector = 'DHCP renew (during capture)'; Error = $_.Exception.Message } }
    }
}
