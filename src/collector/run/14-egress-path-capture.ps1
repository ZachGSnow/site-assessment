# =====================================================================
# PHASE 4: path tests (public IP, DNS, TCP timing, MTU)
# =====================================================================
# Kept as a variable so the retry phase can run it again.
$EgressBlock = {
    $out = [ordered]@{}
    $parseTrace = { param($t) $h = [ordered]@{}; foreach ($l in ($t -split "`n")) { if ($l -match '^([a-z_]+)=(.*)$') { $h[$matches[1]] = $matches[2].Trim() } }; $h }
    try {
        $before = [DateTime]::UtcNow
        $t4 = Invoke-WebRequest -Uri 'https://1.1.1.1/cdn-cgi/trace' -UseBasicParsing -TimeoutSec 10
        $after = [DateTime]::UtcNow
        $tr = & $parseTrace $t4.Content
        $out['PublicIPv4'] = $tr['ip']; $out['CloudflareColo'] = $tr['colo']; $out['Country'] = $tr['loc']; $out['Warp'] = $tr['warp']
        # Clock drift breaks MFA and Kerberos; Cloudflare's trace includes its own Unix timestamp.
        if ($tr['ts']) {
            $serverUtc = (New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)).AddSeconds([double]::Parse($tr['ts'], [Globalization.CultureInfo]::InvariantCulture))
            $localMid = $before.AddTicks([int64](($after - $before).Ticks / 2))
            $out['ClockOffsetSec'] = [math]::Round(($localMid - $serverUtc).TotalSeconds, 1)
        }
    } catch { $out['TraceError'] = $_.Exception.Message }
    try {
        $t6 = Invoke-WebRequest -Uri 'https://speed.cloudflare.com/cdn-cgi/trace' -UseBasicParsing -TimeoutSec 10
        $tr6 = & $parseTrace $t6.Content
        if ($tr6['ip'] -and $tr6['ip'] -ne $out['PublicIPv4']) { $out['PublicIPPreferred'] = $tr6['ip'] }
    } catch { }
    try {
        $meta = Invoke-RestMethod -Uri 'https://speed.cloudflare.com/meta' -UseBasicParsing -TimeoutSec 10
        $out['CfAsn'] = $meta.asn; $out['CfAsOrganization'] = $meta.asOrganization; $out['CfCity'] = $meta.city; $out['CfRegion'] = $meta.region
        if (-not $out['PublicIPv4'] -and $meta.clientIp) { $out['PublicIPv4'] = $meta.clientIp }
    } catch { }
    if ($EnableIpInfo -and $out['PublicIPv4']) {
        try {
            $ii = Invoke-RestMethod -Uri ("https://ipinfo.io/{0}/json" -f $out['PublicIPv4']) -UseBasicParsing -TimeoutSec 10
            $out['IpInfo'] = [ordered]@{ Hostname = $ii.hostname; City = $ii.city; Region = $ii.region; Country = $ii.country; Org = $ii.org; Postal = $ii.postal }
        } catch { $out['IpInfoError'] = $_.Exception.Message }
    }
    $org = $out['CfAsOrganization']
    if (-not $org -and $out['IpInfo']) { $org = $out['IpInfo']['Org'] }
    $out['Carrier'] = $org
    $out['EgressCity'] = if ($out['CfCity']) { '{0}, {1}' -f $out['CfCity'], $out['CfRegion'] } elseif ($out['IpInfo']) { '{0}, {1}' -f $out['IpInfo']['City'], $out['IpInfo']['Region'] } else { $null }
    $out
}
$Result['Egress'] = Invoke-Collector 'Public egress (Cloudflare, ipinfo)' $EgressBlock
if ($EnableDomainCheck) {
    $Result['Domains'] = Invoke-Collector 'Email domain in public DNS (MX, SPF, DMARC, DKIM)' {
        $doms = @(Get-ClientDomains $Result | Select-Object -First 3)
        if (-not $doms.Count) { throw 'no public domain found in the sign-in name, DNS suffixes or AD forest' }
        [ordered]@{ Domains = @($doms | ForEach-Object { [pscustomobject](Get-DomainPosture $_) }) }
    }
}
if ($EnableIpv6Check) { $Result['Ipv6'] = Invoke-Collector 'IPv6 (offered here, reaches the internet?)' { Get-Ipv6State } }

$Result['RdpPath'] =Invoke-Collector 'RDP host DNS and TCP timing' {
    $rows = @()
    foreach ($h in $RdpHosts) {
        $ips = @()
        if (Test-IPv4 $h) { $ips = @($h) }
        else {
            try { $ips = @(Resolve-DnsName -Name $h -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) } catch { }
        }
        $classes = @($ips | ForEach-Object { Get-IpClass $_ } | Sort-Object -Unique)
        $ports = @()
        $portList = @(443, 3389)
        $known = Get-Val (Get-Val $Result['Rdp'] 'DiscoveredPorts') $h
        if ($known) { $portList = @(@($known) + $portList | Select-Object -Unique) }
        if ($ips.Count -gt 0) {
            foreach ($port in $portList) {
                $times = @(); $fail = 0
                for ($n = 0; $n -lt 10; $n++) {
                    $ok = $false
                    $t0 = Get-Date
                    try {
                        $c = New-Object Net.Sockets.TcpClient
                        $task = $c.ConnectAsync($ips[0], $port)
                        $ok = $task.Wait(2000) -and $c.Connected
                        $c.Close()
                    } catch { $ok = $false }
                    $ms = ((Get-Date) - $t0).TotalMilliseconds
                    if ($ok) { $times += $ms } else { $fail++; if ($n -eq 0) { break } }
                }
                $sorted = @($times | Sort-Object)
                $jit = $null
                if ($times.Count -gt 1) { $d = 0; for ($k = 1; $k -lt $times.Count; $k++) { $d += [math]::Abs($times[$k] - $times[$k - 1]) }; $jit = [math]::Round($d / ($times.Count - 1), 1) }
                $ports += [pscustomobject]@{
                    Port = $port; Open = ($times.Count -gt 0); Attempts = $times.Count + $fail; Failures = $fail
                    MedianMs = if ($sorted.Count) { [math]::Round($sorted[[int][math]::Floor($sorted.Count / 2)], 1) } else { $null }
                    MinMs = if ($sorted.Count) { [math]::Round($sorted[0], 1) } else { $null }
                    JitterMs = $jit
                }
            }
        }
        $rows += [pscustomobject]@{ Host = $h; ResolvedIPs = $ips; AddressClass = ($classes -join ','); ResolvesPrivate = ($classes -contains 'Private'); Tcp = $ports }
    }
    $rows
}

if ($EnableTlsCheck -and $script:FullLanguage) {
    $Result['Tls'] = Invoke-Collector 'HTTPS certificate check' {
        # speed.cloudflare.com is the control (a public CA should have issued it); then each remote desktop
        # host that answers on a TLS port. For a bare IP the certificate subject often names the real host.
        $rows = @()
        $rows += Get-TlsInfo 'speed.cloudflare.com' 'speed.cloudflare.com' 443
        foreach ($r in @($Result['RdpPath'])) {
            if (-not $r -or -not @($r.ResolvedIPs).Count) { continue }
            foreach ($tp in @($r.Tcp | Where-Object { $_ -and $_.Open -and $_.Port -ne 3389 } | Select-Object -First 2)) {
                $rows += Get-TlsInfo $r.Host @($r.ResolvedIPs)[0] $tp.Port
            }
        }
        # Issuer names used by firewalls, web filters and antivirus products that re-sign HTTPS.
        $vendorRx = '\b(Fortinet|FortiGate|Sophos|SonicWall|WatchGuard|Palo Alto|Zscaler|Umbrella|Meraki|Netskope|Barracuda|Untangle|Check Point|Forcepoint|iboss|Smoothwall|Kerio|Squid|Avast|AVG|Kaspersky|ESET|Bitdefender|Trend Micro|McAfee|Norton|DO_NOT_TRUST|SSL Inspection|Web Filter)\b'
        foreach ($row in $rows) { if ($row.Issuer -and $row.Issuer -match $vendorRx) { $row.Inspected = $true } }
        [ordered]@{
            Checks = $rows
            InspectionSuspected = [bool](@($rows | Where-Object { $_.Inspected }).Count)
            ControlIssuer = $rows[0].Issuer
        }
    }
}

$Result['Mtu'] = Invoke-Collector 'Path MTU probe' {
    $res = @(Get-PathMtu '1.1.1.1')
    if ($RdpHosts.Count -gt 0) { $res += Get-PathMtu $RdpHosts[0] }
    # The first private (tunnel) target too: its MTU is what a hosted-desktop session actually gets.
    $privTarget = @($RdpHosts | Where-Object { (Test-IPv4 $_) -and (Get-IpClass $_) -eq 'Private' }) | Select-Object -First 1
    if ($privTarget -and $privTarget -ne $RdpHosts[0]) { $res += Get-PathMtu $privTarget }
    $res
}
