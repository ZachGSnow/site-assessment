# =====================================================================
# PHASE 6e (v1.7.0): more facts from this port. Each step is independent, reads only, logs in to
# nothing and runs after everything above is saved.
# =====================================================================
[void](Save-Json 'checkpoint: discovery saved, extra checks not finished')
$sweepDevs = @(@(Get-Val $Result['SubnetSweep'] 'Devices') + @(Get-Val $Result['RemoteSweep'] 'Devices') | Where-Object { $_ })
$primaryAd = @(Get-Val $Result['Network'] 'Adapters' | Where-Object { $_ -and $_.Name -eq (Get-Val $Result['Network'] 'PhysicalAdapter') }) | Select-Object -First 1

if ($EnableModemPage -and $script:FullLanguage -and $srcIp) {
    $Result['IspModem'] = Invoke-Collector 'ISP modem status page' {
        $cands = @('192.168.100.1')
        $pub = "$(Get-Val $Result['Egress'] 'PublicIPv4')"
        foreach ($t in @($Result['Traceroutes'] | Where-Object { $_ -and @('1.1.1.1', '8.8.8.8') -contains $_.Target })) {
            foreach ($h in @($t.Hops | Select-Object -First 3)) { if ($h -and $h.IP -and $pub -and $h.Class -eq 'Public' -and ((("$($h.IP)" -split '\.')[0..2]) -join '.') -eq ((($pub -split '\.')[0..2]) -join '.')) { $cands += "$($h.IP)" } }
        }
        $rows = @()
        foreach ($ip in @($cands | Select-Object -Unique)) {
            $open = @(@(80, 443) | Where-Object { Test-TcpPort $ip $_ 1200 })
            $urls = @(); if ($open -contains 80) { $urls += "http://$ip/" }; if ($open -contains 443) { $urls += "https://$ip/" }
            $pages = @(); if ($urls.Count) { $pages = @(Get-HttpBannersBulk $urls 5000 4) }
            $hay = (@($pages | ForEach-Object { "$($_.Title) $($_.Server) $($_.BodySample) $($_.AuthRealm) $($_.CertSubject)" }) -join ' ')
            $looks = $null
            if ($hay -match 'DOCSIS|Cable Modem|Downstream|Upstream|Touchstone|SURFboard|Hitron|Ubee') { $looks = 'cable modem (DOCSIS)' }
            elseif ($hay -match '\bONT\b|GPON|Optical') { $looks = 'fiber terminal' }
            elseif ($hay -match 'VDSL|ADSL|\bDSL\b') { $looks = 'DSL modem' }
            elseif ($hay.Trim()) { $looks = 'ISP device (type not stated on its page)' }
            $rows += [pscustomobject]@{ Address = $ip; Role = $(if ($ip -eq '192.168.100.1') { 'Modem management address' } else { 'ISP gateway of the static block' }); OpenPorts = $open; LooksLike = $looks; Pages = $pages }
        }
        [ordered]@{ Targets = $rows }
    }
}

if ($EnableWindowsBuild -and $script:FullLanguage -and $sweepDevs.Count) {
    $Result['WindowsHosts'] = Invoke-Collector 'Windows versions (file-sharing handshake, no logon)' {
        $rows = @()
        foreach ($d in @($sweepDevs | Where-Object { @($_.OpenPorts) -contains 445 } | Select-Object -First 80)) {
            $n = Get-SmbNtlmInfo "$($d.IP)" 1500
            $rows += [pscustomobject]@{ IP = "$($d.IP)"; Mac = "$($d.Mac)"; ComputerName = $n.ComputerName; DnsName = $n.DnsName; Domain = $n.Domain; DnsDomain = $n.DnsDomain; OsVersion = $n.OsVersion; Build = $n.Build; Os = $n.Os; Error = $n.Error }
        }
        [ordered]@{ Count = $rows.Count; OsSummary = @($rows | Where-Object { $_.Os } | Group-Object Os | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }); Hosts = $rows }
    }
}

if ($EnableDnsTiming -and $script:FullLanguage -and $primaryAd) {
    $Result['DnsTiming'] = Invoke-Collector 'DNS lookup timing (site server and public resolvers)' {
        $servers = @()
        foreach ($s in @($primaryAd.DnsServers | Where-Object { Test-IPv4 $_ })) { $servers += , @("$s", 'Site DNS server') }
        if ($Gateway -and @($primaryAd.DnsServers) -notcontains $Gateway) { $servers += , @("$Gateway", 'Gateway') }
        $servers += , @('1.1.1.1', 'Public resolver (Cloudflare)'); $servers += , @('8.8.8.8', 'Public resolver (Google)')
        $names = @('outlook.office365.com', 'login.microsoftonline.com', 'teams.microsoft.com', 'www.microsoft.com', 'www.google.com', 'www.amazon.com', 'zoom.us', 'github.com', 'www.cloudflare.com', 'www.wikipedia.org')
        $rows = @()
        foreach ($sv in $servers) {
            $ms = @(); $answered = 0
            $u = New-Object Net.Sockets.UdpClient
            try {
                $u.Client.ReceiveTimeout = 1500; $u.Connect([string]$sv[0], 53)
                # Pass 1 warms the server's cache; pass 2 is timed, so it shows the round trip to the server itself.
                foreach ($pass in 1, 2) {
                    $i = 0
                    foreach ($nm in $names) {
                        $i++; $id = ($pass * 100) + $i
                        $q = New-DnsQuery -Names @($nm) -Type 1 -Id $id -Recurse
                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        try {
                            [void]$u.Send($q, $q.Length)
                            for ($k = 0; $k -lt 3; $k++) {
                                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                                $r = $u.Receive([ref]$ep)
                                if ($r -and $r.Length -ge 12 -and ((([int]$r[0] * 256) + [int]$r[1]) -eq $id)) { $answered++; if ($pass -eq 2) { $ms += [math]::Round($sw.Elapsed.TotalMilliseconds, 1) }; break }
                            }
                        } catch { }
                    }
                }
            } catch { } finally { try { $u.Close() } catch { } }
            $sorted = @($ms | Sort-Object)
            $rows += [pscustomobject]@{ Server = $sv[0]; Role = $sv[1]; Asked = $names.Count * 2; Answered = $answered; MedianMs = $(if ($sorted.Count) { $sorted[[int][math]::Floor($sorted.Count / 2)] } else { $null }); MaxMs = $(if ($sorted.Count) { $sorted[-1] } else { $null }) }
        }
        [ordered]@{ Servers = $rows }
    }
}

if ($EnableCloudCheck -and $script:FullLanguage) {
    $Result['Cloud'] = Invoke-Collector 'Microsoft 365, Teams media and NAT behaviour' {
        $trace = Start-IcmpJob -Kind Trace -Target 'outlook.office365.com' -MaxHops 15 -TimeoutMs 600 -Label 'trace outlook.office365.com'
        $rows = @()
        foreach ($hn in @('outlook.office365.com', 'login.microsoftonline.com', 'teams.microsoft.com', 'graph.microsoft.com')) {
            $row = [ordered]@{ Host = $hn; Address = $null; ConnectMs = $null; Samples = 0 }
            try {
                $addr = @([Net.Dns]::GetHostAddresses($hn) | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0]
                $row['Address'] = "$addr"; $ms = @()
                for ($k = 0; $k -lt 5; $k++) {
                    $c = New-Object Net.Sockets.TcpClient; $sw = [Diagnostics.Stopwatch]::StartNew()
                    try { if ($c.ConnectAsync($addr, 443).Wait(2500) -and $c.Connected) { $ms += [math]::Round($sw.Elapsed.TotalMilliseconds, 1) } } catch { } finally { $c.Close() }
                }
                $row['Samples'] = $ms.Count
                if ($ms.Count) { $row['ConnectMs'] = @($ms | Sort-Object)[[int][math]::Floor($ms.Count / 2)] }
            } catch { }
            $rows += [pscustomobject]$row
        }
        $stun = @(Get-StunMappings @(@('worldaz.tr.teams.microsoft.com', 3478), @('stun.cloudflare.com', 3478), @('stun.l.google.com', 19302)) 1500)
        $mapped = @($stun | Where-Object { $_.MappedPort } | ForEach-Object { $_.MappedPort } | Select-Object -Unique)
        $nat = if (-not $mapped.Count) { 'No STUN server answered: outbound UDP is blocked or filtered' } elseif ($mapped.Count -eq 1) { 'One public port per socket whatever the destination: calls and meetings can connect directly' } else { 'A different public port per destination (symmetric NAT): calls fall back to relays' }
        $ntp = [ordered]@{ Server = 'time.cloudflare.com'; Answered = $false; OffsetSec = $null }
        $u = New-Object Net.Sockets.UdpClient
        try {
            $u.Client.ReceiveTimeout = 1500; $u.Connect('time.cloudflare.com', 123)
            $q = New-Object byte[] 48; $q[0] = 0x1B
            [void]$u.Send($q, 48); $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); $r = $u.Receive([ref]$ep)
            if ($r -and $r.Length -ge 48) {
                $secs = ([double]$r[40] * 16777216) + ([double]$r[41] * 65536) + ([double]$r[42] * 256) + [double]$r[43]
                $srv = (New-Object DateTime(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddSeconds($secs)
                $ntp['Answered'] = $true; $ntp['OffsetSec'] = [math]::Round(($srv - [DateTime]::UtcNow).TotalSeconds, 1)
            }
        } catch { } finally { try { $u.Close() } catch { } }
        $hops = @(ConvertFrom-Tracert (Receive-NativeAsync $trace 60))
        [ordered]@{
            Microsoft365 = $rows; Stun = $stun; NatBehaviour = $nat; Ntp = $ntp
            TeamsMediaPortOpen = [bool](@($stun | Where-Object { $_.Server -like 'worldaz*' -and $_.Answered }).Count)
            OutlookPath = (@($hops | ForEach-Object { if ($_.IP) { "$($_.IP)($($_.AvgMs))" } else { '*' } }) -join ' > ')
            OutlookHops = @($hops | ForEach-Object { [pscustomobject]@{ Hop = $_.Hop; IP = $_.IP; AvgMs = $_.AvgMs; Class = $_.Class } })
        }
    }
}

if ($EnableVoiceSample -and $script:FullLanguage) {
    $Result['Voice'] = Invoke-Collector 'Voice-pace sample (50 packets per second for 20 s per target)' {
        $rows = @()
        $phones = if ($EnableDiscovery) { @(Get-Leads $Result | Where-Object Kind -eq 'PhoneSystem' | ForEach-Object Target) } else { @() }
        foreach ($t in @(@($phones) + @($VoiceTargets) | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 3)) {
            $ok = $false
            try { $pg = New-Object Net.NetworkInformation.Ping; $ok = ($pg.Send([string]$t, 1000).Status -eq 'Success'); $pg.Dispose() } catch { }
            if (-not $ok) { $rows += [pscustomobject]@{ Target = "$t"; Sent = 0; Note = 'does not answer ping, not sampled' }; continue }
            $rows += [pscustomobject](Measure-VoicePath ([string]$t) 20 50)
        }
        [ordered]@{ Samples = $rows }
    }
}

if ($EnablePrinterQuery -and $script:FullLanguage -and $sweepDevs.Count) {
    $Result['PrinterQuery'] = Invoke-Collector 'Printer details (IPP)' {
        $attrs = @('printer-make-and-model', 'printer-name', 'printer-info', 'printer-location', 'printer-firmware-string-version', 'printer-device-id', 'printer-uuid', 'printer-state', 'printer-state-reasons', 'printer-up-time', 'printer-impressions-completed', 'pages-per-minute', 'color-supported')
        $rows = @()
        foreach ($d in @($sweepDevs | Where-Object { @($_.OpenPorts) -contains 631 } | Select-Object -First 40)) {
            $ip = "$($d.IP)"; $got = $null
            foreach ($path in @('/ipp/print', '/ipp', '/')) {
                try {
                    $req = [Net.HttpWebRequest]::Create("http://${ip}:631$path")
                    $req.Method = 'POST'; $req.ContentType = 'application/ipp'; $req.Timeout = 3000; $req.ReadWriteTimeout = 3000; $req.KeepAlive = $false
                    $body = New-IppRequest "ipp://${ip}:631$path" $attrs
                    $req.ContentLength = $body.Length
                    $st = $req.GetRequestStream(); $st.Write($body, 0, $body.Length); $st.Close()
                    $resp = $req.GetResponse(); $msx = New-Object IO.MemoryStream
                    $resp.GetResponseStream().CopyTo($msx); $resp.Close()
                    $parsed = ConvertFrom-IppResponse $msx.ToArray()
                    if ($parsed.Contains('printer-make-and-model') -or $parsed.Contains('printer-name')) { $got = $parsed; break }
                } catch { }
            }
            if ($got) {
                $rows += [pscustomobject]@{ IP = $ip; MakeAndModel = $got['printer-make-and-model']; Name = $got['printer-name']; Info = $got['printer-info']; Location = $got['printer-location']; Firmware = (@($got['printer-firmware-string-version']) -join ', '); DeviceId = $got['printer-device-id']; Uuid = $got['printer-uuid']; State = $got['printer-state']; StateReasons = (@($got['printer-state-reasons']) -join ', '); UpTimeSec = $got['printer-up-time']; PagesPrinted = $got['printer-impressions-completed']; PagesPerMinute = $got['pages-per-minute']; Color = $got['color-supported'] }
            } else { $rows += [pscustomobject]@{ IP = $ip; MakeAndModel = $null; Name = $null; Note = 'port 631 open but no IPP answer' } }
        }
        [ordered]@{ Asked = $rows.Count; Answered = @($rows | Where-Object { $_.MakeAndModel -or $_.Name }).Count; Printers = $rows }
    }
}

if ($EnableCameraQuery -and $script:FullLanguage -and $sweepDevs.Count) {
    $Result['CameraQuery'] = Invoke-Collector 'Camera details (RTSP)' {
        $rows = @()
        foreach ($d in @($sweepDevs | Where-Object { @($_.OpenPorts) -contains 554 } | Select-Object -First 80)) {
            $ip = "$($d.IP)"; $row = [ordered]@{ IP = $ip; Status = $null; Server = $null; Methods = $null }
            $c = New-Object Net.Sockets.TcpClient
            try {
                if ($c.ConnectAsync($ip, 554).Wait(1200) -and $c.Connected) {
                    $ns = $c.GetStream(); $ns.ReadTimeout = 1500; $ns.WriteTimeout = 1500
                    $q = [Text.Encoding]::ASCII.GetBytes("OPTIONS rtsp://${ip}:554/ RTSP/1.0`r`nCSeq: 1`r`nUser-Agent: survey`r`n`r`n")
                    $ns.Write($q, 0, $q.Length)
                    $buf = New-Object byte[] 1024; $n = $ns.Read($buf, 0, $buf.Length)
                    if ($n -gt 0) {
                        $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
                        $row['Status'] = (($txt -split "`r?`n")[0] -replace '[^\x20-\x7E]', '').Trim()
                        if ($txt -match '(?im)^Server:\s*(.+?)\s*$') { $row['Server'] = ($matches[1] -replace '[^\x20-\x7E]', '') }
                        if ($txt -match '(?im)^Public:\s*(.+?)\s*$') { $row['Methods'] = ($matches[1] -replace '[^\x20-\x7E]', '') }
                    }
                }
            } catch { } finally { try { $c.Close() } catch { } }
            $rows += [pscustomobject]$row
        }
        [ordered]@{ Asked = $rows.Count; Answered = @($rows | Where-Object { $_.Status }).Count; ServerSummary = @($rows | Where-Object { $_.Server } | Group-Object Server | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }); Cameras = $rows }
    }
}

if ($EnableOutboundCheck -and $script:FullLanguage) {
    $Result['Outbound'] = Invoke-Collector 'Outbound ports and DNS filtering' {
        $out = [ordered]@{ TestHost = 'portquiz.net'; Reliable = $false; PortsTried = @(); Open = @(); Blocked = @(); DnsTests = @(); FilteringSeen = $false; Note = $null }
        $ports = @(21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1194, 1723, 3389, 5060, 5061, 8080, 8443)
        try {
            $qa = @([Net.Dns]::GetHostAddresses('portquiz.net') | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0]
            # Four at a time with a pause: the test host drops connections that arrive all at once.
            $openAll = @()
            for ($bi = 0; $bi -lt $ports.Count; $bi += 4) {
                $chunk = @($ports[$bi..([math]::Min($bi + 3, $ports.Count - 1))])
                $openMap = Test-TcpPortsBulk @("$qa") $chunk 3000
                $openAll += @($openMap["$qa"] | Where-Object { $null -ne $_ })
                Start-Sleep -Milliseconds 300
            }
            # A second look, one at a time, at the first few that did not connect.
            foreach ($pp in @($ports | Where-Object { $openAll -notcontains $_ } | Select-Object -First 8)) { if (Test-TcpPort "$qa" $pp 3000) { $openAll += $pp } }
            $out['PortsTried'] = $ports; $out['Open'] = @($openAll | Sort-Object -Unique); $out['Blocked'] = @($ports | Where-Object { $openAll -notcontains $_ })
            $out['Reliable'] = ($openAll -contains 443 -or $openAll -contains 80)
            if (-not $out['Reliable']) { $out['Note'] = 'the test host did not accept web connections, so the port results prove nothing' }
        } catch { $out['Note'] = "port test host not reachable: $($_.Exception.Message)" }
        # Test names that DNS security filters block. The site's answer is compared with a public resolver's.
        $ask = {
            param([string]$server, [string]$name)
            $u = New-Object Net.Sockets.UdpClient
            try {
                $u.Client.ReceiveTimeout = 1500; $u.Connect($server, 53)
                $q = New-DnsQuery -Names @($name) -Type 1 -Id 4242 -Recurse
                [void]$u.Send($q, $q.Length); $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); $r = $u.Receive([ref]$ep)
                $ips = @(ConvertFrom-DnsMessage $r | Where-Object { $_.Type -eq 1 } | ForEach-Object { $_.Data })
                return [pscustomobject]@{ Rcode = ([int]$r[3] -band 15); Ips = $ips }
            } catch { return $null } finally { try { $u.Close() } catch { } }
        }
        $siteDns = @($primaryAd.DnsServers | Where-Object { Test-IPv4 $_ })[0]
        if ($siteDns) {
            foreach ($nm in @('internetbadguys.com', 'examplemalwaredomain.com', 'malware.testcategory.com', 'www.examplebotnetdomain.com')) {
                $a = & $ask "$siteDns" $nm; $b = & $ask '1.1.1.1' $nm
                $siteIps = if ($a) { @($a.Ips) } else { @() }
                $sink = @($siteIps | Where-Object { $_ -match '^(0\.0\.0\.0|127\.|146\.112\.61\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' }).Count -gt 0
                $differs = ($a -and $b -and $a.Rcode -ne $b.Rcode) -or $sink
                if ($differs) { $out['FilteringSeen'] = $true }
                $out['DnsTests'] += [pscustomobject]@{ Name = $nm; SiteAnswer = $(if (-not $a) { 'no answer' } elseif ($siteIps.Count) { $siteIps -join ', ' } else { "none (code $($a.Rcode))" }); PublicAnswer = $(if (-not $b) { 'no answer' } elseif (@($b.Ips).Count) { @($b.Ips) -join ', ' } else { "none (code $($b.Rcode))" }); Filtered = [bool]$differs }
            }
        }
        $out
    }
}

if ($EnableGatewayServices -and $script:FullLanguage -and $Gateway -and $srcIp) {
    $Result['GatewayServices'] = Invoke-Collector 'Gateway port-mapping services (UPnP, NAT-PMP)' {
        $out = [ordered]@{ NatPmp = [ordered]@{ Answered = $false; ExternalIp = $null }; Upnp = [ordered]@{ Found = $false; Location = $null; ExternalIp = $null; Mappings = @() } }
        $x = @(Invoke-UdpProbe @(@{ Address = "$Gateway"; Port = 5351; Bytes = [byte[]](0, 0) }) $srcIp 0 1500) | Where-Object { $_.IP -eq "$Gateway" -and $_.Data.Length -ge 12 -and [int]$_.Data[1] -eq 128 } | Select-Object -First 1
        if ($x) { $out['NatPmp']['Answered'] = $true; if (([int]$x.Data[2] * 256) + [int]$x.Data[3] -eq 0) { $out['NatPmp']['ExternalIp'] = ConvertTo-IpText $x.Data 8 } }
        $msg = [Text.Encoding]::ASCII.GetBytes("M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n")
        $loc = $null
        foreach ($rp in @(Invoke-UdpProbe @(@{ Address = '239.255.255.250'; Port = 1900; Bytes = $msg }, @{ Address = '239.255.255.250'; Port = 1900; Bytes = $msg }) $srcIp 0 3000)) {
            $txt = [Text.Encoding]::ASCII.GetString($rp.Data)
            if ($txt -match '(?im)^LOCATION:\s*(\S+)') { $loc = $matches[1]; break }
        }
        if ($loc) {
            $out['Upnp']['Found'] = $true; $out['Upnp']['Location'] = $loc
            try {
                $desc = (Invoke-WebRequest -Uri $loc -UseBasicParsing -TimeoutSec 4).Content
                if ($desc -match '(?s)<serviceType>(urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:\d)</serviceType>.*?<controlURL>([^<]+)</controlURL>') {
                    $svcType = $matches[1]; $ctl = ([Uri]::new([Uri]$loc, $matches[2])).AbsoluteUri
                    $soap = {
                        param([string]$action, [string]$argsXml)
                        $body = "<?xml version=`"1.0`"?><s:Envelope xmlns:s=`"http://schemas.xmlsoap.org/soap/envelope/`" s:encodingStyle=`"http://schemas.xmlsoap.org/soap/encoding/`"><s:Body><u:$action xmlns:u=`"$svcType`">$argsXml</u:$action></s:Body></s:Envelope>"
                        try { return (Invoke-WebRequest -Uri $ctl -Method Post -Body $body -ContentType 'text/xml; charset="utf-8"' -Headers @{ SOAPAction = "`"$svcType#$action`"" } -UseBasicParsing -TimeoutSec 4).Content } catch { return $null }
                    }
                    $e = & $soap 'GetExternalIPAddress' ''
                    if ($e -and $e -match '<NewExternalIPAddress>([^<]*)<') { $out['Upnp']['ExternalIp'] = $matches[1] }
                    for ($i = 0; $i -lt 40; $i++) {
                        $m = & $soap 'GetGenericPortMappingEntry' "<NewPortMappingIndex>$i</NewPortMappingIndex>"
                        if (-not $m -or $m -notmatch '<NewExternalPort>') { break }
                        $f = { param($tag) if ($m -match "<$tag>([^<]*)<") { $matches[1] } else { $null } }
                        $out['Upnp']['Mappings'] += [pscustomobject]@{ ExternalPort = (& $f 'NewExternalPort'); Protocol = (& $f 'NewProtocol'); InternalClient = (& $f 'NewInternalClient'); InternalPort = (& $f 'NewInternalPort'); Description = (& $f 'NewPortMappingDescription'); Enabled = (& $f 'NewEnabled') }
                    }
                }
            } catch { $out['Upnp']['Error'] = $_.Exception.Message }
        }
        $out
    }
}

$tunnelTargets = @(@($TunnelServers) + @(Get-Leads $Result | Where-Object Kind -eq 'Server' | ForEach-Object Target) | Where-Object { $_ } | Select-Object -Unique)
if ($EnableTunnelReach -and $script:FullLanguage -and $srcIp -and $tunnelTargets.Count) {
    $Result['TunnelReach'] = Invoke-Collector 'Servers across the tunnel reachable from this port' {
        $mask = "$(@($primaryAd.SubnetMask)[0])"; if (-not (Test-IPv4 $mask)) { $mask = '255.255.255.0' }
        $targets = @($tunnelTargets | Where-Object { (Test-IPv4 $_) -and -not (Test-SameSubnet $_ $srcIp $mask) } | Select-Object -Unique | Select-Object -First 16)
        if (-not $targets.Count) { throw 'No servers outside this subnet, listed or found' }
        $openMap = Test-TcpPortsBulk $targets $SweepPorts 2500
        $names = @{}; foreach ($rn in @(Get-Val $Result['DnsDiscovery'] 'ReverseNames')) { if ($rn) { $names["$($rn.IP)"] = "$($rn.Name)" } }
        $rows = @()
        foreach ($t in $targets) {
            $op = @($openMap[$t] | Sort-Object)
            $rows += [pscustomobject]@{ IP = $t; Name = $names[$t]; OpenPorts = $op; Role = (Get-DeviceRole ([int[]]$op)) }
        }
        [ordered]@{ PortsTried = $SweepPorts; Servers = $rows }
    }
}

if ($EnableSnmp -and $script:FullLanguage -and $SnmpCommunity -and $srcIp -and $sweepDevs.Count) {
    $Result['Snmp'] = Invoke-Collector "SNMP read with community '$SnmpCommunity'" {
        $sysOids = @('1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.1.4.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0')
        $probe = New-SnmpRequest 0xA0 $SnmpCommunity 7001 $sysOids
        $snmpIps = @(@($sweepDevs | Select-Object -First 400 | ForEach-Object { "$($_.IP)" }) + @(Get-Leads $Result | Where-Object Kind -eq 'Switch' | ForEach-Object Target) | Where-Object { $_ } | Select-Object -Unique)
        $sends = @($snmpIps | ForEach-Object { @{ Address = "$_"; Port = 161; Bytes = $probe } })
        $answers = @{}
        foreach ($x in @(Invoke-UdpProbe $sends $srcIp 0 3000)) {
            $h = @{}; foreach ($vb in @(ConvertFrom-SnmpResponse $x.Data)) { if ($vb.Type -lt 0x80 -and $null -ne $vb.Value) { $h["$($vb.Oid)"] = $vb.Value } }
            if ($h.Count) { $answers[$x.IP] = $h }
        }
        $byIp = @{}; foreach ($d in $sweepDevs) { $byIp["$($d.IP)"] = $d }
        $col = { param($ip, $oid, $max) $t = @{}; foreach ($r in @(Invoke-SnmpWalk $ip $SnmpCommunity $oid $max 1500)) { $t["$($r.Index)"] = $r.Value }; return $t }
        $rows = @(); $budget = [Diagnostics.Stopwatch]::StartNew()
        foreach ($ip in @($answers.Keys | Sort-Object { try { [version]$_ } catch { [version]'0.0' } })) {
            $sys = $answers[$ip]
            $ticks = $sys['1.3.6.1.2.1.1.3.0']
            $row = [ordered]@{ IP = $ip; SysName = "$($sys['1.3.6.1.2.1.1.5.0'])"; SysDescr = "$($sys['1.3.6.1.2.1.1.1.0'])"; SysLocation = "$($sys['1.3.6.1.2.1.1.6.0'])"; SysContact = "$($sys['1.3.6.1.2.1.1.4.0'])"; SysObjectId = "$($sys['1.3.6.1.2.1.1.2.0'])"; UptimeDays = $(if ($null -ne $ticks) { [math]::Round([double]$ticks / 8640000, 1) } else { $null }); Model = $null; Serial = $null; Software = $null; PortSummary = $null; Ports = @(); MacTable = @(); LldpNeighbors = @(); PoeWattsUsed = $null; PoeWattsBudget = $null; Printer = $null; Note = $null }
            if ($budget.Elapsed.TotalSeconds -gt 150) { $row['Note'] = 'time budget reached: system details only'; $rows += [pscustomobject]$row; continue }
            try {
                # Interfaces: name, type, up or down, speed, description
                $ifName = & $col $ip '1.3.6.1.2.1.31.1.1.1.1' 300
                if (-not $ifName.Count) { $ifName = & $col $ip '1.3.6.1.2.1.2.2.1.2' 300 }
                if ($ifName.Count) {
                    $ifType = & $col $ip '1.3.6.1.2.1.2.2.1.3' 300; $ifOper = & $col $ip '1.3.6.1.2.1.2.2.1.8' 300
                    $ifHigh = & $col $ip '1.3.6.1.2.1.31.1.1.1.15' 300; $ifSpeed = @{}; if (-not $ifHigh.Count) { $ifSpeed = & $col $ip '1.3.6.1.2.1.2.2.1.5' 300 }
                    $ifAlias = & $col $ip '1.3.6.1.2.1.31.1.1.1.18' 300
                    $ports = @()
                    foreach ($ix in @($ifName.Keys | Sort-Object { [int]$_ })) {
                        if ($ifType.Count -and "$($ifType[$ix])" -ne '6') { continue }
                        $mbps = if ($ifHigh.ContainsKey($ix)) { [int64]$ifHigh[$ix] } elseif ($ifSpeed.ContainsKey($ix)) { [int64]([double]$ifSpeed[$ix] / 1000000) } else { $null }
                        $ports += [pscustomobject]@{ IfIndex = [int]$ix; Name = "$($ifName[$ix])"; Up = ("$($ifOper[$ix])" -eq '1'); SpeedMbps = $mbps; Description = "$($ifAlias[$ix])"; Macs = 0 }
                    }
                    $row['Ports'] = $ports
                    $up = @($ports | Where-Object { $_.Up })
                    $row['PortSummary'] = ('{0} Ethernet ports, {1} up ({2})' -f $ports.Count, $up.Count, ((@($up | Group-Object SpeedMbps | Sort-Object { [int64]$_.Name } -Descending | ForEach-Object { '{0} at {1} Mbps' -f $_.Count, $_.Name })) -join ', '))
                    if ($ports.Count -ge 5) {
                        # Which MAC address is on which port (the switch's forwarding table)
                        $bp = & $col $ip '1.3.6.1.2.1.17.1.4.1.2' 300
                        $fdb = @(Invoke-SnmpWalk $ip $SnmpCommunity '1.3.6.1.2.1.17.7.1.2.2.1.2' 1500 1500)
                        $qb = $true
                        if (-not $fdb.Count) { $fdb = @(Invoke-SnmpWalk $ip $SnmpCommunity '1.3.6.1.2.1.17.4.3.1.2' 1500 1500); $qb = $false }
                        $mt = @()
                        foreach ($r in $fdb) {
                            $parts = @("$($r.Index)" -split '\.')
                            if ($parts.Count -lt 6) { continue }
                            $macParts = $parts[($parts.Count - 6)..($parts.Count - 1)]
                            $mac = (@($macParts | ForEach-Object { '{0:X2}' -f [int]$_ }) -join '-')
                            $vlan = if ($qb -and $parts.Count -ge 7) { [int]$parts[0] } else { $null }
                            $ifx = if ($bp.ContainsKey("$($r.Value)")) { [int]$bp["$($r.Value)"] } else { [int]$r.Value }
                            $pn = ($ports | Where-Object { $_.IfIndex -eq $ifx } | Select-Object -First 1)
                            if ($pn) { $pn.Macs++ }
                            $mt += [pscustomobject]@{ Mac = $mac; Vlan = $vlan; IfIndex = $ifx; Port = $(if ($pn) { $pn.Name } else { "$ifx" }) }
                        }
                        $row['MacTable'] = $mt
                        $ln = & $col $ip '1.0.8802.1.1.2.1.4.1.1.9' 100
                        if ($ln.Count) {
                            $lp = & $col $ip '1.0.8802.1.1.2.1.4.1.1.8' 100; $ld = & $col $ip '1.0.8802.1.1.2.1.4.1.1.10' 100
                            $row['LldpNeighbors'] = @($ln.Keys | ForEach-Object { $pp = @($_ -split '\.'); [pscustomobject]@{ LocalPort = $(if ($pp.Count -ge 2) { $pp[1] } else { $_ }); Name = "$($ln[$_])"; RemotePort = "$($lp[$_])"; Description = "$($ld[$_])" } })
                        }
                        $pw = & $col $ip '1.3.6.1.2.1.105.1.3.1.1.4' 8; $pb = & $col $ip '1.3.6.1.2.1.105.1.3.1.1.2' 8
                        if ($pw.Count) { $row['PoeWattsUsed'] = ($pw.Values | Measure-Object -Sum).Sum; $row['PoeWattsBudget'] = ($pb.Values | Measure-Object -Sum).Sum }
                    }
                    $em = & $col $ip '1.3.6.1.2.1.47.1.1.1.1.13' 12
                    if ($em.Count) {
                        $k = @($em.Keys | Sort-Object { [int]$_ } | Where-Object { "$($em[$_])".Trim() })[0]
                        if ($k) { $row['Model'] = "$($em[$k])"; $one = Get-SnmpValues $ip $SnmpCommunity @("1.3.6.1.2.1.47.1.1.1.1.11.$k", "1.3.6.1.2.1.47.1.1.1.1.10.$k") 1500; if ($one) { $row['Serial'] = "$($one["1.3.6.1.2.1.47.1.1.1.1.11.$k"])"; $row['Software'] = "$($one["1.3.6.1.2.1.47.1.1.1.1.10.$k"])" } }
                    }
                }
                # Printers: serial number, lifetime page count, supplies
                $d = $byIp[$ip]
                if ($d -and (@($d.OpenPorts) -contains 9100 -or @($d.OpenPorts) -contains 515 -or @($d.OpenPorts) -contains 631 -or "$($row['SysDescr'])" -match 'print|laserjet|mfp|copier|e-studio|lexmark|brother|ricoh|canon|xerox|kyocera')) {
                    $pv = Get-SnmpValues $ip $SnmpCommunity @('1.3.6.1.2.1.43.5.1.1.17.1', '1.3.6.1.2.1.43.10.2.1.4.1.1', '1.3.6.1.2.1.25.3.2.1.3.1') 1500
                    $sd = & $col $ip '1.3.6.1.2.1.43.11.1.1.6' 16; $sl = & $col $ip '1.3.6.1.2.1.43.11.1.1.9' 16; $sm = & $col $ip '1.3.6.1.2.1.43.11.1.1.8' 16
                    $supplies = @($sd.Keys | Sort-Object | ForEach-Object { $lv = $sl[$_]; $mx = $sm[$_]; $pct = if ($null -ne $lv -and $mx -and [double]$mx -gt 0 -and [double]$lv -ge 0) { [int](100 * [double]$lv / [double]$mx) } else { $null }; [pscustomobject]@{ Supply = "$($sd[$_])"; Percent = $pct } })
                    if (($pv -and $pv.Count) -or $supplies.Count) { $row['Printer'] = [ordered]@{ Model = $(if ($pv) { "$($pv['1.3.6.1.2.1.25.3.2.1.3.1'])" }); Serial = $(if ($pv) { "$($pv['1.3.6.1.2.1.43.5.1.1.17.1'])" }); PageCount = $(if ($pv) { $pv['1.3.6.1.2.1.43.10.2.1.4.1.1'] }); Supplies = $supplies } }
                }
                # Routers and layer 3 switches: their own addresses (a public one is the WAN side), the ARP table
                # (the MAC of every device they talk to, on every VLAN) and the routes. The site gateway is asked
                # even if it does not say it forwards.
                $rtab = Get-RouterTables $ip $SnmpCommunity ($ip -eq "$Gateway")
                if ($rtab) { $row['Router'] = $rtab }
                # UPS: battery state, charge, runtime and load (UPS-MIB, else the APC MIB on APC cards)
                $upsStd = Get-SnmpValues $ip $SnmpCommunity @((Get-UpsOidMap).Values) 1500
                $upsApc = $null
                if (-not ($upsStd -and $upsStd.Count) -and ("$($row['SysObjectId'])" -like '1.3.6.1.4.1.318.*' -or "$($row['SysDescr'])" -match 'APC|UPS|PowerChute|Network Management Card')) {
                    $upsApc = Get-SnmpValues $ip $SnmpCommunity @((Get-UpsOidMap -Apc).Values) 1500
                }
                $ups = ConvertTo-UpsStatus $upsStd $upsApc
                if ($ups) { $row['Ups'] = $ups }
            } catch { $row['Note'] = "read stopped: $($_.Exception.Message)" }
            $rows += [pscustomobject]$row
        }
        $routers = @($rows | Where-Object { $_.Router })
        [ordered]@{
            Community = $SnmpCommunity; Asked = $sends.Count; Answered = $rows.Count
            Routers = $routers.Count; ArpEntries = (@($routers | ForEach-Object { @($_.Router.Arp).Count }) | Measure-Object -Sum).Sum
            WanAddresses = @($routers | ForEach-Object { @($_.Router.WanAddresses) } | Where-Object { $_ } | Sort-Object -Unique)
            Ups = @($rows | Where-Object { $_.Ups }).Count
            Devices = $rows
        }
    }
    # Devices found without a MAC (across a router) get it from a router's ARP table.
    $arpMap = @{}
    foreach ($sd in @(Get-Val $Result['Snmp'] 'Devices')) { foreach ($a in @(Get-Prop $sd 'Router', 'Arp')) { if ($a -and -not $arpMap.ContainsKey("$($a.IP)")) { $arpMap["$($a.IP)"] = "$($a.Mac)" } } }
    if ($arpMap.Count) {
        foreach ($d in @(Get-Val $Result['Identify'] 'Devices')) {
            if ($d -and -not $d.Mac -and $arpMap.ContainsKey("$($d.IP)")) { $d.Mac = $arpMap["$($d.IP)"]; $d.MacSource = 'router ARP (SNMP)'; $d.MacVendor = Get-MacVendor $d.Mac }
        }
        foreach ($d in @(Get-Val $Result['RemoteSweep'] 'Devices')) {
            if ($d -and -not $d.Mac -and $arpMap.ContainsKey("$($d.IP)")) { $d.Mac = $arpMap["$($d.IP)"]; $d.Vendor = Get-MacVendor $d.Mac }
        }
    }
}
