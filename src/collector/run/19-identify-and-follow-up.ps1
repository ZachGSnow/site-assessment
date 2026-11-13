# =====================================================================
# PHASE 6d: name what was found. Vendor discovery, multicast discovery, one identify pass over the
# devices the sweep found, questions to the site's own DNS server, the other offices, and who the
# public address is registered to. Same rule as the sweep: the core data is already saved, every
# step stands on its own, and every raw answer is kept so it can be re-read later.
# =====================================================================
$srcIp = Get-Val $Result['Network'] 'SourceIp'

if ($EnableVendorDiscovery -and $script:FullLanguage -and $srcIp) {
    $Result['VendorDiscovery'] = Invoke-Collector 'Vendor discovery (Ubiquiti, MikroTik, Netgear)' {
        $devs = @{}
        foreach ($d in @(Send-VendorDiscovery $srcIp 2500)) { if ($d) { $devs["$($d.Protocol)|$($d.Mac)"] = $d } }
        foreach ($d in @(Get-Val $Result['Capture'] 'VendorAnnouncements')) { if ($d) { $k = "$($d.Protocol)|$($d.Mac)"; if (-not $devs.ContainsKey($k)) { $devs[$k] = $d } } }
        $list = @($devs.Values | Sort-Object { try { [version]"$($_.IP)" } catch { [version]'0.0' } })
        [ordered]@{
            DeviceCount = $list.Count
            Devices = $list
            ModelSummary = @($list | Group-Object { ('{0} {1}' -f ("$($_.Protocol)" -replace ' discovery$', ''), $(if ($_.ModelFull) { $_.ModelFull } else { $_.Model })).Trim() } | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            Note = $(if ($list.Count -eq 0) { 'Nothing answered: no Ubiquiti, MikroTik or Netgear gear on this VLAN, discovery turned off on it, or the firewall on this PC dropped the answers.' })
        }
    }
}

if ($EnableMulticastDiscovery -and $script:FullLanguage -and $srcIp) {
    $Result['Multicast'] = Invoke-Collector 'mDNS and WS-Discovery (printers, cameras, Apple and Google devices)' {
        $svc = @('_services._dns-sd._udp.local', '_device-info._tcp.local', '_ipp._tcp.local', '_ipps._tcp.local', '_printer._tcp.local', '_pdl-datastream._tcp.local', '_scanner._tcp.local', '_uscan._tcp.local', '_http._tcp.local', '_https._tcp.local', '_airplay._tcp.local', '_raop._tcp.local', '_googlecast._tcp.local', '_workstation._tcp.local', '_smb._tcp.local', '_ssh._tcp.local', '_axis-video._tcp.local', '_hap._tcp.local', '_sip._udp.local')
        $sends = @()
        for ($i = 0; $i -lt $svc.Count; $i += 5) { $sends += @{ Address = '224.0.0.251'; Port = 5353; Bytes = (New-DnsQuery -Names @($svc[$i..([math]::Min($i + 4, $svc.Count - 1))]) -Type 12) } }
        $md = @{}
        foreach ($x in @(Invoke-UdpProbe $sends $srcIp 0 3000)) {
            if (-not $md.ContainsKey($x.IP)) { $md[$x.IP] = [ordered]@{ IP = $x.IP; Names = @(); Services = @(); Text = @() } }
            $e = $md[$x.IP]
            foreach ($rr in @(ConvertFrom-DnsMessage $x.Data)) {
                if ($rr.Type -eq 12) {
                    if ($rr.Name -like '_services._dns-sd*') { if ($e['Services'] -notcontains $rr.Data) { $e['Services'] += $rr.Data } }
                    else {
                        $sn = ($rr.Name -replace '\.local\.?$', ''); if ($e['Services'] -notcontains $sn) { $e['Services'] += $sn }
                        $nm = ($rr.Data -replace '\._[A-Za-z0-9-]+\._(tcp|udp)\.local\.?$', ''); if ($nm -and $e['Names'] -notcontains $nm) { $e['Names'] += $nm }
                    }
                }
                elseif ($rr.Type -eq 33) { $nm = ($rr.Data -replace '\.local\.?$', ''); if ($nm -and $e['Names'] -notcontains $nm) { $e['Names'] += $nm } }
                elseif ($rr.Type -eq 16 -and $rr.Data) { if ($e['Text'] -notcontains $rr.Data -and @($e['Text']).Count -lt 6) { $e['Text'] += $rr.Data } }
            }
        }
        $probe = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:' + [Guid]::NewGuid().ToString() + '</wsa:MessageID></soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>'
        $pb = [Text.Encoding]::UTF8.GetBytes($probe)
        $ws = @{}
        foreach ($x in @(Invoke-UdpProbe @(@{ Address = '239.255.255.250'; Port = 3702; Bytes = $pb }, @{ Address = '239.255.255.250'; Port = 3702; Bytes = $pb }) $srcIp 0 3000)) {
            if ($ws.ContainsKey($x.IP)) { continue }
            $txt = [Text.Encoding]::UTF8.GetString($x.Data)
            $types = if ($txt -match '<[^>/]*Types[^>]*>([^<]*)<') { $matches[1].Trim() } else { '' }
            $scopes = if ($txt -match '<[^>/]*Scopes[^>]*>([^<]*)<') { $matches[1].Trim() } else { '' }
            $xaddr = if ($txt -match '<[^>/]*XAddrs[^>]*>([^<]*)<') { $matches[1].Trim() } else { $null }
            $name = if ($scopes -match 'onvif://www\.onvif\.org/name/(\S+)') { [Uri]::UnescapeDataString($matches[1]) } else { $null }
            $hw = if ($scopes -match 'onvif://www\.onvif\.org/hardware/(\S+)') { [Uri]::UnescapeDataString($matches[1]) } else { $null }
            $ws[$x.IP] = [pscustomobject]@{ IP = $x.IP; Types = ($types -replace '[A-Za-z0-9]+:', ''); Name = $name; Hardware = $hw; XAddrs = $xaddr; Scopes = $(if ($scopes.Length -gt 400) { $scopes.Substring(0, 400) } else { $scopes }) }
        }
        [ordered]@{ Mdns = @($md.Values | ForEach-Object { [pscustomobject]$_ }); Wsd = @($ws.Values) }
    }
}

if ($EnableDeviceIdentify -and $script:FullLanguage -and $srcIp) {
    $Result['Identify'] = Invoke-Collector 'Identify devices (web pages, banners, phone models, Windows names)' {
        $sweepDevs = @(@(Get-Val $Result['SubnetSweep'] 'Devices') + @(Get-Val $Result['RemoteSweep'] 'Devices') | Where-Object { $_ } | Select-Object -First $IdentifyMaxDevices)
        if (-not $sweepDevs.Count) { throw 'No devices from the subnet sweep to identify' }
        $has = { param($d, $port) @($d.OpenPorts) -contains $port }
        # What each device already said in the discovery steps, by address or MAC.
        $disc = @{}; $discMac = @{}
        foreach ($d in @(Get-Val $Result['VendorDiscovery'] 'Devices')) { if ($d) { if ($d.IP) { $disc["$($d.IP)"] = $d }; if ($d.Mac) { $discMac["$($d.Mac)"] = $d } } }
        $ssdp = @{}; foreach ($d in @(Get-Val $Result['Ssdp'] 'Devices')) { if ($d) { $ssdp["$($d.IP)"] = $d } }
        $mdns = @{}; foreach ($d in @(Get-Val $Result['Multicast'] 'Mdns')) { if ($d) { $mdns["$($d.IP)"] = $d } }
        $wsd = @{}; foreach ($d in @(Get-Val $Result['Multicast'] 'Wsd')) { if ($d) { $wsd["$($d.IP)"] = $d } }
        $dhcpClass = @{}; foreach ($d in @(Get-Val $Result['Capture'] 'DhcpClients')) { if ($d -and ($d.VendorClass -or $d.Hostname)) { $dhcpClass["$($d.Mac)"] = ("{0} {1}" -f $d.VendorClass, $d.Hostname).Trim() } }
        $neigh = @{}
        foreach ($n in @(Get-Val $Result['Capture'] 'Cdp')) { if ($n) { $neigh["$($n.SenderMac)"] = ("CDP {0} {1} {2}" -f $n.DeviceId, $n.Platform, $n.Software).Trim() } }
        foreach ($n in @(Get-Val $Result['Capture'] 'Lldp')) { if ($n) { $neigh["$($n.SenderMac)"] = ("LLDP {0} {1} {2} {3}" -f $n.SystemName, $n.SystemDescription, $n.MedManufacturer, $n.MedModel).Trim() } }

        Write-Step '  reading web pages'
        $urls = @()
        foreach ($d in $sweepDevs) {
            foreach ($pp in @(@(80, 'http', ''), @(443, 'https', ''), @(8080, 'http', ':8080'), @(8443, 'https', ':8443'))) { if (& $has $d $pp[0]) { $urls += ('{0}://{1}{2}/' -f $pp[1], $d.IP, $pp[2]) } }
        }
        $web = @{}
        foreach ($b in @(Get-HttpBannersBulk $urls 5000 32)) { if (-not $b) { continue }; $ipk = ([Uri]"$($b.Url)").Host; if (-not $web.ContainsKey($ipk)) { $web[$ipk] = @() }; $web[$ipk] += $b }
        Write-Step '  reading SSH and FTP banners, asking phones for their model'
        $ssh = Get-TcpBannersBulk @($sweepDevs | Where-Object { & $has $_ 22 } | ForEach-Object { "$($_.IP)" }) 22 2000
        $ftp = Get-TcpBannersBulk @($sweepDevs | Where-Object { & $has $_ 21 } | ForEach-Object { "$($_.IP)" }) 21 2000
        $sip = @{}
        $sipSends = @()
        foreach ($d in @($sweepDevs | Where-Object { (& $has $_ 5060) -or (& $has $_ 5061) -or "$($_.Vendor)" -match 'Polycom|Yealink|Grandstream|Mitel|Avaya|snom|Fanvil|Obihai' })) {
            $ip = "$($d.IP)"; $tag = Get-Random -Minimum 100000 -Maximum 999999
            $msg = "OPTIONS sip:$ip SIP/2.0`r`nVia: SIP/2.0/UDP ${srcIp}:5060;branch=z9hG4bK$tag;rport`r`nMax-Forwards: 70`r`nFrom: <sip:survey@$srcIp>;tag=$tag`r`nTo: <sip:$ip>`r`nCall-ID: $tag@$srcIp`r`nCSeq: 1 OPTIONS`r`nContact: <sip:survey@${srcIp}:5060>`r`nAccept: application/sdp`r`nContent-Length: 0`r`n`r`n"
            $sipSends += @{ Address = $ip; Port = 5060; Bytes = [Text.Encoding]::ASCII.GetBytes($msg) }
        }
        if ($sipSends.Count) {
            foreach ($x in @(Invoke-UdpProbe $sipSends $srcIp 0 2500)) {
                $txt = [Text.Encoding]::ASCII.GetString($x.Data)
                if (-not $sip.ContainsKey($x.IP) -and $txt -match '(?im)^(?:User-Agent|Server):\s*(.+?)\s*$') { $sip[$x.IP] = ($matches[1] -replace '[^\x20-\x7E]', '') }
            }
        }
        Write-Step '  asking Windows machines for their names'
        $nbq = New-Object byte[] 50
        $nbq[0] = 0x53; $nbq[1] = 0x41; $nbq[5] = 1; $nbq[12] = 0x20; $nbq[13] = 0x43; $nbq[14] = 0x4B
        for ($i = 15; $i -le 44; $i++) { $nbq[$i] = 0x41 }
        $nbq[47] = 0x21; $nbq[49] = 1
        $nbSends = @($sweepDevs | Where-Object { (& $has $_ 445) -or (& $has $_ 139) -or (& $has $_ 135) -or (& $has $_ 3389) } | ForEach-Object { @{ Address = "$($_.IP)"; Port = 137; Bytes = $nbq } })
        $nbns = @{}
        if ($nbSends.Count) { foreach ($x in @(Invoke-UdpProbe $nbSends $srcIp 0 2000)) { $r = ConvertFrom-NbnsStatus $x.Data; if ($r) { $nbns[$x.IP] = $r } } }
        $smb = @{}; foreach ($d in @($sweepDevs | Where-Object { & $has $_ 445 } | Select-Object -First 60)) { $smb["$($d.IP)"] = Get-SmbInfo "$($d.IP)" 1500 }
        $rdp = @{}; foreach ($d in @($sweepDevs | Where-Object { & $has $_ 3389 } | Select-Object -First 60)) { $rdp["$($d.IP)"] = Get-RdpTlsName "$($d.IP)" 2000 }

        $rows = @()
        foreach ($d in $sweepDevs) {
            $ip = "$($d.IP)"; $mac = "$($d.Mac)"; $macVendor = $d.Vendor; $macSource = $(if ($mac) { 'ARP' } else { $null })
            # Across a router there is no ARP entry; a Windows machine's NetBIOS reply carries its MAC.
            if (-not $mac -and $nbns[$ip] -and "$($nbns[$ip].Mac)" -match '^([0-9A-F]{2}-){5}[0-9A-F]{2}$' -and "$($nbns[$ip].Mac)" -ne '00-00-00-00-00-00') {
                $mac = "$($nbns[$ip].Mac)"; $macSource = 'NetBIOS'; $macVendor = Get-MacVendor $mac
            }
            $discHit = if ($disc.ContainsKey($ip)) { $disc[$ip] } elseif ($discMac.ContainsKey($mac)) { $discMac[$mac] } else { $null }
            $rdpName = if ($rdp.ContainsKey($ip)) { $rdp[$ip].Name } else { $null }
            $ev = @{ MacVendor = $macVendor; Name = $d.Name; Ports = @($d.OpenPorts); Disc = $discHit; Sip = $sip[$ip]; Ssdp = $ssdp[$ip]; Wsd = $wsd[$ip]; Mdns = $mdns[$ip]; Http = @($web[$ip] | Where-Object { $_ }); Ssh = $ssh[$ip]; Ftp = $ftp[$ip]; Nbns = $nbns[$ip]; Smb = $smb[$ip]; RdpName = $rdpName; DhcpClass = $dhcpClass[$mac]; Neighbor = $neigh[$mac] }
            $id = Get-DeviceIdentity $ev
            $rows += [pscustomobject][ordered]@{
                IP = $ip; Mac = $mac; MacVendor = $macVendor; MacSource = $macSource; Subnet = $d.Subnet; Remote = [bool]$d.Remote
                Name = $(if ($d.Name) { $d.Name } elseif ($rdpName) { $rdpName } elseif ($nbns[$ip]) { $nbns[$ip].Name } elseif ($discHit) { $discHit.Name } else { $null })
                OpenPorts = @($d.OpenPorts); Kind = $id['Kind']; Vendor = $id['Vendor']; Model = $id['Model']; Firmware = $id['Firmware']; PassThrough = $id['PassThrough']; Confidence = $id['Confidence']; Evidence = $id['Evidence']
                Web = @($web[$ip] | Where-Object { $_ }); SshBanner = $ssh[$ip]; FtpBanner = $ftp[$ip]; SipAgent = $sip[$ip]; NetBios = $nbns[$ip]; Smb = $smb[$ip]; Rdp = $rdp[$ip]
            }
        }
        [ordered]@{
            DeviceCount = $rows.Count
            KindSummary = @($rows | Group-Object { if ($_.Kind) { $_.Kind } else { 'Unidentified' } } | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            ModelSummary = @($rows | Where-Object { $_.Model } | Group-Object { ('{0} {1}' -f $_.Vendor, $_.Model).Trim() } | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            Counts = [ordered]@{ WebPagesRead = $web.Count; SshBanners = $ssh.Count; FtpBanners = $ftp.Count; SipAnswers = $sip.Count; NetBiosNames = $nbns.Count; SmbChecked = $smb.Count; RdpNames = @($rdp.Values | Where-Object { $_.Name }).Count }
            Devices = $rows
        }
    }
}

if ($EnableLeadChecks -and $script:FullLanguage -and $srcIp) {
    $Result['LeadChecks'] = Invoke-Collector 'Follow-up checks on what was found (firewall, modem, servers, storage)' {
        $leads = @(Get-Leads $Result | Where-Object { $_.Kind -in @('Firewall', 'Modem', 'ServerManagement', 'Hypervisor', 'Qnap', 'Synology', 'WindowsWeb') } | Select-Object -First 40)
        if (-not $leads.Count) { return [ordered]@{ Leads = 0; Checks = @() } }
        [ordered]@{ Leads = $leads.Count; Checks = @(Invoke-LeadChecks $leads) }
    }
}

if ($EnableDnsDiscovery -and $script:FullLanguage -and $srcIp) {
    $Result['DnsDiscovery'] = Invoke-Collector 'DNS discovery (reverse names for every office, domain controllers)' {
        $ad = @($Result['Network']['Adapters'] | Where-Object { $_.Name -eq $Result['Network']['PhysicalAdapter'] }) | Select-Object -First 1
        $dnsServer = @($ad.DnsServers | Where-Object { Test-IPv4 $_ })[0]
        if (-not $dnsServer) { throw 'No IPv4 DNS server on the adapter' }
        $suffix = "$($ad.DnsSuffix)"
        $out = [ordered]@{ Server = $dnsServer; Domain = $suffix; SubnetSummary = @(); ReverseNames = @(); DomainControllers = @(); RootDse = $null; ResolverEgress = $null }
        # Reverse names: 254 questions per /24, sent to the site's own DNS server and nowhere else.
        if ((Get-IpClass $dnsServer) -eq 'Private') {
            # The configured office subnets, this one, and any other range heard on the wire (ARP, CDP addresses).
            $heard = @(@(Get-Val $Result['Capture'] 'ArpSubnets' | ForEach-Object { if ($_) { "$($_.Subnet)" -replace '\.0/24$', '' } }) + @(Get-Val $Result['Capture'] 'Cdp' | ForEach-Object { if ($_ -and $_.Address) { (("$($_.Address)" -split '\.')[0..2]) -join '.' } }) | Where-Object { $_ -and (Get-IpClass "$_.1") -eq 'Private' } | Select-Object -Unique | Select-Object -First 4)
            $pres = @(@($SiteSubnets) + @((($srcIp -split '\.')[0..2]) -join '.') + $heard | Where-Object { $_ -match '^\d+\.\d+\.\d+$' } | Select-Object -Unique)
            foreach ($pre in $pres) {
                $o = $pre.Split('.'); $sends = @()
                for ($h = 1; $h -le 254; $h++) { $sends += @{ Address = $dnsServer; Port = 53; Bytes = (New-DnsQuery -Names @("$h.$($o[2]).$($o[1]).$($o[0]).in-addr.arpa") -Type 12 -Id $h -Recurse) } }
                $answered = 0; $names = 0
                foreach ($x in @(Invoke-UdpProbe $sends $srcIp 0 2500)) {
                    $answered++
                    foreach ($rr in @(ConvertFrom-DnsMessage $x.Data)) {
                        if ($rr.Type -eq 12 -and $rr.Name -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa') { $out['ReverseNames'] += [pscustomobject]@{ IP = ('{0}.{1}.{2}.{3}' -f $matches[4], $matches[3], $matches[2], $matches[1]); Name = $rr.Data }; $names++ }
                    }
                }
                $out['SubnetSummary'] += [pscustomobject]@{ Subnet = "$pre.0/24"; Asked = 254; Answered = $answered; Names = $names }
            }
        }
        if ($suffix) {
            foreach ($q in @("_ldap._tcp.dc._msdcs.$suffix", "_ldap._tcp.pdc._msdcs.$suffix", "_gc._tcp.$suffix", "_kerberos._tcp.$suffix")) {
                try { foreach ($a in @(Resolve-DnsName -Name $q -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' })) { $out['DomainControllers'] += [pscustomobject]@{ Record = $q; Target = $a.NameTarget; Port = $a.Port } } } catch { }
            }
        }
        # The directory's own description of itself (anonymous read of the root entry, no logon).
        if ((Get-IpClass $dnsServer) -eq 'Private' -and (Test-TcpPort $dnsServer 389 1500)) {
            try {
                Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
                $lid = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($dnsServer, 389, $false, $false)
                $lc = New-Object System.DirectoryServices.Protocols.LdapConnection($lid)
                $lc.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
                $lc.Timeout = [TimeSpan]::FromSeconds(6)
                $lc.SessionOptions.ProtocolVersion = 3
                [string[]]$attrs = @('defaultNamingContext', 'rootDomainNamingContext', 'dnsHostName', 'serverName', 'domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality', 'isGlobalCatalogReady', 'currentTime')
                $sreq = [System.DirectoryServices.Protocols.SearchRequest]::new('', '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, $attrs)
                $sres = $lc.SendRequest($sreq, [TimeSpan]::FromSeconds(6))
                $lc.Dispose()
                if ($sres.Entries.Count) {
                    $en = $sres.Entries[0]
                    $val = { param($n) if ($en.Attributes.Contains($n)) { "$($en.Attributes[$n][0])" } else { $null } }
                    $lvl = @{ '0' = 'Windows 2000'; '2' = 'Windows Server 2003'; '3' = 'Windows Server 2008'; '4' = 'Windows Server 2008 R2'; '5' = 'Windows Server 2012'; '6' = 'Windows Server 2012 R2'; '7' = 'Windows Server 2016'; '10' = 'Windows Server 2025' }
                    $name = { param($v) if ($null -eq $v) { $null } elseif ($lvl.ContainsKey("$v")) { $lvl["$v"] } else { "level $v" } }
                    $out['RootDse'] = [ordered]@{
                        DnsHostName = & $val 'dnsHostName'; ServerName = & $val 'serverName'; DefaultNamingContext = & $val 'defaultNamingContext'; RootDomain = & $val 'rootDomainNamingContext'
                        DomainLevel = & $name (& $val 'domainFunctionality'); ForestLevel = & $name (& $val 'forestFunctionality'); DomainControllerLevel = & $name (& $val 'domainControllerFunctionality')
                        GlobalCatalog = & $val 'isGlobalCatalogReady'; CurrentTime = & $val 'currentTime'
                    }
                }
            } catch { $out['RootDseError'] = $_.Exception.GetBaseException().Message }
        }
        # Which public address do name lookups come from? (The answer to this name is the asking resolver's address.)
        try {
            $who = @(Resolve-DnsName -Name 'whoami.akamai.net' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' })[0].IPAddress
            if ($who) {
                $re = [ordered]@{ Ip = "$who"; Org = $null; City = $null; SameAsSite = ("$who" -eq "$(Get-Val $Result['Egress'] 'PublicIPv4')") }
                if ($EnableIpInfo -and -not $re['SameAsSite']) { try { $ii = Invoke-RestMethod -Uri "https://ipinfo.io/$who/json" -UseBasicParsing -TimeoutSec 8; $re['Org'] = "$($ii.org)"; $re['City'] = ((@($ii.city, $ii.region) | Where-Object { $_ }) -join ', ') } catch { } }
                $out['ResolverEgress'] = $re
            }
        } catch { }
        $out
    }
}

if ($EnableSiteReach -and $srcIp -and @($SiteSubnets | Where-Object { $_ }).Count) {
    $Result['SiteReach'] = Invoke-Collector 'Other offices (ping and short traceroute)' {
        $localPre = (($srcIp -split '\.')[0..2]) -join '.'
        $targets = @($SiteSubnets | Where-Object { $_ -match '^\d+\.\d+\.\d+$' -and $_ -ne $localPre } | ForEach-Object { "$_.1" })
        # A device the DNS server knows in another office is a better target than a guessed gateway address.
        foreach ($pre in @($SiteSubnets | Where-Object { $_ -ne $localPre })) {
            $known = @(Get-Val $Result['DnsDiscovery'] 'ReverseNames' | Where-Object { $_ -and "$($_.IP)" -like "$pre.*" -and "$($_.IP)" -ne "$pre.1" }) | Select-Object -Last 1
            if ($known) { $targets += "$($known.IP)" }
        }
        $targets = @($targets | Select-Object -Unique | Select-Object -First 12)
        if (-not $targets.Count) { throw 'No other site subnets configured' }
        $jobs = @()
        foreach ($t in $targets) { $jobs += [pscustomobject]@{ Target = $t; Handle = (Start-IcmpJob -Kind Trace -Target $t -MaxHops 8 -TimeoutMs 600 -Label "site trace $t") } }
        $rows = @()
        foreach ($t in $targets) {
            $ok = 0; $ms = @(); $pg = New-Object Net.NetworkInformation.Ping
            for ($k = 0; $k -lt 3; $k++) { try { $r = $pg.Send($t, 1000); if ($r.Status -eq 'Success') { $ok++; $ms += $r.RoundtripTime } } catch { } }
            $pg.Dispose()
            $rows += [pscustomobject]@{ Target = $t; Subnet = ((($t -split '\.')[0..2]) -join '.') + '.0/24'; PingReplies = $ok; AvgMs = $(if ($ms.Count) { [math]::Round((($ms | Measure-Object -Average).Average), 1) } else { $null }); Hops = @(); Path = $null; LastHopIp = $null }
        }
        foreach ($j in $jobs) {
            $hops = @(ConvertFrom-Tracert (Receive-NativeAsync $j.Handle 45))
            $row = $rows | Where-Object { $_.Target -eq $j.Target } | Select-Object -First 1
            $row.Hops = @($hops | ForEach-Object { [pscustomobject]@{ Hop = $_.Hop; IP = $_.IP; AvgMs = $_.AvgMs } })
            $row.Path = (@($hops | ForEach-Object { if ($_.IP) { "$($_.IP)($($_.AvgMs))" } else { '*' } }) -join ' > ')
            $row.LastHopIp = "$((@($hops | Where-Object { $_.IP }) | Select-Object -Last 1).IP)"
        }
        [ordered]@{ Targets = $rows }
    }
}

if ($EnableOwnerLookup -and (Get-Val $Result['Egress'] 'PublicIPv4')) {
    $ownerInfo = Invoke-Collector 'Public address owner (whois)' {
        $pub = "$($Result['Egress']['PublicIPv4'])"
        $rd = Invoke-RestMethod -Uri "https://rdap.org/ip/$pub" -TimeoutSec 15 -Headers @{ Accept = 'application/rdap+json' } -UseBasicParsing
        $o = [ordered]@{ Block = "$($rd.name)"; Handle = "$($rd.handle)"; Range = "$($rd.startAddress) - $($rd.endAddress)"; Type = "$($rd.type)"; Parent = "$($rd.parentHandle)"; RegisteredTo = $null; Address = $null; Registered = $null; Chain = @() }
        foreach ($evt in @($rd.events)) { if ($evt -and "$($evt.eventAction)" -eq 'registration') { $dt = "$($evt.eventDate)"; try { $dt = ([datetime]$evt.eventDate).ToString('yyyy-MM-dd') } catch { }; $o['Registered'] = $dt } }
        $walk = {
            param($ents, $depth)
            foreach ($en in @($ents)) {
                if (-not $en) { continue }
                $fn = $null; $adr = $null
                try { foreach ($it in @($en.vcardArray[1])) { if ("$($it[0])" -eq 'fn') { $fn = "$($it[3])" } elseif ("$($it[0])" -eq 'adr' -and $it[1].label) { $adr = ("$($it[1].label)" -replace "\r?\n", ', ') } } } catch { }
                if ($fn) {
                    $o['Chain'] += ('{0} [{1}]' -f $fn, (@($en.roles) -join ','))
                    if (-not $o['RegisteredTo'] -and @($en.roles) -contains 'registrant') { $o['RegisteredTo'] = $fn; $o['Address'] = $adr }
                }
                if ($depth -lt 3 -and $en.entities) { & $walk $en.entities ($depth + 1) }
            }
        }
        & $walk $rd.entities 0
        $o
    }
    if ($Result['Egress'] -is [System.Collections.IDictionary]) { $Result['Egress']['Owner'] = $ownerInfo }
}
