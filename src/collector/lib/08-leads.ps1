# ---------------------------------------------------------------------
# Leads: what one step found that another step should look at. Get-Leads reads the evidence so far and
# returns Kind, Target, Why; the later steps (SNMP, the voice sample, reach across the tunnel, the
# follow-up checks) take their targets from it instead of fixed lists.
# ---------------------------------------------------------------------
function Get-Leads {
    param($R)
    $out = New-Object Collections.Generic.List[object]
    $seen = @{}
    $add = {
        param([string]$kind, [string]$target, [string]$why)
        if (-not $target) { return }
        $k = "$kind|$target"
        if ($seen.ContainsKey($k)) { if ($seen[$k].Why -notcontains $why) { $seen[$k].Why += $why }; return }
        $o = [pscustomobject]@{ Kind = $kind; Target = $target; Why = @($why) }
        $seen[$k] = $o; $out.Add($o)
    }
    $srcIp = "$(Get-Prop $R 'Network', 'SourceIp')"
    $gw = "$(Get-Prop $R 'Network', 'Gateway')"
    $ad = @(@(Get-Prop $R 'Network', 'Adapters') | Where-Object { $_ -and "$(Get-Prop $_ 'Name')" -eq "$(Get-Prop $R 'Network', 'PhysicalAdapter')" }) | Select-Object -First 1
    $mask = "$(@(Get-Prop $ad 'SubnetMask') | Select-Object -First 1)"; if (-not (Test-IPv4 $mask)) { $mask = '255.255.255.0' }
    $otherSubnet = { param([string]$ip) (Test-IPv4 $ip) -and (Get-IpClass $ip) -eq 'Private' -and -not ($srcIp -and (Test-SameSubnet $ip $srcIp $mask)) }

    # The phone system: DHCP options 66/150 (phones are told where to boot from) and SIP answers that name a PBX
    foreach ($d in @(Get-Prop $R 'Capture', 'DhcpServers')) {
        foreach ($t in @(@(Get-Prop $d 'TftpAddresses') + @(Get-Prop $d 'TftpServer'))) { if ($t -and (Test-IPv4 "$t")) { & $add 'PhoneSystem' "$t" 'DHCP hands phones this boot server (option 66/150)' } }
    }
    foreach ($dv in @(Get-Prop $R 'Identify', 'Devices')) {
        if (-not $dv) { continue }
        if ("$(Get-Prop $dv 'SipAgent')" -match 'Asterisk|FreePBX|3CX|FreeSWITCH|Mitel|Avaya|Cisco-SIPGateway|CUCM|Yeastar|UCM|Elastix|Issabel|Sangoma|NEC|ShoreTel|Vodia') { & $add 'PhoneSystem' "$(Get-Prop $dv 'IP')" "SIP answer names a phone system ($(Get-Prop $dv 'SipAgent'))" }
    }

    # The ISP's own box: a fast private hop right after the gateway (double NAT) is the modem or ONT
    $inet = @(@(Get-Prop $R 'Traceroutes') | Where-Object { $_ -and "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' }) | Select-Object -First 1
    if ($inet -and (Get-Prop $inet 'Analysis', 'DoubleNatLikely')) {
        $hop = @(@(Get-Prop $inet 'Hops') | Where-Object { $_ -and [int](Get-Prop $_ 'Hop') -gt 1 -and "$(Get-Prop $_ 'Class')" -eq 'Private' }) | Select-Object -First 1
        if ($hop) { & $add 'Modem' "$(Get-Prop $hop 'IP')" 'private hop right after the gateway on the way to the internet (double NAT)' }
    }

    # The firewall's make, from its MAC vendor, its web page or vendor discovery
    $gwText = (@("$(Get-Prop $R 'NetworkExtra', 'GatewayVendor')", "$(Get-Prop $R 'GatewayModel')") + @(@(Get-Prop $R 'GatewayProbe') | ForEach-Object { "$(Get-Prop $_ 'Title') $(Get-Prop $_ 'Server') $(Get-Prop $_ 'CertSubject')" })) -join ' '
    if ($gw -and (Get-FirewallChecks $gwText)) { & $add 'Firewall' $gw "gateway looks like $((Get-FirewallChecks $gwText).Vendor)" }

    # Switches that announce a management address (LLDP/CDP): ask them over SNMP even on another VLAN
    foreach ($n in @(@(Get-Prop $R 'Capture', 'Lldp') + @(Get-Prop $R 'Capture', 'Cdp'))) {
        $ip = "$(Get-Prop $n 'MgmtIP')"; if (-not $ip) { $ip = "$(Get-Prop $n 'Address')" }
        if ((Test-IPv4 $ip) -and $ip -ne '0.0.0.0') { & $add 'Switch' $ip "the switch on this port announces it as its management address ($(Get-Prop $n 'Protocol'))" }
    }

    # Servers on other subnets this PC depends on: what to test across the tunnel
    foreach ($sv in @(Get-Prop $R 'Servers', 'Servers')) { foreach ($ip in @(Get-Prop $sv 'IPs')) { if (& $otherSubnet "$ip") { & $add 'Server' "$ip" "this PC uses $(Get-Prop $sv 'Name')" } } }
    foreach ($d in @(Get-Prop $R 'NetworkExtra', 'DnsServers')) { $ip = "$(Get-Prop $d 'Server')"; if (& $otherSubnet $ip) { & $add 'Server' $ip 'DNS server on another subnet' } }
    foreach ($dc in @(Get-Prop $R 'DnsDiscovery', 'DomainControllers')) {
        $name = "$(Get-Prop $dc 'Target')"
        $rn = @(@(Get-Prop $R 'DnsDiscovery', 'ReverseNames') | Where-Object { $_ -and "$(Get-Prop $_ 'Name')" -eq $name }) | Select-Object -First 1
        if ($rn -and (& $otherSubnet "$(Get-Prop $rn 'IP')")) { & $add 'Server' "$(Get-Prop $rn 'IP')" "domain controller $name" }
    }

    # Devices that deserve a closer, specific look
    foreach ($dv in @(Get-Prop $R 'Identify', 'Devices')) {
        if (-not $dv) { continue }
        $ip = "$(Get-Prop $dv 'IP')"
        $ports = @(@(Get-Prop $dv 'OpenPorts') | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
        $text = (@("$(Get-Prop $dv 'MacVendor')", "$(Get-Prop $dv 'Vendor')", "$(Get-Prop $dv 'Model')", "$(Get-Prop $dv 'Kind')") + @(@(Get-Prop $dv 'Web') | ForEach-Object { "$(Get-Prop $_ 'Title') $(Get-Prop $_ 'Server') $(Get-Prop $_ 'CertSubject')" })) -join ' '
        if ($ports -contains 443 -and $text -match 'iDRAC|Integrated Dell Remote Access|iLO|Integrated Lights.Out|Supermicro|XClarity|\bIMM\b|\bBMC\b|MegaRAC|Redfish|IPMI') { & $add 'ServerManagement' $ip 'web page of a server management controller' }
        if ($ports -contains 443 -and $text -match 'VMware ESXi|ESXi|vSphere|VMware vCenter') { & $add 'Hypervisor' $ip 'VMware web page' }
        if ($text -match 'QNAP|QTS') { & $add 'Qnap' $ip 'QNAP storage' }
        if ($text -match 'Synology|DiskStation|DSM') { & $add 'Synology' $ip 'Synology storage' }
        if ($ports -contains 443 -and ($ports -contains 445 -or $ports -contains 3389 -or $text -match 'Windows|Microsoft|IIS')) { & $add 'WindowsWeb' $ip 'Windows server with a web server' }
    }
    return $out.ToArray()
}

function Get-FirewallChecks {
    # Vendor-specific management and VPN pages to look for, from any text that names the make.
    param([string]$Text)
    $map = @(
        @{ Vendor = 'Fortinet'; Match = 'Fortinet|FortiGate|FortiOS'; Checks = @(@(443, '/remote/login', 'SSL-VPN portal'), @(10443, '/remote/login', 'SSL-VPN portal'), @(4443, '/remote/login', 'SSL-VPN portal'), @(8443, '/login', 'admin page')) }
        @{ Vendor = 'SonicWall'; Match = 'SonicWall|SonicOS'; Checks = @(@(443, '/auth.html', 'admin login'), @(4433, '/sslvpnLogin.html', 'SSL-VPN portal')) }
        @{ Vendor = 'WatchGuard'; Match = 'WatchGuard|Fireware'; Checks = @(@(8080, '/', 'admin page'), @(443, '/auth/login', 'authentication portal')) }
        @{ Vendor = 'Sophos'; Match = 'Sophos|Cyberoam'; Checks = @(@(4444, '/webconsole/webpages/login.jsp', 'admin console'), @(443, '/userportal/webpages/myaccount/login.jsp', 'user portal')) }
        @{ Vendor = 'Palo Alto Networks'; Match = 'Palo Alto|PAN-OS|GlobalProtect'; Checks = @(@(443, '/global-protect/login.esp', 'GlobalProtect portal'), @(443, '/php/login.php', 'admin login')) }
        @{ Vendor = 'Cisco'; Match = 'Cisco|\bASA\b|Firepower|Meraki'; Checks = @(@(443, '/+CSCOE+/logon.html', 'AnyConnect portal'), @(80, '/', 'web page')) }
        @{ Vendor = 'Check Point'; Match = 'Check ?Point|Gaia'; Checks = @(@(443, '/sslvpn/Login/Login', 'SSL-VPN portal'), @(4434, '/', 'admin page')) }
        @{ Vendor = 'Ubiquiti'; Match = 'Ubiquiti|UniFi|EdgeOS|EdgeRouter'; Checks = @(@(443, '/', 'UniFi OS or EdgeOS page')) }
        @{ Vendor = 'MikroTik'; Match = 'MikroTik|RouterOS'; Checks = @(@(80, '/webfig/', 'WebFig admin page')) }
        @{ Vendor = 'Netgate / OPNsense'; Match = 'pfSense|Netgate|OPNsense'; Checks = @(@(443, '/', 'admin page')) }
    )
    foreach ($m in $map) {
        if ("$Text" -match $m.Match) {
            return [pscustomobject]@{ Vendor = $m.Vendor; Checks = @($m.Checks | ForEach-Object { [pscustomobject]@{ Port = [int]$_[0]; Path = $_[1]; What = $_[2] } }) }
        }
    }
    return $null
}

function ConvertFrom-RedfishRoot {
    # The Redfish service root (/redfish/v1/, readable without a login): who made the controller.
    param([string]$Json)
    try { $o = $Json | ConvertFrom-Json } catch { return $null }
    if (-not $o -or -not ($o.RedfishVersion -or $o.'@odata.id')) { return $null }
    $vendor = "$($o.Vendor)"
    if (-not $vendor -and $o.Oem) { $vendor = (@($o.Oem.PSObject.Properties | ForEach-Object { $_.Name }) | Select-Object -First 1) }
    return [pscustomobject]@{ Vendor = $vendor; Product = "$($o.Product)"; RedfishVersion = "$($o.RedfishVersion)"; Name = "$($o.Name)" }
}

function ConvertFrom-VimAbout {
    # The answer to the vSphere API's public RetrieveServiceContent call: product, version and build.
    param([string]$Xml)
    if ("$Xml" -notmatch '<fullName>([^<]+)</fullName>') { return $null }
    $full = $matches[1]
    $get = { param($tag) if ("$Xml" -match "<$tag>([^<]+)</$tag>") { $matches[1] } else { $null } }
    return [pscustomobject]@{ FullName = $full; Version = (& $get 'version'); Build = (& $get 'build'); ApiType = (& $get 'apiType') }
}

function ConvertFrom-QnapLogin {
    # QNAP's login check (/cgi-bin/authLogin.cgi) names the model and firmware before anyone signs in.
    param([string]$Xml)
    $get = { param($tag) if ("$Xml" -match "<$tag>\s*(?:<!\[CDATA\[)?([^<\]]+)") { $matches[1].Trim() } else { $null } }
    $model = & $get 'displayModelName'; if (-not $model) { $model = & $get 'modelName' }
    if (-not $model) { return $null }
    return [pscustomobject]@{ Model = $model; Firmware = (& $get 'version'); Build = (& $get 'build') }
}

function Invoke-LeadChecks {
    # The follow-up check for each lead that has one. Read only: page titles and the public
    # description each product gives before anyone signs in. Returns one row per check that answered.
    param($Leads, [int]$TimeoutMs = 5000)
    $rows = @()
    foreach ($l in @($Leads)) {
        $ip = "$($l.Target)"
        switch ($l.Kind) {
            'Firewall' {
                $fc = Get-FirewallChecks ((@($l.Why) -join ' '))
                foreach ($c in @($fc.Checks)) {
                    $scheme = if ($c.Port -in @(80, 8080)) { 'http' } else { 'https' }
                    $u = '{0}://{1}{2}{3}' -f $scheme, $ip, $(if (($scheme -eq 'https' -and $c.Port -ne 443) -or ($scheme -eq 'http' -and $c.Port -ne 80)) { ":$($c.Port)" } else { '' }), $c.Path
                    $h = Invoke-HttpText $u -TimeoutMs $TimeoutMs
                    if ($h.Status -and $h.Status -lt 500 -and $h.Status -ne 404) { $rows += [pscustomobject]@{ Kind = 'Firewall'; IP = $ip; What = "$($fc.Vendor) $($c.What)"; Detail = "port $($c.Port) answers $($h.Status)$(if ($h.Title) { ": $($h.Title)" })"; Url = $u } }
                }
            }
            'Modem' {
                $h = Invoke-HttpText "http://$ip/" -TimeoutMs $TimeoutMs
                if ($h.Status) { $rows += [pscustomobject]@{ Kind = 'Modem'; IP = $ip; What = 'ISP modem or ONT'; Detail = "web page $($h.Status)$(if ($h.Title) { ": $($h.Title)" })$(if ($h.Server) { " ($($h.Server))" })"; Url = "http://$ip/" } }
            }
            'ServerManagement' {
                $h = Invoke-HttpText "https://$ip/redfish/v1/" -ContentType 'application/json' -TimeoutMs $TimeoutMs
                $rf = if ($h.Body) { ConvertFrom-RedfishRoot $h.Body } else { $null }
                if ($rf) { $rows += [pscustomobject]@{ Kind = 'ServerManagement'; IP = $ip; What = ("{0} {1}" -f $rf.Vendor, $rf.Product).Trim(); Detail = "Redfish $($rf.RedfishVersion), reachable from this office port"; Url = "https://$ip/redfish/v1/" } }
            }
            'Hypervisor' {
                $soap = '<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent></soap:Body></soap:Envelope>'
                $h = Invoke-HttpText "https://$ip/sdk" -Method POST -Body $soap -Headers @{ SOAPAction = 'urn:vim25/6.0' } -TimeoutMs $TimeoutMs
                $vm = if ($h.Body) { ConvertFrom-VimAbout $h.Body } else { $null }
                if ($vm) { $rows += [pscustomobject]@{ Kind = 'Hypervisor'; IP = $ip; What = $vm.FullName; Detail = "version $($vm.Version) build $($vm.Build) ($($vm.ApiType))"; Url = "https://$ip/sdk"; Version = $vm.Version } }
            }
            'Qnap' {
                foreach ($u in @("http://${ip}:8080/cgi-bin/authLogin.cgi", "https://$ip/cgi-bin/authLogin.cgi")) {
                    $h = Invoke-HttpText $u -TimeoutMs $TimeoutMs
                    $q = if ($h.Body) { ConvertFrom-QnapLogin $h.Body } else { $null }
                    if ($q) { $rows += [pscustomobject]@{ Kind = 'Storage'; IP = $ip; What = "QNAP $($q.Model)"; Detail = "firmware $($q.Firmware) build $($q.Build)"; Url = $u }; break }
                }
            }
            'Synology' {
                foreach ($u in @("https://${ip}:5001/", "http://${ip}:5000/")) {
                    $h = Invoke-HttpText $u -TimeoutMs $TimeoutMs
                    if ($h.Status -and "$($h.Title) $($h.Body)" -match 'Synology|DiskStation') { $rows += [pscustomobject]@{ Kind = 'Storage'; IP = $ip; What = "Synology $(if ($h.Title) { $h.Title } else { 'DSM' })"; Detail = "DSM sign-in page on $u"; Url = $u }; break }
                }
            }
            'WindowsWeb' {
                $web = Invoke-HttpText "https://$ip/RDWeb/" -TimeoutMs $TimeoutMs
                if ($web.Status -and $web.Status -lt 400 -and "$($web.Title) $($web.Body)" -match 'RD Web|Remote Desktop|RDWeb') { $rows += [pscustomobject]@{ Kind = 'RemoteDesktop'; IP = $ip; What = 'RD Web Access'; Detail = "$($web.Status)$(if ($web.Title) { ": $($web.Title)" })"; Url = "https://$ip/RDWeb/" } }
                $gwr = Invoke-HttpText "https://$ip/remoteDesktopGateway/" -TimeoutMs $TimeoutMs
                if ($gwr.Status -eq 401) { $rows += [pscustomobject]@{ Kind = 'RemoteDesktop'; IP = $ip; What = 'RD Gateway'; Detail = 'asks for a login on /remoteDesktopGateway/'; Url = "https://$ip/remoteDesktopGateway/" } }
            }
        }
    }
    return $rows
}

function Get-AdSites {
    # Active Directory's own list of sites and their subnets, read as the signed-in user (the same
    # directory query any domain PC makes). Runs with a time limit: a far-away domain controller can be slow.
    param([int]$TimeoutSec = 20)
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        Add-Type -AssemblyName System.DirectoryServices
        $f = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $cur = $null; try { $cur = [DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name } catch { }
        [pscustomobject]@{ Forest = $f.Name; CurrentSite = $cur; Sites = @($f.Sites | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Location = $_.Location; Subnets = @($_.Subnets | ForEach-Object { $_.Name }); Servers = @($_.Servers | ForEach-Object { $_.Name }) } }) }
    })
    $h = $ps.BeginInvoke()
    try {
        if (-not $h.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) { try { $ps.Stop() } catch { }; throw "Active Directory did not answer within $TimeoutSec s" }
        $r = @($ps.EndInvoke($h))
        if (-not $r.Count) { throw "Active Directory did not answer: $(@($ps.Streams.Error) | Select-Object -First 1)" }
        # The domain controller this user's logon used (\\DC01), to compare with the PC's own site
        return [ordered]@{ Forest = $r[0].Forest; CurrentSite = $r[0].CurrentSite; LogonServer = "$env:LOGONSERVER".TrimStart('\'); Sites = @($r[0].Sites) }
    } finally { $ps.Dispose() }
}

function Get-AdSiteCheck {
    # Cross-checks Active Directory's sites against where this PC really is: which AD subnet its
    # address falls in, which site that makes it, which domain controller it logged on to and where
    # that DC lives. No traffic: it reads what Get-AdSites and the adapter check already collected.
    param($R)
    $sites = @(@(Get-Prop $R 'AdSites', 'Sites') | Where-Object { $_ })
    if (-not $sites.Count) { return $null }
    $ip = "$(Get-Prop $R 'Network', 'SourceIp')"
    $best = $null; $bestPre = -1; $bestCidr = $null
    foreach ($s in $sites) {
        foreach ($sn in @(Get-Prop $s 'Subnets')) {
            if ("$sn" -notmatch '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$' -or -not (Test-IPv4 $ip)) { continue }
            $rg = ConvertTo-NetRange $matches[1] ([int]$matches[3])
            $n = ConvertTo-IpNumber $ip
            if ($n -ge $rg.NetInt -and $n -le $rg.End -and $rg.Prefix -gt $bestPre) { $best = $s; $bestPre = $rg.Prefix; $bestCidr = "$sn" }
        }
    }
    $short = { param($n) ("$n".Split('.')[0]).ToUpperInvariant() }
    $logon = "$(Get-Prop $R 'AdSites', 'LogonServer')"
    $logonSite = $null
    if ($logon) { $logonSite = @($sites | Where-Object { @(@(Get-Prop $_ 'Servers') | ForEach-Object { & $short $_ }) -contains (& $short $logon) }) | Select-Object -First 1 }
    $pcSite = if ($best) { "$(Get-Prop $best 'Name')" } else { $null }
    return [pscustomobject]@{
        Ip = $ip; AdSubnet = $bestCidr; SiteBySubnet = $pcSite
        CurrentSite = "$(Get-Prop $R 'AdSites', 'CurrentSite')"
        SiteHasDc = $(if ($best) { [bool]@(Get-Prop $best 'Servers').Count } else { $null })
        LogonServer = $logon; LogonServerSite = $(if ($logonSite) { "$(Get-Prop $logonSite 'Name')" } else { $null })
        SitesWithoutDc = @($sites | Where-Object { @(Get-Prop $_ 'Subnets').Count -and -not @(Get-Prop $_ 'Servers').Count } | ForEach-Object { "$(Get-Prop $_ 'Name')" })
    }
}

function Get-AdSiteFlags {
    # Severity, Category, Message rows for what Get-AdSiteCheck found. SiteWide is set only on what
    # describes the directory itself; the rest is about this PC or this user, so the merge names the machine.
    param($C)
    if (-not $C) { return @() }
    $out = @()
    $f = { param($sev, $msg, [switch]$SiteWide) [pscustomobject]@{ Severity = $sev; Category = 'Active Directory'; Message = $msg; SiteWide = [bool]$SiteWide } }
    if ($C.Ip -and -not $C.AdSubnet) {
        $out += & $f 'Medium' "This PC's address $($C.Ip) is in no Active Directory subnet, so it logs on to whichever domain controller answers first, possibly across the WAN: add its subnet to the right site in AD Sites and Services"
    } elseif ($C.CurrentSite -and $C.SiteBySubnet -and $C.CurrentSite -ne $C.SiteBySubnet) {
        $out += & $f 'Low' "This PC reports AD site $($C.CurrentSite), but its subnet $($C.AdSubnet) belongs to site $($C.SiteBySubnet): overlapping or stale subnets in AD Sites and Services"
    }
    $mySite = if ($C.SiteBySubnet) { $C.SiteBySubnet } else { $C.CurrentSite }
    if ($C.LogonServer -and $C.LogonServerSite -and $mySite -and $C.LogonServerSite -ne $mySite -and $C.SiteHasDc) {
        $out += & $f 'Medium' "This user logged on to $($C.LogonServer) in site $($C.LogonServerSite), not to a domain controller in this PC's own site $mySite"
    }
    foreach ($s in @($C.SitesWithoutDc)) { $out += & $f 'Low' "AD site $s has subnets but no domain controller, so its PCs log on across the WAN (fine when that is the design, worth knowing when the link goes down)" -SiteWide }
    return $out
}
