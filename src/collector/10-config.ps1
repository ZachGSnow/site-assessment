# =====================================================================
# CONFIG - edit these before running, or keep them in a -ConfigPath file
# =====================================================================
$SiteList           = @()      # optional numbered menu at the prompt so every machine at a site uses the same name,
                                # e.g. @('Main office', 'Warehouse')

# ---- Hosted desktop ----
# A profile tells the collector which remote desktop service the users work in, so it can find the
# client app, the hosts it talks to and the round trip that matters. The report is labelled with Name.
#   HostPattern  regex for host names in the DNS cache and reverse DNS that belong to the service
#   AppPattern   regex for file, folder and process names of the service's own client app
#   Targets      hosts always tested first: 'host', 'host:port' or an IP
#   ProviderAsn  regex for the provider's network name/ASN: internet that exits there is backhauled
$HostedDesktopName  = 'RDP'    # which profile below to use (or -HostedDesktop)
$HostedDesktopProfiles = [ordered]@{
    RDP = @{ Name = 'Remote desktop'; HostPattern = ''; AppPattern = ''; Targets = @(); ProviderAsn = '' }
    # Hosts from Microsoft's "Required FQDNs and endpoints for Azure Virtual Desktop", end user devices
    # (checked 2026-11-12). The round trip is to the service front door, not to the session host.
    AzureVirtualDesktop = @{
        Name = 'Azure Virtual Desktop'; HostPattern = '\.wvd\.microsoft\.com\b|windows\.cloud\.microsoft\b'; AppPattern = 'msrdc|Remote Desktop|Windows365'
        Targets = @('rdweb.wvd.microsoft.com:443', 'client.wvd.microsoft.com:443'); ProviderAsn = ''
    }
    Windows365 = @{
        Name = 'Windows 365'; HostPattern = '\.wvd\.microsoft\.com\b|windows\.cloud\.microsoft\b|windows365\.microsoft\.com\b'; AppPattern = 'Windows365|Windows App|msrdc'
        Targets = @('windows365.microsoft.com:443', 'rdweb.wvd.microsoft.com:443'); ProviderAsn = ''
    }
    # Domains from Citrix's Citrix Cloud connectivity and Gateway Service pages (checked 2026-11-12).
    # Add your own store URL (<customer>.cloud.com) to $ExtraTargets: it is different for every tenant.
    CitrixCloud = @{
        Name = 'Citrix Cloud'; HostPattern = '(^|[.\s])cloud\.com\b|\.nssvc\.net\b|citrixworkspacesapi\.net\b'; AppPattern = 'Citrix|wfica|SelfService'
        Targets = @(); ProviderAsn = ''
    }
}
$HostedDesktopProfile = $null  # your own profile, used instead of a named one, e.g.
                                # @{ Name = 'Contoso Cloud'; HostPattern = 'contosocloud\.com'; AppPattern = 'ContosoConnect';
                                #    Targets = @('connect.contosocloud.com:443'); ProviderAsn = 'Contoso Cloud|AS64500' }
$ExtraTargets       = @()      # added to the profile's Targets: host or host:port, e.g. 'rdgw.example.com', '203.0.113.10:7765'

# ---- Optional knowledge of the client network (used by discovery and the findings) ----
$SiteSubnets        = @()      # one /24 per office (first 3 octets), e.g. @('10.10.1', '10.10.2'). With -Discovery:
                                # reverse DNS, reachability and a full sweep of each, like $ScanSubnets
$TunnelServers      = @()      # servers across a site tunnel to test from an office port, e.g. @('10.10.0.10')
$ScanSubnets        = @()      # other subnets to sweep with -Discovery: 'a.b.c' (a /24) or 'a.b.c.d/22' to '/30',
                                # e.g. @('10.10.2', '10.10.8.0/23'). $SiteSubnets are swept too. Subnets this PC can reach
                                # are listed at the prompt, and none of those is swept unless you pick it.
$RemoteSweepMaxSubnets = 8     # most other subnets swept in one run
$RemoteSweepPresencePorts = @(22, 80, 443, 445, 3389)   # tried on addresses that ignore ping (hosts that block ICMP)
$VoiceTargets       = @('1.1.1.1')   # call-pace sample targets: add the phone system's IP to test the path to it

# ---- Active discovery (all off unless -Discovery or $EnableDiscovery; each switch can then turn one off) ----
$EnableDiscovery    = $false
$EnableSubnetSweep  = $true    # ping sweep of local subnet (up to /22) + ARP/vendor inventory
$EnableRemoteSweep  = $true    # the same sweep and identification on $ScanSubnets, $SiteSubnets and subnets picked at the prompt
$EnableSweepPorts   = $true    # after the sweep: name lookup + a few TCP ports on each device found (tells servers,
                                # printers, cameras and phones apart). Set $false to keep the sweep to ping + ARP only.
$SweepPorts         = @(21, 22, 23, 53, 80, 88, 135, 139, 389, 443, 445, 515, 554, 631, 1433, 3389, 5060, 5061, 8080, 8291, 8443, 9100)
$EnableVendorDiscovery = $true # one broadcast per vendor discovery protocol (Ubiquiti, MikroTik, Netgear): model and firmware
$EnableMulticastDiscovery = $true # mDNS and WS-Discovery questions: printers, cameras and Apple/Google devices name themselves
$EnableDeviceIdentify = $true  # per device the sweep found: web page title + certificate, SSH/FTP banner, SIP phone model,
                                # Windows name. One request per open port, nothing is logged in to.
$IdentifyMaxDevices = 300      # cap for the identify pass
$EnableDnsDiscovery = $true    # questions to the site's own DNS server: reverse names for $SiteSubnets, domain controllers
$EnableSiteReach    = $true    # ping + short traceroute to the .1 of each $SiteSubnets entry (are the other offices reachable, and how)
$EnableSnmp         = $true    # read-only SNMP with $SnmpCommunity on every device found: switch ports,
                                # which device is on which port, PoE, printer serials and page counts
$SnmpCommunity      = 'public'
$EnableModemPage    = $true    # one web request to the ISP modem's status page (192.168.100.1) and the ISP gateway
$EnableWindowsBuild = $true    # Windows build of each PC from the file-sharing handshake (no logon, no credentials)
$EnablePrinterQuery = $true    # IPP "describe yourself" question to printers (make, model, firmware, page count)
$EnableCameraQuery  = $true    # RTSP OPTIONS to cameras (the reply names the model)
$EnableGatewayServices = $true # does the gateway offer UPnP or NAT-PMP port mapping, and what is mapped (read only)
$EnableTunnelReach  = $true    # which ports on $TunnelServers answer from this office port
$EnableDhcpRenew    = $true    # renew the lease once while the capture runs, so the DHCP answer and its options are recorded
$EnableGatewayProbe = $true    # one HTTPS + one HTTP request to the default gateway (title, server, certificate)
$EnableFirewallPorts = $true   # gateway admin ports 4443/8443/10443 + SSH banner (a few single connections)
$EnableSsdp         = $true    # UPnP/SSDP discovery: routers, APs, printers announce model names (~3 s)
$EnablePrinterProbe = $true    # web page title of each network printer (model identification)
$EnableLeadChecks   = $true    # follow-up checks on what was found: the firewall's own VPN and admin pages, the ISP modem
                                # behind a double NAT, server management controllers (Redfish), VMware hosts, QNAP and
                                # Synology storage, RD Web and RD Gateway. Read only, public pages, nothing is logged in to.

# ---- This PC and its path to the internet (on by default) ----
$EnableOwnerLookup  = $true    # whois (RDAP) for the public IP: who the circuit's address block is registered to
$BandwidthRounds    = 2        # full bandwidth runs; every round is kept, the best one is reported
$EnableDnsTiming    = $true    # how long name lookups take through the site's DNS server compared with a public resolver
$EnableCloudCheck   = $true    # Microsoft 365 front doors, Teams media port, NAT behaviour (STUN) and outbound NTP
$EnableVoiceSample  = $true    # 20 s of pings at call pace (50 per second) to each $VoiceTargets entry
$EnableOutboundCheck = $true   # outbound ports to a public test host (portquiz.net) and test names that DNS filters block
$EnableTlsCheck     = $true    # read who issued the HTTPS certificate for Cloudflare and each remote desktop host (shows HTTPS inspection)
$EnableIpInfo       = $true    # public IP -> ISP/ASN/city lookup via ipinfo.io
$EnableDomainCheck  = $true    # public DNS for the client's email domain (from the user's sign-in name and DNS suffixes):
                                # where mail goes, SPF, DMARC, DKIM, MTA-STS. Asks 1.1.1.1, then this PC's resolver.
$EnableAdSites      = $true    # on a domain PC, Active Directory's own list of sites and their subnets (read as the signed-in user)
$EnableIpv6Check    = $true    # is IPv6 offered here, and does it reach the internet (Cloudflare over IPv6, 10 pings, an AAAA lookup)
$EnableOuiLookup    = $true    # unknown MAC vendor prefixes -> api.macvendors.com (prefix only)
$EnableBandwidth    = $true    # download/upload test with provider failover (below)
$BandwidthProviders = @('Cloudflare', 'MLab', 'Vultr')   # tried in order per direction; Vultr is download-only
                                # M-Lab publishes every test (incl. the public IP) in its open dataset
$VultrTestUrls      = @(        # Vultr 100 MB test files; the fastest-responding one is used
    'https://il-us-ping.vultr.com/vultr.com.100MB.bin',
    'https://ga-us-ping.vultr.com/vultr.com.100MB.bin',
    'https://nj-us-ping.vultr.com/vultr.com.100MB.bin'
)
$BandwidthSeconds   = 10       # per direction
$BandwidthStreams   = 4        # parallel streams
$MaxTestMB          = 1000     # cap on bandwidth test data (download + upload); gigabit needs ~1 GB for a full 10 s
$PingCount          = 180      # samples per target in the ping and TCP series, one per second (180 = 3 minutes)
$LookbackDays       = 30       # event log window
$TempEnableLocation = $true    # briefly allow location so netsh can read Wi-Fi details, then restore
$LldpMinSeconds     = 65       # LLDP/CDP capture window (admin, wired); CDP advertises every 60 s on Cisco/Meraki
$OutputRoot         = ''       # blank = C:\Users\Public\Documents\SiteAssessment (local, not synced to OneDrive)
$CopySummaryToClipboard = $true # paste the summary on your side through your remote support tool's clipboard sync
$OpenFolderWhenDone = $true
# =====================================================================

# Settings from -ConfigPath override the CONFIG block (only names that already exist above).
if ($ConfigPath) {
    $cfg = Import-PowerShellDataFile -LiteralPath $ConfigPath
    foreach ($k in $cfg.Keys) {
        if (Get-Variable -Name $k -Scope 0 -ErrorAction SilentlyContinue) { Set-Variable -Name $k -Value $cfg[$k] }
        else { Write-Host "Config: unknown setting '$k' ignored" -ForegroundColor Yellow }
    }
}
if ($Discovery) { $EnableDiscovery = $true }
if (-not $EnableDiscovery) {
    foreach ($n in @('EnableSubnetSweep', 'EnableRemoteSweep', 'EnableSweepPorts', 'EnableVendorDiscovery', 'EnableMulticastDiscovery', 'EnableDeviceIdentify',
                     'EnableDnsDiscovery', 'EnableSiteReach', 'EnableSnmp', 'EnableModemPage', 'EnableWindowsBuild', 'EnablePrinterQuery',
                     'EnableCameraQuery', 'EnableGatewayServices', 'EnableTunnelReach', 'EnableDhcpRenew', 'EnableGatewayProbe',
                     'EnableFirewallPorts', 'EnableSsdp', 'EnablePrinterProbe', 'EnableLeadChecks')) {
        Set-Variable -Name $n -Value $false
    }
}

# Hosted desktop profile -> the patterns and targets the collector uses. An empty pattern never matches.
if ($HostedDesktop) { $HostedDesktopName = $HostedDesktop; $HostedDesktopProfile = $null }
if ($HostedDesktopProfile -is [System.Collections.IDictionary]) {
    $HostedProfile = $HostedDesktopProfile
    $HostedDesktopName = 'Custom'
} elseif ($HostedDesktopProfiles.Contains($HostedDesktopName)) {
    $HostedProfile = $HostedDesktopProfiles[$HostedDesktopName]
} else {
    throw "Unknown hosted desktop profile '$HostedDesktopName'. Choose one of: $(@($HostedDesktopProfiles.Keys) -join ', '), or set `$HostedDesktopProfile."
}
$NeverMatch    = '(?!)'
$RdpHostHint   = if ("$($HostedProfile.HostPattern)") { "$($HostedProfile.HostPattern)" } else { $NeverMatch }
$RdpAppHint    = if ("$($HostedProfile.AppPattern)") { "$($HostedProfile.AppPattern)" } else { $NeverMatch }
$ProviderAsn   = if ("$($HostedProfile.ProviderAsn)") { "$($HostedProfile.ProviderAsn)" } else { $NeverMatch }
$HostedLabel   = if ("$($HostedProfile.Name)") { "$($HostedProfile.Name)" } else { 'Remote desktop' }
$ExtraTargets  = @(@($HostedProfile.Targets) + @($ExtraTargets) | Where-Object { $_ } | Select-Object -Unique)

$ScriptVersion = '1.0.0'
