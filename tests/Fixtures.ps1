# Builds fictional collector runs (assessment.json in a zip, as the collector writes them) for the
# merge tests and the sample report. Company, people, machines and addresses are all made up:
# public addresses come from the RFC 5737 documentation ranges, names from contoso/northwind.

function New-FixtureHops {
    # One traceroute: gateway, optional extra private hops (tunnel or double NAT), then public hops.
    param([string]$Gateway, [object[]]$Private = @(), [double]$FirstPublicMs = 9, [int]$PublicHops = 4, [string]$Target = '1.1.1.1')
    $hops = @([ordered]@{ Hop = 1; IP = $Gateway; Class = 'Private'; AvgMs = 1; Ptr = $null })
    $n = 2
    foreach ($p in $Private) { $hops += [ordered]@{ Hop = $n; IP = $p.IP; Class = $p.Class; AvgMs = $p.Ms; Ptr = $null }; $n++ }
    for ($k = 0; $k -lt $PublicHops; $k++) {
        $ip = if ($k -eq $PublicHops - 1) { $Target } else { '198.51.100.{0}' -f (10 + $k) }
        $hops += [ordered]@{ Hop = $n; IP = $ip; Class = 'Public'; AvgMs = [math]::Round($FirstPublicMs + 2 * $k, 1); Ptr = $null }
        $n++
    }
    return $hops
}

function New-FixtureTrace {
    param([string]$Target, $Hops, [bool]$Tunnel = $false, [bool]$DoubleNat = $false, [int]$CgnatHops = 0, [bool]$Reached = $true)
    $first = $Hops | Where-Object { $_.Class -eq 'Public' } | Select-Object -First 1
    [ordered]@{
        Target   = $Target
        Analysis = [ordered]@{
            HopCount = @($Hops).Count; FirstPublicHop = $first.Hop; FirstPublicIP = $first.IP; FirstPublicMs = $first.AvgMs; FirstPublicPtr = $null
            PrivateHopsAfterGw = @(); CarrierPrivateHops = @(); CgnatHops = $CgnatHops
            TunnelIndicator = $Tunnel; DoubleNatLikely = $DoubleNat; ReachedTarget = $Reached
        }
        Hops     = @($Hops)
    }
}

function New-FixtureSeries {
    param([string]$Target, [double]$AvgMs, [double]$LossPct = 0, [double]$JitterMs = 2, [int]$Sent = 180, $Port = $null)
    $recv = [int][math]::Round($Sent * (100 - $LossPct) / 100)
    $s = [ordered]@{ Target = $Target; Sent = $Sent; Received = $recv; LossPct = $LossPct; MinMs = [math]::Round($AvgMs * 0.8, 1)
                     AvgMs = $AvgMs; P95Ms = [math]::Round($AvgMs * 1.4, 1); MaxMs = [math]::Round($AvgMs * 2, 1); JitterMs = $JitterMs }
    if ($Port) { $s['Port'] = $Port }
    return $s
}

function New-FixtureRun {
    # One machine's run. Only the fields the merge reads are filled; the rest stay absent, as in a run
    # where a collector was unavailable.
    param(
        [string]$Site, [string]$Hostname, [string]$Serial, [string]$User,
        [ValidateSet('Wired', 'Wi-Fi')][string]$Connection = 'Wired',
        [datetime]$RunStart = [datetime]'2026-03-10T09:00:00',
        [string]$SourceIp, [string]$Gateway, [string]$PublicIp, [string]$Carrier = 'Northwind Fiber',
        [double]$DownMbps = 480, [double]$UpMbps = 95, [double]$IdleMs = 11, [double]$BufferbloatMs = 14,
        [double]$InetAvgMs = 12, [double]$InetLossPct = 0,
        [string]$Verdict = 'Local breakout', [string]$Confidence = 'Medium',
        [hashtable]$HostedDesktop = @{ Profile = 'RDP'; Name = 'Remote desktop'; HostPattern = ''; Targets = @() },
        [string[]]$SelectedTargets = @(), [object[]]$TcpSeries = @(), [object[]]$ExtraTraces = @(),
        [string]$Model = 'OptiPlex 7010', [string]$Manufacturer = 'Dell Inc.', [double]$AgeYears = 2.5,
        [string]$Os = 'Microsoft Windows 11 Pro', [bool]$IsWindows10 = $false, [double]$RamGB = 16,
        [object[]]$Flags = @(), [string]$DataCheck = 'PASS', [string]$Ipv6 = 'Not offered',
        [System.Collections.IDictionary]$Extra = @{}
    )
    $bwStart = $RunStart.AddMinutes(1)
    $hops = New-FixtureHops -Gateway $Gateway -FirstPublicMs ([math]::Max(3, $InetAvgMs - 6))
    $traces = @(New-FixtureTrace '1.1.1.1' $hops) + @($ExtraTraces)
    $wifi = if ($Connection -eq 'Wi-Fi') { [ordered]@{ SSID = 'Northwind-Staff'; Band = '5 GHz'; Channel = 36; SignalPct = 82; RadioType = '802.11ax'; ApVendor = 'Ubiquiti' } } else { $null }
    $run = [ordered]@{
        Meta = [ordered]@{
            ScriptVersion = '1.0.0'; SiteName = $Site; Notes = ''; Hostname = $Hostname; RunStart = $RunStart.ToString('s')
            TimeZone = 'Eastern Standard Time'; RunAsUser = "NORTHWIND\$User"; InventoriedUser = "NORTHWIND\$User"; SameUser = $true
            IsElevated = $false; Discovery = $false; HostedDesktop = $HostedDesktop; AdminTierActive = $false; AdminDowngraded = $false
            LanguageMode = 'FullLanguage'; PSVersion = '5.1.26100.1'; PSHost = 'Windows PowerShell ISE Host'; Stage = 'complete'; RunSeconds = 312
        }
        Network = [ordered]@{
            Adapters = @([ordered]@{ Name = $Connection; Description = $(if ($Connection -eq 'Wired') { 'Intel(R) Ethernet Connection I219-LM' } else { 'Intel(R) Wi-Fi 6E AX211 160MHz' })
                                     Status = 'Up'; IPv4 = @($SourceIp); SubnetMask = @('255.255.255.0'); DhcpEnabled = $true; DhcpServer = $Gateway; DnsServers = @($Gateway) })
            PrimaryAdapter = $Connection; PrimaryClass = $Connection; PhysicalAdapter = $Connection; PhysicalClass = $Connection
            PhysicalLinkMbps = $(if ($Connection -eq 'Wired') { 1000 } else { 1201 }); PhysicalDescription = $Connection
            VpnHoldsDefaultRoute = $false; MultipleConnected = $false; SourceIp = $SourceIp; Gateway = $Gateway
        }
        Machine = [ordered]@{
            Hostname = $Hostname; Manufacturer = $Manufacturer; Model = $Model; SerialNumber = $Serial; FormFactor = 'Desktop'
            ApproxAgeYears = $AgeYears; AgeSource = 'BIOS date'; Cpu = 'Intel(R) Core(TM) i5-13500'; RamGB = $RamGB
            Disks = @([ordered]@{ MediaType = 'SSD'; SizeGB = 512 }); OsCaption = $Os; OsDisplayVersion = '24H2'; IsWindows10 = $IsWindows10
            Tpm = [ordered]@{ Present = $true; SpecVersion = '2.0' }
        }
        Identity = [ordered]@{ JoinType = 'Entra joined'; IntuneEnrolled = $true; UserIsLocalAdmin = $false; MappedDrives = @() }
        Software = [ordered]@{ AppCount = 3; Apps = @([ordered]@{ Name = 'Microsoft 365 Apps for business'; Version = '16.0'; Publisher = 'Microsoft Corporation' }); Tagged = [ordered]@{} }
        Peripherals = [ordered]@{ Printers = @(); Screens = @([ordered]@{ Width = 1920; Height = 1080 }); MonitorCount = 1 }
        Wireless = $(if ($wifi) { [ordered]@{ Status = 'ok'; Current = $wifi } } else { [ordered]@{ Status = 'not connected' } })
        NetworkExtra = [ordered]@{ Gateway = $Gateway; GatewayMac = '00-11-22-33-44-55'; GatewayVendor = 'Ubiquiti Inc'; DnsServers = @() }
        Rdp = [ordered]@{ SelectedTargets = @($SelectedTargets); HostedConnections = @(); DnsCacheHintNames = @(); EventLogServers = @(); UnresolvedCandidates = @() }
        Egress = [ordered]@{ PublicIPv4 = $PublicIp; Carrier = $Carrier; EgressCity = 'Columbus, Ohio'; CfAsOrganization = $Carrier }
        Traceroutes = $traces
        PingSeries = @((New-FixtureSeries $Gateway 1.2 0 0.3), (New-FixtureSeries '1.1.1.1' $InetAvgMs $InetLossPct 2.1))
        TcpSeries = @($TcpSeries)
        Bandwidth = [ordered]@{
            Status = 'ok'; DownloadMbps = $DownMbps; UploadMbps = $UpMbps; DownloadOk = $true; UploadOk = $true
            DownloadProvider = 'Cloudflare'; UploadProvider = 'Cloudflare'; IdleLatencyMs = $IdleMs
            BufferbloatMs = $BufferbloatMs; BufferbloatGrade = $(if ($BufferbloatMs -lt 30) { 'A (good)' } else { 'B (fair)' })
            StartedAt = $bwStart.ToString('s'); FinishedAt = $bwStart.AddSeconds(45).ToString('s')
        }
        Topology = [ordered]@{ Verdict = $Verdict; Confidence = $Confidence; BackhaulScore = 0; SplitScore = 0; Signals = @('Internet trace goes straight from the gateway to a public ISP hop') }
        Findings = @([ordered]@{ Area = 'Traffic design'; Confidence = 'Likely'; Finding = "Traffic design: $Verdict."; Evidence = @('Internet trace goes straight from the gateway to a public ISP hop') })
        Flags = @($Flags)
        Validation = [ordered]@{ Overall = $DataCheck; Checks = @() }
        Errors = @()
        Ipv6 = $(if ($Ipv6 -eq 'Working') { [ordered]@{ Status = 'Working'; GlobalPrefixes = @('2001:db8:20:1::/64'); TemporaryAddresses = $true; UniqueLocal = $false; DefaultRoute = $true; RouterIsLinkLocal = $true; DnsServers = @(); Egress = [ordered]@{ Reached = $true; Prefix = '2001:db8:20:1::/64'; SameAsPc = $true; Colo = 'ORD' }; Ping = [ordered]@{ Sent = 10; Received = 10; LossPct = 0; AvgMs = 14.2 }; AaaaLookup = $true } } else { [ordered]@{ Status = 'Not offered'; GlobalPrefixes = @(); DefaultRoute = $false; UniqueLocal = $false; AaaaLookup = $true } })
    }
    foreach ($k in $Extra.Keys) { $run[$k] = $Extra[$k] }
    return $run
}

function Save-FixtureRun {
    # Writes the run the way the collector does: <site>_<host>_<stamp>\assessment.json + summary.txt, zipped.
    param($Run, [string]$Folder)
    $site = ($Run.Meta.SiteName -replace '[^A-Za-z0-9_-]', '_')
    $name = '{0}_{1}_{2}' -f $site, $Run.Meta.Hostname, ([datetime]$Run.Meta.RunStart).ToString('yyyyMMdd-HHmm')
    $dir = Join-Path $Folder $name
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $dir 'assessment.json'), ($Run | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))
    [IO.File]::WriteAllText((Join-Path $dir 'summary.txt'), "Fixture run $name", (New-Object Text.UTF8Encoding $false))
    $zip = Join-Path $Folder "$name.zip"
    Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $zip -Force
    Remove-Item -LiteralPath $dir -Recurse -Force
    return $zip
}

function New-SingleSiteFixture {
    # One wired PC at one office: the smallest useful assessment.
    param([string]$Folder)
    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    $run = New-FixtureRun -Site 'Main office' -Hostname 'NW-FRONT01' -Serial 'NWSN0001' -User 'jlee' `
        -SourceIp '10.20.1.25' -Gateway '10.20.1.1' -PublicIp '203.0.113.40'
    Save-FixtureRun $run $Folder | Out-Null
}

function New-MultiSiteFixture {
    # Two offices of Northwind Traders working in a hosted desktop ("Contoso Cloud"):
    #   Main office  - a wired PC and a Wi-Fi PC whose bandwidth tests overlapped
    #   Warehouse    - a PC that exits through the main office's public IP (shared egress),
    #                  plus the visiting test laptop also run at the main office (same serial)
    param([string]$Folder)
    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    $hd = @{ Profile = 'Custom'; Name = 'Contoso Cloud'; HostPattern = 'contosocloud\.com'; Targets = @('connect.contosocloud.com:443') }
    $portal = 'connect.contosocloud.com'
    $t0 = [datetime]'2026-03-10T09:00:00'
    $smb1Risk = [ordered]@{ Severity = 'High'; Category = 'Network risk'; Message = '1 device(s) still accept SMBv1, the file-sharing version WannaCry spread over: 10.20.1.10 (nw-fs01)' }
    # With -Discovery, the front desk PC also swept the warehouse subnet across the site tunnel.
    $remote = [ordered]@{
        RemoteSubnets = [ordered]@{ Candidates = @([ordered]@{ Cidr = '10.20.2.0/24'; Reasons = @('route via 10.20.1.254'); Hosted = $false }); Answer = '1'
                                    Selected = @([ordered]@{ Subnet = '10.20.2.0/24'; Reason = 'chosen at the prompt (route via 10.20.1.254)' }); Rejected = @() }
        RemoteSweep = [ordered]@{
            Subnets = @([ordered]@{ Subnet = '10.20.2.0/24'; Reason = 'chosen at the prompt (route via 10.20.1.254)'; AddressesSwept = 254; PingResponders = 1; TcpOnly = 1; Devices = 2; Seconds = 14.2 })
            PortsChecked = @(22, 80, 443, 445, 3389, 9100); PresencePorts = @(22, 80, 443, 445, 3389)
            RoleSummary = @('Printer: 1', 'Windows PC, server or NAS (file sharing on): 1')
            Devices = @(
                [ordered]@{ IP = '10.20.2.40'; Mac = $null; Vendor = $null; RespondedToPing = $true; Name = 'nw-dock-mfp.northwind.local'; OpenPorts = @(80, 443, 9100); Role = 'Printer'; Subnet = '10.20.2.0/24'; Remote = $true }
                [ordered]@{ IP = '10.20.2.31'; Mac = $null; Vendor = $null; RespondedToPing = $false; Name = $null; OpenPorts = @(445); Role = 'Windows PC, server or NAS (file sharing on)'; Subnet = '10.20.2.0/24'; Remote = $true }
            )
        }
        AdSites = [ordered]@{ Forest = 'northwind.local'; CurrentSite = 'Main-Office'; Sites = @(
            [ordered]@{ Name = 'Main-Office'; Location = ''; Subnets = @('10.20.1.0/24') }
            [ordered]@{ Name = 'Warehouse'; Location = ''; Subnets = @('10.20.2.0/24') }
            [ordered]@{ Name = 'Branch'; Location = ''; Subnets = @('10.20.9.0/24') }
        ) }
        LeadChecks = [ordered]@{ Leads = 3; Checks = @(
            [ordered]@{ Kind = 'Firewall'; IP = '10.20.1.1'; What = 'Fortinet SSL-VPN portal'; Detail = 'port 443 answers 200: FortiGate SSL VPN'; Url = 'https://10.20.1.1/remote/login' }
            [ordered]@{ Kind = 'Hypervisor'; IP = '10.20.1.40'; What = 'VMware ESXi 8.0.2 build-22380479'; Detail = 'version 8.0.2 build 22380479 (HostAgent)'; Url = 'https://10.20.1.40/sdk'; Version = '8.0.2' }
        ) }
        Snmp = [ordered]@{ Community = 'public'; Asked = 6; Answered = 2; Routers = 1; ArpEntries = 2; WanAddresses = @('203.0.113.42'); Ups = 1; Devices = @(
            [ordered]@{ IP = '10.20.1.1'; SysName = 'nw-fw01'; SysDescr = 'Contoso Firewall 60'; Model = 'CF-60'; Serial = 'CF60X0001'
                Router = [ordered]@{ Forwarding = $true
                    Addresses = @([ordered]@{ IP = '10.20.1.1'; Mask = '255.255.255.0'; Prefix = 24; IfIndex = 2; Class = 'Private' }, [ordered]@{ IP = '203.0.113.42'; Mask = '255.255.255.248'; Prefix = 29; IfIndex = 5; Class = 'Public' })
                    WanAddresses = @('203.0.113.42')
                    Arp = @([ordered]@{ IP = '10.20.1.25'; Mac = '00-11-22-33-44-01'; IfIndex = 2 }, [ordered]@{ IP = '10.20.1.61'; Mac = '00-11-22-33-44-02'; IfIndex = 2 })
                    Routes = @([ordered]@{ Destination = '0.0.0.0'; Prefix = 0; NextHop = '203.0.113.41' }, [ordered]@{ Destination = '10.20.2.0'; Prefix = 24; NextHop = '10.20.1.254' })
                    DefaultRoute = @('203.0.113.41') } }
            [ordered]@{ IP = '10.20.1.5'; SysName = 'nw-ups01'; SysDescr = 'Contoso Power network card'
                Ups = [ordered]@{ Source = 'UPS-MIB'; Manufacturer = 'Contoso Power'; Model = 'CP1500'; Battery = 'normal'; OnBattery = $true; ChargePct = 80; MinutesRemaining = 12; LoadPct = 40; ReplaceBattery = $null } }
        ) }
        Identify = [ordered]@{ DeviceCount = 2; Devices = @(
            [ordered]@{ IP = '10.20.2.40'; Mac = $null; MacVendor = $null; MacSource = $null; Subnet = '10.20.2.0/24'; Remote = $true; Name = 'nw-dock-mfp.northwind.local'; OpenPorts = @(80, 443, 9100); Kind = 'Printer'; Vendor = 'Contoso'; Model = 'MFP 400'; Confidence = 'Likely'; Evidence = @('web page title: Contoso MFP 400') }
            [ordered]@{ IP = '10.20.2.31'; Mac = '00-15-5D-01-02-03'; MacVendor = 'Microsoft Corporation'; MacSource = 'NetBIOS'; Subnet = '10.20.2.0/24'; Remote = $true; Name = 'NW-DOCK02'; OpenPorts = @(445); Kind = 'Windows computer'; Vendor = 'Microsoft'; Confidence = 'Likely'; Evidence = @('NetBIOS name NW-DOCK02') }
        ) }
    }
    $runs = @(
        (New-FixtureRun -Site 'Main office' -Hostname 'NW-FRONT01' -Serial 'NWSN0001' -User 'jlee' -RunStart $t0 `
            -SourceIp '10.20.1.25' -Gateway '10.20.1.1' -PublicIp '203.0.113.40' -HostedDesktop $hd -SelectedTargets @($portal, 'rdp.example.com') `
            -TcpSeries @((New-FixtureSeries $portal 38 0 3 180 443), (New-FixtureSeries 'rdp.example.com' 20 0 1 180 3389)) -Flags @($smb1Risk) -Ipv6 'Working' -Extra $remote)
        (New-FixtureRun -Site 'Main office' -Hostname 'NW-ACCT02' -Serial 'NWSN0002' -User 'mgarcia' -Connection 'Wi-Fi' -RunStart $t0.AddSeconds(20) `
            -SourceIp '10.20.1.61' -Gateway '10.20.1.1' -PublicIp '203.0.113.40' -DownMbps 210 -UpMbps 80 -HostedDesktop $hd -SelectedTargets @($portal) `
            -TcpSeries @((New-FixtureSeries $portal 44 0.6 6 180 443)) -Model 'Latitude 5440' -AgeYears 6.1 -Os 'Microsoft Windows 10 Pro' -IsWindows10 $true -RamGB 8 `
            -Flags @([ordered]@{ Severity = 'High'; Category = 'Lifecycle'; Message = 'Windows 10 (out of support since Oct 2025)' }, $smb1Risk) -DataCheck 'WARN')
        (New-FixtureRun -Site 'Warehouse' -Hostname 'NW-DOCK01' -Serial 'NWSN0003' -User 'swilson' -RunStart $t0.AddHours(2) `
            -SourceIp '10.20.2.30' -Gateway '10.20.2.1' -PublicIp '203.0.113.40' -DownMbps 95 -UpMbps 18 -InetAvgMs 31 -IdleMs 29 `
            -Verdict 'Full backhaul' -Confidence 'Medium' -HostedDesktop $hd -SelectedTargets @($portal) `
            -TcpSeries @((New-FixtureSeries $portal 61 1.2 9 180 443)))
        (New-FixtureRun -Site 'Main office' -Hostname 'TECH-LAPTOP' -Serial 'TECHSN9' -User 'tech' -RunStart $t0.AddMinutes(40) `
            -SourceIp '10.20.1.90' -Gateway '10.20.1.1' -PublicIp '203.0.113.40' -HostedDesktop $hd -SelectedTargets @($portal, 'jumpbox.example.net') `
            -TcpSeries @((New-FixtureSeries $portal 37 0 3 180 443), (New-FixtureSeries 'jumpbox.example.net' 25 0 2 180 3389)) -Model 'ThinkPad T14' -Manufacturer 'LENOVO')
        (New-FixtureRun -Site 'Warehouse' -Hostname 'TECH-LAPTOP' -Serial 'TECHSN9' -User 'tech' -RunStart $t0.AddHours(2).AddMinutes(30) `
            -SourceIp '10.20.2.90' -Gateway '10.20.2.1' -PublicIp '203.0.113.40' -DownMbps 97 -UpMbps 19 -InetAvgMs 30 -IdleMs 28 `
            -Verdict 'Full backhaul' -HostedDesktop $hd -SelectedTargets @($portal, 'jumpbox.example.net') `
            -TcpSeries @((New-FixtureSeries $portal 59 1 8 180 443), (New-FixtureSeries 'jumpbox.example.net' 40 0 3 180 3389)) -Model 'ThinkPad T14' -Manufacturer 'LENOVO')
    )
    foreach ($r in $runs) { Save-FixtureRun $r $Folder | Out-Null }
}
