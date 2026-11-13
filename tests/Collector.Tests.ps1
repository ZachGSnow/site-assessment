BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    # Load the collector's functions without running a collection.
    . ([scriptblock]::Create((Get-ScriptFunctionText $CollectorPath)))
    $script:Config = Get-ConfigScript $CollectorPath
    # CONFIG values the functions read
    $script:NeverMatch = '(?!)'
    $script:ProviderAsn = $NeverMatch
    $script:HostedLabel = 'Remote desktop'

    function New-Hop { param([int]$Hop, [string]$IP, [double]$Ms) [pscustomobject]@{ Hop = $Hop; IP = $IP; Class = (Get-IpClass $IP); AvgMs = $Ms; Ptr = $null } }
    function New-TraceResult {
        param([string]$Target, [object[]]$Hops)
        @{ Target = $Target; Hops = $Hops; Analysis = (Get-TraceAnalysis $Hops) }
    }
    function New-Run {
        # The parts of a collector result the topology verdict reads.
        param([object[]]$Traces, [string]$Carrier = 'Northwind Fiber', [double]$InetAvgMs = 12, [bool]$VpnDefault = $false,
              [object[]]$RdpPath = @(), [object[]]$Mtu = @(), [string[]]$DnsServers = @('10.20.1.1'))
        @{
            Egress       = @{ Carrier = $Carrier; EgressCity = 'Columbus, Ohio' }
            Traceroutes  = $Traces
            PingSeries   = @(@{ Target = '1.1.1.1'; AvgMs = $InetAvgMs })
            RdpPath      = $RdpPath
            Rdp          = @{ ActiveTcp = @() }
            Mtu          = $Mtu
            Network      = @{ VpnHoldsDefaultRoute = $VpnDefault; Adapters = @(@{ Status = 'Up'; IPv4 = @('10.20.1.25'); SubnetMask = @('255.255.255.0') }) }
            NetworkExtra = @{ DnsServers = @($DnsServers | ForEach-Object { @{ Server = $_; Type = 'Private, not the gateway' } }) }
        }
    }
    $script:Direct = New-TraceResult '1.1.1.1' @((New-Hop 1 '10.20.1.1' 1), (New-Hop 2 '198.51.100.10' 8), (New-Hop 3 '198.51.100.11' 10), (New-Hop 4 '1.1.1.1' 12))
}

Describe 'Collector script' {
    It 'parses without errors' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($CollectorPath, [ref]$null, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }
    It 'ends with the paste-check marker' {
        (Get-Content -LiteralPath $CollectorPath -Tail 3) -join "`n" | Should -Match '# END OF COLLECTOR SCRIPT'
    }
}

Describe 'CONFIG defaults' {
    It 'keeps every active discovery check off by default' {
        $v = & $Config
        $v.EnableDiscovery | Should -BeFalse
        foreach ($n in 'EnableSubnetSweep', 'EnableSweepPorts', 'EnableSnmp', 'EnableDeviceIdentify', 'EnableVendorDiscovery',
                       'EnableMulticastDiscovery', 'EnableGatewayServices', 'EnableModemPage', 'EnableDhcpRenew', 'EnableFirewallPorts') {
            $v[$n] | Should -BeFalse -Because "$n is active discovery"
        }
    }
    It 'turns discovery on with -Discovery' {
        $v = & $Config -Discovery
        $v.EnableDiscovery | Should -BeTrue
        $v.EnableSubnetSweep | Should -BeTrue
        $v.EnableSnmp | Should -BeTrue
    }
    It 'keeps the checks of this PC and its internet path on by default' {
        $v = & $Config
        foreach ($n in 'EnableBandwidth', 'EnableTlsCheck', 'EnableCloudCheck', 'EnableVoiceSample') { $v[$n] | Should -BeTrue -Because $n }
    }
    It 'ships with no site, subnet or server of any client' {
        $v = & $Config
        @($v.SiteList).Count | Should -Be 0
        @($v.SiteSubnets).Count | Should -Be 0
        @($v.TunnelServers).Count | Should -Be 0
        @($v.ExtraTargets).Count | Should -Be 0
    }
    It 'uses the generic RDP profile by default, with patterns that never match' {
        $v = & $Config
        $v.HostedLabel | Should -Be 'Remote desktop'
        'anything.example.com' | Should -Not -Match $v.RdpHostHint
        'anyapp.exe' | Should -Not -Match $v.RdpAppHint
        'Northwind Fiber' | Should -Not -Match $v.ProviderAsn
    }
    It 'loads a named profile with -HostedDesktop and puts its targets first' {
        $v = & $Config -HostedDesktop AzureVirtualDesktop
        $v.HostedLabel | Should -Be 'Azure Virtual Desktop'
        $v.ExtraTargets | Should -Contain 'rdweb.wvd.microsoft.com:443'
        'client.wvd.microsoft.com' | Should -Match $v.RdpHostHint
    }
    It 'matches only the provider''s own domains in the built-in host patterns' -ForEach @(
        @{ Profile = 'CitrixCloud'; Yes = 'northwind.cloud.com'; No = 'contosocloud.com' }
        @{ Profile = 'CitrixCloud'; Yes = 'global-all.g.nssvc.net'; No = 'nssvc.network.example' }
        @{ Profile = 'AzureVirtualDesktop'; Yes = 'rdweb.wvd.microsoft.com'; No = 'mywvd.microsoft.com.example.net' }
        @{ Profile = 'Windows365'; Yes = 'windows365.microsoft.com'; No = 'notwindows365.example.com' }
    ) {
        $v = & $Config -HostedDesktop $Profile
        $Yes | Should -Match $v.RdpHostHint
        $No | Should -Not -Match $v.RdpHostHint
    }
    It 'rejects an unknown profile name' {
        { & $Config -HostedDesktop 'NoSuchProfile' } | Should -Throw '*Unknown hosted desktop profile*'
    }
    It 'applies a -ConfigPath file, including a custom profile' {
        $cfg = Join-Path $TestDrive 'job.psd1'
        Set-Content -LiteralPath $cfg -Value @"
@{
    SiteList = @('Main office', 'Warehouse')
    HostedDesktopProfile = @{ Name = 'Contoso Cloud'; HostPattern = 'contosocloud\.com'; AppPattern = 'ContosoConnect'; Targets = @('connect.contosocloud.com:443'); ProviderAsn = 'Contoso Cloud' }
    EnableSnmp = `$false
}
"@
        $v = & $Config -ConfigPath $cfg -Discovery
        $v.SiteList | Should -Be @('Main office', 'Warehouse')
        $v.HostedLabel | Should -Be 'Contoso Cloud'
        $v.HostedDesktopName | Should -Be 'Custom'
        $v.ExtraTargets | Should -Contain 'connect.contosocloud.com:443'
        $v.EnableSnmp | Should -BeFalse -Because 'a per-job switch still turns one discovery check off'
        $v.EnableSubnetSweep | Should -BeTrue
    }
    It 'every built-in profile has the fields the collector reads' {
        $v = & $Config
        foreach ($k in $v.HostedDesktopProfiles.Keys) {
            $p = $v.HostedDesktopProfiles[$k]
            foreach ($f in 'Name', 'HostPattern', 'AppPattern', 'Targets', 'ProviderAsn') { $p.Contains($f) | Should -BeTrue -Because "$k.$f" }
        }
    }
}

Describe 'Parsing tool output' {
    It 'reads tracert hops, timeouts and the address class' {
        $text = @'
Tracing route to one.one.one.one [1.1.1.1]
over a maximum of 20 hops:

  1    <1 ms    <1 ms    <1 ms  10.20.1.1
  2     *        *        *     Request timed out.
  3     9 ms     8 ms    10 ms  100.64.0.1
  4    12 ms    11 ms    13 ms  198.51.100.10

Trace complete.
'@
        $hops = @(ConvertFrom-Tracert $text)
        $hops.Count | Should -Be 4
        $hops[0].Class | Should -Be 'Private'
        $hops[1].Class | Should -Be 'Timeout'
        $hops[2].Class | Should -Be 'CGNAT'
        $hops[3].AvgMs | Should -Be 12
    }
    It 'reads ping output into loss, average, p95 and jitter' {
        $text = (@(10, 12, 14, 12) | ForEach-Object { "Reply from 1.1.1.1: bytes=32 time=$($_)ms TTL=57" }) -join "`r`n"
        $p = ConvertFrom-PingOutput $text '1.1.1.1' 5
        $p.Received | Should -Be 4
        $p.LossPct | Should -Be 20
        $p.AvgMs | Should -Be 12
        $p.MaxMs | Should -Be 14
        $p.JitterMs | Should -Be 2
    }
}

Describe 'Trace analysis' {
    It 'calls a slow private hop after the gateway a tunnel' {
        $a = Get-TraceAnalysis @((New-Hop 1 '10.20.1.1' 1), (New-Hop 2 '10.0.0.1' 24), (New-Hop 3 '198.51.100.10' 30))
        $a.TunnelIndicator | Should -BeTrue
        $a.DoubleNatLikely | Should -BeFalse
    }
    It 'calls a fast private hop after the gateway double NAT' {
        $a = Get-TraceAnalysis @((New-Hop 1 '10.20.1.1' 1), (New-Hop 2 '192.168.0.1' 2), (New-Hop 3 '198.51.100.10' 9))
        $a.DoubleNatLikely | Should -BeTrue
        $a.TunnelIndicator | Should -BeFalse
    }
    It 'treats private hops after a CGNAT hop as the carrier''s own' {
        $a = Get-TraceAnalysis @((New-Hop 1 '10.20.1.1' 1), (New-Hop 2 '100.64.0.1' 20), (New-Hop 3 '172.16.5.1' 30), (New-Hop 4 '198.51.100.10' 35))
        $a.CgnatHops | Should -Be 1
        $a.TunnelIndicator | Should -BeFalse
        @($a.CarrierPrivateHops).Count | Should -Be 1
    }
}

Describe 'Traffic design verdict' {
    It 'is local breakout when the internet trace goes straight out' {
        (Get-TopologyVerdict (New-Run @($Direct))).Verdict | Should -Be 'Local breakout'
    }
    It 'is full backhaul when the internet exits through the hosted desktop provider' {
        $script:ProviderAsn = 'Contoso Cloud'
        try { (Get-TopologyVerdict (New-Run @($Direct) -Carrier 'AS64500 Contoso Cloud')).Verdict | Should -Be 'Full backhaul' }
        finally { $script:ProviderAsn = $NeverMatch }
    }
    It 'is full backhaul when a client VPN holds the default route' {
        (Get-TopologyVerdict (New-Run @($Direct) -VpnDefault $true)).Verdict | Should -Be 'Full backhaul'
    }
    It 'is a split tunnel when the remote desktop host is private and reached through a tunnel the internet does not use' {
        $rdp = New-TraceResult '10.50.0.10' @((New-Hop 1 '10.20.1.1' 1), (New-Hop 2 '10.50.255.1' 22), (New-Hop 3 '10.50.0.10' 24))
        $run = New-Run @($Direct, $rdp) -RdpPath @(@{ Host = 'rdgw.contoso.com'; ResolvesPrivate = $true; ResolvedIPs = @('10.50.0.10') })
        $v = Get-TopologyVerdict $run @('10.50.0.10')
        $v.Verdict | Should -Be 'Split tunnel (local internet, RDP over tunnel)'
        $v.SplitScore | Should -BeGreaterOrEqual 2
    }
    It 'does not count CGNAT access latency as backhaul' {
        $cg = New-TraceResult '1.1.1.1' @((New-Hop 1 '10.20.1.1' 1), (New-Hop 2 '100.64.0.1' 30), (New-Hop 3 '198.51.100.10' 38), (New-Hop 4 '1.1.1.1' 40))
        $v = Get-TopologyVerdict (New-Run @($cg) -InetAvgMs 40)
        $v.Verdict | Should -Be 'Local breakout'
        $v.BackhaulScore | Should -Be 0
    }
}

Describe 'Bufferbloat grade' {
    It 'grades <Loaded> ms loaded over <Idle> ms idle as <Grade>' -ForEach @(
        @{ Idle = 10; Loaded = 25; Grade = 'A (good)' }
        @{ Idle = 10; Loaded = 80; Grade = 'B (fair)' }
        @{ Idle = 10; Loaded = 200; Grade = 'C (poor)' }
    ) {
        $res = @{ IdleLatencyMs = $Idle; DownloadLoadedLatencyMs = $Loaded; UploadLoadedLatencyMs = $null }
        Update-Bufferbloat $res
        $res['BufferbloatMs'] | Should -Be ($Loaded - $Idle)
        $res['BufferbloatGrade'] | Should -Be $Grade
    }
    It 'leaves the grade empty without an idle figure' {
        $res = @{ IdleLatencyMs = $null; DownloadLoadedLatencyMs = 50 }
        Update-Bufferbloat $res
        $res['BufferbloatGrade'] | Should -BeNullOrEmpty
    }
}

Describe 'Other subnets (Phase A)' {
    It 'is off by default and on with -Discovery' {
        (& $Config).EnableRemoteSweep | Should -BeFalse
        (& $Config -Discovery).EnableRemoteSweep | Should -BeTrue
    }
    It 'reads <Text> as <Cidr>' -ForEach @(
        @{ Text = '10.10.2'; Cidr = '10.10.2.0/24' }
        @{ Text = '10.10.8.0/23'; Cidr = '10.10.8.0/23' }
        @{ Text = '10.10.9.77/23'; Cidr = '10.10.8.0/23' }
        @{ Text = ' 192.168.40.0/30 '; Cidr = '192.168.40.0/30' }
    ) {
        (ConvertTo-SubnetSpec $Text).Cidr | Should -Be $Cidr
    }
    It 'refuses <Text>' -ForEach @(
        @{ Text = '10.0.0.0/16' }, @{ Text = '10.10' }, @{ Text = '300.1.1' }, @{ Text = '10.1.1.0/31' }, @{ Text = 'office' }
    ) {
        ConvertTo-SubnetSpec $Text | Should -BeNullOrEmpty
    }
    It 'lists every usable address of a subnet' {
        $h = Get-SubnetHosts (ConvertTo-SubnetSpec '10.10.2')
        $h.Count | Should -Be 254
        $h[0] | Should -Be '10.10.2.1'
        $h[-1] | Should -Be '10.10.2.254'
    }
    It 'finds the subnets this PC already knows about, without its own' {
        $run = @{
            Network      = @{ Adapters = @(@{ Status = 'Up'; DhcpServer = '10.20.1.1' }) }
            NetworkExtra = @{
                Routes     = @(@{ Prefix = '10.30.0.0/24'; NextHop = '10.20.1.254' }, @{ Prefix = '10.0.0.0/8'; NextHop = '10.20.1.254' }, @{ Prefix = '10.20.1.0/24'; NextHop = '0.0.0.0' })
                DnsServers = @(@{ Server = '10.30.0.5' }, @{ Server = '1.1.1.1' })
            }
            Servers      = @{ Servers = @(@{ Name = 'fs01'; IPs = @('10.40.7.10') }) }
            Peripherals  = @{ Printers = @(@{ Name = 'Front'; HostAddress = '10.20.1.50'; IsVirtual = $false }) }
            Traceroutes  = @(@{ Target = '1.1.1.1'; Hops = @(@{ Hop = 1; IP = '10.20.1.1'; Class = 'Private' }, @{ Hop = 2; IP = '10.99.0.1'; Class = 'Private' }, @{ Hop = 3; IP = '100.64.0.1'; Class = 'CGNAT' }, @{ Hop = 4; IP = '172.16.0.1'; Class = 'Private' }) })
            RdpPath      = @(@{ Host = 'rdgw.contoso.com'; ResolvedIPs = @('10.50.0.10') })
            Rdp          = @{ ActiveTcp = @() }
        }
        $c = @(Get-CandidateSubnets $run @(ConvertTo-NetRange '10.20.1.25' 24))
        $c.Cidr | Should -Be @('10.30.0.0/24', '10.40.7.0/24', '10.50.0.0/24', '10.99.0.0/24')
        ($c | Where-Object Cidr -eq '10.30.0.0/24').Reasons | Should -Contain 'DNS server 10.30.0.5'
        ($c | Where-Object Cidr -eq '10.50.0.0/24').Hosted | Should -BeTrue
        ($c | Where-Object Cidr -eq '10.40.7.0/24').Hosted | Should -BeFalse
    }
    It 'sweeps only what is listed or picked, never this PC''s own subnet, and stops at the limit' {
        $cands = @(
            [pscustomobject]@{ Cidr = '10.30.0.0/24'; Reasons = @('route via 10.20.1.254'); Hosted = $false }
            [pscustomobject]@{ Cidr = '10.40.7.0/24'; Reasons = @('server fs01'); Hosted = $false }
            [pscustomobject]@{ Cidr = '10.50.0.0/24'; Reasons = @('remote desktop host'); Hosted = $true }
        )
        $local = @(ConvertTo-NetRange '10.20.1.25' 24)
        $none = Select-ScanSubnets -Explicit @() -Candidates $cands -Answer '' -Exclude $local
        @($none.Selected).Count | Should -Be 0 -Because 'inferred subnets are never swept on their own'
        $some = Select-ScanSubnets -Explicit @('10.60.1', '10.20.1', 'bad') -Candidates $cands -Answer '1,3' -Exclude $local
        @($some.Selected | ForEach-Object Cidr) | Should -Be @('10.60.1.0/24', '10.30.0.0/24', '10.50.0.0/24')
        $some.Selected[0].Reason | Should -Be 'listed in CONFIG'
        $some.Rejected | Should -Contain '10.20.1.0/24: this PC''s own subnet, covered by the local sweep'
        @($some.Rejected | Where-Object { $_ -like 'bad:*' }).Count | Should -Be 1
        @((Select-ScanSubnets -Candidates $cands -Answer '2-3' -Exclude $local).Selected | ForEach-Object Cidr) | Should -Be @('10.40.7.0/24', '10.50.0.0/24')
        $capped = Select-ScanSubnets -Candidates $cands -Answer 'A' -Exclude $local -Max 2
        @($capped.Selected).Count | Should -Be 2
        @($capped.Rejected | Where-Object { $_ -like '*over the limit*' }).Count | Should -Be 1
    }
    It 'sweeps a subnet across routing: ping, then TCP on hosts that ignore ping, then the sweep ports' {
        # Loopback stands in for the far subnet, so the test sends nothing onto a network.
        $listener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
            $spec = ConvertTo-SubnetSpec '127.0.0.0/30'
            $spec.Reason = 'test'
            $r = Invoke-RemoteSweep -Specs @($spec) -Ports @($port) -PresencePorts @($port) -TimeoutMs 1000
            $r.Subnets[0].Subnet | Should -Be '127.0.0.0/30'
            $r.Subnets[0].AddressesSwept | Should -Be 2
            $one = $r.Devices | Where-Object IP -eq '127.0.0.1'
            $one | Should -Not -BeNullOrEmpty
            $one.Remote | Should -BeTrue
            $one.OpenPorts | Should -Contain $port
            $one.Subnet | Should -Be '127.0.0.0/30'
        } finally { $listener.Stop() }
    }
}

Describe 'Router and UPS tables over SNMP (Phase B)' {
    It 'reads a MAC from an SNMP octet string' {
        ConvertFrom-SnmpMac 'aa:bb:cc:dd:ee:0f' | Should -Be 'AA-BB-CC-DD-EE-0F'
        ConvertFrom-SnmpMac '00-15-5D-01-02-03' | Should -Be '00-15-5D-01-02-03'
        ConvertFrom-SnmpMac '00-00-00-00-00-00' | Should -BeNullOrEmpty
        ConvertFrom-SnmpMac 'Lobby printer' | Should -BeNullOrEmpty
    }
    It 'reads both ARP table layouts' {
        $old = @([pscustomobject]@{ Index = '3.10.20.2.31'; Value = '00-15-5D-01-02-03' }, [pscustomobject]@{ Index = '3.10.20.2.99'; Value = '00-00-00-00-00-00' })
        $new = @([pscustomobject]@{ Index = '4.1.4.10.20.2.40'; Value = 'AC-DE-48-00-11-22' })
        $a = @(ConvertFrom-ArpRows $old)
        $a.Count | Should -Be 1
        $a[0].IP | Should -Be '10.20.2.31'
        $a[0].IfIndex | Should -Be 3
        (ConvertFrom-ArpRows $new)[0].IP | Should -Be '10.20.2.40'
    }
    It 'reads a router''s own addresses and marks the public one' {
        $if = @([pscustomobject]@{ Index = '10.20.1.1'; Value = 2 }, [pscustomobject]@{ Index = '203.0.113.42'; Value = 5 }, [pscustomobject]@{ Index = '127.0.0.1'; Value = 1 })
        $mk = @([pscustomobject]@{ Index = '10.20.1.1'; Value = '255.255.255.0' }, [pscustomobject]@{ Index = '203.0.113.42'; Value = '255.255.255.248' })
        $a = @(ConvertFrom-AddrRows $if $mk)
        $a.Count | Should -Be 2
        ($a | Where-Object IP -eq '203.0.113.42').Class | Should -Be 'Public'
        ($a | Where-Object IP -eq '203.0.113.42').Prefix | Should -Be 29
        ($a | Where-Object IP -eq '10.20.1.1').Prefix | Should -Be 24
    }
    It 'reads routes from the CIDR route table and from the old one' {
        $cidr = @(
            [pscustomobject]@{ Index = '10.20.2.0.255.255.255.0.0.10.20.1.254'; Value = '10.20.1.254' }
            [pscustomobject]@{ Index = '0.0.0.0.0.0.0.0.0.203.0.113.41'; Value = '203.0.113.41' }
        )
        $r = @(ConvertFrom-RouteRows $cidr)
        $r[0].Destination | Should -Be '0.0.0.0'
        $r[0].Prefix | Should -Be 0
        $r[1].Destination | Should -Be '10.20.2.0'
        $r[1].Prefix | Should -Be 24
        $r[1].NextHop | Should -Be '10.20.1.254'
        $legacy = @(ConvertFrom-RouteRows @([pscustomobject]@{ Index = '10.30.0.0'; Value = '10.20.1.254' }) @([pscustomobject]@{ Index = '10.30.0.0'; Value = '255.255.0.0' }) -Legacy)
        $legacy[0].Prefix | Should -Be 16
    }
    It 'reads a UPS from UPS-MIB, including running on battery' {
        $m = Get-UpsOidMap
        $v = @{ $m.Manufacturer = 'Contoso Power'; $m.Model = 'CP1500'; $m.BatteryStatus = 2; $m.MinutesRemaining = 42; $m.ChargePct = 100; $m.OutputSource = 3; $m.LoadPct = 31 }
        $u = ConvertTo-UpsStatus $v $null
        $u.Battery | Should -Be 'normal'
        $u.OnBattery | Should -BeFalse
        $u.MinutesRemaining | Should -Be 42
        $v[$m.OutputSource] = 5
        (ConvertTo-UpsStatus $v $null).OnBattery | Should -BeTrue
    }
    It 'reads an APC card that only answers the APC MIB' {
        $m = Get-UpsOidMap -Apc
        $u = ConvertTo-UpsStatus @{} @{ $m.Model = 'Smart-UPS 1500'; $m.BatteryStatus = 2; $m.ChargePct = 96; $m.RuntimeTicks = 270000; $m.ReplaceBattery = 2; $m.OutputStatus = 2; $m.LoadPct = 22 }
        $u.Source | Should -Be 'APC'
        $u.MinutesRemaining | Should -Be 45
        $u.ReplaceBattery | Should -BeTrue
        ConvertTo-UpsStatus @{} @{} | Should -BeNullOrEmpty
    }
    It 'reads a router''s tables, falling back to the old route table' {
        Mock Get-SnmpValues { @{ '1.3.6.1.2.1.4.1.0' = 1 } }
        Mock Invoke-SnmpWalk { @() }
        Mock Invoke-SnmpWalk -ParameterFilter { $Base -eq '1.3.6.1.2.1.4.20.1.2' } { @([pscustomobject]@{ Index = '10.20.1.1'; Value = 2 }, [pscustomobject]@{ Index = '203.0.113.42'; Value = 5 }) }
        Mock Invoke-SnmpWalk -ParameterFilter { $Base -eq '1.3.6.1.2.1.4.22.1.2' } { @([pscustomobject]@{ Index = '2.10.20.1.60'; Value = '00-15-5D-01-02-04' }) }
        Mock Invoke-SnmpWalk -ParameterFilter { $Base -eq '1.3.6.1.2.1.4.21.1.7' } { @([pscustomobject]@{ Index = '0.0.0.0'; Value = '203.0.113.41' }) }
        Mock Invoke-SnmpWalk -ParameterFilter { $Base -eq '1.3.6.1.2.1.4.21.1.11' } { @([pscustomobject]@{ Index = '0.0.0.0'; Value = '0.0.0.0' }) }
        $t = Get-RouterTables '10.20.1.1' 'public'
        $t.Forwarding | Should -BeTrue
        $t.WanAddresses | Should -Be @('203.0.113.42')
        @($t.Arp).Count | Should -Be 1
        $t.DefaultRoute | Should -Be '203.0.113.41'
    }
    It 'leaves a device that does not route alone' {
        Mock Get-SnmpValues { @{ '1.3.6.1.2.1.4.1.0' = 2 } }
        Mock Invoke-SnmpWalk { @() }
        Get-RouterTables '10.20.1.50' 'public' | Should -BeNullOrEmpty
        Should -Invoke Invoke-SnmpWalk -Times 0 -Exactly
    }
    It 'turns router and UPS readings into findings' {
        $r = @{
            Egress = @{ PublicIPv4 = '198.51.100.7' }
            Snmp = @{ Devices = @(
                @{ IP = '10.20.1.1'; SysName = 'nw-fw01'; SysDescr = 'Contoso Firewall'; Router = @{ Addresses = @(@{ IP = '10.20.1.1'; Prefix = 24; Class = 'Private' }, @{ IP = '203.0.113.42'; Prefix = 29; Class = 'Public' }); WanAddresses = @('203.0.113.42'); Arp = @(1, 2, 3); Routes = @(1); DefaultRoute = @('203.0.113.41') } }
                @{ IP = '10.20.1.5'; SysName = 'ups1'; Ups = @{ Source = 'UPS-MIB'; Manufacturer = 'Contoso Power'; Model = 'CP1500'; Battery = 'normal'; ChargePct = 80; MinutesRemaining = 12; LoadPct = 40; OnBattery = $true } }
            ) }
        }
        $f = @(Get-AssessmentFindings $r)
        $router = $f | Where-Object { $_.Finding -like 'Router nw-fw01*' }
        $router.Finding | Should -Match 'WAN side is 203\.0\.113\.42'
        $router.Finding | Should -Match 'leaves from 198\.51\.100\.7 instead'
        ($f | Where-Object { $_.Finding -like 'UPS*' }).Finding | Should -Match 'RUNNING ON BATTERY'
    }
}

Describe 'Network risks from collected data (Phase C)' {
    BeforeAll {
        $now = [datetime]'2026-11-12T12:00:00'
        $script:RiskRun = @{
            Identify = @{ Devices = @(
                @{ IP = '10.20.1.10'; Name = 'nw-fs01.northwind.local'; OpenPorts = @(445); Smb = @{ Smb1Enabled = $true } }
                @{ IP = '10.20.1.20'; Name = 'nw-sw01'; OpenPorts = @(23, 80); Web = @(@{ Url = 'http://10.20.1.20/'; Status = 200 }) }
                @{ IP = '10.20.1.21'; OpenPorts = @(21, 22); SshBanner = 'SSH-2.0-OpenSSH_6.6.1p1'; Web = @() }
                @{ IP = '10.20.1.22'; OpenPorts = @(22, 80, 443); SshBanner = 'SSH-2.0-OpenSSH_8.9p1'
                   Web = @(@{ Url = 'http://10.20.1.22/'; Status = 301 }, @{ Url = 'https://10.20.1.22/'; Status = 200; CertNotAfter = '2025-06-30T00:00:00' }) }
                @{ IP = '10.20.1.23'; OpenPorts = @(22); SshBanner = 'SSH-2.0-dropbear_2015.67' }
                @{ IP = '10.20.2.31'; Name = 'NW-DOCK02'; Remote = $true; OpenPorts = @(445, 3389) }
            ) }
            Snmp = @{ Community = 'public'; Answered = 3 }
            WindowsHosts = @{ Hosts = @(
                @{ IP = '10.20.1.30'; ComputerName = 'NW-OLD01'; Os = 'Windows 7 / Server 2008 R2' }
                @{ IP = '10.20.1.31'; ComputerName = 'NW-ACCT02'; Os = 'Windows 10 (2004 to 22H2)' }
                @{ IP = '10.20.1.32'; ComputerName = 'NW-SRV19'; Os = 'Windows 10 1809 / Server 2019' }
            ) }
        }
        $script:Risks = @(Get-NetworkRiskFlags $RiskRun -Now $now)
        $script:Find = { param($text) @($Risks | Where-Object { $_.Message -like "*$text*" }) }
    }
    It 'flags SMBv1 as high' {
        $f = & $Find 'SMBv1'
        $f.Severity | Should -Be 'High'
        $f.Message | Should -Match '10\.20\.1\.10 \(nw-fs01\)'
    }
    It 'flags Telnet and FTP' {
        (& $Find 'Telnet').Severity | Should -Be 'Medium'
        (& $Find 'run FTP').Severity | Should -Be 'Low'
    }
    It 'flags a web page that is only on plain HTTP, not one that also has HTTPS' {
        $f = & $Find 'only over plain HTTP'
        $f.Message | Should -Match '1 device'
        $f.Message | Should -Match '10\.20\.1\.20'
        $f.Message | Should -Not -Match '10\.20\.1\.22'
    }
    It 'flags an expired certificate' {
        (& $Find 'expired HTTPS certificate').Message | Should -Match '10\.20\.1\.22'
    }
    It 'flags Remote Desktop and file sharing open across routing' {
        (& $Find 'Remote Desktop answers').Message | Should -Match 'NW-DOCK02'
        (& $Find 'file sharing answers').Severity | Should -Be 'Medium'
    }
    It 'flags SNMP answering on public' {
        (& $Find "community 'public'").Message | Should -Match '^3 device'
    }
    It 'flags old SSH servers, not current ones' {
        $f = & $Find 'SSH server from before 2017'
        $f.Message | Should -Match '^2 device'
        $f.Message | Should -Not -Match '10\.20\.1\.22'
    }
    It 'flags Windows out of support, and leaves the ambiguous server builds alone' {
        (& $Find 'no longer gets security updates').Severity | Should -Be 'High'
        $w10 = & $Find 'run Windows 10'
        $w10.Message | Should -Match 'NW-ACCT02'
        $w10.Message | Should -Not -Match 'NW-SRV19'
    }
    It 'raises nothing on a run without discovery' {
        @(Get-NetworkRiskFlags @{ Network = @{} }).Count | Should -Be 0
    }
    It 'files every risk under one category the merge keeps for the site' {
        @($Risks | ForEach-Object Category | Sort-Object -Unique) | Should -Be @('Network risk')
    }
}

Describe 'IPv6 (Phase D)' {
    It 'is on by default, without -Discovery' {
        (& $Config).EnableIpv6Check | Should -BeTrue
    }
    It 'keeps only the /64 of a global address' {
        ConvertTo-Ipv6Prefix64 '2001:db8:abcd:12:a1b2:c3d4:e5f6:7' | Should -Be '2001:db8:abcd:12::/64'
        ConvertTo-Ipv6Prefix64 '2001:db8::1%12' | Should -Be '2001:db8:0:0::/64'
        ConvertTo-Ipv6Prefix64 '10.20.1.25' | Should -BeNullOrEmpty
        ConvertTo-Ipv6Prefix64 'not an address' | Should -BeNullOrEmpty
    }
    It 'tells <A> is <Kind>' -ForEach @(
        @{ A = '2001:db8::1'; Kind = 'Global' }, @{ A = 'fd12:3456::1'; Kind = 'UniqueLocal' }, @{ A = 'fe80::1%7'; Kind = 'LinkLocal' }, @{ A = '::1'; Kind = 'Other' }
    ) {
        Get-Ipv6Kind $A | Should -Be $Kind
    }
    It 'calls IPv6 <Expected> when <Case>' -ForEach @(
        @{ Case = 'it reached the internet'; Expected = 'Working'; State = @{ GlobalPrefixes = @('2001:db8:1:2::/64'); DefaultRoute = $true; Egress = @{ Reached = $true } } }
        @{ Case = 'a global address cannot get out'; Expected = 'Broken'; State = @{ GlobalPrefixes = @('2001:db8:1:2::/64'); DefaultRoute = $true; Egress = @{ Reached = $false } } }
        @{ Case = 'only a route is offered'; Expected = 'Broken'; State = @{ GlobalPrefixes = @(); DefaultRoute = $true } }
        @{ Case = 'only unique-local addresses exist'; Expected = 'Local only'; State = @{ GlobalPrefixes = @(); UniqueLocal = $true; DefaultRoute = $false } }
        @{ Case = 'nothing is offered'; Expected = 'Not offered'; State = @{ GlobalPrefixes = @(); DefaultRoute = $false } }
    ) {
        Get-Ipv6Verdict $State | Should -Be $Expected
    }
    It 'checks a working IPv6 path and keeps no full address (network calls mocked)' {
        Mock Get-NetAdapter { [pscustomobject]@{ ifIndex = 7; Status = 'Up' } }
        Mock Get-NetIPAddress { @([pscustomobject]@{ InterfaceIndex = 7; AddressState = 'Preferred'; IPAddress = '2001:db8:1:2:a1b2:c3d4:e5f6:7'; SuffixOrigin = 'Random' }, [pscustomobject]@{ InterfaceIndex = 7; AddressState = 'Preferred'; IPAddress = 'fe80::1'; SuffixOrigin = 'Link' }) }
        Mock Get-NetRoute { [pscustomobject]@{ InterfaceIndex = 7; NextHop = 'fe80::1' } }
        Mock Get-DnsClientServerAddress { [pscustomobject]@{ InterfaceIndex = 7; ServerAddresses = @('2001:db8:1:2::53') } }
        Mock Invoke-WebRequest { [pscustomobject]@{ Content = "fl=1`nip=2001:db8:1:2:a1b2:c3d4:e5f6:7`ncolo=ORD`n" } }
        Mock Resolve-DnsName { [pscustomobject]@{ Type = 'AAAA'; IPAddress = '2606:4700:4700::1111' } }
        Mock Measure-Ipv6Ping { [ordered]@{ Sent = 10; Received = 10; LossPct = 0; AvgMs = 14.2 } }
        $s = Get-Ipv6State
        $s.Status | Should -Be 'Working'
        $s.GlobalPrefixes | Should -Be @('2001:db8:1:2::/64')
        $s.TemporaryAddresses | Should -BeTrue
        $s.RouterIsLinkLocal | Should -BeTrue
        $s.Egress.SameAsPc | Should -BeTrue
        $s.Ping.AvgMs | Should -Be 14.2
        ($s | ConvertTo-Json -Depth 5) | Should -Not -Match 'a1b2:c3d4' -Because 'only /64 prefixes are kept'
    }
    It 'does not test the internet path when no IPv6 is offered' {
        Mock Get-NetAdapter { [pscustomobject]@{ ifIndex = 7; Status = 'Up' } }
        Mock Get-NetIPAddress { @([pscustomobject]@{ InterfaceIndex = 7; AddressState = 'Preferred'; IPAddress = 'fe80::1'; SuffixOrigin = 'Link' }) }
        Mock Get-NetRoute { @() }
        Mock Get-DnsClientServerAddress { @() }
        Mock Invoke-WebRequest { throw 'should not be called' }
        Mock Resolve-DnsName { @() }
        Mock Measure-Ipv6Ping { throw 'should not be called' }
        (Get-Ipv6State).Status | Should -Be 'Not offered'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        Should -Invoke Measure-Ipv6Ping -Times 0 -Exactly
    }
    It 'turns the IPv6 state into a finding' {
        $working = @{ Ipv6 = @{ Status = 'Working'; GlobalPrefixes = @('2001:db8:1:2::/64'); DefaultRoute = $true; RouterIsLinkLocal = $true; Egress = @{ Reached = $true; SameAsPc = $true }; Ping = @{ AvgMs = 14.2; LossPct = 0 } } }
        (@(Get-AssessmentFindings $working) | Where-Object { $_.Finding -like 'IPv6*' }).Finding | Should -Match 'works here.*14\.2 ms.*no NAT'
        $broken = @{ Ipv6 = @{ Status = 'Broken'; GlobalPrefixes = @('2001:db8:1:2::/64'); DefaultRoute = $true; Egress = @{ Reached = $false; Error = 'timed out' } } }
        (@(Get-AssessmentFindings $broken) | Where-Object { $_.Finding -like 'IPv6*' }).Finding | Should -Match 'does not reach the internet'
        $none = @{ Ipv6 = @{ Status = 'Not offered' } }
        (@(Get-AssessmentFindings $none) | Where-Object { $_.Finding -like 'IPv6*' }).Finding | Should -Match 'not offered'
    }
}

Describe 'Ping and traceroute in any Windows language' {
    It 'reads ping output in <Lang>' -ForEach @(
        @{ Lang = 'German'; Line = 'Antwort von 1.1.1.1: Bytes=32 Zeit=12ms TTL=57' }
        @{ Lang = 'French'; Line = 'Reponse de 1.1.1.1 : octets=32 temps=12 ms TTL=57' }
        @{ Lang = 'Spanish'; Line = 'Respuesta desde 1.1.1.1: bytes=32 tiempo=12ms TTL=57' }
        @{ Lang = 'Russian'; Line = ('Otvet ot 1.1.1.1: chislo bajt=32 vremya=12' + [char]0x043C + [char]0x0441 + ' TTL=57') }
    ) {
        $text = (@(1..4) | ForEach-Object { $Line }) -join "`r`n"
        $p = ConvertFrom-PingOutput $text '1.1.1.1' 4
        $p.Received | Should -Be 4
        $p.AvgMs | Should -Be 12
    }
    It 'reads a sub-millisecond reply and does not count the byte count as a time' {
        $p = ConvertFrom-PingOutput 'Antwort von 10.20.1.1: Bytes=32 Zeit<1ms TTL=64' '10.20.1.1' 1
        $p.Received | Should -Be 1
        $p.AvgMs | Should -Be 1
    }
    It 'reads tracert hops with Cyrillic milliseconds' {
        $ms = [string][char]0x043C + [char]0x0441
        $text = "  1    <1 $ms    <1 $ms    <1 $ms  10.20.1.1`r`n  2    12 $ms    11 $ms    13 $ms  198.51.100.10"
        $hops = @(ConvertFrom-Tracert $text)
        $hops.Count | Should -Be 2
        $hops[1].AvgMs | Should -Be 12
    }
    It 'pings with .NET and writes it the way English ping.exe does' {
        $script:FullLanguage = $true
        $txt = Invoke-IcmpText -Kind Ping -Target '127.0.0.1' -Count 2 -TimeoutMs 1000 -WaitSec 30
        $txt | Should -Match 'Reply from 127\.0\.0\.1: bytes=32 time'
        $p = ConvertFrom-PingOutput $txt '127.0.0.1' 2
        $p.Received | Should -Be 2
        $p.LossPct | Should -Be 0
    }
    It 'traces with .NET and writes it the way English tracert does' {
        $script:FullLanguage = $true
        $txt = Invoke-IcmpText -Kind Trace -Target '127.0.0.1' -MaxHops 3 -TimeoutMs 500 -WaitSec 30
        $txt | Should -Match 'Tracing route to 127\.0\.0\.1 \[127\.0\.0\.1\]'
        $hops = @(ConvertFrom-Tracert $txt)
        $hops.Count | Should -Be 1
        $hops[0].IP | Should -Be '127.0.0.1'
    }
    It 'says so when a name does not resolve' {
        $script:FullLanguage = $true
        Invoke-IcmpText -Kind Ping -Target 'no-such-host.invalid' -Count 1 -WaitSec 30 | Should -Match 'Unable to resolve'
    }
}

Describe 'Leads: evidence that points at the next check' {
    BeforeAll {
        $script:LeadRun = @{
            Network = @{ SourceIp = '10.20.1.25'; Gateway = '10.20.1.1'; PhysicalAdapter = 'Ethernet'; Adapters = @(@{ Name = 'Ethernet'; SubnetMask = @('255.255.255.0') }) }
            NetworkExtra = @{ GatewayVendor = 'Fortinet, Inc.'; DnsServers = @(@{ Server = '10.20.0.5' }, @{ Server = '10.20.1.1' }) }
            Capture = @{
                DhcpServers = @(@{ Server = '10.20.1.1'; TftpServer = '10.20.0.20' })
                Lldp = @(@{ Protocol = 'LLDP'; MgmtIP = '10.20.99.2' })
            }
            Traceroutes = @(@{ Target = '1.1.1.1'; Analysis = @{ DoubleNatLikely = $true }; Hops = @(@{ Hop = 1; IP = '10.20.1.1'; Class = 'Private' }, @{ Hop = 2; IP = '192.168.0.1'; Class = 'Private' }, @{ Hop = 3; IP = '198.51.100.10'; Class = 'Public' }) })
            Servers = @{ Servers = @(@{ Name = 'nw-fs01'; IPs = @('10.20.0.10') }, @{ Name = 'printsrv'; IPs = @('10.20.1.30') }) }
            Identify = @{ Devices = @(
                @{ IP = '10.20.0.21'; OpenPorts = @(5060); SipAgent = 'Asterisk PBX 18.2' }
                @{ IP = '10.20.0.50'; OpenPorts = @(443); Web = @(@{ Title = 'iDRAC9 - Login' }) }
                @{ IP = '10.20.0.60'; OpenPorts = @(443, 902); Web = @(@{ Title = 'VMware ESXi' }) }
                @{ IP = '10.20.0.70'; OpenPorts = @(8080); MacVendor = 'QNAP Systems, Inc.' }
                @{ IP = '10.20.0.71'; OpenPorts = @(5001); Web = @(@{ Title = 'Synology DiskStation' }) }
                @{ IP = '10.20.0.80'; OpenPorts = @(443, 445, 3389); Kind = 'Windows computer' }
                @{ IP = '10.20.1.90'; OpenPorts = @(80); Web = @(@{ Title = 'Lobby printer' }) }
            ) }
        }
        $script:Leads = @(Get-Leads $LeadRun)
        $script:Of = { param($kind) @($Leads | Where-Object Kind -eq $kind | ForEach-Object Target) }
    }
    It 'finds the phone system from DHCP option 66/150 and from a SIP answer' {
        & $Of 'PhoneSystem' | Should -Be @('10.20.0.20', '10.20.0.21')
    }
    It 'finds the ISP modem behind a double NAT' {
        & $Of 'Modem' | Should -Be @('192.168.0.1')
    }
    It 'knows the firewall''s make from its MAC vendor' {
        & $Of 'Firewall' | Should -Be @('10.20.1.1')
        ($Leads | Where-Object Kind -eq 'Firewall').Why | Should -Match 'Fortinet'
    }
    It 'sends the switch''s announced management address to SNMP' {
        & $Of 'Switch' | Should -Be @('10.20.99.2')
    }
    It 'lists servers on other subnets for the tunnel check, not ones on this subnet' {
        & $Of 'Server' | Should -Be @('10.20.0.10', '10.20.0.5')
    }
    It 'picks out devices that deserve a specific look' {
        & $Of 'ServerManagement' | Should -Be @('10.20.0.50')
        & $Of 'Hypervisor' | Should -Be @('10.20.0.60')
        & $Of 'Qnap' | Should -Be @('10.20.0.70')
        & $Of 'Synology' | Should -Be @('10.20.0.71')
        & $Of 'WindowsWeb' | Should -Be @('10.20.0.80')
        @($Leads | Where-Object Target -eq '10.20.1.90').Count | Should -Be 0
    }
    It 'maps a make to its own VPN and admin pages' {
        $f = Get-FirewallChecks 'FortiGate-60F'
        $f.Vendor | Should -Be 'Fortinet'
        @($f.Checks | Where-Object Path -eq '/remote/login').Count | Should -BeGreaterThan 0
        Get-FirewallChecks 'Some unknown router' | Should -BeNullOrEmpty
    }
    It 'reads a Redfish service root' {
        $r = ConvertFrom-RedfishRoot '{"@odata.id":"/redfish/v1","RedfishVersion":"1.11.0","Vendor":"Dell","Product":"Integrated Dell Remote Access Controller","Name":"Root Service"}'
        $r.Vendor | Should -Be 'Dell'
        $r.Product | Should -Match 'Remote Access'
        ConvertFrom-RedfishRoot '<html>not json</html>' | Should -BeNullOrEmpty
    }
    It 'reads the vSphere API''s description of itself' {
        $x = '<returnval><about><name>VMware ESXi</name><fullName>VMware ESXi 7.0.3 build-21930508</fullName><version>7.0.3</version><build>21930508</build><apiType>HostAgent</apiType></about></returnval>'
        $v = ConvertFrom-VimAbout $x
        $v.Version | Should -Be '7.0.3'
        $v.ApiType | Should -Be 'HostAgent'
    }
    It 'reads a QNAP login check' {
        $q = ConvertFrom-QnapLogin '<QDocRoot><model><modelName><![CDATA[TS-453D]]></modelName><displayModelName><![CDATA[TS-453D]]></displayModelName></model><firmware><version><![CDATA[5.1.4]]></version><build><![CDATA[20231128]]></build></firmware></QDocRoot>'
        $q.Model | Should -Be 'TS-453D'
        $q.Firmware | Should -Be '5.1.4'
    }
    It 'runs the follow-up checks and keeps the ones that answered' {
        Mock Invoke-HttpText {
            switch -Wildcard ($Url) {
                'https://10.20.1.1/remote/login' { [pscustomobject]@{ Status = 200; Title = 'FortiGate SSL VPN'; Body = '' } }
                'https://10.20.0.60/sdk' { [pscustomobject]@{ Status = 200; Body = '<about><fullName>VMware ESXi 7.0.3 build-1</fullName><version>7.0.3</version><build>1</build><apiType>HostAgent</apiType></about>' } }
                'https://10.20.0.50/redfish/v1/' { [pscustomobject]@{ Status = 200; Body = '{"RedfishVersion":"1.11.0","Vendor":"Dell","Product":"iDRAC"}' } }
                'https://10.20.0.80/remoteDesktopGateway/' { [pscustomobject]@{ Status = 401; Body = '' } }
                default { [pscustomobject]@{ Status = 404; Body = '' } }
            }
        }
        $rows = @(Invoke-LeadChecks $Leads)
        ($rows | Where-Object Kind -eq 'Firewall').What | Should -Be 'Fortinet SSL-VPN portal'
        ($rows | Where-Object Kind -eq 'Hypervisor').Version | Should -Be '7.0.3'
        ($rows | Where-Object Kind -eq 'ServerManagement').What | Should -Be 'Dell iDRAC'
        ($rows | Where-Object What -eq 'RD Gateway').IP | Should -Be '10.20.0.80'
        @($rows | Where-Object Kind -eq 'Storage').Count | Should -Be 0 -Because 'nothing answered for the NAS checks'
    }
    It 'offers Active Directory''s subnets and the gateway''s routes at the subnet prompt' {
        $run = @{ AdSites = @{ Sites = @(@{ Name = 'Branch'; Subnets = @('10.20.9.0/24', '10.0.0.0/8') }) }; GatewayRouter = @{ Routes = @(@{ Destination = '10.20.40.0'; Prefix = 24; NextHop = '10.20.1.254' }, @{ Destination = '0.0.0.0'; Prefix = 0; NextHop = '203.0.113.41' }) } }
        $c = @(Get-CandidateSubnets $run @(ConvertTo-NetRange '10.20.1.25' 24))
        $c.Cidr | Should -Be @('10.20.9.0/24', '10.20.40.0/24')
        ($c | Where-Object Cidr -eq '10.20.9.0/24').Reasons | Should -Be @('Active Directory site Branch')
        ($c | Where-Object Cidr -eq '10.20.40.0/24').Reasons | Should -Match 'route on the gateway via 10\.20\.1\.254'
    }
    It 'flags a VMware host out of support and a management controller on the office network' {
        $r = @{ LeadChecks = @{ Checks = @(@{ Kind = 'Hypervisor'; IP = '10.20.0.60'; What = 'VMware ESXi 7.0.3 build-1'; Version = '7.0.3' }, @{ Kind = 'Hypervisor'; IP = '10.20.0.61'; What = 'VMware ESXi 8.0.2'; Version = '8.0.2' }, @{ Kind = 'ServerManagement'; IP = '10.20.0.50'; What = 'Dell iDRAC' }) } }
        $f = @(Get-NetworkRiskFlags $r)
        ($f | Where-Object Message -like '*VMware host*').Message | Should -Match '^1 VMware host'
        ($f | Where-Object Message -like '*management controller*').Severity | Should -Be 'Medium'
    }
    It 'reports Active Directory sites and the follow-up checks as findings' {
        $r = @{ AdSites = @{ Forest = 'northwind.local'; CurrentSite = 'Main-Office'; Sites = @(@{ Name = 'Main-Office'; Subnets = @('10.20.1.0/24') }, @{ Name = 'Lab'; Subnets = @() }) }
                LeadChecks = @{ Checks = @(@{ Kind = 'Modem'; IP = '192.168.0.1'; What = 'ISP modem or ONT'; Detail = 'web page 200: Gateway'; Url = 'http://192.168.0.1/' }) } }
        $f = @(Get-AssessmentFindings $r)
        ($f | Where-Object Finding -like 'Active Directory*').Finding | Should -Match 'belongs to site Main-Office.*1 site\(s\) have no subnets'
        ($f | Where-Object Finding -like 'ISP modem*').Area | Should -Be 'Internet service'
    }
    It 'checks leads only with -Discovery, and reads AD sites on every run' {
        (& $Config).EnableLeadChecks | Should -BeFalse
        (& $Config -Discovery).EnableLeadChecks | Should -BeTrue
        (& $Config).EnableAdSites | Should -BeTrue
    }
}

Describe 'Email and domain posture from public DNS' {
    It 'finds the client''s public domain and leaves internal names out' {
        $r = @{ Identity = @{ Upn = 'jlee@northwindtraders.com' }; NetworkExtra = @{ DnsSuffixSearch = @('northwind.local', 'branch.northwindtraders.com', 'contoso.co.uk') }
                Machine = @{ Domain = 'northwind.local' }; AdSites = @{ Forest = 'northwind.local' } }
        Get-ClientDomains $r | Should -Be @('northwindtraders.com', 'contoso.co.uk')
        Get-ClientDomains @{ Identity = @{ Upn = 'jlee@northwind.onmicrosoft.com' } } | Should -BeNullOrEmpty
    }
    It 'names the mail provider from the MX hosts' {
        Get-MailProvider @('northwindtraders-com.mail.protection.outlook.com') | Should -Be 'Microsoft 365'
        Get-MailProvider @('aspmx.l.google.com') | Should -Be 'Google Workspace'
        Get-MailProvider @('mx1-us1.ppe-hosted.com') | Should -Be 'Proofpoint'
        Get-MailProvider @('mail.example.net') | Should -Be 'other or self-hosted'
    }
    It 'reads SPF: <Rec> ends in <All>' -ForEach @(
        @{ Rec = 'v=spf1 include:spf.protection.outlook.com -all'; All = '-all' }
        @{ Rec = 'v=spf1 a mx ~all'; All = '~all' }
        @{ Rec = 'v=spf1 include:_spf.google.com ?all'; All = '?all' }
        @{ Rec = 'v=spf1 +all'; All = '+all' }
        @{ Rec = 'v=spf1 redirect=_spf.example.net'; All = 'redirect' }
    ) {
        (Get-SpfSummary @('google-site-verification=abc', $Rec)).All | Should -Be $All
    }
    It 'counts SPF lookups and notices two SPF records' {
        $s = Get-SpfSummary @('v=spf1 include:a.example include:b.example a mx -all', 'v=spf1 -all')
        $s.Lookups | Should -Be 4
        $s.Multiple | Should -BeTrue
        (Get-SpfSummary @('some other txt')).Present | Should -BeFalse
    }
    It 'reads DMARC' {
        $d = Get-DmarcSummary @('v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@northwindtraders.com')
        $d.Policy | Should -Be 'quarantine'
        $d.Reports | Should -BeTrue
        (Get-DmarcSummary @()).Present | Should -BeFalse
    }
    It 'looks the domain up in public DNS (DNS mocked)' {
        Mock Resolve-PublicDns {
            switch ("$Name|$Type") {
                'northwindtraders.com|MX' { @([pscustomobject]@{ Type = 'MX'; Preference = 0; NameExchange = 'northwindtraders-com.mail.protection.outlook.com' }) }
                'northwindtraders.com|TXT' { @([pscustomobject]@{ Type = 'TXT'; Strings = @('v=spf1 include:spf.protection.outlook.com ', '-all') }) }
                '_dmarc.northwindtraders.com|TXT' { @([pscustomobject]@{ Type = 'TXT'; Strings = @('v=DMARC1; p=none') }) }
                'selector1._domainkey.northwindtraders.com|CNAME' { @([pscustomobject]@{ Type = 'CNAME'; NameHost = 'selector1-northwindtraders-com._domainkey.northwind.onmicrosoft.com' }) }
                'autodiscover.northwindtraders.com|CNAME' { @([pscustomobject]@{ Type = 'CNAME'; NameHost = 'autodiscover.outlook.com' }) }
                default { @() }
            }
        }
        $p = Get-DomainPosture 'northwindtraders.com'
        $p.Provider | Should -Be 'Microsoft 365'
        $p.Spf.All | Should -Be '-all' -Because 'a TXT record split into strings is joined first'
        $p.Dmarc.Policy | Should -Be 'none'
        $p.DkimSelectors | Should -Be @('selector1')
        $p.Autodiscover | Should -Be @('autodiscover.outlook.com')
        $flags = @(Get-DomainFlags $p)
        ($flags | Where-Object Message -like '*p=none*').Severity | Should -Be 'Low'
        @($flags | Where-Object Message -like '*SPF*').Count | Should -Be 0
    }
    It 'flags a domain that can be spoofed' {
        $p = @{ Domain = 'contoso.co.uk'; Mx = @('mail.contoso.co.uk'); Provider = 'other or self-hosted'; Spf = @{ Present = $true; All = '+all'; Lookups = 1; Multiple = $false }; Dmarc = @{ Present = $false }; DkimSelectors = @() }
        $f = @(Get-DomainFlags $p)
        ($f | Where-Object Message -like '*+all*').Severity | Should -Be 'High'
        ($f | Where-Object Message -like '*no DMARC*').Severity | Should -Be 'Medium'
        @($f | ForEach-Object Category | Sort-Object -Unique) | Should -Be @('Email security')
    }
    It 'turns the lookup into a finding' {
        $r = @{ Domains = @{ Domains = @(@{ Domain = 'northwindtraders.com'; Mx = @('northwindtraders-com.mail.protection.outlook.com'); Provider = 'Microsoft 365'; Spf = @{ Present = $true; All = '-all'; Record = 'v=spf1 -all' }; Dmarc = @{ Present = $true; Policy = 'reject'; Reports = $true; Record = 'v=DMARC1; p=reject' }; DkimSelectors = @('selector1', 'selector2'); MtaSts = $false; Autodiscover = @() }) } }
        (@(Get-AssessmentFindings $r) | Where-Object Area -eq 'Email and domain').Finding | Should -Match 'Microsoft 365.*SPF ends in -all.*DMARC p=reject with reports.*DKIM at selector1, selector2'
    }
}

Describe 'DKIM keys' {
    It 'does not count an empty key (p= with no value) as DKIM' {
        Mock Resolve-PublicDns {
            if ($Type -eq 'TXT' -and $Name -like 'selector1._domainkey.*') { @([pscustomobject]@{ Type = 'TXT'; Strings = @('v=DKIM1; p=') }) }
            elseif ($Type -eq 'TXT' -and $Name -like 'k1._domainkey.*') { @([pscustomobject]@{ Type = 'TXT'; Strings = @('v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA') }) }
            else { @() }
        }
        (Get-DomainPosture 'example.com').DkimSelectors | Should -Be @('k1')
    }
}

Describe 'Collector build' {
    It 'Collect-SiteAssessment.ps1 is what tools\Build-Collector.ps1 makes from src\collector' {
        $out = Join-Path $TestDrive 'built.ps1'
        & (Join-Path $RepoRoot 'tools\Build-Collector.ps1') -OutFile $out | Out-Null
        ([IO.File]::ReadAllText($out) -replace "`r`n", "`n") | Should -Be ([IO.File]::ReadAllText($CollectorPath) -replace "`r`n", "`n") -Because 'edit src\collector, run tools\Build-Collector.ps1, and commit both'
    }
    It 'keeps every function in src\collector\lib and none in the run files' {
        foreach ($f in Get-ChildItem (Join-Path $RepoRoot 'src\collector\run') -Filter *.ps1) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] }).Count | Should -Be 0 -Because "$($f.Name) is run code"
        }
    }
}
