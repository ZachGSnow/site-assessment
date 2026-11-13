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
