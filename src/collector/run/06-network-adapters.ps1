# =====================================================================
# PHASE 1: quick discovery needed before background jobs
# =====================================================================

# ---------------------------------------------------------------------
# Network adapters and primary path (wired vs wireless)
# ---------------------------------------------------------------------
$VpnRegex  = 'TAP-|TAP |TUN|Wintun|WireGuard|Fortinet|FortiClient|PANGP|GlobalProtect|AnyConnect|Cisco Secure|Juniper|SonicWall|NetExtender|WatchGuard|Sophos|OpenVPN|Zscaler|WARP|Cloudflare|Tailscale|ZeroTier|Check Point|Pulse|Ivanti|NordLynx|Hyper-V|vEthernet|VMware|VirtualBox|Npcap|Loopback|Teredo|ISATAP|Bluetooth'
$UsbRegex  = 'USB|Dock|DisplayLink|ASIX|Thunderbolt|Belkin|Anker|Plugable|CalDigit|Targus|Kensington|Dell .*WD|ThinkPad .*Dock|Lenovo .*Dock|HP .*Dock'

$Result['Network'] = Invoke-Collector 'Network adapters and IP config' {
    $adapters = @(Get-NetAdapter -IncludeHidden:$false)
    $nac = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -OperationTimeoutSec 20)
    $ipif = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    $list = @()
    foreach ($a in $adapters) {
        $cfg = $nac | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | Select-Object -First 1
        $metric = ($ipif | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | Select-Object -First 1).InterfaceMetric
        $list += [pscustomobject]@{
            Name              = $a.Name
            Description       = $a.InterfaceDescription
            IfIndex           = $a.ifIndex
            Status            = "$($a.Status)"
            Class             = Get-ConnectionClass $a
            LinkSpeed         = $a.LinkSpeed
            LinkSpeedMbps     = [math]::Round($a.ReceiveLinkSpeed / 1e6)
            FullDuplex        = $a.FullDuplex
            MacAddress        = $a.MacAddress
            NdisPhysicalMedium = "$($a.NdisPhysicalMedium)"
            PhysicalMediaType = "$($a.PhysicalMediaType)"
            Virtual           = $a.Virtual
            DriverVersion     = $a.DriverVersionString
            DriverDate        = $a.DriverDate
            DriverProvider    = $a.DriverProvider
            InterfaceMetric   = $metric
            IPv4              = if ($cfg) { @($cfg.IPAddress | Where-Object { Test-IPv4 $_ }) } else { @() }
            SubnetMask        = if ($cfg) { @($cfg.IPSubnet | Where-Object { $_ -match '\.' }) } else { @() }
            Gateway           = if ($cfg) { @($cfg.DefaultIPGateway) } else { @() }
            DhcpEnabled       = if ($cfg) { $cfg.DHCPEnabled } else { $null }
            DhcpServer        = if ($cfg) { $cfg.DHCPServer } else { $null }
            DhcpLeaseObtained = if ($cfg) { Format-Date $cfg.DHCPLeaseObtained } else { $null }
            DhcpLeaseExpires  = if ($cfg) { Format-Date $cfg.DHCPLeaseExpires } else { $null }
            DnsServers        = if ($cfg) { @($cfg.DNSServerSearchOrder) } else { @() }
            DnsSuffix         = if ($cfg) { $cfg.DNSDomain } else { $null }
        }
    }

    # Primary path: the interface Windows actually uses to reach the internet.
    $primary = $null; $sourceIp = $null; $gateway = $null
    try {
        $fr = Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction Stop
        $ipEntry = $fr | Where-Object { $_.IPAddress } | Select-Object -First 1
        $rtEntry = $fr | Where-Object { $_.NextHop } | Select-Object -First 1
        if ($ipEntry) { $sourceIp = $ipEntry.IPAddress; $primary = $list | Where-Object { $_.IfIndex -eq $ipEntry.InterfaceIndex } | Select-Object -First 1 }
        if ($rtEntry) { $gateway = $rtEntry.NextHop }
    } catch { }
    $defaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        $r = $_
        $im = ($ipif | Where-Object { $_.InterfaceIndex -eq $r.ifIndex } | Select-Object -First 1).InterfaceMetric
        [pscustomobject]@{ IfIndex = $r.ifIndex; Interface = $r.InterfaceAlias; NextHop = $r.NextHop; RouteMetric = $r.RouteMetric; InterfaceMetric = $im; EffectiveMetric = ($r.RouteMetric + $im) }
    } | Sort-Object EffectiveMetric)
    if (-not $primary -and $defaultRoutes.Count -gt 0) {
        $primary = $list | Where-Object { $_.IfIndex -eq $defaultRoutes[0].IfIndex } | Select-Object -First 1
        $gateway = $defaultRoutes[0].NextHop
    }

    # If a VPN/virtual adapter holds the route, find the physical adapter underneath.
    $physicalUnder = $null
    $virtualSwitch = ($primary -and "$($primary.Description) $($primary.Name)" -match 'Hyper-V|vEthernet|VMware|VirtualBox')
    if ($primary -and $primary.Class -eq 'Virtual/VPN') {
        $physicalUnder = $list | Where-Object { $_.Status -eq 'Up' -and $_.Class -notin @('Virtual/VPN', 'Unknown') } |
            Sort-Object InterfaceMetric | Select-Object -First 1
    }
    $physical = if ($physicalUnder) { $physicalUnder } else { $primary }
    $connected = @($list | Where-Object { $_.Status -eq 'Up' -and $_.Class -notin @('Virtual/VPN', 'Unknown') })
    $physGateway = $gateway
    if ($physicalUnder -and @($physicalUnder.Gateway).Count -gt 0) { $physGateway = @($physicalUnder.Gateway)[0] }

    [ordered]@{
        Adapters          = $list
        DefaultRoutes     = $defaultRoutes
        PrimaryAdapter    = if ($primary) { $primary.Name } else { $null }
        PrimaryClass      = if ($primary) { $primary.Class } else { 'No route' }
        PhysicalAdapter   = if ($physical) { $physical.Name } else { $null }
        PhysicalClass     = if ($physical) { $physical.Class } else { 'No route' }
        PhysicalLinkMbps  = if ($physical) { $physical.LinkSpeedMbps } else { $null }
        PhysicalDescription = if ($physical) { $physical.Description } else { $null }
        VpnHoldsDefaultRoute = ([bool]$physicalUnder -and -not $virtualSwitch)
        VirtualSwitchInPath = [bool]$virtualSwitch
        ConnectedPhysical = @($connected | ForEach-Object { '{0} ({1}, {2})' -f $_.Name, $_.Class, $_.LinkSpeed })
        MultipleConnected = ($connected.Count -gt 1)
        SourceIp          = $sourceIp
        Gateway           = $physGateway
        RouteGateway      = $gateway
    }
}
$Net = $Result['Network']
$Gateway = $null
if ($Net -and $Net.Contains('Gateway')) { $Gateway = $Net['Gateway'] }
