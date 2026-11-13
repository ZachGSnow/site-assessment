# ---------------------------------------------------------------------
# IPv6: is it offered on this network, and does it reach the internet? Addresses are kept as /64
# prefixes only: the rest of an IPv6 address can identify the machine.
# ---------------------------------------------------------------------
function ConvertTo-Ipv6Prefix64 {
    # The /64 network of a global IPv6 address, as 'xxxx:xxxx:xxxx:xxxx::/64'; $null for anything else.
    param([string]$Address)
    $a = "$Address".Split('%')[0]
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($a, [ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }
    $b = $ip.GetAddressBytes()
    $groups = for ($i = 0; $i -lt 8; $i += 2) { '{0:x}' -f (([int]$b[$i] -shl 8) + [int]$b[$i + 1]) }
    return (($groups -join ':') + '::/64')
}

function Get-Ipv6Kind {
    # Global (2000::/3), unique local (fc00::/7), link-local (fe80::/10) or other.
    param([string]$Address)
    $a = "$Address".Split('%')[0].ToLower()
    if ($a -match '^fe[89ab][0-9a-f]:') { return 'LinkLocal' }
    if ($a -match '^f[cd][0-9a-f]{2}:') { return 'UniqueLocal' }
    if ($a -match '^[23][0-9a-f]{3}:') { return 'Global' }
    return 'Other'
}

function Get-Ipv6Verdict {
    # Not offered, Local only, Working or Broken, from what the PC holds and whether IPv6 reached the internet.
    param($State)
    $global = @(@(Get-Prop $State 'GlobalPrefixes') | Where-Object { $_ }).Count
    $ula = [bool](Get-Prop $State 'UniqueLocal')
    $route = [bool](Get-Prop $State 'DefaultRoute')
    $reached = [bool](Get-Prop $State 'Egress', 'Reached')
    if ($reached) { return 'Working' }
    if ($global -or $route) { return 'Broken' }
    if ($ula) { return 'Local only' }
    return 'Not offered'
}

function Measure-Ipv6Ping {
    # $Count pings to an IPv6 address, 100 ms apart: Sent, Received, LossPct, AvgMs.
    param([string]$Address, [int]$Count = 10)
    $times = @()
    try {
        $pg = New-Object Net.NetworkInformation.Ping
        for ($k = 0; $k -lt $Count; $k++) { try { $rp = $pg.Send([Net.IPAddress]::Parse($Address), 1000); if ($rp.Status -eq 'Success') { $times += [int]$rp.RoundtripTime } } catch { }; Start-Sleep -Milliseconds 100 }
    } catch { }
    return [ordered]@{ Sent = $Count; Received = $times.Count; LossPct = [math]::Round(100 * ($Count - $times.Count) / [math]::Max(1, $Count), 1); AvgMs = $(if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }) }
}

function Get-Ipv6State {
    # What this PC holds (addresses on adapters that are up, a default route, IPv6 DNS servers) and a test:
    # Cloudflare's trace over IPv6, ten pings and an AAAA lookup.
    $s = [ordered]@{ GlobalPrefixes = @(); TemporaryAddresses = $false; UniqueLocal = $false; DefaultRoute = $false; RouterIsLinkLocal = $null; DnsServers = @(); Egress = $null; Ping = $null; AaaaLookup = $null; Status = $null }
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })
    $addrs = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $up -contains $_.InterfaceIndex -and "$($_.AddressState)" -eq 'Preferred' })
    $glob = @($addrs | Where-Object { (Get-Ipv6Kind $_.IPAddress) -eq 'Global' })
    $s.GlobalPrefixes = @($glob | ForEach-Object { ConvertTo-Ipv6Prefix64 $_.IPAddress } | Where-Object { $_ } | Sort-Object -Unique)
    $s.TemporaryAddresses = [bool]@($glob | Where-Object { "$($_.SuffixOrigin)" -eq 'Random' }).Count
    $s.UniqueLocal = [bool]@($addrs | Where-Object { (Get-Ipv6Kind $_.IPAddress) -eq 'UniqueLocal' }).Count
    $rt = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $up -contains $_.InterfaceIndex })
    $s.DefaultRoute = [bool]$rt.Count
    if ($rt.Count) { $s.RouterIsLinkLocal = ((Get-Ipv6Kind "$($rt[0].NextHop)") -eq 'LinkLocal') }
    $s.DnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $up -contains $_.InterfaceIndex } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -and $_ -notlike 'fec0:*' } | Sort-Object -Unique)
    if ($s.GlobalPrefixes.Count -or $s.DefaultRoute) {
        $eg = [ordered]@{ Reached = $false; Prefix = $null; SameAsPc = $null; Colo = $null; Error = $null }
        try {
            $t = Invoke-WebRequest -Uri 'https://[2606:4700:4700::1111]/cdn-cgi/trace' -UseBasicParsing -TimeoutSec 8
            $h = @{}; foreach ($l in ($t.Content -split "`n")) { if ($l -match '^([a-z_]+)=(.*)$') { $h[$matches[1]] = $matches[2].Trim() } }
            if ($h['ip'] -and (Get-Ipv6Kind $h['ip']) -eq 'Global') {
                $eg.Reached = $true; $eg.Prefix = ConvertTo-Ipv6Prefix64 $h['ip']; $eg.Colo = $h['colo']
                $eg.SameAsPc = ($s.GlobalPrefixes -contains $eg.Prefix)
            }
        } catch { $eg.Error = $_.Exception.Message }
        $s.Egress = $eg
        $s.Ping = Measure-Ipv6Ping '2606:4700:4700::1111' 10
    }
    try { $s.AaaaLookup = [bool]@(Resolve-DnsName -Name 'one.one.one.one' -Type AAAA -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'AAAA' }).Count } catch { $s.AaaaLookup = $false }
    $s.Status = Get-Ipv6Verdict $s
    return $s
}
