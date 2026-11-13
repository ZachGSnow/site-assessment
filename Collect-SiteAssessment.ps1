<#
.SYNOPSIS
    Site assessment collector: endpoint inventory, connection type, remote desktop footprint,
    path and traffic-design tests and a bandwidth test. Writes one zip per run.

.DESCRIPTION
    Built for Windows PowerShell 5.1 in PowerShell ISE, runnable as a standard user.
    Open in ISE and press F5 (or paste into a new Untitled tab and press F5).
    Run ISE as administrator to add TPM, BitLocker, disk health, sign-ins and the
    switch / wire capture; without it those checks are skipped on their own.

    Nothing is installed. Nothing sensitive is collected: no passwords, saved
    credentials, Wi-Fi keys, BitLocker recovery keys, browser data or file contents.
    The public IP is sent to Cloudflare (trace/meta/speed test), ipinfo.io, rdap.org
    (whois for the address block) and api.macvendors.com (MAC vendor prefix only) when
    those options are enabled.

    A plain run looks only at this PC and its path to the internet: inventory, Wi-Fi,
    event logs, the remote desktop footprint, bandwidth, traceroutes, latency and loss,
    and a traffic-design verdict (local breakout, split tunnel or full backhaul).

    Active discovery of other devices on the network is OFF unless you pass -Discovery
    (or set $EnableDiscovery below). It adds: a subnet sweep with a few TCP ports per
    device, vendor discovery (Ubiquiti, MikroTik, Netgear), mDNS, WS-Discovery and SSDP,
    web page titles and SSH/FTP banners, SIP phone models, Windows names and builds,
    read-only SNMP with the default community, IPP and RTSP questions to printers and
    cameras, the ISP modem page, the gateway's admin ports and UPnP/NAT-PMP mappings,
    reverse DNS for the office subnets you list, and reachability of servers you list.
    No logon is attempted anywhere and no default passwords are tried. Only run
    discovery on networks you are authorised to assess.

.PARAMETER SiteName
    Site/office name. Prompted for when omitted.

.PARAMETER Notes
    Optional free-text notes (desk location, etc). Prompted for when omitted.

.PARAMETER OutputPath
    Overrides $OutputRoot for this run.

.PARAMETER NoPrompt
    Do not prompt or open Explorer; use SiteName/Notes as given (SiteName defaults to UNSPECIFIED).

.PARAMETER Discovery
    Turns on active discovery of other devices on the network (see DESCRIPTION).

.PARAMETER HostedDesktop
    Name of a built-in hosted desktop profile: RDP (default), AzureVirtualDesktop,
    Windows365 or CitrixCloud. See $HostedDesktopProfiles below to add your own.

.PARAMETER ConfigPath
    A .psd1 file whose keys override the CONFIG values below for this run (see
    site-assessment.config.example.psd1).
#>
param(
    [string]$SiteName,
    [string]$Notes,
    [string]$OutputPath,
    [switch]$NoPrompt,
    [switch]$Discovery,
    [string]$HostedDesktop,
    [string]$ConfigPath
)

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
$SiteSubnets        = @()      # one /24 per office (first 3 octets), e.g. @('10.10.1', '10.10.2'): reverse DNS and reachability
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

function Write-Step {
    param([string]$Text, [string]$Color = 'Cyan')
    $elapsed = [int]((Get-Date) - $RunStart).TotalSeconds
    Write-Host ('[{0,4}s] {1}' -f $elapsed, $Text) -ForegroundColor $Color
}

function Add-Flag {
    param([string]$Severity, [string]$Category, [string]$Message)
    $script:Flags += [pscustomobject]@{ Severity = $Severity; Category = $Category; Message = $Message }
}

function Invoke-Collector {
    # Runs one collector; any failure is recorded and the run continues.
    param([string]$Name, [scriptblock]$Script, [switch]$AdminOnly)
    if ($AdminOnly -and -not $script:AdminActive) {
        return [ordered]@{ Status = 'skipped (admin tier not active)' }
    }
    Write-Step $Name
    $t0 = Get-Date
    try {
        $out = & $Script
        $script:Timings[$Name] = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
        return $out
    } catch {
        $msg = $_.Exception.Message
        $script:Errors += [pscustomobject]@{ Collector = $Name; Error = $msg }
        $script:Timings[$Name] = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
        Write-Step ("  {0} unavailable: {1}" -f $Name, $msg) 'DarkYellow'
        return [ordered]@{ Status = "unavailable: $msg" }
    }
}

function Save-Json {
    # Writes assessment.json. Called at the checkpoint before active discovery, after the analysis,
    # and after the data check. $Stage records how far the run got, so a run that was cut off is recognizable.
    param([string]$Stage)
    try {
        if ($Stage) { $Result['Meta']['Stage'] = $Stage }
        $Result['Errors'] = $script:Errors
        $json = $Result | ConvertTo-Json -Depth 10
        [IO.File]::WriteAllText((Join-Path $OutDir 'assessment.json'), $json, (New-Object Text.UTF8Encoding $false))
        return $true
    } catch {
        Write-Host "JSON write failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-Val {
    # Safe lookup into a collector result (which may be an error record instead).
    param($Dict, [string]$Key)
    if ($Dict -is [System.Collections.IDictionary] -and $Dict.Contains($Key)) { return $Dict[$Key] }
    return $null
}

function Get-EventsSafe {
    # Get-WinEvent throws when nothing matches; treat that as zero events.
    param([hashtable]$Filter, [int]$Max)
    try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch { if ($_.Exception.Message -match 'No events were found') { return @() } throw }
}

function Format-Date {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') } catch { return "$Value" }
}

function Get-RegValues {
    # Returns a key's values as an ordered hashtable (no PS* noise).
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Path
    $h = [ordered]@{}
    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        if ($p.Name -match 'password|secret|key$|token') { continue }
        $v = $p.Value
        if ($v -is [byte[]]) { $v = '(binary {0} bytes)' -f $v.Length }
        $h[$p.Name] = $v
    }
    return $h
}

function Get-OemEncoding {
    try { return [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage) }
    catch { return [Text.Encoding]::Default }
}

function Invoke-Native {
    # Runs a console exe with a timeout and returns its stdout as a string.
    param([string]$FilePath, [string]$Arguments = '', [int]$TimeoutSec = 60)
    if (-not $script:FullLanguage) {
        $argList = @()
        if ($Arguments) { $argList = $Arguments -split ' ' }
        return (& $FilePath @argList 2>&1 | Out-String)
    }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = Get-OemEncoding
    $p = [Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        throw "$FilePath timed out after $TimeoutSec s"
    }
    $p.WaitForExit()
    return ($outTask.Result + $errTask.Result)
}

function Start-NativeAsync {
    # Starts a console exe in the background; collect with Receive-NativeAsync.
    param([string]$FilePath, [string]$Arguments, [string]$Label)
    if (-not $script:FullLanguage) {
        return [pscustomobject]@{ Label = $Label; FilePath = $FilePath; Arguments = $Arguments; Process = $null; Task = $null }
    }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = Get-OemEncoding
    $p = [Diagnostics.Process]::Start($psi)
    return [pscustomobject]@{ Label = $Label; FilePath = $FilePath; Arguments = $Arguments; Process = $p; Task = $p.StandardOutput.ReadToEndAsync() }
}

function Start-IcmpJob {
    # A ping series or a traceroute with .NET in a background runspace. The output is written the way
    # English ping.exe and tracert.exe print it, so one parser serves every Windows display language.
    # Constrained Language cannot create runspaces, so it falls back to the exes (see ConvertFrom-PingOutput).
    param([ValidateSet('Ping', 'Trace')][string]$Kind, [string]$Target, [int]$Count = 4, [int]$MaxHops = 20, [int]$TimeoutMs = 1000, [string]$Label)
    if (-not $script:FullLanguage) {
        $args0 = if ($Kind -eq 'Ping') { "-n $Count -w $TimeoutMs $Target" } else { "-d -w $TimeoutMs -h $MaxHops $Target" }
        return Start-NativeAsync $(if ($Kind -eq 'Ping') { 'ping.exe' } else { 'tracert.exe' }) $args0 $Label
    }
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        param($kind, $target, $count, $maxHops, $timeout)
        $lines = New-Object Collections.Generic.List[string]
        $addr = $null; $parsed = $null
        if ([Net.IPAddress]::TryParse("$target", [ref]$parsed)) { $addr = $parsed }
        else { try { $addr = @([Net.Dns]::GetHostAddresses("$target") | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0] } catch { } }
        if (-not $addr) { return "Unable to resolve target system name $target." }
        $pinger = New-Object Net.NetworkInformation.Ping
        $buf = New-Object byte[] 32
        # One throwaway loopback ping first: the first send of a session runs a few ms slow.
        try { [void]$pinger.Send([Net.IPAddress]::Loopback, 200) } catch { }
        try {
            if ($kind -eq 'Trace') {
                $lines.Add(''); $lines.Add(('Tracing route to {0} [{1}]' -f $target, $addr)); $lines.Add("over a maximum of $maxHops hops:"); $lines.Add('')
                for ($ttl = 1; $ttl -le $maxHops; $ttl++) {
                    $cells = @(); $hop = $null; $done = $false
                    for ($k = 0; $k -lt 3; $k++) {
                        $sw = [Diagnostics.Stopwatch]::StartNew(); $r = $null
                        try { $r = $pinger.Send($addr, $timeout, $buf, (New-Object Net.NetworkInformation.PingOptions($ttl, $false))) } catch { }
                        # .NET reports 0 ms for a TTL-expired reply, so the stopwatch times every probe.
                        $ms = [int][math]::Round($sw.Elapsed.TotalMilliseconds)
                        if ($r -and ("$($r.Status)" -eq 'TtlExpired' -or "$($r.Status)" -eq 'Success')) {
                            if ("$($r.Status)" -eq 'Success') { $ms = [int]$r.RoundtripTime; $done = $true }
                            $cells += $(if ($ms -lt 1) { '<1 ms' } else { "$ms ms" })
                            if (-not $hop) { $hop = "$($r.Address)" }
                        } else { $cells += '*' }
                    }
                    $lines.Add(('{0,3}  {1,8}  {2,8}  {3,8}  {4}' -f $ttl, $cells[0], $cells[1], $cells[2], $(if ($hop) { $hop } else { 'Request timed out.' })))
                    if ($done) { break }
                }
                $lines.Add(''); $lines.Add('Trace complete.')
            } else {
                $lines.Add(('Pinging {0} with 32 bytes of data:' -f $addr))
                for ($i = 0; $i -lt $count; $i++) {
                    $sw = [Diagnostics.Stopwatch]::StartNew(); $r = $null
                    try { $r = $pinger.Send($addr, $timeout, $buf) } catch { }
                    if ($r -and "$($r.Status)" -eq 'Success') {
                        $tt = if ($r.RoundtripTime -lt 1) { 'time<1ms' } else { "time=$($r.RoundtripTime)ms" }
                        $lines.Add(('Reply from {0}: bytes=32 {1} TTL={2}' -f $r.Address, $tt, $(if ($r.Options) { $r.Options.Ttl } else { 0 })))
                    } else { $lines.Add('Request timed out.') }
                    $rest = 1000 - $sw.ElapsedMilliseconds
                    if ($i -lt $count - 1 -and $rest -gt 0) { Start-Sleep -Milliseconds ([int]$rest) }
                }
            }
        } finally { $pinger.Dispose() }
        return ($lines -join "`r`n")
    }).AddArgument($Kind).AddArgument($Target).AddArgument($Count).AddArgument($MaxHops).AddArgument($TimeoutMs)
    return [pscustomobject]@{ Label = $Label; FilePath = $null; Arguments = $null; Process = $null; Task = $null; PS = $ps; Async = $ps.BeginInvoke() }
}

function Invoke-IcmpText {
    # Start-IcmpJob and wait for it: the text of one ping series or traceroute.
    param([ValidateSet('Ping', 'Trace')][string]$Kind, [string]$Target, [int]$Count = 4, [int]$MaxHops = 20, [int]$TimeoutMs = 1000, [int]$WaitSec = 120)
    return (Receive-NativeAsync (Start-IcmpJob -Kind $Kind -Target $Target -Count $Count -MaxHops $MaxHops -TimeoutMs $TimeoutMs -Label "$Kind $Target") $WaitSec)
}

function Receive-NativeAsync {
    param($Handle, [int]$TimeoutSec = 120)
    if ($Handle.PSObject.Properties['PS'] -and $Handle.PS) {
        if (-not $Handle.Async.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) { try { $Handle.PS.Stop() } catch { } }
        $txt = ''
        try { $txt = (@($Handle.PS.EndInvoke($Handle.Async)) -join "`r`n") } catch { }
        try { $Handle.PS.Dispose() } catch { }
        return $txt
    }
    if ($null -eq $Handle.Process) {
        # Constrained Language fallback: run synchronously now.
        return (Invoke-Native -FilePath $Handle.FilePath -Arguments $Handle.Arguments -TimeoutSec $TimeoutSec)
    }
    if (-not $Handle.Process.WaitForExit($TimeoutSec * 1000)) {
        try { $Handle.Process.Kill() } catch { }
        return ($Handle.Task.Result + "`r`n(timed out)")
    }
    $Handle.Process.WaitForExit()
    return $Handle.Task.Result
}

function Start-TcpSeries {
    # Background TCP connect series (one connect per second). Connect time is one round trip, so this
    # gives loss and jitter to hosts that drop ICMP, such as RDP gateways. FullLanguage only.
    param([string]$Target, [string]$Address, [int]$Port, [int]$Count)
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        param($a, $p, $n)
        $failRun = 0
        for ($i = 0; $i -lt $n; $i++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $c = New-Object Net.Sockets.TcpClient
            $ok = $false
            try { $ok = $c.ConnectAsync($a, $p).Wait(2000) -and $c.Connected } catch { }
            $ms = $sw.Elapsed.TotalMilliseconds
            try { $c.Close() } catch { }
            [pscustomobject]@{ Ok = $ok; Ms = [math]::Round($ms, 1) }
            # A target that stops answering would double the run time; 15 failures in a row ends the series.
            if ($ok) { $failRun = 0 } else { $failRun++; if ($failRun -ge 15) { break } }
            $rest = 1000 - $ms
            if ($rest -gt 0) { Start-Sleep -Milliseconds ([int]$rest) }
        }
    }).AddArgument($Address).AddArgument($Port).AddArgument($Count)
    return [pscustomobject]@{ Target = $Target; Address = $Address; Port = $Port; Count = $Count; PS = $ps; Async = $ps.BeginInvoke() }
}

function Receive-TcpSeries {
    param($Job, [int]$TimeoutSec = 150)
    if (-not $Job.Async.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) { try { $Job.PS.Stop() } catch { } }
    $rows = @()
    try { $rows = @($Job.PS.EndInvoke($Job.Async)) } catch { }
    try { $Job.PS.Dispose() } catch { }
    $times = @($rows | Where-Object { $_.Ok } | ForEach-Object { [double]$_.Ms })
    $sorted = @($times | Sort-Object)
    $jit = $null
    if ($times.Count -gt 1) { $d = 0; for ($k = 1; $k -lt $times.Count; $k++) { $d += [math]::Abs($times[$k] - $times[$k - 1]) }; $jit = [math]::Round($d / ($times.Count - 1), 1) }
    $sent = $rows.Count
    return [ordered]@{
        Target = $Job.Target; Address = $Job.Address; Port = $Job.Port; Method = 'TCP connect'
        Sent = $sent; Received = $times.Count
        LossPct = if ($sent) { [math]::Round(100 * ($sent - $times.Count) / $sent, 1) } else { $null }
        MinMs = if ($sorted.Count) { $sorted[0] } else { $null }
        AvgMs = if ($sorted.Count) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
        P95Ms = if ($sorted.Count) { $sorted[[math]::Min($sorted.Count - 1, [int][math]::Ceiling(0.95 * $sorted.Count) - 1)] } else { $null }
        MaxMs = if ($sorted.Count) { $sorted[-1] } else { $null }
        JitterMs = $jit
    }
}

function ConvertFrom-ColonText {
    # Parses "Key : Value" console output into an ordered hashtable (first value wins).
    param([string]$Text)
    $h = [ordered]@{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*([^:]+?)\s+:\s(.*)$') {
            $k = $matches[1].Trim(); $v = $matches[2].Trim()
            if (-not $h.Contains($k)) { $h[$k] = $v }
        }
    }
    return $h
}
function Get-Prop {
    # Reads $Obj.A.B... from hashtables or objects alike (live results and saved JSON); $null when absent.
    param($Obj, [string[]]$Path)
    foreach ($k in $Path) {
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($k)) { $Obj = $Obj[$k] } else { return $null } }
        else { $pp = $Obj.PSObject.Properties[$k]; if ($pp) { $Obj = $pp.Value } else { return $null } }
    }
    return $Obj
}

function Get-RegString {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

# =====================================================================
# PHASE 6: bandwidth (after the ping, TCP and trace series, so it does not distort them;
# before active discovery, so nothing that might upset security software runs ahead of it)
# Each direction fails over through $BandwidthProviders in order:
#   Cloudflare (download + upload) -> M-Lab NDT7 (download + upload) -> Vultr (download only).
# The helper functions below run inside Measure-Bandwidth and use its $client, $sw,
# $startProbe and $finishProbe through PowerShell's dynamic scoping.
# =====================================================================
function Get-MedianValue { param($Values) $s = @($Values | Where-Object { $null -ne $_ } | Sort-Object); if ($s.Count) { return [math]::Round([double]$s[[int][math]::Floor($s.Count / 2)], 1) } return $null }

function Test-SameSubnet {
    # True when $Ip is inside the subnet of $LocalIp/$Mask (dotted IPv4 only).
    param([string]$Ip, [string]$LocalIp, [string]$Mask)
    $toInt = { param($s) $o = "$s".Split('.'); if ($o.Count -ne 4) { return $null }; ([int64]$o[0] -shl 24) + ([int64]$o[1] -shl 16) + ([int64]$o[2] -shl 8) + [int64]$o[3] }
    $a = & $toInt $Ip; $b = & $toInt $LocalIp; $m = & $toInt $Mask
    if ($null -eq $a -or $null -eq $b -or $null -eq $m) { return $false }
    return (($a -band $m) -eq ($b -band $m))
}

# ---------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------
function Test-IPv4 { param([string]$Ip) return ($Ip -match '^\d{1,3}(\.\d{1,3}){3}$') }

function Get-IpClass {
    param([string]$Ip)
    if (-not (Test-IPv4 $Ip)) {
        if ($Ip -match '^(fe80|fc|fd)') { return 'Private' }
        if ($Ip -match ':') { return 'Public' }
        return 'Unknown'
    }
    $o = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o[0] -eq 10) { return 'Private' }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return 'Private' }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return 'Private' }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return 'CGNAT' }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return 'LinkLocal' }
    if ($o[0] -eq 127) { return 'Loopback' }
    return 'Public'
}

function Resolve-Ptr {
    param([string]$Ip)
    try {
        $r = Resolve-DnsName -Name $Ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1
        if ($r -and $r.NameHost -notmatch 'localhost|^undefined') { return $r.NameHost }
    } catch { }
    return $null
}

function Test-TcpPort {
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 1000)
    $c = New-Object Net.Sockets.TcpClient
    try { $t = $c.ConnectAsync($Address, $Port); return ($t.Wait($TimeoutMs) -and $c.Connected) }
    catch { return $false }
    finally { $c.Close() }
}

function Test-TcpPortsBulk {
    # TCP connect check of every IP x port pair, 400 at a time. Returns @{ ip = @(open ports) }.
    param([string[]]$Ips, [int[]]$Ports, [int]$TimeoutMs = 800)
    $open = @{}
    $pairs = New-Object Collections.Generic.List[object]
    foreach ($ip in $Ips) { foreach ($p in $Ports) { $pairs.Add(@($ip, $p)) } }
    for ($i = 0; $i -lt $pairs.Count; $i += 400) {
        $batch = @(); $tasks = @()
        for ($j = $i; $j -lt [math]::Min($i + 400, $pairs.Count); $j++) {
            $c = New-Object Net.Sockets.TcpClient
            $t = $null
            try { $t = $c.ConnectAsync([string]$pairs[$j][0], [int]$pairs[$j][1]) } catch { }
            $batch += , @($pairs[$j][0], $pairs[$j][1], $c, $t)
            if ($t) { $tasks += $t }
        }
        if ($tasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, $TimeoutMs) } catch { } }
        foreach ($b in $batch) {
            if ($b[3] -and "$($b[3].Status)" -eq 'RanToCompletion' -and $b[2].Connected) {
                if (-not $open.ContainsKey($b[0])) { $open[$b[0]] = @() }
                $open[$b[0]] += [int]$b[1]
            }
            try { $b[2].Close() } catch { }
        }
    }
    return $open
}

function Invoke-UdpProbe {
    # Sends datagrams from one socket and returns every reply heard within $WaitMs as IP, Port, Data.
    # $Sends is a list of @{ Address; Port; Bytes }. With -ListenPort the socket binds that port on
    # every address, for protocols whose answers are broadcast (MikroTik, Netgear).
    param($Sends, [string]$SourceIp, [int]$ListenPort = 0, [int]$WaitMs = 2500, [int]$MaxReplies = 3000)
    $replies = New-Object Collections.Generic.List[object]
    $udp = New-Object Net.Sockets.UdpClient
    try {
        $udp.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket, [Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $udp.EnableBroadcast = $true
        try { $udp.Client.ReceiveBufferSize = 1048576 } catch { }
        # Without this a refused datagram (ICMP port unreachable) makes the next receive fail on Windows.
        try { [void]$udp.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null) } catch { }
        $bindIp = if ($ListenPort -eq 0 -and $SourceIp -and (Test-IPv4 $SourceIp)) { [Net.IPAddress]::Parse($SourceIp) } else { [Net.IPAddress]::Any }
        $udp.Client.Bind((New-Object Net.IPEndPoint($bindIp, $ListenPort)))
        foreach ($s in @($Sends)) {
            try {
                $bytes = [byte[]]$s.Bytes
                [void]$udp.Send($bytes, $bytes.Length, (New-Object Net.IPEndPoint([Net.IPAddress]::Parse([string]$s.Address), [int]$s.Port)))
            } catch { }
        }
        $until = (Get-Date).AddMilliseconds($WaitMs); $rt = $null
        while ((Get-Date) -lt $until -and $replies.Count -lt $MaxReplies) {
            try {
                if (-not $rt) { $rt = $udp.ReceiveAsync() }
                if (-not $rt.Wait(200)) { continue }
                $res = $rt.Result; $rt = $null
                $ip = $res.RemoteEndPoint.Address.ToString()
                if ($ip -eq $SourceIp) { continue }
                $replies.Add([pscustomobject]@{ IP = $ip; Port = $res.RemoteEndPoint.Port; Data = $res.Buffer })
            } catch { $rt = $null }
        }
    } finally { try { $udp.Close() } catch { } }
    return $replies.ToArray()
}

function Get-BroadcastAddress {
    param([string]$Ip, [string]$Mask)
    try {
        $i = [Net.IPAddress]::Parse($Ip).GetAddressBytes(); $m = [Net.IPAddress]::Parse($Mask).GetAddressBytes()
        return ('{0}.{1}.{2}.{3}' -f ([int]$i[0] -bor (255 - [int]$m[0])), ([int]$i[1] -bor (255 - [int]$m[1])), ([int]$i[2] -bor (255 - [int]$m[2])), ([int]$i[3] -bor (255 - [int]$m[3])))
    } catch { return $null }
}

# ---------------------------------------------------------------------
# Other subnets: which ones this PC knows it can reach, which ones to sweep, and the sweep itself.
# Only subnets listed in CONFIG or chosen at the prompt are swept; inferred ones are only reported.
# ---------------------------------------------------------------------
function ConvertTo-IpNumber { param([string]$Ip) $o = "$Ip".Split('.'); return ([int64]$o[0] -shl 24) + ([int64]$o[1] -shl 16) + ([int64]$o[2] -shl 8) + [int64]$o[3] }
function ConvertFrom-IpNumber { param([int64]$N) return '{0}.{1}.{2}.{3}' -f (($N -shr 24) -band 255), (($N -shr 16) -band 255), (($N -shr 8) -band 255), ($N -band 255) }

function ConvertTo-NetRange {
    # Network number and broadcast number of $Ip/$Prefix (any prefix).
    param([string]$Ip, [int]$Prefix)
    $maskInt = ([int64]4294967295 -shl (32 - $Prefix)) -band [int64]4294967295
    $net = (ConvertTo-IpNumber $Ip) -band $maskInt
    return [pscustomobject]@{ NetInt = $net; End = $net + ([int64]1 -shl (32 - $Prefix)) - 1; Prefix = $Prefix }
}

function Get-HttpBanner {
    # One GET with certificate checks off; returns status, Server header, <title> and TLS cert subject/issuer.
    param([string]$Url, [int]$TimeoutMs = 4000)
    $r = [ordered]@{ Url = $Url; Status = $null; Server = $null; Title = $null; CertSubject = $null; CertIssuer = $null; Error = $null }
    $oldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Timeout = $TimeoutMs; $req.ReadWriteTimeout = $TimeoutMs; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 3
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $null
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { $r.Error = $_.Exception.Message } }
        if ($req.ServicePoint.Certificate) {
            $r.CertSubject = $req.ServicePoint.Certificate.Subject
            $r.CertIssuer = $req.ServicePoint.Certificate.Issuer
        }
        if ($resp) {
            $r.Status = [int]$resp.StatusCode
            $r.Server = $resp.Headers['Server']
            try {
                $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                $buf = New-Object char[] 65536
                $n = $sr.Read($buf, 0, $buf.Length)
                $body = New-Object string($buf, 0, $n)
                if ($body -match '<title[^>]*>\s*([^<]{1,120})</title>') { $r.Title = $matches[1].Trim() }
                $sr.Close()
            } catch { }
            $resp.Close()
        }
    } catch { $r.Error = $_.Exception.Message }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb }
    return [pscustomobject]$r
}

function Get-TlsInfo {
    # One TLS handshake; returns who issued the certificate this PC is shown. A firewall or antivirus
    # that inspects HTTPS shows up here as the issuer. Nothing is sent beyond the handshake.
    param([string]$HostName, [string]$Address, [int]$Port = 443, [int]$TimeoutMs = 4000)
    $r = [ordered]@{ Host = $HostName; Address = $Address; Port = $Port; Subject = $null; Issuer = $null; NotAfter = $null; Protocol = $null; PolicyErrors = $null; Inspected = $false; Error = $null }
    $c = New-Object Net.Sockets.TcpClient
    $ssl = $null
    try {
        if (-not ($c.ConnectAsync($Address, $Port).Wait($TimeoutMs) -and $c.Connected)) { throw 'connect failed or timed out' }
        $c.ReceiveTimeout = $TimeoutMs; $c.SendTimeout = $TimeoutMs
        $script:TlsPolicyErrors = $null
        $cb = [Net.Security.RemoteCertificateValidationCallback] { param($s, $cert, $chain, $errs) $script:TlsPolicyErrors = "$errs"; $true }
        $ssl = New-Object Net.Security.SslStream($c.GetStream(), $false, $cb)
        $ssl.AuthenticateAsClient($HostName, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $r.Subject = $cert.Subject; $r.Issuer = $cert.Issuer; $r.NotAfter = Format-Date $cert.NotAfter
        $r.Protocol = "$($ssl.SslProtocol)"; $r.PolicyErrors = $script:TlsPolicyErrors
    } catch { $r.Error = $_.Exception.GetBaseException().Message }
    finally {
        if ($ssl) { try { $ssl.Dispose() } catch { } }
        try { $c.Close() } catch { }
    }
    return [pscustomobject]$r
}

function Initialize-CertTrust {
    # Web requests made in parallel check certificates on worker threads, where a PowerShell script block
    # cannot run. This compiles a two-line callback that accepts device certificates (they are self-signed).
    if ($null -ne $script:CertTrustReady) { return $script:CertTrustReady }
    $script:CertTrustReady = $false
    if (-not $script:FullLanguage) { return $false }
    try {
        if (-not ('SaCertTrust' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition 'using System.Net.Security; using System.Security.Cryptography.X509Certificates; public static class SaCertTrust { public static bool Accept(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; } public static RemoteCertificateValidationCallback Callback = new RemoteCertificateValidationCallback(Accept); }'
        }
        $script:CertTrustReady = $true
    } catch { $script:CertTrustReady = $false }
    return $script:CertTrustReady
}

function Get-HttpBannersBulk {
    # One GET per URL, many at a time: status, Server header, page title, a little page text and the
    # certificate names. Nothing is logged in to. Falls back to one at a time when parallel is not possible.
    param([string[]]$Urls, [int]$TimeoutMs = 5000, [int]$BatchSize = 32)
    $out = @()
    if (-not $Urls -or $Urls.Count -eq 0) { return $out }
    if (-not (Initialize-CertTrust)) {
        foreach ($u in ($Urls | Select-Object -First 60)) { $b = Get-HttpBanner $u 2500; $b | Add-Member -NotePropertyName BodySample -NotePropertyValue $null -Force; $b | Add-Member -NotePropertyName AuthRealm -NotePropertyValue $null -Force; $out += $b }
        return $out
    }
    $oldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    $oldProto = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = [SaCertTrust]::Callback
        # Old phones and printers only speak TLS 1.0/1.1; allow them for this pass if Windows still can.
        try { [Net.ServicePointManager]::SecurityProtocol = $oldProto -bor [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12 } catch { }
        for ($i = 0; $i -lt $Urls.Count; $i += $BatchSize) {
            $batch = @()
            foreach ($u in @($Urls[$i..([math]::Min($i + $BatchSize, $Urls.Count) - 1)])) {
                $req = $null; $task = $null
                try {
                    $req = [Net.HttpWebRequest]::Create($u)
                    $req.ReadWriteTimeout = 3000; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 3; $req.KeepAlive = $false
                    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                    $task = $req.GetResponseAsync()
                } catch { }
                $batch += , @($u, $req, $task)
            }
            $tasks = @($batch | Where-Object { $_[2] } | ForEach-Object { $_[2] })
            if ($tasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, $TimeoutMs) } catch { } }
            foreach ($b in $batch) {
                $r = [ordered]@{ Url = $b[0]; Status = $null; Server = $null; Title = $null; BodySample = $null; AuthRealm = $null; CertSubject = $null; CertIssuer = $null; CertNotAfter = $null; Error = $null }
                $resp = $null
                if (-not $b[2]) { $r.Error = 'request could not be started' }
                elseif ("$($b[2].Status)" -eq 'RanToCompletion') { $resp = $b[2].Result }
                elseif ($b[2].IsFaulted) {
                    $ex = $b[2].Exception.GetBaseException()
                    if ($ex -is [Net.WebException] -and $ex.Response) { $resp = $ex.Response } else { $r.Error = $ex.Message }
                } else { $r.Error = 'timed out'; try { $b[1].Abort() } catch { } }
                try { if ($b[1] -and $b[1].ServicePoint -and $b[1].ServicePoint.Certificate) { $r.CertSubject = $b[1].ServicePoint.Certificate.Subject; $r.CertIssuer = $b[1].ServicePoint.Certificate.Issuer; $r.CertNotAfter = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $b[1].ServicePoint.Certificate).NotAfter.ToString('s') } } catch { }
                if ($resp) {
                    try {
                        $r.Status = [int]$resp.StatusCode
                        $r.Server = $resp.Headers['Server']
                        $wa = $resp.Headers['WWW-Authenticate']
                        if ($wa -and $wa -match 'realm="?([^",]{1,80})') { $r.AuthRealm = $matches[1] }
                        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                        $buf = New-Object char[] 32768
                        $n = $sr.Read($buf, 0, $buf.Length)
                        if ($n -gt 0) {
                            $body = New-Object string($buf, 0, $n)
                            if ($body -match '<title[^>]*>\s*([^<]{1,120})</title>') { $r.Title = (($matches[1] -replace '&nbsp;', ' ' -replace '[^\x20-\x7E]', '') -replace '\s+', ' ').Trim() }
                            $text = ((($body -replace '(?s)<script.*?</script>|<style.*?</style>|<!--.*?-->', ' ') -replace '<[^>]+>', ' ') -replace '&nbsp;', ' ' -replace '[^\x20-\x7E]', ' ') -replace '\s+', ' '
                            $r.BodySample = $text.Trim()
                            if ($r.BodySample.Length -gt 200) { $r.BodySample = $r.BodySample.Substring(0, 200) }
                        }
                        $sr.Close()
                    } catch { if (-not $r.Error) { $r.Error = $_.Exception.Message } }
                    try { $resp.Close() } catch { }
                }
                $out += [pscustomobject]$r
            }
        }
    } finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb
        try { [Net.ServicePointManager]::SecurityProtocol = $oldProto } catch { }
    }
    return $out
}

function Get-TcpBannersBulk {
    # Connects to one port on many addresses and keeps what each service says first (SSH, FTP, Telnet).
    param([string[]]$Ips, [int]$Port, [int]$TimeoutMs = 2000)
    $out = @{}
    if (-not $Ips -or $Ips.Count -eq 0) { return $out }
    $items = @()
    foreach ($ip in $Ips) {
        $c = New-Object Net.Sockets.TcpClient; $t = $null
        try { $t = $c.ConnectAsync([string]$ip, $Port) } catch { }
        $items += , @([string]$ip, $c, $t, $null, $null)
    }
    $ct = @($items | Where-Object { $_[2] } | ForEach-Object { $_[2] })
    if ($ct.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$ct, 1500) } catch { } }
    foreach ($it in $items) {
        if ($it[2] -and "$($it[2].Status)" -eq 'RanToCompletion' -and $it[1].Connected) {
            try { $buf = New-Object byte[] 256; $it[3] = $buf; $it[4] = $it[1].GetStream().ReadAsync($buf, 0, 256) } catch { }
        }
    }
    $rt = @($items | Where-Object { $_[4] } | ForEach-Object { $_[4] })
    if ($rt.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$rt, $TimeoutMs) } catch { } }
    foreach ($it in $items) {
        try { if ($it[4] -and "$($it[4].Status)" -eq 'RanToCompletion' -and $it[4].Result -gt 0) { $s = ConvertTo-AsciiText $it[3] 0 ([int]$it[4].Result); if ($s) { $out[$it[0]] = $s } } } catch { }
        try { $it[1].Close() } catch { }
    }
    return $out
}

function Invoke-HttpText {
    # One HTTP(S) request with certificate checks off: Status, Server, Title, Body (first 64 KB), Error.
    param([string]$Url, [string]$Method = 'GET', [string]$Body, [string]$ContentType = 'text/xml', [hashtable]$Headers = @{}, [int]$TimeoutMs = 5000)
    $r = [ordered]@{ Url = $Url; Status = $null; Server = $null; Title = $null; Body = $null; Error = $null }
    $oldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = $Method; $req.Timeout = $TimeoutMs; $req.ReadWriteTimeout = $TimeoutMs; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 3
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        foreach ($k in $Headers.Keys) { $req.Headers[$k] = $Headers[$k] }
        if ($Body) {
            $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
            $req.ContentType = $ContentType; $req.ContentLength = $bytes.Length
            $st = $req.GetRequestStream(); $st.Write($bytes, 0, $bytes.Length); $st.Close()
        }
        $resp = $null
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { $r.Error = $_.Exception.Message } }
        if ($resp) {
            $r.Status = [int]$resp.StatusCode; $r.Server = $resp.Headers['Server']
            try {
                $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                $buf = New-Object char[] 65536
                $n = $sr.Read($buf, 0, $buf.Length)
                $r.Body = New-Object string($buf, 0, [math]::Max(0, $n))
                if ($r.Body -match '<title[^>]*>\s*([^<]{1,120})</title>') { $r.Title = $matches[1].Trim() }
                $sr.Close()
            } catch { }
            $resp.Close()
        }
    } catch { $r.Error = $_.Exception.Message }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb }
    return [pscustomobject]$r
}

function Get-CpuLaunchYear {
    # Approximate year a CPU generation shipped in volume, from the CPU name. $null when unknown.
    # Used for machine age because a BIOS update resets the BIOS date that age was read from.
    param([string]$Name)
    $intelYear = @{ 2 = 2011; 3 = 2012; 4 = 2013; 5 = 2015; 6 = 2015; 7 = 2017; 8 = 2018; 9 = 2019; 10 = 2020; 11 = 2021; 12 = 2022; 13 = 2023; 14 = 2024 }
    $amdYear = @{ 1 = 2017; 2 = 2018; 3 = 2019; 4 = 2020; 5 = 2021; 6 = 2022; 7 = 2023; 8 = 2024; 9 = 2024 }
    if (-not $Name) { return $null }
    if ($Name -match 'Core\(TM\) Ultra [3579] (\d)\d{2}') { if ($matches[1] -eq '1') { return 2024 } return 2025 }
    if ($Name -match 'Core\(TM\) [3579] \d{3}') { return 2024 }
    if ($Name -match '(\d{1,2})(st|nd|rd|th) Gen Intel') { $g = [int]$matches[1]; if ($intelYear.ContainsKey($g)) { return $intelYear[$g] } }
    if ($Name -match 'Core\(TM\) i[3579]-(\d{4,5})') {
        $num = $matches[1]
        # 5 digits (10210U, 12400) and 4 digits starting with 1 (1035G1, 1235U, 1360P) carry a two-digit generation.
        $g = if ($num.Length -eq 5 -or $num.StartsWith('1')) { [int]$num.Substring(0, 2) } else { [int]$num.Substring(0, 1) }
        if ($intelYear.ContainsKey($g)) { return $intelYear[$g] }
    }
    if ($Name -match 'Ryzen AI') { return 2024 }
    if ($Name -match 'Ryzen [3579] (PRO )?(\d)\d{3}') { $s = [int]$matches[2]; if ($amdYear.ContainsKey($s)) { return $amdYear[$s] } }
    return $null
}

function Get-DeviceRole {
    # Best guess at what a device is from its open ports. The ports are saved too, so this can be refined later.
    param([int[]]$Ports)
    if (-not $Ports -or $Ports.Count -eq 0) { return $null }
    if ($Ports -contains 88 -and $Ports -contains 389) { return 'Domain controller' }
    if ($Ports -contains 9100 -or $Ports -contains 515) { return 'Printer' }
    if ($Ports -contains 554) { return 'Camera or recorder' }
    if ($Ports -contains 5060) { return 'Phone or phone system' }
    if ($Ports -contains 1433) { return 'Database server (SQL Server)' }
    if ($Ports -contains 3389) { return 'Windows PC or server (RDP on)' }
    if ($Ports -contains 445 -or $Ports -contains 139) { return 'Windows PC, server or NAS (file sharing on)' }
    if ($Ports -contains 53) { return 'Router, firewall or DNS server' }
    return 'Device with a web or SSH interface'
}

function Get-FirewallModelHint {
    # Best-effort model from gateway web banners. Fortinet's default certificate CN is the serial
    # number, whose prefix encodes the model (FGT60F..., FG100F..., FWF40F... for FortiWiFi).
    param($Banners)
    foreach ($b in @($Banners)) {
        if (-not $b) { continue }
        $hay = "$($b.CertSubject) $($b.CertIssuer)"
        if ($hay -match '\b(FGT|FG|FWF)(\d{2,4}[A-Z]?)[A-Z0-9]{6,}') {
            $family = if ($matches[1] -eq 'FWF') { 'FortiWiFi' } else { 'FortiGate' }
            return [ordered]@{ Vendor = 'Fortinet'; Model = "$family $($matches[2])"; Source = "certificate $($b.CertSubject)" }
        }
    }
    foreach ($b in @($Banners)) {
        if (-not $b) { continue }
        $hay = "$($b.Title) $($b.Server) $($b.CertSubject) $($b.CertIssuer)"
        foreach ($v in @('Forti', 'SonicWall', 'SonicOS', 'Sophos', 'ApplianceCertificate', 'WatchGuard', 'Meraki', 'Palo Alto', 'pfSense', 'OPNsense', 'UniFi', 'Ubiquiti', 'MikroTik', 'Cisco', 'Starlink', 'Netgear', 'TP-Link', 'eero')) {
            if ($hay -match [regex]::Escape($v)) {
                $name = if ($v -eq 'Forti') { 'Fortinet' } elseif ($v -eq 'SonicOS') { 'SonicWall' } elseif ($v -eq 'ApplianceCertificate') { 'Sophos' } else { $v }
                return [ordered]@{ Vendor = $name; Model = $null; Source = ("web page: {0}" -f (@($b.Title, $b.Server, $b.CertSubject) | Where-Object { $_ } | Select-Object -First 1)) }
            }
        }
    }
    return $null
}

function Get-MacVendor {
    param([string]$Mac)
    if (-not $Mac) { return $null }
    $clean = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($clean.Length -lt 6) { return $null }
    $oui = $clean.Substring(0, 6)
    if ($oui -eq '000000' -or $oui -eq 'FFFFFF') { return $null }
    # Locally administered bit set = randomized/virtual MAC, no vendor.
    $second = [Convert]::ToInt32($clean.Substring(1, 1), 16)
    if ($second -band 2) { return 'Randomized / locally administered' }
    if ($script:OuiTable.ContainsKey($oui)) { return $script:OuiTable[$oui] }
    if ($EnableOuiLookup -and $script:OuiOnlineCount -lt 15) {
        $script:OuiOnlineCount++
        try {
            Start-Sleep -Milliseconds 1100   # free tier: 1 request/second
            $prefix = '{0}-{1}-{2}' -f $oui.Substring(0,2), $oui.Substring(2,2), $oui.Substring(4,2)
            $v = Invoke-RestMethod -Uri "https://api.macvendors.com/$prefix" -TimeoutSec 5 -UseBasicParsing
            $v = "$v".Trim()
            $script:OuiTable[$oui] = $v
            return $v
        } catch {
            $script:OuiTable[$oui] = 'Unknown'
            return 'Unknown'
        }
    }
    return 'Unknown'
}

# =====================================================================
# v1.6.0 helpers: byte readers, vendor discovery parsers, the wire capture summary and the bulk
# probes used by the identify pass. The parsers only read bytes; each keeps the raw reply (hex)
# so anything they miss can be worked out from the saved data afterwards.
# =====================================================================
function ConvertTo-MacText { param([byte[]]$B, [int]$Off) if ($Off + 6 -gt $B.Length) { return $null } return [BitConverter]::ToString($B, $Off, 6) }
function ConvertTo-IpText { param([byte[]]$B, [int]$Off) if ($Off + 4 -gt $B.Length) { return $null } return ('{0}.{1}.{2}.{3}' -f $B[$Off], $B[$Off + 1], $B[$Off + 2], $B[$Off + 3]) }
function ConvertTo-AsciiText { param([byte[]]$B, [int]$Off, [int]$Len) if ($Len -le 0 -or $Off -lt 0 -or $Off + $Len -gt $B.Length) { return '' } return (([Text.Encoding]::ASCII.GetString($B, $Off, $Len)) -replace '[^\x20-\x7E]', '').Trim() }
function ConvertTo-HexText { param([byte[]]$B, [int]$Max = 700) if (-not $B) { return '' } return ([BitConverter]::ToString($B, 0, [math]::Min($B.Length, $Max)) -replace '-', '') }
function Get-MacVendorLocal {
    # Vendor from the built-in table and names already looked up; never goes online.
    param([string]$Mac)
    $clean = ("$Mac" -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($clean.Length -lt 6) { return $null }
    if ([Convert]::ToInt32($clean.Substring(1, 1), 16) -band 2) { return 'Randomized / locally administered' }
    $v = $script:OuiTable[$clean.Substring(0, 6)]
    if ($v -and $v -ne 'Unknown') { return $v }
    return $null
}

function ConvertFrom-UbntDiscovery {
    # Ubiquiti discovery reply (UDP 10001). 4-byte header, then records of type(1) length(2) value.
    param([byte[]]$B)
    if (-not $B -or $B.Length -lt 8) { return $null }
    $r = [ordered]@{ Protocol = 'Ubiquiti discovery'; Mac = $null; IP = $null; Name = $null; Model = $null; ModelFull = $null; Firmware = $null; Essid = $null; UptimeSec = $null; Raw = (ConvertTo-HexText $B) }
    $p = 4
    while ($p + 3 -le $B.Length) {
        $t = [int]$B[$p]; $l = ([int]$B[$p + 1] * 256) + [int]$B[$p + 2]; $p += 3
        if ($p + $l -gt $B.Length) { break }
        switch ($t) {
            1  { if ($l -ge 6) { $r['Mac'] = ConvertTo-MacText $B $p } }
            2  { if ($l -ge 10) { if (-not $r['Mac']) { $r['Mac'] = ConvertTo-MacText $B $p }; if (-not $r['IP']) { $r['IP'] = ConvertTo-IpText $B ($p + 6) } } }
            3  { $r['Firmware'] = ConvertTo-AsciiText $B $p $l }
            10 { if ($l -ge 4) { $r['UptimeSec'] = ([int64]$B[$p] * 16777216) + ([int64]$B[$p + 1] * 65536) + ([int64]$B[$p + 2] * 256) + [int64]$B[$p + 3] } }
            11 { $r['Name'] = ConvertTo-AsciiText $B $p $l }
            12 { $r['Model'] = ConvertTo-AsciiText $B $p $l }
            13 { $r['Essid'] = ConvertTo-AsciiText $B $p $l }
            20 { $r['ModelFull'] = ConvertTo-AsciiText $B $p $l }
            21 { if (-not $r['Model']) { $r['Model'] = ConvertTo-AsciiText $B $p $l } }
            22 { if (-not $r['Firmware']) { $r['Firmware'] = ConvertTo-AsciiText $B $p $l } }
        }
        $p += $l
    }
    if (-not $r['Mac'] -and -not $r['Model'] -and -not $r['Name']) { return $null }
    return [pscustomobject]$r
}

function ConvertFrom-Mndp {
    # MikroTik neighbor discovery (UDP 5678). 4-byte header, then records of type(2) length(2) value.
    param([byte[]]$B)
    if (-not $B -or $B.Length -lt 8) { return $null }
    $r = [ordered]@{ Protocol = 'MikroTik discovery'; Mac = $null; IP = $null; Name = $null; Model = $null; ModelFull = $null; Firmware = $null; Platform = $null; Interface = $null; UptimeSec = $null; Raw = (ConvertTo-HexText $B) }
    $p = 4
    while ($p + 4 -le $B.Length) {
        $t = ([int]$B[$p] * 256) + [int]$B[$p + 1]; $l = ([int]$B[$p + 2] * 256) + [int]$B[$p + 3]; $p += 4
        if ($p + $l -gt $B.Length) { break }
        switch ($t) {
            1  { if ($l -ge 6) { $r['Mac'] = ConvertTo-MacText $B $p } }
            5  { $r['Name'] = ConvertTo-AsciiText $B $p $l }
            7  { $r['Firmware'] = ConvertTo-AsciiText $B $p $l }
            8  { $r['Platform'] = ConvertTo-AsciiText $B $p $l }
            10 { if ($l -ge 4) { $r['UptimeSec'] = [int64][BitConverter]::ToUInt32($B, $p) } }
            12 { $r['Model'] = ConvertTo-AsciiText $B $p $l }
            16 { $r['Interface'] = ConvertTo-AsciiText $B $p $l }
            17 { if ($l -ge 4) { $r['IP'] = ConvertTo-IpText $B $p } }
        }
        $p += $l
    }
    if (-not $r['Mac'] -and -not $r['Name']) { return $null }
    return [pscustomobject]$r
}

function New-NsdpRequest {
    # Netgear switch discovery (UDP 63322): a read request for model, name, MAC, IP and firmware.
    param([string]$HostMac)
    $h = New-Object byte[] 32
    $h[0] = 1; $h[1] = 1
    $hex = ("$HostMac" -replace '[^0-9A-Fa-f]', '')
    if ($hex.Length -ge 12) { for ($i = 0; $i -lt 6; $i++) { $h[8 + $i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) } }
    $h[23] = 1
    $sig = [Text.Encoding]::ASCII.GetBytes('NSDP'); [Array]::Copy($sig, 0, $h, 24, 4)
    $tlv = New-Object Collections.Generic.List[byte]
    foreach ($tag in @(1, 3, 4, 6, 13)) { $tlv.Add(0); $tlv.Add([byte]$tag); $tlv.Add(0); $tlv.Add(0) }
    $tlv.Add(255); $tlv.Add(255); $tlv.Add(0); $tlv.Add(0)
    return [byte[]](@($h) + @($tlv.ToArray()))
}

function ConvertFrom-Nsdp {
    param([byte[]]$B)
    if (-not $B -or $B.Length -lt 36 -or (ConvertTo-AsciiText $B 24 4) -ne 'NSDP') { return $null }
    $r = [ordered]@{ Protocol = 'Netgear discovery'; Mac = $null; IP = $null; Name = $null; Model = $null; ModelFull = $null; Firmware = $null; Raw = (ConvertTo-HexText $B) }
    $p = 32
    while ($p + 4 -le $B.Length) {
        $t = ([int]$B[$p] * 256) + [int]$B[$p + 1]; $l = ([int]$B[$p + 2] * 256) + [int]$B[$p + 3]; $p += 4
        if ($t -eq 65535 -or $p + $l -gt $B.Length) { break }
        switch ($t) {
            1  { $r['Model'] = ConvertTo-AsciiText $B $p $l }
            3  { $r['Name'] = ConvertTo-AsciiText $B $p $l }
            4  { if ($l -ge 6) { $r['Mac'] = ConvertTo-MacText $B $p } }
            6  { if ($l -ge 4) { $r['IP'] = ConvertTo-IpText $B $p } }
            13 { $r['Firmware'] = ConvertTo-AsciiText $B $p $l }
        }
        $p += $l
    }
    if (-not $r['Mac'] -and -not $r['Model']) { return $null }
    return [pscustomobject]$r
}

function Read-DnsName {
    # Reads a (possibly compressed) DNS name. Returns @(name, offset after the name).
    param([byte[]]$B, [int]$Off)
    $labels = @(); $p = $Off; $next = -1; $jumps = 0
    while ($p -lt $B.Length) {
        $len = [int]$B[$p]
        if ($len -eq 0) { $p++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            if ($p + 1 -ge $B.Length) { break }
            if ($next -lt 0) { $next = $p + 2 }
            $p = (($len -band 0x3F) * 256) + [int]$B[$p + 1]
            $jumps++; if ($jumps -gt 20) { break }
            continue
        }
        if ($p + 1 + $len -gt $B.Length) { break }
        $labels += [Text.Encoding]::UTF8.GetString($B, $p + 1, $len)
        $p += 1 + $len
    }
    if ($next -lt 0) { $next = $p }
    return @(($labels -join '.'), $next)
}

function ConvertFrom-DnsMessage {
    # Answer, authority and additional records of a DNS or mDNS message: Name, Type, Data.
    param([byte[]]$B)
    $out = @()
    if (-not $B -or $B.Length -lt 12) { return $out }
    $qd = ([int]$B[4] * 256) + [int]$B[5]
    $rr = (([int]$B[6] * 256) + [int]$B[7]) + (([int]$B[8] * 256) + [int]$B[9]) + (([int]$B[10] * 256) + [int]$B[11])
    $p = 12
    for ($i = 0; $i -lt $qd -and $p -lt $B.Length; $i++) { $n = Read-DnsName $B $p; $p = [int]$n[1] + 4 }
    for ($i = 0; $i -lt $rr -and $p + 10 -le $B.Length; $i++) {
        $n = Read-DnsName $B $p; $p = [int]$n[1]
        if ($p + 10 -gt $B.Length) { break }
        $type = ([int]$B[$p] * 256) + [int]$B[$p + 1]; $rdl = ([int]$B[$p + 8] * 256) + [int]$B[$p + 9]; $p += 10
        if ($p + $rdl -gt $B.Length) { break }
        $data = $null
        if ($type -eq 1 -and $rdl -eq 4) { $data = ConvertTo-IpText $B $p }
        elseif ($type -eq 12) { $data = (Read-DnsName $B $p)[0] }
        elseif ($type -eq 33 -and $rdl -gt 6) { $data = (Read-DnsName $B ($p + 6))[0] }
        elseif ($type -eq 16) {
            $s = @(); $q = $p
            while ($q -lt $p + $rdl) { $l = [int]$B[$q]; if ($q + 1 + $l -gt $p + $rdl) { break }; if ($l) { $s += (([Text.Encoding]::UTF8.GetString($B, $q + 1, $l)) -replace '[^\x20-\x7E]', '') }; $q += 1 + $l }
            $data = $s -join '; '
        }
        if ($null -ne $data) { $out += [pscustomobject]@{ Name = "$($n[0])"; Type = $type; Data = "$data" } }
        $p += $rdl
    }
    return $out
}

function New-DnsQuery {
    # One DNS question per name. $Id lets the caller match replies; $Recurse sets the RD bit (off for mDNS).
    param([string[]]$Names, [int]$Type = 12, [int]$Id = 0, [switch]$Recurse)
    $b = New-Object Collections.Generic.List[byte]
    $b.Add([byte](($Id -shr 8) -band 255)); $b.Add([byte]($Id -band 255))
    $b.Add([byte]$(if ($Recurse) { 1 } else { 0 })); $b.Add(0)
    $b.Add(0); $b.Add([byte]$Names.Count)
    1..6 | ForEach-Object { $b.Add(0) }
    foreach ($n in $Names) {
        foreach ($lab in ($n.Split('.') | Where-Object { $_ })) { $lb = [Text.Encoding]::ASCII.GetBytes($lab); $b.Add([byte]$lb.Length); $b.AddRange([byte[]]$lb) }
        $b.Add(0); $b.Add(0); $b.Add([byte]$Type); $b.Add(0); $b.Add(1)
    }
    return $b.ToArray()
}

function Send-VendorDiscovery {
    # One question per vendor discovery protocol (Ubiquiti UDP 10001, MikroTik UDP 5678, Netgear UDP 63322),
    # sent to the broadcast address. Returns what answered on the sockets; broadcast answers that the
    # firewall drops are picked up from the wire capture instead.
    param([string]$SourceIp, [int]$WaitMs = 2500)
    $targets = @('255.255.255.255')
    $mac = $null
    $ad = @(Get-Val $Result['Network'] 'Adapters' | Where-Object { $_ -and @($_.IPv4) -contains $SourceIp }) | Select-Object -First 1
    if ($ad) {
        $mac = "$($ad.MacAddress)"
        $bc = Get-BroadcastAddress $SourceIp "$(@($ad.SubnetMask)[0])"
        if ($bc -and $bc -ne '255.255.255.255') { $targets += $bc }
    }
    $found = @()
    $sends = @(); foreach ($t in $targets) { $sends += @{ Address = $t; Port = 10001; Bytes = [byte[]](1, 0, 0, 0) }; $sends += @{ Address = $t; Port = 10001; Bytes = [byte[]](2, 8, 0, 0) } }
    foreach ($x in @(Invoke-UdpProbe $sends $SourceIp 0 $WaitMs)) { $d = ConvertFrom-UbntDiscovery $x.Data; if ($d) { if (-not $d.IP) { $d.IP = $x.IP }; $found += $d } }
    $sends = @(); foreach ($t in $targets) { $sends += @{ Address = $t; Port = 5678; Bytes = [byte[]](0, 0, 0, 0) } }
    foreach ($x in @(Invoke-UdpProbe $sends $SourceIp 5678 $WaitMs)) { $d = ConvertFrom-Mndp $x.Data; if ($d) { if (-not $d.IP) { $d.IP = $x.IP }; $found += $d } }
    $nsdp = New-NsdpRequest $mac
    $sends = @(); foreach ($t in $targets) { $sends += @{ Address = $t; Port = 63322; Bytes = $nsdp } }
    foreach ($x in @(Invoke-UdpProbe $sends $SourceIp 63321 $WaitMs)) { $d = ConvertFrom-Nsdp $x.Data; if ($d) { if (-not $d.IP) { $d.IP = $x.IP }; $found += $d } }
    return $found
}

function ConvertFrom-NbnsStatus {
    # NetBIOS node status reply: computer name, workgroup or domain, and the adapter MAC.
    param([byte[]]$B)
    if (-not $B -or $B.Length -lt 57) { return $null }
    $cnt = [int]$B[56]; $p = 57; $computer = $null; $group = $null; $server = $false
    for ($i = 0; $i -lt $cnt -and $p + 18 -le $B.Length; $i++) {
        $nm = ConvertTo-AsciiText $B $p 15; $suffix = [int]$B[$p + 15]; $isGroup = [bool]([int]$B[$p + 16] -band 0x80)
        if ($suffix -eq 0 -and -not $isGroup -and -not $computer) { $computer = $nm }
        if ($suffix -eq 0 -and $isGroup -and -not $group) { $group = $nm }
        if ($suffix -eq 0x20) { $server = $true }
        $p += 18
    }
    if (-not $computer -and -not $group) { return $null }
    return [pscustomobject]@{ Name = $computer; Domain = $group; FileServer = $server; Mac = $(if ($p + 6 -le $B.Length) { ConvertTo-MacText $B $p } else { $null }) }
}

function Get-SmbInfo {
    # Two negotiate messages, no logon: the SMB2/3 dialect and whether signing is required, then whether
    # the old SMB1 protocol still answers.
    param([string]$Ip, [int]$TimeoutMs = 1500)
    $r = [ordered]@{ Smb2Dialect = $null; SigningRequired = $null; Smb1Enabled = $null; ServerTime = $null; Error = $null }
    $exchange = {
        param([byte[]]$Packet)
        $c = New-Object Net.Sockets.TcpClient
        try {
            if (-not ($c.ConnectAsync($Ip, 445).Wait($TimeoutMs) -and $c.Connected)) { return $null }
            $ns = $c.GetStream(); $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs
            $ns.Write($Packet, 0, $Packet.Length)
            $buf = New-Object byte[] 512
            $n = $ns.Read($buf, 0, $buf.Length)
            if ($n -le 0) { return $null }
            $got = New-Object byte[] $n; [Array]::Copy($buf, 0, $got, 0, $n)
            return , $got
        } catch { return $null } finally { try { $c.Close() } catch { } }
    }
    try {
        # SMB2 negotiate: 4-byte length, 64-byte header, 36-byte request, dialects 2.0.2, 2.1, 3.0 and 3.0.2.
        $p = New-Object byte[] 112
        $p[3] = 108
        $p[4] = 0xFE; $p[5] = 0x53; $p[6] = 0x4D; $p[7] = 0x42; $p[8] = 64; $p[18] = 1
        $p[68] = 36; $p[70] = 4; $p[72] = 1
        $guid = [Guid]::NewGuid().ToByteArray(); [Array]::Copy($guid, 0, $p, 80, 16)
        $dialects = @(0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03)
        for ($i = 0; $i -lt 8; $i++) { $p[104 + $i] = [byte]$dialects[$i] }
        $resp = & $exchange $p
        if ($resp -and $resp.Length -ge 76 -and $resp[4] -eq 0xFE -and $resp[5] -eq 0x53) {
            $dial = [int]$resp[72] + ([int]$resp[73] * 256)
            $r['Smb2Dialect'] = '{0}.{1}.{2}' -f ($dial -shr 8), (($dial -shr 4) -band 15), ($dial -band 15)
            $r['SigningRequired'] = [bool]([int]$resp[70] -band 2)
            if ($resp.Length -ge 116) { try { $ft = [BitConverter]::ToInt64($resp, 108); if ($ft -gt 0) { $r['ServerTime'] = Format-Date ([DateTime]::FromFileTimeUtc($ft).ToLocalTime()) } } catch { } }
        } elseif (-not $resp) { $r['Error'] = 'no answer to SMB2 negotiate' }
        # SMB1 negotiate offering only "NT LM 0.12". An SMB1 answer that accepts it means SMB1 is still on.
        $s = New-Object byte[] 51
        $s[3] = 47
        $s[4] = 0xFF; $s[5] = 0x53; $s[6] = 0x4D; $s[7] = 0x42; $s[8] = 0x72; $s[13] = 0x18; $s[14] = 0x53; $s[15] = 0xC8
        $s[37] = 12; $s[39] = 2
        $nt = [Text.Encoding]::ASCII.GetBytes('NT LM 0.12'); [Array]::Copy($nt, 0, $s, 40, 10)
        $r1 = & $exchange $s
        $r['Smb1Enabled'] = [bool]($r1 -and $r1.Length -ge 39 -and $r1[4] -eq 0xFF -and $r1[5] -eq 0x53 -and $r1[8] -eq 0x72 -and -not ($r1[37] -eq 0xFF -and $r1[38] -eq 0xFF))
    } catch { $r['Error'] = $_.Exception.Message }
    return [pscustomobject]$r
}

function Get-RdpTlsName {
    # Remote Desktop: asks for a TLS session and reads the certificate name (the computer's own name).
    # No credentials are sent.
    param([string]$Ip, [int]$TimeoutMs = 2000)
    $r = [ordered]@{ Name = $null; NlaOffered = $null; Error = $null }
    $c = New-Object Net.Sockets.TcpClient
    $ssl = $null
    try {
        if (-not ($c.ConnectAsync($Ip, 3389).Wait($TimeoutMs) -and $c.Connected)) { throw 'connect failed' }
        $ns = $c.GetStream(); $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs
        $req = [byte[]](3, 0, 0, 19, 14, 0xE0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0)
        $ns.Write($req, 0, $req.Length)
        $buf = New-Object byte[] 64
        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -lt 19 -or $buf[11] -ne 2) { throw 'TLS not offered' }
        $r['NlaOffered'] = [bool]([int]$buf[15] -band 2)
        $cb = [Net.Security.RemoteCertificateValidationCallback] { param($s, $cert, $chain, $errs) $true }
        $ssl = New-Object Net.Security.SslStream($ns, $false, $cb)
        $ssl.AuthenticateAsClient($Ip, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        if ($cert.Subject -match 'CN=([^,]+)') { $r['Name'] = $matches[1].Trim() }
    } catch { $r['Error'] = $_.Exception.GetBaseException().Message }
    finally { if ($ssl) { try { $ssl.Dispose() } catch { } }; try { $c.Close() } catch { } }
    return [pscustomobject]$r
}

function Get-PhonePortSpeed {
    # Speed of the PC pass-through port on common Polycom models, from the model number.
    param([string]$Model)
    if ($Model -match 'VVX[ _]?(\d{3})') {
        $n = [int]$matches[1]
        if (@(101, 150, 201, 300, 301, 400, 401) -contains $n) { return '10/100' }
        if (@(250, 310, 311, 350, 410, 411, 450, 500, 501, 600, 601) -contains $n) { return 'Gigabit' }
    }
    if ($Model -match '(?:SPIP|SoundPoint IP)[ _]?(\d{3})') {
        $n = [int]$matches[1]
        if (@(560, 670) -contains $n) { return 'Gigabit' }
        if (@(320, 321, 330, 331, 335, 430, 450, 550, 650) -contains $n) { return '10/100' }
    }
    if ($Model -match 'Trio|CCX') { return 'Gigabit' }
    return $null
}

function Get-DeviceIdentity {
    # Works out what a device is from everything it said about itself. $Ev keys (all optional):
    # MacVendor, Name, Ports, Disc, Sip, Ssdp, Wsd, Mdns, Http (banners), Ssh, Ftp, Nbns, Smb, RdpName,
    # DhcpClass, Neighbor. Returns Kind, Vendor, Model, Firmware, Confidence and the evidence used.
    param($Ev)
    $evid = New-Object Collections.Generic.List[string]
    $kind = $null; $vendor = $null; $model = $null; $fw = $null; $conf = 'Possible'; $pass = $null
    $note = { param($src, $val) $v = ("$val" -replace '\s+', ' ').Trim(); if ($v) { $evid.Add("${src}: $v") } }

    $d = $Ev['Disc']
    if ($d) {
        $vendor = ("$($d.Protocol)" -replace ' discovery$', '')
        $model = if ($d.ModelFull) { "$($d.ModelFull)" } else { "$($d.Model)" }
        $fw = "$($d.Firmware)"; $conf = 'Confirmed'
        & $note $d.Protocol ("{0} {1} {2}" -f $d.Name, $model, $fw)
        if ("$model $($d.Model)" -match 'EdgeRouter|^ER-|\bER-|USG|UDM|UXG|RB\d|CCR|hEX|hAP') { $kind = 'Router or firewall' }
        elseif ("$model $($d.Model)" -match 'Switch|^US|\bUSW|\bES-|CRS|^GS|^XS|^JGS|^MS\d') { $kind = 'Switch' }
        elseif ("$model $($d.Model)" -match 'UAP|\bU6|\bU7|\bAC\b|nanoHD|FlexHD|WAX|WAC|\bcAP|wAP|LiteBeam|NanoStation|airMAX') { $kind = 'Access point' }
        else { $kind = 'Network device' }
    }
    if ($Ev['Sip']) {
        $ua = "$($Ev['Sip'])"; & $note 'SIP user agent' $ua
        if (-not $kind) { $kind = 'Desk phone' }
        if ($ua -match 'Polycom\w*-([A-Za-z]+)_(\w+)-UA/([\d.]+)') { $vendor = 'Polycom'; $model = ('{0} {1}' -f $matches[1], $matches[2]) -replace '^SPIP', 'SoundPoint IP' -replace '^SSIP', 'SoundStation IP'; $fw = $matches[3]; $conf = 'Confirmed' }
        elseif ($ua -match '(Yealink|Grandstream|Fanvil|Mitel|Aastra|Avaya|Htek|Snom|snom|Cisco|Panasonic|Digium|Sangoma|Obihai|Poly|Algo|CyberData|Valcom)[ /_-]*([A-Za-z0-9-]+)?[ /_-]*([\d][\w.]*)?') { $vendor = $matches[1]; if ($matches[2]) { $model = $matches[2] }; if ($matches[3]) { $fw = $matches[3] }; $conf = 'Confirmed' }
        elseif ($ua -match 'Asterisk|FreePBX|FreeSWITCH|3CX|Kamailio|OpenSIPS') { $kind = 'Phone system'; $vendor = $matches[0]; $conf = 'Confirmed' }
        $pass = Get-PhonePortSpeed "$model"
    }
    $s = $Ev['Ssdp']
    if ($s -and ($s.Model -or $s.Manufacturer)) { & $note 'UPnP' ("{0} {1} {2}" -f $s.Manufacturer, $s.Model, $s.FriendlyName); if (-not $model -and $s.Model -and "$($s.Model)" -ne 'IPC') { $model = "$($s.Model)"; $conf = 'Confirmed' }; if (-not $vendor -and $s.Manufacturer -and "$($s.Manufacturer)" -ne 'General') { $vendor = "$($s.Manufacturer)" } }
    $w = $Ev['Wsd']
    if ($w) { & $note 'WS-Discovery' ("{0} {1} {2}" -f $w.Name, $w.Hardware, $w.Types); if (-not $model -and $w.Hardware) { $model = "$($w.Hardware)"; $conf = 'Confirmed' } }
    $m = $Ev['Mdns']
    if ($m) {
        & $note 'mDNS' ("{0} | {1}" -f (@($m.Names) -join ', '), (@($m.Text) -join '; '))
        if (-not $model -and "$(@($m.Text) -join '; ')" -match '(?:^|; )(?:ty|md|model|product)=\(?([^;)]{2,60})') { $model = $matches[1].Trim(); $conf = 'Confirmed' }
    }
    $nb = $Ev['Neighbor']
    if ($nb) { & $note 'Announced on the wire' $nb }
    foreach ($h in @($Ev['Http'])) { if ($h -and ($h.Title -or $h.Server -or $h.CertSubject -or $h.AuthRealm)) { & $note ("Web page {0}" -f ("$($h.Url)" -replace '^(https?)://[^:/]+(:\d+)?.*$', '$1$2')) ("{0} | server {1} | realm {2} | cert {3}" -f $h.Title, $h.Server, $h.AuthRealm, $h.CertSubject) } }
    if ($Ev['Ssh']) { & $note 'SSH banner' $Ev['Ssh'] }
    if ($Ev['Ftp']) { & $note 'FTP banner' $Ev['Ftp'] }
    if ($Ev['DhcpClass']) { & $note 'DHCP vendor class' $Ev['DhcpClass'] }
    $win = $false
    if ($Ev['Nbns']) { & $note 'NetBIOS' ("{0} in {1}" -f $Ev['Nbns'].Name, $Ev['Nbns'].Domain); $win = $true }
    if ($Ev['RdpName']) { & $note 'Remote Desktop certificate' $Ev['RdpName']; $win = $true }
    if ($Ev['Smb'] -and $Ev['Smb'].Smb2Dialect) { & $note 'File sharing' ("SMB {0}, signing {1}, SMB1 {2}" -f $Ev['Smb'].Smb2Dialect, $(if ($Ev['Smb'].SigningRequired) { 'required' } else { 'not required' }), $(if ($Ev['Smb'].Smb1Enabled) { 'ON' } else { 'off' })) }

    # Everything the device said, as one text, matched against known product names (most specific first).
    $hay = (@($evid) + @("$($Ev['Name'])")) -join ' | '
    $rules = @(
        @('EdgeOS|EdgeRouter', 'Router or firewall', 'Ubiquiti', '(EdgeRouter[\w -]{0,20}|\bER-[\w-]+)'),
        @('EdgeSwitch', 'Switch', 'Ubiquiti', '(EdgeSwitch[\w -]{0,20}|\bES-[\w-]+)'),
        @('UniFi|UBNT|Ubiquiti', 'Network device', 'Ubiquiti', '(\bU[A-Z0-9]{1,4}-[\w-]+|UniFi [\w -]{2,30})'),
        @('FortiGate|FortiWiFi|\bFGT\d|\bFG\d{2,4}[A-Z]|\bFWF\d', 'Firewall', 'Fortinet', '(Forti(?:Gate|WiFi)[- ]?\w+|\bF(?:GT|G|WF)\d{2,4}[A-Z]?)'),
        @('FortiSwitch|FortiAP|Fortinet', 'Network device', 'Fortinet', '(Forti(?:Switch|AP)[- ]?\w+)'),
        @('SonicWall|SonicOS', 'Firewall', 'SonicWall', '(\b(?:TZ|NSa|NSA|SOHO)\s?\d+\w*)'),
        @('WatchGuard|Fireware', 'Firewall', 'WatchGuard', '(\b[TM]\d{2,4}(?:-W)?\b)'),
        @('Sophos|ApplianceCertificate', 'Firewall', 'Sophos', '(\b(?:XGS|XG|SG)\s?\d+\w*)'),
        @('Meraki', 'Network device', 'Cisco Meraki', '(\b(?:MX|MS|MR|Z)\d+\w*)'),
        @('pfSense', 'Firewall', 'pfSense', $null), @('OPNsense', 'Firewall', 'OPNsense', $null),
        @('MikroTik|RouterOS|ROSSSH', 'Router or switch', 'MikroTik', '(\b(?:RB|CRS|CCR|hAP|hEX)[\w-]*)'),
        @('PAN-OS|Palo Alto|GlobalProtect', 'Firewall', 'Palo Alto Networks', '(\bPA-\d+\w*)'),
        @('ArubaOS|Aruba|ProCurve|OfficeConnect|Mocana', 'Switch or access point', 'Aruba / HPE', '(\bJ\d{4}[A-Z]\b|\b(?:2530|2540|2930|1930|1950|1960)[\w-]*)'),
        @('NETGEAR|ProSAFE', 'Switch or access point', 'Netgear', '(\b(?:GS|XS|MS|WAX|WAC|JGS|FS)\d+[\w-]*)'),
        @('TP-LINK|Omada|JetStream', 'Network device', 'TP-Link', '(\b(?:TL-|EAP|SG|SX)\w[\w-]*)'),
        @('Ruckus|Unleashed', 'Access point or switch', 'Ruckus', '(\b(?:R|H|T|ICX)\d{3,4}\w*)'),
        @('JUNOS|Juniper', 'Network device', 'Juniper', '(\b(?:EX|SRX|QFX)\d+[\w-]*)'),
        @('D-Link', 'Network device', 'D-Link', '(\bD[GEW][SAR]-[\w-]+)'), @('Zyxel', 'Network device', 'Zyxel', $null), @('EnGenius', 'Access point or switch', 'EnGenius', $null),
        @('Cambium', 'Access point', 'Cambium', $null), @('ExtremeXOS|Extreme Networks', 'Switch', 'Extreme', $null), @('PowerConnect|Dell Networking|Dell EMC Networking', 'Switch', 'Dell', $null),
        @('Cisco', 'Network device', 'Cisco', '(\b(?:SG|CBS|WS-C|C9|ISR|ASA|SF)\d[\w-]*)'),
        @('Polycom|\bPoly\b', 'Desk phone', 'Polycom', '(\b(?:VVX|Trio|CCX)\s?\d+\w*|SoundPoint IP \d+|SoundStation[\w ]{0,12})'),
        @('Yealink', 'Desk phone', 'Yealink', '(\b(?:SIP-)?[TWCV]P?\d{2}\w*)'), @('Grandstream', 'Desk phone or gateway', 'Grandstream', '(\b(?:GXP|GRP|GXV|HT|DP|UCM|GWN)\d+\w*)'),
        @('snom', 'Phone or paging device', 'snom', '(snom\s?\w+|\bPA1\b|\bD\d{3}\b)'), @('Mitel|Aastra', 'Desk phone', 'Mitel', $null), @('\bAlgo\b', 'Paging device', 'Algo', '(\b\d{4}\b)'),
        @('Avaya', 'Desk phone', 'Avaya', $null), @('Fanvil', 'Desk phone', 'Fanvil', $null), @('CyberData|Valcom', 'Paging device', $null, $null),
        @('TopAccess|e-STUDIO', 'Printer or copier', 'Toshiba', '(e-STUDIO\s?\w+)'),
        @('LaserJet|OfficeJet|DesignJet|PageWide|JetDirect|Virata-EmWeb|HP HTTP Server', 'Printer', 'HP', '((?:Color )?(?:LaserJet|OfficeJet|DesignJet|PageWide)(?: \w+){0,3}? [A-Z]{0,2}\d{3,4}\w*)'),
        @('Brother|debut/', 'Printer', 'Brother', '(\b(?:HL|MFC|DCP|QL|PT|TD|ADS)-\w+)'),
        @('Lexmark', 'Printer', 'Lexmark', '(Lexmark\s+\w+)'), @('RICOH|Web Image Monitor|Savin|Lanier', 'Printer or copier', 'Ricoh', '(\b(?:MP|IM|SP)\s?C?\d+\w*)'),
        @('Canon|imageRUNNER|imageCLASS|Remote UI', 'Printer or copier', 'Canon', '((?:imageRUNNER|imageCLASS|\biR|\bMF|\bLBP)[\w -]{2,24})'),
        @('Xerox|CentreWare|VersaLink|AltaLink|WorkCentre', 'Printer or copier', 'Xerox', '((?:VersaLink|AltaLink|WorkCentre|Phaser)\s?\w+)'),
        @('KYOCERA|ECOSYS|TASKalfa|Command Center', 'Printer or copier', 'Kyocera', '((?:ECOSYS|TASKalfa)\s?\w+)'),
        @('KONICA|bizhub|PageScope', 'Printer or copier', 'Konica Minolta', '(bizhub\s?\w+)'), @('\bSHARP\b', 'Printer or copier', 'Sharp', '(\b(?:MX|BP)-\w+)'),
        @('EPSON', 'Printer', 'Epson', $null), @('Zebra|\bZTC\b', 'Label printer', 'Zebra', '(\bZ[TDQ]\d+\w*)'), @('Star Micronics|\bTSP\d', 'Receipt or label printer', 'Star Micronics', '(\bTSP\d+\w*)'),
        @('\bAXIS\b', 'Camera or audio device', 'Axis', '(AXIS\s+[A-Z]{1,2}\d{3,4}[\w-]*)'),
        @('Hanwha|Wisenet|Samsung Techwin|\b[XQPLT]N[VDOPBFM]-\w+', 'Camera', 'Hanwha', '(\b[XQPLT]N[VDOPBFM]-\w+)'),
        @('Hikvision|DNVRS|App-webs', 'Camera or recorder', 'Hikvision', '(\bDS-[\w-]+)'), @('Dahua|\bDH-', 'Camera or recorder', 'Dahua', '(\bDH-[\w-]+|\bIPC-[\w-]+)'),
        @('Avigilon', 'Camera', 'Avigilon', $null), @('Verkada', 'Camera', 'Verkada', $null), @('VIVOTEK', 'Camera', 'Vivotek', $null), @('Uniview', 'Camera', 'Uniview', $null),
        @('NetworkVideoTransmitter|onvif', 'Camera', $null, $null), @('NetworkVideoRecorder|\bNVR\b|\bDVR\b', 'Video recorder', $null, $null),
        @('Mercury Security|\bLP\d{4}\b|\bEP\d{4}\b', 'Door access controller', 'Mercury Security', '(\b(?:LP|EP)\d{4}\b)'), @('\bUKG\b|Kronos|InTouch', 'Time clock', 'UKG', $null),
        @('Ingenico|Verifone|PAX Technology', 'Card payment terminal', $null, $null),
        @('Synology|DiskStation', 'NAS', 'Synology', '(\b[DR]S\d+\+?\w*)'), @('QNAP', 'NAS', 'QNAP', '(\bTS-\w+)'), @('TrueNAS|FreeNAS', 'NAS', 'TrueNAS', $null),
        @('iDRAC|Integrated Dell Remote', 'Server management card', 'Dell', $null), @('\biLO\b|Integrated Lights-Out', 'Server management card', 'HPE', $null), @('\bIPMI\b|Supermicro|ATEN International', 'Server management card', 'Supermicro', $null),
        @('VMware ESXi', 'Virtualization host', 'VMware', $null), @('Proxmox', 'Virtualization host', 'Proxmox', $null),
        @('\bAPC\b|American Power|Network Management Card', 'UPS or power', 'APC', $null), @('\bEaton\b|CyberPower|Tripp Lite', 'UPS or power', $null, $null),
        @('Atrust|A-TRUST|\bWyse\b|\bIGEL\b|ThinPro|10ZiG', 'Thin client', $null, $null),
        @('AirPort|_airplay|_companion-link|\bApple\b', 'Apple device', 'Apple', $null), @('Chromecast|_googlecast|Google Home', 'Streaming or smart device', 'Google', $null), @('\bRoku\b', 'Streaming device', 'Roku', $null), @('Sonos', 'Speaker', 'Sonos', $null),
        @('Microsoft-IIS|Microsoft-HTTPAPI|Windows', 'Windows PC or server', 'Microsoft', $null)
    )
    foreach ($rule in $rules) {
        if ($hay -match $rule[0]) {
            if (-not $kind) { $kind = $rule[1] }
            if (-not $vendor -and $rule[2]) { $vendor = $rule[2] }
            if (-not $model -and $rule[3] -and $hay -match $rule[3]) { $model = $matches[1].Trim() }
            if ($conf -eq 'Possible') { $conf = 'Likely' }
            break
        }
    }
    if ($win -and (-not $kind -or $kind -match '^Windows')) { $kind = 'Windows PC or server'; if ($conf -eq 'Possible') { $conf = 'Likely' } }
    $mv = "$($Ev['MacVendor'])"
    if (-not $kind) {
        if ($mv -match 'Polycom|Yealink|Grandstream|Mitel|Avaya|Snom|Fanvil|Obihai') { $kind = 'Desk phone' }
        elseif ($mv -match 'A-TRUST|Atrust|Wyse|IGEL') { $kind = 'Thin client' }
        elseif ($mv -match 'Brother|Canon|Epson|Lexmark|Xerox|Ricoh|Konica|Kyocera|Sharp|Zebra|TOKYO ELECTRIC|Toshiba Tec|Oki ') { $kind = 'Printer or copier' }
        elseif ($mv -match 'Axis Comm|Hikvision|Dahua|Hanwha|Samsung Techwin|Verkada|Avigilon|Vivotek|Uniview') { $kind = 'Camera' }
        elseif ($mv -match 'Mercury Security') { $kind = 'Door access controller' }
        elseif ($mv -match 'UKG|Kronos') { $kind = 'Time clock' }
        elseif ($mv -match 'INGENICO|Verifone') { $kind = 'Card payment terminal' }
        elseif ($mv -match 'Ubiquiti|Meraki|Aruba|Ruckus|Fortinet|SonicWall|WatchGuard|Netgear|TP-Link|Juniper|Palo Alto|Sophos|MikroTik|Cisco|Extreme|EnGenius|Zyxel|D-Link') { $kind = 'Network device' }
        elseif ($mv -match 'Randomized') { $kind = 'Phone, tablet or personal device (private address)' }
        else { $kind = Get-DeviceRole ([int[]]@($Ev['Ports'] | Where-Object { $_ })) }
        if ($kind -eq 'Phone or phone system') { $kind = 'Desk phone' }
    }
    if (-not $vendor -and $mv -and $mv -notmatch 'Unknown|Randomized|IEEE Registration') { $vendor = $mv }
    return [ordered]@{ Kind = $kind; Vendor = $vendor; Model = $model; Firmware = $fw; PassThrough = $pass; Confidence = $conf; Evidence = @($evid) }
}

function Get-WindowsBuildName {
    param([int]$Build)
    if ($Build -ge 26100) { return 'Windows 11 24H2 or later / Server 2025' }
    if ($Build -ge 22000) { return 'Windows 11' }
    if ($Build -eq 20348) { return 'Windows Server 2022' }
    if ($Build -ge 19041 -and $Build -le 19045) { return 'Windows 10 (2004 to 22H2)' }
    if ($Build -eq 17763) { return 'Windows 10 1809 / Server 2019' }
    if ($Build -ge 10240 -and $Build -lt 19041) { if ($Build -eq 14393) { return 'Windows 10 1607 / Server 2016' } return 'Windows 10 (old release)' }
    if ($Build -eq 9600) { return 'Windows 8.1 / Server 2012 R2' }
    if ($Build -eq 9200) { return 'Windows 8 / Server 2012' }
    if ($Build -ge 7600 -and $Build -le 7601) { return 'Windows 7 / Server 2008 R2' }
    if ($Build -gt 0) { return "build $Build" }
    return $null
}

function Get-SmbNtlmInfo {
    # File-sharing handshake up to the server's challenge. No logon is attempted and no credentials are
    # sent; the challenge itself names the computer and its domain and carries the Windows build number.
    param([string]$Ip, [int]$TimeoutMs = 1500)
    $r = [ordered]@{ ComputerName = $null; DnsName = $null; Domain = $null; DnsDomain = $null; OsVersion = $null; Build = $null; Os = $null; Error = $null }
    $c = New-Object Net.Sockets.TcpClient
    try {
        if (-not ($c.ConnectAsync($Ip, 445).Wait($TimeoutMs) -and $c.Connected)) { throw 'connect failed' }
        $ns = $c.GetStream(); $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs
        $hdr = { param([int]$cmd, [int]$msgId) $h = New-Object byte[] 64; $h[0] = 0xFE; $h[1] = 0x53; $h[2] = 0x4D; $h[3] = 0x42; $h[4] = 64; $h[12] = [byte]$cmd; $h[14] = 1; $h[24] = [byte]$msgId; return , $h }
        $send = {
            param([byte[]]$body)
            $len = $body.Length
            $pkt = [byte[]](@(0, [byte](($len -shr 16) -band 255), [byte](($len -shr 8) -band 255), [byte]($len -band 255)) + @($body))
            $ns.Write($pkt, 0, $pkt.Length)
            $buf = New-Object byte[] 4096
            $n = $ns.Read($buf, 0, $buf.Length)
            if ($n -le 0) { return $null }
            $got = New-Object byte[] $n; [Array]::Copy($buf, 0, $got, 0, $n)
            return , $got
        }
        $neg = New-Object byte[] 44; $neg[0] = 36; $neg[2] = 4; $neg[4] = 1
        $g = [Guid]::NewGuid().ToByteArray(); [Array]::Copy($g, 0, $neg, 12, 16)
        $d = @(0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03); for ($i = 0; $i -lt 8; $i++) { $neg[36 + $i] = [byte]$d[$i] }
        $resp = & $send (Join-Bytes (& $hdr 0 0) $neg)
        if (-not $resp -or $resp.Length -lt 70 -or $resp[4] -ne 0xFE) { throw 'no SMB2 answer' }
        $ntlm = New-Object byte[] 40
        $sig = [Text.Encoding]::ASCII.GetBytes('NTLMSSP'); [Array]::Copy($sig, 0, $ntlm, 0, 7); $ntlm[8] = 1
        $ntlm[12] = 0x97; $ntlm[13] = 0x82; $ntlm[14] = 0x08; $ntlm[15] = 0xE2
        $ntlm[32] = 10; $ntlm[34] = 0x61; $ntlm[35] = 0x4A; $ntlm[39] = 15
        $ss = New-Object byte[] 24; $ss[0] = 25; $ss[3] = 1; $ss[12] = 88; $ss[14] = [byte]$ntlm.Length
        $resp = & $send (Join-Bytes (& $hdr 1 1) $ss $ntlm)
        if (-not $resp) { throw 'no answer to session setup' }
        $idx = -1
        for ($i = 0; $i -le $resp.Length - 56; $i++) { if ($resp[$i] -eq 0x4E -and $resp[$i + 1] -eq 0x54 -and $resp[$i + 2] -eq 0x4C -and $resp[$i + 3] -eq 0x4D -and $resp[$i + 4] -eq 0x53 -and $resp[$i + 5] -eq 0x53 -and $resp[$i + 6] -eq 0x50 -and $resp[$i + 7] -eq 0 -and $resp[$i + 8] -eq 2) { $idx = $i; break } }
        if ($idx -lt 0) { throw 'no NTLM challenge in the answer' }
        $flags = [BitConverter]::ToUInt32($resp, $idx + 20)
        if ($flags -band 0x02000000) {
            $build = [int][BitConverter]::ToUInt16($resp, $idx + 50)
            $r['OsVersion'] = '{0}.{1}.{2}' -f [int]$resp[$idx + 48], [int]$resp[$idx + 49], $build
            $r['Build'] = $build; $r['Os'] = Get-WindowsBuildName $build
        }
        $tiLen = [int][BitConverter]::ToUInt16($resp, $idx + 40); $p = $idx + [int][BitConverter]::ToUInt32($resp, $idx + 44)
        $end = [math]::Min($resp.Length, $p + $tiLen)
        while ($p + 4 -le $end) {
            $id = [int][BitConverter]::ToUInt16($resp, $p); $l = [int][BitConverter]::ToUInt16($resp, $p + 2)
            if ($id -eq 0 -or $p + 4 + $l -gt $end) { break }
            $val = [Text.Encoding]::Unicode.GetString($resp, $p + 4, $l)
            switch ($id) { 1 { $r['ComputerName'] = $val } 2 { $r['Domain'] = $val } 3 { $r['DnsName'] = $val } 4 { $r['DnsDomain'] = $val } }
            $p += 4 + $l
        }
    } catch { $r['Error'] = $_.Exception.GetBaseException().Message }
    finally { try { $c.Close() } catch { } }
    return [pscustomobject]$r
}

function New-IppRequest {
    # IPP Get-Printer-Attributes: the standard "describe yourself" question a print client asks.
    param([string]$Uri, [string[]]$Attributes)
    $b = New-Object Collections.Generic.List[byte]
    $b.AddRange([byte[]](1, 1, 0, 0x0B, 0, 0, 0, 1, 1))
    $attr = {
        param([int]$tag, [string]$name, [string]$value)
        $nb = [Text.Encoding]::ASCII.GetBytes("$name"); $vb = [Text.Encoding]::ASCII.GetBytes("$value")
        $b.Add([byte]$tag); $b.Add([byte]($nb.Length -shr 8)); $b.Add([byte]($nb.Length -band 255)); if ($nb.Length) { $b.AddRange([byte[]]$nb) }
        $b.Add([byte]($vb.Length -shr 8)); $b.Add([byte]($vb.Length -band 255)); if ($vb.Length) { $b.AddRange([byte[]]$vb) }
    }
    & $attr 0x47 'attributes-charset' 'utf-8'
    & $attr 0x48 'attributes-natural-language' 'en'
    & $attr 0x45 'printer-uri' $Uri
    $first = $true
    foreach ($a in $Attributes) { & $attr 0x44 $(if ($first) { 'requested-attributes' } else { '' }) $a; $first = $false }
    $b.Add(3)
    return , $b.ToArray()
}
function ConvertFrom-IppResponse {
    # Attribute name to value (or values) from an IPP reply; '_status' is the IPP status code.
    param([byte[]]$B)
    $out = [ordered]@{}
    if (-not $B -or $B.Length -lt 9) { return $out }
    $out['_status'] = ([int]$B[2] * 256) + [int]$B[3]
    $p = 8; $last = $null
    while ($p -lt $B.Length) {
        $tag = [int]$B[$p]; $p++
        if ($tag -eq 3) { break }
        if ($tag -lt 0x10) { continue }
        if ($p + 2 -gt $B.Length) { break }
        $nl = ([int]$B[$p] * 256) + [int]$B[$p + 1]; $p += 2
        if ($p + $nl + 2 -gt $B.Length) { break }
        $name = if ($nl) { [Text.Encoding]::ASCII.GetString($B, $p, $nl) } else { $last }
        $p += $nl
        $vl = ([int]$B[$p] * 256) + [int]$B[$p + 1]; $p += 2
        if ($p + $vl -gt $B.Length) { break }
        $val = $null
        if (($tag -eq 0x21 -or $tag -eq 0x23) -and $vl -eq 4) { $val = ([int]$B[$p] * 16777216) + ([int]$B[$p + 1] * 65536) + ([int]$B[$p + 2] * 256) + [int]$B[$p + 3] }
        elseif ($tag -eq 0x22 -and $vl -ge 1) { $val = [bool]$B[$p] }
        elseif ($tag -ge 0x30) { $val = ConvertTo-AsciiText $B $p $vl }
        $p += $vl; $last = $name
        if ($name -and $null -ne $val -and "$val" -ne '') { if ($out.Contains($name)) { $out[$name] = @($out[$name]) + $val } else { $out[$name] = $val } }
    }
    return $out
}

function Get-CaptureSummary {
    # Reads the pktmon capture a second time and reports what the wire shows: who answers DHCP and with
    # which options, spanning tree (the switch this port hangs off, the root switch), LLDP/CDP neighbors
    # with their capabilities and voice VLAN, VLAN tags, other subnets heard in ARP, and how busy the
    # broadcast domain is. Frames this PC sent are left out.
    param([string]$Path, [int]$Seconds, [string[]]$LocalMacs)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $own = @{}
    foreach ($m in @($LocalMacs)) { $k = ("$m" -replace '[^0-9A-Fa-f]', '').ToUpper(); if ($k) { $own[$k] = $true } }
    $frames = 0; $bcast = 0; $truncated = $false
    $etypes = @{}; $vlans = @{}; $arp = @{}; $talk = @{}; $udpPorts = @{}
    $stp = @{}; $dhcpSrv = @{}; $dhcpCli = @{}; $ra = @{}; $lldp = @{}; $cdp = @{}; $ann = @{}; $arpDup = @{}
    $lldpCaps = @('Other', 'Repeater', 'Bridge', 'WLAN access point', 'Router', 'Telephone', 'DOCSIS', 'Station')
    $mau = @{ 10 = '10BASE-T full'; 15 = '100BASE-TX half'; 16 = '100BASE-TX full'; 29 = '1000BASE-T half'; 30 = '1000BASE-T full'; 54 = '10GBASE-T' }
    $pos = 0
    while ($pos + 12 -le $bytes.Length) {
        $type = [BitConverter]::ToUInt32($bytes, $pos)
        $len  = [int][BitConverter]::ToUInt32($bytes, $pos + 4)
        if ($len -lt 12 -or $pos + $len -gt $bytes.Length) { break }
        $capLen = 0
        if ($type -eq 6) { $capLen = [int][BitConverter]::ToUInt32($bytes, $pos + 20) }
        if ($type -eq 6 -and $capLen -ge 14 -and $pos + 28 + $capLen -le $bytes.Length) {
            if ($frames -ge 40000) { $truncated = $true; break }
            $f = New-Object byte[] $capLen
            [Array]::Copy($bytes, $pos + 28, $f, 0, $capLen)
            $srcMac = [BitConverter]::ToString($f, 6, 6)
            if (-not $own.ContainsKey(($srcMac -replace '-', ''))) {
                $frames++
                $isB = ($f[0] -eq 255 -and $f[1] -eq 255 -and $f[2] -eq 255 -and $f[3] -eq 255 -and $f[4] -eq 255 -and $f[5] -eq 255)
                $off = 14; $et = ([int]$f[12] * 256) + [int]$f[13]
                if ($et -eq 0x8100 -and $capLen -ge 18) {
                    $vid = "$((([int]$f[14] -band 0x0F) * 256) + [int]$f[15])"
                    $vlans[$vid] = 1 + [int]$vlans[$vid]
                    $et = ([int]$f[16] * 256) + [int]$f[17]; $off = 18
                }
                if ($isB) { $bcast++; $talk[$srcMac] = 1 + [int]$talk[$srcMac] }
                $etKey = if ($et -le 1500) { 'LLC' } else { '0x{0:X4}' -f $et }
                $etypes[$etKey] = 1 + [int]$etypes[$etKey]

                if ($et -eq 0x0806 -and $capLen -ge $off + 28) {
                    $spa = ConvertTo-IpText $f ($off + 14)
                    # Untagged only: a tagged frame belongs to another VLAN, not to this port's network.
                    if ($off -eq 14 -and $spa -and $spa -ne '0.0.0.0') {
                        $sha = ConvertTo-MacText $f ($off + 8)
                        if ($arp.ContainsKey($spa) -and $arp[$spa] -ne $sha) { $arpDup[$spa] = "$($arp[$spa]) and $sha" }
                        $arp[$spa] = $sha
                    }
                }
                elseif ($et -eq 0x0800 -and $capLen -ge $off + 28) {
                    $ihl = ([int]$f[$off] -band 0x0F) * 4
                    if ([int]$f[$off + 9] -eq 17 -and $capLen -ge $off + $ihl + 8) {
                        $u = $off + $ihl
                        $sp = ([int]$f[$u] * 256) + [int]$f[$u + 1]; $dp = ([int]$f[$u + 2] * 256) + [int]$f[$u + 3]; $pl = $u + 8
                        $srcIp = ConvertTo-IpText $f ($off + 12)
                        $udpPorts["$dp"] = 1 + [int]$udpPorts["$dp"]
                        if (($sp -eq 67 -or $sp -eq 68) -and $capLen -ge $pl + 241) {
                            $opt = @{}; $q = $pl + 240
                            while ($q + 2 -le $capLen) {
                                $ot = [int]$f[$q]
                                if ($ot -eq 255) { break }
                                if ($ot -eq 0) { $q++; continue }
                                $ol = [int]$f[$q + 1]
                                if ($q + 2 + $ol -gt $capLen) { break }
                                $opt[$ot] = @(($q + 2), $ol); $q += 2 + $ol
                            }
                            $oStr = { param($k) if ($opt.ContainsKey($k)) { ConvertTo-AsciiText $f $opt[$k][0] $opt[$k][1] } }
                            $oIps = { param($k) if ($opt.ContainsKey($k)) { $l = @(); for ($z = 0; $z + 4 -le $opt[$k][1]; $z += 4) { $l += ConvertTo-IpText $f ($opt[$k][0] + $z) }; $l -join ', ' } }
                            $giaddr = ConvertTo-IpText $f ($pl + 24)
                            if ($sp -eq 67) {
                                $sid = if ($opt.ContainsKey(54)) { ConvertTo-IpText $f $opt[54][0] } else { $srcIp }
                                if (-not $dhcpSrv.ContainsKey($sid)) { $dhcpSrv[$sid] = [ordered]@{ Server = $sid; SentFromIp = $srcIp; SentFromMac = $srcMac; RelayAgent = $null; Messages = 0; Mask = $null; Router = $null; Dns = $null; Domain = $null; LeaseSeconds = $null; TftpServer = $null; TftpAddresses = $null; BootFile = $null; Ntp = $null; VendorSpecificHex = $null } }
                                $e = $dhcpSrv[$sid]; $e['Messages']++
                                if ($giaddr -and $giaddr -ne '0.0.0.0') { $e['RelayAgent'] = $giaddr }
                                foreach ($pair in @(@(1, 'Mask'), @(3, 'Router'), @(6, 'Dns'), @(42, 'Ntp'), @(150, 'TftpAddresses'))) { $v = & $oIps $pair[0]; if ($v) { $e[$pair[1]] = $v } }
                                foreach ($pair in @(@(15, 'Domain'), @(66, 'TftpServer'), @(67, 'BootFile'))) { $v = & $oStr $pair[0]; if ($v) { $e[$pair[1]] = $v } }
                                if ($opt.ContainsKey(51) -and $opt[51][1] -ge 4) { $o = $opt[51][0]; $e['LeaseSeconds'] = ([int64]$f[$o] * 16777216) + ([int64]$f[$o + 1] * 65536) + ([int64]$f[$o + 2] * 256) + [int64]$f[$o + 3] }
                                if ($opt.ContainsKey(43)) { $e['VendorSpecificHex'] = ([BitConverter]::ToString($f, $opt[43][0], [math]::Min($opt[43][1], 64)) -replace '-', '') }
                            } else {
                                $ch = ConvertTo-MacText $f ($pl + 28)
                                if (-not $dhcpCli.ContainsKey($ch)) { $dhcpCli[$ch] = [ordered]@{ Mac = $ch; Hostname = $null; VendorClass = $null; RequestedIp = $null; Messages = 0 } }
                                $c = $dhcpCli[$ch]; $c['Messages']++
                                $v = & $oStr 12; if ($v) { $c['Hostname'] = $v }
                                $v = & $oStr 60; if ($v) { $c['VendorClass'] = $v }
                                $v = & $oIps 50; if ($v) { $c['RequestedIp'] = $v }
                            }
                        }
                        elseif (($dp -eq 10001 -or $sp -eq 10001 -or $dp -eq 5678 -or $dp -eq 63321) -and $capLen -gt $pl + 8) {
                            $payload = New-Object byte[] ($capLen - $pl)
                            [Array]::Copy($f, $pl, $payload, 0, $payload.Length)
                            $d = if ($dp -eq 10001 -or $sp -eq 10001) { ConvertFrom-UbntDiscovery $payload } elseif ($dp -eq 63321) { ConvertFrom-Nsdp $payload } else { ConvertFrom-Mndp $payload }
                            if ($d) { if (-not $d.IP) { $d.IP = $srcIp }; if (-not $d.Mac) { $d.Mac = $srcMac }; $ann["$($d.Protocol)|$($d.Mac)"] = $d }
                        }
                    }
                }
                elseif ($et -eq 0x86DD -and $capLen -ge $off + 41) {
                    if ([int]$f[$off + 6] -eq 58 -and [int]$f[$off + 40] -eq 134) { $ra[$srcMac] = 1 + [int]$ra[$srcMac] }
                }
                elseif ($et -eq 0x88CC) {
                    $n = [ordered]@{ Protocol = 'LLDP'; SenderMac = $srcMac; ChassisMac = $null; SystemName = $null; SystemDescription = $null; PortId = $null; PortDescription = $null; Capabilities = @(); MgmtIP = $null; PortVlan = $null; VlanNames = @(); LinkMode = $null; MedDeviceClass = $null; VoiceVlan = $null; VoiceVlanTagged = $null; MedManufacturer = $null; MedModel = $null; MedFirmware = $null; MedSoftware = $null; MedSerial = $null; Frames = 1 }
                    $p = $off
                    while ($p + 2 -le $capLen) {
                        $hdr = ([int]$f[$p] * 256) + [int]$f[$p + 1]
                        $tt = $hdr -shr 9; $tl = $hdr -band 0x1FF; $p += 2
                        if ($tt -eq 0 -or $p + $tl -gt $capLen) { break }
                        if ($tt -eq 1 -and $tl -ge 7 -and $f[$p] -eq 4) { $n['ChassisMac'] = ConvertTo-MacText $f ($p + 1) }
                        elseif ($tt -eq 2 -and $tl -ge 2) { if ($tl -ge 7 -and $f[$p] -eq 3) { $n['PortId'] = 'MAC ' + (ConvertTo-MacText $f ($p + 1)) } else { $n['PortId'] = ConvertTo-AsciiText $f ($p + 1) ($tl - 1) } }
                        elseif ($tt -eq 4) { $n['PortDescription'] = ConvertTo-AsciiText $f $p $tl }
                        elseif ($tt -eq 5) { $n['SystemName'] = ConvertTo-AsciiText $f $p $tl }
                        elseif ($tt -eq 6) { $n['SystemDescription'] = ConvertTo-AsciiText $f $p $tl }
                        elseif ($tt -eq 7 -and $tl -ge 4) {
                            $bits = ([int]$f[$p + 2] * 256) + [int]$f[$p + 3]
                            if (-not $bits) { $bits = ([int]$f[$p] * 256) + [int]$f[$p + 1] }
                            $caps = @(); for ($bi = 0; $bi -lt 8; $bi++) { if ($bits -band (1 -shl $bi)) { $caps += $lldpCaps[$bi] } }
                            $n['Capabilities'] = $caps
                        }
                        elseif ($tt -eq 8 -and $tl -ge 6 -and $f[$p + 1] -eq 1) { $n['MgmtIP'] = ConvertTo-IpText $f ($p + 2) }
                        elseif ($tt -eq 127 -and $tl -ge 4) {
                            $oui = '{0:X2}{1:X2}{2:X2}' -f $f[$p], $f[$p + 1], $f[$p + 2]; $st = [int]$f[$p + 3]
                            if ($oui -eq '0080C2' -and $st -eq 1 -and $tl -ge 6) { $n['PortVlan'] = ([int]$f[$p + 4] * 256) + [int]$f[$p + 5] }
                            elseif ($oui -eq '0080C2' -and $st -eq 3 -and $tl -ge 7) { $n['VlanNames'] = @($n['VlanNames']) + ('{0} {1}' -f (([int]$f[$p + 4] * 256) + [int]$f[$p + 5]), (ConvertTo-AsciiText $f ($p + 7) ([math]::Min([int]$f[$p + 6], $tl - 7)))).Trim() }
                            elseif ($oui -eq '00120F' -and $st -eq 1 -and $tl -ge 9) { $mt = ([int]$f[$p + 7] * 256) + [int]$f[$p + 8]; $n['LinkMode'] = if ($mau.ContainsKey($mt)) { $mau[$mt] } else { "MAU type $mt" } }
                            elseif ($oui -eq '0012BB' -and $st -eq 1 -and $tl -ge 7) { $n['MedDeviceClass'] = switch ([int]$f[$p + 6]) { 1 { 'Endpoint class I' } 2 { 'Endpoint class II (media)' } 3 { 'Endpoint class III (phone)' } 4 { 'Network connectivity (switch)' } default { "class $([int]$f[$p + 6])" } } }
                            elseif ($oui -eq '0012BB' -and $st -eq 2 -and $tl -ge 8 -and ([int]$f[$p + 4] -eq 1 -or -not $n['VoiceVlan'])) {
                                $n['VoiceVlan'] = (([int]$f[$p + 5] -band 0x1F) * 128) + ([int]$f[$p + 6] -shr 1)
                                $n['VoiceVlanTagged'] = [bool]([int]$f[$p + 5] -band 0x40)
                            }
                            elseif ($oui -eq '0012BB' -and $st -ge 5 -and $st -le 10) {
                                $key = @{ 5 = 'MedHardware'; 6 = 'MedFirmware'; 7 = 'MedSoftware'; 8 = 'MedSerial'; 9 = 'MedManufacturer'; 10 = 'MedModel' }[$st]
                                if ($n.Contains($key)) { $n[$key] = ConvertTo-AsciiText $f ($p + 4) ($tl - 4) }
                            }
                        }
                        $p += $tl
                    }
                    $k = "$($n['ChassisMac'])|$($n['PortId'])|$srcMac"
                    if ($lldp.ContainsKey($k)) { $lldp[$k]['Frames']++ } else { $lldp[$k] = $n }
                }
                elseif ($et -le 1500) {
                    $dst = [BitConverter]::ToString($f, 0, 6)
                    if ($dst -eq '01-00-0C-CC-CC-CC' -and $capLen -ge $off + 16 -and $f[$off + 6] -eq 0x20 -and $f[$off + 7] -eq 0x00) {
                        $n = [ordered]@{ Protocol = 'CDP'; SenderMac = $srcMac; DeviceId = $null; PortId = $null; Platform = $null; Software = $null; Capabilities = @(); Address = $null; NativeVlan = $null; VoiceVlan = $null; Frames = 1 }
                        $p = $off + 12
                        while ($p + 4 -le $capLen) {
                            $tt = ([int]$f[$p] * 256) + [int]$f[$p + 1]; $tl = ([int]$f[$p + 2] * 256) + [int]$f[$p + 3]
                            if ($tl -lt 4 -or $p + $tl -gt $capLen) { break }
                            $s = ConvertTo-AsciiText $f ($p + 4) ($tl - 4)
                            if ($tt -eq 1) { $n['DeviceId'] = $s } elseif ($tt -eq 3) { $n['PortId'] = $s } elseif ($tt -eq 5) { $n['Software'] = $s } elseif ($tt -eq 6) { $n['Platform'] = $s }
                            elseif ($tt -eq 4 -and $tl -ge 8) { $cb = [int]$f[$p + 7]; $caps = @(); foreach ($pair in @(@(1, 'Router'), @(2, 'Bridge'), @(8, 'Switch'), @(16, 'Host'), @(64, 'Repeater'), @(128, 'Telephone'))) { if ($cb -band $pair[0]) { $caps += $pair[1] } }; $n['Capabilities'] = $caps }
                            elseif ($tt -eq 10 -and $tl -ge 6) { $n['NativeVlan'] = ([int]$f[$p + 4] * 256) + [int]$f[$p + 5] }
                            elseif ($tt -eq 14 -and $tl -ge 7) { $n['VoiceVlan'] = ([int]$f[$p + 5] * 256) + [int]$f[$p + 6] }
                            elseif ($tt -eq 2 -and $tl -ge 17 -and $f[$p + 8] -eq 1 -and $f[$p + 10] -eq 0xCC) { $n['Address'] = ConvertTo-IpText $f ($p + 13) }
                            $p += $tl
                        }
                        $k = "$($n['DeviceId'])|$($n['PortId'])|$srcMac"
                        if ($cdp.ContainsKey($k)) { $cdp[$k]['Frames']++ } else { $cdp[$k] = $n }
                    }
                    else {
                        $b = -1; $proto = $null
                        if ($dst -eq '01-80-C2-00-00-00' -and $capLen -ge $off + 3 -and $f[$off] -eq 0x42 -and $f[$off + 1] -eq 0x42) { $b = $off + 3; $proto = 'Spanning tree' }
                        elseif ($dst -eq '01-00-0C-CC-CC-CD' -and $capLen -ge $off + 8) { $b = $off + 8; $proto = 'Cisco per-VLAN spanning tree' }
                        if ($b -ge 0 -and $capLen -ge $b + 27 -and ([int]$f[$b + 3] -eq 0 -or [int]$f[$b + 3] -eq 2)) {
                            $brMac = ConvertTo-MacText $f ($b + 19); $portId = ([int]$f[$b + 25] * 256) + [int]$f[$b + 26]
                            $k = "$proto|$brMac|$portId"
                            if ($stp.ContainsKey($k)) { $stp[$k]['Frames']++ }
                            else {
                                $stp[$k] = [ordered]@{
                                    Protocol = $(if ([int]$f[$b + 2] -ge 2) { "$proto (rapid)" } else { $proto }); SenderMac = $srcMac
                                    BridgeMac = $brMac; BridgePriority = ([int]$f[$b + 17] * 256) + [int]$f[$b + 18]; PortId = $portId
                                    RootMac = ConvertTo-MacText $f ($b + 7); RootPriority = ([int]$f[$b + 5] * 256) + [int]$f[$b + 6]
                                    RootPathCost = ([int64]$f[$b + 13] * 16777216) + ([int64]$f[$b + 14] * 65536) + ([int64]$f[$b + 15] * 256) + [int64]$f[$b + 16]
                                    ThisSwitchIsRoot = ($brMac -eq (ConvertTo-MacText $f ($b + 7))); Frames = 1
                                }
                            }
                        }
                    }
                }
            }
        }
        $pos += $len
    }
    $subnets = @($arp.Keys | Group-Object { ($_ -split '\.')[0..2] -join '.' } | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Subnet = "$($_.Name).0/24"; Hosts = $_.Count; Sample = (@($_.Group | Select-Object -First 4) -join ', ') } })
    $secs = [math]::Max(1, $Seconds)
    [ordered]@{
        Seconds = $Seconds; Frames = $frames; Truncated = $truncated
        BroadcastFrames = $bcast; BroadcastPerSecond = [math]::Round($bcast / $secs, 1)
        Note = 'Counts are approximate: pktmon can record one frame at more than one point.'
        EtherTypes = @($etypes.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
        VlanTagsSeen = @($vlans.Keys | Sort-Object { [int]$_ })
        EapolFrames = [int]$etypes['0x888E']
        ArpConflicts = @($arpDup.GetEnumerator() | ForEach-Object { [pscustomobject]@{ IP = $_.Key; Macs = $_.Value } })
        ArpSubnets = $subnets
        ArpHosts = @($arp.GetEnumerator() | Sort-Object { try { [version]$_.Key } catch { [version]'0.0' } } | Select-Object -First 600 | ForEach-Object { [pscustomobject]@{ IP = $_.Key; Mac = $_.Value } })
        TopBroadcasters = @($talk.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { [pscustomobject]@{ Mac = $_.Key; Vendor = (Get-MacVendorLocal $_.Key); Frames = $_.Value } })
        UdpBroadcastPorts = @($udpPorts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
        SpanningTree = @($stp.Values | ForEach-Object { $_['SenderVendor'] = Get-MacVendorLocal $_['SenderMac']; $_['RootVendor'] = Get-MacVendorLocal $_['RootMac']; [pscustomobject]$_ })
        Lldp = @($lldp.Values | ForEach-Object { $_['ChassisVendor'] = Get-MacVendorLocal $(if ($_['ChassisMac']) { $_['ChassisMac'] } else { $_['SenderMac'] }); [pscustomobject]$_ })
        Cdp = @($cdp.Values | ForEach-Object { [pscustomobject]$_ })
        DhcpServers = @($dhcpSrv.Values | ForEach-Object { [pscustomobject]$_ })
        DhcpClients = @($dhcpCli.Values | Select-Object -First 400 | ForEach-Object { [pscustomobject]$_ })
        Ipv6RouterAdvertisers = @($ra.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Mac = $_.Key; Vendor = (Get-MacVendorLocal $_.Key); Frames = $_.Value } })
        VendorAnnouncements = @($ann.Values)
    }
}

# =====================================================================
# PHASE 5: collect background jobs
# =====================================================================
function ConvertFrom-NeighborCapture {
    # Parses LLDP and CDP frames out of a pktmon pcapng file.
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $frames = @()
    $pos = 0
    while ($pos + 12 -le $bytes.Length) {
        $type = [BitConverter]::ToUInt32($bytes, $pos)
        $len  = [BitConverter]::ToUInt32($bytes, $pos + 4)
        if ($len -lt 12 -or $pos + $len -gt $bytes.Length) { break }
        if ($type -eq 6) {
            $capLen = [BitConverter]::ToUInt32($bytes, $pos + 20)
            $data = New-Object byte[] $capLen
            [Array]::Copy($bytes, $pos + 28, $data, 0, $capLen)
            $frames += ,$data
        }
        $pos += $len
    }
    $txt = { param($b, $off) [Text.Encoding]::ASCII.GetString($b, $off, $b.Length - $off) -replace '[^\x20-\x7E]', '' }
    $mac = { param($b, $off) (($b[$off..($off + 5)] | ForEach-Object { '{0:X2}' -f $_ }) -join '-') }
    # IEEE 802.3 operational MAU types seen most often (RFC 4836).
    $mau = @{ 10 = '10BASE-T full'; 15 = '100BASE-TX half'; 16 = '100BASE-TX full'; 29 = '1000BASE-T half'; 30 = '1000BASE-T full'; 54 = '10GBASE-T' }
    $found = @()
    foreach ($f in $frames) {
        if ($f.Length -lt 16) { continue }
        $etype = ($f[12] * 256) + $f[13]
        if ($etype -eq 0x88CC) {
            $info = [ordered]@{ Protocol = 'LLDP'; SystemName = $null; Model = $null; Port = $null; PortId = $null; PortDescription = $null; LinkMode = $null; Vlan = $null; MgmtIP = $null; ChassisMac = $null; ChassisVendor = $null; SystemDescription = $null }
            $p = 14
            while ($p + 2 -le $f.Length) {
                $hdr = ($f[$p] * 256) + $f[$p + 1]
                $tt = $hdr -shr 9; $tl = $hdr -band 0x1FF
                $p += 2
                if ($tt -eq 0 -or $p + $tl -gt $f.Length) { break }
                $val = New-Object byte[] $tl
                [Array]::Copy($f, $p, $val, 0, $tl)
                switch ($tt) {
                    1 { if ($tl -ge 7 -and $val[0] -eq 4) { $info['ChassisMac'] = & $mac $val 1 } }
                    # Port ID subtype 3 is a MAC address; the others are text (interface alias/name, local).
                    2 { if ($tl -ge 7 -and $val[0] -eq 3) { $info['PortId'] = 'MAC ' + (& $mac $val 1) } else { $info['PortId'] = & $txt $val 1 } }
                    4 { $info['PortDescription'] = & $txt $val 0 }
                    5 { $info['SystemName'] = & $txt $val 0 }
                    6 { $info['SystemDescription'] = & $txt $val 0 }
                    8 { if ($tl -ge 6 -and $val[1] -eq 1) { $info['MgmtIP'] = '{0}.{1}.{2}.{3}' -f $val[2], $val[3], $val[4], $val[5] } }
                    127 {
                        if ($tl -ge 6 -and $val[0] -eq 0x00 -and $val[1] -eq 0x80 -and $val[2] -eq 0xC2 -and $val[3] -eq 1) { $info['Vlan'] = ($val[4] * 256) + $val[5] }
                        elseif ($tl -ge 9 -and $val[0] -eq 0x00 -and $val[1] -eq 0x12 -and $val[2] -eq 0x0F -and $val[3] -eq 1) {
                            $m = ($val[7] * 256) + $val[8]
                            $info['LinkMode'] = if ($mau.ContainsKey($m)) { $mau[$m] } else { "MAU type $m" }
                        }
                    }
                }
                $p += $tl
            }
            # Human-friendly port: a short description (often just the port number) beats a MAC-style port ID.
            $info['Port'] = if ($info['PortDescription'] -and $info['PortDescription'].Length -le 24) { $info['PortDescription'] } else { $info['PortId'] }
            if ($info['SystemDescription']) { $info['Model'] = ($info['SystemDescription'] -split ',')[0].Trim() }
            if ($info['ChassisMac']) { $info['ChassisVendor'] = Get-MacVendor $info['ChassisMac'] }
            $found += [pscustomobject]$info
        } elseif ($f[0] -eq 0x01 -and $f[1] -eq 0x00 -and $f[2] -eq 0x0C -and $f[3] -eq 0xCC) {
            # CDP over 802.3 + LLC/SNAP: header 14 + 8, then version/ttl/checksum (4)
            $info = [ordered]@{ Protocol = 'CDP'; SystemName = $null; Model = $null; Port = $null; PortId = $null; PortDescription = $null; LinkMode = $null; Vlan = $null; MgmtIP = $null; ChassisMac = $null; ChassisVendor = $null; SystemDescription = $null }
            $p = 26
            while ($p + 4 -le $f.Length) {
                $tt = ($f[$p] * 256) + $f[$p + 1]; $tl = ($f[$p + 2] * 256) + $f[$p + 3]
                if ($tl -lt 4 -or $p + $tl -gt $f.Length) { break }
                $s = [Text.Encoding]::ASCII.GetString($f, $p + 4, $tl - 4) -replace '[^\x20-\x7E]', ''
                switch ($tt) { 1 { $info['SystemName'] = $s } 3 { $info['PortId'] = $s } 5 { $info['SystemDescription'] = $s } 6 { $info['Model'] = $s } 10 { if ($tl -ge 6) { $info['Vlan'] = ($f[$p + 4] * 256) + $f[$p + 5] } } }
                $p += $tl
            }
            $info['Port'] = $info['PortId']
            $found += [pscustomobject]$info
        }
    }
    [ordered]@{
        FramesCaptured = $frames.Count
        Neighbors = @($found | Sort-Object Protocol, SystemName, Port -Unique)
        Note = if ($found.Count -eq 0) { 'No LLDP/CDP seen: switch is unmanaged, LLDP disabled, or interval > capture window' } else { $null }
    }
}

# ---------------------------------------------------------------------
# v1.7.0 helpers: SNMP (read only), Windows build from the file-sharing handshake, IPP, RTSP, STUN,
# NTP and the fast ping used for the voice sample.
# ---------------------------------------------------------------------
function ConvertTo-BerLength { param([int]$Len) if ($Len -lt 128) { return , ([byte[]]@($Len)) } elseif ($Len -lt 256) { return , ([byte[]]@(0x81, $Len)) } else { return , ([byte[]]@(0x82, ($Len -shr 8), ($Len -band 255))) } }
function Join-Bytes {
    # Concatenates byte arrays (and single values) into one byte[].
    $l = New-Object Collections.Generic.List[byte]
    foreach ($a in $args) { if ($null -ne $a) { $l.AddRange([byte[]]$a) } }
    return , $l.ToArray()
}
function ConvertTo-BerTlv { param([int]$Tag, [byte[]]$Value) if ($null -eq $Value) { $Value = [byte[]]@() }; return , (Join-Bytes ([byte[]]@($Tag)) (ConvertTo-BerLength $Value.Length) $Value) }
function ConvertTo-BerInt {
    param([int]$N)
    $b = New-Object Collections.Generic.List[byte]; $v = $N
    do { $b.Insert(0, [byte]($v -band 255)); $v = $v -shr 8 } while ($v -gt 0)
    if ($b[0] -band 0x80) { $b.Insert(0, 0) }
    return , (ConvertTo-BerTlv 2 $b.ToArray())
}
function ConvertTo-BerOid {
    param([string]$Oid)
    $p = @($Oid.Trim('.').Split('.') | ForEach-Object { [uint32]$_ })
    $b = New-Object Collections.Generic.List[byte]
    $b.Add([byte](($p[0] * 40) + $p[1]))
    for ($i = 2; $i -lt $p.Count; $i++) {
        $v = $p[$i]; $chunk = New-Object Collections.Generic.List[byte]
        $chunk.Add([byte]($v -band 0x7F)); $v = $v -shr 7
        while ($v -gt 0) { $chunk.Insert(0, [byte](($v -band 0x7F) -bor 0x80)); $v = $v -shr 7 }
        $b.AddRange($chunk)
    }
    return , (ConvertTo-BerTlv 6 $b.ToArray())
}
function New-SnmpRequest {
    # SNMP v2c message. $PduType: 0xA0 get, 0xA1 get-next, 0xA5 get-bulk (then the two numbers are
    # non-repeaters and max-repetitions).
    param([int]$PduType, [string]$Community, [int]$RequestId, [string[]]$Oids, [int]$NonRepeaters = 0, [int]$MaxRepetitions = 0)
    $vb = New-Object Collections.Generic.List[byte]
    foreach ($o in $Oids) { $vb.AddRange([byte[]](ConvertTo-BerTlv 0x30 (Join-Bytes (ConvertTo-BerOid $o) ([byte[]]@(5, 0))))) }
    $pdu = Join-Bytes (ConvertTo-BerInt $RequestId) (ConvertTo-BerInt $NonRepeaters) (ConvertTo-BerInt $MaxRepetitions) (ConvertTo-BerTlv 0x30 $vb.ToArray())
    $msg = Join-Bytes (ConvertTo-BerInt 1) (ConvertTo-BerTlv 4 ([Text.Encoding]::ASCII.GetBytes($Community))) (ConvertTo-BerTlv $PduType $pdu)
    return , (ConvertTo-BerTlv 0x30 $msg)
}
function Read-BerTlv {
    # Returns @(tag, value start, value length, offset after) or $null.
    param([byte[]]$B, [int]$Pos)
    if ($Pos -lt 0 -or $Pos + 2 -gt $B.Length) { return $null }
    $tag = [int]$B[$Pos]; $l = [int]$B[$Pos + 1]; $p = $Pos + 2
    if ($l -band 0x80) {
        $n = $l -band 0x7F
        if ($n -lt 1 -or $n -gt 3 -or $p + $n -gt $B.Length) { return $null }
        $l = 0; for ($i = 0; $i -lt $n; $i++) { $l = ($l * 256) + [int]$B[$p + $i] }
        $p += $n
    }
    if ($p + $l -gt $B.Length) { return $null }
    return @($tag, $p, $l, ($p + $l))
}
function ConvertFrom-BerValue {
    param([byte[]]$B, [int]$Tag, [int]$Start, [int]$Len)
    if ($Tag -eq 6) {
        if ($Len -lt 1) { return '' }
        $parts = New-Object Collections.Generic.List[string]
        $parts.Add([string][math]::Floor([int]$B[$Start] / 40)); $parts.Add([string]([int]$B[$Start] % 40))
        $v = [uint64]0
        for ($i = $Start + 1; $i -lt $Start + $Len; $i++) { $v = ($v * 128) + ([int]$B[$i] -band 0x7F); if (-not ([int]$B[$i] -band 0x80)) { $parts.Add([string]$v); $v = [uint64]0 } }
        return ($parts -join '.')
    }
    if ($Tag -eq 2) { $v = [int64]0; if ($Len -gt 0 -and ([int]$B[$Start] -band 0x80)) { $v = -1 }; for ($i = 0; $i -lt $Len; $i++) { $v = ($v * 256) + [int]$B[$Start + $i] }; return $v }
    if ($Tag -eq 0x41 -or $Tag -eq 0x42 -or $Tag -eq 0x43 -or $Tag -eq 0x46) { $v = [uint64]0; for ($i = 0; $i -lt $Len; $i++) { $v = ($v * 256) + [uint64]$B[$Start + $i] }; return $v }
    if ($Tag -eq 0x40 -and $Len -eq 4) { return ConvertTo-IpText $B $Start }
    if ($Tag -eq 4) {
        if ($Len -eq 0) { return '' }
        $printable = $true
        for ($i = $Start; $i -lt $Start + $Len; $i++) { $ch = [int]$B[$i]; if (($ch -lt 32 -and $ch -ne 9 -and $ch -ne 10 -and $ch -ne 13 -and $ch -ne 0) -or $ch -gt 126) { $printable = $false; break } }
        if ($printable) { return ((([Text.Encoding]::ASCII.GetString($B, $Start, $Len)) -replace '[^\x20-\x7E]', ' ') -replace '\s+', ' ').Trim() }
        return [BitConverter]::ToString($B, $Start, $Len)
    }
    if ($Tag -eq 0x80) { return 'noSuchObject' } if ($Tag -eq 0x81) { return 'noSuchInstance' } if ($Tag -eq 0x82) { return 'endOfMibView' }
    return $null
}
function ConvertFrom-SnmpResponse {
    # The variable bindings of an SNMP message as Oid, Type, Value.
    param([byte[]]$B)
    $out = @()
    if (-not $B) { return $out }
    $m = Read-BerTlv $B 0; if (-not $m -or $m[0] -ne 0x30) { return $out }
    $v = Read-BerTlv $B $m[1]; if (-not $v) { return $out }
    $c = Read-BerTlv $B $v[3]; if (-not $c) { return $out }
    $pdu = Read-BerTlv $B $c[3]; if (-not $pdu) { return $out }
    $rid = Read-BerTlv $B $pdu[1]; if (-not $rid) { return $out }
    $es = Read-BerTlv $B $rid[3]; if (-not $es) { return $out }
    $ei = Read-BerTlv $B $es[3]; if (-not $ei) { return $out }
    $vbl = Read-BerTlv $B $ei[3]; if (-not $vbl) { return $out }
    $p = $vbl[1]; $end = $vbl[3]
    while ($p -lt $end) {
        $vb = Read-BerTlv $B $p; if (-not $vb) { break }
        $o = Read-BerTlv $B $vb[1]; if (-not $o -or $o[0] -ne 6) { break }
        $val = Read-BerTlv $B $o[3]; if (-not $val) { break }
        $out += [pscustomobject]@{ Oid = (ConvertFrom-BerValue $B 6 $o[1] $o[2]); Type = $val[0]; Value = (ConvertFrom-BerValue $B $val[0] $val[1] $val[2]) }
        $p = $vb[3]
    }
    return $out
}
function Get-SnmpValues {
    # One GET for several OIDs. Returns @{ oid = value } for the ones that exist, or $null when nothing answered.
    param([string]$Ip, [string]$Community, [string[]]$Oids, [int]$TimeoutMs = 1500)
    $u = New-Object Net.Sockets.UdpClient
    try {
        $u.Client.ReceiveTimeout = $TimeoutMs; $u.Connect($Ip, 161)
        $pkt = New-SnmpRequest 0xA0 $Community (Get-Random -Minimum 1000 -Maximum 60000) $Oids
        for ($t = 0; $t -lt 2; $t++) {
            try {
                [void]$u.Send($pkt, $pkt.Length)
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $resp = $u.Receive([ref]$ep)
                $h = @{}
                foreach ($vb in @(ConvertFrom-SnmpResponse $resp)) { if ($vb.Type -lt 0x80 -and $null -ne $vb.Value) { $h["$($vb.Oid)"] = $vb.Value } }
                return $h
            } catch { }
        }
    } catch { } finally { try { $u.Close() } catch { } }
    return $null
}
function Invoke-SnmpWalk {
    # Reads one table column (everything under $Base) with get-bulk, falling back to get-next for old agents.
    # Returns rows of Index (the part of the OID after $Base) and Value.
    param([string]$Ip, [string]$Community, [string]$Base, [int]$MaxRows = 300, [int]$TimeoutMs = 1500)
    $rows = New-Object Collections.Generic.List[object]
    $root = $Base.Trim('.'); $cur = $root; $rid = Get-Random -Minimum 1000 -Maximum 50000; $bulk = $true
    $u = New-Object Net.Sockets.UdpClient
    try {
        $u.Client.ReceiveTimeout = $TimeoutMs; $u.Connect($Ip, 161)
        while ($rows.Count -lt $MaxRows) {
            $rid++
            $pkt = if ($bulk) { New-SnmpRequest 0xA5 $Community $rid @($cur) 0 20 } else { New-SnmpRequest 0xA1 $Community $rid @($cur) }
            $resp = $null
            for ($t = 0; $t -lt 2 -and -not $resp; $t++) { try { [void]$u.Send($pkt, $pkt.Length); $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); $resp = $u.Receive([ref]$ep) } catch { } }
            $vbs = @(ConvertFrom-SnmpResponse $resp)
            if (-not $vbs.Count) { if ($bulk -and $rows.Count -eq 0) { $bulk = $false; continue }; break }
            $done = $false
            foreach ($vb in $vbs) {
                $oid = "$($vb.Oid)"
                if ($vb.Type -ge 0x80 -or -not $oid.StartsWith("$root.") -or $oid -eq $cur) { $done = $true; break }
                $rows.Add([pscustomobject]@{ Index = $oid.Substring($root.Length + 1); Value = $vb.Value }); $cur = $oid
                if ($rows.Count -ge $MaxRows) { $done = $true; break }
            }
            if ($done) { break }
        }
    } catch { } finally { try { $u.Close() } catch { } }
    return $rows.ToArray()
}

# ---------------------------------------------------------------------
# Router and UPS tables over SNMP (read only, same community as the rest of the SNMP step).
# The parsers take the rows Invoke-SnmpWalk returns (Index = the OID part after the column).
# ---------------------------------------------------------------------
function ConvertFrom-SnmpMac {
    # A MAC from an SNMP octet string; $null unless it is six bytes that are not all zero.
    param($Value)
    $v = "$Value".Trim().ToUpper() -replace ':', '-'
    if ($v -notmatch '^([0-9A-F]{2}-){5}[0-9A-F]{2}$' -or $v -eq '00-00-00-00-00-00' -or $v -eq 'FF-FF-FF-FF-FF-FF') { return $null }
    return $v
}

function ConvertFrom-ArpRows {
    # ipNetToMediaPhysAddress (1.3.6.1.2.1.4.22.1.2, index ifIndex.a.b.c.d) or ipNetToPhysicalPhysAddress
    # (1.3.6.1.2.1.4.35.1.4, index ifIndex.1.4.a.b.c.d for IPv4) -> IP, Mac, IfIndex.
    param($Rows)
    $out = @()
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $p = @("$($r.Index)" -split '\.')
        $ip = $null
        if ($p.Count -eq 5) { $ip = ($p[1..4]) -join '.' }
        elseif ($p.Count -eq 7 -and $p[1] -eq '1' -and $p[2] -eq '4') { $ip = ($p[3..6]) -join '.' }
        $mac = ConvertFrom-SnmpMac $r.Value
        if ($ip -and $mac) { $out += [pscustomobject]@{ IP = $ip; Mac = $mac; IfIndex = [int]$p[0] } }
    }
    return $out
}

function ConvertFrom-AddrRows {
    # ipAdEntIfIndex (1.3.6.1.2.1.4.20.1.2) and ipAdEntNetMask (1.3.6.1.2.1.4.20.1.3), both indexed by the
    # address -> IP, Mask, Prefix, IfIndex, Class. Loopback addresses are left out.
    param($IfRows, $MaskRows)
    $masks = @{}; foreach ($m in @($MaskRows)) { if ($m) { $masks["$($m.Index)"] = "$($m.Value)" } }
    $out = @()
    foreach ($r in @($IfRows)) {
        if (-not $r -or -not (Test-IPv4 "$($r.Index)") -or "$($r.Index)" -like '127.*') { continue }
        $mk = $masks["$($r.Index)"]; $pre = $null
        if (Test-IPv4 $mk) { $pre = 0; $mi = ConvertTo-IpNumber $mk; for ($bit = 31; $bit -ge 0; $bit--) { if (($mi -shr $bit) -band 1) { $pre++ } else { break } } }
        $out += [pscustomobject]@{ IP = "$($r.Index)"; Mask = $mk; Prefix = $pre; IfIndex = [int]$r.Value; Class = (Get-IpClass "$($r.Index)") }
    }
    return $out
}

function ConvertFrom-RouteRows {
    # ipCidrRouteNextHop (1.3.6.1.2.1.4.24.4.1.4, index dest.mask.tos.nexthop) -> Destination, Prefix, NextHop.
    # Or, with -Legacy, ipRouteNextHop (1.3.6.1.2.1.4.21.1.7, index dest) plus ipRouteMask rows.
    param($Rows, $MaskRows = @(), [switch]$Legacy)
    $toPrefix = { param($mk) if (-not (Test-IPv4 $mk)) { return $null }; $n = 0; $mi = ConvertTo-IpNumber $mk; for ($bit = 31; $bit -ge 0; $bit--) { if (($mi -shr $bit) -band 1) { $n++ } else { break } }; $n }
    $out = @()
    if ($Legacy) {
        $masks = @{}; foreach ($m in @($MaskRows)) { if ($m) { $masks["$($m.Index)"] = "$($m.Value)" } }
        foreach ($r in @($Rows)) { if ($r -and (Test-IPv4 "$($r.Index)")) { $out += [pscustomobject]@{ Destination = "$($r.Index)"; Prefix = (& $toPrefix $masks["$($r.Index)"]); NextHop = "$($r.Value)" } } }
    } else {
        foreach ($r in @($Rows)) {
            $p = @("$($r.Index)" -split '\.')
            if ($p.Count -ne 13) { continue }
            $out += [pscustomobject]@{ Destination = ($p[0..3] -join '.'); Prefix = (& $toPrefix ($p[4..7] -join '.')); NextHop = "$($r.Value)" }
        }
    }
    return @($out | Sort-Object { ConvertTo-IpNumber $_.Destination }, Prefix)
}

function Get-UpsOidMap {
    # The UPS values read over SNMP: RFC 1628 UPS-MIB, or with -Apc the APC PowerNet-MIB for network
    # cards that do not answer UPS-MIB.
    param([switch]$Apc)
    if ($Apc) {
        return [ordered]@{
            Model = '1.3.6.1.4.1.318.1.1.1.1.1.1.0'; BatteryStatus = '1.3.6.1.4.1.318.1.1.1.2.1.1.0'; ChargePct = '1.3.6.1.4.1.318.1.1.1.2.2.1.0'
            RuntimeTicks = '1.3.6.1.4.1.318.1.1.1.2.2.3.0'; ReplaceBattery = '1.3.6.1.4.1.318.1.1.1.2.2.4.0'; OutputStatus = '1.3.6.1.4.1.318.1.1.1.4.1.1.0'; LoadPct = '1.3.6.1.4.1.318.1.1.1.4.2.3.0'
        }
    }
    return [ordered]@{
        Manufacturer = '1.3.6.1.2.1.33.1.1.1.0'; Model = '1.3.6.1.2.1.33.1.1.2.0'; BatteryStatus = '1.3.6.1.2.1.33.1.2.1.0'
        MinutesRemaining = '1.3.6.1.2.1.33.1.2.3.0'; ChargePct = '1.3.6.1.2.1.33.1.2.4.0'; OutputSource = '1.3.6.1.2.1.33.1.4.1.0'; LoadPct = '1.3.6.1.2.1.33.1.4.4.1.5.1'
    }
}

function ConvertTo-UpsStatus {
    # Values read with $UpsOids (-Standard) or $ApcUpsOids (-Apc) -> one plain UPS record, or $null.
    param($Standard, $Apc)
    $UpsOids = Get-UpsOidMap; $ApcUpsOids = Get-UpsOidMap -Apc
    $num = { param($v) if ($null -eq $v -or "$v" -eq '') { return $null }; try { return [double]$v } catch { return $null } }
    if ($Standard -and ($Standard[$UpsOids.Model] -or $Standard[$UpsOids.BatteryStatus])) {
        $bs = & $num $Standard[$UpsOids.BatteryStatus]; $src = & $num $Standard[$UpsOids.OutputSource]
        return [pscustomobject]@{
            Source = 'UPS-MIB'; Manufacturer = "$($Standard[$UpsOids.Manufacturer])".Trim(); Model = "$($Standard[$UpsOids.Model])".Trim()
            Battery = $(switch ($bs) { 2 { 'normal' } 3 { 'low' } 4 { 'depleted' } default { 'unknown' } })
            OnBattery = ($src -eq 5); ChargePct = (& $num $Standard[$UpsOids.ChargePct]); MinutesRemaining = (& $num $Standard[$UpsOids.MinutesRemaining])
            LoadPct = (& $num $Standard[$UpsOids.LoadPct]); ReplaceBattery = $null
        }
    }
    if ($Apc -and ($Apc[$ApcUpsOids.Model] -or $Apc[$ApcUpsOids.BatteryStatus])) {
        $bs = & $num $Apc[$ApcUpsOids.BatteryStatus]; $os = & $num $Apc[$ApcUpsOids.OutputStatus]; $rt = & $num $Apc[$ApcUpsOids.RuntimeTicks]
        return [pscustomobject]@{
            Source = 'APC'; Manufacturer = 'APC'; Model = "$($Apc[$ApcUpsOids.Model])".Trim()
            Battery = $(switch ($bs) { 2 { 'normal' } 3 { 'low' } 4 { 'in fault' } default { 'unknown' } })
            OnBattery = ($os -eq 3); ChargePct = (& $num $Apc[$ApcUpsOids.ChargePct]); MinutesRemaining = $(if ($null -ne $rt) { [math]::Round($rt / 6000, 0) } else { $null })
            LoadPct = (& $num $Apc[$ApcUpsOids.LoadPct]); ReplaceBattery = ((& $num $Apc[$ApcUpsOids.ReplaceBattery]) -eq 2)
        }
    }
    return $null
}

function Get-RouterTables {
    # A router's own addresses, ARP table and routes, read only. Returns $null when it is not a router.
    param([string]$Ip, [string]$Community, [bool]$Force = $false)
    $fw = Get-SnmpValues $Ip $Community @('1.3.6.1.2.1.4.1.0') 1500
    # No SNMP answer at all: stop here. Walking the tables would only time out (about 45 s on a home router).
    if ($null -eq $fw) { return $null }
    $isRouter = ($fw -and "$($fw['1.3.6.1.2.1.4.1.0'])" -eq '1')
    if (-not $isRouter -and -not $Force) { return $null }
    $addr = @(ConvertFrom-AddrRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.20.1.2' 100 1500) (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.20.1.3' 100 1500))
    $arp = @(ConvertFrom-ArpRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.22.1.2' 2000 1500))
    if (-not $arp.Count) { $arp = @(ConvertFrom-ArpRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.35.1.4' 2000 1500)) }
    $routes = @(ConvertFrom-RouteRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.24.4.1.4' 300 1500))
    if (-not $routes.Count) { $routes = @(ConvertFrom-RouteRows (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.21.1.7' 300 1500) (Invoke-SnmpWalk $Ip $Community '1.3.6.1.2.1.4.21.1.11' 300 1500) -Legacy) }
    if (-not $isRouter -and -not $addr.Count -and -not $arp.Count -and -not $routes.Count) { return $null }
    return [ordered]@{
        Forwarding = $isRouter
        Addresses = $addr
        WanAddresses = @($addr | Where-Object { $_.Class -eq 'Public' } | ForEach-Object { $_.IP })
        Arp = $arp
        Routes = $routes
        DefaultRoute = @($routes | Where-Object { $_.Destination -eq '0.0.0.0' -and $_.Prefix -eq 0 } | ForEach-Object { $_.NextHop } | Select-Object -First 1)
    }
}

function ConvertTo-SubnetSpec {
    # 'a.b.c' (taken as a /24) or 'a.b.c.d/nn' with nn from 22 to 30. Anything else returns $null.
    param([string]$Text)
    $t = "$Text".Trim()
    if ($t -match '^\d{1,3}\.\d{1,3}\.\d{1,3}$') { $t = "$t.0/24" }
    if ($t -notmatch '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$') { return $null }
    $ip = $matches[1]; $prefix = [int]$matches[3]
    if (@($ip.Split('.') | Where-Object { [int]$_ -gt 255 }).Count -or $prefix -lt 22 -or $prefix -gt 30) { return $null }
    $r = ConvertTo-NetRange $ip $prefix
    return [pscustomobject]@{ Cidr = '{0}/{1}' -f (ConvertFrom-IpNumber $r.NetInt), $prefix; NetInt = $r.NetInt; End = $r.End; First = $r.NetInt + 1; Last = $r.End - 1; Prefix = $prefix; Reason = $null }
}

function Get-SubnetHosts {
    param($Spec)
    $out = New-Object Collections.Generic.List[string]
    for ($h = [int64]$Spec.First; $h -le [int64]$Spec.Last; $h++) { $out.Add((ConvertFrom-IpNumber $h)) }
    return , $out.ToArray()
}

function Test-RangeOverlap { param($A, $B) return ([int64]$A.NetInt -le [int64]$B.End -and [int64]$B.NetInt -le [int64]$A.End) }

function Get-CandidateSubnets {
    # Private subnets this PC already knows about from data it collected (routes, DNS, DHCP and other
    # servers, printer ports, private traceroute hops, remote desktop lookups). Nothing is sent to build it.
    # $Exclude: ranges to leave out (this PC's own subnets). Hosted = a remote desktop target is in it,
    # so it may be the provider's network rather than the client's.
    param($R, $Exclude = @())
    $found = [ordered]@{}
    $note = {
        param($spec, $why, [bool]$hosted)
        if (-not $spec) { return }
        foreach ($x in @($Exclude)) { if ($x -and (Test-RangeOverlap $spec $x)) { return } }
        if (-not $found.Contains($spec.Cidr)) { $found[$spec.Cidr] = [pscustomobject]@{ Cidr = $spec.Cidr; NetInt = $spec.NetInt; End = $spec.End; Reasons = @(); Hosted = $false } }
        $e = $found[$spec.Cidr]
        if ($e.Reasons -notcontains $why) { $e.Reasons += $why }
        if ($hosted) { $e.Hosted = $true }
    }
    $addIp = {
        param([string]$ip, [string]$why, [bool]$hosted)
        if (-not (Test-IPv4 $ip) -or (Get-IpClass $ip) -ne 'Private') { return }
        $n = ConvertTo-IpNumber $ip
        # An address inside a subnet already found from a route belongs to that subnet.
        foreach ($k in @($found.Keys)) { $f = $found[$k]; if ($n -ge $f.NetInt -and $n -le $f.End) { & $note (ConvertTo-SubnetSpec $k) $why $hosted; return } }
        & $note (ConvertTo-SubnetSpec ((@($ip.Split('.'))[0..2]) -join '.')) $why $hosted
    }
    foreach ($rt in @(Get-Prop $R 'NetworkExtra', 'Routes')) {
        if (-not $rt -or "$(Get-Prop $rt 'Prefix')" -notmatch '^(\d{1,3}(\.\d{1,3}){3})/(\d+)$') { continue }
        $pre = [int]$matches[3]
        if ($pre -lt 22 -or $pre -gt 30 -or (Get-IpClass $matches[1]) -ne 'Private') { continue }
        $hop = "$(Get-Prop $rt 'NextHop')"
        & $note (ConvertTo-SubnetSpec "$($matches[1])/$pre") ("route " + $(if ($hop -and $hop -ne '0.0.0.0') { "via $hop" } else { 'on-link' })) $false
    }
    foreach ($d in @(Get-Prop $R 'NetworkExtra', 'DnsServers')) { if ($d) { & $addIp "$(Get-Prop $d 'Server')" "DNS server $(Get-Prop $d 'Server')" $false } }
    foreach ($a in @(Get-Prop $R 'Network', 'Adapters')) { if ($a -and (Get-Prop $a 'DhcpServer')) { & $addIp "$(Get-Prop $a 'DhcpServer')" "DHCP server $(Get-Prop $a 'DhcpServer')" $false } }
    foreach ($sv in @(Get-Prop $R 'Servers', 'Servers')) { if ($sv) { foreach ($ip in @(Get-Prop $sv 'IPs')) { & $addIp "$ip" "server $(Get-Prop $sv 'Name')" $false } } }
    foreach ($p in @(Get-Prop $R 'Peripherals', 'Printers')) { if ($p -and -not (Get-Prop $p 'IsVirtual') -and (Get-Prop $p 'HostAddress')) { & $addIp "$(Get-Prop $p 'HostAddress')" "printer $(Get-Prop $p 'Name')" $false } }
    foreach ($t in @(Get-Prop $R 'Traceroutes')) {
        if (-not $t) { continue }
        foreach ($hp in @(@(Get-Prop $t 'Hops') | Where-Object { $_ } | Sort-Object { [int](Get-Prop $_ 'Hop') })) {
            $c = "$(Get-Prop $hp 'Class')"
            if ($c -eq 'CGNAT' -or $c -eq 'Public') { break }
            if ([int](Get-Prop $hp 'Hop') -gt 1 -and $c -eq 'Private') { & $addIp "$(Get-Prop $hp 'IP')" "traceroute hop to $(Get-Prop $t 'Target')" $false }
        }
    }
    foreach ($rp in @(Get-Prop $R 'RdpPath')) { if ($rp) { foreach ($ip in @(Get-Prop $rp 'ResolvedIPs')) { & $addIp "$ip" "remote desktop host $(Get-Prop $rp 'Host')" $true } } }
    foreach ($c in @(Get-Prop $R 'Rdp', 'ActiveTcp')) { if ($c) { & $addIp "$(Get-Prop $c 'RemoteAddress')" 'live remote desktop session' $true } }
    foreach ($site in @(Get-Prop $R 'AdSites', 'Sites')) { foreach ($sn in @(Get-Prop $site 'Subnets')) { $sp = ConvertTo-SubnetSpec "$sn"; if ($sp -and (Get-IpClass (("$sn" -split '/')[0])) -eq 'Private') { & $note $sp "Active Directory site $(Get-Prop $site 'Name')" $false } } }
    foreach ($rt in @(Get-Prop $R 'GatewayRouter', 'Routes')) {
        $sp = if ($null -ne (Get-Prop $rt 'Prefix')) { ConvertTo-SubnetSpec ("{0}/{1}" -f (Get-Prop $rt 'Destination'), (Get-Prop $rt 'Prefix')) } else { $null }
        if ($sp -and (Get-IpClass "$(Get-Prop $rt 'Destination')") -eq 'Private') { & $note $sp "route on the gateway via $(Get-Prop $rt 'NextHop') (SNMP)" $false }
    }
    return @($found.Values | Sort-Object NetInt | ForEach-Object { [pscustomobject]@{ Cidr = $_.Cidr; Reasons = @($_.Reasons); Hosted = $_.Hosted } })
}

function Select-ScanSubnets {
    # The subnets to sweep: every valid entry from CONFIG, then the candidates picked at the prompt
    # ('1,3', '2-4', 'A' for all, empty for none). This PC's own subnets and anything past $Max are left out.
    param([string[]]$Explicit = @(), $Candidates = @(), [string]$Answer = '', $Exclude = @(), [int]$Max = 8)
    $sel = New-Object Collections.Generic.List[object]; $rej = New-Object Collections.Generic.List[string]
    $take = {
        param($spec, [string]$reason)
        if (@($sel | Where-Object { Test-RangeOverlap $_ $spec }).Count) { return }
        foreach ($x in @($Exclude)) { if ($x -and (Test-RangeOverlap $spec $x)) { $rej.Add("$($spec.Cidr): this PC's own subnet, covered by the local sweep"); return } }
        if ($sel.Count -ge $Max) { $rej.Add("$($spec.Cidr): over the limit of $Max subnets per run"); return }
        $spec.Reason = $reason
        $sel.Add($spec)
    }
    foreach ($e in @($Explicit | Where-Object { "$_".Trim() })) {
        $s = ConvertTo-SubnetSpec $e
        if ($s) { & $take $s 'listed in CONFIG' } else { $rej.Add("${e}: not a.b.c or a.b.c.d/22 to /30") }
    }
    $cands = @($Candidates | Where-Object { $_ })
    $idx = @()
    if ("$Answer" -match '^\s*(a|all)\s*$') { if ($cands.Count) { $idx = 0..($cands.Count - 1) } }
    else {
        foreach ($part in @("$Answer" -split '[,;\s]+' | Where-Object { $_ })) {
            if ($part -match '^(\d+)-(\d+)$') { $idx += ([int]$matches[1] - 1)..([int]$matches[2] - 1) }
            elseif ($part -match '^\d+$') { $idx += [int]$part - 1 }
        }
    }
    foreach ($i in @($idx | Sort-Object -Unique)) {
        if ($i -lt 0 -or $i -ge $cands.Count) { continue }
        $s = ConvertTo-SubnetSpec $cands[$i].Cidr
        if ($s) { & $take $s ('chosen at the prompt (' + (@($cands[$i].Reasons) | Select-Object -First 1) + ')') }
    }
    return [pscustomobject]@{ Selected = $sel.ToArray(); Rejected = $rej.ToArray() }
}

function Invoke-RemoteSweep {
    # Sweeps subnets on the far side of a router: ping every address, try a few TCP ports on the ones
    # that ignore ping, then a name lookup and the sweep ports on every device that answered. MAC
    # addresses do not cross a router; they come later from NetBIOS or the router's own ARP table.
    param($Specs, [int[]]$Ports = @(), [int[]]$PresencePorts = @(), [int]$TimeoutMs = 1000)
    $devices = @(); $summary = @()
    foreach ($sp in @($Specs)) {
        $t0 = Get-Date
        $hosts = Get-SubnetHosts $sp
        $alive = @{}
        # Smaller batches with a pause than the local sweep: this traffic crosses a router or a tunnel.
        for ($b0 = 0; $b0 -lt $hosts.Count; $b0 += 128) {
            $chunk = @($hosts[$b0..([math]::Min($b0 + 127, $hosts.Count - 1))])
            $pingers = @(); $tasks = @()
            foreach ($t in $chunk) { $p = New-Object Net.NetworkInformation.Ping; $pingers += $p; $tasks += $p.SendPingAsync($t, $TimeoutMs) }
            try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, $TimeoutMs + 4000) | Out-Null } catch { }
            for ($j = 0; $j -lt $tasks.Count; $j++) { if ($tasks[$j].IsCompleted -and -not $tasks[$j].IsFaulted -and $tasks[$j].Result.Status -eq 'Success') { $alive[$chunk[$j]] = $true } }
            foreach ($p in $pingers) { $p.Dispose() }
            Start-Sleep -Milliseconds 150
        }
        $tcpOnly = @{}
        $silent = @($hosts | Where-Object { -not $alive.ContainsKey($_) })
        if (@($PresencePorts).Count -and $silent.Count) { $pm = Test-TcpPortsBulk $silent $PresencePorts $TimeoutMs; foreach ($k in $pm.Keys) { $tcpOnly[$k] = @($pm[$k]) } }
        $live = @(@($alive.Keys) + @($tcpOnly.Keys) | Sort-Object -Unique | Sort-Object { [version]$_ })
        $minW = 0; $minIo = 0
        [Threading.ThreadPool]::GetMinThreads([ref]$minW, [ref]$minIo)
        [void][Threading.ThreadPool]::SetMinThreads([math]::Max($minW, 128), $minIo)
        $nameTasks = @{}
        foreach ($ip in $live) { try { $nameTasks[$ip] = [Net.Dns]::GetHostEntryAsync([string]$ip) } catch { } }
        $open = if (@($Ports).Count -and $live.Count) { Test-TcpPortsBulk $live $Ports $TimeoutMs } else { @{} }
        if ($nameTasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($nameTasks.Values), 8000) } catch { } }
        [void][Threading.ThreadPool]::SetMinThreads($minW, $minIo)
        foreach ($ip in $live) {
            $nt = $nameTasks[$ip]
            $name = if ($nt -and "$($nt.Status)" -eq 'RanToCompletion' -and $nt.Result.HostName -and $nt.Result.HostName -ne $ip) { $nt.Result.HostName } else { $null }
            $ports = @(@($open[$ip]) + @($tcpOnly[$ip]) | Where-Object { $null -ne $_ } | Sort-Object -Unique)
            $devices += [pscustomobject]@{ IP = $ip; Mac = $null; Vendor = $null; RespondedToPing = $alive.ContainsKey($ip); Name = $name; OpenPorts = $ports; Role = (Get-DeviceRole $ports); Subnet = $sp.Cidr; Remote = $true }
        }
        $summary += [pscustomobject]@{ Subnet = $sp.Cidr; Reason = $sp.Reason; AddressesSwept = $hosts.Count; PingResponders = $alive.Count; TcpOnly = $tcpOnly.Count; Devices = $live.Count; Seconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1) }
    }
    return [ordered]@{
        Subnets = $summary
        PortsChecked = @($Ports); PresencePorts = @($PresencePorts)
        RoleSummary = @($devices | Where-Object { $_.Role } | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        Devices = $devices
    }
}

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
    # Severity, Category, Message rows for what Get-AdSiteCheck found.
    param($C)
    if (-not $C) { return @() }
    $out = @()
    $f = { param($sev, $msg) [pscustomobject]@{ Severity = $sev; Category = 'Active Directory'; Message = $msg } }
    if ($C.Ip -and -not $C.AdSubnet) {
        $out += & $f 'Medium' "This PC's address $($C.Ip) is in no Active Directory subnet, so it logs on to whichever domain controller answers first, possibly across the WAN: add its subnet to the right site in AD Sites and Services"
    } elseif ($C.CurrentSite -and $C.SiteBySubnet -and $C.CurrentSite -ne $C.SiteBySubnet) {
        $out += & $f 'Low' "This PC reports AD site $($C.CurrentSite), but its subnet $($C.AdSubnet) belongs to site $($C.SiteBySubnet): overlapping or stale subnets in AD Sites and Services"
    }
    $mySite = if ($C.SiteBySubnet) { $C.SiteBySubnet } else { $C.CurrentSite }
    if ($C.LogonServer -and $C.LogonServerSite -and $mySite -and $C.LogonServerSite -ne $mySite -and $C.SiteHasDc) {
        $out += & $f 'Medium' "This user logged on to $($C.LogonServer) in site $($C.LogonServerSite), not to a domain controller in this PC's own site $mySite"
    }
    foreach ($s in @($C.SitesWithoutDc)) { $out += & $f 'Low' "AD site $s has subnets but no domain controller, so its PCs log on across the WAN (fine when that is the design, worth knowing when the link goes down)" }
    return $out
}

function Get-StunMappings {
    # Asks STUN servers, from one socket, which public address and port they see. The same port from
    # two servers means the NAT keeps one mapping per socket (good for calls); different ports means it does not.
    param($Servers, [int]$TimeoutMs = 1500)
    $out = @()
    $u = New-Object Net.Sockets.UdpClient
    try {
        $u.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)))
        $u.Client.ReceiveTimeout = $TimeoutMs
        try { [void]$u.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null) } catch { }
        foreach ($s in @($Servers)) {
            $row = [ordered]@{ Server = "$($s[0]):$($s[1])"; Answered = $false; MappedIp = $null; MappedPort = $null; LocalPort = $u.Client.LocalEndPoint.Port; Ms = $null }
            try {
                $addr = @([Net.Dns]::GetHostAddresses([string]$s[0]) | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0]
                $req = New-Object byte[] 20; $req[1] = 1; $req[4] = 0x21; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42
                $tx = [Guid]::NewGuid().ToByteArray(); [Array]::Copy($tx, 0, $req, 8, 12)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                [void]$u.Send($req, 20, (New-Object Net.IPEndPoint($addr, [int]$s[1])))
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $r = $u.Receive([ref]$ep)
                $row['Ms'] = [math]::Round($sw.Elapsed.TotalMilliseconds, 1); $row['Answered'] = $true
                $p = 20
                while ($p + 4 -le $r.Length) {
                    $t = ([int]$r[$p] * 256) + [int]$r[$p + 1]; $l = ([int]$r[$p + 2] * 256) + [int]$r[$p + 3]
                    if ($t -eq 0x0020 -and $l -ge 8) { $row['MappedPort'] = ((([int]$r[$p + 6] * 256) + [int]$r[$p + 7]) -bxor 0x2112); $row['MappedIp'] = '{0}.{1}.{2}.{3}' -f ([int]$r[$p + 8] -bxor 0x21), ([int]$r[$p + 9] -bxor 0x12), ([int]$r[$p + 10] -bxor 0xA4), ([int]$r[$p + 11] -bxor 0x42) }
                    elseif ($t -eq 0x0001 -and $l -ge 8 -and -not $row['MappedIp']) { $row['MappedPort'] = ([int]$r[$p + 6] * 256) + [int]$r[$p + 7]; $row['MappedIp'] = ConvertTo-IpText $r ($p + 8) }
                    $p += 4 + $l + ((4 - ($l % 4)) % 4)
                }
            } catch { }
            $out += [pscustomobject]$row
        }
    } catch { } finally { try { $u.Close() } catch { } }
    return $out
}

function Measure-VoicePath {
    # A call sends a packet every 20 ms. This pings at that pace and reports what a call would feel:
    # loss, bursts of loss, jitter and an estimated call-quality score (MOS, 1 to 4.4).
    param([string]$Target, [int]$Seconds = 20, [int]$PerSecond = 50)
    $n = $Seconds * $PerSecond; $interval = 1000.0 / $PerSecond
    $pool = @(); for ($i = 0; $i -lt 40; $i++) { $pool += New-Object Net.NetworkInformation.Ping }
    $tasks = New-Object object[] $n
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $n; $i++) {
        while ($sw.Elapsed.TotalMilliseconds -lt $i * $interval) { [Threading.Thread]::SpinWait(300) }
        try { $tasks[$i] = $pool[$i % 40].SendPingAsync($Target, 400) } catch { $tasks[$i] = $null }
    }
    Start-Sleep -Milliseconds 600
    $rtt = New-Object 'Collections.Generic.List[double]'; $lost = 0; $burst = 0; $maxBurst = 0; $jsum = 0.0; $jn = 0; $prev = $null
    foreach ($t in $tasks) {
        $ok = $false
        try { if ($t -and "$($t.Status)" -eq 'RanToCompletion' -and "$($t.Result.Status)" -eq 'Success') { $ok = $true } } catch { }
        if ($ok) { $v = [double]$t.Result.RoundtripTime; $rtt.Add($v); if ($null -ne $prev) { $jsum += [math]::Abs($v - $prev); $jn++ }; $prev = $v; $burst = 0 }
        else { $lost++; $burst++; if ($burst -gt $maxBurst) { $maxBurst = $burst } }
    }
    foreach ($p in $pool) { try { $p.Dispose() } catch { } }
    $r = [ordered]@{ Target = $Target; Sent = $n; Received = $rtt.Count; LossPct = [math]::Round(100.0 * $lost / $n, 2); LongestLossBurst = $maxBurst; AvgMs = $null; MaxMs = $null; P99Ms = $null; JitterMs = $null; Mos = $null; Rating = $null; PacketsPerSecond = $PerSecond; Seconds = $Seconds }
    if ($rtt.Count) {
        $sorted = @($rtt | Sort-Object)
        $avg = ($rtt | Measure-Object -Average).Average; $jit = if ($jn) { $jsum / $jn } else { 0 }
        $r['AvgMs'] = [math]::Round($avg, 1); $r['MaxMs'] = $sorted[-1]; $r['P99Ms'] = $sorted[[int][math]::Floor(($sorted.Count - 1) * 0.99)]; $r['JitterMs'] = [math]::Round($jit, 2)
        # Simplified E-model: one-way delay is half the round trip, jitter counts double, each 1% loss costs 2.5.
        $eff = ($avg / 2) + (2 * $jit) + 10
        $rf = if ($eff -lt 160) { 93.2 - ($eff / 40) } else { 93.2 - (($eff - 120) / 10) }
        $rf = [math]::Max(0.0, [double]($rf - (2.5 * $r['LossPct'])))
        $mos = 1 + (0.035 * $rf) + (0.000007 * $rf * ($rf - 60) * (100 - $rf))
        $r['Mos'] = [math]::Round([math]::Min(4.4, [math]::Max(1.0, [double]$mos)), 2)
        $r['Rating'] = if ($r['Mos'] -ge 4.0) { 'good' } elseif ($r['Mos'] -ge 3.6) { 'acceptable' } else { 'poor' }
    }
    return $r
}

function Get-PathMtu {
    param([string]$Target)
    $probe = {
        param($size)
        if ($script:FullLanguage) {
            # Don't-fragment ping of $size bytes; PacketTooBig is the "needs to be fragmented" answer in any language.
            try {
                $r = (New-Object Net.NetworkInformation.Ping).Send($Target, 1500, (New-Object byte[] $size), (New-Object Net.NetworkInformation.PingOptions(64, $true)))
                if ("$($r.Status)" -eq 'Success') { return 'ok' }
                if ("$($r.Status)" -eq 'PacketTooBig') { return 'frag' }
            } catch { }
            return 'none'
        }
        $o = Invoke-Native 'ping.exe' "-f -l $size -n 1 -w 1500 $Target" 6
        if ($o -match 'needs to be fragmented|Packet needs') { return 'frag' }
        if ($o -match '[=<]\s*\d+\s*(ms|\u043c\u0441)') { return 'ok' }
        return 'none'
    }
    $first = & $probe 1472
    if ($first -eq 'ok') { return [ordered]@{ Target = $Target; MtuBytes = 1500; Note = 'Full 1500' } }
    if ((& $probe 576) -ne 'ok') { return [ordered]@{ Target = $Target; MtuBytes = $null; Note = 'ICMP blocked or no reply' } }
    $lo = 548; $hi = 1472
    while ($hi - $lo -gt 4) {
        $mid = [int](($lo + $hi) / 2)
        if ((& $probe $mid) -eq 'ok') { $lo = $mid } else { $hi = $mid }
    }
    return [ordered]@{ Target = $Target; MtuBytes = $lo + 28; Note = 'Reduced (tunnel/PPPoE overhead likely)' }
}

function ConvertFrom-Tracert {
    param([string]$Text)
    $hops = @()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*(\d+)\s+(\*|<?\s*\d+\s*(?:ms|\u043c\u0441))\s+(\*|<?\s*\d+\s*(?:ms|\u043c\u0441))\s+(\*|<?\s*\d+\s*(?:ms|\u043c\u0441))\s+(.+?)\s*$') {
            $hopNum = [int]$matches[1]
            $rtts = @($matches[2], $matches[3], $matches[4]) | Where-Object { $_ -ne '*' } | ForEach-Object { [int](($_ -replace '[^\d]', '')) }
            $addr = $matches[5].Trim()
            $ip = if ($addr -match '(\d{1,3}(\.\d{1,3}){3})') { $matches[1] } else { $null }
            $hops += [pscustomobject]@{
                Hop = $hopNum; IP = $ip; Class = if ($ip) { Get-IpClass $ip } else { 'Timeout' }
                AvgMs = if ($rtts.Count) { [math]::Round((($rtts | Measure-Object -Average).Average), 1) } else { $null }
                Ptr = $null
            }
        }
    }
    return $hops
}

function Get-TraceAnalysis {
    param($Hops)
    $firstPublic = $Hops | Where-Object { $_.Class -eq 'Public' } | Select-Object -First 1
    $firstCgnat = $Hops | Where-Object { $_.Class -eq 'CGNAT' } | Select-Object -First 1
    $afterGw = @($Hops | Where-Object { $_.Hop -gt 1 -and (-not $firstPublic -or $_.Hop -lt $firstPublic.Hop) })
    $privateAfterGw = @($afterGw | Where-Object { $_.Class -eq 'Private' })
    # Private hops after a CGNAT hop are inside the carrier's network (Starlink, cellular, some cable ISPs).
    $carrierHops = @($privateAfterGw | Where-Object { $firstCgnat -and $_.Hop -gt $firstCgnat.Hop })
    $customerHops = @($privateAfterGw | Where-Object { -not ($firstCgnat -and $_.Hop -gt $firstCgnat.Hop) })
    # A customer-side private hop with real latency looks like a tunnel/MPLS (or ISP-internal); low latency = double NAT.
    $tunnelHops = @($customerHops | Where-Object { $_.AvgMs -ge 6 })
    [ordered]@{
        HopCount           = $Hops.Count
        FirstPublicHop     = if ($firstPublic) { $firstPublic.Hop } else { $null }
        FirstPublicIP      = if ($firstPublic) { $firstPublic.IP } else { $null }
        FirstPublicMs      = if ($firstPublic) { $firstPublic.AvgMs } else { $null }
        PrivateHopsAfterGw = @($customerHops | ForEach-Object { '{0}@{1}ms' -f $_.IP, $_.AvgMs })
        CarrierPrivateHops = @($carrierHops | ForEach-Object { '{0}@{1}ms' -f $_.IP, $_.AvgMs })
        CgnatHops          = @($Hops | Where-Object { $_.Class -eq 'CGNAT' }).Count
        TunnelIndicator    = ($tunnelHops.Count -gt 0)
        DoubleNatLikely    = ($customerHops.Count -gt 0 -and $tunnelHops.Count -eq 0)
        ReachedTarget      = $false
    }
}

function ConvertFrom-PingOutput {
    param([string]$Text, [string]$Target, [int]$Sent)
    $times = @()
    # 'time=12ms' in English, 'Zeit=12ms', 'temps=12 ms', 'tiempo<1 ms', Cyrillic 'ms'... the number after = or <, followed by ms.
    foreach ($m in [regex]::Matches($Text, '[=<]\s*(\d+)\s*(?:ms|\u043c\u0441)\b')) { $times += [int]$m.Groups[1].Value }
    $recv = $times.Count
    $sorted = @($times | Sort-Object)
    $jit = $null
    if ($times.Count -gt 1) { $d = 0; for ($k = 1; $k -lt $times.Count; $k++) { $d += [math]::Abs($times[$k] - $times[$k - 1]) }; $jit = [math]::Round($d / ($times.Count - 1), 1) }
    [ordered]@{
        Target  = $Target
        Sent    = $Sent
        Received = $recv
        LossPct = if ($Sent) { [math]::Round(100 * ($Sent - $recv) / $Sent, 1) } else { $null }
        MinMs   = if ($recv) { $sorted[0] } else { $null }
        AvgMs   = if ($recv) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
        P95Ms   = if ($recv) { $sorted[[math]::Min($sorted.Count - 1, [int][math]::Ceiling(0.95 * $sorted.Count) - 1)] } else { $null }
        MaxMs   = if ($recv) { $sorted[-1] } else { $null }
        JitterMs = $jit
    }
}

function ConvertTo-TraceResult {
    # Saves the raw tracert text next to the JSON and returns the parsed hops plus analysis.
    param([string]$Target, [string]$Text)
    Set-Content -LiteralPath (Join-Path $OutDir ('traceroute_{0}.txt' -f ($Target -replace '[^A-Za-z0-9\.-]', '_'))) -Value $Text
    $hops = @(ConvertFrom-Tracert $Text)
    $pub = 0
    foreach ($h in $hops) {
        if ($h.Class -eq 'Public' -and $pub -lt 2) { $h.Ptr = Resolve-Ptr $h.IP; $pub++ }
    }
    $an = Get-TraceAnalysis $hops
    $destIp = if ($Text -match '\[(\d{1,3}(\.\d{1,3}){3})\]') { $matches[1] } elseif (Test-IPv4 $Target) { $Target } else { $null }
    $lastHop = $hops | Where-Object { $_.IP } | Select-Object -Last 1
    $an['ReachedTarget'] = [bool]($destIp -and $lastHop -and $lastHop.IP -eq $destIp)
    $an['FirstPublicPtr'] = ($hops | Where-Object { $_.Ptr } | Select-Object -First 1).Ptr
    return [pscustomobject]@{ Target = $Target; Analysis = $an; Hops = $hops }
}

function Get-ThroughputStats {
    # Mbps over the run minus the TCP ramp-up (first 2 s or 20%), plus the best 1-second window.
    param($Samples, [double]$T0)
    if ($Samples.Count -lt 2) { return @(0, 0) }
    $dur = $Samples[$Samples.Count - 1].T - $T0
    $skip = $T0 + [math]::Min(2.0, $dur * 0.2)
    $a = $Samples | Where-Object { $_.T -ge $skip } | Select-Object -First 1
    $b = $Samples[$Samples.Count - 1]
    if (-not $a -or $b.T - $a.T -lt 0.5) { $a = $Samples[0] }
    $mbps = if ($b.T - $a.T -gt 0) { ($b.B - $a.B) * 8 / ($b.T - $a.T) / 1e6 } else { 0 }
    $peak = 0
    for ($x = 0; $x -lt $Samples.Count; $x++) {
        for ($y = $x + 1; $y -lt $Samples.Count; $y++) {
            if ($Samples[$y].T - $Samples[$x].T -ge 1.0) { $v = ($Samples[$y].B - $Samples[$x].B) * 8 / ($Samples[$y].T - $Samples[$x].T) / 1e6; if ($v -gt $peak) { $peak = $v }; break }
        }
    }
    return @([math]::Round($mbps, 1), [math]::Round($peak, 1))
}

function Invoke-HttpDownloadTest {
    # Multi-stream HTTP download for $BandwidthSeconds; $UrlFactory returns the URL for each new request.
    param([scriptblock]$UrlFactory, [int64]$CapBytes)
    $out = @{ Ok = $false; Mbps = $null; PeakMbps = $null; MB = 0; LoadedLatencyMs = $null; HttpStatus = @(); Errors = @(); Had429 = $false; RetryAfterSec = $null }
    $cts = New-Object Threading.CancellationTokenSource
    $streams = @{}
    $total = [int64]0
    $samples = New-Object Collections.Generic.List[object]
    $loaded = @()
    $probeTask = $null; $probeStart = 0; $lastProbe = 0
    $status = @{}; $errors = @(); $faults = 0
    $start = $sw.Elapsed.TotalSeconds
    $deadline = $start + $BandwidthSeconds
    $startStream = {
        param($slot)
        $req = $client.GetAsync((& $UrlFactory), [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token)
        $streams[$slot] = @{ Phase = 'head'; Req = $req; Stream = $null; Read = $null; Buf = (New-Object byte[] 262144) }
    }
    for ($s = 0; $s -lt $BandwidthStreams; $s++) { & $startStream $s }
    while ($sw.Elapsed.TotalSeconds -lt $deadline -and $total -lt $CapBytes) {
        $tasks = @()
        foreach ($k in @($streams.Keys)) {
            $st = $streams[$k]
            if ($st.Phase -eq 'head') { $tasks += $st.Req } elseif ($st.Phase -eq 'body' -and $st.Read) { $tasks += $st.Read }
        }
        if ($tasks.Count -eq 0) { break }   # every stream gave up (errors/non-200)
        [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$tasks, 100)
        foreach ($k in @($streams.Keys)) {
            $st = $streams[$k]
            if ($st.Phase -eq 'head' -and $st.Req.IsCompleted) {
                if ($st.Req.IsFaulted -or $st.Req.IsCanceled) {
                    $faults++
                    if ($st.Req.Exception) { $m = $st.Req.Exception.GetBaseException().Message; if ($errors -notcontains $m -and $errors.Count -lt 3) { $errors += $m } }
                    if ($faults -lt 20) { & $startStream $k } else { $st.Phase = 'dead' }
                    continue
                }
                $resp = $st.Req.Result
                $code = [int]$resp.StatusCode
                $status["$code"] = 1 + [int]$status["$code"]
                if (-not $resp.IsSuccessStatusCode) {
                    if ($code -eq 429) {
                        $out.Had429 = $true
                        try { $dlt = $resp.Headers.RetryAfter.Delta; if ($dlt) { $out.RetryAfterSec = [int]([TimeSpan]$dlt).TotalSeconds } } catch { }
                    }
                    # Stop this stream instead of hammering the endpoint.
                    try { $resp.Dispose() } catch { }
                    $st.Phase = 'dead'
                    continue
                }
                $st.Stream = $resp.Content.ReadAsStreamAsync().Result
                $st.Phase = 'body'
                $st.Read = $st.Stream.ReadAsync($st.Buf, 0, $st.Buf.Length, $cts.Token)
            } elseif ($st.Phase -eq 'body' -and $st.Read.IsCompleted) {
                $n = 0
                if (-not $st.Read.IsFaulted -and -not $st.Read.IsCanceled) { $n = $st.Read.Result }
                if ($n -gt 0) {
                    $total += $n
                    $st.Read = $st.Stream.ReadAsync($st.Buf, 0, $st.Buf.Length, $cts.Token)
                } else {
                    try { $st.Stream.Dispose(); $st.Req.Result.Dispose() } catch { }
                    & $startStream $k
                }
            }
        }
        $now = $sw.Elapsed.TotalSeconds
        if ($samples.Count -eq 0 -or $now - $samples[$samples.Count - 1].T -ge 0.25) { $samples.Add([pscustomobject]@{ T = $now; B = $total }) }
        if ($probeTask -and $probeTask.IsCompleted) {
            $lv = & $finishProbe $probeTask $probeStart
            if ($null -ne $lv) { $loaded += $lv }
            $probeTask = $null
        }
        if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $start -gt 0.3) {
            $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now
            $probeTask = & $startProbe
        }
    }
    $cts.Cancel()
    $samples.Add([pscustomobject]@{ T = $sw.Elapsed.TotalSeconds; B = $total })
    foreach ($k in @($streams.Keys)) { try { if ($streams[$k].Stream) { $streams[$k].Stream.Dispose() } } catch { } }
    if ($probeTask) { try { [void]$probeTask.Wait(2500) } catch { } }
    $stats = Get-ThroughputStats $samples $start
    $out.MB = [math]::Round($total / 1MB, 1)
    $out.HttpStatus = @($status.Keys | Sort-Object | ForEach-Object { '{0} x{1}' -f $_, $status[$_] })
    $out.Errors = $errors
    $out.LoadedLatencyMs = Get-MedianValue $loaded
    if ($total -ge 1MB) { $out.Ok = $true; $out.Mbps = $stats[0]; $out.PeakMbps = $stats[1] }
    return $out
}

function Invoke-CloudflareUpload {
    param([int64]$CapBytes)
    $out = @{ Ok = $false; Mbps = $null; MB = 0; LoadedLatencyMs = $null; HttpStatus = @(); Errors = @(); Had429 = $false; RetryAfterSec = $null }
    $rand = New-Object Random
    $payload = New-Object byte[] (16MB)
    $rand.NextBytes($payload)
    $size = 1MB
    $inflight = @{}
    $ulBytes = [int64]0
    $loaded = @(); $probeTask = $null; $probeStart = 0; $lastProbe = 0
    $status = @{}; $errors = @()
    $ulStart = $sw.Elapsed.TotalSeconds
    $ulDeadline = $ulStart + $BandwidthSeconds
    $lastDone = $ulStart
    $sent = [int64]0
    for ($s = 0; $s -lt $BandwidthStreams; $s++) {
        $inflight[$s] = @{ Task = $client.PostAsync('https://speed.cloudflare.com/__up', [Net.Http.ByteArrayContent]::new($payload, 0, $size)); Size = $size; Started = $sw.Elapsed.TotalSeconds }
        $sent += $size
    }
    while ($true) {
        $now = $sw.Elapsed.TotalSeconds
        $active = @($inflight.Keys | Where-Object { $inflight[$_] })
        if ($active.Count -eq 0) { break }
        if ($now -gt $ulDeadline + 8) { break }
        $tasks = @($active | ForEach-Object { $inflight[$_].Task })
        [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$tasks, 100)
        foreach ($k in $active) {
            $it = $inflight[$k]
            if (-not $it.Task.IsCompleted) { continue }
            $took = $sw.Elapsed.TotalSeconds - $it.Started
            $okPost = $false
            if (-not $it.Task.IsFaulted -and -not $it.Task.IsCanceled) {
                $resp = $it.Task.Result
                $code = [int]$resp.StatusCode
                $status["$code"] = 1 + [int]$status["$code"]
                if ($resp.IsSuccessStatusCode) {
                    $okPost = $true
                    $ulBytes += $it.Size; $lastDone = $sw.Elapsed.TotalSeconds
                    if ($took -lt 0.5 -and $size -lt 16MB) { $size = [int]($size * 2) }
                } elseif ($code -eq 429) {
                    $out.Had429 = $true
                    try { $dlt = $resp.Headers.RetryAfter.Delta; if ($dlt) { $out.RetryAfterSec = [int]([TimeSpan]$dlt).TotalSeconds } } catch { }
                }
                try { $resp.Dispose() } catch { }
            } elseif ($it.Task.Exception) {
                $m = $it.Task.Exception.GetBaseException().Message
                if ($errors -notcontains $m -and $errors.Count -lt 3) { $errors += $m }
            }
            $inflight[$k] = $null
            if ($okPost -and $sw.Elapsed.TotalSeconds -lt $ulDeadline -and $sent -lt $CapBytes) {
                $inflight[$k] = @{ Task = $client.PostAsync('https://speed.cloudflare.com/__up', [Net.Http.ByteArrayContent]::new($payload, 0, $size)); Size = $size; Started = $sw.Elapsed.TotalSeconds }
                $sent += $size
            }
        }
        $now = $sw.Elapsed.TotalSeconds
        if ($probeTask -and $probeTask.IsCompleted) {
            $lv = & $finishProbe $probeTask $probeStart
            if ($null -ne $lv) { $loaded += $lv }
            $probeTask = $null
        }
        if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $ulStart -gt 0.3 -and $now -lt $ulDeadline) {
            $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now
            $probeTask = & $startProbe
        }
    }
    if ($probeTask) { try { [void]$probeTask.Wait(2500) } catch { } }
    $ulDur = $lastDone - $ulStart
    $out.MB = [math]::Round($ulBytes / 1MB, 1)
    $out.HttpStatus = @($status.Keys | Sort-Object | ForEach-Object { '{0} x{1}' -f $_, $status[$_] })
    $out.Errors = $errors
    $out.LoadedLatencyMs = Get-MedianValue $loaded
    if ($ulBytes -ge 1MB -and $ulDur -gt 0) { $out.Ok = $true; $out.Mbps = [math]::Round($ulBytes * 8 / $ulDur / 1e6, 1) }
    return $out
}

function Get-MlabServers {
    # M-Lab's locate API returns the nearest NDT7 servers with short-lived access tokens.
    $l = Invoke-RestMethod -Uri 'https://locate.measurementlab.net/v2/nearest/ndt/ndt7' -UseBasicParsing -TimeoutSec 10
    return @(@($l.results) | ForEach-Object {
        [pscustomobject]@{ Machine = $_.machine; City = $_.location.city; Country = $_.location.country; Download = $_.urls.'wss:///ndt/v7/download'; Upload = $_.urls.'wss:///ndt/v7/upload' }
    } | Where-Object { $_.Download -and $_.Upload })
}

function Invoke-Ndt7Test {
    # One NDT7 test over WebSocket (protocol net.measurementlab.ndt.v7). Download: the server
    # streams for ~10 s. Upload: we send growing binary messages for $BandwidthSeconds.
    param([string]$Url, [string]$Direction, [int64]$CapBytes = [int64]::MaxValue)
    $out = @{ Ok = $false; Mbps = $null; PeakMbps = $null; ClientMbps = $null; ServerMbps = $null; MinRttMs = $null; MB = 0; LoadedLatencyMs = $null; Error = $null }
    $ws = New-Object Net.WebSockets.ClientWebSocket
    $ws.Options.AddSubProtocol('net.measurementlab.ndt.v7')
    $ws.Options.SetBuffer(65536, 65536)
    $cts = New-Object Threading.CancellationTokenSource
    $samples = New-Object Collections.Generic.List[object]
    $loaded = @(); $probeTask = $null; $probeStart = 0; $lastProbe = 0
    $total = [int64]0
    $lastServer = $null
    try {
        $connect = $ws.ConnectAsync([Uri]$Url, $cts.Token)
        if (-not $connect.Wait(10000)) { throw 'WebSocket connect timed out' }
        $buf = New-Object byte[] 1048576
        $seg = [ArraySegment[byte]]::new($buf)
        $text = New-Object Text.StringBuilder
        $start = $sw.Elapsed.TotalSeconds
        $recv = $ws.ReceiveAsync($seg, $cts.Token)
        $closed = $false
        $handleRecv = {
            # Returns $false once the server closes the connection.
            if ($recv.IsFaulted -or $recv.IsCanceled) { return $false }
            $r = $recv.Result
            if ("$($r.MessageType)" -eq 'Close') { return $false }
            if ("$($r.MessageType)" -eq 'Binary') { if ($Direction -eq 'download') { $script:ndtRecvBytes += $r.Count } }
            else {
                [void]$text.Append([Text.Encoding]::UTF8.GetString($buf, 0, $r.Count))
                if ($r.EndOfMessage) { $script:ndtLastServer = $text.ToString(); [void]$text.Clear() }
            }
            return $true
        }
        $script:ndtRecvBytes = [int64]0; $script:ndtLastServer = $null
        if ($Direction -eq 'download') {
            $deadline = $start + 13
            # The server streams for 10 s regardless of speed; stop early at the data cap.
            while (-not $closed -and $sw.Elapsed.TotalSeconds -lt $deadline -and $total -lt $CapBytes) {
                if ($recv.Wait(100)) {
                    if (& $handleRecv) { $recv = $ws.ReceiveAsync($seg, $cts.Token) } else { $closed = $true }
                }
                $total = $script:ndtRecvBytes
                $now = $sw.Elapsed.TotalSeconds
                if ($samples.Count -eq 0 -or $now - $samples[$samples.Count - 1].T -ge 0.25) { $samples.Add([pscustomobject]@{ T = $now; B = $total }) }
                if ($probeTask -and $probeTask.IsCompleted) { $lv = & $finishProbe $probeTask $probeStart; if ($null -ne $lv) { $loaded += $lv }; $probeTask = $null }
                if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $start -gt 0.3) { $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now; $probeTask = & $startProbe }
            }
        } else {
            $payload = New-Object byte[] (1MB)
            (New-Object Random).NextBytes($payload)
            $size = 8192
            $pending = 0
            $send = $null
            $deadline = $start + $BandwidthSeconds
            while (-not $closed -and $sw.Elapsed.TotalSeconds -lt $deadline) {
                if (-not $send -or $send.IsCompleted) {
                    if ($send -and ($send.IsFaulted -or $send.IsCanceled)) { throw "upload send failed: $($send.Exception.GetBaseException().Message)" }
                    if ($send) { $total += $pending }
                    # NDT7 guidance: grow the message while it is under 1/16 of what has been sent.
                    # Capped at 64 KB: larger frames from the .NET Framework client got reset by some servers.
                    if ($size -lt 64KB -and $total -ge 16 * $size) { $size = $size * 2 }
                    $pending = $size
                    $send = $ws.SendAsync([ArraySegment[byte]]::new($payload, 0, $size), [Net.WebSockets.WebSocketMessageType]::Binary, $true, $cts.Token)
                }
                if ($recv.IsCompleted) { if (& $handleRecv) { $recv = $ws.ReceiveAsync($seg, $cts.Token) } else { $closed = $true } }
                [void]$send.Wait(50)
                $now = $sw.Elapsed.TotalSeconds
                if ($samples.Count -eq 0 -or $now - $samples[$samples.Count - 1].T -ge 0.25) { $samples.Add([pscustomobject]@{ T = $now; B = $total }) }
                if ($probeTask -and $probeTask.IsCompleted) { $lv = & $finishProbe $probeTask $probeStart; if ($null -ne $lv) { $loaded += $lv }; $probeTask = $null }
                if (-not $probeTask -and $now - $lastProbe -ge 0.5 -and $now - $start -gt 0.3) { $probeStart = $sw.Elapsed.TotalMilliseconds; $lastProbe = $now; $probeTask = & $startProbe }
            }
            if ($send -and $send.Wait(3000) -and -not $send.IsFaulted) { $total += $pending }
            # Give the server a moment to send its final measurement.
            $until = $sw.Elapsed.TotalSeconds + 1.5
            while (-not $closed -and $sw.Elapsed.TotalSeconds -lt $until) {
                if ($recv.Wait(100)) { if (& $handleRecv) { $recv = $ws.ReceiveAsync($seg, $cts.Token) } else { $closed = $true } }
            }
        }
        $samples.Add([pscustomobject]@{ T = $sw.Elapsed.TotalSeconds; B = $total })
        $lastServer = $script:ndtLastServer
        $stats = Get-ThroughputStats $samples $start
        $out.ClientMbps = $stats[0]; $out.PeakMbps = $stats[1]
        $out.MB = [math]::Round($total / 1MB, 1)
        if ($lastServer) {
            try {
                $m = $lastServer | ConvertFrom-Json
                $ti = $m.TCPInfo
                if ($ti -and $ti.ElapsedTime -gt 0) {
                    $bytes = if ($Direction -eq 'download') { [double]$ti.BytesAcked } else { [double]$ti.BytesReceived }
                    if ($bytes -gt 0) { $out.ServerMbps = [math]::Round($bytes * 8 / ([double]$ti.ElapsedTime / 1e6) / 1e6, 1) }
                    if ($ti.MinRTT) { $out.MinRttMs = [math]::Round([double]$ti.MinRTT / 1000, 1) }
                }
            } catch { }
        }
        # Upload bytes counted on our side include what is still queued in the socket, so prefer the server's figure there.
        $out.Mbps = if ($Direction -eq 'upload' -and $out.ServerMbps) { $out.ServerMbps } else { $out.ClientMbps }
        $out.Ok = ($total -ge 1MB -and $out.Mbps -gt 0)
    } catch {
        $out.Error = $_.Exception.GetBaseException().Message
    } finally {
        try { [void]$ws.CloseOutputAsync([Net.WebSockets.WebSocketCloseStatus]::NormalClosure, '', $cts.Token).Wait(2000) } catch { }
        try { $ws.Abort(); $ws.Dispose() } catch { }
        if ($probeTask) { try { [void]$probeTask.Wait(2500) } catch { } }
    }
    $out.LoadedLatencyMs = Get-MedianValue $loaded
    return $out
}

function Select-VultrUrl {
    # Fastest Vultr test file by time-to-first-response on a HEAD request.
    $best = $null; $bestMs = [double]::MaxValue
    foreach ($u in $VultrTestUrls) {
        $t0 = $sw.Elapsed.TotalMilliseconds
        try {
            $req = New-Object Net.Http.HttpRequestMessage([Net.Http.HttpMethod]::Head, $u)
            $resp = $client.SendAsync($req).Result
            $ms = $sw.Elapsed.TotalMilliseconds - $t0
            if ($resp.IsSuccessStatusCode -and $ms -lt $bestMs) { $best = $u; $bestMs = $ms }
            $resp.Dispose()
        } catch { }
    }
    return $best
}

function Update-Bufferbloat {
    # Bufferbloat = worst loaded latency minus idle latency, graded like common speed tests.
    param($Res)
    $worstLoaded = @($Res['DownloadLoadedLatencyMs'], $Res['UploadLoadedLatencyMs']) | Where-Object { $null -ne $_ } | Sort-Object -Descending | Select-Object -First 1
    $Res['BufferbloatMs'] = if ($null -ne $worstLoaded -and $null -ne $Res['IdleLatencyMs']) { [math]::Round($worstLoaded - $Res['IdleLatencyMs'], 1) } else { $null }
    $Res['BufferbloatGrade'] = if ($null -eq $Res['BufferbloatMs']) { $null } elseif ($Res['BufferbloatMs'] -lt 30) { 'A (good)' } elseif ($Res['BufferbloatMs'] -lt 100) { 'B (fair)' } elseif ($Res['BufferbloatMs'] -lt 250) { 'C (poor)' } else { 'D (bad)' }
}

function Measure-Bandwidth {
    # -Only limits the run to one direction (the retry phase uses it for whichever direction failed).
    param([string[]]$Only = @('Download', 'Upload'))
    # StartedAt/FinishedAt let the merge spot two machines at a site testing at the same time.
    $res = [ordered]@{ Providers = ($BandwidthProviders -join ' > '); Method = $null; StartedAt = Format-Date (Get-Date); FinishedAt = $null }
    $capBytes = [int64]$MaxTestMB * 1MB
    if (-not $script:FullLanguage) {
        # Constrained Language: plain cmdlets only, Cloudflare only, single stream.
        $res.Method = 'Invoke-WebRequest single stream (Constrained Language fallback, lower confidence)'
        try {
            $t0 = Get-Date
            $r = Invoke-WebRequest -Uri ('https://speed.cloudflare.com/__down?bytes={0}' -f [int64]([math]::Min(25MB, $capBytes / 2))) -UseBasicParsing -TimeoutSec 60
            $sec = ((Get-Date) - $t0).TotalSeconds
            $res['DownloadMbps'] = [math]::Round($r.RawContentLength * 8 / $sec / 1e6, 1); $res['DownloadOk'] = $true; $res['DownloadProvider'] = 'Cloudflare'
        } catch { $res['DownloadOk'] = $false; $res['DownloadFailure'] = $_.Exception.Message }
        try {
            $body = New-Object byte[] (5MB)
            $t0 = Get-Date
            Invoke-WebRequest -Uri 'https://speed.cloudflare.com/__up' -Method Post -Body $body -UseBasicParsing -TimeoutSec 60 | Out-Null
            $sec = ((Get-Date) - $t0).TotalSeconds
            $res['UploadMbps'] = [math]::Round($body.Length * 8 / $sec / 1e6, 1); $res['UploadOk'] = $true; $res['UploadProvider'] = 'Cloudflare'
        } catch { $res['UploadOk'] = $false; $res['UploadFailure'] = $_.Exception.Message }
        return $res
    }
    $res.Method = "$BandwidthStreams HTTP streams (Cloudflare/Vultr) or one WebSocket (M-Lab NDT7), $BandwidthSeconds s per direction"
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.UseProxy = $true
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $sw = [Diagnostics.Stopwatch]::StartNew()

    # Latency is measured with ICMP to 1.1.1.1 (comparable to the ping series);
    # HTTP round trips are the fallback when ICMP is blocked.
    $pinger = New-Object Net.NetworkInformation.Ping
    $useIcmp = $false
    try { $useIcmp = ($pinger.Send('1.1.1.1', 1000).Status -eq 'Success') } catch { }
    $res['LatencyMethod'] = if ($useIcmp) { 'ICMP to 1.1.1.1' } else { 'HTTP round trip to speed.cloudflare.com' }
    $startProbe = {
        if ($useIcmp) { return $pinger.SendPingAsync('1.1.1.1', 2000) }
        return $client.GetAsync('https://speed.cloudflare.com/__down?bytes=0', [Net.Http.HttpCompletionOption]::ResponseHeadersRead)
    }
    $finishProbe = {
        param($task, $startedMs)
        if ($task.IsFaulted -or $task.IsCanceled) { return $null }
        if ($useIcmp) { if ($task.Result.Status -eq 'Success') { return [double]$task.Result.RoundtripTime } return $null }
        try { $task.Result.Dispose() } catch { }
        return ($sw.Elapsed.TotalMilliseconds - $startedMs)
    }

    # Idle latency
    $idle = @()
    for ($i = 0; $i -lt 21; $i++) {
        $t = $sw.Elapsed.TotalMilliseconds
        $p = & $startProbe
        try { [void]$p.Wait(2500) } catch { }
        $v = & $finishProbe $p $t
        if ($i -gt 0 -and $null -ne $v) { $idle += $v }   # first probe warms up TLS/ARP and is discarded
        if ($useIcmp) { Start-Sleep -Milliseconds 100 }
    }
    $res['IdleLatencyMs'] = Get-MedianValue $idle
    if ($idle.Count -gt 1) { $d = 0; for ($k = 1; $k -lt $idle.Count; $k++) { $d += [math]::Abs($idle[$k] - $idle[$k - 1]) }; $res['IdleJitterMs'] = [math]::Round($d / ($idle.Count - 1), 1) }

    $attempts = New-Object Collections.Generic.List[object]
    $mlabCache = @{}
    $dlCap = [int64]($capBytes * 0.6)
    $ulCap = [int64]($capBytes * 0.4)

    $runDirection = {
        # Tries each provider in order for one direction; returns the first good result (or $null).
        # M-Lab upload is held back to the second pass: from Windows PowerShell's WebSocket client it
        # reads low, so Cloudflare gets a second chance first.
        param([string]$Dir, [int]$Pass = 1)
        foreach ($prov in $BandwidthProviders) {
            if ($Dir -eq 'Upload' -and $prov -eq 'MLab' -and $Pass -eq 1) { continue }
            $r = $null; $detail = $null; $label = $prov
            if ($prov -eq 'Cloudflare') {
                Write-Step "  $Dir via Cloudflare"
                $r = if ($Dir -eq 'Download') { Invoke-HttpDownloadTest { 'https://speed.cloudflare.com/__down?bytes=26214400' } $dlCap } else { Invoke-CloudflareUpload $ulCap }
                if (-not $r.Ok -and $r.Had429 -and $r.RetryAfterSec -ge 1 -and $r.RetryAfterSec -le 20) {
                    Write-Step ("  Cloudflare asked to wait {0} s; retrying once" -f $r.RetryAfterSec) 'Yellow'
                    Start-Sleep -Seconds $r.RetryAfterSec
                    $r = if ($Dir -eq 'Download') { Invoke-HttpDownloadTest { 'https://speed.cloudflare.com/__down?bytes=26214400' } $dlCap } else { Invoke-CloudflareUpload $ulCap }
                }
                $why = @()
                if ($r.HttpStatus) { $why += 'HTTP ' + ($r.HttpStatus -join ', ') }
                if ($r.Errors) { $why += $r.Errors[0] }
                if ($r.Had429) { $why += 'rate-limited' }
                $detail = $why -join '; '
            } elseif ($prov -eq 'MLab') {
                if (-not $mlabCache.ContainsKey('servers')) {
                    try { $mlabCache['servers'] = @(Get-MlabServers) } catch { $mlabCache['servers'] = @(); $mlabCache['error'] = $_.Exception.Message }
                }
                $servers = @($mlabCache['servers'])
                if ($servers.Count -eq 0) { $detail = "M-Lab locate failed: $($mlabCache['error'])" }
                foreach ($srv in ($servers | Select-Object -First 2)) {
                    # Each locate token is single use, so a server is only tried once per direction.
                    Write-Step ("  {0} via M-Lab ({1}{2})" -f $Dir, $srv.Machine.Split('.')[0], $(if ($srv.City) { ", $($srv.City)" } else { '' }))
                    $url = if ($Dir -eq 'Download') { $srv.Download } else { $srv.Upload }
                    $r = Invoke-Ndt7Test $url $Dir.ToLower() $(if ($Dir -eq 'Download') { $dlCap } else { $ulCap })
                    $label = "M-Lab NDT7 ($($srv.Machine.Split('.')[0]))"
                    $detail = if ($r.Ok) { "server-side $($r.ServerMbps) Mbps, min RTT $($r.MinRttMs) ms" } else { $r.Error }
                    if ($r.Ok -and $Dir -eq 'Upload') { $r['Note'] = 'M-Lab upload from this client reads low; treat as a lower bound' }
                    if ($r.Ok) { break }
                }
                # A fresh locate is needed for any later retry.
                $mlabCache.Remove('servers')
            } elseif ($prov -eq 'Vultr') {
                if ($Dir -ne 'Download') { continue }
                $vu = Select-VultrUrl
                if (-not $vu) { $detail = 'no Vultr test file reachable' }
                else {
                    $label = 'Vultr (' + ([Uri]$vu).Host.Split('.')[0] + ')'
                    Write-Step "  Download via $label"
                    $r = Invoke-HttpDownloadTest ([scriptblock]::Create("'$vu'")) $dlCap
                    $detail = if ($r.Ok) { $null } else { (@(if ($r.HttpStatus) { 'HTTP ' + ($r.HttpStatus -join ', ') }) + @($r.Errors | Select-Object -First 1)) -join '; ' }
                }
            } else { continue }
            $ok = [bool]($r -and $r.Ok)
            $attempts.Add([pscustomobject]@{ Direction = $Dir; Provider = $label; Ok = $ok; Mbps = $(if ($ok) { $r.Mbps }); Detail = $detail })
            if ($ok) { $r['Provider'] = $label; return $r }
            Write-Step ("  {0} via {1} failed: {2}" -f $Dir, $label, $detail) 'Yellow'
        }
        return $null
    }

    $wantDl = ($Only -contains 'Download'); $wantUl = ($Only -contains 'Upload')
    $dl = $null; $ul = $null
    if ($wantDl) { $dl = & $runDirection 'Download' }
    if ($wantUl) { $ul = & $runDirection 'Upload' }
    if (($wantDl -and -not $dl) -or ($wantUl -and -not $ul)) {
        # One more pass for whatever failed, after a pause (rate limits usually clear quickly).
        Write-Step '  Bandwidth incomplete; waiting 30 s and trying every provider once more' 'Yellow'
        Start-Sleep -Seconds 30
        if ($wantDl -and -not $dl) { $dl = & $runDirection 'Download' 2 }
        if ($wantUl -and -not $ul) { $ul = & $runDirection 'Upload' 2 }
    }

    foreach ($pair in @(@('Download', $dl), @('Upload', $ul))) {
        $dir = $pair[0]; $r = $pair[1]
        if ($Only -notcontains $dir) { continue }
        if ($r) {
            $res["${dir}Ok"] = $true
            $res["${dir}Mbps"] = $r.Mbps
            if ($dir -eq 'Download') { $res['DownloadPeakMbps'] = $r.PeakMbps }
            $res["${dir}MB"] = $r.MB
            $res["${dir}LoadedLatencyMs"] = $r.LoadedLatencyMs
            $res["${dir}Provider"] = $r.Provider
            if ($r.ServerMbps) { $res["${dir}ServerMbps"] = $r.ServerMbps }
            if ($r.MinRttMs) { $res["${dir}MinRttMs"] = $r.MinRttMs }
            $failedFirst = @($attempts | Where-Object { $_.Direction -eq $dir -and -not $_.Ok } | ForEach-Object { $_.Provider } | Select-Object -Unique)
            $noteParts = @()
            if ($failedFirst.Count) { $noteParts += "Fallback used after: $($failedFirst -join ', ')" }
            if ($r.Note) { $noteParts += $r.Note }
            if ($noteParts.Count) { $res["${dir}Note"] = $noteParts -join '; ' }
        } else {
            $res["${dir}Ok"] = $false
            $res["${dir}Mbps"] = $null
            $res["${dir}Failure"] = ((@($attempts | Where-Object Direction -eq $dir) | ForEach-Object { '{0}: {1}' -f $_.Provider, $_.Detail }) -join ' | ')
        }
    }
    $res['Attempts'] = $attempts.ToArray()   # @() on a generic List fails when stored in an ordered dictionary
    Update-Bufferbloat $res
    $res['TestedOver'] = '{0} - {1}' -f $Result['Network']['PhysicalClass'], $Result['Network']['PhysicalAdapter']
    $res['FinishedAt'] = Format-Date (Get-Date)
    try { $client.Dispose(); $pinger.Dispose() } catch { }
    return $res
}
function Test-TraceUsable { param($T) return [bool]($T -and @($T.Hops | Where-Object { $_.IP }).Count -ge 2) }

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

# ---------------------------------------------------------------------
# Email and domain posture from public DNS: where mail goes and whether SPF, DMARC and DKIM protect the
# client's domain. The domain comes from what the PC already knows (the user's sign-in name, the DNS
# suffixes, the AD forest); internal-only names are left out.
# ---------------------------------------------------------------------
function Get-ClientDomains {
    param($R)
    $names = @()
    $upn = "$(Get-Prop $R 'Identity', 'Upn')"; if ($upn -match '@([A-Za-z0-9.-]+)$') { $names += $matches[1] }
    $names += @(Get-Prop $R 'NetworkExtra', 'DnsSuffixSearch')
    $names += "$(Get-Prop $R 'Machine', 'Domain')"
    $names += "$(Get-Prop $R 'AdSites', 'Forest')"
    $out = @()
    foreach ($n in $names) {
        $d = "$n".Trim().TrimEnd('.').ToLower()
        if ($d -notmatch '^[a-z0-9-]+(\.[a-z0-9-]+)+$') { continue }
        if ($d -match '\.(local|lan|internal|intra|intranet|corp|home|localdomain|private|ad|domain|test|example|invalid)$|onmicrosoft\.com$|\.arpa$') { continue }
        $parts = @($d.Split('.'))
        # The registrable domain: the last two labels, or three for names like contoso.co.uk
        $keep = if ($parts.Count -ge 3 -and $parts[-1].Length -eq 2 -and $parts[-2] -in @('co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'ltd', 'plc')) { 3 } else { 2 }
        if ($parts.Count -lt $keep) { continue }
        $out += ($parts[($parts.Count - $keep)..($parts.Count - 1)] -join '.')
    }
    return @($out | Select-Object -Unique)
}

function Get-MailProvider {
    param([string[]]$MxHosts)
    $t = (@($MxHosts) -join ' ').ToLower()
    if (-not $t) { return $null }
    if ($t -match 'mail\.protection\.outlook\.com') { return 'Microsoft 365' }
    if ($t -match 'google\.com|googlemail\.com') { return 'Google Workspace' }
    if ($t -match 'pphosted\.com|ppe-hosted\.com') { return 'Proofpoint' }
    if ($t -match 'mimecast') { return 'Mimecast' }
    if ($t -match 'barracudanetworks\.com') { return 'Barracuda' }
    if ($t -match 'iphmx\.com') { return 'Cisco Secure Email' }
    if ($t -match 'messagelabs|symanteccloud') { return 'Broadcom Email Security' }
    if ($t -match 'sophos') { return 'Sophos Email' }
    if ($t -match 'secureserver\.net') { return 'GoDaddy' }
    if ($t -match 'zoho') { return 'Zoho Mail' }
    return 'other or self-hosted'
}

function Get-SpfSummary {
    # The SPF record among a domain's TXT records: the record, how it ends (-all, ~all, ?all, +all),
    # how many DNS lookups it costs at the top level (10 is the limit), and whether there is more than one.
    param([string[]]$Txt)
    $spf = @(@($Txt) | Where-Object { "$_" -match '^\s*v=spf1\b' })
    if (-not $spf.Count) { return [pscustomobject]@{ Present = $false; Record = $null; All = $null; Lookups = 0; Multiple = $false } }
    $rec = "$($spf[0])"
    $all = if ($rec -match '([-~?+]?)all\b') { if ($matches[1]) { "$($matches[1])all" } else { '+all' } } elseif ($rec -match 'redirect=') { 'redirect' } else { 'none' }
    # Count term by term: include, a, mx, ptr, exists and redirect each cost a lookup (ip4, ip6 and all do not).
    $lookups = @(@($rec -split '\s+') | Where-Object { ($_ -replace '^[-~?+]', '') -match '^(?i)(include:|a$|a[:/]|mx$|mx[:/]|ptr|exists:|redirect=)' }).Count
    return [pscustomobject]@{ Present = $true; Record = $rec; All = $all; Lookups = $lookups; Multiple = ($spf.Count -gt 1) }
}

function Get-DmarcSummary {
    param([string[]]$Txt)
    $rec = @(@($Txt) | Where-Object { "$_" -match '^\s*v=DMARC1' }) | Select-Object -First 1
    if (-not $rec) { return [pscustomobject]@{ Present = $false; Record = $null; Policy = $null; Pct = $null; Reports = $false } }
    $tag = { param($n) if ("$rec" -match "(?i)(?:^|;)\s*$n\s*=\s*([^;]+)") { $matches[1].Trim() } else { $null } }
    return [pscustomobject]@{ Present = $true; Record = "$rec"; Policy = (& $tag 'p'); Pct = (& $tag 'pct'); Reports = [bool](& $tag 'rua') }
}

function Resolve-PublicDns {
    # A lookup through a public resolver first (internal DNS often answers differently for the client's
    # own domain), then through this PC's resolver. Returns the answer records of the asked type.
    param([string]$Name, [string]$Type)
    foreach ($srv in @('1.1.1.1', $null)) {
        try {
            $a = if ($srv) { @(Resolve-DnsName -Name $Name -Type $Type -Server $srv -DnsOnly -QuickTimeout -ErrorAction Stop) } else { @(Resolve-DnsName -Name $Name -Type $Type -DnsOnly -QuickTimeout -ErrorAction Stop) }
            return @($a | Where-Object { "$($_.Type)" -eq $Type })
        } catch {
            if ("$($_.Exception.Message)" -match 'does not exist|DNS name does not exist|NXDOMAIN|No records') { return @() }
        }
    }
    return @()
}

function Get-DomainPosture {
    param([string]$Domain)
    $txt = { param($n) @(Resolve-PublicDns $n 'TXT' | ForEach-Object { (@($_.Strings) -join '') }) }
    $mx = @(Resolve-PublicDns $Domain 'MX' | Sort-Object Preference | ForEach-Object { "$($_.NameExchange)".TrimEnd('.').ToLower() } | Where-Object { $_ })
    $spf = Get-SpfSummary (& $txt $Domain)
    $dmarc = Get-DmarcSummary (& $txt "_dmarc.$Domain")
    $dkim = @()
    foreach ($sel in @('selector1', 'selector2', 'google', 'k1', 's1', 'default')) {
        $c = @(Resolve-PublicDns "$sel._domainkey.$Domain" 'CNAME')
        # A key must have a value: "p=" with nothing after it is how a domain says it has no DKIM key.
        $t = if (-not $c.Count) { @(& $txt "$sel._domainkey.$Domain" | Where-Object { $_ -match '(?:^|;)\s*p=[A-Za-z0-9+/]{20,}' }) } else { @() }
        if ($c.Count -or $t.Count) { $dkim += $sel }
    }
    $auto = @(Resolve-PublicDns "autodiscover.$Domain" 'CNAME' | ForEach-Object { "$($_.NameHost)".TrimEnd('.').ToLower() })
    return [ordered]@{
        Domain = $Domain; Mx = $mx; Provider = (Get-MailProvider $mx)
        Spf = $spf; Dmarc = $dmarc; DkimSelectors = $dkim
        MtaSts = [bool]@(& $txt "_mta-sts.$Domain" | Where-Object { $_ -match 'v=STSv1' }).Count
        TlsRpt = [bool]@(& $txt "_smtp._tls.$Domain" | Where-Object { $_ -match 'v=TLSRPTv1' }).Count
        Autodiscover = @($auto | Select-Object -First 1)
    }
}

function Get-DomainFlags {
    # Severity, Category, Message rows for what public DNS shows about one domain.
    param($P)
    $d = "$(Get-Prop $P 'Domain')"
    $out = @()
    $f = { param($sev, $msg) [pscustomobject]@{ Severity = $sev; Category = 'Email security'; Message = $msg } }
    $hasMx = @(Get-Prop $P 'Mx').Count -gt 0
    $spf = Get-Prop $P 'Spf'; $dm = Get-Prop $P 'Dmarc'
    if (-not (Get-Prop $spf 'Present')) { $out += & $f $(if ($hasMx) { 'Medium' } else { 'Low' }) "${d}: no SPF record, so anyone can send mail that claims to come from it" }
    elseif ("$(Get-Prop $spf 'All')" -eq '+all') { $out += & $f 'High' "${d}: the SPF record ends in +all, which allows every server on the internet to send as it" }
    elseif ("$(Get-Prop $spf 'All')" -in @('?all', 'none')) { $out += & $f 'Low' "${d}: the SPF record does not end in -all or ~all, so it protects nothing" }
    if (Get-Prop $spf 'Multiple') { $out += & $f 'Medium' "${d}: more than one SPF record, which makes SPF fail for every message" }
    if ([int](Get-Prop $spf 'Lookups') -gt 10) { $out += & $f 'Medium' "${d}: the SPF record needs more than 10 DNS lookups, which makes SPF fail" }
    if (-not (Get-Prop $dm 'Present')) { $out += & $f 'Medium' "${d}: no DMARC record, so spoofed mail claiming to be from it is delivered" }
    elseif ("$(Get-Prop $dm 'Policy')" -eq 'none') { $out += & $f 'Low' "${d}: DMARC is set to p=none, which only reports and blocks nothing" }
    if ($hasMx -and "$(Get-Prop $P 'Provider')" -eq 'Microsoft 365' -and -not @(Get-Prop $P 'DkimSelectors' | Where-Object { $_ -like 'selector*' }).Count) { $out += & $f 'Low' "${d}: Microsoft 365 DKIM signing is not published (no selector1/selector2 records)" }
    return $out
}

function Get-AccessType {
    # The kind of internet access, when the carrier's network name says it outright. $null when it does
    # not (most telcos sell fiber, DSL and wireless under one name, so they are not guessed).
    param([string]$Carrier)
    $c = "$Carrier"
    if ($c -match 'Space Exploration|Starlink|SpaceX') { return 'Starlink (low-orbit satellite)' }
    if ($c -match 'Viasat|Hughes|EchoStar|Inmarsat') { return 'geostationary satellite' }
    if ($c -match 'T-Mobile|Cellco|Verizon Wireless|AT&T Mobility|Sprint|UScellular|US Cellular') { return 'cellular or fixed wireless' }
    if ($c -match 'Comcast|Charter|Spectrum|Cox Comm|Altice|Optimum|Mediacom|WideOpenWest|\bWOW\b|Sparklight|Cable One|Rogers|Shaw|Virgin Media|Liberty') { return 'cable' }
    return $null
}

# ---------------------------------------------------------------------
# Network risks, read from what discovery already collected. Nothing extra is sent to any device.
# Returns Severity, Category, Message rows for Add-Flag.
# ---------------------------------------------------------------------
function Get-NetworkRiskFlags {
    param($R, [datetime]$Now = (Get-Date))
    $out = New-Object Collections.Generic.List[object]
    $flag = { param($sev, $msg) $out.Add([pscustomobject]@{ Severity = $sev; Category = 'Network risk'; Message = $msg }) }
    $label = { param($d) $n = "$(Get-Prop $d 'Name')"; if ($n) { '{0} ({1})' -f (Get-Prop $d 'IP'), $n.Split('.')[0] } else { "$(Get-Prop $d 'IP')" } }
    $list = { param($items) $a = @($items); $t = (@($a | Select-Object -First 6 | ForEach-Object { & $label $_ })) -join ', '; if ($a.Count -gt 6) { $t += " and $($a.Count - 6) more" }; $t }
    $devs = @(@(Get-Prop $R 'Identify', 'Devices') | Where-Object { $_ })
    $ports = { param($d) @(@(Get-Prop $d 'OpenPorts') | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ }) }

    $smb1 = @($devs | Where-Object { Get-Prop $_ 'Smb', 'Smb1Enabled' })
    if ($smb1.Count) { & $flag 'High' "$($smb1.Count) device(s) still accept SMBv1, the file-sharing version WannaCry spread over: $(& $list $smb1)" }
    $telnet = @($devs | Where-Object { (& $ports $_) -contains 23 })
    if ($telnet.Count) { & $flag 'Medium' "$($telnet.Count) device(s) accept Telnet, where logins cross the network in clear text: $(& $list $telnet)" }
    $ftp = @($devs | Where-Object { (& $ports $_) -contains 21 })
    if ($ftp.Count) { & $flag 'Low' "$($ftp.Count) device(s) run FTP, where logins cross the network in clear text: $(& $list $ftp)" }

    # A web page only over plain HTTP: whatever is typed into its login crosses the network unencrypted.
    $httpOnly = @($devs | Where-Object {
        $w = @(@(Get-Prop $_ 'Web') | Where-Object { $_ -and (Get-Prop $_ 'Status') })
        @($w | Where-Object { "$(Get-Prop $_ 'Url')" -like 'http://*' }).Count -and -not @($w | Where-Object { "$(Get-Prop $_ 'Url')" -like 'https://*' }).Count
    })
    if ($httpOnly.Count) { & $flag 'Low' "$($httpOnly.Count) device(s) offer their web page only over plain HTTP, so a login there is sent unencrypted: $(& $list $httpOnly)" }

    $expired = @($devs | Where-Object {
        @(@(Get-Prop $_ 'Web') | Where-Object { $na = "$(Get-Prop $_ 'CertNotAfter')"; $na -and ([datetime]$na) -lt $Now }).Count
    })
    if ($expired.Count) { & $flag 'Low' "$($expired.Count) device(s) present an expired HTTPS certificate, which teaches people to click through certificate warnings: $(& $list $expired)" }

    # Remote Desktop and file sharing reachable from an office port across routing
    $remote = @($devs | Where-Object { Get-Prop $_ 'Remote' })
    $rdp = @($remote | Where-Object { (& $ports $_) -contains 3389 })
    if ($rdp.Count) { & $flag 'Medium' "From an ordinary office port, Remote Desktop answers on $($rdp.Count) device(s) on other subnets, with nothing filtering in between: $(& $list $rdp)" }
    $smb = @($remote | Where-Object { (& $ports $_) -contains 445 })
    if ($smb.Count) { & $flag 'Medium' "From an ordinary office port, file sharing answers on $($smb.Count) device(s) on other subnets, the path ransomware spreads along: $(& $list $smb)" }

    $snmpN = Get-Prop $R 'Snmp', 'Answered'
    if ($snmpN -and "$(Get-Prop $R 'Snmp', 'Community')" -eq 'public') {
        & $flag 'Medium' "$snmpN device(s) answer SNMP with the default community 'public': anyone on the network can read their configuration, ARP tables and routes"
    }

    # SSH servers from before 2017 (OpenSSH under 7.4, Dropbear before 2017)
    $oldSsh = @($devs | Where-Object {
        $b = "$(Get-Prop $_ 'SshBanner')"
        ($b -match 'OpenSSH_(\d+)\.(\d+)' -and ([int]$matches[1] -lt 7 -or ([int]$matches[1] -eq 7 -and [int]$matches[2] -lt 4))) -or ($b -match 'dropbear_(\d{4})' -and [int]$matches[1] -lt 2017)
    })
    if ($oldSsh.Count) { & $flag 'Low' "$($oldSsh.Count) device(s) run an SSH server from before 2017, a sign of firmware that has not been updated in years: $(& $list $oldSsh)" }

    # Windows that no longer gets security updates, named by the file-sharing handshake
    $hosts = @(@(Get-Prop $R 'WindowsHosts', 'Hosts') | Where-Object { $_ })
    $dead = @($hosts | Where-Object { "$(Get-Prop $_ 'Os')" -match '^Windows (7|8)\b' })
    if ($dead.Count) { & $flag 'High' "$($dead.Count) machine(s) on the network run Windows that no longer gets security updates (Windows 7 or 8, Server 2008 R2 or 2012): $((@($dead | Select-Object -First 6 | ForEach-Object { '{0} ({1}, {2})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'ComputerName'), (Get-Prop $_ 'Os') })) -join ', ')" }
    $checks = @(@(Get-Prop $R 'LeadChecks', 'Checks') | Where-Object { $_ })
    $oldEsx = @($checks | Where-Object { "$(Get-Prop $_ 'Kind')" -eq 'Hypervisor' -and "$(Get-Prop $_ 'Version')" -match '^(5|6|7)\.' })
    if ($oldEsx.Count) { & $flag 'High' "$($oldEsx.Count) VMware host(s) run a version out of general support (6.x ended 2022, 7.0 in October 2025): $((@($oldEsx | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'What') })) -join ', ')" }
    $bmc = @($checks | Where-Object { "$(Get-Prop $_ 'Kind')" -eq 'ServerManagement' })
    if ($bmc.Count) { & $flag 'Medium' "$($bmc.Count) server management controller(s) (iDRAC, iLO and similar) can be reached from an ordinary office port; they belong on a management network: $((@($bmc | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'What') })) -join ', ')" }
    $w10 = @($hosts | Where-Object { "$(Get-Prop $_ 'Os')" -like 'Windows 10 (*' })
    if ($w10.Count) { & $flag 'Medium' "$($w10.Count) machine(s) on the network run Windows 10, out of support since October 2025 unless they are LTSC or covered by Extended Security Updates: $((@($w10 | Select-Object -First 6 | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'ComputerName') })) -join ', ')" }

    return $out.ToArray()
}

function Get-AssessmentFindings {
    # Turns the collected evidence into plain statements, each with what it rests on and how sure it is:
    # Confirmed (measured directly), Likely (several signs agree), Possible (one sign, or an inference).
    # Reads live results and saved JSON alike, so it can be re-run on old runs.
    param($R)
    $out = New-Object Collections.Generic.List[object]
    $add = { param($area, $conf, $text, $evidence) $out.Add([pscustomobject]@{ Area = $area; Confidence = $conf; Finding = "$text"; Evidence = @(@($evidence) | Where-Object { $_ } | ForEach-Object { "$_" }) }) }
    $net = Get-Prop $R 'Network'; $bw = Get-Prop $R 'Bandwidth'; $cap = Get-Prop $R 'Capture'; $eg = Get-Prop $R 'Egress'
    $class = "$(Get-Prop $net 'PhysicalClass')"; $wired = ($class -like 'Wired*')
    $link = Get-Prop $net 'PhysicalLinkMbps'; $srcIp = "$(Get-Prop $net 'SourceIp')"; $gw = "$(Get-Prop $net 'Gateway')"
    $elev = [bool](Get-Prop $R 'Meta', 'AdminTierActive')
    $ad = @(@(Get-Prop $net 'Adapters') | Where-Object { $_ -and "$(Get-Prop $_ 'Name')" -eq "$(Get-Prop $net 'PhysicalAdapter')" }) | Select-Object -First 1
    $mask = "$(@(Get-Prop $ad 'SubnetMask') | Select-Object -First 1)"
    if ($mask -notmatch '^\d+\.\d+\.\d+\.\d+$') { $mask = '255.255.255.0' }
    $pre = { param($ip) (("$ip" -split '\.')[0..2] -join '.') }

    $machine = ("$(Get-Prop $R 'Machine', 'Manufacturer') $(Get-Prop $R 'Machine', 'Model')").Trim()
    if ((Get-Prop $R 'Preflight', 'LooksLikeHostedDesktop') -or $machine -match 'VMware|Virtual Machine|VirtualBox|KVM|QEMU|Xen') {
        & $add 'This run' 'Confirmed' 'This run was made on a virtual machine or hosted desktop. Everything below describes the data center or cloud it runs in, not an office.' @("Machine: $machine", "Address: $srcIp", "Egress: $(Get-Prop $eg 'Carrier')")
    }

    # ---- What the wire capture heard ----
    $lldp = @(@(Get-Prop $cap 'Lldp') | Where-Object { $_ }); $cdp = @(@(Get-Prop $cap 'Cdp') | Where-Object { $_ }); $stp = @(@(Get-Prop $cap 'SpanningTree') | Where-Object { $_ })
    $haveCap = ($null -ne $cap -and $null -ne (Get-Prop $cap 'Frames'))
    $captureRan = $haveCap -or ($null -ne (Get-Prop $R 'Lldp', 'FramesCaptured'))
    $capSecs = Get-Prop $cap 'Seconds'; if (-not $capSecs) { $capSecs = 65 }
    $switches = @(); $phones = @(); $others = @(); $foreign = @(); $voiceVlan = $null
    foreach ($n in $lldp) {
        $caps = @(Get-Prop $n 'Capabilities'); $cls = "$(Get-Prop $n 'MedDeviceClass')"
        $label = (@("$(Get-Prop $n 'SystemName')", "$(Get-Prop $n 'SystemDescription')", "$(Get-Prop $n 'ChassisVendor')") | Where-Object { $_ }) -join ', '
        if (-not $label) { $label = "MAC $(Get-Prop $n 'SenderMac')" }
        if ($caps -contains 'Telephone' -or $cls -like '*phone*') { $phones += "$label (LLDP)" }
        elseif ($caps -contains 'Bridge' -or $caps -contains 'WLAN access point' -or $cls -like 'Network connectivity*') {
            $port = "$(Get-Prop $n 'PortDescription')"; if (-not $port) { $port = "$(Get-Prop $n 'PortId')" }
            $switches += [pscustomobject]@{ Label = $label; Port = $port; Vlan = Get-Prop $n 'PortVlan'; LinkMode = "$(Get-Prop $n 'LinkMode')"; MgmtIP = "$(Get-Prop $n 'MgmtIP')"; Proto = 'LLDP' }
            if (Get-Prop $n 'VoiceVlan') { $voiceVlan = Get-Prop $n 'VoiceVlan' }
        }
        else { $others += "$label (LLDP)"; $ip = "$(Get-Prop $n 'MgmtIP')"; if ($ip -and $srcIp -and -not (Test-SameSubnet $ip $srcIp $mask)) { $foreign += "$ip ($label)" } }
    }
    foreach ($n in $cdp) {
        $caps = @(Get-Prop $n 'Capabilities')
        $label = (@("$(Get-Prop $n 'DeviceId')", "$(Get-Prop $n 'Platform')", "$(Get-Prop $n 'Software')") | Where-Object { $_ }) -join ', '
        if ($caps -contains 'Telephone') { $phones += "$label (CDP)" }
        elseif ($caps -contains 'Switch' -or $caps -contains 'Bridge') {
            $switches += [pscustomobject]@{ Label = $label; Port = "$(Get-Prop $n 'PortId')"; Vlan = Get-Prop $n 'NativeVlan'; LinkMode = ''; MgmtIP = "$(Get-Prop $n 'Address')"; Proto = 'CDP' }
            if (Get-Prop $n 'VoiceVlan') { $voiceVlan = Get-Prop $n 'VoiceVlan' }
        }
        else { $others += "$label (CDP)"; $ip = "$(Get-Prop $n 'Address')"; if ($ip -and $srcIp -and -not (Test-SameSubnet $ip $srcIp $mask)) { $foreign += "$ip ($label)" } }
    }
    if (-not $haveCap) {
        # Runs made before 1.6.0 only have the older neighbor list, without capabilities.
        foreach ($n in @(@(Get-Prop $R 'Lldp', 'Neighbors') | Where-Object { $_ })) {
            $label = (@("$(Get-Prop $n 'SystemName')", "$(Get-Prop $n 'SystemDescription')") | Where-Object { $_ }) -join ', '
            if ("$(Get-Prop $n 'Protocol')" -eq 'LLDP' -and "$(Get-Prop $n 'Port')" -notmatch '^eth\d') { $switches += [pscustomobject]@{ Label = $label; Port = "$(Get-Prop $n 'Port')"; Vlan = Get-Prop $n 'Vlan'; LinkMode = "$(Get-Prop $n 'LinkMode')"; MgmtIP = "$(Get-Prop $n 'MgmtIP')"; Proto = 'LLDP' } }
            else { $others += "$label ($(Get-Prop $n 'Protocol'))" }
        }
    }

    # ---- Speed test: did the port or the circuit set the limit? ----
    $down = Get-Prop $bw 'DownloadMbps'; $up = Get-Prop $bw 'UploadMbps'; $peak = Get-Prop $bw 'DownloadPeakMbps'
    $capped = $false
    if ($down) {
        $ev = @("Link speed: $link Mbps ($class)", "Download $down Mbps (peak $peak), upload $up Mbps, via $(Get-Prop $bw 'DownloadProvider')")
        $rounds = @(@(Get-Prop $bw 'Rounds') | Where-Object { $_ -and (Get-Prop $_ 'DownloadOk') })
        $spread = $null
        if ($rounds.Count -gt 1) {
            $vals = @($rounds | ForEach-Object { [double](Get-Prop $_ 'DownloadMbps') })
            $mx = ($vals | Measure-Object -Maximum).Maximum; $mn = ($vals | Measure-Object -Minimum).Minimum
            if ($mx -gt 0) { $spread = [int][math]::Round(100 * ($mx - $mn) / $mx) }
            $ev += ('Rounds (down/up Mbps): {0}; spread {1}%' -f (($rounds | ForEach-Object { '{0}/{1}' -f (Get-Prop $_ 'DownloadMbps'), (Get-Prop $_ 'UploadMbps') }) -join ', '), $spread)
        }
        if ($link) { $capped = ([double]$down -ge 0.85 * [double]$link) -or ($peak -and [double]$peak -ge 0.95 * [double]$link) }
        if (-not $wired) {
            & $add 'Speed test' 'Likely' "Tested over $class at a radio rate of $link Mbps: the result ($down down / $up up Mbps) reflects the wireless link as much as the circuit." $ev
        } elseif ($capped -and [double]$link -lt 1000) {
            & $add 'Speed test' 'Confirmed' "The speed test ran into the limit of this port ($link Mbps link), so it measured the port, not the circuit. The circuit delivers at least $down down / $up up Mbps; its real speed is not known from this run." $ev
        } elseif ($capped) {
            & $add 'Speed test' 'Confirmed' "Download reached the limit of the $link Mbps link ($down Mbps, peak $peak): the circuit is at least that fast. Upload measured $up Mbps." $ev
        } elseif ($link) {
            $c = if ($null -ne $spread -and $spread -le 15) { 'Confirmed' } else { 'Likely' }
            & $add 'Speed test' $c "The port linked at $link Mbps and the test stayed well under it, so $down down / $up up Mbps reflects the internet circuit (or its provisioned speed), not this port." $ev
        }
        if ($null -ne $spread -and $spread -gt 25) { & $add 'Speed test' 'Likely' "The rounds differ by $spread%: the circuit was busy or unstable while testing. Treat the best round as the capability and the spread as contention." $ev }
        if ($up -and [double]$down -gt 0 -and $machine -notmatch 'VMware|Virtual Machine|VirtualBox|KVM|QEMU|Xen') {
            $ratio = [double]$up / [double]$down
            if ($capped -and [double]$up -gt 40) { & $add 'Internet service' 'Likely' "Upload reached $up Mbps even through the port limit, which rules out older cable and DSL tiers: a symmetrical service (fiber or a newer cable tier)." @("Download $down, upload $up Mbps") }
            elseif (-not $capped -and $ratio -ge 0.7) { & $add 'Internet service' 'Likely' "Upload is close to download ($up vs $down Mbps): a symmetrical service, typically fiber." @("Upload/download ratio $([math]::Round($ratio, 2))") }
            elseif (-not $capped -and $ratio -le 0.25) {
                $acc = Get-AccessType "$(Get-Prop $eg 'Carrier')"
                & $add 'Internet service' 'Likely' "Upload is a fraction of download ($up vs $down Mbps): an asymmetric service, $(if ($acc) { "as expected on $acc" } else { 'such as cable, DSL, satellite or cellular' })." @("Upload/download ratio $([math]::Round($ratio, 2))")
            }
        }
    }

    # ---- Where this port lands ----
    if ($wired) {
        $heard = @()
        if ($others.Count) { $heard += "Other devices announcing themselves on this port: $((@($others) | Select-Object -First 6) -join '; ')" }
        if (-not $elev -or -not $captureRan) {
            & $add 'Switch port' 'Possible' 'The wire capture did not run (ISE not elevated, or the capture failed), so the switch behind this port could not be identified.' @("Elevated: $elev", "Link speed: $link Mbps")
        } elseif ($phones.Count) {
            $t = "This jack is the pass-through port of a desk phone: $($phones[0])."
            if ($link -and [double]$link -lt 1000) { $t += " That is why the link is $link Mbps." }
            & $add 'Switch port' 'Confirmed' $t (@("Phone announced itself on this port: $($phones -join '; ')", "Link speed: $link Mbps") + $heard)
        } elseif ($switches.Count) {
            $s = $switches[0]
            $t = "This port is on a managed switch: $($s.Label), port $($s.Port)"
            if ($s.Vlan) { $t += ", VLAN $($s.Vlan)" }
            $t += '.'
            if ($s.LinkMode -like '100*' -or $s.LinkMode -like '10BASE*') { $t += " The switch itself reports this port at $($s.LinkMode): a 10/100 port, or cabling that cannot carry gigabit." }
            elseif ($link -and [double]$link -lt 1000) { $t += " The link is only $link Mbps although a managed switch is directly upstream: check the cable and the port speed setting." }
            & $add 'Switch port' 'Confirmed' $t (@("Announced by $($s.Proto): $($s.Label)", "Management address: $($s.MgmtIP)", "Link mode reported by the switch: $($s.LinkMode)", "Link speed seen by this PC: $link Mbps") + $heard)
        } elseif ($stp.Count) {
            $b = $stp[0]
            & $add 'Switch port' 'Likely' "No switch announced itself by LLDP or CDP, but spanning-tree frames from $(Get-Prop $b 'BridgeMac') ($(Get-Prop $b 'SenderVendor')) reached this port: a managed switch is upstream with discovery protocols turned off." (@("Spanning tree: bridge $(Get-Prop $b 'BridgeMac'), root $(Get-Prop $b 'RootMac') ($(Get-Prop $b 'RootVendor')), root path cost $(Get-Prop $b 'RootPathCost')", "Listened for $capSecs s, elevated") + $heard)
        } elseif ($link -and [double]$link -lt 1000) {
            & $add 'Switch port' 'Likely' "No switch announced itself in $capSecs s of listening (no LLDP, no CDP, no spanning tree) and the link is only $link Mbps. Together that points to something unmanaged between this jack and the real switch: a desk phone's pass-through port, a small 10/100 switch, or old two-pair cabling." (@("Run elevated: yes; capture ran for $capSecs s", "Link speed: $link Mbps on an adapter set to auto-negotiate", 'No LLDP or CDP frame from a switch, no spanning-tree frame') + $heard)
        } else {
            & $add 'Switch port' 'Possible' "No switch announced itself in $capSecs s of listening (no LLDP, CDP or spanning tree) although the link is $link Mbps: the switch is unmanaged, or has discovery protocols and spanning tree turned off." (@("Run elevated: yes; capture ran for $capSecs s") + $heard)
        }
        if ($stp.Count) {
            $b = $stp[0]
            $t = if (Get-Prop $b 'ThisSwitchIsRoot') { "The switch this port hangs off is itself the spanning-tree root ($(Get-Prop $b 'RootMac'), $(Get-Prop $b 'RootVendor'))." } else { "The spanning-tree root (the core switch) is $(Get-Prop $b 'RootMac') ($(Get-Prop $b 'RootVendor')), priority $(Get-Prop $b 'RootPriority'), $(Get-Prop $b 'RootPathCost') in path cost away from this port." }
            & $add 'Switching' 'Confirmed' $t @("Protocol: $(Get-Prop $b 'Protocol')", "Sending bridge: $(Get-Prop $b 'BridgeMac') priority $(Get-Prop $b 'BridgePriority')")
        }
    }

    # ---- DNS and DHCP: where they live ----
    $dhcp = "$(Get-Prop $ad 'DhcpServer')"; $dnsList = @(@(Get-Prop $ad 'DnsServers') | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
    $traces = @(@(Get-Prop $R 'Traceroutes') | Where-Object { $_ })
    $pings = @(@(Get-Prop $R 'PingSeries') | Where-Object { $_ })
    $where = {
        param($ip)
        if (-not $ip) { return 'none' }
        if ($ip -eq $gw) { return 'gateway' }
        if ($srcIp -and (Test-SameSubnet $ip $srcIp $mask)) { return 'lan' }
        if ((Get-IpClass $ip) -eq 'Private') { return 'remote' }
        return 'public'
    }
    $pathTo = {
        param($ip)
        $t = $traces | Where-Object { "$(Get-Prop $_ 'Target')" -eq $ip } | Select-Object -First 1
        if (-not $t) { $t = $traces | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (& $pre $tp) -eq (& $pre $ip) } | Select-Object -First 1 }
        if (-not $t) { return $null }
        $hops = @(@(Get-Prop $t 'Hops') | Where-Object { $_ })
        $p = $pings | Where-Object { "$(Get-Prop $_ 'Target')" -eq "$(Get-Prop $t 'Target')" } | Select-Object -First 1
        return [pscustomobject]@{ Target = "$(Get-Prop $t 'Target')"; HopCount = $hops.Count; Path = (@($hops | ForEach-Object { if (Get-Prop $_ 'IP') { "$(Get-Prop $_ 'IP') ($(Get-Prop $_ 'AvgMs') ms)" } else { 'no reply' } }) -join ' > '); AvgMs = Get-Prop $p 'AvgMs'; LossPct = Get-Prop $p 'LossPct'; Jitter = Get-Prop $p 'JitterMs' }
    }
    if ($ad) {
        $dns1 = "$($dnsList | Select-Object -First 1)"
        $wDhcp = & $where $dhcp; $wDns = & $where $dns1
        $ev = @("DHCP server on the lease: $dhcp", "DNS servers: $($dnsList -join ', ')", "This PC: $srcIp mask $mask, gateway $gw")
        $relay = @(@(Get-Prop $cap 'DhcpServers') | Where-Object { $_ -and (Get-Prop $_ 'RelayAgent') }) | Select-Object -First 1
        if ($relay) { $ev += "DHCP answers on the wire came through relay agent $(Get-Prop $relay 'RelayAgent') for server $(Get-Prop $relay 'Server')" }
        $lo = Get-Prop $ad 'DhcpLeaseObtained'; $le = Get-Prop $ad 'DhcpLeaseExpires'
        if ($lo -and $le) { try { $ev += ('Lease length: {0:N1} hours' -f (([datetime]$le) - ([datetime]$lo)).TotalHours) } catch { } }
        if ($wDhcp -eq 'remote' -or $wDns -eq 'remote') {
            $remote = if ($wDns -eq 'remote') { $dns1 } else { $dhcp }
            $p = & $pathTo $remote
            $what = if ($wDhcp -eq 'remote' -and $wDns -eq 'remote') { if ($dhcp -eq $dns1) { "DHCP and DNS for this office both come from $dhcp" } else { "DHCP ($dhcp) and DNS ($dns1) for this office both come from servers" } } elseif ($wDns -eq 'remote') { "DNS for this office comes from $dns1" } else { "DHCP for this office comes from $dhcp" }
            if ($p) {
                $ev += "Path to $($p.Target): $($p.Path)"
                if ($null -ne $p.AvgMs) { $ev += "Round trip $($p.AvgMs) ms, loss $($p.LossPct)%, jitter $($p.Jitter) ms" }
                & $add 'DNS and DHCP' 'Confirmed' "$what, which is not on site: it is $($p.HopCount) hops away over a private path. If that path or the far end is down, PCs here cannot get an address or resolve names, so even local internet stops working." $ev
            } else {
                & $add 'DNS and DHCP' 'Likely' "$what on another private network (not this LAN, not the gateway). No trace to it was run, so the path is not confirmed, but it is not on site unless another local subnet exists." $ev
            }
        } elseif ($wDhcp -eq 'gateway' -and ($wDns -eq 'gateway' -or $wDns -eq 'public')) {
            & $add 'DNS and DHCP' 'Confirmed' "The gateway hands out addresses$(if ($wDns -eq 'gateway') { ' and answers DNS' } else { "; DNS goes to public resolvers ($($dnsList -join ', '))" }): basic connectivity does not depend on any server." $ev
        } elseif ($wDhcp -eq 'lan' -or $wDns -eq 'lan') {
            & $add 'DNS and DHCP' 'Confirmed' "DHCP and/or DNS come from a server on this LAN ($((@($dhcp, $dns1) | Where-Object { $_ -and (& $where $_) -eq 'lan' } | Select-Object -Unique) -join ', ')): an on-site server, usually a domain controller." $ev
        } elseif ($wDhcp -eq 'none' -and $dns1) {
            & $add 'DNS and DHCP' 'Confirmed' "This adapter has a static address (no DHCP); DNS is $($dnsList -join ', ')." $ev
        }
        $servers = @(@(Get-Prop $cap 'DhcpServers') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'Server')" } | Select-Object -Unique)
        if ($servers.Count -gt 1) { & $add 'DNS and DHCP' 'Confirmed' "More than one DHCP server answered on this network during the capture: $($servers -join ', '). One of them may be unintended." @("Servers seen: $($servers -join ', ')") }
        $tftp = @(@(Get-Prop $cap 'DhcpServers') | Where-Object { $_ -and ((Get-Prop $_ 'TftpServer') -or (Get-Prop $_ 'TftpAddresses')) }) | Select-Object -First 1
        if ($tftp) { & $add 'Phones' 'Confirmed' "DHCP hands phones a provisioning server: $(Get-Prop $tftp 'TftpServer') $(Get-Prop $tftp 'TftpAddresses')." @("DHCP option 66/150 from $(Get-Prop $tftp 'Server')") }
    }

    # ---- Traffic design, tunnel, internet ----
    $topo = Get-Prop $R 'Topology'
    if (Get-Prop $topo 'Verdict') {
        $c = switch ("$(Get-Prop $topo 'Confidence')") { 'High' { 'Confirmed' } 'Medium-High' { 'Likely' } 'Medium' { 'Likely' } default { 'Possible' } }
        $sig = @(@(Get-Prop $topo 'Signals') | Where-Object { $_ })
        & $add 'Traffic design' $c "Traffic design: $(Get-Prop $topo 'Verdict')." @($sig | Select-Object -First 6)
    }
    $inet = $pings | Where-Object { "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' } | Select-Object -First 1
    $priv = @($pings | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -ne $gw -and $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (Get-IpClass $tp) -eq 'Private' -and (Get-Prop $_ 'Received') })
    $tcps = @(@(Get-Prop $R 'TcpSeries') | Where-Object { $_ })
    if ($priv.Count) {
        $b = $priv | Sort-Object { [double](Get-Prop $_ 'AvgMs') } | Select-Object -First 1
        $worstLoss = ($priv | ForEach-Object { [double](Get-Prop $_ 'LossPct') } | Measure-Object -Maximum).Maximum
        $ev = @($priv | ForEach-Object { "$(Get-Prop $_ 'Target'): avg $(Get-Prop $_ 'AvgMs') ms, p95 $(Get-Prop $_ 'P95Ms') ms, jitter $(Get-Prop $_ 'JitterMs') ms, loss $(Get-Prop $_ 'LossPct')%" })
        if ($inet) { $ev += "Internet (1.1.1.1): avg $(Get-Prop $inet 'AvgMs') ms, jitter $(Get-Prop $inet 'JitterMs') ms, loss $(Get-Prop $inet 'LossPct')%" }
        $pub = $tcps | Where-Object { "$(Get-Prop $_ 'Address')" -and (Get-IpClass "$(Get-Prop $_ 'Address')") -eq 'Public' } | Select-Object -First 1
        $t = "Servers and desktops across the private tunnel answer in $(Get-Prop $b 'AvgMs') ms with $worstLoss% loss and $(Get-Prop $b 'JitterMs') ms jitter over $(Get-Prop $b 'Sent') samples."
        if ($pub) { $ev += "$(Get-Prop $pub 'Target') tcp/$(Get-Prop $pub 'Port') over the public internet: avg $(Get-Prop $pub 'AvgMs') ms, p95 $(Get-Prop $pub 'P95Ms') ms"; if ([double](Get-Prop $pub 'AvgMs') -gt 1.3 * [double](Get-Prop $b 'AvgMs')) { $t += " The public route to the provider ($(Get-Prop $pub 'AvgMs') ms average, $(Get-Prop $pub 'P95Ms') ms at the 95th percentile) is slower and less steady than the tunnel." } }
        & $add 'Tunnel' 'Confirmed' $t $ev
    }
    $mtu = @(@(Get-Prop $R 'Mtu') | Where-Object { $_ })
    $mtuPriv = $mtu | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (Get-IpClass $tp) -eq 'Private' } | Select-Object -First 1
    $mtuInet = $mtu | Where-Object { "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' } | Select-Object -First 1
    if ($mtuPriv -and (Get-Prop $mtuPriv 'MtuBytes')) {
        $mb = [int](Get-Prop $mtuPriv 'MtuBytes')
        if ($mb -lt 1500) { & $add 'Tunnel' 'Confirmed' "The largest packet that crosses the tunnel unfragmented is $mb bytes ($(1500 - $mb) bytes of tunnel overhead); the internet path carries $(Get-Prop $mtuInet 'MtuBytes')." @("Probe target $(Get-Prop $mtuPriv 'Target')") }
        else { & $add 'Tunnel' 'Confirmed' 'Full 1500-byte packets cross the tunnel path unfragmented (no visible tunnel overhead to this target).' @("Probe target $(Get-Prop $mtuPriv 'Target')") }
    } elseif ($mtuPriv) { & $add 'Tunnel' 'Possible' 'The tunnel packet size limit could not be measured (the far end does not answer large pings).' @("Probe target $(Get-Prop $mtuPriv 'Target'): $(Get-Prop $mtuPriv 'Note')") }

    $pubIp = "$(Get-Prop $eg 'PublicIPv4')"
    if ($pubIp) {
        $own = Get-Prop $eg 'Owner'
        $carrierTxt = @("$(Get-Prop $eg 'Carrier')", "$(Get-Prop $eg 'EgressCity')" | Where-Object { $_ -and $_ -ne ', ' })
        $t = "Internet leaves this office from $pubIp$(if ($carrierTxt.Count -eq 2) { " on $($carrierTxt[0]) ($($carrierTxt[1]))" } elseif ($carrierTxt.Count) { " ($($carrierTxt[0]))" })."
        $ev = @(); if (Get-Prop $eg 'IpInfo', 'Hostname') { $ev += "Reverse name: $(Get-Prop $eg 'IpInfo', 'Hostname')" }
        if (Get-Prop $own 'RegisteredTo') {
            $t += " The address block $(Get-Prop $own 'Range') is registered to $(Get-Prop $own 'RegisteredTo')"
            if (Get-Prop $own 'Address') { $t += " at $(Get-Prop $own 'Address')" }
            if (Get-Prop $own 'Registered') { $t += " since $(Get-Prop $own 'Registered')" }
            $t += '.'
            if ("$(Get-Prop $own 'RegisteredTo')" -match $ProviderAsn) { $t += ' That is the hosted desktop provider, not the client, so the provider is probably the account holder for this circuit.' }
            $ev += "Whois block $(Get-Prop $own 'Block') ($(Get-Prop $own 'Type')); chain: $(@(Get-Prop $own 'Chain') -join ' > ')"
        }
        & $add 'Internet service' 'Confirmed' $t $ev
        $t1 = $traces | Where-Object { "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' } | Select-Object -First 1
        $an = Get-Prop $t1 'Analysis'
        if ($an) {
            if ((Get-Prop $an 'CgnatHops') -gt 0) { & $add 'Internet service' 'Confirmed' 'The carrier puts this circuit behind carrier-grade NAT: there is no public address of its own, so inbound connections and some VPNs will not work.' @("Trace: $((@(Get-Prop $t1 'Hops') | Select-Object -First 5 | ForEach-Object { "$(Get-Prop $_ 'IP') [$(Get-Prop $_ 'Class')]" }) -join ' > ')") }
            elseif (Get-Prop $an 'DoubleNatLikely') { & $add 'Internet service' 'Likely' "There are two layers of NAT (for example an ISP modem in router mode in front of the firewall): $((@(Get-Prop $an 'PrivateHopsAfterGw')) -join ', ')." @() }
            elseif (-not (Get-Prop $an 'TunnelIndicator')) { & $add 'Internet service' 'Confirmed' 'One NAT at the gateway, then straight onto the carrier: no carrier NAT, no second router in the path.' @("First public hop: $(Get-Prop $an 'FirstPublicIP') at $(Get-Prop $an 'FirstPublicMs') ms ($(Get-Prop $an 'FirstPublicPtr'))") }
        }
        # Access type from the latency step into the carrier: an inference, kept at Possible.
        $steps = @()
        foreach ($t in @($traces | Where-Object { @('1.1.1.1', '8.8.8.8') -contains "$(Get-Prop $_ 'Target')" })) {
            $pubHops = @(@(Get-Prop $t 'Hops') | Where-Object { $_ -and "$(Get-Prop $_ 'Class')" -eq 'Public' -and $null -ne (Get-Prop $_ 'AvgMs') } | Select-Object -First 2)
            if ($pubHops.Count -eq 2) { $steps += [double](Get-Prop $pubHops[1] 'AvgMs') }
        }
        if ($steps.Count) {
            $s2 = ($steps | Measure-Object -Minimum).Minimum
            $acc = Get-AccessType "$(Get-Prop $eg 'Carrier')"
            # When the carrier's name already says satellite or cellular, the hop timing guess adds nothing
            if ($acc -and $acc -notlike 'cable') { }
            elseif ($s2 -ge 8) { & $add 'Internet service' 'Possible' "The second carrier hop is $s2 ms away. That latency step is typical of cable (DOCSIS) or fixed wireless access; fiber usually shows 1 to 4 ms there." @("Second public hop latency per trace: $($steps -join ', ') ms") }
            elseif ($s2 -le 4) { & $add 'Internet service' 'Possible' "The second carrier hop is only $s2 ms away, which is typical of a fiber hand-off." @("Second public hop latency per trace: $($steps -join ', ') ms") }
        }
    }
    $accessType = Get-AccessType "$(Get-Prop $eg 'Carrier')"
    if ($accessType) { & $add 'Internet service' 'Likely' "The circuit is $accessType, going by the carrier's network name ($(Get-Prop $eg 'Carrier'))." @() }
    $re = Get-Prop $R 'DnsDiscovery', 'ResolverEgress'
    if ($re -and (Get-Prop $re 'Ip') -and $pubIp -and "$(Get-Prop $re 'Ip')" -ne $pubIp) {
        # Where name lookups leave depends on which DNS servers the PC uses. Public resolvers always look
        # up names from their own servers; only a private DNS server exiting elsewhere means a tunnel.
        $dnsSrv = @(@(Get-Prop $R 'NetworkExtra', 'DnsServers') | ForEach-Object { "$(Get-Prop $_ 'Server')" } | Where-Object { Test-IPv4 $_ })
        $allPublic = $dnsSrv.Count -and -not @($dnsSrv | Where-Object { (Get-IpClass $_) -ne 'Public' }).Count
        if ($allPublic) {
            & $add 'DNS and DHCP' 'Confirmed' "Name lookups go straight to public resolvers ($($dnsSrv -join ', ')), so they reach the internet from the resolver's own servers ($(Get-Prop $re 'Ip'), $(Get-Prop $re 'Org')), not from this office. That is normal for public DNS." @("whoami.akamai.net answered $(Get-Prop $re 'Ip')")
        } else {
            & $add 'DNS and DHCP' 'Confirmed' "Name lookups reach the internet from $(Get-Prop $re 'Ip') ($(Get-Prop $re 'Org'), $(Get-Prop $re 'City')), not from this office's own address ($pubIp): the site's DNS server forwards them from somewhere else (the far end of a tunnel, or a filtering service), so content networks may place these users there." @("whoami.akamai.net answered $(Get-Prop $re 'Ip')", "DNS servers: $($dnsSrv -join ', ')")
        }
    }

    # ---- Gateway ----
    $idDevs = @(@(Get-Prop $R 'Identify', 'Devices') | Where-Object { $_ })
    $gwId = $idDevs | Where-Object { "$(Get-Prop $_ 'IP')" -eq $gw } | Select-Object -First 1
    $gwVendor = "$(Get-Prop $R 'NetworkExtra', 'GatewayVendor')"
    $gwModel = Get-Prop $R 'GatewayModel'
    $fwPorts = @(@(Get-Prop $R 'FirewallPorts', 'Ports') | Where-Object { $_ -and (Get-Prop $_ 'Open') } | ForEach-Object { Get-Prop $_ 'Port' })
    $webOpen = @(@(Get-Prop $R 'GatewayProbe') | Where-Object { $_ -and (Get-Prop $_ 'Status') } | ForEach-Object { "$(Get-Prop $_ 'Url')" })
    if ($gw) {
        $name = $null; $c = 'Possible'; $ev = @("MAC maker: $gwVendor ($(Get-Prop $R 'NetworkExtra', 'GatewayMac'))")
        if ($gwId -and (Get-Prop $gwId 'Model')) { $name = "$(Get-Prop $gwId 'Vendor') $(Get-Prop $gwId 'Model')"; if (Get-Prop $gwId 'Firmware') { $name += ", firmware $(Get-Prop $gwId 'Firmware')" }; $c = "$(Get-Prop $gwId 'Confidence')"; $ev += @(Get-Prop $gwId 'Evidence') }
        elseif (Get-Prop $gwModel 'Vendor') { $name = "$(Get-Prop $gwModel 'Vendor') $(Get-Prop $gwModel 'Model')".Trim(); $c = 'Likely'; $ev += "$(Get-Prop $gwModel 'Source')" }
        elseif ($gwId -and (Get-Prop $gwId 'Vendor')) { $name = "$(Get-Prop $gwId 'Vendor') ($(Get-Prop $gwId 'Kind'))"; $c = 'Likely'; $ev += @(Get-Prop $gwId 'Evidence') }
        elseif ($gwVendor -and $gwVendor -ne 'Unknown') { $name = "made by $gwVendor (model not readable)" }
        if ($name) {
            $t = "The gateway ($gw) is $name."
            if ($webOpen.Count -or $fwPorts.Count) { $t += " Its admin interface answers from the user network ($((@($webOpen) + @($fwPorts | ForEach-Object { "tcp/$_" })) -join ', '))." }
            & $add 'Gateway' $c $t $ev
        }
    }

    # ---- Equipment that named itself ----
    $vd = @(@(Get-Prop $R 'VendorDiscovery', 'Devices') | Where-Object { $_ })
    if ($vd.Count) {
        $groups = @($vd | Group-Object { ('{0} {1}' -f ("$(Get-Prop $_ 'Protocol')" -replace ' discovery$', ''), $(if (Get-Prop $_ 'ModelFull') { Get-Prop $_ 'ModelFull' } else { Get-Prop $_ 'Model' })).Trim() } | Sort-Object Count -Descending)
        & $add 'Network equipment' 'Confirmed' "$($vd.Count) network devices named themselves: $(($groups | ForEach-Object { "$($_.Count) x $($_.Name)" }) -join ', ')." @($vd | Select-Object -First 12 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name') $(Get-Prop $_ 'Model') firmware $(Get-Prop $_ 'Firmware')" })
    } elseif ($null -ne (Get-Prop $R 'VendorDiscovery')) {
        $ubnt = @(@(Get-Prop $R 'SubnetSweep', 'Devices') | Where-Object { $_ -and "$(Get-Prop $_ 'Vendor')" -match 'Ubiquiti|MikroTik|Routerboard|NETGEAR' }).Count
        if ($ubnt) { & $add 'Network equipment' 'Possible' "$ubnt devices from Ubiquiti, MikroTik or Netgear are on the network but none answered its vendor discovery protocol: discovery is turned off on them, or this PC's firewall dropped the answers. Models have to come from the closet walk." @() }
    }

    # ---- Network layout ----
    $sweep = Get-Prop $R 'SubnetSweep'
    $kinds = @{}
    if ($idDevs.Count) { foreach ($d in $idDevs) { $k = "$(Get-Prop $d 'Kind')"; if (-not $k) { $k = 'Unidentified' }; $kinds[$k] = 1 + [int]$kinds[$k] } }
    else { foreach ($d in @(@(Get-Prop $sweep 'Devices') | Where-Object { $_ })) { $k = "$(Get-Prop $d 'Role')"; if (-not $k) { $k = 'Unidentified' }; $kinds[$k] = 1 + [int]$kinds[$k] } }
    $total = ($kinds.Values | Measure-Object -Sum).Sum
    if ($total) {
        $mix = @($kinds.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Value) $($_.Key)" })
        $groupsPresent = @()
        foreach ($g in @(@('phones', 'phone'), @('cameras', 'camera|recorder'), @('printers', 'printer|copier'), @('computers', 'Windows|thin client|computer'), @('door access', 'door access'), @('payment terminals', 'payment'), @('time clocks', 'time clock'))) { if (@($kinds.Keys | Where-Object { $_ -match $g[1] }).Count) { $groupsPresent += $g[0] } }
        $subnet = "$(Get-Prop $sweep 'Subnet')"; $swept = Get-Prop $sweep 'AddressesSwept'
        $ev = @("Devices by kind: $($mix -join ', ')", "No VLAN tag was seen on this port: $(-not (@(Get-Prop $cap 'VlanTagsSeen') | Where-Object { $_ }))")
        if ($groupsPresent.Count -ge 3) { & $add 'Network layout' 'Confirmed' "One flat network: $($groupsPresent -join ', ') all sit in $subnet together, reachable from this user port with nothing separating them." $ev }
        if ($groupsPresent -contains 'payment terminals') { & $add 'Network layout' 'Confirmed' 'A card payment terminal shares the network with every other device: a card-data compliance concern.' @($ev[0]) }
        if ($swept -and ($total / [double]$swept) -ge 0.6) { & $add 'Network layout' 'Confirmed' "The address range is $([int](100 * $total / [double]$swept))% used ($total of $swept addresses live): little room to grow in one DHCP scope." @("Subnet $subnet") }
    }
    $arpSubs = @(@(Get-Prop $cap 'ArpSubnets') | Where-Object { $_ -and $srcIp -and "$(Get-Prop $_ 'Subnet')" -ne ((& $pre $srcIp) + '.0/24') })
    if ($foreign.Count -or $arpSubs.Count) {
        $ev = @()
        if ($foreign.Count) { $ev += "Devices on this wire announcing addresses outside $srcIp/$mask`: $((@($foreign) | Select-Object -First 8) -join '; ')" }
        foreach ($a in $arpSubs) { $ev += "ARP heard from $(Get-Prop $a 'Subnet'): $(Get-Prop $a 'Hosts') hosts, e.g. $(Get-Prop $a 'Sample')" }
        $nets = @(@($foreign | ForEach-Object { (& $pre (($_ -split ' ')[0])) + '.0/24' }) + @($arpSubs | ForEach-Object { "$(Get-Prop $_ 'Subnet')" }) | Select-Object -Unique)
        & $add 'Network layout' 'Confirmed' "More than one IP range shares this wire: devices in $($nets -join ', ') were heard on a port that sits in $((& $pre $srcIp) + '.0/24'). They are separated by addressing only, not by a VLAN." $ev
    }
    $tags = @(@(Get-Prop $cap 'VlanTagsSeen') | Where-Object { $_ })
    if ($tags.Count) { & $add 'Network layout' 'Confirmed' "Tagged frames for VLAN $($tags -join ', ') reached this port: it is a trunk or hybrid port, and those VLANs exist on the switch." @() }
    if ($voiceVlan) {
        $phoneCount = @($kinds.Keys | Where-Object { $_ -match 'phone' } | ForEach-Object { $kinds[$_] } | Measure-Object -Sum).Sum
        $t = "The switch advertises voice VLAN $voiceVlan to phones."
        if ($phoneCount) { $t += " Yet $phoneCount phones answer in the data subnet, so they are not using it." }
        & $add 'Phones' 'Confirmed' $t @()
    }
    if ($haveCap) {
        $bps = Get-Prop $cap 'BroadcastPerSecond'
        if ($null -ne $bps) {
            $lvl = if ([double]$bps -ge 100) { 'heavy' } elseif ([double]$bps -ge 30) { 'busy' } else { 'ordinary' }
            & $add 'Network layout' 'Likely' "Broadcast traffic on this network is $lvl`: about $bps frames per second reach every port." @("Captured $(Get-Prop $cap 'BroadcastFrames') broadcast frames in $capSecs s (approximate)", "Busiest senders: $((@(Get-Prop $cap 'TopBroadcasters') | Where-Object { $_ } | Select-Object -First 4 | ForEach-Object { "$(Get-Prop $_ 'Mac') $(Get-Prop $_ 'Vendor') ($(Get-Prop $_ 'Frames'))" }) -join '; ')")
        }
        $ra = @(@(Get-Prop $cap 'Ipv6RouterAdvertisers') | Where-Object { $_ })
        if ($ra.Count) { & $add 'Network layout' 'Confirmed' "IPv6 router advertisements are being sent on this network by $(($ra | ForEach-Object { "$(Get-Prop $_ 'Mac') $(Get-Prop $_ 'Vendor')" }) -join ', '). If that is not the gateway, something else is offering itself as a router." @() }
    }

    # ---- Phones and Windows machines ----
    $ph = @($idDevs | Where-Object { "$(Get-Prop $_ 'Kind')" -match 'phone' })
    if ($ph.Count) {
        $models = @($ph | Where-Object { Get-Prop $_ 'Model' } | Group-Object { "$(Get-Prop $_ 'Vendor') $(Get-Prop $_ 'Model')" } | Sort-Object Count -Descending | ForEach-Object { "$($_.Count) x $($_.Name)" })
        $slow = @($ph | Where-Object { "$(Get-Prop $_ 'PassThrough')" -eq '10/100' }).Count; $fast = @($ph | Where-Object { "$(Get-Prop $_ 'PassThrough')" -eq 'Gigabit' }).Count
        if ($models.Count) { & $add 'Phones' 'Confirmed' "$($ph.Count) desk phones; models read from the phones themselves: $($models -join ', ')." @() }
        if ($slow) { & $add 'Phones' 'Likely' "$slow of $($ph.Count) phones are models whose PC pass-through port is 10/100 only ($fast are gigabit). Any PC plugged in behind one of those links at 100 Mbps regardless of the switch." @('From the model numbers reported by the phones') }
        elseif ($fast -and $link -and [double]$link -lt 1000 -and $wired) { & $add 'Phones' 'Likely' "The phones that reported a model have gigabit pass-through ports, so a phone is not the reason for the $link Mbps link here: look at the cable or the switch port." @() }
    }
    $smb1 = @($idDevs | Where-Object { Get-Prop $_ 'Smb', 'Smb1Enabled' })
    if ($smb1.Count) { & $add 'Windows machines' 'Confirmed' "The old SMB1 file-sharing protocol is still enabled on $($smb1.Count) machines: $((@($smb1) | Select-Object -First 8 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name')" }) -join ', ')." @() }
    $smbAll = @($idDevs | Where-Object { Get-Prop $_ 'Smb', 'Smb2Dialect' })
    if ($smbAll.Count) {
        $unsigned = @($smbAll | Where-Object { -not (Get-Prop $_ 'Smb', 'SigningRequired') }).Count
        & $add 'Windows machines' 'Confirmed' "$($smbAll.Count) machines answer Windows file sharing; $unsigned of them do not require signed connections." @("Dialects: $((@($smbAll | Group-Object { "$(Get-Prop $_ 'Smb', 'Smb2Dialect')" } | ForEach-Object { "SMB $($_.Name) x $($_.Count)" })) -join ', ')")
    }

    # ---- Other offices and the directory ----
    $sr = @(@(Get-Prop $R 'SiteReach', 'Targets') | Where-Object { $_ })
    $reach = @($sr | Where-Object { (Get-Prop $_ 'PingReplies') -gt 0 -or "$(Get-Prop $_ 'LastHopIp')" -eq "$(Get-Prop $_ 'Target')" })
    if ($sr.Count) {
        if ($reach.Count) {
            $tunnelHops = @($traces | Where-Object { $tp = "$(Get-Prop $_ 'Target')"; $tp -match '^\d+\.\d+\.\d+\.\d+$' -and (Get-IpClass $tp) -eq 'Private' } | ForEach-Object { @(Get-Prop $_ 'Hops') | Where-Object { $_ -and (Get-Prop $_ 'IP') } | Select-Object -First 1 } | ForEach-Object { "$(Get-Prop $_ 'IP')" } | Select-Object -Unique)
            $via = @($reach | Where-Object { $h = @(@(Get-Prop $_ 'Hops') | Where-Object { $_ -and (Get-Prop $_ 'IP') } | ForEach-Object { "$(Get-Prop $_ 'IP')" }); @($h | Where-Object { $tunnelHops -contains $_ }).Count -gt 0 })
            $t = "Other office networks answer from here: $(($reach | ForEach-Object { "$(Get-Prop $_ 'Target') ($(Get-Prop $_ 'AvgMs') ms)" }) -join ', ')."
            if ($via.Count -and $tunnelHops.Count) { $t += " The path to them goes through the same tunnel hop as the hosted desktop or data center ($($tunnelHops -join ', ')): offices talk to each other through the provider, not directly." }
            & $add 'Other offices' 'Confirmed' $t @($sr | ForEach-Object { "$(Get-Prop $_ 'Target'): $(Get-Prop $_ 'PingReplies')/3 pings, path $(Get-Prop $_ 'Path')" })
        } else {
            & $add 'Other offices' 'Likely' 'None of the other office gateways tried answered from here: either the addressing guess is wrong for them, or offices cannot reach each other.' @($sr | ForEach-Object { "$(Get-Prop $_ 'Target'): path $(Get-Prop $_ 'Path')" })
        }
    }
    $ss = @(@(Get-Prop $R 'DnsDiscovery', 'SubnetSummary') | Where-Object { $_ -and (Get-Prop $_ 'Names') -gt 0 })
    if ($ss.Count) { & $add 'Other offices' 'Confirmed' "The site DNS server holds reverse names for these networks: $(($ss | ForEach-Object { "$(Get-Prop $_ 'Subnet') ($(Get-Prop $_ 'Names') names)" }) -join ', '). The names are in the saved data and identify devices at offices not visited." @() }
    $rd = Get-Prop $R 'DnsDiscovery', 'RootDse'
    if ($rd -and (Get-Prop $rd 'DnsHostName')) {
        & $add 'Directory' 'Confirmed' "The DNS server is domain controller $(Get-Prop $rd 'DnsHostName') for $(Get-Prop $rd 'DefaultNamingContext'), domain functional level $(Get-Prop $rd 'DomainLevel'), forest $(Get-Prop $rd 'ForestLevel')." @("Server object: $(Get-Prop $rd 'ServerName')", "Domain controllers in DNS: $((@(Get-Prop $R 'DnsDiscovery', 'DomainControllers') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'Target')" } | Select-Object -Unique) -join ', ')")
    }

    # ================= v1.7.0 evidence =================
    # ---- ISP modem page ----
    foreach ($m in @(@(Get-Prop $R 'IspModem', 'Targets') | Where-Object { $_ -and (Get-Prop $_ 'LooksLike') })) {
        $pg = @(@(Get-Prop $m 'Pages') | Where-Object { $_ }) | Select-Object -First 1
        $c = if ("$(Get-Prop $m 'LooksLike')" -like 'ISP device*') { 'Possible' } else { 'Confirmed' }
        & $add 'Internet service' $c "A device answers at $(Get-Prop $m 'Address') ($(Get-Prop $m 'Role')): $(Get-Prop $m 'LooksLike')." @("Page title: $(Get-Prop $pg 'Title')", "Server: $(Get-Prop $pg 'Server')", "Page text: $(Get-Prop $pg 'BodySample')")
    }
    # ---- No access control on the port ----
    if ($wired -and $srcIp -and (Get-Prop $ad 'DhcpEnabled') -and $haveCap -and -not (Get-Prop $cap 'EapolFrames')) {
        & $add 'Network layout' 'Confirmed' "No network access control on this port: a laptop the network had never seen was given an address ($srcIp) and full reach with no authentication." @('No 802.1X (EAPOL) frame was seen on the port', "Devices reachable from it: $total")
    }
    foreach ($dup in @(@(Get-Prop $cap 'ArpConflicts') | Where-Object { $_ })) { & $add 'Network layout' 'Confirmed' "Address conflict: $(Get-Prop $dup 'IP') is being claimed by two devices ($(Get-Prop $dup 'Macs'))." @() }

    # ---- SNMP ----
    $snmp = Get-Prop $R 'Snmp'
    $sd = @(@(Get-Prop $snmp 'Devices') | Where-Object { $_ })
    if ($snmp -and $sd.Count) {
        & $add 'Network equipment' 'Confirmed' "$($sd.Count) devices answer SNMP with the default community '$(Get-Prop $snmp 'Community')': anyone on this network can read their configuration details. $((@($sd | Select-Object -First 10 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'SysName')" })) -join ', ')." @($sd | Select-Object -First 8 | ForEach-Object { "$(Get-Prop $_ 'IP'): $(Get-Prop $_ 'SysDescr')" })
        $macKind = @{}
        foreach ($d in $idDevs) { $macKind["$(Get-Prop $d 'Mac')"] = "$(Get-Prop $d 'Kind')" }
        $myMacs = @(@(Get-Prop $net 'Adapters') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'MacAddress')" } | Where-Object { $_ })
        foreach ($s in @($sd | Where-Object { @(Get-Prop $_ 'Ports').Count -ge 5 })) {
            $ports = @(@(Get-Prop $s 'Ports') | Where-Object { $_ }); $upPorts = @($ports | Where-Object { Get-Prop $_ 'Up' })
            $slow = @($upPorts | Where-Object { $sp = Get-Prop $_ 'SpeedMbps'; $null -ne $sp -and [double]$sp -gt 0 -and [double]$sp -lt 1000 })
            $label = (@("$(Get-Prop $s 'SysName')", "$(Get-Prop $s 'Model')") | Where-Object { $_ }) -join ', '; if (-not $label) { $label = "$(Get-Prop $s 'IP')" }
            $ev = @("$(Get-Prop $s 'IP'): $(Get-Prop $s 'SysDescr')", "Up for $(Get-Prop $s 'UptimeDays') days; serial $(Get-Prop $s 'Serial'); software $(Get-Prop $s 'Software')")
            if ($null -ne (Get-Prop $s 'PoeWattsUsed')) { $ev += "PoE: $(Get-Prop $s 'PoeWattsUsed') W in use of $(Get-Prop $s 'PoeWattsBudget') W" }
            $t = "Switch $label`: $(Get-Prop $s 'PortSummary')."
            if ($slow.Count) { $t += " $($slow.Count) of its live ports run below 1 Gbps: $((@($slow | Select-Object -First 16 | ForEach-Object { "$(Get-Prop $_ 'Name') ($(Get-Prop $_ 'SpeedMbps'))" })) -join ', ')." }
            & $add 'Switching' 'Confirmed' $t $ev
            $mt = @(@(Get-Prop $s 'MacTable') | Where-Object { $_ })
            if ($mt.Count) {
                $mine = $mt | Where-Object { $myMacs -contains "$(Get-Prop $_ 'Mac')" } | Select-Object -First 1
                if ($mine) {
                    $onPort = @($mt | Where-Object { "$(Get-Prop $_ 'Port')" -eq "$(Get-Prop $mine 'Port')" })
                    $pinfo = $ports | Where-Object { "$(Get-Prop $_ 'Name')" -eq "$(Get-Prop $mine 'Port')" } | Select-Object -First 1
                    if ($onPort.Count -le 3) {
                        $others = @($onPort | Where-Object { $myMacs -notcontains "$(Get-Prop $_ 'Mac')" } | ForEach-Object { $k = $macKind["$(Get-Prop $_ 'Mac')"]; "$(Get-Prop $_ 'Mac')$(if ($k) { " ($k)" })" })
                        $t2 = "This laptop is on $label port $(Get-Prop $mine 'Port'), which the switch reports at $(Get-Prop $pinfo 'SpeedMbps') Mbps."
                        if ($others.Count) { $t2 += " The same port also carries $($others -join ', '): the laptop is plugged in behind that device." }
                        & $add 'Switch port' 'Confirmed' $t2 @("From the switch's own forwarding table ($($mt.Count) addresses)")
                    }
                }
                # Ports that carry a phone and one other device: a PC plugged into the back of a phone.
                $byPort = @($mt | Group-Object { "$(Get-Prop $_ 'Port')" } | Where-Object { $_.Count -ge 2 -and $_.Count -le 3 })
                $behind = @($byPort | Where-Object { @($_.Group | Where-Object { $macKind["$(Get-Prop $_ 'Mac')"] -match 'phone' }).Count -ge 1 })
                if ($behind.Count) {
                    $slowBehind = @($behind | Where-Object { $pn = $_.Name; $pp = $ports | Where-Object { "$(Get-Prop $_ 'Name')" -eq $pn } | Select-Object -First 1; $pp -and $null -ne (Get-Prop $pp 'SpeedMbps') -and [double](Get-Prop $pp 'SpeedMbps') -lt 1000 })
                    & $add 'Phones' 'Confirmed' "On $label, $($behind.Count) ports carry a desk phone plus one more device: PCs or thin clients plugged into the back of a phone. $($slowBehind.Count) of those ports run below 1 Gbps." @("Ports: $((@($behind | Select-Object -First 20 | ForEach-Object { $_.Name })) -join ', ')")
                }
            }
        }
        $pr = @($sd | Where-Object { (Get-Prop $_ 'Printer', 'Serial') -or (Get-Prop $_ 'Printer', 'PageCount') })
        if ($pr.Count) { & $add 'Printers' 'Confirmed' "$($pr.Count) printers gave serial numbers and lifetime page counts over SNMP." @($pr | Select-Object -First 15 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Printer', 'Model'): serial $(Get-Prop $_ 'Printer', 'Serial'), $(Get-Prop $_ 'Printer', 'PageCount') pages" }) }
    } elseif ($snmp -and $null -ne (Get-Prop $snmp 'Asked')) {
        & $add 'Network equipment' 'Confirmed' "No device answered SNMP with the community '$(Get-Prop $snmp 'Community')' ($(Get-Prop $snmp 'Asked') asked): SNMP is off or the community was changed." @()
    }
    # Devices that restarted together (uptime from discovery and SNMP)
    $ups = @(@($vd | ForEach-Object { if (Get-Prop $_ 'UptimeSec') { [pscustomobject]@{ Name = "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name')"; Days = [math]::Round([double](Get-Prop $_ 'UptimeSec') / 86400, 1) } } }) + @($sd | ForEach-Object { if ($null -ne (Get-Prop $_ 'UptimeDays')) { [pscustomobject]@{ Name = "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'SysName')"; Days = [double](Get-Prop $_ 'UptimeDays') } } }) | Where-Object { $_ })
    if ($ups.Count -ge 3) {
        $grp = @($ups | Group-Object { [math]::Round($_.Days) } | Sort-Object Count -Descending | Select-Object -First 1)
        if ($grp.Count -and $grp[0].Count -ge 3 -and [double]$grp[0].Name -lt 60) { & $add 'Network equipment' 'Likely' "$($grp[0].Count) network devices all restarted about $($grp[0].Name) days ago: a power event or maintenance at that time." @($grp[0].Group | Select-Object -First 8 | ForEach-Object { "$($_.Name): up $($_.Days) days" }) }
    }

    # ---- Windows versions ----
    $wh = @(@(Get-Prop $R 'WindowsHosts', 'Hosts') | Where-Object { $_ -and (Get-Prop $_ 'Build') })
    if ($wh.Count) {
        $w10 = @($wh | Where-Object { $b = [int](Get-Prop $_ 'Build'); $b -ge 10240 -and $b -le 19045 }); $old = @($wh | Where-Object { [int](Get-Prop $_ 'Build') -lt 10240 })
        $t = "$($wh.Count) Windows machines on this network reported their version: $((@(Get-Prop $R 'WindowsHosts', 'OsSummary')) -join '; ')."
        if ($w10.Count -or $old.Count) { $t += " $($w10.Count + $old.Count) of them run Windows 10 or older, which is out of support." }
        & $add 'Windows machines' 'Confirmed' $t @($wh | Select-Object -First 20 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'ComputerName') ($(Get-Prop $_ 'DnsDomain')): $(Get-Prop $_ 'OsVersion')" })
    }

    # ---- DNS timing and fallback ----
    $dt = @(@(Get-Prop $R 'DnsTiming', 'Servers') | Where-Object { $_ })
    $site = $dt | Where-Object { "$(Get-Prop $_ 'Role')" -eq 'Site DNS server' -and $null -ne (Get-Prop $_ 'MedianMs') } | Select-Object -First 1
    $pubDns = @($dt | Where-Object { "$(Get-Prop $_ 'Role')" -like 'Public*' })
    $pubOk = $pubDns | Where-Object { (Get-Prop $_ 'Answered') -gt 0 -and $null -ne (Get-Prop $_ 'MedianMs') } | Sort-Object { [double](Get-Prop $_ 'MedianMs') } | Select-Object -First 1
    if ($dt.Count) {
        $ev = @($dt | ForEach-Object { "$(Get-Prop $_ 'Server') ($(Get-Prop $_ 'Role')): answered $(Get-Prop $_ 'Answered') of $(Get-Prop $_ 'Asked'), median $(Get-Prop $_ 'MedianMs') ms" })
        if ($site -and (Get-IpClass "$(Get-Prop $site 'Server')") -eq 'Public') {
            # The site's DNS servers are public resolvers already: no fallback advice to give
            & $add 'DNS and DHCP' 'Confirmed' "DHCP hands out public resolvers as DNS servers; a lookup through $(Get-Prop $site 'Server') takes $(Get-Prop $site 'MedianMs') ms." $ev
        } elseif ($site -and $pubOk) {
            & $add 'DNS and DHCP' 'Confirmed' "A name lookup through the site's DNS server takes $(Get-Prop $site 'MedianMs') ms; the same lookup sent straight to a public resolver takes $(Get-Prop $pubOk 'MedianMs') ms. Public DNS is reachable from this office, so listing a second DNS server in DHCP would keep internet working when the path to $(Get-Prop $site 'Server') is down." $ev
        } elseif ($site -and $pubDns.Count) {
            & $add 'DNS and DHCP' 'Confirmed' "Public DNS resolvers do not answer from this office (outbound DNS is blocked), so the site's DNS server ($(Get-Prop $site 'Server'), $(Get-Prop $site 'MedianMs') ms per lookup) is the only way to resolve names." $ev
        }
        $gwDns = $dt | Where-Object { "$(Get-Prop $_ 'Role')" -eq 'Gateway' -and (Get-Prop $_ 'Answered') -gt 0 } | Select-Object -First 1
        if ($gwDns) { & $add 'DNS and DHCP' 'Confirmed' "The gateway itself answers DNS ($(Get-Prop $gwDns 'MedianMs') ms) although DHCP does not hand it out: it could serve as the local resolver." @() }
    }

    # ---- Cloud services ----
    $cl = Get-Prop $R 'Cloud'
    $m365 = @(@(Get-Prop $cl 'Microsoft365') | Where-Object { $_ -and $null -ne (Get-Prop $_ 'ConnectMs') })
    if ($m365.Count) {
        $worst = ($m365 | ForEach-Object { [double](Get-Prop $_ 'ConnectMs') } | Measure-Object -Maximum).Maximum
        $lvl = if ($worst -le 60) { 'well within' } elseif ($worst -le 120) { 'within' } else { 'outside' }
        & $add 'Cloud services' 'Confirmed' "Microsoft 365 front doors answer in $((@($m365 | ForEach-Object { "$(Get-Prop $_ 'ConnectMs') ms ($("$(Get-Prop $_ 'Host')".Split('.')[0]))" })) -join ', ') from this office, $lvl what Microsoft 365 needs." @("Path to Outlook: $(Get-Prop $cl 'OutlookPath')")
    }
    if ($cl -and $null -ne (Get-Prop $cl 'NatBehaviour')) {
        $t = if (Get-Prop $cl 'TeamsMediaPortOpen') { 'The Teams media relay answers on UDP 3478 from this office.' } else { 'The Teams media relay did not answer on UDP 3478: calls would fall back to TCP, with worse quality.' }
        & $add 'Cloud services' 'Confirmed' "$t NAT behaviour: $(Get-Prop $cl 'NatBehaviour')." @(@(Get-Prop $cl 'Stun') | Where-Object { $_ } | ForEach-Object { "$(Get-Prop $_ 'Server'): answered $(Get-Prop $_ 'Answered'), public port $(Get-Prop $_ 'MappedPort') for local port $(Get-Prop $_ 'LocalPort'), $(Get-Prop $_ 'Ms') ms" })
    }

    # ---- Voice sample ----
    foreach ($v in @(@(Get-Prop $R 'Voice', 'Samples') | Where-Object { $_ -and (Get-Prop $_ 'Sent') -gt 0 })) {
        $tg = "$(Get-Prop $v 'Target')"
        $what = if ((Get-IpClass $tg) -eq 'Private') { "the phone system path ($tg, across the tunnel)" } else { "the internet path ($tg), which a cloud phone service would use" }
        & $add 'Phones' 'Confirmed' "Call quality over ${what}: estimated score $(Get-Prop $v 'Mos') of 4.4 ($(Get-Prop $v 'Rating')). Loss $(Get-Prop $v 'LossPct')%, jitter $(Get-Prop $v 'JitterMs') ms, longest gap $(Get-Prop $v 'LongestLossBurst') packets." @("$(Get-Prop $v 'Sent') packets at $(Get-Prop $v 'PacketsPerSecond') per second; average $(Get-Prop $v 'AvgMs') ms, 99th percentile $(Get-Prop $v 'P99Ms') ms, worst $(Get-Prop $v 'MaxMs') ms", 'Score is an estimate from ping timing, which is coarser than real call traffic')
    }

    # ---- Printers and cameras that described themselves ----
    $pq = @(@(Get-Prop $R 'PrinterQuery', 'Printers') | Where-Object { $_ -and (Get-Prop $_ 'MakeAndModel') })
    if ($pq.Count) { & $add 'Printers' 'Confirmed' "$($pq.Count) printers described themselves: $((@($pq | Group-Object { "$(Get-Prop $_ 'MakeAndModel')" } | Sort-Object Count -Descending | ForEach-Object { "$($_.Count) x $($_.Name)" })) -join ', ')." @($pq | Select-Object -First 15 | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'MakeAndModel'): firmware $(Get-Prop $_ 'Firmware'), pages $(Get-Prop $_ 'PagesPrinted'), state $(Get-Prop $_ 'StateReasons')" }) }
    $cq = @(@(Get-Prop $R 'CameraQuery', 'Cameras') | Where-Object { $_ -and (Get-Prop $_ 'Server') })
    if ($cq.Count) { & $add 'Cameras' 'Confirmed' "$($cq.Count) cameras or recorders named their software over RTSP: $((@(Get-Prop $R 'CameraQuery', 'ServerSummary')) -join '; ')." @($cq | Select-Object -First 12 | ForEach-Object { "$(Get-Prop $_ 'IP'): $(Get-Prop $_ 'Server')" }) }

    # ---- Outbound filtering ----
    $ob = Get-Prop $R 'Outbound'
    if ($ob -and @(Get-Prop $ob 'PortsTried').Count) {
        $blocked = @(@(Get-Prop $ob 'Blocked') | Where-Object { $null -ne $_ }); $open = @(@(Get-Prop $ob 'Open') | Where-Object { $null -ne $_ })
        if (-not (Get-Prop $ob 'Reliable')) { & $add 'Internet service' 'Possible' 'The outbound port test was inconclusive: the public test host did not accept connections, so nothing can be said about outbound filtering from this run.' @("Open: $($open -join ', ')") }
        elseif ($open.Count -and $blocked.Count -le 3) { & $add 'Internet service' 'Confirmed' "The gateway does not filter outbound traffic: $($open.Count) of $($open.Count + $blocked.Count) test ports connect out$(if ($blocked.Count) { " (not $($blocked -join ', '), which carriers commonly block)" })." @("Open: $($open -join ', ')") }
        elseif ($open.Count) { & $add 'Internet service' 'Confirmed' "Outbound traffic is filtered: $($blocked.Count) of $($open.Count + $blocked.Count) test ports are blocked ($($blocked -join ', '))." @("Open: $($open -join ', ')") }
        $dn = @(@(Get-Prop $ob 'DnsTests') | Where-Object { $_ })
        if ($dn.Count) {
            if (Get-Prop $ob 'FilteringSeen') { & $add 'Internet service' 'Confirmed' "A DNS security filter is in place: known test names are blocked ($((@($dn | Where-Object { Get-Prop $_ 'Filtered' } | ForEach-Object { "$(Get-Prop $_ 'Name')" })) -join ', '))." @($dn | ForEach-Object { "$(Get-Prop $_ 'Name'): site answer $(Get-Prop $_ 'SiteAnswer'); public answer $(Get-Prop $_ 'PublicAnswer')" }) }
            else { & $add 'Internet service' 'Likely' 'No DNS security filtering: test names that filters block resolve normally through the site DNS server.' @($dn | ForEach-Object { "$(Get-Prop $_ 'Name'): site answer $(Get-Prop $_ 'SiteAnswer'); public answer $(Get-Prop $_ 'PublicAnswer')" }) }
        }
    }

    # ---- Email domain ----
    foreach ($p in @(@(Get-Prop $R 'Domains', 'Domains') | Where-Object { $_ })) {
        $spf = Get-Prop $p 'Spf'; $dm = Get-Prop $p 'Dmarc'
        $bits = @()
        $bits += $(if (@(Get-Prop $p 'Mx').Count) { "mail goes to $(Get-Prop $p 'Provider') ($((@(Get-Prop $p 'Mx') | Select-Object -First 2) -join ', '))" } else { 'no MX record (it receives no mail)' })
        $bits += $(if (Get-Prop $spf 'Present') { "SPF ends in $(Get-Prop $spf 'All')" } else { 'no SPF' })
        $bits += $(if (Get-Prop $dm 'Present') { "DMARC p=$(Get-Prop $dm 'Policy')$(if (Get-Prop $dm 'Reports') { ' with reports' })" } else { 'no DMARC' })
        $bits += $(if (@(Get-Prop $p 'DkimSelectors').Count) { "DKIM at $((@(Get-Prop $p 'DkimSelectors')) -join ', ')" } else { 'no DKIM at the usual selectors' })
        if (Get-Prop $p 'MtaSts') { $bits += 'MTA-STS on' }
        & $add 'Email and domain' 'Confirmed' "$(Get-Prop $p 'Domain'): $($bits -join '; ')." @(@("SPF: $(Get-Prop $spf 'Record')", "DMARC: $(Get-Prop $dm 'Record')", "Autodiscover: $(@(Get-Prop $p 'Autodiscover') -join ', ')") | Where-Object { $_ -notmatch ': $' })
    }

    # ---- IPv6 ----
    $v6 = Get-Prop $R 'Ipv6'
    $v6s = "$(Get-Prop $v6 'Status')"
    if ($v6s) {
        $pre = @(@(Get-Prop $v6 'GlobalPrefixes') | Where-Object { $_ })
        $ev6 = @($(if ($pre.Count) { "Global prefix(es): $($pre -join ', ')$(if (Get-Prop $v6 'TemporaryAddresses') { ' (privacy addresses in use)' })" }),
                 $(if (Get-Prop $v6 'DefaultRoute') { "IPv6 default route$(if (Get-Prop $v6 'RouterIsLinkLocal') { ' via the router''s link-local address (router advertisements)' })" } else { 'No IPv6 default route' }),
                 $(if (@(Get-Prop $v6 'DnsServers').Count) { "IPv6 DNS servers: $((@(Get-Prop $v6 'DnsServers')) -join ', ')" }),
                 $(if ($null -ne (Get-Prop $v6 'AaaaLookup')) { "IPv6 (AAAA) name lookups: $(if (Get-Prop $v6 'AaaaLookup') { 'answered' } else { 'no answer' })" }))
        if ($v6s -eq 'Working') {
            $ms = Get-Prop $v6 'Ping', 'AvgMs'
            $t = "IPv6 works here: this PC reaches the internet over IPv6$(if ($null -ne $ms) { " in $ms ms (Cloudflare, $(Get-Prop $v6 'Ping', 'LossPct')% loss)" })."
            if (Get-Prop $v6 'Egress', 'SameAsPc') { $t += ' It leaves from its own address, with no NAT: inbound IPv6 is held back only by the firewall''s IPv6 rules, so they need the same care as the IPv4 ones.' }
            $ob = Get-Prop $R 'Outbound'
            if (@(Get-Prop $ob 'DnsTests').Count) { $t += ' The DNS filtering test above ran over IPv4 only.' }
            & $add 'Internet service' 'Confirmed' $t $ev6
        } elseif ($v6s -eq 'Broken') {
            & $add 'Internet service' 'Confirmed' "IPv6 is offered here but does not reach the internet. Apps try IPv6 first and wait for it to fail, which shows up as slow first connections; fix the IPv6 path or stop advertising it." @($ev6 + @("Cloudflare over IPv6: $(if (Get-Prop $v6 'Egress', 'Error') { Get-Prop $v6 'Egress', 'Error' } else { 'no answer' })"))
        } elseif ($v6s -eq 'Local only') {
            & $add 'Internet service' 'Confirmed' 'Only unique-local IPv6 addresses are in use here (no global prefix and no IPv6 route out): IPv6 works inside the network only.' $ev6
        } else {
            & $add 'Internet service' 'Confirmed' 'IPv6 is not offered on this network: everything runs over IPv4.' $ev6
        }
    }

    # ---- Gateway port mapping ----
    $gs = Get-Prop $R 'GatewayServices'
    if ($gs) {
        $np = [bool](Get-Prop $gs 'NatPmp', 'Answered'); $up = [bool](Get-Prop $gs 'Upnp', 'Found')
        $maps = @(@(Get-Prop $gs 'Upnp', 'Mappings') | Where-Object { $_ })
        if ($np -or $up) {
            $t = "The gateway lets any device on the network open inbound ports by itself ($((@($(if ($up) { 'UPnP' }), $(if ($np) { 'NAT-PMP' })) | Where-Object { $_ }) -join ' and ') is on)."
            if ($maps.Count) { $t += " $($maps.Count) port mappings exist now." }
            & $add 'Gateway' 'Confirmed' $t @($maps | Select-Object -First 12 | ForEach-Object { "$(Get-Prop $_ 'Protocol') $(Get-Prop $_ 'ExternalPort') to $(Get-Prop $_ 'InternalClient'):$(Get-Prop $_ 'InternalPort') ($(Get-Prop $_ 'Description'))" })
        } else { & $add 'Gateway' 'Confirmed' 'The gateway does not offer UPnP or NAT-PMP port mapping.' @() }
    }

    # ---- Routers and UPS over SNMP ----
    foreach ($sd in @(@(Get-Prop $R 'Snmp', 'Devices') | Where-Object { $_ -and (Get-Prop $_ 'Router') })) {
        $rt = Get-Prop $sd 'Router'
        $nm = "$(Get-Prop $sd 'SysName')"; if (-not $nm) { $nm = "$(Get-Prop $sd 'IP')" }
        $wan = @(@(Get-Prop $rt 'WanAddresses') | Where-Object { $_ })
        $t = "Router $nm answered SNMP: $(@(Get-Prop $rt 'Addresses').Count) addresses of its own, $(@(Get-Prop $rt 'Arp').Count) entries in its ARP table and $(@(Get-Prop $rt 'Routes').Count) routes."
        if ($wan.Count) { $t += " Its WAN side is $($wan -join ', '): that is the circuit it serves, even where no machine was run." }
        $pub = "$(Get-Prop $R 'Egress', 'PublicIPv4')"
        if ($wan.Count -and $pub -and $wan -notcontains $pub) { $t += " Traffic from this PC leaves from $pub instead, so another device (an ISP modem doing NAT, or another firewall) is in the path or this router is not this office's exit." }
        $privNets = @(@(Get-Prop $rt 'Addresses') | Where-Object { $_ -and (Get-Prop $_ 'Class') -eq 'Private' } | ForEach-Object { '{0}/{1}' -f (Get-Prop $_ 'IP'), (Get-Prop $_ 'Prefix') })
        & $add 'Network equipment' 'Confirmed' $t @(@("Interfaces with addresses: $($privNets -join ', ')"), $(if (Get-Prop $rt 'DefaultRoute') { "Default route via $(@(Get-Prop $rt 'DefaultRoute') -join ', ')" }), "System: $(Get-Prop $sd 'SysDescr')")
    }
    foreach ($sd in @(@(Get-Prop $R 'Snmp', 'Devices') | Where-Object { $_ -and (Get-Prop $_ 'Ups') })) {
        $u = Get-Prop $sd 'Ups'
        $bits = @("battery $(Get-Prop $u 'Battery')")
        if ($null -ne (Get-Prop $u 'ChargePct')) { $bits += "$(Get-Prop $u 'ChargePct')% charged" }
        if ($null -ne (Get-Prop $u 'MinutesRemaining')) { $bits += "$(Get-Prop $u 'MinutesRemaining') minutes of runtime" }
        if ($null -ne (Get-Prop $u 'LoadPct')) { $bits += "$(Get-Prop $u 'LoadPct')% load" }
        if (Get-Prop $u 'OnBattery') { $bits += 'RUNNING ON BATTERY' }
        if (Get-Prop $u 'ReplaceBattery') { $bits += 'battery needs replacing' }
        & $add 'Network equipment' 'Confirmed' "UPS $((("$(Get-Prop $u 'Manufacturer') $(Get-Prop $u 'Model')").Trim())) at $(Get-Prop $sd 'IP'): $($bits -join ', ')." @("Read over SNMP ($(Get-Prop $u 'Source'))")
    }

    # ---- Active Directory sites ----
    $sites = @(@(Get-Prop $R 'AdSites', 'Sites') | Where-Object { $_ })
    if ($sites.Count) {
        $t = "Active Directory lists $($sites.Count) site(s) in $(Get-Prop $R 'AdSites', 'Forest'): $((@($sites | Select-Object -First 8 | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'Name'), $(if (@(Get-Prop $_ 'Subnets').Count) { (@(Get-Prop $_ 'Subnets') | Select-Object -First 4) -join ', ' } else { 'no subnets' }) })) -join '; ')."
        if (Get-Prop $R 'AdSites', 'CurrentSite') { $t += " This PC belongs to site $(Get-Prop $R 'AdSites', 'CurrentSite')." }
        $empty = @($sites | Where-Object { -not @(Get-Prop $_ 'Subnets').Count })
        if ($empty.Count) { $t += " $($empty.Count) site(s) have no subnets, so their machines log on to whichever domain controller answers first." }
        $ac = Get-AdSiteCheck $R
        $ev = @('Read from Active Directory Sites and Services as the signed-in user')
        if ($ac) {
            $ev += $(if ($ac.AdSubnet) { "This PC's address $($ac.Ip) is in AD subnet $($ac.AdSubnet) (site $($ac.SiteBySubnet))" } else { "This PC's address $($ac.Ip) is in no AD subnet" })
            if ($ac.LogonServer) { $ev += "Logon server: $($ac.LogonServer)$(if ($ac.LogonServerSite) { " in site $($ac.LogonServerSite)" })" }
        }
        & $add 'Network layout' 'Confirmed' $t $ev
    }

    # ---- Follow-up checks on leads ----
    foreach ($c in @(@(Get-Prop $R 'LeadChecks', 'Checks') | Where-Object { $_ })) {
        $area = switch ("$(Get-Prop $c 'Kind')") { 'Firewall' { 'Gateway' } 'Modem' { 'Internet service' } default { 'Network equipment' } }
        & $add $area 'Confirmed' "$(Get-Prop $c 'What') at $(Get-Prop $c 'IP'): $(Get-Prop $c 'Detail')." @("Checked $(Get-Prop $c 'Url')")
    }

    # ---- Remote desktop transport ----
    $rt = Get-RdpTransportCheck $R
    if ($rt -and $rt.Verdict -ne 'Not known' -and @(Get-Prop $R 'Rdp', 'SelectedTargets').Count) {
        $t = switch -Wildcard ($rt.Verdict) {
            'UDP in use' { 'Remote desktop sessions on this PC have been using UDP, the faster transport.' }
            'UDP possible' { 'Remote desktop sessions here can use UDP: it gets out, and the NAT keeps one public port per connection.' }
            'TCP only: UDP turned off*' { 'Remote desktop sessions on this PC can only use TCP: UDP is turned off for the RDP client.' }
            'TCP only: outbound UDP blocked' { 'Remote desktop sessions here can only use TCP: outbound UDP is blocked, so they stall more on packet loss.' }
            'Relayed UDP only*' { 'The NAT here gives each destination its own public port (symmetric NAT), so Azure Virtual Desktop can only use UDP through its TURN relay.' }
            default { "Remote desktop UDP may fail here: $($rt.Verdict)." }
        }
        if (@($rt.Caveats).Count) { $t += " Microsoft lists these as getting in the way of a direct UDP path: $(@($rt.Caveats) -join '; ')." }
        & $add 'Remote desktop' $(if ($rt.Verdict -in @('UDP in use', 'TCP only: outbound UDP blocked') -or $rt.Verdict -like 'TCP only*') { 'Confirmed' } else { 'Likely' }) $t @($rt.Evidence)
    }

    # ---- Other subnets ----
    $rsSubs = @(@(Get-Prop $R 'RemoteSweep', 'Subnets') | Where-Object { $_ })
    if ($rsSubs.Count) {
        $rsDev = @(@(Get-Prop $R 'RemoteSweep', 'Devices') | Where-Object { $_ })
        $t = "Across routing, $($rsDev.Count) devices answered on $($rsSubs.Count) other subnet(s): $((@($rsSubs | ForEach-Object { '{0} ({1})' -f (Get-Prop $_ 'Subnet'), (Get-Prop $_ 'Devices') })) -join ', ')."
        $roles = @(Get-Prop $R 'RemoteSweep', 'RoleSummary' | Where-Object { $_ })
        if ($roles.Count) { $t += " By open ports: $(($roles | Select-Object -First 5) -join '; ')." }
        & $add 'Network layout' 'Confirmed' $t @($rsSubs | ForEach-Object { "$(Get-Prop $_ 'Subnet'): $(Get-Prop $_ 'PingResponders') answered ping, $(Get-Prop $_ 'TcpOnly') only on TCP, $(Get-Prop $_ 'Seconds') s ($(Get-Prop $_ 'Reason'))" })
    }
    $swept = @($rsSubs | ForEach-Object { "$(Get-Prop $_ 'Subnet')" })
    $notSwept = @(@(Get-Prop $R 'RemoteSubnets', 'Candidates') | Where-Object { $_ -and $swept -notcontains "$(Get-Prop $_ 'Cidr')" })
    if ($notSwept.Count) {
        & $add 'Network layout' 'Possible' "This PC knows of $($notSwept.Count) other private subnet(s) that were not swept: $((@($notSwept | Select-Object -First 8 | ForEach-Object { Get-Prop $_ 'Cidr' })) -join ', '). Add the client's ones to `$ScanSubnets to sweep them with -Discovery." @($notSwept | ForEach-Object { "$(Get-Prop $_ 'Cidr'): $((@(Get-Prop $_ 'Reasons') | Select-Object -First 3) -join '; ')$(if (Get-Prop $_ 'Hosted') { ' (remote desktop target here)' })" })
    }

    # ---- Reach across the tunnel ----
    $tr = @(@(Get-Prop $R 'TunnelReach', 'Servers') | Where-Object { $_ -and @(Get-Prop $_ 'OpenPorts' | Where-Object { $null -ne $_ }).Count })
    if ($tr.Count) {
        $rdp = @($tr | Where-Object { @(Get-Prop $_ 'OpenPorts') -contains 3389 }); $smbs = @($tr | Where-Object { @(Get-Prop $_ 'OpenPorts') -contains 445 })
        $t = "From an ordinary office port, $($tr.Count) servers across the tunnel accept connections with no filtering in between."
        if ($rdp.Count) { $t += " Remote Desktop is open on $($rdp.Count) of them ($((@($rdp | Select-Object -First 6 | ForEach-Object { $n = "$(Get-Prop $_ 'Name')"; if ($n) { $n.Split('.')[0] } else { "$(Get-Prop $_ 'IP')" } })) -join ', '))." }
        if ($smbs.Count) { $t += " File sharing is open on $($smbs.Count)." }
        & $add 'Tunnel' 'Confirmed' $t @($tr | ForEach-Object { "$(Get-Prop $_ 'IP') $(Get-Prop $_ 'Name'): ports $((@(Get-Prop $_ 'OpenPorts')) -join ', ')" })
    }
    return $out.ToArray()
}

# =====================================================================
# PHASE 7: analysis, flags, summary
# =====================================================================
function Get-TopologyVerdict {
    # Scores backhaul and split-tunnel signals from one run. Uses $ProviderAsn and $HostedLabel from CONFIG.
    param($Result, [string[]]$RdpHosts = @())
    $signals = @()
    $backhaul = 0; $split = 0
    $eg = $Result['Egress']
    $carrier = Get-Val $eg 'Carrier'
    if ($carrier -match $ProviderAsn) { $backhaul += 3; $signals += "Egress ASN is '$carrier' ($HostedLabel provider): internet exits via the provider" }
    elseif ($carrier) { $signals += "Egress ISP/ASN: $carrier ($(Get-Val $eg 'EgressCity'))" }

    $inet = $Result['Traceroutes'] | Where-Object { $_.Target -eq '1.1.1.1' } | Select-Object -First 1
    if ($inet) {
        $a = $inet.Analysis
        # On its own a private hop is only a hint (some ISPs number their edge privately); it needs a second signal.
        if ($a['TunnelIndicator']) { $backhaul += 1; $signals += "Internet trace crosses private hop(s) with latency before reaching the ISP (tunnel/MPLS or ISP-internal): $($a['PrivateHopsAfterGw'] -join ', ')" }
        elseif ($a['DoubleNatLikely']) { $signals += "Internet trace shows low-latency private hop(s) after gateway (double NAT, e.g. ISP modem + firewall): $($a['PrivateHopsAfterGw'] -join ', ')" }
        elseif ($a['CgnatHops'] -gt 0) { $signals += 'Internet trace goes from the gateway into carrier-grade NAT (ISP-side), i.e. straight out the local circuit' }
        else { $signals += 'Internet trace goes straight from the gateway to a public ISP hop' }
        if (@($a['CarrierPrivateHops']).Count -gt 0) { $signals += "Private hops after the CGNAT hop are carrier-internal, ignored: $($a['CarrierPrivateHops'] -join ', ')" }
        # A distant first public hop only hints at backhaul when it is not just access latency:
        # skip satellite/cellular/CGNAT paths and cases where it roughly equals end-to-end latency.
        $inetPing = @($Result['PingSeries']) | Where-Object { $_ -and $_.Target -eq '1.1.1.1' } | Select-Object -First 1
        $e2e = if ($inetPing) { $inetPing.AvgMs } else { $null }
        $accessLatency = ($a['CgnatHops'] -gt 0) -or ($e2e -and $a['FirstPublicMs'] -ge 0.7 * $e2e)
        if ($a['FirstPublicMs'] -ge 30 -and -not $accessLatency) { $backhaul += 1; $signals += "First public hop is far away ($($a['FirstPublicMs']) ms) compared with end-to-end latency" }
        elseif ($a['FirstPublicMs'] -ge 30) { $signals += "First public hop at $($a['FirstPublicMs']) ms is access-link latency (satellite/cellular/CGNAT or similar), not counted as backhaul" }
        if ($a['FirstPublicPtr']) { $signals += "First public hop rDNS: $($a['FirstPublicPtr'])" }
    }

    $rdpTraces = @($Result['Traceroutes'] | Where-Object { $RdpHosts -contains $_.Target })
    foreach ($t in $rdpTraces) {
        if ($t.Analysis['TunnelIndicator'] -and -not ($inet -and $inet.Analysis['TunnelIndicator'])) { $split += 2; $signals += "RDP trace to $($t.Target) goes through a private tunnel hop that internet traffic does not" }
    }
    foreach ($r in @($Result['RdpPath'])) {
        if ($r -and $r.ResolvesPrivate) { $split += 2; $signals += "RDP host $($r.Host) resolves to a private IP ($($r.ResolvedIPs -join ', ')): reached over a tunnel" }
    }
    $actPriv = @(Get-Val $Result['Rdp'] 'ActiveTcp' | Where-Object { $_.Class -eq 'Private' })
    if ($actPriv.Count -gt 0) { $split += 2; $signals += "Live RDP session is connected to a private IP ($(($actPriv | ForEach-Object { $_.RemoteAddress }) -join ', '))" }

    # DNS on this machine's own subnet is an on-prem server (DC, file server, firewall DNS), not a tunnel.
    # Private DNS on some other subnet hints that DNS is reached over a tunnel; it counts once.
    $localNets = @()
    foreach ($a in @(Get-Val $Result['Network'] 'Adapters' | Where-Object { $_ -and $_.Status -eq 'Up' })) {
        $ips = @($a.IPv4); $masks = @($a.SubnetMask)
        for ($q = 0; $q -lt $ips.Count; $q++) { if ($ips[$q] -and $masks.Count -gt $q) { $localNets += [pscustomobject]@{ Ip = $ips[$q]; Mask = $masks[$q] } } }
    }
    $onPremDns = @(); $remoteDns = @()
    foreach ($d in @(Get-Val $Result['NetworkExtra'] 'DnsServers')) {
        if (-not $d -or $d.Type -notlike 'Private, not the gateway*') { continue }
        if (@($localNets | Where-Object { Test-SameSubnet $d.Server $_.Ip $_.Mask }).Count) { $onPremDns += $d.Server } else { $remoteDns += $d.Server }
    }
    if ($onPremDns.Count) { $signals += "DNS server(s) on this machine's own subnet ($($onPremDns -join ', ')): on-prem server or DC, not a tunnel" }
    if ($remoteDns.Count) { $split += 1; $signals += "DNS server(s) on another private subnet ($($remoteDns -join ', ')): DNS may be reached over a tunnel" }
    $script:OnPremDns = $onPremDns
    $mtu = @($Result['Mtu'])
    $mtuInet = ($mtu | Where-Object { $_.Target -eq '1.1.1.1' } | Select-Object -First 1)
    $mtuRdp = ($mtu | Where-Object { $_.Target -ne '1.1.1.1' } | Select-Object -First 1)
    if ($mtuInet -and $mtuInet.MtuBytes -and $mtuInet.MtuBytes -lt 1500) { $signals += "Internet path MTU is $($mtuInet.MtuBytes) (PPPoE or tunnel overhead)"; if ($mtuInet.MtuBytes -lt 1440) { $backhaul += 1 } }
    if ($mtuRdp -and $mtuRdp.MtuBytes -and $mtuRdp.MtuBytes -lt 1440 -and (-not $mtuInet.MtuBytes -or $mtuInet.MtuBytes -ge 1492)) { $split += 1; $signals += "RDP path MTU is $($mtuRdp.MtuBytes) while internet is $($mtuInet.MtuBytes): tunnel to RDP" }
    if (Get-Val $Result['Network'] 'VpnHoldsDefaultRoute') { $backhaul += 2; $signals += 'A client VPN adapter holds the default route on this PC (full tunnel)' }

    $verdict = 'Local breakout'
    if ($backhaul -ge 2) { $verdict = 'Full backhaul' }
    elseif ($split -ge 2) { $verdict = 'Split tunnel (local internet, RDP over tunnel)' }
    $score = [math]::Max($backhaul, $split)
    $confidence = if ($verdict -eq 'Local breakout') { if ($signals.Count -ge 3) { 'Medium-High' } else { 'Medium' } } elseif ($score -ge 4) { 'High' } elseif ($score -ge 2) { 'Medium' } else { 'Low' }
    [ordered]@{ Verdict = $verdict; Confidence = $confidence; BackhaulScore = $backhaul; SplitScore = $split; Signals = $signals }
}

function Get-UserFolder {
    # Resolves a shell folder (Desktop, Personal, Downloads GUID) for the inventoried user.
    param([string]$ValueName, [string]$Fallback)
    $paths = @("$($script:UserHive)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
               "$($script:UserHive)\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
    foreach ($k in $paths) {
        try {
            # Read unexpanded so %USERPROFILE% maps to the inventoried user, not the runner.
            $v = (Get-Item -LiteralPath $k -ErrorAction Stop).GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
            if ($v) {
                $v = $v -replace '%USERPROFILE%', $script:UserProfile
                $v = [Environment]::ExpandEnvironmentVariables($v)
                if (Test-Path -LiteralPath $v) { return $v }
            }
        } catch { }
    }
    return (Join-Path $script:UserProfile $Fallback)
}
function Test-WritableFolder {
    param([string]$Folder)
    try {
        if (-not (Test-Path -LiteralPath $Folder)) { New-Item -ItemType Directory -Path $Folder -Force | Out-Null }
        $probe = Join-Path $Folder ('.sa_write_test_{0}' -f (Get-Random))
        Set-Content -LiteralPath $probe -Value 'x'
        Remove-Item -LiteralPath $probe -Force
        return $true
    } catch { return $false }
}

function Get-ConnectionClass {
    param($Adapter)
    $desc = "$($Adapter.InterfaceDescription) $($Adapter.Name)"
    $ndis = "$($Adapter.NdisPhysicalMedium)"
    $pmt  = "$($Adapter.PhysicalMediaType)"
    if ($desc -match 'Remote NDIS|RNDIS') { return 'Phone tether (USB)' }
    if ($ndis -eq '9' -or $ndis -match '802_11' -or $pmt -match '802\.11|Wireless LAN') { return 'Wi-Fi' }
    if ($ndis -eq '8' -or $pmt -match 'Wireless WAN|Mobile Broadband') { return 'Cellular' }
    if ($desc -match $VpnRegex -or $Adapter.Virtual) { return 'Virtual/VPN' }
    if ($ndis -eq '14' -or $ndis -match '802_3' -or $pmt -match '802\.3') {
        if ($desc -match $UsbRegex) { return 'Wired (USB/dock)' }
        return 'Wired (onboard)'
    }
    return 'Unknown'
}

function Read-RdpFile {
    param([string]$Path)
    $h = [ordered]@{ Path = $Path; Modified = Format-Date (Get-Item -LiteralPath $Path).LastWriteTime }
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        if ($line -match '^([^:]+):([isb]):(.*)$') {
            $k = $matches[1].Trim().ToLower()
            if ($k -match 'password|signature') { continue }
            if ($RdpSafeKeys -contains $k) { $h[$k] = $matches[3].Trim() }
        }
    }
    return $h
}

function Get-LocationPolicy {
    $r = [ordered]@{ PolicyBlocked = $false; PolicyReason = $null; DeviceValue = $null; UserValue = $null; DesktopAppsValue = $null }
    $policies = @(
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; N = 'LetAppsAccessLocation'; Bad = 2 },
        @{ P = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy'; N = 'LetAppsAccessLocation'; Bad = 2 },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; N = 'DisableLocation'; Bad = 1 },
        @{ P = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System'; N = 'AllowLocation'; Bad = 0 }
    )
    foreach ($p in $policies) {
        $v = Get-RegString $p.P $p.N
        if ($null -ne $v -and [int]$v -eq $p.Bad) { $r.PolicyBlocked = $true; $r.PolicyReason = '{0}\{1}={2}' -f $p.P, $p.N, $v }
    }
    $r.DeviceValue = Get-RegString "HKLM:\$LocKey" 'Value'
    $r.UserValue = Get-RegString "HKCU:\$LocKey" 'Value'
    $r.DesktopAppsValue = Get-RegString "HKCU:\$LocKey\NonPackaged" 'Value'
    return $r
}

function Enable-TempLocation {
    # Returns the list of changes so Restore-TempLocation can undo exactly what was touched.
    param([bool]$IncludeDevice)
    $paths = @("HKCU:\$LocKey", "HKCU:\$LocKey\NonPackaged")
    if ($IncludeDevice) { $paths = @("HKLM:\$LocKey") + $paths }
    $changes = @()
    foreach ($p in $paths) {
        $existed = Test-Path -LiteralPath $p
        $orig = Get-RegString $p 'Value'
        if ($orig -eq 'Allow') { continue }
        if (-not $existed) { New-Item -Path $p -Force | Out-Null }
        New-ItemProperty -LiteralPath $p -Name 'Value' -Value 'Allow' -PropertyType String -Force | Out-Null
        $changes += [pscustomobject]@{ Path = $p; Existed = $existed; Original = $orig }
    }
    return $changes
}

function Restore-TempLocation {
    param($Changes)
    $failed = @()
    foreach ($c in @($Changes)[($Changes.Count - 1)..0]) {
        try {
            if ($null -ne $c.Original) { New-ItemProperty -LiteralPath $c.Path -Name 'Value' -Value $c.Original -PropertyType String -Force | Out-Null }
            else { Remove-ItemProperty -LiteralPath $c.Path -Name 'Value' -ErrorAction Stop }
            if (-not $c.Existed) { Remove-Item -LiteralPath $c.Path -Force -ErrorAction SilentlyContinue }
        } catch { $failed += $c.Path }
    }
    return $failed
}
function Add-Line { param([string]$Text = '') $L.Add($Text) }

# =====================================================================
# PHASE 8: data check. assessment.json is read back from disk exactly as the merge
# will read it, and every section the reports depend on is checked for real values.
# =====================================================================
function Get-Field {
    # Property or key lookup that works on both live results and JSON read back from disk.
    param($Obj, [string]$Name)
    if ($null -eq $Obj -or $Obj -is [string]) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] }; return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-AssessmentData {
    # Returns one row per check: Status OK, INFO (expected gap), WARN (usable, something missing) or FAIL (re-run).
    param($D, [string]$Folder)
    $rows = New-Object Collections.Generic.List[object]
    $add = { param($Check, $Status, $Detail) $rows.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = "$Detail" }) }

    $meta = Get-Field $D 'Meta'
    if ((Get-Field $meta 'Hostname') -and (Get-Field $meta 'RunStart')) { & $add 'Run identity' 'OK' ('{0} at {1}' -f (Get-Field $meta 'Hostname'), (Get-Field $meta 'RunStart')) }
    else { & $add 'Run identity' 'FAIL' 'hostname or run time missing' }
    $site = "$(Get-Field $meta 'SiteName')"
    if ($site -and $site -ne 'UNSPECIFIED') { & $add 'Site name' 'OK' $site } else { & $add 'Site name' 'WARN' 'no site name (can be fixed in the merge with -SiteMap)' }

    $net = Get-Field $D 'Network'
    $cls = "$(Get-Field $net 'PhysicalClass')"
    if ($cls -and $cls -ne 'No route' -and (Get-Field $net 'SourceIp')) { & $add 'Connection' 'OK' ('{0}, {1} via gateway {2}' -f $cls, (Get-Field $net 'SourceIp'), (Get-Field $net 'Gateway')) }
    else { & $add 'Connection' 'FAIL' 'no network route found' }

    $eg = Get-Field $D 'Egress'
    if (Get-Field $eg 'PublicIPv4') { & $add 'Public IP / carrier' 'OK' ('{0} ({1})' -f (Get-Field $eg 'PublicIPv4'), (Get-Field $eg 'Carrier')) }
    else { & $add 'Public IP / carrier' 'FAIL' 'public IP not identified' }

    $bwD = Get-Field $D 'Bandwidth'
    if ("$(Get-Field $bwD 'Status')" -eq 'disabled in config') { & $add 'Bandwidth' 'WARN' 'disabled in config' }
    else {
        foreach ($dir in 'Download', 'Upload') {
            $mbps = Get-Field $bwD "${dir}Mbps"
            if ((Get-Field $bwD "${dir}Ok") -and $null -ne $mbps -and [double]$mbps -gt 0) { & $add "Bandwidth $($dir.ToLower())" 'OK' ('{0} Mbps via {1}' -f $mbps, (Get-Field $bwD "${dir}Provider")) }
            else {
                $why = if (Get-Field $bwD "${dir}Failure") { Get-Field $bwD "${dir}Failure" } elseif (Get-Field $bwD 'Status') { Get-Field $bwD 'Status' } else { 'no provider returned a result (check $BandwidthProviders)' }
                & $add "Bandwidth $($dir.ToLower())" 'FAIL' $why
            }
        }
        if ($null -ne (Get-Field $bwD 'BufferbloatMs')) { & $add 'Latency under load' 'OK' ('{0:+0.#;-0.#;0} ms over idle, grade {1}' -f [double](Get-Field $bwD 'BufferbloatMs'), (Get-Field $bwD 'BufferbloatGrade')) }
        else { & $add 'Latency under load' 'WARN' 'not measured' }
    }

    $traces = @(@(Get-Field $D 'Traceroutes') | Where-Object { $_ })
    foreach ($tgt in '1.1.1.1', '8.8.8.8') {
        $t = $traces | Where-Object { $_.Target -eq $tgt } | Select-Object -First 1
        $answered = @(@(Get-Field $t 'Hops') | Where-Object { $_ -and $_.IP }).Count
        $an = Get-Field $t 'Analysis'
        if ($answered -ge 2 -and (Test-Path -LiteralPath (Join-Path $Folder ('traceroute_{0}.txt' -f $tgt)))) {
            & $add "Traceroute $tgt" 'OK' ('{0} hops, first public hop #{1} {2}' -f @(Get-Field $t 'Hops').Count, (Get-Field $an 'FirstPublicHop'), (Get-Field $an 'FirstPublicIP'))
        } else {
            & $add "Traceroute $tgt" $(if ($tgt -eq '1.1.1.1') { 'FAIL' } else { 'WARN' }) $(if (-not $t) { 'missing' } else { "only $answered hop(s) answered" })
        }
    }

    $pings = @(@(Get-Field $D 'PingSeries') | Where-Object { $_ })
    $tcps = @(@(Get-Field $D 'TcpSeries') | Where-Object { $_ })
    $inet = @($pings + $tcps) | Where-Object { $_.Target -eq '1.1.1.1' -and $_.Received -gt 0 } | Select-Object -First 1
    if ($inet) { & $add 'Internet loss / latency' 'OK' ('1.1.1.1 loss {0}%, avg {1} ms, jitter {2} ms ({3})' -f $inet.LossPct, $inet.AvgMs, $inet.JitterMs, $(if (Get-Field $inet 'Method') { 'TCP' } else { 'ping' })) }
    else { & $add 'Internet loss / latency' 'FAIL' 'no replies from 1.1.1.1 by ping or TCP' }
    $gw = Get-Field $net 'Gateway'
    $gp = $pings | Where-Object { $_.Target -eq $gw -and $_.Received -gt 0 } | Select-Object -First 1
    if ($gp) { & $add 'Gateway loss / latency' 'OK' ('loss {0}%, avg {1} ms' -f $gp.LossPct, $gp.AvgMs) } else { & $add 'Gateway loss / latency' 'WARN' 'gateway does not answer ping' }

    $rdpD = Get-Field $D 'Rdp'
    $targets = @(@(Get-Field $rdpD 'SelectedTargets') | Where-Object { $_ })
    $ownTargets = @($targets | Where-Object { $extraHosts -notcontains $_ })
    if ($targets.Count -eq 0) { & $add 'Remote desktop targets' 'WARN' 'none resolved' }
    elseif ($ownTargets.Count -eq 0) { & $add 'Remote desktop targets' 'WARN' ("only the fixed target ({0}); no remote desktop use found on this PC, so no session history. A PC whose user works in the hosted desktop gives more" -f ($targets -join ', ')) }
    else { & $add 'Remote desktop targets' 'OK' ($targets -join ', ') }
    if ($targets.Count) {
        $traceInfo = foreach ($tg in $targets) { $t = $traces | Where-Object { $_.Target -eq $tg } | Select-Object -First 1; '{0}: {1} hops' -f $tg, @(@(Get-Field $t 'Hops') | Where-Object { $_ -and $_.IP }).Count }
        $noTrace = @($targets | Where-Object { $tg = $_; -not ($traces | Where-Object { $_.Target -eq $tg -and @($_.Hops | Where-Object { $_ -and $_.IP }).Count -ge 1 }) })
        & $add 'Traceroutes to targets' $(if ($noTrace.Count) { 'WARN' } else { 'OK' }) (@($traceInfo) -join '; ')
        $series = @(@($pings + $tcps) | Where-Object { $targets -contains $_.Target -and $_.Received -gt 0 })
        if ($series.Count) { & $add 'Remote desktop loss / latency' 'OK' ((@($series | ForEach-Object { '{0}{1} loss {2}% avg {3} ms' -f $_.Target, $(if (Get-Field $_ 'Port') { " tcp/$($_.Port)" } else { '' }), $_.LossPct, $_.AvgMs })) -join '; ') }
        else { & $add 'Remote desktop loss / latency' 'WARN' 'no ping or TCP replies from any target' }
        $openT = @(@(Get-Field $D 'RdpPath') | Where-Object { $_ -and @(@($_.Tcp) | Where-Object { $_ -and $_.Open }).Count })
        if ($openT.Count) { & $add 'Remote desktop reachability' 'OK' ("{0} of {1} target(s) answer on TCP" -f $openT.Count, $targets.Count) } else { & $add 'Remote desktop reachability' 'WARN' 'no target answered on any TCP port' }
    }

    $mD = Get-Field $D 'Machine'
    if ((Get-Field $mD 'SerialNumber') -and (Get-Field $mD 'Model') -and (Get-Field $mD 'OsBuild')) { & $add 'Machine inventory' 'OK' ('{0} {1}, S/N {2}' -f (Get-Field $mD 'Manufacturer'), (Get-Field $mD 'Model'), (Get-Field $mD 'SerialNumber')) }
    else { & $add 'Machine inventory' 'WARN' 'model, serial or OS missing' }
    $appCount = Get-Field (Get-Field $D 'Software') 'AppCount'
    if ($appCount -gt 0) { & $add 'Software inventory' 'OK' "$appCount apps" } else { & $add 'Software inventory' 'WARN' 'no installed apps read' }
    $topo = Get-Field $D 'Topology'
    if (Get-Field $topo 'Verdict') { & $add 'Topology verdict' 'OK' ('{0} ({1})' -f (Get-Field $topo 'Verdict'), (Get-Field $topo 'Confidence')) } else { & $add 'Topology verdict' 'WARN' 'not decided' }

    if ($EnableSubnetSweep) {
        $sw = Get-Field $D 'SubnetSweep'
        $cnt = Get-Field $sw 'ArpEntries'
        if ($cnt -gt 0) { & $add 'Subnet sweep' 'OK' ('{0} devices on {1}, {2} identified by name or ports{3}' -f $cnt, (Get-Field $sw 'Subnet'), [int](Get-Field $sw 'Identified'), $(if (Get-Field $sw 'Note') { " ($(Get-Field $sw 'Note'))" } else { '' })) }
        else { & $add 'Subnet sweep' 'WARN' $(if (Get-Field $sw 'Status') { Get-Field $sw 'Status' } else { 'no devices found' }) }
    }
    $tlsD = Get-Field $D 'Tls'
    if ($tlsD -and (Get-Field $tlsD 'Checks')) {
        $answered = @(@(Get-Field $tlsD 'Checks') | Where-Object { $_ -and $_.Issuer }).Count
        if (Get-Field $tlsD 'InspectionSuspected') { & $add 'HTTPS certificates' 'WARN' 'HTTPS inspection suspected (see HTTPS CERTIFICATES in summary.txt)' }
        elseif ($answered) { & $add 'HTTPS certificates' 'OK' "$answered certificate(s) read, no inspection seen" }
        else { & $add 'HTTPS certificates' 'WARN' 'no certificate could be read' }
    }
    $hdaD = Get-Field (Get-Field $D 'Rdp') 'HostedDesktopApp'
    if ($hdaD) {
        if (Get-Field $hdaD 'Found') { & $add 'Hosted-desktop app' 'OK' ('found, {0} host name(s) in its files' -f @(@(Get-Field $hdaD 'Hosts') | Where-Object { $_ }).Count) }
        else { & $add 'Hosted-desktop app' 'INFO' 'No app matching the hosted desktop profile for this user (run on a PC whose user works in it)' }
    }
    if ($cls -eq 'Wi-Fi') {
        $wl = Get-Field $D 'Wireless'; $wc = Get-Field $wl 'Current'
        if ($null -ne (Get-Field $wc 'SignalPct')) { & $add 'Wi-Fi details' 'OK' ('{0}, {1}%, {2}' -f (Get-Field $wc 'SSID'), (Get-Field $wc 'SignalPct'), (Get-Field $wc 'Band')) }
        else {
            # Say why: a policy block applies to every managed PC, so a second machine will not fill the gap.
            $why = Get-Field (Get-Field $wl 'LocationWorkaround') 'Result'
            if (-not $why) { $why = Get-Field $wl 'Status' }
            & $add 'Wi-Fi details' 'WARN' ("radio details not read ({0}); SSID {1}" -f $why, (Get-Field $wc 'SSID'))
        }
    }
    if (Get-Field $meta 'AdminTierActive') {
        $adm = Get-Field $D 'Admin'
        if ($adm -and -not (Get-Field $adm 'Status')) { & $add 'Admin checks' 'OK' 'TPM, BitLocker, disk health and sign-ins collected' } else { & $add 'Admin checks' 'WARN' (Get-Field $adm 'Status') }
        if ($cls -like 'Wired*') {
            $nb = @(@(Get-Field (Get-Field $D 'Lldp') 'Neighbors') | Where-Object { $_ })
            if ($nb.Count) { & $add 'Switch (LLDP/CDP)' 'OK' ((@($nb | ForEach-Object { '{0} port {1}' -f $(if ($_.Model) { $_.Model } else { $_.SystemName }), $_.Port })) -join '; ') }
            else { & $add 'Switch (LLDP/CDP)' 'WARN' 'nothing heard: unmanaged switch, or LLDP/CDP turned off' }
        }
    } else { & $add 'Admin checks' 'INFO' 'skipped: ISE was not run as administrator' }

    $errs = @(@(Get-Field $D 'Errors') | Where-Object { $_ })
    if ($errs.Count) { & $add 'Collector errors' 'WARN' ((@($errs | ForEach-Object { $_.Collector } | Select-Object -Unique)) -join ', ') } else { & $add 'Collector errors' 'OK' 'none' }
    return $rows.ToArray()
}

function Test-ZipOutput {
    # Opens the finished zip the way the merge will and confirms the files and data are in it.
    param([string]$Zip, [string[]]$Required)
    $problems = @()
    $tmp = Join-Path $env:TEMP ('sa_verify_{0}' -f (Get-Random))
    try {
        Expand-Archive -LiteralPath $Zip -DestinationPath $tmp -Force
        foreach ($f in $Required) { if (-not (Test-Path -LiteralPath (Join-Path $tmp $f))) { $problems += "$f missing from the zip" } }
        $j = [IO.File]::ReadAllText((Join-Path $tmp 'assessment.json')) | ConvertFrom-Json
        if ((Get-Field (Get-Field $j 'Meta') 'Hostname') -ne $env:COMPUTERNAME) { $problems += 'assessment.json in the zip is not from this machine' }
        if (-not (Get-Field (Get-Field $j 'Validation') 'Overall')) { $problems += 'assessment.json in the zip has no data check' }
    } catch { $problems += "zip could not be read back: $($_.Exception.Message)" }
    finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    $size = (Get-Item -LiteralPath $Zip -ErrorAction SilentlyContinue).Length
    return [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = $problems; SizeKB = $(if ($size) { [math]::Round($size / 1KB) } else { 0 }) }
}

# ---------------------------------------------------------------------
# Remote desktop transport: can sessions here use UDP, or are they stuck on TCP? RDP over TCP feels
# slower and stalls on loss. Read from what the run already collected: the RDP client's own record of
# UDP attempts, the client UDP policy, the STUN test (UDP 3478 out and how the NAT maps ports), and
# Microsoft's list of things that break RDP Shortpath (double NAT, carrier-grade NAT, a full-tunnel
# VPN, packet inspection). Sends nothing.
# ---------------------------------------------------------------------
function Get-RdpTransportCheck {
    param($R)
    $udp = Get-Prop $R 'EventLogs', 'RdpClient', 'Udp'
    $est = [int](Get-Prop $udp 'Established'); $att = [int](Get-Prop $udp 'Attempted'); $fail = [int](Get-Prop $udp 'Failed')
    $pol = Get-Prop $R 'Session', 'UdpPolicy'
    $stun = @(@(Get-Prop $R 'Cloud', 'Stun') | Where-Object { $_ })
    $answered = @($stun | Where-Object { Get-Prop $_ 'Answered' })
    $ports = @($answered | ForEach-Object { Get-Prop $_ 'MappedPort' } | Where-Object { $_ } | Select-Object -Unique)
    $profile = "$(Get-Prop $R 'Meta', 'HostedDesktop', 'Profile')"
    $shortpath = $profile -in @('AzureVirtualDesktop', 'Windows365')
    $inet = @(@(Get-Prop $R 'Traceroutes') | Where-Object { $_ -and "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' }) | Select-Object -First 1

    $evidence = @()
    if ($att -or $est -or $fail) { $evidence += "RDP client log: UDP attempted $att, established $est, failed $fail" }
    if (Get-Prop $pol 'UdpDisabled') { $evidence += "UDP is turned off for the RDP client ($(Get-Prop $pol 'Source'))" }
    if ($stun.Count) { $evidence += "STUN on UDP: $($answered.Count) of $($stun.Count) servers answered$(if ($ports.Count -gt 1) { ', with a different public port for each (symmetric NAT)' } elseif ($ports.Count -eq 1) { ', with the same public port for each' })" }

    $verdict = if ($est -gt 0) { 'UDP in use' }
               elseif (Get-Prop $pol 'UdpDisabled') { 'TCP only: UDP turned off on this PC' }
               elseif ($stun.Count -and -not $answered.Count) { 'TCP only: outbound UDP blocked' }
               elseif ($ports.Count -gt 1) { $(if ($shortpath) { 'Relayed UDP only (symmetric NAT)' } else { 'UDP may fail (symmetric NAT)' }) }
               elseif ($answered.Count) { 'UDP possible' }
               else { 'Not known' }

    # What Microsoft says gets in the way of a direct UDP path (RDP Shortpath, public networks)
    $caveats = @()
    if (Get-Prop $inet 'Analysis', 'DoubleNatLikely') { $caveats += 'double NAT (an ISP router doing NAT in front of the firewall)' }
    if ([int](Get-Prop $inet 'Analysis', 'CgnatHops') -gt 0) { $caveats += 'carrier-grade NAT at the ISP' }
    if (Get-Prop $R 'Network', 'VpnHoldsDefaultRoute') { $caveats += 'a full-tunnel VPN carries all traffic' }
    if (Get-Prop $R 'Tls', 'InspectionSuspected') { $caveats += 'HTTPS inspection, so packet inspection is likely in the path' }
    return [pscustomobject]@{ Verdict = $verdict; Shortpath = $shortpath; Caveats = $caveats; Evidence = $evidence }
}

function Get-RdpTransportFlags {
    param($C, [bool]$UsesRemoteDesktop = $true)
    if (-not $C -or -not $UsesRemoteDesktop) { return @() }
    $f = { param($sev, $msg) [pscustomobject]@{ Severity = $sev; Category = 'RDP'; Message = $msg } }
    switch -Wildcard ("$($C.Verdict)") {
        'TCP only: outbound UDP blocked' { return @(& $f 'Medium' 'Remote desktop sessions can only use TCP here: outbound UDP is blocked. Allow UDP 3478 out (and, for Azure Virtual Desktop or Windows 365, UDP to 51.5.0.0/16 port 3478) so sessions can use the faster UDP transport') }
        'TCP only: UDP turned off*' { return @(& $f 'Medium' 'Remote desktop sessions can only use TCP: UDP is turned off for the RDP client on this PC (policy "Turn Off UDP On Client" or the client setting)') }
        'Relayed UDP only*' { return @(& $f 'Low' 'Symmetric NAT here: Azure Virtual Desktop can only use UDP through the TURN relay, so UDP 3478 to 51.5.0.0/16 must stay open') }
        default { return @() }
    }
}

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$RunStart = Get-Date

# Paste check: a copy cut short by the clipboard could run part-way and save nothing.
# The last line of this file is a marker; if it is missing, stop before doing anything.
$endMarker = '# END OF ' + 'COLLECTOR SCRIPT'
$selfText = $null
try {
    if ($PSCommandPath) { $selfText = Get-Content -LiteralPath $PSCommandPath -Raw -ErrorAction Stop }
    elseif ($psISE -and $psISE.CurrentFile) { $selfText = $psISE.CurrentFile.Editor.Text }
} catch { }
if ($selfText -and $selfText -notlike "*$endMarker*") {
    Write-Host ''
    Write-Host 'STOP: this copy of the script is incomplete (the end of the file is missing).' -ForegroundColor Red
    Write-Host 'The paste was probably cut short. Nothing was run. Paste it again, or transfer the .ps1 file and open that.' -ForegroundColor Red
    return
}

# ---------------------------------------------------------------------
# Console + bookkeeping helpers
# ---------------------------------------------------------------------
$script:Errors  = @()
$script:Flags   = @()
$script:Timings = [ordered]@{}

# ---------------------------------------------------------------------
# MAC vendor lookup (embedded table for network gear, online fallback)
# ---------------------------------------------------------------------
$script:OuiTable = @{}
$ouiSeed = @{
    'Fortinet'   = '00090F 085B0E 704CA5 906CAC E81CBA 04D590 94FF3C'
    'SonicWall'  = '0017C5 C0EAE4 18B169'
    'Cisco Meraki' = '00180A 0C8DDB 881544 E0553D AC17C8 2C3F0B 683A1E E0CBBC'
    'Ubiquiti'   = '00156D 002722 0418D6 24A43C 44D9E7 687251 788A20 802AA8 B4FBE4 DC9FDB F09FC2 FCECDA 74ACB9 18E829 E063DA 245A4C 784558 68D79A 70A741 D021F9 AC8BA9'
    'WatchGuard' = '00907F'
    'Sophos'     = '001A8C'
    'Palo Alto Networks' = '001B17 00869C B40C25 08306B'
    'Aruba (HPE)' = '000B86 001A1E 24DEC6 6CF37F 94B40F D8C7C8 204C03 9C1C12 84D47E 40E3D6 B45D50 F05C19'
}
foreach ($vendor in $ouiSeed.Keys) {
    foreach ($o in ($ouiSeed[$vendor] -split ' ')) { $script:OuiTable[$o] = $vendor }
}
$script:OuiOnlineCount = 0

# (end of v1.6.0 helpers)

# =====================================================================
# PREFLIGHT
# =====================================================================
$script:FullLanguage = ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
try { [Net.ServicePointManager]::DefaultConnectionLimit = 64 } catch { }
try { [Net.ServicePointManager]::Expect100Continue = $false } catch { }

$currentId  = [Security.Principal.WindowsIdentity]::GetCurrent()
$isElevated = (New-Object Security.Principal.WindowsPrincipal $currentId).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:AdminActive = $isElevated

Write-Host ''
Write-Host "Site Assessment Collector v$ScriptVersion" -ForegroundColor White
Write-Host ('Running as {0}  elevated={1}  discovery={2}  language={3}' -f $currentId.Name, $isElevated, [bool]$EnableDiscovery, $ExecutionContext.SessionState.LanguageMode)
Write-Host ("Hosted desktop profile: {0}" -f $HostedLabel)
if ($EnableDiscovery) {
    Write-Host 'Discovery is ON: other devices on this network will be swept and asked to identify themselves.' -ForegroundColor Yellow
    Write-Host '                 Only continue on a network you are authorised to assess.' -ForegroundColor Yellow
} else {
    Write-Host 'Discovery is off: only this PC and its path to the internet are measured (-Discovery adds the network).'
}
if ($isElevated) {
    Write-Host 'ISE is elevated: admin checks (TPM, BitLocker, LLDP/CDP, sign-ins, Wi-Fi report) will run.' -ForegroundColor Green
} else {
    Write-Host 'ISE is not elevated: admin checks are skipped (run ISE as administrator to include them).'
}
if (-not $script:FullLanguage) {
    Write-Host 'WARNING: Constrained Language Mode detected (AppLocker/WDAC). Using slower fallbacks.' -ForegroundColor Yellow
}

if (-not $NoPrompt) {
    if (-not $SiteName -and @($SiteList).Count -gt 0) {
        $menu = "Choose the site:`n"
        for ($k = 0; $k -lt $SiteList.Count; $k++) { $menu += ('  {0}) {1}' -f ($k + 1), $SiteList[$k]) + "`n" }
        $menu += '  or type a different site name'
        Write-Host $menu
        $pick = Read-Host 'Site number or name'
        $num = 0
        if ([int]::TryParse("$pick".Trim(), [ref]$num) -and $num -ge 1 -and $num -le $SiteList.Count) { $SiteName = $SiteList[$num - 1] }
        else { $SiteName = $pick }
    }
    if (-not $SiteName) { $SiteName = Read-Host 'Site / office name (required)' }
    if (-not $Notes)    { $Notes    = Read-Host 'Notes (desk/location, optional)' }
}
if (-not $SiteName) { $SiteName = 'UNSPECIFIED' }
$SiteName = $SiteName.Trim()
$siteSafe = ($SiteName -replace '[^A-Za-z0-9_-]', '_')

$Result = [ordered]@{}

# ---------------------------------------------------------------------
# Inventoried user (the signed-in console user, not necessarily the runner)
# ---------------------------------------------------------------------
$script:UserSid = $currentId.User.Value
$script:UserName = $currentId.Name
$script:UserProfile = $env:USERPROFILE
try {
    $mySession = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $explorers = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -OperationTimeoutSec 15
    $exp = $explorers | Where-Object { $_.SessionId -eq $mySession } | Select-Object -First 1
    if (-not $exp) { $exp = $explorers | Select-Object -First 1 }
    if ($exp) {
        $sidResult = Invoke-CimMethod -InputObject $exp -MethodName GetOwnerSid
        $ownResult = Invoke-CimMethod -InputObject $exp -MethodName GetOwner
        if ($sidResult.Sid) {
            $script:UserSid = $sidResult.Sid
            $script:UserName = ('{0}\{1}' -f $ownResult.Domain, $ownResult.User)
            $prof = Get-CimInstance Win32_UserProfile -Filter ("SID='{0}'" -f $script:UserSid) -OperationTimeoutSec 15
            if ($prof -and $prof.LocalPath) { $script:UserProfile = $prof.LocalPath }
        }
    }
} catch { }
$script:UserHive = "Registry::HKEY_USERS\$($script:UserSid)"
$script:SameUser = ($script:UserSid -eq $currentId.User.Value)
$script:UserDesktop   = Get-UserFolder 'Desktop' 'Desktop'
$script:UserDocuments = Get-UserFolder 'Personal' 'Documents'
$script:UserDownloads = Get-UserFolder '{374DE290-123F-4565-9164-39C4925E467B}' 'Downloads'
$script:UserLocalApp  = Join-Path $script:UserProfile 'AppData\Local'
$script:UserRoaming   = Join-Path $script:UserProfile 'AppData\Roaming'

# Output folder
if ($OutputPath) { $OutputRoot = $OutputPath }
if ($NoPrompt) { $OpenFolderWhenDone = $false; $CopySummaryToClipboard = $false }
if (-not $OutputRoot) {
    # Same path on every machine, writable by standard users, not synced to the client's OneDrive.
    $candidates = @((Join-Path ([Environment]::GetFolderPath('CommonDocuments')) 'SiteAssessment'),
                    (Join-Path $script:UserProfile 'SiteAssessment'),
                    (Join-Path $env:TEMP 'SiteAssessment'))
    foreach ($c in $candidates) { if (Test-WritableFolder $c) { $OutputRoot = $c; break } }
}
if (-not $OutputRoot -or -not (Test-WritableFolder $OutputRoot)) { $OutputRoot = $env:TEMP }
$runName = '{0}_{1}_{2}' -f $siteSafe, $env:COMPUTERNAME, $RunStart.ToString('yyyyMMdd-HHmm')
$OutDir = Join-Path $OutputRoot $runName
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $OutDir 'transcript.log') -Force | Out-Null; $script:Transcript = $true } catch { $script:Transcript = $false }

Write-Step ("Site: {0}   Inventoried user: {1}   Output: {2}" -f $SiteName, $script:UserName, $OutDir) 'White'

$Result['Meta'] = [ordered]@{
    ScriptVersion     = $ScriptVersion
    SiteName          = $SiteName
    Notes             = $Notes
    Hostname          = $env:COMPUTERNAME
    RunStart          = Format-Date $RunStart
    TimeZone          = [TimeZoneInfo]::Local.Id
    RunAsUser         = $currentId.Name
    InventoriedUser   = $script:UserName
    InventoriedSid    = $script:UserSid
    InventoriedProfile = $script:UserProfile
    SameUser          = $script:SameUser
    IsElevated        = $isElevated
    Discovery         = [bool]$EnableDiscovery
    HostedDesktop     = [ordered]@{ Profile = $HostedDesktopName; Name = $HostedLabel; HostPattern = "$($HostedProfile.HostPattern)"; Targets = @($ExtraTargets) }
    AdminTierActive   = $script:AdminActive
    AdminDowngraded   = $false
    LanguageMode      = "$($ExecutionContext.SessionState.LanguageMode)"
    PSVersion         = $PSVersionTable.PSVersion.ToString()
    PSHost            = $Host.Name
    Options           = [ordered]@{
        SubnetSweep = $EnableSubnetSweep; GatewayProbe = $EnableGatewayProbe; IpInfo = $EnableIpInfo
        FirewallPorts = $EnableFirewallPorts; Ssdp = $EnableSsdp; PrinterProbe = $EnablePrinterProbe
        SweepPorts = $EnableSweepPorts; RemoteSweep = $EnableRemoteSweep; TlsCheck = $EnableTlsCheck
        OuiLookup = $EnableOuiLookup; Ipv6Check = $EnableIpv6Check; DomainCheck = $EnableDomainCheck; Bandwidth = $EnableBandwidth; BandwidthSeconds = $BandwidthSeconds
        BandwidthStreams = $BandwidthStreams; MaxTestMB = $MaxTestMB; PingCount = $PingCount; LookbackDays = $LookbackDays
        BandwidthRounds = $BandwidthRounds; VendorDiscovery = $EnableVendorDiscovery; MulticastDiscovery = $EnableMulticastDiscovery
        Snmp = $EnableSnmp; ModemPage = $EnableModemPage; WindowsBuild = $EnableWindowsBuild; DnsTiming = $EnableDnsTiming; CloudCheck = $EnableCloudCheck
        VoiceSample = $EnableVoiceSample; PrinterQuery = $EnablePrinterQuery; CameraQuery = $EnableCameraQuery; OutboundCheck = $EnableOutboundCheck
        GatewayServices = $EnableGatewayServices; TunnelReach = $EnableTunnelReach; DhcpRenew = $EnableDhcpRenew
        LeadChecks = $EnableLeadChecks; AdSites = $EnableAdSites; DeviceIdentify = $EnableDeviceIdentify; DnsDiscovery = $EnableDnsDiscovery; SiteReach = $EnableSiteReach; OwnerLookup = $EnableOwnerLookup
    }
}

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

# ---------------------------------------------------------------------
# Connection check: printed before anything is measured, so a wrong starting point is seen now.
# Link speed is only reported here (the findings at the end say whether the port or the circuit
# set the limit). The one question asked is whether to go on when this looks like a hosted desktop.
# ---------------------------------------------------------------------
$script:Preflight = [ordered]@{ Model = $null; IsVirtualMachine = $false; LooksLikeHostedDesktop = $false; Notes = @(); Answer = $null }
try {
    $pcs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15
    $script:Preflight['Model'] = ('{0} {1}' -f $pcs.Manufacturer, $pcs.Model).Trim()
    $script:Preflight['IsVirtualMachine'] = [bool]($script:Preflight['Model'] -match 'VMware|Virtual Machine|VirtualBox|KVM|QEMU|Xen|Parallels|Amazon EC2|Google Compute')
} catch { }
try {
    $pfAd = $null
    if ($Net -is [System.Collections.IDictionary] -and $Net.Contains('Adapters')) { $pfAd = @($Net['Adapters'] | Where-Object { $_.Name -eq $Net['PhysicalAdapter'] }) | Select-Object -First 1 }
    $pfWired = ($pfAd -and "$($Net['PhysicalClass'])" -like 'Wired*')
    Write-Host ''
    Write-Host 'CONNECTION CHECK' -ForegroundColor White
    if ($pfAd) {
        Write-Host ('  Adapter   {0} ({1})' -f $pfAd.Description, $Net['PhysicalClass'])
        Write-Host ('  Link      {0} Mbps{1}' -f $Net['PhysicalLinkMbps'], $(if ($pfWired) { '' } else { ' (radio rate, changes with signal)' }))
        Write-Host ('  Address   {0}  mask {1}  gateway {2}' -f (@($pfAd.IPv4) -join ', '), @($pfAd.SubnetMask)[0], $Gateway)
        Write-Host ('  DHCP      {0}' -f $(if ($pfAd.DhcpEnabled) { "from $($pfAd.DhcpServer)" } else { 'off (static address)' }))
        Write-Host ('  DNS       {0}' -f (@($pfAd.DnsServers) -join ', '))
    } else {
        Write-Host '  No active adapter with a route to the internet was found.' -ForegroundColor Yellow
    }
    Write-Host ('  Machine   {0}{1}' -f $script:Preflight['Model'], $(if ($script:Preflight['IsVirtualMachine']) { '  (virtual machine)' } else { '' }))
    $pfNotes = @()
    if ($pfWired -and $Net['PhysicalLinkMbps'] -and $Net['PhysicalLinkMbps'] -lt 1000) { $pfNotes += "Link is $($Net['PhysicalLinkMbps']) Mbps, so the speed test cannot read above that on this port. The findings at the end say whether the port or the circuit set the limit." }
    if ($pfWired -and -not $script:AdminActive) { $pfNotes += 'ISE is not elevated: the switch cannot be identified and the wire capture will not run.' }
    if ($pfAd -and @($pfAd.IPv4 | Where-Object { $_ -like '169.254.*' }).Count) { $pfNotes += 'The adapter has a 169.254 address: no DHCP server answered.' }
    if ($Net -is [System.Collections.IDictionary] -and $Net['VpnHoldsDefaultRoute']) { $pfNotes += "A VPN adapter holds the default route ($($Net['PrimaryAdapter'])): results would describe the VPN, not this site. Disconnect it and run again." }
    if ($Net -is [System.Collections.IDictionary] -and $Net['MultipleConnected']) { $pfNotes += "More than one adapter is connected ($(@($Net['ConnectedPhysical']) -join '; ')). Turn off the one you are not testing." }
    $pfIp = if ($pfAd) { "$(@($pfAd.IPv4)[0])" } else { '' }
    $pfHosted = ($script:Preflight['IsVirtualMachine'])
    $script:Preflight['LooksLikeHostedDesktop'] = [bool]$pfHosted
    foreach ($nt in $pfNotes) { Write-Host "  NOTE      $nt" -ForegroundColor Yellow }
    $script:Preflight['Notes'] = $pfNotes
    if ($pfHosted) {
        Write-Host '  WARNING   This looks like a hosted desktop or virtual machine, not a PC at the site.' -ForegroundColor Red
        Write-Host '            A run here measures the data center or cloud, not the office network.' -ForegroundColor Red
        if (-not $NoPrompt) {
            $script:Preflight['Answer'] = Read-Host '  Type Y to run here anyway, anything else to stop'
            if ("$($script:Preflight['Answer'])".Trim() -notmatch '^(y|yes)$') {
                Write-Host 'Stopped. Nothing was measured. Run the script on a PC or laptop plugged into the site network.' -ForegroundColor Yellow
                if ($script:Transcript) { try { Stop-Transcript | Out-Null } catch { } }
                return
            }
        }
    }
    Write-Host ''
} catch { $script:Errors += [pscustomobject]@{ Collector = 'Connection check'; Error = $_.Exception.Message } }
$Result['Preflight'] = $script:Preflight

# ---------------------------------------------------------------------
# RDP footprint (needed early for target list)
# ---------------------------------------------------------------------
$RdpSafeKeys = @('full address','alternate full address','gateway hostname','gatewayusagemethod','gatewayprofileusagemethod',
    'gatewaycredentialssource','workspace id','remoteapplicationmode','remoteapplicationname','remoteapplicationprogram',
    'redirectprinters','redirectclipboard','drivestoredirect','devicestoredirect','usbdevicestoredirect','camerastoredirect',
    'audiomode','audiocapturemode','redirectsmartcards','redirectcomports','redirectposdevices','redirectwebauthn','redirectlocation',
    'use multimon','selectedmonitors','screen mode id','desktopwidth','desktopheight','session bpp','dynamic resolution',
    'smart sizing','connection type','networkautodetect','bandwidthautodetect','autoreconnection enabled','username',
    'prompt for credentials','authentication level','enablecredsspsupport','kdcproxyname','use redirection server name',
    'loadbalanceinfo','server port','enablerdsaadauth','targetisaadjoined')

$Result['Rdp'] = Invoke-Collector 'RDP client footprint' {
    $out = [ordered]@{}

    # Client versions
    $mstsc = Join-Path $env:WINDIR 'System32\mstsc.exe'
    $out['MstscVersion'] = if (Test-Path $mstsc) { (Get-Item $mstsc).VersionInfo.ProductVersion } else { $null }
    $msrdcPaths = @((Join-Path $script:UserLocalApp 'Apps\Remote Desktop\msrdcw.exe'),
                    (Join-Path ${env:ProgramFiles} 'Remote Desktop\msrdcw.exe'))
    $out['MsrdcPath'] = ($msrdcPaths | Where-Object { Test-Path $_ } | Select-Object -First 1)
    $out['MsrdcVersion'] = if ($out['MsrdcPath']) { (Get-Item $out['MsrdcPath']).VersionInfo.ProductVersion } else { $null }
    try {
        $out['AppxClients'] = @(Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -match 'Windows365|RemoteDesktop' } |
            ForEach-Object { '{0} {1}' -f $_.Name, $_.Version })
    } catch { $out['AppxClients'] = @() }

    # RDP history (MRU) and per-server hints
    $tsc = "$($script:UserHive)\Software\Microsoft\Terminal Server Client"
    $mru = Get-RegValues "$tsc\Default"
    $out['Mru'] = if ($mru) { @($mru.Values) } else { @() }
    $servers = @()
    if (Test-Path -LiteralPath "$tsc\Servers") {
        foreach ($k in (Get-ChildItem -LiteralPath "$tsc\Servers")) {
            $hint = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).UsernameHint
            $servers += [pscustomobject]@{ Server = $k.PSChildName; UsernameHint = $hint }
        }
    }
    $out['Servers'] = $servers
    $out['LocalDevicesApproved'] = Get-RegValues "$tsc\LocalDevices"

    # Workspace (RemoteApp and Desktop Connections) feeds
    $feeds = @()
    $feedRoot = "$($script:UserHive)\Software\Microsoft\Workspaces\Feeds"
    if (Test-Path -LiteralPath $feedRoot) {
        foreach ($k in (Get-ChildItem -LiteralPath $feedRoot)) { $feeds += Get-RegValues $k.PSPath }
    }
    $out['WorkspaceFeeds'] = $feeds

    # Remote Desktop (MSRDC) subscription URLs
    $rdUrls = @()
    $rdDir = Join-Path $script:UserLocalApp 'rdclientwpf'
    if (Test-Path -LiteralPath $rdDir) {
        foreach ($f in (Get-ChildItem -LiteralPath $rdDir -Recurse -File -Include *.json -ErrorAction SilentlyContinue | Select-Object -First 30)) {
            try {
                $txt = [IO.File]::ReadAllText($f.FullName)
                foreach ($m in [regex]::Matches($txt, 'https://[A-Za-z0-9\.\-]+(/[A-Za-z0-9\.\-_/]*)?')) { $rdUrls += $m.Value }
            } catch { }
        }
    }
    $out['MsrdcSubscriptionUrls'] = @($rdUrls | Where-Object { $_ -notmatch 'schemas|w3\.org|json-schema' } | Sort-Object -Unique)

    # .rdp files
    $rdpFiles = @()
    $searchRoots = @($script:UserDesktop, $script:UserDocuments, $script:UserDownloads, (Join-Path $env:PUBLIC 'Desktop'))
    foreach ($root in $searchRoots) {
        if ($root -and (Test-Path -LiteralPath $root)) {
            $rdpFiles += @(Get-ChildItem -LiteralPath $root -Filter *.rdp -File -Force -ErrorAction SilentlyContinue)
        }
    }
    $wsDir = Join-Path $script:UserLocalApp 'Microsoft\Workspaces'
    if (Test-Path -LiteralPath $wsDir) {
        $rdpFiles += @(Get-ChildItem -LiteralPath $wsDir -Filter *.rdp -File -Recurse -Force -ErrorAction SilentlyContinue)
    }
    $parsed = @()
    foreach ($f in ($rdpFiles | Sort-Object FullName -Unique | Select-Object -First 50)) {
        try { $parsed += Read-RdpFile $f.FullName } catch { }
    }
    $out['RdpFiles'] = $parsed

    # Shortcuts pointing at RDP or web portals
    $shortcuts = @()
    $rdpish = '\.rdp|mstsc|msrdc|rdweb|rdgateway|remote ?desktop|workspace|webclient|rdp|citrix|horizon|windows365|cloudpc'
    $wsh = $null
    try { $wsh = New-Object -ComObject WScript.Shell } catch { }
    $scDirs = @(
        @{ Path = $script:UserDesktop; AllUrl = $true },
        @{ Path = (Join-Path $env:PUBLIC 'Desktop'); AllUrl = $true },
        @{ Path = (Join-Path $script:UserRoaming 'Microsoft\Windows\Start Menu\Programs'); AllUrl = $false },
        @{ Path = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'); AllUrl = $false },
        @{ Path = (Join-Path $script:UserRoaming 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'); AllUrl = $true }
    )
    foreach ($d in $scDirs) {
        if (-not (Test-Path -LiteralPath $d.Path)) { continue }
        $files = @(Get-ChildItem -LiteralPath $d.Path -Recurse -File -Include *.lnk, *.url, *.appref-ms -Force -ErrorAction SilentlyContinue | Select-Object -First 400)
        foreach ($f in $files) {
            $target = $null; $args2 = $null
            try {
                if ($f.Extension -eq '.url') {
                    $u = Get-Content -LiteralPath $f.FullName -ErrorAction Stop | Where-Object { $_ -like 'URL=*' } | Select-Object -First 1
                    if ($u) { $target = $u.Substring(4) }
                } elseif ($f.Extension -eq '.appref-ms') {
                    # ClickOnce shortcut: "<deployment URL>#<app>.application, Culture=..."
                    $txt = [IO.File]::ReadAllText($f.FullName)
                    if ($txt -match '(https?://[^#\s,]+)') { $target = $matches[1] }
                } elseif ($wsh) {
                    $lnk = $wsh.CreateShortcut($f.FullName)
                    $target = $lnk.TargetPath; $args2 = $lnk.Arguments
                }
            } catch { }
            $hay = "$($f.Name) $target $args2"
            if (($d.AllUrl -and $f.Extension -eq '.url') -or ($hay -match $rdpish) -or ($hay -match "$RdpHostHint|$RdpAppHint")) {
                $shortcuts += [pscustomobject]@{ Name = $f.Name; Location = $d.Path; Target = $target; Arguments = $args2 }
            }
        }
    }
    $out['Shortcuts'] = $shortcuts

    # Client-side RDP policy
    $out['PolicyMachine'] = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $out['PolicyMachineClient'] = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client'
    $out['PolicyUser'] = Get-RegValues "$($script:UserHive)\Software\Policies\Microsoft\Windows NT\Terminal Services"

    # Live session: RDP client processes and their connections. Some hosted desktop apps host the RDP client
    # inside its own process, so processes named like it count too.
    $procRegex = '^(mstsc|msrdc|msrdcw|Windows365|wfica32|CDViewer|vmware-view|vmware-remotemks)$'
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $procRegex -or $_.ProcessName -match "$RdpHostHint|$RdpAppHint" })
    $out['RunningClients'] = @($procs | ForEach-Object { '{0} (pid {1})' -f $_.ProcessName, $_.Id })
    $conns = @(); $udp = @()
    if ($procs.Count -gt 0) {
        $pids = @($procs | ForEach-Object { $_.Id })
        try {
            $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $pids -contains $_.OwningProcess } |
                ForEach-Object { [pscustomobject]@{ Process = ($procs | Where-Object Id -eq $_.OwningProcess | Select-Object -First 1).ProcessName; RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort; Class = (Get-IpClass $_.RemoteAddress) } })
        } catch { }
        try {
            $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $pids -contains $_.OwningProcess } |
                ForEach-Object { [pscustomobject]@{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort } })
        } catch { }
    }
    $out['ActiveTcp'] = $conns
    $out['ActiveUdpSockets'] = $udp
    $out['UdpLikelyInUse'] = ($udp.Count -gt 0)

    # Hosted desktop traffic from any process: IPs the DNS cache maps to a name matching the profile, plus reverse DNS
    # on connections from RDP-type processes or on non-web ports (443 is everything, so it is skipped).
    $hintNames = @(); $hintIps = @{}
    try {
        foreach ($c in @(Get-DnsClientCache -ErrorAction Stop)) {
            if ("$($c.Entry) $($c.Data)" -notmatch $RdpHostHint) { continue }
            $hintNames += "$($c.Entry)".ToLower()
            if ([int]$c.Type -eq 1 -and (Test-IPv4 "$($c.Data)")) { $hintIps["$($c.Data)"] = "$($c.Entry)".ToLower() }
        }
    } catch { }
    $out['DnsCacheHintNames'] = @($hintNames | Select-Object -Unique)
    $hintConns = @()
    try {
        $pidSet = @($procs | ForEach-Object { $_.Id })
        $ptrBudget = 12
        foreach ($g in @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { (Get-IpClass $_.RemoteAddress) -eq 'Public' } | Group-Object RemoteAddress)) {
            $c = $g.Group[0]
            $name = $hintIps[$g.Name]
            if (-not $name -and $ptrBudget -gt 0 -and (($pidSet -contains $c.OwningProcess) -or $c.RemotePort -notin @(80, 443))) {
                $ptrBudget--
                $ptr = Resolve-Ptr $g.Name
                if ($ptr -match $RdpHostHint) { $name = $ptr.ToLower() }
            }
            if ($name) {
                $pn = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                $hintConns += [pscustomobject]@{ Name = $name; RemoteAddress = $g.Name; RemotePort = $c.RemotePort; Process = $pn }
            }
        }
    } catch { }
    $out['HostedConnections'] = $hintConns

    # Servers the RDP client connected to recently (any client that uses the RDP ActiveX control logs here).
    $evServers = @()
    try {
        foreach ($e in @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'; Id = 1024; StartTime = (Get-Date).AddDays(-$LookbackDays) } 300)) {
            if ($e.Message -match '\(([^)]+)\)') { $evServers += $matches[1].Trim().ToLower() }
        }
    } catch { }
    $out['EventLogServers'] = @($evServers | Select-Object -Unique)

    # Hosted-desktop client footprint (often a per-user ClickOnce app): where it
    # is, its version, and the host names found in its config and log files. Only host names are kept;
    # no file contents are copied. This works without signing in to the service.
    $appRx = "$RdpHostHint|$RdpAppHint"
    $app = [ordered]@{ Found = $false; Folders = @(); Executables = @(); Files = @(); Hosts = @() }
    try {
        $roots = @(); $exeHits = @()
        $clickOnce = Join-Path $script:UserLocalApp 'Apps\2.0'
        if (Test-Path -LiteralPath $clickOnce) {
            $exeHits = @(Get-ChildItem -LiteralPath $clickOnce -Recurse -File -Filter *.exe -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match $appRx } | Select-Object -First 10)
            foreach ($x in $exeHits) { $roots += $x.DirectoryName }
            # Per-user settings sit under Apps\2.0\Data in folders that share the app folder's shortened name (avat..tion_...).
            $prefixes = @($exeHits | ForEach-Object { ($_.Directory.Name -split '_')[0] } | Select-Object -Unique)
            $dataDir = Join-Path $clickOnce 'Data'
            if ($prefixes.Count -and (Test-Path -LiteralPath $dataDir)) {
                $roots += @(Get-ChildItem -LiteralPath $dataDir -Recurse -Depth 3 -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $prefixes -contains ($_.Name -split '_')[0] } | ForEach-Object { $_.FullName })
            }
        }
        foreach ($base in @($script:UserLocalApp, $script:UserRoaming, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $base -or -not (Test-Path -LiteralPath $base)) { continue }
            foreach ($hit in @(Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $appRx })) {
                $roots += $hit.FullName
                $exeHits += @(Get-ChildItem -LiteralPath $hit.FullName -Recurse -File -Filter *.exe -Force -ErrorAction SilentlyContinue | Select-Object -First 5)
            }
        }
        $roots = @($roots | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 12)
        $noise = 'schemas\.|w3\.org|microsoft\.com|xmlsoap|openxmlformats|digicert|verisign|symantec|thawte|globalsign|sectigo|usertrust|comodoca|letsencrypt|json-schema|newtonsoft|github\.com|nuget\.org|mozilla\.org|purl\.org|adobe\.com|aka\.ms|live\.com|msftauth|windowsupdate|msocsp|entrust|godaddy|amazontrust|pki\.goog'
        $found = @(); $files = @()
        foreach ($root in $roots) {
            $cand = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(config|json|xml|ini|txt|log|settings|manifest|application)$' -and $_.Length -le 2MB } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 40)
            foreach ($f in $cand) {
                $files += [pscustomobject]@{ File = $f.FullName; SizeKB = [math]::Round($f.Length / 1KB, 1); Modified = Format-Date $f.LastWriteTime }
                try {
                    $txt = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                    foreach ($m in [regex]::Matches($txt, '(?i)\b(?:https?|wss?|rdp)://([a-z0-9][a-z0-9\.\-]*\.[a-z]{2,})(?::(\d{2,5}))?')) {
                        $hn = $m.Groups[1].Value.ToLower()
                        if ($hn -match $noise) { continue }
                        if ($m.Groups[2].Success) { $found += ('{0}:{1}' -f $hn, $m.Groups[2].Value) } else { $found += $hn }
                    }
                    # Bare host names (no scheme) count only when they look like the provider's own domains.
                    foreach ($m in [regex]::Matches($txt, '(?i)\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|cloud|us|co|app)\b')) {
                        if ($m.Value -match $appRx) { $found += $m.Value.ToLower() }
                    }
                } catch { }
            }
        }
        $app.Found = ($roots.Count -gt 0)
        $app.Folders = $roots
        $app.Executables = @($exeHits | Sort-Object FullName -Unique | Select-Object -First 10 | ForEach-Object {
            [pscustomobject]@{ Path = $_.FullName; Version = $_.VersionInfo.ProductVersion; Description = $_.VersionInfo.FileDescription; Modified = Format-Date $_.LastWriteTime } })
        $app.Files = @($files | Select-Object -First 60)
        $app.Hosts = @($found | Select-Object -Unique | Select-Object -First 40)
    } catch { $app['Error'] = $_.Exception.Message }
    $out['HostedDesktopApp'] = $app

    # Target host list, keeping any non-default port seen (e.g. host:7765)
    $addHost = {
        param($v, $port)
        if (-not $v) { return }
        $v = "$v".Trim()
        if ($v -match '^https://') { $port = 443 }
        $v = $v -replace '^[a-z]+://', ''
        $v = ($v -split '[/\s]')[0]
        if ($v -match '^([^:]+):(\d+)$') { $v = $matches[1]; $port = [int]$matches[2] }
        if (-not $v -or $v -match '^(localhost|127\.)') { return }
        $v = $v.ToLower()
        $script:tmpHosts += $v
        if ($port) {
            if (-not $script:tmpPorts.ContainsKey($v)) { $script:tmpPorts[$v] = @() }
            if ($script:tmpPorts[$v] -notcontains [int]$port) { $script:tmpPorts[$v] += [int]$port }
        }
    }
    $script:tmpHosts = @()
    $script:tmpPorts = @{}
    foreach ($m in $out['Mru']) { & $addHost $m }
    foreach ($s in $servers) { & $addHost $s.Server }
    foreach ($r in $parsed) { & $addHost $r['full address'] $r['server port']; & $addHost $r['gateway hostname'] 443 }
    foreach ($f in $feeds) { foreach ($v in $f.Values) { if ("$v" -match '^https?://') { & $addHost $v } } }
    foreach ($u in $out['MsrdcSubscriptionUrls']) { if ($u -notmatch 'microsoft\.com|windows\.net|live\.com|msftauth|aka\.ms') { & $addHost $u } }
    foreach ($c in $conns) { & $addHost $c.RemoteAddress $c.RemotePort }
    foreach ($c in $hintConns) { & $addHost $c.Name $c.RemotePort }
    foreach ($s in $out['EventLogServers']) { & $addHost $s }
    foreach ($s in @($app.Hosts)) { if ($s -match $appRx) { & $addHost $s } }
    foreach ($s in $out['DnsCacheHintNames']) { & $addHost $s }
    # Order matters: strongest evidence first, so the target cap keeps it.
    $out['DiscoveredHosts'] = @($script:tmpHosts | Select-Object -Unique)
    $portMap = [ordered]@{}
    foreach ($k in ($script:tmpPorts.Keys | Sort-Object)) { $portMap[$k] = @($script:tmpPorts[$k]) }
    $out['DiscoveredPorts'] = $portMap
    $out
}

# ExtraTargets (host or host:port) go first so they survive the 6-target cap.
$extraHosts = @()
$portMap = Get-Val $Result['Rdp'] 'DiscoveredPorts'
if ($portMap -isnot [System.Collections.IDictionary]) { $portMap = [ordered]@{} }
foreach ($t in $ExtraTargets) {
    if (-not $t) { continue }
    $t = (("$t".Trim().ToLower() -replace '^[a-z]+://', '') -split '/')[0]
    if ($t -match '^([^:]+):(\d+)$') {
        $t = $matches[1]; $port = [int]$matches[2]
        if (-not $portMap.Contains($t)) { $portMap[$t] = @() }
        if (@($portMap[$t]) -notcontains $port) { $portMap[$t] = @(@($portMap[$t]) + $port) }
    }
    $extraHosts += $t
}
if ($Result['Rdp'] -is [System.Collections.IDictionary]) { $Result['Rdp']['DiscoveredPorts'] = $portMap }
$discovered = @()
if ($Result['Rdp'] -is [System.Collections.IDictionary] -and $Result['Rdp'].Contains('DiscoveredHosts')) { $discovered = @($Result['Rdp']['DiscoveredHosts']) }
# Names that do not resolve (internal session hosts behind a gateway, old entries) would waste one of the 6 slots.
$candidates = @(@($extraHosts) + @($discovered) | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 15)
$RdpHosts = @(); $unresolvedHosts = @()
foreach ($h in $candidates) {
    if ($RdpHosts.Count -ge 6) { break }
    if (Test-IPv4 $h) { $RdpHosts += $h; continue }
    $resolves = $false
    try { $resolves = [bool](@(Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' }).Count) } catch { }
    if ($resolves) { $RdpHosts += $h } else { $unresolvedHosts += $h }
}
if ($Result['Rdp'] -is [System.Collections.IDictionary]) { $Result['Rdp']['SelectedTargets'] = $RdpHosts; $Result['Rdp']['UnresolvedCandidates'] = $unresolvedHosts }
Write-Step ("Remote desktop targets: {0}" -f $(if ($RdpHosts.Count) { $RdpHosts -join ', ' } else { '(none found)' }))

# =====================================================================
# PHASE 2: background traceroutes + ping series
# =====================================================================
$Targets = @('1.1.1.1', '8.8.8.8') + $RdpHosts
$Jobs = @()
Write-Step 'Starting background traceroutes and ping series'
foreach ($t in $Targets) {
    $Jobs += [pscustomobject]@{ Kind = 'Trace'; Target = $t; Handle = (Start-IcmpJob -Kind Trace -Target $t -MaxHops 20 -TimeoutMs 750 -Label "trace $t") }
}
$PingTargets = @()
if ($Gateway) { $PingTargets += $Gateway }
$PingTargets += '1.1.1.1'
$PingTargets += $RdpHosts
$PingTargets = @($PingTargets | Select-Object -Unique)
# Hosts that ignore ICMP would only add timeouts and false 100% loss; precheck with 2 quick pings.
$script:IcmpSilent = @()
if ($script:FullLanguage) {
    foreach ($t in $PingTargets) {
        $ok = $false
        for ($k = 0; $k -lt 2 -and -not $ok; $k++) {
            try { $pr = (New-Object Net.NetworkInformation.Ping).Send($t, 800); if ($pr.Status -eq 'Success') { $ok = $true } } catch { }
        }
        if (-not $ok) { $script:IcmpSilent += $t }
    }
}
foreach ($t in $PingTargets) {
    if ($script:IcmpSilent -contains $t) { continue }
    $Jobs += [pscustomobject]@{ Kind = 'Ping'; Target = $t; Handle = (Start-IcmpJob -Kind Ping -Target $t -Count $PingCount -TimeoutMs 1000 -Label "ping $t") }
}
if ($script:IcmpSilent.Count) { Write-Step ("  No ICMP reply (ping series skipped, TCP series used): {0}" -f ($script:IcmpSilent -join ', ')) }

# TCP connect series to the first 3 remote desktop hosts that answer, each on the first port that answers.
$TcpSeriesJobs = @()
if ($script:FullLanguage) {
    foreach ($h in $RdpHosts) {
        if ($TcpSeriesJobs.Count -ge 3) { break }
        try {
            $addr = $h
            if (-not (Test-IPv4 $h)) { $addr = @(Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' })[0].IPAddress }
            $tryPorts = @(@(Get-Val $portMap $h) + @(443, 3389) | Where-Object { $_ } | Select-Object -Unique)
            $openPort = $tryPorts | Where-Object { Test-TcpPort $addr $_ 1500 } | Select-Object -First 1
            if ($openPort) { $TcpSeriesJobs += Start-TcpSeries $h $addr $openPort $PingCount }
        } catch { $script:Errors += [pscustomobject]@{ Collector = "TCP series $h"; Error = $_.Exception.Message } }
    }
    if ($TcpSeriesJobs.Count) { Write-Step ("  TCP series running: {0}" -f (($TcpSeriesJobs | ForEach-Object { '{0} tcp/{1}' -f $_.Target, $_.Port }) -join ', ')) }
}

# Admin + wired: LLDP/CDP capture with pktmon runs alongside everything else.
$script:PktmonStarted = $false
$PktmonEtl = Join-Path $OutDir 'lldp.etl'
$PktmonStartTime = $null
if ($script:AdminActive -and $Net -and "$($Net['PhysicalClass'])" -like 'Wired*') {
    try {
        Write-Step 'Admin: starting pktmon LLDP/CDP capture (stops automatically)'
        Invoke-Native 'pktmon.exe' 'filter remove' 15 | Out-Null
        Invoke-Native 'pktmon.exe' 'filter add LLDP -d 0x88CC' 15 | Out-Null
        Invoke-Native 'pktmon.exe' 'filter add CDP -m 01-00-0C-CC-CC-CC' 15 | Out-Null
        # Also listen to what every port on the VLAN hears anyway: broadcasts (ARP, DHCP, vendor discovery),
        # spanning tree and IPv6 router advertisements. Nothing is sent. A failed filter only narrows the capture.
        foreach ($flt in @('BCAST -m FF-FF-FF-FF-FF-FF', 'STP -m 01-80-C2-00-00-00', 'PVST -m 01-00-0C-CC-CC-CD', 'IPV6RA -m 33-33-00-00-00-01', 'UBNT -t UDP -p 10001', 'MNDP -t UDP -p 5678', 'NSDP -t UDP -p 63321', 'DHCP -t UDP -p 67', 'EAPOL -d 0x888E')) {
            try { Invoke-Native 'pktmon.exe' "filter add $flt" 15 | Out-Null } catch { }
        }
        Invoke-Native 'pktmon.exe' ('start --capture --comp nics --pkt-size 0 --file-name "{0}"' -f $PktmonEtl) 20 | Out-Null
        $script:PktmonStarted = $true
        $PktmonStartTime = Get-Date
    } catch {
        $script:Errors += [pscustomobject]@{ Collector = 'pktmon start'; Error = $_.Exception.Message }
    }
    # Vendor discovery questions go out once while the capture is listening: MikroTik and Netgear answer
    # by broadcast, which Windows Firewall would drop before a socket sees it, but the capture records it.
    if ($script:PktmonStarted -and $EnableVendorDiscovery -and $script:FullLanguage) {
        try { [void](Send-VendorDiscovery (Get-Val $Net 'SourceIp') 400) } catch { $script:Errors += [pscustomobject]@{ Collector = 'Vendor discovery (during capture)'; Error = $_.Exception.Message } }
    }
    # A lease renewal (the address is kept, nothing drops) makes the DHCP server answer while the capture
    # listens, so its address and the options it hands out are on record.
    if ($script:PktmonStarted -and $EnableDhcpRenew) {
        try {
            $rnAd = @($Net['Adapters'] | Where-Object { $_.Name -eq $Net['PhysicalAdapter'] }) | Select-Object -First 1
            if ($rnAd -and $rnAd.DhcpEnabled) { Invoke-Native 'ipconfig.exe' ('/renew "{0}"' -f $rnAd.Name) 25 | Out-Null }
        } catch { $script:Errors += [pscustomobject]@{ Collector = 'DHCP renew (during capture)'; Error = $_.Exception.Message } }
    }
}

# =====================================================================
# PHASE 3: local inventory (runs while the jobs work)
# =====================================================================
$Result['Machine'] = Invoke-Collector 'Machine and lifecycle' {
    $cs   = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 20
    $bios = Get-CimInstance Win32_BIOS -OperationTimeoutSec 20
    $os   = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 20
    $cpu  = @(Get-CimInstance Win32_Processor -OperationTimeoutSec 20)
    $mem  = @(Get-CimInstance Win32_PhysicalMemory -OperationTimeoutSec 20)
    $enc  = Get-CimInstance Win32_SystemEnclosure -OperationTimeoutSec 20
    $csp  = Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 20
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $laptopTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
    $isLaptop = [bool](@($enc.ChassisTypes) | Where-Object { $laptopTypes -contains $_ })
    $biosDate = $bios.ReleaseDate
    $biosAge = if ($biosDate) { [math]::Round(((Get-Date) - $biosDate).TotalDays / 365.25, 1) } else { $null }
    # A BIOS update moves the BIOS date forward, so an old PC can look new. When the CPU generation
    # is clearly older than the BIOS date, age comes from the CPU generation instead.
    $cpuName = ($cpu | Select-Object -First 1).Name
    $cpuYear = Get-CpuLaunchYear $cpuName
    $cpuAge = if ($cpuYear) { [math]::Round(((Get-Date) - (Get-Date -Year $cpuYear -Month 7 -Day 1)).TotalDays / 365.25, 1) } else { $null }
    $ageYears = $biosAge; $ageSource = 'BIOS date'
    if ($null -ne $cpuAge -and ($null -eq $biosAge -or $cpuAge -gt $biosAge + 1)) {
        $ageYears = $cpuAge
        $ageSource = if ($null -eq $biosAge) { 'CPU generation' } else { 'CPU generation (BIOS updated since purchase)' }
    }
    $build = [int]$os.BuildNumber
    $secureBoot = $null
    try { $secureBoot = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop).UEFISecureBootEnabled } catch { }
    $fwType = $null
    try { $fw = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction Stop).PEFirmwareType; $fwType = switch ($fw) { 1 { 'BIOS (legacy)' } 2 { 'UEFI' } default { "$fw" } } } catch { }

    $disks = @()
    try {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.FriendlyName; MediaType = "$($_.MediaType)"; BusType = "$($_.BusType)"; SizeGB = [math]::Round($_.Size / 1GB); Health = "$($_.HealthStatus)" }
        })
    } catch {
        $disks = @(Get-CimInstance Win32_DiskDrive -OperationTimeoutSec 20 | ForEach-Object {
            [pscustomobject]@{ Name = $_.Model; MediaType = "$($_.MediaType)"; BusType = $_.InterfaceType; SizeGB = [math]::Round($_.Size / 1GB); Health = $_.Status }
        })
    }
    $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 20 | ForEach-Object {
        [pscustomobject]@{ Drive = $_.DeviceID; SizeGB = [math]::Round($_.Size / 1GB); FreeGB = [math]::Round($_.FreeSpace / 1GB, 1); FreePct = if ($_.Size) { [math]::Round(100 * $_.FreeSpace / $_.Size) } else { $null } }
    })

    # TPM via tpmtool (often works without admin)
    $tpm = [ordered]@{}
    try {
        $tt = Invoke-Native 'tpmtool.exe' 'getdeviceinformation' 20
        foreach ($line in ($tt -split "`r?`n")) {
            if ($line -match '^\s*-?\s*(TPM Present|TPM Version|TPM Manufacturer ID|TPM Manufacturer Full Name|TPM Manufacturer Version|Is Initialized|Ready For Storage|Ready For Attestation)\s*:\s*(.*)$') { $tpm[$matches[1]] = $matches[2].Trim() }
        }
    } catch { $tpm['Error'] = $_.Exception.Message }

    # Battery health
    $battery = $null
    if (Get-CimInstance Win32_Battery -OperationTimeoutSec 10 -ErrorAction SilentlyContinue) {
        try {
            $xmlPath = Join-Path $env:TEMP ('sa_battery_{0}.xml' -f (Get-Random))
            Invoke-Native 'powercfg.exe' ('/batteryreport /xml /output "{0}"' -f $xmlPath) 30 | Out-Null
            [xml]$bx = Get-Content -LiteralPath $xmlPath -Raw
            Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue
            $battery = @($bx.BatteryReport.Batteries.Battery | ForEach-Object {
                $design = [double]$_.DesignCapacity; $full = [double]$_.FullChargeCapacity
                [pscustomobject]@{ Id = $_.Id; Manufacturer = $_.Manufacturer; DesignmWh = $design; FullChargemWh = $full; HealthPct = if ($design -gt 0) { [math]::Round(100 * $full / $design) } else { $null }; CycleCount = $_.CycleCount }
            })
        } catch { $battery = "unavailable: $($_.Exception.Message)" }
    }

    [ordered]@{
        Hostname        = $env:COMPUTERNAME
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        ModelVersion    = $csp.Version
        SerialNumber    = $bios.SerialNumber
        ChassisTypes    = @($enc.ChassisTypes)
        FormFactor      = if ($isLaptop) { 'Laptop' } else { 'Desktop/Other' }
        BiosVersion     = $bios.SMBIOSBIOSVersion
        BiosDate        = Format-Date $biosDate
        ApproxAgeYears  = $ageYears
        AgeSource       = $ageSource
        BiosAgeYears    = $biosAge
        CpuLaunchYear   = $cpuYear
        Cpu             = $cpuName
        CpuCores        = ($cpu | Measure-Object NumberOfCores -Sum).Sum
        CpuThreads      = ($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum
        RamGB           = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        RamSlots        = @($mem | ForEach-Object { '{0} {1}GB {2}MHz' -f $_.DeviceLocator, [math]::Round($_.Capacity / 1GB), $_.Speed })
        Disks           = $disks
        Volumes         = $vols
        OsCaption       = $os.Caption
        OsVersion       = $os.Version
        OsBuild         = $build
        OsUbr           = $cv.UBR
        OsDisplayVersion = $cv.DisplayVersion
        OsEdition       = $cv.EditionID
        OsArchitecture  = $os.OSArchitecture
        IsWindows10     = ($build -lt 22000)
        OsInstallDate   = Format-Date $os.InstallDate
        LastBoot        = Format-Date $os.LastBootUpTime
        UptimeDays      = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        FirmwareType    = $fwType
        SecureBootRegistry = $secureBoot
        Tpm             = $tpm
        Battery         = $battery
        Domain          = $cs.Domain
        PartOfDomain    = $cs.PartOfDomain
    }
}

$Result['Identity'] = Invoke-Collector 'Identity and user structure' {
    $out = [ordered]@{}
    $ds = Invoke-Native 'dsregcmd.exe' '/status' 30
    $kv = ConvertFrom-ColonText $ds
    $keep = @('AzureAdJoined','EnterpriseJoined','DomainJoined','DomainName','WorkplaceJoined','TenantName','TenantId','MdmUrl','MdmComplianceUrl','DeviceId','AzureAdPrt','IsUserAzureAD','NgcSet','WorkplaceTenantName')
    $dj = [ordered]@{}
    foreach ($k in $keep) { if ($kv.Contains($k)) { $dj[$k] = $kv[$k] } }
    $out['Dsregcmd'] = $dj
    $join = 'Workgroup'
    if ($dj['AzureAdJoined'] -eq 'YES' -and $dj['DomainJoined'] -eq 'YES') { $join = 'Hybrid Entra joined' }
    elseif ($dj['AzureAdJoined'] -eq 'YES') { $join = 'Entra joined' }
    elseif ($dj['DomainJoined'] -eq 'YES') { $join = 'AD domain joined' }
    elseif ($dj['WorkplaceJoined'] -eq 'YES') { $join = 'Workgroup + Entra registered' }
    $out['JoinType'] = $join
    $out['IntuneEnrolled'] = [bool]$dj['MdmUrl']

    if ($script:SameUser) {
        try { $out['Upn'] = (Invoke-Native 'whoami.exe' '/upn' 10).Trim() } catch { }
        try {
            $g = ((Invoke-Native 'whoami.exe' '/groups /fo csv' 10) -split "`r?`n" | Where-Object { $_.Trim() }) | ConvertFrom-Csv
            $out['Groups'] = @($g | ForEach-Object { $_.'Group Name' } | Where-Object { $_ -and $_ -notmatch '^(Mandatory Label|NT AUTHORITY\\(LogonSessionId|This Organization|Authenticated|INTERACTIVE|Local account)|LOCAL$|CONSOLE LOGON)' })
            $out['UserIsLocalAdmin'] = [bool]($g | Where-Object { $_.SID -eq 'S-1-5-32-544' })
        } catch { }
    } else {
        $out['Note'] = 'Run by a different account than the signed-in user; group membership is for the runner and is not collected.'
    }

    # Local Administrators members (net localgroup is the most tolerant of orphaned/Entra SIDs)
    $adminGroup = 'Administrators'
    try { $adminGroup = ((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value -split '\\')[-1] } catch { }
    $members = @()
    try {
        $raw = Invoke-Native 'net.exe' ('localgroup "{0}"' -f $adminGroup) 15
        $inList = $false
        foreach ($line in ($raw -split "`r?`n")) {
            if ($line -match '^-{5,}') { $inList = $true; continue }
            if ($inList) {
                if ($line -match '^The command completed' -or -not $line.Trim()) { continue }
                $members += $line.Trim()
            }
        }
    } catch { }
    $out['LocalAdmins'] = $members
    if (-not $out.Contains('UserIsLocalAdmin')) {
        $short = ($script:UserName -split '\\')[-1]
        $out['UserIsLocalAdmin'] = [bool]($members | Where-Object { $_ -eq $script:UserName -or ($_ -split '\\')[-1] -eq $short })
    }

    try {
        $out['LocalUsers'] = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; LastLogon = Format-Date $_.LastLogon; PasswordLastSet = Format-Date $_.PasswordLastSet }
        })
    } catch { }

    $profiles = @()
    foreach ($p in @(Get-CimInstance Win32_UserProfile -Filter 'Special=False' -OperationTimeoutSec 20)) {
        $name = $null
        try { $name = (New-Object Security.Principal.SecurityIdentifier $p.SID).Translate([Security.Principal.NTAccount]).Value } catch { }
        $ntuser = $null
        try { $ntuser = Format-Date (Get-Item -LiteralPath (Join-Path $p.LocalPath 'NTUSER.DAT') -Force -ErrorAction Stop).LastWriteTime } catch { }
        $profiles += [pscustomobject]@{ Account = $name; Sid = $p.SID; Path = $p.LocalPath; Loaded = $p.Loaded; LastUseTime = Format-Date $p.LastUseTime; NtuserLastWrite = $ntuser }
    }
    $out['Profiles'] = $profiles
    $recent = @($profiles | Where-Object { $_.NtuserLastWrite -and ([datetime]$_.NtuserLastWrite) -gt (Get-Date).AddDays(-$LookbackDays) })
    $out['ProfilesActiveInLookback'] = $recent.Count
    $out['LikelyShared'] = ($recent.Count -gt 1)

    try { $out['SessionsQuser'] = (Invoke-Native 'quser.exe' '' 10).Trim() } catch { }

    $drives = @()
    $netKey = "$($script:UserHive)\Network"
    if (Test-Path -LiteralPath $netKey) {
        foreach ($k in (Get-ChildItem -LiteralPath $netKey)) {
            $drives += [pscustomobject]@{ Drive = $k.PSChildName.ToUpper() + ':'; RemotePath = (Get-ItemProperty -LiteralPath $k.PSPath).RemotePath }
        }
    }
    $out['MappedDrives'] = $drives

    $od = @()
    $odRoot = "$($script:UserHive)\Software\Microsoft\OneDrive\Accounts"
    if (Test-Path -LiteralPath $odRoot) {
        foreach ($k in (Get-ChildItem -LiteralPath $odRoot)) {
            $v = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($v.UserEmail -or $v.UserFolder) { $od += [pscustomobject]@{ Account = $k.PSChildName; UserEmail = $v.UserEmail; UserFolder = $v.UserFolder; TenantName = $v.DisplayName } }
        }
    }
    $out['OneDrive'] = $od
    $out
}

$Result['Software'] = Invoke-Collector 'Installed software and security' {
    $paths = @(
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; S = 'Machine' },
        @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; S = 'Machine32' },
        @{ P = "$($script:UserHive)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; S = 'User' }
    )
    $apps = @()
    foreach ($x in $paths) {
        foreach ($i in @(Get-ItemProperty -Path $x.P -ErrorAction SilentlyContinue)) {
            if (-not $i.DisplayName -or $i.SystemComponent -eq 1 -or $i.ParentKeyName) { continue }
            $apps += [pscustomobject]@{ Name = "$($i.DisplayName)".Trim(); Version = $i.DisplayVersion; Publisher = $i.Publisher; InstallDate = $i.InstallDate; Scope = $x.S }
        }
    }
    $apps = @($apps | Sort-Object Name, Version -Unique)

    $tagRules = [ordered]@{
        RMM          = 'ConnectWise Automate|LabTech|Datto RMM|CentraStage|Autotask Endpoint|NinjaRMM|NinjaOne|N-able|SolarWinds MSP|Kaseya|Atera|Syncro|Pulseway|Action1|ManageEngine|Tactical RMM|Mesh ?Agent|Automox|Immybot'
        RemoteAccess = 'ScreenConnect|ConnectWise Control|TeamViewer|AnyDesk|Splashtop|GoTo|LogMeIn|BeyondTrust|Bomgar|RustDesk|Chrome Remote Desktop|Zoho Assist'
        Security     = 'Huntress|SentinelOne|CrowdStrike|Sophos|Bitdefender|ESET|Malwarebytes|Webroot|Trend Micro|Symantec|McAfee|Trellix|Cylance|Carbon Black|Arctic Wolf|Blackpoint|Todyl|Cisco Secure Endpoint|ThreatLocker|Avast|AVG|Norton|Kaspersky|Defender for Endpoint|Rapid7|Qualys|Liongard|Perch'
        VPN          = 'FortiClient|GlobalProtect|AnyConnect|Cisco Secure Client|NetExtender|Mobile Connect|WatchGuard|Sophos Connect|OpenVPN|WireGuard|Zscaler|Cloudflare WARP|Netskope|Pulse Secure|Ivanti Secure|Check Point|Tailscale|ZeroTier|NordLayer|Perimeter 81|Twingate|Meraki'
        RemoteDesktop = 'Remote Desktop|Windows App|Citrix Workspace|VMware Horizon|Omnissa|Parallels Client|ThinPrint|TSPrint|TSScan|RDP|Terminal Services'
        Office       = '^Microsoft (365|Office)'
        Browser      = '^Google Chrome$|Mozilla Firefox|^Microsoft Edge$|Brave'
    }
    $tagged = [ordered]@{}
    foreach ($tag in $tagRules.Keys) {
        $tagged[$tag] = @($apps | Where-Object { "$($_.Name) $($_.Publisher)" -match $tagRules[$tag] } | ForEach-Object { ('{0} {1}' -f $_.Name, $_.Version).Trim() })
    }
    $vpnVendor = @()
    foreach ($v in $tagged['VPN']) {
        if ($v -match 'FortiClient') { $vpnVendor += 'Fortinet' }
        elseif ($v -match 'GlobalProtect') { $vpnVendor += 'Palo Alto Networks' }
        elseif ($v -match 'AnyConnect|Cisco Secure Client') { $vpnVendor += 'Cisco' }
        elseif ($v -match 'NetExtender|Mobile Connect') { $vpnVendor += 'SonicWall' }
        elseif ($v -match 'WatchGuard') { $vpnVendor += 'WatchGuard' }
        elseif ($v -match 'Sophos Connect') { $vpnVendor += 'Sophos' }
        elseif ($v -match 'Meraki') { $vpnVendor += 'Cisco Meraki' }
    }

    $av = @()
    try {
        $av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -OperationTimeoutSec 20 -ErrorAction Stop | ForEach-Object {
            $hex = '{0:X6}' -f [int]$_.productState
            [pscustomobject]@{ Name = $_.displayName; State = $_.productState; Enabled = ($hex.Substring(2, 2) -match '1[01]'); UpToDate = ($hex.Substring(4, 2) -eq '00') }
        })
    } catch { }
    $fwProd = @()
    try { $fwProd = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct -OperationTimeoutSec 20 -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch { }
    $winFw = @()
    try { $winFw = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Profile = $_.Name; Enabled = "$($_.Enabled)" } }) } catch { }
    $netProfile = @()
    try { $netProfile = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; Network = $_.Name; Category = "$($_.NetworkCategory)"; IPv4Connectivity = "$($_.IPv4Connectivity)" } }) } catch { }
    $hotfix = @()
    try {
        $hotfix = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 5 |
            ForEach-Object { [pscustomobject]@{ Id = $_.HotFixID; Description = $_.Description; InstalledOn = Format-Date $_.InstalledOn } })
    } catch { }
    $defender = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender = [ordered]@{ AMRunningMode = $mp.AMRunningMode; RealTimeProtection = $mp.RealTimeProtectionEnabled; SignatureLastUpdated = Format-Date $mp.AntivirusSignatureLastUpdated; SignatureAgeDays = $mp.AntivirusSignatureAge; TamperProtected = $mp.IsTamperProtected }
    } catch { }

    # BitLocker without admin: Shell property on the OS volume
    $bl = $null
    try {
        $shell = New-Object -ComObject Shell.Application
        $sysDrive = $env:SystemDrive
        $raw = $shell.NameSpace(17).ParseName($sysDrive).ExtendedProperty('System.Volume.BitLockerProtection')
        $map = @{ 0 = 'Not encryptable'; 1 = 'On'; 2 = 'Off'; 3 = 'Encrypting'; 4 = 'Decrypting'; 5 = 'Suspended'; 6 = 'On (locked)' }
        $bl = [ordered]@{ Drive = $sysDrive; Raw = $raw; Status = if ($null -ne $raw -and $map.ContainsKey([int]$raw)) { $map[[int]$raw] } else { 'Unknown' } }
    } catch { }

    [ordered]@{
        AppCount        = $apps.Count
        Apps            = $apps
        Tagged          = $tagged
        FirewallVendorHintsFromVpnClient = @($vpnVendor | Sort-Object -Unique)
        AntiVirus       = $av
        FirewallProducts = $fwProd
        WindowsFirewall = $winFw
        NetworkProfiles = $netProfile
        RecentHotfixes  = $hotfix
        Defender        = $defender
        BitLocker       = $bl
    }
}

$Result['Peripherals'] = Invoke-Collector 'Printers and peripherals' {
    $out = [ordered]@{}

    # Printers
    $ports = @{}
    try { foreach ($p in @(Get-PrinterPort -ErrorAction Stop)) { $ports[$p.Name] = $p } } catch { }
    $defaultPrinter = $null
    try {
        $dev = (Get-ItemProperty -LiteralPath "$($script:UserHive)\Software\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction Stop).Device
        if ($dev) { $defaultPrinter = ($dev -split ',')[0] }
    } catch { }
    $virtualRegex = 'Microsoft Print to PDF|Microsoft XPS|OneNote|^Fax$|Send To OneNote|Adobe PDF|PDF24|CutePDF|Snagit|Webex Document'
    $printers = @()
    try {
        foreach ($p in @(Get-Printer -ErrorAction Stop)) {
            $port = $ports[$p.PortName]
            $hostAddr = $null
            if ($port -and $port.PrinterHostAddress) { $hostAddr = $port.PrinterHostAddress }
            elseif ($p.PortName -match '^IP_(\d{1,3}(\.\d{1,3}){3})') { $hostAddr = $matches[1] }
            elseif ($p.PortName -match '^(\d{1,3}(\.\d{1,3}){3})') { $hostAddr = $matches[1] }
            $portType = 'Other'
            if ($p.Type -eq 'Connection' -or $p.Name -like '\\*') { $portType = 'Shared (print server)' }
            elseif ($p.PortName -match '^USB') { $portType = 'USB' }
            elseif ($p.PortName -match '^WSD') { $portType = 'WSD (network)' }
            elseif ($hostAddr) { $portType = 'TCP/IP' }
            elseif ($p.PortName -match '^(LPT|COM)\d') { $portType = 'Parallel/Serial' }
            elseif ($p.PortName -match '^TS\d') { $portType = 'RDP redirected' }
            elseif ($p.PortName -match 'PORTPROMPT|nul:|FILE:|SHRFAX|OneNote|PDF') { $portType = 'Virtual' }
            $printers += [pscustomobject]@{
                Name = $p.Name; Driver = $p.DriverName; Port = $p.PortName; PortType = $portType; HostAddress = $hostAddr
                Shared = $p.Shared; ShareName = $p.ShareName; Location = $p.Location; Status = "$($p.PrinterStatus)"
                IsDefault = ($p.Name -eq $defaultPrinter); IsVirtual = ($p.Name -match $virtualRegex -or $portType -eq 'Virtual')
            }
        }
    } catch { $out['PrinterError'] = $_.Exception.Message }
    $out['Printers'] = $printers
    $out['DefaultPrinter'] = $defaultPrinter
    $userConns = @()
    $pc = "$($script:UserHive)\Printers\Connections"
    if (Test-Path -LiteralPath $pc) { $userConns = @(Get-ChildItem -LiteralPath $pc | ForEach-Object { $_.PSChildName -replace ',', '\' }) }
    $out['UserPrinterConnections'] = $userConns

    # PnP devices by class
    $pnp = @(Get-CimInstance Win32_PnPEntity -OperationTimeoutSec 30 | Where-Object { $_.Present -ne $false })
    $classMap = [ordered]@{
        'Scanner/Camera' = '^(Image|Camera)$'
        'Audio'          = '^AudioEndpoint$'
        'SmartCard'      = '^(SmartCardReader|SmartCard)$'
        'Serial/COM'     = '^Ports$'
        'Biometric'      = '^Biometric$'
        'Phone/WPD'      = '^WPD$'
        'Bluetooth'      = '^Bluetooth$'
    }
    $byClass = [ordered]@{}
    foreach ($k in $classMap.Keys) {
        $byClass[$k] = @($pnp | Where-Object { "$($_.PNPClass)" -match $classMap[$k] } | ForEach-Object { $_.Name } | Where-Object { $_ } | Sort-Object -Unique)
    }
    $byClass['Bluetooth'] = @($byClass['Bluetooth'] | Where-Object { $_ -notmatch 'Enumerator|Protocol|Transport|Service|LE Generic|Generic Access|Generic Attribute|Device \(RFCOMM|Avrcp|Hands-Free|Audio Gateway|Wireless Bluetooth' })
    $out['DevicesByClass'] = $byClass

    $notableRegex = 'Topaz|Wacom|signotec|Scriptel|ePad|StepOver|Evolis|Zebra|DYMO|Rollo|Fujitsu|ScanSnap|fi-\d|Canon|Epson|Brother|Panini|Digital Check|RDM|Magtek|Ingenico|Verifone|Honeywell|Metrologic|Symbol|Datalogic|Jabra|Plantronics|Poly|Logitech|Yealink|Sennheiser|EPOS|YubiKey|Yubico|Kodak|Visioneer|Ambir|Star Micronics|Seiko|Citizen|HID Global|OMNIKEY|Identiv|Elo|Topaz'
    $usb = @($pnp | Where-Object { $_.DeviceID -match '^(USB|HID)\\VID_' -and $_.Name -notmatch 'Root Hub|Generic USB Hub|USB Composite Device|Host Controller|HID-compliant (vendor|system|consumer|device)|USB Input Device|Generic SuperSpeed|USB Mass Storage|Billboard' } |
        ForEach-Object {
            $vid = $null; $pidv = $null
            if ($_.DeviceID -match 'VID_([0-9A-F]{4})') { $vid = $matches[1] }
            if ($_.DeviceID -match 'PID_([0-9A-F]{4})') { $pidv = $matches[1] }
            [pscustomobject]@{ Name = $_.Name; Manufacturer = $_.Manufacturer; Class = "$($_.PNPClass)"; VID = $vid; PID = $pidv }
        } | Sort-Object Name, VID, PID -Unique)
    $out['UsbDevices'] = $usb
    $out['NotableDevices'] = @($pnp | Where-Object { "$($_.Name) $($_.Manufacturer)" -match $notableRegex -and "$($_.PNPClass)" -notmatch '^(System|SoftwareDevice|SoftwareComponent|Net|Monitor|Display)$' } |
        ForEach-Object { '{0} [{1}]' -f $_.Name, $_.PNPClass } | Sort-Object -Unique)
    $out['Docks'] = @($pnp | Where-Object { $_.Name -match 'Dock|WD19|WD22|TB16|TB18|Thunderbolt\(TM\) Controller|DisplayLink|USB-C Dock|CalDigit|Plugable|Targus|Kensington' } | ForEach-Object { $_.Name } | Sort-Object -Unique)

    # Displays
    $mons = @()
    try {
        $ids = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -OperationTimeoutSec 15 -ErrorAction Stop)
        $parms = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -OperationTimeoutSec 15 -ErrorAction SilentlyContinue)
        foreach ($m in $ids) {
            $dec = { param($a) if ($a) { (($a | Where-Object { $_ -ne 0 }) | ForEach-Object { [char]$_ }) -join '' } }
            $bp = $parms | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
            $diag = $null
            if ($bp -and $bp.MaxHorizontalImageSize -gt 0) { $diag = [math]::Round([math]::Sqrt([math]::Pow($bp.MaxHorizontalImageSize, 2) + [math]::Pow($bp.MaxVerticalImageSize, 2)) / 2.54, 1) }
            $mons += [pscustomobject]@{ Manufacturer = & $dec $m.ManufacturerName; Model = & $dec $m.UserFriendlyName; Serial = & $dec $m.SerialNumberID; Year = $m.YearOfManufacture; DiagonalInches = $diag }
        }
    } catch { }
    $out['Monitors'] = $mons
    $screens = @()
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $screens = @([System.Windows.Forms.Screen]::AllScreens | ForEach-Object { [pscustomobject]@{ Device = $_.DeviceName; Primary = $_.Primary; Width = $_.Bounds.Width; Height = $_.Bounds.Height } })
    } catch { }
    $out['Screens'] = $screens
    $out['MonitorCount'] = [math]::Max($mons.Count, $screens.Count)
    $out['Gpu'] = @(Get-CimInstance Win32_VideoController -OperationTimeoutSec 15 | ForEach-Object { '{0} (driver {1})' -f $_.Name, $_.DriverVersion })

    # Local peripherals vs RDP redirection settings
    $rdpFiles = @()
    if ($Result['Rdp'] -and $Result['Rdp'].Contains('RdpFiles')) { $rdpFiles = @($Result['Rdp']['RdpFiles']) }
    $realPrinters = @($printers | Where-Object { -not $_.IsVirtual })
    $checks = @()
    foreach ($r in $rdpFiles) {
        $eff = [ordered]@{
            Printers   = if ($r.Contains('redirectprinters')) { $r['redirectprinters'] -eq '1' } else { $true }
            Clipboard  = if ($r.Contains('redirectclipboard')) { $r['redirectclipboard'] -eq '1' } else { $true }
            Drives     = if ($r.Contains('drivestoredirect')) { [bool]$r['drivestoredirect'] } else { $false }
            SmartCards = if ($r.Contains('redirectsmartcards')) { $r['redirectsmartcards'] -eq '1' } else { $true }
            ComPorts   = if ($r.Contains('redirectcomports')) { $r['redirectcomports'] -eq '1' } else { $false }
            UsbDevices = if ($r.Contains('usbdevicestoredirect')) { [bool]$r['usbdevicestoredirect'] } else { $false }
            Camera     = if ($r.Contains('camerastoredirect')) { [bool]$r['camerastoredirect'] } else { $false }
            AudioPlay  = if ($r.Contains('audiomode')) { $r['audiomode'] -eq '0' } else { $true }
            Microphone = if ($r.Contains('audiocapturemode')) { $r['audiocapturemode'] -eq '1' } else { $false }
            MultiMon   = if ($r.Contains('use multimon')) { $r['use multimon'] -eq '1' } else { $false }
        }
        $gaps = @()
        if ($realPrinters.Count -gt 0 -and -not $eff.Printers) { $gaps += 'local printers but printer redirection off' }
        if ($byClass['SmartCard'].Count -gt 0 -and -not $eff.SmartCards) { $gaps += 'smart card reader but smart card redirection off' }
        if ($byClass['Serial/COM'].Count -gt 0 -and -not $eff.ComPorts) { $gaps += 'COM devices but COM redirection off' }
        if ($byClass['Scanner/Camera'].Count -gt 0 -and -not ($eff.Camera -or $eff.UsbDevices)) { $gaps += 'scanner/camera present but camera/USB redirection off' }
        if ($out['MonitorCount'] -gt 1 -and -not $eff.MultiMon) { $gaps += 'multiple monitors but multimon off' }
        $checks += [pscustomobject]@{ RdpFile = $r['Path']; Target = $r['full address']; Effective = $eff; Gaps = $gaps }
    }
    $out['RedirectionCheck'] = $checks
    $out
}

# ---------------------------------------------------------------------
# Windows 11 24H2+ only lets netsh read Wi-Fi details when location is allowed for desktop apps.
# These helpers allow it briefly for the running account and put every value back afterwards.
# ---------------------------------------------------------------------
$LocKey = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'

$Result['Wireless'] = Invoke-Collector 'Wireless' {
    $hasWifi = @($Result['Network']['Adapters'] | Where-Object { $_.Class -eq 'Wi-Fi' }).Count -gt 0
    if (-not $hasWifi) { return [ordered]@{ Status = 'No Wi-Fi adapter' } }
    $out = [ordered]@{}
    $isBlocked = { param($t) $t -match 'location permission|Location services|ms-settings:privacy-location' }
    $loc = [ordered]@{ Needed = $false; Attempted = $false; Result = $null; Restored = $null }
    $changes = @()
    $nText = $null
    try {
        $ifText = Invoke-Native 'netsh.exe' 'wlan show interfaces' 20
        if (& $isBlocked $ifText) {
            $loc.Needed = $true
            $pol = Get-LocationPolicy
            $loc['Before'] = $pol
            $deviceOff = ($pol.DeviceValue -eq 'Deny')
            if (-not $TempEnableLocation) { $loc.Result = 'Not attempted ($TempEnableLocation = $false)' }
            elseif ($pol.PolicyBlocked) { $loc.Result = "Blocked by policy ($($pol.PolicyReason)); not overridden" }
            elseif ($deviceOff -and -not $script:AdminActive) { $loc.Result = 'Location services are off device-wide; only admin mode can enable them temporarily' }
            else {
                $loc.Attempted = $true
                $changes = @(Enable-TempLocation -IncludeDevice $deviceOff)
                Start-Sleep -Milliseconds 1500
                $ifText = Invoke-Native 'netsh.exe' 'wlan show interfaces' 20
                $loc.Result = if (& $isBlocked $ifText) { 'Still blocked after temporary enable' } else { 'Temporarily enabled; Wi-Fi read OK' }
            }
        }
        if (-not (& $isBlocked $ifText)) {
            try { $nText = Invoke-Native 'netsh.exe' 'wlan show networks mode=bssid' 25 } catch { }
        }
    } finally {
        if ($changes.Count -gt 0) {
            $failed = @(Restore-TempLocation $changes)
            $loc.Restored = ($failed.Count -eq 0)
            if ($failed.Count) {
                Write-Step ("  WARNING: could not restore location setting(s): {0}" -f ($failed -join ', ')) 'Red'
                $loc['RestoreFailed'] = $failed
            }
        }
    }
    $out['LocationWorkaround'] = $loc
    if (& $isBlocked $ifText) {
        $out['Status'] = 'Blocked by Windows location permission'
        $out['Fix'] = if ("$($loc.Result)" -like 'Blocked by policy*') { "Location is disabled by policy ($($loc['Before'].PolicyReason)); Wi-Fi radio details cannot be read on this machine. SSID comes from the network profile instead." }
                      elseif ("$($loc.Result)" -like 'Location services are off device-wide*') { 'Re-run in an elevated ISE, or turn on Settings > Privacy & security > Location > Location services.' }
                      else { "Workaround: $($loc.Result). Manual fix: Settings > Privacy & security > Location: turn on Location services and 'Let desktop apps access your location', then re-run." }
        Write-Step "  Wi-Fi details blocked by location permission ($($loc.Result))" 'Yellow'
    } elseif ($loc.Attempted) {
        Write-Step '  Location allowed temporarily for the Wi-Fi read, then restored'
    }
    $i = ConvertFrom-ColonText $ifText
    $bssid = if ($i['AP BSSID']) { $i['AP BSSID'] } else { $i['BSSID'] }
    $sig = $null
    if ($i['Signal'] -match '(\d+)%') { $sig = [int]$matches[1] }
    $rssi = $null
    if ($i['Rssi'] -match '(-?\d+)') { $rssi = [int]$matches[1] }
    $ch = $null
    if ($i['Channel'] -match '(\d+)') { $ch = [int]$matches[1] }
    $band = $i['Band']
    if (-not $band -and $ch) { $band = if ($ch -le 14) { '2.4 GHz' } else { '5 GHz (or 6 GHz)' } }
    $out['Current'] = [ordered]@{
        State = $i['State']; SSID = $i['SSID']; BSSID = $bssid; ApVendor = (Get-MacVendor $bssid)
        RadioType = $i['Radio type']; Band = $band; Channel = $ch; Authentication = $i['Authentication']; Cipher = $i['Cipher']
        SignalPct = $sig; ApproxDbm = if ($rssi) { $rssi } elseif ($null -ne $sig) { [int](($sig / 2) - 100) } else { $null }
        ReceiveMbps = $i['Receive rate (Mbps)']; TransmitMbps = $i['Transmit rate (Mbps)']; Profile = $i['Profile']
        Adapter = $i['Description']; ConnectionMode = $i['Connection mode']; SsidSource = 'netsh'
    }
    if (-not $out['Current'].SSID) {
        # netsh blocked: the network profile name is normally the SSID and needs no location permission.
        try {
            $wifiIdx = @($Result['Network']['Adapters'] | Where-Object { $_.Class -eq 'Wi-Fi' -and $_.Status -eq 'Up' } | ForEach-Object { $_.IfIndex })
            $prof = Get-NetConnectionProfile -ErrorAction Stop | Where-Object { $wifiIdx -contains $_.InterfaceIndex } | Select-Object -First 1
            if ($prof) { $out['Current'].SSID = $prof.Name; $out['Current'].SsidSource = 'network profile (netsh blocked)' }
        } catch { }
    }

    # Nearby networks
    $nets = @()
    try {
        $ssid = $null; $auth = $null; $cur = $null
        foreach ($line in ($nText -split "`r?`n")) {
            if ($line -match '^SSID \d+ : (.*)$') { $ssid = $matches[1].Trim(); continue }
            if ($line -match '^\s+Authentication\s+:\s(.*)$') { $auth = $matches[1].Trim(); continue }
            if ($line -match '^\s+BSSID \d+\s+:\s(.*)$') {
                if ($cur) { $nets += [pscustomobject]$cur }
                $cur = [ordered]@{ SSID = $ssid; Auth = $auth; BSSID = $matches[1].Trim(); SignalPct = $null; Radio = $null; Band = $null; Channel = $null }
                continue
            }
            if ($cur) {
                if ($line -match '^\s+Signal\s+:\s(\d+)%') { $cur.SignalPct = [int]$matches[1] }
                elseif ($line -match '^\s+Radio type\s+:\s(.*)$') { $cur.Radio = $matches[1].Trim() }
                elseif ($line -match '^\s+Band\s+:\s(.*)$') { $cur.Band = $matches[1].Trim() }
                elseif ($line -match '^\s+Channel\s+:\s(\d+)') { $cur.Channel = [int]$matches[1] }
            }
        }
        if ($cur) { $nets += [pscustomobject]$cur }
    } catch { }
    foreach ($n in $nets) {
        $vendor = $null
        $clean = ($n.BSSID -replace '[^0-9A-Fa-f]', '').ToUpper()
        if ($clean.Length -ge 6 -and $script:OuiTable.ContainsKey($clean.Substring(0, 6))) { $vendor = $script:OuiTable[$clean.Substring(0, 6)] }
        $n | Add-Member -NotePropertyName Vendor -NotePropertyValue $vendor
    }
    $out['Nearby'] = $nets
    $out['NearbyBssidCount'] = $nets.Count
    $out['NearbySsidCount'] = @($nets | Select-Object -ExpandProperty SSID -Unique).Count
    if ($out['Current'].SSID) {
        $same = @($nets | Where-Object { $_.SSID -eq $out['Current'].SSID })
        $out['SameSsidAps'] = $same.Count
        $out['SameSsidVendors'] = @($same | ForEach-Object { $_.Vendor } | Where-Object { $_ } | Sort-Object -Unique)
    }
    $chanLoad = @($nets | Where-Object { $_.Channel } | Group-Object Channel | Sort-Object Count -Descending | ForEach-Object { 'ch{0}={1}' -f $_.Name, $_.Count })
    $out['ChannelLoad'] = $chanLoad

    # Saved profile names only (never keys)
    try {
        $pText = Invoke-Native 'netsh.exe' 'wlan show profiles' 15
        $out['SavedProfiles'] = @($pText -split "`r?`n" | Where-Object { $_ -match 'Profile\s+:\s(.+)$' } | ForEach-Object { ($_ -split ':\s', 2)[1].Trim() })
    } catch { }

    # Wi-Fi event history
    try {
        $ev = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime = (Get-Date).AddDays(-$LookbackDays) } 3000)
        # A "real drop" is a disconnect followed by a reconnect to the same SSID within 2 minutes.
        # Disconnects without a quick reconnect are mostly the laptop leaving (moving, sleep, shutdown).
        $cd = @($ev | Where-Object { $_.Id -eq 8001 -or $_.Id -eq 8003 } | Sort-Object TimeCreated | ForEach-Object {
            $ssidV = $null; $reason = $null
            if ($_.Message -match 'SSID:\s*(.+)') { $ssidV = $matches[1].Trim() }
            if ($_.Message -match 'Reason:\s*(.+)') { $reason = $matches[1].Trim() }
            [pscustomobject]@{ Id = $_.Id; Time = $_.TimeCreated; SSID = $ssidV; Reason = $reason }
        })
        $drops = @()
        for ($x = 0; $x -lt $cd.Count; $x++) {
            if ($cd[$x].Id -ne 8003) { continue }
            for ($y = $x + 1; $y -lt $cd.Count; $y++) {
                if (($cd[$y].Time - $cd[$x].Time).TotalSeconds -gt 120) { break }
                if ($cd[$y].Id -eq 8001 -and $cd[$y].SSID -eq $cd[$x].SSID) {
                    $drops += [pscustomobject]@{ Time = Format-Date $cd[$x].Time; SSID = $cd[$x].SSID; Reason = $cd[$x].Reason; DownSeconds = [int]($cd[$y].Time - $cd[$x].Time).TotalSeconds }
                    break
                }
            }
        }
        $out['Events'] = [ordered]@{
            Connected     = @($ev | Where-Object Id -eq 8001).Count
            ConnectFailed = @($ev | Where-Object Id -eq 8002).Count
            Disconnected  = @($ev | Where-Object Id -eq 8003).Count
            RealDrops     = $drops.Count
            RealDropsBySsid = @($drops | Group-Object SSID | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })
            RecentRealDrops = @($drops | Select-Object -Last 10)
            DropReasons   = @($drops | Group-Object Reason | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })
        }
    } catch { $out['Events'] = "unavailable: $($_.Exception.Message)" }
    $out
}

$Result['EventLogs'] = Invoke-Collector 'Event logs (RDP client, System)' {
    $out = [ordered]@{}
    $since = (Get-Date).AddDays(-$LookbackDays)

    # RDP client history
    try {
        $ev = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'; StartTime = $since } 1500)
        # Event 1026 primary disconnect reasons (Microsoft IMsTscAxEvents::OnDisconnected and the TechNet
        # "Disconnect Codes and Reasons" table), grouped by what caused them.
        $reasonMap = @{
            '0' = 'No information'; '1' = 'Local disconnect by user'; '2' = 'Remote logoff by user'; '3' = 'Remote disconnect by server (admin, error or network)'
            '260' = 'DNS lookup failed'; '262' = 'Out of memory'; '263' = 'Normal session end'; '264' = 'Connection timed out'; '516' = 'Winsock connect failed (unreachable)'
            '520' = 'Host not found'; '772' = 'Winsock send failed (network error)'; '776' = 'Invalid IP address'; '1028' = 'Winsock receive failed'; '1030' = 'Security data invalid'
            '1032' = 'Internal error'; '1288' = 'DNS lookup failed'; '1540' = 'Host name lookup failed'; '1796' = 'Time-out'; '1800' = 'Console session already in progress'
            '2052' = 'Bad IP address'; '2055' = 'Login failed'; '2056' = 'License negotiation failed'; '2308' = 'Socket closed (connection lost)'; '2310' = 'Internal security error'
            '2311' = 'Unexpected server certificate'; '2312' = 'Licensing time-out'; '2566' = 'Internal security error'; '2567' = 'User has no account'; '2820' = 'Error prevented the connection'
            '2822' = 'Encryption error'; '2823' = 'Account disabled'; '2825' = 'Server requires NLA'; '3078' = 'Decryption error'; '3079' = 'Account restricted'; '3080' = 'Decompression error'
            '3335' = 'Account locked out'; '3591' = 'Account expired'; '3592' = 'Failed to reconnect to session'; '3847' = 'Password expired'; '4359' = 'Logon restricted to other computers'
            '4615' = 'Must change password'; '5639' = 'Credential delegation not allowed'; '5895' = 'Delegation needs mutual auth'; '6151' = 'No authentication authority reachable'
            '6919' = 'Certificate invalid or clock skew'; '7175' = 'Wrong smart card PIN'; '7431' = 'Client/server clock difference'; '8455' = 'Fresh credentials required'; '8711' = 'Smart card blocked'
            '9732' = 'Client/server version mismatch'; '50331649' = 'RD Gateway: bad user name or password'; '50331651' = 'RD Gateway certificate problem'; '50331654' = 'RD Gateway certificate problem'
            '50331657' = 'RD Gateway: send error (network down)'; '50331658' = 'RD Gateway: receive error (network down)'; '50331660' = 'RD Gateway unreachable'; '50331661' = 'RD Gateway temporarily unavailable'
            '50331672' = 'RD Gateway ended the connection'; '50331673' = 'RD Gateway admin ended the connection'; '50331675' = 'Not authorized by RD Gateway policy'; '50331676' = 'Not authorized by RD Gateway policy'
            '50331680' = 'Web proxy requires authentication'; '50331698' = 'Idle time limit'; '50331699' = 'Session time limit'; '50331716' = 'Forward proxy failure'; '50331722' = 'Network does not allow the HTTPS ports'
        }
        $cat = @{}
        foreach ($c in '0', '1', '2', '263') { $cat[$c] = 'User/normal' }
        foreach ($c in '260', '264', '516', '520', '772', '1028', '1288', '1540', '1796', '2308', '3592', '50331657', '50331658', '50331660', '50331661', '50331680', '50331716', '50331722') { $cat[$c] = 'Network' }
        foreach ($c in '2055', '2567', '2823', '3079', '3335', '3591', '3847', '4359', '4615', '5639', '5895', '6151', '7175', '8455', '8711', '50331649', '50331675', '50331676') { $cat[$c] = 'Authentication' }
        foreach ($c in '3', '1800', '50331672', '50331673', '50331698', '50331699') { $cat[$c] = 'Server/policy' }
        foreach ($c in '1030', '2310', '2311', '2566', '2822', '6919', '7431', '50331651', '50331654', '3078', '3080') { $cat[$c] = 'Security/certificate' }
        foreach ($c in '2056', '2312') { $cat[$c] = 'Licensing' }
        $attempts = @(); $disc = @()
        foreach ($e in $ev) {
            if ($e.Id -eq 1024) {
                $srv = $null
                if ($e.Message -match '\(([^)]+)\)') { $srv = $matches[1] }
                $attempts += $srv
            } elseif ($e.Id -eq 1026) {
                $code = $null
                if ($e.Message -match 'Reason=\s*(\d+)') { $code = $matches[1] }
                $category = if ($code -and $cat.ContainsKey("$code")) { $cat["$code"] } else { 'Other' }
                $disc += [pscustomobject]@{ Time = Format-Date $e.TimeCreated; Code = $code; Meaning = $reasonMap["$code"]; Category = $category }
            }
        }
        # UDP side channel: 1102 attempted, 1103 established, 1104 failed (stays on TCP), 1105 closed (also at
        # every normal session end), 226 UDP state-machine error.
        $udp = [ordered]@{
            Attempted = @($ev | Where-Object Id -eq 1102).Count; Established = @($ev | Where-Object Id -eq 1103).Count
            Failed = @($ev | Where-Object Id -eq 1104).Count; Closed = @($ev | Where-Object Id -eq 1105).Count; StateErrors = @($ev | Where-Object Id -eq 226).Count
        }
        $udp['Status'] = if ($udp.Established -gt 0 -and $udp.Failed -eq 0) { 'UDP works' }
                         elseif ($udp.Established -gt 0) { "UDP works sometimes ($($udp.Established) established, $($udp.Failed) failed)" }
                         elseif ($udp.Failed -gt 0) { 'UDP fails: sessions run on TCP only' }
                         elseif ($udp.Attempted -gt 0) { 'UDP attempted, result not logged' }
                         elseif ($attempts.Count -gt 0) { 'No UDP attempts (server or gateway does not offer UDP)' }
                         else { 'No RDP sessions logged' }
        $unexpected = @($disc | Where-Object { $_.Code -and $_.Category -ne 'User/normal' })
        $network = @($disc | Where-Object { $_.Category -eq 'Network' })
        $out['RdpClient'] = [ordered]@{
            EventCount = $ev.Count
            ConnectAttempts = $attempts.Count
            ServersSeen = @($attempts | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
            Disconnects = $disc.Count
            UnexpectedDisconnects = $unexpected.Count
            NetworkDisconnects = $network.Count
            DisconnectsByCategory = @($disc | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })
            DisconnectReasons = @($disc | Group-Object Code | Sort-Object Count -Descending | ForEach-Object { '{0} {1} x{2}' -f $_.Name, $reasonMap["$($_.Name)"], $_.Count })
            RecentDisconnects = @($disc | Select-Object -First 15)
            AllDisconnects = $disc
            Udp = $udp
            UdpTransportEvents = ($udp.Attempted + $udp.Established + $udp.Failed + $udp.Closed)
            FirstEvent = if ($ev.Count) { Format-Date $ev[-1].TimeCreated } else { $null }
        }
    } catch { $out['RdpClient'] = "unavailable: $($_.Exception.Message)" }

    # System log warnings/errors, grouped
    try {
        $sys = @(Get-EventsSafe @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $since } 4000)
        $groups = @($sys | Group-Object ProviderName, Id | Sort-Object Count -Descending)
        $nicRegex = 'e1.express|e1iexpress|e1rexpress|e2f|rt640|rtux|Rtl|Netwtw|Netwbw|Netwaw|b57nd|bnxt|mrvl|Realtek|Intel.*Ethernet|athw|Qualcomm|mtkwl|RTWlan|NDIS|Tcpip'
        $top = @()
        $nic = @()
        $rank = 0
        # The 25 largest groups go in SystemTop; NIC groups are checked at any size so rare link drops still count.
        foreach ($g in $groups) {
            $sample = $g.Group[0]
            $isTop = ($rank -lt 25); $rank++
            $isNic = ($sample.ProviderName -match $nicRegex)
            if (-not $isTop -and -not $isNic) { continue }
            $msg = $null
            try { $msg = ("$($sample.Message)" -split "`r?`n")[0] } catch { }
            if ($msg -and $msg.Length -gt 160) { $msg = $msg.Substring(0, 160) }
            $row = [pscustomobject]@{ Provider = $sample.ProviderName; Id = $sample.Id; Count = $g.Count; Last = Format-Date $sample.TimeCreated; Sample = $msg }
            if ($isTop) { $top += $row }
            if ($isNic -and $msg -match 'disconnect|link.*down|reset|lost') { $nic += $row }
        }
        $out['SystemTop'] = $top
        $out['NicLinkEvents'] = $nic
        $out['NicLinkEventCount'] = ($nic | Measure-Object Count -Sum).Sum
        $out['UnexpectedShutdowns'] = @($sys | Where-Object { ($_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41) -or ($_.ProviderName -eq 'EventLog' -and $_.Id -eq 6008) }).Count
        $out['DnsClientTimeouts'] = @($sys | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-DNS-Client' -and $_.Id -eq 1014 }).Count
    } catch { $out['System'] = "unavailable: $($_.Exception.Message)" }
    $out
}

$Result['NetworkExtra'] = Invoke-Collector 'Gateway, DNS, proxy, routes' {
    $out = [ordered]@{}
    $gw = $Gateway
    $out['Gateway'] = $gw
    if ($gw -and (Test-IPv4 $gw)) {
        try { Invoke-Native 'ping.exe' "-n 1 -w 500 $gw" 5 | Out-Null } catch { }
        $nb = Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-){5}00$' } | Select-Object -First 1
        $out['GatewayMac'] = if ($nb) { $nb.LinkLayerAddress } else { $null }
        $out['GatewayVendor'] = if ($nb) { Get-MacVendor $nb.LinkLayerAddress } else { $null }
        $out['GatewayPtr'] = Resolve-Ptr $gw
    }

    # DNS servers classified
    $known = @{ '1.1.1.1' = 'Cloudflare'; '1.0.0.1' = 'Cloudflare'; '8.8.8.8' = 'Google'; '8.8.4.4' = 'Google'; '9.9.9.9' = 'Quad9'; '149.112.112.112' = 'Quad9'; '208.67.222.222' = 'OpenDNS/Umbrella'; '208.67.220.220' = 'OpenDNS/Umbrella'; '4.2.2.1' = 'Level3'; '4.2.2.2' = 'Level3' }
    $dns = @()
    $primaryIf = @($Result['Network']['Adapters'] | Where-Object { $_.Name -eq $Result['Network']['PrimaryAdapter'] })
    $servers = @()
    foreach ($a in $primaryIf) { $servers += $a.DnsServers }
    try { $servers += @(Get-DnsClientServerAddress -AddressFamily IPv6 -InterfaceAlias $Result['Network']['PrimaryAdapter'] -ErrorAction Stop).ServerAddresses } catch { }
    foreach ($s in ($servers | Where-Object { $_ } | Select-Object -Unique)) {
        $kind = Get-IpClass $s
        $label = if ($s -eq $gw) { 'Gateway (firewall/router)' }
                 elseif ($known.ContainsKey($s)) { "Public resolver ($($known[$s]))" }
                 elseif ($kind -eq 'Private') { 'Private, not the gateway (internal DNS / DC / tunnel)' }
                 elseif ($kind -eq 'Public') { 'Public (likely ISP)' }
                 else { $kind }
        $dns += [pscustomobject]@{ Server = $s; Type = $label }
    }
    $out['DnsServers'] = $dns
    $out['DnsSuffixSearch'] = @(try { (Get-DnsClientGlobalSetting -ErrorAction Stop).SuffixSearchList } catch { })

    # Proxy
    $out['WinHttpProxy'] = try { ((Invoke-Native 'netsh.exe' 'winhttp show proxy' 10) -split "`r?`n" | Where-Object { $_.Trim() }) -join ' | ' } catch { $null }
    $ie = Get-RegValues "$($script:UserHive)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if ($ie) { $out['UserProxy'] = [ordered]@{ ProxyEnable = $ie['ProxyEnable']; ProxyServer = $ie['ProxyServer']; AutoConfigURL = $ie['AutoConfigURL']; ProxyOverride = $ie['ProxyOverride'] } }

    # Error counters on the physical adapter since boot (no admin needed): errors point at a cable or switch port.
    try {
        $phys = $Result['Network']['PhysicalAdapter']
        if ($phys) {
            $st = Get-NetAdapterStatistics -Name $phys -ErrorAction Stop
            $out['AdapterStats'] = [ordered]@{
                Adapter = $phys; ReceivedPackets = $st.ReceivedUnicastPackets + $st.ReceivedMulticastPackets + $st.ReceivedBroadcastPackets
                SentPackets = $st.SentUnicastPackets + $st.SentMulticastPackets + $st.SentBroadcastPackets
                ReceiveErrors = $st.ReceivedPacketErrors; SendErrors = $st.OutboundPacketErrors
                ReceiveDiscards = $st.ReceivedDiscardedPackets; SendDiscards = $st.OutboundDiscardedPackets
            }
        }
    } catch { $out['AdapterStats'] = "unavailable: $($_.Exception.Message)" }

    # Hosts file entries
    try { $out['HostsEntries'] = @(Get-Content "$env:WINDIR\System32\drivers\etc\hosts" -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#\s]' } | ForEach-Object { $_.Trim() }) } catch { }

    # Routes (minus multicast/broadcast noise)
    $out['Routes'] = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -notmatch '^(224\.|255\.255\.255\.255|127\.)' -and $_.DestinationPrefix -notmatch '/32$' } |
        ForEach-Object { [pscustomobject]@{ Prefix = $_.DestinationPrefix; NextHop = $_.NextHop; Interface = $_.InterfaceAlias; Metric = $_.RouteMetric } })
    $out
}

$Result['Servers'] = Invoke-Collector 'Servers this PC depends on' {
    # Names come from what the PC already uses (mapped drives, shared printers, its domain). Each one is
    # resolved and placed: this subnet (on-prem here), another private subnet (another site or a tunnel)
    # or public (cloud). Internal names only resolve on site, so this cannot be done later.
    $cands = @()
    foreach ($d in @(Get-Val $Result['Identity'] 'MappedDrives')) {
        if ($d -and "$($d.RemotePath)" -match '^\\\\([^\\]+)\\') { $cands += [pscustomobject]@{ Name = $matches[1]; Source = "mapped drive $($d.Drive) $($d.RemotePath)" } }
    }
    foreach ($p in @(Get-Val $Result['Peripherals'] 'Printers')) {
        if ($p -and "$($p.Name)" -match '^\\\\([^\\]+)\\') { $cands += [pscustomobject]@{ Name = $matches[1]; Source = "shared printer $($p.Name)" } }
    }
    foreach ($c in @(Get-Val $Result['Peripherals'] 'UserPrinterConnections')) {
        if ("$c" -match '^\\\\([^\\]+)\\') { $cands += [pscustomobject]@{ Name = $matches[1]; Source = "user printer connection $c" } }
    }
    $dc = $null
    if (Get-Val $Result['Machine'] 'PartOfDomain') {
        $dc = [ordered]@{ Domain = Get-Val $Result['Machine'] 'Domain' }
        try {
            $raw = Invoke-Native 'nltest.exe' ('/dsgetdc:{0}' -f $dc['Domain']) 20
            foreach ($line in ($raw -split "`r?`n")) {
                if ($line -match '^\s*DC:\s*\\\\(\S+)') { $dc['Name'] = $matches[1] }
                elseif ($line -match '^\s*Address:\s*\\\\(\S+)') { $dc['Address'] = $matches[1] }
                elseif ($line -match '^\s*Dc Site Name:\s*(.+?)\s*$') { $dc['DcSite'] = $matches[1] }
                elseif ($line -match '^\s*Our Site Name:\s*(.+?)\s*$') { $dc['ClientSite'] = $matches[1] }
            }
            if ($dc['Name']) { $cands += [pscustomobject]@{ Name = $dc['Name']; Source = "domain controller for $($dc['Domain'])" } }
            else { $dc['Error'] = (($raw -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' ') }
        } catch { $dc['Error'] = $_.Exception.Message }
    }
    $localNets = @()
    foreach ($a in @(Get-Val $Result['Network'] 'Adapters' | Where-Object { $_ -and $_.Status -eq 'Up' })) {
        $ipsA = @($a.IPv4); $masks = @($a.SubnetMask)
        for ($q = 0; $q -lt $ipsA.Count; $q++) { if ($ipsA[$q] -and $masks.Count -gt $q) { $localNets += [pscustomobject]@{ Ip = $ipsA[$q]; Mask = $masks[$q] } } }
    }
    $rows = @()
    foreach ($g in @($cands | Group-Object { "$($_.Name)".ToLower() } | Select-Object -First 20)) {
        $name = $g.Group[0].Name
        $ips = @()
        if (Test-IPv4 $name) { $ips = @($name) }
        else {
            try { $ips = @(Resolve-DnsName -Name $name -Type A -QuickTimeout -ErrorAction Stop | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and (Test-IPv4 $_) } | Select-Object -Unique) } catch { }
        }
        $where = 'Does not resolve from this PC'
        $smb = $null
        if ($ips.Count) {
            $cls = Get-IpClass $ips[0]
            $onLink = [bool](@($localNets | Where-Object { Test-SameSubnet $ips[0] $_.Ip $_.Mask }).Count)
            $where = if ($cls -eq 'Private' -and $onLink) { 'On-prem, this subnet' }
                     elseif ($cls -eq 'Private') { 'Private, another subnet (another site, VLAN or tunnel)' }
                     elseif ($cls -eq 'Public') { 'Public (cloud or hosted)' }
                     else { $cls }
            try { $smb = Test-TcpPort $ips[0] 445 1000 } catch { }
        }
        $rows += [pscustomobject]@{ Name = $name; Sources = @($g.Group | ForEach-Object { $_.Source } | Select-Object -Unique); IPs = $ips; Location = $where; FileSharingReachable = $smb }
    }
    [ordered]@{ Servers = $rows; DomainController = $dc }
}

if ($EnableAdSites -and $script:FullLanguage -and (Get-Val $Result['Machine'] 'PartOfDomain')) {
    $Result['AdSites'] = Invoke-Collector 'Active Directory sites and subnets' { Get-AdSites 20 }
}

$Result['Patching'] = Invoke-Collector 'Windows Update, reboot, Microsoft 365' {
    $out = [ordered]@{}
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
    if (Get-RegString 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations') { $reasons += 'Pending file renames' }
    $out['PendingReboot'] = ($reasons.Count -gt 0)
    $out['PendingRebootReasons'] = $reasons

    # Update source: WSUS, Windows Update for Business policy, or plain Windows Update.
    $wu = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $au = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $out['WsusServer'] = Get-Val $wu 'WUServer'
    $out['UseWsus'] = ((Get-Val $au 'UseWUServer') -eq 1)
    $out['WufbDeferQualityDays'] = Get-Val $wu 'DeferQualityUpdatesPeriodInDays'
    $out['WufbDeferFeatureDays'] = Get-Val $wu 'DeferFeatureUpdatesPeriodInDays'
    # Last OS patch. Update history is mostly daily Defender signatures and Store apps, which say nothing
    # about OS patching, so only Windows OS updates count. Get-HotFix also lists installed cumulative
    # updates when history was cleared or another tool (RMM, WSUS) installed them; the newer source wins.
    $candidates = @()
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $srch = $sess.CreateUpdateSearcher()
        $cnt = $srch.GetTotalHistoryCount()
        $hist = @()
        if ($cnt -gt 0) { $hist = @($srch.QueryHistory(0, [math]::Min(1000, $cnt))) }
        $ok = @($hist | Where-Object { $_.ResultCode -eq 2 -and $_.Title } | Sort-Object Date -Descending)
        $osInclude = 'Cumulative Update for Windows|Security Update \(KB|Security Update for Windows|Feature update to Windows|Servicing Stack Update|Update for Windows 1[01]'
        $osExclude = 'Defender|Security Intelligence|KB2267602|KB4052623|KB890830|Malicious Software|\.NET|Driver|Firmware'
        $osOk = @($ok | Where-Object { $_.Title -match $osInclude -and $_.Title -notmatch $osExclude })
        if ($ok.Count) { $out['LastAnyUpdate'] = '{0} {1}' -f (Format-Date $ok[0].Date.ToLocalTime()), $ok[0].Title }
        if ($osOk.Count) { $candidates += [pscustomobject]@{ Date = $osOk[0].Date.ToLocalTime(); Title = $osOk[0].Title; Source = 'update history' } }
        $out['FailedUpdatesRecent'] = @($hist | Where-Object { $_.ResultCode -in @(4, 5) } | Select-Object -First 5 | ForEach-Object { '{0} {1}' -f (Format-Date $_.Date.ToLocalTime()), $_.Title })
    } catch { $out['UpdateHistoryError'] = $_.Exception.Message }
    try {
        $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) { $candidates += [pscustomobject]@{ Date = [datetime]$hf.InstalledOn; Title = '{0} {1}' -f $hf.HotFixID, $hf.Description; Source = 'installed KBs (Get-HotFix)' } }
    } catch { }
    $newest = $candidates | Sort-Object Date -Descending | Select-Object -First 1
    $out['LastUpdateInstalled'] = if ($newest) { Format-Date $newest.Date } else { $null }
    $out['LastUpdateTitle'] = if ($newest) { $newest.Title } else { $null }
    $out['LastUpdateSource'] = if ($newest) { $newest.Source } else { $null }
    $out['DaysSinceLastUpdate'] = if ($newest) { [math]::Round(((Get-Date) - $newest.Date).TotalDays, 0) } else { $null }

    # Microsoft 365 Apps (Click-to-Run)
    $c2r = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    if ($c2r) {
        $channels = @{
            '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current'
            '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current (Preview)'
            '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise'
            '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise'
            'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise (Preview)'
            '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta'
        }
        $chanUrl = "$(Get-Val $c2r 'UpdateChannel') $(Get-Val $c2r 'CDNBaseUrl')"
        $chan = $null
        foreach ($g in $channels.Keys) { if ($chanUrl -match $g) { $chan = $channels[$g]; break } }
        $out['M365'] = [ordered]@{
            Version = Get-Val $c2r 'VersionToReport'; Platform = Get-Val $c2r 'Platform'; Channel = $chan
            Products = Get-Val $c2r 'ProductReleaseIds'; SharedActivation = ((Get-Val $c2r 'SharedComputerLicensing') -eq '1')
        }
    } else { $out['M365'] = $null }
    $out
}

# ---------------------------------------------------------------------
# Session health: things on the PC itself that make a hosted desktop drop or feel slow.
# Read-only. Each part stands alone, so one that fails leaves the others in place.
# ---------------------------------------------------------------------
$Result['Session'] = Invoke-Collector 'Session health (client crashes, UDP policy, load, adapter power)' {
    $out = [ordered]@{}
    $since = (Get-Date).AddDays(-$LookbackDays)

    # 1. Crashes and hangs of the RDP / hosted-desktop client (Application log: 1000 crash, 1002 hang, 1026 .NET crash)
    try {
        $appPattern = "mstsc|msrdc|$RdpAppHint"
        $ev = @(Get-EventsSafe @{ LogName = 'Application'; Id = 1000, 1002, 1026; StartTime = $since } 2000)
        $hits = @()
        foreach ($e in $ev) {
            if ($e.ProviderName -notin @('Application Error', 'Application Hang', '.NET Runtime')) { continue }
            $txt = $null
            try { $txt = "$($e.Properties[0].Value)" } catch { }
            if (-not $txt) { continue }
            if ($txt.Length -gt 300) { $txt = $txt.Substring(0, 300) }
            $app = if ($txt -match '(?i)([\w\.\-]+\.exe)') { $Matches[1] } else { ($txt -split "`r?`n")[0] }
            if ($app -notmatch "(?i)$appPattern") { continue }
            $hits += [pscustomobject]@{ Time = Format-Date $e.TimeCreated; Kind = $(if ($e.Id -eq 1002) { 'Hang' } else { 'Crash' }); App = $app }
        }
        $out['ClientCrashes'] = @($hits | Where-Object { $_.Kind -eq 'Crash' }).Count
        $out['ClientHangs'] = @($hits | Where-Object { $_.Kind -eq 'Hang' }).Count
        $out['ClientCrashByApp'] = @($hits | Group-Object App, Kind | Sort-Object Count -Descending | ForEach-Object { '{0} {1} x{2}' -f $_.Group[0].App, $_.Group[0].Kind.ToLower(), $_.Count })
        $out['ClientCrashRecent'] = @($hits | Select-Object -First 10)
        $out['AppErrorEventsChecked'] = $ev.Count
    } catch { $out['ClientCrashStatus'] = "unavailable: $($_.Exception.Message)" }

    # 2. RDP UDP transport turned off on the client (policy "Turn Off UDP On Client", or the client setting)
    try {
        $pol = Get-RegString 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client' 'fClientDisableUDP'
        $mach = Get-RegString 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client' 'DisableUDPTransport'
        $usr = Get-RegString 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client' 'DisableUDPTransport'
        $src = @()
        if ("$pol" -eq '1') { $src += 'group policy' }
        if ("$mach" -eq '1') { $src += 'machine setting' }
        if ("$usr" -eq '1') { $src += 'user setting' }
        $out['UdpPolicy'] = [ordered]@{ UdpDisabled = ($src.Count -gt 0); Source = ($src -join ' + '); PolicyValue = $pol; MachineValue = $mach; UserValue = $usr }
    } catch { $out['UdpPolicyStatus'] = "unavailable: $($_.Exception.Message)" }

    # 3. Display area (more pixels means more bandwidth per hosted-desktop user)
    try {
        $scr = @(Get-Val $Result['Peripherals'] 'Screens' | Where-Object { $_ })
        $modes = @(Get-CimInstance Win32_VideoController -OperationTimeoutSec 15 | Where-Object { $_.CurrentHorizontalResolution } | ForEach-Object { '{0}x{1}' -f $_.CurrentHorizontalResolution, $_.CurrentVerticalResolution })
        $px = 0
        foreach ($s in $scr) { $px += [double]$s.Width * [double]$s.Height }
        $out['Displays'] = [ordered]@{ Count = $scr.Count; Sizes = @($scr | ForEach-Object { '{0}x{1}' -f $_.Width, $_.Height }); TotalMegapixels = [math]::Round($px / 1000000, 1); VideoModes = $modes }
    } catch { $out['DisplaysStatus'] = "unavailable: $($_.Exception.Message)" }

    # 4. CPU and memory load while the user's normal programs are open
    try {
        $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
        $cpu = @()
        for ($i = 0; $i -lt 3; $i++) {
            $v = (Get-CimInstance Win32_Processor -OperationTimeoutSec 15 | Measure-Object LoadPercentage -Average).Average
            if ($null -ne $v) { $cpu += [int]$v }
            if ($i -lt 2) { Start-Sleep -Milliseconds 700 }
        }
        $procs = @(Get-Process -ErrorAction SilentlyContinue)
        $byName = @($procs | Group-Object ProcessName | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count; MB = [math]::Round((($_.Group | Measure-Object WorkingSet64 -Sum).Sum) / 1MB) } } | Sort-Object MB -Descending | Select-Object -First 6)
        $totalMb = [math]::Round($os.TotalVisibleMemorySize / 1024)
        $freeMb = [math]::Round($os.FreePhysicalMemory / 1024)
        $commitPct = $null
        if ($os.TotalVirtualMemorySize -gt 0) { $commitPct = [math]::Round(100 * ($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / $os.TotalVirtualMemorySize) }
        $out['Load'] = [ordered]@{
            CpuSamplesPct = $cpu; CpuAvgPct = $(if ($cpu.Count) { [int](($cpu | Measure-Object -Average).Average) } else { $null })
            MemoryTotalMB = $totalMb; MemoryFreeMB = $freeMb; MemoryUsedPct = $(if ($totalMb -gt 0) { [math]::Round(100 * ($totalMb - $freeMb) / $totalMb) } else { $null }); CommitUsedPct = $commitPct
            ProcessCount = $procs.Count; TopByMemory = @($byName | ForEach-Object { if ($_.Count -gt 1) { '{0} x{1} {2} MB' -f $_.Name, $_.Count, $_.MB } else { '{0} {1} MB' -f $_.Name, $_.MB } })
            Note = 'Sampled early in the run, while only the light latency tests were running in the background'
        }
    } catch { $out['LoadStatus'] = "unavailable: $($_.Exception.Message)" }

    # 5. Is Windows allowed to power down the network adapter in use?
    try {
        $physName = Get-Val $Result['Network'] 'PhysicalAdapter'
        if ($physName) {
            $allow = $null; $source = $null; $pnpVal = $null
            try {
                $pm = Get-NetAdapterPowerManagement -Name $physName -ErrorAction Stop
                if ($pm -and "$($pm.AllowComputerToTurnOffDevice)") { $allow = "$($pm.AllowComputerToTurnOffDevice)"; $source = 'Get-NetAdapterPowerManagement' }
            } catch { }
            try {
                $guid = "$((Get-NetAdapter -Name $physName -ErrorAction Stop).InterfaceGuid)"
                $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
                foreach ($k in @(Get-ChildItem -LiteralPath $classKey -ErrorAction SilentlyContinue)) {
                    $p = $null
                    try { $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
                    if ("$($p.NetCfgInstanceId)" -ne $guid) { continue }
                    $prop = $p.PSObject.Properties['PnPCapabilities']
                    if ($prop) { $pnpVal = [int]$prop.Value }
                    if (-not $allow -and $null -ne $pnpVal) {
                        # Bit 8 set (the usual value is 24) means "allow the computer to turn off this device" is unticked.
                        $allow = if ($pnpVal -band 8) { 'Disabled' } else { 'Enabled' }
                        $source = 'registry PnPCapabilities'
                    }
                    break
                }
            } catch { }
            if (-not $allow) {
                # No explicit setting. PCs that sleep with Modern Standby (S0) have no such checkbox: Windows manages the adapter.
                $modern = $false
                try { $modern = ((("$(Invoke-Native 'powercfg.exe' '/a' 20)") -split "\r?\n\s*\r?\n")[0] -match '\(S0') } catch { }
                if ($modern) { $allow = 'Not applicable (Modern Standby manages the adapter)'; $source = 'powercfg /a' }
                else { $allow = 'Default (not turned off)'; $source = 'no PnPCapabilities value in the registry' }
            }
            $out['AdapterPower'] = [ordered]@{ Adapter = $physName; AllowTurnOff = $(if ($allow) { $allow } else { 'Unknown' }); PnPCapabilities = $pnpVal; Source = $source }
        }
    } catch { $out['AdapterPowerStatus'] = "unavailable: $($_.Exception.Message)" }
    $out
}

# ---------------------------------------------------------------------
# Admin tier
# ---------------------------------------------------------------------
$Result['Admin'] = Invoke-Collector 'Admin tier' -AdminOnly {
    $out = [ordered]@{}
    try {
        $t = Get-Tpm -ErrorAction Stop
        $spec = $null
        try { $spec = (Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop).SpecVersion } catch { }
        $out['Tpm'] = [ordered]@{ Present = $t.TpmPresent; Ready = $t.TpmReady; Enabled = $t.TpmEnabled; Activated = $t.TpmActivated; ManufacturerId = $t.ManufacturerIdTxt; SpecVersion = $spec; Is20 = ("$spec" -match '^2\.0') }
    } catch { $out['Tpm'] = "unavailable: $($_.Exception.Message)" }
    try { $out['SecureBoot'] = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $out['SecureBoot'] = "unavailable: $($_.Exception.Message)" }
    try {
        $out['BitLocker'] = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Mount = $_.MountPoint; VolumeType = "$($_.VolumeType)"; Status = "$($_.VolumeStatus)"; Protection = "$($_.ProtectionStatus)"; Method = "$($_.EncryptionMethod)"; Percent = $_.EncryptionPercentage; Protectors = @($_.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" }) }
        })
    } catch { $out['BitLocker'] = "unavailable: $($_.Exception.Message)" }
    try {
        $out['DiskReliability'] = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $d = $_
            $rc = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
            [pscustomobject]@{ Disk = $d.FriendlyName; MediaType = "$($d.MediaType)"; WearPct = $rc.Wear; PowerOnHours = $rc.PowerOnHours; TemperatureC = $rc.Temperature; ReadErrorsTotal = $rc.ReadErrorsTotal; WriteErrorsTotal = $rc.WriteErrorsTotal }
        })
    } catch { $out['DiskReliability'] = "unavailable: $($_.Exception.Message)" }
    try {
        $primaryName = $Result['Network']['PhysicalAdapter']
        if ($primaryName) {
            $out['AdapterAdvanced'] = @(Get-NetAdapterAdvancedProperty -Name $primaryName -ErrorAction Stop |
                Where-Object { $_.DisplayName -match 'Speed|Duplex|Energy|Green|Roam|Band|Preferred|Power|Wake|802\.11|MIMO|Channel Width|Throughput|Jumbo|Flow' } |
                ForEach-Object { [pscustomobject]@{ Setting = $_.DisplayName; Value = $_.DisplayValue } })
        }
    } catch { $out['AdapterAdvanced'] = "unavailable: $($_.Exception.Message)" }

    # Interactive logons on this PC (real user structure)
    try {
        $ms = [int64]$LookbackDays * 86400000
        $xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]"
        $ev = @(Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents 5000 -ErrorAction Stop)
        $rows = @()
        foreach ($e in $ev) {
            $x = [xml]$e.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            if ($d['TargetUserName'] -match '^(DWM-|UMFD-|SYSTEM$|LOCAL SERVICE|NETWORK SERVICE)' -or $d['TargetUserName'] -like '*$') { continue }
            $type = switch ($d['LogonType']) { '2' { 'Console' } '10' { 'RDP into this PC' } '11' { 'Cached' } default { $d['LogonType'] } }
            $rows += [pscustomobject]@{ User = ('{0}\{1}' -f $d['TargetDomainName'], $d['TargetUserName']); Type = $type; Time = $e.TimeCreated }
        }
        $out['InteractiveLogons'] = @($rows | Group-Object User | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{ User = $_.Name; Count = $_.Count; Types = (($_.Group | Select-Object -ExpandProperty Type -Unique) -join ', '); Last = Format-Date (($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time) }
        })
    } catch { $out['InteractiveLogons'] = "unavailable: $($_.Exception.Message)" }

    # WLAN report (admin only)
    if ($Result['Wireless'] -and $Result['Wireless'].Contains('Current')) {
        try {
            Invoke-Native 'netsh.exe' 'wlan show wlanreport' 90 | Out-Null
            $src = Join-Path $env:ProgramData 'Microsoft\Windows\WlanReport\wlan-report-latest.html'
            if (Test-Path $src) { Copy-Item $src (Join-Path $OutDir 'wlanreport.html') -Force; $out['WlanReport'] = 'wlanreport.html' }
        } catch { $out['WlanReport'] = "unavailable: $($_.Exception.Message)" }
    }
    $out
}

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

$seriesLeft = [math]::Max(0, [int]($PingCount + 15 - ((Get-Date) - $RunStart).TotalSeconds))
Write-Step ("Waiting for traceroutes and the {0}-sample ping and TCP series (about {1} s left; this wait is expected)" -f $PingCount, $seriesLeft)
$traceResults = @(); $pingResults = @()
foreach ($j in $Jobs) {
    try {
        $txt = Receive-NativeAsync $j.Handle $(if ($j.Kind -eq 'Ping') { $PingCount + 60 } else { 150 })
        if ($j.Kind -eq 'Trace') {
            $traceResults += ConvertTo-TraceResult $j.Target $txt
        } else {
            $pingResults += [pscustomobject](ConvertFrom-PingOutput $txt $j.Target $PingCount)
        }
    } catch {
        $script:Errors += [pscustomobject]@{ Collector = "$($j.Kind) $($j.Target)"; Error = $_.Exception.Message }
    }
}
$Result['Traceroutes'] = $traceResults
$Result['PingSeries'] = $pingResults
$Result['IcmpSilentTargets'] = $script:IcmpSilent
$tcpResults = @()
foreach ($tj in $TcpSeriesJobs) {
    try { $tcpResults += [pscustomobject](Receive-TcpSeries $tj ($PingCount + 90)) }
    catch { $script:Errors += [pscustomobject]@{ Collector = "TCP series $($tj.Target)"; Error = $_.Exception.Message } }
}
$Result['TcpSeries'] = $tcpResults

# Stop pktmon (at least $LldpMinSeconds after start so one LLDP and one CDP interval are covered) and parse.
if ($script:PktmonStarted) {
    $Result['Lldp'] = Invoke-Collector 'Admin: LLDP/CDP capture' {
        $wait = $LldpMinSeconds - ((Get-Date) - $PktmonStartTime).TotalSeconds
        if ($wait -gt 0) { Write-Step ("  waiting {0:N0}s more for LLDP frames" -f $wait); Start-Sleep -Seconds ([math]::Ceiling($wait)) }
        try { Invoke-Native 'pktmon.exe' 'stop' 60 | Out-Null } finally {
            try { Invoke-Native 'pktmon.exe' 'filter remove' 15 | Out-Null } catch { }
            $script:PktmonStarted = $false
        }
        $pcap = Join-Path $OutDir 'lldp.pcapng'
        Invoke-Native 'pktmon.exe' ('etl2pcap "{0}" --out "{1}"' -f $PktmonEtl, $pcap) 60 | Out-Null
        Remove-Item -LiteralPath $PktmonEtl -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $pcap)) { throw 'pcapng conversion failed' }
        $script:CaptureSeconds = [int]((Get-Date) - $PktmonStartTime).TotalSeconds
        $script:CapturePath = $pcap
        ConvertFrom-NeighborCapture $pcap
    }
    # Second read of the same file: what the wire says about switches, VLANs, DHCP and other subnets.
    if ($script:CapturePath) {
        $Result['Capture'] = Invoke-Collector 'Admin: wire capture summary' {
            $localMacs = @(Get-Val $Result['Network'] 'Adapters' | ForEach-Object { "$($_.MacAddress)" } | Where-Object { $_ })
            Get-CaptureSummary $script:CapturePath $script:CaptureSeconds $localMacs
        }
    }
}

if ($EnableBandwidth) {
    $Result['Bandwidth'] = Invoke-Collector 'Bandwidth test' { Measure-Bandwidth }
} else {
    $Result['Bandwidth'] = [ordered]@{ Status = 'disabled in config' }
}

# Extra rounds: one sample is easy to argue with. Every round is a full test and all of them are
# kept; the best one becomes the reported result, because a speed test can read low but not high.
if ($EnableBandwidth -and $BandwidthRounds -gt 1 -and (Get-Val $Result['Bandwidth'] 'DownloadOk')) {
    try {
        $bwRounds = @($Result['Bandwidth'])
        for ($rn = 2; $rn -le $BandwidthRounds; $rn++) {
            Start-Sleep -Seconds 8
            $bwMore = Invoke-Collector "Bandwidth test (round $rn of $BandwidthRounds)" { Measure-Bandwidth }
            if ($bwMore -is [System.Collections.IDictionary] -and $bwMore.Contains('DownloadOk')) { $bwRounds += $bwMore }
        }
        $bwSumm = @(); $rn = 0
        foreach ($r in $bwRounds) {
            $rn++
            $bwSumm += [pscustomobject]@{ Round = $rn; DownloadOk = $r['DownloadOk']; DownloadMbps = $r['DownloadMbps']; DownloadPeakMbps = $r['DownloadPeakMbps']; DownloadProvider = $r['DownloadProvider']; UploadOk = $r['UploadOk']; UploadMbps = $r['UploadMbps']; UploadProvider = $r['UploadProvider']; IdleLatencyMs = $r['IdleLatencyMs']; StartedAt = $r['StartedAt']; FinishedAt = $r['FinishedAt'] }
        }
        $bwBest = $bwRounds | Where-Object { $_['DownloadOk'] } | Sort-Object { [double]$_['DownloadMbps'] } -Descending | Select-Object -First 1
        $bwBestUp = $bwRounds | Where-Object { $_['UploadOk'] } | Sort-Object { [double]$_['UploadMbps'] } -Descending | Select-Object -First 1
        if ($bwBest) {
            if ($bwBestUp -and -not [object]::ReferenceEquals($bwBestUp, $bwBest) -and (-not $bwBest['UploadOk'] -or [double]$bwBestUp['UploadMbps'] -gt [double]$bwBest['UploadMbps'])) {
                foreach ($k in @($bwBestUp.Keys)) { if ($k -like 'Upload*') { $bwBest[$k] = $bwBestUp[$k] } }
            }
            $Result['Bandwidth'] = $bwBest
        }
        $Result['Bandwidth']['Rounds'] = $bwSumm
    } catch { $script:Errors += [pscustomobject]@{ Collector = 'Bandwidth rounds'; Error = $_.Exception.Message } }
}

# =====================================================================
# PHASE 6b: one more try at anything critical that came back empty.
# There is only one visit, so a gap is retried now instead of found later.
# =====================================================================
$script:Retried = @()

$tr1 = @($Result['Traceroutes']) | Where-Object { $_ -and $_.Target -eq '1.1.1.1' } | Select-Object -First 1
if (-not (Test-TraceUsable $tr1)) {
    Write-Step 'Retry: traceroute to 1.1.1.1' 'Yellow'
    $script:Retried += 'traceroute 1.1.1.1'
    try {
        $newTr = ConvertTo-TraceResult '1.1.1.1' (Invoke-IcmpText -Kind Trace -Target '1.1.1.1' -MaxHops 20 -TimeoutMs 1000 -WaitSec 120)
        if (Test-TraceUsable $newTr) { $Result['Traceroutes'] = @(@($Result['Traceroutes']) | Where-Object { $_ -and $_.Target -ne '1.1.1.1' }) + @($newTr) }
    } catch { $script:Errors += [pscustomobject]@{ Collector = 'Retry traceroute 1.1.1.1'; Error = $_.Exception.Message } }
}

$pg1 = @($Result['PingSeries']) | Where-Object { $_ -and $_.Target -eq '1.1.1.1' } | Select-Object -First 1
if (-not $pg1 -or -not $pg1.Received) {
    Write-Step 'Retry: ping series to 1.1.1.1 (30 pings)' 'Yellow'
    $script:Retried += 'ping 1.1.1.1'
    try {
        $newPg = [pscustomobject](ConvertFrom-PingOutput (Invoke-IcmpText -Kind Ping -Target '1.1.1.1' -Count 30 -TimeoutMs 1000 -WaitSec 60) '1.1.1.1' 30)
        if ($newPg.Received) { $Result['PingSeries'] = @(@($Result['PingSeries']) | Where-Object { $_ -and $_.Target -ne '1.1.1.1' }) + @($newPg) }
        elseif ($script:FullLanguage) {
            # ICMP blocked on this network: measure loss and latency with TCP connects instead.
            Write-Step '  ICMP to 1.1.1.1 blocked; using a TCP series to 1.1.1.1:443' 'Yellow'
            $Result['TcpSeries'] = @(@($Result['TcpSeries']) | Where-Object { $_ }) + @([pscustomobject](Receive-TcpSeries (Start-TcpSeries '1.1.1.1' '1.1.1.1' 443 30) 60))
        }
    } catch { $script:Errors += [pscustomobject]@{ Collector = 'Retry ping 1.1.1.1'; Error = $_.Exception.Message } }
}

if (-not (Get-Val $Result['Egress'] 'PublicIPv4')) {
    Write-Step 'Retry: public IP and carrier' 'Yellow'
    $script:Retried += 'public egress'
    Start-Sleep -Seconds 5
    $eg2 = Invoke-Collector 'Public egress (retry)' $EgressBlock
    if (Get-Val $eg2 'PublicIPv4') { $Result['Egress'] = $eg2 }
}

if ($EnableBandwidth) {
    $bw = $Result['Bandwidth']
    $missing = @()
    if (-not (Get-Val $bw 'DownloadOk')) { $missing += 'Download' }
    if (-not (Get-Val $bw 'UploadOk')) { $missing += 'Upload' }
    if ($missing.Count) {
        Write-Step ("Retry: bandwidth ({0}) after a 45 s pause" -f ($missing -join ' + ')) 'Yellow'
        $script:Retried += "bandwidth $($missing -join '+')"
        Start-Sleep -Seconds 45
        $bw2 = Invoke-Collector 'Bandwidth test (retry)' { Measure-Bandwidth -Only $missing }
        if ($bw -isnot [System.Collections.IDictionary] -or -not $bw.Contains('DownloadOk')) {
            # The first run crashed outright; take the retry as it is.
            if ($bw2 -is [System.Collections.IDictionary] -and $bw2.Contains('DownloadOk')) { $Result['Bandwidth'] = $bw2 }
        } elseif ($bw2 -is [System.Collections.IDictionary]) {
            foreach ($dir in $missing) {
                if (-not $bw2["${dir}Ok"]) { continue }
                foreach ($k in @($bw2.Keys)) { if ($k -like "$dir*") { $bw[$k] = $bw2[$k] } }
                if ($bw.Contains("${dir}Failure")) { $bw.Remove("${dir}Failure") }
                $bw["${dir}Note"] = (@($bw2["${dir}Note"], 'measured on retry') | Where-Object { $_ }) -join '; '
            }
            $bw['Attempts'] = @(@($bw['Attempts']) + @($bw2['Attempts']) | Where-Object { $_ })
            Update-Bufferbloat $bw
            if ($bw2['FinishedAt']) { $bw['FinishedAt'] = $bw2['FinishedAt'] }
        }
    }
}
$Result['Meta']['Retried'] = $script:Retried

# =====================================================================
# PHASE 6c: active discovery, deliberately last. Bandwidth, traceroutes and the path tests are
# already done and are saved here first (checkpoint), so if security software or the firewall
# reacts to the gateway probes or the sweep, the core data is already on disk.
# =====================================================================
[void](Save-Json 'checkpoint: core data saved, active discovery not finished')
Write-Step $(if ($EnableDiscovery) { 'Core data saved. Starting active discovery (gateway probes, device discovery, subnet sweep)' } else { 'Core data saved. Discovery is off: finishing the checks of this PC and its internet path' })

# ---- Other subnets: what this PC can reach (no traffic), and which to sweep (-Discovery only) ----
$script:ScanSpecs = @()
try {
    $localRanges = @()
    foreach ($a in @(Get-Val $Result['Network'] 'Adapters')) {
        if (-not $a -or $a.Status -ne 'Up') { continue }
        $ips = @($a.IPv4); $masks = @($a.SubnetMask)
        for ($q = 0; $q -lt $ips.Count; $q++) {
            if (-not (Test-IPv4 "$($ips[$q])") -or "$($ips[$q])" -like '169.254.*') { continue }
            $mk = if ($masks.Count -gt $q -and (Test-IPv4 "$($masks[$q])")) { "$($masks[$q])" } else { '255.255.255.0' }
            $pre = 0; $mi = ConvertTo-IpNumber $mk; for ($bit = 31; $bit -ge 0; $bit--) { if (($mi -shr $bit) -band 1) { $pre++ } else { break } }
            $localRanges += ConvertTo-NetRange "$($ips[$q])" $pre
        }
    }
    if ($EnableDiscovery -and $EnableSnmp -and $script:FullLanguage -and $Gateway -and $SnmpCommunity) {
        $Result['GatewayRouter'] = Invoke-Collector 'Gateway routes over SNMP (for the subnet list)' {
            $gt = Get-RouterTables "$Gateway" $SnmpCommunity $true
            # A gateway without SNMP is normal (most small offices): note it, it is not a collector error
            if (-not $gt) { return [ordered]@{ Status = 'no SNMP answer from the gateway' } }
            $gt
        }
    }
    $cands = @(Get-CandidateSubnets $Result $localRanges)
    $rsOut = [ordered]@{ Candidates = $cands; Answer = $null; Selected = @(); Rejected = @() }
    if ($EnableDiscovery -and $EnableRemoteSweep -and $script:FullLanguage) {
        $explicit = @(@($ScanSubnets) + @($SiteSubnets) | Where-Object { $_ })
        $explicitSpecs = @($explicit | ForEach-Object { ConvertTo-SubnetSpec $_ } | Where-Object { $_ })
        $offer = @($cands | Where-Object { $c = ConvertTo-SubnetSpec $_.Cidr; -not @($explicitSpecs | Where-Object { Test-RangeOverlap $_ $c }).Count })
        $answer = ''
        if ($offer.Count -and -not $NoPrompt) {
            Write-Host ''
            Write-Host 'OTHER SUBNETS this PC can reach. None is swept unless you pick it:' -ForegroundColor White
            for ($k = 0; $k -lt $offer.Count; $k++) {
                $why = (@($offer[$k].Reasons) | Select-Object -First 3) -join '; '
                Write-Host ('  {0,2}) {1,-18} {2}' -f ($k + 1), $offer[$k].Cidr, $why)
                if ($offer[$k].Hosted) { Write-Host '                         a remote desktop target is here: this may be the provider''s network, not the client''s' -ForegroundColor Yellow }
            }
            $answer = Read-Host 'Sweep which? Numbers (1,3 or 2-4), A for all, Enter for none'
        }
        $sel = Select-ScanSubnets -Explicit $explicit -Candidates $offer -Answer $answer -Exclude $localRanges -Max $RemoteSweepMaxSubnets
        $script:ScanSpecs = @($sel.Selected)
        $rsOut['Answer'] = $answer
        $rsOut['Selected'] = @($sel.Selected | ForEach-Object { [pscustomobject]@{ Subnet = $_.Cidr; Reason = $_.Reason } })
        $rsOut['Rejected'] = @($sel.Rejected)
        foreach ($rj in @($sel.Rejected)) { Write-Step "  Not swept: $rj" 'DarkYellow' }
    }
    $Result['RemoteSubnets'] = $rsOut
} catch { $script:Errors += [pscustomobject]@{ Collector = 'Other subnets'; Error = $_.Exception.Message } }

if ($EnableGatewayProbe -and $Gateway) {
    $Result['GatewayProbe'] = Invoke-Collector 'Gateway banner probe' {
        # A 1 s port check first, so a gateway that ignores web requests (guest Wi-Fi) costs seconds, not 10.
        foreach ($pp in @(@('https', 443), @('http', 80))) {
            if (Test-TcpPort $Gateway $pp[1] 1000) { Get-HttpBanner ('{0}://{1}/' -f $pp[0], $Gateway) 5000 }
            else { [pscustomobject]@{ Url = ('{0}://{1}/' -f $pp[0], $Gateway); Status = $null; Server = $null; Title = $null; CertSubject = $null; CertIssuer = $null; Error = "tcp/$($pp[1]) closed or filtered" } }
        }
    }
    $Result['GatewayModel'] = Get-FirewallModelHint @($Result['GatewayProbe'])
}

if ($EnableFirewallPorts -and $Gateway -and (Test-IPv4 $Gateway)) {
    $Result['FirewallPorts'] = Invoke-Collector 'Gateway admin ports + SSH banner' {
        $rows = @()
        # 4443/8443/10443 FortiGate and generic admin, 4433 SonicWall SSL VPN, 4444 Sophos admin,
        # 8080 WatchGuard Web UI, 4118 WatchGuard WSM (not HTTPS; open/closed is the signal).
        foreach ($port in @(4443, 8443, 10443, 4433, 4444, 8080, 4118)) {
            $open = Test-TcpPort $Gateway $port 1200
            $b = $null
            if ($open -and $port -ne 4118) { $b = Get-HttpBanner ("https://{0}:{1}/" -f $Gateway, $port) 4000 }
            $rows += [pscustomobject]@{ Port = $port; Open = $open; Title = $(if ($b) { $b.Title }); Server = $(if ($b) { $b.Server }); CertSubject = $(if ($b) { $b.CertSubject }); CertIssuer = $(if ($b) { $b.CertIssuer }); Banner = $null }
        }
        # SSH announces itself on connect (e.g. "SSH-2.0-...").
        $ssh = [pscustomobject]@{ Port = 22; Open = $false; Title = $null; Server = $null; CertSubject = $null; CertIssuer = $null; Banner = $null }
        $c = New-Object Net.Sockets.TcpClient
        try {
            $t = $c.ConnectAsync($Gateway, 22)
            if ($t.Wait(1200) -and $c.Connected) {
                $ssh.Open = $true
                $ns = $c.GetStream(); $ns.ReadTimeout = 2000
                $buf = New-Object byte[] 256
                try { $n = $ns.Read($buf, 0, $buf.Length); if ($n -gt 0) { $ssh.Banner = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -replace '[^\x20-\x7E]', '').Trim() } } catch { }
            }
        } catch { } finally { $c.Close() }
        $rows += $ssh
        $hints = @()
        foreach ($r in $rows) {
            $hay = "$($r.Title) $($r.Server) $($r.CertSubject) $($r.CertIssuer) $($r.Banner)"
            if ($hay -match 'Forti') { $hints += 'Fortinet' }
            elseif ($hay -match 'SonicWall|SonicOS') { $hints += 'SonicWall' }
            elseif ($hay -match 'Sophos') { $hints += 'Sophos' }
            elseif ($hay -match 'WatchGuard') { $hints += 'WatchGuard' }
            elseif ($hay -match 'Meraki') { $hints += 'Cisco Meraki' }
            elseif ($hay -match 'Palo ?Alto|PAN-OS|GlobalProtect') { $hints += 'Palo Alto Networks' }
            elseif ($hay -match 'ApplianceCertificate') { $hints += 'Sophos' }
            elseif ($hay -match 'pfSense|OPNsense|UniFi|Ubiquiti|EdgeOS|MikroTik|Cisco') { $hints += $matches[0] }
        }
        $openPorts = @($rows | Where-Object { $_.Open } | ForEach-Object { $_.Port })
        if ($openPorts -contains 4444) { $hints += 'Sophos (admin port 4444 open)' }
        if ($openPorts -contains 8080 -and $openPorts -contains 4118) { $hints += 'WatchGuard (ports 8080 + 4118 open)' }
        # A Meraki MX answers DNS for wired.meraki.com with its own LAN address (when clients use it for DNS).
        $meraki = $null
        try {
            $mr = @(Resolve-DnsName -Name 'wired.meraki.com' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' })[0]
            if ($mr -and (Get-IpClass $mr.IPAddress) -eq 'Private') {
                $mb = Get-HttpBanner ('http://{0}/' -f $mr.IPAddress) 4000
                $meraki = [ordered]@{ LocalStatusPageIp = $mr.IPAddress; Title = $mb.Title; Server = $mb.Server; Error = $mb.Error }
                $hints += 'Cisco Meraki (MX local status page)'
            }
        } catch { }
        [ordered]@{ Ports = $rows; VendorHints = @($hints | Sort-Object -Unique); MerakiLocalStatus = $meraki }
    }
}

if ($EnableSsdp -and $script:FullLanguage) {
    $Result['Ssdp'] = Invoke-Collector 'SSDP/UPnP discovery' {
        $src = Get-Val $Result['Network'] 'SourceIp'
        $udp = New-Object Net.Sockets.UdpClient
        $found = @{}
        try {
            $bindIp = if ($src -and (Test-IPv4 $src)) { [Net.IPAddress]::Parse($src) } else { [Net.IPAddress]::Any }
            $udp.Client.Bind((New-Object Net.IPEndPoint($bindIp, 0)))
            $udp.Client.ReceiveTimeout = 400
            $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: ssdp:all`r`n`r`n"
            $bytes = [Text.Encoding]::ASCII.GetBytes($msg)
            $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Parse('239.255.255.250'), 1900)
            [void]$udp.Send($bytes, $bytes.Length, $ep)
            [void]$udp.Send($bytes, $bytes.Length, $ep)
            $until = (Get-Date).AddSeconds(3)
            $rt = $null
            while ((Get-Date) -lt $until) {
                # ReceiveAsync returns the sender with the data ([ref] on Receive did not update in PowerShell).
                # One receive stays pending across loop passes so no reply is dropped.
                if (-not $rt) { $rt = $udp.ReceiveAsync() }
                if (-not $rt.Wait(400)) { continue }
                if ($rt.IsFaulted) { $rt = $null; continue }
                $data = $rt.Result.Buffer
                $ip = $rt.Result.RemoteEndPoint.Address.ToString()
                $rt = $null
                if ($ip -eq $src) { continue }
                $txt = [Text.Encoding]::ASCII.GetString($data)
                $loc = $null; $srv = $null
                if ($txt -match '(?im)^LOCATION:\s*(\S+)') { $loc = $matches[1] }
                if ($txt -match '(?im)^SERVER:\s*(.+)$') { $srv = $matches[1].Trim() }
                if (-not $found.ContainsKey($ip)) { $found[$ip] = [ordered]@{ IP = $ip; Server = $srv; Locations = @(); FriendlyName = $null; Manufacturer = $null; Model = $null; ModelNumber = $null; DeviceType = $null } }
                if ($loc -and $found[$ip].Locations -notcontains $loc) { $found[$ip].Locations += $loc }
                if (-not $found[$ip].Server -and $srv) { $found[$ip].Server = $srv }
            }
        } finally { $udp.Close() }
        # Each device's description XML names the model.
        $fetched = 0
        foreach ($ip in @($found.Keys)) {
            $d = $found[$ip]
            foreach ($loc in ($d.Locations | Select-Object -First 2)) {
                if ($fetched -ge 20 -or $d.Model) { break }
                $fetched++
                try {
                    $resp = Invoke-WebRequest -Uri $loc -UseBasicParsing -TimeoutSec 3
                    [xml]$x = $resp.Content
                    $dev = $x.root.device
                    if ($dev) {
                        $d.FriendlyName = "$($dev.friendlyName)"; $d.Manufacturer = "$($dev.manufacturer)"
                        $d.Model = "$($dev.modelName)"; $d.ModelNumber = "$($dev.modelNumber)"; $d.DeviceType = ("$($dev.deviceType)" -replace '^urn:schemas-upnp-org:device:', '')
                    }
                } catch { }
            }
        }
        $devices = @($found.Values | ForEach-Object { [pscustomobject]@{ IP = $_.IP; FriendlyName = $_.FriendlyName; Manufacturer = $_.Manufacturer; Model = $_.Model; ModelNumber = $_.ModelNumber; DeviceType = $_.DeviceType; Server = $_.Server } } | Sort-Object { try { [version]$_.IP } catch { [version]'0.0' } })
        [ordered]@{ DeviceCount = $devices.Count; Devices = $devices }
    }
}

if ($EnableSubnetSweep) {
    $Result['SubnetSweep'] = Invoke-Collector 'Subnet sweep' {
        $primary = @($Result['Network']['Adapters'] | Where-Object { $_.Name -eq $Result['Network']['PhysicalAdapter'] }) | Select-Object -First 1
        # @() because a one-item array assigned from an if-expression collapses to a plain string.
        $ip = @($primary.IPv4)[0]
        if (-not $ip) { throw 'No IPv4 address on the primary adapter' }
        # Sweep the adapter's real subnet (not an assumed /24), capped at the /22 around this machine.
        $toInt = { param($s) $o = "$s".Split('.'); ([int64]$o[0] -shl 24) + ([int64]$o[1] -shl 16) + ([int64]$o[2] -shl 8) + [int64]$o[3] }
        $toIp = { param([int64]$n) '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255) }
        $mask = @($primary.SubnetMask)[0]
        if (-not (Test-IPv4 $mask)) { $mask = '255.255.255.0' }
        $maskInt = & $toInt $mask
        $prefix = 0
        for ($bit = 31; $bit -ge 0; $bit--) { if (($maskInt -shr $bit) -band 1) { $prefix++ } else { break } }
        $sweepNote = $null
        if ($prefix -lt 22) { $sweepNote = "Subnet is /$prefix; only the /22 around this machine was swept"; $prefix = 22 }
        if ($prefix -gt 30) { throw "Subnet /$prefix is too small to sweep" }
        $netInt = (& $toInt $ip) -band (([int64]4294967295 -shl (32 - $prefix)) -band [int64]4294967295)
        $bcastInt = $netInt + ([int64]1 -shl (32 - $prefix)) - 1
        $targets = New-Object Collections.Generic.List[string]
        for ($h = $netInt + 1; $h -lt $bcastInt; $h++) { $targets.Add((& $toIp $h)) }
        $alive = @()
        # Batches of 256 keep the number of open ping handles reasonable on a /22.
        for ($b0 = 0; $b0 -lt $targets.Count; $b0 += 256) {
            $chunk = @($targets[$b0..([math]::Min($b0 + 255, $targets.Count - 1))])
            $pingers = @(); $tasks = @()
            foreach ($t in $chunk) { $p = New-Object Net.NetworkInformation.Ping; $pingers += $p; $tasks += $p.SendPingAsync($t, 600) }
            try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, 8000) | Out-Null } catch { }
            for ($j = 0; $j -lt $tasks.Count; $j++) {
                if ($tasks[$j].IsCompleted -and -not $tasks[$j].IsFaulted -and $tasks[$j].Result.Status -eq 'Success') { $alive += $chunk[$j] }
            }
            foreach ($p in $pingers) { $p.Dispose() }
        }
        $neigh = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $primary.IfIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-){5}00$|^(FF-){5}FF$' -and "$($_.State)" -ne 'Unreachable' } |
            Where-Object { $n = & $toInt $_.IPAddress; $n -gt $netInt -and $n -lt $bcastInt })
        $devices = @()
        foreach ($n in $neigh) {
            $devices += [pscustomobject]@{ IP = $n.IPAddress; Mac = $n.LinkLayerAddress; Vendor = (Get-MacVendor $n.LinkLayerAddress); RespondedToPing = ($alive -contains $n.IPAddress); Name = $null; OpenPorts = @(); Role = $null }
        }
        # Identify what was found: a name lookup and a few TCP ports per device (first 256 devices).
        $identified = 0
        if ($EnableSweepPorts -and $script:FullLanguage -and $devices.Count) {
            $scan = @($devices | Select-Object -First 256)
            # Name lookups block a thread each until they answer or time out, so allow enough threads for the batch.
            $minW = 0; $minIo = 0
            [Threading.ThreadPool]::GetMinThreads([ref]$minW, [ref]$minIo)
            [void][Threading.ThreadPool]::SetMinThreads([math]::Max($minW, 128), $minIo)
            $nameTasks = @{}
            foreach ($d in $scan) { try { $nameTasks[$d.IP] = [Net.Dns]::GetHostEntryAsync([string]$d.IP) } catch { } }
            $openMap = Test-TcpPortsBulk @($scan | ForEach-Object { $_.IP }) $SweepPorts 800
            if ($nameTasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($nameTasks.Values), 8000) } catch { } }
            [void][Threading.ThreadPool]::SetMinThreads($minW, $minIo)
            foreach ($d in $scan) {
                $t = $nameTasks[$d.IP]
                if ($t -and "$($t.Status)" -eq 'RanToCompletion' -and $t.Result.HostName -and $t.Result.HostName -ne $d.IP) { $d.Name = $t.Result.HostName }
                if ($openMap.ContainsKey($d.IP)) { $d.OpenPorts = @($openMap[$d.IP] | Sort-Object) }
                $d.Role = Get-DeviceRole $d.OpenPorts
                if ($d.Name -or $d.Role) { $identified++ }
            }
        }
        [ordered]@{
            Subnet = '{0}/{1}' -f (& $toIp $netInt), $prefix
            Note = $sweepNote
            PortsChecked = $(if ($EnableSweepPorts -and $script:FullLanguage) { $SweepPorts } else { @() })
            Identified = $identified
            RoleSummary = @($devices | Where-Object { $_.Role } | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            AddressesSwept = $targets.Count
            PingResponders = $alive.Count
            ArpEntries = $devices.Count
            Devices = @($devices | Sort-Object { [version]$_.IP })
            VendorSummary = @($devices | Group-Object Vendor | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        }
    }
}

if ($EnableRemoteSweep -and $script:FullLanguage -and @($script:ScanSpecs).Count) {
    $Result['RemoteSweep'] = Invoke-Collector ("Other subnets ({0}): ping and TCP sweep across routing" -f ((@($script:ScanSpecs) | ForEach-Object { $_.Cidr }) -join ', ')) {
        Invoke-RemoteSweep -Specs $script:ScanSpecs -Ports $(if ($EnableSweepPorts) { $SweepPorts } else { @() }) -PresencePorts $RemoteSweepPresencePorts -TimeoutMs 1000
    }
}

# Runs after the sweep so printers the sweep found are identified too.
if ($EnablePrinterProbe) {
    $Result['PrinterProbe'] = Invoke-Collector 'Network printer web pages' {
        $ips = @()
        foreach ($p in @(Get-Val $Result['Peripherals'] 'Printers')) { if ($p -and $p.HostAddress -and (Test-IPv4 $p.HostAddress)) { $ips += $p.HostAddress } }
        $printVendors = 'Hewlett|HP Inc|Brother|Canon|Epson|Seiko Epson|Xerox|Lexmark|Ricoh|Kyocera|Konica|Sharp|Toshiba|Zebra|Oki|Fuji'
        foreach ($d in @(Get-Val $Result['SubnetSweep'] 'Devices')) { if ($d -and ($d.Vendor -match $printVendors -or $d.Role -eq 'Printer')) { $ips += $d.IP } }
        $rows = @()
        foreach ($ip in ($ips | Select-Object -Unique | Select-Object -First 15)) {
            $row = [ordered]@{ IP = $ip; Reachable = $false; Title = $null; Server = $null; Url = $null }
            foreach ($scheme in @(@('http', 80), @('https', 443))) {
                if (Test-TcpPort $ip $scheme[1] 1000) {
                    $row.Reachable = $true
                    $b = Get-HttpBanner ('{0}://{1}/' -f $scheme[0], $ip) 4000
                    if ($b.Title -or $b.Server) { $row.Title = $b.Title; $row.Server = $b.Server; $row.Url = $b.Url; break }
                }
            }
            $rows += [pscustomobject]$row
        }
        $rows
    }
}

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
            elseif ($hay -match 'Starlink') { $looks = 'Starlink dish (satellite terminal)' }
            elseif (@($pages | Where-Object { $_.Title }).Count) { $looks = "ISP device, page titled '$(@($pages | Where-Object { $_.Title })[0].Title)'" }
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

try { $Result['Leads'] = @(Get-Leads $Result) } catch { $script:Errors += [pscustomobject]@{ Collector = 'Leads'; Error = $_.Exception.Message } }
$Topology = Invoke-Collector 'Topology verdict' { Get-TopologyVerdict $Result $RdpHosts }
$Result['Topology'] = $Topology

# What the evidence adds up to: saved with the data and printed at the end of the run.
$script:Findings = @()
try {
    $areaOrder = @('This run', 'Speed test', 'Switch port', 'Switching', 'Internet service', 'Traffic design', 'Remote desktop', 'Tunnel', 'DNS and DHCP', 'Cloud services', 'Gateway', 'Network equipment', 'Network layout', 'Phones', 'Windows machines', 'Printers', 'Cameras', 'Other offices', 'Directory')
    $fi = 0
    $script:Findings = @(Get-AssessmentFindings $Result | ForEach-Object { $fi++; $ix = [array]::IndexOf($areaOrder, "$($_.Area)"); if ($ix -lt 0) { $ix = 99 }; [pscustomobject]@{ Sort = ($ix * 1000) + $fi; Item = $_ } } | Sort-Object Sort | ForEach-Object { $_.Item })
} catch { $script:Errors += [pscustomobject]@{ Collector = 'Findings'; Error = $_.Exception.Message } }
$Result['Findings'] = $script:Findings

# ---------------- Flags ----------------
try {
    foreach ($dp in @(Get-Val $Result['Domains'] 'Domains')) { foreach ($df in @(Get-DomainFlags $dp)) { Add-Flag $df.Severity $df.Category $df.Message } }
    foreach ($af in @(Get-AdSiteFlags (Get-AdSiteCheck $Result))) { Add-Flag $af.Severity $af.Category $af.Message }
    $Result['RdpTransport'] = Get-RdpTransportCheck $Result
    foreach ($rf in @(Get-RdpTransportFlags $Result['RdpTransport'] ([bool]@($RdpHosts).Count))) { Add-Flag $rf.Severity $rf.Category $rf.Message }
    if ("$(Get-Prop $Result 'Ipv6', 'Status')" -eq 'Broken') { Add-Flag 'Medium' 'Network' 'IPv6 is offered but does not reach the internet (slow first connections)' }
    foreach ($rf in @(Get-NetworkRiskFlags $Result)) { Add-Flag $rf.Severity $rf.Category $rf.Message }
    foreach ($sd in @(Get-Val $Result['Snmp'] 'Devices')) {
        $u = Get-Prop $sd 'Ups'
        if (-not $u) { continue }
        $un = ("UPS {0} at {1}" -f ("$($u.Manufacturer) $($u.Model)").Trim(), $sd.IP)
        if ($u.OnBattery) { Add-Flag 'High' 'Power' "$un is running on battery" }
        if ($u.Battery -in @('low', 'depleted', 'in fault')) { Add-Flag 'High' 'Power' "$un reports its battery as $($u.Battery)" }
        if ($u.ReplaceBattery) { Add-Flag 'High' 'Power' "$un says its battery needs replacing" }
        if ($null -ne $u.MinutesRemaining -and $u.MinutesRemaining -lt 10) { Add-Flag 'Medium' 'Power' "$un has only $($u.MinutesRemaining) minutes of runtime at the current load" }
        if ($null -ne $u.LoadPct -and $u.LoadPct -ge 80) { Add-Flag 'Medium' 'Power' "$un is loaded to $($u.LoadPct)%" }
    }
    $m = $Result['Machine']
    if (Get-Val $m 'IsWindows10') { Add-Flag 'High' 'Lifecycle' 'Windows 10 (out of support since Oct 2025)' }
    if ((Get-Val $m 'RamGB') -and $m['RamGB'] -lt 7.5) { Add-Flag 'Medium' 'Lifecycle' "Only $($m['RamGB']) GB RAM" }
    if (@(Get-Val $m 'Disks' | Where-Object { $_.MediaType -eq 'HDD' }).Count -gt 0) { Add-Flag 'Medium' 'Lifecycle' 'Spinning hard drive (HDD)' }
    if ((Get-Val $m 'ApproxAgeYears') -ge 5) { Add-Flag 'Medium' 'Lifecycle' "About $($m['ApproxAgeYears']) years old (from $(Get-Val $m 'AgeSource'))" }
    $tpmV = Get-Val (Get-Val $m 'Tpm') 'TPM Version'
    $tpmP = "$(Get-Val (Get-Val $m 'Tpm') 'TPM Present')"
    $adminTpm = Get-Val $Result['Admin'] 'Tpm'
    if ($adminTpm -is [System.Collections.IDictionary]) {
        if (-not $adminTpm['Present']) { Add-Flag 'High' 'Lifecycle' 'No TPM (admin check)' }
        elseif (-not $adminTpm['Is20']) { Add-Flag 'High' 'Lifecycle' 'No TPM 2.0 (admin check)' }
    }
    elseif ($tpmP -match '^(False|No)') { Add-Flag 'High' 'Lifecycle' 'No TPM detected (tpmtool)' }
    elseif ($tpmV -and $tpmV -notmatch '^2') { Add-Flag 'High' 'Lifecycle' "TPM version $tpmV" }
    foreach ($b in @(Get-Val $m 'Battery')) { if ($b -and $b.HealthPct -and $b.HealthPct -lt 60) { Add-Flag 'Medium' 'Lifecycle' "Battery health $($b.HealthPct)% of design" } }
    foreach ($v in @(Get-Val $m 'Volumes')) { if ($v -and $v.FreePct -ne $null -and $v.FreePct -lt 10) { Add-Flag 'Low' 'Lifecycle' "Drive $($v.Drive) only $($v.FreePct)% free" } }

    $n = $Result['Network']
    if ("$(Get-Val $n 'PhysicalClass')" -like 'Wired*' -and (Get-Val $n 'PhysicalLinkMbps') -and $n['PhysicalLinkMbps'] -lt 1000) { Add-Flag 'Medium' 'Network' "Wired link negotiated at $($n['PhysicalLinkMbps']) Mbps (cable/switch port)" }
    if (Get-Val $n 'MultipleConnected') { Add-Flag 'Low' 'Network' "Multiple connections up: $($n['ConnectedPhysical'] -join '; ')" }
    if ("$(Get-Val $n 'PhysicalClass')" -eq 'Phone tether (USB)') { Add-Flag 'High' 'Network' 'Internet is via a phone tether' }
    $w = Get-Val $Result['Wireless'] 'Current'
    if ($w -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi') {
        if ($w['SignalPct'] -ne $null -and $w['SignalPct'] -lt 50) { Add-Flag 'Medium' 'Wireless' "Weak Wi-Fi signal ($($w['SignalPct'])%)" }
        if ("$($w['Band'])" -like '2.4*') { Add-Flag 'Medium' 'Wireless' 'Connected on 2.4 GHz' }
        if ("$($w['RadioType'])" -match '802\.11[bgn]$') { Add-Flag 'Low' 'Wireless' "Legacy radio type $($w['RadioType'])" }
    }
    if ((Get-Val $Result['Wireless'] 'Status') -like 'Blocked*') {
        # A policy block applies to every managed PC; a permission block can differ per machine.
        $locWhy = "$(Get-Val (Get-Val $Result['Wireless'] 'LocationWorkaround') 'Result')"
        $flagText = if ($locWhy -like 'Blocked by policy*') { 'Wi-Fi details blocked: location is disabled by policy (likely on every managed PC)' } else { 'Wi-Fi details blocked by location permission' }
        Add-Flag 'Low' 'Wireless' $flagText
    }
    $wev = Get-Val $Result['Wireless'] 'Events'
    # Only drops on the network this run is on count; a laptop's history at other places is not this site.
    $curSsid = if ($w -is [System.Collections.IDictionary]) { $w['SSID'] } else { $null }
    if ("$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi' -and $curSsid -and $wev -is [System.Collections.IDictionary]) {
        $siteDrops = @($wev['RecentRealDrops'] | Where-Object { $_ -and $_.SSID -eq $curSsid }).Count
        $bySsid = @($wev['RealDropsBySsid'] | Where-Object { $_ -like "$curSsid x*" })
        if ($bySsid.Count -and $bySsid[0] -match ' x(\d+)$') { $siteDrops = [int]$matches[1] }
        $wev['SiteSsidDrops'] = $siteDrops
        if ($siteDrops -ge 10) { Add-Flag $(if ($siteDrops -ge 30) { 'High' } else { 'Medium' }) 'Wireless' "$siteDrops Wi-Fi drops with quick reconnect on '$curSsid' in $LookbackDays days" }
    }
    if (@($script:OnPremDns).Count) { Add-Flag 'Medium' 'Infrastructure' "On-prem DNS server(s) on the LAN ($($script:OnPremDns -join ', ')): likely domain controller(s) or servers; confirm what runs on them" }
    $nas = @(@(Get-Val $Result['Ssdp'] 'Devices') | Where-Object { $_ -and "$($_.Manufacturer) $($_.Model)" -match 'Synology|QNAP|Western Digital|WD My|Buffalo|Asustor|TrueNAS|NETGEAR ReadyNAS|Drobo|TerraMaster' })
    foreach ($nd in $nas) { Add-Flag 'Medium' 'Infrastructure' ("On-prem NAS found: {0} {1} '{2}' at {3}" -f $nd.Manufacturer, $nd.Model, $nd.FriendlyName, $nd.IP) }

    foreach ($p in @($Result['PingSeries'])) {
        if (-not $p) { continue }
        if ($p.LossPct -ge 1) { Add-Flag $(if ($p.LossPct -ge 5) { 'High' } else { 'Medium' }) 'Path' "Packet loss $($p.LossPct)% to $($p.Target)" }
        if ($p.JitterMs -ge 30) { Add-Flag 'Medium' 'Path' "Jitter $($p.JitterMs) ms to $($p.Target)" }
    }
    foreach ($ts in @($Result['TcpSeries'])) {
        if (-not $ts -or -not $ts.Sent) { continue }
        if ($ts.LossPct -ge 1) { Add-Flag $(if ($ts.LossPct -ge 5) { 'High' } else { 'Medium' }) 'Path' "TCP connect loss $($ts.LossPct)% to $($ts.Target):$($ts.Port)" }
        if ($ts.JitterMs -ge 30) { Add-Flag 'Medium' 'Path' "Jitter $($ts.JitterMs) ms to $($ts.Target):$($ts.Port) (TCP)" }
    }
    # Microsoft (AVD connection quality): round trip under 150 ms is fine, 150-200 ms is OK for text work, over 200 ms degrades.
    $rdpRtt = @(@($Result['TcpSeries']) + @($Result['PingSeries']) | Where-Object { $_ -and $RdpHosts -contains $_.Target -and $null -ne $_.AvgMs })
    foreach ($rt in $rdpRtt) {
        $how = if ($rt.Method) { 'TCP' } else { 'ping' }
        if ($rt.AvgMs -gt 200) { Add-Flag 'High' 'RDP' "Round trip to $($rt.Target) is $($rt.AvgMs) ms ($how); over 200 ms degrades remote desktop use" }
        elseif ($rt.AvgMs -gt 150) { Add-Flag 'Medium' 'RDP' "Round trip to $($rt.Target) is $($rt.AvgMs) ms ($how); Microsoft recommends under 150 ms" }
    }
    $ast = Get-Val $Result['NetworkExtra'] 'AdapterStats'
    if ($ast -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -like 'Wired*') {
        $errs = [double]$ast['ReceiveErrors'] + [double]$ast['SendErrors']
        $pkts = [double]$ast['ReceivedPackets'] + [double]$ast['SentPackets']
        if ($errs -gt 0 -and $pkts -gt 0 -and ($errs / $pkts) -ge 0.0001) { Add-Flag 'Medium' 'Network' ("{0} adapter errors in {1:N0} packets since boot (cable or switch port)" -f $errs, $pkts) }
    }
    foreach ($mt in @($Result['Mtu'])) { if ($mt -and $mt.MtuBytes -and $mt.MtuBytes -lt 1500) { Add-Flag 'Low' 'Path' "Reduced MTU $($mt.MtuBytes) to $($mt.Target)" } }
    $bw = $Result['Bandwidth']
    if ((Get-Val $bw 'BufferbloatMs') -ge 100) { Add-Flag 'High' 'Path' "Bufferbloat: latency rises $($bw['BufferbloatMs']) ms under load (RDP lag)" }
    if ((Get-Val $bw 'UploadMbps') -ne $null -and $bw['UploadMbps'] -lt 5) { Add-Flag 'Medium' 'Path' "Low upload ($($bw['UploadMbps']) Mbps)" }
    if ($bw -is [System.Collections.IDictionary] -and $bw.Contains('DownloadOk') -and -not $bw['DownloadOk']) { Add-Flag 'High' 'Run' "Download bandwidth NOT measured by any provider ($($bw['DownloadFailure'])); re-run this machine" }
    if ($bw -is [System.Collections.IDictionary] -and $bw.Contains('UploadOk') -and -not $bw['UploadOk']) { Add-Flag 'High' 'Run' "Upload bandwidth NOT measured by any provider ($($bw['UploadFailure'])); re-run this machine" }
    $tlsF = $Result['Tls']
    if ($tlsF -is [System.Collections.IDictionary] -and $tlsF['InspectionSuspected']) {
        $insp = @($tlsF['Checks'] | Where-Object { $_ -and $_.Inspected } | ForEach-Object { '{0} (issuer {1})' -f $_.Host, $_.Issuer })
        Add-Flag 'Medium' 'Security' "HTTPS inspection: $($insp -join '; '). Inspecting the connection to the hosted desktop is a known cause of remote desktop problems"
    }
    $srvF = @(Get-Val $Result['Servers'] 'Servers' | Where-Object { $_ -and $_.Location -like 'On-prem*' })
    if ($srvF.Count) { Add-Flag 'Medium' 'Infrastructure' ("This PC uses on-prem server(s) on its own subnet: {0}" -f (($srvF | ForEach-Object { '{0} ({1})' -f $_.Name, ($_.Sources -join ', ') }) -join '; ')) }
    foreach ($dcDev in @(Get-Val $Result['SubnetSweep'] 'Devices' | Where-Object { $_ -and $_.Role -eq 'Domain controller' })) {
        Add-Flag 'Medium' 'Infrastructure' ("Domain controller on the LAN: {0} {1}" -f $dcDev.IP, $dcDev.Name)
    }
    $ptF = $Result['Patching']
    if ((Get-Val $ptF 'DaysSinceLastUpdate') -ge 45) { Add-Flag 'Medium' 'Patching' "No Windows OS update installed in $($ptF['DaysSinceLastUpdate']) days (last: $($ptF['LastUpdateTitle']))" }
    if (Get-Val $ptF 'PendingReboot') { Add-Flag 'Low' 'Patching' "Reboot pending ($($ptF['PendingRebootReasons'] -join ', '))" }
    $clkF = Get-Val $Result['Egress'] 'ClockOffsetSec'
    if ($null -ne $clkF -and [math]::Abs($clkF) -ge 60) { Add-Flag 'Medium' 'Stability' "Clock is off by $clkF s (breaks MFA/Kerberos)" }
    $admF = $Result['Admin']
    if ($script:AdminActive -and (Get-Val $admF 'SecureBoot') -eq $false) { Add-Flag 'Low' 'Security' 'Secure Boot is off (admin-confirmed)' }
    foreach ($bl in @(Get-Val $admF 'BitLocker')) { if ($bl -and $bl.VolumeType -eq 'OperatingSystem' -and $bl.Protection -ne 'On') { Add-Flag 'Medium' 'Security' "BitLocker protection $($bl.Protection) on $($bl.Mount) (admin-confirmed)" } }
    foreach ($dr in @(Get-Val $admF 'DiskReliability')) { if ($dr -and $dr.WearPct -ge 80) { Add-Flag 'High' 'Lifecycle' "SSD wear $($dr.WearPct)% on $($dr.Disk)" } }

    $rc = Get-Val $Result['EventLogs'] 'RdpClient'
    if ($rc -is [System.Collections.IDictionary]) {
        if ($rc['NetworkDisconnects'] -ge 3) {
            $netReasons = @($rc['AllDisconnects'] | Where-Object { $_ -and $_.Category -eq 'Network' } | Group-Object Code | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
            Add-Flag 'High' 'RDP' "$($rc['NetworkDisconnects']) network-caused RDP disconnects in $LookbackDays days (codes $netReasons)"
        } elseif ($rc['UnexpectedDisconnects'] -ge 5) { Add-Flag 'Medium' 'RDP' "$($rc['UnexpectedDisconnects']) unexpected RDP disconnects in $LookbackDays days ($($rc['DisconnectsByCategory'] -join ', '))" }
        $udpF = $rc['Udp']
        if ($udpF -is [System.Collections.IDictionary] -and $udpF['Failed'] -gt 0 -and $udpF['Established'] -eq 0) { Add-Flag 'Low' 'RDP' 'RDP UDP never established; sessions run on TCP only, which is more sensitive to packet loss' }
    }
    if ((Get-Val $Result['EventLogs'] 'NicLinkEventCount') -ge 10) { Add-Flag 'Medium' 'Network' "Network adapter reset/link-down events: $($Result['EventLogs']['NicLinkEventCount']) in $LookbackDays days" }
    if ((Get-Val $Result['EventLogs'] 'UnexpectedShutdowns') -ge 2) { Add-Flag 'Medium' 'Stability' "$($Result['EventLogs']['UnexpectedShutdowns']) unexpected shutdowns" }
    if ($RdpHosts.Count -eq 0) { Add-Flag 'Medium' 'RDP' 'No remote desktop target resolved on this machine' }
    # Session health (its own try so a problem here cannot skip the flags that follow)
    try {
        $sh = $Result['Session']
        $crashTotal = [int](Get-Val $sh 'ClientCrashes') + [int](Get-Val $sh 'ClientHangs')
        if ($crashTotal -ge 1) { Add-Flag $(if ($crashTotal -ge 3) { 'Medium' } else { 'Low' }) 'RDP' ("Remote desktop client crashed or hung {0} time(s) in {1} days ({2})" -f $crashTotal, $LookbackDays, (@(Get-Val $sh 'ClientCrashByApp') -join ', ')) }
        $udpPol = Get-Val $sh 'UdpPolicy'
        if ($udpPol -is [System.Collections.IDictionary] -and $udpPol['UdpDisabled']) { Add-Flag 'Low' 'RDP' "RDP UDP transport is turned off on this PC ($($udpPol['Source'])); sessions run on TCP only, which is more sensitive to packet loss" }
        $ld = Get-Val $sh 'Load'
        if ($ld -is [System.Collections.IDictionary]) {
            if ($null -ne $ld['MemoryUsedPct'] -and $ld['MemoryUsedPct'] -ge 90) { Add-Flag 'Medium' 'Performance' ("Memory nearly full during the run: {0}% of {1} GB in use (largest: {2})" -f $ld['MemoryUsedPct'], [math]::Round($ld['MemoryTotalMB'] / 1024, 1), ((@($ld['TopByMemory']) | Select-Object -First 3) -join ', ')) }
            if ($null -ne $ld['CpuAvgPct'] -and $ld['CpuAvgPct'] -ge 80) { Add-Flag 'Medium' 'Performance' "CPU busy during the run: $($ld['CpuAvgPct'])% average over $(@($ld['CpuSamplesPct']).Count) samples" }
        }
        $dp = Get-Val $sh 'Displays'
        if ($dp -is [System.Collections.IDictionary] -and $dp['TotalMegapixels'] -ge 8) { Add-Flag 'Low' 'Peripherals' ("Large display area ({0}): a hosted desktop this size needs more bandwidth per user" -f (@($dp['Sizes']) -join ' + ')) }
        $ap = Get-Val $sh 'AdapterPower'
        if ($ap -is [System.Collections.IDictionary] -and "$($ap['AllowTurnOff'])" -match '^(Enabled|Default)' -and "$(Get-Val $Result['Network'] 'PhysicalClass')" -notlike 'Wired*') {
            $dropCount = [int](Get-Val (Get-Val $Result['Wireless'] 'Events') 'SiteSsidDrops') + [int](Get-Val (Get-Val $Result['EventLogs'] 'RdpClient') 'NetworkDisconnects') + [int](Get-Val $Result['EventLogs'] 'NicLinkEventCount')
            if ($dropCount -ge 3) { Add-Flag 'Low' 'Network' "Adapter power saving has not been turned off on $($ap['Adapter']) and this PC has $dropCount recorded connection drops in $LookbackDays days: untick 'Allow the computer to turn off this device'" }
        }
    } catch { $script:Errors += [pscustomobject]@{ Collector = 'Flags (session health)'; Error = $_.Exception.Message } }

    $sw = $Result['Software']
    $blStatus = Get-Val (Get-Val $sw 'BitLocker') 'Status'
    if ($blStatus -in @('Off', 'Suspended')) { Add-Flag 'Medium' 'Security' "BitLocker $blStatus on OS drive" }
    if (@(Get-Val $sw 'AntiVirus' | Where-Object { $_.Enabled }).Count -eq 0 -and (Get-Val $sw 'AntiVirus')) { Add-Flag 'High' 'Security' 'No enabled antivirus reported' }
    if (Get-Val $Result['Identity'] 'UserIsLocalAdmin') { Add-Flag 'Medium' 'Security' 'Signed-in user is a local administrator' }
    if (Get-Val $Result['Identity'] 'LikelyShared') { Add-Flag 'Low' 'Identity' "$($Result['Identity']['ProfilesActiveInLookback']) user profiles active in $LookbackDays days (shared PC?)" }

    foreach ($c in @(Get-Val $Result['Peripherals'] 'RedirectionCheck')) { foreach ($g in @($c.Gaps)) { if ($g) { Add-Flag 'Medium' 'Peripherals' "$g ($([IO.Path]::GetFileName($c.RdpFile)))" } } }
    if ($Result['Meta']['AdminDowngraded']) { Add-Flag 'Low' 'Run' 'Admin tests skipped (ISE not elevated)' }
} catch {
    $script:Errors += [pscustomobject]@{ Collector = 'Flags'; Error = $_.Exception.Message }
}
$Result['Flags'] = $script:Flags
$Result['Errors'] = $script:Errors
$Result['Timings'] = $script:Timings
$Result['Meta']['RunSeconds'] = [int]((Get-Date) - $RunStart).TotalSeconds

# Save again now that the analysis is in, so nothing later (summary, check, zip) can lose it.
[void](Save-Json 'analysis done, data check pending')

# ---------------- Summary text ----------------
$L = New-Object Collections.Generic.List[string]
# Wrapped so a formatting problem in the summary can never stop the data from being written and checked.
try {
$m = $Result['Machine']; $n = $Result['Network']; $eg = $Result['Egress']; $bw = $Result['Bandwidth']; $w = Get-Val $Result['Wireless'] 'Current'

Add-Line ('=' * 72)
Add-Line ("SITE ASSESSMENT  {0}  /  {1}" -f $SiteName, $env:COMPUTERNAME)
Add-Line ("Run {0}  ({1} s)  by {2}  user {3}" -f $Result['Meta']['RunStart'], $Result['Meta']['RunSeconds'], $currentId.Name, $script:UserName)
Add-Line ("Admin tier: {0}" -f $(if ($script:AdminActive) { 'ACTIVE' } else { 'off' }))
if (Get-Prop $Result 'Ipv6', 'Status') { Add-Line ("IPv6: {0}{1}" -f (Get-Prop $Result 'Ipv6', 'Status'), $(if ($null -ne (Get-Prop $Result 'Ipv6', 'Ping', 'AvgMs')) { " ($(Get-Prop $Result 'Ipv6', 'Ping', 'AvgMs') ms to Cloudflare)" })) }
if ($Notes) { Add-Line "Notes: $Notes" }
Add-Line ('=' * 72)
Add-Line ''
Add-Line 'CONNECTION'
$connLine = '  {0} - {1} ({2})' -f (Get-Val $n 'PhysicalClass'), (Get-Val $n 'PhysicalDescription'), $(if (Get-Val $n 'PhysicalLinkMbps') { "$($n['PhysicalLinkMbps']) Mbps link" } else { 'link n/a' })
Add-Line $connLine
if ($w -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi' -and $w['SSID'] -and $w['SsidSource'] -ne 'netsh') {
    Add-Line ('  Wi-Fi: SSID {0} (from {1}; radio details unavailable)' -f $w['SSID'], $w['SsidSource'])
} elseif ($w -is [System.Collections.IDictionary] -and "$(Get-Val $n 'PhysicalClass')" -eq 'Wi-Fi' -and $w['SSID']) {
    Add-Line ('  Wi-Fi: SSID {0}, {1}, {2}, ch {3}, signal {4}% (~{5} dBm), rx {6} Mbps, AP {7} ({8})' -f $w['SSID'], $w['RadioType'], $w['Band'], $w['Channel'], $w['SignalPct'], $w['ApproxDbm'], $w['ReceiveMbps'], $w['BSSID'], $w['ApVendor'])
}
if (Get-Val $n 'VpnHoldsDefaultRoute') { Add-Line "  Default route held by VPN adapter: $($n['PrimaryAdapter'])" }
$wevS = Get-Val $Result['Wireless'] 'Events'
if ($wevS -is [System.Collections.IDictionary]) {
    $onSsid = if ($null -ne $wevS['SiteSsidDrops']) { "$($wevS['SiteSsidDrops']) on the current network; " } else { '' }
    Add-Line ('  Wi-Fi history, this machine ({0} days): {1}{2} real drops on all networks, {3} disconnects total, {4} failed connects' -f $LookbackDays, $onSsid, $wevS['RealDrops'], $wevS['Disconnected'], $wevS['ConnectFailed'])
}
$locS = Get-Val $Result['Wireless'] 'LocationWorkaround'
if ($locS -is [System.Collections.IDictionary] -and $locS['Needed']) { Add-Line ('  Location workaround: {0}{1}' -f $locS['Result'], $(if ($locS['Attempted']) { "; restored=$($locS['Restored'])" } else { '' })) }
Add-Line ('  IP {0}  gateway {1}  gateway vendor {2}' -f (Get-Val $n 'SourceIp'), (Get-Val $n 'Gateway'), (Get-Val $Result['NetworkExtra'] 'GatewayVendor'))
$gm = $Result['GatewayModel']
if ($gm -is [System.Collections.IDictionary]) { Add-Line ('  Firewall: {0}  (from {1})' -f $(if ($gm['Model']) { "$($gm['Vendor']) $($gm['Model'])" } else { $gm['Vendor'] }), $gm['Source']) }
foreach ($gp in @($Result['GatewayProbe'])) {
    if (-not $gp -or -not $gp.Url) { continue }
    if ($gp.Error -and -not $gp.Status) { Add-Line ('  Gateway probe {0}: {1}' -f $gp.Url, $gp.Error); continue }
    Add-Line ('  Gateway probe {0}: HTTP {1}  title "{2}"  server "{3}"{4}' -f $gp.Url, $gp.Status, $gp.Title, $gp.Server, $(if ($gp.CertSubject) { "  cert $($gp.CertSubject) (issuer $($gp.CertIssuer))" } else { '' }))
}
Add-Line ('  DNS: {0}' -f ((@(Get-Val $Result['NetworkExtra'] 'DnsServers') | ForEach-Object { if (@($script:OnPremDns) -contains $_.Server) { "$($_.Server) [on-prem, this subnet]" } else { "$($_.Server) [$($_.Type)]" } }) -join '; '))
Add-Line ('  Public IP {0}  carrier {1}  egress {2}  CF colo {3}' -f (Get-Val $eg 'PublicIPv4'), (Get-Val $eg 'Carrier'), (Get-Val $eg 'EgressCity'), (Get-Val $eg 'CloudflareColo'))
Add-Line ''
Add-Line 'TOPOLOGY'
Add-Line ('  Verdict: {0}  (confidence {1})' -f (Get-Val $Topology 'Verdict'), (Get-Val $Topology 'Confidence'))
foreach ($s in @(Get-Val $Topology 'Signals')) { Add-Line "   - $s" }
Add-Line ''
Add-Line 'BANDWIDTH'
if ($bw -is [System.Collections.IDictionary] -and $bw.Contains('DownloadOk')) {
    $dlText = if ($bw['DownloadOk']) { '{0} Mbps (peak {1}) via {2}' -f $bw['DownloadMbps'], $bw['DownloadPeakMbps'], $bw['DownloadProvider'] } else { "NOT MEASURED - $($bw['DownloadFailure'])" }
    $ulText = if ($bw['UploadOk']) { '{0} Mbps via {1}' -f $bw['UploadMbps'], $bw['UploadProvider'] } else { "NOT MEASURED - $($bw['UploadFailure'])" }
    Add-Line "  Down $dlText"
    Add-Line "  Up   $ulText"
    if ($bw['DownloadNote']) { Add-Line "  Download note: $($bw['DownloadNote'])" }
    if ($bw['UploadNote']) { Add-Line "  Upload note: $($bw['UploadNote'])" }
    if ($bw['DownloadMinRttMs'] -or $bw['UploadMinRttMs']) { Add-Line ('  M-Lab server view: down {0} Mbps, up {1} Mbps, min RTT {2} ms' -f $bw['DownloadServerMbps'], $bw['UploadServerMbps'], $(if ($bw['DownloadMinRttMs']) { $bw['DownloadMinRttMs'] } else { $bw['UploadMinRttMs'] })) }
    foreach ($at in @($bw['Attempts'] | Where-Object { $_ -and -not $_.Ok })) { Add-Line ('  Failed attempt: {0} via {1}: {2}' -f $at.Direction, $at.Provider, $at.Detail) }
    $na = { param($v) if ($null -eq $v -or "$v" -eq '') { 'n/a' } else { $v } }
    Add-Line ('  Idle latency {0} ms (jitter {1})  loaded down {2} ms / up {3} ms  bufferbloat {4}' -f (& $na (Get-Val $bw 'IdleLatencyMs')), (& $na (Get-Val $bw 'IdleJitterMs')), (& $na (Get-Val $bw 'DownloadLoadedLatencyMs')), (& $na (Get-Val $bw 'UploadLoadedLatencyMs')), (& $na (Get-Val $bw 'BufferbloatGrade')))
} else { Add-Line "  $(Get-Val $bw 'Status')" }
Add-Line ''
Add-Line 'LATENCY / LOSS (ping series, then TCP connect series)'
foreach ($p in @($Result['PingSeries'])) { if ($p) { Add-Line ('  {0,-34} loss {1,5}%  avg {2,6} ms  p95 {3,6} ms  jitter {4,5} ms' -f $p.Target, $p.LossPct, $p.AvgMs, $p.P95Ms, $p.JitterMs) } }
foreach ($p in @($Result['TcpSeries'])) { if ($p) { Add-Line ('  {0,-34} loss {1,5}%  avg {2,6} ms  p95 {3,6} ms  jitter {4,5} ms' -f ('{0} tcp/{1}' -f $p.Target, $p.Port), $p.LossPct, $p.AvgMs, $p.P95Ms, $p.JitterMs) } }
Add-Line ''
Add-Line 'TRACEROUTES'
foreach ($t in @($Result['Traceroutes'])) {
    if (-not $t) { continue }
    Add-Line ('  {0}: {1} hops, first public hop #{2} {3} ({4} ms) {5}' -f $t.Target, $t.Analysis['HopCount'], $t.Analysis['FirstPublicHop'], $t.Analysis['FirstPublicIP'], $t.Analysis['FirstPublicMs'], $t.Analysis['FirstPublicPtr'])
    $path = ($t.Hops | Select-Object -First 6 | ForEach-Object { if ($_.IP) { "$($_.IP)($($_.AvgMs))" } else { '*' } }) -join ' > '
    Add-Line "     $path"
}
Add-Line ''
Add-Line 'RDP'
$rdp = $Result['Rdp']
# Only clients that are installed are listed.
$clientParts = @()
if (Get-Val $rdp 'MstscVersion') { $clientParts += "mstsc $(Get-Val $rdp 'MstscVersion')" }
if (Get-Val $rdp 'MsrdcVersion') { $clientParts += "MSRDC $(Get-Val $rdp 'MsrdcVersion')" }
$clientParts += @(Get-Val $rdp 'AppxClients' | Where-Object { $_ })
Add-Line ('  Clients: {0}' -f $(if ($clientParts.Count) { $clientParts -join '; ' } else { 'none found' }))
Add-Line ('  Targets: {0}' -f $(if ($RdpHosts.Count) { $RdpHosts -join ', ' } else { 'none found' }))
foreach ($r in @($Result['RdpPath'])) { if ($r) { Add-Line ('  {0} -> {1} [{2}]  {3}' -f $r.Host, ($r.ResolvedIPs -join ','), $r.AddressClass, (($r.Tcp | ForEach-Object { if ($_.Open) { "tcp/$($_.Port) $($_.MedianMs) ms" } else { "tcp/$($_.Port) closed" } }) -join ', ')) } }
if (@(Get-Val $rdp 'RunningClients').Count) { Add-Line ('  Live session: {0}; UDP sockets: {1}' -f ((Get-Val $rdp 'RunningClients') -join ', '), (Get-Val $rdp 'UdpLikelyInUse')) }
$rc = Get-Val $Result['EventLogs'] 'RdpClient'
if ($rc -is [System.Collections.IDictionary]) {
    Add-Line ('  Last {0} days: {1} connects, {2} disconnects ({3} unexpected, {4} network): {5}' -f $LookbackDays, $rc['ConnectAttempts'], $rc['Disconnects'], $rc['UnexpectedDisconnects'], $rc['NetworkDisconnects'], ($rc['DisconnectReasons'] -join '; '))
    if ($rc['Udp'] -is [System.Collections.IDictionary]) { Add-Line ('  UDP transport: {0} (attempted {1}, established {2}, failed {3})' -f $rc['Udp']['Status'], $rc['Udp']['Attempted'], $rc['Udp']['Established'], $rc['Udp']['Failed']) }
}
$avc = @(Get-Val $rdp 'HostedConnections')
if ($avc.Count -and $avc[0]) { Add-Line ('  Live hosted desktop connections: {0}' -f (($avc | ForEach-Object { '{0} {1}:{2} ({3})' -f $_.Name, $_.RemoteAddress, $_.RemotePort, $_.Process }) -join '; ')) }
if (@(Get-Val $rdp 'UnresolvedCandidates').Count) { Add-Line ('  Not tested (name does not resolve): {0}' -f ((Get-Val $rdp 'UnresolvedCandidates') -join ', ')) }
$hda = Get-Val $rdp 'HostedDesktopApp'
if ($hda -is [System.Collections.IDictionary]) {
    if ($hda['Found']) {
        Add-Line ('  Hosted-desktop app: {0}' -f ((@($hda['Executables']) | ForEach-Object { '{0} {1}' -f [IO.Path]::GetFileName($_.Path), $_.Version }) -join '; '))
        if (@($hda['Hosts']).Count) { Add-Line ('  Hosts named in its files: {0}' -f (@($hda['Hosts']) -join ', ')) }
    } else { Add-Line '  Hosted-desktop app: not found on this PC (no app matching the hosted desktop profile for this user)' }
}
Add-Line ''
Add-Line 'MACHINE'
Add-Line ('  {0} {1}  S/N {2}  {3}  ~{4} yrs (from {5})' -f (Get-Val $m 'Manufacturer'), (Get-Val $m 'Model'), (Get-Val $m 'SerialNumber'), (Get-Val $m 'FormFactor'), (Get-Val $m 'ApproxAgeYears'), (Get-Val $m 'AgeSource'))
Add-Line ('  {0}  {1} GB RAM  {2}' -f (Get-Val $m 'Cpu'), (Get-Val $m 'RamGB'), ((@(Get-Val $m 'Disks') | ForEach-Object { "$($_.SizeGB)GB $($_.MediaType)" }) -join ', '))
$tpmShow = Get-Val (Get-Val $m 'Tpm') 'TPM Version'
if (-not $tpmShow -and "$(Get-Val (Get-Val $m 'Tpm') 'TPM Present')" -match '^(False|No)') { $tpmShow = 'none' }
Add-Line ('  {0} {1} (build {2}.{3})  TPM {4}  SecureBoot {5}' -f (Get-Val $m 'OsCaption'), (Get-Val $m 'OsDisplayVersion'), (Get-Val $m 'OsBuild'), (Get-Val $m 'OsUbr'), $tpmShow, (Get-Val $m 'SecureBootRegistry'))
$id = $Result['Identity']
Add-Line ('  Join: {0}  tenant {1}  Intune {2}  user local admin {3}' -f (Get-Val $id 'JoinType'), (Get-Val (Get-Val $id 'Dsregcmd') 'TenantName'), (Get-Val $id 'IntuneEnrolled'), (Get-Val $id 'UserIsLocalAdmin'))
$swr = $Result['Software']
Add-Line ('  RMM: {0}' -f ((@(Get-Val (Get-Val $swr 'Tagged') 'RMM')) -join ', '))
$secList = @(Get-Val (Get-Val $swr 'Tagged') 'Security') + @(Get-Val $swr 'AntiVirus' | ForEach-Object { $_.Name })
Add-Line ('  Security: {0}' -f ((@($secList | Where-Object { $_ } | Sort-Object -Unique)) -join ', '))
Add-Line ('  VPN clients: {0}' -f ((@(Get-Val (Get-Val $swr 'Tagged') 'VPN')) -join ', '))
$pt = $Result['Patching']
if ($pt -is [System.Collections.IDictionary]) {
    $src = if ($pt['UseWsus']) { "WSUS $($pt['WsusServer'])" } elseif ($null -ne $pt['WufbDeferQualityDays']) { "WUfB policy (quality defer $($pt['WufbDeferQualityDays']) d)" } else { 'Windows Update' }
    Add-Line ('  Updates: last OS update {0} ({1} days ago, {2}, from {3}) via {4}; pending reboot {5}{6}' -f $pt['LastUpdateInstalled'], $pt['DaysSinceLastUpdate'], $pt['LastUpdateTitle'], $pt['LastUpdateSource'], $src, $pt['PendingReboot'], $(if ($pt['PendingReboot']) { " ($($pt['PendingRebootReasons'] -join ', '))" } else { '' }))
    $o365 = $pt['M365']
    if ($o365) { Add-Line ('  Microsoft 365 Apps: {0} {1}, {2} channel{3}' -f $o365['Version'], $o365['Platform'], $(if ($o365['Channel']) { $o365['Channel'] } else { 'unknown' }), $(if ($o365['SharedActivation']) { ', shared computer activation' } else { '' })) }
    else { Add-Line '  Microsoft 365 Apps: not installed (Click-to-Run)' }
}
$clk = Get-Val $Result['Egress'] 'ClockOffsetSec'
if ($null -ne $clk) { Add-Line ('  Clock offset vs Cloudflare: {0} s' -f $clk) }
$adm = $Result['Admin']
Add-Line ''
Add-Line 'ADMIN CHECKS'
if (-not $script:AdminActive) { Add-Line '  Not run (admin tier off)' }
elseif ($adm -is [System.Collections.IDictionary]) {
    $tp = $adm['Tpm']
    if ($tp -is [System.Collections.IDictionary]) { Add-Line ('  TPM: present {0}, ready {1}, spec {2}, maker {3}' -f $tp['Present'], $tp['Ready'], $tp['SpecVersion'], "$($tp['ManufacturerId'])".Trim()) } else { Add-Line "  TPM: $tp" }
    Add-Line ('  Secure Boot (confirmed): {0}' -f $adm['SecureBoot'])
    foreach ($b in @($adm['BitLocker'])) { if ($b -and $b.Mount) { Add-Line ('  BitLocker {0}: {1}, protection {2}, {3}, protectors {4}' -f $b.Mount, $b.Status, $b.Protection, $b.Method, ($b.Protectors -join '+')) } elseif ($b) { Add-Line "  BitLocker: $b" } }
    foreach ($d in @($adm['DiskReliability'])) {
        if (-not $d -or -not $d.Disk) { continue }
        # NVMe drives often leave some counters empty; only print what the drive reports.
        $parts = @()
        if ($null -ne $d.WearPct) { $parts += "wear $($d.WearPct)%" }
        if ($d.TemperatureC) { $parts += "temp $($d.TemperatureC) C" }
        if ($d.PowerOnHours) { $parts += "power-on $($d.PowerOnHours) h" }
        if ($null -ne $d.ReadErrorsTotal -and "$($d.ReadErrorsTotal)" -ne '') { $parts += "read errors $($d.ReadErrorsTotal)" }
        Add-Line ('  Disk {0}: {1}' -f $d.Disk, $(if ($parts.Count) { $parts -join ', ' } else { 'no health counters reported' }))
    }
    $lg = $adm['InteractiveLogons']
    if ($lg -is [string]) { Add-Line "  Sign-ins: $lg" }
    else { Add-Line ('  Sign-ins ({0} days): {1}' -f $LookbackDays, ((@($lg) | Where-Object { $_ } | ForEach-Object { '{0} x{1} [{2}] last {3}' -f $_.User, $_.Count, $_.Types, $_.Last }) -join '; ')) }
    if ($adm['WlanReport'] -eq 'wlanreport.html') { Add-Line '  Wi-Fi report: wlanreport.html (in the zip)' }
}
$sh = $Result['Session']
if ($sh -is [System.Collections.IDictionary]) {
    Add-Line ''
    Add-Line 'SESSION HEALTH (this PC)'
    if ($null -ne (Get-Val $sh 'ClientCrashes')) { Add-Line ('  Remote desktop client, last {0} days: {1} crash(es), {2} hang(s){3}' -f $LookbackDays, $sh['ClientCrashes'], $sh['ClientHangs'], $(if (@($sh['ClientCrashByApp']).Count) { ': ' + (@($sh['ClientCrashByApp']) -join ', ') } else { '' })) }
    $udpPolS = Get-Val $sh 'UdpPolicy'
    if ($udpPolS -is [System.Collections.IDictionary]) { Add-Line ('  RDP UDP on this client: {0}' -f $(if ($udpPolS['UdpDisabled']) { "turned off ($($udpPolS['Source']))" } else { 'not turned off' })) }
    $dpS = Get-Val $sh 'Displays'
    if ($dpS -is [System.Collections.IDictionary] -and @($dpS['Sizes']).Count) { Add-Line ('  Displays: {0} ({1} megapixels)' -f (@($dpS['Sizes']) -join ' + '), $dpS['TotalMegapixels']) }
    $ldS = Get-Val $sh 'Load'
    if ($ldS -is [System.Collections.IDictionary]) {
        Add-Line ('  CPU {0}% average, memory {1}% of {2} GB in use' -f $ldS['CpuAvgPct'], $ldS['MemoryUsedPct'], [math]::Round($ldS['MemoryTotalMB'] / 1024, 1))
        if (@($ldS['TopByMemory']).Count) { Add-Line ('  Largest programs in memory: {0}' -f (@($ldS['TopByMemory']) -join '; ')) }
    }
    $apS = Get-Val $sh 'AdapterPower'
    if ($apS -is [System.Collections.IDictionary]) { Add-Line ('  Adapter power saving on {0}: {1}' -f $apS['Adapter'], $apS['AllowTurnOff']) }
}
Add-Line ''
Add-Line 'PERIPHERALS'
$pr = $Result['Peripherals']
foreach ($p in @(Get-Val $pr 'Printers' | Where-Object { -not $_.IsVirtual })) { Add-Line ('  Printer: {0} [{1}{2}] driver {3}{4}' -f $p.Name, $p.PortType, $(if ($p.HostAddress) { " $($p.HostAddress)" } else { '' }), $p.Driver, $(if ($p.IsDefault) { ' (default)' } else { '' })) }
Add-Line ('  Monitors: {0}  {1}' -f (Get-Val $pr 'MonitorCount'), ((@(Get-Val $pr 'Monitors') | ForEach-Object { "$($_.Manufacturer) $($_.Model) $($_.DiagonalInches)in" }) -join '; '))
$dbc = Get-Val $pr 'DevicesByClass'
if ($dbc -is [System.Collections.IDictionary]) { foreach ($k in $dbc.Keys) { if (@($dbc[$k]).Count) { Add-Line ('  {0}: {1}' -f $k, (@($dbc[$k]) -join '; ')) } } }
if (@(Get-Val $pr 'NotableDevices').Count) { Add-Line ('  Notable: {0}' -f ((Get-Val $pr 'NotableDevices') -join '; ')) }
if (@(Get-Val $pr 'Docks').Count) { Add-Line ('  Docks: {0}' -f ((Get-Val $pr 'Docks') -join '; ')) }
$sweep = $Result['SubnetSweep']
if ($sweep) {
    Add-Line ''
    Add-Line 'LOCAL NETWORK (subnet sweep)'
    if (Get-Val $sweep 'Subnet') {
        Add-Line ('  {0}: {1} devices seen, {2} answered ping' -f $sweep['Subnet'], $sweep['ArpEntries'], $sweep['PingResponders'])
        if ($sweep['Note']) { Add-Line "  $($sweep['Note'])" }
        if (@($sweep['RoleSummary']).Count) { Add-Line ('  By type: {0}' -f (@($sweep['RoleSummary']) -join '; ')) }
        foreach ($dv in @($sweep['Devices'] | Where-Object { $_ -and ($_.Name -or $_.Role) } | Select-Object -First 60)) {
            Add-Line ('  {0,-15} {1}' -f $dv.IP, ((@($dv.Name, $dv.Role, $(if (@($dv.OpenPorts).Count) { 'ports ' + (@($dv.OpenPorts) -join ',') }), $dv.Vendor) | Where-Object { $_ }) -join ' | '))
        }
        Add-Line ('  Vendors: {0}' -f ((@($sweep['VendorSummary'])) -join '; '))
    } else { Add-Line "  $(Get-Val $sweep 'Status')" }
}
$srvS = $Result['Servers']
if ($srvS -is [System.Collections.IDictionary] -and $srvS.Contains('Servers')) {
    Add-Line ''
    Add-Line 'SERVERS THIS PC USES'
    if (@($srvS['Servers']).Count -eq 0) { Add-Line '  none (no mapped drives, shared printers or domain)' }
    foreach ($sv in @($srvS['Servers'])) { if ($sv) { Add-Line ('  {0} -> {1} [{2}]  {3}' -f $sv.Name, $(if (@($sv.IPs).Count) { @($sv.IPs) -join ',' } else { 'no address' }), $sv.Location, (@($sv.Sources) -join '; ')) } }
    $dcS = $srvS['DomainController']
    if ($dcS -is [System.Collections.IDictionary]) { Add-Line ('  Domain {0}: controller {1} {2}, AD site {3}{4}' -f $dcS['Domain'], $dcS['Name'], $dcS['Address'], $dcS['ClientSite'], $(if ($dcS['Error']) { "  ($($dcS['Error']))" } else { '' })) }
}
$tlsS = $Result['Tls']
if ($tlsS -is [System.Collections.IDictionary] -and $tlsS.Contains('Checks')) {
    Add-Line ''
    Add-Line ('HTTPS CERTIFICATES (inspection suspected: {0})' -f $tlsS['InspectionSuspected'])
    foreach ($tc in @($tlsS['Checks'])) {
        if (-not $tc) { continue }
        if ($tc.Error) { Add-Line ('  {0}:{1}  no TLS answer: {2}' -f $tc.Host, $tc.Port, $tc.Error) }
        else { Add-Line ('  {0}:{1}  issued by {2}  for {3}  ({4}, check: {5})' -f $tc.Host, $tc.Port, $tc.Issuer, $tc.Subject, $tc.Protocol, $tc.PolicyErrors) }
    }
}
$fwp = $Result['FirewallPorts']
if ($fwp -is [System.Collections.IDictionary] -and $fwp.Contains('Ports')) {
    Add-Line ''
    Add-Line 'GATEWAY ADMIN PORTS'
    $openP = @($fwp['Ports'] | Where-Object { $_.Open })
    if ($openP.Count -eq 0) { Add-Line '  4443/8443/10443/22 all closed' }
    foreach ($p in $openP) { Add-Line ('  tcp/{0} open  {1}' -f $p.Port, ((@($p.Title, $p.Server, $p.CertSubject, $p.Banner) | Where-Object { $_ }) -join ' | ')) }
    if (@($fwp['VendorHints']).Count) { Add-Line ('  Vendor hints: {0}' -f ($fwp['VendorHints'] -join ', ')) }
}
$ssdp = $Result['Ssdp']
if ($ssdp -is [System.Collections.IDictionary] -and $ssdp.Contains('Devices')) {
    Add-Line ''
    Add-Line ('UPNP / SSDP DEVICES ({0})' -f $ssdp['DeviceCount'])
    foreach ($d in @($ssdp['Devices'])) { if ($d) { Add-Line ('  {0,-15} {1}' -f $d.IP, ((@($d.Manufacturer, $d.Model, $d.ModelNumber, $d.FriendlyName, $d.DeviceType) | Where-Object { $_ } | Select-Object -Unique) -join ' | ')) } }
}
$pp = @($Result['PrinterProbe'])
if ($pp.Count -and $pp[0] -and $pp[0].IP) {
    Add-Line ''
    Add-Line 'NETWORK PRINTER WEB PAGES'
    foreach ($p in $pp) { if ($p) { Add-Line ('  {0,-15} {1}' -f $p.IP, $(if (-not $p.Reachable) { 'not reachable from here' } else { (@($p.Title, $p.Server) | Where-Object { $_ }) -join ' | ' })) } }
}
$lldp = $Result['Lldp']
if ($lldp) {
    Add-Line ''
    Add-Line 'SWITCH (LLDP/CDP)'
    foreach ($nb in @(Get-Val $lldp 'Neighbors')) {
        if (-not $nb) { continue }
        Add-Line ('  {0}: {1}' -f $nb.Protocol, $(if ($nb.Model) { $nb.Model } else { 'model not advertised' }))
        $bits = @("name $($nb.SystemName)", "this PC on port $($nb.Port)")
        if ($nb.LinkMode) { $bits += "link $($nb.LinkMode)" }
        if ($nb.Vlan) { $bits += "VLAN $($nb.Vlan)" }
        if ($nb.MgmtIP) { $bits += "management $($nb.MgmtIP)" }
        Add-Line ('    ' + ($bits -join ', '))
        if ($nb.SystemDescription -and $nb.SystemDescription -ne $nb.Model) { Add-Line "    $($nb.SystemDescription)" }
    }
    if (Get-Val $lldp 'Note') { Add-Line "  $($lldp['Note'])" }
}
Add-Line ''
Add-Line 'FLAGS'
if ($script:Flags.Count -eq 0) { Add-Line '  none' }
foreach ($f in ($script:Flags | Sort-Object @{ Expression = { @{ High = 0; Medium = 1; Low = 2 }[$_.Severity] } })) { Add-Line ('  [{0}] {1}: {2}' -f $f.Severity, $f.Category, $f.Message) }
if ($script:Errors.Count) {
    Add-Line ''
    Add-Line 'COLLECTOR ERRORS (see errors.log)'
    foreach ($e in $script:Errors) { Add-Line ('  {0}: {1}' -f $e.Collector, $e.Error) }
}
$wifiFix = Get-Val $Result['Wireless'] 'Fix'
if ($wifiFix) { Add-Line ''; Add-Line "WI-FI FIX: $wifiFix" }
} catch {
    Add-Line ''
    Add-Line "SUMMARY INCOMPLETE: $($_.Exception.Message) (the data in assessment.json is not affected)"
}

# Safety net: never leave a packet capture running.
if ($script:PktmonStarted) {
    try { Invoke-Native 'pktmon.exe' 'stop' 60 | Out-Null; Invoke-Native 'pktmon.exe' 'filter remove' 15 | Out-Null } catch { }
}

Write-Step 'Checking the collected data'
$checks = @()
try {
    $parsed = [IO.File]::ReadAllText((Join-Path $OutDir 'assessment.json')) | ConvertFrom-Json
    $checks = @(Test-AssessmentData $parsed $OutDir)
} catch {
    $checks = @([pscustomobject]@{ Check = 'assessment.json'; Status = 'FAIL'; Detail = "could not be read back: $($_.Exception.Message)" })
}
$overall = if (@($checks | Where-Object Status -eq 'FAIL').Count) { 'FAIL' } elseif (@($checks | Where-Object Status -eq 'WARN').Count) { 'WARN' } else { 'PASS' }
$Result['Validation'] = [ordered]@{ Overall = $overall; CheckedAt = Format-Date (Get-Date); Retried = $script:Retried; Checks = $checks }
$Result['Meta']['RunSeconds'] = [int]((Get-Date) - $RunStart).TotalSeconds
$jsonSaved = Save-Json 'complete'

# Short result block: top of summary.txt, validation.txt, and the only thing printed at the end.
$B = New-Object Collections.Generic.List[string]
$B.Add('=' * 72)
$B.Add(('DATA CHECK: {0}    {1} / {2}    ({3} s)' -f $overall, $SiteName, $env:COMPUTERNAME, $Result['Meta']['RunSeconds']))
$B.Add('=' * 72)
$keyChecks = @('Connection', 'Bandwidth download', 'Bandwidth upload', 'Internet loss / latency', 'Traceroute 1.1.1.1', 'Remote desktop loss / latency')
foreach ($c in $checks) {
    if ($c.Status -eq 'OK' -and $keyChecks -notcontains $c.Check) { continue }
    $B.Add(('  {0,-5} {1,-30} {2}' -f $c.Status, $c.Check, $c.Detail))
}
if ($script:Retried.Count) { $B.Add(('  Retried during this run: {0}' -f ($script:Retried -join ', '))) }
$failed = @($checks | Where-Object Status -eq 'FAIL' | ForEach-Object { $_.Check })
if ($failed.Count) { $B.Add(''); $B.Add(('  ACTION: run it again here (from another port if you can). Missing: {0}' -f ($failed -join ', '))) }
elseif ($overall -eq 'WARN') { $B.Add(''); $B.Add('  Data is usable. The WARN lines are gaps; run again only if one of them matters for this site.') }

# Findings block: what the evidence adds up to, then a short list of what named itself.
$FB = New-Object Collections.Generic.List[string]
try {
    if (@($script:Findings).Count) {
        $FB.Add('')
        $FB.Add('=' * 72)
        $FB.Add('FINDINGS   Confirmed = measured directly, Likely = several signs agree, Possible = one sign')
        $FB.Add('=' * 72)
        $lastArea = $null
        foreach ($f in @($script:Findings)) {
            if ("$($f.Area)" -ne $lastArea) { $FB.Add(''); $FB.Add("$($f.Area)".ToUpper()); $lastArea = "$($f.Area)" }
            $FB.Add(('  [{0}] {1}' -f $f.Confidence, $f.Finding))
            foreach ($e in @($f.Evidence | Select-Object -First 4)) { $FB.Add("        - $e") }
        }
    }
    $disco = @()
    $ks = @(Get-Val $Result['Identify'] 'KindSummary' | Where-Object { $_ }); if ($ks.Count) { $disco += "  Devices by kind:   $($ks -join '; ')" }
    $ms = @(Get-Val $Result['Identify'] 'ModelSummary' | Where-Object { $_ } | Select-Object -First 25); if ($ms.Count) { $disco += "  Models read:       $($ms -join '; ')" }
    $vs = @(Get-Val $Result['VendorDiscovery'] 'ModelSummary' | Where-Object { $_ }); if ($vs.Count) { $disco += "  Vendor discovery:  $($vs -join '; ')" }
    $rn = @(Get-Val $Result['DnsDiscovery'] 'SubnetSummary' | Where-Object { $_ } | ForEach-Object { '{0} {1} names' -f $_.Subnet, $_.Names }); if ($rn.Count) { $disco += "  Reverse DNS names: $($rn -join '; ')" }
    $cs = Get-Val $Result['Capture'] 'Frames'; if ($null -ne $cs) { $disco += ('  Wire capture:      {0} frames in {1} s, {2} broadcast/s, {3} LLDP, {4} CDP, {5} spanning tree, {6} DHCP server(s)' -f $cs, $Result['Capture']['Seconds'], $Result['Capture']['BroadcastPerSecond'], @($Result['Capture']['Lldp']).Count, @($Result['Capture']['Cdp']).Count, @($Result['Capture']['SpanningTree']).Count, @($Result['Capture']['DhcpServers']).Count) }
    $rss = @(Get-Val $Result['RemoteSweep'] 'Subnets' | Where-Object { $_ }); if ($rss.Count) { $disco += "  Other subnets:     $((@($rss | ForEach-Object { '{0} {1} devices' -f $_.Subnet, $_.Devices })) -join '; ')" }
    $wo = @(Get-Val $Result['WindowsHosts'] 'OsSummary' | Where-Object { $_ }); if ($wo.Count) { $disco += "  Windows versions:  $($wo -join '; ')" }
    $sn = Get-Val $Result['Snmp'] 'Answered'; if ($null -ne $sn) { $disco += ('  SNMP:              {0} of {1} devices answered community {2}' -f $sn, $Result['Snmp']['Asked'], $Result['Snmp']['Community']) }
    $rtn = Get-Val $Result['Snmp'] 'Routers'; if ($rtn) { $disco += ('  Routers (SNMP):    {0}, {1} ARP entries, WAN {2}' -f $rtn, $Result['Snmp']['ArpEntries'], $(if (@($Result['Snmp']['WanAddresses']).Count) { @($Result['Snmp']['WanAddresses']) -join ', ' } else { 'not seen' })) }
    $upn = Get-Val $Result['Snmp'] 'Ups'; if ($upn) { $disco += ('  UPS (SNMP):        {0}' -f $upn) }
    $pqa = Get-Val $Result['PrinterQuery'] 'Answered'; if ($null -ne $pqa) { $disco += ('  Printers (IPP):    {0} of {1} described themselves' -f $pqa, $Result['PrinterQuery']['Asked']) }
    $lcs = @(Get-Val $Result['LeadChecks'] 'Checks' | Where-Object { $_ }); if ($lcs.Count) { $disco += "  Follow-up checks: $((@($lcs | Select-Object -First 6 | ForEach-Object { '{0} {1}' -f $_.IP, $_.What })) -join '; ')" }
    $cqa = Get-Val $Result['CameraQuery'] 'Answered'; if ($null -ne $cqa) { $disco += ('  Cameras (RTSP):    {0} of {1} answered' -f $cqa, $Result['CameraQuery']['Asked']) }
    if ($disco.Count) { $FB.Add(''); $FB.Add('DISCOVERY'); foreach ($ln in $disco) { $FB.Add($ln) } }
} catch { $script:Errors += [pscustomobject]@{ Collector = 'Findings text'; Error = $_.Exception.Message } }

try { [IO.File]::WriteAllLines((Join-Path $OutDir 'summary.txt'), [string[]](@($B.ToArray()) + @($FB.ToArray()) + @('') + @($L.ToArray()))) } catch { Write-Host "summary.txt write failed: $($_.Exception.Message)" -ForegroundColor Red }
try {
    $vt = @($B.ToArray()) + @('', 'ALL CHECKS') + @($checks | ForEach-Object { '  {0,-5} {1,-27} {2}' -f $_.Status, $_.Check, $_.Detail })
    [IO.File]::WriteAllLines((Join-Path $OutDir 'validation.txt'), [string[]]$vt)
} catch { }
if ($script:Errors.Count) { try { $script:Errors | Format-List | Out-String | Set-Content -LiteralPath (Join-Path $OutDir 'errors.log') } catch { } }

if ($script:Transcript) { try { Stop-Transcript | Out-Null } catch { } }
$zip = "$OutDir.zip"
$zipMade = $false; $zipErr = $null
try {
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zip -Force
    $zipMade = $true
} catch {
    $zipErr = $_.Exception.Message
    if ($script:FullLanguage) {
        try {
            if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::CreateFromDirectory($OutDir, $zip)
            $zipMade = $true
        } catch { $zipErr = "$zipErr; fallback: $($_.Exception.Message)" }
    }
}
$required = @('assessment.json', 'summary.txt', 'validation.txt')
if (@($checks | Where-Object { $_.Check -eq 'Traceroute 1.1.1.1' -and $_.Status -eq 'OK' }).Count) { $required += 'traceroute_1.1.1.1.txt' }
$zipCheck = if ($zipMade) { Test-ZipOutput $zip $required } else { [pscustomobject]@{ Ok = $false; Problems = @("zip not created: $zipErr"); SizeKB = 0 } }

$color = switch ($overall) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
Write-Host ''
foreach ($line in $B) { Write-Host $line -ForegroundColor $color }
foreach ($line in $FB) {
    $fc = if ($line -match '^\s+\[Confirmed\]') { 'White' } elseif ($line -match '^\s+\[Likely\]') { 'Cyan' } elseif ($line -match '^\s+\[Possible\]') { 'Gray' } elseif ($line -match '^\s+- ') { 'DarkGray' } else { 'Yellow' }
    Write-Host $line -ForegroundColor $fc
}
Write-Host ''
if ($zipCheck.Ok -and $jsonSaved) {
    Write-Host ("Saved and verified: {0} ({1} KB)" -f $zip, $zipCheck.SizeKB) -ForegroundColor Green
} else {
    Write-Host 'OUTPUT PROBLEM: the zip did not verify. Retrieve the whole folder instead:' -ForegroundColor Red
    Write-Host "  $OutDir" -ForegroundColor Red
    foreach ($p in @($zipCheck.Problems)) { Write-Host "  - $p" -ForegroundColor Red }
    if (-not $jsonSaved) { Write-Host '  - assessment.json could not be written' -ForegroundColor Red }
}
if ($CopySummaryToClipboard) {
    try { Set-Clipboard -Value ((@($B.ToArray()) + @($FB.ToArray()) + @('') + @($L.ToArray())) -join "`r`n") } catch { }
}
if ($OpenFolderWhenDone) {
    try {
        if ($zipMade -and (Test-Path -LiteralPath $zip)) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"{0}"' -f $zip) }
        else { Invoke-Item -LiteralPath $OutputRoot }
    } catch { }
}

# END OF COLLECTOR SCRIPT (keep this as the last line: the paste check at the top looks for it)
