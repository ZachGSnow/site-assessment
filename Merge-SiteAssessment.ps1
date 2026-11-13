<#
.SYNOPSIS
    Merges Collect-SiteAssessment zips/folders into CSVs and one HTML report.

.DESCRIPTION
    Windows PowerShell 5.1 compatible. Point -Path at a folder that holds the
    *.zip files (and/or extracted run folders). Output goes to -OutDir
    (default: <Path>\_merged). Re-running overwrites the previous merge.
    -Path can also be one zip (only that run is merged; output goes to
    _merged next to the zip) or one extracted run folder.

    CSVs:   Sites, Endpoints, Printers, Peripherals, NetworkGear, Flags, Findings, Devices,
            Software, Traceroutes, PingSeries, RdpTargets, Subnets, IpOwners
    Report: Report.html (self-contained; expand/collapse, search, sortable
            tables, dark mode, prints fully expanded)

    The latest run is kept per site + machine + connection type, so one laptop
    tested wired and on Wi-Fi at the same site counts as two endpoints.

.PARAMETER NoEnrich
    Skips the enrichment pass, so the merge makes no network requests at all.
    Without it the merge looks up, from the PC it runs on: the maker of each MAC
    address that was not identified on site (IEEE registry, downloaded once), and
    for each public IP address in the runs the network that announces it (Team
    Cymru, over DNS), who the block is registered to (the registries' RDAP whois)
    and its reverse DNS name. Only public IP addresses are sent. It also asks
    Shodan's InternetDB what is visible from the internet on each site's own public
    address (open ports, known vulnerabilities).

.PARAMETER CacheDir
    Where lookups are kept between merges (default: %LOCALAPPDATA%\SiteAssessment\cache).

.PARAMETER TestDevice
    Host names or serial numbers of machines that are not client PCs (a laptop
    brought in to test with). A machine whose serial number appears at two or more
    sites is treated this way automatically. For a test device the report keeps the
    network results (bandwidth, traceroute, latency, sweep) and leaves out the
    machine's own hardware, software, printers, history and unrelated RDP targets.

.PARAMETER NoTestDeviceDetection
    Turns the automatic detection off (-TestDevice still applies).

.PARAMETER TargetHint
    Optional regex for extra RDP targets that belong to the hosted desktop. Normally not needed:
    each run records its hosted desktop profile, and targets matching that profile are used.
    Only matching targets are kept for a test device.

.PARAMETER SiteMap
    Renames sites at merge time (case-insensitive), e.g. to fix a typo without re-running:
    -SiteMap @{ 'main ofice' = 'Main office'; 'test-admin-wired' = 'Main office' }

.EXAMPLE
    .\Merge-SiteAssessment.ps1 -Path C:\Assessments\Client -ClientName 'Client Name'
#>
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$OutDir,
    [string]$ClientName = 'Site Assessment',
    [hashtable]$SiteMap = @{},
    [switch]$NoEnrich,
    [string]$CacheDir,
    [string[]]$TestDevice = @(),
    [switch]$NoTestDeviceDetection,
    [string]$TargetHint = ''
)

$ErrorActionPreference = 'Stop'
# -Path can be the folder that holds the zips / run folders, one zip, or one extracted run folder.
if (-not (Test-Path -LiteralPath $Path)) { throw "Path not found: $Path" }
$Path = (Resolve-Path -LiteralPath $Path).ProviderPath
$singleZip = $null
if (Test-Path -LiteralPath $Path -PathType Leaf) {
    $singleZip = Get-Item -LiteralPath $Path
    if ($singleZip.Extension -ne '.zip') { throw "-Path must be a folder or a .zip from the collector, not $($singleZip.Name)" }
    $Path = $singleZip.DirectoryName
}
if (-not $OutDir) { $OutDir = Join-Path $Path '_merged' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$work = Join-Path $env:TEMP ('sa_merge_{0}' -f (Get-Random))
New-Item -ItemType Directory -Path $work -Force | Out-Null

# ---------------------------------------------------------------------
# Small helpers (names chosen to avoid built-in aliases such as h = Get-History)
# ---------------------------------------------------------------------
function V { param($Obj, [string]$Name) if ($null -eq $Obj -or $Obj -is [string]) { return $null } $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value } return $null }
function J { param($Value, [string]$Sep = '; ') if ($null -eq $Value) { return '' } return (@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join $Sep }
function Enc { param($Text) return [Net.WebUtility]::HtmlEncode("$Text") }
function Median { param($Values) $s = @($Values | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [double]$_ } | Sort-Object); if ($s.Count -eq 0) { return $null } return $s[[int][math]::Floor($s.Count / 2)] }
function MaxOf { param($Values) $s = @($Values | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [double]$_ }); if ($s.Count -eq 0) { return $null } return ($s | Measure-Object -Maximum).Maximum }
function SiteKey { param([string]$Name) return (("$Name".Trim() -replace '\s+', ' ').ToLowerInvariant()) }
function SevRank { param([string]$Sev) switch ($Sev) { 'High' { 0 } 'Medium' { 1 } default { 2 } } }

# IPv4 math for the Known subnets section ([int64] so the top bit never goes negative).
$Mask32 = [int64]4294967295
function Test-IPv4Text { param([string]$Ip) return ("$Ip" -match '^\d{1,3}(\.\d{1,3}){3}$') }
function ConvertTo-IpInt { param([string]$Ip) $o = $Ip.Split('.'); return ([int64]$o[0] -shl 24) + ([int64]$o[1] -shl 16) + ([int64]$o[2] -shl 8) + [int64]$o[3] }
function ConvertFrom-IpInt { param([int64]$N) return '{0}.{1}.{2}.{3}' -f (($N -shr 24) -band 255), (($N -shr 16) -band 255), (($N -shr 8) -band 255), ($N -band 255) }
function Get-PrefixFromMask {
    param([string]$Mask)
    $n = ConvertTo-IpInt $Mask; $c = 0
    for ($i = 31; $i -ge 0; $i--) { if (($n -shr $i) -band 1) { $c++ } else { break } }
    return $c
}
function Get-NetworkCidr {
    param([string]$Ip, [int]$Prefix)
    $mask = if ($Prefix -le 0) { [int64]0 } else { (($Mask32 -shl (32 - $Prefix)) -band $Mask32) }
    return '{0}/{1}' -f (ConvertFrom-IpInt ((ConvertTo-IpInt $Ip) -band $mask)), $Prefix
}
function Test-InCidr { param([string]$Ip, [string]$Cidr) $p = $Cidr.Split('/'); return ((Get-NetworkCidr $Ip ([int]$p[1])) -eq (Get-NetworkCidr $p[0] ([int]$p[1]))) }
function Test-PrivateIp {
    param([string]$Ip)
    if (-not (Test-IPv4Text $Ip)) { return $false }
    $o = $Ip.Split('.') | ForEach-Object { [int]$_ }
    return ($o[0] -eq 10 -or ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) -or ($o[0] -eq 192 -and $o[1] -eq 168))
}

# ---------------------------------------------------------------------
# Load every assessment.json (from zips and folders)
# ---------------------------------------------------------------------
$jsonFiles = @()
$zipNames = @()
$zips = if ($singleZip) { @($singleZip) } else { @(Get-ChildItem -LiteralPath $Path -Filter *.zip -File) }
foreach ($z in $zips) {
    $zipNames += $z.BaseName
    $dest = Join-Path $work $z.BaseName
    try { Expand-Archive -LiteralPath $z.FullName -DestinationPath $dest -Force } catch { Write-Warning "Could not extract $($z.Name): $($_.Exception.Message)"; continue }
    $jsonFiles += @(Get-ChildItem -LiteralPath $dest -Filter assessment.json -Recurse -File)
}
if (-not $singleZip) {
    foreach ($d in @(Get-ChildItem -LiteralPath $Path -Directory | Where-Object { $_.Name -ne '_merged' -and $zipNames -notcontains $_.Name })) {
        $jsonFiles += @(Get-ChildItem -LiteralPath $d.FullName -Filter assessment.json -Recurse -File)
    }
    # -Path is itself one extracted run folder
    $jsonFiles += @(Get-ChildItem -LiteralPath $Path -Filter assessment.json -File)
}
if ($jsonFiles.Count -eq 0) { throw "No assessment.json found under $Path" }

$runs = @()
foreach ($f in $jsonFiles) {
    try {
        $raw = [IO.File]::ReadAllText($f.FullName)
        $o = $raw | ConvertFrom-Json
        $sumPath = Join-Path $f.DirectoryName 'summary.txt'
        $o | Add-Member -NotePropertyName _Raw -NotePropertyValue $raw
        $o | Add-Member -NotePropertyName _Summary -NotePropertyValue $(if (Test-Path -LiteralPath $sumPath) { [IO.File]::ReadAllText($sumPath) } else { $null })
        # -SiteMap renames happen before anything is grouped.
        $siteName = "$(V $o.Meta 'SiteName')".Trim()
        foreach ($k in $SiteMap.Keys) { if ((SiteKey $k) -eq (SiteKey $siteName)) { $siteName = "$($SiteMap[$k])".Trim(); break } }
        $o.Meta.SiteName = $siteName
        $o | Add-Member -NotePropertyName _SiteKey -NotePropertyValue (SiteKey $siteName)
        $o | Add-Member -NotePropertyName _Conn -NotePropertyValue "$(V $o.Network 'PhysicalClass')"
        $runs += $o
    } catch { Write-Warning "Skipping $($f.FullName): $($_.Exception.Message)" }
}
# Keep the latest run per site + machine + connection type. Site names match ignoring case and extra spaces.
$runs = @($runs | Group-Object { '{0}|{1}|{2}' -f $_._SiteKey, (V $_.Meta 'Hostname'), $_._Conn } | ForEach-Object { $_.Group | Sort-Object { V $_.Meta 'RunStart' } -Descending | Select-Object -First 1 })
# Label each run: the hostname, plus the connection when one machine was tested more than one way at a site.
$dupHosts = @{}
foreach ($g in ($runs | Group-Object { '{0}|{1}' -f $_._SiteKey, (V $_.Meta 'Hostname') })) { if ($g.Count -gt 1) { $dupHosts[$g.Name] = $true } }
foreach ($r in $runs) {
    $hn0 = V $r.Meta 'Hostname'
    $lbl = if ($dupHosts.ContainsKey("$($r._SiteKey)|$hn0")) { '{0} ({1})' -f $hn0, $r._Conn } else { $hn0 }
    $r | Add-Member -NotePropertyName _Label -NotePropertyValue $lbl
}
# Display name per site = the most common spelling used.
$siteDisplay = @{}
foreach ($g in ($runs | Group-Object _SiteKey)) {
    $siteDisplay[$g.Name] = ($g.Group | Group-Object { "$(V $_.Meta 'SiteName')".Trim() } | Sort-Object Count -Descending | Select-Object -First 1).Name
}
Write-Host ("Loaded {0} endpoint run(s) from {1} file(s)" -f $runs.Count, $jsonFiles.Count)

# Hosted desktop targets. Each run records the profile it used (name, host pattern, fixed targets).
# Strict = targets that match the profile (or -TargetHint). When a run has none, every remote desktop
# target it selected counts, so a plain RDP profile still gets a round trip.
function Get-HostHead { param([string]$T) return ((("$T".Trim().ToLower() -replace '^[a-z]+://', '') -split '/')[0] -replace ':\d+$', '') }
$script:HostedSet = @{}
$hostedNames = @()
foreach ($r in $runs) {
    $hd = V $r.Meta 'HostedDesktop'
    $pat = "$(V $hd 'HostPattern')"
    $fixed = @(@(V $hd 'Targets') | Where-Object { $_ } | ForEach-Object { Get-HostHead $_ })
    $sel = @(@(V $r.Rdp 'SelectedTargets') | Where-Object { $_ } | ForEach-Object { "$_".ToLower() })
    $strict = @($sel | Where-Object { ($fixed -contains $_) -or ($pat -and $_ -match $pat) -or ($TargetHint -and $_ -match $TargetHint) })
    $all = if ($strict.Count) { $strict } else { $sel }
    $r | Add-Member -NotePropertyName _HostedStrict -NotePropertyValue $strict -Force
    $r | Add-Member -NotePropertyName _Hosted -NotePropertyValue $all -Force
    foreach ($t in $all) { $script:HostedSet[$t] = $true }
    if (V $hd 'Name') { $hostedNames += "$(V $hd 'Name')" }
}
$HostedLabel = if ($hostedNames.Count) { ($hostedNames | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name } else { 'Remote desktop' }
function Test-Hosted { param($Target) return $script:HostedSet.ContainsKey("$Target".ToLower()) }


# ---------------------------------------------------------------------
# Per-endpoint rows and flat tables
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# Test devices: a laptop carried from site to site describes the network at each site, not the
# client's PCs. Its own hardware, software, printers, history and unrelated RDP targets are taken
# out here, before anything is counted, so they cannot colour a site's status or the fleet figures.
# A machine is a test device when its serial number shows up at two or more sites, or when it is
# named with -TestDevice.
# ---------------------------------------------------------------------
function Get-MachineKey {
    param($Run)
    $sn = "$(V $Run.Machine 'SerialNumber')".Trim()
    if ($sn -and $sn -notmatch '^(To be filled.*|Default string|System Serial Number|None|N/A|0+)$') { return "SN:$sn".ToUpperInvariant() }
    return "HN:$(V $Run.Meta 'Hostname')".ToUpperInvariant()
}

function Test-DeviceOnlyFlag {
    # True for findings about the machine itself; false for findings about the site's network.
    param([string]$Category, [string]$Message)
    if ($Category -in @('Lifecycle', 'Patching', 'Identity', 'Performance', 'Stability', 'Peripherals')) { return $true }
    if ($Category -eq 'Security') { return ($Message -notmatch '^HTTPS inspection') }
    if ($Category -eq 'RDP') { return ($Message -match 'disconnects in|UDP|crashed or hung') }
    if ($Category -eq 'Network') { return ($Message -match 'adapter errors|reset/link-down|power saving') }
    if ($Category -eq 'Wireless') { return ($Message -match 'details blocked') }
    return $false
}

function Clear-RunList {
    param($Obj, [string]$Name)
    if ($null -ne $Obj -and $Obj -isnot [string] -and $Obj.PSObject.Properties[$Name]) { $Obj.$Name = @() }
}

$testKeys = @{}
if (-not $NoTestDeviceDetection) {
    foreach ($g in ($runs | Group-Object { Get-MachineKey $_ })) {
        if (@($g.Group | ForEach-Object { $_._SiteKey } | Sort-Object -Unique).Count -ge 2) { $testKeys[$g.Name] = 'seen at {0} sites' -f @($g.Group | ForEach-Object { $_._SiteKey } | Sort-Object -Unique).Count }
    }
}
foreach ($td in @($TestDevice)) {
    if (-not $td) { continue }
    foreach ($r in $runs) {
        if ("$(V $r.Meta 'Hostname')" -eq "$td" -or "$(V $r.Machine 'SerialNumber')".Trim() -eq "$td") { $k = Get-MachineKey $r; if (-not $testKeys.ContainsKey($k)) { $testKeys[$k] = 'named with -TestDevice' } }
    }
}
$testNames = @{}
foreach ($r in $runs) {
    $k = Get-MachineKey $r
    $isTest = $testKeys.ContainsKey($k)
    $r | Add-Member -NotePropertyName _IsTest -NotePropertyValue $isTest -Force
    $r | Add-Member -NotePropertyName _DeviceFlags -NotePropertyValue @() -Force
    if (-not $isTest) { continue }
    $testNames["$(V $r.Meta 'Hostname')"] = $testKeys[$k]
    # Targets: keep the internet checks, the gateway and anything that is the hosted desktop; drop the rest
    # (they come from the laptop's own RDP history and have nothing to do with this site).
    $gwIp = "$(V $r.Network 'Gateway')"
    foreach ($listName in 'Traceroutes', 'PingSeries', 'TcpSeries') {
        if ($r.PSObject.Properties[$listName]) {
            $r.$listName = @(@($r.$listName) | Where-Object { $_ -and ("$($_.Target)" -in @('1.1.1.1', '8.8.8.8') -or ($gwIp -and "$($_.Target)" -eq $gwIp) -or (@($r._HostedStrict) -contains "$($_.Target)".ToLower())) })
        }
    }
    if ($r.PSObject.Properties['RdpPath']) { $r.RdpPath = @(@($r.RdpPath) | Where-Object { $_ -and (@($r._HostedStrict) -contains "$($_.Host)".ToLower()) }) }
    # The laptop's own printers, drives, servers and software
    Clear-RunList $r 'PrinterProbe'
    Clear-RunList (V $r 'Peripherals') 'Printers'
    Clear-RunList (V $r 'Peripherals') 'UserPrinterConnections'
    Clear-RunList (V $r 'Identity') 'MappedDrives'
    Clear-RunList (V $r 'Software') 'Apps'
    Clear-RunList (V $r 'Servers') 'Servers'
    # Findings: the ones about the laptop itself are set aside and not counted for the site
    $siteFl = @(); $devFl = @()
    foreach ($fl in @($r.Flags)) { if ($fl) { if (Test-DeviceOnlyFlag "$($fl.Category)" "$($fl.Message)") { $devFl += $fl } else { $siteFl += $fl } } }
    if ($r.PSObject.Properties['Flags']) { $r.Flags = $siteFl }
    $r._DeviceFlags = $devFl
}
foreach ($tn in ($testNames.Keys | Sort-Object)) { Write-Host ("Test device: {0} ({1}). Its own hardware, software, printers, history and unrelated RDP targets are left out; its network results are kept." -f $tn, $testNames[$tn]) -ForegroundColor Yellow }

$endpoints = @(); $printers = @(); $periph = @(); $gear = @(); $flags = @(); $deviceFlags = @()
$runFindings = @(); $devices = @()
$software = @(); $traceRows = @(); $pingRows = @(); $rdpRows = @()
foreach ($r in $runs) {
    $site = $siteDisplay[$r._SiteKey]; $hostName = $r._Label
    $m = $r.Machine; $n = $r.Network; $bw = $r.Bandwidth; $eg = $r.Egress; $w = V $r.Wireless 'Current'; $adm = $r.Admin; $pt = $r.Patching
    $inetPing = @($r.PingSeries) | Where-Object { $_ -and $_.Target -eq '1.1.1.1' } | Select-Object -First 1
    $gwPing = @($r.PingSeries) | Where-Object { $_ -and $_.Target -eq (V $n 'Gateway') } | Select-Object -First 1
    $inetTrace = @($r.Traceroutes) | Where-Object { $_ -and $_.Target -eq '1.1.1.1' } | Select-Object -First 1
    $rdpc = V $r.EventLogs 'RdpClient'
    $admTpm = V $adm 'Tpm'
    $tpm = if (V $admTpm 'SpecVersion') { "$(V $admTpm 'SpecVersion')".Split(',')[0].Trim() } else { V (V $m 'Tpm') 'TPM Version' }
    # No TPM at all reads as 'None' so it counts against TPM 2.0 (an empty value means it was not checked).
    $tpmPresent = if ($null -ne (V $admTpm 'Present')) { V $admTpm 'Present' } else { V (V $m 'Tpm') 'TPM Present' }
    if (-not $tpm -and "$tpmPresent" -match '^(False|No)') { $tpm = 'None' }
    $sb = V $adm 'SecureBoot'
    $secureBoot = if ($sb -is [bool]) { "$sb" } else { "$(V $m 'SecureBootRegistry') (registry)" }
    $osBl = @(V $adm 'BitLocker') | Where-Object { $_ -and (V $_ 'VolumeType') -eq 'OperatingSystem' } | Select-Object -First 1
    $bitlocker = if ($osBl) { 'Protection {0} ({1})' -f (V $osBl 'Protection'), (V $osBl 'Status') } else { V (V $r.Software 'BitLocker') 'Status' }
    $wear = MaxOf (@(V $adm 'DiskReliability') | ForEach-Object { V $_ 'WearPct' })
    $m365 = V $pt 'M365'
    $wev = V $r.Wireless 'Events'
    $highFlags = @($r.Flags | Where-Object { $_ -and $_.Severity -eq 'High' }).Count
    # Data check written by collector 1.3.0+; older runs have none.
    $val = V $r 'Validation'
    # A run cut off part-way (session lost, PC isolated) leaves assessment.json at the stage it reached.
    $stage = "$(V $r.Meta 'Stage')"
    $dataCheck = if (V $val 'Overall') { V $val 'Overall' }
                 elseif ($stage -like 'checkpoint*') { 'INCOMPLETE (stopped during active discovery; bandwidth and traceroutes kept)' }
                 elseif ($stage) { 'INCOMPLETE (stopped before the data check)' }
                 else { 'not checked (collector before 1.3.0)' }
    $tlsInfo = V $r 'Tls'
    $httpsInspection = if (V $tlsInfo 'InspectionSuspected') { J (@(V $tlsInfo 'Checks') | Where-Object { $_ -and $_.Inspected } | ForEach-Object { '{0}: {1}' -f $_.Host, $_.Issuer }) } elseif ($tlsInfo) { 'Not seen' } else { $null }
    $srvList = @(V (V $r 'Servers') 'Servers') | Where-Object { $_ }
    $dataIssues = J (@(V $val 'Checks') | Where-Object { $_ -and $_.Status -in @('FAIL', 'WARN') } | ForEach-Object { '{0} {1}: {2}' -f $_.Status, $_.Check, $_.Detail })
    # Hosted desktop round trip: TCP series first (gateways often drop ping), then ping.
    $avSeries = @(@($r.TcpSeries) + @($r.PingSeries) | Where-Object { $_ -and (@($r._Hosted) -contains "$($_.Target)".ToLower()) -and $_.Received -gt 0 }) | Select-Object -First 1
    $udpInfo = V $rdpc 'Udp'
    # Session health (collector 1.5.0+); display sizes are also in older runs.
    $sess = V $r 'Session'
    $sessLoad = V $sess 'Load'; $sessUdp = V $sess 'UdpPolicy'; $sessPower = V $sess 'AdapterPower'
    $screenSizes = @(@(V $r.Peripherals 'Screens') | Where-Object { $_ -and $_.Width } | ForEach-Object { '{0}x{1}' -f $_.Width, $_.Height })
    $crashBy = @(@(V $sess 'ClientCrashByApp') | Where-Object { $_ })
    $endpoints += [pscustomobject][ordered]@{
        Site = $site; Hostname = $hostName; Role = $(if ($r._IsTest) { 'Test laptop' } else { 'Client PC' }); User = V $r.Meta 'InventoriedUser'; RunStart = V $r.Meta 'RunStart'; Notes = V $r.Meta 'Notes'; AdminTier = V $r.Meta 'AdminTierActive'
        Connection = V $n 'PhysicalClass'; LinkMbps = V $n 'PhysicalLinkMbps'; Adapter = V $n 'PhysicalDescription'
        WifiSsid = V $w 'SSID'; WifiBand = V $w 'Band'; WifiChannel = V $w 'Channel'; WifiSignalPct = V $w 'SignalPct'; WifiRadio = V $w 'RadioType'; ApVendor = V $w 'ApVendor'; WifiRealDrops = $(if ("$(V $n 'PhysicalClass')" -eq 'Wi-Fi') { V $wev 'SiteSsidDrops' })
        PublicIP = V $eg 'PublicIPv4'; Carrier = V $eg 'Carrier'; EgressCity = V $eg 'EgressCity'; BehindCgnat = [bool]((V (V $inetTrace 'Analysis') 'CgnatHops') -gt 0)
        Verdict = V $r.Topology 'Verdict'; Confidence = V $r.Topology 'Confidence'
        DownMbps = V $bw 'DownloadMbps'; UpMbps = V $bw 'UploadMbps'; DownloadFailure = V $bw 'DownloadFailure'; UploadFailure = V $bw 'UploadFailure'
        DownProvider = $(if (V $bw 'DownloadProvider') { V $bw 'DownloadProvider' } elseif (V $bw 'DownloadOk') { 'Cloudflare' }); UpProvider = $(if (V $bw 'UploadProvider') { V $bw 'UploadProvider' } elseif (V $bw 'UploadOk') { 'Cloudflare' })
        IdleMs = V $bw 'IdleLatencyMs'; BufferbloatMs = V $bw 'BufferbloatMs'; BufferbloatGrade = V $bw 'BufferbloatGrade'
        InetLossPct = V $inetPing 'LossPct'; InetAvgMs = V $inetPing 'AvgMs'; InetPingSent = V $inetPing 'Sent'; InetJitterMs = V $inetPing 'JitterMs'; GwLossPct = V $gwPing 'LossPct'
        RdpUnexpectedDisconnects = V $rdpc 'UnexpectedDisconnects'; RdpNetworkDisconnects = V $rdpc 'NetworkDisconnects'; RdpUdp = V $udpInfo 'Status'
        HostedTarget = $(if ($avSeries) { '{0}{1}' -f $avSeries.Target, $(if (V $avSeries 'Port') { " tcp/$($avSeries.Port)" } else { ' (ping)' }) }); HostedAvgMs = V $avSeries 'AvgMs'; HostedLossPct = V $avSeries 'LossPct'; HostedJitterMs = V $avSeries 'JitterMs'
        DataCheck = $dataCheck; DataIssues = $dataIssues
        BandwidthStarted = V $bw 'StartedAt'; BandwidthFinished = V $bw 'FinishedAt'; HttpsInspection = $httpsInspection
        ServersUsed = J ($srvList | ForEach-Object { '{0} [{1}]' -f $_.Name, $_.Location })
        HostedDesktopApp = J (@(V (V $r.Rdp 'HostedDesktopApp') 'Executables') | ForEach-Object { if ($_) { '{0} {1}' -f (Split-Path $_.Path -Leaf), $_.Version } })
        HostedDesktopHosts = J (V (V $r.Rdp 'HostedDesktopApp') 'Hosts') ', '
        ClientCrashes = $(if ($null -ne (V $sess 'ClientCrashes')) { '{0} crash(es), {1} hang(s){2}' -f (V $sess 'ClientCrashes'), (V $sess 'ClientHangs'), $(if ($crashBy.Count) { ': ' + ($crashBy -join ', ') }) })
        UdpPolicy = $(if ($sessUdp) { if (V $sessUdp 'UdpDisabled') { "Turned off ($(V $sessUdp 'Source'))" } else { 'Not turned off' } })
        Displays = $(if ($screenSizes.Count) { $screenSizes -join ' + ' })
        CpuAvgPct = V $sessLoad 'CpuAvgPct'; MemUsedPct = V $sessLoad 'MemoryUsedPct'; TopMemory = J (V $sessLoad 'TopByMemory') ', '
        AdapterPowerSaving = $(if ($sessPower) { switch ("$(V $sessPower 'AllowTurnOff')") { 'Enabled' { 'On (Windows may turn the adapter off)' } 'Disabled' { 'Turned off' } default { "$(V $sessPower 'AllowTurnOff')" } } })
        Manufacturer = V $m 'Manufacturer'; Model = V $m 'Model'; Serial = V $m 'SerialNumber'; FormFactor = V $m 'FormFactor'; AgeYears = V $m 'ApproxAgeYears'; AgeSource = $(if (V $m 'AgeSource') { V $m 'AgeSource' } else { 'BIOS date' }); BiosDate = V $m 'BiosDate'
        Cpu = V $m 'Cpu'; RamGB = V $m 'RamGB'; Disks = J (@(V $m 'Disks') | ForEach-Object { if ($_) { '{0}GB {1}' -f $_.SizeGB, $_.MediaType } })
        Os = V $m 'OsCaption'; OsEdition = V $m 'OsEdition'; OsVersion = V $m 'OsDisplayVersion'; Build = V $m 'OsBuild'; IsWin10 = V $m 'IsWindows10'
        Tpm = $tpm; SecureBoot = $secureBoot; BitLocker = $bitlocker; DiskWearPct = $wear
        JoinType = V $r.Identity 'JoinType'; Tenant = V (V $r.Identity 'Dsregcmd') 'TenantName'; Intune = V $r.Identity 'IntuneEnrolled'
        UserIsLocalAdmin = V $r.Identity 'UserIsLocalAdmin'; ActiveProfiles = V $r.Identity 'ProfilesActiveInLookback'
        LastUpdate = V $pt 'LastUpdateInstalled'; DaysSinceUpdate = V $pt 'DaysSinceLastUpdate'; LastUpdateTitle = V $pt 'LastUpdateTitle'; PendingReboot = V $pt 'PendingReboot'
        M365Version = V $m365 'Version'; M365Channel = V $m365 'Channel'; ClockOffsetSec = V $eg 'ClockOffsetSec'
        RMM = J (V (V $r.Software 'Tagged') 'RMM'); Security = J (V (V $r.Software 'Tagged') 'Security'); VPN = J (V (V $r.Software 'Tagged') 'VPN')
        Monitors = V $r.Peripherals 'MonitorCount'
        RdpTargets = J (@($r.RdpPath) | ForEach-Object { if ($_) { $_.Host } })
        GatewayVendor = V $r.NetworkExtra 'GatewayVendor'
        FirewallModel = $(if (V $r.GatewayModel 'Model') { '{0} {1}' -f (V $r.GatewayModel 'Vendor'), (V $r.GatewayModel 'Model') } else { V $r.GatewayModel 'Vendor' })
        FirewallHints = J (@(V $r.FirewallPorts 'VendorHints') | Sort-Object -Unique)
        VpnClientVendor = J (@(V $r.Software 'FirewallVendorHintsFromVpnClient') | Sort-Object -Unique)
        FlagCount = @($r.Flags | Where-Object { $_ }).Count; HighFlags = $highFlags
    }
    foreach ($p in @(V $r.Peripherals 'Printers')) {
        if (-not $p -or $p.IsVirtual) { continue }
        $probe = @($r.PrinterProbe) | Where-Object { $_ -and $_.IP -eq $p.HostAddress } | Select-Object -First 1
        $printers += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Printer = $p.Name; Driver = $p.Driver; PortType = $p.PortType; HostAddress = $p.HostAddress; WebTitle = V $probe 'Title'; Default = $p.IsDefault; Shared = $p.Shared }
    }
    $dbc = V $r.Peripherals 'DevicesByClass'
    $gaps = @(V $r.Peripherals 'RedirectionCheck') | ForEach-Object { if ($_) { $_.Gaps } }
    $periph += [pscustomobject][ordered]@{
        Site = $site; Hostname = $hostName
        Monitors = J (@(V $r.Peripherals 'Monitors') | ForEach-Object { if ($_) { ('{0} {1} {2}in' -f $_.Manufacturer, $_.Model, $_.DiagonalInches).Trim() } })
        Docks = J (V $r.Peripherals 'Docks'); ScannerCamera = J (V $dbc 'Scanner/Camera'); Audio = J (V $dbc 'Audio'); SmartCard = J (V $dbc 'SmartCard')
        SerialCom = J (V $dbc 'Serial/COM'); Notable = J (V $r.Peripherals 'NotableDevices'); RedirectionGaps = J $gaps
    }
    foreach ($a in @(V $r.Software 'Apps')) { if ($a) { $software += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Name = $a.Name; Version = $a.Version; Publisher = $a.Publisher; Scope = $a.Scope } } }
    foreach ($t in @($r.Traceroutes)) {
        if (-not $t) { continue }
        foreach ($hp in @($t.Hops)) { if ($hp) { $traceRows += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Target = $t.Target; Hop = $hp.Hop; IP = $hp.IP; Class = $hp.Class; AvgMs = $hp.AvgMs; Ptr = $hp.Ptr } } }
    }
    foreach ($p in @($r.TcpSeries)) { if ($p) { $pingRows += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Target = ('{0} tcp/{1}' -f $p.Target, $p.Port); Sent = $p.Sent; Received = $p.Received; LossPct = $p.LossPct; MinMs = $p.MinMs; AvgMs = $p.AvgMs; P95Ms = $p.P95Ms; MaxMs = $p.MaxMs; JitterMs = $p.JitterMs } } }
    foreach ($p in @($r.PingSeries)) { if ($p) { $pingRows += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Target = $p.Target; Sent = $p.Sent; Received = $p.Received; LossPct = $p.LossPct; MinMs = $p.MinMs; AvgMs = $p.AvgMs; P95Ms = $p.P95Ms; MaxMs = $p.MaxMs; JitterMs = $p.JitterMs } } }
    foreach ($rp in @($r.RdpPath)) {
        if (-not $rp) { continue }
        foreach ($tc in @($rp.Tcp)) { if ($tc) { $rdpRows += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Host = $rp.Host; ResolvedIPs = J $rp.ResolvedIPs; AddressClass = $rp.AddressClass; Port = $tc.Port; Open = $tc.Open; MedianMs = $tc.MedianMs; JitterMs = $tc.JitterMs } } }
    }
    $ne = $r.NetworkExtra
    if (V $ne 'GatewayMac') {
        $detail = J (@(@($r.GatewayProbe) | ForEach-Object { if ($_ -and ($_.Title -or $_.CertSubject)) { ('{0} {1} {2}' -f $_.Title, $_.Server, $_.CertSubject).Trim() } }) + @(@(V $r.FirewallPorts 'Ports') | Where-Object { $_ -and $_.Open } | ForEach-Object { ('tcp/{0} {1}{2}' -f $_.Port, $_.Title, $_.Banner).Trim() }))
        $gear += [pscustomobject][ordered]@{ Site = $site; SeenFrom = $hostName; Type = 'Gateway / firewall'; Name = V $ne 'GatewayPtr'; IP = V $ne 'Gateway'; Mac = V $ne 'GatewayMac'; Vendor = V $ne 'GatewayVendor'; Detail = $detail }
    }
    if ($w -and (V $w 'BSSID')) { $gear += [pscustomobject][ordered]@{ Site = $site; SeenFrom = $hostName; Type = 'Access point (connected)'; Name = V $w 'SSID'; IP = $null; Mac = V $w 'BSSID'; Vendor = V $w 'ApVendor'; Detail = ('{0} ch{1} {2}%' -f (V $w 'Band'), (V $w 'Channel'), (V $w 'SignalPct')) } }
    foreach ($ap in @(V $r.Wireless 'Nearby')) {
        if ($ap -and $w -and $ap.SSID -eq (V $w 'SSID') -and $ap.BSSID -ne (V $w 'BSSID')) { $gear += [pscustomobject][ordered]@{ Site = $site; SeenFrom = $hostName; Type = 'Access point (same SSID)'; Name = $ap.SSID; IP = $null; Mac = $ap.BSSID; Vendor = $ap.Vendor; Detail = ('{0} ch{1} {2}%' -f $ap.Band, $ap.Channel, $ap.SignalPct) } }
    }
    foreach ($nb in @(V $r.Lldp 'Neighbors')) {
        if (-not $nb) { continue }
        # Older runs had no Model/Port fields; derive them the same way the collector now does.
        $model = if (V $nb 'Model') { V $nb 'Model' } elseif ($nb.SystemDescription) { ($nb.SystemDescription -split ',')[0].Trim() } else { $null }
        $port = if (V $nb 'Port') { V $nb 'Port' } elseif ($nb.PortDescription -and "$($nb.PortDescription)".Length -le 24) { $nb.PortDescription } else { $nb.PortId }
        $bits = @("this PC on port $port")
        if (V $nb 'LinkMode') { $bits += "link $(V $nb 'LinkMode')" }
        if ($nb.Vlan) { $bits += "VLAN $($nb.Vlan)" }
        if ($nb.SystemDescription -and $nb.SystemDescription -ne $model) { $bits += $nb.SystemDescription }
        $gear += [pscustomobject][ordered]@{ Site = $site; SeenFrom = $hostName; Type = "Switch ($($nb.Protocol))"; Name = $(if ($model) { "$model ($($nb.SystemName))" } else { $nb.SystemName }); IP = $nb.MgmtIP; Mac = $nb.ChassisMac; Vendor = $nb.ChassisVendor; Detail = ($bits -join '; ') }
    }
    foreach ($sd in @(V $r.Ssdp 'Devices')) {
        if ($sd) { $gear += [pscustomobject][ordered]@{ Site = $site; SeenFrom = $hostName; Type = 'UPnP device'; Name = $sd.FriendlyName; IP = $sd.IP; Mac = $null; Vendor = $sd.Manufacturer; Detail = ('{0} {1} {2}' -f $sd.Model, $sd.ModelNumber, $sd.DeviceType).Trim() } }
    }
    foreach ($dv in @(V $r.SubnetSweep 'Devices')) {
        if ($dv) {
            $ports = @(V $dv 'OpenPorts') | Where-Object { $_ }
            $detail = J @((V $dv 'Role'), $(if (@($ports).Count) { 'ports ' + (@($ports) -join ',') }), $(if ($dv.RespondedToPing) { 'answers ping' } else { 'ARP only' }))
            $gear += [pscustomobject][ordered]@{ Site = $site; SeenFrom = $hostName; Type = 'Subnet device'; Name = V $dv 'Name'; IP = $dv.IP; Mac = $dv.Mac; Vendor = $dv.Vendor; Detail = $detail }
        }
    }
    foreach ($sv in $srvList) {
        $gear += [pscustomobject][ordered]@{ Site = $site; SeenFrom = $hostName; Type = 'Server in use by a PC'; Name = $sv.Name; IP = (J $sv.IPs ', '); Mac = $null; Vendor = $null; Detail = ('{0}; {1}' -f $sv.Location, (J $sv.Sources)) }
    }
    foreach ($fl in @($r.Flags)) { if ($fl) { $flags += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Severity = $fl.Severity; Category = $fl.Category; Message = $fl.Message; Scope = 'Site' } } }
    foreach ($fl in @($r._DeviceFlags)) { if ($fl) { $deviceFlags += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Severity = $fl.Severity; Category = $fl.Category; Message = $fl.Message; Scope = 'Test laptop itself (not counted)' } } }
    # Collector 1.6.0+: the run's own correlated findings, and every device it identified.
    foreach ($fd in @(V $r 'Findings')) {
        if ($fd) { $runFindings += [pscustomobject][ordered]@{ Site = $site; Hostname = $hostName; Area = $fd.Area; Confidence = $fd.Confidence; Finding = $fd.Finding; Evidence = (J @($fd.Evidence) ' | ') } }
    }
    foreach ($dv in @(V (V $r 'Identify') 'Devices')) {
        if (-not $dv) { continue }
        $win = @(V (V $r 'WindowsHosts') 'Hosts') | Where-Object { $_ -and $_.IP -eq $dv.IP } | Select-Object -First 1
        $rn = @(V (V $r 'DnsDiscovery') 'ReverseNames') | Where-Object { $_ -and $_.IP -eq $dv.IP } | Select-Object -First 1
        $devices += [pscustomobject][ordered]@{
            Site = $site; SeenFrom = $hostName; IP = $dv.IP; Mac = $dv.Mac; MacVendor = $dv.MacVendor
            Name = $(if ($dv.Name) { $dv.Name } elseif ($rn) { $rn.Name } else { $null }); DnsName = $(if ($rn) { $rn.Name })
            Kind = $dv.Kind; Vendor = $dv.Vendor; Model = $dv.Model; Firmware = $dv.Firmware; Confidence = $dv.Confidence
            WindowsVersion = $(if ($win -and $win.Os) { '{0} ({1})' -f $win.Os, $win.OsVersion }); OpenPorts = (J @($dv.OpenPorts) ',')
            Evidence = (J @($dv.Evidence | Select-Object -First 4) ' | ')
        }
    }
}
$gear = @($gear | Sort-Object Site, Type, IP, Mac -Unique)
# A test laptop has no history at the site: blank the fields that would otherwise read as the site's.
foreach ($e in $endpoints) {
    if ($e.Role -ne 'Test laptop') { continue }
    foreach ($fld in 'RdpUnexpectedDisconnects', 'RdpNetworkDisconnects', 'RdpUdp', 'WifiRealDrops', 'VpnClientVendor', 'ClientCrashes', 'UdpPolicy', 'HostedDesktopApp', 'HostedDesktopHosts', 'RMM', 'Security', 'VPN') { $e.$fld = $null }
}

# ---------------------------------------------------------------------
# Known subnets: assembled only from data each machine already collected
# (adapter IP/mask, routes, printer ports, DNS/DHCP servers, private
# traceroute hops, RDP lookups). Nothing here sends any traffic.
# ---------------------------------------------------------------------
$subnetMap = [ordered]@{}
$kindRank = @{ 'Local (machine is on it)' = 0; 'Route on a machine' = 1; 'Inferred /24 (from an address)' = 2 }
$epLocal = @{}
function Add-Subnet {
    param([string]$Site, [string]$Cidr, [string]$Kind, [string]$Source, [string]$SeenFrom, [string]$Device, [string]$Note)
    $key = "$Site|$Cidr"
    if (-not $subnetMap.Contains($key)) {
        $subnetMap[$key] = [ordered]@{ Site = $Site; Subnet = $Cidr; Kind = $Kind; Sources = @(); SeenFrom = @(); KnownAddresses = @(); Notes = @() }
    }
    $e = $subnetMap[$key]
    if ($kindRank[$Kind] -lt $kindRank[$e.Kind]) { $e.Kind = $Kind }
    if ($Source -and $e.Sources -notcontains $Source) { $e.Sources += $Source }
    if ($SeenFrom -and $e.SeenFrom -notcontains $SeenFrom) { $e.SeenFrom += $SeenFrom }
    if ($Device -and $e.KnownAddresses -notcontains $Device) { $e.KnownAddresses += $Device }
    if ($Note -and $e.Notes -notcontains $Note) { $e.Notes += $Note }
}
function Add-AddressSubnet {
    # Place a single private address in a subnet already known at this site, else assume a /24.
    param([string]$Site, [string]$Ip, [string]$Source, [string]$SeenFrom, [string]$Note)
    if (-not (Test-PrivateIp $Ip)) { return }
    $match = $null
    foreach ($k in @($subnetMap.Keys)) {
        $s = $subnetMap[$k]
        if ($s.Site -eq $Site -and $s.Kind -ne 'Inferred /24 (from an address)' -and (Test-InCidr $Ip $s.Subnet)) {
            if (-not $match -or [int]$s.Subnet.Split('/')[1] -gt [int]$match.Split('/')[1]) { $match = $s.Subnet }
        }
    }
    if ($match) { Add-Subnet $Site $match 'Route on a machine' $Source $SeenFrom $Ip $Note }
    else { Add-Subnet $Site (Get-NetworkCidr $Ip 24) 'Inferred /24 (from an address)' $Source $SeenFrom $Ip $Note }
}

# Pass 1: subnets the machines are on, plus routes in their route tables.
foreach ($r in $runs) {
    $site = $siteDisplay[$r._SiteKey]; $hn = $r._Label
    $locals = @()
    foreach ($a in @(V $r.Network 'Adapters')) {
        if (-not $a -or $a.Status -ne 'Up') { continue }
        $ipsA = @($a.IPv4) | Where-Object { Test-IPv4Text $_ }
        $masks = @($a.SubnetMask) | Where-Object { Test-IPv4Text $_ }
        for ($i = 0; $i -lt @($ipsA).Count; $i++) {
            $ip = @($ipsA)[$i]
            if ($ip -like '169.254.*') { continue }
            $mask = if (@($masks).Count -gt $i) { @($masks)[$i] } else { '255.255.255.0' }
            $cidr = Get-NetworkCidr $ip (Get-PrefixFromMask $mask)
            $locals += $cidr
            $gwNote = if (@($a.Gateway) | Where-Object { $_ }) { "gateway $(J $a.Gateway ', ')" } else { $null }
            Add-Subnet $site $cidr 'Local (machine is on it)' ("{0} adapter {1} ({2})" -f $hn, $a.Name, $a.Class) $hn $ip $gwNote
        }
    }
    $epLocal["$site|$hn"] = @($locals | Select-Object -Unique)
    # Windows keeps routes for disconnected adapters; only count interfaces that are up.
    $upNames = @(@(V $r.Network 'Adapters') | Where-Object { $_ -and $_.Status -eq 'Up' } | ForEach-Object { $_.Name })
    foreach ($rt in @(V $r.NetworkExtra 'Routes')) {
        if (-not $rt -or "$($rt.Prefix)" -notmatch '^(\d{1,3}(\.\d{1,3}){3})/(\d+)$') { continue }
        $net = $matches[1]; $pre = [int]$matches[3]
        if ($pre -eq 0 -or $pre -ge 32 -or -not (Test-PrivateIp $net)) { continue }
        if ($upNames -notcontains $rt.Interface) { continue }
        $cidr = Get-NetworkCidr $net $pre
        $onLink = (-not $rt.NextHop -or $rt.NextHop -eq '0.0.0.0')
        if ($onLink -and $locals -contains $cidr) { continue }
        $via = if ($onLink) { 'on-link' } else { "via $($rt.NextHop)" }
        Add-Subnet $site $cidr 'Route on a machine' ("{0} route {1} ({2})" -f $hn, $via, $rt.Interface) $hn $null $null
    }
}

# Pass 2: single addresses that point at other subnets.
foreach ($r in $runs) {
    $site = $siteDisplay[$r._SiteKey]; $hn = $r._Label
    foreach ($p in @(V $r.Peripherals 'Printers')) {
        if (-not $p -or -not $p.HostAddress -or $p.IsVirtual) { continue }
        $probe = @($r.PrinterProbe) | Where-Object { $_ -and $_.IP -eq $p.HostAddress } | Select-Object -First 1
        $note = $null
        if ($probe) { $note = if ($probe.Reachable) { "printer $($p.HostAddress) answered the web-page check from $hn" } else { "printer $($p.HostAddress) did not answer from $hn" } }
        Add-AddressSubnet $site $p.HostAddress ("{0} printer '{1}'" -f $hn, $p.Name) $hn $note
    }
    foreach ($d in @(V $r.NetworkExtra 'DnsServers')) { if ($d -and $d.Server) { Add-AddressSubnet $site $d.Server ("{0} DNS server {1}" -f $hn, $d.Server) $hn $null } }
    foreach ($sv in @(V (V $r 'Servers') 'Servers')) { if ($sv) { foreach ($ip in @($sv.IPs)) { if ($ip) { Add-AddressSubnet $site $ip ("{0} uses server {1}" -f $hn, $sv.Name) $hn $null } } } }
    foreach ($a in @(V $r.Network 'Adapters')) {
        if ($a -and $a.Status -eq 'Up' -and $a.DhcpServer -and (Test-IPv4Text $a.DhcpServer)) { Add-AddressSubnet $site $a.DhcpServer ("{0} DHCP server {1}" -f $hn, $a.DhcpServer) $hn $null }
    }
    foreach ($t in @($r.Traceroutes)) {
        if (-not $t) { continue }
        # Customer-side private hops only: stop at the first carrier-grade NAT or public hop.
        foreach ($hp in @($t.Hops | Sort-Object Hop)) {
            if (-not $hp -or -not $hp.IP) { continue }
            if ($hp.Class -eq 'CGNAT' -or $hp.Class -eq 'Public') { break }
            if ($hp.Hop -gt 1 -and $hp.Class -eq 'Private') { Add-AddressSubnet $site $hp.IP ("{0} traceroute hop {1} to {2}" -f $hn, $hp.Hop, $t.Target) $hn $null }
        }
    }
    foreach ($rp in @($r.RdpPath)) { if ($rp) { foreach ($ip in @($rp.ResolvedIPs)) { Add-AddressSubnet $site $ip ("{0} RDP host {1} resolves here" -f $hn, $rp.Host) $hn $null } } }
    foreach ($c in @(V $r.Rdp 'ActiveTcp')) { if ($c -and $c.RemoteAddress) { Add-AddressSubnet $site $c.RemoteAddress ("{0} live RDP session to {1}" -f $hn, $c.RemoteAddress) $hn $null } }
}

$subnets = @($subnetMap.Values | ForEach-Object {
    [pscustomobject][ordered]@{ Site = $_.Site; Subnet = $_.Subnet; Kind = $_.Kind; KnownAddresses = J $_.KnownAddresses ', '; Sources = J $_.Sources; SeenFrom = J $_.SeenFrom ', '; Notes = J $_.Notes }
} | Sort-Object Site, @{ Expression = { $kindRank[$_.Kind] } }, Subnet)
foreach ($e in $endpoints) { $e | Add-Member -NotePropertyName LocalSubnet -NotePropertyValue (J $epLocal["$($e.Site)|$($e.Hostname)"] ', ') -Force }

# ---------------------------------------------------------------------
# Enrichment pass (needs internet where the merge runs; -NoEnrich skips it)
#   MAC vendors : the IEEE OUI registry, downloaded once and cached. Nothing from the runs is sent.
#   IP owners   : Team Cymru (over DNS) for the network that announces each public address, the
#                 regional registry's RDAP service (whois) for who the block is registered to, and
#                 reverse DNS for hops that had no name. Only public IP addresses are sent.
# Results are cached under -CacheDir, so merging again does not repeat the lookups.
# ---------------------------------------------------------------------
$enrich = [ordered]@{ Ran = $false; IpTotal = 0; IpLookedUp = 0; IpFromCache = 0; RdapCalls = 0; PtrAdded = 0; MacFilled = 0; MacRandom = 0; OuiSource = $null; Notes = @() }
$ipInfo = @{}
$ipSeen = @{}
$exposure = @{}

function Test-PublicIPv4 {
    param([string]$Ip)
    if (-not (Test-IPv4Text $Ip)) { return $false }
    $o = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o[0] -eq 0 -or $o[0] -eq 10 -or $o[0] -eq 127 -or $o[0] -ge 224) { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }
    return $true
}

function Add-IpSeen {
    param($Ip, [string]$Label)
    $ip = "$Ip".Trim()
    if (-not (Test-PublicIPv4 $ip)) { return }
    if (-not $ipSeen.ContainsKey($ip)) { $ipSeen[$ip] = New-Object System.Collections.Generic.List[string] }
    if (-not $ipSeen[$ip].Contains($Label)) { $ipSeen[$ip].Add($Label) }
}

function Get-TxtRecord {
    # One DNS TXT answer as text, or $null.
    param([string]$Name)
    $ans = Resolve-DnsName -Name $Name -Type TXT -DnsOnly -QuickTimeout -ErrorAction Stop
    return (@($ans | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join '' }) | Select-Object -First 1)
}

function Get-VendorKind {
    # A rough device type from the maker's name, used only when the open ports said nothing.
    param([string]$Vendor)
    switch -Regex ($Vendor) {
        'Yealink|Polycom|Grandstream|Mitel|Avaya|Snom|Poly\b|Cisco SPA|Obihai|Fanvil|Algo ' { return 'phone' }
        'Brother|Canon|Epson|Lexmark|Xerox|Ricoh|Konica|Kyocera|Sharp|Zebra|Oki |Toshiba Tec|Fuji ?film|Riso' { return 'printer or copier' }
        'Axis Comm|Hikvision|Dahua|Hanwha|Verkada|Amcrest|Reolink|Uniview|Lorex|Vivotek|Avigilon' { return 'camera or recorder' }
        'Ubiquiti|Meraki|Aruba|Ruckus|Fortinet|SonicWall|WatchGuard|Netgear|TP-Link|Juniper|Palo Alto|Sophos|MikroTik|Extreme Net|Datto|Cambium|EnGenius|Linksys|Zyxel|D-Link|Peplink|Cradlepoint|Arista|Brocade|Adtran|Calix|ARRIS|CommScope|Technicolor|Sagemcom|eero' { return 'network equipment' }
        'Sonos|Roku|Amazon|Google|Nest Labs|Ring |Espressif|Tuya|Ecobee|Belkin|Wyze|Samsung Electronics|LG Electronics|Vizio|TCL' { return 'TV, speaker or smart device' }
        'Apple' { return 'Apple device' }
        'Synology|QNAP|Buffalo|Western Digital|Drobo' { return 'NAS' }
        'APC|American Power|Schneider|Eaton|CyberPower|Tripp' { return 'UPS or power' }
        'Hewlett|HP Inc' { return 'computer or printer' }
        'Dell|Lenovo|Intel|Microsoft|ASUSTek|Acer|Micro-Star|Gigabyte|LCFC|Wistron|Pegatron|Liteon|AzureWave|Realtek|Hon Hai|Foxconn|Quanta|Compal|Rivet|Killer' { return 'computer' }
    }
    return $null
}

if (-not $NoEnrich) {
    $enrich.Ran = $true
    $ProgressPreference = 'SilentlyContinue'
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    if (-not $CacheDir) { $CacheDir = Join-Path $env:LOCALAPPDATA 'SiteAssessment\cache' }
    try { New-Item -ItemType Directory -Path $CacheDir -Force -ErrorAction Stop | Out-Null } catch { $enrich.Notes += "Cache folder not usable ($CacheDir): lookups are not saved" }
    $ua = 'SiteAssessment-Merge'

    # ---- MAC vendors from the IEEE registry (cached as a small prefix-to-name file)
    $oui = @{}
    $ouiTsv = Join-Path $CacheDir 'oui.tsv'
    $haveFile = Test-Path -LiteralPath $ouiTsv
    $stale = (-not $haveFile) -or ((Get-Item -LiteralPath $ouiTsv).LastWriteTime -lt (Get-Date).AddDays(-60))
    if ($stale) {
        $tmp = Join-Path $work 'oui-download.tmp'
        try {
            Invoke-WebRequest -Uri 'https://standards-oui.ieee.org/oui/oui.csv' -OutFile $tmp -TimeoutSec 60 -UseBasicParsing -UserAgent "Mozilla/5.0 $ua" -ErrorAction Stop
            $rows = @(Import-Csv -LiteralPath $tmp -Encoding UTF8)
            $lines = New-Object System.Collections.Generic.List[string]
            foreach ($row in $rows) { $a = "$($row.Assignment)".Trim().ToUpperInvariant(); if ($a.Length -eq 6) { $lines.Add($a + "`t" + ("$($row.'Organization Name')".Trim() -replace "`t", ' ')) } }
            if ($lines.Count -lt 10000) { throw "only $($lines.Count) entries parsed" }
            # Small blocks (7 and 9 hex digits) name the small makers; without them they all read "IEEE Registration Authority".
            foreach ($extra in 'https://standards-oui.ieee.org/oui28/mam.csv', 'https://standards-oui.ieee.org/oui36/oui36.csv') {
                try {
                    Invoke-WebRequest -Uri $extra -OutFile $tmp -TimeoutSec 60 -UseBasicParsing -UserAgent "Mozilla/5.0 $ua" -ErrorAction Stop
                    foreach ($row in @(Import-Csv -LiteralPath $tmp -Encoding UTF8)) { $a = "$($row.Assignment)".Trim().ToUpperInvariant(); if ($a.Length -in 7, 9) { $lines.Add($a + "`t" + ("$($row.'Organization Name')".Trim() -replace "`t", ' ')) } }
                } catch { $enrich.Notes += "IEEE small-block list not downloaded ($extra): a few small makers may read 'IEEE Registration Authority'" }
            }
            [IO.File]::WriteAllLines($ouiTsv, $lines, (New-Object Text.UTF8Encoding $false))
            $enrich.OuiSource = "IEEE OUI registry, downloaded $(Get-Date -Format 'yyyy-MM-dd')"
        } catch {
            $ieeeError = $_.Exception.Message
            try {
                # Second source: the Wireshark manufacturer list (built from the same IEEE registry).
                Invoke-WebRequest -Uri 'https://www.wireshark.org/download/automated/data/manuf' -OutFile $tmp -TimeoutSec 60 -UseBasicParsing -UserAgent "Mozilla/5.0 $ua" -ErrorAction Stop
                $lines = New-Object System.Collections.Generic.List[string]
                foreach ($ln in [IO.File]::ReadAllLines($tmp)) {
                    if ($ln -match '^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\t([^\t]*)(\t(.*))?$') {
                        $nm = if ($Matches[6]) { $Matches[6] } else { $Matches[4] }
                        $lines.Add(("$($Matches[1])$($Matches[2])$($Matches[3])").ToUpperInvariant() + "`t" + $nm.Trim())
                    }
                }
                if ($lines.Count -lt 10000) { throw "only $($lines.Count) entries parsed" }
                [IO.File]::WriteAllLines($ouiTsv, $lines, (New-Object Text.UTF8Encoding $false))
                $enrich.OuiSource = "Wireshark manufacturer list, downloaded $(Get-Date -Format 'yyyy-MM-dd')"
            } catch {
                $enrich.Notes += "MAC vendor list could not be downloaded (IEEE: $ieeeError; Wireshark: $($_.Exception.Message))" + $(if ($haveFile) { '; using the older cached copy' } else { '' })
            }
        }
    }
    if (Test-Path -LiteralPath $ouiTsv) {
        foreach ($ln in [IO.File]::ReadAllLines($ouiTsv)) { $ix = $ln.IndexOf("`t"); if ($ix -in 6, 7, 9) { $oui[$ln.Substring(0, $ix)] = $ln.Substring($ix + 1) } }
        if (-not $enrich.OuiSource) { $enrich.OuiSource = "IEEE OUI registry, cached copy from $((Get-Item -LiteralPath $ouiTsv).LastWriteTime.ToString('yyyy-MM-dd'))" }
    }
    function Get-MacOwner {
        # Vendor for a MAC, 'Randomized (private) address' for locally administered ones, or $null.
        param([string]$Mac)
        $hex = ("$Mac" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($hex.Length -lt 12) { return $null }
        if ('26AE'.Contains($hex.Substring(1, 1))) { return 'Randomized (private) address' }
        foreach ($len in 9, 7, 6) { $k = $hex.Substring(0, $len); if ($oui.ContainsKey($k)) { return $oui[$k] } }
        return 'Not in the IEEE registry (virtual or made-up address)'
    }
    if ($oui.Count) {
        foreach ($g in $gear) {
            if (-not $g.Mac) { continue }
            $known = ($g.Vendor -and "$($g.Vendor)" -ne 'Unknown')
            if (-not $known) {
                $v = Get-MacOwner $g.Mac
                if ($v) { $g.Vendor = $v; if ($v -like 'Randomized*') { $enrich.MacRandom++ } elseif ($v -notlike 'Not in the IEEE*') { $enrich.MacFilled++ } }
            }
            # A subnet device whose ports said nothing: say what its maker usually builds.
            if ($g.Type -eq 'Subnet device' -and $g.Vendor -and "$($g.Detail)" -match '^(answers ping|ARP only)$') {
                $kind = Get-VendorKind "$($g.Vendor)"
                if ($kind) { $g.Detail = "likely $kind (from the maker); $($g.Detail)" }
            }
        }
        foreach ($dv in $devices) {
            if ($dv.Mac -and (-not $dv.MacVendor -or "$($dv.MacVendor)" -eq 'Unknown')) { $v = Get-MacOwner $dv.Mac; if ($v) { $dv.MacVendor = $v; if (-not $dv.Vendor -and $v -notlike 'Randomized*' -and $v -notlike 'Not in the IEEE*') { $dv.Vendor = $v } } }
        }
        foreach ($r in $runs) {
            $e = $endpoints | Where-Object { $_.Site -eq $siteDisplay[$r._SiteKey] -and $_.Hostname -eq $r._Label } | Select-Object -First 1
            if (-not $e) { continue }
            if (-not $e.GatewayVendor -or "$($e.GatewayVendor)" -eq 'Unknown') { $v = Get-MacOwner (V $r.NetworkExtra 'GatewayMac'); if ($v) { $e.GatewayVendor = $v } }
            if (-not $e.ApVendor -or "$($e.ApVendor)" -eq 'Unknown') { $v = Get-MacOwner (V (V $r.Wireless 'Current') 'BSSID'); if ($v) { $e.ApVendor = $v } }
        }
    }

    # ---- Public IP addresses seen anywhere in the runs
    foreach ($r in $runs) {
        $sn = $siteDisplay[$r._SiteKey]
        Add-IpSeen (V $r.Egress 'PublicIPv4') "$sn public IP"
        foreach ($t in @($r.Traceroutes)) { if ($t) { foreach ($hp in @($t.Hops)) { if ($hp -and $hp.IP) { Add-IpSeen $hp.IP "$sn traceroute hop" } } } }
        foreach ($rp in @($r.RdpPath)) { if ($rp) { foreach ($a in @($rp.ResolvedIPs)) { Add-IpSeen $a "RDP target $($rp.Host)" } } }
        foreach ($p in @($r.TcpSeries)) { if ($p) { Add-IpSeen (V $p 'Address') "RDP target $($p.Target)" } }
        foreach ($sv in @(V (V $r 'Servers') 'Servers')) { if ($sv) { foreach ($a in @($sv.IPs)) { Add-IpSeen $a "server $($sv.Name) ($sn)" } } }
        foreach ($c in @(V $r.Rdp 'HostedConnections')) { if ($c) { Add-IpSeen (V $c 'RemoteAddress') "live $HostedLabel connection ($sn)" } }
    }
    $enrich.IpTotal = $ipSeen.Count

    # ---- Cache of earlier answers (30 days)
    $ipCachePath = Join-Path $CacheDir 'ip-owners.json'
    $ipCache = @{}
    if (Test-Path -LiteralPath $ipCachePath) {
        try { foreach ($p in ([IO.File]::ReadAllText($ipCachePath) | ConvertFrom-Json).PSObject.Properties) { $ipCache[$p.Name] = $p.Value } } catch { }
    }
    $freshAfter = (Get-Date).AddDays(-30)
    $todo = @()
    foreach ($ip in $ipSeen.Keys) {
        $c = $ipCache[$ip]
        $ok = $false
        if ($c) { try { $ok = ([datetime]$c.Fetched -gt $freshAfter) } catch { } }
        if ($ok) { $ipInfo[$ip] = $c; $enrich.IpFromCache++ } else { $todo += $ip }
    }

    if ($todo.Count) {
        Write-Host ("Enrichment: looking up {0} public address(es) ({1} already cached)..." -f $todo.Count, $enrich.IpFromCache)
        $asNames = @{}
        $ranges = New-Object System.Collections.ArrayList
        $dnsFails = 0; $rdapFails = 0; $dnsOff = $false; $rdapOff = $false
        if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) { $dnsOff = $true; $enrich.Notes += 'Resolve-DnsName is not available here: network names and reverse DNS skipped' }
        $rdapBase = @{ arin = 'https://rdap.arin.net/registry/ip/'; ripencc = 'https://rdap.db.ripe.net/ip/'; apnic = 'https://rdap.apnic.net/ip/'; lacnic = 'https://rdap.lacnic.net/rdap/ip/'; afrinic = 'https://rdap.afrinic.net/rdap/ip/' }
        $hopOnly = @{}
        foreach ($ip in $todo) { $hopOnly[$ip] = (@($ipSeen[$ip] | Where-Object { $_ -notlike '*traceroute hop' }).Count -eq 0) }
        foreach ($ip in ($todo | Sort-Object @{ Expression = { [int]$hopOnly[$_] } }, @{ Expression = { ConvertTo-IpInt $_ } })) {
            $rec = [ordered]@{ IP = $ip; Asn = $null; Network = $null; Prefix = $null; Country = $null; Registry = $null; NetName = $null; RegisteredTo = $null; Range = $null; Ptr = $null; Fetched = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
            $gotAny = $false
            # Network that announces the address (Team Cymru, over DNS)
            if (-not $dnsOff) {
                try {
                    $o = $ip.Split('.')
                    $txt = Get-TxtRecord ('{3}.{2}.{1}.{0}.origin.asn.cymru.com' -f $o[0], $o[1], $o[2], $o[3])
                    $dnsFails = 0
                    if ($txt) {
                        $f = @($txt -split '\|' | ForEach-Object { $_.Trim() })
                        $rec.Asn = (@($f[0] -split '\s+') | Select-Object -First 1); $rec.Prefix = $f[1]; $rec.Country = $f[2]; $rec.Registry = $f[3]
                        if ($rec.Asn -and -not $asNames.ContainsKey($rec.Asn)) {
                            $asNames[$rec.Asn] = $null
                            try {
                                $at = Get-TxtRecord ("AS{0}.asn.cymru.com" -f $rec.Asn)
                                if ($at) {
                                    $nm = (@($at -split '\|') | Select-Object -Last 1).Trim() -replace ',\s*[A-Z]{2}$', ''
                                    if ($nm -match ' - ') { $nm = ($nm -split ' - ', 2)[1] }
                                    $asNames[$rec.Asn] = $nm.Trim()
                                }
                            } catch { }
                        }
                        if ($rec.Asn) { $rec.Network = ('AS{0} {1}' -f $rec.Asn, $asNames[$rec.Asn]).Trim(); $gotAny = $true }
                    }
                } catch {
                    # "No such name" is an answer (address not announced); anything else counts toward giving up.
                    if ("$($_.Exception.Message)" -notmatch 'DNS name does not exist|NXDOMAIN|DNS_ERROR_RCODE_NAME_ERROR') { $dnsFails++ }
                    if ($dnsFails -ge 3) { $dnsOff = $true; $enrich.Notes += "Network lookups stopped after 3 failures in a row: $($_.Exception.Message)" }
                }
            }
            # Who the block is registered to (RDAP, the registries' whois). One call covers every address in the same block.
            $ipNum = ConvertTo-IpInt $ip
            $hit = if ($hopOnly[$ip]) { $ranges | Where-Object { $ipNum -ge $_.Start -and $ipNum -le $_.End } | Sort-Object { $_.End - $_.Start } | Select-Object -First 1 } else { $null }
            if ($hit) { $rec.NetName = $hit.NetName; $rec.RegisteredTo = $hit.RegisteredTo; $rec.Range = $hit.Range; $gotAny = $true }
            elseif (-not $rdapOff) {
                $base = if ($rec.Registry -and $rdapBase.ContainsKey("$($rec.Registry)")) { $rdapBase["$($rec.Registry)"] } else { 'https://rdap.org/ip/' }
                try {
                    if ($enrich.RdapCalls) { Start-Sleep -Milliseconds 250 }
                    $enrich.RdapCalls++
                    $rd = Invoke-RestMethod -Uri ($base + $ip) -TimeoutSec 20 -Headers @{ Accept = 'application/rdap+json' } -UserAgent $ua -ErrorAction Stop
                    $rdapFails = 0
                    $org = $null
                    foreach ($role in 'registrant', 'administrative', 'technical') {
                        foreach ($en in @($rd.entities)) {
                            if (-not $en -or (@($en.roles) -notcontains $role)) { continue }
                            $fn = $null
                            try { $fn = @(@($en.vcardArray)[1] | Where-Object { $_ -and $_[0] -eq 'fn' } | ForEach-Object { $_[3] }) | Select-Object -First 1 } catch { }
                            if ($fn) { $org = "$fn"; break }
                        }
                        if ($org) { break }
                    }
                    $rec.NetName = "$($rd.name)"; $rec.RegisteredTo = $org
                    if ((Test-IPv4Text "$($rd.startAddress)") -and (Test-IPv4Text "$($rd.endAddress)")) {
                        $rec.Range = "$($rd.startAddress) - $($rd.endAddress)"
                        [void]$ranges.Add([pscustomobject]@{ Start = (ConvertTo-IpInt "$($rd.startAddress)"); End = (ConvertTo-IpInt "$($rd.endAddress)"); NetName = $rec.NetName; RegisteredTo = $org; Range = $rec.Range })
                    }
                    $gotAny = $true
                } catch {
                    $code = $null
                    try { $code = [int]$_.Exception.Response.StatusCode } catch { }
                    if ($code -eq 404) { $rdapFails = 0 }
                    elseif ($code -eq 429) { $rdapOff = $true; $enrich.Notes += 'The whois (RDAP) service asked us to slow down: remaining addresses have no "registered to" (merge again later to fill them)' }
                    else { $rdapFails++; if ($rdapFails -ge 3) { $rdapOff = $true; $enrich.Notes += "Whois (RDAP) lookups stopped after 3 failures in a row: $($_.Exception.Message)" } }
                }
            }
            # Reverse DNS
            if (-not $dnsOff) {
                try { $rec.Ptr = (@(Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.NameHost } | ForEach-Object { $_.NameHost }) | Select-Object -First 1) } catch { }
            }
            $obj = [pscustomobject]$rec
            if ($gotAny -or $rec.Ptr) { $ipInfo[$ip] = $obj }
            # Only complete answers are cached, so a partial one is retried next time.
            if ($gotAny -and -not $dnsOff -and -not $rdapOff) { $ipCache[$ip] = $obj }
            if ($gotAny) { $enrich.IpLookedUp++ }
            if ($dnsOff -and $rdapOff) { $enrich.Notes += 'No lookup service could be reached (offline?): the report is built without network owners'; break }
        }
        try {
            $outCache = [ordered]@{}
            foreach ($k in ($ipCache.Keys | Sort-Object)) { $outCache[$k] = $ipCache[$k] }
            [IO.File]::WriteAllText($ipCachePath, ($outCache | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
        } catch { }
    }

    # ---- Put the answers on the rows the report and CSVs use
    foreach ($r in $runs) {
        foreach ($t in @($r.Traceroutes)) {
            if (-not $t) { continue }
            foreach ($hp in @($t.Hops)) {
                if (-not $hp) { continue }
                $i = if ($hp.IP) { $ipInfo["$($hp.IP)"] } else { $null }
                $hp | Add-Member -NotePropertyName Owner -NotePropertyValue $(if ($i) { $i.Network }) -Force
                $hp | Add-Member -NotePropertyName Asn -NotePropertyValue $(if ($i) { $i.Asn }) -Force
                $hp | Add-Member -NotePropertyName RegisteredTo -NotePropertyValue $(if ($i) { $i.RegisteredTo }) -Force
                if ($i -and $i.Ptr -and -not $hp.Ptr) { $hp | Add-Member -NotePropertyName Ptr -NotePropertyValue $i.Ptr -Force; $enrich.PtrAdded++ }
            }
        }
    }
    foreach ($row in $traceRows) {
        $i = if ($row.IP) { $ipInfo["$($row.IP)"] } else { $null }
        if ($i -and $i.Ptr -and -not $row.Ptr) { $row.Ptr = $i.Ptr }
        $row | Add-Member -NotePropertyName Network -NotePropertyValue $(if ($i) { $i.Network }) -Force
        $row | Add-Member -NotePropertyName RegisteredTo -NotePropertyValue $(if ($i) { $i.RegisteredTo }) -Force
    }
    foreach ($row in $rdpRows) {
        $owners = @("$($row.ResolvedIPs)" -split '[;,]\s*' | ForEach-Object { $i = $ipInfo[$_.Trim()]; if ($i) { if ($i.RegisteredTo) { $i.RegisteredTo } else { $i.Network } } } | Where-Object { $_ } | Sort-Object -Unique)
        $row | Add-Member -NotePropertyName Owner -NotePropertyValue ($owners -join '; ') -Force
    }
    foreach ($e in $endpoints) {
        $i = if ($e.PublicIP) { $ipInfo["$($e.PublicIP)"] } else { $null }
        $e | Add-Member -NotePropertyName PublicIpNetwork -NotePropertyValue $(if ($i) { $i.Network }) -Force
        $e | Add-Member -NotePropertyName PublicIpRegisteredTo -NotePropertyValue $(if ($i -and $i.RegisteredTo) { '{0}{1}' -f $i.RegisteredTo, $(if ($i.NetName) { " (block $($i.NetName), $($i.Range))" }) }) -Force
    }
    # ---- What the internet can see on each site's public address: Shodan's InternetDB (free, no key).
    # Only the sites' own public IP addresses are sent. Answers are kept for 7 days.
    $expCachePath = Join-Path $CacheDir 'exposure.json'
    $expCache = @{}
    if (Test-Path -LiteralPath $expCachePath) { try { foreach ($p in ([IO.File]::ReadAllText($expCachePath) | ConvertFrom-Json).PSObject.Properties) { $expCache[$p.Name] = $p.Value } } catch { } }
    foreach ($ip in @($endpoints | ForEach-Object { $_.PublicIP } | Where-Object { $_ -and (Test-PublicIPv4 $_) } | Sort-Object -Unique)) {
        $c = $expCache[$ip]; $fresh = $false
        if ($c) { try { $fresh = ([datetime]$c.Checked -gt (Get-Date).AddDays(-7)) } catch { } }
        if (-not $fresh) {
            $rec = [ordered]@{ IP = $ip; Listed = $false; Ports = @(); Hostnames = @(); Tags = @(); Vulns = @(); Cpes = @(); Checked = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Error = $null }
            try {
                $x = Invoke-RestMethod -Uri "https://internetdb.shodan.io/$ip" -TimeoutSec 15 -UserAgent $ua -ErrorAction Stop
                $rec.Listed = $true; $rec.Ports = @($x.ports); $rec.Hostnames = @($x.hostnames); $rec.Tags = @($x.tags); $rec.Vulns = @($x.vulns); $rec.Cpes = @($x.cpes)
            } catch {
                # 404 means Shodan has no record of the address, which is itself the answer.
                $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
                if ($code -ne 404) { $rec.Error = $_.Exception.Message }
            }
            $c = [pscustomobject]$rec
            if (-not $rec.Error) { $expCache[$ip] = $c }
        }
        $exposure[$ip] = $c
    }
    try { $oc = [ordered]@{}; foreach ($k in ($expCache.Keys | Sort-Object)) { $oc[$k] = $expCache[$k] }; [IO.File]::WriteAllText($expCachePath, ($oc | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false)) } catch { }
    foreach ($e in $endpoints) {
        $x = if ($e.PublicIP) { $exposure["$($e.PublicIP)"] } else { $null }
        $e | Add-Member -NotePropertyName ExposedPorts -NotePropertyValue $(if ($x -and $x.Listed) { (@($x.Ports) -join ', ') } elseif ($x -and -not $x.Error) { 'none listed' }) -Force
        $e | Add-Member -NotePropertyName ExposedVulns -NotePropertyValue $(if ($x) { (@($x.Vulns) -join ', ') }) -Force
        $e | Add-Member -NotePropertyName ExposedTags -NotePropertyValue $(if ($x) { (@($x.Tags) -join ', ') }) -Force
    }
    foreach ($ip in @($exposure.Keys | Sort-Object)) { $x = $exposure[$ip]; Write-Host ("Exposure (Shodan): {0} -> {1}" -f $ip, $(if ($x.Error) { "lookup failed: $($x.Error)" } elseif ($x.Listed) { "ports $(@($x.Ports) -join ', ')" + $(if (@($x.Vulns).Count) { "; vulnerabilities $(@($x.Vulns | Select-Object -First 6) -join ', ')" } else { '' }) } else { 'nothing listed' })) }

    foreach ($g in $gear) {
        if ($g.Type -ne 'Server in use by a PC') { continue }
        $owners = @("$($g.IP)" -split ',\s*' | ForEach-Object { $i = $ipInfo[$_.Trim()]; if ($i) { if ($i.RegisteredTo) { $i.RegisteredTo } else { $i.Network } } } | Where-Object { $_ } | Sort-Object -Unique)
        if ($owners.Count) { $g.Detail = "$($g.Detail); address registered to $($owners -join ', ')" }
    }
    Write-Host ("Enrichment: {0} public address(es) ({1} looked up, {2} from cache, {3} whois calls), {4} unnamed hop(s) given a reverse-DNS name, {5} MAC vendor(s) filled, {6} randomized MAC(s) labelled" -f $enrich.IpTotal, $enrich.IpLookedUp, $enrich.IpFromCache, $enrich.RdapCalls, $enrich.PtrAdded, $enrich.MacFilled, $enrich.MacRandom)
    foreach ($nt in $enrich.Notes) { Write-Warning $nt }
}
# One row per public address, for the report and IpOwners.csv
$ipOwnerRows = @($ipSeen.Keys | Sort-Object { ConvertTo-IpInt $_ } | ForEach-Object {
    $i = $ipInfo[$_]
    [pscustomobject][ordered]@{ IP = $_; Network = $(if ($i) { $i.Network }); RegisteredTo = $(if ($i) { $i.RegisteredTo }); Block = $(if ($i) { $i.NetName }); Range = $(if ($i) { $i.Range }); Announced = $(if ($i) { $i.Prefix }); Country = $(if ($i) { $i.Country }); ReverseDns = $(if ($i) { $i.Ptr }); SeenAs = ($ipSeen[$_] -join '; ') }
})

# ---------------------------------------------------------------------
# Per-site rollup and cross-site egress check
# ---------------------------------------------------------------------
$ipToSites = @{}
foreach ($e in $endpoints) { if ($e.PublicIP) { if (-not $ipToSites.ContainsKey($e.PublicIP)) { $ipToSites[$e.PublicIP] = @() }; $ipToSites[$e.PublicIP] += $e.Site } }
$sites = @()
foreach ($g in ($endpoints | Group-Object Site | Sort-Object Name)) {
    $eps = @($g.Group)
    $ips = @($eps | ForEach-Object { $_.PublicIP } | Where-Object { $_ } | Sort-Object -Unique)
    $shared = @($ips | ForEach-Object { @($ipToSites[$_]) } | Where-Object { $_ -ne $g.Name } | Sort-Object -Unique)
    $verdicts = @($eps | ForEach-Object { $_.Verdict } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending)
    $siteVerdict = if ($verdicts.Count) { $verdicts[0].Name } else { 'Unknown' }
    $notes = @()
    if ($shared.Count) {
        # Two sites on the same carrier-grade NAT can share an IP without any backhaul.
        $otherCgnat = @($endpoints | Where-Object { $shared -contains $_.Site -and $ips -contains $_.PublicIP } | Where-Object { -not $_.BehindCgnat }).Count -eq 0
        $thisCgnat = @($eps | Where-Object { -not $_.BehindCgnat }).Count -eq 0
        if ($thisCgnat -and $otherCgnat) { $notes += "Same public IP as $($shared -join ', '), but all are behind carrier-grade NAT (same carrier), so this is not proof of backhaul" }
        else {
            $notes += "Same public IP as $($shared -join ', '): shared egress / backhaul"
            if ($siteVerdict -eq 'Local breakout') { $siteVerdict = 'Shared egress with other site(s)' }
        }
    }
    foreach ($ipx in $ips) {
        $x = $exposure[$ipx]
        if ($x -and $x.Listed -and @($x.Ports).Count) { $notes += "Shodan lists $ipx with these ports open to the internet: $(@($x.Ports) -join ', ')" + $(if (@($x.Vulns).Count) { " (known vulnerabilities flagged: $(@($x.Vulns | Select-Object -First 6) -join ', '))" } else { '' }) }
        elseif ($x -and -not $x.Error) { $notes += "Shodan has nothing listed for ${ipx}: no service on it has been seen from the internet" }
    }
    if ($verdicts.Count -gt 1) { $notes += 'Endpoints disagree: ' + (($verdicts | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', ') }
    if ($eps.Count -lt 2) { $notes += 'One machine tested: the traffic design and figures are that machine''s. A second machine (one wired, one Wi-Fi) would confirm the verdict and separate the circuit from the desk' }
    $testEps = @($eps | Where-Object { $_.Role -eq 'Test laptop' })
    if ($testEps.Count -and $testEps.Count -eq $eps.Count) { $notes += "Tested with a visiting laptop only ($((@($testEps | ForEach-Object { $_.Hostname }) | Sort-Object -Unique) -join ', ')): the results describe this site's network. No client PC was tested here, so there is nothing on desks, printers, peripherals or real session history" }
    elseif ($testEps.Count) { $notes += "$((@($testEps | ForEach-Object { $_.Hostname }) | Sort-Object -Unique) -join ', ') is a visiting test laptop: its network results are used, its own hardware, software and history are left out" }
    $cutOff = @($eps | Where-Object { "$($_.DataCheck)" -like 'INCOMPLETE*' })
    if ($cutOff.Count) { $notes += "Run did not finish on: $(($cutOff | ForEach-Object { $_.Hostname }) -join ', ')" }
    # Two machines testing bandwidth at the same moment share the circuit, so both read low.
    $bwWin = @($eps | Where-Object { $_.BandwidthStarted -and $_.BandwidthFinished } | ForEach-Object {
        try { [pscustomobject]@{ Name = $_.Hostname; S = [datetime]$_.BandwidthStarted; E = [datetime]$_.BandwidthFinished } } catch { } })
    $overlaps = @()
    for ($x = 0; $x -lt $bwWin.Count; $x++) { for ($y = $x + 1; $y -lt $bwWin.Count; $y++) {
        if ($bwWin[$x].S -lt $bwWin[$y].E -and $bwWin[$y].S -lt $bwWin[$x].E) { $overlaps += "$($bwWin[$x].Name) and $($bwWin[$y].Name)" } } }
    if ($overlaps.Count) { $notes += "Bandwidth tests ran at the same time on $($overlaps -join '; '): they shared the circuit, so both results read low" }
    $inspected = @($eps | Where-Object { $_.HttpsInspection -and $_.HttpsInspection -ne 'Not seen' })
    if ($inspected.Count) { $notes += "HTTPS inspection seen from $(($inspected | ForEach-Object { $_.Hostname }) -join ', '): $(($inspected | ForEach-Object { $_.HttpsInspection } | Sort-Object -Unique) -join '; ')" }
    $badData = @($eps | Where-Object { $_.DataCheck -eq 'FAIL' })
    if ($badData.Count) { $notes += "Data check FAILED on: $(($badData | ForEach-Object { '{0} ({1})' -f $_.Hostname, (($_.DataIssues -split '; ' | Where-Object { $_ -like 'FAIL*' }) -replace '^FAIL ', '' -join ', ') }) -join '; ')" }
    $failedBw = @($eps | Where-Object { $_.DownloadFailure -or $_.UploadFailure })
    if ($failedBw.Count) { $notes += "Bandwidth test failed on: $(($failedBw | ForEach-Object { $_.Hostname }) -join ', ')" }
    $wired = @($eps | Where-Object { "$($_.Connection)" -like 'Wired*' })
    $wifi = @($eps | Where-Object { $_.Connection -eq 'Wi-Fi' })
    $wiredDown = Median ($wired | ForEach-Object { $_.DownMbps })
    $wifiDown = Median ($wifi | ForEach-Object { $_.DownMbps })
    # Circuit estimate = best wired result; Wi-Fi only measures the WLAN. Without a wired run, best of all.
    $useWired = ($wired.Count -gt 0 -and $null -ne (MaxOf ($wired | ForEach-Object { $_.DownMbps })))
    $circuitSet = if ($useWired) { $wired } else { $eps }
    $circuitBasis = if ($useWired) { 'best wired' } else { 'best result, no wired run' }
    if ($wiredDown -and $wifiDown -and $wifiDown -lt 0.6 * $wiredDown) { $notes += "Wi-Fi ($wifiDown Mbps) well below wired ($wiredDown Mbps): WLAN is a bottleneck" }
    $localSets = @($eps | ForEach-Object { $_.LocalSubnet } | Where-Object { $_ } | Sort-Object -Unique)
    if ($localSets.Count -gt 1) { $notes += 'Machines are on different local subnets: ' + (($eps | ForEach-Object { if ($_.Hostname -like "*($($_.Connection))") { '{0} {1}' -f $_.Hostname, $_.LocalSubnet } else { '{0} {1} ({2})' -f $_.Hostname, $_.LocalSubnet, $_.Connection } }) -join '; ') + ' - the site is segmented (VLANs or separate wired/Wi-Fi networks)' }
    $siteSubnets = @($subnets | Where-Object { $_.Site -eq $g.Name })
    $siteGear = @($gear | Where-Object { $_.Site -eq $g.Name })
    $siteFlags = @($flags | Where-Object { $_.Site -eq $g.Name })
    $high = @($siteFlags | Where-Object Severity -eq 'High').Count
    $med = @($siteFlags | Where-Object Severity -eq 'Medium').Count
    # A site whose data is incomplete is never shown green, even with no flags (a cut-off run has none).
    $status = if ($high -gt 0) { 'Red' } elseif ($med -gt 0 -or $cutOff.Count -or $badData.Count) { 'Amber' } else { 'Green' }
    $sites += [pscustomobject][ordered]@{
        Site = $g.Name; Status = $status; Endpoints = $eps.Count; Wired = $wired.Count; WiFi = $wifi.Count
        Verdict = $siteVerdict; PublicIPs = J $ips; Carrier = J ($eps | ForEach-Object { $_.Carrier } | Sort-Object -Unique); EgressCity = J ($eps | ForEach-Object { $_.EgressCity } | Sort-Object -Unique)
        CarrierName = J ($eps | ForEach-Object { "$($_.Carrier)" -replace '^AS\d+\s+', '' } | Where-Object { $_ } | Sort-Object -Unique)
        MedianDownMbps = Median ($eps | ForEach-Object { $_.DownMbps }); MaxDownMbps = MaxOf ($eps | ForEach-Object { $_.DownMbps })
        MedianUpMbps = Median ($eps | ForEach-Object { $_.UpMbps }); MaxUpMbps = MaxOf ($eps | ForEach-Object { $_.UpMbps })
        WiredMedianDown = $wiredDown; WifiMedianDown = $wifiDown
        CircuitDownMbps = MaxOf ($circuitSet | ForEach-Object { $_.DownMbps }); CircuitUpMbps = MaxOf ($circuitSet | ForEach-Object { $_.UpMbps }); CircuitBasis = $circuitBasis
        MedianIdleMs = $(if ($null -ne (Median ($eps | ForEach-Object { $_.IdleMs }))) { Median ($eps | ForEach-Object { $_.IdleMs }) } else { Median ($eps | ForEach-Object { $_.InetAvgMs }) })
        LatencyBasis = $(if ($null -ne (Median ($eps | ForEach-Object { $_.IdleMs }))) { 'idle' } elseif ($null -ne (Median ($eps | ForEach-Object { $_.InetAvgMs }))) { 'ping' } else { $null })
        PingSamples = MaxOf ($eps | ForEach-Object { $_.InetPingSent }); WorstBufferbloatMs = MaxOf ($eps | ForEach-Object { $_.BufferbloatMs })
        HostedMedianMs = Median ($eps | ForEach-Object { $_.HostedAvgMs }); HostedWorstLossPct = MaxOf ($eps | ForEach-Object { $_.HostedLossPct })
        RdpNetworkDrops = (@($eps | ForEach-Object { $_.RdpNetworkDisconnects } | Where-Object { $null -ne $_ -and "$_" -ne '' }) | Measure-Object -Sum).Sum
        DataChecks = J (@($eps | Group-Object DataCheck | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })) ', '
        WorstInetLossPct = MaxOf ($eps | ForEach-Object { $_.InetLossPct })
        GatewayVendors = J ($siteGear | Where-Object { $_.Type -like 'Gateway*' } | ForEach-Object { $_.Vendor } | Where-Object { $_ } | Sort-Object -Unique)
        FirewallModel = J (@($eps | ForEach-Object { $_.FirewallModel }) | Where-Object { $_ } | Sort-Object -Unique)
        FirewallHints = J (@($eps | ForEach-Object { $_.FirewallHints -split '; ' }) | Where-Object { $_ } | Sort-Object -Unique)
        VpnClientVendors = J (@($eps | ForEach-Object { $_.VpnClientVendor -split '; ' }) | Where-Object { $_ } | Sort-Object -Unique)
        ApVendors = J ($siteGear | Where-Object { $_.Type -like 'Access point*' } | ForEach-Object { $_.Vendor } | Where-Object { $_ } | Sort-Object -Unique)
        ApBssids = @($siteGear | Where-Object { $_.Type -like 'Access point*' } | ForEach-Object { $_.Mac } | Where-Object { $_ } | Sort-Object -Unique).Count
        Switches = J ($siteGear | Where-Object { $_.Type -like 'Switch*' } | ForEach-Object { $(if ($_.IP) { '{0} at {1}' -f $_.Name, $_.IP } else { $_.Name }) } | Sort-Object -Unique)
        Win10Count = @($eps | Where-Object { $_.IsWin10 -and $_.Role -ne 'Test laptop' }).Count
        HighFlags = $high; MediumFlags = $med
        KnownSubnets = $siteSubnets.Count; LocalSubnets = J $localSets ', '
        ExposedPorts = J (@($ips | ForEach-Object { $x = $exposure[$_]; if ($x -and $x.Listed) { "$($_): $(@($x.Ports) -join ' ')" } elseif ($x -and -not $x.Error) { "$($_): none listed" } }))
        Notes = J $notes
    }
}

$endpoints | Export-Csv (Join-Path $OutDir 'Endpoints.csv') -NoTypeInformation
$sites | Export-Csv (Join-Path $OutDir 'Sites.csv') -NoTypeInformation
$printers | Export-Csv (Join-Path $OutDir 'Printers.csv') -NoTypeInformation
$periph | Export-Csv (Join-Path $OutDir 'Peripherals.csv') -NoTypeInformation
$gear | Export-Csv (Join-Path $OutDir 'NetworkGear.csv') -NoTypeInformation
@($flags) + @($deviceFlags) | Export-Csv (Join-Path $OutDir 'Flags.csv') -NoTypeInformation
$software | Export-Csv (Join-Path $OutDir 'Software.csv') -NoTypeInformation
$traceRows | Export-Csv (Join-Path $OutDir 'Traceroutes.csv') -NoTypeInformation
$pingRows | Export-Csv (Join-Path $OutDir 'PingSeries.csv') -NoTypeInformation
$rdpRows | Export-Csv (Join-Path $OutDir 'RdpTargets.csv') -NoTypeInformation
$subnets | Export-Csv (Join-Path $OutDir 'Subnets.csv') -NoTypeInformation
$runFindings | Export-Csv (Join-Path $OutDir 'Findings.csv') -NoTypeInformation
# One row per device per site: the same address seen from two ports at one site is listed once.
$devices = @($devices | Group-Object { '{0}|{1}' -f $_.Site, $_.IP } | ForEach-Object { $_.Group | Sort-Object { @($_.Evidence -split ' \| ').Count } -Descending | Select-Object -First 1 })
$devices | Sort-Object Site, @{ Expression = { try { [version]$_.IP } catch { [version]'0.0' } } } | Export-Csv (Join-Path $OutDir 'Devices.csv') -NoTypeInformation
$ipOwnerRows | Export-Csv (Join-Path $OutDir 'IpOwners.csv') -NoTypeInformation

# ---------------------------------------------------------------------
# HTML building blocks
# ---------------------------------------------------------------------
function New-Table {
    # Sortable, searchable table. $Columns entries are 'Property' or 'Property|Header'.
    param($Rows, [string[]]$Columns)
    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 0) { return '<p class="muted">None.</p>' }
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('<div class="tw"><table class="data"><thead><tr>')
    foreach ($c in $Columns) { $hdr = ($c -split '\|')[-1]; [void]$sb.Append('<th>' + (Enc $hdr) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $prop = ($c -split '\|')[0]
            $v = V $r $prop
            if ($v -is [bool]) { $v = if ($v) { 'Yes' } else { 'No' } }
            if ($prop -eq 'Severity') { [void]$sb.Append(('<td><span class="sev sev-{0}">{0}</span></td>' -f (Enc $v))) }
            elseif ($prop -eq 'Status') { [void]$sb.Append(('<td><span class="dot dot-{0}"></span>{0}</td>' -f (Enc $v))) }
            elseif ("$v".Length -gt 40) { [void]$sb.Append('<td class="long">' + (Enc $v) + '</td>') }
            else { [void]$sb.Append('<td>' + (Enc $v) + '</td>') }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function New-KV {
    # Card grid of label/value pairs; pairs with empty values are skipped.
    param([object[]]$Pairs)
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('<div class="kv">')
    for ($i = 0; $i -lt $Pairs.Count; $i += 2) {
        $val = $Pairs[$i + 1]
        if ($val -is [bool]) { $val = if ($val) { 'Yes' } else { 'No' } }
        if ($null -eq $val -or "$val".Trim() -eq '') { continue }
        [void]$sb.Append('<div><b>' + (Enc $Pairs[$i]) + '</b><span>' + (Enc $val) + '</span></div>')
    }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

function New-Section {
    # Collapsible section; $Open renders it expanded. $Extra is ready-made HTML shown at the right of the title line.
    param([string]$Title, [string]$Body, [switch]$Open, [string]$Class = 'sec', [string]$Badge, [string]$Id, [string]$Extra)
    $o = if ($Open) { ' open' } else { '' }
    $i = if ($Id) { " id=""$Id""" } else { '' }
    $b = if ($Badge) { " <span class=""badge"">$(Enc $Badge)</span>" } else { '' }
    return "<details class=""$Class""$i$o><summary><span class=""s-title"">$(Enc $Title)</span>$b$Extra</summary><div class=""body"">$Body</div></details>"
}

function New-Panel {
    # Always-visible titled block.
    param([string]$Title, [string]$Body, [string]$Sub, [string]$Class)
    $s = if ($Sub) { "<span class=""p-sub"">$(Enc $Sub)</span>" } else { '' }
    return "<div class=""panel $Class""><div class=""p-head""><h4>$(Enc $Title)</h4>$s</div>$Body</div>"
}

function Num {
    # Number as text with a fixed decimal point, or $null when there is no value.
    param($Value, [int]$Digits = 1)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    return ([math]::Round([double]$Value, $Digits)).ToString([Globalization.CultureInfo]::InvariantCulture)
}

function NiceMax {
    # Rounds a chart maximum up to 1, 2 or 5 times a power of ten.
    param([double]$Value)
    if ($Value -le 0) { return 1 }
    $p = [math]::Pow(10, [math]::Floor([math]::Log10($Value)))
    foreach ($m in 1, 2, 5, 10) { if ($Value -le $m * $p) { return $m * $p } }
    return 10 * $p
}

function Get-RttState {
    # Microsoft's hosted-desktop guidance: under 150 ms fine, 150 to 200 acceptable, over 200 degraded.
    param($Ms)
    if ($null -eq $Ms -or "$Ms" -eq '') { return $null }
    $m = [double]$Ms
    if ($m -gt 200) { return @('Red', 'Over 200 ms: degraded') }
    if ($m -ge 150) { return @('Amber', '150 to 200 ms: acceptable for text work') }
    return @('Green', 'Under 150 ms: fine')
}

function Get-LossState {
    param($Pct)
    if ($null -eq $Pct -or "$Pct" -eq '') { return $null }
    $p = [double]$Pct
    if ($p -ge 5) { return @('Red', '5% or more: high') }
    if ($p -ge 1) { return @('Amber', '1% or more: noticeable') }
    return @('Green', 'Under 1%')
}

function New-StateTag {
    # Status dot plus words, so the state never depends on color alone.
    param($State)
    if (-not $State) { return '' }
    return "<span class=""t-state""><span class=""dot dot-$($State[0])""></span>$(Enc $State[1])</span>"
}

function New-Tile {
    # Headline number: label, value with unit, optional status and a line of context.
    param([string]$Label, $Value, [string]$Unit, [string]$Sub, [string]$Class, $State)
    $v = if ($null -eq $Value -or "$Value" -eq '') { '<span class="t-val t-na">n/a</span>' }
         else { '<span class="t-val">' + (Enc $Value) + $(if ($Unit) { '<small>' + (Enc $Unit) + '</small>' }) + '</span>' }
    $sub = if ($Sub) { '<span class="t-sub">' + (Enc $Sub) + '</span>' } else { '' }
    return "<div class=""tile $Class""><span class=""t-lbl"">$(Enc $Label)</span>$v$(New-StateTag $State)$sub</div>"
}

function Get-VerdictClass { param([string]$Verdict) if ($Verdict -like 'Local*') { 'v-local' } elseif ($Verdict -like 'Split*') { 'v-split' } elseif ($Verdict -like 'Unknown*') { 'v-unknown' } else { 'v-back' } }

function Get-ConnClass { param([string]$Connection) if ($Connection -like 'Wired*') { 'wired' } elseif ($Connection -eq 'Wi-Fi') { 'wifi' } else { 'other' } }

function New-BwBars {
    # Download and upload bars on one shared scale. $Items: Label, Chip, Down, Up, DownFail, UpFail, DownSrc, UpSrc.
    param($Items, [string]$SrcWord = 'via')
    $items = @($Items | Where-Object { $_ })
    $max = MaxOf (@($items | ForEach-Object { $_.Down; $_.Up }))
    if (-not $max) { return '<p class="muted">No bandwidth results.</p>' }
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('<div class="legend"><span><i class="sw sw-down"></i>Download</span><span><i class="sw sw-up"></i>Upload</span><span class="lg-note">Mbps, one scale for all bars</span></div><div class="bars">')
    foreach ($it in $items) {
        $chip = if ($it.Chip) { ' <span class="chip">' + (Enc $it.Chip) + '</span>' } else { '' }
        [void]$sb.Append('<div class="bar-host">' + (Enc $it.Label) + $chip + '</div>')
        foreach ($dir in @(@('Down', 'down', $it.Down, $it.DownFail, $it.DownSrc), @('Up', 'up', $it.Up, $it.UpFail, $it.UpSrc))) {
            if ($dir[3]) { [void]$sb.Append(('<div class="bar-row"><span class="bar-lbl">{0}</span><span class="bar-fail">Not measured: {1}</span></div>' -f $dir[0], (Enc $dir[3]))); continue }
            if ($null -eq $dir[2] -or "$($dir[2])" -eq '') { [void]$sb.Append(('<div class="bar-row"><span class="bar-lbl">{0}</span><span class="muted">no result</span></div>' -f $dir[0])); continue }
            $frac = [math]::Max(0.004, [math]::Round([double]$dir[2] / $max, 4)).ToString([Globalization.CultureInfo]::InvariantCulture)
            $src = if ($dir[4]) { " $SrcWord " + $dir[4] } else { '' }
            $tip = Enc ("{0}: {1}load {2} Mbps{3}" -f $it.Label, $dir[0], (Num $dir[2]), $src)
            [void]$sb.Append(('<div class="bar-row" data-tip="{0}"><span class="bar-lbl">{1}</span><div class="bar-track"><div class="bar {2}" style="width:calc((100% - 150px) * {3})"></div><span class="bar-val">{4} Mbps</span><span class="bar-src">{5}</span></div></div>' -f $tip, $dir[0], $dir[1], $frac, (Num $dir[2]), (Enc $dir[4])))
        }
    }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

function Get-HopClassLabel {
    param([string]$Class)
    switch ($Class) { 'Private' { 'Private (LAN or tunnel)' } 'CGNAT' { 'Carrier NAT' } 'Public' { 'Public internet' } 'Timeout' { 'No reply' } default { "Other ($Class)" } }
}

function Get-TraceKind {
    param([string]$Target)
    if ($Target -eq '1.1.1.1') { return 'Internet' }
    if ($Target -eq '8.8.8.8') { return 'Internet (second check)' }
    if (Test-Hosted $Target) { return $HostedLabel }
    return 'RDP target'
}

function Get-TraceFacts {
    # Plain numbers for one traceroute: hops that answered, trailing silent hops, last answer.
    param($Trace)
    $hops = @($Trace.Hops | Where-Object { $_ })
    $last = -1
    for ($i = 0; $i -lt $hops.Count; $i++) { if ($hops[$i].IP) { $last = $i } }
    $shown = if ($last -ge 0) { @($hops[0..$last]) } else { @() }
    $lastMs = $null
    foreach ($h in $shown) { if ($null -ne $h.AvgMs -and "$($h.AvgMs)" -ne '') { $lastMs = $h.AvgMs } }
    return [pscustomobject]@{ Hops = $hops; Shown = $shown; Silent = ($hops.Count - 1 - $last); LastHop = $(if ($last -ge 0) { $hops[$last].Hop }); LastMs = $lastMs
        Reached = [bool](V (V $Trace 'Analysis') 'ReachedTarget') }
}

function New-TraceChart {
    # One traceroute as a column per hop: height is the round trip to that hop, color is the kind of network.
    param($Trace, [string]$EndToEnd)
    $f = Get-TraceFacts $Trace
    $ScaleMax = [math]::Max(50, (NiceMax ([double](MaxOf (@($f.Shown | ForEach-Object { $_.AvgMs }) + 1)))))
    $an = V $Trace 'Analysis'
    $kind = Get-TraceKind "$($Trace.Target)"
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('<div class="tc"><div class="tc-head"><span class="tc-kind">' + (Enc $kind) + '</span><span class="tc-target">' + (Enc $Trace.Target) + '</span></div>')
    if ($f.Shown.Count -eq 0) { [void]$sb.Append('<p class="muted">No hop answered.</p></div>'); return $sb.ToString() }
    $lines = @()
    if ($f.Reached) { $lines += ('<b>{0} hops</b>, {1} ms at the destination' -f $f.LastHop, (Num $f.LastMs)) }
    else {
        $l = '<b>{0} hops answered</b> ({1} ms at the last one), then silent: the destination does not answer traceroute' -f $f.Shown.Count, (Num $f.LastMs)
        $lines += $l
    }
    if ($EndToEnd) { $lines += 'End to end: <b>' + (Enc $EndToEnd) + '</b>' }
    $fp = V $an 'FirstPublicHop'
    if ($fp) {
        $who = if (V $an 'FirstPublicPtr') { V $an 'FirstPublicPtr' } else { V $an 'FirstPublicIP' }
        $lines += 'Leaves the private network at hop {0}: {1}' -f $fp, (Enc $who)
    }
    $tun = @(V $an 'PrivateHopsAfterGw') | Where-Object { $_ }
    if ($tun.Count) { $lines += 'Private hops after the gateway: ' + (Enc ($tun -join ', ')) + ' (a tunnel or a second router)' }
    if ((V $an 'CgnatHops') -gt 0) { $lines += 'Carrier NAT in the path' }
    $nets = @()
    foreach ($h in $f.Shown) {
        $own = V $h 'Owner'
        if (-not $own) { continue }
        $nm = "$own" -replace '^AS\d+\s*', ''
        if (-not $nm) { $nm = "$own" }
        if ($nets.Count -and $nets[-1].Name -eq $nm) { $nets[-1].To = $h.Hop } else { $nets += [pscustomobject]@{ Name = $nm; From = $h.Hop; To = $h.Hop } }
    }
    if ($nets.Count) { $lines += 'Networks crossed: ' + (($nets | ForEach-Object { '{0} ({1})' -f (Enc $_.Name), $(if ($_.From -eq $_.To) { "hop $($_.From)" } else { "hops $($_.From) to $($_.To)" }) }) -join ', then ') }
    [void]$sb.Append('<ul class="tc-facts"><li>' + ($lines -join '</li><li>') + '</li></ul>')
    $plotH = 96
    [void]$sb.Append(('<div class="tc-plot"><div class="tc-y"><span>{0} ms</span><span>0</span></div><div class="tc-cols">' -f (Num $ScaleMax 0)))
    $n = $f.Shown.Count
    for ($i = 0; $i -lt $n; $i++) {
        $h = $f.Shown[$i]
        $cls = if ($h.Class -in @('Private', 'CGNAT', 'Public', 'Timeout')) { $h.Class } else { 'Other' }
        $hasMs = ($null -ne $h.AvgMs -and "$($h.AvgMs)" -ne '')
        $tipParts = @("Hop $($h.Hop)")
        if ($h.IP) { $tipParts += "$($h.IP)" }
        if ($h.Ptr) { $tipParts += "$($h.Ptr)" }
        if (V $h 'Owner') { $tipParts += "$(V $h 'Owner')" }
        if ((V $h 'RegisteredTo') -and "$(V $h 'Owner')" -notlike "*$(V $h 'RegisteredTo')*") { $tipParts += "registered to $(V $h 'RegisteredTo')" }
        $tipParts += $(if ($hasMs) { "$(Num $h.AvgMs) ms" } else { 'no reply' })
        $tipParts += (Get-HopClassLabel "$($h.Class)")
        $tip = ($tipParts | ForEach-Object { Enc $_ }) -join '&#10;'
        $px = if ($hasMs -and $ScaleMax -gt 0) { [math]::Max(2, [math]::Round($plotH * [double]$h.AvgMs / $ScaleMax)) } else { 0 }
        $lbl = if ($i -eq $n - 1 -and $hasMs) { '<span class="tc-v">' + (Num $h.AvgMs) + ' ms</span>' } else { '' }
        $bar = if ($cls -eq 'Timeout' -or -not $hasMs) { '<div class="tc-bar c-Timeout"></div>' } else { '<div class="tc-bar c-{0}" style="height:{1}px">{2}</div>' -f $cls, $px, $lbl }
        [void]$sb.Append(('<div class="tc-col" data-tip="{0}">{1}<span class="tc-n">{2}</span></div>' -f $tip, $bar, $h.Hop))
    }
    [void]$sb.Append('<div class="tc-end">' + $(if ($f.Silent -gt 0) { "+$($f.Silent) silent" }) + '</div>')
    [void]$sb.Append('</div></div>')
    [void]$sb.Append('<details class="mini"><summary>Hop table</summary><div class="body">' + (New-Table $f.Hops $(if ($ipInfo.Count) { @('Hop', 'IP', 'Class', 'AvgMs|Avg ms', 'Ptr|Reverse DNS', 'Owner|Network', 'RegisteredTo|Registered to') } else { @('Hop', 'IP', 'Class', 'AvgMs|Avg ms', 'Ptr|Reverse DNS') })) + '</div></details></div>')
    return $sb.ToString()
}

function Get-ShortDomain {
    # Last two labels of a reverse-DNS name, which usually name the carrier (carrier.example.net -> example.net).
    param([string]$Name)
    if (-not $Name) { return $null }
    $parts = @($Name.TrimEnd('.').Split('.'))
    if ($parts.Count -lt 2 -or $Name -match '^[\d\.]+$') { return $Name }
    return ($parts[($parts.Count - 2)..($parts.Count - 1)] -join '.')
}

$css = @'
:root { --bg:#f4f6f8; --card:#ffffff; --fg:#17202b; --muted:#5f6b7a; --line:#dde2e8; --head:#eef1f5; --accent:#1f5fa8;
  --red:#c0352b; --amber:#a86200; --green:#1f7a43; --chip:#e9eef4; --shadow:0 1px 2px rgba(16,24,40,.06);
  --s-down:#2a78d6; --s-up:#eb6834; --h-pub:#2a78d6; --h-cgn:#1baf7a; --h-priv:#8a93a0; }
@media (prefers-color-scheme: dark) { :root { --bg:#101317; --card:#181c22; --fg:#e4e9ef; --muted:#97a3b1; --line:#2a313a; --head:#1f252d; --accent:#6aa7ec;
  --red:#f0705f; --amber:#f2b03c; --green:#4cc27b; --chip:#242b34; --shadow:none;
  --s-down:#3987e5; --s-up:#d95926; --h-pub:#3987e5; --h-cgn:#199e70; --h-priv:#6f7a88; } }
* { box-sizing:border-box; }
html { scroll-padding-top:104px; }
body { background:var(--bg); color:var(--fg); font:14px/1.5 "Segoe UI", system-ui, Arial, sans-serif; margin:0; }
a { color:var(--accent); }
header.top { position:sticky; top:0; z-index:5; background:var(--card); border-bottom:1px solid var(--line); padding:10px 20px 8px; }
.top-row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; max-width:1320px; margin:0 auto; }
header.top h1 { font-size:18px; margin:0 12px 0 0; }
header.top .meta { color:var(--muted); font-size:12.5px; margin-right:auto; }
header.top input { padding:6px 10px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); min-width:220px; }
header.top button { padding:6px 10px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); cursor:pointer; }
nav.jump { display:flex; flex-wrap:wrap; gap:6px; max-width:1320px; margin:8px auto 0; }
nav.jump a { text-decoration:none; color:var(--fg); font-size:12.5px; font-weight:600; padding:3px 10px; border:1px solid var(--line); border-radius:14px; background:var(--bg); }
nav.jump a:hover { border-color:var(--accent); color:var(--accent); }
main { max-width:1320px; margin:0 auto; padding:8px 20px 40px; }
h2 { font-size:19px; margin:30px 0 12px; }
h4 { font-size:13.5px; margin:14px 0 6px; }
.muted { color:var(--muted); }
.lead { color:var(--muted); margin:-6px 0 12px; max-width:80ch; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; background:var(--chip); vertical-align:middle; }
.chip { font-size:11px; font-weight:600; padding:1px 7px; border-radius:9px; background:var(--chip); color:var(--muted); white-space:nowrap; }
.v-local { color:var(--green); } .v-split { color:var(--amber); } .v-back { color:var(--red); } .v-unknown { color:var(--muted); }
.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; background:var(--muted); flex:none; }
.dot-Red { background:var(--red); } .dot-Amber { background:var(--amber); } .dot-Green { background:var(--green); }
.pill { display:inline-flex; align-items:center; font-size:12px; font-weight:600; padding:2px 10px 2px 8px; border-radius:12px; border:1px solid var(--line); background:var(--card); white-space:nowrap; }

/* Overview: one card per site */
.scards { display:grid; grid-template-columns:repeat(auto-fill, minmax(330px, 1fr)); gap:14px; }
a.scard { display:block; text-decoration:none; color:inherit; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; box-shadow:var(--shadow); border-top:4px solid var(--muted); }
a.scard:hover { border-color:var(--accent); }
a.scard.Red { border-top-color:var(--red); } a.scard.Amber { border-top-color:var(--amber); } a.scard.Green { border-top-color:var(--green); }
.sc-head { display:flex; align-items:center; justify-content:space-between; gap:8px; }
.sc-head h3 { margin:0; font-size:16px; }
.sc-sub { color:var(--muted); font-size:12.5px; margin:2px 0 10px; }
.sc-nums { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:10px; }
.sc-num { border-left:4px solid var(--s-down); padding-left:10px; } .sc-num.up { border-left-color:var(--s-up); }
.sc-num span { display:block; font-size:12px; color:var(--muted); font-weight:600; }
.sc-num b { font-size:30px; line-height:1.1; font-weight:650; font-variant-numeric:tabular-nums; } .sc-num b small { font-size:13px; color:var(--muted); font-weight:600; margin-left:4px; }
.sc-row { display:flex; justify-content:space-between; gap:10px; font-size:13px; padding:3px 0; border-top:1px solid var(--line); }
.sc-row > span:first-child { color:var(--muted); flex:none; } .sc-row > span:last-child { text-align:right; }

/* Headline tiles */
.hero { display:grid; grid-template-columns:repeat(12, 1fr); gap:12px; margin:4px 0 14px; }
.tile { grid-column:span 3; background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 14px; display:flex; flex-direction:column; gap:2px; min-width:0; box-shadow:var(--shadow); }
.tile.big { grid-column:span 6; padding:16px 18px; border-top:4px solid var(--s-down); } .tile.big.up { border-top-color:var(--s-up); }
.t-lbl { font-size:12.5px; color:var(--muted); font-weight:600; }
.t-val { font-size:26px; font-weight:650; line-height:1.15; font-variant-numeric:tabular-nums; } .t-val small { font-size:.5em; color:var(--muted); font-weight:600; margin-left:5px; }
.tile.big .t-val { font-size:48px; } .tile.big .t-val small { font-size:.36em; }
.t-na { color:var(--muted); }
.t-state { display:inline-flex; align-items:center; font-size:12.5px; font-weight:600; }
.t-sub { font-size:12.5px; color:var(--muted); overflow-wrap:anywhere; }
.note { border:1px solid var(--line); border-left:4px solid var(--amber); background:var(--card); border-radius:8px; padding:8px 12px; margin:0 0 14px; }
.note ul { margin:4px 0 0 18px; padding:0; }

/* Panels */
.grid2 { display:grid; grid-template-columns:repeat(auto-fit, minmax(440px, 1fr)); gap:14px; margin-bottom:14px; }
.panel { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 16px 14px; min-width:0; box-shadow:var(--shadow); margin-bottom:14px; }
.grid2 > .panel { margin-bottom:0; }
.p-head { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; margin-bottom:6px; } .p-head h4 { margin:0; font-size:15px; } .p-sub { color:var(--muted); font-size:12.5px; }
.legend { display:flex; flex-wrap:wrap; gap:14px; font-size:12.5px; margin:2px 0 8px; align-items:center; } .legend > span { display:inline-flex; align-items:center; }
.sw { display:inline-block; width:12px; height:12px; border-radius:3px; margin-right:6px; }
.sw-down { background:var(--s-down); } .sw-up { background:var(--s-up); } .sw-pub { background:var(--h-pub); } .sw-cgn { background:var(--h-cgn); } .sw-priv { background:var(--h-priv); }
.sw-none { border:1px solid var(--muted); background:transparent; height:6px; }
.lg-note { color:var(--muted); }

/* Bandwidth bars */
.bars { margin:4px 0 4px; } .bar-host { font-weight:600; margin-top:10px; }
.bar-row { display:flex; align-items:center; gap:8px; margin:3px 0; } .bar-lbl { width:42px; color:var(--muted); font-size:12px; flex:none; }
.bar-track { flex:1; display:flex; align-items:center; gap:8px; min-width:0; }
.bar { height:14px; border-radius:0 4px 4px 0; flex:none; } .bar.down { background:var(--s-down); } .bar.up { background:var(--s-up); }
.bar-val { font-variant-numeric:tabular-nums; font-size:12.5px; font-weight:600; white-space:nowrap; }
.bar-src { color:var(--muted); font-size:11.5px; white-space:nowrap; } .bar-fail { color:var(--red); font-size:12.5px; }

/* Round trip by site */
.rtt-row { display:flex; align-items:center; gap:10px; margin:5px 0; } .rtt-lbl { width:130px; flex:none; font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.rtt-track { position:relative; flex:1; height:18px; min-width:0; } .rtt-track .bar { position:absolute; left:0; top:2px; }
.rtt-track .gl { position:absolute; top:-5px; bottom:-5px; width:1px; background:var(--line); }
.rtt-axis .rtt-track { height:14px; } .rtt-axis .tick { position:absolute; top:0; transform:translateX(-50%); font-size:11.5px; color:var(--muted); white-space:nowrap; }
.rtt-val { width:170px; flex:none; font-size:12.5px; display:flex; gap:8px; align-items:center; } .rtt-val b { font-variant-numeric:tabular-nums; }

/* Traceroute charts */
.mach { border-top:1px solid var(--line); padding-top:10px; margin-top:10px; } .mach:first-of-type { border-top:0; margin-top:0; padding-top:0; }
.mach-h { font-weight:600; margin-bottom:6px; }
.tc-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(400px, 1fr)); gap:12px; }
.tc { border:1px solid var(--line); border-radius:8px; padding:10px 12px; background:var(--bg); min-width:0; }
.tc-head { display:flex; align-items:baseline; gap:8px; flex-wrap:wrap; } .tc-kind { font-weight:650; font-size:14px; } .tc-target { color:var(--muted); font-size:12.5px; overflow-wrap:anywhere; }
ul.tc-facts { margin:4px 0 8px 16px; padding:0; font-size:12.5px; } ul.tc-facts li { margin:1px 0; overflow-wrap:anywhere; }
.tc-plot { display:flex; gap:6px; align-items:stretch; overflow-x:auto; padding-top:18px; }
.tc-y { display:flex; flex-direction:column; justify-content:space-between; font-size:11px; color:var(--muted); height:96px; text-align:right; flex:none; min-width:44px; }
.tc-cols { display:flex; align-items:flex-end; gap:2px; border-bottom:1px solid var(--line); height:96px; margin-bottom:18px; position:relative; background:linear-gradient(var(--line), var(--line)) top / 100% 1px no-repeat; }
.tc-col { position:relative; width:18px; flex:none; display:flex; flex-direction:column; justify-content:flex-end; align-items:center; height:100%; }
.tc-col:hover { background:var(--head); }
.tc-bar { width:100%; border-radius:4px 4px 0 0; position:relative; }
.c-Public { background:var(--h-pub); } .c-CGNAT { background:var(--h-cgn); } .c-Private, .c-Other { background:var(--h-priv); }
.c-Timeout { height:6px; border:1px solid var(--muted); border-bottom:0; background:transparent; border-radius:3px 3px 0 0; }
.tc-n { position:absolute; bottom:-17px; font-size:10.5px; color:var(--muted); }
.tc-v { position:absolute; left:100%; top:-5px; margin-left:4px; white-space:nowrap; font-size:11.5px; font-weight:600; font-variant-numeric:tabular-nums; }
.tc-end { align-self:flex-end; font-size:11px; color:var(--muted); white-space:nowrap; padding-left:60px; min-height:1px; }

/* Collapsible sections */
details { background:var(--card); border:1px solid var(--line); border-radius:10px; margin:10px 0; }
details > summary { cursor:pointer; padding:10px 14px; font-weight:600; list-style:none; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
details > summary::-webkit-details-marker { display:none; }
details > summary::before { content:'+'; display:inline-block; width:14px; color:var(--muted); flex:none; }
details[open] > summary::before { content:'-'; }
details > .body { padding:4px 14px 14px; }
details.site { border:0; background:transparent; margin:26px 0; }
details.site > summary { font-size:19px; padding:10px 0; border-bottom:2px solid var(--line); margin-bottom:12px; }
details.site > summary .s-right { margin-left:auto; font-size:12.5px; font-weight:400; color:var(--muted); display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
details.site > .body { padding:0; }
details.ep > summary .s-right { margin-left:auto; font-size:12.5px; font-weight:400; color:var(--muted); }
details.mini { margin:6px 0 0; border-radius:6px; background:var(--card); } details.mini > summary { padding:4px 10px; font-size:12px; font-weight:600; color:var(--muted); } details.mini > .body { padding:0 10px 8px; }
.kv { display:grid; grid-template-columns:repeat(auto-fill, minmax(210px, 1fr)); gap:8px; margin:6px 0 12px; }
.kv div { border:1px solid var(--line); border-radius:8px; padding:7px 10px; background:var(--card); overflow-wrap:anywhere; } .kv b { display:block; font-size:11.5px; color:var(--muted); font-weight:600; }
.stats { display:grid; grid-template-columns:repeat(auto-fill, minmax(150px, 1fr)); gap:10px; margin-bottom:14px; }
.stat { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 12px; box-shadow:var(--shadow); } .stat b { display:block; font-size:24px; font-variant-numeric:tabular-nums; } .stat span { color:var(--muted); font-size:12.5px; }
.tw { overflow-x:auto; margin:6px 0 12px; }
table.data { border-collapse:collapse; width:100%; font-size:12.5px; }
table.data th, table.data td { border-bottom:1px solid var(--line); padding:5px 8px; text-align:left; vertical-align:top; }
table.data td.long { min-width:240px; }
table.data th { background:var(--head); white-space:nowrap; cursor:pointer; position:sticky; top:0; user-select:none; }
table.data th.asc::after { content:' ^'; } table.data th.desc::after { content:' v'; }
.sev { font-weight:600; } .sev-High { color:var(--red); } .sev-Medium { color:var(--amber); } .sev-Low { color:var(--muted); }
ul.ev { margin:4px 0 12px 18px; padding:0; } ul.ev li { margin:2px 0; }
pre { background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:10px; overflow:auto; max-height:520px; font-size:12px; line-height:1.4; }
.hidden-row { display:none; }
.tip { position:fixed; z-index:20; display:none; pointer-events:none; background:var(--fg); color:var(--bg); font-size:12px; line-height:1.4; padding:6px 9px; border-radius:6px; white-space:pre-line; max-width:340px; overflow-wrap:anywhere; }
@media print { header.top input, header.top button, nav.jump { display:none; } header.top { position:static; } details, .panel, .tile, .tc { break-inside:avoid; } pre { max-height:none; } .tip { display:none !important; } }
@media (max-width:900px) { header.top { position:static; } html { scroll-padding-top:8px; } .tile { grid-column:span 6; } .tile.big { grid-column:span 6; } .tile.big .t-val { font-size:36px; } .rtt-val { width:auto; flex-wrap:wrap; } .rtt-lbl { width:110px; } }
@media (max-width:560px) { header.top input { min-width:0; width:100%; } .tile, .tile.big { grid-column:span 12; } .grid2, .tc-grid { grid-template-columns:1fr; } main { padding:8px 12px 30px; } }
'@

$js = @'
(function () {
  function all(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }
  document.getElementById('expandAll').onclick = function () { all('details').forEach(function (d) { d.open = true; }); };
  document.getElementById('collapseAll').onclick = function () { all('details').forEach(function (d) { if (!d.classList.contains('site')) { d.open = false; } }); };
  window.addEventListener('beforeprint', function () { all('details').forEach(function (d) { d.dataset.wasOpen = d.open ? '1' : '0'; d.open = true; }); });
  window.addEventListener('afterprint', function () { all('details').forEach(function (d) { if (d.dataset.wasOpen === '0') { d.open = false; } }); });
  function openHash() {
    var id = location.hash.slice(1); if (!id) { return; }
    var el = document.getElementById(id); if (!el) { return; }
    for (var d = el; d; d = d.parentElement) { if (d.tagName === 'DETAILS') { d.open = true; } }
    el.scrollIntoView();
  }
  window.addEventListener('hashchange', openHash); openHash();
  var box = document.getElementById('search');
  box.addEventListener('input', function () {
    var q = box.value.trim().toLowerCase();
    all('table.data tbody tr').forEach(function (tr) { tr.classList.toggle('hidden-row', q !== '' && tr.textContent.toLowerCase().indexOf(q) < 0); });
    if (q !== '') { all('details').forEach(function (d) { if (d.textContent.toLowerCase().indexOf(q) >= 0) { d.open = true; } }); }
  });
  all('table.data th').forEach(function (th) {
    th.addEventListener('click', function () {
      var table = th.closest('table'), tbody = table.tBodies[0], idx = Array.prototype.indexOf.call(th.parentNode.children, th);
      var asc = !th.classList.contains('asc');
      Array.prototype.forEach.call(th.parentNode.children, function (o) { o.classList.remove('asc', 'desc'); });
      th.classList.add(asc ? 'asc' : 'desc');
      var rows = Array.prototype.slice.call(tbody.rows);
      rows.sort(function (a, b) {
        var x = a.cells[idx].textContent.trim(), y = b.cells[idx].textContent.trim();
        var nx = parseFloat(x), ny = parseFloat(y);
        var r = (!isNaN(nx) && !isNaN(ny) && /^-?[\d.]+/.test(x) && /^-?[\d.]+/.test(y)) ? nx - ny : x.localeCompare(y, undefined, { numeric: true });
        return asc ? r : -r;
      });
      rows.forEach(function (r) { tbody.appendChild(r); });
    });
  });
  var tip = document.createElement('div'); tip.className = 'tip'; document.body.appendChild(tip);
  document.addEventListener('mouseover', function (ev) {
    var el = ev.target.closest ? ev.target.closest('[data-tip]') : null;
    if (!el) { tip.style.display = 'none'; return; }
    tip.textContent = el.getAttribute('data-tip'); tip.style.display = 'block';
  });
  document.addEventListener('mousemove', function (ev) {
    if (tip.style.display !== 'block') { return; }
    var x = ev.clientX + 14, y = ev.clientY + 14, w = tip.offsetWidth, h = tip.offsetHeight;
    if (x + w > window.innerWidth - 8) { x = ev.clientX - w - 14; }
    if (y + h > window.innerHeight - 8) { y = ev.clientY - h - 14; }
    tip.style.left = Math.max(4, x) + 'px'; tip.style.top = Math.max(4, y) + 'px';
  });
})();
'@

# ---------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------
$sb = New-Object Text.StringBuilder
$gen = Get-Date -Format 'yyyy-MM-dd HH:mm'

# Per-site numbers the page leads with (circuit basis machine, worst loss, reference path).
$siteView = @{}
$siteIdx = 0
foreach ($s in $sites) {
    $eps = @($endpoints | Where-Object Site -eq $s.Site)
    $siteRuns = @($runs | Where-Object { $siteDisplay[$_._SiteKey] -eq $s.Site })
    $wiredEps = @($eps | Where-Object { "$($_.Connection)" -like 'Wired*' -and $null -ne $_.DownMbps -and "$($_.DownMbps)" -ne '' })
    $set = if ($wiredEps.Count) { $wiredEps } else { $eps }
    $downEp = $set | Where-Object { $null -ne $_.DownMbps -and "$($_.DownMbps)" -ne '' } | Sort-Object { [double]$_.DownMbps } -Descending | Select-Object -First 1
    $upEp = $set | Where-Object { $null -ne $_.UpMbps -and "$($_.UpMbps)" -ne '' } | Sort-Object { [double]$_.UpMbps } -Descending | Select-Object -First 1
    $refEp = if ($downEp) { $downEp } else { $eps | Select-Object -First 1 }
    $refRun = $siteRuns | Where-Object { $_._Label -eq $refEp.Hostname } | Select-Object -First 1
    $refTrace = @($refRun.Traceroutes) | Where-Object { $_ -and $_.Target -eq '1.1.1.1' } | Select-Object -First 1
    $avTrace = @($refRun.Traceroutes) | Where-Object { $_ -and (Test-Hosted $_.Target) } | Select-Object -First 1
    $high = [int]$s.HighFlags; $med = [int]$s.MediumFlags
    $pill = if ($high) { "$high high finding$(if ($high -ne 1) { 's' })" }
            elseif ("$($s.DataChecks)" -match 'INCOMPLETE|FAIL') { 'Data incomplete' }
            elseif ($med) { "$med medium finding$(if ($med -ne 1) { 's' })" }
            else { 'No findings' }
    $siteView[$s.Site] = [pscustomobject]@{
        Id = "site-$siteIdx"; Eps = $eps; Runs = $siteRuns; DownEp = $downEp; UpEp = $upEp; RefEp = $refEp
        RefTrace = $refTrace; RefFacts = $(if ($refTrace) { Get-TraceFacts $refTrace }); AvTrace = $avTrace; AvFacts = $(if ($avTrace) { Get-TraceFacts $avTrace })
        WorstLoss = MaxOf ($eps | ForEach-Object { $_.InetLossPct }); Pill = $pill
    }
    $siteIdx++
}

[void]$sb.Append("<!doctype html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>$(Enc $ClientName) - Site Assessment</title><style>$css</style></head><body>")
[void]$sb.Append("<header class=""top""><div class=""top-row""><h1>$(Enc $ClientName)</h1><span class=""meta"">Site assessment - $($sites.Count) site(s), $($endpoints.Count) endpoint(s) - generated $gen</span><input id=""search"" type=""search"" placeholder=""Search all tables...""><button id=""expandAll"" type=""button"">Expand all</button><button id=""collapseAll"" type=""button"">Collapse all</button></div>")
[void]$sb.Append('<nav class="jump"><a href="#overview">Overview</a>')
foreach ($s in $sites) { [void]$sb.Append(('<a href="#{0}">{1}</a>' -f $siteView[$s.Site].Id, (Enc $s.Site))) }
if ($ipInfo.Count) { [void]$sb.Append('<a href="#addresses">Addresses</a>') }
[void]$sb.Append('<a href="#fleet">Fleet</a><a href="#method">Methodology</a></nav></header><main>')

# ---- Overview: one card per site, bandwidth first
[void]$sb.Append('<h2 id="overview">Overview</h2><div class="scards">')
foreach ($s in $sites) {
    $sv = $siteView[$s.Site]
    $down = if ($null -ne $s.CircuitDownMbps) { Num $s.CircuitDownMbps } else { 'n/a' }
    $up = if ($null -ne $s.CircuitUpMbps) { Num $s.CircuitUpMbps } else { 'n/a' }
    $carrier = if ($s.CarrierName) { $s.CarrierName } else { 'carrier not identified' }
    [void]$sb.Append(("<a class=""scard {0}"" href=""#{1}""><div class=""sc-head""><h3>{2}</h3><span class=""pill""><span class=""dot dot-{0}""></span>{3}</span></div>" -f $s.Status, $sv.Id, (Enc $s.Site), (Enc $sv.Pill)))
    [void]$sb.Append(("<div class=""sc-sub"">{0} - <span class=""{1}"" style=""font-weight:600"">{2}</span></div>" -f (Enc $carrier), (Get-VerdictClass $s.Verdict), (Enc $s.Verdict)))
    [void]$sb.Append(("<div class=""sc-nums""><div class=""sc-num""><span>Download</span><b>{0}<small>Mbps</small></b></div><div class=""sc-num up""><span>Upload</span><b>{1}<small>Mbps</small></b></div></div>" -f $down, $up))
    $avState = Get-RttState $s.HostedMedianMs
    $avWord = if ($avState) { @{ Green = 'fine'; Amber = 'acceptable'; Red = 'degraded' }[$avState[0]] } else { $null }
    $av = if ($avState) { "$(Num $s.HostedMedianMs) ms ($avWord), worst loss $($s.HostedWorstLossPct)%" } else { 'not measured' }
    $avDot = if ($avState) { "<span class=""dot dot-$($avState[0])""></span>" } else { '' }
    [void]$sb.Append(("<div class=""sc-row""><span>Round trip to $(Enc $HostedLabel)</span><span>{0}{1}</span></div>" -f $avDot, (Enc $av)))
    $path = if ($sv.RefFacts) { "$($sv.RefFacts.Shown.Count) hops to the internet" + $(if ($sv.AvFacts) { ", $($sv.AvFacts.Shown.Count)$(if (-not $sv.AvFacts.Reached) { '+' }) to $HostedLabel" }) } else { 'no traceroute' }
    [void]$sb.Append(("<div class=""sc-row""><span>Path</span><span>{0}</span></div>" -f (Enc $path)))
    $lat = if ($null -ne $s.MedianIdleMs -and "$($s.MedianIdleMs)" -ne '') { "$($s.MedianIdleMs) ms $(if ($s.LatencyBasis -eq 'ping') { 'ping to 1.1.1.1' } else { 'idle' })" } else { 'n/a' }
    $bb = if ($null -ne $s.WorstBufferbloatMs -and "$($s.WorstBufferbloatMs)" -ne '') { ", +$($s.WorstBufferbloatMs) ms under load" } else { '' }
    [void]$sb.Append(("<div class=""sc-row""><span>Internet latency</span><span>{0}</span></div>" -f (Enc "$lat$bb")))
    [void]$sb.Append(("<div class=""sc-row""><span>Circuit basis</span><span>{0}</span></div>" -f (Enc $s.CircuitBasis)))
    [void]$sb.Append(("<div class=""sc-row""><span>Machines tested</span><span>{0} ({1} wired, {2} Wi-Fi)</span></div>" -f $s.Endpoints, $s.Wired, $s.WiFi))
    [void]$sb.Append(("<div class=""sc-row""><span>Data check</span><span>{0}</span></div></a>" -f (Enc $s.DataChecks)))
}
[void]$sb.Append('</div>')

if ($sites.Count -gt 1) {
    $bwItems = @($sites | ForEach-Object { [pscustomobject]@{ Label = $_.Site; Chip = $_.CircuitBasis; Down = $_.CircuitDownMbps; Up = $_.CircuitUpMbps; DownSrc = $siteView[$_.Site].DownEp.Hostname; UpSrc = $siteView[$_.Site].UpEp.Hostname } })
    $rttMax = [math]::Max(250, (NiceMax ([double](MaxOf (@($sites | ForEach-Object { $_.HostedMedianMs }) + 1)))))
    $rtt = New-Object Text.StringBuilder
    $p150 = (Num (100 * 150 / $rttMax) 2); $p200 = (Num (100 * 200 / $rttMax) 2)
    [void]$rtt.Append(('<div class="rtt"><div class="rtt-row rtt-axis"><span class="rtt-lbl"></span><div class="rtt-track"><span class="tick" style="left:{0}%">150</span><span class="tick" style="left:{1}%">200</span></div><span class="rtt-val"></span></div>' -f $p150, $p200))
    foreach ($s in $sites) {
        $ms = $s.HostedMedianMs
        $has = ($null -ne $ms -and "$ms" -ne '')
        $w = if ($has) { Num ([math]::Max(0.5, 100 * [double]$ms / $rttMax)) 2 } else { '0' }
        $st = Get-RttState $ms
        $valHtml = if ($has) { '<b>' + (Num $ms) + ' ms</b>' + (New-StateTag @($st[0], @{ Green = 'fine'; Amber = 'acceptable'; Red = 'degraded' }[$st[0]])) } else { '<span class="muted">not measured</span>' }
        $tip = Enc ("{0}: median round trip to $HostedLabel {1} ms, worst loss {2}%" -f $s.Site, (Num $ms), $s.HostedWorstLossPct)
        [void]$rtt.Append(('<div class="rtt-row" data-tip="{0}"><span class="rtt-lbl">{1}</span><div class="rtt-track"><i class="gl" style="left:{2}%"></i><i class="gl" style="left:{3}%"></i><div class="bar down" style="width:{4}%"></div></div><span class="rtt-val">{5}</span></div>' -f $tip, (Enc $s.Site), $p150, $p200, $w, $valHtml))
    }
    [void]$rtt.Append('</div>')
    [void]$sb.Append('<h2>Compare sites</h2><div class="grid2">')
    [void]$sb.Append((New-Panel 'Circuit bandwidth by site' (New-BwBars $bwItems -SrcWord 'from') 'Best wired result per site; the machine it came from is named after each bar'))
    [void]$sb.Append((New-Panel "Round trip to $HostedLabel by site" $rtt.ToString() 'Median across machines, in ms. Under 150 is fine, over 200 degrades the session.'))
    [void]$sb.Append('</div>')
}

$topHigh = @($flags | Where-Object Severity -eq 'High' | Sort-Object Site, Hostname | Select-Object -First 12)
[void]$sb.Append('<h2>Key findings</h2>')
if ($topHigh.Count) { [void]$sb.Append((New-Table $topHigh @('Site', 'Hostname|Machine', 'Category', 'Message|Finding'))) }
else { [void]$sb.Append('<p class="muted">No high-severity findings.</p>') }

if ($sites.Count -ge 2) { [void]$sb.Append((New-Section 'Site comparison table (every site-level figure)' (New-Table $sites @('Status', 'Site', 'Endpoints', 'Wired', 'WiFi|Wi-Fi', 'Verdict', 'CarrierName|Carrier', 'PublicIPs|Public IP', 'CircuitDownMbps|Circuit down', 'CircuitUpMbps|Circuit up', 'CircuitBasis|Circuit basis', 'WifiMedianDown|Wi-Fi down (median)', 'MedianIdleMs|Latency ms', 'WorstBufferbloatMs|Bufferbloat ms', 'WorstInetLossPct|Loss %', "HostedMedianMs|$HostedLabel ms", "HostedWorstLossPct|$HostedLabel loss %", 'RdpNetworkDrops|RDP network drops (30d)', 'DataChecks|Data check', 'FirewallModel|Firewall', 'GatewayVendors|Gateway MAC vendor', 'FirewallHints|Firewall (admin ports)', 'VpnClientVendors|VPN client vendor', 'ApVendors|AP vendors', 'KnownSubnets|Subnets', 'Win10Count|Win10', 'Notes')) -Open:($sites.Count -gt 1))) }

# ---- Per site: bandwidth and path first, then everything else
foreach ($s in $sites) {
    $name = $s.Site
    $sv = $siteView[$name]
    $eps = $sv.Eps
    $siteRuns = $sv.Runs
    $body = New-Object Text.StringBuilder

    # Headline tiles
    $downSub = if ($sv.DownEp) { "$($s.CircuitBasis): $($sv.DownEp.Hostname) ($($sv.DownEp.Connection)) via $($sv.DownEp.DownProvider)" } else { 'not measured' }
    $upSub = if ($sv.UpEp) { "$($s.CircuitBasis): $($sv.UpEp.Hostname) ($($sv.UpEp.Connection)) via $($sv.UpEp.UpProvider)" } else { 'not measured' }
    $avSub = if ($null -ne $s.HostedMedianMs -and "$($s.HostedMedianMs)" -ne '') { "median of $(@($eps | Where-Object { $null -ne $_.HostedAvgMs -and "$($_.HostedAvgMs)" -ne '' }).Count) machine(s), worst loss $($s.HostedWorstLossPct)%" } else { "no $HostedLabel host answered" }
    $latBasis = if ($s.LatencyBasis -eq 'ping') { 'ping to 1.1.1.1, median (no bandwidth test)' } else { 'idle, median' }
    $latSub = if ($null -ne $s.WorstBufferbloatMs -and "$($s.WorstBufferbloatMs)" -ne '') { "$latBasis; worst rise under load +$($s.WorstBufferbloatMs) ms" } else { $latBasis }
    $pathVal = $null; $pathSub = 'no traceroute to 1.1.1.1'
    if ($sv.RefFacts -and $sv.RefFacts.Shown.Count) {
        $pathVal = $sv.RefFacts.Shown.Count
        $an = V $sv.RefTrace 'Analysis'
        $who = Get-ShortDomain "$(if (V $an 'FirstPublicPtr') { V $an 'FirstPublicPtr' } else { V $an 'FirstPublicIP' })"
        $pathSub = "to 1.1.1.1 from $($sv.RefEp.Hostname)" + $(if (V $an 'FirstPublicHop') { "; leaves the private network at hop $(V $an 'FirstPublicHop') ($who)" })
    }
    [void]$body.Append('<div class="hero">')
    [void]$body.Append((New-Tile 'Download' (Num $s.CircuitDownMbps) 'Mbps' $downSub 'big'))
    [void]$body.Append((New-Tile 'Upload' (Num $s.CircuitUpMbps) 'Mbps' $upSub 'big up'))
    [void]$body.Append((New-Tile "Round trip to $HostedLabel" (Num $s.HostedMedianMs) 'ms' $avSub '' (Get-RttState $s.HostedMedianMs)))
    [void]$body.Append((New-Tile 'Internet latency' (Num $s.MedianIdleMs) 'ms' $latSub))
    [void]$body.Append((New-Tile 'Packet loss to the internet' (Num $sv.WorstLoss) '%' "worst machine, $(if ($s.PingSamples) { $s.PingSamples } else { 'the' }) pings to 1.1.1.1" '' (Get-LossState $sv.WorstLoss)))
    [void]$body.Append((New-Tile 'Hops to the internet' $pathVal '' $pathSub))
    [void]$body.Append('</div>')
    if ($s.Notes) {
        [void]$body.Append('<div class="note"><b>Notes for this site</b><ul>')
        foreach ($nt in ($s.Notes -split '; ')) { if ($nt) { [void]$body.Append('<li>' + (Enc $nt) + '</li>') } }
        [void]$body.Append('</ul></div>')
    }

    # Bandwidth by machine + latency and loss
    $bwItems = @($eps | ForEach-Object { [pscustomobject]@{ Label = $_.Hostname; Chip = $_.Connection; Down = $_.DownMbps; Up = $_.UpMbps; DownFail = $_.DownloadFailure; UpFail = $_.UploadFailure; DownSrc = $_.DownProvider; UpSrc = $_.UpProvider } })
    [void]$body.Append('<div class="grid2">')
    [void]$body.Append((New-Panel 'Bandwidth by machine' (New-BwBars $bwItems) '10 seconds per direction; the test service is named after each bar'))
    [void]$body.Append((New-Panel 'Latency and loss' (New-Table ($pingRows | Where-Object Site -eq $name) @('Hostname|Machine', 'Target', 'LossPct|Loss %', 'AvgMs|Avg ms', 'P95Ms|p95 ms', 'MaxMs|Max ms', 'JitterMs|Jitter ms')) "$(if ($s.PingSamples) { "$($s.PingSamples) samples, one per second," } else { 'One sample per second' }) per target"))
    [void]$body.Append('</div>')

    # Traceroutes: internet and hosted desktop per machine as charts, the rest one click away
    $tr = New-Object Text.StringBuilder
    [void]$tr.Append('<div class="legend"><span><i class="sw sw-priv"></i>Private (LAN or tunnel)</span><span><i class="sw sw-cgn"></i>Carrier NAT</span><span><i class="sw sw-pub"></i>Public internet</span><span><i class="sw sw-none"></i>No reply</span><span class="lg-note">One column per hop; height is the round trip to that hop. Each chart has its own scale, shown at its left. Hover a column for its address.</span></div>')
    foreach ($rr in $siteRuns) {
        $traces = @($rr.Traceroutes | Where-Object { $_ })
        if ($traces.Count -eq 0) { continue }
        $e = $eps | Where-Object Hostname -eq $rr._Label | Select-Object -First 1
        $inet = $traces | Where-Object { $_.Target -eq '1.1.1.1' } | Select-Object -First 1
        $avt = $traces | Where-Object { Test-Hosted $_.Target } | Select-Object -First 1
        if (-not $avt) { $avt = $traces | Where-Object { $_.Target -notin @('1.1.1.1', '8.8.8.8') } | Select-Object -First 1 }
        $primary = @($inet, $avt | Where-Object { $_ })
        if ($primary.Count -eq 0) { $primary = @($traces[0]) }
        $primaryTargets = @($primary | ForEach-Object { $_.Target })
        $rest = @($traces | Where-Object { $primaryTargets -notcontains $_.Target })
        [void]$tr.Append('<div class="mach"><div class="mach-h">' + (Enc $rr._Label) + ' <span class="chip">' + (Enc $e.Connection) + '</span></div><div class="tc-grid">')
        foreach ($t in $primary) {
            $ser = @(@($rr.TcpSeries) + @($rr.PingSeries) | Where-Object { $_ -and $_.Target -eq $t.Target -and $_.Received -gt 0 }) | Select-Object -First 1
            $e2e = if ($ser) { '{0} ms average, {1}% loss ({2}, {3} samples)' -f (Num $ser.AvgMs), $ser.LossPct, $(if (V $ser 'Port') { "TCP connect to port $($ser.Port)" } else { 'ping' }), $ser.Sent } else { $null }
            [void]$tr.Append((New-TraceChart $t $e2e))
        }
        [void]$tr.Append('</div>')
        if ($rest.Count) {
            $more = New-Object Text.StringBuilder
            [void]$more.Append('<div class="tc-grid">')
            foreach ($t in $rest) {
                $ser = @(@($rr.TcpSeries) + @($rr.PingSeries) | Where-Object { $_ -and $_.Target -eq $t.Target -and $_.Received -gt 0 }) | Select-Object -First 1
                $e2e = if ($ser) { '{0} ms average, {1}% loss' -f (Num $ser.AvgMs), $ser.LossPct } else { $null }
                [void]$more.Append((New-TraceChart $t $e2e))
            }
            [void]$more.Append('</div>')
            [void]$tr.Append('<details class="mini"><summary>' + (Enc ("More traces from {0} ({1}): {2}" -f $rr._Label, $rest.Count, (($rest | ForEach-Object { $_.Target }) -join ', '))) + '</summary><div class="body">' + $more.ToString() + '</div></details>')
        }
        [void]$tr.Append('</div>')
    }
    [void]$body.Append((New-Panel 'Path: traceroute from each machine' $tr.ToString() "To the internet (1.1.1.1) and to $HostedLabel"))

    # Site facts + topology evidence
    $ev = New-Object Text.StringBuilder
    [void]$ev.Append('<ul class="ev">')
    foreach ($rr in $siteRuns) { foreach ($sig in @(V $rr.Topology 'Signals')) { if ($sig) { [void]$ev.Append('<li><b>' + (Enc $rr._Label) + ':</b> ' + (Enc $sig) + '</li>') } } }
    [void]$ev.Append('</ul>')
    $facts = New-KV @('Carrier', $s.Carrier, 'Public IP', $s.PublicIPs, 'Egress location', $s.EgressCity,
        'Public IP registered to (whois)', (J (@($eps | ForEach-Object { V $_ 'PublicIpRegisteredTo' } | Where-Object { $_ } | Sort-Object -Unique))),
        'Wired median down', $(if ($null -ne $s.WiredMedianDown) { "$($s.WiredMedianDown) Mbps" }), 'Wi-Fi median down', $(if ($null -ne $s.WifiMedianDown) { "$($s.WifiMedianDown) Mbps" }),
        'Firewall', $s.FirewallModel, 'Gateway MAC vendor', $s.GatewayVendors, 'Firewall (admin ports)', $s.FirewallHints, 'VPN client vendor on PCs', $s.VpnClientVendors,
        'Wireless', $(if ($s.ApVendors) { "$($s.ApVendors) ($($s.ApBssids) BSSIDs seen)" } else { 'not identified' }), 'Switching', $(if ($s.Switches) { $s.Switches } else { 'not identified (needs admin run on a wired machine)' }))
    [void]$body.Append((New-Panel 'Site facts' ($facts + "<h4>Topology: $(Enc $s.Verdict)</h4>" + $ev.ToString())))

    # Machines and findings, visible
    [void]$body.Append((New-Panel 'Machines tested' (New-Table $eps @('Hostname|Machine', 'Role', 'User', 'Connection', 'DownMbps|Down', 'UpMbps|Up', "HostedAvgMs|$HostedLabel ms", 'InetLossPct|Loss %', 'Model', 'AgeYears|Age yrs', 'Os|OS', 'RamGB|RAM GB', 'MemUsedPct|Memory used %', 'Displays', 'Tpm|TPM', 'HighFlags|High flags', 'FlagCount|All flags', 'DataCheck|Data check')) 'Full detail for each machine is further down'))
    $sf = @($flags | Where-Object Site -eq $name | Sort-Object @{ Expression = { SevRank $_.Severity } }, Hostname)
    [void]$body.Append((New-Section 'Findings' (New-Table $sf @('Severity', 'Hostname|Machine', 'Category', 'Message|Finding')) -Open:($sf.Count -gt 0) -Badge ("{0} high, {1} medium" -f $s.HighFlags, $s.MediumFlags)))
    $rf = @($runFindings | Where-Object Site -eq $name | Sort-Object @{ Expression = { switch ("$($_.Confidence)") { 'Confirmed' { 0 } 'Likely' { 1 } default { 2 } } } }, Area)
    if ($rf.Count) { [void]$body.Append((New-Section 'What the evidence adds up to (collector findings)' (New-Table $rf @('Confidence', 'Hostname|Machine', 'Area', 'Finding', 'Evidence')) -Open -Badge ("{0} findings" -f $rf.Count))) }
    $sd = @($devices | Where-Object Site -eq $name)
    if ($sd.Count) {
        $kinds = (@($sd | Group-Object { if ($_.Kind) { $_.Kind } else { 'Unidentified' } } | Sort-Object Count -Descending | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', ')
        [void]$body.Append((New-Section 'Devices identified on the network' (('<p class="muted">' + (Enc $kinds) + '</p>') + (New-Table @($sd | Sort-Object Kind, @{ Expression = { try { [version]$_.IP } catch { [version]'0.0' } } }) @('Kind', 'IP', 'Name', 'Vendor', 'Model', 'Firmware', 'WindowsVersion|Windows', 'MacVendor|MAC maker', 'OpenPorts|Open ports', 'Confidence'))) -Badge ("{0} devices" -f $sd.Count)))
    }

    # Network detail
    [void]$body.Append((New-Section 'Connection detail by machine' (New-Table $eps @('Hostname|Machine', 'Connection', 'LocalSubnet|Subnet', 'DownMbps|Down', 'DownProvider|Down via', 'UpMbps|Up', 'UpProvider|Up via', 'LinkMbps|Link Mbps', 'WifiSsid|SSID', 'WifiBand|Band', 'WifiSignalPct|Signal %', 'WifiRealDrops|Wi-Fi drops on this SSID (30d)', 'IdleMs|Idle ms', 'BufferbloatMs|Bufferbloat ms', "HostedAvgMs|$HostedLabel ms", "HostedLossPct|$HostedLabel loss %", 'RdpNetworkDisconnects|RDP network drops (30d)', 'RdpUdp|RDP UDP', 'Verdict', 'DataCheck|Data check'))))
    $rdpT = @($rdpRows | Where-Object Site -eq $name)
    if ($rdpT.Count) { [void]$body.Append((New-Section 'RDP target reachability' (New-Table $rdpT $(if ($ipInfo.Count) { @('Hostname|Machine', 'Host|Target', 'ResolvedIPs|Resolves to', 'Owner|Registered to', 'AddressClass|Class', 'Port', 'Open', 'MedianMs|Median ms', 'JitterMs|Jitter ms') } else { @('Hostname|Machine', 'Host|Target', 'ResolvedIPs|Resolves to', 'AddressClass|Class', 'Port', 'Open', 'MedianMs|Median ms', 'JitterMs|Jitter ms') })) -Badge ("{0} checks" -f $rdpT.Count))) }

    $siteGear = @($gear | Where-Object { $_.Site -eq $name })
    $mainGear = @($siteGear | Where-Object { $_.Type -ne 'Subnet device' })
    $sweep = @($siteGear | Where-Object { $_.Type -eq 'Subnet device' })
    $gearBody = (New-Table $mainGear @('Type', 'Name', 'IP', 'Mac|MAC', 'Vendor', 'Detail', 'SeenFrom|Seen from'))
    if ($sweep.Count) { $gearBody += (New-Section ("Subnet sweep devices ({0})" -f $sweep.Count) (New-Table $sweep @('IP', 'Name', 'Detail|Type and open ports', 'Vendor', 'Mac|MAC', 'SeenFrom|Seen from')) -Open:($sweep.Count -le 40)) }
    [void]$body.Append((New-Section 'Network equipment' $gearBody -Badge ("{0} items" -f $siteGear.Count)))

    $sn = @($subnets | Where-Object Site -eq $name)
    $snBody = '<p class="muted">Assembled from data each machine already collected (adapter address and mask, route table, printer ports, DNS/DHCP servers, private traceroute hops, RDP lookups). Nothing was scanned to build this list. "Inferred /24" means only an address was seen, so the real mask is unknown.</p>'
    $snBody += (New-Table $sn @('Subnet', 'Kind', 'KnownAddresses|Known addresses', 'Sources|How it was found', 'SeenFrom|Seen from', 'Notes'))
    [void]$body.Append((New-Section 'Known subnets' $snBody -Open:($sn.Count -gt 1) -Badge ("{0} subnet(s)" -f $sn.Count)))

    # One block per machine: the title line carries its headline numbers, the body is grouped and open
    [void]$body.Append('<h4>Machine detail</h4>')
    foreach ($rr in $siteRuns) {
        $hn = $rr._Label
        $e = $eps | Where-Object Hostname -eq $hn | Select-Object -First 1
        $mb = New-Object Text.StringBuilder
        [void]$mb.Append('<h4>Test results</h4>')
        [void]$mb.Append((New-KV @('Download', $(if ($null -ne $e.DownMbps -and "$($e.DownMbps)" -ne '') { "$($e.DownMbps) Mbps via $($e.DownProvider)" } else { $e.DownloadFailure }),
            'Upload', $(if ($null -ne $e.UpMbps -and "$($e.UpMbps)" -ne '') { "$($e.UpMbps) Mbps via $($e.UpProvider)" } else { $e.UploadFailure }),
            'Internet latency', $(if ($null -ne $e.IdleMs) { "$($e.IdleMs) ms idle, +$($e.BufferbloatMs) ms under load ($($e.BufferbloatGrade))" }),
            'Internet loss / jitter', $(if ($null -ne $e.InetLossPct) { "$($e.InetLossPct)% loss, $($e.InetJitterMs) ms jitter" }),
            "$HostedLabel round trip", $(if ($null -ne $e.HostedAvgMs) { "$($e.HostedAvgMs) ms avg, $($e.HostedLossPct)% loss, $($e.HostedJitterMs) ms jitter ($($e.HostedTarget))" }),
            'Connection', "$($e.Connection) $(if ($e.LinkMbps) { "($($e.LinkMbps) Mbps link)" })", 'Subnet', $e.LocalSubnet, 'Public IP', $e.PublicIP,
            'Adapter power saving', $e.AdapterPowerSaving,
            'Topology verdict', "$($e.Verdict) ($($e.Confidence))", 'HTTPS inspection', $e.HttpsInspection, 'Data check', $e.DataCheck, 'Data gaps', $e.DataIssues)))
        $isTest = ($e.Role -eq 'Test laptop')
        if ($isTest) { [void]$mb.Append('<div class="note"><b>Visiting test laptop, not a client PC.</b> Its bandwidth, traceroute and latency results describe this site. Its own hardware, software, printers, history and unrelated RDP targets are left out of this report; the zip from the run still holds them.</div>') }
        if (-not $isTest) {
        [void]$mb.Append('<h4>Machine</h4>')
        [void]$mb.Append((New-KV @('User', $e.User, 'Run', "$($e.RunStart)$(if ($e.AdminTier) { ' (admin tier)' })", 'Notes', $e.Notes,
            'Model', "$($e.Manufacturer) $($e.Model)", 'Serial', $e.Serial, 'Form factor / age', "$($e.FormFactor), ~$($e.AgeYears) yrs (from $($e.AgeSource); BIOS $($e.BiosDate))",
            'CPU', $e.Cpu, 'RAM', "$($e.RamGB) GB", 'Disks', $e.Disks, 'OS', "$($e.Os) $($e.OsVersion) (build $($e.Build))",
            'Monitors', $(if ($e.Displays) { "$($e.Monitors): $($e.Displays)" } else { $e.Monitors }),
            'CPU / memory in use during the run', $(if ($null -ne $e.MemUsedPct) { "CPU $($e.CpuAvgPct)%, memory $($e.MemUsedPct)%" }), 'Largest programs in memory', $e.TopMemory)))
        [void]$mb.Append('<h4>Security, patching and management</h4>')
        [void]$mb.Append((New-KV @('TPM / Secure Boot', "$($e.Tpm) / $($e.SecureBoot)", 'BitLocker', $e.BitLocker, 'SSD wear', $(if ($null -ne $e.DiskWearPct) { "$($e.DiskWearPct)%" }),
            'Join / tenant', "$($e.JoinType) $(if ($e.Tenant) { "/ $($e.Tenant)" })", 'Intune', $e.Intune, 'User is local admin', $e.UserIsLocalAdmin,
            'Last Windows OS update', "$($e.LastUpdate) $(if ($null -ne $e.DaysSinceUpdate) { "($($e.DaysSinceUpdate) days)" }) $($e.LastUpdateTitle)".Trim(), 'Pending reboot', $e.PendingReboot,
            'Microsoft 365 Apps', "$($e.M365Version) $($e.M365Channel)".Trim(), 'Clock offset', $(if ($null -ne $e.ClockOffsetSec) { "$($e.ClockOffsetSec) s" }),
            'RMM', $e.RMM, 'Security', $e.Security, 'VPN clients', $e.VPN)))
        $rdp = $rr.Rdp
        $rc = V $rr.EventLogs 'RdpClient'
        [void]$mb.Append('<h4>Hosted desktop and RDP</h4>')
        [void]$mb.Append((New-KV @('Hosted-desktop app', $e.HostedDesktopApp, 'Hosts named in its files', $e.HostedDesktopHosts, 'Servers this PC uses', $e.ServersUsed,
            'Client crashes / hangs (30d)', $e.ClientCrashes, 'RDP UDP on this client', $e.UdpPolicy,
            'mstsc', (V $rdp 'MstscVersion'), 'Remote Desktop (MSRDC)', (V $rdp 'MsrdcVersion'), 'Store clients', (J (V $rdp 'AppxClients')), 'Targets', (J (V $rdp 'DiscoveredHosts')),
            'RDP history', (J (V $rdp 'Mru')), 'Running clients', (J (V $rdp 'RunningClients')), 'UDP in use', (V $rdp 'UdpLikelyInUse'),
            'Connects (30d)', (V $rc 'ConnectAttempts'), 'Disconnects / unexpected / network', $(if ($rc -and $rc -isnot [string]) { "$(V $rc 'Disconnects') / $(V $rc 'UnexpectedDisconnects') / $(V $rc 'NetworkDisconnects')" }), 'Disconnect reasons', (J (V $rc 'DisconnectReasons')),
            'Disconnects by cause', (J (V $rc 'DisconnectsByCategory')), 'UDP transport', (V (V $rc 'Udp') 'Status'),
            "Live $HostedLabel connections", (J (@(V $rdp 'HostedConnections') | ForEach-Object { if ($_) { '{0} {1}:{2} ({3})' -f $_.Name, $_.RemoteAddress, $_.RemotePort, $_.Process } })),
            "$HostedLabel names in DNS cache", (J (V $rdp 'DnsCacheHintNames')), 'Servers in RDP event log', (J (V $rdp 'EventLogServers')), 'Not tested (did not resolve)', (J (V $rdp 'UnresolvedCandidates')))))
        }
        $wl = $rr.Wireless
        $wev = V $wl 'Events'
        $wc = V $wl 'Current'
        if ("$($e.Connection)" -eq 'Wi-Fi' -or (V $wc 'SSID')) {
            [void]$mb.Append('<h4>Wi-Fi</h4>')
            [void]$mb.Append((New-KV @('Status', (V $wl 'Status'), 'SSID', (V $wc 'SSID'), 'Radio / band / channel', ("$(V $wc 'RadioType') $(V $wc 'Band') $(if (V $wc 'Channel') { "ch $(V $wc 'Channel')" })".Trim()),
                'Signal', $(if (V $wc 'SignalPct') { "$(V $wc 'SignalPct')% (~$(V $wc 'ApproxDbm') dBm)" }), 'AP', ("$(V $wc 'BSSID') $(V $wc 'ApVendor')".Trim()), 'Nearby networks', $(if (V $wl 'NearbyBssidCount') { "$(V $wl 'NearbySsidCount') SSIDs / $(V $wl 'NearbyBssidCount') BSSIDs" }),
                'Drops on this SSID (30d)', (V $wev 'SiteSsidDrops'), 'Drops, all networks this machine used (30d)', (V $wev 'RealDrops'), 'Drops by SSID', (J (V $wev 'RealDropsBySsid')), 'Disconnects total', (V $wev 'Disconnected'), 'Location workaround', (V (V $wl 'LocationWorkaround') 'Result'))))
        }
        $mf = @($flags | Where-Object { $_.Site -eq $name -and $_.Hostname -eq $hn } | Sort-Object @{ Expression = { SevRank $_.Severity } })
        if ($mf.Count) { [void]$mb.Append('<h4>Findings on this machine</h4>' + (New-Table $mf @('Severity', 'Category', 'Message|Finding'))) }
        $df = @($deviceFlags | Where-Object { $_.Site -eq $name -and $_.Hostname -eq $hn } | Sort-Object @{ Expression = { SevRank $_.Severity } })
        if ($df.Count) { [void]$mb.Append((New-Section ('About the laptop itself, not counted for this site ({0})' -f $df.Count) (New-Table $df @('Severity', 'Category', 'Message|Finding')))) }
        if (-not $isTest) {
        [void]$mb.Append('<h4>Printers</h4>')
        [void]$mb.Append((New-Table ($printers | Where-Object { $_.Site -eq $name -and $_.Hostname -eq $hn }) @('Printer', 'Driver', 'PortType|Port type', 'HostAddress|IP', 'WebTitle|Web page', 'Default')))
        [void]$mb.Append('<h4>Peripherals and RDP redirection</h4>')
        $pp = $periph | Where-Object { $_.Site -eq $name -and $_.Hostname -eq $hn } | Select-Object -First 1
        [void]$mb.Append((New-KV @('Monitors', (V $pp 'Monitors'), 'Docks', (V $pp 'Docks'), 'Scanner / camera', (V $pp 'ScannerCamera'), 'Audio', (V $pp 'Audio'), 'Smart card', (V $pp 'SmartCard'), 'Serial / COM', (V $pp 'SerialCom'), 'Notable devices', (V $pp 'Notable'), 'Redirection gaps', (V $pp 'RedirectionGaps'))))
        $apps = @($software | Where-Object { $_.Site -eq $name -and $_.Hostname -eq $hn })
        [void]$mb.Append((New-Section ("Installed software ({0})" -f $apps.Count) (New-Table $apps @('Name', 'Version', 'Publisher', 'Scope'))))
        if ($rr._Summary) { [void]$mb.Append((New-Section 'Collector summary (text)' ('<pre>' + (Enc $rr._Summary) + '</pre>'))) }
        [void]$mb.Append((New-Section 'Raw data (JSON)' ('<pre>' + (Enc $rr._Raw) + '</pre>')))
        }
        $badge = if ($e.HighFlags) { "$($e.HighFlags) high" } elseif ($e.FlagCount) { "$($e.FlagCount) flags" } else { 'no flags' }
        if ($isTest) { $badge = "test laptop, $badge" }
        $bits = @("$($e.Manufacturer) $($e.Model)".Trim(), "$($e.Connection)")
        if ($null -ne $e.DownMbps -and "$($e.DownMbps)" -ne '') { $bits += "$(Num $e.DownMbps) down / $(if ($null -ne $e.UpMbps -and "$($e.UpMbps)" -ne '') { Num $e.UpMbps } else { 'n/a' }) up Mbps" }
        if ($null -ne $e.HostedAvgMs -and "$($e.HostedAvgMs)" -ne '') { $bits += "$HostedLabel $(Num $e.HostedAvgMs) ms" }
        $right = '<span class="s-right">' + (Enc (($bits | Where-Object { $_ }) -join '  |  ')) + '</span>'
        [void]$body.Append((New-Section $hn $mb.ToString() -Class 'ep' -Badge $badge -Extra $right))
    }
    $right = '<span class="s-right"><span class="pill"><span class="dot dot-{0}"></span>{1}</span><span class="{2}" style="font-weight:600">{3}</span><span>{4}</span><span>{5} machine(s)</span></span>' -f $s.Status, (Enc $sv.Pill), (Get-VerdictClass $s.Verdict), (Enc $s.Verdict), (Enc $s.CarrierName), $s.Endpoints
    [void]$sb.Append((New-Section $name $body.ToString() -Open -Class 'site' -Id $sv.Id -Extra $right))
}

# ---- Public addresses and who owns them (from the enrichment pass)
if ($ipInfo.Count) {
    [void]$sb.Append('<h2 id="addresses">Public addresses and who owns them</h2>')
    [void]$sb.Append('<p class="lead">Every public IP address in the runs, looked up when this report was built. Network is who announces the address on the internet; Registered to is the whois record for the block it sits in.</p>')
    [void]$sb.Append((New-Panel ('{0} addresses' -f $ipOwnerRows.Count) (New-Table $ipOwnerRows @('IP', 'Network', 'RegisteredTo|Registered to', 'Block', 'Range', 'Country', 'ReverseDns|Reverse DNS', 'SeenAs|Seen as')) $(if ($enrich.OuiSource) { "MAC vendors: $($enrich.OuiSource)" })))
    if ($enrich.Notes.Count) { [void]$sb.Append('<div class="note"><b>Lookup notes</b><ul>' + (($enrich.Notes | ForEach-Object { '<li>' + (Enc $_) + '</li>' }) -join '') + '</ul></div>') }
}

# ---- Fleet (client PCs only; a visiting test laptop is not part of the client's fleet)
$fleetEps = @($endpoints | Where-Object { $_.Role -ne 'Test laptop' })
$fleetLeftOut = @($endpoints | Where-Object { $_.Role -eq 'Test laptop' } | ForEach-Object { $_.Hostname } | Sort-Object -Unique)
$noTpm2 = @($fleetEps | Where-Object { $_.Tpm -and "$($_.Tpm)" -notmatch '^2' }).Count
$lowRam = @($fleetEps | Where-Object { $_.RamGB -and [double]$_.RamGB -lt 7.5 }).Count
$hdd = @($fleetEps | Where-Object { $_.Disks -match 'HDD' }).Count
$old = @($fleetEps | Where-Object { $_.AgeYears -and [double]$_.AgeYears -ge 5 }).Count
$win10 = @($fleetEps | Where-Object { $_.IsWin10 }).Count
$blOff = @($fleetEps | Where-Object { "$($_.BitLocker)" -match 'Off|Suspended' }).Count
[void]$sb.Append('<h2 id="fleet">Fleet</h2>')
if ($fleetLeftOut.Count) { [void]$sb.Append('<p class="lead">Client PCs only. Left out: ' + (Enc ($fleetLeftOut -join ', ')) + ' (visiting test laptop).' + $(if ($fleetEps.Count -eq 0) { ' No client PC was tested, so this section is empty.' }) + '</p>') }
if ($fleetEps.Count) {
[void]$sb.Append('<div class="stats">')
foreach ($st in @(@($fleetEps.Count, 'client PCs assessed'), @($win10, 'on Windows 10 (out of support)'), @($noTpm2, 'without TPM 2.0'), @($old, '5+ years old (BIOS date / CPU generation)'), @($lowRam, 'under 8 GB RAM'), @($hdd, 'with a spinning HDD'), @($blOff, 'BitLocker off/suspended'))) {
    [void]$sb.Append(("<div class=""stat""><b>{0}</b><span>{1}</span></div>" -f $st[0], (Enc $st[1])))
}
[void]$sb.Append('</div>')
[void]$sb.Append((New-Panel 'Hardware lifecycle (all machines)' (New-Table $fleetEps @('Site', 'Hostname|Machine', 'Manufacturer', 'Model', 'Serial', 'FormFactor|Form', 'AgeYears|Age yrs', 'Cpu|CPU', 'RamGB|RAM GB', 'Disks', 'Os|OS', 'OsVersion|Version', 'Tpm|TPM', 'SecureBoot|Secure Boot', 'BitLocker', 'DiskWearPct|SSD wear %', 'JoinType|Join', 'Intune', 'M365Channel|M365 channel'))))
$matrix = @($software | Group-Object Name | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject][ordered]@{ Name = $_.Name; Machines = @($_.Group | Select-Object -ExpandProperty Hostname -Unique).Count; Versions = J ($_.Group | ForEach-Object { $_.Version } | Where-Object { $_ } | Sort-Object -Unique) ', '; Publisher = ($_.Group | Select-Object -First 1).Publisher }
})
$tooling = @()
foreach ($tag in @('RMM', 'Security', 'VPN')) {
    $vals = @($fleetEps | ForEach-Object { $_.$tag -split '; ' } | Where-Object { $_ })
    foreach ($grp in ($vals | ForEach-Object { ($_ -replace '\s+[\d\.]+$', '').Trim() } | Group-Object | Sort-Object Count -Descending)) { $tooling += [pscustomobject][ordered]@{ Category = $tag; Product = $grp.Name; Machines = $grp.Count } }
}
[void]$sb.Append((New-Section 'Management and security tooling' (New-Table $tooling @('Category', 'Product', 'Machines')) -Open -Badge ("{0} products" -f $tooling.Count)))
[void]$sb.Append((New-Section ("Software inventory matrix ({0} titles)" -f $matrix.Count) (New-Table $matrix @('Name', 'Machines', 'Versions', 'Publisher'))))
$warranty = New-Object Text.StringBuilder
foreach ($grp in ($fleetEps | Where-Object { $_.Serial } | Group-Object Manufacturer | Sort-Object Name)) {
    [void]$warranty.Append('<h4>' + (Enc $grp.Name) + " ($($grp.Count))</h4><pre>" + (Enc (($grp.Group | ForEach-Object { $_.Serial }) -join "`r`n")) + '</pre>')
}
[void]$sb.Append((New-Section 'Serial numbers by manufacturer (for warranty lookup)' $warranty.ToString()))
}

# ---- Methodology
$method = @'
<h4>How each machine was tested</h4>
<ul class="ev">
<li><b>Connection type</b> comes from the adapter that carries the default route (wired, Wi-Fi, USB/dock, phone tether, VPN).</li>
<li><b>Bandwidth</b> runs 10 seconds per direction and ignores the first 2 seconds of ramp-up. Each direction fails over between providers: Cloudflare (4 parallel streams), then M-Lab NDT7 (a public measurement service, one WebSocket), then Vultr test files (download only, 4 streams). The provider used is shown next to every result; providers agree closely but not exactly. Latency under load is measured with ping to 1.1.1.1 while the test runs; the increase over idle is reported as <b>bufferbloat</b> (A under 30 ms, B under 100 ms, C under 250 ms, D above). Bufferbloat is the usual cause of laggy RDP sessions even on fast circuits.</li>
<li><b>Latency and loss</b> are a 180-ping series (3 minutes; older runs used 60) to the gateway, 1.1.1.1 and any RDP host that answers ping, plus a TCP connect series of the same length (one per second) to the first three remote desktop hosts. The TCP series measures hosts that ignore ping, which remote desktop gateways often do; one TCP connect takes one round trip.</li>
<li><b>{HOSTED} targets</b>: every machine tests the fixed targets of its hosted desktop profile, then hosts found in RDP history, .rdp files, remote desktop shortcuts, the RDP client event log, names in the DNS cache that match the profile and live connections that reverse-resolve to it.</li>
<li><b>Round trip to {HOSTED}</b> follows Microsoft's Azure Virtual Desktop guidance: under 150 ms is fine, 150 to 200 ms is acceptable for text work, over 200 ms degrades the experience. Microsoft's bandwidth figures assume under 0.1% packet loss.</li>
<li><b>RDP disconnects</b> (client event 1026) are grouped by cause using Microsoft's reason codes. Network causes are 264, 516, 772, 1028, 1796, 2308 and the RD Gateway network errors. <b>RDP UDP</b> comes from client events 1102 (attempted), 1103 (established) and 1104 (failed: TCP only).</li>
<li><b>Order of work</b>: bandwidth, traceroutes and the latency series run first and are saved before anything that probes the network (gateway ports, device discovery, subnet sweep). A run that was cut off during that last part still has its core results and is marked INCOMPLETE.</li>
<li><b>Subnet sweep</b> pings the machine's own subnet (up to a /22), then looks up a name and tries 13 common TCP ports on each device that answered. The type shown (printer, domain controller, camera, phone, Windows host) is a guess from the open ports.</li>
<li><b>Servers a PC uses</b> come from its mapped drives, shared printers and domain, resolved on site: on this subnet (on-prem here), another private subnet (another site or a tunnel) or public (cloud).</li>
<li><b>HTTPS inspection</b> is detected from who issued the certificate the PC is shown for Cloudflare and for each remote desktop host. A firewall, web filter or antivirus name as the issuer means the connection is being opened and re-signed.</li>
<li><b>Data check</b>: before saving, each machine reads its own results back from disk and checks them. Anything critical that failed (bandwidth, traceroute, ping, public IP) is retried once, and the zip is opened again to confirm it holds the data. FAIL means a critical item is still missing; WARN means the data is usable with gaps.</li>
<li><b>Session health</b> (collector 1.5.0 and later) covers the PC itself: crashes and hangs of the remote desktop client in the Application log (events 1000, 1002, 1026), whether RDP UDP is turned off on the client by policy or setting, the display sizes Windows reports, CPU and memory in use early in the run with the largest programs in memory, and whether Windows may power down the network adapter in use.</li>
<li><b>Enrichment</b> happens when the report is built, not on site. MAC addresses with no maker are matched against the IEEE registry (downloaded once and kept; nothing is sent), and addresses that are locally administered are labelled as randomized. Each public IP address is looked up three ways: the network that announces it (Team Cymru), the whois record for its block (the regional registry's RDAP service) and its reverse DNS name. Only the IP addresses are sent. Answers are kept for 30 days. The merge can be run with -NoEnrich to make no requests at all.</li>
<li><b>Test laptops</b>: a machine whose serial number appears at two or more sites (or that is named when the report is built) is a visiting test device, not a client PC. Its bandwidth, traceroute, latency and sweep results are used for the site. Its own hardware, software, printers, mapped drives, session history and any RDP targets that are not the hosted desktop are left out, findings about the laptop itself do not count toward a site's status, and it is not part of the fleet figures.</li>
<li><b>Traceroutes</b> go to 1.1.1.1, 8.8.8.8 and each RDP target. The first public hop and its reverse DNS usually name the carrier.</li>
<li><b>Circuit speed</b> on each site card is the best wired result, because Wi-Fi results measure the wireless network, not the internet line. A site with no wired run shows its best result and says so.</li>
<li><b>Machine age</b> comes from the BIOS date. A BIOS update moves that date forward, so when the CPU generation is more than a year older than the BIOS date, age comes from the CPU generation instead (approximate, can read a year high).</li>
<li><b>Last OS update</b> counts Windows cumulative and security updates only (from update history or installed KBs), not Defender signatures or Store apps.</li>
<li><b>Wi-Fi drops</b> count only disconnects followed by a reconnect to the same network within 2 minutes, so a laptop leaving the building is not counted.</li>
</ul>
<h4>How the topology verdict is decided</h4>
<ul class="ev">
<li><b>Local breakout</b>: internet traffic leaves through this site's own circuit (the trace goes from the gateway straight to the ISP).</li>
<li><b>Split tunnel</b>: internet is local, but RDP hosts are reached over a tunnel (they resolve to private IPs, or the RDP trace passes through private hops that internet traffic does not).</li>
<li><b>Full backhaul</b>: internet traffic itself leaves through another location (egress ASN belongs to the hosted desktop provider or a datacenter, private tunnel hops before the ISP plus another signal, or a VPN adapter holds the default route).</li>
<li>Private hops <i>after</i> a carrier-grade NAT hop (100.64.0.0/10) belong to the carrier (Starlink, cellular, some cable) and are ignored.</li>
<li>Across sites, the same public IP at two sites indicates shared egress, unless both are behind carrier-grade NAT on the same carrier.</li>
</ul>
<h4>Flag thresholds</h4>
<ul class="ev">
<li>High: Windows 10, no TPM 2.0, packet loss 5%+, bufferbloat 100 ms+, 3+ network-caused RDP disconnects in 30 days, round trip to {HOSTED} over 200 ms, 30+ Wi-Fi drops, SSD wear 80%+, no enabled antivirus, phone tether.</li>
<li>Medium: round trip to {HOSTED} 150 to 200 ms, 5+ unexpected RDP disconnects, network adapter errors, under 8 GB RAM, HDD, 5+ years old, wired link under 1 Gbps, weak or 2.4 GHz Wi-Fi, packet loss 1%+, jitter 30 ms+, upload under 5 Mbps, 10+ Wi-Fi drops, no Windows OS update in 45 days, clock off by 60 s+, BitLocker off, user is local admin, peripherals without matching RDP redirection, 3+ remote desktop client crashes or hangs, memory 90%+ in use or CPU 80%+ busy during the run.</li>
<li>Low (shown per site and per machine): 1 or 2 client crashes, RDP UDP turned off on the client, display area of 8 megapixels or more (one 4K screen), adapter power saving on a Wi-Fi or USB adapter that has 3+ recorded drops.</li>
</ul>
'@
$method = $method.Replace('{HOSTED}', (Enc $HostedLabel))
[void]$sb.Append((New-Section 'Methodology' $method -Id 'method'))
[void]$sb.Append("</main><script>$js</script></body></html>")
[IO.File]::WriteAllText((Join-Path $OutDir 'Report.html'), $sb.ToString(), (New-Object Text.UTF8Encoding $false))

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Wrote merged output to $OutDir" -ForegroundColor Green
$sites | Format-Table Status, Site, Endpoints, Verdict, CircuitDownMbps, CircuitUpMbps, HostedMedianMs, DataChecks -AutoSize | Out-String -Width 200 | Write-Host
$failedRuns = @($endpoints | Where-Object { $_.DataCheck -eq 'FAIL' })
foreach ($fr in $failedRuns) { Write-Host ("Data check FAILED: {0} / {1}: {2}" -f $fr.Site, $fr.Hostname, $fr.DataIssues) -ForegroundColor Red }
