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
