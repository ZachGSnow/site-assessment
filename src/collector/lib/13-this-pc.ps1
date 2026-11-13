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
    # The fixed targets (the hosted desktop profile and $ExtraTargets) are the ones that must answer. Targets
    # found only in this PC's RDP history may be old or office-only hosts: their silence is not a gap.
    $fixedHosts = @(@(Get-Field (Get-Field (Get-Field $D 'Meta') 'HostedDesktop') 'Targets') | Where-Object { $_ } | ForEach-Object { ((("$_".Trim().ToLower() -replace '^[a-z]+://', '') -split '/')[0] -replace ':\d+$', '') })
    if (-not $fixedHosts.Count) { $fixedHosts = @($extraHosts | Where-Object { $_ }) }
    $ownTargets = @($targets | Where-Object { $fixedHosts -notcontains $_ })
    $historyOnly = ($targets.Count -gt 0 -and $ownTargets.Count -eq $targets.Count)
    if ($targets.Count -eq 0 -and -not $fixedHosts.Count) { & $add 'Remote desktop targets' 'INFO' 'no remote desktop use found on this PC and no hosted desktop profile targets set' }
    elseif ($targets.Count -eq 0) { & $add 'Remote desktop targets' 'WARN' 'none resolved' }
    elseif ($ownTargets.Count -eq 0) { & $add 'Remote desktop targets' 'WARN' ("only the fixed target ({0}); no remote desktop use found on this PC, so no session history. A PC whose user works in the hosted desktop gives more" -f ($targets -join ', ')) }
    else { & $add 'Remote desktop targets' 'OK' ($targets -join ', ') }
    if ($targets.Count) {
        $traceInfo = foreach ($tg in $targets) { $t = $traces | Where-Object { $_.Target -eq $tg } | Select-Object -First 1; '{0}: {1} hops' -f $tg, @(@(Get-Field $t 'Hops') | Where-Object { $_ -and $_.IP }).Count }
        $noTrace = @($targets | Where-Object { $tg = $_; -not ($traces | Where-Object { $_.Target -eq $tg -and @($_.Hops | Where-Object { $_ -and $_.IP }).Count -ge 1 }) })
        & $add 'Traceroutes to targets' $(if ($noTrace.Count) { 'WARN' } else { 'OK' }) (@($traceInfo) -join '; ')
        $series = @(@($pings + $tcps) | Where-Object { $targets -contains $_.Target -and $_.Received -gt 0 })
        if ($series.Count) { & $add 'Remote desktop loss / latency' 'OK' ((@($series | ForEach-Object { '{0}{1} loss {2}% avg {3} ms' -f $_.Target, $(if (Get-Field $_ 'Port') { " tcp/$($_.Port)" } else { '' }), $_.LossPct, $_.AvgMs })) -join '; ') }
        elseif ($historyOnly) { & $add 'Remote desktop loss / latency' 'INFO' 'the hosts in this PC''s RDP history do not answer from here (old or office-only hosts); set a hosted desktop profile or $ExtraTargets to measure the one that matters' }
        else { & $add 'Remote desktop loss / latency' 'WARN' 'no ping or TCP replies from any target' }
        $openT = @(@(Get-Field $D 'RdpPath') | Where-Object { $_ -and @(@($_.Tcp) | Where-Object { $_ -and $_.Open }).Count })
        if ($openT.Count) { & $add 'Remote desktop reachability' 'OK' ("{0} of {1} target(s) answer on TCP" -f $openT.Count, $targets.Count) }
        elseif ($historyOnly) { & $add 'Remote desktop reachability' 'INFO' 'no host from the RDP history answered on TCP' }
        else { & $add 'Remote desktop reachability' 'WARN' 'no target answered on any TCP port' }
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
            # Blocked by policy is how most managed PCs are set up: report it, but it is not a gap to fix by re-running
            & $add 'Wi-Fi details' $(if ("$why" -like 'Blocked by policy*') { 'INFO' } else { 'WARN' }) ("radio details not read ({0}); SSID {1}" -f $why, (Get-Field $wc 'SSID'))
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
