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
