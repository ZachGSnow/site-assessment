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
