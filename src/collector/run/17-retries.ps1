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
