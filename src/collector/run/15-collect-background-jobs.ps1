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
