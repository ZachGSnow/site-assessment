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
