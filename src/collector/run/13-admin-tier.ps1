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
