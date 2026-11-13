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
