function Get-CaptureSummary {
    # Reads the pktmon capture a second time and reports what the wire shows: who answers DHCP and with
    # which options, spanning tree (the switch this port hangs off, the root switch), LLDP/CDP neighbors
    # with their capabilities and voice VLAN, VLAN tags, other subnets heard in ARP, and how busy the
    # broadcast domain is. Frames this PC sent are left out.
    param([string]$Path, [int]$Seconds, [string[]]$LocalMacs)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $own = @{}
    foreach ($m in @($LocalMacs)) { $k = ("$m" -replace '[^0-9A-Fa-f]', '').ToUpper(); if ($k) { $own[$k] = $true } }
    $frames = 0; $bcast = 0; $truncated = $false
    $etypes = @{}; $vlans = @{}; $arp = @{}; $talk = @{}; $udpPorts = @{}
    $stp = @{}; $dhcpSrv = @{}; $dhcpCli = @{}; $ra = @{}; $lldp = @{}; $cdp = @{}; $ann = @{}; $arpDup = @{}
    $lldpCaps = @('Other', 'Repeater', 'Bridge', 'WLAN access point', 'Router', 'Telephone', 'DOCSIS', 'Station')
    $mau = @{ 10 = '10BASE-T full'; 15 = '100BASE-TX half'; 16 = '100BASE-TX full'; 29 = '1000BASE-T half'; 30 = '1000BASE-T full'; 54 = '10GBASE-T' }
    $pos = 0
    while ($pos + 12 -le $bytes.Length) {
        $type = [BitConverter]::ToUInt32($bytes, $pos)
        $len  = [int][BitConverter]::ToUInt32($bytes, $pos + 4)
        if ($len -lt 12 -or $pos + $len -gt $bytes.Length) { break }
        $capLen = 0
        if ($type -eq 6) { $capLen = [int][BitConverter]::ToUInt32($bytes, $pos + 20) }
        if ($type -eq 6 -and $capLen -ge 14 -and $pos + 28 + $capLen -le $bytes.Length) {
            if ($frames -ge 40000) { $truncated = $true; break }
            $f = New-Object byte[] $capLen
            [Array]::Copy($bytes, $pos + 28, $f, 0, $capLen)
            $srcMac = [BitConverter]::ToString($f, 6, 6)
            if (-not $own.ContainsKey(($srcMac -replace '-', ''))) {
                $frames++
                $isB = ($f[0] -eq 255 -and $f[1] -eq 255 -and $f[2] -eq 255 -and $f[3] -eq 255 -and $f[4] -eq 255 -and $f[5] -eq 255)
                $off = 14; $et = ([int]$f[12] * 256) + [int]$f[13]
                if ($et -eq 0x8100 -and $capLen -ge 18) {
                    $vid = "$((([int]$f[14] -band 0x0F) * 256) + [int]$f[15])"
                    $vlans[$vid] = 1 + [int]$vlans[$vid]
                    $et = ([int]$f[16] * 256) + [int]$f[17]; $off = 18
                }
                if ($isB) { $bcast++; $talk[$srcMac] = 1 + [int]$talk[$srcMac] }
                $etKey = if ($et -le 1500) { 'LLC' } else { '0x{0:X4}' -f $et }
                $etypes[$etKey] = 1 + [int]$etypes[$etKey]

                if ($et -eq 0x0806 -and $capLen -ge $off + 28) {
                    $spa = ConvertTo-IpText $f ($off + 14)
                    # Untagged only: a tagged frame belongs to another VLAN, not to this port's network.
                    if ($off -eq 14 -and $spa -and $spa -ne '0.0.0.0') {
                        $sha = ConvertTo-MacText $f ($off + 8)
                        if ($arp.ContainsKey($spa) -and $arp[$spa] -ne $sha) { $arpDup[$spa] = "$($arp[$spa]) and $sha" }
                        $arp[$spa] = $sha
                    }
                }
                elseif ($et -eq 0x0800 -and $capLen -ge $off + 28) {
                    $ihl = ([int]$f[$off] -band 0x0F) * 4
                    if ([int]$f[$off + 9] -eq 17 -and $capLen -ge $off + $ihl + 8) {
                        $u = $off + $ihl
                        $sp = ([int]$f[$u] * 256) + [int]$f[$u + 1]; $dp = ([int]$f[$u + 2] * 256) + [int]$f[$u + 3]; $pl = $u + 8
                        $srcIp = ConvertTo-IpText $f ($off + 12)
                        $udpPorts["$dp"] = 1 + [int]$udpPorts["$dp"]
                        if (($sp -eq 67 -or $sp -eq 68) -and $capLen -ge $pl + 241) {
                            $opt = @{}; $q = $pl + 240
                            while ($q + 2 -le $capLen) {
                                $ot = [int]$f[$q]
                                if ($ot -eq 255) { break }
                                if ($ot -eq 0) { $q++; continue }
                                $ol = [int]$f[$q + 1]
                                if ($q + 2 + $ol -gt $capLen) { break }
                                $opt[$ot] = @(($q + 2), $ol); $q += 2 + $ol
                            }
                            $oStr = { param($k) if ($opt.ContainsKey($k)) { ConvertTo-AsciiText $f $opt[$k][0] $opt[$k][1] } }
                            $oIps = { param($k) if ($opt.ContainsKey($k)) { $l = @(); for ($z = 0; $z + 4 -le $opt[$k][1]; $z += 4) { $l += ConvertTo-IpText $f ($opt[$k][0] + $z) }; $l -join ', ' } }
                            $giaddr = ConvertTo-IpText $f ($pl + 24)
                            if ($sp -eq 67) {
                                $sid = if ($opt.ContainsKey(54)) { ConvertTo-IpText $f $opt[54][0] } else { $srcIp }
                                if (-not $dhcpSrv.ContainsKey($sid)) { $dhcpSrv[$sid] = [ordered]@{ Server = $sid; SentFromIp = $srcIp; SentFromMac = $srcMac; RelayAgent = $null; Messages = 0; Mask = $null; Router = $null; Dns = $null; Domain = $null; LeaseSeconds = $null; TftpServer = $null; TftpAddresses = $null; BootFile = $null; Ntp = $null; VendorSpecificHex = $null } }
                                $e = $dhcpSrv[$sid]; $e['Messages']++
                                if ($giaddr -and $giaddr -ne '0.0.0.0') { $e['RelayAgent'] = $giaddr }
                                foreach ($pair in @(@(1, 'Mask'), @(3, 'Router'), @(6, 'Dns'), @(42, 'Ntp'), @(150, 'TftpAddresses'))) { $v = & $oIps $pair[0]; if ($v) { $e[$pair[1]] = $v } }
                                foreach ($pair in @(@(15, 'Domain'), @(66, 'TftpServer'), @(67, 'BootFile'))) { $v = & $oStr $pair[0]; if ($v) { $e[$pair[1]] = $v } }
                                if ($opt.ContainsKey(51) -and $opt[51][1] -ge 4) { $o = $opt[51][0]; $e['LeaseSeconds'] = ([int64]$f[$o] * 16777216) + ([int64]$f[$o + 1] * 65536) + ([int64]$f[$o + 2] * 256) + [int64]$f[$o + 3] }
                                if ($opt.ContainsKey(43)) { $e['VendorSpecificHex'] = ([BitConverter]::ToString($f, $opt[43][0], [math]::Min($opt[43][1], 64)) -replace '-', '') }
                            } else {
                                $ch = ConvertTo-MacText $f ($pl + 28)
                                if (-not $dhcpCli.ContainsKey($ch)) { $dhcpCli[$ch] = [ordered]@{ Mac = $ch; Hostname = $null; VendorClass = $null; RequestedIp = $null; Messages = 0 } }
                                $c = $dhcpCli[$ch]; $c['Messages']++
                                $v = & $oStr 12; if ($v) { $c['Hostname'] = $v }
                                $v = & $oStr 60; if ($v) { $c['VendorClass'] = $v }
                                $v = & $oIps 50; if ($v) { $c['RequestedIp'] = $v }
                            }
                        }
                        elseif (($dp -eq 10001 -or $sp -eq 10001 -or $dp -eq 5678 -or $dp -eq 63321) -and $capLen -gt $pl + 8) {
                            $payload = New-Object byte[] ($capLen - $pl)
                            [Array]::Copy($f, $pl, $payload, 0, $payload.Length)
                            $d = if ($dp -eq 10001 -or $sp -eq 10001) { ConvertFrom-UbntDiscovery $payload } elseif ($dp -eq 63321) { ConvertFrom-Nsdp $payload } else { ConvertFrom-Mndp $payload }
                            if ($d) { if (-not $d.IP) { $d.IP = $srcIp }; if (-not $d.Mac) { $d.Mac = $srcMac }; $ann["$($d.Protocol)|$($d.Mac)"] = $d }
                        }
                    }
                }
                elseif ($et -eq 0x86DD -and $capLen -ge $off + 41) {
                    if ([int]$f[$off + 6] -eq 58 -and [int]$f[$off + 40] -eq 134) { $ra[$srcMac] = 1 + [int]$ra[$srcMac] }
                }
                elseif ($et -eq 0x88CC) {
                    $n = [ordered]@{ Protocol = 'LLDP'; SenderMac = $srcMac; ChassisMac = $null; SystemName = $null; SystemDescription = $null; PortId = $null; PortDescription = $null; Capabilities = @(); MgmtIP = $null; PortVlan = $null; VlanNames = @(); LinkMode = $null; MedDeviceClass = $null; VoiceVlan = $null; VoiceVlanTagged = $null; MedManufacturer = $null; MedModel = $null; MedFirmware = $null; MedSoftware = $null; MedSerial = $null; Frames = 1 }
                    $p = $off
                    while ($p + 2 -le $capLen) {
                        $hdr = ([int]$f[$p] * 256) + [int]$f[$p + 1]
                        $tt = $hdr -shr 9; $tl = $hdr -band 0x1FF; $p += 2
                        if ($tt -eq 0 -or $p + $tl -gt $capLen) { break }
                        if ($tt -eq 1 -and $tl -ge 7 -and $f[$p] -eq 4) { $n['ChassisMac'] = ConvertTo-MacText $f ($p + 1) }
                        elseif ($tt -eq 2 -and $tl -ge 2) { if ($tl -ge 7 -and $f[$p] -eq 3) { $n['PortId'] = 'MAC ' + (ConvertTo-MacText $f ($p + 1)) } else { $n['PortId'] = ConvertTo-AsciiText $f ($p + 1) ($tl - 1) } }
                        elseif ($tt -eq 4) { $n['PortDescription'] = ConvertTo-AsciiText $f $p $tl }
                        elseif ($tt -eq 5) { $n['SystemName'] = ConvertTo-AsciiText $f $p $tl }
                        elseif ($tt -eq 6) { $n['SystemDescription'] = ConvertTo-AsciiText $f $p $tl }
                        elseif ($tt -eq 7 -and $tl -ge 4) {
                            $bits = ([int]$f[$p + 2] * 256) + [int]$f[$p + 3]
                            if (-not $bits) { $bits = ([int]$f[$p] * 256) + [int]$f[$p + 1] }
                            $caps = @(); for ($bi = 0; $bi -lt 8; $bi++) { if ($bits -band (1 -shl $bi)) { $caps += $lldpCaps[$bi] } }
                            $n['Capabilities'] = $caps
                        }
                        elseif ($tt -eq 8 -and $tl -ge 6 -and $f[$p + 1] -eq 1) { $n['MgmtIP'] = ConvertTo-IpText $f ($p + 2) }
                        elseif ($tt -eq 127 -and $tl -ge 4) {
                            $oui = '{0:X2}{1:X2}{2:X2}' -f $f[$p], $f[$p + 1], $f[$p + 2]; $st = [int]$f[$p + 3]
                            if ($oui -eq '0080C2' -and $st -eq 1 -and $tl -ge 6) { $n['PortVlan'] = ([int]$f[$p + 4] * 256) + [int]$f[$p + 5] }
                            elseif ($oui -eq '0080C2' -and $st -eq 3 -and $tl -ge 7) { $n['VlanNames'] = @($n['VlanNames']) + ('{0} {1}' -f (([int]$f[$p + 4] * 256) + [int]$f[$p + 5]), (ConvertTo-AsciiText $f ($p + 7) ([math]::Min([int]$f[$p + 6], $tl - 7)))).Trim() }
                            elseif ($oui -eq '00120F' -and $st -eq 1 -and $tl -ge 9) { $mt = ([int]$f[$p + 7] * 256) + [int]$f[$p + 8]; $n['LinkMode'] = if ($mau.ContainsKey($mt)) { $mau[$mt] } else { "MAU type $mt" } }
                            elseif ($oui -eq '0012BB' -and $st -eq 1 -and $tl -ge 7) { $n['MedDeviceClass'] = switch ([int]$f[$p + 6]) { 1 { 'Endpoint class I' } 2 { 'Endpoint class II (media)' } 3 { 'Endpoint class III (phone)' } 4 { 'Network connectivity (switch)' } default { "class $([int]$f[$p + 6])" } } }
                            elseif ($oui -eq '0012BB' -and $st -eq 2 -and $tl -ge 8 -and ([int]$f[$p + 4] -eq 1 -or -not $n['VoiceVlan'])) {
                                $n['VoiceVlan'] = (([int]$f[$p + 5] -band 0x1F) * 128) + ([int]$f[$p + 6] -shr 1)
                                $n['VoiceVlanTagged'] = [bool]([int]$f[$p + 5] -band 0x40)
                            }
                            elseif ($oui -eq '0012BB' -and $st -ge 5 -and $st -le 10) {
                                $key = @{ 5 = 'MedHardware'; 6 = 'MedFirmware'; 7 = 'MedSoftware'; 8 = 'MedSerial'; 9 = 'MedManufacturer'; 10 = 'MedModel' }[$st]
                                if ($n.Contains($key)) { $n[$key] = ConvertTo-AsciiText $f ($p + 4) ($tl - 4) }
                            }
                        }
                        $p += $tl
                    }
                    $k = "$($n['ChassisMac'])|$($n['PortId'])|$srcMac"
                    if ($lldp.ContainsKey($k)) { $lldp[$k]['Frames']++ } else { $lldp[$k] = $n }
                }
                elseif ($et -le 1500) {
                    $dst = [BitConverter]::ToString($f, 0, 6)
                    if ($dst -eq '01-00-0C-CC-CC-CC' -and $capLen -ge $off + 16 -and $f[$off + 6] -eq 0x20 -and $f[$off + 7] -eq 0x00) {
                        $n = [ordered]@{ Protocol = 'CDP'; SenderMac = $srcMac; DeviceId = $null; PortId = $null; Platform = $null; Software = $null; Capabilities = @(); Address = $null; NativeVlan = $null; VoiceVlan = $null; Frames = 1 }
                        $p = $off + 12
                        while ($p + 4 -le $capLen) {
                            $tt = ([int]$f[$p] * 256) + [int]$f[$p + 1]; $tl = ([int]$f[$p + 2] * 256) + [int]$f[$p + 3]
                            if ($tl -lt 4 -or $p + $tl -gt $capLen) { break }
                            $s = ConvertTo-AsciiText $f ($p + 4) ($tl - 4)
                            if ($tt -eq 1) { $n['DeviceId'] = $s } elseif ($tt -eq 3) { $n['PortId'] = $s } elseif ($tt -eq 5) { $n['Software'] = $s } elseif ($tt -eq 6) { $n['Platform'] = $s }
                            elseif ($tt -eq 4 -and $tl -ge 8) { $cb = [int]$f[$p + 7]; $caps = @(); foreach ($pair in @(@(1, 'Router'), @(2, 'Bridge'), @(8, 'Switch'), @(16, 'Host'), @(64, 'Repeater'), @(128, 'Telephone'))) { if ($cb -band $pair[0]) { $caps += $pair[1] } }; $n['Capabilities'] = $caps }
                            elseif ($tt -eq 10 -and $tl -ge 6) { $n['NativeVlan'] = ([int]$f[$p + 4] * 256) + [int]$f[$p + 5] }
                            elseif ($tt -eq 14 -and $tl -ge 7) { $n['VoiceVlan'] = ([int]$f[$p + 5] * 256) + [int]$f[$p + 6] }
                            elseif ($tt -eq 2 -and $tl -ge 17 -and $f[$p + 8] -eq 1 -and $f[$p + 10] -eq 0xCC) { $n['Address'] = ConvertTo-IpText $f ($p + 13) }
                            $p += $tl
                        }
                        $k = "$($n['DeviceId'])|$($n['PortId'])|$srcMac"
                        if ($cdp.ContainsKey($k)) { $cdp[$k]['Frames']++ } else { $cdp[$k] = $n }
                    }
                    else {
                        $b = -1; $proto = $null
                        if ($dst -eq '01-80-C2-00-00-00' -and $capLen -ge $off + 3 -and $f[$off] -eq 0x42 -and $f[$off + 1] -eq 0x42) { $b = $off + 3; $proto = 'Spanning tree' }
                        elseif ($dst -eq '01-00-0C-CC-CC-CD' -and $capLen -ge $off + 8) { $b = $off + 8; $proto = 'Cisco per-VLAN spanning tree' }
                        if ($b -ge 0 -and $capLen -ge $b + 27 -and ([int]$f[$b + 3] -eq 0 -or [int]$f[$b + 3] -eq 2)) {
                            $brMac = ConvertTo-MacText $f ($b + 19); $portId = ([int]$f[$b + 25] * 256) + [int]$f[$b + 26]
                            $k = "$proto|$brMac|$portId"
                            if ($stp.ContainsKey($k)) { $stp[$k]['Frames']++ }
                            else {
                                $stp[$k] = [ordered]@{
                                    Protocol = $(if ([int]$f[$b + 2] -ge 2) { "$proto (rapid)" } else { $proto }); SenderMac = $srcMac
                                    BridgeMac = $brMac; BridgePriority = ([int]$f[$b + 17] * 256) + [int]$f[$b + 18]; PortId = $portId
                                    RootMac = ConvertTo-MacText $f ($b + 7); RootPriority = ([int]$f[$b + 5] * 256) + [int]$f[$b + 6]
                                    RootPathCost = ([int64]$f[$b + 13] * 16777216) + ([int64]$f[$b + 14] * 65536) + ([int64]$f[$b + 15] * 256) + [int64]$f[$b + 16]
                                    ThisSwitchIsRoot = ($brMac -eq (ConvertTo-MacText $f ($b + 7))); Frames = 1
                                }
                            }
                        }
                    }
                }
            }
        }
        $pos += $len
    }
    $subnets = @($arp.Keys | Group-Object { ($_ -split '\.')[0..2] -join '.' } | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Subnet = "$($_.Name).0/24"; Hosts = $_.Count; Sample = (@($_.Group | Select-Object -First 4) -join ', ') } })
    $secs = [math]::Max(1, $Seconds)
    [ordered]@{
        Seconds = $Seconds; Frames = $frames; Truncated = $truncated
        BroadcastFrames = $bcast; BroadcastPerSecond = [math]::Round($bcast / $secs, 1)
        Note = 'Counts are approximate: pktmon can record one frame at more than one point.'
        EtherTypes = @($etypes.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
        VlanTagsSeen = @($vlans.Keys | Sort-Object { [int]$_ })
        EapolFrames = [int]$etypes['0x888E']
        ArpConflicts = @($arpDup.GetEnumerator() | ForEach-Object { [pscustomobject]@{ IP = $_.Key; Macs = $_.Value } })
        ArpSubnets = $subnets
        ArpHosts = @($arp.GetEnumerator() | Sort-Object { try { [version]$_.Key } catch { [version]'0.0' } } | Select-Object -First 600 | ForEach-Object { [pscustomobject]@{ IP = $_.Key; Mac = $_.Value } })
        TopBroadcasters = @($talk.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { [pscustomobject]@{ Mac = $_.Key; Vendor = (Get-MacVendorLocal $_.Key); Frames = $_.Value } })
        UdpBroadcastPorts = @($udpPorts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
        SpanningTree = @($stp.Values | ForEach-Object { $_['SenderVendor'] = Get-MacVendorLocal $_['SenderMac']; $_['RootVendor'] = Get-MacVendorLocal $_['RootMac']; [pscustomobject]$_ })
        Lldp = @($lldp.Values | ForEach-Object { $_['ChassisVendor'] = Get-MacVendorLocal $(if ($_['ChassisMac']) { $_['ChassisMac'] } else { $_['SenderMac'] }); [pscustomobject]$_ })
        Cdp = @($cdp.Values | ForEach-Object { [pscustomobject]$_ })
        DhcpServers = @($dhcpSrv.Values | ForEach-Object { [pscustomobject]$_ })
        DhcpClients = @($dhcpCli.Values | Select-Object -First 400 | ForEach-Object { [pscustomobject]$_ })
        Ipv6RouterAdvertisers = @($ra.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Mac = $_.Key; Vendor = (Get-MacVendorLocal $_.Key); Frames = $_.Value } })
        VendorAnnouncements = @($ann.Values)
    }
}

# =====================================================================
# PHASE 5: collect background jobs
# =====================================================================
function ConvertFrom-NeighborCapture {
    # Parses LLDP and CDP frames out of a pktmon pcapng file.
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $frames = @()
    $pos = 0
    while ($pos + 12 -le $bytes.Length) {
        $type = [BitConverter]::ToUInt32($bytes, $pos)
        $len  = [BitConverter]::ToUInt32($bytes, $pos + 4)
        if ($len -lt 12 -or $pos + $len -gt $bytes.Length) { break }
        if ($type -eq 6) {
            $capLen = [BitConverter]::ToUInt32($bytes, $pos + 20)
            $data = New-Object byte[] $capLen
            [Array]::Copy($bytes, $pos + 28, $data, 0, $capLen)
            $frames += ,$data
        }
        $pos += $len
    }
    $txt = { param($b, $off) [Text.Encoding]::ASCII.GetString($b, $off, $b.Length - $off) -replace '[^\x20-\x7E]', '' }
    $mac = { param($b, $off) (($b[$off..($off + 5)] | ForEach-Object { '{0:X2}' -f $_ }) -join '-') }
    # IEEE 802.3 operational MAU types seen most often (RFC 4836).
    $mau = @{ 10 = '10BASE-T full'; 15 = '100BASE-TX half'; 16 = '100BASE-TX full'; 29 = '1000BASE-T half'; 30 = '1000BASE-T full'; 54 = '10GBASE-T' }
    $found = @()
    foreach ($f in $frames) {
        if ($f.Length -lt 16) { continue }
        $etype = ($f[12] * 256) + $f[13]
        if ($etype -eq 0x88CC) {
            $info = [ordered]@{ Protocol = 'LLDP'; SystemName = $null; Model = $null; Port = $null; PortId = $null; PortDescription = $null; LinkMode = $null; Vlan = $null; MgmtIP = $null; ChassisMac = $null; ChassisVendor = $null; SystemDescription = $null }
            $p = 14
            while ($p + 2 -le $f.Length) {
                $hdr = ($f[$p] * 256) + $f[$p + 1]
                $tt = $hdr -shr 9; $tl = $hdr -band 0x1FF
                $p += 2
                if ($tt -eq 0 -or $p + $tl -gt $f.Length) { break }
                $val = New-Object byte[] $tl
                [Array]::Copy($f, $p, $val, 0, $tl)
                switch ($tt) {
                    1 { if ($tl -ge 7 -and $val[0] -eq 4) { $info['ChassisMac'] = & $mac $val 1 } }
                    # Port ID subtype 3 is a MAC address; the others are text (interface alias/name, local).
                    2 { if ($tl -ge 7 -and $val[0] -eq 3) { $info['PortId'] = 'MAC ' + (& $mac $val 1) } else { $info['PortId'] = & $txt $val 1 } }
                    4 { $info['PortDescription'] = & $txt $val 0 }
                    5 { $info['SystemName'] = & $txt $val 0 }
                    6 { $info['SystemDescription'] = & $txt $val 0 }
                    8 { if ($tl -ge 6 -and $val[1] -eq 1) { $info['MgmtIP'] = '{0}.{1}.{2}.{3}' -f $val[2], $val[3], $val[4], $val[5] } }
                    127 {
                        if ($tl -ge 6 -and $val[0] -eq 0x00 -and $val[1] -eq 0x80 -and $val[2] -eq 0xC2 -and $val[3] -eq 1) { $info['Vlan'] = ($val[4] * 256) + $val[5] }
                        elseif ($tl -ge 9 -and $val[0] -eq 0x00 -and $val[1] -eq 0x12 -and $val[2] -eq 0x0F -and $val[3] -eq 1) {
                            $m = ($val[7] * 256) + $val[8]
                            $info['LinkMode'] = if ($mau.ContainsKey($m)) { $mau[$m] } else { "MAU type $m" }
                        }
                    }
                }
                $p += $tl
            }
            # Human-friendly port: a short description (often just the port number) beats a MAC-style port ID.
            $info['Port'] = if ($info['PortDescription'] -and $info['PortDescription'].Length -le 24) { $info['PortDescription'] } else { $info['PortId'] }
            if ($info['SystemDescription']) { $info['Model'] = ($info['SystemDescription'] -split ',')[0].Trim() }
            if ($info['ChassisMac']) { $info['ChassisVendor'] = Get-MacVendor $info['ChassisMac'] }
            $found += [pscustomobject]$info
        } elseif ($f[0] -eq 0x01 -and $f[1] -eq 0x00 -and $f[2] -eq 0x0C -and $f[3] -eq 0xCC) {
            # CDP over 802.3 + LLC/SNAP: header 14 + 8, then version/ttl/checksum (4)
            $info = [ordered]@{ Protocol = 'CDP'; SystemName = $null; Model = $null; Port = $null; PortId = $null; PortDescription = $null; LinkMode = $null; Vlan = $null; MgmtIP = $null; ChassisMac = $null; ChassisVendor = $null; SystemDescription = $null }
            $p = 26
            while ($p + 4 -le $f.Length) {
                $tt = ($f[$p] * 256) + $f[$p + 1]; $tl = ($f[$p + 2] * 256) + $f[$p + 3]
                if ($tl -lt 4 -or $p + $tl -gt $f.Length) { break }
                $s = [Text.Encoding]::ASCII.GetString($f, $p + 4, $tl - 4) -replace '[^\x20-\x7E]', ''
                switch ($tt) { 1 { $info['SystemName'] = $s } 3 { $info['PortId'] = $s } 5 { $info['SystemDescription'] = $s } 6 { $info['Model'] = $s } 10 { if ($tl -ge 6) { $info['Vlan'] = ($f[$p + 4] * 256) + $f[$p + 5] } } }
                $p += $tl
            }
            $info['Port'] = $info['PortId']
            $found += [pscustomobject]$info
        }
    }
    [ordered]@{
        FramesCaptured = $frames.Count
        Neighbors = @($found | Sort-Object Protocol, SystemName, Port -Unique)
        Note = if ($found.Count -eq 0) { 'No LLDP/CDP seen: switch is unmanaged, LLDP disabled, or interval > capture window' } else { $null }
    }
}
