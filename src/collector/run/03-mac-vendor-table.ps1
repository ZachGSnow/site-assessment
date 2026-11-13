# ---------------------------------------------------------------------
# MAC vendor lookup (embedded table for network gear, online fallback)
# ---------------------------------------------------------------------
$script:OuiTable = @{}
$ouiSeed = @{
    'Fortinet'   = '00090F 085B0E 704CA5 906CAC E81CBA 04D590 94FF3C'
    'SonicWall'  = '0017C5 C0EAE4 18B169'
    'Cisco Meraki' = '00180A 0C8DDB 881544 E0553D AC17C8 2C3F0B 683A1E E0CBBC'
    'Ubiquiti'   = '00156D 002722 0418D6 24A43C 44D9E7 687251 788A20 802AA8 B4FBE4 DC9FDB F09FC2 FCECDA 74ACB9 18E829 E063DA 245A4C 784558 68D79A 70A741 D021F9 AC8BA9'
    'WatchGuard' = '00907F'
    'Sophos'     = '001A8C'
    'Palo Alto Networks' = '001B17 00869C B40C25 08306B'
    'Aruba (HPE)' = '000B86 001A1E 24DEC6 6CF37F 94B40F D8C7C8 204C03 9C1C12 84D47E 40E3D6 B45D50 F05C19'
}
foreach ($vendor in $ouiSeed.Keys) {
    foreach ($o in ($ouiSeed[$vendor] -split ' ')) { $script:OuiTable[$o] = $vendor }
}
$script:OuiOnlineCount = 0
