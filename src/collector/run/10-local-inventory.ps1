# =====================================================================
# PHASE 3: local inventory (runs while the jobs work)
# =====================================================================
$Result['Machine'] = Invoke-Collector 'Machine and lifecycle' {
    $cs   = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 20
    $bios = Get-CimInstance Win32_BIOS -OperationTimeoutSec 20
    $os   = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 20
    $cpu  = @(Get-CimInstance Win32_Processor -OperationTimeoutSec 20)
    $mem  = @(Get-CimInstance Win32_PhysicalMemory -OperationTimeoutSec 20)
    $enc  = Get-CimInstance Win32_SystemEnclosure -OperationTimeoutSec 20
    $csp  = Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 20
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $laptopTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
    $isLaptop = [bool](@($enc.ChassisTypes) | Where-Object { $laptopTypes -contains $_ })
    $biosDate = $bios.ReleaseDate
    $biosAge = if ($biosDate) { [math]::Round(((Get-Date) - $biosDate).TotalDays / 365.25, 1) } else { $null }
    # A BIOS update moves the BIOS date forward, so an old PC can look new. When the CPU generation
    # is clearly older than the BIOS date, age comes from the CPU generation instead.
    $cpuName = ($cpu | Select-Object -First 1).Name
    $cpuYear = Get-CpuLaunchYear $cpuName
    $cpuAge = if ($cpuYear) { [math]::Round(((Get-Date) - (Get-Date -Year $cpuYear -Month 7 -Day 1)).TotalDays / 365.25, 1) } else { $null }
    $ageYears = $biosAge; $ageSource = 'BIOS date'
    if ($null -ne $cpuAge -and ($null -eq $biosAge -or $cpuAge -gt $biosAge + 1)) {
        $ageYears = $cpuAge
        $ageSource = if ($null -eq $biosAge) { 'CPU generation' } else { 'CPU generation (BIOS updated since purchase)' }
    }
    $build = [int]$os.BuildNumber
    $secureBoot = $null
    try { $secureBoot = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop).UEFISecureBootEnabled } catch { }
    $fwType = $null
    try { $fw = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction Stop).PEFirmwareType; $fwType = switch ($fw) { 1 { 'BIOS (legacy)' } 2 { 'UEFI' } default { "$fw" } } } catch { }

    $disks = @()
    try {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.FriendlyName; MediaType = "$($_.MediaType)"; BusType = "$($_.BusType)"; SizeGB = [math]::Round($_.Size / 1GB); Health = "$($_.HealthStatus)" }
        })
    } catch {
        $disks = @(Get-CimInstance Win32_DiskDrive -OperationTimeoutSec 20 | ForEach-Object {
            [pscustomobject]@{ Name = $_.Model; MediaType = "$($_.MediaType)"; BusType = $_.InterfaceType; SizeGB = [math]::Round($_.Size / 1GB); Health = $_.Status }
        })
    }
    $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 20 | ForEach-Object {
        [pscustomobject]@{ Drive = $_.DeviceID; SizeGB = [math]::Round($_.Size / 1GB); FreeGB = [math]::Round($_.FreeSpace / 1GB, 1); FreePct = if ($_.Size) { [math]::Round(100 * $_.FreeSpace / $_.Size) } else { $null } }
    })

    # TPM via tpmtool (often works without admin)
    $tpm = [ordered]@{}
    try {
        $tt = Invoke-Native 'tpmtool.exe' 'getdeviceinformation' 20
        foreach ($line in ($tt -split "`r?`n")) {
            if ($line -match '^\s*-?\s*(TPM Present|TPM Version|TPM Manufacturer ID|TPM Manufacturer Full Name|TPM Manufacturer Version|Is Initialized|Ready For Storage|Ready For Attestation)\s*:\s*(.*)$') { $tpm[$matches[1]] = $matches[2].Trim() }
        }
    } catch { $tpm['Error'] = $_.Exception.Message }

    # Battery health
    $battery = $null
    if (Get-CimInstance Win32_Battery -OperationTimeoutSec 10 -ErrorAction SilentlyContinue) {
        try {
            $xmlPath = Join-Path $env:TEMP ('sa_battery_{0}.xml' -f (Get-Random))
            Invoke-Native 'powercfg.exe' ('/batteryreport /xml /output "{0}"' -f $xmlPath) 30 | Out-Null
            [xml]$bx = Get-Content -LiteralPath $xmlPath -Raw
            Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue
            $battery = @($bx.BatteryReport.Batteries.Battery | ForEach-Object {
                $design = [double]$_.DesignCapacity; $full = [double]$_.FullChargeCapacity
                [pscustomobject]@{ Id = $_.Id; Manufacturer = $_.Manufacturer; DesignmWh = $design; FullChargemWh = $full; HealthPct = if ($design -gt 0) { [math]::Round(100 * $full / $design) } else { $null }; CycleCount = $_.CycleCount }
            })
        } catch { $battery = "unavailable: $($_.Exception.Message)" }
    }

    [ordered]@{
        Hostname        = $env:COMPUTERNAME
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        ModelVersion    = $csp.Version
        SerialNumber    = $bios.SerialNumber
        ChassisTypes    = @($enc.ChassisTypes)
        FormFactor      = if ($isLaptop) { 'Laptop' } else { 'Desktop/Other' }
        BiosVersion     = $bios.SMBIOSBIOSVersion
        BiosDate        = Format-Date $biosDate
        ApproxAgeYears  = $ageYears
        AgeSource       = $ageSource
        BiosAgeYears    = $biosAge
        CpuLaunchYear   = $cpuYear
        Cpu             = $cpuName
        CpuCores        = ($cpu | Measure-Object NumberOfCores -Sum).Sum
        CpuThreads      = ($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum
        RamGB           = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        RamSlots        = @($mem | ForEach-Object { '{0} {1}GB {2}MHz' -f $_.DeviceLocator, [math]::Round($_.Capacity / 1GB), $_.Speed })
        Disks           = $disks
        Volumes         = $vols
        OsCaption       = $os.Caption
        OsVersion       = $os.Version
        OsBuild         = $build
        OsUbr           = $cv.UBR
        OsDisplayVersion = $cv.DisplayVersion
        OsEdition       = $cv.EditionID
        OsArchitecture  = $os.OSArchitecture
        IsWindows10     = ($build -lt 22000)
        OsInstallDate   = Format-Date $os.InstallDate
        LastBoot        = Format-Date $os.LastBootUpTime
        UptimeDays      = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        FirmwareType    = $fwType
        SecureBootRegistry = $secureBoot
        Tpm             = $tpm
        Battery         = $battery
        Domain          = $cs.Domain
        PartOfDomain    = $cs.PartOfDomain
    }
}

$Result['Identity'] = Invoke-Collector 'Identity and user structure' {
    $out = [ordered]@{}
    $ds = Invoke-Native 'dsregcmd.exe' '/status' 30
    $kv = ConvertFrom-ColonText $ds
    $keep = @('AzureAdJoined','EnterpriseJoined','DomainJoined','DomainName','WorkplaceJoined','TenantName','TenantId','MdmUrl','MdmComplianceUrl','DeviceId','AzureAdPrt','IsUserAzureAD','NgcSet','WorkplaceTenantName')
    $dj = [ordered]@{}
    foreach ($k in $keep) { if ($kv.Contains($k)) { $dj[$k] = $kv[$k] } }
    $out['Dsregcmd'] = $dj
    $join = 'Workgroup'
    if ($dj['AzureAdJoined'] -eq 'YES' -and $dj['DomainJoined'] -eq 'YES') { $join = 'Hybrid Entra joined' }
    elseif ($dj['AzureAdJoined'] -eq 'YES') { $join = 'Entra joined' }
    elseif ($dj['DomainJoined'] -eq 'YES') { $join = 'AD domain joined' }
    elseif ($dj['WorkplaceJoined'] -eq 'YES') { $join = 'Workgroup + Entra registered' }
    $out['JoinType'] = $join
    $out['IntuneEnrolled'] = [bool]$dj['MdmUrl']

    if ($script:SameUser) {
        try { $out['Upn'] = (Invoke-Native 'whoami.exe' '/upn' 10).Trim() } catch { }
        try {
            $g = ((Invoke-Native 'whoami.exe' '/groups /fo csv' 10) -split "`r?`n" | Where-Object { $_.Trim() }) | ConvertFrom-Csv
            $out['Groups'] = @($g | ForEach-Object { $_.'Group Name' } | Where-Object { $_ -and $_ -notmatch '^(Mandatory Label|NT AUTHORITY\\(LogonSessionId|This Organization|Authenticated|INTERACTIVE|Local account)|LOCAL$|CONSOLE LOGON)' })
            $out['UserIsLocalAdmin'] = [bool]($g | Where-Object { $_.SID -eq 'S-1-5-32-544' })
        } catch { }
    } else {
        $out['Note'] = 'Run by a different account than the signed-in user; group membership is for the runner and is not collected.'
    }

    # Local Administrators members (net localgroup is the most tolerant of orphaned/Entra SIDs)
    $adminGroup = 'Administrators'
    try { $adminGroup = ((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value -split '\\')[-1] } catch { }
    $members = @()
    try {
        $raw = Invoke-Native 'net.exe' ('localgroup "{0}"' -f $adminGroup) 15
        $inList = $false
        foreach ($line in ($raw -split "`r?`n")) {
            if ($line -match '^-{5,}') { $inList = $true; continue }
            if ($inList) {
                if ($line -match '^The command completed' -or -not $line.Trim()) { continue }
                $members += $line.Trim()
            }
        }
    } catch { }
    $out['LocalAdmins'] = $members
    if (-not $out.Contains('UserIsLocalAdmin')) {
        $short = ($script:UserName -split '\\')[-1]
        $out['UserIsLocalAdmin'] = [bool]($members | Where-Object { $_ -eq $script:UserName -or ($_ -split '\\')[-1] -eq $short })
    }

    try {
        $out['LocalUsers'] = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; LastLogon = Format-Date $_.LastLogon; PasswordLastSet = Format-Date $_.PasswordLastSet }
        })
    } catch { }

    $profiles = @()
    foreach ($p in @(Get-CimInstance Win32_UserProfile -Filter 'Special=False' -OperationTimeoutSec 20)) {
        $name = $null
        try { $name = (New-Object Security.Principal.SecurityIdentifier $p.SID).Translate([Security.Principal.NTAccount]).Value } catch { }
        $ntuser = $null
        try { $ntuser = Format-Date (Get-Item -LiteralPath (Join-Path $p.LocalPath 'NTUSER.DAT') -Force -ErrorAction Stop).LastWriteTime } catch { }
        $profiles += [pscustomobject]@{ Account = $name; Sid = $p.SID; Path = $p.LocalPath; Loaded = $p.Loaded; LastUseTime = Format-Date $p.LastUseTime; NtuserLastWrite = $ntuser }
    }
    $out['Profiles'] = $profiles
    $recent = @($profiles | Where-Object { $_.NtuserLastWrite -and ([datetime]$_.NtuserLastWrite) -gt (Get-Date).AddDays(-$LookbackDays) })
    $out['ProfilesActiveInLookback'] = $recent.Count
    $out['LikelyShared'] = ($recent.Count -gt 1)

    try { $out['SessionsQuser'] = (Invoke-Native 'quser.exe' '' 10).Trim() } catch { }

    $drives = @()
    $netKey = "$($script:UserHive)\Network"
    if (Test-Path -LiteralPath $netKey) {
        foreach ($k in (Get-ChildItem -LiteralPath $netKey)) {
            $drives += [pscustomobject]@{ Drive = $k.PSChildName.ToUpper() + ':'; RemotePath = (Get-ItemProperty -LiteralPath $k.PSPath).RemotePath }
        }
    }
    $out['MappedDrives'] = $drives

    $od = @()
    $odRoot = "$($script:UserHive)\Software\Microsoft\OneDrive\Accounts"
    if (Test-Path -LiteralPath $odRoot) {
        foreach ($k in (Get-ChildItem -LiteralPath $odRoot)) {
            $v = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($v.UserEmail -or $v.UserFolder) { $od += [pscustomobject]@{ Account = $k.PSChildName; UserEmail = $v.UserEmail; UserFolder = $v.UserFolder; TenantName = $v.DisplayName } }
        }
    }
    $out['OneDrive'] = $od
    $out
}

$Result['Software'] = Invoke-Collector 'Installed software and security' {
    $paths = @(
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; S = 'Machine' },
        @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; S = 'Machine32' },
        @{ P = "$($script:UserHive)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; S = 'User' }
    )
    $apps = @()
    foreach ($x in $paths) {
        foreach ($i in @(Get-ItemProperty -Path $x.P -ErrorAction SilentlyContinue)) {
            if (-not $i.DisplayName -or $i.SystemComponent -eq 1 -or $i.ParentKeyName) { continue }
            $apps += [pscustomobject]@{ Name = "$($i.DisplayName)".Trim(); Version = $i.DisplayVersion; Publisher = $i.Publisher; InstallDate = $i.InstallDate; Scope = $x.S }
        }
    }
    $apps = @($apps | Sort-Object Name, Version -Unique)

    $tagRules = [ordered]@{
        RMM          = 'ConnectWise Automate|LabTech|Datto RMM|CentraStage|Autotask Endpoint|NinjaRMM|NinjaOne|N-able|SolarWinds MSP|Kaseya|Atera|Syncro|Pulseway|Action1|ManageEngine|Tactical RMM|Mesh ?Agent|Automox|Immybot'
        RemoteAccess = 'ScreenConnect|ConnectWise Control|TeamViewer|AnyDesk|Splashtop|GoTo|LogMeIn|BeyondTrust|Bomgar|RustDesk|Chrome Remote Desktop|Zoho Assist'
        Security     = 'Huntress|SentinelOne|CrowdStrike|Sophos|Bitdefender|ESET|Malwarebytes|Webroot|Trend Micro|Symantec|McAfee|Trellix|Cylance|Carbon Black|Arctic Wolf|Blackpoint|Todyl|Cisco Secure Endpoint|ThreatLocker|Avast|AVG|Norton|Kaspersky|Defender for Endpoint|Rapid7|Qualys|Liongard|Perch'
        VPN          = 'FortiClient|GlobalProtect|AnyConnect|Cisco Secure Client|NetExtender|Mobile Connect|WatchGuard|Sophos Connect|OpenVPN|WireGuard|Zscaler|Cloudflare WARP|Netskope|Pulse Secure|Ivanti Secure|Check Point|Tailscale|ZeroTier|NordLayer|Perimeter 81|Twingate|Meraki'
        RemoteDesktop = 'Remote Desktop|Windows App|Citrix Workspace|VMware Horizon|Omnissa|Parallels Client|ThinPrint|TSPrint|TSScan|RDP|Terminal Services'
        Office       = '^Microsoft (365|Office)'
        Browser      = '^Google Chrome$|Mozilla Firefox|^Microsoft Edge$|Brave'
    }
    $tagged = [ordered]@{}
    foreach ($tag in $tagRules.Keys) {
        $tagged[$tag] = @($apps | Where-Object { "$($_.Name) $($_.Publisher)" -match $tagRules[$tag] } | ForEach-Object { ('{0} {1}' -f $_.Name, $_.Version).Trim() })
    }
    $vpnVendor = @()
    foreach ($v in $tagged['VPN']) {
        if ($v -match 'FortiClient') { $vpnVendor += 'Fortinet' }
        elseif ($v -match 'GlobalProtect') { $vpnVendor += 'Palo Alto Networks' }
        elseif ($v -match 'AnyConnect|Cisco Secure Client') { $vpnVendor += 'Cisco' }
        elseif ($v -match 'NetExtender|Mobile Connect') { $vpnVendor += 'SonicWall' }
        elseif ($v -match 'WatchGuard') { $vpnVendor += 'WatchGuard' }
        elseif ($v -match 'Sophos Connect') { $vpnVendor += 'Sophos' }
        elseif ($v -match 'Meraki') { $vpnVendor += 'Cisco Meraki' }
    }

    $av = @()
    try {
        $av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -OperationTimeoutSec 20 -ErrorAction Stop | ForEach-Object {
            $hex = '{0:X6}' -f [int]$_.productState
            [pscustomobject]@{ Name = $_.displayName; State = $_.productState; Enabled = ($hex.Substring(2, 2) -match '1[01]'); UpToDate = ($hex.Substring(4, 2) -eq '00') }
        })
    } catch { }
    $fwProd = @()
    try { $fwProd = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct -OperationTimeoutSec 20 -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch { }
    $winFw = @()
    try { $winFw = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Profile = $_.Name; Enabled = "$($_.Enabled)" } }) } catch { }
    $netProfile = @()
    try { $netProfile = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; Network = $_.Name; Category = "$($_.NetworkCategory)"; IPv4Connectivity = "$($_.IPv4Connectivity)" } }) } catch { }
    $hotfix = @()
    try {
        $hotfix = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 5 |
            ForEach-Object { [pscustomobject]@{ Id = $_.HotFixID; Description = $_.Description; InstalledOn = Format-Date $_.InstalledOn } })
    } catch { }
    $defender = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender = [ordered]@{ AMRunningMode = $mp.AMRunningMode; RealTimeProtection = $mp.RealTimeProtectionEnabled; SignatureLastUpdated = Format-Date $mp.AntivirusSignatureLastUpdated; SignatureAgeDays = $mp.AntivirusSignatureAge; TamperProtected = $mp.IsTamperProtected }
    } catch { }

    # BitLocker without admin: Shell property on the OS volume
    $bl = $null
    try {
        $shell = New-Object -ComObject Shell.Application
        $sysDrive = $env:SystemDrive
        $raw = $shell.NameSpace(17).ParseName($sysDrive).ExtendedProperty('System.Volume.BitLockerProtection')
        $map = @{ 0 = 'Not encryptable'; 1 = 'On'; 2 = 'Off'; 3 = 'Encrypting'; 4 = 'Decrypting'; 5 = 'Suspended'; 6 = 'On (locked)' }
        $bl = [ordered]@{ Drive = $sysDrive; Raw = $raw; Status = if ($null -ne $raw -and $map.ContainsKey([int]$raw)) { $map[[int]$raw] } else { 'Unknown' } }
    } catch { }

    [ordered]@{
        AppCount        = $apps.Count
        Apps            = $apps
        Tagged          = $tagged
        FirewallVendorHintsFromVpnClient = @($vpnVendor | Sort-Object -Unique)
        AntiVirus       = $av
        FirewallProducts = $fwProd
        WindowsFirewall = $winFw
        NetworkProfiles = $netProfile
        RecentHotfixes  = $hotfix
        Defender        = $defender
        BitLocker       = $bl
    }
}

$Result['Peripherals'] = Invoke-Collector 'Printers and peripherals' {
    $out = [ordered]@{}

    # Printers
    $ports = @{}
    try { foreach ($p in @(Get-PrinterPort -ErrorAction Stop)) { $ports[$p.Name] = $p } } catch { }
    $defaultPrinter = $null
    try {
        $dev = (Get-ItemProperty -LiteralPath "$($script:UserHive)\Software\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction Stop).Device
        if ($dev) { $defaultPrinter = ($dev -split ',')[0] }
    } catch { }
    $virtualRegex = 'Microsoft Print to PDF|Microsoft XPS|OneNote|^Fax$|Send To OneNote|Adobe PDF|PDF24|CutePDF|Snagit|Webex Document'
    $printers = @()
    try {
        foreach ($p in @(Get-Printer -ErrorAction Stop)) {
            $port = $ports[$p.PortName]
            $hostAddr = $null
            if ($port -and $port.PrinterHostAddress) { $hostAddr = $port.PrinterHostAddress }
            elseif ($p.PortName -match '^IP_(\d{1,3}(\.\d{1,3}){3})') { $hostAddr = $matches[1] }
            elseif ($p.PortName -match '^(\d{1,3}(\.\d{1,3}){3})') { $hostAddr = $matches[1] }
            $portType = 'Other'
            if ($p.Type -eq 'Connection' -or $p.Name -like '\\*') { $portType = 'Shared (print server)' }
            elseif ($p.PortName -match '^USB') { $portType = 'USB' }
            elseif ($p.PortName -match '^WSD') { $portType = 'WSD (network)' }
            elseif ($hostAddr) { $portType = 'TCP/IP' }
            elseif ($p.PortName -match '^(LPT|COM)\d') { $portType = 'Parallel/Serial' }
            elseif ($p.PortName -match '^TS\d') { $portType = 'RDP redirected' }
            elseif ($p.PortName -match 'PORTPROMPT|nul:|FILE:|SHRFAX|OneNote|PDF') { $portType = 'Virtual' }
            $printers += [pscustomobject]@{
                Name = $p.Name; Driver = $p.DriverName; Port = $p.PortName; PortType = $portType; HostAddress = $hostAddr
                Shared = $p.Shared; ShareName = $p.ShareName; Location = $p.Location; Status = "$($p.PrinterStatus)"
                IsDefault = ($p.Name -eq $defaultPrinter); IsVirtual = ($p.Name -match $virtualRegex -or $portType -eq 'Virtual')
            }
        }
    } catch { $out['PrinterError'] = $_.Exception.Message }
    $out['Printers'] = $printers
    $out['DefaultPrinter'] = $defaultPrinter
    $userConns = @()
    $pc = "$($script:UserHive)\Printers\Connections"
    if (Test-Path -LiteralPath $pc) { $userConns = @(Get-ChildItem -LiteralPath $pc | ForEach-Object { $_.PSChildName -replace ',', '\' }) }
    $out['UserPrinterConnections'] = $userConns

    # PnP devices by class
    $pnp = @(Get-CimInstance Win32_PnPEntity -OperationTimeoutSec 30 | Where-Object { $_.Present -ne $false })
    $classMap = [ordered]@{
        'Scanner/Camera' = '^(Image|Camera)$'
        'Audio'          = '^AudioEndpoint$'
        'SmartCard'      = '^(SmartCardReader|SmartCard)$'
        'Serial/COM'     = '^Ports$'
        'Biometric'      = '^Biometric$'
        'Phone/WPD'      = '^WPD$'
        'Bluetooth'      = '^Bluetooth$'
    }
    $byClass = [ordered]@{}
    foreach ($k in $classMap.Keys) {
        $byClass[$k] = @($pnp | Where-Object { "$($_.PNPClass)" -match $classMap[$k] } | ForEach-Object { $_.Name } | Where-Object { $_ } | Sort-Object -Unique)
    }
    $byClass['Bluetooth'] = @($byClass['Bluetooth'] | Where-Object { $_ -notmatch 'Enumerator|Protocol|Transport|Service|LE Generic|Generic Access|Generic Attribute|Device \(RFCOMM|Avrcp|Hands-Free|Audio Gateway|Wireless Bluetooth' })
    $out['DevicesByClass'] = $byClass

    $notableRegex = 'Topaz|Wacom|signotec|Scriptel|ePad|StepOver|Evolis|Zebra|DYMO|Rollo|Fujitsu|ScanSnap|fi-\d|Canon|Epson|Brother|Panini|Digital Check|RDM|Magtek|Ingenico|Verifone|Honeywell|Metrologic|Symbol|Datalogic|Jabra|Plantronics|Poly|Logitech|Yealink|Sennheiser|EPOS|YubiKey|Yubico|Kodak|Visioneer|Ambir|Star Micronics|Seiko|Citizen|HID Global|OMNIKEY|Identiv|Elo|Topaz'
    $usb = @($pnp | Where-Object { $_.DeviceID -match '^(USB|HID)\\VID_' -and $_.Name -notmatch 'Root Hub|Generic USB Hub|USB Composite Device|Host Controller|HID-compliant (vendor|system|consumer|device)|USB Input Device|Generic SuperSpeed|USB Mass Storage|Billboard' } |
        ForEach-Object {
            $vid = $null; $pidv = $null
            if ($_.DeviceID -match 'VID_([0-9A-F]{4})') { $vid = $matches[1] }
            if ($_.DeviceID -match 'PID_([0-9A-F]{4})') { $pidv = $matches[1] }
            [pscustomobject]@{ Name = $_.Name; Manufacturer = $_.Manufacturer; Class = "$($_.PNPClass)"; VID = $vid; PID = $pidv }
        } | Sort-Object Name, VID, PID -Unique)
    $out['UsbDevices'] = $usb
    $out['NotableDevices'] = @($pnp | Where-Object { "$($_.Name) $($_.Manufacturer)" -match $notableRegex -and "$($_.PNPClass)" -notmatch '^(System|SoftwareDevice|SoftwareComponent|Net|Monitor|Display)$' } |
        ForEach-Object { '{0} [{1}]' -f $_.Name, $_.PNPClass } | Sort-Object -Unique)
    $out['Docks'] = @($pnp | Where-Object { $_.Name -match 'Dock|WD19|WD22|TB16|TB18|Thunderbolt\(TM\) Controller|DisplayLink|USB-C Dock|CalDigit|Plugable|Targus|Kensington' } | ForEach-Object { $_.Name } | Sort-Object -Unique)

    # Displays
    $mons = @()
    try {
        $ids = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -OperationTimeoutSec 15 -ErrorAction Stop)
        $parms = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -OperationTimeoutSec 15 -ErrorAction SilentlyContinue)
        foreach ($m in $ids) {
            $dec = { param($a) if ($a) { (($a | Where-Object { $_ -ne 0 }) | ForEach-Object { [char]$_ }) -join '' } }
            $bp = $parms | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
            $diag = $null
            if ($bp -and $bp.MaxHorizontalImageSize -gt 0) { $diag = [math]::Round([math]::Sqrt([math]::Pow($bp.MaxHorizontalImageSize, 2) + [math]::Pow($bp.MaxVerticalImageSize, 2)) / 2.54, 1) }
            $mons += [pscustomobject]@{ Manufacturer = & $dec $m.ManufacturerName; Model = & $dec $m.UserFriendlyName; Serial = & $dec $m.SerialNumberID; Year = $m.YearOfManufacture; DiagonalInches = $diag }
        }
    } catch { }
    $out['Monitors'] = $mons
    $screens = @()
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $screens = @([System.Windows.Forms.Screen]::AllScreens | ForEach-Object { [pscustomobject]@{ Device = $_.DeviceName; Primary = $_.Primary; Width = $_.Bounds.Width; Height = $_.Bounds.Height } })
    } catch { }
    $out['Screens'] = $screens
    $out['MonitorCount'] = [math]::Max($mons.Count, $screens.Count)
    $out['Gpu'] = @(Get-CimInstance Win32_VideoController -OperationTimeoutSec 15 | ForEach-Object { '{0} (driver {1})' -f $_.Name, $_.DriverVersion })

    # Local peripherals vs RDP redirection settings
    $rdpFiles = @()
    if ($Result['Rdp'] -and $Result['Rdp'].Contains('RdpFiles')) { $rdpFiles = @($Result['Rdp']['RdpFiles']) }
    $realPrinters = @($printers | Where-Object { -not $_.IsVirtual })
    $checks = @()
    foreach ($r in $rdpFiles) {
        $eff = [ordered]@{
            Printers   = if ($r.Contains('redirectprinters')) { $r['redirectprinters'] -eq '1' } else { $true }
            Clipboard  = if ($r.Contains('redirectclipboard')) { $r['redirectclipboard'] -eq '1' } else { $true }
            Drives     = if ($r.Contains('drivestoredirect')) { [bool]$r['drivestoredirect'] } else { $false }
            SmartCards = if ($r.Contains('redirectsmartcards')) { $r['redirectsmartcards'] -eq '1' } else { $true }
            ComPorts   = if ($r.Contains('redirectcomports')) { $r['redirectcomports'] -eq '1' } else { $false }
            UsbDevices = if ($r.Contains('usbdevicestoredirect')) { [bool]$r['usbdevicestoredirect'] } else { $false }
            Camera     = if ($r.Contains('camerastoredirect')) { [bool]$r['camerastoredirect'] } else { $false }
            AudioPlay  = if ($r.Contains('audiomode')) { $r['audiomode'] -eq '0' } else { $true }
            Microphone = if ($r.Contains('audiocapturemode')) { $r['audiocapturemode'] -eq '1' } else { $false }
            MultiMon   = if ($r.Contains('use multimon')) { $r['use multimon'] -eq '1' } else { $false }
        }
        $gaps = @()
        if ($realPrinters.Count -gt 0 -and -not $eff.Printers) { $gaps += 'local printers but printer redirection off' }
        if ($byClass['SmartCard'].Count -gt 0 -and -not $eff.SmartCards) { $gaps += 'smart card reader but smart card redirection off' }
        if ($byClass['Serial/COM'].Count -gt 0 -and -not $eff.ComPorts) { $gaps += 'COM devices but COM redirection off' }
        if ($byClass['Scanner/Camera'].Count -gt 0 -and -not ($eff.Camera -or $eff.UsbDevices)) { $gaps += 'scanner/camera present but camera/USB redirection off' }
        if ($out['MonitorCount'] -gt 1 -and -not $eff.MultiMon) { $gaps += 'multiple monitors but multimon off' }
        $checks += [pscustomobject]@{ RdpFile = $r['Path']; Target = $r['full address']; Effective = $eff; Gaps = $gaps }
    }
    $out['RedirectionCheck'] = $checks
    $out
}
