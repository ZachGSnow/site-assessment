# ---------------------------------------------------------------------
# Inventoried user (the signed-in console user, not necessarily the runner)
# ---------------------------------------------------------------------
$script:UserSid = $currentId.User.Value
$script:UserName = $currentId.Name
$script:UserProfile = $env:USERPROFILE
try {
    $mySession = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $explorers = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -OperationTimeoutSec 15
    $exp = $explorers | Where-Object { $_.SessionId -eq $mySession } | Select-Object -First 1
    if (-not $exp) { $exp = $explorers | Select-Object -First 1 }
    if ($exp) {
        $sidResult = Invoke-CimMethod -InputObject $exp -MethodName GetOwnerSid
        $ownResult = Invoke-CimMethod -InputObject $exp -MethodName GetOwner
        if ($sidResult.Sid) {
            $script:UserSid = $sidResult.Sid
            $script:UserName = ('{0}\{1}' -f $ownResult.Domain, $ownResult.User)
            $prof = Get-CimInstance Win32_UserProfile -Filter ("SID='{0}'" -f $script:UserSid) -OperationTimeoutSec 15
            if ($prof -and $prof.LocalPath) { $script:UserProfile = $prof.LocalPath }
        }
    }
} catch { }
$script:UserHive = "Registry::HKEY_USERS\$($script:UserSid)"
$script:SameUser = ($script:UserSid -eq $currentId.User.Value)
$script:UserDesktop   = Get-UserFolder 'Desktop' 'Desktop'
$script:UserDocuments = Get-UserFolder 'Personal' 'Documents'
$script:UserDownloads = Get-UserFolder '{374DE290-123F-4565-9164-39C4925E467B}' 'Downloads'
$script:UserLocalApp  = Join-Path $script:UserProfile 'AppData\Local'
$script:UserRoaming   = Join-Path $script:UserProfile 'AppData\Roaming'

# Output folder
if ($OutputPath) { $OutputRoot = $OutputPath }
if ($NoPrompt) { $OpenFolderWhenDone = $false; $CopySummaryToClipboard = $false }
if (-not $OutputRoot) {
    # Same path on every machine, writable by standard users, not synced to the client's OneDrive.
    $candidates = @((Join-Path ([Environment]::GetFolderPath('CommonDocuments')) 'SiteAssessment'),
                    (Join-Path $script:UserProfile 'SiteAssessment'),
                    (Join-Path $env:TEMP 'SiteAssessment'))
    foreach ($c in $candidates) { if (Test-WritableFolder $c) { $OutputRoot = $c; break } }
}
if (-not $OutputRoot -or -not (Test-WritableFolder $OutputRoot)) { $OutputRoot = $env:TEMP }
$runName = '{0}_{1}_{2}' -f $siteSafe, $env:COMPUTERNAME, $RunStart.ToString('yyyyMMdd-HHmm')
$OutDir = Join-Path $OutputRoot $runName
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $OutDir 'transcript.log') -Force | Out-Null; $script:Transcript = $true } catch { $script:Transcript = $false }

Write-Step ("Site: {0}   Inventoried user: {1}   Output: {2}" -f $SiteName, $script:UserName, $OutDir) 'White'

$Result['Meta'] = [ordered]@{
    ScriptVersion     = $ScriptVersion
    SiteName          = $SiteName
    Notes             = $Notes
    Hostname          = $env:COMPUTERNAME
    RunStart          = Format-Date $RunStart
    TimeZone          = [TimeZoneInfo]::Local.Id
    RunAsUser         = $currentId.Name
    InventoriedUser   = $script:UserName
    InventoriedSid    = $script:UserSid
    InventoriedProfile = $script:UserProfile
    SameUser          = $script:SameUser
    IsElevated        = $isElevated
    Discovery         = [bool]$EnableDiscovery
    HostedDesktop     = [ordered]@{ Profile = $HostedDesktopName; Name = $HostedLabel; HostPattern = "$($HostedProfile.HostPattern)"; Targets = @($ExtraTargets) }
    AdminTierActive   = $script:AdminActive
    AdminDowngraded   = $false
    LanguageMode      = "$($ExecutionContext.SessionState.LanguageMode)"
    PSVersion         = $PSVersionTable.PSVersion.ToString()
    PSHost            = $Host.Name
    Options           = [ordered]@{
        SubnetSweep = $EnableSubnetSweep; GatewayProbe = $EnableGatewayProbe; IpInfo = $EnableIpInfo
        FirewallPorts = $EnableFirewallPorts; Ssdp = $EnableSsdp; PrinterProbe = $EnablePrinterProbe
        SweepPorts = $EnableSweepPorts; RemoteSweep = $EnableRemoteSweep; TlsCheck = $EnableTlsCheck
        OuiLookup = $EnableOuiLookup; Ipv6Check = $EnableIpv6Check; DomainCheck = $EnableDomainCheck; Bandwidth = $EnableBandwidth; BandwidthSeconds = $BandwidthSeconds
        BandwidthStreams = $BandwidthStreams; MaxTestMB = $MaxTestMB; PingCount = $PingCount; LookbackDays = $LookbackDays
        BandwidthRounds = $BandwidthRounds; VendorDiscovery = $EnableVendorDiscovery; MulticastDiscovery = $EnableMulticastDiscovery
        Snmp = $EnableSnmp; ModemPage = $EnableModemPage; WindowsBuild = $EnableWindowsBuild; DnsTiming = $EnableDnsTiming; CloudCheck = $EnableCloudCheck
        VoiceSample = $EnableVoiceSample; PrinterQuery = $EnablePrinterQuery; CameraQuery = $EnableCameraQuery; OutboundCheck = $EnableOutboundCheck
        GatewayServices = $EnableGatewayServices; TunnelReach = $EnableTunnelReach; DhcpRenew = $EnableDhcpRenew
        LeadChecks = $EnableLeadChecks; AdSites = $EnableAdSites; DeviceIdentify = $EnableDeviceIdentify; DnsDiscovery = $EnableDnsDiscovery; SiteReach = $EnableSiteReach; OwnerLookup = $EnableOwnerLookup
    }
}
