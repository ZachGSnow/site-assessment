# (end of helpers)

# =====================================================================
# PREFLIGHT
# =====================================================================
$script:FullLanguage = ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
try { [Net.ServicePointManager]::DefaultConnectionLimit = 64 } catch { }
try { [Net.ServicePointManager]::Expect100Continue = $false } catch { }

$currentId  = [Security.Principal.WindowsIdentity]::GetCurrent()
$isElevated = (New-Object Security.Principal.WindowsPrincipal $currentId).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:AdminActive = $isElevated

Write-Host ''
Write-Host "Site Assessment Collector v$ScriptVersion" -ForegroundColor White
Write-Host ('Running as {0}  elevated={1}  discovery={2}  language={3}' -f $currentId.Name, $isElevated, [bool]$EnableDiscovery, $ExecutionContext.SessionState.LanguageMode)
Write-Host ("Hosted desktop profile: {0}" -f $HostedLabel)
if ($EnableDiscovery) {
    Write-Host 'Discovery is ON: other devices on this network will be swept and asked to identify themselves.' -ForegroundColor Yellow
    Write-Host '                 Only continue on a network you are authorised to assess.' -ForegroundColor Yellow
} else {
    Write-Host 'Discovery is off: only this PC and its path to the internet are measured (-Discovery adds the network).'
}
if ($isElevated) {
    Write-Host 'ISE is elevated: admin checks (TPM, BitLocker, LLDP/CDP, sign-ins, Wi-Fi report) will run.' -ForegroundColor Green
} else {
    Write-Host 'ISE is not elevated: admin checks are skipped (run ISE as administrator to include them).'
}
if (-not $script:FullLanguage) {
    Write-Host 'WARNING: Constrained Language Mode detected (AppLocker/WDAC). Using slower fallbacks.' -ForegroundColor Yellow
}

if (-not $NoPrompt) {
    if (-not $SiteName -and @($SiteList).Count -gt 0) {
        $menu = "Choose the site:`n"
        for ($k = 0; $k -lt $SiteList.Count; $k++) { $menu += ('  {0}) {1}' -f ($k + 1), $SiteList[$k]) + "`n" }
        $menu += '  or type a different site name'
        Write-Host $menu
        $pick = Read-Host 'Site number or name'
        $num = 0
        if ([int]::TryParse("$pick".Trim(), [ref]$num) -and $num -ge 1 -and $num -le $SiteList.Count) { $SiteName = $SiteList[$num - 1] }
        else { $SiteName = $pick }
    }
    if (-not $SiteName) { $SiteName = Read-Host 'Site / office name (required)' }
    if (-not $Notes)    { $Notes    = Read-Host 'Notes (desk/location, optional)' }
}
if (-not $SiteName) { $SiteName = 'UNSPECIFIED' }
$SiteName = $SiteName.Trim()
$siteSafe = ($SiteName -replace '[^A-Za-z0-9_-]', '_')

$Result = [ordered]@{}
