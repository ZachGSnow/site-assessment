# ---------------------------------------------------------------------
# Email and domain posture from public DNS: where mail goes and whether SPF, DMARC and DKIM protect the
# client's domain. The domain comes from what the PC already knows (the user's sign-in name, the DNS
# suffixes, the AD forest); internal-only names are left out.
# ---------------------------------------------------------------------
function Get-ClientDomains {
    param($R)
    $names = @()
    $upn = "$(Get-Prop $R 'Identity', 'Upn')"; if ($upn -match '@([A-Za-z0-9.-]+)$') { $names += $matches[1] }
    $names += @(Get-Prop $R 'NetworkExtra', 'DnsSuffixSearch')
    $names += "$(Get-Prop $R 'Machine', 'Domain')"
    $names += "$(Get-Prop $R 'AdSites', 'Forest')"
    $out = @()
    foreach ($n in $names) {
        $d = "$n".Trim().TrimEnd('.').ToLower()
        if ($d -notmatch '^[a-z0-9-]+(\.[a-z0-9-]+)+$') { continue }
        if ($d -match '\.(local|lan|internal|intra|intranet|corp|home|localdomain|private|ad|domain|test|example|invalid)$|onmicrosoft\.com$|\.arpa$') { continue }
        $parts = @($d.Split('.'))
        # The registrable domain: the last two labels, or three for names like contoso.co.uk
        $keep = if ($parts.Count -ge 3 -and $parts[-1].Length -eq 2 -and $parts[-2] -in @('co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'ltd', 'plc')) { 3 } else { 2 }
        if ($parts.Count -lt $keep) { continue }
        $out += ($parts[($parts.Count - $keep)..($parts.Count - 1)] -join '.')
    }
    return @($out | Select-Object -Unique)
}

function Get-MailProvider {
    param([string[]]$MxHosts)
    $t = (@($MxHosts) -join ' ').ToLower()
    if (-not $t) { return $null }
    if ($t -match 'mail\.protection\.outlook\.com') { return 'Microsoft 365' }
    if ($t -match 'google\.com|googlemail\.com') { return 'Google Workspace' }
    if ($t -match 'pphosted\.com|ppe-hosted\.com') { return 'Proofpoint' }
    if ($t -match 'mimecast') { return 'Mimecast' }
    if ($t -match 'barracudanetworks\.com') { return 'Barracuda' }
    if ($t -match 'iphmx\.com') { return 'Cisco Secure Email' }
    if ($t -match 'messagelabs|symanteccloud') { return 'Broadcom Email Security' }
    if ($t -match 'sophos') { return 'Sophos Email' }
    if ($t -match 'secureserver\.net') { return 'GoDaddy' }
    if ($t -match 'zoho') { return 'Zoho Mail' }
    return 'other or self-hosted'
}

function Get-SpfSummary {
    # The SPF record among a domain's TXT records: the record, how it ends (-all, ~all, ?all, +all),
    # how many DNS lookups it costs at the top level (10 is the limit), and whether there is more than one.
    param([string[]]$Txt)
    $spf = @(@($Txt) | Where-Object { "$_" -match '^\s*v=spf1\b' })
    if (-not $spf.Count) { return [pscustomobject]@{ Present = $false; Record = $null; All = $null; Lookups = 0; Multiple = $false } }
    $rec = "$($spf[0])"
    $all = if ($rec -match '([-~?+]?)all\b') { if ($matches[1]) { "$($matches[1])all" } else { '+all' } } elseif ($rec -match 'redirect=') { 'redirect' } else { 'none' }
    # Count term by term: include, a, mx, ptr, exists and redirect each cost a lookup (ip4, ip6 and all do not).
    $lookups = @(@($rec -split '\s+') | Where-Object { ($_ -replace '^[-~?+]', '') -match '^(?i)(include:|a$|a[:/]|mx$|mx[:/]|ptr|exists:|redirect=)' }).Count
    return [pscustomobject]@{ Present = $true; Record = $rec; All = $all; Lookups = $lookups; Multiple = ($spf.Count -gt 1) }
}

function Get-DmarcSummary {
    param([string[]]$Txt)
    $rec = @(@($Txt) | Where-Object { "$_" -match '^\s*v=DMARC1' }) | Select-Object -First 1
    if (-not $rec) { return [pscustomobject]@{ Present = $false; Record = $null; Policy = $null; Pct = $null; Reports = $false } }
    $tag = { param($n) if ("$rec" -match "(?i)(?:^|;)\s*$n\s*=\s*([^;]+)") { $matches[1].Trim() } else { $null } }
    return [pscustomobject]@{ Present = $true; Record = "$rec"; Policy = (& $tag 'p'); Pct = (& $tag 'pct'); Reports = [bool](& $tag 'rua') }
}

function Resolve-PublicDns {
    # A lookup through a public resolver first (internal DNS often answers differently for the client's
    # own domain), then through this PC's resolver. Returns the answer records of the asked type.
    param([string]$Name, [string]$Type)
    foreach ($srv in @('1.1.1.1', $null)) {
        try {
            $a = if ($srv) { @(Resolve-DnsName -Name $Name -Type $Type -Server $srv -DnsOnly -QuickTimeout -ErrorAction Stop) } else { @(Resolve-DnsName -Name $Name -Type $Type -DnsOnly -QuickTimeout -ErrorAction Stop) }
            return @($a | Where-Object { "$($_.Type)" -eq $Type })
        } catch {
            if ("$($_.Exception.Message)" -match 'does not exist|DNS name does not exist|NXDOMAIN|No records') { return @() }
        }
    }
    return @()
}

function Get-DomainPosture {
    param([string]$Domain)
    $txt = { param($n) @(Resolve-PublicDns $n 'TXT' | ForEach-Object { (@($_.Strings) -join '') }) }
    $mx = @(Resolve-PublicDns $Domain 'MX' | Sort-Object Preference | ForEach-Object { "$($_.NameExchange)".TrimEnd('.').ToLower() } | Where-Object { $_ })
    $spf = Get-SpfSummary (& $txt $Domain)
    $dmarc = Get-DmarcSummary (& $txt "_dmarc.$Domain")
    $dkim = @()
    foreach ($sel in @('selector1', 'selector2', 'google', 'k1', 's1', 'default')) {
        $c = @(Resolve-PublicDns "$sel._domainkey.$Domain" 'CNAME')
        # A key must have a value: "p=" with nothing after it is how a domain says it has no DKIM key.
        $t = if (-not $c.Count) { @(& $txt "$sel._domainkey.$Domain" | Where-Object { $_ -match '(?:^|;)\s*p=[A-Za-z0-9+/]{20,}' }) } else { @() }
        if ($c.Count -or $t.Count) { $dkim += $sel }
    }
    $auto = @(Resolve-PublicDns "autodiscover.$Domain" 'CNAME' | ForEach-Object { "$($_.NameHost)".TrimEnd('.').ToLower() })
    return [ordered]@{
        Domain = $Domain; Mx = $mx; Provider = (Get-MailProvider $mx)
        Spf = $spf; Dmarc = $dmarc; DkimSelectors = $dkim
        MtaSts = [bool]@(& $txt "_mta-sts.$Domain" | Where-Object { $_ -match 'v=STSv1' }).Count
        TlsRpt = [bool]@(& $txt "_smtp._tls.$Domain" | Where-Object { $_ -match 'v=TLSRPTv1' }).Count
        Autodiscover = @($auto | Select-Object -First 1)
    }
}

function Get-DomainFlags {
    # Severity, Category, Message rows for what public DNS shows about one domain.
    param($P)
    $d = "$(Get-Prop $P 'Domain')"
    $out = @()
    $f = { param($sev, $msg) [pscustomobject]@{ Severity = $sev; Category = 'Email security'; Message = $msg; SiteWide = $true } }
    $hasMx = @(Get-Prop $P 'Mx').Count -gt 0
    $spf = Get-Prop $P 'Spf'; $dm = Get-Prop $P 'Dmarc'
    if (-not (Get-Prop $spf 'Present')) { $out += & $f $(if ($hasMx) { 'Medium' } else { 'Low' }) "${d}: no SPF record, so anyone can send mail that claims to come from it" }
    elseif ("$(Get-Prop $spf 'All')" -eq '+all') { $out += & $f 'High' "${d}: the SPF record ends in +all, which allows every server on the internet to send as it" }
    elseif ("$(Get-Prop $spf 'All')" -in @('?all', 'none')) { $out += & $f 'Low' "${d}: the SPF record does not end in -all or ~all, so it protects nothing" }
    if (Get-Prop $spf 'Multiple') { $out += & $f 'Medium' "${d}: more than one SPF record, which makes SPF fail for every message" }
    if ([int](Get-Prop $spf 'Lookups') -gt 10) { $out += & $f 'Medium' "${d}: the SPF record needs more than 10 DNS lookups, which makes SPF fail" }
    if (-not (Get-Prop $dm 'Present')) { $out += & $f 'Medium' "${d}: no DMARC record, so spoofed mail claiming to be from it is delivered" }
    elseif ("$(Get-Prop $dm 'Policy')" -eq 'none') { $out += & $f 'Low' "${d}: DMARC is set to p=none, which only reports and blocks nothing" }
    if ($hasMx -and "$(Get-Prop $P 'Provider')" -eq 'Microsoft 365' -and -not @(Get-Prop $P 'DkimSelectors' | Where-Object { $_ -like 'selector*' }).Count) { $out += & $f 'Low' "${d}: Microsoft 365 DKIM signing is not published (no selector1/selector2 records)" }
    return $out
}
