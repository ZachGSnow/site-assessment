BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')

    function Invoke-Merge {
        # Runs the merge in a child process of the same PowerShell, as a user would, with no network.
        param([string]$Path, [string[]]$Extra = @())
        $exe = (Get-Process -Id $PID).Path
        $out = & $exe -NoProfile -ExecutionPolicy Bypass -File $MergePath -Path $Path -ClientName 'Northwind Traders' -NoEnrich @Extra 2>&1
        if ($LASTEXITCODE) { throw "Merge failed: $($out -join "`n")" }
        return (Join-Path $Path '_merged')
    }

    $script:Single = Join-Path $TestDrive 'single'
    New-SingleSiteFixture $Single
    $script:SingleOut = Invoke-Merge $Single

    $script:Multi = Join-Path $TestDrive 'multi'
    New-MultiSiteFixture $Multi
    $script:MultiOut = Invoke-Merge $Multi
}

Describe 'Merge script' {
    It 'parses without errors' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($MergePath, [ref]$null, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }
}

Describe 'One machine at one site' {
    BeforeAll {
        $script:Sites = @(Import-Csv (Join-Path $SingleOut 'Sites.csv'))
        $script:Html = [IO.File]::ReadAllText((Join-Path $SingleOut 'Report.html'))
    }
    It 'writes the report and every CSV' {
        foreach ($f in 'Report.html', 'Sites.csv', 'Endpoints.csv', 'Flags.csv', 'Findings.csv', 'Traceroutes.csv', 'PingSeries.csv') {
            Join-Path $SingleOut $f | Should -Exist
        }
    }
    It 'reports the one site with its verdict and circuit' {
        $Sites.Count | Should -Be 1
        $Sites[0].Site | Should -Be 'Main office'
        $Sites[0].Verdict | Should -Be 'Local breakout'
        [double]$Sites[0].CircuitDownMbps | Should -Be 480
    }
    It 'explains what one machine shows instead of warning about it' {
        $Html | Should -Match 'One machine tested'
        $Html | Should -Not -Match 'Fewer than 2 endpoints'
    }
    It 'leaves out the site comparison table' {
        $Html | Should -Not -Match 'Site comparison table'
    }
    It 'labels the round trip with the run''s hosted desktop profile' {
        $Html | Should -Match 'Round trip to Remote desktop'
    }
    It 'takes the sample count from the data' {
        $Html | Should -Match '180 pings to 1\.1\.1\.1'
    }
}

Describe 'Two sites, a hosted desktop and a visiting laptop' {
    BeforeAll {
        $script:Sites = @(Import-Csv (Join-Path $MultiOut 'Sites.csv'))
        $script:Eps = @(Import-Csv (Join-Path $MultiOut 'Endpoints.csv'))
        $script:Html = [IO.File]::ReadAllText((Join-Path $MultiOut 'Report.html'))
        $script:Main = $Sites | Where-Object Site -eq 'Main office'
        $script:Warehouse = $Sites | Where-Object Site -eq 'Warehouse'
    }
    It 'groups the runs into two sites' {
        $Sites.Count | Should -Be 2
        [int]$Main.Endpoints | Should -Be 3
        [int]$Warehouse.Endpoints | Should -Be 2
    }
    It 'spots the laptop seen at both sites as a test device' {
        @($Eps | Where-Object { $_.Hostname -eq 'TECH-LAPTOP' } | ForEach-Object Role | Sort-Object -Unique) | Should -Be @('Test laptop')
        @($Eps | Where-Object { $_.Hostname -ne 'TECH-LAPTOP' } | ForEach-Object Role | Sort-Object -Unique) | Should -Be @('Client PC')
    }
    It 'drops the test laptop''s own remote desktop targets and keeps the hosted desktop' {
        $rdp = @(Import-Csv (Join-Path $MultiOut 'PingSeries.csv') | Where-Object { $_.Hostname -eq 'TECH-LAPTOP' })
        @($rdp | Where-Object { $_.Target -like 'jumpbox.example.net*' }).Count | Should -Be 0
        @($rdp | Where-Object { $_.Target -like 'connect.contosocloud.com*' }).Count | Should -BeGreaterThan 0
    }
    It 'flags two sites that leave through the same public address' {
        $Main.Verdict | Should -Be 'Shared egress with other site(s)'
        $Main.Notes | Should -Match 'Same public IP as Warehouse'
    }
    It 'warns when two bandwidth tests at a site overlapped' {
        $Main.Notes | Should -Match 'Bandwidth tests ran at the same time'
    }
    It 'measures the round trip to the hosted desktop named in the profile' {
        [double]$Main.HostedMedianMs | Should -Be 38
        $Html | Should -Match 'Round trip to Contoso Cloud'
        $Html | Should -Match 'Contoso Cloud ms'
    }
    It 'shows the site comparison table' {
        $Html | Should -Match 'Site comparison table'
    }
    It 'counts the Windows 10 PC as a high finding' {
        $Html | Should -Match 'Windows 10 \(out of support'
    }
}

Describe 'Devices swept across routing' {
    BeforeAll {
        $script:Devs = @(Import-Csv (Join-Path $MultiOut 'Devices.csv'))
        $script:Subs = @(Import-Csv (Join-Path $MultiOut 'Subnets.csv'))
        $script:Html = [IO.File]::ReadAllText((Join-Path $MultiOut 'Report.html'))
    }
    It 'files them under the site that owns their subnet' {
        $mfp = $Devs | Where-Object IP -eq '10.20.2.40'
        $mfp.Site | Should -Be 'Warehouse'
        $mfp.SeenFrom | Should -Be 'NW-FRONT01 at Main office, across routing'
        $mfp.Subnet | Should -Be '10.20.2.0/24'
    }
    It 'keeps a MAC learned from NetBIOS and says where it came from' {
        $pc = $Devs | Where-Object IP -eq '10.20.2.31'
        $pc.Mac | Should -Be '00-15-5D-01-02-03'
        $pc.MacSource | Should -Be 'NetBIOS'
    }
    It 'records the swept subnet and what answered' {
        $w = $Subs | Where-Object { $_.Subnet -eq '10.20.2.0/24' -and $_.Site -eq 'Warehouse' }
        $w | Should -Not -BeNullOrEmpty
        $w.Sources | Should -Match 'swept it from Main office'
        $w.Notes | Should -Match '2 devices answered'
    }
    It 'lists them in their own table in the report' {
        $Html | Should -Match 'Devices on other subnets, swept across routing \(2\)'
    }
}

Describe 'Router and UPS tables in the report' {
    BeforeAll {
        $script:Ra = @(Import-Csv (Join-Path $MultiOut 'RouterAddresses.csv'))
        $script:Rt = @(Import-Csv (Join-Path $MultiOut 'Routes.csv'))
        $script:Ups = @(Import-Csv (Join-Path $MultiOut 'Ups.csv'))
        $script:Gear = @(Import-Csv (Join-Path $MultiOut 'NetworkGear.csv'))
        $script:Html = [IO.File]::ReadAllText((Join-Path $MultiOut 'Report.html'))
    }
    It 'lists the router''s addresses with the WAN side marked public' {
        ($Ra | Where-Object Address -eq '203.0.113.42').Class | Should -Be 'Public'
        ($Ra | Where-Object Address -eq '203.0.113.42').Site | Should -Be 'Main office'
    }
    It 'lists the routes' {
        $Rt.Count | Should -Be 2
        ($Rt | Where-Object Destination -eq '10.20.2.0').NextHop | Should -Be '10.20.1.254'
    }
    It 'lists the UPS and that it is on battery' {
        $Ups.Count | Should -Be 1
        $Ups[0].OnBattery | Should -Be 'True'
        $Ups[0].MinutesRemaining | Should -Be '12'
    }
    It 'adds SNMP devices to the network equipment' {
        ($Gear | Where-Object { $_.Type -eq 'Router (SNMP)' }).Name | Should -Be 'nw-fw01'
        ($Gear | Where-Object { $_.Type -eq 'UPS (SNMP)' }).Detail | Should -Match 'ON BATTERY'
    }
    It 'shows the router''s WAN address in the site facts and a routers section' {
        $Html | Should -Match 'Router WAN address \(SNMP\)'
        $Html | Should -Match 'Routers and UPS \(SNMP\)'
    }
}

Describe 'Network risks in the merged report' {
    BeforeAll { $script:Fl = @(Import-Csv (Join-Path $MultiOut 'Flags.csv')) }
    It 'keeps one copy of a network risk two machines at a site both saw' {
        @($Fl | Where-Object { $_.Category -eq 'Network risk' -and $_.Site -eq 'Main office' -and $_.Message -like '*SMBv1*' }).Count | Should -Be 1
    }
    It 'keeps it for the site, not as a device-only finding' {
        ($Fl | Where-Object { $_.Category -eq 'Network risk' } | Select-Object -First 1).Scope | Should -Be 'Site'
    }
}

Describe 'Methodology' {
    BeforeAll {
        $script:HtmlS = [IO.File]::ReadAllText((Join-Path $SingleOut 'Report.html'))
        # Runs from before the sweep's port count and subnet limit were recorded
        $script:OldDir = Join-Path $TestDrive 'older'
        New-Item -ItemType Directory -Path $OldDir -Force | Out-Null
        Save-FixtureRun (New-FixtureRun -Site 'Main office' -Hostname 'NW-OLD01' -Serial 'NWSN0901' -User 'jlee' -SourceIp '10.20.1.26' -Gateway '10.20.1.1' -PublicIp '203.0.113.40' -NoOptions) $OldDir | Out-Null
        $script:HtmlOld = [IO.File]::ReadAllText((Join-Path (Invoke-Merge $OldDir) 'Report.html'))
        $script:MixDir = Join-Path $TestDrive 'mixed'
        New-Item -ItemType Directory -Path $MixDir -Force | Out-Null
        Save-FixtureRun (New-FixtureRun -Site 'Main office' -Hostname 'NW-OLD01' -Serial 'NWSN0901' -User 'jlee' -SourceIp '10.20.1.26' -Gateway '10.20.1.1' -PublicIp '203.0.113.40' -NoOptions) $MixDir | Out-Null
        Save-FixtureRun (New-FixtureRun -Site 'Main office' -Hostname 'NW-NEW01' -Serial 'NWSN0902' -User 'akim' -SourceIp '10.20.1.27' -Gateway '10.20.1.1' -PublicIp '203.0.113.40' -RunStart ([datetime]'2026-03-10T10:00:00')) $MixDir | Out-Null
        $script:HtmlMix = [IO.File]::ReadAllText((Join-Path (Invoke-Merge $MixDir) 'Report.html'))
    }
    It 'takes the sweep port count and subnet limit from the runs' {
        $HtmlS | Should -Match 'tries 22 common TCP ports on each device that answered\.'
        $HtmlS | Should -Match 'at most 8 per run'
    }
    It 'uses neutral wording for runs that did not record them' {
        $HtmlOld | Should -Match 'tries a set of common TCP ports'
        $HtmlOld | Should -Match 'a limited number per run'
    }
    It 'says older runs may differ when old and new runs are merged together' {
        $HtmlMix | Should -Match 'tries 22 common TCP ports on each device that answered \(runs from older collectors may have used a different set\)'
    }
    It 'leaves no placeholder behind' {
        foreach ($h in @($HtmlS, $HtmlOld, $HtmlMix)) { $h | Should -Not -Match '\{(SWEEPPORTS|OLDERPORTS|MAXSUBNETS|HOSTED)\}' }
    }
}

Describe 'Site-wide flags from two machines' {
    BeforeAll {
        . ([scriptblock]::Create((Get-ScriptFunctionText $MergePath)))
        $tel = '{n} device(s) accept Telnet, where logins cross the network in clear text: {list}'
        $risk = {
            param($site, $pc, $tpl, $kind, $devs, $count = -1)
            [pscustomobject]@{ Site = $site; Hostname = $pc; Severity = 'Medium'; Category = 'Network risk'; Message = (Format-RiskMessage $tpl $devs $count); Scope = 'Site'
                Kind = $kind; Template = $tpl; Devices = @($devs); Count = $(if ($count -ge 0) { $count } else { @($devs).Count }); SiteWide = $true }
        }
        $old = { param($site, $cat, $msg) [pscustomobject]@{ Site = $site; Hostname = 'PC'; Severity = 'Medium'; Category = $cat; Message = $msg; Scope = 'Site'; Kind = $null; Template = $null; Devices = @(); Count = $null; SiteWide = $null } }
        $script:Kept = @(Select-SiteWideFlags @(
            (& $risk 'Main office' 'NW-FRONT01' $tel 'Telnet' @('10.0.0.5', '10.0.0.6')),
            (& $risk 'Main office' 'NW-LAB01' $tel 'Telnet' @('10.0.1.7', '10.0.1.8', '10.0.1.9')),
            (& $risk 'Warehouse' 'NW-WH01' $tel 'Telnet' @('10.0.2.5')),
            (& $risk 'Main office' 'NW-FRONT01' "{n} device(s) answer SNMP with the default community 'public'" 'SnmpPublic' @() 3),
            (& $risk 'Main office' 'NW-LAB01' "{n} device(s) answer SNMP with the default community 'public'" 'SnmpPublic' @() 5),
            (& $risk 'Main office' 'NW-FRONT01' '{n} device(s) still accept SMBv1, the file-sharing version WannaCry spread over: {list}' 'Smb1' @('10.0.0.9')),
            (& $old 'Main office' 'Email security' 'contoso.com: no DMARC record, so spoofed mail claiming to be from it is delivered'),
            (& $old 'Main office' 'Email security' 'contoso.com: no DMARC record, so spoofed mail claiming to be from it is delivered'),
            (& $old 'Main office' 'Email security' 'contoso.com: DMARC is set to p=none, which only reports and blocks nothing')))
    }
    It 'keeps one Telnet risk per site, naming every device either machine found' {
        $t = @($Kept | Where-Object { $_.Site -eq 'Main office' -and $_.Kind -eq 'Telnet' })
        $t.Count | Should -Be 1
        $t[0].Message | Should -Be '5 device(s) accept Telnet, where logins cross the network in clear text: 10.0.0.5, 10.0.0.6, 10.0.1.7, 10.0.1.8, 10.0.1.9'
        $t[0].Hostname | Should -Be 'NW-FRONT01, NW-LAB01'
    }
    It 'keeps the larger count for a risk with no device list' {
        (@($Kept | Where-Object { $_.Kind -eq 'SnmpPublic' })).Message | Should -BeLike '5 device(s) answer SNMP*'
    }
    It 'keeps the same risk at another site' {
        @($Kept | Where-Object { $_.Site -eq 'Warehouse' }).Count | Should -Be 1
    }
    It 'keeps different risks apart' {
        @($Kept | Where-Object { $_.Kind -eq 'Smb1' }).Count | Should -Be 1
    }
    It 'keeps different email findings for one domain apart, and drops exact repeats' {
        @($Kept | Where-Object { $_.Category -eq 'Email security' }).Count | Should -Be 2
    }
    It 'treats an AD flag about one PC as that machine''s, and older runs by category' {
        Test-SiteWideFlag ([pscustomobject]@{ Category = 'Active Directory'; SiteWide = $false }) | Should -BeFalse
        Test-SiteWideFlag ([pscustomobject]@{ Category = 'Active Directory'; SiteWide = $true }) | Should -BeTrue
        Test-SiteWideFlag ([pscustomobject]@{ Category = 'Network risk'; SiteWide = $null }) | Should -BeTrue
        Test-SiteWideFlag ([pscustomobject]@{ Category = 'Wireless'; SiteWide = $null }) | Should -BeFalse
    }
}

Describe 'IPv6 in the merged report' {
    BeforeAll {
        $script:Eps6 = @(Import-Csv (Join-Path $MultiOut 'Endpoints.csv'))
        $script:Sites6 = @(Import-Csv (Join-Path $MultiOut 'Sites.csv'))
    }
    It 'records each machine''s IPv6 state, prefix and round trip' {
        $e = $Eps6 | Where-Object Hostname -eq 'NW-FRONT01'
        $e.Ipv6 | Should -Be 'Working'
        $e.Ipv6Prefix | Should -Be '2001:db8:20:1::/64'
        $e.Ipv6Ms | Should -Be '14.2'
    }
    It 'rolls it up per site, showing every state its machines saw' {
        ($Sites6 | Where-Object Site -eq 'Main office').Ipv6 | Should -Be 'Not offered, Working' -Because 'one PC there has IPv6 and two do not'
        ($Sites6 | Where-Object Site -eq 'Warehouse').Ipv6 | Should -Be 'Not offered'
    }
}

Describe 'Leads in the merged report' {
    BeforeAll {
        $script:SubsL = @(Import-Csv (Join-Path $MultiOut 'Subnets.csv'))
        $script:SitesL = @(Import-Csv (Join-Path $MultiOut 'Sites.csv'))
        $script:GearL = @(Import-Csv (Join-Path $MultiOut 'NetworkGear.csv'))
    }
    It 'lists a subnet only Active Directory knows about' {
        $b = $SubsL | Where-Object Subnet -eq '10.20.9.0/24'
        $b.Kind | Should -Be 'Active Directory site'
        $b.Site | Should -Be 'AD site Branch'
    }
    It 'shows the Active Directory site of each office' {
        ($SitesL | Where-Object Site -eq 'Main office').AdSite | Should -Be 'Main-Office'
    }
    It 'adds what the follow-up checks found to the network equipment' {
        ($GearL | Where-Object Type -eq 'Firewall page').Name | Should -Be 'Fortinet SSL-VPN portal'
        ($GearL | Where-Object Type -eq 'VMware host').IP | Should -Be '10.20.1.40'
    }
}

Describe 'Email domains in the merged report' {
    BeforeAll { $script:Doms = @(Import-Csv (Join-Path $MultiOut 'Domains.csv')); $script:HtmlM = [IO.File]::ReadAllText((Join-Path $MultiOut 'Report.html')) }
    It 'lists each domain once, even when several machines checked it' {
        $Doms.Count | Should -Be 1
        $Doms[0].Domain | Should -Be 'northwindtraders.com'
        $Doms[0].Dmarc | Should -Be 'p=none'
    }
    It 'shows the email domain table near the top of the report' {
        $HtmlM | Should -Match 'Email and domain \(public DNS\)'
    }
}

Describe 'Site diagrams' {
    BeforeAll { $script:DiagDir = Join-Path $MultiOut 'diagrams' }
    It 'writes one diagram per site, as valid SVG' {
        foreach ($f in 'Main_office.svg', 'Warehouse.svg') {
            $p = Join-Path $DiagDir $f
            $p | Should -Exist
            { [xml][IO.File]::ReadAllText($p) } | Should -Not -Throw
        }
    }
    It 'draws only what the runs found, with the best name for each box' {
        $t = [IO.File]::ReadAllText((Join-Path $DiagDir 'Main_office.svg'))
        $t | Should -Match 'nw-fw01 \(CF-60\)' -Because 'the gateway''s own SNMP answer beats its MAC vendor'
        $t | Should -Match 'WAN 203\.0\.113\.42'
        $t | Should -Match 'Contoso Cloud'
        $t | Should -Match 'CP1500 ON BATTERY'
        $t | Should -Match 'SSID Northwind-Staff'
        $w = [IO.File]::ReadAllText((Join-Path $DiagDir 'Warehouse.svg'))
        $w | Should -Not -Match 'UPS' -Because 'no UPS was found at the warehouse'
        $w | Should -Not -Match 'Other subnets' -Because 'devices on its own subnet are not other subnets'
    }
    It 'puts the diagram in the report' {
        [IO.File]::ReadAllText((Join-Path $MultiOut 'Report.html')) | Should -Match 'Site diagram'
    }
}

Describe 'Remote desktop transport in the merged report' {
    It 'shows each machine''s transport and the site''s' {
        $e = @(Import-Csv (Join-Path $MultiOut 'Endpoints.csv')) | Where-Object Hostname -eq 'NW-FRONT01'
        $e.RdpTransport | Should -Be 'UDP possible'
        (@(Import-Csv (Join-Path $MultiOut 'Sites.csv')) | Where-Object Site -eq 'Main office').RdpTransport | Should -Be 'UDP possible'
    }
}

Describe 'What to fix first' {
    BeforeAll { $script:HtmlF = [IO.File]::ReadAllText((Join-Path $MultiOut 'Report.html')) }
    It 'opens the report with the fix list, before the overview' {
        $HtmlF.IndexOf('<h2 id="fix">What to fix first</h2>') | Should -BeGreaterThan 0
        $HtmlF.IndexOf('<h2 id="fix">') | Should -BeLessThan $HtmlF.IndexOf('<h2 id="overview">')
    }
    It 'lists each high finding once, worst first, with where it was seen' {
        $list = [regex]::Match($HtmlF, '(?s)<div class="fix"><ol>(.*?)</ol>').Groups[1].Value
        @([regex]::Matches($list, '<li>')).Count | Should -Be 2
        @([regex]::Matches($list, 'SMBv1')).Count | Should -Be 1 -Because 'two machines reported it, it is one line'
        $list | Should -Match 'Windows 10 \(out of support since Oct 2025\) <span class="where">\(Main office - NW-ACCT02\)'
    }
    It 'puts the email domain table after the site comparison' {
        $HtmlF.IndexOf('Email and domain (public DNS)') | Should -BeGreaterThan $HtmlF.IndexOf('Site comparison table')
        $HtmlF | Should -Not -Match '<h2>Key findings</h2>'
    }
}

Describe 'Site diagram after the first real run' {
    It 'shows the ISP box the modem check found and the devices on the local network' {
        $t = [IO.File]::ReadAllText((Join-Path (Join-Path $MultiOut 'diagrams') 'Main_office.svg'))
        $t | Should -Match '192\.168\.100\.1 - Northwind Fiber ONT'
        $t | Should -Match '2 devices on the local network'
        $t | Should -Match 'Contoso Printing'
        $t | Should -Not -Match 'Randomized'
        $t | Should -Match 'public 203\.0\.113\.40 - Northwind Fiber' -Because 'the address comes first so a long carrier name cannot hide it'
    }
}
