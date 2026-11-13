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
