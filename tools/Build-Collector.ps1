<#
.SYNOPSIS
    Builds Collect-SiteAssessment.ps1, the single file you paste into PowerShell ISE, from src\collector.

.DESCRIPTION
    The collector is kept as small files so it can be read, reviewed and changed in pieces, but it is
    used as one script (pasted into ISE, or copied to a PC on its own). This joins the pieces in order:
    00-header.ps1 (help and parameters), 10-config.ps1 (CONFIG), lib\*.ps1 (every function),
    run\*.ps1 (what a run does, in order) and 99-end.ps1 (the paste-check marker).

    Edit the files under src\collector, run this, and commit both. The tests fail when the committed
    Collect-SiteAssessment.ps1 does not match what this builds.

.PARAMETER OutFile
    Where to write the result (default: Collect-SiteAssessment.ps1 at the repository root).

.PARAMETER Check
    Do not write anything; exit 1 if the existing file differs from what would be built.
#>
param(
    [string]$OutFile,
    [switch]$Check
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'src\collector'
if (-not $OutFile) { $OutFile = Join-Path $root 'Collect-SiteAssessment.ps1' }

$parts = @((Join-Path $src '00-header.ps1'), (Join-Path $src '10-config.ps1'))
$parts += @(Get-ChildItem -LiteralPath (Join-Path $src 'lib') -Filter *.ps1 -File | Sort-Object Name | ForEach-Object { $_.FullName })
$parts += @(Get-ChildItem -LiteralPath (Join-Path $src 'run') -Filter *.ps1 -File | Sort-Object Name | ForEach-Object { $_.FullName })
$parts += (Join-Path $src '99-end.ps1')

$sb = New-Object Text.StringBuilder
for ($i = 0; $i -lt $parts.Count; $i++) {
    $t = ([IO.File]::ReadAllText($parts[$i]) -replace "`r?`n", "`r`n").Trim("`r", "`n")
    [void]$sb.Append($t)
    if ($i -lt $parts.Count - 1) { [void]$sb.Append("`r`n`r`n") } else { [void]$sb.Append("`r`n") }
}
$built = $sb.ToString()

$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($built, [ref]$null, [ref]$errors)
if ($errors) { throw "The built collector does not parse: line $($errors[0].Extent.StartLineNumber): $($errors[0].Message)" }

if ($Check) {
    $current = if (Test-Path -LiteralPath $OutFile) { [IO.File]::ReadAllText($OutFile) -replace "`r?`n", "`n" } else { '' }
    if ($current -ne ($built -replace "`r`n", "`n")) {
        Write-Host "$OutFile is out of date: run tools\Build-Collector.ps1 and commit the result." -ForegroundColor Red
        exit 1
    }
    Write-Host "$OutFile matches src\collector ($($parts.Count) parts)."
    exit 0
}
[IO.File]::WriteAllText($OutFile, $built, (New-Object Text.UTF8Encoding $false))
Write-Host "Built $OutFile from $($parts.Count) parts."
