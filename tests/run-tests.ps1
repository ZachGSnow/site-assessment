# Runs every Pester test and exits non-zero on any failed, skipped or not-run test.
# Works in Windows PowerShell 5.1 and PowerShell 7 (CI runs both). Needs Pester 5 or later:
#   Install-Module Pester -RequiredVersion 6.2.0 -Scope CurrentUser -Force -SkipPublisherCheck
$ErrorActionPreference = 'Stop'
$pester = Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester -or $pester.Version.Major -lt 5) { throw 'Pester 5 or later is required (see the comment at the top of this file).' }
Import-Module $pester.Path -Force

$cfg = New-PesterConfiguration
$cfg.Run.Path = $PSScriptRoot
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Detailed'
$r = Invoke-Pester -Configuration $cfg

Write-Host ('PowerShell {0}: {1} passed, {2} failed, {3} skipped, {4} not run' -f $PSVersionTable.PSVersion, $r.PassedCount, $r.FailedCount, $r.SkippedCount, $r.NotRunCount)
if ($r.Result -ne 'Passed' -or $r.FailedCount -or $r.SkippedCount -or $r.NotRunCount -or $r.FailedContainersCount) { exit 1 }
exit 0
