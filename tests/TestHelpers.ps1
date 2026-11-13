# Shared helpers for the Pester tests.

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:CollectorPath = Join-Path $script:RepoRoot 'Collect-SiteAssessment.ps1'
$script:MergePath = Join-Path $script:RepoRoot 'Merge-SiteAssessment.ps1'

function Get-ScriptFunctionText {
    # The collector runs top to bottom when invoked, so tests load its top-level functions from the
    # parsed file instead of running it. Returns one script text with every top-level function.
    param([string]$Path)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Parse errors in ${Path}: $($errors[0].Message)" }
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    return (($fns | ForEach-Object { $_.Extent.Text }) -join "`n")
}

function Get-ConfigScript {
    # The param block and CONFIG section of the collector (everything before $ScriptVersion), followed
    # by a line that returns the resolved settings. Lets tests check defaults, -Discovery and profiles.
    param([string]$Path)
    $text = [IO.File]::ReadAllText($Path)
    $cut = $text.IndexOf('$ScriptVersion = ')
    if ($cut -lt 0) { throw 'No $ScriptVersion line in the collector' }
    $out = @'

$vars = [ordered]@{}
foreach ($v in Get-Variable -Scope Local) { $vars[$v.Name] = $v.Value }
$vars
'@
    return [scriptblock]::Create($text.Substring(0, $cut) + $out)
}
