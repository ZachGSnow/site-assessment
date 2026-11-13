$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$RunStart = Get-Date

# Paste check: a copy cut short by the clipboard could run part-way and save nothing.
# The last line of this file is a marker; if it is missing, stop before doing anything.
$endMarker = '# END OF ' + 'COLLECTOR SCRIPT'
$selfText = $null
try {
    if ($PSCommandPath) { $selfText = Get-Content -LiteralPath $PSCommandPath -Raw -ErrorAction Stop }
    elseif ($psISE -and $psISE.CurrentFile) { $selfText = $psISE.CurrentFile.Editor.Text }
} catch { }
if ($selfText -and $selfText -notlike "*$endMarker*") {
    Write-Host ''
    Write-Host 'STOP: this copy of the script is incomplete (the end of the file is missing).' -ForegroundColor Red
    Write-Host 'The paste was probably cut short. Nothing was run. Paste it again, or transfer the .ps1 file and open that.' -ForegroundColor Red
    return
}
