$ErrorActionPreference='Stop'
$failed=$false
Get-ChildItem "$PSScriptRoot/../windows/*.ps1","$PSScriptRoot/*.ps1","$PSScriptRoot/../cproxy.ps1" | ForEach-Object {
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { $errors | Format-List; $failed=$true }
}
if ($failed) { exit 1 }; Write-Host 'PASS: PowerShell syntax'
