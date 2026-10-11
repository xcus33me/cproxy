# Managed by cproxy
# Run a private temporary copy so Windows can update/remove the installed binary.
$ErrorActionPreference='Stop'
. "$PSScriptRoot\common.ps1"
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cproxy-ui-'+[guid]::NewGuid())
$previous=$env:CPROXY_SOURCE_DIR
try {
    New-Item -ItemType Directory $temp | Out-Null; Set-PrivateAcl $temp
    $binary=Join-Path $temp 'cproxy.exe'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'cproxy-ui.exe') -Destination $binary
    $env:CPROXY_SOURCE_DIR=$PSScriptRoot
    $code=(Invoke-Native $binary @($args) $false).ExitCode
} finally { $env:CPROXY_SOURCE_DIR=$previous; Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
exit $code
