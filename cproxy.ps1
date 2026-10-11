# Source entrypoint. Release bundles include bin/cproxy.exe.
$ErrorActionPreference='Stop'
$ui=Join-Path $PSScriptRoot 'bin\cproxy.exe'
if (-not (Test-Path -LiteralPath $ui)) {
    if (-not (Get-Command go.exe -ErrorAction SilentlyContinue)) {
        if ((Read-Host 'Install Go to build the interface? [y/N]') -ne 'y') { exit 130 }
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'Install Go 1.25.8+ or download a cproxy release bundle.' }
        winget.exe install --id GoLang.Go --exact --source winget
        if ($LASTEXITCODE -ne 0) { throw 'Go installation failed.' }
        $env:Path=[Environment]::GetEnvironmentVariable('Path','Machine')+';'+[Environment]::GetEnvironmentVariable('Path','User')
    }
    New-Item -ItemType Directory (Join-Path $PSScriptRoot '.build') -Force | Out-Null
    $ui=Join-Path $PSScriptRoot '.build\cproxy.exe'
    Push-Location $PSScriptRoot
    try { go.exe build -trimpath -o "$ui.new.exe" ./cmd/cproxy; if ($LASTEXITCODE -ne 0) { throw 'Interface build failed.' }; Move-Item -LiteralPath "$ui.new.exe" -Destination $ui -Force }
    finally { Pop-Location }
}
. "$PSScriptRoot\windows\common.ps1"
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cproxy-ui-'+[guid]::NewGuid())
$previous=$env:CPROXY_SOURCE_DIR
try {
    New-Item -ItemType Directory $temp | Out-Null; Set-PrivateAcl $temp
    $running=Join-Path $temp 'cproxy.exe'; Copy-Item -LiteralPath $ui -Destination $running
    $env:CPROXY_SOURCE_DIR=$PSScriptRoot
    $code=(Invoke-Native $running @($args) $false).ExitCode
}
finally { $env:CPROXY_SOURCE_DIR=$previous; Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
exit $code
