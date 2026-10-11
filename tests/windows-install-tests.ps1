# Windows-only installer transaction tests. Task Scheduler/network are fixtures, never real tasks.
$ErrorActionPreference='Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { Write-Host 'SKIP: Windows installer tests require Windows'; exit 0 }
. "$PSScriptRoot\..\windows\install.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$originalLocal=$env:LOCALAPPDATA
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cproxy install test '+[guid]::NewGuid())
New-Item -ItemType Directory $temp | Out-Null
$env:LOCALAPPDATA=$temp
$script:SPDir=Join-Path $temp 'SelectiveProxy'; $script:SPConfig=Join-Path $script:SPDir 'config.json'; $script:SPSettings=Join-Path $script:SPDir 'settings.json'
$script:TestTask=$null; $script:FailNetwork=$false; $script:Busy=$false
$script:FailStop=$false; $script:FailBackupCleanup=$false
function Remove-Item {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Recurse,[switch]$Force)
    if ($script:FailBackupCleanup -and $LiteralPath -like '*.SelectiveProxy.backup.*') {
        $script:FailBackupCleanup=$false
        throw 'fixture backup cleanup failure'
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse:$Recurse -Force:$Force
}
$fake=Join-Path $temp 'sing-box.cmd'
[IO.File]::WriteAllText($fake,"@echo off`r`nif `"%1`"==`"version`" echo sing-box version 1.12.0`r`nif exist `"$temp\fail-check`" exit /b 1`r`nexit /b 0`r`n")
function Get-SingBox { return $fake }
function Assert-Key($Path) { if (-not (Test-Path -LiteralPath $Path)) { throw 'Key missing' } }
function Confirm-HostKey($Params) { }
function Test-Tcp($Server,$Port) { return $script:Busy }
function Get-ScheduledTask { param($TaskName,$ErrorAction); return $script:TestTask }
function Export-ScheduledTask { param($TaskName); return '<fixture />' }
function New-FixtureTask {
    return [pscustomobject]@{ State='Ready'; Description='Managed by cproxy'; Principal=[pscustomobject]@{UserId=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value};
        Actions=@([pscustomobject]@{Arguments=('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File '+(ConvertTo-NativeArgument (Join-Path $script:SPDir 'run-proxy.ps1')))}) }
}
function Register-ProxyTask($Mode) { $script:TestTask=New-FixtureTask }
function Register-ScheduledTask { param($TaskName,$Xml,[switch]$Force); $script:TestTask=New-FixtureTask }
function Start-ScheduledTask { param($TaskName); $script:TestTask.State='Running' }
function Stop-ScheduledTask { param($TaskName); $script:TestTask.State='Ready' }
function Stop-Proxy {
    Stop-ScheduledTask -TaskName $script:SPTask
    if ($script:FailStop) { $script:FailStop=$false; throw 'fixture stop failure' }
}
function Unregister-ScheduledTask { param($TaskName,$Confirm,$ErrorAction); $script:TestTask=$null }
function Wait-Proxy($Context) { if ($script:FailNetwork) { throw 'fixture network failure' }; return '203.0.113.9' }
$key=Join-Path $temp 'key with spaces'; [IO.File]::WriteAllText($key,'fixture'); Set-PrivateAcl $key
$p=[pscustomobject]@{server='vps.example.org';ssh_port=22;user='proxy';key=$key;host_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF8CGAfWLRTdqdxvGlFtZk7UlGJKCvtaBHwgbLLMRFoh';proxy_port=2080;domains=@('local');cidrs=@('10.0.0.0/8');key_mode='unattended';expected_ips=@('203.0.113.9')}
$params=Join-Path $temp 'params.json'; Write-Json $params $p
try {
    Invoke-SelectiveProxyInstall $params
    $before=[IO.File]::ReadAllText($script:SPConfig)
    $s=Read-Json $script:SPSettings; $s.local_tests=@('http://127.0.0.1:8000/'); Write-Json $script:SPSettings $s
    Invoke-SelectiveProxyInstall
    Assert ([IO.File]::ReadAllText($script:SPConfig) -eq $before) 'idempotent config'
    Assert ((Read-Json $script:SPSettings).local_tests[0] -eq 'http://127.0.0.1:8000/') 'user settings retained'
    New-Item -ItemType File (Join-Path $temp 'fail-check') | Out-Null
    $failed=$false; try { Invoke-SelectiveProxyInstall $params } catch { $failed=$true }
    Assert $failed 'check failure rejected'
    Assert ([IO.File]::ReadAllText($script:SPConfig) -eq $before) 'check preserves config'
    Assert ($script:TestTask.State -eq 'Running') 'check preserves running task'
    Remove-Item -LiteralPath (Join-Path $temp 'fail-check')
    $script:FailNetwork=$true; $failed=$false
    try { Invoke-SelectiveProxyInstall $params } catch { $failed=$true }
    Assert $failed 'startup failure rejected'
    Assert ([IO.File]::ReadAllText($script:SPConfig) -eq $before) 'startup rolls config back'
    Assert ($script:TestTask.State -eq 'Running') 'startup restores running task'
    $script:FailNetwork=$false
    $script:FailStop=$true; $failed=$false
    try { Invoke-SelectiveProxyInstall $params } catch { $failed=$true }
    Assert $failed 'stop failure reported'
    Assert ($script:TestTask.State -eq 'Running') 'stop failure restores previous running task'
    Assert ([IO.File]::ReadAllText($script:SPConfig) -eq $before) 'stop failure preserves config'
    $script:FailBackupCleanup=$true; $p.proxy_port=2081; Write-Json $params $p
    Invoke-SelectiveProxyInstall $params
    Assert ((Read-Json $script:SPConfig).inbounds[0].listen_port -eq 2081) 'cleanup failure retains valid new installation'
    Assert ($script:TestTask.State -eq 'Running') 'cleanup failure retains running task'
    $p.proxy_port=2080; Write-Json $params $p; Invoke-SelectiveProxyInstall $params
    [IO.File]::WriteAllText($script:SPConfig,'broken'); Stop-Proxy
    Assert ($script:TestTask.State -eq 'Ready') 'stop works with corrupt config'
    [IO.File]::WriteAllText($script:SPConfig,$before)
    $foreign=New-FixtureTask; $foreign.Principal.UserId='S-1-5-18'; $failed=$false
    try { Assert-OwnedTask $foreign } catch { $failed=$true }; Assert $failed 'foreign principal rejected'
    $script:TestTask=$null; $script:Busy=$true; $failed=$false
    try { Invoke-SelectiveProxyInstall $params } catch { $failed=$true }; Assert $failed 'busy port rejected'
    $script:Busy=$false
    $profile=Join-Path $script:SPDir 'firefox-Claude'; New-Item -ItemType Directory $profile | Out-Null
    [IO.File]::WriteAllText((Join-Path $profile 'prefs.js'),'preserve')
    . "$PSScriptRoot\..\windows\uninstall.ps1"
    Assert (Test-Path -LiteralPath (Join-Path $profile 'prefs.js')) 'uninstall retains profile'
    Assert (Test-Owned) 'retained profile can be reinstalled'
    # Reloaded common helpers are replaced with fixtures again for the reinstall.
    function Get-SingBox { return $fake }
    function Assert-Key($Path) { if (-not (Test-Path -LiteralPath $Path)) { throw 'Key missing' } }
    function Wait-Proxy($Context) { return '203.0.113.9' }
    Invoke-SelectiveProxyInstall $params
    Assert ([IO.File]::ReadAllText((Join-Path $profile 'prefs.js')) -eq 'preserve') 'reinstall retains profile'
    Write-Host 'PASS: Windows installer idempotence, validation, rollback, cleanup, stop, ownership, port conflict'
} finally {
    $env:LOCALAPPDATA=$originalLocal
    Remove-Item -LiteralPath $temp -Recurse -Force
}
