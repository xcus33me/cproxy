[CmdletBinding()]
param([string]$ParamsFile='', [switch]$Reconfigure, [string]$WizardFile='')
. "$PSScriptRoot\common.ps1"

function Confirm-HostKey($Params) {
    $probe=Invoke-Native 'ssh-keyscan.exe' @('-T','5','-p',([string]$Params.ssh_port),$Params.server)
    $scan=$probe.Output -split "`n"
    $keys=@($scan | Where-Object { $_ -notmatch '^#' } | ForEach-Object { $parts=$_ -split '\s+'; if ($parts.Count -ge 3) { $parts[1]+' '+$parts[2] } })
    if ($Params.host_key -notin $keys) { throw 'SSH host key mismatch or VPS unavailable.' }
}
function Get-AutomaticHostKey([string]$Server, [int]$Port, [string[]]$Offered, [string[]]$KnownHostsFiles) {
    if (Test-Path -LiteralPath $script:SPConfig) {
        Assert-ProxyConfig
        $old=Get-ConfigParams (Read-Json $script:SPConfig)
        if ($old.server -eq $Server -and $old.ssh_port -eq $Port) {
            if ($old.host_key -cnotin $Offered) { throw 'VPS key changed. The saved key will not be replaced automatically.' }
            return $old.host_key
        }
    }
    $lookup=$Server; if ($Port -ne 22) { $lookup='['+$Server+']:'+ $Port }
    $known=@()
    foreach ($file in $KnownHostsFiles) {
        if (-not (Test-Path -LiteralPath $file)) { continue }
        # Fail on unreadable files instead of treating existing trust as absent.
        $null=[IO.File]::ReadAllText($file)
        $probe=Invoke-Native 'ssh-keygen.exe' @('-F',$lookup,'-f',$file)
        if ($probe.ExitCode -gt 1) { throw "Cannot check $file" }
        $lines=@($probe.Output -split "`n" | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() })
        foreach ($line in $lines) {
            if ($line -match '^\s*@') { throw 'Revoked key or SSH CA found. Automatic setup for this trust type is unsupported.' }
            $parts=$line.Trim() -split '\s+'
            if ($parts.Count -ge 3) { $known+=($parts[1]+' '+$parts[2]) }
        }
    }
    if ($known.Count -gt 0) {
        foreach ($candidate in $known) {
            if ($candidate -cin $Offered) { Write-Host 'Using the saved SSH server key.'; return $candidate }
        }
        throw 'VPS key does not match the saved SSH key. Check the server address; installation cancelled.'
    }
    $preferred=@($Offered | Where-Object { $_ -cmatch '^ssh-ed25519 ' } | Select-Object -First 1)
    if ($preferred.Count -eq 0) { $preferred=@($Offered | Select-Object -First 1) }
    if ($preferred.Count -eq 0) { throw 'SSH server not reachable.' }
    Write-Host 'First connection: the SSH server key will be saved automatically.'
    return $preferred[0]
}
function Get-WizardParams([string]$File) {
    $p=Read-Json $File
    if ($p.server -notmatch '^[A-Za-z0-9][A-Za-z0-9.:-]*$') { throw 'Invalid VPS address.' }
    if ($p.key.StartsWith('~/') -or $p.key.StartsWith('~\')) { $p.key=Join-Path $HOME $p.key.Substring(2) }
    $probe=Invoke-Native 'ssh-keyscan.exe' @('-T','5','-p',([string]$p.ssh_port),'-t','ed25519,ecdsa,rsa',$p.server)
    $offered=@($probe.Output -split "`n" | Where-Object { $_ -match '^\S+\s+(ssh-|ecdsa-)' })
    $keys=@($offered | ForEach-Object { $parts=$_.Trim() -split '\s+'; $parts[1]+' '+$parts[2] })
    $knownFiles=@((Join-Path $HOME '.ssh\known_hosts'))
    if ($env:PROGRAMDATA) { $knownFiles+=(Join-Path $env:PROGRAMDATA 'ssh\ssh_known_hosts') }
    $hostKey=Get-AutomaticHostKey $p.server ([int]$p.ssh_port) $keys $knownFiles
    $p | Add-Member -NotePropertyName host_key -NotePropertyValue $hostKey -Force
    $p | Add-Member -NotePropertyName domains -NotePropertyValue @('local') -Force
    $p | Add-Member -NotePropertyName cidrs -NotePropertyValue @('127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','::1/128','fc00::/7','fe80::/10') -Force
    if (Test-Path -LiteralPath $script:SPConfig) {
        $old=Get-ConfigParams (Read-Json $script:SPConfig)
        $p.domains=$old.domains; $p.cidrs=$old.cidrs
        if ($old.server -ne $p.server -or $old.ssh_port -ne $p.ssh_port) { $p | Add-Member -NotePropertyName expected_ips -NotePropertyValue @() -Force }
    }
    return $p
}
function Register-ProxyTask([string]$Mode) {
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File '+(ConvertTo-NativeArgument (Join-Path $script:SPDir 'run-proxy.ps1'))
    $action=New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $script:SPDir
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $definition=New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description 'Managed by cproxy'
    if ($Mode -eq 'unattended') { $definition.Triggers=@(New-ScheduledTaskTrigger -AtLogOn -User $user) }
    # Session mode has no logon trigger. Unlock starts it explicitly.
    Register-ScheduledTask -TaskName $script:SPTask -InputObject $definition -Force | Out-Null
}
function Invoke-SelectiveProxyInstall([string]$Parameters='', [switch]$Change, [string]$Wizard='') {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or [Environment]::OSVersion.Version.Major -lt 10) { throw 'Windows 10/11 required.' }
    if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'PowerShell 5.1+ required.' }
    if ($env:PROCESSOR_ARCHITECTURE -notin @('AMD64','ARM64')) { throw 'Use 64-bit PowerShell on x64/ARM64 Windows.' }
    foreach ($name in @('ssh-keygen.exe','ssh-keyscan.exe','curl.exe')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "$name missing. Enable OpenSSH Client in Windows Optional Features, or see docs/windows.md." }
    }
    try { $binary=Get-SingBox } catch {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'Install winget (App Installer), then winget install --id SagerNet.sing-box --exact.' }
        if ((Read-Host 'Install sing-box through winget? [y/N]') -ne 'y') { throw 'Installation cancelled.' }
        & winget.exe install --id SagerNet.sing-box --exact --source winget
        if ($LASTEXITCODE -ne 0) { throw 'winget failed. See docs/windows.md.' }
        $env:Path=[Environment]::GetEnvironmentVariable('Path','Machine')+';'+[Environment]::GetEnvironmentVariable('Path','User')
        $binary=Get-SingBox
    }
    $version=@(& $binary version); if ($LASTEXITCODE -ne 0) { throw 'sing-box version failed.' }
    if (($version[0] -split '\s+')[2] -notmatch '^(\d+)\.(\d+)\.(\d+)') { throw 'Cannot parse sing-box version.' }
    if ([version]$Matches[0] -lt [version]'1.12.0') { throw 'sing-box >= 1.12 required.' }
    New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
    $lock=[IO.File]::Open((Join-Path $env:LOCALAPPDATA '.SelectiveProxy.install.lock'),'OpenOrCreate','ReadWrite','None')
    $stage=Join-Path $env:LOCALAPPDATA ('.SelectiveProxy.stage.'+[guid]::NewGuid())
    $backup=Join-Path $env:LOCALAPPDATA ('.SelectiveProxy.backup.'+[guid]::NewGuid())
    $applied=$false; $previousTask=$null; $taskWasRunning=$false; $existing=$false
    try {
        if (Test-Path -LiteralPath $script:SPDir) {
            if (-not (Test-Owned) -or (Get-Item -LiteralPath $script:SPDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Existing directory is not owned by cproxy.' }
            $existing=$true
        }
        $task=Get-ScheduledTask -TaskName $script:SPTask -ErrorAction SilentlyContinue
        if ($task) {
            Assert-OwnedTask $task
            $previousTask=Export-ScheduledTask -TaskName $script:SPTask
            $taskWasRunning=$task.State -eq 'Running'
        }
        New-Item -ItemType Directory -Path $stage | Out-Null; Set-PrivateAcl $stage
        if ($existing) { Copy-Item -LiteralPath $script:SPDir -Destination (Join-Path $stage 'app') -Recurse }
        else { New-Item -ItemType Directory -Path (Join-Path $stage 'app') | Out-Null }
        $app=Join-Path $stage 'app'
        if ($Wizard) { $p=Get-WizardParams $Wizard; $Change=$true }
        elseif ($Parameters) { $p=Read-Json $Parameters }
        elseif ($existing -and -not $Change -and (Test-Path -LiteralPath $script:SPConfig)) { Assert-ProxyConfig; $p=Get-ConfigParams (Read-Json $script:SPConfig) }
        else { throw 'Run cproxy setup for interactive configuration, or use -ParamsFile.' }
        $settingsPath=Join-Path $app 'settings.json'
        if (Test-Path -LiteralPath $settingsPath) { $settings=Read-Json $settingsPath }
        else { $settings=[pscustomobject]@{expected_ips=@(); local_tests=@()} }
        $mode=Get-Option $p 'key_mode' (Get-Option $settings 'key_mode' 'unattended')
        if (-not [IO.Path]::IsPathRooted($p.key)) { throw 'Private key path must be absolute.' }
        $encrypted=''
        if ($mode -eq 'session') {
            if ($existing -and -not $Change -and -not $Parameters) { $encrypted=$settings.encrypted_key_path }
            else {
                $encrypted=$p.key; Assert-KeyAcl $encrypted
                $p.key=Join-Path $script:SPDir 'runtime\session.key'
                # Unlock in staging before any running installation is touched.
                Unlock-Key $encrypted (Join-Path $app 'runtime\session.key')
            }
        } elseif ($mode -eq 'unattended') { Assert-KeyAcl $p.key; Assert-Key $p.key }
        else { throw 'key_mode must be unattended or session.' }
        $candidate=Join-Path $app 'config.json'
        if ($existing -and -not $Change -and -not $Parameters -and (Test-Path -LiteralPath $script:SPConfig)) {
            Copy-Item -LiteralPath $script:SPConfig -Destination $candidate -Force
        } else { Write-Json $candidate (New-ProxyConfig $p) }
        Assert-ProxyConfig $candidate
        # During session staging check a temporary config that points at the staged decrypted copy.
        $checkFile=$candidate
        if ($mode -eq 'session') {
            $checkConfig=Read-Json $candidate; $checkConfig.outbounds[0].private_key_path=Join-Path $app 'runtime\session.key'
            $checkFile=Join-Path $stage 'check.json'; Write-Json $checkFile $checkConfig
        }
        & $binary check -c $checkFile; if ($LASTEXITCODE -ne 0) { throw 'sing-box check failed; existing installation preserved.' }
        Confirm-HostKey $p
        if ((Test-Tcp '127.0.0.1' $p.proxy_port) -and -not ($existing -and $taskWasRunning)) { throw 'Local proxy port is occupied.' }
        $settings | Add-Member -NotePropertyName binary -NotePropertyValue $binary -Force
        $settings | Add-Member -NotePropertyName key_mode -NotePropertyValue $mode -Force
        $settings | Add-Member -NotePropertyName encrypted_key_path -NotePropertyValue $encrypted -Force
        foreach ($name in @('expected_ips','local_tests')) {
            if ($p.PSObject.Properties[$name]) { $settings | Add-Member -NotePropertyName $name -NotePropertyValue @($p.$name) -Force }
        }
        Write-Json $settingsPath $settings
        foreach ($name in @('common.ps1','proxyctl.ps1','claude-vpn.ps1','run-proxy.ps1','uninstall.ps1','install.ps1','cproxy.ps1')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $app -Force }
        if ($env:CPROXY_UI_BINARY) { Copy-Item -LiteralPath $env:CPROXY_UI_BINARY -Destination (Join-Path $app 'cproxy-ui.exe') -Force }
        Copy-Item -LiteralPath $script:SPTemplate -Destination (Join-Path $app 'sing-box.json.tpl') -Force
        [IO.File]::WriteAllText((Join-Path $app '.cproxy-owner'),'cproxy-v1')
        $applied=$true
        if ($task) { Stop-Proxy }
        if ($existing) { Move-Item -LiteralPath $script:SPDir -Destination $backup }
        Move-Item -LiteralPath $app -Destination $script:SPDir
        Set-PrivateAcl $script:SPDir
        Register-ProxyTask $mode
        Start-ScheduledTask -TaskName $script:SPTask
        $null=Wait-Proxy (Get-ProxyContext)
        $applied=$false
        if (Test-Path -LiteralPath $backup) {
            try { Remove-Item -LiteralPath $backup -Recurse -Force }
            catch { Write-Warning "Ready, but previous backup could not be fully removed: $backup" }
        }
        Write-Host "Ready: & `"$script:SPDir\proxyctl.ps1`" test"
        Write-Host "Firefox: & `"$script:SPDir\proxyctl.ps1`" browser"
        Write-Host "Claude: & `"$script:SPDir\claude-vpn.ps1`" --help"
        if ($mode -eq 'session') { Write-Host 'Session mode: lock when finished, unlock after login. No logon trigger; decrypted copy is on disk with private ACLs.' }
    } finally {
        # Ctrl+C bypasses catch in PowerShell, but finally always runs.
        # Keep the transaction guard active until readiness has succeeded.
        if ($applied) {
            Write-Warning 'Installation failed; restoring previous version.'
            try { Stop-Proxy } catch { Write-Warning $_ }
            if ((Test-Path -LiteralPath $backup) -or -not $existing) {
                if (Test-Path -LiteralPath $script:SPDir) { Remove-Item -LiteralPath $script:SPDir -Recurse -Force }
            }
            if (Test-Path -LiteralPath $backup) { Move-Item -LiteralPath $backup -Destination $script:SPDir }
            if ($previousTask) { Register-ScheduledTask -TaskName $script:SPTask -Xml $previousTask -Force | Out-Null }
            else { Unregister-ScheduledTask -TaskName $script:SPTask -Confirm:$false -ErrorAction SilentlyContinue }
            if ($taskWasRunning) { Start-ScheduledTask -TaskName $script:SPTask }
        }
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
        $lock.Dispose()
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $ParamsFile -and -not $WizardFile) {
        $launcher=Join-Path $PSScriptRoot '..\cproxy.ps1'; if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'cproxy-ui.exe')) { $launcher=Join-Path $PSScriptRoot 'cproxy.ps1' }
        & $launcher setup; exit $LASTEXITCODE
    }
    try { Invoke-SelectiveProxyInstall $ParamsFile -Change:$Reconfigure -Wizard:$WizardFile } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
