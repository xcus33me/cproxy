# Shared native helpers. Compatible with Windows PowerShell 5.1 and PowerShell 7.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:SPDir = Join-Path $env:LOCALAPPDATA 'SelectiveProxy'
$script:SPConfig = Join-Path $script:SPDir 'config.json'
$script:SPSettings = Join-Path $script:SPDir 'settings.json'
$script:SPTask = 'SelectiveProxy-unsupported-platform'
if ([Environment]::OSVersion.Platform -eq 'Win32NT') { $script:SPTask = 'SelectiveProxy-'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
$script:SPTemplate = Join-Path $PSScriptRoot '..\config\sing-box.json.tpl'
if (-not (Test-Path -LiteralPath $script:SPTemplate)) { $script:SPTemplate = Join-Path $script:SPDir 'sing-box.json.tpl' }
function Get-Option($Object, [string]$Name, $Default) {
    if ($Object -and $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}
function Read-Json([string]$File) { [IO.File]::ReadAllText($File, [Text.Encoding]::UTF8) | ConvertFrom-Json }
function Write-Json([string]$File, $Object) {
    [IO.File]::WriteAllText($File, ($Object | ConvertTo-Json -Depth 30), (New-Object Text.UTF8Encoding $false))
}
function Test-PrivateCidr([string]$Value) {
    if ($Value -in @('::1/128','fc00::/7','fe80::/10')) { return $true }
    if ($Value -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)$') { return $false }
    $a=@([int]$Matches[1],[int]$Matches[2],[int]$Matches[3],[int]$Matches[4]); $n=[int]$Matches[5]
    if (@($a | Where-Object { $_ -gt 255 }).Count -gt 0 -or $n -gt 32) { return $false }
    return (($a[0] -eq 10 -and $n -ge 8) -or ($a[0] -eq 127 -and $n -ge 8) -or
        ($a[0] -eq 172 -and $a[1] -ge 16 -and $a[1] -le 31 -and $n -ge 12) -or
        ($a[0] -eq 192 -and $a[1] -eq 168 -and $n -ge 16))
}
function Test-SafeDomain([string]$Value) {
    if ($Value -cnotmatch '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' -or $Value.Contains('..')) { return $false }
    foreach ($d in @('anthropic.com','claude.ai','claude.com','claudeusercontent.com','claudemcpcontent.com','api4.ipify.org','api6.ipify.org')) {
        if ($d -eq $Value -or $d.EndsWith('.'+$Value) -or $Value.EndsWith('.'+$d)) { return $false }
    }
    return $true
}
function New-ProxyConfig($Params, [string]$Template=$script:SPTemplate) {
    if ($Params.server -notmatch '^[A-Za-z0-9][A-Za-z0-9.:-]*$') { throw 'Invalid VPS hostname/IP.' }
    foreach ($name in @('ssh_port','proxy_port')) {
        $v=$Params.$name
        if ($v -is [string] -or $v -lt 1 -or $v -gt 65535 -or [math]::Floor($v) -ne $v) { throw "Invalid $name." }
    }
    foreach ($name in @('user','key')) {
        if ([string]::IsNullOrWhiteSpace($Params.$name) -or $Params.$name -match '[\x00-\x1f\x7f]') { throw "Invalid $name." }
    }
    if ($Params.host_key -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,2}$') { throw 'A verified SSH host key is required.' }
    foreach ($d in $Params.domains) { if (-not (Test-SafeDomain $d)) { throw "Unsafe direct domain: $d" } }
    foreach ($c in $Params.cidrs) { if (-not (Test-PrivateCidr $c)) { throw "Only private direct CIDRs are allowed: $c" } }
    $config=Read-Json $Template
    $config.inbounds[0].listen_port=$Params.proxy_port
    $config.outbounds[0].server=$Params.server; $config.outbounds[0].server_port=$Params.ssh_port
    $config.outbounds[0].user=$Params.user; $config.outbounds[0].private_key_path=$Params.key
    $config.outbounds[0].host_key=@($Params.host_key)
    $algorithm=($Params.host_key -split ' ')[0]
    if ($algorithm -eq 'ssh-rsa') { $config.outbounds[0].host_key_algorithms=@('rsa-sha2-512','rsa-sha2-256') }
    else { $config.outbounds[0].host_key_algorithms=@($algorithm) }
    $config.route.rules[2].ip_cidr=@($Params.cidrs); $config.route.rules[3].domain_suffix=@($Params.domains)
    $config.route.rules=@($config.route.rules | Where-Object {
        (-not $_.PSObject.Properties['ip_cidr'] -or @($_.ip_cidr).Count -gt 0) -and
        (-not $_.PSObject.Properties['domain_suffix'] -or @($_.domain_suffix).Count -gt 0)
    })
    return $config
}
function Get-ConfigParams($Config) {
    $direct=@($Config.route.rules | Where-Object { (Get-Option $_ 'outbound' '') -eq 'direct' })
    return [pscustomobject]@{ server=$Config.outbounds[0].server; ssh_port=$Config.outbounds[0].server_port;
        user=$Config.outbounds[0].user; key=$Config.outbounds[0].private_key_path; host_key=$Config.outbounds[0].host_key[0];
        proxy_port=$Config.inbounds[0].listen_port;
        domains=@($direct | ForEach-Object { Get-Option $_ 'domain_suffix' @() });
        cidrs=@($direct | ForEach-Object { Get-Option $_ 'ip_cidr' @() }) }
}
function ConvertTo-Canonical($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts=@(foreach ($k in @($Value.Keys | Sort-Object)) { ($k | ConvertTo-Json -Compress)+':'+(ConvertTo-Canonical $Value[$k]) })
        return '{'+($parts -join ',')+'}'
    }
    if ($Value -is [pscustomobject]) {
        $parts=@(foreach ($k in @($Value.PSObject.Properties.Name | Sort-Object)) { ($k | ConvertTo-Json -Compress)+':'+(ConvertTo-Canonical $Value.$k) })
        return '{'+($parts -join ',')+'}'
    }
    if ($Value -is [array]) { return '['+(@($Value | ForEach-Object { ConvertTo-Canonical $_ }) -join ',')+']' }
    return ($Value | ConvertTo-Json -Compress)
}
function Assert-ProxyConfig([string]$File=$script:SPConfig, [string]$Template=$script:SPTemplate) {
    if (-not (Test-Path -LiteralPath $File)) { throw 'Configuration missing; run install.ps1.' }
    $c=Read-Json $File; $expected=New-ProxyConfig (Get-ConfigParams $c) $Template
    $c.PSObject.Properties.Remove('log'); $expected.PSObject.Properties.Remove('log')
    if ((ConvertTo-Canonical $c) -cne (ConvertTo-Canonical $expected)) { throw 'Unsafe configuration: only loopback, pinned SSH and private exclusions are permitted.' }
}
function Get-ProxyContext {
    Assert-ProxyConfig
    $c=Read-Json $script:SPConfig
    $settings=Read-Json $script:SPSettings
    if ($settings.key_mode -notin @('unattended','session')) { throw 'Invalid key_mode.' }
    foreach ($ip in @(Get-Option $settings 'expected_ips' @())) { if (-not (Test-IPAddress $ip)) { throw 'Invalid expected_ips.' } }
    if ($settings.key_mode -eq 'session' -and $c.outbounds[0].private_key_path -ne (Join-Path $script:SPDir 'runtime\session.key')) { throw 'Runtime key path differs from dedicated session file.' }
    return [pscustomobject]@{ Config=$c; Port=$c.inbounds[0].listen_port; Proxy="http://127.0.0.1:$($c.inbounds[0].listen_port)"; Settings=$settings }
}
function Test-Tcp([string]$Server, [int]$Port) {
    $client=New-Object Net.Sockets.TcpClient
    try {
        $task=$client.ConnectAsync($Server,$Port)
        if (-not $task.Wait(3000)) { return $false }
        return $client.Connected
    } catch { return $false } finally { $client.Dispose() }
}
function Invoke-Native([string]$Executable, [string[]]$NativeArgs, [bool]$Capture=$true) {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Executable; $info.UseShellExecute=$false
    $info.Arguments=(@($NativeArgs | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
    $info.RedirectStandardOutput=$Capture; $info.RedirectStandardError=$Capture
    $process=New-Object Diagnostics.Process; $process.StartInfo=$info
    try {
        if (-not $process.Start()) { throw 'Native process failed to start.' }
        $output=''
        if ($Capture) {
            $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        }
        $process.WaitForExit()
        if ($Capture) { $output=$stdout.GetAwaiter().GetResult(); $null=$stderr.GetAwaiter().GetResult() }
        return [pscustomobject]@{ ExitCode=$process.ExitCode; Output=$output }
    } finally { $process.Dispose() }
}
function Invoke-ProxyFetch([string]$Proxy, [string]$Url) {
    # ProcessStartInfo preserves empty --proxy/--noproxy even in Windows PowerShell 5.1.
    $result=Invoke-Native 'curl.exe' @('-q','--silent','--show-error','--fail','--connect-timeout','5','--max-time','15','--proto','=http,https','--noproxy','','--proxy',$Proxy,$Url)
    if ($result.ExitCode -ne 0) { throw "Network probe failed ($($result.ExitCode)). Inspect proxyctl logs." }
    return $result.Output.Trim()
}
function Test-IPAddress([string]$Value) {
    $ip=$null; return [Net.IPAddress]::TryParse($Value,[ref]$ip)
}
function Assert-ProxyRunning {
    if (-not (Test-Owned)) { throw 'cproxy is not installed. Run cproxy setup.' }
    $task=Get-ScheduledTask -TaskName $script:SPTask -ErrorAction SilentlyContinue
    if (-not $task -or $task.State -ne 'Running') { throw 'cproxy is not running. Start it through the menu.' }
    Assert-OwnedTask $task
}
function Confirm-Egress($Context) {
    Assert-ProxyRunning
    $ip=Invoke-ProxyFetch $Context.Proxy 'https://api4.ipify.org'
    if (-not (Test-IPAddress $ip)) { throw 'IP service returned an invalid response.' }
    $pins=@(Get-Option $Context.Settings 'expected_ips' @())
    if ($pins.Count -gt 0) {
        if ($ip -notin $pins) { throw "Unexpected egress IP ($ip); Claude launch blocked. Verify expected_ips with VPS." }
    }
    return $ip
}
function Get-SingBox {
    $command=Get-Command sing-box.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    if (Test-Path -LiteralPath $script:SPSettings) {
        $path=Get-Option (Read-Json $script:SPSettings) 'binary' ''
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    throw 'sing-box.exe missing from PATH. Reopen PowerShell after installation.'
}
function Assert-Key([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Private key must be a regular readable file.' }
    $result=Invoke-Native 'ssh-keygen.exe' @('-y','-P','','-f',$Path)
    if ($result.ExitCode -ne 0) { throw 'Key is encrypted or invalid. Choose session mode, or a dedicated restricted unencrypted key.' }
}
function Set-PrivateAcl([string]$Path) {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $system=New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
    if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        $acl=New-Object Security.AccessControl.DirectorySecurity
        $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else { $acl=New-Object Security.AccessControl.FileSecurity; $inherit=[Security.AccessControl.InheritanceFlags]::None }
    $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false)
    foreach ($identity in @($sid,$system)) {
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl',$inherit,'None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-KeyAcl([string]$Path) {
    $acl=Get-Acl -LiteralPath $Path
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @($user,'S-1-5-18','S-1-5-32-544')) {
            throw 'SSH key has broad ACLs. Restrict its permissions; see docs/windows.md.'
        }
    }
}
function Unlock-Key([string]$Source, [string]$Destination) {
    New-Item -ItemType Directory -Path (Split-Path $Destination) -Force | Out-Null
    Set-PrivateAcl (Split-Path $Destination)
    Copy-Item -LiteralPath $Source -Destination $Destination -Force; Set-PrivateAcl $Destination
    Write-Host 'Enter old passphrase; new passphrase is empty. The passphrase is not stored.'
    try {
        $result=Invoke-Native 'ssh-keygen.exe' @('-p','-N','','-f',$Destination) $false
        if ($result.ExitCode -ne 0) { throw 'Unlock failed.' }
        Assert-Key $Destination
    } catch { Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue; throw }
}
function Test-Owned {
    if (-not (Test-Path -LiteralPath $script:SPDir) -or (Get-Item -LiteralPath $script:SPDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
    return ((Test-Path -LiteralPath "$script:SPDir\.cproxy-owner") -and ((Get-Content -LiteralPath "$script:SPDir\.cproxy-owner" -Raw).Trim() -eq 'cproxy-v1')) }
function ConvertTo-NativeArgument([AllowEmptyString()][string]$Value) {
    # CommandLineToArgvW/CRT quoting: double backslashes before quote and closing quote.
    return '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'
}
function New-ClaudeProcessInfo([string]$Executable, [string[]]$CliArgs, [string]$Proxy) {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Executable; $info.UseShellExecute=$false
    $info.Arguments=(@($CliArgs | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
    foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy')) { $info.EnvironmentVariables[$name]=$Proxy }
    foreach ($name in @('NO_PROXY','no_proxy')) { $info.EnvironmentVariables[$name]='localhost,127.0.0.1,::1' }
    $info.EnvironmentVariables.Remove('ALL_PROXY'); $info.EnvironmentVariables.Remove('all_proxy')
    return $info
}
function Assert-OwnedTask($Task) {
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $id=$Task.Principal.UserId
    if ($id -notmatch '^S-1-') { $id=(New-Object Security.Principal.NTAccount $id).Translate([Security.Principal.SecurityIdentifier]).Value }
    $expected='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File '+(ConvertTo-NativeArgument (Join-Path $script:SPDir 'run-proxy.ps1'))
    if ($Task.Description -ne 'Managed by cproxy' -or $id -ne $user -or @($Task.Actions).Count -ne 1 -or $Task.Actions[0].Arguments -ne $expected) {
        throw 'Task does not belong to the current cproxy installation.'
    }
}
function Stop-Proxy {
    $task=Get-ScheduledTask -TaskName $script:SPTask -ErrorAction SilentlyContinue
    if ($task) {
        Assert-OwnedTask $task
        Stop-ScheduledTask -TaskName $script:SPTask
    }
    $state=Join-Path $script:SPDir 'process.json'
    if (Test-Path -LiteralPath $state) {
        $record=Read-Json $state
        $process=Get-Process -Id $record.pid -ErrorAction SilentlyContinue
        if ($process -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $record.ticks) {
            $details=Get-CimInstance Win32_Process -Filter "ProcessId=$($record.pid)"
            $binary=Get-Option $record 'binary' ''
            if ($details.ExecutablePath -eq $binary -and $details.CommandLine.Contains($script:SPConfig)) { Stop-Process -Id $record.pid -Force; $process.WaitForExit(5000) | Out-Null }
            else { throw 'Process identity differs; refusing to kill it.' }
        }
        Remove-Item -LiteralPath $state -Force
    }
}
function Wait-Proxy($Context) {
    for ($i=0; $i -lt 15; $i++) {
        if (Test-Tcp '127.0.0.1' $Context.Port) { return (Confirm-Egress $Context) }
        Start-Sleep -Seconds 1
    }
    throw 'Proxy did not become ready; inspect proxyctl logs and Task Scheduler.'
}
