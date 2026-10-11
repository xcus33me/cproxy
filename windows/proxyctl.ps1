# Managed by cproxy
param([string]$Command='help', [switch]$Once)
. "$PSScriptRoot\common.ps1"
function Show-Usage { Write-Host 'proxyctl.ps1 status|start|stop|restart|test|logs|config|browser|unlock|lock' }
if ($Command -notin @('status','start','stop','restart','test','logs','config','browser','unlock','lock','help')) { Show-Usage; exit 2 }
if ($Once -and $Command -ne 'logs') { Show-Usage; exit 2 }
if ($args.Count -gt 0) { Show-Usage; exit 2 }
try {
    if ($Command -eq 'help') { Show-Usage; exit 0 }
    if ($Command -eq 'config') { Write-Host $script:SPConfig; Write-Host 'Change parameters: install.ps1 -Reconfigure'; exit 0 }
    if ($Command -eq 'logs') {
        $path=Join-Path $script:SPDir 'sing-box.error.log'
        if (-not (Test-Path -LiteralPath $path)) { throw 'No log yet; check Task Scheduler.' }
        if ($Once) { Get-Content -LiteralPath $path -Tail 60 } else { Get-Content -LiteralPath $path -Tail 60 -Wait }; exit 0
    }
    if ($Command -eq 'stop') { Stop-Proxy; exit 0 }
    $context=Get-ProxyContext
    switch ($Command) {
        'status' {
            $failed=$false
            try { $binary=Get-SingBox; & $binary version | Select-Object -First 1 } catch { Write-Host $_; $failed=$true }
            Write-Host "Config: $script:SPConfig"
            $task=Get-ScheduledTask -TaskName $script:SPTask -ErrorAction SilentlyContinue
            if ($task) { Write-Host "Task: $($task.State)"; if ($task.State -ne 'Running') { $failed=$true } }
            else { Write-Host 'Task missing'; $failed=$true }
            $port=Test-Tcp '127.0.0.1' $context.Port; Write-Host "Local port: $port"; if (-not $port) { $failed=$true }
            $ssh=Test-Tcp $context.Config.outbounds[0].server $context.Config.outbounds[0].server_port
            Write-Host "VPS SSH TCP (not authentication): $ssh"; if (-not $ssh) { $failed=$true }
            try {
                $address=[Net.Dns]::GetHostAddresses($context.Config.outbounds[0].server)[0].IPAddressToString
                Find-NetRoute -RemoteIPAddress $address | Format-Table InterfaceAlias,NextHop,RouteMetric
            } catch { Write-Host 'Route lookup unavailable; inspect Get-NetRoute with Amnezia on/off.' }
            if ($failed) { exit 1 }
        }
        { $_ -in @('start','restart') } {
            $binary=Get-SingBox; & $binary check -c $script:SPConfig
            if ($LASTEXITCODE -ne 0) { throw 'Invalid sing-box configuration.' }
            if ($Command -eq 'restart') { Stop-Proxy }
            if ((Test-Tcp '127.0.0.1' $context.Port) -and (Get-ScheduledTask -TaskName $script:SPTask).State -ne 'Running') { throw 'Proxy port is occupied by another process.' }
            Start-ScheduledTask -TaskName $script:SPTask; $null=Wait-Proxy $context
        }
        'stop' { Stop-Proxy }
        'unlock' {
            if ($context.Settings.key_mode -ne 'session') { throw 'Using unattended key.' }
            Stop-Proxy
            Unlock-Key $context.Settings.encrypted_key_path $context.Config.outbounds[0].private_key_path
            Enable-ScheduledTask -TaskName $script:SPTask | Out-Null
            Start-ScheduledTask -TaskName $script:SPTask; $null=Wait-Proxy $context
        }
        'lock' {
            if ($context.Settings.key_mode -ne 'session') { throw 'Using unattended key.' }
            Stop-Proxy; Disable-ScheduledTask -TaskName $script:SPTask | Out-Null
            Remove-Item -LiteralPath (Join-Path $script:SPDir 'runtime\session.key') -Force -ErrorAction SilentlyContinue
        }
        'browser' {
            $null=Confirm-Egress $context
            $firefox=Get-Command firefox.exe -ErrorAction SilentlyContinue
            if ($firefox) { $binary=$firefox.Source }
            else {
                $binary=Join-Path $env:ProgramFiles 'Mozilla Firefox\firefox.exe'
                if (-not (Test-Path -LiteralPath $binary)) { throw 'Firefox missing. Install it or add firefox.exe to PATH.' }
            }
            $profile=Join-Path $script:SPDir 'firefox-Claude'; New-Item -ItemType Directory $profile -Force | Out-Null
            $prefs=Join-Path $profile 'user.js'
            if ((Test-Path -LiteralPath $prefs) -and (Get-Content -LiteralPath $prefs -TotalCount 1) -ne '// Managed by cproxy') { throw 'Existing user.js is not owned by cproxy.' }
            $text=@"
// Managed by cproxy
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "");
user_pref("network.proxy.http_port", 0);
user_pref("network.proxy.ssl", "");
user_pref("network.proxy.ssl_port", 0);
user_pref("network.proxy.share_proxy_settings", false);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", $($context.Port));
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.socks5_remote_dns", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("network.proxy.failover_direct", false);
user_pref("network.proxy.allow_bypass", false);
user_pref("network.trr.mode", 5);
user_pref("media.peerconnection.enabled", false);
user_pref("network.http.http3.enable", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("network.predictor.enabled", false);
"@
            [IO.File]::WriteAllText($prefs,$text,(New-Object Text.UTF8Encoding $false))
            Start-Process -FilePath $binary -ArgumentList ('--no-remote --new-instance --profile '+(ConvertTo-NativeArgument $profile)+' https://claude.ai') | Out-Null
        }
        'test' {
            $failed=$false; $http=''; $socks=''; $http6=''; $socks6=''
            foreach ($kind in @('direct','HTTP','SOCKS5')) {
                $proxy=''; if ($kind -eq 'HTTP') { $proxy=$context.Proxy }; if ($kind -eq 'SOCKS5') { $proxy="socks5h://127.0.0.1:$($context.Port)" }
                try {
                    $ip=Invoke-ProxyFetch $proxy 'https://api4.ipify.org'
                    if (-not (Test-IPAddress $ip)) { throw 'Invalid IP' }
                    Write-Host "IPv4 $kind : $ip"
                    if ($kind -eq 'HTTP') { $http=$ip }; if ($kind -eq 'SOCKS5') { $socks=$ip }
                } catch { Write-Host "IPv4 $kind : ERROR"; if ($kind -ne 'direct') { $failed=$true } }
                try {
                    $ip6=Invoke-ProxyFetch $proxy 'https://api6.ipify.org'
                    if (-not (Test-IPAddress $ip6) -or -not $ip6.Contains(':')) { throw 'Invalid IPv6 response' }
                    Write-Host "IPv6 $kind : $ip6"
                    if ($kind -eq 'HTTP') { $http6=$ip6 }; if ($kind -eq 'SOCKS5') { $socks6=$ip6 }
                }
                catch { Write-Host "IPv6 $kind : unavailable" }
            }
            if (-not $http -or $http -ne $socks) { $failed=$true }
            if ($http6 -and $socks6 -and $http6 -ne $socks6) { Write-Host 'HTTP and SOCKS5 IPv6 differ'; $failed=$true }
            try { $null=Confirm-Egress $context } catch { Write-Host $_; $failed=$true }
            foreach ($url in @(Get-Option $context.Settings 'local_tests' @())) {
                try { $null=Invoke-ProxyFetch '' $url; $null=Invoke-ProxyFetch $context.Proxy $url; Write-Host 'Local test target: reachable direct and proxied' }
                catch { Write-Host 'Local test target: failed'; $failed=$true }
            }
            Write-Host 'Fail-closed config verified; perform the outage acceptance check in docs/windows.md.'
            if ($failed) { exit 1 }
        }
    }
    exit 0
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
