# Managed by cproxy
. "$PSScriptRoot\common.ps1"
try {
    if (-not (Test-Owned)) { throw 'No managed installation; nothing removed.' }
    $lock=[IO.File]::Open((Join-Path $env:LOCALAPPDATA '.SelectiveProxy.install.lock'),'OpenOrCreate','ReadWrite','None')
    try {
        Stop-Proxy
        $task=Get-ScheduledTask -TaskName $script:SPTask -ErrorAction SilentlyContinue
        if ($task) { Unregister-ScheduledTask -TaskName $script:SPTask -Confirm:$false }
        $runtime=Join-Path $script:SPDir 'runtime\session.key'
        Remove-Item -LiteralPath $runtime -Force -ErrorAction SilentlyContinue
        foreach ($name in @('config.json','settings.json','sing-box.json.tpl','common.ps1','proxyctl.ps1','claude-vpn.ps1','run-proxy.ps1','uninstall.ps1','install.ps1','cproxy.ps1','cproxy-ui.exe','process.json','sing-box.log','sing-box.error.log')) {
            Remove-Item -LiteralPath (Join-Path $script:SPDir $name) -Force -ErrorAction SilentlyContinue
        }
        $runtimeDir=Join-Path $script:SPDir 'runtime'
        if ((Test-Path -LiteralPath $runtimeDir) -and @(Get-ChildItem -LiteralPath $runtimeDir -Force).Count -eq 0) { Remove-Item -LiteralPath $runtimeDir -Force }
        $remaining=@(Get-ChildItem -LiteralPath $script:SPDir -Force | Where-Object { $_.Name -ne '.cproxy-owner' })
        if ($remaining.Count -eq 0) {
            Remove-Item -LiteralPath (Join-Path $script:SPDir '.cproxy-owner') -Force
            Remove-Item -LiteralPath $script:SPDir -Force
        }
    } finally { $lock.Dispose() }
    Write-Host 'Removed cproxy files/task only. Firefox profile, original keys and sing-box are preserved.'
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
