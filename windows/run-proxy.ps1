# Managed by cproxy. The scheduled task owns this hidden supervisor and its single child.
. "$PSScriptRoot\common.ps1"
$mutex=New-Object Threading.Mutex($false, ('Local\SelectiveProxy-'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
if (-not $mutex.WaitOne(0)) { exit 0 }
$child=$null
try {
    Assert-ProxyConfig
    $context=Get-ProxyContext
    $binary=Get-SingBox
    & $binary check -c $script:SPConfig
    if ($LASTEXITCODE -ne 0) { throw 'sing-box check failed.' }
    while ($true) {
        # A stale session key never silently becomes an unattended credential.
        if ($context.Settings.key_mode -eq 'session' -and -not (Test-Path -LiteralPath $context.Config.outbounds[0].private_key_path)) { exit 0 }
        foreach ($name in @('sing-box.log','sing-box.error.log')) {
            $path=Join-Path $script:SPDir $name
            if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 2097152) { [IO.File]::WriteAllText($path,'') }
        }
        $child=Start-Process -FilePath $binary -ArgumentList ('run -c '+(ConvertTo-NativeArgument $script:SPConfig)) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $script:SPDir 'sing-box.log') -RedirectStandardError (Join-Path $script:SPDir 'sing-box.error.log')
        Write-Json (Join-Path $script:SPDir 'process.json') ([pscustomobject]@{ pid=$child.Id; ticks=$child.StartTime.ToUniversalTime().Ticks.ToString(); binary=$child.Path })
        $child.WaitForExit(); $child.Dispose(); $child=$null
        Start-Sleep -Seconds 5
    }
} finally {
    if ($child -and -not $child.HasExited) { $child.Kill(); $child.Dispose() }
    $mutex.ReleaseMutex(); $mutex.Dispose()
}
