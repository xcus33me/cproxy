# Managed by cproxy
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
try {
    $context=Get-ProxyContext
    $null=Confirm-Egress $context
    if ('--bg' -in $args -or ($args.Count -gt 0 -and $args[0] -eq 'agents')) { throw 'Background supervisor requires explicit settings; see docs/claude-code.md.' }
    $command=Get-Command claude -ErrorAction Stop
    $cliArgs=@($args)
    if ($command.Source.EndsWith('.cmd',[StringComparison]::OrdinalIgnoreCase) -or $command.Source.EndsWith('.ps1',[StringComparison]::OrdinalIgnoreCase)) {
        $entry=Join-Path (Split-Path $command.Source) 'node_modules\@anthropic-ai\claude-code\cli.js'
        if (-not (Test-Path -LiteralPath $entry)) { throw 'Unsupported Claude launcher. Install the native claude.exe or standard npm Claude Code.' }
        $executable=(Get-Command node.exe -ErrorAction Stop).Source
        $cliArgs=@($entry)+$cliArgs
    } else { $executable=$command.Source }
    $process=New-Object Diagnostics.Process
    $process.StartInfo=New-ClaudeProcessInfo $executable $cliArgs $context.Proxy
    if (-not $process.Start()) { throw 'Claude process failed to start.' }
    $process.WaitForExit(); $code=$process.ExitCode; $process.Dispose()
    exit $code
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
