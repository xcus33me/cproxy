# No Pester dependency. Cross-platform generation/wrapper tests; Windows installer tests below.
$ErrorActionPreference = 'Stop'
if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = [IO.Path]::GetTempPath() }
. "$PSScriptRoot/../windows/common.ps1"
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$hostKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF8CGAfWLRTdqdxvGlFtZk7UlGJKCvtaBHwgbLLMRFoh'
$p = [pscustomobject]@{ server='vps.example.org'; ssh_port=22; user='proxy"name'; key='C:\Users\User Name\.ssh\key'; host_key=$hostKey; proxy_port=2080; domains=@('local'); cidrs=@('10.0.0.0/8') }
$c = New-ProxyConfig $p "$PSScriptRoot/../config/sing-box.json.tpl"
Assert ($c.inbounds[0].listen -eq '127.0.0.1') 'loopback'
Assert ($c.outbounds[0].private_key_path -eq $p.key) 'Windows path escaping'
Assert ($c.outbounds[0].user -eq $p.user) 'quoted user'
Assert ($c.route.final -eq 'ssh-out') 'SSH final'
Assert ($c.outbounds[0].host_key[0] -eq $hostKey) 'pinned host'
foreach ($bad in @('', 'ssh-ed25519 ???')) {
    $p.host_key=$bad; $rejected=$false
    try { $null=New-ProxyConfig $p "$PSScriptRoot/../config/sing-box.json.tpl" } catch { $rejected=$true }
    Assert $rejected 'invalid host key rejected'
}
$p.host_key=$hostKey
foreach ($bad in @('0.0.0.0/0','8.8.8.8/32','10.0.0.0/7')) {
    $p.cidrs=@($bad); $rejected=$false
    try { $null=New-ProxyConfig $p "$PSScriptRoot/../config/sing-box.json.tpl" } catch { $rejected=$true }
    Assert $rejected 'public direct rejected'
}
$p.cidrs=@('10.0.0.0/8')
foreach ($bad in @('com','anthropic.com','api.anthropic.com','org')) {
    $p.domains=@($bad); $rejected=$false
    try { $null=New-ProxyConfig $p "$PSScriptRoot/../config/sing-box.json.tpl" } catch { $rejected=$true }
    Assert $rejected 'protected exclusion rejected'
}
$p.domains=@('local')
$temp = Join-Path ([IO.Path]::GetTempPath()) ('cproxy-test-' + [guid]::NewGuid())
New-Item -ItemType Directory $temp | Out-Null
try {
    $file=Join-Path $temp 'config.json'; Write-Json $file (New-ProxyConfig $p "$PSScriptRoot/../config/sing-box.json.tpl")
    Assert-ProxyConfig $file "$PSScriptRoot/../config/sing-box.json.tpl"
    $c=Read-Json $file; $c.route.final='direct'; Write-Json $file $c
    $rejected=$false; try { Assert-ProxyConfig $file "$PSScriptRoot/../config/sing-box.json.tpl" } catch { $rejected=$true }
    Assert $rejected 'unsafe config rejected'
    $unicodePath='C:\Users\'+[char]0x0422+[char]0x0435+' User\key'
    $p.key=$unicodePath; Write-Json $file (New-ProxyConfig $p "$PSScriptRoot/../config/sing-box.json.tpl")
    Assert ((Read-Json $file).outbounds[0].private_key_path -ceq $unicodePath) 'UTF8 paths round trip even in PS5.1'
    foreach ($arg in @('a b','a"b','ends\','', 'x$y')) {
        $quoted=ConvertTo-NativeArgument $arg
        Assert ($quoted.StartsWith('"') -and $quoted.EndsWith('"')) 'native quoting'
    }
    # Wrapper environment changes must be confined to a child process.
    $env:NO_PROXY='*'; $env:https_proxy='http://wrong'
    $psi=New-ClaudeProcessInfo 'claude.exe' @('--help','a b') 'http://127.0.0.1:2080'
    Assert ($psi.EnvironmentVariables['NO_PROXY'] -eq 'localhost,127.0.0.1,::1') 'safe bypass'
    Assert ($psi.EnvironmentVariables['https_proxy'] -eq 'http://127.0.0.1:2080') 'lowercase override'
    Assert ($env:NO_PROXY -eq '*') 'parent unchanged'
# Real child-process argument round trip, including empty arguments.
$exe=(Get-Process -Id $PID).Path
$capture=Join-Path $temp 'args.ps1'
[IO.File]::WriteAllText($capture,'[Environment]::GetCommandLineArgs() | ConvertTo-Json -Compress')
$result=Invoke-Native $exe @('-NoProfile','-File',$capture,'a b','a"b','ends\','')
Assert ($result.ExitCode -eq 0) 'native helper child exits successfully'
$roundTrip=$result.Output | ConvertFrom-Json
Assert ($roundTrip[-4] -eq 'a b' -and $roundTrip[-3] -eq 'a"b' -and $roundTrip[-2] -eq 'ends\' -and $roundTrip[-1] -eq '') 'native helper preserves empty and quoted arguments'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Host 'PASS: configuration, policy, paths, child environment'
& {
    function Assert-ProxyRunning { }
    function Invoke-ProxyFetch($Proxy,$Url) { return '203.0.113.9' }
    $context=[pscustomobject]@{Proxy='http://127.0.0.1:2080'; Settings=[pscustomobject]@{expected_ips=@()} }
    Assert ((Confirm-Egress $context) -eq '203.0.113.9') 'equal direct/proxy exits allowed without optional pin'
    $context.Settings.expected_ips=@('198.51.100.1'); $rejected=$false
    try { $null=Confirm-Egress $context } catch { $rejected=$true }
    Assert $rejected 'explicit expected IP still enforced'
}
& {
    function Test-Owned { return $true }
    function Assert-OwnedTask($Task) { }
    function Get-ScheduledTask { return [pscustomobject]@{State='Ready'} }
    function Invoke-ProxyFetch($Proxy,$Url) { throw 'Must not fetch through a foreign proxy' }
    $rejected=$false
    try { $null=Confirm-Egress ([pscustomobject]@{Proxy='http://127.0.0.1:2080';Settings=[pscustomobject]@{expected_ips=@()}}) } catch { $rejected=$_.Exception.Message -match 'not running' }
    Assert $rejected 'stopped service prevents use of another local proxy'
}
