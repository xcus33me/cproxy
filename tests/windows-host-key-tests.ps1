# Exercise automatic host-key selection without touching the user's SSH files.
$ErrorActionPreference='Stop'
if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA=[IO.Path]::GetTempPath() }
. "$PSScriptRoot/../windows/install.ps1"
function Assert($Condition,$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cproxy host test '+[guid]::NewGuid())
New-Item -ItemType Directory $temp | Out-Null
$script:SPConfig=Join-Path $temp 'config.json'
$hostKey='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF8CGAfWLRTdqdxvGlFtZk7UlGJKCvtaBHwgbLLMRFoh'
$otherKey=$hostKey.Replace('IF8C','IG8C')
$nativeInvoke=(Get-Command Invoke-Native).ScriptBlock
function Invoke-Native($File,$Arguments) {
    if ($File -eq 'ssh-keyscan.exe') { return [pscustomobject]@{ExitCode=0; Output=('vps.example.org '+$hostKey)} }
    if ($File -eq 'ssh-keygen.exe') {
        $binary='ssh-keygen'; if ([Environment]::OSVersion.Platform -eq 'Win32NT') { $binary='ssh-keygen.exe' }
        return & $nativeInvoke $binary $Arguments
    }
    throw "Unexpected program: $File"
}
try {
    $wizard=Join-Path $temp 'wizard.json'
    Write-Json $wizard ([pscustomobject]@{server='vps.example.org';ssh_port=22;user='proxy';key='C:\Users\User Name\.ssh\key';key_mode='unattended';proxy_port=2080})
    $p=Get-WizardParams $wizard
    Assert ($p.host_key -ceq $hostKey) 'wizard pins automatically without a fingerprint question'
    $known=Join-Path $temp 'known_hosts'
    [IO.File]::WriteAllText($known,('[vps.example.org]:2222 '+$hostKey+"`n"))
    $binary='ssh-keygen'; if ([Environment]::OSVersion.Platform -eq 'Win32NT') { $binary='ssh-keygen.exe' }
    $hash=& $nativeInvoke $binary @('-H','-f',$known)
    Assert ($hash.ExitCode -eq 0) 'fixture known_hosts hashes successfully'
    $before=[IO.File]::ReadAllText($known)
    $selected=Get-AutomaticHostKey 'vps.example.org' 2222 @($hostKey) @($known)
    Assert ($selected -ceq $hostKey) 'reuse hashed host at nonstandard port'
    Assert ([IO.File]::ReadAllText($known) -ceq $before) 'leave known_hosts unchanged'
    [IO.File]::WriteAllText($known,('vps.example.org '+$otherKey+"`n"))
    $rejected=$false
    try { $null=Get-AutomaticHostKey 'vps.example.org' 22 @($hostKey) @($known) } catch { $rejected=$true }
    Assert $rejected 'reject changed known host'
    foreach ($marker in @('@revoked','@cert-authority')) {
        [IO.File]::WriteAllText($known,($marker+' vps.example.org '+$hostKey+"`n"))
        $rejected=$false
        try { $null=Get-AutomaticHostKey 'vps.example.org' 22 @($hostKey) @($known) } catch { $rejected=$true }
        Assert $rejected 'do not bootstrap revoked or certificate trust'
    }
    $p.domains=@('local'); $p.cidrs=@('10.0.0.0/8')
    Write-Json $script:SPConfig (New-ProxyConfig $p "$PSScriptRoot/../config/sing-box.json.tpl")
    $rejected=$false
    try { $null=Get-AutomaticHostKey 'vps.example.org' 22 @($otherKey) @() } catch { $rejected=$true }
    Assert $rejected 'reconfigure does not silently change existing pin'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Host 'PASS: automatic host key, hashed known hosts, changed and revoked keys'
