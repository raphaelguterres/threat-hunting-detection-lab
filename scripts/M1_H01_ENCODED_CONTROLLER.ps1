# Owner-approved H01 controller. One encoded child, one disabled task, no policy bypass.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunDirectory,[Parameter(Mandatory=$true)][string]$SourceDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
try {
    $manifest=Get-Content -Raw -LiteralPath (Join-Path $RunDirectory 'manifest.json') | ConvertFrom-Json
    if($manifest.session -notmatch '^[a-f0-9-]{36}$'){throw 'InvalidSession'}
    $evidence=Join-Path $env:LOCALAPPDATA ('WazuhH01Live-'+$manifest.session)
    $preflight=Get-Content -Raw -LiteralPath (Join-Path $evidence 'preflight.json') | ConvertFrom-Json
    $baseline=Get-Content -Raw -LiteralPath (Join-Path $evidence 'baseline.json') | ConvertFrom-Json
    if($preflight.session -cne $manifest.session -or $baseline.session -cne $manifest.session -or $preflight.ready -ne $true -or $preflight.task_template_validated -ne $true){throw 'FreshPreflightRequired'}
    $control=@((Join-Path $env:WINDIR 'System32\VBoxControl.exe'),(Join-Path $env:ProgramFiles 'Oracle\VirtualBox Guest Additions\VBoxControl.exe')) | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
    if(-not $control){throw 'GuestChannelMissing'}
    $propertyRoot='/H01/'+$manifest.session
    $lines=@(& $control --nologo guestproperty get ($propertyRoot+'/approval'))
    $value=@($lines | Where-Object {$_ -match '^Value: '}) | Select-Object -First 1
    if($LASTEXITCODE -ne 0 -or -not $value -or $value -notmatch '^Value: (.+)$'){throw 'NewOwnerApprovalRequired'}
    $approval=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1])) | ConvertFrom-Json
    if($approval.session -cne $manifest.session -or $approval.authorized -ne $true -or $approval.scope -cne 'one_disabled_h01_task_no_action'){throw 'ApprovalScopeMismatch'}
    $now=[DateTimeOffset]::UtcNow
    if($now -lt [DateTimeOffset]::Parse($approval.from_utc).AddMinutes(-1) -or $now -gt [DateTimeOffset]::Parse($approval.until_utc).AddMinutes(-3)){throw 'ApprovalWindowClosedOrClockInvalid'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if($identity.User.Value -cne $baseline.actor_sid){throw 'OperatorChanged'}
    if((Get-FileHash -LiteralPath 'C:\Program Files (x86)\ossec-agent\ossec.conf' -Algorithm SHA256).Hash.ToLowerInvariant() -cne $baseline.config_sha256){throw 'AgentConfigurationChanged'}
    $payload=Join-Path $evidence 'payload.ps1'
    $template=Join-Path $evidence 'task-template.xml'
    $payloadSource=Join-Path $SourceDirectory 'M1_H01_DISABLED_TASK_PAYLOAD.ps1'
    $templateSource=Join-Path $SourceDirectory '..\config\h01-disabled-task-template.xml'
    foreach($item in @(@($payloadSource,$payload,$manifest.payload_sha256),@($templateSource,$template,$manifest.template_sha256))) {
        if((Get-FileHash -LiteralPath $item[0] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item[2]){throw 'ReviewedSourceChanged'}
        [IO.File]::Copy($item[0],$item[1],$false)
        if((Get-FileHash -LiteralPath $item[1] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item[2]){throw 'LocalCopyMismatch'}
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'manifest.json') -Encoding UTF8
    $approval | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'approval.json') -Encoding UTF8
    $token=[IO.File]::Open((Join-Path $evidence 'execution-started.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes((@{session=$manifest.session;started_utc=[DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json))
        $token.Write($bytes,0,$bytes.Length)
    } finally {$token.Dispose()}
    $decoded="& '"+$payload.Replace("'","''")+"' -EvidenceDirectory '"+$evidence.Replace("'","''")+"'"
    [IO.File]::WriteAllText((Join-Path $evidence 'decoded-wrapper.txt'),$decoded)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decoded))
    $powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & $powershell -NoProfile -NonInteractive -EncodedCommand $encoded
    $result=$LASTEXITCODE
    Write-Output ('H01_CHILD_EXIT='+$result)
    exit $result
} catch {
    Write-Output ('H01_CONTROLLER_STOPPED='+$_.Exception.Message)
    exit 2
}
