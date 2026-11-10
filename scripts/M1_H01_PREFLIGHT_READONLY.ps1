# Read-only H01 preflight. No task registration, encoded process or configuration change.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
try {
    $manifest=Get-Content -Raw -LiteralPath (Join-Path $RunDirectory 'manifest.json') | ConvertFrom-Json
    if($manifest.session -notmatch '^[a-f0-9-]{36}$' -or $manifest.task_name -notmatch '^Wazuh_H01_20261110_[a-f0-9]{8}$'){throw 'InvalidSession'}
    $control=@((Join-Path $env:WINDIR 'System32\VBoxControl.exe'),(Join-Path $env:ProgramFiles 'Oracle\VirtualBox Guest Additions\VBoxControl.exe')) | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
    if(-not $control){throw 'GuestChannelMissing'}
    $root='/H01/'+$manifest.session
    $evidence=Join-Path $env:LOCALAPPDATA ('WazuhH01Live-'+$manifest.session)
    if(-not (Test-Path -LiteralPath $evidence)){[void](New-Item -ItemType Directory -Path $evidence)}
    function Publish([string]$name,$value) {
        $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Depth 5 -Compress)))
        if(($root+'/'+$name).Length -gt 63 -or $encoded.Length -gt 1023){throw 'GuestPropertySizeLimit'}
        & $control --nologo guestproperty set ($root+'/'+$name) $encoded --flags 'TRANSIENT,TRANSRESET,RDONLYHOST' | Out-Null
        if($LASTEXITCODE){throw 'GuestChannelFailed'}
    }
    function Fields($event) {
        $xml=New-Object Xml.XmlDocument
        $xml.XmlResolver=$null
        $xml.LoadXml($event.ToXml())
        $map=@{}
        foreach($node in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")){$map[$node.GetAttribute('Name')]=$node.InnerText}
        return $map
    }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $admin=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if(-not $admin -or $identity.User.Value -notmatch '-500$'){throw 'ExpectedOperatorRequired'}
    $agentRoot='C:\Program Files (x86)\ossec-agent'
    if(@(Get-Content -LiteralPath (Join-Path $agentRoot 'client.keys') | Where-Object {$_ -match '^004\s'}).Count -ne 1){throw 'WrongAgent'}
    $serviceOK=(Get-Service WazuhSvc).Status -eq 'Running'
    $schedulerOK=(Get-Service Schedule).Status -eq 'Running'
    $sysmonOK=(Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational').IsEnabled
    $security=Get-WinEvent -ListLog Security
    $audit=@(& auditpol.exe /get '/subcategory:Other Object Access Events') -join "`n"
    $auditOK=$LASTEXITCODE -eq 0 -and $audit -match '(?i)\bSuccess\b'
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $templatePath=Join-Path $RunDirectory 'task-template.xml'
    if((Get-FileHash -LiteralPath $templatePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.template_sha256){throw 'ReviewedTemplateMismatch'}
    $definition=$scheduler.NewTask(0)
    $definition.XmlText=[IO.File]::ReadAllText($templatePath)
    $definition.Principal.UserId=$identity.User.Value
    $definition.Principal.LogonType=3
    $definition.Principal.RunLevel=0
    $templateOK=$definition.Settings.Enabled -eq $false -and $definition.Settings.AllowDemandStart -eq $false -and $definition.Triggers.Count -eq 0 -and $definition.Actions.Count -eq 1
    if(-not $templateOK){throw 'DisabledTaskDefinitionRejected'}
    $folder=$scheduler.GetFolder('\')
    $conflict=$false
    $tasks=$folder.GetTasks(1)
    for($i=1;$i -le $tasks.Count;$i++){if($tasks.Item($i).Name -ieq $manifest.task_name){$conflict=$true}}
    $configHash=(Get-FileHash -LiteralPath (Join-Path $agentRoot 'ossec.conf') -Algorithm SHA256).Hash.ToLowerInvariant()
    $auditHash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($audit))).Replace('-','').ToLowerInvariant()
    $baseline=@{session=$manifest.session;actor_sid=$identity.User.Value;actor_name=$identity.Name;config_sha256=$configHash;audit_sha256=$auditHash;guest_utc=[DateTimeOffset]::UtcNow.ToString('o')}
    $baseline | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'baseline.json') -Encoding UTF8
    Publish 'baseline' $baseline
    $oldEvents=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -ErrorAction SilentlyContinue)
    $eligible=@(foreach($event in $oldEvents){
        $fields=Fields $event
        if($fields['SubjectUserSid'] -eq $identity.User.Value -and $fields['TaskName'] -match '^\\Wazuh' -and $event.TimeCreated -lt (Get-Date).AddMinutes(-30)){
            [pscustomobject]@{event=$event;fields=$fields}
        }
    })
    if($eligible.Count -gt 0) {
        $old=$eligible[0]
        [IO.File]::WriteAllText((Join-Path $evidence 'historical-task-event.xml'),$old.event.ToXml())
        $historical=@{record_id=[string]$old.event.RecordId;timestamp_utc=$old.event.TimeCreated.ToUniversalTime().ToString('o');task_name=$old.fields['TaskName'];actor_sid=$old.fields['SubjectUserSid']}
        $historical | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'historical-task.json') -Encoding UTF8
        Publish 'historical' $historical
    }
    $ready=$serviceOK -and $schedulerOK -and $sysmonOK -and $security.IsEnabled -and $auditOK -and -not $conflict
    $summary=@{session=$manifest.session;ready=$ready;agent_id='004';admin=$admin;wazuh_running=$serviceOK;scheduler_running=$schedulerOK;sysmon_enabled=$sysmonOK;security_enabled=$security.IsEnabled;audit_success=$auditOK;task_template_validated=$templateOK;task_conflict=$conflict;historic4698_count=$oldEvents.Count;historical_actor_matched_control_available=($eligible.Count -gt 0);active_changes=$false}
    $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'preflight.json') -Encoding UTF8
    Publish 'preflight' $summary
    Write-Output ('H01_PREFLIGHT_READY='+$ready)
    Write-Output ('HISTORICAL_CONTROL_AVAILABLE='+($eligible.Count -gt 0))
    Write-Output 'TASKS_CREATED=0;ENCODED_TEST_PROCESSES=0;CONFIGURATION_OR_POLICY_CHANGED=FALSE'
    if(-not $ready){exit 2}
    exit 0
} catch {
    Write-Output ('H01_PREFLIGHT_FAILED='+$_.Exception.Message)
    exit 2
}
