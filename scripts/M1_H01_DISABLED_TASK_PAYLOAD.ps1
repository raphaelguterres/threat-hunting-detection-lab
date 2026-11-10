# One disabled, triggerless task registration for authorized H01 telemetry.
# Never calls Run, enables the task, changes audit policy or restarts Wazuh.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$EvidenceDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$created=$false
$folder=$null
$manifest=$null
$exitCode=2
function Fields($event) {
    $xml=New-Object Xml.XmlDocument
    $xml.XmlResolver=$null
    $xml.LoadXml($event.ToXml())
    $fields=@{}
    foreach($node in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")){$fields[$node.GetAttribute('Name')]=$node.InnerText}
    return $fields
}
function Publish([string]$name,$value) {
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Depth 5 -Compress)))
    if(($propertyRoot+'/'+$name).Length -gt 63 -or $encoded.Length -gt 1023){throw 'GuestPropertySizeLimit'}
    & $control --nologo guestproperty set ($propertyRoot+'/'+$name) $encoded --flags 'TRANSIENT,TRANSRESET,RDONLYHOST' | Out-Null
    if($LASTEXITCODE){throw 'GuestChannelFailed'}
}
function New-H01Definition($scheduler,[string]$template,[string]$sid,[string]$marker) {
    $definition=$scheduler.NewTask(0)
    $definition.XmlText=[IO.File]::ReadAllText($template)
    $definition.RegistrationInfo.Description=$marker
    $definition.Principal.UserId=$sid
    $definition.Principal.LogonType=3
    $definition.Principal.RunLevel=0
    if($definition.Settings.Enabled -ne $false -or $definition.Settings.AllowDemandStart -ne $false -or $definition.Triggers.Count -ne 0){throw 'TaskMustBeDisabledAndTriggerless'}
    return $definition
}
try {
    $manifest=Get-Content -Raw -LiteralPath (Join-Path $EvidenceDirectory 'manifest.json') | ConvertFrom-Json
    $baseline=Get-Content -Raw -LiteralPath (Join-Path $EvidenceDirectory 'baseline.json') | ConvertFrom-Json
    $approval=Get-Content -Raw -LiteralPath (Join-Path $EvidenceDirectory 'approval.json') | ConvertFrom-Json
    if($manifest.session -notmatch '^[a-f0-9-]{36}$' -or $manifest.task_name -notmatch '^Wazuh_H01_20261110_[a-f0-9]{8}$' -or $approval.session -cne $manifest.session -or $approval.authorized -ne $true){throw 'SessionOrApprovalInvalid'}
    $deadline=[DateTimeOffset]::Parse($approval.until_utc)
    if([DateTimeOffset]::UtcNow -lt [DateTimeOffset]::Parse($approval.from_utc).AddMinutes(-1) -or [DateTimeOffset]::UtcNow -gt $deadline.AddMinutes(-1)){throw 'ActiveTestWindowClosed'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if($identity.User.Value -cne $baseline.actor_sid -or -not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'WrongOperator'}
    $agentRoot='C:\Program Files (x86)\ossec-agent'
    if(@(Get-Content -LiteralPath (Join-Path $agentRoot 'client.keys') | Where-Object {$_ -match '^004\s'}).Count -ne 1){throw 'WrongAgent'}
    $config=Join-Path $agentRoot 'ossec.conf'
    if((Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() -cne $baseline.config_sha256 -or (Get-Service WazuhSvc).Status -ne 'Running'){throw 'AgentOrConfigChanged'}
    $audit=@(& auditpol.exe /get '/subcategory:Other Object Access Events') -join "`n"
    if($LASTEXITCODE -ne 0 -or $audit -notmatch '(?i)\bSuccess\b'){throw 'AuditSuccessUnavailable'}
    $propertyRoot='/H01/'+$manifest.session
    $control=@((Join-Path $env:WINDIR 'System32\VBoxControl.exe'),(Join-Path $env:ProgramFiles 'Oracle\VirtualBox Guest Additions\VBoxControl.exe')) | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
    if(-not $control){throw 'GuestChannelMissing'}
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $folder=$scheduler.GetFolder('\')
    $tasks=$folder.GetTasks(1)
    for($i=1;$i -le $tasks.Count;$i++){if($tasks.Item($i).Name -ieq $manifest.task_name){throw 'TaskAlreadyExists'}}
    $marker='Authorized benign H01 '+$manifest.session
    $definition=New-H01Definition $scheduler (Join-Path $EvidenceDirectory 'task-template.xml') $identity.User.Value $marker
    $start=Get-Date
    $registered=$folder.RegisterTaskDefinition($manifest.task_name,$definition,2,$identity.Name,$null,3,$null)
    $created=$true
    if($registered.Enabled -ne $false -or $registered.Definition.Triggers.Count -ne 0){throw 'RegisteredTaskStateUnexpected'}
    Publish 'state' @{session=$manifest.session;phase='TASK_REGISTERED_DISABLED'}
    $securityMatches=@();$processMatches=@()
    for($attempt=0;$attempt -lt 15;$attempt++) {
        $security=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698;StartTime=$start.AddSeconds(-2)} -MaxEvents 200 -ErrorAction SilentlyContinue)
        $securityMatches=@(foreach($event in $security){$fields=Fields $event;if($fields['TaskName'].TrimStart('\') -ceq $manifest.task_name){[pscustomobject]@{event=$event;fields=$fields}}})
        $processes=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$start.AddMinutes(-2)} -MaxEvents 500 -ErrorAction SilentlyContinue)
        $processMatches=@(foreach($event in $processes){
            $fields=Fields $event
            if($fields['ProcessId'] -eq [string]$PID -and $fields['Image'] -match '(?i)\\powershell\.exe$' -and $fields['CommandLine'] -match '(?i)-EncodedCommand\s+'){
                [pscustomobject]@{event=$event;fields=$fields}
            }
        })
        if($securityMatches.Count -eq 1 -and $processMatches.Count -eq 1){break}
        Start-Sleep -Seconds 2
    }
    if($securityMatches.Count -ne 1 -or $processMatches.Count -ne 1){throw 'NativeSourcesNotUnique'}
    $sec=$securityMatches[0];$proc=$processMatches[0]
    $sameActor=$sec.fields['SubjectUserSid'] -ceq $identity.User.Value -and $proc.fields['User'] -ieq $identity.Name
    $sameHost=$sec.event.MachineName -ieq $proc.event.MachineName
    $gap=($sec.event.TimeCreated.ToUniversalTime()-$proc.event.TimeCreated.ToUniversalTime()).TotalSeconds
    if(-not $sameActor -or -not $sameHost -or $gap -le 0 -or $gap -gt 900 -or -not $proc.fields['ProcessGuid']){throw 'NativeIdentityOrOrderMismatch'}
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'sysmon-process.xml'),$proc.event.ToXml())
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'security-task.xml'),$sec.event.ToXml())
    Publish 'process' @{record_id=[string]$proc.event.RecordId;process_guid=$proc.fields['ProcessGuid'];process_id=[string]$PID;timestamp_utc=$proc.event.TimeCreated.ToUniversalTime().ToString('o');actor_name=$proc.fields['User']}
    Publish 'task' @{record_id=[string]$sec.event.RecordId;timestamp_utc=$sec.event.TimeCreated.ToUniversalTime().ToString('o');task_name=$sec.fields['TaskName'];actor_sid=$sec.fields['SubjectUserSid'];actor_domain=$sec.fields['SubjectDomainName'];actor_name=$sec.fields['SubjectUserName']}
    Publish 'state' @{session=$manifest.session;phase='NATIVE_COLLECTED';same_actor=$sameActor;same_host=$sameHost;gap_seconds=$gap;task_payload_executed=$false}
    Write-Output 'H01_NATIVE_PROCESS_AND_TASK=PASS;SAME_ACTOR_AND_HOST=TRUE;TASK_ACTION_EXECUTED=FALSE'
    $exitCode=0
} catch {
    Write-Output ('H01_TEST_FAILED='+$_.Exception.Message)
    if($manifest -and $folder){Publish 'state' @{session=$manifest.session;phase='FAILED_NATIVE_OR_REGISTRATION'}}
} finally {
    $removed=$false;$absent=$false
    if($created -and $folder) {
        $current=$folder.GetTask($manifest.task_name)
        if($current.Definition.RegistrationInfo.Description -ceq $marker -and $current.Enabled -eq $false -and $current.Definition.Triggers.Count -eq 0){$folder.DeleteTask($manifest.task_name,0);$removed=$true}
    }
    if($folder -and $manifest) {
        $remaining=0;$tasks=$folder.GetTasks(1)
        for($i=1;$i -le $tasks.Count;$i++){if($tasks.Item($i).Name -ieq $manifest.task_name){$remaining++}}
        $absent=$remaining -eq 0
        $unchanged=(Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $baseline.config_sha256
        $post=@{session=$manifest.session;task_created=$created;task_removed=$removed;task_absent=$absent;config_unchanged=$unchanged;service_running=((Get-Service WazuhSvc).Status -eq 'Running');task_action_executed=$false}
        $post | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'postcheck.json') -Encoding UTF8
        Publish 'postcheck' $post
        if(-not $removed -or -not $absent -or -not $unchanged){$exitCode=3}
    }
}
exit $exitCode
