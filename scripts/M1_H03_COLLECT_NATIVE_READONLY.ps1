# Read existing Sysmon records only. NEVER executes, creates, modifies or deletes a probe.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
try {
    $manifest=Get-Content -Raw -LiteralPath (Join-Path $RunDirectory 'manifest.json') | ConvertFrom-Json
    if($manifest.session -notmatch '^[a-f0-9-]{36}$'){throw 'InvalidSession'}
    $evidence=Join-Path $env:LOCALAPPDATA ('WazuhH03Live-'+$manifest.session)
    if(-not (Test-Path -LiteralPath $evidence -PathType Container)){throw 'OriginalSessionMissing'}
    $control=@((Join-Path $env:WINDIR 'System32\VBoxControl.exe'),(Join-Path $env:ProgramFiles 'Oracle\VirtualBox Guest Additions\VBoxControl.exe')) | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
    if(-not $control){throw 'GuestChannelMissing'}
    $root='/H03/'+$manifest.session
    function Publish([string]$name,$value) {
        $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Compress -Depth 6)))
        if(($root+'/'+$name).Length -gt 63 -or $encoded.Length -gt 1023){throw 'GuestPropertySizeLimit'}
        & $control --nologo guestproperty set ($root+'/'+$name) $encoded --flags 'TRANSIENT,TRANSRESET,RDONLYHOST' | Out-Null
        if($LASTEXITCODE){throw 'GuestChannelFailed'}
    }
    $paths=@{positive='C:\SecurityLab\H03\H03-BenignProbe.exe';negative='C:\SecurityLab\H03\H03-NegativeProbe.exe'}
    $recordedIds=@()
    $savedNative=Join-Path $evidence 'native-events.json'
    if(Test-Path -LiteralPath $savedNative -PathType Leaf) {
        $recordedIds=@((Get-Content -Raw -LiteralPath $savedNative | ConvertFrom-Json) | ForEach-Object {[string]$_.record_id})
        if($recordedIds.Count -ne 2 -or @($recordedIds | Select-Object -Unique).Count -ne 2){throw 'SavedNativeReferencesAmbiguous'}
    }
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 2000)
    $selected=@(foreach($event in $events) {
        if($recordedIds.Count -gt 0 -and [string]$event.RecordId -cnotin $recordedIds){continue}
        $xml=New-Object Xml.XmlDocument
        $xml.XmlResolver=$null
        $xml.LoadXml($event.ToXml())
        $fields=@{}
        foreach($node in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")){$fields[$node.GetAttribute('Name')]=$node.InnerText}
        foreach($role in @('positive','negative')) {
            if($fields['Image'] -ieq $paths[$role]) {
                if($event.ProviderName -ne 'Microsoft-Windows-Sysmon' -or $fields['Hashes'] -notmatch ('(?i)(?:^|,)SHA256='+[regex]::Escape($manifest.sha256_v2)+'(?:,|$)')){throw 'NativeIdentityOrHashMismatch'}
                [pscustomobject]@{role=$role;record_id=[string]$event.RecordId;timestamp_utc=$event.TimeCreated.ToUniversalTime().ToString('o');image=$fields['Image'];hashes=$fields['Hashes'];process_guid=$fields['ProcessGuid'];xml=$event.ToXml()}
            }
        }
    })
    foreach($role in @('positive','negative')){if(@($selected | Where-Object {$_.role -eq $role}).Count -ne 1){throw ('UnexpectedNativeCount_'+$role)}}
    $selected | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'native-events.json') -Encoding UTF8
    foreach($event in $selected){Publish ('native-'+$event.role) @{role=$event.role;record_id=$event.record_id;process_guid=$event.process_guid;timestamp_utc=$event.timestamp_utc;sha256_v2_match=$true}}
    $active='C:\Program Files (x86)\ossec-agent\ossec.conf'
    $proposal=Join-Path $env:LOCALAPPDATA 'WazuhH03ChangeC-20261110\proposal.conf'
    if((Get-FileHash -LiteralPath $active).Hash -cne (Get-FileHash -LiteralPath $proposal).Hash){throw 'ActiveConfigurationChanged'}
    $remaining=@(Get-ChildItem -LiteralPath 'C:\SecurityLab\H03' -Force).Count
    if($remaining -ne 0 -or (Get-Service WazuhSvc).Status -ne 'Running'){throw 'PostcheckFailed'}
    $cleanup=@{session=$manifest.session;cleanup_pass=$true;remaining_test_files=0;config_unchanged=$true;service_running=$true}
    $cleanup | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'cleanup-readonly-postcheck.json') -Encoding UTF8
    Publish 'cleanup' $cleanup
    Publish 'state' @{session=$manifest.session;phase='NATIVE_COLLECTED';guest_utc=[DateTimeOffset]::UtcNow.ToString('o');config_equals_proposal=$true}
    Write-Output 'READONLY_NATIVE_EID1=2;HASHES_MATCH=TRUE;TARGET_EMPTY=TRUE;CONFIG_UNCHANGED=TRUE;SERVICE_RUNNING=TRUE;NEW_EXECUTIONS=0'
    exit 0
} catch {
    Write-Output ('READONLY_COLLECTION_FAILED='+$_.Exception.Message)
    exit 2
}
