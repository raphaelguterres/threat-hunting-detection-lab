# Run manually in the authorized Windows guest only. No Wazuh configuration changes.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$created=@()
$phase='preflight'
$manifest=$null
$configHash=$null
$exitCode=2
$EvidenceDirectory=$null
$VBoxControl=@((Join-Path $env:WINDIR 'System32\VBoxControl.exe'),(Join-Path $env:ProgramFiles 'Oracle\VirtualBox Guest Additions\VBoxControl.exe')) | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
function Publish([string]$name,$value) {
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Compress -Depth 6)))
    if(($propertyRoot+'/'+$name).Length -gt 63 -or $encoded.Length -gt 1023){throw 'GuestPropertySizeLimit'}
    & $VBoxControl guestproperty set ($propertyRoot+'/'+$name) $encoded --flags 'TRANSIENT,TRANSRESET,RDONLYHOST' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'GuestPropertyPublishFailed'}
}
function Hash([string]$path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
function State([string]$value) {
    $data=@{session=$manifest.session;phase=$value;guest_utc=[DateTimeOffset]::UtcNow.ToString('o')}
    $data | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'status.json') -Encoding UTF8
    Publish 'state' $data
    Write-Output ('H03_PHASE='+$value)
}
function Await-Receipt([string]$gate) {
    $limit=[DateTimeOffset]::UtcNow.AddMinutes(5)
    while([DateTimeOffset]::UtcNow -lt $limit -and [DateTimeOffset]::UtcNow -lt $deadline) {
        $receipt=@(& $VBoxControl guestproperty get ($propertyRoot+'/'+$gate+'-confirmed')) -join ''
        if($LASTEXITCODE -eq 0 -and $receipt -match '^Value: (.+)$') {
            $proof=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1])) | ConvertFrom-Json
            if($proof.session -cne $manifest.session -or $proof.gate -cne $gate -or $proof.manager_indexer_exact -ne $true){throw 'InvalidReceipt'}
            if((Hash $probe) -cne $(if($gate -eq 'baseline'){$manifest.sha256_v1}else{$manifest.sha256_v2})){throw 'ProbeChangedWhileWaiting'}
            return
        }
        Start-Sleep -Seconds 2
    }
    throw 'ReceiptTimeoutNoExecution'
}
try {
    $manifest=Get-Content -Raw -LiteralPath (Join-Path $RunDirectory 'manifest.json') | ConvertFrom-Json
    if($manifest.session -notmatch '^[a-f0-9-]{36}$'){throw 'InvalidSession'}
    $propertyRoot='/H03/'+$manifest.session
    if(-not $VBoxControl){throw 'GuestAdditionsChannelUnavailable'}
    $deadline=[DateTimeOffset]::Parse($manifest.authorized_until_utc)
    if([DateTimeOffset]::UtcNow -ge $deadline.AddMinutes(-3)){throw 'WindowClosed'}
    $EvidenceDirectory=Join-Path $env:LOCALAPPDATA ('WazuhH03Live-'+$manifest.session)
    if(Test-Path -LiteralPath $EvidenceDirectory){throw 'SessionAlreadyUsed'}
    [void](New-Item -ItemType Directory -Path $EvidenceDirectory)
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -notmatch '-500$'){throw 'WrongOperatorContext'}
    $agentRoot='C:\Program Files (x86)\ossec-agent'
    $keyLines=@(Get-Content -LiteralPath (Join-Path $agentRoot 'client.keys') | Where-Object {$_ -match '^004\s'})
    if($keyLines.Count -ne 1){throw 'WrongAgent'}
    $service=Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    if($service.State -ne 'Running' -or $service.StartName -ne 'LocalSystem'){throw 'AgentNotReady'}
    $volume=Get-Volume -DriveLetter C
    if($volume.FileSystem -ne 'NTFS' -or $volume.HealthStatus -ne 'Healthy'){throw 'VolumeNotReady'}
    $target='C:\SecurityLab\H03'
    foreach($path in @('C:\SecurityLab',$target)) {
        $item=Get-Item -LiteralPath $path -Force
        if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'UnsafeDirectory'}
        $acl=Get-Acl -LiteralPath $path
        $aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if(-not $acl.AreAccessRulesProtected -or $aces.Count -ne 3){throw 'UnexpectedDirectoryACL'}
        foreach($ace in $aces) {
            if($ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544',$identity.User.Value) -or $ace.AccessControlType -ne 'Allow'){throw 'UnexpectedDirectoryPrincipal'}
        }
    }
    if(@(Get-ChildItem -LiteralPath $target -Force).Count -ne 0){throw 'TargetNotEmpty'}
    $config=Join-Path $agentRoot 'ossec.conf'
    $configHash=Hash $config
    $xml=New-Object Xml.XmlDocument
    $xml.XmlResolver=$null
    $xml.Load($config)
    $nodes=@($xml.SelectNodes('/ossec_config/syscheck/directories') | Where-Object {$_.InnerText -eq $target -and $_.GetAttribute('realtime') -eq 'yes' -and $_.GetAttribute('check_all') -eq 'yes'})
    if($nodes.Count -ne 1){throw 'RealtimeTargetMissing'}
    $log='Microsoft-Windows-Sysmon/Operational'
    if(-not (Get-WinEvent -ListLog $log).IsEnabled){throw 'SysmonDisabled'}
    $v1=Join-Path $RunDirectory 'probe-v1.exe'
    $v2=Join-Path $RunDirectory 'probe-v2.exe'
    if((Hash $v1) -cne $manifest.sha256_v1 -or (Hash $v2) -cne $manifest.sha256_v2 -or $manifest.sha256_v1 -ceq $manifest.sha256_v2){throw 'StagedArtifactMismatch'}
    $probe=Join-Path $target 'H03-BenignProbe.exe'
    $negative=Join-Path $target 'H03-NegativeProbe.exe'
    $start=Get-Date
    $created+= $probe
    [IO.File]::Copy($v1,$probe,$false)
    if((Hash $probe) -cne $manifest.sha256_v1){throw 'BaselineCopyMismatch'}
    State 'BASELINE_READY'
    Await-Receipt 'baseline'
    $phase='modify'
    [IO.File]::Copy($v2,$probe,$true)
    State 'MODIFIED_READY'
    Await-Receipt 'modified'
    if([DateTimeOffset]::UtcNow -ge $deadline.AddMinutes(-1)){throw 'NoTimeForExecutionAndCleanup'}
    $phase='execute'
    $output=@(& $probe)
    if($LASTEXITCODE -ne 0 -or $output.Count -ne 1 -or $output[0] -cne 'H03_BENIGN_PROBE_VERSION_2'){throw 'PositiveProbeFailed'}
    $created+= $negative
    [IO.File]::Copy($v2,$negative,$false)
    if((Hash $negative) -cne $manifest.sha256_v2){throw 'NegativeCopyMismatch'}
    $output=@(& $negative)
    if($LASTEXITCODE -ne 0 -or $output.Count -ne 1 -or $output[0] -cne 'H03_BENIGN_PROBE_VERSION_2'){throw 'NegativeProbeFailed'}
    $phase='native_evidence'
    $selected=@()
    for($attempt=0;$attempt -lt 15;$attempt++) {
        $events=@(Get-WinEvent -FilterHashtable @{LogName=$log;Id=1;StartTime=$start.AddSeconds(-1)} -MaxEvents 1000 -ErrorAction SilentlyContinue)
        $selected=@(foreach($event in $events) {
            $eventXml=New-Object Xml.XmlDocument
            $eventXml.XmlResolver=$null
            $eventXml.LoadXml($event.ToXml())
            $fields=@{}
            foreach($node in $eventXml.SelectNodes('/Event/EventData/Data')){$fields[$node.GetAttribute('Name')]=$node.InnerText}
            if($fields['Image'] -ieq $probe -or $fields['Image'] -ieq $negative) {
                if($event.ProviderName -ne 'Microsoft-Windows-Sysmon'){throw 'UnexpectedProvider'}
                [pscustomobject]@{record_id=$event.RecordId;timestamp_utc=$event.TimeCreated.ToUniversalTime().ToString('o');image=$fields['Image'];hashes=$fields['Hashes'];process_guid=$fields['ProcessGuid'];xml=$event.ToXml()}
            }
        })
        if($selected.Count -ge 2){break}
        Start-Sleep -Seconds 2
    }
    $positiveEvents=@($selected | Where-Object {$_.image -ieq $probe})
    $negativeEvents=@($selected | Where-Object {$_.image -ieq $negative})
    if($positiveEvents.Count -ne 1 -or $negativeEvents.Count -ne 1){throw 'NativeEventCountInvalid'}
    foreach($event in $selected){if($event.hashes -notmatch ('(?i)(?:^|,)SHA256='+[regex]::Escape($manifest.sha256_v2)+'(?:,|$)')){throw 'NativeExecutionHashMismatch'}}
    @($selected) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'native-events.json') -Encoding UTF8
    foreach($event in $selected) {
        $role=if($event.image -ieq $probe){'positive'}else{'negative'}
        Publish ('native-'+$role) @{record_id=[string]$event.record_id;process_guid=$event.process_guid;timestamp_utc=$event.timestamp_utc;sha256_v2_match=$true;role=$role}
    }
    if((Hash $config) -cne $configHash){throw 'AgentConfigChanged'}
    State 'NATIVE_COLLECTED'
    Write-Output 'GUEST_EXECUTIONS=2;NATIVE_SYSMON_EID1=2;CONFIG_UNCHANGED=TRUE'
    $exitCode=0
} catch {
    Write-Output ('H03_TEST_FAILED_PHASE='+$phase+';ERROR='+$_.Exception.Message)
    if($manifest -and $EvidenceDirectory -and (Test-Path -LiteralPath $EvidenceDirectory)){State ('FAILED_'+$phase)}
} finally {
    $cleanup=$true
    foreach($path in $created) {
        if(Test-Path -LiteralPath $path) {
            $expected=@($manifest.sha256_v1,$manifest.sha256_v2)
            if((Hash $path) -cin $expected -and -not ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                Remove-Item -LiteralPath $path -Force
            } else {$cleanup=$false}
        }
    }
    if($manifest -and $EvidenceDirectory -and (Test-Path -LiteralPath $EvidenceDirectory)) {
        $cleanupResult=@{session=$manifest.session;cleanup_pass=$cleanup;remaining_test_files=@($created | Where-Object {Test-Path -LiteralPath $_}).Count;config_unchanged=[bool]($configHash -and (Hash $config) -ceq $configHash);service_running=((Get-Service WazuhSvc).Status -eq 'Running')}
        $cleanupResult | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'cleanup.json') -Encoding UTF8
        Publish 'cleanup' $cleanupResult
    }
    Write-Output ('TEST_FILES_CLEANED='+$cleanup)
}
if(-not $cleanup){exit 3}
exit $exitCode
