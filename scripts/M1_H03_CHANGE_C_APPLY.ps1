# Authorized agent 004 only. No test files/binaries. One directive, guarded recovery.
$ErrorActionPreference = 'Stop'
$step = 'window'
$applied = $false
$restartAttempted = $false
$source = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$deadline = [DateTimeOffset]::Parse('2026-11-10T21:01:01Z')
function Hash-Bytes([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($sha.ComputeHash($bytes)) } finally { $sha.Dispose() }
}
function Assert-OneAddition([string]$before,[string]$after) {
    foreach ($text in @($before,$after)) { if ($text -match '(?i)<!DOCTYPE|<!ENTITY') { throw 'DtdProhibited' } }
    $old = New-Object Xml.XmlDocument
    $old.PreserveWhitespace = $true; $old.XmlResolver = $null; $old.LoadXml($before)
    $new = New-Object Xml.XmlDocument
    $new.PreserveWhitespace = $true; $new.XmlResolver = $null; $new.LoadXml($after)
    if ($old.DocumentElement.Name -ne 'ossec_config' -or $old.SelectNodes('/ossec_config/syscheck').Count -ne 1) { throw 'BaselineStructureInvalid' }
    if ($new.DocumentElement.Name -ne 'ossec_config' -or $new.SelectNodes('/ossec_config/syscheck').Count -ne 1) { throw 'ProposalStructureInvalid' }
    $path = 'C:\SecurityLab\H03'
    if (@($old.SelectNodes('/ossec_config/syscheck/directories') | Where-Object { $_.InnerText.Trim() -ieq $path }).Count) { throw 'AlreadyConfigured' }
    $nodes = @($new.SelectNodes('/ossec_config/syscheck/directories') | Where-Object { $_.InnerText -ceq $path })
    if ($nodes.Count -ne 1) { throw 'TargetCountInvalid' }
    $node = $nodes[0]
    if ($node.Attributes.Count -ne 2 -or $node.GetAttribute('realtime') -cne 'yes' -or $node.GetAttribute('check_all') -cne 'yes' -or $node.ChildNodes.Count -ne 1) { throw 'TargetAttributesInvalid' }
    [void]$node.ParentNode.RemoveChild($node)
    if ($old.OuterXml -cne $new.OuterXml) { throw 'DiffExceedsSingleAddition' }
}
function Restart-WazuhOnly {
    Stop-Service -Name WazuhSvc -ErrorAction Stop
    (Get-Service WazuhSvc).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
    Start-Service -Name WazuhSvc -ErrorAction Stop
    (Get-Service WazuhSvc).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))
}
try {
    $now = [DateTimeOffset]::UtcNow
    if ($now -gt $deadline -or $now -lt [DateTimeOffset]::Parse('2026-11-10T20:31:01Z')) { throw 'WindowClosedOrClockInvalid' }
    $step = 'agent_identity_and_acl'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -notmatch '-500$') { throw 'BackupOwnerAdminRequired' }
    $keys = [IO.File]::ReadAllLines('C:\Program Files (x86)\ossec-agent\client.keys')
    if (@($keys | Where-Object { $_ -match '^004\s' }).Count -ne 1) { throw 'Agent004Required' }
    $stage = Join-Path $env:LOCALAPPDATA 'WazuhH03ChangeC-20261110'
    $allowed = @('S-1-5-18','S-1-5-32-544',$identity.User.Value)
    foreach ($path in @('C:\SecurityLab','C:\SecurityLab\H03',$stage)) {
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'InvalidDirectory' }
        $acl = Get-Acl -LiteralPath $path
        $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 3 -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.User.Value) { throw 'UnsafeDirectoryAcl' }
        foreach ($rule in $rules) {
            $expected = [Security.AccessControl.FileSystemRights]::FullControl
            if ($rule.IdentityReference.Value -eq $identity.User.Value) { $expected = [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::Synchronize }
            if ($rule.IdentityReference.Value -notin $allowed -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $rule.FileSystemRights -ne $expected) { throw 'UnexpectedDirectoryAccess' }
        }
    }
    if (@(Get-ChildItem -LiteralPath 'C:\SecurityLab\H03' -Force).Count) { throw 'TargetMustStillBeEmpty' }
    $volume = Get-Volume -DriveLetter C
    if ($volume.FileSystem -ne 'NTFS' -or $volume.HealthStatus -ne 'Healthy' -or $volume.SizeRemaining -lt 1GB) { throw 'VolumeNotReady' }
    $svc = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    if ($svc.State -ne 'Running' -or $svc.StartName -ne 'LocalSystem') { throw 'UnexpectedServiceState' }
    $step = 'baseline_and_proposal'
    $manifestFile = Join-Path $stage 'manifest.json'
    $step = 'manifest_read'
    $manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
    if ($manifest.stage -ne 'PREPARED_NOT_APPLIED') { throw 'StageNotPrepared' }
    $original = [IO.File]::ReadAllBytes((Join-Path $stage 'baseline.conf'))
    $proposal = [IO.File]::ReadAllBytes((Join-Path $stage 'proposal.conf'))
    $step = 'baseline_hash'
    if ((Hash-Bytes $original) -ne $manifest.original_sha256) { throw 'BaselineChanged' }
    $step = 'proposal_hash'
    if ((Hash-Bytes $proposal) -ne $manifest.proposal_sha256) { throw 'ProposalChanged' }
    $step = 'live_config_hash'
    if ((Hash-Bytes ([IO.File]::ReadAllBytes($source))) -ne $manifest.original_sha256) { throw 'LiveConfigurationChanged' }
    $step = 'live_config_acl'
    $baselineAcl = [IO.File]::ReadAllText((Join-Path $stage 'baseline-acl.sddl'))
    if ((Get-Acl -LiteralPath $source).Sddl -cne $baselineAcl) { throw 'LiveFileAclChanged' }
    $step = 'dpapi_recovery'
    Add-Type -AssemblyName System.Security
    $encrypted = [IO.File]::ReadAllBytes((Join-Path $env:LOCALAPPDATA 'WazuhM1ChangeC-20261104T201324Z\ossec-conf.dpapi.bin'))
    $restored = [Security.Cryptography.ProtectedData]::Unprotect($encrypted,[Text.Encoding]::UTF8.GetBytes('Wazuh-M1-ChangeC-Agent004-v1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
    if ((Hash-Bytes $restored) -ne $manifest.original_sha256) { throw 'RecoveryMismatch' }
    $step = 'single_addition_validation'
    Assert-OneAddition ([IO.File]::ReadAllText((Join-Path $stage 'baseline.conf'))) ([IO.File]::ReadAllText((Join-Path $stage 'proposal.conf')))
    $step = 'atomic_replace'
    if ([DateTimeOffset]::UtcNow -gt $deadline.AddMinutes(-3)) { throw 'InsufficientWindowForRecovery' }
    $replacement = Join-Path $stage 'apply.conf'
    if (Test-Path -LiteralPath $replacement) { throw 'ApplyFileAlreadyExistsReviewRequired' }
    [IO.File]::WriteAllBytes($replacement,$proposal)
    [IO.File]::Replace($replacement,$source,$null)
    $applied = $true
    if ((Hash-Bytes ([IO.File]::ReadAllBytes($source))) -ne $manifest.proposal_sha256 -or (Get-Acl -LiteralPath $source).Sddl -cne $baselineAcl) { throw 'PostReplaceIntegrityFailure' }
    $step = 'restart_wazuh'
    $restartAttempted = $true
    Restart-WazuhOnly
    $manifest.stage = 'APPLIED_AWAITING_DASHBOARD_VERIFICATION'
    $manifest | Add-Member -NotePropertyName applied_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    [IO.File]::WriteAllText($manifestFile,($manifest | ConvertTo-Json))
    Write-Output 'CHANGE_C=APPLIED_AWAITING_DASHBOARD_VERIFICATION'
    Write-Output 'AGENT_ID=004'
    Write-Output 'CONFIG_DIFF=ONE_REALTIME_CHECK_ALL_DIRECTORY_ONLY'
    Write-Output 'POST_CONFIG_HASH_AND_ACL=PASS'
    Write-Output 'WAZUH_SERVICE=RUNNING'
    Write-Output 'ROLLBACK_BYTES_VERIFIED=TRUE'
    Write-Output 'ACTIVE_FIM_TARGET=VERIFY_IN_DASHBOARD'
    Write-Output 'TEST_ARTIFACTS_OR_BINARIES=NONE'
    Write-Output 'M1_FINAL_GATE=BLOCKED'
    exit 0
} catch {
    Write-Output ('CHANGE_C=FAILED_AT_' + $step)
    Write-Output ('ERROR_TYPE=' + $_.Exception.GetType().Name)
    Write-Output ('SCRIPT_ERROR_LINE=' + $_.InvocationInfo.ScriptLineNumber)
    $safeReasons = @('StageNotPrepared','BaselineChanged','ProposalChanged','LiveConfigurationChanged','LiveFileAclChanged','RecoveryMismatch','DtdProhibited','BaselineStructureInvalid','ProposalStructureInvalid','AlreadyConfigured','TargetCountInvalid','TargetAttributesInvalid','DiffExceedsSingleAddition')
    if ($_.Exception.Message -in $safeReasons) { Write-Output ('CHECK_FAILURE=' + $_.Exception.Message) }
    if ($applied) {
        try {
            if ((Hash-Bytes ([IO.File]::ReadAllBytes($source))) -ne $manifest.proposal_sha256) { throw 'UnrecognizedLiveFileDoNotOverwrite' }
            $recoveryFile = Join-Path $stage 'recovery.conf'
            if (Test-Path -LiteralPath $recoveryFile) { throw 'RecoveryFileAlreadyExists' }
            [IO.File]::WriteAllBytes($recoveryFile,$original)
            [IO.File]::Replace($recoveryFile,$source,$null)
            if ((Get-Acl -LiteralPath $source).Sddl -cne $baselineAcl) { $restoreAcl = New-Object Security.AccessControl.FileSecurity; $restoreAcl.SetSecurityDescriptorSddlForm($baselineAcl); Set-Acl -LiteralPath $source -AclObject $restoreAcl }
            Restart-WazuhOnly
            if ((Hash-Bytes ([IO.File]::ReadAllBytes($source))) -ne $manifest.original_sha256 -or (Get-Acl -LiteralPath $source).Sddl -cne $baselineAcl) { throw 'RecoveryIntegrityFailure' }
            $manifest.stage = 'ROLLED_BACK_AFTER_FAILURE'
            [IO.File]::WriteAllText($manifestFile,($manifest | ConvertTo-Json))
            Write-Output 'ROLLBACK=BASELINE_RESTORED_AND_SERVICE_RUNNING'
        } catch { Write-Output 'ROLLBACK=REQUIRES_OPERATOR_ATTENTION_DO_NOT_RETRY' }
    } else { Write-Output 'LIVE_CONFIG_REPLACED=NO' }
    exit 2
}
