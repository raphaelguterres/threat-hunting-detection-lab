# Authorized Change C preparation only. Does not replace ossec.conf or restart services.
$ErrorActionPreference = 'Stop'
$step = 'authorization_window'
$parentCreated = $false
$targetCreated = $false
try {
    $deadline = [DateTimeOffset]::Parse('2026-11-10T18:51:52Z')
    if ([DateTimeOffset]::UtcNow -gt $deadline -or [DateTimeOffset]::UtcNow -lt [DateTimeOffset]::Parse('2026-11-10T18:21:52Z')) { throw 'WindowClosedOrClockInvalid' }
    $step = 'identity_volume_service'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'AdministratorRequired' }
    if ($identity.User.Value -notmatch '-500$') { throw 'ExpectedBackupOwnerAccountRequired' }
    $volume = Get-Volume -DriveLetter C
    if ($volume.FileSystem -ne 'NTFS' -or $volume.HealthStatus -ne 'Healthy' -or $volume.SizeRemaining -lt 1GB) { throw 'VolumeNotReady' }
    $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    if ($service.State -ne 'Running' -or $service.StartName -ne 'LocalSystem') { throw 'UnexpectedServiceStateOrIdentity' }
    $parent = 'C:\SecurityLab'
    $target = 'C:\SecurityLab\H03'
    if ((Test-Path -LiteralPath $parent) -or (Test-Path -LiteralPath $target)) { throw 'TargetOrParentAlreadyExistsReviewRequired' }
    $source = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
    $original = [IO.File]::ReadAllBytes($source)
    $originalAcl = (Get-Acl -LiteralPath $source).Sddl
    $step = 'backup_recovery'
    Add-Type -AssemblyName System.Security
    $backup = Join-Path $env:LOCALAPPDATA 'WazuhM1ChangeC-20261104T201324Z\ossec-conf.dpapi.bin'
    $entropy = [Text.Encoding]::UTF8.GetBytes('Wazuh-M1-ChangeC-Agent004-v1')
    $recovered = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($backup),$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    function Digest([byte[]]$bytes) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return [Convert]::ToBase64String($sha.ComputeHash($bytes)) } finally { $sha.Dispose() }
    }
    if ((Digest $original) -ne (Digest $recovered)) { throw 'BackupDoesNotMatchCurrentConfig' }
    $step = 'proposal_only'
    $utf8 = New-Object Text.UTF8Encoding($false,$true)
    $offset = 0
    if ($original.Length -ge 3 -and $original[0] -eq 239 -and $original[1] -eq 187 -and $original[2] -eq 191) { $offset = 3 }
    $text = $utf8.GetString($original,$offset,$original.Length-$offset)
    if ($text -match '(?i)<!DOCTYPE|<!ENTITY') { throw 'UnexpectedXmlDeclaration' }
    $xml = New-Object Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.XmlResolver = $null
    $xml.LoadXml($text)
    if ($xml.DocumentElement.Name -ne 'ossec_config' -or $xml.SelectNodes('/ossec_config/syscheck').Count -ne 1) { throw 'UnexpectedConfigStructure' }
    if ($text -match '(?i)SecurityLab\\H03') { throw 'TargetAlreadyReferenced' }
    $closing = [regex]::Matches($text,'</syscheck\s*>')
    if ($closing.Count -ne 1) { throw 'UnexpectedSyscheckClosingCount' }
    $addition = '<directories realtime="yes" check_all="yes">C:\SecurityLab\H03</directories>'
    $candidateText = $text.Insert($closing[0].Index,$addition)
    $candidateXml = New-Object Xml.XmlDocument
    $candidateXml.PreserveWhitespace = $true
    $candidateXml.XmlResolver = $null
    $candidateXml.LoadXml($candidateText)
    $added = @($candidateXml.SelectNodes('/ossec_config/syscheck/directories') | Where-Object { $_.InnerText -eq $target })
    if ($added.Count -ne 1) { throw 'ProposalTargetCountInvalid' }
    [void]$added[0].ParentNode.RemoveChild($added[0])
    if ($candidateXml.OuterXml -cne $xml.OuterXml) { throw 'ProposalExceedsSingleDirective' }
    $candidate = $utf8.GetBytes($candidateText)
    if ($offset -eq 3) { $candidate = [byte[]](@(239,187,191) + $candidate) }
    $step = 'protected_directories'
    $allowed = @('S-1-5-18','S-1-5-32-544',$identity.User.Value)
    function New-RestrictedDirectory([string]$path) {
        if (Test-Path -LiteralPath $path) { throw 'DirectoryAlreadyExists' }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner($identity.User)
        foreach ($sid in $allowed) {
            $rights = [Security.AccessControl.FileSystemRights]::FullControl
            if ($sid -eq $identity.User.Value) { $rights = [Security.AccessControl.FileSystemRights]::Modify }
            $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),$rights,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.AddAccessRule($rule)
        }
        [void][IO.Directory]::CreateDirectory($path,$acl)
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'UnexpectedReparsePoint' }
        $effective = Get-Acl -LiteralPath $path
        $rules = @($effective.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if (-not $effective.AreAccessRulesProtected -or $rules.Count -ne 3 -or $effective.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.User.Value) { throw 'DirectoryAclInvalid' }
        foreach ($rule in $rules) {
            $expected = [Security.AccessControl.FileSystemRights]::FullControl
            if ($rule.IdentityReference.Value -eq $identity.User.Value) { $expected = [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::Synchronize }
            if ($rule.IdentityReference.Value -notin $allowed -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or $rule.FileSystemRights -ne $expected) { throw 'UnexpectedAccessRule' }
        }
    }
    New-RestrictedDirectory $parent
    $parentCreated = $true
    New-RestrictedDirectory $target
    $targetCreated = $true
    $stage = Join-Path $env:LOCALAPPDATA 'WazuhH03ChangeC-20261110'
    New-RestrictedDirectory $stage
    [IO.File]::WriteAllBytes((Join-Path $stage 'baseline.conf'),$original)
    [IO.File]::WriteAllBytes((Join-Path $stage 'proposal.conf'),$candidate)
    [IO.File]::WriteAllText((Join-Path $stage 'baseline-acl.sddl'),$originalAcl)
    $manifest = @{ authorized_until_utc=$deadline.ToString('o'); original_sha256=(Digest $original); proposal_sha256=(Digest $candidate); stage='PREPARED_NOT_APPLIED'; target=$target }
    [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'),($manifest | ConvertTo-Json))
    if ((Digest ([IO.File]::ReadAllBytes($source))) -ne (Digest $original)) { throw 'LiveConfigurationChangedDuringPreparation' }
    Write-Output 'PARENT_AND_TARGET_CREATED=TRUE'
    Write-Output 'EFFECTIVE_ACL_PROTECTED_THREE_EXPECTED_SIDS=TRUE'
    Write-Output 'PROPOSAL_DIFF=ONE_REALTIME_CHECK_ALL_DIRECTORY_ONLY'
    Write-Output 'BACKUP_RECOVERY_MATCH=TRUE'
    Write-Output 'BASELINE_AND_PROPOSAL_STAGED=TRUE'
    Write-Output 'LIVE_CONFIG_MODIFIED=NO'
    Write-Output 'SERVICE_RESTARTED=NO'
    Write-Output 'ARTIFACT_TESTED_OR_EXECUTED=NO'
    Write-Output 'CHANGE_C=PREPARED_NOT_APPLIED'
    exit 0
} catch {
    Write-Output ('CHANGE_C=STOPPED_AT_' + $step)
    Write-Output ('ERROR_TYPE=' + $_.Exception.GetType().Name)
    Write-Output ('PARENT_CREATED=' + $parentCreated)
    Write-Output ('TARGET_CREATED=' + $targetCreated)
    Write-Output 'NO_AUTOMATIC_DELETION;INSPECT_BEFORE_RETRY'
    exit 2
}
