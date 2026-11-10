$ErrorActionPreference = 'Stop'
try {
    $target = 'C:\SecurityLab\H03'
    $volume = Get-Volume -DriveLetter C
    Write-Output ('CHECK_UTC=' + [DateTime]::UtcNow.ToString('o'))
    Write-Output ('FILESYSTEM=' + $volume.FileSystem)
    Write-Output ('VOLUME_HEALTH=' + $volume.HealthStatus)
    Write-Output ('FREE_GIB=' + [Math]::Round($volume.SizeRemaining / 1GB, 2))
    Write-Output ('WAZUH_SERVICE=' + (Get-Service WazuhSvc).Status)
    $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4')
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $index = 0
    foreach ($path in @('C:\','C:\SecurityLab',$target)) {
        $index++
        $exists = Test-Path -LiteralPath $path
        Write-Output ('PATH_' + $index + '_EXISTS=' + $exists)
        if (-not $exists) { continue }
        $item = Get-Item -LiteralPath $path -Force
        Write-Output ('PATH_' + $index + '_IS_DIRECTORY=' + $item.PSIsContainer)
        Write-Output ('PATH_' + $index + '_REPARSE=' + [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint))
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'ReparsePointRequiresReview' }
        $acl = Get-Acl -LiteralPath $path
        $rules = $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
        $broad = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -in $broadSids -and ($_.FileSystemRights -band $writeMask) })
        Write-Output ('PATH_' + $index + '_ACL_PROTECTED=' + $acl.AreAccessRulesProtected)
        Write-Output ('PATH_' + $index + '_BROAD_WRITE_RULES=' + $broad.Count)
    }
    Write-Output 'PATH_ORDER=VOLUME_ROOT,PARENT,H03_TARGET'
    Write-Output 'PREFLIGHT_COLLECTION=COMPLETE_REVIEW_REQUIRED'
    Write-Output 'CONFIG_ACL_FILES_SERVICES_MODIFIED=NO'
    Write-Output 'CHANGE_C_AUTHORIZED=NO'
    exit 0
} catch {
    Write-Output ('PREFLIGHT=FAILED;ERROR_TYPE=' + $_.Exception.GetType().Name)
    exit 2
}
