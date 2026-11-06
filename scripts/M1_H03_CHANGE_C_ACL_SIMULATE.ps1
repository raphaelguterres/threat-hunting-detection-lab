# H03 Change C: ACL-only, in-memory simulation. Never creates or edits files/ACLs.
[CmdletBinding()]
param([string]$OperatorSid = "")
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\SecurityLab\H03'
$untrusted = @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4')
$systemSid = 'S-1-5-18'
$adminSid = 'S-1-5-32-544'
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$propagate = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
function Add-SimulatedRule([string]$sidText,[System.Security.AccessControl.FileSystemRights]$rights) {
  $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$propagate,$allow)
  $acl.AddAccessRule($rule)
}
$validOperator = $false
if ($OperatorSid) {
  try {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($OperatorSid)
    $validOperator = $OperatorSid -notin ($untrusted + @($systemSid,$adminSid))
  } catch {
    $validOperator = $false
  }
}
Add-SimulatedRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)
Add-SimulatedRule $adminSid ([System.Security.AccessControl.FileSystemRights]::FullControl)
if ($validOperator) {
  Add-SimulatedRule $OperatorSid ([System.Security.AccessControl.FileSystemRights]::Modify)
}
$rules = @($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
$broadWrite = @($rules | Where-Object {
   $_.IdentityReference.Value -in $untrusted -and
   $_.AccessControlType -eq 'Allow' -and
   (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -ne 0 -or
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -ne 0)
})
Write-Output 'MODE=IN_MEMORY_ONLY'
Write-Output 'TARGET=H03_ISOLATED_PROPOSED_NOT_CREATED'
Write-Output ('SIMULATED_ACL_RULES='+$rules.Count)
Write-Output ('SIMULATED_BROAD_WRITE_ACES='+$broadWrite.Count)
Write-Output ('SIMULATED_INHERITANCE_PROTECTED='+$acl.AreAccessRulesProtected)
Write-Output ('SYSTEM_FULL_CONTROL_PRESENT='+(@($rules|Where-Object {$_.IdentityReference.Value -eq $systemSid}).Count -eq 1))
Write-Output ('ADMIN_FULL_CONTROL_PRESENT='+(@($rules|Where-Object {$_.IdentityReference.Value -eq $adminSid}).Count -eq 1))
Write-Output ('OPERATOR_SID_VALID='+$validOperator)
Write-Output 'LIVE_ACL_CHANGED=NO'
Write-Output 'DIRECTORY_CREATED=NO'
Write-Output 'DEPLOYMENT_GATE=BLOCKED'
if ($rules.Count -lt 2 -or $broadWrite.Count -gt 0 -or -not $acl.AreAccessRulesProtected -or ($OperatorSid -and -not $validOperator)) {exit 2}
