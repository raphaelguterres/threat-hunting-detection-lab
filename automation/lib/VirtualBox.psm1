Set-StrictMode -Version Latest
function Invoke-VBoxManage {
    param([Parameter(Mandatory)][string]$VBoxManage, [Parameter(Mandatory)][string[]]$Arguments)
    $output = & $VBoxManage @Arguments 2>&1
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = @($output | ForEach-Object { $_.ToString() }) }
}

function Get-VBoxInventory {
    param([Parameter(Mandatory)][string]$VBoxManage)
    $all = Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @('list','vms')
    $running = Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @('list','runningvms')
    [pscustomobject]@{ all = $all.Output; running = $running.Output; exit_code = [math]::Max($all.ExitCode, $running.ExitCode) }
}

function Get-VBoxVmInfo {
    param([Parameter(Mandatory)][string]$VBoxManage, [Parameter(Mandatory)][string]$Vm)
    $result = Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @('showvminfo', $Vm, '--machinereadable')
    [pscustomobject]@{ exit_code = $result.ExitCode; lines = $result.Output }
}

function Get-VBoxGuestProperties {
    param([Parameter(Mandatory)][string]$VBoxManage, [Parameter(Mandatory)][string]$Vm)
    $result = Invoke-VBoxManage -VBoxManage $VBoxManage -Arguments @('guestproperty','enumerate',$Vm)
    [pscustomobject]@{ exit_code = $result.ExitCode; lines = $result.Output | Where-Object { $_ -match 'GuestAdditions|LoggedInUsers|Net/' } }
}

Export-ModuleMember -Function Invoke-VBoxManage,Get-VBoxInventory,Get-VBoxVmInfo,Get-VBoxGuestProperties
