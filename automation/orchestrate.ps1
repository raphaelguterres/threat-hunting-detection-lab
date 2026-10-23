[CmdletBinding(SupportsShouldProcess = $true, PositionalBinding = $false)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Discover','Health','Validate-Sysmon','Collect-Evidence','Status')]
    [string]$Mode,
    [string]$InventoryPath,
    [string]$OutputDirectory,
    [switch]$NoParallel
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
if ([string]::IsNullOrWhiteSpace($InventoryPath)) { $InventoryPath = Join-Path $scriptRoot 'inventory.local.json' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $scriptRoot 'artifacts' }
Import-Module (Join-Path $PSScriptRoot 'lib\Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib\VirtualBox.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib\Transport.psm1') -Force

function Get-SafeInventory {
    if (-not (Test-Path -LiteralPath $InventoryPath -PathType Leaf)) {
        throw "Inventory not found: $InventoryPath. Copy inventory.example.json to inventory.local.json and replace only locally verified values."
    }
    $inventory = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json
    if (-not $inventory.targets -or @($inventory.targets).Count -eq 0) { throw 'Inventory has no targets.' }
    foreach ($target in @($inventory.targets)) {
        foreach ($required in 'id','vm_name','vm_uuid','transport','timeout_seconds') {
            if ([string]::IsNullOrWhiteSpace([string]$target.$required)) { throw "Target '$($target.id)' lacks '$required'." }
        }
    }
    return $inventory
}

function Write-MarkdownSummary {
    param([object[]]$Results, [string]$Directory, [string]$RunId)
    $path = Join-Path $Directory "summary-$RunId.md"
    $lines = @('# Dual-VM orchestration summary', '', "Generated (UTC): $(Get-UtcNowString)", '', '| Target | Phase | Status | Duration (s) | Evidence |', '|---|---|---|---:|---|')
    foreach ($result in $Results) { $lines += "| $($result.target) | $($result.phase) | $($result.status) | $($result.duration) | $($result.evidence_path) |" }
    $lines += '', 'Messages:', ''
    foreach ($result in $Results) { $lines += "- **$($result.target) / $($result.phase):** $($result.message)" }
    Set-Content -LiteralPath $path -Value $lines -Encoding utf8
    return $path
}

function Get-VmHealthStatus {
    param([int]$ExitCode, [string[]]$Lines)
    if ($ExitCode -ne 0) { return 'FAIL' }
    $state = @($Lines | Where-Object { $_ -match '^VMState="(.+)"$' } | Select-Object -First 1)
    if ($state.Count -eq 0) { return 'FAIL' }
    if ($state[0] -match '^VMState="running"$') { return 'PASS' }
    return 'FAIL'
}

$started = Get-Date
$runId = $started.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$results = [System.Collections.Generic.List[object]]::new()
try {
    $inventory = Get-SafeInventory
    $vbox = Find-VBoxManage -ConfiguredPath $inventory.virtualbox.vboxmanage_path
    if (-not $vbox) { throw 'VBoxManage.exe was not found. Install VirtualBox or set virtualbox.vboxmanage_path in the local inventory.' }
    $hostEvidence = Write-JsonEvidence -Data ([pscustomobject]@{ generated_at = Get-UtcNowString; vboxmanage = $vbox; mode = $Mode; powershell = $PSVersionTable.PSVersion.ToString() }) -Directory $OutputDirectory -Name "host-$runId"

    if ($Mode -eq 'Discover') {
        $data = Get-VBoxInventory -VBoxManage $vbox
        $path = Write-JsonEvidence -Data $data -Directory $OutputDirectory -Name "discover-$runId"
        $results.Add((New-Result -Target 'host' -Phase 'Discover' -Status ($(if ($data.exit_code -eq 0) {'PASS'} else {'FAIL'})) -ExitCode $data.exit_code -EvidencePath $path -Message 'Local VirtualBox inventory collected.'))
        foreach ($target in @($inventory.targets)) {
            $info = Get-VBoxVmInfo -VBoxManage $vbox -Vm $target.vm_uuid
            $path = Write-JsonEvidence -Data $info -Directory $OutputDirectory -Name "vm-$($target.id)-$runId"
            $status = if ($info.exit_code -eq 0) {'PASS'} else {'FAIL'}
            $results.Add((New-Result -Target $target.id -Phase 'Discover' -Status $status -ExitCode $info.exit_code -EvidencePath $path -Message 'VM metadata checked by UUID.'))
        }
    } elseif ($Mode -eq 'Health') {
        # Independent local VirtualBox metadata queries are dispatched in parallel where jobs are available.
        $targets = @($inventory.targets)
        if (-not $NoParallel -and $targets.Count -gt 1) {
            $jobs = foreach ($target in $targets) { Start-Job -ScriptBlock { param($exe,$uuid,$id) $out = & $exe showvminfo $uuid --machinereadable 2>&1; [pscustomobject]@{ id=$id; exit_code=$LASTEXITCODE; lines=@($out | ForEach-Object { $_.ToString() }) } } -ArgumentList $vbox,$target.vm_uuid,$target.id }
            $jobResults = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job -Force
            foreach ($jobResult in $jobResults) {
                $path = Write-JsonEvidence -Data $jobResult -Directory $OutputDirectory -Name "health-$($jobResult.id)-$runId"
                $status = Get-VmHealthStatus -ExitCode $jobResult.exit_code -Lines $jobResult.lines
                $message = if ($status -eq 'PASS') {'VM is running; local state queried in parallel.'} else {'VM is not running or its state could not be verified.'}
                $results.Add((New-Result -Target $jobResult.id -Phase 'Health-VirtualBox' -Status $status -ExitCode $jobResult.exit_code -EvidencePath $path -Message $message))
            }
        } else {
            foreach ($target in $targets) {
                $info = Get-VBoxVmInfo -VBoxManage $vbox -Vm $target.vm_uuid
                $path = Write-JsonEvidence -Data $info -Directory $OutputDirectory -Name "health-$($target.id)-$runId"
                $status = Get-VmHealthStatus -ExitCode $info.exit_code -Lines $info.lines
                $message = if ($status -eq 'PASS') {'VM is running; local state queried.'} else {'VM is not running or its state could not be verified.'}
                $results.Add((New-Result -Target $target.id -Phase 'Health-VirtualBox' -Status $status -ExitCode $info.exit_code -EvidencePath $path -Message $message))
            }
        }
        foreach ($target in $targets) { $results.Add((Get-TransportReadiness -Target $target -Phase 'Health-Transport')) }
    } elseif ($Mode -eq 'Collect-Evidence') {
        foreach ($target in @($inventory.targets)) {
            $properties = Get-VBoxGuestProperties -VBoxManage $vbox -Vm $target.vm_uuid
            $path = Write-JsonEvidence -Data $properties -Directory $OutputDirectory -Name "guest-properties-$($target.id)-$runId"
            $results.Add((New-Result -Target $target.id -Phase 'Collect-Evidence' -Status ($(if ($properties.exit_code -eq 0) {'PASS'} else {'FAIL'})) -ExitCode $properties.exit_code -EvidencePath $path -Message 'Read-only guest properties collected; no guest command was executed.'))
        }
    } elseif ($Mode -eq 'Validate-Sysmon') {
        foreach ($target in @($inventory.targets)) { $results.Add((Get-TransportReadiness -Target $target -Phase 'Validate-Sysmon')) }
    } else {
        $previous = Get-ChildItem -LiteralPath $OutputDirectory -Filter 'summary-*.md' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $message = if ($previous) { "Latest local summary: $($previous.FullName)" } else { 'No previous local run summary exists.' }
        $results.Add((New-Result -Target 'host' -Phase 'Status' -Status 'PASS' -EvidencePath $hostEvidence -Message $message))
    }
} catch {
    $results.Add((New-Result -Target 'host' -Phase $Mode -Status 'FAIL' -ExitCode 1 -Message $_.Exception.Message -StartedAt $started))
}

$summary = Write-MarkdownSummary -Results $results.ToArray() -Directory $OutputDirectory -RunId $runId
$results | Format-Table target,phase,status,exit_code,evidence_path -AutoSize
Write-Host "Summary: $summary"
if (@($results | Where-Object { $_.status -eq 'FAIL' }).Count -gt 0) { exit 1 }
