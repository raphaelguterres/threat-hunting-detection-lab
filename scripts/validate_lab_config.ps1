[CmdletBinding()]
param(
    [string]$ProjectRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent $scriptDirectory }

$failures = [System.Collections.Generic.List[string]]::new()
function Assert-LabCondition {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { Write-Host "PASS  $Message" -ForegroundColor Green }
    else { Write-Host "FAIL  $Message" -ForegroundColor Red; $script:failures.Add($Message) }
}

function Read-LabXml {
    param([string]$RelativePath)
    $path = Join-Path $ProjectRoot $RelativePath
    try { return [xml](Get-Content -LiteralPath $path -Raw) }
    catch { $script:failures.Add("XML inválido: $RelativePath ($($_.Exception.Message))"); return $null }
}

$rules = Read-LabXml 'config/local_rules.xml'
if ($null -ne $rules) {
    $ruleIds = @($rules.SelectNodes('//rule') | ForEach-Object { [string]$_.id })
    Assert-LabCondition ($ruleIds.Count -eq @($ruleIds | Select-Object -Unique).Count) 'IDs de regras locais são únicos.'
    foreach ($id in '100100','100101','100102','100103') {
        Assert-LabCondition ($ruleIds -contains $id) "Regra local $id existe."
    }
}

$sysmon = Read-LabXml 'config/windows/sysmon-lab.xml'
if ($null -ne $sysmon) {
    foreach ($eventName in 'ProcessCreate','NetworkConnect','FileCreate') {
        Assert-LabCondition ($null -ne $sysmon.SelectSingleNode("//*[local-name()='$eventName']")) "Sysmon inclui $eventName."
    }
}

foreach ($relativePath in @(
    'config/windows/wazuh-sysmon-eventchannel.xml',
    'tests/windows-sysmon-validation.md',
    'tests/linux-fim-validation.md',
    'tests/detection-quality-gate.md',
    'playbooks/response-governance.md',
    'docs/remote-dual-vm-operations.md'
)) {
    Assert-LabCondition (Test-Path -LiteralPath (Join-Path $ProjectRoot $relativePath) -PathType Leaf) "Artefato obrigatório existe: $relativePath"
}

if ($failures.Count -gt 0) {
    Write-Error ("Validação falhou: " + ($failures -join '; '))
    exit 1
}

Write-Host 'Configuração do laboratório validada.' -ForegroundColor Green
