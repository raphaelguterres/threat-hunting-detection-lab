# Offline HOST ONLY build of two versions of a harmless H03 probe.
# NEVER copies binaries into the WindowsServer VM and does not modify Wazuh FIM.
[CmdletBinding()]
param([switch]$RunOnHost)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source=Join-Path $repo 'tests\fixtures\h03_benign_probe.cs'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$dest=Join-Path $repo '.lab\h03-binary-artifacts'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)){throw 'MissingSource'}
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)){throw 'CSharpCompilerUnavailable'}
if (-not (Test-Path -LiteralPath $dest -PathType Container)) {
  [void](New-Item -Path $dest -ItemType Directory -Force)
}
$probeA=Join-Path $dest 'H03-BenignProbe-v1.exe'
$probeB=Join-Path $dest 'H03-BenignProbe-v2.exe'
foreach ($file in @($probeA,$probeB)) {
  if(Test-Path -LiteralPath $file -PathType Leaf){throw 'OutputExistsRefuseOverwrite'}
}
& $compiler /nologo /target:exe /optimize+ ("/out:" + $probeA) $source
if ($LASTEXITCODE -ne 0){throw 'CompilerVersion1Failed'}
& $compiler /nologo /target:exe /optimize+ /define:H03_V2 ("/out:" + $probeB) $source
if ($LASTEXITCODE -ne 0){throw 'CompilerVersion2Failed'}
$h1=(Get-FileHash -LiteralPath $probeA -Algorithm SHA256).Hash
$h2=(Get-FileHash -LiteralPath $probeB -Algorithm SHA256).Hash
if ($h1 -eq $h2){throw 'VersionsMustHaveDifferentHashes'}
Write-Output 'H03_BUILD_MODE=HOST_ONLY_PRIVATE_STAGING'
Write-Output 'BINARIES_BUILT=2'
Write-Output 'SHA256_VERSIONS_DISTINCT=TRUE'
Write-Output 'ARTIFACT_PATHS=PRIVATE_LAB_NOT_PRINTED'
if ($RunOnHost) {
  $a=& $probeA
  if ($LASTEXITCODE -ne 0 -or $a -ne 'H03_BENIGN_PROBE_VERSION_1'){throw 'HostV1TestFailed'}
  $b=& $probeB
  if ($LASTEXITCODE -ne 0 -or $b -ne 'H03_BENIGN_PROBE_VERSION_2'){throw 'HostV2TestFailed'}
  Write-Output 'HOST_EXECUTIONS=2'
  Write-Output 'HOST_FUNCTIONAL_TEST=PASS'
} else {
  Write-Output 'HOST_EXECUTIONS=0'
}
Write-Output 'WINDOWS_SERVER_GUEST_EXECUTIONS=0'
Write-Output 'WAZUH_FIM_EVENTS_EXPECTED_FROM_THIS_STEP=0'
Write-Output 'H03_REAL_PAIR=NOT_TESTED'
Write-Output 'DEPLOYMENT_GATE=BLOCKED'
